
// Snort includes

// System includes
#include <cassert>
#include <format>
#include <iostream>
#include <regex>

// Local includes
#include <lioli.h>
#include <lioli_path.h>

// Debug includes
#include <perfetto.h>
PERFETTO_DEFINE_CATEGORIES(
perfetto::Category("trout_test").SetDescription("Sample trace"),
perfetto::Category("trout_exclude").SetDescription("Sample trace"));


namespace LioLi {
namespace {
// Helper functions for serializing
class Binary {
public:
  // Convert to format compatible with GO varints
  static std::ostream &as_varint(std::ostream &os, uint64_t number) {

    do {
      uint8_t digit = number & 0b0111'1111;
      number >>= 7;
      if (number)
        digit |= 0b1000'0000;
      os << digit;
    } while (number);

    return os;
  }
};

class LorthHelpers {
public:
  static std::string escape2(const std::string &&in) {
		TRACE_EVENT("trout_test", "string escape2", "string", in);
    std::string output;
    for (char c : in) {
      // Normal format chars are escaped C style
      switch (c) {
      case '\\':
        output += "\\\\";
        continue;
      case '\"':
        output += "\\\"";
        continue;

      case '\n':
        output += "\\n";
        continue;

      case '\t':
        output += "\\t";
        continue;

      case '\r':
        output += "\\r";
        continue;
      }

      // Printable ascii is transfered raw
      if (c >= ' ' && c <= '~') {
        output += c;
        continue;
      }

      // What remains are hex escaped
      output += std::format("\\x{:02x}", c);
    }

    return output;
  }

  static std::string escape(const std::string &&in) {
    // Chars that should be escaped
    TRACE_EVENT("trout_test", "org string escape", "string", in);
    const static std::string esc("\"\n\t\r");

    std::string::size_type spos = 0;
    std::string::size_type sfind = in.find_first_of(esc);

    // Bail if nothing to do
    if (in.npos == sfind)
      return in;

    std::string outstring;

    do {
      char replacer;
      switch (in[sfind]) {
      case '\"':
        replacer = '"';
        break;
      case '\n':
        replacer = 'n';
        break;
      case '\t':
        replacer = 't';
        break;
      case '\r':
        replacer = 'r';
        break;
      default:
        assert(false); // We don't know how to replace
      }

      outstring +=
          in.substr(spos, sfind - spos); // note, we don't add 1, as the pos we
                                         // found shouldn't be copied
      outstring += '\\';
      outstring += replacer;
      spos = sfind + 1;
      sfind = in.find_first_of(esc, spos);
    } while (in.npos != sfind);

    // Copy reminder of string
    outstring += in.substr(spos);

    return outstring;
  }
};

} // namespace

void Tree::Node::set_end(size_t new_end) { end = new_end; }

void Tree::Node::add_as_child(const Node &node) {
	TRACE_EVENT("trout_test", "add const child node");
  last_child_added = children.emplace_after(last_child_added, node);
  last_child_added->adjust(end);
  end = last_child_added->end;
}

void Tree::Node::add_as_child(Node &&node) {
	TRACE_EVENT("trout_test", "add non-const child node");
  last_child_added = children.insert_after(last_child_added, std::move(node));
  last_child_added->adjust(end);
  end = last_child_added->end;
}

// Copy version of append
void Tree::Node::append(const Node &node) {
TRACE_EVENT("trout_test", "append node by copy");
  // We only know how to merge node names, if one is null or they are equal
  if (node.my_name.size() == 0) {
    // Do nothing
  } else if (my_name.size() == 0) {
    my_name = node.my_name;
  } else if (my_name != node.my_name) {
    assert(false);
  }

  for (auto child_node : node.children) {
    last_child_added = children.emplace_after(last_child_added, child_node);
    // Adjust the newly created child trees start and end
    last_child_added->adjust(end);
  }

  end += node.end;
}

// Move version of append
void Tree::Node::append(Node &&node) {
	TRACE_EVENT("trout_test", "append node by move");
  // We only know how to merge node names, if one is null or they are equal
  if (node.my_name.size() == 0) {
    // Do nothing
  } else if (my_name.size() == 0) {
    my_name = std::move(node.my_name);
  } else if (my_name != node.my_name) {
    assert(false);
  }

  // Shift the incoming node to be after this one
  node.adjust(end);
  // Set new end
  end = node.end;

  // Move nodes children to use
  while (node.children.begin() != node.children.end()) {
    last_child_added = children.insert_after(last_child_added,
                                             std::move(node.children.front()));
    node.children.pop_front();
  }

  // Clean up last fields of node
  node.start = 0;
  node.end = 0;
}

Tree::Node::Node(){};

Tree::Node::Node(const Node &p)
    : my_name(p.my_name), start(p.start), end(p.end), children(p.children) {
  last_child_added = children.before_begin();

  auto tmp = last_child_added;

  while (++tmp != children.end()) {
    last_child_added = tmp;
  }
}

Tree::Node::Node(Node &&src) {
  my_name = std::move(src.my_name);
  src.my_name.clear();
  start = src.start;
  src.start = 0;
  end = src.end;
  src.end = 0;
  children = std::move(src.children);
  src.children.clear();

  // The before begin iterator is specific to a given forward list, but
  // iterators to elements that are moved, points to the moved elements
  if (src.last_child_added != src.children.before_begin()) {
    last_child_added = src.last_child_added;
    src.last_child_added = children.before_begin();
  } else {
    last_child_added = children.before_begin();
  }
}

Tree::Node::Node(std::string name) : my_name(name) {
  assert(Path::is_valid_node_name(name));
}

void Tree::Node::adjust(size_t delta) {
	TRACE_EVENT("trout_test", "node adjust");
  start += delta;
  end += delta;

  for (auto &child : children) {
    child.adjust(delta);
  }
}

std::string Tree::Node::dump_string(const std::string &raw,
                                    unsigned level) const {
TRACE_EVENT("trout_test", "dump string");
  std::string output;
  output.insert(0, level, '-');

  output += my_name + ": ";

  output += LorthHelpers::escape2(raw.substr(start, end - start));

  output += "\n";

  for (auto &child : children) {
    output += child.dump_string(raw, level + 1);
  }
  return output;
}

std::string Tree::Node::dump_lorth(const std::string &raw,
                                   unsigned level) const {
TRACE_EVENT("trout_test", "dump lorth");																		 
  std::string output;
  std::string spacer;
  spacer.insert(0, level, ' ');

  output += spacer;
  output += my_name + " ";

  if (!children.empty()) {
    output += "{\n";

    size_t ep = start;
    for (auto &child : children) {
      if (ep != child.start) {
        output += spacer + " \"" + raw.substr(ep, child.start - ep) + "\" .\n";
      }
      output += child.dump_lorth(raw, level + 1);
      ep = child.end;
    }
    if (ep != end) {
      output += spacer + " \"" + raw.substr(ep, end - ep) + "\" .\n";
    }
    output += spacer + "}\n";
  } else {

    output +=
        "\"" + LorthHelpers::escape2(raw.substr(start, end - start)) + "\" .\n";
  }

  return output;
}

std::string Tree::Node::dump_python(const std::string &raw, unsigned level,
                                    bool array_item) const {
TRACE_EVENT("trout_test", "dump python");
  assert(my_name.size() >= 1); // A name must at least have 1 char
  bool is_array = (my_name[0] == '#');
  std::string output;
  std::string nc_output; // String containing the NonChild part of raw
  std::string c_output;  // String contianing the Child part of raw
  std::string spacer;
  spacer.insert(0, level * 2, ' ');

  size_t pos = start; // Current position

  for (auto &child : children) {
    nc_output += raw.substr(pos, child.start - pos);
    c_output += child.dump_python(raw, level + 1, is_array);
    pos = child.end;
  }

  nc_output += raw.substr(pos, end - pos);

  output += spacer;

  if (!array_item) {
    output += '\"' + my_name + "\" : ";
  }

  output += "(\"" + LorthHelpers::escape2(std::move(nc_output)) + "\",";

  if (is_array) {
    if (c_output.empty()) {
      output += "(),),\n"; // NOTE: Python needs a comma after an empty tuple to
                           // recognize it as a tuple
    } else {
      output += "(\n" + c_output + spacer + " ),\n";
      output += spacer + "),\n";
    }
  } else {
    if (c_output.empty()) {
      output += "{}),\n";
    } else {
      output += "{\n" + c_output + spacer + " }\n";
      output += spacer + "),\n";
    }
  }

  return output;
}

std::string Tree::Node::dump_binary(size_t delta, bool add_root_node) const {
	TRACE_EVENT("trout_test", "dump binary");
  std::string output;

  if (add_root_node) {
    if (!children.empty()) {
      output.append(2,
                    0); // Reserve 2 bytes at the beginning for string content
    }

    auto name_length = my_name.size(); // Length of the name of this node

    assert(name_length <= 0b0011'1111'1111'1111); // We can't serialize names
                                                  // longer than 14 bits

    output += static_cast<char>(0b0100'0000 | (name_length & 0b0011'1111));
    output += static_cast<char>(name_length >> 6);

    output += my_name;

    auto skip = start - delta; // How much of the raw string should be skipped
                               // before this node starts
    auto length = end - start; // Length of the raw string captured by this node
    if (skip <= 0b0000'0111 && length <= 0b0000'1111) {
      // 1 byte (3-bit start delta (x), 4 bit length (y) 0b0xxx yyyy
      output += static_cast<char>((skip << 4) | length);
    } else if (skip <= 0b0011'1111 && length <= 0b1111'1111) {
      // 2 bytes (6-bit start delta (x), 8 bit length (y) 0b10xx xxxx yyyy
      // yyyy
      output += static_cast<char>(0b1000'0000 | skip);
      output += static_cast<char>(length);
    } else {
      // 4 bytes (14-bit start delta (x), 16 bit length (y) 0b11xx xxxx xxxx
      // xxxx yyyy yyyy yyyy yyyy
      assert(
          skip <= 0b0011'1111'1111'1111 &&
          length <=
              0b1111'1111'1111'1111); // These are the max sizes we can encode
      // TODO: We probably want to fail gracefully here, e.g. consider
      // truncating data / child nodes

      output += static_cast<char>(0b1100'0000 | (0b0011'1111 & skip));
      output += static_cast<char>(skip >> 6);
      output += static_cast<char>(0b1111'1111 & length);
      output += static_cast<char>(length >> 8);
    }
  }
  size_t new_start = start;

  for (auto &child : children) {
    output += child.dump_binary(new_start,
                                true /* Can't be the root node, if it is a
                                        child, so first node must be included */
    );
    new_start = child.end;
  }

  if (add_root_node && !children.empty()) {
    auto length =
        output.size() - 2; // We don't include the size bytes in the length
    assert(length <= 0b0111'1111'1111'1111); // We only have 15 bits for the
                                             // length encoding
    output[0] = 0b1000'0000 | (length & 0b0111'1111);
    output[1] = length >> 7;
  }
  return output;
}

bool Tree::Node::is_valid(size_t start, size_t end) const {
	
	TRACE_EVENT("trout_test", "check node is valid", "node name", (my_name.length()?my_name.c_str():"empty"));
	TRACE_EVENT("trout_test", "inside check node");

	{
		TRACE_EVENT("trout_test", "Trace a trace");
		{
			TRACE_EVENT("trout_exclude", "Excluded trace");
		}

	}

	{
		TRACE_EVENT("trout_test", "Trace a trace");
		{
			TRACE_EVENT("trout_test", "Included trace");
		}

	}


	
  if (this->start < start || this->end > end) {
    return false;
  }

{
	TRACE_EVENT("trout_test", "inside check node - looping");
  size_t sp = this->start;
  for (auto &child : children) {
    if (!child.is_valid(sp, end)) {
      return false;
    }
    sp = child.end; // Next child can't have overlap with previous one
  }
}
  return true;
}

bool Tree::Node::lookup(std::string key, size_t &start, size_t &end,
                        size_t &skip) const {
  // Extract node name until the next '.' (note key == key.substr(0,npos))
  auto dot_pos = key.find('.');
  std::string child_key =
      (dot_pos != std::string::npos) ? key.substr(dot_pos + 1) : "";

  // std::cout << "MKRTEST: At: " << my_name << " Looking for: " << key << "
  // skip is: " << skip << std::endl;

  if (my_name != key.substr(0, dot_pos)) {
    return false;
  }

  if (child_key.length() == 0) {
    if (skip > 0) {
      skip--;
      // std::cout << "MKRTEST: skipping match" << std::endl;
      return false;
    }

    //		std::cout << "MKRTEST: That was me" << std::endl;
    start = this->start;
    end = this->end;

    // std::cout << "MKRTEST: MATCH!!!" << std::endl;
    return true;
  }

  // std::cout << "MKRTEST: At: " << my_name << " Looking for: " << child_key <<
  // " skip is: " << skip << std::endl;

  //	std::cout << "MKRTEST: Searching for a child named: " << child_key <<
  // std::endl;
  for (auto &child : children) {
    // std::cout << "MKRTEST: At: " << my_name << " Looking at child: " <<
    // child.my_name << std::endl;
    if (child.lookup(child_key, start, end, skip)) {
      return true;
    }
  }

  return false;
}

bool Tree::Node::regex_lookup(
    std::regex &regex, std::function<bool(size_t start, size_t end)> lambda,
    std::string &rkey) const {
  std::cmatch m;

  std::string my_path = rkey + my_name;

  // std::cout << "MKRTEST: Now checking: " << my_path << std::endl;

  if (std::regex_match(my_path.c_str(), m, regex)) {
    // std::cout << "MKRTEST: MATCH!!!" << std::endl;
    if (!lambda(start, end)) {
      return false;
    }
  }

  my_path += '.';

  for (auto &child : children) {
    //    std::cout << "MKRTEST: At: " << my_path
    //              << " Looking at child: " << child.my_name << std::endl;
    if (!child.regex_lookup(regex, lambda, my_path)) {
      return false;
    }
  }

  return true;
}

Tree::Tree() {}

Tree::Tree(const std::string &name) : me(name) {
  assert(Path::is_valid_node_name(name));
}

Tree &Tree::operator<<(const std::string &text) {
  assert(is_valid());

  raw += text;
  me.set_end(raw.size());

  assert(is_valid());
  return *this;
}

Tree &Tree::operator<<(const int number) {
  assert(is_valid());

  std::string sn = std::to_string(number);
  raw += sn;
  me.set_end(raw.size());

  assert(is_valid());
  return *this;
}

Tree &Tree::operator<<(const Tree &tree) {
  assert(is_valid());
  assert(tree.is_valid());

  raw += tree.raw;
  me.add_as_child(tree.me);

  assert(is_valid());
  assert(tree.is_valid());

  return *this;
}

Tree &Tree::operator<<(Tree &&tree) {
  assert(is_valid());
  assert(tree.is_valid());

  if (raw.size() == 0) {
    raw.swap(tree.raw); // no need to copy string if target string is empty
  } else {
    raw += tree.raw;
    tree.raw.clear();
  }

  me.add_as_child(std::move(tree.me));

  assert(is_valid());
  assert(tree.is_valid());
  return *this;
}

void Tree::merge(const Tree &tree, bool node_merge) {
  if (node_merge) {
    // TODO: Make node_merge version
    assert(false);
  } else {
    // Merge the nodes
    me.append(tree.me);
    // Merge he data
    raw.append(tree.raw);
  }
}

void Tree::merge(Tree &&tree, bool node_merge) {
  if (node_merge) {
    // TODO: Make node_merge version
    assert(false);
  } else {
    // Merge the nodes
    me.append(std::move(tree.me));
    // Merge he data
    raw.append(tree.raw);
    // Clear incoming tree
    tree.raw.clear();
  }
}

bool Tree::operator==(const Tree &tree) const {
  return 0 == tree.as_string().compare(as_string());
}

std::string Tree::as_string() const { return me.dump_string(raw); }

std::string Tree::as_lorth() const {
  std::string output = me.dump_lorth(raw);
  output = output.substr(0, output.length() - 1) + ";\n";
  return output;
}

std::string Tree::as_python() const {
  std::string output = me.dump_python(raw, 1);
  output = output.substr(0, output.length() - 2);
  return output;
}

std::string Tree::lookup(std::string key) const {
  size_t start;
  size_t end;
  size_t skip = 0;

  // std::cout << "MKRTEST: Tree::lookup(" << key << ")" << std::endl;

  if (me.lookup(key, start, end, skip)) {
    return raw.substr(start, end - start);
  }

  return "";
}

void Tree::regex_lookup(std::string regex,
                        std::function<bool(std::string value)> lambda) const {
  std::regex re(regex);
  std::string blank;
  me.regex_lookup(
      re,
      [this, lambda](size_t start, size_t end) {
        return lambda(raw.substr(start, end - start));
      },
      blank);
}

bool Tree::is_valid() const {
  size_t rs = raw.size();

  return me.is_valid(0, rs);
}

LioLi::LioLi() {}

void LioLi::insert_header() {
  ss << '\x4' << "BILL" << '\x0' << '\x2';
  for (int i = 0; i < 9; i++) {
    ss << secret[i];
  }
}

void LioLi::insert_terminator() {
  // BILL02 format does not use terminators
}

size_t LioLi::length() { return ss.str().length(); }

std::string LioLi::move_binary() {
  return std::move(ss).str(); // we clear ss by the move
}

std::ostream &operator<<(std::ostream &os, LioLi &out) {
  os << out.move_binary();
  return os;
}

LioLi &operator<<(LioLi &ll, const Tree &bf) {
  Binary::as_varint(ll.ss, bf.raw.size());
  ll.ss << bf.raw;

  std::string tree = bf.me.dump_binary(0, ll.add_root_node);

  Binary::as_varint(ll.ss, tree.size());
  ll.ss << tree;

  return ll;
}

} // namespace LioLi
