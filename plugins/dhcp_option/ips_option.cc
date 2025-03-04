
// Snort includes
#include <framework/cursor.h>
#include <framework/module.h>
#include <hash/hash_key_operations.h>
#include <protocols/packet.h>

// System includes
#include <cassert>

// Local includes
#include "flow_data.h"
#include "ips_option.h"

// Debug includes

namespace dhcp_option {
namespace {

static const char *s_name = "dhcp_option";
static const char *s_help = "Filters on values of DHCP options";

static const snort::Parameter module_params[] = {
    {"~", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Identifies specific DHCP option (1 to 254) or symbolic name for option"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// We store the actual table in a seperate file, as it is big and noisy to have
// here
static const std::map<std::string, uint8_t> symbol_table{
#include "ips_option_symbol_table.txt"
};

class Module : public snort::Module {

  uint8_t value = 0;

  Module() : snort::Module(s_name, s_help, module_params) {}

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {

    if (val.is("~")) {
      val.lower(); // Convert string to lower case
      std::string type = val.get_as_string();

      // Check if we got a numeric value in the allowed range
      long number;
      if (val.strtol(number)) {
        value = number;
      } else {
        // If it wasn't a number, see if it is a known symbolic name
        auto symbolic = symbol_table.find(type);

        if (symbolic == symbol_table.end()) {
          return false;
        }

        value = symbolic->second;
      }

      // Validate value is safe
      if (value > 0 && value < 255) {
        return true;
      }
    }

    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override { return DETECT; }

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }

  uint8_t getValue() { return value; }
};

class IpsOption : public snort::IpsOption {

  uint8_t value = 0;

  IpsOption(Module &module)
      : snort::IpsOption(s_name), value(module.getValue()) {}

  // Hash compare is used as a fast way to compare two instances of IpsOption
  uint32_t hash() const override {
    uint32_t a = snort::IpsOption::hash(), b = value, c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
  }

  // If hashes match a real comparison check is made
  bool operator==(const snort::IpsOption &ips) const override {
    return snort::IpsOption::operator==(ips) &&
           dynamic_cast<const IpsOption &>(ips).value == value;
  }

  EvalStatus eval(Cursor &c, snort::Packet *p) override {

    if (!p->flow)
      return NO_MATCH;

    FlowData *flow_data =
        dynamic_cast<FlowData *>(p->flow->get_flow_data(FlowData::get_id()));

    if (!flow_data) {
      return NO_MATCH;
    }

    size_t offset, size;

    if (value == 0 || !flow_data->get(value, offset, size)) {
      // If we don't have the option or it is unset, then there isn't a match
      return NO_MATCH;
    }

    // Set cursor to point to the option of this data
    c.set(s_name, p->data + offset, size);

    return MATCH;
  }

  snort::CursorActionType get_cursor_type() const override {
    return snort::CAT_ADJUST;
  }

public:
  static snort::IpsOption *ctor(snort::Module *module, IpsInfo &) {
    assert(module);
    return new IpsOption(*dynamic_cast<Module *>(module));
  }

  static void dtor(snort::IpsOption *p) { delete p; }
};

} // namespace

const snort::IpsApi ips_option = {{
                                      PT_IPS_OPTION,
                                      sizeof(snort::IpsApi),
                                      IPSAPI_VERSION,
                                      0,
                                      API_RESERVED,
                                      API_OPTIONS,
                                      s_name,
                                      s_help,
                                      Module::ctor,
                                      Module::dtor,
                                  },
                                  snort::OPT_TYPE_DETECTION,
                                  0,
                                  PROTO_BIT__TCP,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  IpsOption::ctor,
                                  IpsOption::dtor,
                                  nullptr};

} // namespace dhcp_option
