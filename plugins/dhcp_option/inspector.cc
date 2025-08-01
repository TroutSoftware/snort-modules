
// Snort includes
#include <detection/detection_engine.h>
#include <framework/base_api.h>
#include <framework/counts.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <protocols/packet.h>

// System includes
#include <cassert>
#include <cstring>
#include <memory>

// Global includes
#include <trout_gid.h>

// Local includes
#include "flow_data.h"
#include "inspector.h"

// Debug includes

namespace dhcp_option {
namespace {

static const char *s_name = "dhcp";
static const char *s_help = "Identifies and parses DHCP packages";

static const unsigned gid = Common::trout_gid; // Module wide GID

// SID List
enum class SID {
  valid = 1010,
  invalid = 1011,
  no_options = 1012,
  invalid_op_code = 1013,
  sname_not_terminated = 1014,
  file_not_terminated = 1015,
  magic_cookie_fail = 1016,
  options_corrupted = 1017,
  no_flow = 1018,
  misplaced_subnet = 1019,
};

unsigned U(SID sid) { return static_cast<unsigned>(sid); }

static const snort::RuleMap s_rules[] = {
    {U(SID::valid), "Valid DHCP packet"},
    {U(SID::invalid), "Invalid DHCP packet"},
    {U(SID::no_options), "No options"},
    {U(SID::invalid_op_code), "Invalide op code"},
    {U(SID::sname_not_terminated), "sname is not zero terminated"},
    {U(SID::file_not_terminated), "file field is not zero terminated"},
    {U(SID::magic_cookie_fail), "magic cookie doesn't match"},
    {U(SID::options_corrupted), "options list is corrupted"},
    {U(SID::misplaced_subnet), "misplaced subnet"},
    {0, nullptr}};

static const snort::Parameter module_params[] = {
    {"header_parsing", snort::Parameter::PT_BOOL, nullptr, "true",
     "Won't do any validation of the header if set to false"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// Note: Snort pegs are not part of the snort namespace, this array must match
// the PegData struct
const PegInfo s_pegs[] = {
    {CountType::SUM, "valid_dhcp_package", "Number of valid dhcp packets seen"},
    {CountType::SUM, "invalid_dhcp_package",
     "Number of invalid dhcp packets seen"},
    {CountType::SUM, "no_upd_data",
     "Number of packages that doesn't have udp data"},
    {CountType::SUM, "insufficient_upd_data",
     "Packages that has udp data, but not the minimum required by RFC2131"},
    {CountType::SUM, "no_options",
     "Packages that doesn't contain space for an options field"},
    {CountType::SUM, "headers_parsed",
     "Packages that had their headers passed"},
    {CountType::SUM, "headers_skipped",
     "Packages that had their header check skipped"},
    {CountType::SUM, "boot_request", "Packages that are BOOTREQUEST"},
    {CountType::SUM, "boot_reply", "Packages that are BOOTREPLY"},
    {CountType::SUM, "invalid_op_code",
     "Packages that contained invalid op codes"},
    {CountType::SUM, "unknown_htype",
     "Packages that contained htype fields, that wasn't (1) 10mb ethernet"},
    {CountType::SUM, "invalid_hlen", "Packages with hlen != 6"},
    {CountType::SUM, "sname_not_terminated",
     "Packages with an sname field that isn't zero terminated"},
    {CountType::SUM, "file_not_terminated",
     "Packages with a file filed that isn't zero terminated"},
    {CountType::SUM, "magic_cookie_fail",
     "Packages with an invalid magic cookie for options field"},
    {CountType::SUM, "options_corrupted",
     "Packages with an invalid formatted options field"},
    {CountType::SUM, "duplicate_option", "Packages with duplicate options"},
    {CountType::SUM, "options_valid", "Packages with valid options list"},
    {CountType::SUM, "no_flow",
     "Packages that apear to be DHCP but doesn't have a flow"},
    {CountType::SUM, "misplaced_subnet", "Router option preceeded subnet mask"},
    {CountType::END, nullptr, nullptr}};

// This must match the s_pegs[] array
static THREAD_LOCAL struct PegCounts {
  PegCount valid = 0;
  PegCount invalid = 0;
  PegCount no_udp_data = 0;
  PegCount insufficient_udp_data = 0;
  PegCount no_options = 0;
  PegCount header_parsed = 0;
  PegCount header_skipped = 0;
  PegCount boot_request = 0;
  PegCount boot_reply = 0;
  PegCount invalid_op_code = 0;
  PegCount unknown_htype = 0;
  PegCount invalid_hlen = 0;
  PegCount sname_not_terminated = 0;
  PegCount file_not_terminated = 0;
  PegCount magic_cookie_fail = 0;
  PegCount options_corrupted = 0;
  PegCount duplicate_option = 0;
  PegCount options_valid = 0;
  PegCount no_flow_data = 0;
  PegCount misplaced_subnet = 0;
} s_peg_counts;

// Compile time sanity check of number of entries in s_pegs and s_peg_counts
static_assert(
    (sizeof(s_pegs) / sizeof(PegInfo)) - 1 ==
        sizeof(PegCounts) / sizeof(PegCount),
    "Entries in s_pegs doesn't match number of entries in s_peg_counts");

class Module : public snort::Module {
  bool parse_header = true;

  const PegInfo *get_pegs() const override { return s_pegs; }
  PegCount *get_counts() const override {
    return reinterpret_cast<PegCount *>(&s_peg_counts);
  }
  unsigned get_gid() const override { return gid; }
  const snort::RuleMap *get_rules() const override { return s_rules; }
  bool is_bindable() const override { return true; }
  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("header_parsing")) {
      parse_header = val.get_bool();
    }
    return true;
  }

  // Snort seems to complain if usage type isn't INSPECT when type is SERVICE
  Usage get_usage() const override { return INSPECT; }

  Module() : snort::Module(s_name, s_help, module_params) {}

public:
  static snort::Module *ctor() { return new Module(); }

  static void dtor(snort::Module *p) { delete p; }

  bool parseHeader() { return parse_header; }
};

class Inspector : public snort::Inspector {

  Module &module;

  Inspector(Module &module) : module(module) {}

  ~Inspector() {}

  void queue(SID sid) { snort::DetectionEngine::queue_event(gid, U(sid)); }

  void eval(snort::Packet *p) override {

    if (!p || !p->is_udp() || !p->has_udp_data()) {
      queue(SID::invalid);
      s_peg_counts.no_udp_data++;
      s_peg_counts.invalid++;
      return;
    }

    // See RFC2131 for details about parsing this structure
    struct RFC2131DHCPMsgHeader {
      uint8_t op;
      uint8_t htype;
      uint8_t hlen;
      uint8_t hops;
      uint32_t xid;
      uint16_t secs;
      uint16_t flags;
      uint32_t ciaddr;
      uint32_t yiaddr;
      uint32_t siaddr;
      uint32_t giaddr;
      uint8_t chaddr[16];
      uint8_t sname[64];
      uint8_t file[128];
    };

    // This check validates that we have enough data to fill the
    // RFC2131DHCPMsgHeader data
    if (p->dsize < sizeof(RFC2131DHCPMsgHeader)) {
      queue(SID::invalid);
      s_peg_counts.insufficient_udp_data++;
      s_peg_counts.invalid++;
      return;
    }

    if (module.parseHeader()) {

      const RFC2131DHCPMsgHeader *header =
          reinterpret_cast<const RFC2131DHCPMsgHeader *>(p->data);

      switch (header->op) {
      case 0x01:
        s_peg_counts.boot_request++;
        break;
      case 0x02:
        s_peg_counts.boot_reply++;
        break;
      default:
        queue(SID::invalid_op_code);
        queue(SID::invalid);
        s_peg_counts.invalid_op_code++;
        s_peg_counts.invalid++;
        return;
      }

      if (header->htype != 1) {
        queue(SID::invalid);
        s_peg_counts.unknown_htype++;
        s_peg_counts.invalid++;
        return;
      }

      if (header->hlen != 6) {
        queue(SID::invalid);
        s_peg_counts.invalid_hlen++;
        s_peg_counts.invalid++;
        return;
      }

      // Ensure sname is zero terminated
      if (nullptr == std::memchr(header->sname, 0, sizeof(header->sname))) {
        queue(SID::sname_not_terminated);
        queue(SID::invalid);
        s_peg_counts.sname_not_terminated++;
        s_peg_counts.invalid++;
        return;
      }

      if (nullptr == std::memchr(header->file, 0, sizeof(header->file))) {
        queue(SID::file_not_terminated);
        queue(SID::invalid);
        s_peg_counts.file_not_terminated++;
        s_peg_counts.invalid++;
        return;
      }

      s_peg_counts.header_parsed++; // We only count a header as parsed if we
                                    // checked all fields
    } else {
      s_peg_counts.header_skipped++;
    } // Header parsing condition

    // Bail if we don't have any options
    if (p->dsize == sizeof(RFC2131DHCPMsgHeader)) {
      queue(SID::no_options);
      queue(SID::valid);
      s_peg_counts.no_options++;
      s_peg_counts.valid++;
      return;
    }

    ////////// Options parsing //////////
    // TODO: Find C++ std container that does the job

    // This class is specialized for the way we parse the DHCP options
    // structure, it is NOT a generic index class
    class Index {
      size_t remainder;
      size_t index;

    public:
      Index(size_t size, size_t start) : remainder(size - start), index(start) {
        assert(size >= start);
      }

      size_t operator++(int) {
        assert(remainder > 0);
        remainder--;
        return index++;
      }

      Index &operator+=(const uint8_t rhs) {
        // If we try to increment past the end, mark index as empty - this only
        // works because we know we are parsing a DHCP options structure
        if (remainder <= rhs) {
          remainder = 0;
        } else {
          remainder -= rhs;
          index += rhs;
        }
        return *this;
      }

      size_t bytesLeft() { return remainder; }

      bool hasMore() { return remainder > 0; }

      operator size_t() const {
        assert(remainder > 0);
        return index;
      }

    } index(p->dsize, sizeof(RFC2131DHCPMsgHeader));

    // See RFC2132 for how to parse option field, finding magic numbers etc
    if (index.bytesLeft() < 4 /* Magic cookie length */
        || p->data[index++] != 0x63 || p->data[index++] != 0x82 ||
        p->data[index++] != 0x53 || p->data[index++] != 0x63) {
      queue(SID::magic_cookie_fail);
      queue(SID::invalid);
      s_peg_counts.magic_cookie_fail++;
      s_peg_counts.invalid++;
      return;
    }

    // Check that we have a flow
    if (!p->flow) {
      queue(SID::no_flow);
      queue(SID::invalid);
      s_peg_counts.no_flow_data++;
      s_peg_counts.invalid++;
      return;
    }

    // Delete any existing flow data, from previous packets
    if (nullptr != p->flow->get_flow_data(FlowData::get_id())) {
      p->flow->free_flow_data(FlowData::get_id());
    }

    auto flowData = std::make_unique<FlowData>(
        this); // Store flow data in unique ptr so clean up will be automatic if
               // not used

    while (index.hasMore()) {
      auto type = p->data[index++];
      switch (type) {
      case 0:     // Pad option
        continue; // Goto next option
      case 255:   // End option
        // If we come here all is good, and we can add flow data to the packet
        p->flow->set_flow_data(flowData.release());

        queue(SID::valid);
        s_peg_counts.options_valid++;
        s_peg_counts.valid++;
        return;

      case 1: // Subnet mask is not allowed to follow router option in a reply
              // RFC2132 §3.3
        if (flowData->has(3 /* Router Option */)) {
          queue(SID::misplaced_subnet);
          s_peg_counts.misplaced_subnet++;
          goto failed_options_parsing; // Use goto as we can't double break
        }
        // TODO: Check length of this and many other options with rules for
        // their length
        break;

      default:
        break;
      }

      size_t length =
          p->data[index++]; // The data byte is not part of the length,
                            // and if index is advanced past the end,
                            // hasMore will return false in the while
                            // loop and result in an invalid event
      size_t offset = index;
      index += length;

      // If data is invalid (e.g. wrong length), flow data won't be added to
      // the package as it is only added on sucesfull parsing
      if (!flowData->set(type, offset, length)) {
        // If we get a false in return from the flowData.set, it means
        // duplicate entry
        s_peg_counts.duplicate_option++;
        break;
      }
    }

  failed_options_parsing:

    queue(SID::options_corrupted);
    queue(SID::invalid);
    s_peg_counts.options_corrupted++;
    s_peg_counts.invalid++;
  }

public:
  static snort::Inspector *ctor(snort::Module *module) {
    return new Inspector(*dynamic_cast<Module *>(module));
  }

  static void dtor(snort::Inspector *p) { delete p; }
};

} // namespace

const snort::InspectApi inspector = {
    {
        PT_INSPECTOR,
        sizeof(snort::InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        Module::ctor,
        Module::dtor,
    },
    snort::IT_SERVICE,
    PROTO_BIT__UDP,
    nullptr, // buffers
    s_name,  // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    Inspector::ctor,
    Inspector::dtor,
    nullptr, // ssn
    nullptr  // reset
};

} // namespace dhcp_option
