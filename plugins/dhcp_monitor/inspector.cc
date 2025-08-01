
// Snort includes
#include "framework/inspector.h"
#include "detection/detection_engine.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/dhcp_events.h"
#include "pub_sub/intrinsic_event_ids.h"

// System includes
#include <cassert>
#include <mutex>
#include <shared_mutex>

// Global includes
#include "trout_gid.h"

// Local includes
#include "inspector.h"

// Debug includes

namespace dhcp_monitor {
namespace {

const static unsigned dhcp_monitor_gid = Common::trout_gid;
const static unsigned dhcp_monitor_ip_conflict_sid = 1001;
const static unsigned dhcp_monitor_dhcp_conflict_sid = 1002;
const static unsigned dhcp_monitor_unknown_network_sid = 1003;

static const snort::Parameter dhcp_monitor_params[] = {
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

static const snort::RuleMap s_rules[] = {
    {dhcp_monitor_ip_conflict_sid, "ip conflict"},
    {dhcp_monitor_dhcp_conflict_sid, "dhcp conflict"},
    {dhcp_monitor_unknown_network_sid, "unknown network"},
    {0, nullptr}};

struct DHCPStats {
  PegCount info_count;
  PegCount check_count;
  PegCount check_count_fail;
  PegCount update_count;
  PegCount network_count;
  PegCount unknown_count;
  PegCount no_ip_count;
  PegCount src_dst_ip_err_count;
  PegCount ip_pass_count;
  PegCount ip_dual_pass_count;
  PegCount dhcp_flagged;
  PegCount ip_flagged;
  PegCount dual_ip_flagged;
};

static THREAD_LOCAL DHCPStats s_dhcp_stats = {0, 0, 0, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0};

const PegInfo s_pegs[] = {
    {CountType::SUM, "info_event", "info events received"},
    {CountType::SUM, "check_count", "number of checks done"},
    {CountType::SUM, "check_count_fail", "number of checks done that failed"},
    {CountType::SUM, "network_update", "network address updates"},
    {CountType::SUM, "network_set", "network address's"},
    {CountType::SUM, "unknown_network", "unknown network used"},
    {CountType::SUM, "no_ip", "no ip in (stream) packet"},
    {CountType::SUM, "src_dst_ipv4_err",
     "either not ipV4 or src or dst ip missing"},
    {CountType::SUM, "ip_pass", "ip's seen within range"},
    {CountType::SUM, "dual_ip_pass", "at least one of pair has passed"},
    {CountType::SUM, "dhcp_flagged", "DHCP network addr changed"},
    {CountType::SUM, "ip_flagged",
     "single ip seen and not being in known range"},
    {CountType::SUM, "dual_ip_flagged",
     "src and dst of package had unknown ip's"},

    {CountType::END, nullptr, nullptr}};

class DHCPMonitorModule : public snort::Module {

  const PegInfo *get_pegs() const override { return s_pegs; }
  PegCount *get_counts() const override { return (PegCount *)&s_dhcp_stats; }
  unsigned get_gid() const override { return dhcp_monitor_gid; }
  const snort::RuleMap *get_rules() const override { return s_rules; }

public:
  DHCPMonitorModule()
      : Module("dhcp_monitor",
               "Monitors DHCP comunication looking for unexpected use of "
               "network addresss",
               dhcp_monitor_params) {}
};

class DHCPMonitorInspector : public snort::Inspector {
  class DHCPRecord {
    uint32_t network_address;
    uint32_t network_mask;

  public:
    DHCPRecord(uint32_t network_address, uint32_t network_mask)
        : network_address(network_address), network_mask(network_mask) {
      s_dhcp_stats.network_count++;
    }

    bool validate(uint32_t ip_address) {
      s_dhcp_stats.check_count++;
      if (network_address == (ip_address & network_mask)) {
        return true;
      }
      s_dhcp_stats.check_count_fail++;
      return false;
    }

    uint32_t get_network_address() { return network_address; }
    uint32_t get_network_mask() { return network_mask; }

    void update(uint32_t network_address, uint32_t network_mask) {
      s_dhcp_stats.update_count++;
      this->network_address = network_address;
      this->network_mask = network_mask;
    }
  };

  struct {
    std::shared_mutex mutex;
    std::map<uint32_t, DHCPRecord> map;
  } network;

  // Must be called with the network.mutex taken if the record is from the
  // network member
  void validate(uint32_t ip, DHCPRecord &record) {
    if (!record.validate(ip)) {
      flag_ip_conflict(ip, record);
    } else {
      s_dhcp_stats.ip_pass_count++;
    }
  }

  // Must be called with the network.mutex taken if the record is from the
  // network member
  void validate(uint32_t ip1, uint32_t ip2, DHCPRecord &record) {
    if (!record.validate(ip1) && !record.validate(ip2)) {
      flag_ip_conflict(ip1, ip2, record);
    } else {
      s_dhcp_stats.ip_dual_pass_count++;
    }
  }

public:
  DHCPMonitorInspector(DHCPMonitorModule *) {}

  ~DHCPMonitorInspector() {}

  void eval(snort::Packet *) override {}

  bool configure(snort::SnortConfig *) override;

  void flag_ip_conflict(uint32_t /*ip*/, DHCPRecord & /*record*/) {
    s_dhcp_stats.ip_flagged++;
    snort::DetectionEngine::queue_event(dhcp_monitor_gid,
                                        dhcp_monitor_ip_conflict_sid);
  }

  void flag_ip_conflict(uint32_t /*ip1*/, uint32_t /*ip2*/,
                        DHCPRecord & /*record*/) {
    s_dhcp_stats.dual_ip_flagged++;
    snort::DetectionEngine::queue_event(dhcp_monitor_gid,
                                        dhcp_monitor_ip_conflict_sid);
  }

  void flag_dhcp_conflict(uint32_t /*ip*/, uint32_t /*new_mask*/,
                          DHCPRecord & /*record*/) {
    s_dhcp_stats.dhcp_flagged++;
    snort::DetectionEngine::queue_event(dhcp_monitor_gid,
                                        dhcp_monitor_dhcp_conflict_sid);
  }

  void flag_unknown_network(uint32_t /*ip*/, uint32_t /*network*/) {
    s_dhcp_stats.unknown_count++;
    snort::DetectionEngine::queue_event(dhcp_monitor_gid,
                                        dhcp_monitor_unknown_network_sid);
  }

  void flag_unknown_network(uint32_t /*ip1*/, uint32_t /*ip2*/,
                            uint32_t /*network*/) {
    s_dhcp_stats.unknown_count++;
    snort::DetectionEngine::queue_event(dhcp_monitor_gid,
                                        dhcp_monitor_unknown_network_sid);
  }

  void validate(uint16_t vlan_id, uint32_t ip) {
    std::shared_lock lock(network.mutex);

    auto record = network.map.find(vlan_id);

    if (record == network.map.end()) {
      flag_unknown_network(ip, vlan_id);
    } else {
      validate(ip, record->second);
    }
  }

  void validate(uint16_t vlan_id, uint32_t ip1, uint32_t ip2) {
    std::shared_lock lock(network.mutex);

    auto record = network.map.find(vlan_id);

    if (record == network.map.end()) {
      flag_unknown_network(ip1, ip2, vlan_id);
    } else {
      validate(ip1, ip2, record->second);
    }
  }

  void add_ip_mask(uint16_t vlan_id, uint32_t ip, uint32_t network_mask) {
    std::unique_lock lock(network.mutex);

    // Check if record exists
    auto record = network.map.find(vlan_id);

    if (record == network.map.end()) {
      network.map.emplace(
          std::make_pair(vlan_id, DHCPRecord(ip & network_mask, network_mask)));
    } else {
      if (record->second.get_network_mask() != network_mask ||
          !record->second.validate(ip)) {
        flag_dhcp_conflict(ip, network_mask, record->second);
        record->second.update(ip & network_mask, network_mask);
      }
    }
  }
};

class DHCPInfoEventHandler : public snort::DataHandler {
  DHCPMonitorInspector *inspector;

public:
  DHCPInfoEventHandler(DHCPMonitorInspector *inspector)
      : DataHandler("dhcp_monitor"), inspector(inspector) {
    assert(inspector);
  };

  void handle(snort::DataEvent &event, snort::Flow *) override {
    s_dhcp_stats.info_count++;

    snort::DHCPInfoEvent &dhcp_info_event =
        dynamic_cast<snort::DHCPInfoEvent &>(
            event); // NOTE: Will throw bad_cast exception if failing

    assert(event.get_packet());

    uint16_t vlan_id = event.get_packet()->get_flow_vlan_id();

    inspector->add_ip_mask(vlan_id, dhcp_info_event.get_ip_address(),
                           htonl(dhcp_info_event.get_subnet_mask()));
    inspector->validate(vlan_id, dhcp_info_event.get_router());
  }
};

class EventHandler : public snort::DataHandler {
  DHCPMonitorInspector *inspector;
  unsigned event_type;

public:
  EventHandler(DHCPMonitorInspector *inspector, unsigned event_type)
      : DataHandler("dhcp_monitor"), inspector(inspector),
        event_type(event_type) {
    assert(inspector);
  };

  void handle(snort::DataEvent &event, snort::Flow *) override {
    const snort::Packet *p = event.get_packet();

    // Bail if no packet, or packet don't have ip
    if (!p || !p->has_ip()) {
      s_dhcp_stats.no_ip_count++;
      return;
    }

    const snort::SfIp *src = p->ptrs.ip_api.get_src();
    const snort::SfIp *dst = p->ptrs.ip_api.get_dst();

    // Bail if src and dst aren't both IPv4
    if (!src || !src->is_ip4() || !dst || !dst->is_ip4()) {
      s_dhcp_stats.src_dst_ip_err_count++;
      return;
    }

    inspector->validate(p->get_flow_vlan_id(), src->get_ip4_value(),
                        dst->get_ip4_value());
  }
};

bool DHCPMonitorInspector::configure(snort::SnortConfig *) {
  snort::DataBus::subscribe_network(snort::appid_pub_key,
                                    snort::AppIdEventIds::DHCP_INFO,
                                    new DHCPInfoEventHandler(this));
  snort::DataBus::subscribe_network(
      snort::intrinsic_pub_key, snort::IntrinsicEventIds::FLOW_SERVICE_CHANGE,
      new EventHandler(this, snort::IntrinsicEventIds::FLOW_SERVICE_CHANGE));
  snort::DataBus::subscribe_network(
      snort::intrinsic_pub_key, snort::IntrinsicEventIds::FLOW_STATE_SETUP,
      new EventHandler(this, snort::IntrinsicEventIds::FLOW_STATE_SETUP));
  snort::DataBus::subscribe_network(
      snort::intrinsic_pub_key, snort::IntrinsicEventIds::FLOW_STATE_RELOADED,
      new EventHandler(this, snort::IntrinsicEventIds::FLOW_STATE_RELOADED));
  snort::DataBus::subscribe_network(
      snort::intrinsic_pub_key, snort::IntrinsicEventIds::PKT_WITHOUT_FLOW,
      new EventHandler(this, snort::IntrinsicEventIds::PKT_WITHOUT_FLOW));
  snort::DataBus::subscribe_network(
      snort::intrinsic_pub_key, snort::IntrinsicEventIds::FLOW_NO_SERVICE,
      new EventHandler(this, snort::IntrinsicEventIds::FLOW_NO_SERVICE));

  return true;
}

} // namespace

const snort::InspectApi dhcpmonitor_api = {
    {
        PT_INSPECTOR,
        sizeof(snort::InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "dhcp_monitor",
        "Monitors use of network addresses and DHCP requests",
        []() -> snort::Module * { return new DHCPMonitorModule; },
        [](snort::Module *m) { delete m; },
    },

    snort::IT_PASSIVE,
    PROTO_BIT__ALL,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    [](snort::Module *module) -> snort::Inspector * {
      assert(module);
      return new DHCPMonitorInspector(
          dynamic_cast<DHCPMonitorModule *>(module));
    },
    [](snort::Inspector *p) { delete p; },
    nullptr, // ssn
    nullptr  // reset
};

} // namespace dhcp_monitor
