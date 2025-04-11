//
// This file contains the exported list of plugins from this module
//

// Snort includes
#include <framework/inspector.h>

// System includes

// Local includes
#include "alert_lioli/alert_lioli.h"
#include "alert_lioli/ips_lioli_bind.h"
#include "alert_lioli/ips_lioli_tag.h"
#include "dhcp_monitor/inspector.h"
#include "dhcp_option/inspector.h"
#include "dhcp_option/ips_option.h"
#include "dhcp_option/ips_option_ip_filter.h"
#include "log/logger_file.h"
#include "log/logger_null.h"
#include "log/logger_pipe.h"
#include "log/logger_stdout.h"
#include "log/serializer_bill.h"
#include "log/serializer_csv.h"
#include "log/serializer_lorth.h"
#include "log/serializer_python.h"
#include "log/serializer_txt.h"
#include "smnp/inspector.h"
#include "trout_netflow/trout_netflow.h"
#include "trout_wizard/plugin_def.h"

#include <perfetto.h>
PERFETTO_DEFINE_CATEGORIES(
  perfetto::Category("trout_test").SetDescription("Testing Perfetto"),
  perfetto::Category("trout_exclude").SetDescription("Timing Perfetto"));

PERFETTO_TRACK_EVENT_STATIC_STORAGE();

class Perfetto_Tracer {
  perfetto::TracingInitArgs args;
public:
  Perfetto_Tracer() {
    args.backends |= perfetto::kInProcessBackend;
    args.backends |= perfetto::kSystemBackend;
    perfetto::Tracing::Initialize(args);

    perfetto::TrackEvent::Register();

    //TRACE_EVENT("trout_test", "In constructor");
  }
  
  
} p_tracer;


// clang-format off
SO_PUBLIC const snort::BaseApi *snort_plugins[] = {
  &alert_lioli::log_api.base,
  &dhcp_monitor::dhcpmonitor_api.base,
  &dhcp_option::inspector.base,
  &dhcp_option::ips_option.base,
  &ip_filter::ips_option.base,
  &ips_lioli_bind::ips_option.base,
  &ips_lioli_tag::ips_option.base,
  &logger_file::inspect_api.base,
  &logger_null::inspect_api.base,
  &logger_pipe::inspect_api.base,
  &logger_stdout::inspect_api.base,
  &serializer_bill::inspect_api.base,
  &serializer_csv::inspect_api.base,
  &serializer_lorth::inspect_api.base,
  &serializer_python::inspect_api.base,
  &serializer_txt::inspect_api.base,
  &smnp::inspect_api.base,
  &trout_netflow::inspect_api.base,
  &trout_wizard::inspect_api.base,
  
  nullptr
};
// clang-format on
