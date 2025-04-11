
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>

// System includes
#include <iostream>
#include <mutex>

// Local includes
#include "lioli.h"
#include "log_framework.h"
#include "logger_stdout.h"

// Debug includes
#include <perfetto.h>
PERFETTO_DEFINE_CATEGORIES(
perfetto::Category("trout_test").SetDescription("Sample trace"));

namespace logger_stdout {
namespace {

static const char *s_name = "logger_stdout";
static const char *s_help =
    "Outputs LioLi trees stdout, it only supports text output";

static const snort::Parameter module_params[] = {
    {"serializer", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Serializer to use for generating output"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// MAIN object of this file
class Logger : public LioLi::Logger {
  std::mutex mutex; // Protects members

  std::string serializer_name;

  std::shared_ptr<LioLi::Serializer::Context> context;

  LioLi::Serializer::Context &get_context() {
    if (!context) {
      auto serializer = LioLi::LogDB::get<LioLi::Serializer>(serializer_name);

      if (serializer->is_binary()) {
        snort::ErrorMessage(
            "ERROR: %s is binary, %s only support text based serializers\n",
            serializer_name.c_str(), s_name);

        // Default to the null serializer
        serializer = LioLi::Serializer::get_null_obj();
      }

      context = serializer->create_context();
    }

    return *context.get();
  }

public:
  Logger() : LioLi::Logger(s_name) {}

  ~Logger() {
    // We can't request a context here, as it isn't safe during shutdown
    if (context)
      std::cout << context->close();
  }

  void set_serializer(const char *name) {
    std::scoped_lock lock(mutex);

    assert(!context ||
           serializer_name == name); // If we have a context when a new name is
                                     // set, it is the wrong context

    serializer_name = name;
  }

  void operator<<(const LioLi::Tree &&tree) override {
    TRACE_EVENT("trout_test", "Serializing to stdout");
    std::scoped_lock lock(mutex);

    std::cout << get_context().serialize(std::move(tree));
  }
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    LioLi::LogDB::register_type<Logger>();
  }

  bool serializer_set = false;

  bool begin(const char *, int, snort::SnortConfig *) override {
    serializer_set = false;
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    if (!serializer_set) {
      snort::ErrorMessage("ERROR: no serializer specified for %s\n", s_name);
    }
    return serializer_set;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {
    if (val.is("serializer") && val.get_as_string().size() > 0) {

      LioLi::LogDB::get<Logger>(s_name)->set_serializer(val.get_string());

      serializer_set = true;

      return true;
    }

    // fail if we didn't get something valid
    return false;
  }

  Usage get_usage() const override {
    return GLOBAL;
  } // TODO(mkr): Figure out what the usage type means

public:
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

class Inspector : public snort::Inspector {
  void eval(snort::Packet *) override {};

public:
  static snort::Inspector *ctor(snort::Module *) { return new Inspector(); }
  static void dtor(snort::Inspector *p) { delete p; }
};

} // namespace

const snort::InspectApi inspect_api = {
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

    snort::IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    Inspector::ctor,
    Inspector::dtor,
    nullptr, // ssn
    nullptr  // reset
};

} // namespace logger_stdout
