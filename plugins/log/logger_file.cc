
// Snort includes
#include <framework/decode_data.h>
#include <framework/inspector.h>
#include <framework/module.h>
#include <log/messages.h>

// System includes
#include <fstream>
#include <iostream>
#include <mutex>

// Local includes
#include "lioli.h"
#include "log_framework.h"
#include "logger_file.h"

// Debug includes
#include <perfetto.h>
PERFETTO_DEFINE_CATEGORIES(
perfetto::Category("trout_test").SetDescription("Sample trace"));


namespace logger_file {
namespace {

static const char *s_name = "logger_file";
static const char *s_help =
    "Outputs LioLi trees stdout, it only supports text output";

static const snort::Parameter module_params[] = {
    {"file_name", snort::Parameter::PT_STRING, nullptr, nullptr,
     "File name logs should be written to"},
    {"file_env", snort::Parameter::PT_STRING, nullptr, nullptr,
     "File name will be read from environment variable"},
    {"serializer", snort::Parameter::PT_STRING, nullptr, nullptr,
     "Serializer to use for generating output"},
    {nullptr, snort::Parameter::PT_MAX, nullptr, nullptr, nullptr}};

// MAIN object of this file
class Logger : public LioLi::Logger {
  std::mutex mutex; // Protects members

  std::string serializer_name;
  std::string file_name;

  std::shared_ptr<LioLi::Serializer::Context> context;
  std::ofstream ofile;

  LioLi::Serializer::Context &get_context() {
    if (!context) {
      auto serializer = LioLi::LogDB::get<LioLi::Serializer>(serializer_name);

      context = serializer->create_context();
    }

    return *context.get();
  }

  std::ofstream &get_ofile() {
    if (!ofile.is_open()) {
      std::ios_base::openmode open_mode = std::ios_base::out;

      auto serializer = LioLi::LogDB::get<LioLi::Serializer>(serializer_name);

      if (serializer->is_binary()) {
        open_mode |= std::ios_base::binary;
      }

      ofile.open(file_name, open_mode);

      if (!ofile.good()) {
        snort::ErrorMessage("ERROR: Could not open output file %s\n",
                            serializer_name.c_str());
      }
    }
    return ofile;
  }

public:
  Logger() : LioLi::Logger(s_name) {}

  ~Logger() {
    // We can't request a context here, as it isn't safe during shutdown
    if (context)
      get_ofile() << context->close();
  }

  void set_serializer(const char *name) {
    std::scoped_lock lock(mutex);

    assert(!context ||
           serializer_name == name); // If we have a context when a new name is
                                     // set, it is the wrong context

    serializer_name = name;
  }

  // Returns true if filename is ok
  bool set_file_name(std::string name) {
    std::scoped_lock lock(mutex);

    file_name = name;
    return true;
  }

  void operator<<(const LioLi::Tree &&tree) override {
		TRACE_EVENT("trout_test", "Serializing to file", "tree conten", tree.as_string().c_str());
		//TRACE_EVENT("trout_test", "Serializing to file");
    std::scoped_lock lock(mutex);

    get_ofile() << get_context().serialize(std::move(tree));
  }
};

class Module : public snort::Module {
  Module() : snort::Module(s_name, s_help, module_params) {
    LioLi::LogDB::register_type<Logger>();
  }

  bool file_name_set = false;
  bool serializer_set = false;

  bool begin(const char *, int, snort::SnortConfig *) override {
    file_name_set = false;
    serializer_set = false;
    return true;
  }

  bool end(const char *, int, snort::SnortConfig *) override {
    if (!file_name_set) {
      snort::ErrorMessage("ERROR: no file_name specified for %s\n", s_name);
    }
    if (!serializer_set) {
      snort::ErrorMessage("ERROR: serializer not specified for %s\n", s_name);
    }
    return file_name_set && serializer_set;
  }

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override {

    auto logger = LioLi::LogDB::get<Logger>(s_name);
    assert(logger); // Something went very wrong, if we can't find our self

    if (val.is("serializer") && val.get_as_string().size() > 0) {
      logger->set_serializer(val.get_string());
      serializer_set = true;

      return true;
    } else if (val.is("file_name") && val.get_as_string().size() > 0) {
      if (file_name_set) {
        snort::ErrorMessage("ERROR: You can only set name/env once in %s\n",
                            s_name);
        return false;
      }

      file_name_set = logger->set_file_name(val.get_string());

      return true;
    } else if (val.is("file_env")) {
      std::string env_name = val.get_as_string();
      const char *name = std::getenv(env_name.c_str());

      if (name && *name) {
        if (file_name_set) {
          snort::ErrorMessage("ERROR: You can only set name/env once in %s\n",
                              s_name);
          return false;
        }

        logger->set_file_name(name);
        file_name_set = true;

        return true;
      }

      snort::ErrorMessage(
          "ERROR: Could not read log file name from environment: %s in %s\n",
          env_name.c_str(), s_name);
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

} // namespace logger_file
