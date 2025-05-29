#ifndef settings_d22993cc
#define settings_d22993cc

// Snort includes
#include <framework/value.h>

// System includes
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>

// Global includes
#include <log_framework.h>
// Local includes
#include "module.h"
// Debug includes

namespace trout_wizard {

class Module;

struct Settings : std::enable_shared_from_this<Settings> {
  PegCounts &pegs;
  Settings(const char *module_name, PegCounts &pegs);

  // Settings for all map entries
  std::shared_ptr<LioLi::Logger> logger;

public:
  std::string logger_name;
  bool inference = false;
  bool concatenate = false;
  bool pack_data = false;
  uint32_t split_size = 253;
  std::string tag;

  LioLi::Logger &get_logger();

  struct Dataset {
    std::string protocol;
    std::unordered_set<uint32_t> tgm_set;
  };

  std::list<std::unique_ptr<Dataset>>
      data_set; // This might be made more inteligent at a later time

private:
  friend Module;

  std::string module_name;

  bool begin(const char *, int);
  bool end(const char *);
  bool set(const char *, snort::Value &val);

  std::unique_ptr<Dataset> zero_item;
  std::unique_ptr<Dataset> current_item;

  void reset(); // Clears all settings to default values
};
} // namespace trout_wizard

#endif // #ifndef settings_d22993cc
