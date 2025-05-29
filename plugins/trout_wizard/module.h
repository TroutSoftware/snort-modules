#ifndef module_1d34881e
#define module_1d34881e

// Snort includes
#include <framework/counts.h>
#include <framework/module.h>
// System includes
#include <iostream>

// Global includes
#include <log_framework.h>

#define ENABLE_INFERENCE
//  Local includes

namespace trout_wizard {

class Settings;

// This must match the s_pegs[] array
struct PegCounts {
  PegCount pkg_processed = 0;
  PegCount srv_detected = 0;
};

class Module : public snort::Module {
  std::shared_ptr<Settings> settings;

  Module();
  ~Module();

  bool begin(const char *, int, snort::SnortConfig *) override;
  bool end(const char *, int, snort::SnortConfig *) override;

  bool set(const char *, snort::Value &val, snort::SnortConfig *) override;

  Usage get_usage() const override;

  const PegInfo *get_pegs() const override;

  PegCount *get_counts() const override;

  bool is_bindable() const override;

public:
  std::shared_ptr<Settings> get_settings();
  PegCounts &get_peg_counts();
  static snort::Module *ctor() { return new Module(); }
  static void dtor(snort::Module *p) { delete p; }
};

} // namespace trout_wizard

#endif // #ifndef module_1d34881e
