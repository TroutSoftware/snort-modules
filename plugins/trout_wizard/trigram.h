#ifndef trigram_d22993dd
#define trigram_d22993dd

// Snort includes
#include <framework/value.h>

// System includes

// Global includes

// Local includes
#include "module.h"
// Debug includes

namespace trout_wizard {
constexpr int SIZE = 1 << 24;
class Negative_cache {
  std::array<int, SIZE> ntgs_index;
  std::vector<uint32_t> ntgs;

public:
  Negative_cache();
  void add(uint32_t);
  bool test(uint32_t);
  void reset();
};
} // namespace trout_wizard
#endif // trigram_d22993dd