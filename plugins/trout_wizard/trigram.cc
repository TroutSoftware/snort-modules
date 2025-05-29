// Snort includes

// System includes

// Global includes

// Local includes
#include "trigram.h"

// Debug includes

namespace trout_wizard {
#ifdef ENABLE_INFERENCE

Negative_cache::Negative_cache() {
  ntgs_index.fill(0);
  ntgs.assign(SIZE, 0);
}

void Negative_cache::add(uint32_t tgm) {
  ntgs.push_back(tgm);
  ntgs_index[tgm] = ntgs.size() - 1;
}

bool Negative_cache::test(uint32_t tgm) {
  uint32_t i = ntgs_index[tgm];

  if (i < ntgs.size()) {
    return ntgs[i] == tgm ? true : false;
  }
  return false;
}
// Need to decide when we have reset the negative cache.
void Negative_cache::reset() { return ntgs.clear(); }
#endif
} // namespace trout_wizard