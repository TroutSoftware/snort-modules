
#ifndef TRIGRAM_DATASET_H
#define TRIGRAM_DATASET_H

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

struct TrigramSet {
  std::string protocol;
  std::uint32_t tgs;
};

extern std::vector<TrigramSet> trigram;

#endif // TRIGRAM_DATASET_H