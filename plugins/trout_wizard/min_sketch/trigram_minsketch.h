
#ifndef MIN_SKETCH_H
#define MIN_SKETCH_H

#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <limits>
#include <unordered_map>

struct TrigramSet
{
  std::string protocol;
  std::string tgs;
};

extern std::vector<TrigramSet> trigram;

#endif