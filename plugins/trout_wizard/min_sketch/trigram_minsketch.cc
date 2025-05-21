#include "trigram_minsketch.h"

using namespace std;

//********* Trigram Minsketch Class ******/
class Trigram_MinSketch
{
private:
  int width, depth;
  std::vector<std::vector<int>> table;

  uint32_t hashFun(uint32_t tgm, int level)
  {
    uint32_t x = tgm;

    // form Level + tgm --> 1tgm,2tgm...
    x = (level & 0xff) << 24 | (tgm & 0xffffff);

    // hashing technique
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
  }

public:
  Trigram_MinSketch(int width, int depth) : width(width), depth(depth)
  {
    table = std::vector<std::vector<int>>(depth, std::vector<int>(width, 0));
  }

  void add(const uint32_t &item, int count = 1)
  {
    for (int i = 0; i < depth; ++i)
    {
      size_t hash = hashFun(item, i);
      int index = hash % width;

      table[i][index] += count;
    }
  }
  // validating the value stored, can be removed
  int test(const uint32_t &item)
  {
    int min_count = std::numeric_limits<int>::max();
    for (int i = 0; i < depth; ++i)
    {
      size_t hash = hashFun(item, i);
      int index = hash % width;
      min_count = std::min(min_count, table[i][index]);
    }
    return min_count;
  }

  // hashmap table
  std::vector<std::vector<int>> get_minskech()
  {
    return table;
  }
};

// Converting the dataset into misketch based on trigram data
int main()
{
  std::unordered_map<std::string, std::vector<uint32_t>> dataset;
  std::unordered_map<std::string, std::vector<std::vector<int>>> minsketch;

  // Group tgms under each protocol
  for (const auto &[proto, tgm] : trigram)
  {
    uint32_t t = static_cast<uint32_t>(std::stoul(tgm, nullptr, 16));
    dataset[proto].push_back(t);
  }
  // Form the trigram minsketch for each protocol
  for (const auto &[proto, tgms] : dataset)
  {
    Trigram_MinSketch cms(32, 6);
    for (const auto &t : tgms)
    {
      cms.add(t);
    }
    minsketch[proto] = cms.get_minskech();
  }

  // for printing, can be removed
  for (auto &[proto, tgms] : minsketch)
  {
    std::cout << "protocol - " << proto << std::endl;
    for (const auto &row : tgms)
    {
      for (int val : row)
        std::cout << val << " ";
      std::cout << "\n";
    }
  }

  return 0;
}
