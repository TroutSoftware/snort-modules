#include "trigram_dataset.h"

// fetching the (protocol and tgm list) string from the dataset
int main() {
  std::unordered_map<std::string, std::vector<uint32_t>> dataset;

  // Group tgms under each protocol
  for (const auto &[proto, tgm] : trigram) {
    dataset[proto].push_back(tgm);
  }

  std::ostringstream ops;

  ops << "{\n";
  for (auto &[proto, vec] : dataset) {
    ops << "{" << "protocol =" << "\"" << proto << "\"" << ",\n"
        << "tgm_set = " << "\"";
    for (size_t i = 0; i < vec.size(); ++i) {
      ops << std::hex << vec[i];
      if (i != vec.size() - 1)
        ops << ",";
    }
    ops << "\"" << "},\n";
  }
  ops << "}";

  std::cout << ops.str();

  return 0;
}
