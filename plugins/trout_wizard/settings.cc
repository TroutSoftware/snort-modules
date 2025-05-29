// Snort includes

// System includes

// Global includes

// Local includes
#include "settings.h"

// Debug includes

namespace trout_wizard {
Settings::Settings(const char *module_name, PegCounts &pegs)
    : pegs(pegs), module_name(module_name) {}

bool Settings::begin(const char *s, int) {
  if (module_name == s)
    // Check if this is a fresh load of settings
    if (module_name == s) {
      reset();
      return true;
    }

  // Processing the data_set
  if (module_name + ".data_set" == s) {
    if (current_item) {
      if (zero_item) {
        snort::ErrorMessage("ERROR: Internal parsing error on %s", s);
        return false;
      }
      current_item.swap(zero_item);
    }
    current_item.reset(new Dataset);
    return true;
  }

  // We got something in that we don't know how to handle
  return false;
}

bool Settings::end(const char *s) {
  if (module_name == s) {
    // TODO: Validate settings
    return true;
  }

  if (module_name + ".data_set" == s) {
    if (!current_item) {
      snort::ErrorMessage(
          "ERROR: Internal parsing error on %s, end with no beginning\n", s);
      return false;
    }

    data_set.emplace_back(current_item.release());
    current_item.swap(zero_item);
    return true;
  }

  return false;
}

LioLi::Logger &Settings::get_logger() {
  if (!logger) {
    logger = LioLi::LogDB::get<LioLi::Logger>(logger_name.c_str());
  }
  return *logger;
}

std::unordered_set<uint32_t> stringToSet(const std::string &input) {
  std::unordered_set<uint32_t> result;
  std::stringstream ss(input);
  std::string token;

  while (std::getline(ss, token, ',')) {
    if (!token.empty()) {
      result.insert(static_cast<uint32_t>(std::stoul(token, nullptr, 16)));
    }
  }

  return result;
}

bool Settings::set(const char *, snort::Value &val) {
  if (val.is("logger") && val.get_as_string().size() > 0) {
    logger_name = val.get_string();
  } else if (val.is("inference")) {
    inference = val.get_bool();
  } else if (val.is("protocol")) {
    assert(current_item);
    current_item->protocol = val.get_string();
  } else if (val.is("tgm_set")) {
    assert(current_item);
    current_item->tgm_set = stringToSet(val.get_string());
  } else if (val.is("concatenate")) {
    concatenate = val.get_bool();
  } else if (val.is("pack_data")) {
    pack_data = val.get_bool();
  } else if (val.is("split_size")) {
    split_size = val.get_uint32();
  } else if (val.is("tag") && val.get_as_string().size() > 0) {
    tag = val.get_string();
  } else {
    // fail if we didn't get something valid
    return false;
  }

  return true;
}

void Settings::reset() {
  // NOTE: Some values have their defaults from the module_params in module.cc
  data_set.clear();
  zero_item.reset();
  current_item.reset();
}

} // namespace trout_wizard
