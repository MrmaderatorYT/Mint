#pragma once

#include <string>
#include <vector>

#include "mint/base/types.h"

namespace mint {

struct RecoveredString {
    std::string text;
    u8 key = 0;
    u32 score = 0;
};

RecoveredString decodeXorString(const std::vector<u8>& encoded, u8 key);
std::vector<RecoveredString> recoverXorStrings(const std::vector<u8>& bytes,
                                               size_t minLength = 4,
                                               size_t maxCandidates = 128);

}  // namespace mint
