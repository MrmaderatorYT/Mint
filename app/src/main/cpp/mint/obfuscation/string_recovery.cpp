#include "mint/obfuscation/string_recovery.h"

#include <algorithm>

namespace mint {

RecoveredString decodeXorString(const std::vector<u8>& encoded, u8 key) {
    RecoveredString result;
    result.key = key;
    for (u8 byte : encoded) {
        const u8 decoded = byte ^ key;
        if (decoded == 0) break;
        result.text.push_back(static_cast<char>(decoded));
        if ((decoded >= 0x20 && decoded < 0x7f) || decoded == '\n' || decoded == '\t') ++result.score;
    }
    return result;
}

std::vector<RecoveredString> recoverXorStrings(const std::vector<u8>& bytes, size_t minLength, size_t maxCandidates) {
    std::vector<RecoveredString> result;
    for (u8 key = 1; key != 0; ++key) {
        for (size_t start = 0; start < bytes.size() && result.size() < maxCandidates; ++start) {
            std::vector<u8> encoded;
            for (size_t i = start; i < bytes.size() && i < start + 256; ++i) {
                encoded.push_back(bytes[i]);
                if ((bytes[i] ^ key) == 0) break;
            }
            if (encoded.size() < minLength || (encoded.back() ^ key) != 0) continue;
            RecoveredString candidate = decodeXorString(encoded, key);
            if (candidate.text.size() >= minLength && candidate.score * 100 >= candidate.text.size() * 70) result.push_back(std::move(candidate));
        }
    }
    std::sort(result.begin(), result.end(), [](const RecoveredString& a, const RecoveredString& b) { return a.score > b.score; });
    return result;
}

}  // namespace mint
