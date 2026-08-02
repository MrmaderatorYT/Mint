#include "mint/detectors/crypto_detector.h"

#include <algorithm>

namespace mint {

std::vector<DetectorFinding> detectCrypto(const ElfImage& image) {
    std::vector<DetectorFinding> result;
    for (const ElfSymbol& symbol : image.symbols()) {
        if (symbol.name.empty()) continue;
        const std::string& n = symbol.name;
        const bool crypto = n.find("EVP_") == 0 || n.find("AES_") == 0 || n.find("RSA_") == 0 ||
            n.find("SHA") != std::string::npos || n.find("sodium") != std::string::npos ||
            n.find("ChaCha") != std::string::npos || n.find("HMAC") != std::string::npos;
        if (crypto) result.push_back({FindingKind::kCrypto, symbol.value, 94, n, "known cryptographic API or primitive"});
    }
    return result;
}

}  // namespace mint
