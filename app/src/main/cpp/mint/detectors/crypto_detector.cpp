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

    // Constants, not just names.
    //
    // Matching symbol names finds crypto only in a binary that still has symbols —
    // which is precisely the binary nobody needs help with. A packed or stripped
    // library keeps its tables, because the algorithm cannot run without them, so
    // the S-boxes and round constants are what actually survive.
    //
    // Each needle is the first eight bytes of a table as it sits in memory: byte
    // arrays literally, word arrays little-endian, which is the layout on both
    // architectures this engine targets. Eight bytes of a known constant is far past
    // coincidence, so a hit is reported at high confidence.
    struct Signature {
        const char* name;
        u8 bytes[8];
    };
    static const Signature kSignatures[] = {
        {"AES S-box",            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5}},
        {"AES inverse S-box",    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38}},
        {"AES Te0 table",        {0xa5, 0x63, 0x63, 0xc6, 0x84, 0x7c, 0x7c, 0xf8}},
        {"SHA-256 initial state",{0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb}},
        {"SHA-256 round table",  {0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71}},
        {"SHA-512 initial state",{0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a}},
        {"MD5 or SHA-1 state",   {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}},
        {"MD5 sine table",       {0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8}},
        {"CRC-32 table",         {0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77}},
        {"Blowfish P-array",     {0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85}},
        {"ChaCha/Salsa20 sigma", {'e', 'x', 'p', 'a', 'n', 'd', ' ', '3'}},
    };

    for (const MemorySegment& segment : image.memory().segments()) {
        // Constant tables live in data. A match inside code is a coincidence of
        // instruction encodings far more often than it is a table.
        if (segment.executable() || segment.data.size() < 8) continue;
        const u8* data = segment.data.data();
        const size_t size = segment.data.size();
        for (const Signature& signature : kSignatures) {
            for (size_t i = 0; i + 8 <= size; ++i) {
                if (std::memcmp(data + i, signature.bytes, 8) != 0) continue;
                result.push_back({FindingKind::kCrypto, segment.start + i, 97,
                                  signature.name, "cryptographic constant table"});
                break;  // One report per table per segment; the rest is the same table.
            }
        }
    }
    return result;
}

}  // namespace mint
