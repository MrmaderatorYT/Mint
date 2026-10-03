#include "mint/base/sha256.h"
#include <array>
#include <cstring>

namespace mint {
namespace {
constexpr u32 constants[] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
u32 rotate(u32 value, unsigned bits) { return (value >> bits) | (value << (32 - bits)); }
void block(const u8* bytes, std::array<u32, 8>* state) {
    u32 words[64] = {};
    for (size_t i = 0; i < 16; ++i) for (size_t b = 0; b < 4; ++b) words[i] = (words[i] << 8) | bytes[i * 4 + b];
    for (size_t i = 16; i < 64; ++i) {
        const u32 a = rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3);
        const u32 b = rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10);
        words[i] = words[i - 16] + a + words[i - 7] + b;
    }
    auto work = *state;
    for (size_t i = 0; i < 64; ++i) {
        const u32 s1 = rotate(work[4], 6) ^ rotate(work[4], 11) ^ rotate(work[4], 25);
        const u32 choose = (work[4] & work[5]) ^ (~work[4] & work[6]);
        const u32 first = work[7] + s1 + choose + constants[i] + words[i];
        const u32 s0 = rotate(work[0], 2) ^ rotate(work[0], 13) ^ rotate(work[0], 22);
        const u32 majority = (work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2]);
        for (size_t j = 7; j > 0; --j) work[j] = work[j - 1];
        work[4] += first; work[0] = first + s0 + majority;
    }
    for (size_t i = 0; i < 8; ++i) (*state)[i] += work[i];
}
}
std::string sha256(ByteView bytes) {
    std::array<u32, 8> state{{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}};
    size_t offset = 0;
    while (bytes.size() - offset >= 64) { block(bytes.data() + offset, &state); offset += 64; }
    u8 tail[128] = {}; const size_t count = bytes.size() - offset;
    if (count) std::memcpy(tail, bytes.data() + offset, count); tail[count] = 0x80;
    const size_t end = count >= 56 ? 128 : 64; const u64 bits = static_cast<u64>(bytes.size()) * 8;
    for (size_t i = 0; i < 8; ++i) tail[end - 1 - i] = static_cast<u8>(bits >> (i * 8));
    block(tail, &state); if (end == 128) block(tail + 64, &state);
    static constexpr char hex[] = "0123456789abcdef";
    std::string result; result.reserve(64);
    for (u32 word : state) for (int shift = 28; shift >= 0; shift -= 4) result.push_back(hex[(word >> shift) & 15]);
    return result;
}
}
