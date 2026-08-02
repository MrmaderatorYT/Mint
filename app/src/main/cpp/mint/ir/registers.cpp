#include "mint/ir/registers.h"

#include <cstdio>

namespace mint {
namespace {

std::string synthetic(u64 offset, u8 size) {
    char buffer[48];
    std::snprintf(buffer, sizeof(buffer), "r%llu.%u",
                  static_cast<unsigned long long>(offset), unsigned(size));
    return buffer;
}

std::string numbered(const char* prefix, unsigned index) {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "%s%u", prefix, index);
    return buffer;
}

std::string arm64Name(u64 offset, u8 size) {
    if (offset < arm64::kSp && offset % 8 == 0) {
        const unsigned index = unsigned(offset / 8);
        if (size == 8) return numbered("x", index);
        if (size == 4) return numbered("w", index);
        return synthetic(offset, size);
    }
    if (offset == arm64::kSp) return size == 4 ? "wsp" : "sp";
    if (offset == arm64::kPc) return "pc";
    if (offset == arm64::kFlagN) return "N";
    if (offset == arm64::kFlagZ) return "Z";
    if (offset == arm64::kFlagC) return "C";
    if (offset == arm64::kFlagV) return "V";
    if (offset == arm64::kFpsr) return "fpsr";

    if (offset >= arm64::kV0 && offset < arm64::kFpsr) {
        const u64 relative = offset - arm64::kV0;
        if (relative % 16 == 0) {
            const unsigned index = unsigned(relative / 16);
            switch (size) {
                case 16: return numbered("q", index);
                case 8: return numbered("d", index);
                case 4: return numbered("s", index);
                case 2: return numbered("h", index);
                case 1: return numbered("b", index);
                default: break;
            }
        }
    }
    return synthetic(offset, size);
}

constexpr const char* kGpr64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                                   "rsi", "rdi", "r8",  "r9",  "r10", "r11",
                                   "r12", "r13", "r14", "r15"};
constexpr const char* kGpr32[16] = {"eax",  "ecx",  "edx",  "ebx",  "esp",  "ebp",
                                    "esi",  "edi",  "r8d",  "r9d",  "r10d", "r11d",
                                    "r12d", "r13d", "r14d", "r15d"};
constexpr const char* kGpr16[16] = {"ax",   "cx",   "dx",   "bx",   "sp",   "bp",
                                    "si",   "di",   "r8w",  "r9w",  "r10w", "r11w",
                                    "r12w", "r13w", "r14w", "r15w"};
constexpr const char* kGpr8[16] = {"al",   "cl",   "dl",   "bl",   "spl",  "bpl",
                                   "sil",  "dil",  "r8b",  "r9b",  "r10b", "r11b",
                                   "r12b", "r13b", "r14b", "r15b"};

std::string x86Name(u64 offset, u8 size) {
    if (offset < x86::kRip) {
        const unsigned index = unsigned(offset / 8);
        const u64 within = offset % 8;
        if (within == 0) {
            switch (size) {
                case 8: return kGpr64[index];
                case 4: return kGpr32[index];
                case 2: return kGpr16[index];
                case 1: return kGpr8[index];
                default: break;
            }
        }
        // ah, ch, dh, bh — the legacy high-byte registers, which are the reason
        // this file is addressed by byte offset in the first place.
        if (within == 1 && size == 1 && index < 4) {
            static constexpr const char* kHigh[4] = {"ah", "ch", "dh", "bh"};
            return kHigh[index];
        }
        return synthetic(offset, size);
    }
    if (offset == x86::kRip) return "rip";
    if (offset == x86::kFlagCf) return "CF";
    if (offset == x86::kFlagPf) return "PF";
    if (offset == x86::kFlagAf) return "AF";
    if (offset == x86::kFlagZf) return "ZF";
    if (offset == x86::kFlagSf) return "SF";
    if (offset == x86::kFlagDf) return "DF";
    if (offset == x86::kFlagOf) return "OF";
    if (offset == x86::kFsBase) return "fs_base";
    if (offset == x86::kGsBase) return "gs_base";

    if (offset >= x86::kXmm0 && offset < x86::kFileSize) {
        const u64 relative = offset - x86::kXmm0;
        if (relative % 16 == 0) {
            const unsigned index = unsigned(relative / 16);
            switch (size) {
                case 16: return numbered("xmm", index);
                case 8: return numbered("xmm", index) + ".q0";
                case 4: return numbered("xmm", index) + ".d0";
                default: break;
            }
        }
    }
    return synthetic(offset, size);
}

}  // namespace

u64 registerFileSize(Arch arch) {
    switch (arch) {
        case Arch::kAArch64: return arm64::kFileSize;
        case Arch::kX86_64: return x86::kFileSize;
        case Arch::kDalvik: return 4096;
        default: return 0;
    }
}

std::string registerName(Arch arch, u64 offset, u8 size) {
    switch (arch) {
        case Arch::kAArch64: return arm64Name(offset, size);
        case Arch::kX86_64: return x86Name(offset, size);
        default: return synthetic(offset, size);
    }
}

}  // namespace mint
