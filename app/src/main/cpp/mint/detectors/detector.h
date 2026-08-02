#pragma once

#include <string>
#include <vector>

#include "mint/base/types.h"
#include "mint/loader/elf_image.h"

namespace mint {

enum class FindingKind : u8 { kCrypto, kAntiDebug, kAntiRoot, kVirtualization, kPacker };

struct DetectorFinding {
    FindingKind kind = FindingKind::kCrypto;
    Address address = 0;
    u8 confidence = 0;
    std::string name;
    std::string detail;
};

std::vector<DetectorFinding> runDetectors(const ElfImage& image);
const char* findingKindName(FindingKind kind);

}  // namespace mint
