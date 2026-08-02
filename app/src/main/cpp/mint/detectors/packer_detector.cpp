#include "mint/detectors/packer_detector.h"

#include <cstring>

namespace mint {

std::vector<DetectorFinding> detectPackers(const ElfImage& image) {
    std::vector<DetectorFinding> result;
    for (const ElfSection& section : image.sections()) {
        if (section.name.find("UPX") != std::string::npos || section.name.find("packed") != std::string::npos ||
            section.name.find("protect") != std::string::npos) {
            result.push_back({FindingKind::kPacker, section.addr, 90, section.name, "packer-like section name"});
        }
    }
    for (const MemorySegment& segment : image.memory().segments()) {
        if (segment.data.size() < 4) continue;
        const u8* p = segment.data.data();
        for (size_t i = 0; i + 4 <= segment.data.size(); ++i) {
            if (std::memcmp(p + i, "UPX!", 4) == 0) {
                result.push_back({FindingKind::kPacker, segment.start + i, 99, "UPX!", "UPX signature"});
                break;
            }
        }
    }
    return result;
}

}  // namespace mint
