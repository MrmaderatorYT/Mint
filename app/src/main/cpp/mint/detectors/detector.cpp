#include "mint/detectors/detector.h"

#include "mint/detectors/antitamper_detector.h"
#include "mint/detectors/crypto_detector.h"
#include "mint/detectors/packer_detector.h"

namespace mint {

const char* findingKindName(FindingKind kind) {
    switch (kind) {
        case FindingKind::kCrypto: return "crypto";
        case FindingKind::kAntiDebug: return "anti-debug";
        case FindingKind::kAntiRoot: return "anti-root";
        case FindingKind::kVirtualization: return "virtualization";
        case FindingKind::kPacker: return "packer";
    }
    return "unknown";
}

std::vector<DetectorFinding> runDetectors(const ElfImage& image) {
    std::vector<DetectorFinding> result = detectCrypto(image);
    std::vector<DetectorFinding> anti = detectAntiTamper(image);
    result.insert(result.end(), anti.begin(), anti.end());
    std::vector<DetectorFinding> packers = detectPackers(image);
    result.insert(result.end(), packers.begin(), packers.end());
    return result;
}

}  // namespace mint
