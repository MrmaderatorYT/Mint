#include "mint/detectors/detector.h"

#include <algorithm>

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

    // Deduplicated here rather than in each detector, because the cause is shared:
    // a symbol present in both .symtab and .dynsym is walked twice, so every finding
    // keyed on a symbol name came out doubled. Two identical lines read as two
    // findings, which overstates what was found.
    std::sort(result.begin(), result.end(),
              [](const DetectorFinding& a, const DetectorFinding& b) {
                  if (a.address != b.address) return a.address < b.address;
                  if (a.kind != b.kind) return a.kind < b.kind;
                  return a.detail < b.detail;
              });
    result.erase(std::unique(result.begin(), result.end(),
                             [](const DetectorFinding& a, const DetectorFinding& b) {
                                 return a.address == b.address && a.kind == b.kind &&
                                        a.detail == b.detail;
                             }),
                 result.end());
    return result;
}

}  // namespace mint
