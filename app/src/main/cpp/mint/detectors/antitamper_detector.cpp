#include "mint/detectors/antitamper_detector.h"

#include <cstring>

namespace mint {
namespace {

bool contains(const std::string& haystack, const char* needle) { return haystack.find(needle) != std::string::npos; }

}  // namespace

std::vector<DetectorFinding> detectAntiTamper(const ElfImage& image) {
    std::vector<DetectorFinding> result;
    for (const ElfSymbol& symbol : image.symbols()) {
        const std::string& n = symbol.name;
        if (contains(n, "ptrace") || contains(n, "procfs") || contains(n, "TracerPid") || contains(n, "debugger"))
            result.push_back({FindingKind::kAntiDebug, symbol.value, 91, n, "debugger or tracing check"});
        if (contains(n, "su") || contains(n, "root") || contains(n, "getprop") || contains(n, "system_property"))
            result.push_back({FindingKind::kAntiRoot, symbol.value, 72, n, "root or privileged-environment check"});
    }
    for (const MemorySegment& segment : image.memory().segments()) {
        if (segment.data.empty()) continue;
        const char* data = reinterpret_cast<const char*>(segment.data.data());
        const size_t size = segment.data.size();
        const char* needles[] = {"/system/xbin/su", "/system/bin/su", "TracerPid", "ro.debuggable", "test-keys"};
        for (const char* needle : needles) {
            const size_t length = std::strlen(needle);
            for (size_t i = 0; i + length <= size; ++i) if (std::memcmp(data + i, needle, length) == 0) {
                result.push_back({contains(needle, "Tracer") ? FindingKind::kAntiDebug : FindingKind::kAntiRoot,
                                  segment.start + i, 88, needle, "suspicious runtime string"});
                break;
            }
        }
    }
    return result;
}

}  // namespace mint
