#include "mint/detectors/antitamper_detector.h"

#include <cctype>
#include <cstring>

namespace mint {
namespace {

bool contains(const std::string& haystack, const char* needle) { return haystack.find(needle) != std::string::npos; }

/// Whether `name` refers to the `su` binary, rather than merely containing those two
/// letters.
///
/// A substring test flagged `checksum` as a root check, and would equally flag
/// `result`, `issue`, `consume` and `measure`. Two letters carry no signal on their
/// own — what carries it is `su` standing alone as a name or as a path component.
bool mentionsSuBinary(const std::string& name) {
    size_t at = name.find("su");
    while (at != std::string::npos) {
        const bool startsToken = at == 0 || name[at - 1] == '/' || name[at - 1] == '_';
        const size_t after = at + 2;
        const bool endsToken = after == name.size() || name[after] == '/' ||
                               name[after] == '_' || name[after] == '.';
        if (startsToken && endsToken) return true;
        at = name.find("su", at + 1);
    }
    return false;
}

/// Whether `name` looks like a check for a rooted device, rather than any use of the
/// word "root".
///
/// A bare substring test reported `filesystem::path::__root_name`,
/// `__root_directory` and `__root_path_raw` as root checks — a path's root is not a
/// device's. The same trap catches tree and XML roots, `rootfs`, and `cbrt`.
///
/// So "root" has to stand as its own token *and* sit beside something that reads
/// like a test. Requiring both means an obfuscated checker named `r00t` is missed;
/// that is the right way to be wrong here, because a false finding in a security
/// report gets read as evidence.
bool mentionsRootCheck(const std::string& name) {
    std::string lower;
    lower.reserve(name.size());
    for (const char c : name) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Words that make the surrounding "root" structural rather than a privilege check.
    for (const char* innocent : {"path", "director", "_name", "element", "node",
                                 "tree", "rootfs", "_dir"}) {
        if (lower.find(innocent) != std::string::npos) return false;
    }

    size_t at = lower.find("root");
    bool token = false;
    while (at != std::string::npos) {
        const bool startsToken =
            at == 0 || !std::isalpha(static_cast<unsigned char>(lower[at - 1]));
        const size_t after = at + 4;
        // "rooted" counts: the participle is what a checker gets named after.
        const bool endsToken =
            after == lower.size() ||
            !std::isalpha(static_cast<unsigned char>(lower[after])) ||
            lower.compare(after, 2, "ed") == 0;
        if (startsToken && endsToken) { token = true; break; }
        at = lower.find("root", at + 1);
    }
    if (!token) return false;

    for (const char* verb : {"is", "has", "check", "detect", "test", "verify", "su",
                             "jail", "magisk", "busybox"}) {
        if (lower.find(verb) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

std::vector<DetectorFinding> detectAntiTamper(const ElfImage& image) {
    std::vector<DetectorFinding> result;
    for (const ElfSymbol& symbol : image.symbols()) {
        const std::string& n = symbol.name;
        if (contains(n, "ptrace") || contains(n, "procfs") || contains(n, "TracerPid") || contains(n, "debugger"))
            result.push_back({FindingKind::kAntiDebug, symbol.value, 91, n, "debugger or tracing check"});
        if (mentionsSuBinary(n) || mentionsRootCheck(n) || contains(n, "getprop") || contains(n, "system_property"))
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
