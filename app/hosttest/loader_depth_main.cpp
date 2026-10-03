#include "mint/analysis/exception_metadata.h"
#include "mint/loader/elf_image.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {
using namespace mint;
size_t checks = 0;
void require(bool value, const char* description) {
    ++checks;
    if (!value) { std::cerr << "loader depth: " << description << '\n'; std::exit(1); }
}
template <typename T> void put(std::vector<u8>& bytes, size_t at, T value) {
    require(at <= bytes.size() && sizeof(T) <= bytes.size() - at, "fixture write bounds");
    std::memcpy(bytes.data() + at, &value, sizeof(T));
}
void text(std::vector<u8>& bytes, size_t at, const std::string& value) {
    require(at <= bytes.size() && value.size() + 1 <= bytes.size() - at, "fixture string bounds");
    std::memcpy(bytes.data() + at, value.c_str(), value.size() + 1);
}
ByteView view(const std::vector<u8>& bytes) { return ByteView(bytes.data(), bytes.size()); }
bool warning(const ElfImage& image, const std::string& needle) {
    return std::any_of(image.warnings().begin(), image.warnings().end(), [&](const auto& message) { return message.find(needle) != std::string::npos; });
}
constexpr Address machBase = 0x100000000;
constexpr Address peBase = 0x140000000;

std::vector<u8> mach(bool chained) {
    std::vector<u8> bytes(0x1400);
    put<u32>(bytes, 0, 0xfeedfacf); put<u32>(bytes, 4, 0x0100000c);
    put<u32>(bytes, 8, 2); put<u32>(bytes, 12, 2); put<u32>(bytes, 16, 4);
    put<u32>(bytes, 20, 424); put<u32>(bytes, 24, 0x200000);
    size_t at = 32;
    put<u32>(bytes, at, 0x19); put<u32>(bytes, at + 4, 312); text(bytes, at + 8, "__TEXT");
    put<u64>(bytes, at + 24, machBase); put<u64>(bytes, at + 32, 0x1000);
    put<u64>(bytes, at + 48, 0x1000); put<u32>(bytes, at + 56, 5); put<u32>(bytes, at + 60, 5); put<u32>(bytes, at + 64, 3);
    const auto section = [&](size_t index, const std::string& name, u32 offset, u32 size, u32 flags) {
        const size_t record = at + 72 + index * 80;
        text(bytes, record, name); text(bytes, record + 16, "__TEXT");
        put<u64>(bytes, record + 32, machBase + offset); put<u64>(bytes, record + 40, size);
        put<u32>(bytes, record + 48, offset); put<u32>(bytes, record + 64, flags);
    };
    section(0, "__text", 0x600, 0x80, 0x80000400);
    section(1, "__unwind_info", 0x800, 0x100, 0);
    section(2, "__gcc_except_tab", 0xa00, 0x40, 0);
    at += 312;
    put<u32>(bytes, at, 0x19); put<u32>(bytes, at + 4, 72); text(bytes, at + 8, "__LINKEDIT");
    put<u64>(bytes, at + 24, machBase + 0x2000); put<u64>(bytes, at + 32, 0x400);
    put<u64>(bytes, at + 40, 0x1000); put<u64>(bytes, at + 48, 0x400);
    put<u32>(bytes, at + 56, 1); put<u32>(bytes, at + 60, 1);
    at += 72;
    put<u32>(bytes, at, 0x80000028); put<u32>(bytes, at + 4, 24); put<u64>(bytes, at + 8, 0x600);
    at += 24;
    put<u32>(bytes, at, 0x80000034); put<u32>(bytes, at + 4, 16);
    put<u32>(bytes, at + 8, chained ? 0x1100 : 0); put<u32>(bytes, at + 12, chained ? 76 : 0);
    for (size_t code : {size_t{0x600}, size_t{0x620}, size_t{0x640}}) put<u32>(bytes, code, 0xd65f03c0);

    // Two-level regular compact-unwind page: one exact function, personality
    // index 1, a separate LSDA index and a mandatory terminal index entry.
    put<u32>(bytes, 0x800, 1); put<u32>(bytes, 0x804, 28); put<u32>(bytes, 0x808, 1);
    put<u32>(bytes, 0x80c, 32); put<u32>(bytes, 0x810, 1);
    put<u32>(bytes, 0x814, 36); put<u32>(bytes, 0x818, 2); put<u32>(bytes, 0x81c, 0x52000000);
    put<u32>(bytes, 0x820, 0x620);
    put<u32>(bytes, 0x824, 0x600); put<u32>(bytes, 0x828, 72); put<u32>(bytes, 0x82c, 60);
    put<u32>(bytes, 0x830, 0x650); put<u32>(bytes, 0x834, 0); put<u32>(bytes, 0x838, 68);
    put<u32>(bytes, 0x83c, 0x600); put<u32>(bytes, 0x840, 0xa00);
    put<u32>(bytes, 0x848, 2); put<u16>(bytes, 0x84c, 8); put<u16>(bytes, 0x84e, 1);
    put<u32>(bytes, 0x850, 0x600); put<u32>(bytes, 0x854, 0x52000000);
    // LPStart/ttype omitted, ULEB call-site encoding, one cleanup region.
    const u8 lsda[] = {0xff, 0xff, 0x01, 0x04, 0x00, 0x10, 0x20, 0x00};
    std::copy(std::begin(lsda), std::end(lsda), bytes.begin() + 0xa00);

    if (chained) {
        put<u32>(bytes, 0x1104, 28); put<u32>(bytes, 0x1108, 64); put<u32>(bytes, 0x110c, 68);
        put<u32>(bytes, 0x1110, 1); put<u32>(bytes, 0x1114, 1);
        put<u32>(bytes, 0x111c, 2); put<u32>(bytes, 0x1120, 12); put<u32>(bytes, 0x1124, 0);
        put<u32>(bytes, 0x1128, 24); put<u16>(bytes, 0x112c, 0x1000); put<u16>(bytes, 0x112e, 12);
        put<u16>(bytes, 0x113c, 1); put<u16>(bytes, 0x113e, 0xb00);
        text(bytes, 0x1144, "_linked");
        // ARM64E_USERLAND24 authenticated rebase, plain offset rebase, then
        // authenticated bind. PAC/diversity are inventoried, never evaluated.
        put<u64>(bytes, 0xb00, (u64{1} << 63) | (u64{1} << 51) | (u64{0x1234} << 32) | (u64{1} << 48) | 0x600);
        put<u64>(bytes, 0xb08, (u64{1} << 51) | 0x620);
        put<u64>(bytes, 0xb10, (u64{1} << 63) | (u64{1} << 62) | (u64{0xabcd} << 32) | (u64{2} << 49));
    }
    return bytes;
}

std::vector<u8> pe() {
    std::vector<u8> bytes(0x800);
    put<u16>(bytes, 0, 0x5a4d); put<u32>(bytes, 0x3c, 0x80); put<u32>(bytes, 0x80, 0x4550);
    put<u16>(bytes, 0x84, 0x8664); put<u16>(bytes, 0x86, 2); put<u16>(bytes, 0x94, 240); put<u16>(bytes, 0x96, 0x22);
    constexpr size_t optional = 0x98, table = optional + 240;
    put<u16>(bytes, optional, 0x20b); put<u32>(bytes, optional + 16, 0x1000); put<u64>(bytes, optional + 24, peBase);
    put<u32>(bytes, optional + 32, 0x1000); put<u32>(bytes, optional + 36, 0x200);
    put<u32>(bytes, optional + 56, 0x3000); put<u32>(bytes, optional + 60, 0x200); put<u32>(bytes, optional + 108, 16);
    put<u32>(bytes, optional + 112 + 3 * 8, 0x2000); put<u32>(bytes, optional + 116 + 3 * 8, 12);
    text(bytes, table, ".text"); put<u32>(bytes, table + 8, 0x200); put<u32>(bytes, table + 12, 0x1000);
    put<u32>(bytes, table + 16, 0x200); put<u32>(bytes, table + 20, 0x200); put<u32>(bytes, table + 36, 0x60000020);
    text(bytes, table + 40, ".rdata"); put<u32>(bytes, table + 48, 0x400); put<u32>(bytes, table + 52, 0x2000);
    put<u32>(bytes, table + 56, 0x400); put<u32>(bytes, table + 60, 0x400); put<u32>(bytes, table + 76, 0x40000040);
    bytes[0x200] = bytes[0x220] = 0xc3;
    put<u32>(bytes, 0x400, 0x1000); put<u32>(bytes, 0x404, 0x1040); put<u32>(bytes, 0x408, 0x2080);
    bytes[0x480] = 9; bytes[0x481] = 1; bytes[0x482] = 1;
    bytes[0x484] = 1; bytes[0x485] = 2; put<u32>(bytes, 0x488, 0x1020);
    return bytes;
}

void compactUnwind() {
    auto bytes = mach(false); ElfImage image;
    require(image.load(view(bytes)).ok(), "compact unwind image loads");
    require(image.runtimeFunctions().size() == 1, "one compact-unwind function range");
    const auto& frame = image.runtimeFunctions().front();
    require(frame.start == machBase + 0x600 && frame.end == machBase + 0x650, "exact compact function range");
    require(frame.personality == machBase + 0x620 && frame.lsda == machBase + 0xa00, "personality/LSDA indices resolved separately");
    auto exceptions = inspectExceptionMetadata(image);
    require(exceptions.functions.size() == 1 && exceptions.functions[0].callSites.size() == 1, "compact-unwind LSDA consumed without an eh_frame");
    const auto& function = exceptions.functions[0];
    require(function.landingPads.size() == 1 && function.landingPads[0].address == machBase + 0x620 && function.landingPads[0].regions.size() == 1, "landing pad protects exact region");
    const auto& region = function.landingPads[0].regions.front();
    require(region.start == machBase + 0x600 && region.end == machBase + 0x610 && region.cleanup && region.callSiteIndex == 0, "cleanup grouping preserves source action identity");

    auto badPersonality = bytes; put<u32>(badPersonality, 0x854, 0x62000000);
    ElfImage invalid; require(invalid.load(view(badPersonality)).ok(), "invalid compact personality still allows binary analysis");
    require(invalid.runtimeFunctions().empty() && warning(invalid, "compact unwind"), "bad personality table rejected atomically");
    auto badLsda = bytes; put<u32>(badLsda, 0x840, 0x5000);
    require(invalid.load(view(badLsda)).ok() && invalid.runtimeFunctions().empty(), "unmapped LSDA rejected without fake frame");
    auto compressed = bytes;
    put<u32>(compressed, 0x848, 3); put<u16>(compressed, 0x84c, 12); put<u16>(compressed, 0x850, 16); put<u16>(compressed, 0x852, 0);
    put<u32>(compressed, 0x854, 0); // common encoding 0, function delta 0.
    require(invalid.load(view(compressed)).ok() && invalid.runtimeFunctions().size() == 1 && invalid.runtimeFunctions()[0].lsda == machBase + 0xa00, "compressed second-level page resolves common encoding");
    put<u32>(compressed, 0x854, 0x01000000);
    require(invalid.load(view(compressed)).ok() && invalid.runtimeFunctions().empty(), "out-of-range compressed encoding fails closed");
}

void chainedPointers() {
    auto bytes = mach(true); ElfImage image; require(image.load(view(bytes)).ok(), "ARM64e chained image loads");
    require(image.relocations().size() == 3, "three exact ARM64e chain entries");
    Address raw = 0, target = 0;
    require(image.memory().readInt(machBase + 0xb00, &raw) && (raw >> 63), "authenticated original word retained for inventory");
    require(image.resolvePointer(machBase + 0xb00, &target) && target == machBase + 0x600, "authenticated rebase metadata strips PAC fields to its link-time offset");
    require(image.resolvePointer(machBase + 0xb08, &target) && target == machBase + 0x620, "ARM64e userland offset rebase normalized");
    require(!image.resolvePointer(machBase + 0xb10, &target), "authenticated external bind remains unresolved without runtime evidence");
    require(image.relocations().back().source == ElfRelocation::Source::kContainerBind && image.relocations().back().symbolName == "_linked", "authenticated bind preserves exact import identity");

    auto bad = bytes; put<u16>(bad, 0x112e, 4); ElfImage invalid;
    require(invalid.load(view(bad)).ok() && invalid.relocations().empty() && warning(invalid, "chained fixups"), "unknown authenticated chain format never guessed");
    require(!invalid.resolvePointer(machBase + 0xb00, &target), "unsupported encoded word is not a canonical runtime pointer");
    bad = bytes; put<u64>(bad, 0xb00, (u64{1} << 63) | (u64{0x7ff} << 51) | 0x600);
    require(invalid.load(view(bad)).ok() && invalid.relocations().empty() && !invalid.resolvePointer(machBase + 0xb00, &target), "out-of-page chain rejects all partial pointer records");
    bad = bytes; put<u64>(bad, 0xb10, (u64{1} << 63) | (u64{1} << 62) | 1);
    require(invalid.load(view(bad)).ok() && invalid.relocations().empty(), "out-of-range ARM64e import ordinal rejected atomically");
}

void windowsUnwind() {
    auto bytes = pe(); ElfImage image; require(image.load(view(bytes)).ok(), "PE handler fixture loads");
    require(image.runtimeFunctions().size() == 1 && image.runtimeFunctions()[0].unwindValidated, "x64 handler unwind structure validated");
    const auto& frame = image.runtimeFunctions()[0];
    require(frame.handler == peBase + 0x1020 && frame.personality == frame.handler && frame.handlerData == peBase + 0x208c, "SEH handler and opaque language data inventoried");

    auto chain = bytes; chain[0x480] = 33; chain[0x481] = chain[0x482] = 0;
    put<u32>(chain, 0x484, 0x1020); put<u32>(chain, 0x488, 0x1030); put<u32>(chain, 0x48c, 0x20c0); chain[0x4c0] = 1;
    ElfImage candidate; require(candidate.load(view(chain)).ok() && candidate.runtimeFunctions().size() == 1 && candidate.runtimeFunctions()[0].unwindValidated && candidate.runtimeFunctions()[0].chainedStart == peBase + 0x1020, "chained UNWIND_INFO exact function relationship");
    auto bad = bytes; bad[0x480] = 41;
    require(candidate.load(view(bad)).ok() && candidate.runtimeFunctions().size() == 1 && !candidate.runtimeFunctions()[0].unwindValidated, "handler and chained flags cannot coexist");
    bad = bytes; put<u32>(bad, 0x488, 0x2000);
    require(candidate.load(view(bad)).ok() && !candidate.runtimeFunctions()[0].unwindValidated && candidate.runtimeFunctions()[0].handler == kNoAddress, "non-executable handler not published");
    bad = chain; put<u32>(bad, 0x48c, 0x2080);
    require(candidate.load(view(bad)).ok() && !candidate.runtimeFunctions()[0].unwindValidated && candidate.runtimeFunctions()[0].chainedStart == kNoAddress, "self-referential unwind chain not published");
    bad = bytes; put<u32>(bad, 0x408, 0x23fe);
    require(candidate.load(view(bad)).ok() && !candidate.runtimeFunctions()[0].unwindValidated, "truncated x64 unwind header remains a bounded partial range");
    bad = bytes; put<u32>(bad, 0x98 + 116 + 3 * 8, 11);
    require(candidate.load(view(bad)).ok() && candidate.runtimeFunctions().empty(), "partial exception-directory entry rejects ranges atomically");
}
} // namespace

int main() {
    compactUnwind(); chainedPointers(); windowsUnwind();
    std::cout << "loader depth: " << checks << " checks passed\n";
}
