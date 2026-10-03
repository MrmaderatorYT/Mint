#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>
#include <vector>
#include <iterator>
#include <unistd.h>

#include "mint/loader/elf_image.h"
#include "mint/session.h"

namespace {
using namespace mint;
int checks = 0;
int failures = 0;
void expect(bool value, const char* description) {
    ++checks;
    if (!value) { ++failures; std::fprintf(stderr, "FAIL: %s\n", description); }
}
template <class T> void put(std::vector<u8>& bytes, size_t offset, T value) {
    if (offset + sizeof(T) > bytes.size()) std::abort();
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}
void text(std::vector<u8>& bytes, size_t offset, const std::string& value) {
    if (offset + value.size() + 1 > bytes.size()) std::abort();
    std::memcpy(bytes.data() + offset, value.c_str(), value.size() + 1);
}
ByteView view(const std::vector<u8>& bytes) { return ByteView(bytes.data(), bytes.size()); }

std::vector<u8> pe(Arch architecture) {
    std::vector<u8> bytes(0x800, 0);
    put<u16>(bytes, 0, 0x5a4d);
    put<u32>(bytes, 0x3c, 0x80);
    put<u32>(bytes, 0x80, 0x4550);
    put<u16>(bytes, 0x84, architecture == Arch::kX86_64 ? 0x8664 : 0xaa64);
    put<u16>(bytes, 0x86, 2);
    put<u16>(bytes, 0x94, 240);
    put<u16>(bytes, 0x96, 0x22);
    const size_t optional = 0x98;
    put<u16>(bytes, optional, 0x20b);
    put<u32>(bytes, optional + 16, 0x1000);
    put<u64>(bytes, optional + 24, 0x140000000);
    put<u32>(bytes, optional + 32, 0x1000);
    put<u32>(bytes, optional + 36, 0x200);
    put<u32>(bytes, optional + 56, 0x3000);
    put<u32>(bytes, optional + 60, 0x200);
    put<u16>(bytes, optional + 70, 0x40);
    put<u32>(bytes, optional + 108, 16);
    put<u32>(bytes, optional + 112, 0x2000);
    put<u32>(bytes, optional + 116, 0x80);
    put<u32>(bytes, optional + 120, 0x2080);
    put<u32>(bytes, optional + 124, 40);
    const size_t sections = optional + 240;
    text(bytes, sections, ".text");
    put<u32>(bytes, sections + 8, 0x180);
    put<u32>(bytes, sections + 12, 0x1000);
    put<u32>(bytes, sections + 16, 0x100);
    put<u32>(bytes, sections + 20, 0x200);
    put<u32>(bytes, sections + 36, 0x60000020);
    text(bytes, sections + 40, ".rdata");
    put<u32>(bytes, sections + 48, 0x400);
    put<u32>(bytes, sections + 52, 0x2000);
    put<u32>(bytes, sections + 56, 0x400);
    put<u32>(bytes, sections + 60, 0x400);
    put<u32>(bytes, sections + 76, 0x40000040);
    if (architecture == Arch::kX86_64) bytes[0x200] = 0xc3;
    else put<u32>(bytes, 0x200, 0xd65f03c0);
    // One named export and one imported IAT slot.
    put<u32>(bytes, 0x40c, 0x2060);
    put<u32>(bytes, 0x410, 1);
    put<u32>(bytes, 0x414, 1);
    put<u32>(bytes, 0x418, 1);
    put<u32>(bytes, 0x41c, 0x2030);
    put<u32>(bytes, 0x420, 0x2040);
    put<u32>(bytes, 0x424, 0x2048);
    put<u32>(bytes, 0x430, 0x1000);
    put<u32>(bytes, 0x440, 0x2050);
    put<u16>(bytes, 0x448, 0);
    text(bytes, 0x450, "fixture_entry");
    text(bytes, 0x460, "fixture.dll");
    put<u32>(bytes, 0x480, 0x2240);
    put<u32>(bytes, 0x48c, 0x2200);
    put<u32>(bytes, 0x490, 0x2260);
    text(bytes, 0x600, "kernel32.dll");
    put<u16>(bytes, 0x610, 0);
    text(bytes, 0x612, "ExitProcess");
    put<u64>(bytes, 0x640, 0x2210);
    put<u64>(bytes, 0x660, 0x2210);
    return bytes;
}

std::vector<u8> macho(Arch architecture) {
    std::vector<u8> bytes(0x600, 0);
    const Address base = 0x100000000;
    put<u32>(bytes, 0, 0xfeedfacf);
    put<u32>(bytes, 4, architecture == Arch::kX86_64 ? 0x01000007 : 0x0100000c);
    put<u32>(bytes, 8, 3);
    put<u32>(bytes, 12, 2);
    put<u32>(bytes, 16, 6);
    put<u32>(bytes, 20, 408);
    put<u32>(bytes, 24, 0x200000);
    size_t at = 32;
    put<u32>(bytes, at, 0x19);
    put<u32>(bytes, at + 4, 232);
    text(bytes, at + 8, "__TEXT");
    put<u64>(bytes, at + 24, base);
    put<u64>(bytes, at + 32, 0x400);
    put<u64>(bytes, at + 48, 0x400);
    put<u32>(bytes, at + 56, 5);
    put<u32>(bytes, at + 60, 5);
    put<u32>(bytes, at + 64, 2);
    text(bytes, at + 72, "__text");
    text(bytes, at + 88, "__TEXT");
    put<u64>(bytes, at + 104, base + 0x200);
    put<u64>(bytes, at + 112, 0x80);
    put<u32>(bytes, at + 120, 0x200);
    put<u32>(bytes, at + 136, 0x80000400);
    text(bytes, at + 152, "__cstring");
    text(bytes, at + 168, "__TEXT");
    put<u64>(bytes, at + 184, base + 0x280);
    put<u64>(bytes, at + 192, 0x40);
    put<u32>(bytes, at + 200, 0x280);
    put<u32>(bytes, at + 216, 2);
    at += 232;
    put<u32>(bytes, at, 0x19);
    put<u32>(bytes, at + 4, 72);
    text(bytes, at + 8, "__LINKEDIT");
    put<u64>(bytes, at + 24, base + 0x1000);
    put<u64>(bytes, at + 32, 0x200);
    put<u64>(bytes, at + 40, 0x400);
    put<u64>(bytes, at + 48, 0x200);
    put<u32>(bytes, at + 56, 1);
    put<u32>(bytes, at + 60, 1);
    at += 72;
    put<u32>(bytes, at, 0x80000028);
    put<u32>(bytes, at + 4, 24);
    put<u64>(bytes, at + 8, 0x200);
    at += 24;
    put<u32>(bytes, at, 2);
    put<u32>(bytes, at + 4, 24);
    put<u32>(bytes, at + 8, 0x400);
    put<u32>(bytes, at + 12, 2);
    put<u32>(bytes, at + 16, 0x420);
    put<u32>(bytes, at + 20, 0x20);
    at += 24;
    put<u32>(bytes, at, 0x26);
    put<u32>(bytes, at + 4, 16);
    put<u32>(bytes, at + 8, 0x450);
    put<u32>(bytes, at + 12, 4);
    at += 16;
    put<u32>(bytes, at, 0xc);
    put<u32>(bytes, at + 4, 40);
    put<u32>(bytes, at + 8, 24);
    text(bytes, at + 24, "libc.dylib");
    if (architecture == Arch::kX86_64) bytes[0x200] = 0xc3;
    else put<u32>(bytes, 0x200, 0xd65f03c0);
    text(bytes, 0x280, "hello native world");
    put<u32>(bytes, 0x400, 1);
    bytes[0x404] = 0xf;
    bytes[0x405] = 1;
    put<u64>(bytes, 0x408, base + 0x200);
    put<u32>(bytes, 0x410, 8);
    bytes[0x414] = 1;
    text(bytes, 0x421, "_entry");
    text(bytes, 0x428, "_puts");
    bytes[0x450] = 0x80;
    bytes[0x451] = 4;
    bytes[0x452] = 0x20;
    return bytes;
}

void peTests() {
    for (Arch architecture : {Arch::kX86_64, Arch::kAArch64}) {
        auto bytes = pe(architecture);
        ElfImage image;
        Status status = image.load(view(bytes));
        expect(status.ok(), status.toString().c_str());
        expect(image.loaded() && image.arch() == architecture && image.format() == ImageFormat::kPe64, "PE format/architecture");
        expect(image.entryPoint() == 0x140001000 && image.imageBase() == 0x140000000, "PE VA entry/base");
        expect(image.memory().segments().size() == 3, "PE headers and sections mapped");
        expect(image.memory().isExecutable(image.entryPoint()) && !image.memory().isExecutable(0x140002000), "PE section permissions");
        u32 bss = 1;
        expect(image.memory().readInt(0x140001100, &bss) && bss == 0, "PE virtual tail zero-filled");
        expect(image.soname() == "fixture.dll" && image.neededLibraries().size() == 1, "PE library names");
        const ElfSymbol* exported = image.findSymbol("fixture_entry");
        expect(exported && exported->isFunction() && !exported->undefined && exported->value == image.entryPoint(), "PE named export function");
        const ElfSymbol* imported = image.findSymbol("kernel32.dll!ExitProcess");
        expect(imported && imported->undefined && imported->value == 0, "PE imports not treated as functions at zero");
        expect(image.relocations().size() == 1 && image.relocations()[0].offset == 0x140002260, "PE IAT reference address");
        u64 offset = 0;
        expect(image.fileOffsetAt(image.entryPoint(), 1, &offset) && offset == 0x200, "PE VA to file mapping");
        const u8 replacement[] = {0x90};
        const u8 original = bytes[0x200];
        expect(image.applyPatch(image.entryPoint(), ByteView(replacement, sizeof(replacement))).ok(), "PE in-memory patch");
        expect(image.memory().viewAt(image.entryPoint(), 1).data()[0] == 0x90 && bytes[0x200] == original, "patch does not change source bytes");
        expect(image.findSection(".text")->data.data()[0] == 0x90, "patch updates section backing");
        expect(image.fileOffsetAt(image.entryPoint(), 1, &offset) && offset == 0x200, "patched mapping still points at original file offset");
        expect(!image.applyPatch(0x140001100, ByteView(replacement, 1)).ok(), "BSS patches rejected");
        ElfImage copy = image;
        const u8 second[] = {0xcc};
        expect(image.applyPatch(image.entryPoint(), ByteView(second, 1)).ok() &&
               copy.memory().viewAt(copy.entryPoint(), 1).data()[0] == 0x90, "patch is copy-on-write");
        image.resetPatches();
        expect(image.memory().viewAt(image.entryPoint(), 1).data()[0] == original &&
               image.findSection(".text")->data.data()[0] == original, "patch reset restores original mapping");
    }
    const auto fixture = pe(Arch::kX86_64);
    for (const auto& change : std::vector<std::pair<size_t, u32>>{
         {0x3c, 0xfffffff0}, {0x98 + 56, 0xffffffff}, {0x98 + 16, 0x4000},
         {0x188 + 12, 0x100}, {0x188 + 20, 0x7ff}, {0x188 + 52, 0x1000}}) {
        auto broken = fixture;
        put<u32>(broken, change.first, change.second);
        ElfImage image;
        expect(!image.load(view(broken)).ok() && !image.loaded(), "invalid PE extents rejected");
    }
    auto broken = fixture;
    put<u16>(broken, 0x98, 0x10b);
    ElfImage image;
    expect(!image.load(view(broken)).ok(), "PE32 explicitly unsupported");
    put<u16>(broken, 0x98, 0x20b);
    put<u16>(broken, 0x84, 0x14c);
    expect(!image.load(view(broken)).ok(), "PE x86-32 explicitly unsupported");
    broken = fixture;
    put<u32>(broken, 0x414, 0xffffffff);
    expect(image.load(view(broken)).ok() && !image.warnings().empty(), "malformed optional PE export metadata safely ignored");
    for (size_t length = 0; length < fixture.size(); ++length) {
        const Status ignored = image.load(ByteView(fixture.data(), length));
        (void)ignored;
    }
    for (Arch architecture : {Arch::kX86_64, Arch::kAArch64}) {
        auto extended = pe(architecture); const size_t optional = 0x98;
        put<u32>(extended, optional + 112 + 5 * 8, 0x20c0); put<u32>(extended, optional + 116 + 5 * 8, 12);
        put<u32>(extended, 0x4c0, 0x2000); put<u32>(extended, 0x4c4, 12); put<u16>(extended, 0x4c8, 0xa3e0);
        put<u64>(extended, 0x7e0, 0x140001000);
        put<u32>(extended, optional + 112 + 13 * 8, 0x20e0); put<u32>(extended, optional + 116 + 13 * 8, 64);
        put<u32>(extended, 0x4e0, 1); put<u32>(extended, 0x4e4, 0x2220); put<u32>(extended, 0x4ec, 0x22a0); put<u32>(extended, 0x4f0, 0x2280);
        text(extended, 0x620, "delay.dll"); put<u64>(extended, 0x680, 0x22c0); put<u64>(extended, 0x6a0, 0x22c0);
        text(extended, 0x6c2, "DelayedCall");
        put<u32>(extended, optional + 112 + 3 * 8, 0x2300); put<u32>(extended, optional + 116 + 3 * 8, architecture == Arch::kX86_64 ? 12 : 8);
        put<u32>(extended, 0x700, 0x1000);
        if (architecture == Arch::kX86_64) { put<u32>(extended, 0x704, 0x1001); put<u32>(extended, 0x708, 0x2310); extended[0x710] = 1; }
        else put<u32>(extended, 0x704, 5); // packed ARM64 unwind, four-byte range.
        ElfImage image; expect(image.load(view(extended)).ok(), "PE extended metadata loads");
        expect(image.findSymbol("delay.dll!DelayedCall") && image.findSymbol("delay.dll!DelayedCall")->undefined, "delay imports retain unresolved linkage identity");
        expect(image.relocations().size() == 3, "regular/delay IAT and base fixup records");
        Address pointer = 0; expect(image.resolvePointer(0x1400023e0, &pointer) && pointer == 0x140001000, "PE preferred base pointer remains exact");
        expect(!image.resolvePointer(0x1400022a0, &pointer), "unresolved delay thunk is not an executable pointer");
        expect(image.runtimeFunctions().size() == 1 && image.runtimeFunctions()[0].start == image.entryPoint() &&
            image.runtimeFunctions()[0].end == image.entryPoint() + (architecture == Arch::kX86_64 ? 1 : 4), "PE exception directory proves exact x64/ARM64 range");
        put<u32>(extended, 0x4c4, 10); put<u16>(extended, 0x4c8, 0x43e0);
        expect(image.load(view(extended)).ok() && image.relocations().size() == 2, "malformed HIGHADJ publishes no partial base table");
    }
}

void machoTests() {
    for (Arch architecture : {Arch::kX86_64, Arch::kAArch64}) {
        auto bytes = macho(architecture);
        ElfImage image;
        Status status = image.load(view(bytes));
        expect(status.ok(), status.toString().c_str());
        expect(image.format() == ImageFormat::kMachO64 && image.arch() == architecture, "Mach-O format/architecture");
        expect(image.entryPoint() == 0x100000200 && image.imageBase() == 0x100000000, "Mach-O LC_MAIN file offset translated");
        expect(image.memory().segments().size() == 2 && image.sections().size() == 2, "Mach-O segment/section mapping");
        expect(image.findSection("__TEXT,__text")->executable() &&
               !image.findSection("__TEXT,__cstring")->executable(), "Mach-O code/data section attributes");
        expect(image.findSymbol("_entry") && image.findSymbol("_entry")->value == image.entryPoint(), "Mach-O nlist symbol");
        expect(image.findSymbol("_puts") && image.findSymbol("_puts")->undefined, "Mach-O undefined import");
        expect(image.symbols().size() == 4 && image.neededLibraries().size() == 1, "Mach-O function starts and dylibs");
        expect(image.describeAddress(image.entryPoint()) == "_entry", "Mach-O real names outrank synthetic function starts");
        u64 offset = 0;
        expect(image.fileOffsetAt(image.entryPoint(), 4, &offset) && offset == 0x200, "Mach-O VA to file offset");
    }
    const auto fixture = macho(Arch::kX86_64);
    for (const auto& change : std::vector<std::pair<size_t, u32>>{
         {16, 0xffffffff}, {20, 0xffffffff}, {36, 7}, {32 + 64, 0xffffffff},
         {32 + 120, 0x5ff}, {32 + 184, 0}, {32 + 232 + 24, 0x100}}) {
        auto broken = fixture;
        put<u32>(broken, change.first, change.second);
        ElfImage image;
        expect(!image.load(view(broken)).ok() && !image.loaded(), "invalid Mach-O tables/mappings rejected");
    }
    auto broken = fixture;
    put<u32>(broken, 0, 0xbebafeca);
    ElfImage image;
    expect(!image.load(view(broken)).ok(), "fat Mach-O not silently selected");
    broken = fixture;
    put<u32>(broken, 0, 0xcffaedfe);
    expect(!image.load(view(broken)).ok(), "big-endian Mach-O unsupported");
    broken = fixture;
    put<u32>(broken, 4, 0x01000017);
    expect(!image.load(view(broken)).ok(), "unsupported Mach-O CPU rejected");
    for (size_t length = 0; length < fixture.size(); ++length) {
        const Status ignored = image.load(ByteView(fixture.data(), length));
        (void)ignored;
    }
    auto dyld = fixture;
    put<u32>(dyld, 16, 7); put<u32>(dyld, 20, 456);
    const size_t command = 32 + 408;
    put<u32>(dyld, command, 0x80000022); put<u32>(dyld, command + 4, 48);
    const u8 rebases[] = {0x11, 0x20, 0xe0, 5, 0x51, 0};
    const u8 bindings[] = {0x11, 0x40, '_', 'p', 'u', 't', 's', 0, 0x51, 0x70, 0xf0, 5, 0x90, 0};
    put<u32>(dyld, command + 8, 0x490); put<u32>(dyld, command + 12, sizeof(rebases)); std::memcpy(dyld.data() + 0x490, rebases, sizeof(rebases));
    put<u32>(dyld, command + 16, 0x480); put<u32>(dyld, command + 20, sizeof(bindings)); std::memcpy(dyld.data() + 0x480, bindings, sizeof(bindings));
    put<u64>(dyld, 0x2e0, 0x100000200); put<u64>(dyld, 0x2f0, 0x100000200);
    const u8 exports[] = {0, 1, '_', 'n', 'e', 'w', 0, 8, 3, 0, 0xa0, 4, 0};
    put<u32>(dyld, command + 40, 0x4b0); put<u32>(dyld, command + 44, sizeof(exports)); std::memcpy(dyld.data() + 0x4b0, exports, sizeof(exports));
    expect(image.load(view(dyld)).ok(), "Mach-O dyld streams load");
    expect(image.relocations().size() == 2 && image.findSymbol("_new") && image.findSymbol("_new")->value == 0x100000220, "dyld bind/rebase and export trie decoded");
    Address target = 0; expect(image.resolvePointer(0x1000002e0, &target) && target == 0x100000200, "dyld rebase pointer normalized");
    expect(!image.resolvePointer(0x1000002f0, &target), "dyld unresolved bind overrides misleading stored pointer");
    dyld[0x4b7] = 0; expect(image.load(view(dyld)).ok() && !image.findSymbol("_new"), "cyclic export trie rejected atomically");
    // A single offset-format chain with rebase and imported bind in one page.
    auto chained = fixture; put<u32>(chained, 16, 7); put<u32>(chained, 20, 424);
    put<u32>(chained, command, 0x80000034); put<u32>(chained, command + 4, 16);
    put<u32>(chained, command + 8, 0x480); put<u32>(chained, command + 12, 0x80);
    put<u32>(chained, 0x484, 28); put<u32>(chained, 0x488, 72); put<u32>(chained, 0x48c, 76);
    put<u32>(chained, 0x490, 1); put<u32>(chained, 0x494, 1); // one import format1.
    put<u32>(chained, 0x49c, 2); put<u32>(chained, 0x4a0, 12); // segment count and first starts record.
    put<u32>(chained, 0x4a8, 24); put<u16>(chained, 0x4ac, 0x1000); put<u16>(chained, 0x4ae, 6);
    put<u16>(chained, 0x4bc, 1); put<u16>(chained, 0x4be, 0x2e0);
    put<u32>(chained, 0x4c8, 1); text(chained, 0x4cc, "_puts");
    put<u64>(chained, 0x2e0, 0x200 | (u64{2} << 51)); put<u64>(chained, 0x2e8, u64{1} << 63);
    expect(image.load(view(chained)).ok() && image.relocations().size() == 2, "offset-format chained rebase/bind parsed");
    expect(image.resolvePointer(0x1000002e0, &target) && target == 0x100000200, "encoded chained offset resolves preferred VA");
    expect(!image.resolvePointer(0x1000002e8, &target), "encoded imported chain never becomes fake target");
    put<u16>(chained, 0x4ae, 99);
    expect(image.load(view(chained)).ok() && image.relocations().empty() && !image.resolvePointer(0x1000002e0, &target), "unsupported chained format fails closed for encoded pointers");
    // Universal selection keeps original-container file offsets for patches.
    std::vector<u8> universal(0x2600, 0); put<u32>(universal, 0, 0xcafebabe); put<u32>(universal, 4, 2);
    put<u32>(universal, 8, 0x01000007); put<u32>(universal, 16, 0x1000); put<u32>(universal, 20, fixture.size()); put<u32>(universal, 24, 12);
    put<u32>(universal, 28, 0x0100000c); put<u32>(universal, 36, 0x2000); put<u32>(universal, 40, fixture.size()); put<u32>(universal, 44, 12);
    std::memcpy(universal.data() + 0x1000, fixture.data(), fixture.size()); const auto arm = macho(Arch::kAArch64);
    std::memcpy(universal.data() + 0x2000, arm.data(), arm.size());
    expect(image.load(view(universal)).ok() && image.arch() == Arch::kX86_64, "universal default selects first supported table slice");
    u64 fileOffset = 0; expect(image.fileOffsetAt(image.entryPoint(), 1, &fileOffset) && fileOffset == 0x1200, "fat x64 patch offset is whole-container offset");
    expect(image.loadMachOSlice(view(universal), Arch::kAArch64).ok() && image.fileOffsetAt(image.entryPoint(), 4, &fileOffset) && fileOffset == 0x2200, "explicit fat slice selection preserves ARM patch offsets");
    put<u32>(universal, 36, 0x1000); expect(!image.load(view(universal)).ok(), "overlapping fat slices rejected");
    // Minimal thin32 i386 executable (no host ABI structs).
    std::vector<u8> narrow(0x300, 0); put<u32>(narrow, 0, 0xfeedface); put<u32>(narrow, 4, 7); put<u32>(narrow, 12, 2);
    put<u32>(narrow, 16, 2); put<u32>(narrow, 20, 148); size_t at = 28;
    put<u32>(narrow, at, 1); put<u32>(narrow, at + 4, 124); text(narrow, at + 8, "__TEXT");
    put<u32>(narrow, at + 24, 0x1000); put<u32>(narrow, at + 28, narrow.size()); put<u32>(narrow, at + 36, narrow.size());
    put<u32>(narrow, at + 40, 5); put<u32>(narrow, at + 44, 5); put<u32>(narrow, at + 48, 1);
    text(narrow, at + 56, "__text"); text(narrow, at + 72, "__TEXT"); put<u32>(narrow, at + 88, 0x1200);
    put<u32>(narrow, at + 92, 0x20); put<u32>(narrow, at + 96, 0x200); put<u32>(narrow, at + 112, 0x80000400);
    at += 124; put<u32>(narrow, at, 0x80000028); put<u32>(narrow, at + 4, 24); put<u64>(narrow, at + 8, 0x200); narrow[0x200] = 0xc3;
    expect(image.load(view(narrow)).ok() && image.arch() == Arch::kX86_32 && image.pointerSize() == 4 && std::string(image.formatName()) == "Mach-O32" && image.entryPoint() == 0x1200, "thin32 i386 loaded with exact pointer width and name");
}

void rawTests() {
    std::vector<u8> bytes{0xc0, 0x03, 0x5f, 0xd6, 0xc3};
    ElfImage image;
    expect(!image.load(view(bytes)).ok(), "unknown bytes require explicit raw import");
    expect(image.loadRaw(view(bytes), Arch::kAArch64, 0x1000, 0x1000).ok() &&
           image.format() == ImageFormat::kRaw && image.entryPoint() == 0x1000, "explicit raw mapping");
    u64 offset = 1;
    expect(image.fileOffsetAt(0x1000, 4, &offset) && offset == 0, "raw file offset mapping");
    expect(!image.loadRaw(view(bytes), Arch::kAArch64, 0x1000, 0x1001).ok(), "unaligned raw ARM entry rejected");
    expect(!image.loadRaw(view(bytes), Arch::kX86_64, 0x1000, 0x2000).ok(), "raw entry outside mapping rejected");
    expect(!image.loadRaw(view(bytes), Arch::kUnknown, 0, 0).ok(), "raw architecture must be explicit");
    expect(!image.loadRaw(view(bytes), Arch::kX86_64, std::numeric_limits<Address>::max() - 2,
                         std::numeric_limits<Address>::max() - 2).ok(), "raw mapping overflow rejected");
    expect(!image.loadRaw({}, Arch::kX86_64, 0, 0).ok(), "empty raw import rejected");
}

void elfPatchTests() {
    std::vector<u8> bytes(0x500, 0);
    elf::Ehdr header{};
    std::memcpy(header.ident, elf::kMagic, sizeof(elf::kMagic));
    header.ident[elf::kEiClass] = elf::kElfClass64;
    header.ident[elf::kEiData] = elf::kElfData2Lsb;
    header.machine = elf::kEmX86_64;
    header.type = elf::kEtDyn;
    header.entry = 0x1100;
    header.phoff = sizeof(header);
    header.phentsize = sizeof(elf::Phdr);
    header.phnum = 1;
    header.shoff = 0x300;
    header.shentsize = sizeof(elf::Shdr);
    header.shnum = 2;
    std::memcpy(bytes.data(), &header, sizeof(header));
    elf::Phdr segment{};
    segment.type = elf::kPtLoad;
    segment.flags = elf::kPfR | elf::kPfX;
    segment.vaddr = 0x1000;
    segment.filesz = bytes.size();
    segment.memsz = 0x580;
    std::memcpy(bytes.data() + header.phoff, &segment, sizeof(segment));
    elf::Shdr relocationSection{};
    relocationSection.type = elf::kShtRela;
    relocationSection.offset = 0x400;
    relocationSection.size = sizeof(elf::Rela);
    relocationSection.entsize = sizeof(elf::Rela);
    std::memcpy(bytes.data() + 0x300 + sizeof(elf::Shdr), &relocationSection, sizeof(relocationSection));
    elf::Rela relocation{};
    relocation.offset = 0x1200;
    relocation.info = elf::kRX86_64Relative;
    relocation.addend = 0x1100;
    std::memcpy(bytes.data() + 0x400, &relocation, sizeof(relocation));
    bytes[0x100] = 0xc3;
    ElfImage image;
    expect(image.load(view(bytes)).ok() && image.format() == ImageFormat::kElf64, "ELF64 semantics preserved");
    Address pointer = 0;
    expect(image.resolvePointer(0x1200, &pointer) && pointer == 0x1100, "original ELF relative relocation resolved");
    const Address replacement = 0x1300;
    expect(image.applyPatch(0x1200, ByteView(reinterpret_cast<const u8*>(&replacement), sizeof(replacement))).ok(), "ELF pointer patch applied");
    expect(image.resolvePointer(0x1200, &pointer) && pointer == replacement, "patched pointer overrides stale relocation addend");
    image.resetPatches();
    expect(image.resolvePointer(0x1200, &pointer) && pointer == 0x1100, "reset restores ELF relocation resolution");
    header.phnum = 2;
    std::memcpy(bytes.data(), &header, sizeof(header));
    segment.vaddr = 0x1100;
    segment.offset = 0x100;
    segment.filesz = 0x100;
    segment.memsz = 0x100;
    std::memcpy(bytes.data() + header.phoff + header.phentsize, &segment, sizeof(segment));
    expect(image.load(view(bytes)).ok() && image.memory().hasOverlaps(), "ELF overlapping segments remain analysable");
    const u8 one[] = {0x90};
    expect(!image.applyPatch(0x1100, ByteView(one, 1)).ok(), "ambiguous overlapping mapping cannot be patched");
}
void selectedMachOSessionTests() {
    struct OwnedFiles {
        std::vector<std::string> paths;
        ~OwnedFiles(){for(const auto& path:paths){unlink(path.c_str());unlink((path+".analysis").c_str());}}
        std::string fresh(bool absent=false){std::string path="/private/tmp/mint-macho-session-XXXXXX";const int fd=mkstemp(path.data());expect(fd>=0,"create owned Mach-O workflow fixture");if(fd<0)return {};close(fd);paths.push_back(path);if(absent)unlink(path.c_str());return path;}
    } files;
    const auto x86=macho(Arch::kX86_64);auto arm=macho(Arch::kAArch64);put<u32>(arm,0x200,0xd28000e0);put<u32>(arm,0x204,0xd65f03c0);
    std::vector<u8> universal(0x2600,0);put<u32>(universal,0,0xcafebabe);put<u32>(universal,4,2);
    put<u32>(universal,8,0x01000007);put<u32>(universal,16,0x1000);put<u32>(universal,20,x86.size());put<u32>(universal,24,12);
    put<u32>(universal,28,0x0100000c);put<u32>(universal,36,0x2000);put<u32>(universal,40,arm.size());put<u32>(universal,44,12);
    std::copy(x86.begin(),x86.end(),universal.begin()+0x1000);std::copy(arm.begin(),arm.end(),universal.begin()+0x2000);
    const auto input=files.fresh(),project=files.fresh(true),exported=files.fresh(true);if(input.empty()||project.empty()||exported.empty())return;
    {std::ofstream output(input,std::ios::binary);output.write(reinterpret_cast<const char*>(universal.data()),universal.size());expect(output.good(),"write owned fat Mach-O fixture");}
    const Address entry=0x100000200;std::string assembled;
    {Session selected;const auto opened=selected.openMachOPath(input,Arch::kAArch64);expect(opened.ok(),opened.toString().c_str());if(!opened.ok())return;
        expect(selected.image().arch()==Arch::kAArch64,"Session explicitly selects nonfirst fat slice");u64 offset=0;expect(selected.image().fileOffsetAt(entry,4,&offset)&&offset==0x2200,"Session retains complete-container second-slice patch offset");
        expect(selected.attachProject(project).ok()&&selected.analyze().ok(),"attach and analyze persistent explicitly selected slice");
        expect(selected.editAnnotation(entry,"name","selected_arm_entry").ok()&&selected.editAnnotation(entry,"comment","nonfirst slice persisted").ok()&&selected.defineType("FatSlicePacket=struct{tag:u32;length:u32}").ok(),"selected slice records real Program annotations and types");
        expect(selected.assembleAt(entry,"mov x0,9",true,&assembled).ok()&&selected.exportPatchedCopy(exported).ok(),"selected ARM assembler patch exports complete fat container");
    }
    {Session reopened;expect(reopened.openMachOPath(input,Arch::kAArch64).ok()&&reopened.attachProject(project).ok()&&reopened.analyze().ok(),"reopen explicit nonfirst slice and typed Program");expect(reopened.annotation(entry,"name")=="selected_arm_entry"&&reopened.annotation(entry,"comment")=="nonfirst slice persisted"&&reopened.typesCHeaderText().find("FatSlicePacket")!=std::string::npos&&!reopened.annotation(entry,"patch").empty(),"selected slice annotations/types/patch survive cold reopen");}
    {Session wrong;expect(wrong.openPath(input).ok()&&wrong.image().arch()==Arch::kX86_64&&!wrong.attachProject(project).ok(),"first-slice default cannot bind second-slice Program even at identical VA");}
    const auto read=[](const std::string& path){std::ifstream input(path,std::ios::binary);return std::vector<u8>(std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>());};
    auto expected=universal;put<u32>(expected,0x2200,0xd2800120);expect(read(exported)==expected,"export changes exact selected instruction bytes only; first slice/table/gaps untouched");expect(read(input)==universal,"selected-slice overlay never modifies original universal source");
    {Session patched;expect(patched.openMachOPath(exported,Arch::kAArch64).ok()&&patched.analyze().ok()&&patched.irTextFor(entry).find("9")!=std::string::npos,"exported whole container can reopen same explicit slice with changed IR");}
}
}  // namespace

int main(int argc, char** argv) {
    peTests();
    machoTests();
    rawTests();
    elfPatchTests();
    selectedMachOSessionTests();
    if (argc > 1) {
        std::ifstream input(argv[1], std::ios::binary | std::ios::ate);
        const std::streamoff length = input.tellg();
        expect(input && length > 0 && length < 512 * 1024 * 1024, "real input is readable and bounded");
        if (input && length > 0 && length < 512 * 1024 * 1024) {
            std::vector<u8> bytes(static_cast<size_t>(length));
            input.seekg(0);
            input.read(reinterpret_cast<char*>(bytes.data()), length);
            ElfImage image;
            const Status status = image.load(view(bytes));
            expect(status.ok(), status.toString().c_str());
            if (status.ok()) std::printf("real native input: %s %s, %zu blocks, %zu sections, %zu symbols\n",
                image.formatName(), archName(image.arch()), image.memory().segments().size(),
                image.sections().size(), image.symbols().size());
        }
    }
    std::printf("native loader contracts: %d checks, %d failures; truncated-prefix sweeps completed\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
