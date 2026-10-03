#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

#include "mint/loader/elf_image.h"
#include "mint/disasm/disassembler.h"
#include "mint/analysis/code_analyzer.h"

namespace {
using namespace mint;
int checks = 0, failures = 0;
bool expect(bool condition, const std::string& name) {
    ++checks;
    if (!condition) { ++failures; std::cerr << "FAIL " << name << '\n'; }
    return condition;
}
template<class T> void put(std::vector<u8>* bytes, size_t offset, T value) {
    if (offset + sizeof(T) > bytes->size()) std::abort();
    std::memcpy(bytes->data() + offset, &value, sizeof(value));
}
ByteView view(const std::vector<u8>& bytes) { return ByteView(bytes.data(), bytes.size()); }

std::vector<u8> elf32(u16 machine) {
    std::vector<u8> bytes(1024);
    const u8 ident[16] = {0x7f, 'E', 'L', 'F', 1, 1, 1};
    std::memcpy(bytes.data(), ident, sizeof(ident));
    put<u16>(&bytes, 16, elf::kEtDyn); put<u16>(&bytes, 18, machine); put<u32>(&bytes, 20, 1);
    put<u32>(&bytes, 24, machine == 40 ? 0x1001 : 0x1000);
    put<u32>(&bytes, 28, 52); put<u32>(&bytes, 32, 0x340); put<u16>(&bytes, 40, 52);
    put<u16>(&bytes, 42, 32); put<u16>(&bytes, 44, 2); put<u16>(&bytes, 46, 40);
    put<u16>(&bytes, 48, 8); put<u16>(&bytes, 50, 7);
    auto segment = [&](size_t offset, u32 type, u32 fileOffset, u32 address, u32 fileSize, u32 memorySize, u32 flags) {
        put<u32>(&bytes, offset, type); put<u32>(&bytes, offset + 4, fileOffset);
        put<u32>(&bytes, offset + 8, address); put<u32>(&bytes, offset + 16, fileSize);
        put<u32>(&bytes, offset + 20, memorySize); put<u32>(&bytes, offset + 24, flags); put<u32>(&bytes, offset + 28, 1);
    };
    segment(52, elf::kPtLoad, 0x100, 0x1000, 0x200, 0x240, elf::kPfR | elf::kPfX);
    segment(84, elf::kPtDynamic, 0x140, 0x1040, 64, 64, elf::kPfR);
    if (machine == 40) {
        put<u16>(&bytes, 0x100, 0x2007); put<u16>(&bytes, 0x102, 0x4770); // Thumb movs/bx lr
        put<u32>(&bytes, 0x108, 0xe3a00007); put<u32>(&bytes, 0x10c, 0xe12fff1e); // ARM mov/bx lr
    } else if (machine == 3) {
        bytes[0x100] = 0xb8; put<u32>(&bytes, 0x101, 7); bytes[0x105] = 0xc3;
    } else { put<u32>(&bytes, 0x100, 0x00700513); put<u32>(&bytes, 0x104, 0x00008067); }
    put<u32>(&bytes, 0x118, machine == 40 ? 0x1001 : 0x1000);
    put<u32>(&bytes, 0x11c, 0xdeadbeef); put<u32>(&bytes, 0x130, machine == 40 ? 0x1001 : 0x1000);
    const char strings[] = "\0main\0imported\0libdemo.so\0demo.so\0$a\0";
    std::memcpy(bytes.data() + 0x240, strings, sizeof(strings));
    auto dynamic = [&](size_t index, i32 tag, u32 value) { put<i32>(&bytes, 0x140 + index * 8, tag); put<u32>(&bytes, 0x144 + index * 8, value); };
    dynamic(0, elf::kDtStrTab, 0x1140); dynamic(1, elf::kDtStrSz, sizeof(strings));
    dynamic(2, elf::kDtNeeded, 15); dynamic(3, elf::kDtSoName, 26);
    dynamic(4, elf::kDtInitArray, 0x1030); dynamic(5, elf::kDtInitArraySz, 4); dynamic(6, elf::kDtNull, 0);
    auto symbol = [&](size_t index, u32 name, u32 value, u32 size, u8 info, u16 section) {
        const size_t at = 0x200 + index * 16;
        put<u32>(&bytes, at, name); put<u32>(&bytes, at + 4, value); put<u32>(&bytes, at + 8, size);
        bytes[at + 12] = info; put<u16>(&bytes, at + 14, section);
    };
    symbol(1, 1, machine == 40 ? 0x1001 : 0x1000, 8, 0x12, 1);
    symbol(2, 6, 0, 0, 0x12, 0); symbol(3, 34, 0x1008, 0, 0, 1);
    const u32 relative = machine == 40 ? 23 : (machine == 3 ? 8 : 3);
    put<u32>(&bytes, 0x280, 0x1018); put<u32>(&bytes, 0x284, relative);
    const char names[] = "\0.text\0.dynstr\0.dynsym\0.rel.dyn\0.dynamic\0.bss\0.shstrtab\0";
    std::memcpy(bytes.data() + 0x300, names, sizeof(names));
    auto section = [&](size_t index, u32 name, u32 type, u32 flags, u32 address, u32 offset, u32 size, u32 link, u32 info, u32 stride) {
        const size_t at = 0x340 + index * 40;
        put<u32>(&bytes, at, name); put<u32>(&bytes, at + 4, type); put<u32>(&bytes, at + 8, flags);
        put<u32>(&bytes, at + 12, address); put<u32>(&bytes, at + 16, offset); put<u32>(&bytes, at + 20, size);
        put<u32>(&bytes, at + 24, link); put<u32>(&bytes, at + 28, info); put<u32>(&bytes, at + 32, 4); put<u32>(&bytes, at + 36, stride);
    };
    // Increase fixture size before writing the final table entries.
    bytes.resize(0x500);
    section(1, 1, elf::kShtProgBits, 6, 0x1000, 0x100, 0x20, 0, 0, 0);
    section(2, 7, elf::kShtStrTab, 2, 0x1140, 0x240, sizeof(strings), 0, 0, 0);
    section(3, 15, elf::kShtDynSym, 2, 0x1100, 0x200, 64, 2, 1, 16);
    section(4, 23, elf::kShtRel, 2, 0x1180, 0x280, 8, 3, 1, 8);
    section(5, 32, elf::kShtDynamic, 2, 0x1040, 0x140, 64, 2, 0, 8);
    section(6, 41, elf::kShtNoBits, 3, 0x1200, 0, 0x40, 0, 0, 0);
    section(7, 46, elf::kShtStrTab, 0, 0, 0x300, sizeof(names), 0, 0, 0);
    return bytes;
}

void loadContracts(u16 machine, Arch arch) {
    auto bytes = elf32(machine);
    ElfImage image;
    expect(image.load(view(bytes)).ok(), "load ELF32 " + std::string(archName(arch)));
    expect(image.loaded() && image.format() == ImageFormat::kElf32 && image.arch() == arch && image.pointerSize() == 4, "ELF32 architecture/format/pointer width");
    expect(image.entryPoint() == 0x1000 && image.isPositionIndependent(), "ELF32 canonical entry and PIE");
    expect(image.memory().isExecutable(0x1000) && !image.memory().segments().front().writable(), "ELF32 segment permissions");
    u32 zero = 1; expect(image.memory().readInt(0x1200, &zero) && zero == 0, "ELF32 BSS is zero-filled");
    const auto* main = image.findSymbol("main"), *imported = image.findSymbol("imported");
    expect(main && main->isFunction() && main->value == 0x1000 && imported && imported->undefined, "ELF32 symbols and imports");
    expect(image.neededLibraries() == std::vector<std::string>{"libdemo.so"} && image.soname() == "demo.so", "ELF32 dynamic dependency metadata");
    Address pointer = 0;
    expect(image.resolvePointer(0x1018, &pointer) && pointer == (machine == 40 ? 0x1001 : 0x1000), "ELF32 REL implicit addend pointer");
    expect(image.initializers() == std::vector<Address>{machine == 40 ? Address{0x1001} : Address{0x1000}}, "ELF32 four-byte initializer array");
    const u8 patch[4] = {0x10, 0x10, 0, 0};
    expect(image.applyPatch(0x1018, ByteView(patch, sizeof(patch))).ok() && image.resolvePointer(0x1018, &pointer) && pointer == 0x1010, "ELF32 edited pointer overrides REL");
    u64 offset = 0; expect(image.fileOffsetAt(0x1018, 4, &offset) && offset == 0x118, "ELF32 patched pointer retains original file offset");
    image.resetPatches(); expect(image.resolvePointer(0x1018, &pointer) && pointer == (machine == 40 ? 0x1001 : 0x1000), "ELF32 reset restores relative pointer");
    if (machine == 40) {
        expect(image.architectureAt(0x1000) == Arch::kThumb && image.architectureAt(0x1008) == Arch::kArm32 &&
               image.architectureAt(0x1009) == Arch::kThumb && image.canonicalAddress(0x1001) == 0x1000, "ELF32 ARM/Thumb mode map");
    }
    auto broken = bytes; broken[5] = 2;
    expect(!image.load(view(broken)).ok(), "ELF32 big-endian rejected");
    broken = bytes; put<u16>(&broken, 18, 0xffff);
    expect(!image.load(view(broken)).ok(), "ELF32 unknown machine rejected");
    broken = bytes; put<u32>(&broken, 52 + 16, 0xffffffff); put<u32>(&broken, 32, 0); put<u16>(&broken, 48, 0);
    expect(!image.load(view(broken)).ok(), "ELF32 invalid segment cannot manufacture a file mapping");
    broken = bytes; put<u32>(&broken, 52 + 8, 0xfffffff0); put<u32>(&broken, 32, 0); put<u16>(&broken, 48, 0);
    expect(!image.load(view(broken)).ok(), "ELF32 virtual overflow rejected");
    broken = bytes; put<u16>(&broken, 46, 1);
    expect(image.load(view(broken)).ok() && !image.warnings().empty(), "ELF32 broken sections preserve usable PT_LOAD");
    for (size_t size = 0; size < bytes.size(); ++size) {
        ElfImage prefix;
        const auto status = prefix.load(ByteView(bytes.data(), size));
        expect(!status.ok() || prefix.loaded(), "ELF32 prefix parser never publishes incomplete success");
    }
}

void decoded(Arch arch, Address address, const std::vector<u8>& bytes, FlowKind flow, Address target, unsigned size, const char* label) {
    Disassembler decoder;
    expect(decoder.open(arch).ok(), std::string(label) + " decoder opens");
    DecodedInsn result;
    expect(decoder.decodeVerbose(address, view(bytes), &result) && result.record.flow == flow &&
           result.record.target == target && result.record.size == size && !result.mnemonic.empty(), std::string(label) + " decoded flow/target/size");
}
bool pluginDecode(Address address, ByteView bytes, DecodedInsn* output) {
    if (bytes.empty() || bytes.data()[0] != 0x7a) return false;
    output->record.address = address; output->record.size = 1; output->record.flow = FlowKind::kReturn;
    output->mnemonic = "plugin-ret"; return true;
}
void decoderContracts() {
    decoded(Arch::kArm32, 0x1000, {0x1e,0xff,0x2f,0xe1}, FlowKind::kReturn, kNoAddress, 4, "ARM bx lr");
    decoded(Arch::kArm32, 0x1000, {0x02,0,0,0xeb}, FlowKind::kCall, 0x1010, 4, "ARM direct bl");
    decoded(Arch::kThumb, 0x1001, {0x70,0x47}, FlowKind::kReturn, kNoAddress, 2, "Thumb canonical bx lr");
    decoded(Arch::kThumb, 0x1000, {0x02,0xe0}, FlowKind::kJump, 0x1009, 2, "Thumb tagged direct b");
    decoded(Arch::kX86_32, 0x1000, {0xe8,0x0b,0,0,0}, FlowKind::kCall, 0x1010, 5, "x86-32 direct call");
    decoded(Arch::kX86_32, 0x1000, {0xc3}, FlowKind::kReturn, kNoAddress, 1, "x86-32 ret");
    for (const auto arch : {Arch::kRiscV32, Arch::kRiscV64}) {
        decoded(arch, 0x1000, {0x67,0x80,0,0}, FlowKind::kReturn, kNoAddress, 4, "RISC-V jalr return");
        decoded(arch, 0x1000, {0xef,0,0,0x01}, FlowKind::kCall, 0x1010, 4, "RISC-V jal ra");
        decoded(arch, 0x1000, {0x6f,0,0,0x01}, FlowKind::kJump, 0x1010, 4, "RISC-V jal zero");
        decoded(arch, 0x1000, {0x63,0x04,0,0}, FlowKind::kCondJump, 0x1008, 4, "RISC-V conditional branch");
        decoded(arch, 0x1000, {0x82,0x80}, FlowKind::kReturn, kNoAddress, 2, "RISC-V compressed return");
        decoded(arch, 0x1000, {0x02,0x90}, FlowKind::kTrap, kNoAddress, 2, "RISC-V compressed breakpoint");
    }
    const auto builtin = architectureDescriptions();
    expect(builtin.size() >= 7, "native architecture registry includes every builtin");
    for (const auto& item : builtin) {
        Disassembler decoder; expect(decoder.open(item.architecture).ok() && decoder.minInstructionSize() == item.minInstructionSize &&
                                    decoder.maxInstructionSize() == item.maxInstructionSize, "registry descriptor agrees with decoder");
    }
    ArchitectureDescription plugin{static_cast<Arch>(128), "test-native", "Test native decoder", 4, 1, 1, 1, 0, 0, false, pluginDecode};
    expect(registerArchitectureDescription(plugin).ok(), "register real external decoder descriptor");
    expect(!registerArchitectureDescription(plugin).ok(), "external decoder cannot replace existing descriptor");
    decoded(plugin.architecture, 0x1000, {0x7a}, FlowKind::kReturn, kNoAddress, 1, "external callback");
    auto invalid = plugin; invalid.architecture = Arch::kAArch64;
    expect(!registerArchitectureDescription(invalid).ok(), "architecture plugin cannot replace builtin");
    invalid = plugin; invalid.architecture = static_cast<Arch>(129); invalid.id = "bad-size"; invalid.maxInstructionSize = 255;
    expect(!registerArchitectureDescription(invalid).ok(), "architecture plugin instruction bounds validated");
}

void analyzerContracts() {
    for (const auto machine : {u16{40}, u16{3}, u16{243}}) {
        auto bytes = elf32(machine);
        ElfImage image; expect(image.load(view(bytes)).ok(), "ELF32 analyzer source loads");
        CodeAnalyzer::Options options; options.linearSweepFallback = false;
        options.debugFunctionEntries = {0x1008};
        if (machine != 40) {
            if (machine == 3) bytes[0x108] = 0xc3;
            else put<u32>(&bytes, 0x108, 0x00008067);
            expect(image.load(view(bytes)).ok(), "ELF32 debug-root fixture loads");
        }
        CodeAnalyzer analyzer;
        expect(analyzer.analyze(image, options).ok() && analyzer.functionAt(0x1000) && analyzer.functionAt(0x1008), "ELF32 recursive descent and DWARF roots");
        const auto* debug = analyzer.functionAt(0x1008);
        expect(debug && debug->origin == FunctionOrigin::kDwarf && debug->decodeArch == image.architectureAt(0x1008), "DWARF provenance and actual decode architecture");
        CodeAnalyzer restored;
        const auto state = analyzer.snapshot();
        expect(restored.restore(image, options, state).ok() && restored.code().instructions().size() == state.instructions.size() &&
               restored.functionAt(0x1008) && restored.functionAt(0x1008)->decodeArch == debug->decodeArch, "ELF32 native snapshot restores modes and debug roots");
        options.userFunctionEntries = {0x1008};
        expect(analyzer.analyze(image, options).ok() && analyzer.functionAt(0x1008)->origin == FunctionOrigin::kUser, "explicit user function overrides DWARF root");
        options.excludedRanges = {{0x1038, 0x1040}};
        expect(analyzer.analyze(image, options).ok(), "analyze with authoritative scalar data");
        const u8 scalar[] = {0x55}; expect(image.applyPatch(0x1038, ByteView(scalar, sizeof(scalar))).ok(), "patch authoritative scalar data");
        CodeAnalyzer::IncrementalResult update;
        expect(analyzer.reanalyzeChanged(image, options, {{0x1038,0x1039}}, &update).ok() && update.used && update.functionsReanalyzed == 0,
               "safe classified data-only patch does not rediscover code");
    }
    auto bytes = elf32(40);
    put<u32>(&bytes, 24, 0x1000); put<u32>(&bytes, 0x214, 0x1000); // ARM entry/main
    put<u32>(&bytes, 0x100, 0xfa000002); // blx Thumb function at 0x1010
    put<u32>(&bytes, 0x104, 0xe12fff1e); // bx lr
    put<u16>(&bytes, 0x110, 0x2009); put<u16>(&bytes, 0x112, 0x4770);
    put<u32>(&bytes, 0x118, 0x1000); put<u32>(&bytes, 0x130, 0x1000);
    ElfImage image; expect(image.load(view(bytes)).ok(), "mixed ARM-to-Thumb call image loads");
    CodeAnalyzer::Options options; options.linearSweepFallback = false;
    CodeAnalyzer analyzer;
    expect(analyzer.analyze(image, options).ok() && analyzer.functionAt(0x1000) && analyzer.functionAt(0x1010) &&
           analyzer.functionAt(0x1000)->decodeArch == Arch::kArm32 && analyzer.functionAt(0x1010)->decodeArch == Arch::kThumb,
           "BLX creates canonical Thumb callee despite preceding ARM mapping");
    expect(analyzer.code().find(0x1000) && analyzer.code().find(0x1000)->target == 0x1010 &&
           analyzer.code().find(0x1010) && analyzer.code().find(0x1010)->size == 2 && !analyzer.code().find(0x1011),
           "mixed ARM/Thumb code map stores canonical instruction and target addresses");
    CodeAnalyzer restored;
    expect(restored.restore(image, options, analyzer.snapshot()).ok() && restored.functionAt(0x1010)->decodeArch == Arch::kThumb,
           "mixed ARM/Thumb snapshot validates encoded BLX mode");
    const u8 immediate[] = {0x0b,0x20};
    expect(image.applyPatch(0x1010, ByteView(immediate, sizeof(immediate))).ok(), "patch Thumb callee arithmetic");
    CodeAnalyzer::IncrementalResult update;
    expect(analyzer.reanalyzeChanged(image, options, {{0x1010,0x1012}}, &update).ok() && update.used && update.functionsReanalyzed == 1,
           "Thumb callee patch reanalyzes only its correctly decoded owner");
    expect(restored.restore(image, options, analyzer.snapshot()).ok(), "patched mixed-mode snapshot remains restorable");
}
}

int main(int argc, char** argv) {
    loadContracts(40, Arch::kArm32); loadContracts(3, Arch::kX86_32); loadContracts(243, Arch::kRiscV32);
    decoderContracts();
    analyzerContracts();
    for (int i = 1; i < argc; ++i) {
        std::ifstream input(argv[i], std::ios::binary);
        const std::vector<u8> bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
        ElfImage image; expect(!bytes.empty() && image.load(view(bytes)).ok(), std::string("real ELF image ") + argv[i]);
        if (image.loaded()) {
            Disassembler decoder; const Address entry = image.entryPoint();
            expect(decoder.open(image.architectureAt(entry)).ok(), "real image entry decoder");
            DecodedInsn decodedEntry; expect(decoder.decodeVerbose(entry, image.memory().viewAt(entry, 16), &decodedEntry), "real image entry instruction");
            std::cout << image.formatName() << ' ' << archName(image.arch()) << ": " << image.symbols().size() << " symbols, " << image.relocations().size() << " relocations\n";
        }
    }
    std::cout << "ELF32/native decoder contracts: " << checks << " checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
