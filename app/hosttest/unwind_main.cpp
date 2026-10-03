#include <cstring>
#include <iostream>
#include <vector>

#include "mint/analysis/code_analyzer.h"
#include "mint/analysis/unwind_roots.h"
#include "mint/base/mapped_file.h"

using namespace mint;

namespace {

template <typename T>
void store(std::vector<u8>* bytes, size_t at, T value) {
    if (at + sizeof(T) > bytes->size()) bytes->resize(at + sizeof(T));
    std::memcpy(bytes->data() + at, &value, sizeof(T));
}

void append(std::vector<u8>* bytes, u64 value, size_t width) {
    for (size_t i = 0; i < width; ++i) bytes->push_back(static_cast<u8>(value >> (8 * i)));
}

void leb(std::vector<u8>* bytes, i64 value, bool isSigned) {
    if (!isSigned) {
        u64 rest = static_cast<u64>(value);
        do {
            const u8 part = rest & 0x7f;
            rest >>= 7;
            bytes->push_back(part | (rest ? 0x80 : 0));
        } while (rest != 0);
        return;
    }
    bool more = true;
    while (more) {
        const u8 part = static_cast<u8>(value) & 0x7f;
        value >>= 7;
        more = !((value == 0 && (part & 0x40) == 0) ||
                 (value == -1 && (part & 0x40) != 0));
        bytes->push_back(part | (more ? 0x80 : 0));
    }
}

void encoded(std::vector<u8>* bytes, u8 encoding, Address target) {
    const Address field = 0x4000 + bytes->size();
    const Address base = (encoding & 0x70) == 0x10 ? field
        : (encoding & 0x70) == 0x30 ? 0x4000 : 0;
    const u64 value = target - base;
    switch (encoding & 0xf) {
        case 1: leb(bytes, static_cast<i64>(value), false); break;
        case 9: leb(bytes, static_cast<i64>(value), true); break;
        case 2: case 10: append(bytes, value, 2); break;
        case 3: case 11: append(bytes, value, 4); break;
        default: append(bytes, value, 8); break;
    }
}

std::vector<u8> header(u8 tableEncoding) {
    std::vector<u8> bytes{1, 0x1b, 3, tableEncoding};
    encoded(&bytes, 0x1b, 0x3000);
    append(&bytes, 2, 4);
    encoded(&bytes, tableEncoding, 0x1000);
    encoded(&bytes, tableEncoding, 0x3010);
    encoded(&bytes, tableEncoding, 0x1010);
    encoded(&bytes, tableEncoding, 0x3030);
    return bytes;
}

bool check(bool condition, const char* message) {
    if (!condition) std::cerr << "unwind correctness: " << message << '\n';
    return condition;
}

std::vector<u8> minimalElf() {
    std::vector<u8> bytes(0x200, 0);
    elf::Ehdr eh{};
    std::memcpy(eh.ident, elf::kMagic, 4);
    eh.ident[elf::kEiClass] = elf::kElfClass64;
    eh.ident[elf::kEiData] = elf::kElfData2Lsb;
    eh.ident[elf::kEiVersion] = 1;
    eh.type = elf::kEtExec; eh.machine = elf::kEmX86_64; eh.version = 1;
    eh.entry = 0x1000; eh.ehsize = sizeof(eh); eh.phoff = sizeof(eh);
    eh.phentsize = sizeof(elf::Phdr); eh.phnum = 1;
    std::memcpy(bytes.data(), &eh, sizeof(eh));
    elf::Phdr ph{};
    ph.type = elf::kPtLoad; ph.flags = elf::kPfR | elf::kPfX;
    ph.offset = 0x100; ph.vaddr = 0x1000; ph.filesz = 0x40; ph.memsz = 0x40;
    ph.align = 0x100;
    std::memcpy(bytes.data() + sizeof(eh), &ph, sizeof(ph));
    bytes[0x100] = 0x90; bytes[0x101] = 0x90; bytes[0x102] = 0xc3;
    bytes[0x110] = 0x48; bytes[0x111] = 0xb8; // movabs rax, imm64
    bytes[0x11a] = 0xc3;
    return bytes;
}

bool tests() {
    bool ok = true;
    std::vector<u8> code(0x40, 0xc3);
    std::vector<u8> frames(0x80, 0);
    store<u32>(&frames, 0, 12); store<u32>(&frames, 4, 0);
    frames[8] = 1; frames[9] = 0; frames[10] = 1;
    frames[11] = 0x78; frames[12] = 16;
    for (size_t fde : {size_t(0x10), size_t(0x30)}) {
        store<u32>(&frames, fde, 20);
        store<u32>(&frames, fde + 4, static_cast<u32>(fde + 4));
        store<u64>(&frames, fde + 8, fde == 0x10 ? 0x1000 : 0x1010);
        store<u64>(&frames, fde + 16, 16);
    }
    MemoryMap memory;
    memory.addSegment(0x1000, code.size(), {code.data(), code.size()}, kMemRead | kMemExec, "code");
    memory.addSegment(0x3000, frames.size(), {frames.data(), frames.size()}, kMemRead, "frames");
    memory.finalize();
    std::vector<UnwindFunctionRoot> roots;
    for (u8 encoding : {u8(0x00), u8(0x01), u8(0x02), u8(0x03), u8(0x04),
                        u8(0x1b), u8(0x3b), u8(0x39), u8(0x3a), u8(0x3c)}) {
        const auto bytes = header(encoding);
        const Status status = parseEhFrameHeader({bytes.data(), bytes.size()}, 0x4000,
                                                 memory, 8, 20, &roots);
        ok &= check(status.ok() && roots.size() == 2 && roots[0].entry == 0x1000 &&
                    roots[1].entry == 0x1010 && roots[0].fde == 0x3010,
                    "absolute/relative/LEB table decoding");
    }
    auto bytes = header(0x3b);
    for (size_t size = 0; size < bytes.size(); ++size) {
        roots.push_back({0xbad, 0xbad});
        ok &= check(!parseEhFrameHeader({bytes.data(), size}, 0x4000, memory, 8, 20, &roots).ok()
                    && roots.empty(), "truncation rejected transactionally");
    }
    auto invalid = bytes;
    store<u32>(&invalid, 8, 0xffffffffu);
    ok &= check(!parseEhFrameHeader({invalid.data(), invalid.size()}, 0x4000, memory, 8, 20, &roots).ok(),
                "huge count rejected");
    invalid = bytes; store<i32>(&invalid, 20, 0x0fff - 0x4000);
    ok &= check(!parseEhFrameHeader({invalid.data(), invalid.size()}, 0x4000, memory, 8, 20, &roots).ok(),
                "unsorted or nonexecutable entry rejected");
    store<u32>(&frames, 0x14, 0);
    ok &= check(!parseEhFrameHeader({bytes.data(), bytes.size()}, 0x4000, memory, 8, 20, &roots).ok(),
                "CIE presented as FDE rejected");
    store<u32>(&frames, 0x14, 0x14);
    invalid = bytes; invalid[3] = 0x4b;
    ok &= check(!parseEhFrameHeader({invalid.data(), invalid.size()}, 0x4000, memory, 8, 20, &roots).ok(),
                "unsupported relative base rejected");
    invalid = bytes; invalid[2] = 0xff;
    ok &= check(parseEhFrameHeader({invalid.data(), invalid.size()}, 0x4000, memory, 8, 20, &roots).ok()
                && roots.empty(), "omitted search table supported");
    invalid = {1, 0x1b, 1, 0x3b}; encoded(&invalid, 0x1b, 0x3000);
    invalid.insert(invalid.end(), 10, 0xff);
    ok &= check(!parseEhFrameHeader({invalid.data(), invalid.size()}, 0x4000, memory, 8, 20, &roots).ok(),
                "overflowing LEB count rejected");

    std::vector<u8> slots(32, 0);
    store<u64>(&slots, 0, 0x1000); store<u64>(&slots, 8, 0x3010);
    store<u64>(&slots, 16, 0x1010); store<u64>(&slots, 24, 0x3030);
    memory.addSegment(0x5000, slots.size(), {slots.data(), slots.size()}, kMemRead, "indirect");
    memory.finalize();
    invalid = {1, 0x1b, 3, 0x80}; encoded(&invalid, 0x1b, 0x3000); append(&invalid, 2, 4);
    for (Address slot : {Address(0x5000), Address(0x5008), Address(0x5010), Address(0x5018)}) append(&invalid, slot, 8);
    ok &= check(parseEhFrameHeader({invalid.data(), invalid.size()}, 0x4000, memory, 8, 20, &roots).ok()
                && roots.size() == 2, "indirect pointers use mapped bytes");

    auto elfBytes = minimalElf();
    ElfImage image;
    ok &= check(image.load({elfBytes.data(), elfBytes.size()}).ok(), "minimal ELF loads");
    CodeAnalyzer analyzer;
    CodeAnalyzer::Options options;
    options.linearSweepFallback = false;
    options.userFunctionEntries = {0x1001, 0x1001};
    ok &= check(analyzer.analyze(image, options).ok(), "explicit user seeds analyze");
    const Function* start = analyzer.functionAt(0x1000);
    const Function* user = analyzer.functionAt(0x1001);
    ok &= check(start && start->instructions.size() == 1 && user && user->instructions.size() == 2
                && user->origin == FunctionOrigin::kUser, "user root is authoritative deterministic boundary");
    ok &= check(analyzer.analyze(image, options).ok() && analyzer.functions().size() == 2
                && analyzer.code().size() == 3, "reanalyzing resets finalized code and indexes");
    options.userFunctionEntries = {};
    options.excludedRanges = {{0x1001, 0x1002}, {0x1001, 0x1003}};
    ok &= check(analyzer.analyze(image, options).ok() && analyzer.code().size() == 1
                && analyzer.code().find(0x1001) == nullptr, "overlapping data ranges block descent");
    options.userFunctionEntries = {0x1010};
    options.excludedRanges = {{0x1014, 0x1016}};
    ok &= check(analyzer.analyze(image, options).ok() && analyzer.code().covering(0x1014) == nullptr,
                "variable-width instruction cannot cross data boundary");
    options.userFunctionEntries = {0x1014};
    ok &= check(!analyzer.analyze(image, options).ok(), "seed in excluded data rejected");
    options.userFunctionEntries = {}; options.excludedRanges = {{0x1014, 0x1014}};
    ok &= check(!analyzer.analyze(image, options).ok(), "empty/reversed data range rejected");

    auto indirectElf = minimalElf();
    indirectElf[0x100] = 0xff; indirectElf[0x101] = 0x25;
    store<i32>(&indirectElf, 0x102, 0x2a); // jmp qword ptr [rip + 0x2a]
    store<u64>(&indirectElf, 0x130, 0x1020); indirectElf[0x120] = 0xc3;
    ElfImage indirectImage;
    ok &= check(indirectImage.load({indirectElf.data(), indirectElf.size()}).ok(), "immutable indirect fixture loads");
    options = CodeAnalyzer::Options{}; options.linearSweepFallback = false;
    ok &= check(analyzer.analyze(indirectImage, options).ok() && analyzer.functionAt(0x1000) &&
                analyzer.functionAt(0x1000)->resolvedIndirectJumps.size() == 1 &&
                analyzer.code().find(0x1020) && analyzer.code().find(0x1000)->target == 0x1020,
                "RIP-relative immutable pointer recovers an indirect CFG edge");
    elf::Phdr mutablePh{};
    std::memcpy(&mutablePh, indirectElf.data() + sizeof(elf::Ehdr), sizeof(mutablePh));
    mutablePh.flags |= elf::kPfW;
    std::memcpy(indirectElf.data() + sizeof(elf::Ehdr), &mutablePh, sizeof(mutablePh));
    ElfImage mutableImage;
    ok &= check(mutableImage.load({indirectElf.data(), indirectElf.size()}).ok() &&
                analyzer.analyze(mutableImage, options).ok() && analyzer.functionAt(0x1000) &&
                analyzer.functionAt(0x1000)->resolvedIndirectJumps.empty() &&
                analyzer.functionAt(0x1000)->incomplete && analyzer.code().find(0x1020) == nullptr,
                "mutable pointer slot cannot prove an indirect target");
    mutablePh.flags &= ~elf::kPfW;
    std::memcpy(indirectElf.data() + sizeof(elf::Ehdr), &mutablePh, sizeof(mutablePh));
    indirectElf[0x101] = 0x15; indirectElf[0x106] = 0xc3;
    ElfImage callImage;
    ok &= check(callImage.load({indirectElf.data(), indirectElf.size()}).ok() &&
                analyzer.analyze(callImage, options).ok() && analyzer.functionAt(0x1020) &&
                analyzer.functionAt(0x1000)->callees == std::vector<Address>{0x1020},
                "immutable indirect call seeds a named callee and keeps fallthrough");

    auto relocationElf = minimalElf(); relocationElf.resize(0x280);
    elf::Ehdr relocationHeader{};
    std::memcpy(&relocationHeader, relocationElf.data(), sizeof(relocationHeader));
    relocationHeader.shoff = 0x200; relocationHeader.shnum = 2;
    relocationHeader.shentsize = sizeof(elf::Shdr);
    std::memcpy(relocationElf.data(), &relocationHeader, sizeof(relocationHeader));
    elf::Shdr relocationSection{};
    relocationSection.type = elf::kShtRela; relocationSection.offset = 0x180;
    relocationSection.size = sizeof(elf::Rela); relocationSection.entsize = sizeof(elf::Rela);
    std::memcpy(relocationElf.data() + 0x200 + sizeof(elf::Shdr), &relocationSection, sizeof(relocationSection));
    elf::Rela relocation{};
    relocation.offset = 0x1030; relocation.info = elf::kRX86_64Relative; relocation.addend = 0x1020;
    std::memcpy(relocationElf.data() + 0x180, &relocation, sizeof(relocation));
    relocationElf[0x120] = 0xc3;
    ElfImage relocationImage;
    ok &= check(relocationImage.load({relocationElf.data(), relocationElf.size()}).ok() &&
                analyzer.analyze(relocationImage, options).ok() && analyzer.functionAt(0x1020) &&
                analyzer.functionAt(0x1020)->origin == FunctionOrigin::kRelocation,
                "executable relocation addend seeds otherwise unreachable function");

    const std::vector<u8> rawCode{0xc3};
    ElfImage rawImage;
    ok &= check(rawImage.loadRaw({rawCode.data(), rawCode.size()}, Arch::kX86_64, 0, 0).ok() &&
                analyzer.analyze(rawImage, options).ok() && analyzer.functionAt(0),
                "raw zero entry remains a valid function root");
    const std::vector<u8> armCode{0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6};
    ElfImage armImage;
    options.excludedRanges = {{0x1002, 0x1004}};
    ok &= check(armImage.loadRaw({armCode.data(), armCode.size()}, Arch::kAArch64, 0x1000, 0x1000).ok() &&
                analyzer.analyze(armImage, options).ok() && analyzer.code().covering(0x1002) == nullptr &&
                analyzer.code().find(0x1000) && analyzer.code().find(0x1000)->size == 2,
                "failed fixed-width decode cannot claim user-defined data bytes");
    return ok;
}

}  // namespace

int main(int argc, char** argv) {
    if (!tests()) return 1;
    if (argc > 1) {
        MappedFile file;
        if (!file.open(argv[1]).ok()) return 2;
        ElfImage image;
        if (!image.load(file.view()).ok()) return 2;
        std::vector<std::string> warnings;
        const auto roots = collectUnwindRoots(image, 200000, &warnings);
        for (const auto& warning : warnings) std::cerr << warning << '\n';
        std::cout << "real binary unwind roots: " << roots.size() << '\n';
        if (!warnings.empty()) return 3;
        CodeAnalyzer analyzer;
        if (!analyzer.analyze(image).ok()) return 4;
        size_t unwind = 0, relocation = 0;
        for (const Function& function : analyzer.functions()) {
            unwind += function.origin == FunctionOrigin::kUnwind;
            relocation += function.origin == FunctionOrigin::kRelocation;
        }
        std::cout << "analyzed " << analyzer.functions().size() << " functions; unwind="
                  << unwind << " relocation=" << relocation << '\n';
    }
    std::cout << "unwind/user-boundary correctness tests passed\n";
    return 0;
}
