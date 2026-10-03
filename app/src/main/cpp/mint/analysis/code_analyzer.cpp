#include "mint/analysis/code_analyzer.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <utility>

#include "mint/base/log.h"
#include "mint/analysis/unwind_roots.h"
#include "mint/ir/lifter.h"
#include "mint/ir/normalize.h"
#include "mint/ssa/ssa_builder.h"

namespace mint {
namespace {

const std::vector<Address> kNoCallers;

/// A JNI entry point is reachable only from the Java side, so nothing in the
/// native image calls it and descent would never find it. For an APK these are
/// often the only interesting roots, so they are recognised by name.
bool isJniExport(const std::string& name) {
    if (name == "JNI_OnLoad" || name == "JNI_OnUnload") return true;
    return name.compare(0, 5, "Java_") == 0;
}

std::string cleanOperand(std::string value) {
    while (!value.empty() &&
           (std::isspace(static_cast<unsigned char>(value.front())) ||
            value.front() == '[')) {
        value.erase(value.begin());
    }
    while (!value.empty() &&
           (std::isspace(static_cast<unsigned char>(value.back())) ||
            value.back() == ']')) {
        value.pop_back();
    }
    return value;
}

std::vector<std::string> commaFields(const std::string& operands) {
    std::vector<std::string> fields;
    size_t start = 0;
    while (start <= operands.size()) {
        const size_t comma = operands.find(',', start);
        fields.push_back(cleanOperand(
            operands.substr(start, comma == std::string::npos
                                       ? std::string::npos : comma - start)));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return fields;
}

bool registerNumber(const std::string& operand, unsigned* number) {
    const std::string value = cleanOperand(operand);
    if (value.size() < 2 || (value[0] != 'x' && value[0] != 'w')) return false;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(value.c_str() + 1, &end, 10);
    if (end == value.c_str() + 1 || *end != '\0' || parsed > 30) return false;
    *number = static_cast<unsigned>(parsed);
    return true;
}

bool immediateValue(const std::string& operand, u64* value) {
    std::string text = cleanOperand(operand);
    if (!text.empty() && text[0] == '#') text.erase(text.begin());
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(text.c_str(), &end, 0);
    if (end == text.c_str() || *end != '\0') return false;
    *value = static_cast<u64>(parsed);
    return true;
}

bool shiftAmount(const std::string& operand, unsigned* shift) {
    const std::string text = cleanOperand(operand);
    if (text.compare(0, 3, "lsl") != 0) return false;
    const size_t marker = text.find('#');
    if (marker == std::string::npos) return false;
    u64 value = 0;
    if (!immediateValue(text.substr(marker), &value) || value >= 63) return false;
    *shift = static_cast<unsigned>(value);
    return true;
}

struct ArmWindowInsn {
    Address address = 0;
    std::string mnemonic;
    std::vector<std::string> operands;
};

bool functionExtent(const ElfImage& image, Address entry,
                    Address* low, Address* high) {
    const ElfSymbol* best = nullptr;
    for (const ElfSymbol& symbol : image.symbols()) {
        if (!symbol.isFunction() || symbol.undefined || symbol.value != entry ||
            symbol.size == 0) {
            continue;
        }
        if (best == nullptr || symbol.size < best->size) best = &symbol;
    }
    if (best == nullptr ||
        best->value > std::numeric_limits<Address>::max() - best->size) {
        return false;
    }
    *low = best->value;
    *high = best->value + best->size;
    return true;
}

i64 signedTableEntry(u64 value, u32 width) {
    if (width == 0 || width >= 8) return static_cast<i64>(value);
    const unsigned bits = width * 8;
    const u64 sign = u64(1) << (bits - 1);
    const u64 mask = (u64(1) << bits) - 1;
    value &= mask;
    return static_cast<i64>((value ^ sign) - sign);
}

/// A RIP-relative branch through an immutable pointer slot is independent of
/// register state and predecessor paths. Mutable GOT/function-pointer slots
/// cannot prove a target because runtime writes may replace their value.
bool recoverImmutableX86Pointer(const ElfImage& image, const InsnRecord& record,
                                Address* target) {
    if ((image.arch() != Arch::kX86_64 && image.arch() != Arch::kX86_32) ||
        (record.flow != FlowKind::kIndirectCall && record.flow != FlowKind::kIndirectJump)) return false;
    const ByteView bytes = image.memory().viewAt(record.address, record.size);
    u8 opcode = 0, modrm = 0;
    size_t prefix = 0;
    if (record.size == 7) {
        u8 rex = 0;
        if (!bytes.byteAt(0, &rex) || rex != 0x48) return false;
        prefix = 1;
    } else if (record.size != 6) return false;
    if (!bytes.byteAt(prefix, &opcode) || opcode != 0xff ||
        !bytes.byteAt(prefix + 1, &modrm) ||
        modrm != (record.flow == FlowKind::kIndirectJump ? 0x25 : 0x15)) return false;
    i32 displacement = 0;
    if (!bytes.read(prefix + 2, &displacement)) return false;
    Address slot = image.arch() == Arch::kX86_32 ? static_cast<u32>(displacement) : record.next();
    if (image.arch() == Arch::kX86_32) {
        // IA-32 mod=00,r/m=101 is an absolute disp32 slot, not RIP-relative.
    } else if (displacement >= 0) {
        if (slot > std::numeric_limits<Address>::max() - static_cast<u32>(displacement)) return false;
        slot += static_cast<u32>(displacement);
    } else {
        const u64 magnitude = static_cast<u64>(-static_cast<i64>(displacement));
        if (slot < magnitude) return false;
        slot -= magnitude;
    }
    const MemorySegment* segment = image.memory().segmentAt(slot);
    if (segment == nullptr || segment->writable() ||
        image.memory().viewAt(slot, image.pointerSize()).size() != image.pointerSize() ||
        !image.resolvePointer(slot, target)) return false;
    return image.memory().isExecutable(*target);
}

/// Recovers the compact AArch64 PIC switch emitted by Clang:
///
///   cmp   wIndex, #max
///   adr   xTable, table
///   adr   xBase, case0
///   ldrh  wEntry, [xTable, xIndex, lsl #1]
///   add   xTarget, xBase, xEntry, lsl #2
///   br    xTarget
///
/// This runs during descent, before CodeMap is finalised, so following the
/// targets brings the case bodies into the function instead of discovering a
/// table only after the CFG has already lost them.
bool recoverArm64PicSwitch(const ElfImage& image, Disassembler* disassembler,
                           Address functionEntry, Address branch,
                           std::vector<Address>* targets) {
    targets->clear();
    if (image.arch() != Arch::kAArch64 || branch < 4) return false;

    DecodedInsn branchInsn;
    ByteView branchBytes = image.memory().viewAt(branch, 4);
    if (branchBytes.size() < 4 ||
        !disassembler->decodeVerbose(branch, branchBytes, &branchInsn) ||
        branchInsn.mnemonic != "br") {
        return false;
    }
    const std::vector<std::string> branchFields =
        commaFields(branchInsn.operands);
    unsigned targetRegister = 0;
    if (branchFields.size() != 1 ||
        !registerNumber(branchFields[0], &targetRegister)) {
        return false;
    }

    std::vector<ArmWindowInsn> window;
    constexpr unsigned kWindow = 20;
    const Address earliest =
        branch >= kWindow * 4 ? branch - kWindow * 4 : 0;
    for (Address address = earliest; address < branch; address += 4) {
        DecodedInsn decoded;
        ByteView bytes = image.memory().viewAt(address, 4);
        if (bytes.size() < 4 ||
            !disassembler->decodeVerbose(address, bytes, &decoded)) {
            continue;
        }
        window.push_back(
            ArmWindowInsn{address, decoded.mnemonic,
                          commaFields(decoded.operands)});
    }

    int addPosition = -1;
    unsigned baseRegister = 0;
    unsigned entryRegister = 0;
    unsigned targetShift = 0;
    for (int i = static_cast<int>(window.size()) - 1; i >= 0; --i) {
        const ArmWindowInsn& candidate = window[static_cast<size_t>(i)];
        if (candidate.mnemonic != "add" || candidate.operands.size() != 4) {
            continue;
        }
        unsigned destination = 0;
        if (registerNumber(candidate.operands[0], &destination) &&
            destination == targetRegister &&
            registerNumber(candidate.operands[1], &baseRegister) &&
            registerNumber(candidate.operands[2], &entryRegister) &&
            shiftAmount(candidate.operands[3], &targetShift)) {
            addPosition = i;
            break;
        }
    }
    if (addPosition < 0) return false;

    int loadPosition = -1;
    unsigned tableRegister = 0;
    unsigned indexRegister = 0;
    unsigned tableShift = 0;
    u32 entryWidth = 0;
    bool signedEntry = false;
    for (int i = addPosition - 1; i >= 0; --i) {
        const ArmWindowInsn& candidate = window[static_cast<size_t>(i)];
        if (candidate.operands.size() != 4) continue;
        if (candidate.mnemonic == "ldrb") entryWidth = 1;
        else if (candidate.mnemonic == "ldrh") entryWidth = 2;
        else if (candidate.mnemonic == "ldr") entryWidth = 4;
        else if (candidate.mnemonic == "ldrsb") {
            entryWidth = 1;
            signedEntry = true;
        } else if (candidate.mnemonic == "ldrsh") {
            entryWidth = 2;
            signedEntry = true;
        } else if (candidate.mnemonic == "ldrsw") {
            entryWidth = 4;
            signedEntry = true;
        } else {
            continue;
        }
        unsigned destination = 0;
        if (registerNumber(candidate.operands[0], &destination) &&
            destination == entryRegister &&
            registerNumber(candidate.operands[1], &tableRegister) &&
            registerNumber(candidate.operands[2], &indexRegister) &&
            shiftAmount(candidate.operands[3], &tableShift)) {
            loadPosition = i;
            break;
        }
        entryWidth = 0;
        signedEntry = false;
    }
    if (loadPosition < 0 || entryWidth == 0 ||
        (u64(1) << tableShift) < entryWidth) {
        return false;
    }

    Address tableBase = 0;
    Address targetBase = 0;
    bool haveTableBase = false;
    bool haveTargetBase = false;
    u32 count = 0;
    for (int i = loadPosition - 1; i >= 0; --i) {
        const ArmWindowInsn& candidate = window[static_cast<size_t>(i)];
        if (candidate.mnemonic == "adr" && candidate.operands.size() == 2) {
            unsigned destination = 0;
            u64 immediate = 0;
            if (!registerNumber(candidate.operands[0], &destination) ||
                !immediateValue(candidate.operands[1], &immediate)) {
                continue;
            }
            if (!haveTableBase && destination == tableRegister) {
                tableBase = immediate;
                haveTableBase = true;
            }
            if (!haveTargetBase && destination == baseRegister) {
                targetBase = immediate;
                haveTargetBase = true;
            }
        }
        if (candidate.mnemonic == "cmp" && candidate.operands.size() == 2) {
            unsigned compared = 0;
            u64 maximum = 0;
            if (registerNumber(candidate.operands[0], &compared) &&
                compared == indexRegister &&
                immediateValue(candidate.operands[1], &maximum) &&
                maximum < 256) {
                count = static_cast<u32>(maximum + 1);
            }
        }
    }
    if (!haveTableBase || !haveTargetBase || count < 2) return false;

    Address functionLow = 0;
    Address functionHigh = 0;
    if (!functionExtent(image, functionEntry, &functionLow, &functionHigh)) {
        return false;
    }

    const u64 tableStride = u64(1) << tableShift;
    const u64 targetScale = u64(1) << targetShift;
    for (u32 index = 0; index < count; ++index) {
        u64 raw = 0;
        const Address slot = tableBase + u64(index) * tableStride;
        if (!image.memory().read(slot, &raw, entryWidth)) return false;
        const i64 entry = signedEntry ? signedTableEntry(raw, entryWidth)
                                      : static_cast<i64>(raw);
        const Address target = static_cast<Address>(
            static_cast<i64>(targetBase) +
            entry * static_cast<i64>(targetScale));
        if (target < functionLow || target >= functionHigh ||
            !image.memory().isExecutable(target)) {
            targets->clear();
            return false;
        }
        if (std::find(targets->begin(), targets->end(), target) ==
            targets->end()) {
            targets->push_back(target);
        }
    }
    return targets->size() >= 2;
}

}  // namespace

const char* functionOriginName(FunctionOrigin origin) {
    switch (origin) {
        case FunctionOrigin::kEntryPoint: return "entry-point";
        case FunctionOrigin::kSymbol: return "symbol";
        case FunctionOrigin::kInitializer: return "initializer";
        case FunctionOrigin::kCallTarget: return "call-target";
        case FunctionOrigin::kPltStub: return "plt-stub";
        case FunctionOrigin::kJniExport: return "jni-export";
        case FunctionOrigin::kUser: return "user";
        case FunctionOrigin::kUnwind: return "unwind";
        case FunctionOrigin::kRelocation: return "relocation";
        case FunctionOrigin::kLinearSweep: return "linear-sweep";
        case FunctionOrigin::kDwarf: return "dwarf";
    }
    return "?";
}

void CodeAnalyzer::addWarning(std::string message) {
    if (warnings_.size() < 256) warnings_.push_back(std::move(message));
}

void CodeAnalyzer::seedRoot(Address addr, FunctionOrigin origin, std::string name,
                            std::vector<Root>* roots) {
    if (addr == kNoAddress) return;
    Arch mode = Arch::kUnknown;
    if (imageArch_ == Arch::kArm32 || imageArch_ == Arch::kThumb) {
        if (addr & 1) mode = Arch::kThumb;
        addr &= ~Address{1};
        if (mode == Arch::kUnknown) {
            const auto hint = branchModeHints_.find(addr);
            if (hint != branchModeHints_.end()) mode = hint->second;
        }
    }
    if (!knownEntries_.insert(addr).second) return;
    roots->push_back(Root{addr, origin, std::move(name), mode});
}

void CodeAnalyzer::collectRoots(const ElfImage& image, const Options& options,
                               std::vector<Root>* roots) {
    for (Address address : debugFunctionEntries_) {
        functionBoundaries_.insert(address);
        seedRoot(address, FunctionOrigin::kDwarf, image.describeAddress(address), roots);
    }
    // Order matters only for naming: whichever origin claims an address first
    // keeps it, so the more informative origins go first.
    if (image.entryPoint() != 0 || image.format() == ImageFormat::kRaw) {
        functionBoundaries_.insert(image.entryPoint());
        std::string name="_start";
        for(const auto& symbol:image.symbols())if(symbol.isFunction() && !symbol.undefined && image.canonicalAddress(symbol.value)==image.entryPoint()){name=symbol.name;break;}
        seedRoot(image.entryPoint(), FunctionOrigin::kEntryPoint, std::move(name), roots);
    }

    // Initialisers before everything else. These run before any Java code touches
    // the library, which is why packers and anti-debug checks live here, and they
    // are the roots a user most wants to see first.
    for (Address pointer : image.initializers()) {
        const Address addr = image.canonicalAddress(pointer);
        functionBoundaries_.insert(addr);
        std::string name = image.describeAddress(addr);
        seedRoot(pointer, FunctionOrigin::kInitializer, std::move(name), roots);
    }
    for (Address pointer : image.finalizers()) {
        const Address addr = image.canonicalAddress(pointer);
        functionBoundaries_.insert(addr);
        std::string name = image.describeAddress(addr);
        seedRoot(pointer, FunctionOrigin::kInitializer, std::move(name), roots);
    }

    for (const ElfSymbol& symbol : image.symbols()) {
        if (!symbol.isFunction() || symbol.undefined) continue;
        if (symbol.value == 0 && !image.memory().isExecutable(0)) continue;
        if (!image.memory().isExecutable(symbol.value)) continue;

        functionBoundaries_.insert(symbol.value);

        const FunctionOrigin origin = isJniExport(symbol.name)
                                          ? FunctionOrigin::kJniExport
                                          : FunctionOrigin::kSymbol;
        seedRoot(symbol.value, origin, symbol.name, roots);
    }

    // PLT stubs are real code and the listing should name them, but they are a
    // handful of instructions of linker glue, so they are seeded last and never
    // treated as interesting.
    //
    // They must be boundaries. A tail call to an imported function compiles to a
    // plain branch into a PLT stub, and without a boundary here the descent walks
    // into the stub and appends its instructions to the caller — which is exactly
    // the systematic overrun the symbol-extent check caught.
    for (const auto& stub : image.pltStubs()) {
        functionBoundaries_.insert(stub.first);
        seedRoot(stub.first, FunctionOrigin::kPltStub, stub.second + "@plt", roots);
    }

    std::vector<std::string> unwindWarnings;
    for (const UnwindFunctionRoot& unwind :
         collectUnwindRoots(image, options.maxFunctions, &unwindWarnings)) {
        const Address address = image.canonicalAddress(unwind.entry);
        ArchitectureDescription description;
        if (excluded(address) || !architectureDescription(image.architectureAt(unwind.entry), &description) ||
            address % description.instructionAlignment != 0) continue;
        functionBoundaries_.insert(address);
        seedRoot(unwind.entry, FunctionOrigin::kUnwind,
                 image.describeAddress(unwind.entry), roots);
    }
    for (std::string& warning : unwindWarnings) addWarning(std::move(warning));
    size_t runtimeRoots=0;
    for(const auto& runtime:image.runtimeFunctions()) {
        if(runtimeRoots>=options.maxFunctions){addWarning("runtime function-root limit reached");break;}
        const auto address=image.canonicalAddress(runtime.start);ArchitectureDescription description;
        if(runtime.end<=runtime.start || excluded(address) || !image.memory().isExecutable(address) ||
           !architectureDescription(image.architectureAt(runtime.start),&description) || address%description.instructionAlignment)continue;
        functionBoundaries_.insert(address);
        if(image.memory().isExecutable(runtime.end-1))functionBoundaries_.insert(runtime.end);
        seedRoot(runtime.start,FunctionOrigin::kUnwind,image.describeAddress(runtime.start),roots);++runtimeRoots;
    }

    // Only pointer-valued relocations are roots. Reading an arbitrary PC32
    // instruction operand as a 64-bit pointer can invent plausible addresses.
    // Defined function symbols referenced by any relocation are safe seeds too.
    size_t relocationRoots = 0;
    for (const ElfRelocation& relocation : image.relocations()) {
        if (relocationRoots >= options.maxFunctions) {
            addWarning("relocation function-root limit reached");
            break;
        }
        const ElfSymbol* symbol = relocation.symbolName.empty()
            ? nullptr : image.findSymbol(relocation.symbolName);
        Address target = 0;
        const bool definedFunction = symbol != nullptr && !symbol->undefined &&
                                     symbol->isFunction() && relocation.addend == 0;
        const bool pointerRelocation = image.arch() == Arch::kAArch64
            ? (relocation.type == elf::kRAArch64Abs64 || relocation.type == elf::kRAArch64GlobDat ||
               relocation.type == elf::kRAArch64JumpSlot || relocation.type == elf::kRAArch64Relative ||
               relocation.type == elf::kRAArch64IRelative)
            : ((image.arch() == Arch::kX86_64 || image.arch() == Arch::kX86_32) &&
               (relocation.type == elf::kRX86_64_64 || relocation.type == elf::kRX86_64GlobDat ||
                relocation.type == elf::kRX86_64JumpSlot || relocation.type == elf::kRX86_64Relative ||
                relocation.type == elf::kRX86_64IRelative || (image.arch() == Arch::kX86_32 && relocation.type == 42))) ||
              ((image.arch() == Arch::kArm32 || image.arch() == Arch::kThumb) &&
               (relocation.type == 2 || relocation.type == 21 || relocation.type == 22 || relocation.type == 23 || relocation.type == 160)) ||
              ((image.arch() == Arch::kRiscV32 || image.arch() == Arch::kRiscV64) &&
               (relocation.type == 1 || relocation.type == 2 || relocation.type == 3 || relocation.type == 5 || relocation.type == 58));
        if (definedFunction) target = symbol->value;
        else if (!pointerRelocation || !image.resolvePointer(relocation.offset, &target)) continue;
        const Address canonical = image.canonicalAddress(target);
        ArchitectureDescription description;
        if (!image.memory().isExecutable(canonical) || excluded(canonical) ||
            !architectureDescription(image.architectureAt(target), &description) || canonical % description.instructionAlignment != 0) continue;
        functionBoundaries_.insert(canonical);
        if (knownEntries_.count(canonical) == 0) {
            seedRoot(target, FunctionOrigin::kRelocation, image.describeAddress(target), roots);
            ++relocationRoots;
        }
    }

    sortedFunctionBoundaries_.assign(functionBoundaries_.begin(), functionBoundaries_.end());
    std::sort(sortedFunctionBoundaries_.begin(), sortedFunctionBoundaries_.end());

    MINT_LOGI("seeded %zu analysis roots, %zu function boundaries", roots->size(),
              functionBoundaries_.size());
}

bool CodeAnalyzer::excluded(Address address) const {
    const auto next = std::upper_bound(excludedRanges_.begin(), excludedRanges_.end(), address,
        [](Address value, const AddressRange& range) { return value < range.start; });
    if (next == excludedRanges_.begin()) return false;
    return address < (next - 1)->end;
}

size_t CodeAnalyzer::decodeLimit(Address address, size_t requested) const {
    if (excluded(address)) return 0;
    const auto nextData = std::upper_bound(excludedRanges_.begin(), excludedRanges_.end(), address,
        [](Address value, const AddressRange& range) { return value < range.start; });
    if (nextData != excludedRanges_.end()) {
        requested = static_cast<size_t>(std::min<u64>(requested, nextData->start - address));
    }
    const auto nextFunction = std::upper_bound(sortedFunctionBoundaries_.begin(),
                                              sortedFunctionBoundaries_.end(), address);
    if (nextFunction != sortedFunctionBoundaries_.end()) {
        requested = static_cast<size_t>(std::min<u64>(requested, *nextFunction - address));
    }
    return requested;
}

bool CodeAnalyzer::decodeRecord(const ElfImage& image, Address address, InsnRecord* record,
                               Address functionEntry, Arch functionArch) {
    Arch desired = functionEntry == kNoAddress ? image.architectureAt(address) :
        image.architectureAt(address, functionEntry, functionArch);
    if (functionEntry == kNoAddress) {
        const auto saved = instructionArchitectures_.find(address);
        if (saved != instructionArchitectures_.end()) desired = saved->second;
    }
    if (disassembler_.arch() != desired && !disassembler_.open(desired).ok()) return false;
    const ByteView bytes = image.memory().viewAt(
        address, decodeLimit(address, disassembler_.maxInstructionSize()));
    if (bytes.empty()) return false;
    const bool decoded = disassembler_.decode(address, bytes, record);
    instructionArchitectures_[address] = desired;
    if (!decoded) {
        record->flow = FlowKind::kInvalid;
        record->size = static_cast<u8>(std::min<size_t>(record->size, bytes.size()));
    } else {
        if (record->hasKnownTarget() && (image.arch() == Arch::kArm32 || image.arch() == Arch::kThumb)) {
            branchModeHints_[image.canonicalAddress(record->target)] = (record->target & 1) ? Arch::kThumb : Arch::kArm32;
            record->target = image.canonicalAddress(record->target);
        }
        Address target = kNoAddress;
        if (recoverImmutableX86Pointer(image, *record, &target) && !excluded(target)) {
            record->target = target;
        }
    }
    return decoded;
}

bool CodeAnalyzer::recoverBranchTargets(const ElfImage& image, Address functionEntry,
                                        const InsnRecord& record, std::vector<Address>* targets) {
    targets->clear();
    if (record.flow != FlowKind::kIndirectJump) return false;
    if (record.hasKnownTarget()) targets->push_back(record.target);
    else if (const auto* proven = provenIndirectSite(functionEntry, record.address, false)) {
        for (const auto& target : proven->targets) targets->push_back(target.address);
    }
    else if (!recoverArm64PicSwitch(image, &disassembler_, functionEntry, record.address, targets)) return false;
    targets->erase(std::remove_if(targets->begin(), targets->end(),
                  [this](Address target) { return excluded(target); }), targets->end());
    return true;
}

void CodeAnalyzer::descend(const ElfImage& image, const Options& options,
                           const Root& root, std::vector<Root>* pending) {
    const MemoryMap& memory = image.memory();
    if (!memory.isExecutable(root.address) || excluded(root.address)) return;

    Function function;
    function.entry = root.address;
    function.name = root.name;
    function.origin = root.origin;
    function.decodeArch = root.decodeArch == Arch::kUnknown ? image.architectureAt(root.address) : root.decodeArch;
    function.lowAddress = root.address;
    function.highAddress = root.address;

    // Visited is per function, while the code map is global. An address decoded
    // by an earlier function is not re-decoded, but it is still walked here so
    // that shared code appears in both functions' bodies — which is the correct
    // answer for hand-written assembly and for obfuscators that deliberately
    // overlap function bodies.
    std::unordered_set<Address> visited;
    std::vector<Address> worklist;
    worklist.push_back(root.address);

    std::unordered_set<Address> callees;

    // A symbol saying "a function starts here" also says the previous function
    // ended. Without this, a `bl` whose target happens to be the very next
    // address — which is how a call to a noreturn handler placed immediately
    // after the caller compiles — makes the fall-through walk straight into the
    // callee, and the two functions merge into one.
    auto crossesIntoAnotherFunction = [&](Address addr) {
        return addr != function.entry && functionBoundaries_.count(addr) != 0;
    };

    // Follows an address unless doing so would leave this function.
    auto follow = [&](Address addr) {
        if (excluded(addr)) return;
        const auto mode = branchModeHints_.find(addr);
        const bool interworking = (function.decodeArch == Arch::kArm32 || function.decodeArch == Arch::kThumb) &&
            mode != branchModeHints_.end() && mode->second != function.decodeArch;
        if (crossesIntoAnotherFunction(addr) || interworking) {
            callees.insert(addr);
            if (options.followCalls) {
                const auto hint = branchModeHints_.find(addr);
                pending->push_back(Root{addr, FunctionOrigin::kCallTarget, {}, hint == branchModeHints_.end() ? Arch::kUnknown : hint->second});
            }
            return;
        }
        worklist.push_back(addr);
    };

    while (!worklist.empty()) {
        if (options.cancel != nullptr && options.cancel->load(std::memory_order_relaxed)) {
            function.incomplete = true;
            break;
        }
        const Address addr = worklist.back();
        worklist.pop_back();

        if (!visited.insert(addr).second) continue;

        if (code_.size() >= options.maxInstructions) {
            stats_.reachedInstructionLimit = 1;
            function.incomplete = true;
            break;
        }
        if (excluded(addr)) continue;
        if (!memory.isExecutable(addr)) {
            // A branch out of executable memory is not something to follow, and
            // it is a strong signal on its own.
            function.incomplete = true;
            continue;
        }

        // The code map is not finalised during discovery, so it can only answer
        // membership, not hand back a record. Re-decoding an address a second
        // function also reaches is cheaper than carrying a discovery-time record
        // index for the sake of the rare shared-code case.
        if (memory.viewAt(addr, decodeLimit(addr, disassembler_.maxInstructionSize())).empty()) {
            function.incomplete = true;
            continue;
        }

        InsnRecord record;
        bool decoded = decodeRecord(image, addr, &record, function.entry, function.decodeArch);

        const Address staticIndirectTarget = decoded &&
            (record.flow == FlowKind::kIndirectCall || record.flow == FlowKind::kIndirectJump)
            ? record.target : kNoAddress;

        if (!decoded) {
            record.address = addr;
            record.flow = FlowKind::kInvalid;
            ++function.undecodableSites;
            ++stats_.undecodableSites;
            function.incomplete = true;
        }

        code_.insert(record);
        if (options.progress != nullptr && options.progressTotalBytes != 0) {
            const size_t covered = std::min(options.progressTotalBytes, code_.size());
            const int value = 10 + static_cast<int>(covered * 75 / options.progressTotalBytes);
            options.progress->store(std::min(85, value), std::memory_order_relaxed);
        }
        function.instructions.push_back(addr);
        function.lowAddress = std::min(function.lowAddress, record.address);
        function.highAddress = std::max(function.highAddress, record.next());

        if (!decoded) continue;

        switch (record.flow) {
            case FlowKind::kNormal:
                follow(record.next());
                break;

            case FlowKind::kCondJump:
                follow(record.next());
                if (record.hasKnownTarget()) follow(record.target);
                else function.incomplete = true;
                break;

            case FlowKind::kJump:
                // An unconditional branch out of this function is a tail call, and
                // follow() already treats a branch to another function's entry that
                // way. A chain of tail-calling functions would otherwise collapse
                // into one enormous body whose decompilation is unreadable.
                if (record.hasKnownTarget()) follow(record.target);
                else function.incomplete = true;
                break;

            case FlowKind::kCall:
                if (record.hasKnownTarget()) {
                    if (!excluded(record.target)) callees.insert(record.target);
                    if (options.followCalls && !excluded(record.target)) {
                        const auto hint = branchModeHints_.find(record.target);
                        pending->push_back(Root{record.target, FunctionOrigin::kCallTarget, {},
                            hint == branchModeHints_.end() ? Arch::kUnknown : hint->second});
                    }
                }
                // The return lands on the following instruction — unless that
                // address is another function's entry, in which case the callee
                // never returns and this function is over.
                follow(record.next());
                break;

            case FlowKind::kIndirectCall:
                // The callee is unknown but control returns, so the function body
                // continues. Not a completeness problem.
                if (staticIndirectTarget != kNoAddress) {
                    callees.insert(staticIndirectTarget);
                    if (options.followCalls) {
                        pending->push_back(Root{staticIndirectTarget, FunctionOrigin::kCallTarget, {}, image.architectureAt(staticIndirectTarget)});
                    }
                }
                if (const auto* proven = provenIndirectSite(function.entry, record.address, true)) {
                    for (const auto& target : proven->targets) {
                        if (excluded(target.address)) continue;
                        callees.insert(target.address);
                        branchModeHints_[target.address] = target.decodeArch;
                        if (options.followCalls) pending->push_back(Root{target.address, FunctionOrigin::kCallTarget, {}, target.decodeArch});
                    }
                }
                follow(record.next());
                break;

            case FlowKind::kIndirectJump:
                // The one that actually costs us coverage: no target, and control
                // does not come back. This is the shape of both a switch jump table
                // and an OLLVM dispatcher, and resolving it is what the emulator
                // and jump-table recovery are for.
                ++function.indirectJumps;
                ++stats_.indirectJumps;
                {
                    std::vector<Address> targets;
                    if (recoverBranchTargets(image, function.entry, record, &targets)) {
                        if (const auto* proven = provenIndirectSite(function.entry, record.address, false))
                            for (const auto& target : proven->targets) branchModeHints_[target.address] = target.decodeArch;
                        function.resolvedIndirectJumps.push_back(
                            ResolvedIndirectJump{record.address, targets});
                        for (Address target : targets) follow(target);
                    } else {
                        function.incomplete = true;
                    }
                }
                break;

            case FlowKind::kReturn:
            case FlowKind::kTrap:
            case FlowKind::kInvalid:
                break;
        }
    }

    if (function.instructions.empty()) return;

    std::sort(function.instructions.begin(), function.instructions.end());
    function.callees.assign(callees.begin(), callees.end());
    std::sort(function.callees.begin(), function.callees.end());

    functions_.push_back(std::move(function));
}

void CodeAnalyzer::linearSweep(const ElfImage& image, const Options& options,
                               std::vector<Root>* pending) {
    // Descent only reaches what something branches to. In a stripped library with
    // few exports that can leave most of .text untouched, so any executable
    // stretch that descent never covered is swept for plausible function starts.
    //
    // Restricted to AArch64. Fixed-width instructions make a sweep well-aligned
    // and its results trustworthy; on x86-64 a sweep that begins mid-instruction
    // yields convincing nonsense, and inventing false functions is worse than
    // reporting a gap.
    if (image.arch() != Arch::kAArch64) {
        addWarning(
            "linear-sweep fallback is AArch64-only; unreached code in this " + std::string(archName(image.arch())) +
            " image was left undecoded rather than guessed at");
        return;
    }

    const size_t before = pending->size();

    for (const ElfSection& section : image.sections()) {
        if (!section.executable() || section.size == 0) continue;

        if (section.addr > std::numeric_limits<Address>::max() - section.size) continue;
        const Address sectionEnd = section.addr + section.size;
        for (Address addr = section.addr; addr <= sectionEnd && sectionEnd - addr >= 4;
             addr += 4) {
            if (options.cancel != nullptr && options.cancel->load(std::memory_order_relaxed)) return;
            if (decodeLimit(addr, 4) < 4) continue;
            if (code_.contains(addr)) continue;
            if (knownEntries_.count(addr) != 0) continue;

            ByteView bytes = image.memory().viewAt(addr, 4);
            if (bytes.size() < 4) continue;

            InsnRecord record;
            if (!disassembler_.decode(addr, bytes, &record)) continue;

            // Only treat a gap as a function start if it looks like one. A
            // prologue that saves the frame pointer and link register is the
            // overwhelmingly common opening on AArch64; anything else is more
            // likely the middle of a function whose entry we already missed, and
            // seeding it would produce a bogus function.
            u32 word = 0;
            if (!bytes.read<u32>(0, &word)) continue;

            // stp x29, x30, [sp, #imm]  /  stp x29, x30, [sp, #-imm]!
            const bool framePush = (word & 0xffc07fffu) == 0xa9807bfdu ||
                                   (word & 0xffc07fffu) == 0xa9007bfdu;
            // sub sp, sp, #imm — a leaf function with locals and no frame record.
            const bool stackAlloc = (word & 0xffc003ffu) == 0xd10003ffu;
            // paciasp — the first instruction of any function built with pointer
            // authentication, which is the default in current NDKs.
            const bool pacPrologue = word == 0xd503233fu;

            if (!framePush && !stackAlloc && !pacPrologue) continue;

            if (pending->size() - before >= options.maxFunctions) break;
            pending->push_back(Root{addr, FunctionOrigin::kLinearSweep, {}});
            knownEntries_.insert(addr);
        }
    }

    stats_.functionsFromSweep = pending->size() - before;
    if (stats_.functionsFromSweep > 0) {
        MINT_LOGI("linear sweep found %zu additional function candidates",
                  stats_.functionsFromSweep);
    }
}

void CodeAnalyzer::buildIndexes() {
    functionByEntry_.reserve(functions_.size());
    for (size_t i = 0; i < functions_.size(); ++i) {
        functionByEntry_.emplace(functions_[i].entry, i);
    }

    // Lowest entry wins for shared instructions, which makes the mapping stable
    // regardless of discovery order.
    std::vector<size_t> order(functions_.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return functions_[a].entry < functions_[b].entry;
    });

    for (size_t index : order) {
        for (Address addr : functions_[index].instructions) {
            functionByInstruction_.emplace(addr, index);
        }
    }

    for (const Function& function : functions_) {
        for (Address callee : function.callees) {
            callers_[callee].push_back(function.entry);
        }
    }
    for (auto& entry : callers_) {
        std::sort(entry.second.begin(), entry.second.end());
        entry.second.erase(std::unique(entry.second.begin(), entry.second.end()),
                           entry.second.end());
    }
}

Status CodeAnalyzer::analyze(const ElfImage& image) { return analyze(image, Options()); }

Status CodeAnalyzer::analyzeDiscovery(const ElfImage& image, const Options& options,
                                     const std::map<Address, IndirectFlowReport>& proven) {
    std::vector<Root> pending;
    Status status = prepareState(image, options, &pending);
    if (!status.ok()) return status;
    indirectFlowReports_ = proven;

    Options effective = options;
    for (const MemorySegment& segment : image.memory().segments()) {
        if ((segment.flags & kMemExec) != 0) effective.progressTotalBytes += segment.data.size();
    }
    if (effective.progress != nullptr) effective.progress->store(10, std::memory_order_relaxed);

    // One pass over the worklist, then the sweep, then whatever the sweep added.
    // Descent may append to `pending` while it runs, which is why this is an
    // index walk and not a range-for.
    size_t cursor = 0;
    while (cursor < pending.size()) {
        if (effective.cancel != nullptr && effective.cancel->load(std::memory_order_relaxed)) {
            return Status::error(ErrorCode::kInternalError, "analysis cancelled");
        }
        if (functions_.size() >= effective.maxFunctions) {
            addWarning("function limit of " + std::to_string(effective.maxFunctions) +
                       " reached; analysis is partial");
            break;
        }
        const Root root = pending[cursor++];
        if (root.address == kNoAddress) continue;
        // Roots appended by descent never went through seedRoot, so dedupe here.
        // A set, not a scan over functions_: a large library discovers tens of
        // thousands of call targets and a linear check would make this quadratic.
        if (!analyzed_.insert(root.address).second) continue;
        knownEntries_.insert(root.address);
        descend(image, effective, root, &pending);
    }

    if (effective.linearSweepFallback && functions_.size() < effective.maxFunctions) {
        const size_t sweepStart = pending.size();
        linearSweep(image, effective, &pending);
        for (size_t i = sweepStart; i < pending.size(); ++i) {
            if (effective.cancel != nullptr && effective.cancel->load(std::memory_order_relaxed)) {
                return Status::error(ErrorCode::kInternalError, "analysis cancelled");
            }
            if (functions_.size() >= effective.maxFunctions) break;
            const Root root = pending[i];
            if (!analyzed_.insert(root.address).second) continue;
            descend(image, effective, root, &pending);
        }
    }

    code_.finalize();

    // CFGs are built after the code map is finalised, because building one needs
    // random access to instructions by address.
    // Count materialized sweep functions, not candidates left on the worklist
    // when a resource limit stops analysis. This is reproducible from a snapshot.
    stats_.functionsFromSweep = 0;
    for (Function& function : functions_) {
        function.cfg =
            ControlFlowGraph::build(code_, function.instructions, function.entry,
                                    function.resolvedIndirectJumps);
        stats_.blocks += function.cfg.size();
        stats_.edges += function.cfg.edgeCount();
        if (function.incomplete) ++stats_.incompleteFunctions;
        if (function.origin == FunctionOrigin::kLinearSweep) ++stats_.functionsFromSweep;

        if (function.name.empty()) {
            char buffer[32];
            snprintf(buffer, sizeof(buffer), "sub_%llx",
                     static_cast<unsigned long long>(function.entry));
            function.name = buffer;
        }
    }

    std::sort(functions_.begin(), functions_.end(),
              [](const Function& a, const Function& b) { return a.entry < b.entry; });

    buildIndexes();

    stats_.instructions = code_.size();
    stats_.functions = functions_.size();
    hasState_ = true;
    if (effective.progress != nullptr) effective.progress->store(100, std::memory_order_relaxed);

    MINT_LOGI("analysis: %zu functions, %zu instructions, %zu blocks, %zu edges, "
              "%zu incomplete",
              stats_.functions, stats_.instructions, stats_.blocks, stats_.edges,
              stats_.incompleteFunctions);
    return Status::success();
}

const IndirectFlowSite* CodeAnalyzer::provenIndirectSite(Address entry, Address address, bool call) const {
    const auto report = indirectFlowReports_.find(entry);
    if (report == indirectFlowReports_.end()) return nullptr;
    for (const auto& site : report->second.sites)
        if (site.address == address && site.call == call && site.complete && !site.targets.empty()) return &site;
    return nullptr;
}

bool CodeAnalyzer::sameProvenFlow(const IndirectFlowReport& a, const IndirectFlowReport& b) {
    using Key = std::tuple<Address, bool, Address, Arch>;
    auto keys = [](const IndirectFlowReport& report) {
        std::vector<Key> result;
        for (const auto& site : report.sites) if (site.complete)
            for (const auto& target : site.targets) result.emplace_back(site.address, site.call, target.address, target.decodeArch);
        std::sort(result.begin(), result.end());
        return result;
    };
    return keys(a) == keys(b);
}

Status CodeAnalyzer::proveIndirectFlow(const ElfImage& image, const Function& function, IndirectFlowReport* report) const {
    *report = {}; report->functionEntry = function.entry;
    bool needed = false;
    for (Address address : function.instructions) {
        const auto* record = code_.find(address);
        if (record && (record->flow == FlowKind::kIndirectCall || record->flow == FlowKind::kIndirectJump)) needed = true;
    }
    if (!needed) { report->converged = true; return Status::success(); }
    // One function cannot monopolize a mobile analysis. Unsupported plugin
    // lifters and mixed-mode bodies remain unresolved rather than guessed.
    if (function.instructions.size() > 65536) return Status::success();
    for (Address address : function.instructions) {
        const auto mode = instructionArchitectures_.find(address);
        if (mode != instructionArchitectures_.end() && mode->second != function.decodeArch) return Status::success();
    }
    Lifter lifter; IrFunction ir; SsaFunction ssa;
    if (!lifter.open(function.decodeArch).ok() || !lifter.liftFunction(function, image.memory(), &ir).ok() || !ir.verify().empty()) return Status::success();
    normalizeRegisterAccesses(&ir);
    if (!buildSsa(ir, &ssa).ok() || !ssa.verify().empty()) return Status::success();
    Status status = recoverIndirectFlow(image, ssa, report);
    if (!status.ok()) { *report = {}; report->functionEntry = function.entry; return Status::success(); }
    for (auto& site : report->sites) {
        const auto* record = code_.find(site.address);
        if (!record || (site.call ? record->flow != FlowKind::kIndirectCall : record->flow != FlowKind::kIndirectJump)) site.complete = false;
        for (const auto& target : site.targets) {
            const auto mode = instructionArchitectures_.find(target.address);
            if (excluded(target.address) || (mode != instructionArchitectures_.end() && mode->second != target.decodeArch)) site.complete = false;
        }
        if (!site.complete && site.confidence == IndirectFlowConfidence::kProven) {
            site.confidence = IndirectFlowConfidence::kPartial;
            site.reason = "target conflicts with authoritative data, instruction ownership or decode mode";
        }
    }
    return Status::success();
}

Status CodeAnalyzer::analyze(const ElfImage& image, const Options& options) {
    std::map<Address, IndirectFlowReport> proofs;
    Options effective = options;
    // Discovery can repeat when proven SSA edges expose previously unseen
    // blocks. Expose phase progress instead of prematurely reporting 100%.
    effective.progress = nullptr;
    if (options.progress) options.progress->store(10, std::memory_order_relaxed);
    for (unsigned round = 0; round < 8; ++round) {
        if (options.cancel && options.cancel->load(std::memory_order_relaxed)) return Status::error(ErrorCode::kInternalError, "analysis cancelled");
        Status status = analyzeDiscovery(image, effective, proofs);
        if (!status.ok()) return status;
        std::map<Address, IndirectFlowReport> current;
        size_t liftedInstructions = 0;
        for (const auto& function : functions_) {
            if (options.cancel && options.cancel->load(std::memory_order_relaxed)) return Status::error(ErrorCode::kInternalError, "analysis cancelled");
            IndirectFlowReport report; report.functionEntry = function.entry;
            bool needed = function.indirectJumps != 0;
            if (!needed) for (Address address : function.instructions) {
                const auto* record = code_.find(address);
                if (record && record->flow == FlowKind::kIndirectCall) { needed = true; break; }
            }
            if (!needed) continue;
            // Global bound complements each pass's finite-set operation limit.
            if (function.instructions.size() <= 1000000 - std::min<size_t>(1000000, liftedInstructions)) {
                proveIndirectFlow(image, function, &report);
                liftedInstructions += function.instructions.size();
            }
            if (!report.sites.empty()) current.emplace(function.entry, std::move(report));
        }
        bool changed = false;
        const IndirectFlowReport empty;
        for (const auto& pair : proofs) {
            const auto found = current.find(pair.first);
            if (!sameProvenFlow(pair.second, found == current.end() ? empty : found->second)) { changed = true; break; }
        }
        if (!changed) for (const auto& pair : current) {
            const auto found = proofs.find(pair.first);
            if (!sameProvenFlow(pair.second, found == proofs.end() ? empty : found->second)) { changed = true; break; }
        }
        indirectFlowReports_ = current;
        if (!changed) {
            if (options.progress) options.progress->store(100, std::memory_order_relaxed);
            return Status::success();
        }
        proofs = std::move(current);
        if (options.progress) options.progress->store(20 + static_cast<int>((round + 1) * 9), std::memory_order_relaxed);
    }
    // Never retain stale proof edges when widening discovered an unknown path
    // or the fixedpoint exceeded its bound. The ordinary static/table pass is
    // the safe fallback; all failed general evidence remains display-only.
    Status status = analyzeDiscovery(image, effective, {});
    if (status.ok()) {
        addWarning("general indirect-flow fixedpoint limit reached; general CFG targets were left unresolved");
        if (options.progress) options.progress->store(100, std::memory_order_relaxed);
    }
    return status;
}

const Function* CodeAnalyzer::functionAt(Address entry) const {
    auto it = functionByEntry_.find(entry);
    return it == functionByEntry_.end() ? nullptr : &functions_[it->second];
}

const Function* CodeAnalyzer::functionContaining(Address addr) const {
    auto it = functionByInstruction_.find(addr);
    return it == functionByInstruction_.end() ? nullptr : &functions_[it->second];
}

const std::vector<Address>& CodeAnalyzer::callersOf(Address entry) const {
    auto it = callers_.find(entry);
    return it == callers_.end() ? kNoCallers : it->second;
}

}  // namespace mint
