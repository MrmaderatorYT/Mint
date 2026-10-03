#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "mint/decompile/c_emitter.h"
#include "mint/decompile/decompiler.h"
#include "mint/ir/ir_simplify.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"
#include "mint/ir/stack_analysis.h"
#include "mint/ssa/ssa_builder.h"

using namespace mint;

namespace {
size_t checks = 0;
void require(bool condition, const char* message) {
    ++checks;
    if (!condition) { std::fprintf(stderr, "stack analysis: %s\n", message); std::exit(1); }
}

struct Fixture {
    IrFunction ir;
    u64 nextTemp = 0;
    u32 current = 0;
    explicit Fixture(Arch arch, size_t blocks = 1) {
        ir.arch = arch; ir.entry = 0x1000; ir.name = arch == Arch::kAArch64 ? "a64_stack" : "x86_stack";
        ir.blocks.resize(blocks);
        for (u32 i = 0; i < blocks; ++i) {
            ir.blocks[i].id = i; ir.blocks[i].start = 0x1000 + i * 0x100; ir.blocks[i].end = ir.blocks[i].start + 0x100;
        }
    }
    Varnode sp() const { return Varnode::reg(ir.arch == Arch::kAArch64 ? arm64::kSp : x86::kRsp, 8); }
    Varnode fp() const { return Varnode::reg(ir.arch == Arch::kAArch64 ? arm64::kXn(29) : x86::kRbp, 8); }
    Varnode result() const { return Varnode::reg(ir.arch == Arch::kAArch64 ? arm64::kX0 : x86::kRax, 8); }
    Varnode argument() const { return Varnode::reg(ir.arch == Arch::kAArch64 ? arm64::kX0 : x86::kRdi, 8); }
    Varnode temporary(u8 width = 8) { return Varnode::temp(nextTemp++, width); }
    void block(u32 index) { current = index; ir.blocks[index].firstInsn = static_cast<u32>(ir.insns.size()); }
    void add(MintOp op, Varnode dest = Varnode::invalid(), Varnode a = Varnode::invalid(), Varnode b = Varnode::invalid(), Varnode c = Varnode::invalid()) {
        IrInsn insn; insn.op = op; insn.dest = dest; insn.a = a; insn.b = b; insn.c = c;
        insn.address = ir.blocks[current].start + ir.blocks[current].insnCount * 4;
        ir.insns.push_back(insn); ++ir.blocks[current].insnCount; ++ir.machineInsnCount;
    }
    Varnode address(i64 offset, Varnode base = Varnode::invalid()) {
        if (!base.valid()) base = sp();
        Varnode addr = temporary();
        add(offset < 0 ? MintOp::kSub : MintOp::kAdd, addr, base,
            Varnode::constant(static_cast<u64>(offset < 0 ? -offset : offset), 8));
        return addr;
    }
    void store(Varnode address, u64 value = 7, u8 width = 8) {
        add(MintOp::kStore, Varnode::invalid(), address, Varnode::constant(value, width));
    }
    Varnode load(Varnode address, u8 width = 8) {
        Varnode value = temporary(width); add(MintOp::kLoad, value, address); return value;
    }
    void ret(Varnode value) {
        if (value.size == 8) add(MintOp::kCopy, result(), value);
        else add(MintOp::kZeroExt, result(), value);
        add(MintOp::kReturn, Varnode::invalid(), ir.arch == Arch::kAArch64
            ? Varnode::reg(arm64::kXn(30), 8) : Varnode::constant(0x2000, 8));
    }
    SsaFunction ssa() {
        ir.tempCount = static_cast<u32>(nextTemp);
        for (auto& cfg : ir.blocks) for (u32 next : cfg.successors) ir.blocks[next].predecessors.push_back(cfg.id);
        const auto issues = ir.verify();
        for (const auto& issue : issues) std::fprintf(stderr, "%s\n", issue.c_str());
        require(issues.empty(), "fixture IR verification");
        IrFunction normalized = ir; normalizeRegisterAccesses(&normalized);
        SsaFunction result; SsaBuildStats stats;
        require(buildSsa(normalized, &result, &stats).ok(), "build SSA");
        require(result.verify().empty(), "SSA verification");
        return result;
    }
};

StackAnalysis analyze(const SsaFunction& function) {
    StackAnalysis result;
    const Status status = analyzeStackMemory(function, &result);
    if (!status.ok()) std::fprintf(stderr, "%s\n", status.toString().c_str());
    require(status.ok(), "analyze stack memory");
    require(result.values.size() == function.values.size(), "one fact per SSA value");
    require(result.accessByInstruction.size() == function.insns.size(), "instruction binding table");
    return result;
}
const StackSlot* slotAt(const StackAnalysis& result, i64 offset, u8 width) {
    for (const auto& slot : result.slots) if (slot.offset == offset && slot.width == width) return &slot;
    return nullptr;
}
std::vector<const StackAccess*> reads(const StackAnalysis& result) {
    std::vector<const StackAccess*> found;
    for (const auto& access : result.accesses) if (!access.store) found.push_back(&access);
    return found;
}
std::string emit(const SsaFunction& function) {
    return emitC(function, structureControlFlow(function));
}

void leaf(Arch arch) {
    Fixture f(arch); f.block(0);
    f.add(MintOp::kSub, f.sp(), f.sp(), Varnode::constant(32, 8));
    f.add(MintOp::kCopy, f.fp(), f.sp());
    const Varnode address = f.address(8, f.fp()); // entry SP - 24
    f.store(address, 9, 4);
    const Varnode loaded = f.load(address, 4);
    f.add(MintOp::kAdd, f.sp(), f.sp(), Varnode::constant(32, 8)); f.ret(loaded);
    const SsaFunction function = f.ssa(); const StackAnalysis result = analyze(function);
    const StackSlot* slot = slotAt(result, -24, 4);
    require(slot && slot->promoted && slot->initializedBeforeEveryRead && !slot->overlaps, "SP/FP leaf local promoted");
    const auto loads = reads(result);
    require(loads.size() == 1 && loads[0]->reachingStore != kNoValue && loads[0]->memoryVersion, "exact store -> load dependency");
    require(result.storeLoadDependencies == 1 && !result.barriers && !result.unknownAccesses, "leaf memory summary");
    const std::string c = emit(function);
    require(c.find("uint32_t mint_stack_m18_4;") != std::string::npos, "real typed C local");
    require(c.find("mint_stack_m18_4 = 0x9;") != std::string::npos, "store rendered as local assignment");
    require(c.find(" = mint_stack_m18_4;") != std::string::npos, "load rendered as local read");
    require(c.find("*const mint_stack_m18_4") == std::string::npos, "leaf not rendered as pointer-only report");
    DecompileResult decompiled;
    require(decompileIr(f.ir, &decompiled).ok(), "full decompilation path");
    require(decompiled.cSource.find("mint_stack_m18_4") != std::string::npos, "decompiler integrates stack pass");
}

void barrier(Arch arch, bool unknownStore) {
    Fixture f(arch); f.block(0); const Varnode address = f.address(-8);
    f.store(address, 7);
    if (unknownStore) f.add(MintOp::kStore, Varnode::invalid(), f.argument(), Varnode::constant(99, 8));
    else f.add(MintOp::kCall, Varnode::invalid(), Varnode::constant(0x3000, 8));
    const Varnode after = f.load(address); f.ret(after);
    const SsaFunction function = f.ssa(); const StackAnalysis result = analyze(function);
    require(reads(result).size() == 1 && reads(result)[0]->reachingStore == kNoValue && !reads(result)[0]->initialized, "alias/call kills memory dependency");
    const StackSlot* slot = slotAt(result, -8, 8);
    require(slot && !slot->promoted, "barrier forbids local promotion");
    require(unknownStore ? result.unknownWrites == 1 : result.barriers == 1, "barrier counted");
    const std::string c = emit(function);
    require(c.find("uint64_t *const mint_stack_m8_8 =") != std::string::npos, "barrier slot remains memory-backed");
    require(c.find("*mint_stack_m8_8 = 0x7;") != std::string::npos, "memory-backed assignment");
    require(c.find(" = *mint_stack_m8_8;") != std::string::npos, "memory-backed read remains ordered");
}

void overlap(Arch arch) {
    Fixture f(arch); f.block(0); const Varnode wide = f.address(-16); f.store(wide, 7, 8);
    const Varnode partial = f.address(-12); f.store(partial, 9, 4);
    f.ret(f.load(wide, 8));
    const SsaFunction function = f.ssa(); const StackAnalysis result = analyze(function);
    require(slotAt(result, -16, 8) && slotAt(result, -16, 8)->overlaps, "wide slot overlap detected");
    require(slotAt(result, -12, 4) && slotAt(result, -12, 4)->overlaps, "partial slot overlap detected");
    require(reads(result)[0]->reachingStore == kNoValue, "partial write kills whole-slot dependency");
    require(emit(function).find("mint_stack_m10_8;") == std::string::npos, "overlaps are not independent locals");
}

void diamond(Arch arch, bool conflictSp, bool writeBoth) {
    Fixture f(arch, 4);
    f.ir.blocks[0].successors = {1, 2}; f.ir.blocks[1].successors = {3}; f.ir.blocks[2].successors = {3};
    f.block(0);
    const Varnode condition = f.temporary(1);
    f.add(MintOp::kEqual, condition, f.argument(), Varnode::constant(0, 8));
    f.add(MintOp::kCondBranch, Varnode::invalid(), condition, Varnode::constant(0x1100, 8));
    f.block(1);
    f.add(MintOp::kSub, f.sp(), f.sp(), Varnode::constant(16, 8));
    f.store(f.sp(), 11);
    f.add(MintOp::kBranch, Varnode::invalid(), Varnode::constant(0x1300, 8));
    f.block(2);
    f.add(MintOp::kSub, f.sp(), f.sp(), Varnode::constant(conflictSp ? 32 : 16, 8));
    if (writeBoth) f.store(f.sp(), 22);
    f.add(MintOp::kBranch, Varnode::invalid(), Varnode::constant(0x1300, 8));
    f.block(3); f.ret(f.load(f.sp()));
    const SsaFunction function = f.ssa(); const StackAnalysis result = analyze(function);
    if (conflictSp) {
        require(reads(result).empty() && result.unknownStackAccesses == 1, "conflicting SP phi remains unknown");
        for (const auto& slot : result.slots) require(!slot.promoted, "unknown stack read forbids disconnected locals");
        require(emit(function).find("unresolved stack accesses: 1") != std::string::npos, "unknown stack state is explicit");
    } else {
        require(reads(result).size() == 1 && reads(result)[0]->reachingStore == kNoValue, "different incoming stores are not one reaching definition");
        require(reads(result)[0]->initialized == writeBoth, "write-before-read requires every predecessor");
        require(slotAt(result, -16, 8)->promoted == writeBoth, "phi-joined local promoted only with all-path initialization");
    }
}

void loop(Arch arch, bool driftingSp) {
    Fixture f(arch, 3); f.ir.blocks[0].successors = {1}; f.ir.blocks[1].successors = {1, 2};
    f.block(0); const Varnode address = f.address(-8); f.store(address, 7);
    f.add(MintOp::kBranch, Varnode::invalid(), Varnode::constant(0x1100, 8));
    f.block(1);
    if (driftingSp) f.add(MintOp::kSub, f.sp(), f.sp(), Varnode::constant(8, 8));
    const Varnode value = f.load(driftingSp ? f.sp() : address);
    const Varnode condition = f.temporary(1);
    f.add(MintOp::kEqual, condition, f.argument(), Varnode::constant(0, 8));
    f.add(MintOp::kCondBranch, Varnode::invalid(), condition, Varnode::constant(0x1100, 8));
    f.block(2); f.ret(value);
    const StackAnalysis result = analyze(f.ssa());
    if (driftingSp) require(result.unknownStackAccesses == 1 && reads(result).empty(), "drifting loop SP converges to unknown");
    else require(reads(result).size() == 1 && reads(result)[0]->reachingStore != kNoValue, "stable loop preserves reaching store");
}

void escapeAndUninitialized(Arch arch) {
    Fixture f(arch); f.block(0); const Varnode address = f.address(-8);
    const Varnode before = f.load(address); f.store(address, 7);
    f.ret(before);
    const StackAnalysis uninitialized = analyze(f.ssa());
    require(!uninitialized.slots[0].promoted && !uninitialized.slots[0].initializedBeforeEveryRead, "uninitialized slot kept memory-backed");
    Fixture escaped(arch); escaped.block(0); const Varnode pointer = escaped.address(-8); escaped.store(pointer, 7);
    escaped.ret(pointer);
    const SsaFunction function = escaped.ssa(); const StackAnalysis result = analyze(function);
    require(result.escapedStackAddress && !result.slots[0].promoted, "returned stack address is an escape");
    require(emit(function).find("*const mint_stack_m8_8") != std::string::npos, "escaping memory alias is preserved");
}

void unknownEffects(Arch arch) {
    Fixture f(arch); f.block(0); const Varnode address = f.address(-8); f.store(address);
    f.add(MintOp::kIntrinsic); f.ret(f.load(address));
    const StackAnalysis result = analyze(f.ssa());
    require(result.barriers == 1 && result.slots.empty() && result.unknownStackAccesses == 2, "intrinsic may clobber SP/FP; no exact frame guessed");
    Fixture dynamic(arch); dynamic.block(0);
    dynamic.add(MintOp::kSub, dynamic.sp(), dynamic.sp(), dynamic.argument());
    dynamic.ret(dynamic.load(dynamic.sp()));
    const StackAnalysis unknown = analyze(dynamic.ssa());
    require(unknown.slots.empty() && unknown.unknownStackAccesses == 1, "dynamic allocation SP remains unknown");
}

void nameCollision(Arch arch) {
    Fixture f(arch); f.block(0); const Varnode address = f.address(-8); f.store(address); f.ret(f.load(address));
    const SsaFunction function = f.ssa(); CEmitterOptions options;
    options.prototypes = [](Address) { UserPrototype p; p.returnType = "uint64_t"; p.parameters.push_back({"uint64_t", "mint_stack_m8_8"}); return p; };
    const std::string c = emitC(function, structureControlFlow(function), options);
    require(c.find("uint64_t mint_stack_m8_8_;") != std::string::npos, "generated slot does not collide with user parameter");
}
}  // namespace

int main(int argc, char** argv) {
    for (Arch arch : {Arch::kAArch64, Arch::kX86_64}) {
        leaf(arch); barrier(arch, false); barrier(arch, true); overlap(arch);
        diamond(arch, false, true); diamond(arch, false, false); diamond(arch, true, true);
        loop(arch, false); loop(arch, true); escapeAndUninitialized(arch); unknownEffects(arch); nameCollision(arch);
    }
    if (argc == 2 && std::string(argv[1]) == "--emit-c") {
        std::printf("#include <stdint.h>\n#include <stdbool.h>\nuint64_t op_undefined(void);\nuint64_t call();\n");
        for (Arch arch : {Arch::kAArch64, Arch::kX86_64}) {
            Fixture f(arch); f.block(0); const Varnode address = f.address(-8); f.store(address, 42); f.ret(f.load(address));
            std::printf("%s\n", emit(f.ssa()).c_str());
        }
    }
    std::fprintf(stderr, "stack analysis: %zu checks passed\n", checks);
    return 0;
}
