#include "mint/ir/stack_analysis.h"

#include <algorithm>
#include <cstdio>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <utility>

#include "mint/ir/registers.h"

namespace mint {
namespace {
bool memoryBarrier(MintOp op) {return op==MintOp::kCall||op==MintOp::kCallInd||op==MintOp::kIntrinsic||op==MintOp::kMemoryFence||op==MintOp::kAtomicLoad||op==MintOp::kAtomicStore||op==MintOp::kAtomicExchange||op==MintOp::kAtomicAdd||op==MintOp::kAtomicCompareExchange||op==MintOp::kVectorStore;}

constexpr size_t kMaxValues = 2000000;
constexpr size_t kMaxInsns = 2000000;
constexpr size_t kMaxBlocks = 200000;
constexpr size_t kMaxSlots = 4096;
constexpr size_t kMaxMemoryEntries = 1000000;
constexpr size_t kMaxMemoryWork = 16000000;
constexpr i64 kMaxFrameDisplacement = 16 * 1024 * 1024;

// Bottom only exists while the worklist is being solved. It is never exposed
// as a known fact to a caller, and unresolved cycles are finally made unknown.
enum class FactKind : u8 { kBottom, kUnknown, kConstant, kStack };
struct Fact {
    FactKind kind = FactKind::kBottom;
    i64 offset = 0;
    bool mayStack = false;
};

bool equal(const Fact& a, const Fact& b) {
    return a.kind == b.kind && a.offset == b.offset && a.mayStack == b.mayStack;
}
Fact unknown(bool stack = false) { return {FactKind::kUnknown, 0, stack}; }
Fact meet(const Fact& a, const Fact& b) {
    if (a.kind == FactKind::kBottom) return b;
    if (b.kind == FactKind::kBottom) return a;
    if (a.kind == b.kind && a.offset == b.offset) {
        Fact result = a; result.mayStack = a.mayStack || b.mayStack; return result;
    }
    return unknown(a.mayStack || b.mayStack);
}
bool addSigned(i64 a, i64 b, i64* out) {
    if ((b > 0 && a > std::numeric_limits<i64>::max() - b) ||
        (b < 0 && a < std::numeric_limits<i64>::min() - b)) return false;
    *out = a + b; return true;
}
bool negate(i64 value, i64* out) {
    if (value == std::numeric_limits<i64>::min()) return false;
    *out = -value; return true;
}
u64 widthMask(u8 width) {
    return width >= 8 ? ~u64(0) : ((u64(1) << (width * 8)) - 1);
}
i64 signedBits(u64 bits) {
    if (bits <= static_cast<u64>(std::numeric_limits<i64>::max())) return static_cast<i64>(bits);
    return -1 - static_cast<i64>(~bits);
}
u8 pointerWidth(Arch arch) {
    return arch==Arch::kArm32 || arch==Arch::kThumb || arch==Arch::kX86_32 || arch==Arch::kRiscV32 ? 4 : 8;
}
bool registerAt(const SsaValue& value, u64 offset, u8 width) {
    return value.storage.space == Space::kRegister && value.storage.offset == offset && value.storage.size == width;
}
bool stackRegisters(Arch arch, u64* sp, u64* fp) {
    if (arch == Arch::kAArch64) { *sp = arm64::kSp; *fp = arm64::kXn(29); return true; }
    if (arch == Arch::kX86_64) { *sp = x86::kRsp; *fp = x86::kRbp; return true; }
    if (arch == Arch::kX86_32) { *sp = x86::kRsp; *fp = x86::kRbp; return true; }
    if (arch == Arch::kArm32 || arch==Arch::kThumb) { *sp=arm32::kSp;*fp=arm32::kRn(11);return true; }
    if (arch == Arch::kRiscV32 || arch==Arch::kRiscV64) { *sp=riscv::kSp;*fp=riscv::kXn(8);return true; }
    return false;
}

Fact evaluate(const SsaFunction& function, SsaId id, const std::vector<Fact>& facts) {
    const SsaValue& value = function.values[id];
    if (value.def == SsaDef::kConstant) {
        return {FactKind::kConstant, signedBits(value.storage.offset & widthMask(value.storage.size)), false};
    }
    if (value.def == SsaDef::kEntry) return facts[id];
    if (value.def == SsaDef::kPhi) {
        if (value.defIndex >= function.phis.size()) return unknown();
        const SsaPhi& phi = function.phis[value.defIndex];
        if (phi.dead) return unknown();
        Fact result;
        for (SsaId argument : phi.args) {
            result = meet(result, argument < facts.size() ? facts[argument] : unknown());
        }
        return result;
    }
    if (value.defIndex >= function.insns.size()) return unknown();
    const SsaInsn& insn = function.insns[value.defIndex];
    if (insn.dead || insn.dest != id) return unknown(); // Call clobbers are not copies.
    auto source = [&](unsigned slot) { return insn.use[slot] < facts.size() ? facts[insn.use[slot]] : unknown(); };
    const Fact a = source(0), b = source(1);
    const bool mayStack = a.mayStack || b.mayStack;
    if (insn.op == MintOp::kCopy) {
        if (a.kind == FactKind::kStack && value.storage.size != pointerWidth(function.arch)) return unknown(true);
        return a;
    }
    if (insn.op == MintOp::kAdd || insn.op == MintOp::kSub) {
        if (a.kind == FactKind::kBottom || b.kind == FactKind::kBottom) return {};
        if (a.kind == FactKind::kConstant && b.kind == FactKind::kConstant) {
            const u64 left = static_cast<u64>(a.offset), right = static_cast<u64>(b.offset);
            const u64 bits = insn.op == MintOp::kAdd ? left + right : left - right;
            return {FactKind::kConstant, signedBits(bits & widthMask(value.storage.size)), false};
        }
        const Fact* base = &a; const Fact* displacement = &b;
        if (insn.op == MintOp::kAdd && b.kind == FactKind::kStack) { base = &b; displacement = &a; }
        if (base->kind == FactKind::kStack && displacement->kind == FactKind::kConstant && value.storage.size == pointerWidth(function.arch)) {
            i64 delta = displacement->offset, offset = 0;
            if ((insn.op != MintOp::kSub || negate(delta, &delta)) && addSigned(base->offset, delta, &offset) &&
                offset >= -kMaxFrameDisplacement && offset <= kMaxFrameDisplacement) return {FactKind::kStack, offset, true};
        }
        return unknown(mayStack);
    }
    if (insn.op == MintOp::kSelect) {
        const Fact yes = source(1), no = source(2);
        if (a.kind == FactKind::kConstant) return a.offset ? yes : no;
        return meet(yes, no);
    }
    if (insn.op == MintOp::kZeroExt || insn.op == MintOp::kTrunc || insn.op == MintOp::kSignExt) {
        if (a.kind == FactKind::kBottom) return {};
        if (a.kind != FactKind::kConstant) return unknown(a.mayStack);
        u64 bits = static_cast<u64>(a.offset);
        if (insn.op == MintOp::kSignExt && insn.use[0] < function.values.size()) {
            const u8 width = function.values[insn.use[0]].storage.size;
            if (width && width < 8 && (bits & (u64(1) << (width * 8 - 1)))) bits |= ~widthMask(width);
        }
        return {FactKind::kConstant, signedBits(bits & widthMask(value.storage.size)), false};
    }
    if (insn.op == MintOp::kLoad) return unknown(); // Memory contents are not address facts.
    return unknown(mayStack);
}

using SlotKey = std::pair<i64, u8>;
using MemoryState = std::map<u32, u32>; // slot -> reaching store version (0 = initialized join)
bool overlaps(const StackSlot& a, const StackSlot& b) {
    return a.offset < b.offset + b.width && b.offset < a.offset + a.width;
}
std::string slotName(i64 offset, u8 width) {
    const u64 magnitude = offset < 0 ? static_cast<u64>(-(offset + 1)) + 1 : static_cast<u64>(offset);
    char buffer[80];
    std::snprintf(buffer, sizeof(buffer), "mint_stack_%s%llx_%u", offset < 0 ? "m" : "p",
                  static_cast<unsigned long long>(magnitude), static_cast<unsigned>(width));
    return buffer;
}

}  // namespace

Status analyzeStackMemory(const SsaFunction& function, StackAnalysis* result) {
    if (!result) return Status::error(ErrorCode::kInternalError, "missing stack analysis output");
    *result = {};
    u64 sp = 0, fp = 0;
    if (!stackRegisters(function.arch, &sp, &fp)) return Status::error(ErrorCode::kUnsupported, "stack analysis has no ABI for this architecture");
    if (function.values.size() > kMaxValues || function.insns.size() > kMaxInsns || function.blocks.size() > kMaxBlocks)
        return Status::error(ErrorCode::kTooLarge, "stack analysis resource limit");
    if (function.blocks.empty()) return Status::success();
    for (size_t i = 0; i < function.blocks.size(); ++i) {
        const SsaBlock& block = function.blocks[i];
        if (block.id != i || block.firstInsn > function.insns.size() || block.insnCount > function.insns.size() - block.firstInsn)
            return Status::error(ErrorCode::kBadFormat, "invalid stack analysis CFG block");
        for (u32 next : block.successors) if (next >= function.blocks.size()) return Status::error(ErrorCode::kBadFormat, "invalid stack analysis CFG edge");
    }
    StackAnalysis prepared;
    prepared.accessByInstruction.assign(function.insns.size(), kNoValue);
    std::vector<Fact> facts(function.values.size());
    std::vector<std::vector<SsaId>> users(function.values.size());
    for (SsaId id = 0; id < function.values.size(); ++id) {
        const SsaValue& value = function.values[id];
        if (value.storage.size == 0 || value.storage.size > 16) return Status::error(ErrorCode::kBadFormat, "invalid SSA value width");
        if (value.def == SsaDef::kEntry) {
            if (registerAt(value, sp,pointerWidth(function.arch))) { facts[id] = {FactKind::kStack, 0, true}; prepared.entryStackValue = id; }
            // Incoming FP belongs to the caller, not to this function's new
            // frame. It becomes our frame base only after a proven SP copy.
            else facts[id] = unknown();
        }
        auto dependency = [&](SsaId use) { if (use < users.size()) users[use].push_back(id); };
        if (value.def == SsaDef::kInsn && value.defIndex < function.insns.size()) {
            const SsaInsn& insn = function.insns[value.defIndex];
            for (unsigned slot = 0; slot < opInfo(insn.op).sources; ++slot) dependency(insn.use[slot]);
        } else if (value.def == SsaDef::kPhi && value.defIndex < function.phis.size()) {
            for (SsaId use : function.phis[value.defIndex].args) dependency(use);
        }
    }
    std::deque<SsaId> pending;
    std::vector<u8> queued(function.values.size(), 1);
    for (SsaId id = 0; id < function.values.size(); ++id) pending.push_back(id);
    auto solve = [&]() {
        while (!pending.empty()) {
            const SsaId id = pending.front(); pending.pop_front(); queued[id] = 0;
            const Fact next = meet(facts[id], evaluate(function, id, facts));
            if (equal(facts[id], next)) continue;
            facts[id] = next;
            for (SsaId user : users[id]) if (!queued[user]) { queued[user] = 1; pending.push_back(user); }
        }
    };
    solve();
    for (SsaId id = 0; id < facts.size(); ++id) if (facts[id].kind == FactKind::kBottom) {
        facts[id] = unknown();
        for (SsaId user : users[id]) if (!queued[user]) { queued[user] = 1; pending.push_back(user); }
    }
    solve();
    for (const Fact& fact : facts) {
        const StackValueKind kind = fact.kind == FactKind::kStack ? StackValueKind::kEntrySpRelative :
            fact.kind == FactKind::kConstant ? StackValueKind::kConstant : StackValueKind::kUnknown;
        prepared.values.push_back({kind, fact.offset, fact.mayStack});
    }
    std::vector<u8> reachable(function.blocks.size(), 0);
    std::vector<u32> walk{0};
    while (!walk.empty()) {
        const u32 block = walk.back(); walk.pop_back();
        if (reachable[block]) continue;
        reachable[block] = 1;
        for (u32 next : function.blocks[block].successors) walk.push_back(next);
    }
    // Intrinsics explicitly may write any register, including SP/FP, but the
    // register SSA currently has no intrinsic clobber definitions. Do not let
    // that missing definition create an exact stack address across the barrier.
    // Until those clobbers are modeled, abandon affine stack facts for this
    // function (rather than guessing which paths preserve the frame).
    bool unknownRegisterEffect = false;
    for (const SsaInsn& insn : function.insns) {
        if (!insn.dead && insn.block < reachable.size() && reachable[insn.block] && insn.op == MintOp::kIntrinsic) unknownRegisterEffect = true;
    }
    if (unknownRegisterEffect) {
        for (size_t id = 0; id < facts.size(); ++id) if (facts[id].kind == FactKind::kStack) {
            facts[id] = unknown(true);
            prepared.values[id] = {StackValueKind::kUnknown, 0, true};
        }
    }
    std::map<SlotKey, u32> slots;
    for (u32 index = 0; index < function.insns.size(); ++index) {
        const SsaInsn& insn = function.insns[index];
        if (insn.dead || insn.block >= reachable.size() || !reachable[insn.block]) continue;
        const bool memory = insn.op == MintOp::kLoad || insn.op == MintOp::kStore;
        if (memory) {
            const SsaId address = insn.use[0];
            const SsaId value = insn.op == MintOp::kLoad ? insn.dest : insn.use[1];
            const u8 width = value < function.values.size() ? function.values[value].storage.size : 0;
            if (address < facts.size() && facts[address].kind == FactKind::kStack && width && width <= 16) {
                const SlotKey key{facts[address].offset, width};
                slots.emplace(key, 0);
                if (slots.size() > kMaxSlots) return Status::error(ErrorCode::kTooLarge, "too many recovered stack slots");
            } else {
                ++prepared.unknownAccesses;
                if (address < facts.size() && facts[address].mayStack) ++prepared.unknownStackAccesses;
                if (insn.op == MintOp::kStore) ++prepared.unknownWrites;
            }
        }
        if (memoryBarrier(insn.op)) ++prepared.barriers;
        // The memory address use itself is not an escape. Storing a stack address
        // as a value, passing it, or letting an unmodelled operation consume it is.
        for (unsigned operand = 0; operand < opInfo(insn.op).sources; ++operand) {
            const SsaId use = insn.use[operand];
            if (use >= facts.size() || !facts[use].mayStack) continue;
            const bool addressOnly = memory && operand == 0;
            const bool affine = insn.op == MintOp::kCopy || insn.op == MintOp::kAdd || insn.op == MintOp::kSub || insn.op == MintOp::kSelect;
            const bool comparison = insn.op == MintOp::kEqual || insn.op == MintOp::kNotEqual || insn.op == MintOp::kLessU || insn.op == MintOp::kLessS || insn.op == MintOp::kLessEqU || insn.op == MintOp::kLessEqS;
            if (!addressOnly && !affine && !comparison) prepared.escapedStackAddress = true;
        }
    }
    for (const auto& returned : function.returnValues) if (returned.second < facts.size() && facts[returned.second].mayStack) prepared.escapedStackAddress = true;
    for (auto& pair : slots) {
        pair.second = static_cast<u32>(prepared.slots.size());
        prepared.slots.push_back({pair.first.first, pair.first.second, slotName(pair.first.first, pair.first.second), false, true, false});
    }
    for (size_t i = 0; i < prepared.slots.size(); ++i) {
        for (size_t j = i + 1; j < prepared.slots.size() && prepared.slots[j].offset < prepared.slots[i].offset + prepared.slots[i].width; ++j) {
            if (overlaps(prepared.slots[i], prepared.slots[j])) prepared.slots[i].overlaps = prepared.slots[j].overlaps = true;
        }
    }
    for (u32 index = 0; index < function.insns.size(); ++index) {
        const SsaInsn& insn = function.insns[index];
        if (insn.dead || insn.block >= reachable.size() || !reachable[insn.block] || (insn.op != MintOp::kLoad && insn.op != MintOp::kStore)) continue;
        const SsaId address = insn.use[0], value = insn.op == MintOp::kLoad ? insn.dest : insn.use[1];
        if (address >= facts.size() || facts[address].kind != FactKind::kStack || value >= function.values.size()) continue;
        const auto found = slots.find({facts[address].offset, function.values[value].storage.size});
        if (found == slots.end()) continue;
        prepared.accessByInstruction[index] = static_cast<u32>(prepared.accesses.size());
        prepared.accesses.push_back({index, found->second, insn.op == MintOp::kStore, 0, kNoValue, false});
    }

    // Build predecessors from the actual successor graph rather than trusting a
    // caller's cached lists. A join preserves initialization only on every path,
    // and preserves one defining version only when all paths agree on that store.
    std::vector<std::vector<u32>> predecessors(function.blocks.size());
    for (const SsaBlock& block : function.blocks) for (u32 next : block.successors) predecessors[next].push_back(block.id);
    std::vector<MemoryState> outgoing(function.blocks.size());
    std::vector<u8> processed(function.blocks.size(), 0), inQueue(function.blocks.size(), 0);
    std::deque<u32> blocks{0}; inQueue[0] = 1;
    size_t memoryEntries = 0, work = 0;
    auto incoming = [&](u32 block) {
        MemoryState state;
        bool first = block != 0; // The external entry edge has unknown memory.
        for (u32 pred : predecessors[block]) {
            if (!processed[pred]) continue;
            if (first) { state = outgoing[pred]; first = false; continue; }
            for (auto it = state.begin(); it != state.end();) {
                const auto match = outgoing[pred].find(it->first);
                if (match == outgoing[pred].end()) it = state.erase(it);
                else { if (it->second != match->second) it->second = 0; ++it; }
            }
        }
        return state;
    };
    auto transfer = [&](u32 block, MemoryState state, bool record) {
        const SsaBlock& cfg = function.blocks[block];
        for (u32 i = cfg.firstInsn; i < cfg.firstInsn + cfg.insnCount; ++i) {
            const SsaInsn& insn = function.insns[i];
            if (insn.dead) continue;
            const u32 ai = prepared.accessByInstruction[i];
            if (ai != kNoValue) {
                StackAccess& access = prepared.accesses[ai];
                const auto previous = state.find(access.slot);
                if (record) {
                    access.initialized = previous != state.end();
                    access.memoryVersion = previous == state.end() ? 0 : previous->second;
                    access.reachingStore = access.memoryVersion ? access.memoryVersion - 1 : kNoValue;
                    if (!access.store) {
                        prepared.slots[access.slot].initializedBeforeEveryRead &= access.initialized;
                        if (access.reachingStore != kNoValue) ++prepared.storeLoadDependencies;
                    }
                }
                if (access.store) {
                    for (auto it = state.begin(); it != state.end();) {
                        if (overlaps(prepared.slots[it->first], prepared.slots[access.slot])) it = state.erase(it); else ++it;
                    }
                    state[access.slot] = i + 1;
                    if (record) access.memoryVersion = i + 1;
                }
            } else if (insn.op == MintOp::kStore) state.clear();
            if (memoryBarrier(insn.op)) state.clear();
        }
        return state;
    };
    while (!blocks.empty()) {
        const u32 block = blocks.front(); blocks.pop_front(); inQueue[block] = 0;
        work += function.blocks[block].insnCount + outgoing[block].size() + predecessors[block].size();
        if (work > kMaxMemoryWork) return Status::error(ErrorCode::kTooLarge, "stack memory convergence resource limit");
        MemoryState next = transfer(block, incoming(block), false);
        const bool changed = !processed[block] || next != outgoing[block];
        memoryEntries -= outgoing[block].size(); memoryEntries += next.size();
        if (memoryEntries > kMaxMemoryEntries) return Status::error(ErrorCode::kTooLarge, "stack memory state resource limit");
        outgoing[block] = std::move(next); processed[block] = 1;
        if (changed) for (u32 successor : function.blocks[block].successors) if (!inQueue[successor]) { inQueue[successor] = 1; blocks.push_back(successor); }
    }
    for (u32 block = 0; block < function.blocks.size(); ++block) if (processed[block]) transfer(block, incoming(block), true);
    for (StackSlot& slot : prepared.slots) {
        slot.promoted = slot.offset < 0 && slot.offset + slot.width <= 0 && !slot.overlaps &&
            slot.initializedBeforeEveryRead && !prepared.escapedStackAddress && !prepared.barriers && !prepared.unknownAccesses;
    }
    *result = std::move(prepared);
    return Status::success();
}

}  // namespace mint
