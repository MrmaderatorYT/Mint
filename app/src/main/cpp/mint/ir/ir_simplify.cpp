#include "mint/ir/ir_simplify.h"

#include <algorithm>
#include <unordered_set>
#include <utility>
#include <vector>

namespace mint {
namespace {

u64 maskFor(u8 size) {
    if (size >= 8) return ~u64(0);
    return (u64(1) << (unsigned(size) * 8)) - 1;
}

u64 signExtend(u64 value, u8 size) {
    if (size >= 8) return value;
    const u64 mask = maskFor(size);
    const u64 sign = u64(1) << (unsigned(size) * 8 - 1);
    value &= mask;
    return (value & sign) != 0 ? value | ~mask : value;
}

bool fold(const IrInsn& input, Varnode* result) {
    const Varnode& a = input.a;
    const Varnode& b = input.b;
    const Varnode& c = input.c;
    if (input.dest.size == 0) return false;
    if (input.op == MintOp::kCopy && a.isConstant()) {
        *result = Varnode::constant(a.offset & maskFor(input.dest.size), input.dest.size);
        return true;
    }
    if (input.op == MintOp::kZeroExt && a.isConstant()) {
        *result = Varnode::constant(a.offset & maskFor(input.dest.size), input.dest.size);
        return true;
    }
    if (input.op == MintOp::kSignExt && a.isConstant()) {
        *result = Varnode::constant(signExtend(a.offset, a.size) & maskFor(input.dest.size),
                                    input.dest.size);
        return true;
    }
    if (input.op == MintOp::kTrunc && a.isConstant()) {
        *result = Varnode::constant(a.offset & maskFor(input.dest.size), input.dest.size);
        return true;
    }
    if (!a.isConstant() || (opInfo(input.op).sources >= 2 && !b.isConstant())) return false;

    const u64 widthMask = maskFor(input.dest.size);
    const u64 av = a.offset & widthMask;
    const u64 bv = b.offset & widthMask;
    u64 value = 0;
    bool folded = true;
    switch (input.op) {
        case MintOp::kAdd: value = av + bv; break;
        case MintOp::kSub: value = av - bv; break;
        case MintOp::kMul: value = av * bv; break;
        case MintOp::kAnd: value = av & bv; break;
        case MintOp::kOr: value = av | bv; break;
        case MintOp::kXor: value = av ^ bv; break;
        case MintOp::kNeg: value = 0 - av; break;
        case MintOp::kNot: value = ~av; break;
        case MintOp::kShl: value = bv >= unsigned(input.dest.size) * 8 ? 0 : av << bv; break;
        case MintOp::kShrU: value = bv >= unsigned(input.dest.size) * 8 ? 0 : av >> bv; break;
        case MintOp::kShrS:
            {
                const i64 signedValue = static_cast<i64>(signExtend(av, input.dest.size));
                value = bv >= unsigned(input.dest.size) * 8
                            ? (signedValue < 0 ? widthMask : 0)
                            : static_cast<u64>(signedValue >> bv);
            }
            break;
        case MintOp::kEqual: value = av == bv; break;
        case MintOp::kNotEqual: value = av != bv; break;
        case MintOp::kLessU: value = av < bv; break;
        case MintOp::kLessS: value = signExtend(av, a.size) < signExtend(bv, b.size); break;
        case MintOp::kLessEqU: value = av <= bv; break;
        case MintOp::kLessEqS: value = signExtend(av, a.size) <= signExtend(bv, b.size); break;
        case MintOp::kSelect:
            if (!a.isConstant()) return false;
            *result = (a.offset != 0 ? b : c);
            return result->valid();
        default: folded = false; break;
    }
    if (!folded) return false;
    *result = Varnode::constant(value & maskFor(input.dest.size), input.dest.size);
    return true;
}

}  // namespace

Status simplifyIr(IrFunction* function, IrSimplifyStats* stats) {
    if (function == nullptr) {
        return Status::error(ErrorCode::kInternalError, "no IR to simplify");
    }
    if (stats != nullptr) *stats = {};

    for (IrInsn& insn : function->insns) {
        Varnode folded;
        if (fold(insn, &folded)) {
            insn.op = MintOp::kCopy;
            insn.a = folded;
            insn.b = Varnode::invalid();
            insn.c = Varnode::invalid();
            if (stats != nullptr) ++stats->constantsFolded;
        }
    }

    // This is intentionally a global may-use check, not an unsound flat-list
    // reaching-definition approximation. It removes values no later operation can
    // observe while retaining overwritten writes whose alias may be used on another
    // CFG path.
    std::vector<u8> removed(function->insns.size(), 0);
    for (size_t i = 0; i < function->insns.size(); ++i) {
        IrInsn& insn = function->insns[i];
        if (!insn.dest.valid() || hasSideEffect(insn.op)) continue;
        bool used = false;
        for (size_t j = 0; j < function->insns.size() && !used; ++j) {
            if (i == j) continue;
            for (unsigned slot = 0; slot < 3; ++slot) {
                const Varnode& source = function->insns[j].source(slot);
                if (insn.dest.overlaps(source)) {
                    used = true;
                    break;
                }
            }
        }
        if (!used) {
            removed[i] = 1;
            if (stats != nullptr) ++stats->deadWritesRemoved;
        }
    }

    if (std::find(removed.begin(), removed.end(), u8(1)) != removed.end()) {
        std::vector<IrInsn> simplified;
        simplified.reserve(function->insns.size());
        // Rebuild with the original block ranges retained in a side vector.
        std::vector<std::pair<u32, u32>> ranges;
        ranges.reserve(function->blocks.size());
        for (const IrBlock& block : function->blocks) ranges.push_back({block.firstInsn, block.insnCount});
        if (function->blocks.empty()) {
            for (u32 index = 0; index < function->insns.size(); ++index) {
                if (removed[index] == 0) simplified.push_back(function->insns[index]);
            }
        }
        for (size_t bi = 0; bi < function->blocks.size(); ++bi) {
            IrBlock& block = function->blocks[bi];
            const u32 oldStart = ranges[bi].first;
            const u32 oldCount = ranges[bi].second;
            block.firstInsn = static_cast<u32>(simplified.size());
            for (u32 j = 0; j < oldCount; ++j) {
                const u32 oldIndex = oldStart + j;
                if (oldIndex < removed.size() && removed[oldIndex] != 0) continue;
                simplified.push_back(function->insns[oldIndex]);
            }
            block.insnCount = static_cast<u32>(simplified.size()) - block.firstInsn;
        }
        function->insns = std::move(simplified);
    }
    return Status::success();
}

Status simplifySsa(SsaFunction* function, SsaSimplifyStats* stats) {
    if (function == nullptr) {
        return Status::error(ErrorCode::kInternalError, "no SSA to simplify");
    }
    if (stats != nullptr) *stats = {};
    const std::vector<std::string> problems = function->verify();
    if (!problems.empty()) {
        return Status::error(ErrorCode::kBadFormat,
                             "cannot simplify invalid SSA: " + problems.front());
    }

    std::vector<SsaId> parent(function->values.size());
    for (SsaId i = 0; i < parent.size(); ++i) parent[i] = i;
    auto find = [&](SsaId id) {
        if (id == kNoValue || id >= parent.size()) return id;
        SsaId root = id;
        while (parent[root] != root) root = parent[root];
        while (parent[id] != id) {
            const SsaId next = parent[id];
            parent[id] = root;
            id = next;
        }
        return root;
    };

    for (SsaInsn& insn : function->insns) {
        if (insn.op == MintOp::kCopy && insn.dest != kNoValue && insn.use[0] != kNoValue) {
            parent[insn.dest] = find(insn.use[0]);
            insn.dead = true;
            if (stats != nullptr) ++stats->copiesPropagated;
        }
    }
    for (SsaPhi& phi : function->phis) {
        if (phi.dead || phi.dest == kNoValue) continue;
        SsaId replacement = kNoValue;
        bool same = true;
        for (SsaId argument : phi.args) {
            const SsaId canonical = find(argument);
            if (canonical == phi.dest) continue;
            if (replacement == kNoValue) replacement = canonical;
            if (replacement != canonical) {
                same = false;
                break;
            }
        }
        if (same && replacement != kNoValue) {
            parent[phi.dest] = find(replacement);
            phi.dead = true;
            if (stats != nullptr) ++stats->trivialPhisRemoved;
        }
    }
    for (SsaInsn& insn : function->insns) {
        for (SsaId& use : insn.use) use = find(use);
    }
    for (SsaPhi& phi : function->phis) {
        for (SsaId& argument : phi.args) argument = find(argument);
    }

    // Copy propagation rewrote operands to their canonical values; the recorded
    // return values are operands too, in every sense that matters, so they have to
    // follow. And a returned value counts as used even though no instruction names
    // it — the caller reads it — or elimination would delete the one definition the
    // function exists to produce.
    for (auto& entry : function->returnValues) entry.second = find(entry.second);

    std::vector<u32> uses(function->values.size(), 0);
    for (const auto& entry : function->returnValues) {
        if (entry.second != kNoValue && entry.second < uses.size()) ++uses[entry.second];
    }
    for (const SsaInsn& insn : function->insns) {
        for (SsaId use : insn.use) {
            if (use != kNoValue) ++uses[use];
        }
    }
    for (const SsaPhi& phi : function->phis) {
        for (SsaId argument : phi.args) {
            if (argument != kNoValue) ++uses[argument];
        }
    }
    for (SsaId id = 0; id < function->values.size(); ++id) {
        function->values[id].uses = uses[id];
        if (uses[id] == 0 && function->values[id].def == SsaDef::kInsn) {
            const u32 index = function->values[id].defIndex;
            if (index < function->insns.size() && !hasSideEffect(function->insns[index].op)) {
                if (!function->insns[index].dead) {
                    function->insns[index].dead = true;
                    if (stats != nullptr) ++stats->deadInstructionsRemoved;
                }
            }
        }
    }
    return Status::success();
}

}  // namespace mint
