#include "mint/ir/dataflow.h"

#include <algorithm>

namespace mint {
namespace {

bool validValue(const SsaFunction& function, SsaId id) {
    return id != kNoValue && id < function.values.size();
}

}  // namespace

Status buildDefUse(const SsaFunction& function, SsaDefUse* out) {
    if (out == nullptr) {
        return Status::error(ErrorCode::kInternalError, "no def-use output");
    }
    const std::vector<std::string> problems = function.verify();
    if (!problems.empty()) {
        return Status::error(ErrorCode::kBadFormat,
                             "cannot build def-use chains from invalid SSA: " +
                                 problems.front());
    }

    out->uses.assign(function.values.size(), {});
    for (u32 index = 0; index < function.insns.size(); ++index) {
        const SsaInsn& insn = function.insns[index];
        for (u8 slot = 0; slot < 3; ++slot) {
            if (!validValue(function, insn.use[slot])) continue;
            out->uses[insn.use[slot]].push_back(
                SsaUseSite{SsaUseKind::kInstruction, index, slot, kNoValue});
        }
    }
    for (u32 index = 0; index < function.phis.size(); ++index) {
        const SsaPhi& phi = function.phis[index];
        const std::vector<u32>& predecessors = function.blocks[phi.block].predecessors;
        const size_t count = std::min(phi.args.size(), predecessors.size());
        for (size_t edge = 0; edge < count; ++edge) {
            if (!validValue(function, phi.args[edge])) continue;
            out->uses[phi.args[edge]].push_back(
                SsaUseSite{SsaUseKind::kPhi, index, static_cast<u8>(edge),
                           predecessors[edge]});
        }
    }
    return Status::success();
}

Status computeLiveness(const SsaFunction& function, SsaLiveness* out) {
    if (out == nullptr) {
        return Status::error(ErrorCode::kInternalError, "no liveness output");
    }
    const std::vector<std::string> problems = function.verify();
    if (!problems.empty()) {
        return Status::error(ErrorCode::kBadFormat,
                             "cannot compute liveness from invalid SSA: " +
                                 problems.front());
    }

    const size_t blockCount = function.blocks.size();
    out->liveIn.assign(blockCount, {});
    out->liveOut.assign(blockCount, {});
    std::vector<std::unordered_set<SsaId>> localUses(blockCount);
    std::vector<std::unordered_set<SsaId>> defs(blockCount);

    for (const SsaPhi& phi : function.phis) {
        if (phi.block < blockCount && validValue(function, phi.dest)) {
            defs[phi.block].insert(phi.dest);
        }
    }
    for (const SsaBlock& block : function.blocks) {
        std::unordered_set<SsaId>& defined = defs[block.id];
        for (u32 i = 0; i < block.insnCount; ++i) {
            const SsaInsn& insn = function.insns[block.firstInsn + i];
            for (SsaId use : insn.use) {
                if (validValue(function, use) && defined.find(use) == defined.end()) {
                    localUses[block.id].insert(use);
                }
            }
            if (validValue(function, insn.dest)) defined.insert(insn.dest);
        }
    }

    // Phi arguments are live on the edge from predecessor to phi block. The
    // block-level representation below unions them into liveOut; this retains the
    // conservative property needed by dead-code elimination without pretending a
    // phi argument is live at the beginning of every predecessor.
    std::vector<std::unordered_set<SsaId>> edgePhi(blockCount);
    for (const SsaPhi& phi : function.phis) {
        if (phi.block >= blockCount) continue;
        const std::vector<u32>& predecessors = function.blocks[phi.block].predecessors;
        const size_t count = std::min(phi.args.size(), predecessors.size());
        for (size_t edge = 0; edge < count; ++edge) {
            if (predecessors[edge] < blockCount && validValue(function, phi.args[edge])) {
                edgePhi[predecessors[edge]].insert(phi.args[edge]);
            }
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t reverse = blockCount; reverse != 0; --reverse) {
            const u32 block = static_cast<u32>(reverse - 1);
            std::unordered_set<SsaId> newOut = edgePhi[block];
            for (u32 successor : function.blocks[block].successors) {
                if (successor >= blockCount) continue;
                newOut.insert(out->liveIn[successor].begin(),
                              out->liveIn[successor].end());
            }

            std::unordered_set<SsaId> newIn = localUses[block];
            for (SsaId value : newOut) {
                if (defs[block].find(value) == defs[block].end()) newIn.insert(value);
            }
            if (newOut != out->liveOut[block] || newIn != out->liveIn[block]) {
                out->liveOut[block] = std::move(newOut);
                out->liveIn[block] = std::move(newIn);
                changed = true;
            }
        }
    }
    return Status::success();
}

}  // namespace mint
