#include "mint/obfuscation/ollvm_detect.h"

namespace mint {

bool recoverOpaquePredicate(MintOp op, const Varnode& a, const Varnode& b, bool* result) {
    if (!result) return false;
    if (op == MintOp::kXor && a == b) { *result = false; return true; }
    if (op == MintOp::kOr && a == b && a.isConstant()) { *result = a.offset != 0; return true; }
    if ((op == MintOp::kEqual || op == MintOp::kNotEqual) && a.isConstant() && b.isConstant()) {
        const bool equal = a.offset == b.offset;
        *result = op == MintOp::kEqual ? equal : !equal;
        return true;
    }
    if (op == MintOp::kAdd && b.isConstant() && b.offset == 0) return false;
    return false;
}

std::vector<OllvmFinding> detectOllvm(const IrFunction& function) {
    std::vector<OllvmFinding> findings;
    for (const IrBlock& block : function.blocks) {
        if (block.successors.size() >= 4) findings.push_back({OllvmPattern::kFlattenedDispatcher, block.id, block.start, 75});
        for (u32 i = 0; i < block.insnCount; ++i) {
            const IrInsn& insn = function.insns[block.firstInsn + i];
            bool predicate = false;
            if (recoverOpaquePredicate(insn.op, insn.a, insn.b, &predicate)) findings.push_back({OllvmPattern::kOpaquePredicate, block.id, insn.address, 92});
            if (insn.op == MintOp::kOr || insn.op == MintOp::kXor) {
                for (u32 prior = block.firstInsn; prior < block.firstInsn + i; ++prior) {
                    const IrInsn& definition = function.insns[prior];
                    if (definition.op == MintOp::kNot && ((definition.dest == insn.a && definition.a == insn.b) || (definition.dest == insn.b && definition.a == insn.a))) {
                        findings.push_back({OllvmPattern::kOpaquePredicate, block.id, insn.address, 88});
                        break;
                    }
                }
            }
        }
        if (block.successors.size() == 1 && block.successors.front() == block.id) findings.push_back({OllvmPattern::kSuspiciousDeadLoop, block.id, block.start, 65});
    }
    return findings;
}

}  // namespace mint
