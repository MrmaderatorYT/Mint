#include "mint/ir/lifter_dalvik.h"

#include <algorithm>
#include <unordered_map>

namespace mint {
namespace {

Varnode dalvikReg(u32 index) { return Varnode::reg(static_cast<u64>(index) * 8, 8); }
Address codeAddress(u32 offset) { return 0xd0000000ull + offset * 2ull; }

u32 targetOffset(u32 offset, i32 delta) { return static_cast<u32>(static_cast<i64>(offset) + delta); }

Varnode logicalNot(IrBuilder& builder, const Varnode& value) {
    return builder.binary(
        MintOp::kEqual, value, Varnode::constant(0, value.size));
}

}  // namespace

Status liftDalvik(const DexMethod& method, IrFunction* out) {
    if (!out) return Status::error(ErrorCode::kInternalError, "null Dalvik IR output");
    *out = {};
    out->entry = codeAddress(0); out->name = method.classDescriptor + "->" + method.name; out->arch = Arch::kDalvik;
    if (method.code.empty()) return Status::success();
    std::vector<u32> boundaries{0};
    for (u32 pc = 0; pc < method.code.size();) {
        const u8 op = static_cast<u8>(method.code[pc] & 0xff);
        u32 width = 1;
        if (op == 0x28) width = 1; else if (op == 0x29) width = 2; else if (op == 0x2a) width = 3;
        else if (op == 0x12 || op == 0x13 || op == 0x32 || op == 0x33 || op == 0x38 || op == 0x39) width = (op == 0x13 || op >= 0x32) ? 2 : 1;
        else if (op == 0x14 || op == 0x15 || op == 0x16 || op == 0x17) width = 3;
        else if (op == 0x6e || op == 0x6f || op == 0x70 || op == 0x71 || op == 0x72 || op == 0x74 || op == 0x75 || op == 0x76 || op == 0x77) width = 3;
        if ((op == 0x28 || op == 0x29 || op == 0x2a || (op >= 0x32 && op <= 0x39)) && pc + width <= method.code.size()) {
            i32 delta = 0;
            if (op == 0x28) delta = static_cast<i8>(method.code[pc] >> 8);
            else if (op == 0x29) delta = static_cast<i16>(method.code[pc + 1]);
            else if (op == 0x2a && pc + 2 < method.code.size()) {
                delta = static_cast<i32>(method.code[pc + 1] |
                                         (static_cast<u32>(method.code[pc + 2]) << 16));
            } else if (pc + 1 < method.code.size()) {
                delta = static_cast<i16>(method.code[pc + 1]);
            }
            boundaries.push_back(targetOffset(pc, delta)); if (pc + width < method.code.size()) boundaries.push_back(pc + width);
        }
        pc += width;
    }
    boundaries.push_back(static_cast<u32>(method.code.size()));
    std::sort(boundaries.begin(), boundaries.end()); boundaries.erase(std::unique(boundaries.begin(), boundaries.end()), boundaries.end());
    std::unordered_map<u32, u32> blockByPc;
    for (size_t i = 0; i + 1 < boundaries.size(); ++i) { IrBlock block; block.id = static_cast<u32>(i); block.start = codeAddress(boundaries[i]); block.end = codeAddress(boundaries[i + 1]); block.firstInsn = static_cast<u32>(out->insns.size()); blockByPc[boundaries[i]] = block.id; out->blocks.push_back(block); }
    out->tempCount = 0; // Dalvik locals use fixed register slots; SSA versions them later.
    for (size_t bi = 0; bi + 1 < boundaries.size(); ++bi) {
        IrBlock& block = out->blocks[bi];
        IrBuilder builder(out);
        u32 pc = boundaries[bi]; const u32 end = boundaries[bi + 1];
        while (pc < end && pc < method.code.size()) {
            const u16 unit = method.code[pc]; const u8 op = static_cast<u8>(unit & 0xff);
            const u8 va = static_cast<u8>((unit >> 8) & (op >= 0x38 && op <= 0x3d ? 0xff : 0xf));
            const u8 vb = static_cast<u8>((unit >> 12) & 0xf);
            builder.setAddress(codeAddress(pc));
            const Varnode a = dalvikReg(va), b = dalvikReg(vb);
            u32 width = 1;
            if (op == 0x00) { width = 1; }
            else if (op == 0x01 || op == 0x02 || op == 0x03) { builder.assign(a, b); }
            else if (op == 0x12) { i8 literal = static_cast<i8>((unit >> 12) & 0xf); if ((literal & 8) != 0) literal = static_cast<i8>(literal - 16); builder.assign(a, Varnode::constant(static_cast<u64>(static_cast<i64>(literal)), 8)); }
            else if (op == 0x13 && pc + 1 < method.code.size()) { builder.assign(a, Varnode::constant(static_cast<u64>(static_cast<i16>(method.code[pc + 1])), 8)); width = 2; }
            else if (op == 0x14 && pc + 2 < method.code.size()) { const u32 literal = method.code[pc + 1] | (static_cast<u32>(method.code[pc + 2]) << 16); builder.assign(a, Varnode::constant(literal, 8)); width = 3; }
            else if ((op >= 0x90 && op <= 0x9f) && pc + 1 < method.code.size()) { const u8 dst = static_cast<u8>(unit >> 8); const u8 src1 = static_cast<u8>(method.code[pc + 1] & 0xff); const u8 src2 = static_cast<u8>(method.code[pc + 1] >> 8); const MintOp arithmetic = op == 0x90 ? MintOp::kAdd : op == 0x91 ? MintOp::kSub : op == 0x92 ? MintOp::kMul : op == 0x93 ? MintOp::kDivS : op == 0x94 ? MintOp::kRemS : op == 0x95 ? MintOp::kAnd : op == 0x96 ? MintOp::kOr : MintOp::kXor; builder.emit(arithmetic, dalvikReg(dst), dalvikReg(src1), dalvikReg(src2)); width = 2; }
            else if (op == 0x28 || op == 0x29 || op == 0x2a) { const i32 delta = op == 0x28 ? static_cast<i8>(unit >> 8) : op == 0x29 ? static_cast<i16>(method.code[pc + 1]) : static_cast<i32>(method.code[pc + 1] | (static_cast<u32>(method.code[pc + 2]) << 16)); builder.emit(MintOp::kBranch, Varnode::invalid(), Varnode::constant(codeAddress(targetOffset(pc, delta)), 8)); width = op == 0x28 ? 1 : op == 0x29 ? 2 : 3; }
            else if ((op >= 0x32 && op <= 0x37) || (op >= 0x38 && op <= 0x3d)) {
                const i16 delta = static_cast<i16>(method.code[pc + 1]);
                const bool zeroForm = op >= 0x38;
                const Varnode rhs = zeroForm ? Varnode::constant(0, 8) : b;
                Varnode cond;
                if (op == 0x32 || op == 0x38) cond = builder.binary(MintOp::kEqual, a, rhs);
                else if (op == 0x33 || op == 0x39) cond = builder.binary(MintOp::kNotEqual, a, rhs);
                else if (op == 0x34 || op == 0x3a) cond = builder.binary(MintOp::kLessS, a, rhs);
                else if (op == 0x36 || op == 0x3c) cond = builder.binary(MintOp::kLessS, rhs, a);
                else {
                    const Varnode less = builder.binary(MintOp::kLessS,
                                                         op == 0x35 || op == 0x3b ? a : rhs,
                                                         op == 0x35 || op == 0x3b ? rhs : a);
                    cond = logicalNot(builder, less);
                }
                builder.emit(MintOp::kCondBranch, Varnode::invalid(), cond,
                             Varnode::constant(codeAddress(targetOffset(pc, delta)), 8));
                width = 2;
            }
            else if (op == 0x0e) { builder.emit(MintOp::kReturn, Varnode::invalid()); }
            else if (op == 0x0f || op == 0x10 || op == 0x11) { builder.emit(MintOp::kReturn, Varnode::invalid(), a); }
            else if (op >= 0x6e && op <= 0x72) { builder.emit(MintOp::kCall, Varnode::invalid(), Varnode::constant(method.code.size() > pc + 1 ? method.code[pc + 1] : 0, 8)); width = 3; }
            else { builder.emitIntrinsic(op); }
            pc += width;
            if (!out->insns.empty() && isTerminator(out->insns.back().op)) break;
        }
        block.insnCount = static_cast<u32>(out->insns.size()) - block.firstInsn;
        if (!block.insnCount) { builder.setAddress(block.start); builder.emitIntrinsic(0); block.insnCount = 1; }
        const IrInsn& last = out->insns[block.firstInsn + block.insnCount - 1];
        if (last.op == MintOp::kBranch) { const Address target = last.a.offset; const auto it = blockByPc.find(static_cast<u32>((target - 0xd0000000ull) / 2)); if (it != blockByPc.end()) block.successors.push_back(it->second); }
        else if (last.op == MintOp::kCondBranch) { const Address target = last.b.offset; const auto it = blockByPc.find(static_cast<u32>((target - 0xd0000000ull) / 2)); if (it != blockByPc.end()) block.successors.push_back(it->second); const auto fall = blockByPc.find(static_cast<u32>((block.end - 0xd0000000ull) / 2)); if (fall != blockByPc.end()) block.successors.push_back(fall->second); }
        else if (last.op != MintOp::kReturn) { const auto fall = blockByPc.find(static_cast<u32>((block.end - 0xd0000000ull) / 2)); if (fall != blockByPc.end()) block.successors.push_back(fall->second); }
    }
    for (IrBlock& block : out->blocks) for (u32 target : block.successors) if (target < out->blocks.size()) out->blocks[target].predecessors.push_back(block.id);
    out->machineInsnCount = static_cast<u32>(method.code.size());
    return Status::success();
}

}  // namespace mint
