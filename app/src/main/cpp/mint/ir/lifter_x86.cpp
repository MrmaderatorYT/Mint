// x86-64 -> MintIR.
//
// This front-end intentionally starts with the scalar instructions that make
// ordinary compiler output readable: moves, arithmetic, compares, calls and
// conditional branches. Unsupported SIMD/string/privileged instructions remain
// explicit intrinsics, so a partial lift is visible rather than silently wrong.

#include "mint/ir/lifter_internal.h"

#include <capstone/x86.h>

#include "mint/ir/registers.h"

namespace mint {
namespace {

struct Operand {
    Varnode value;
    Varnode address;
    bool memory = false;
};

Varnode zero(u8 size) { return Varnode::constant(0, size); }

Varnode logicalNot(IrBuilder& builder, const Varnode& value) {
    // kNot is a bitwise complement: for a one-byte boolean ~1 is 0xfe, which is
    // still true to kCondBranch. Boolean negation must produce exactly 0 or 1.
    return builder.binary(MintOp::kEqual, value, zero(value.size));
}

u64 truncateToWidth(u64 value, u8 size) {
    if (size == 0 || size >= 8) return value;
    return value & ((u64(1) << (unsigned(size) * 8)) - 1);
}

Varnode registerView(unsigned capstoneRegister, u8 operandSize) {
    Varnode value = registerFromCapstone(Arch::kX86_64, capstoneRegister);
    // Capstone names scalar XMM operands with XMM registers, whose architectural
    // storage is 16 bytes, while the instruction may touch only the low 4 or 8.
    // Keep the operand's view instead of widening a movss/movsd into a full write.
    if (value.valid() && operandSize != 0 && operandSize < value.size) {
        value.size = operandSize;
    }
    return value;
}

Varnode effectiveAddress(const cs_insn& insn, const cs_x86_op& operand,
                         IrBuilder& builder) {
    const x86_op_mem& mem = operand.mem;
    Varnode address;
    if (mem.base == X86_REG_RIP) {
        address = Varnode::constant(static_cast<u64>(insn.address + insn.size + mem.disp), 8);
    } else if (mem.base != X86_REG_INVALID) {
        address = registerFromCapstone(Arch::kX86_64, mem.base);
    } else {
        address = Varnode::constant(static_cast<u64>(mem.disp), 8);
    }
    if (mem.index != X86_REG_INVALID) {
        Varnode index = registerFromCapstone(Arch::kX86_64, mem.index);
        if (mem.scale != 1) index = builder.binary(MintOp::kMul, index,
                                                     Varnode::constant(mem.scale, index.size));
        address = builder.binary(MintOp::kAdd, address, index);
    }
    if (mem.base != X86_REG_RIP && mem.disp != 0) {
        address = builder.binary(MintOp::kAdd, address,
                                 Varnode::constant(static_cast<u64>(mem.disp), 8));
    }
    return address;
}

Operand readOperand(const cs_insn& insn, const cs_x86_op& operand, IrBuilder& builder) {
    Operand result;
    if (operand.type == X86_OP_REG) {
        result.value = registerView(operand.reg, operand.size);
    } else if (operand.type == X86_OP_IMM) {
        const u8 width = operand.size ? operand.size : 8;
        // Capstone exposes signed immediates as i64. The IR constant is an
        // unsigned bit pattern, so -48 in an 8-bit add must become 0xd0 rather
        // than 0xffffffffffffffd0 tagged as one byte.
        result.value = Varnode::constant(
            truncateToWidth(static_cast<u64>(operand.imm), width), width);
    } else if (operand.type == X86_OP_MEM) {
        result.memory = true;
        result.address = effectiveAddress(insn, operand, builder);
        result.value = builder.newTemp(operand.size ? operand.size : 8);
        builder.emit(MintOp::kLoad, result.value, result.address);
    }
    return result;
}

Operand writeTarget(const cs_insn& insn, const cs_x86_op& operand,
                    IrBuilder& builder) {
    Operand result;
    if (operand.type == X86_OP_REG) {
        result.value = registerView(operand.reg, operand.size);
    } else if (operand.type == X86_OP_MEM) {
        result.memory = true;
        result.address = effectiveAddress(insn, operand, builder);
    }
    return result;
}

void writeOperand(const cs_x86_op& operand, const Operand& destination,
                  Varnode value, IrBuilder& builder) {
    if (!value.valid()) return;
    if (operand.type == X86_OP_MEM) {
        if (value.size != operand.size) value = builder.resize(value, operand.size, false);
        builder.emit(MintOp::kStore, Varnode::invalid(), destination.address, value);
    } else if (operand.type == X86_OP_REG) {
        const Varnode target = registerView(operand.reg, operand.size);
        if (!target.valid()) return;
        if (value.size != target.size) value = builder.resize(value, target.size, false);
        // Every 32-bit GPR write in 64-bit mode clears the upper half. Treating
        // eax as an ordinary four-byte window would preserve stale rax[63:32].
        if (target.size == 4 && target.offset < x86::kRip &&
            target.offset % 8 == 0) {
            builder.assign(Varnode::reg(target.offset, 8),
                           builder.resize(value, 8, false));
            return;
        }
        builder.assign(target, value);
    }
}

Varnode flag(u64 offset) { return Varnode::reg(offset, 1); }

Varnode conditionForId(u16 id, IrBuilder& builder) {
    if (id == X86_INS_JE) return flag(x86::kFlagZf);
    if (id == X86_INS_JNE) return logicalNot(builder, flag(x86::kFlagZf));
    if (id == X86_INS_JB) return flag(x86::kFlagCf);
    if (id == X86_INS_JAE) return logicalNot(builder, flag(x86::kFlagCf));
    if (id == X86_INS_JBE) return builder.binary(MintOp::kOr, flag(x86::kFlagCf), flag(x86::kFlagZf));
    if (id == X86_INS_JA) return builder.binary(
        MintOp::kAnd, logicalNot(builder, flag(x86::kFlagCf)),
        logicalNot(builder, flag(x86::kFlagZf)));
    if (id == X86_INS_JO) return flag(x86::kFlagOf);
    if (id == X86_INS_JNO) return logicalNot(builder, flag(x86::kFlagOf));
    if (id == X86_INS_JS) return flag(x86::kFlagSf);
    if (id == X86_INS_JNS) return logicalNot(builder, flag(x86::kFlagSf));
    if (id == X86_INS_JP) return flag(x86::kFlagPf);
    if (id == X86_INS_JNP) return logicalNot(builder, flag(x86::kFlagPf));
    if (id == X86_INS_JL) return builder.binary(MintOp::kNotEqual, flag(x86::kFlagSf), flag(x86::kFlagOf));
    if (id == X86_INS_JGE) return logicalNot(
        builder,
        builder.binary(MintOp::kNotEqual, flag(x86::kFlagSf), flag(x86::kFlagOf)));
    if (id == X86_INS_JLE) {
        const Varnode signedLess = builder.binary(MintOp::kNotEqual, flag(x86::kFlagSf), flag(x86::kFlagOf));
        return builder.binary(MintOp::kOr, flag(x86::kFlagZf), signedLess);
    }
    if (id == X86_INS_JG) {
        const Varnode signedGreater = logicalNot(
            builder,
            builder.binary(MintOp::kNotEqual, flag(x86::kFlagSf), flag(x86::kFlagOf)));
        return builder.binary(
            MintOp::kAnd, logicalNot(builder, flag(x86::kFlagZf)), signedGreater);
    }
    return {};
}

Varnode conditionFor(const cs_insn& insn, IrBuilder& builder) {
    return conditionForId(insn.id, builder);
}

Varnode cmovConditionFor(u16 id, IrBuilder& builder) {
    switch (id) {
        case X86_INS_CMOVAE: return conditionForId(X86_INS_JAE, builder);
        case X86_INS_CMOVA: return conditionForId(X86_INS_JA, builder);
        case X86_INS_CMOVBE: return conditionForId(X86_INS_JBE, builder);
        case X86_INS_CMOVB: return conditionForId(X86_INS_JB, builder);
        case X86_INS_CMOVE: return conditionForId(X86_INS_JE, builder);
        case X86_INS_CMOVGE: return conditionForId(X86_INS_JGE, builder);
        case X86_INS_CMOVG: return conditionForId(X86_INS_JG, builder);
        case X86_INS_CMOVLE: return conditionForId(X86_INS_JLE, builder);
        case X86_INS_CMOVL: return conditionForId(X86_INS_JL, builder);
        case X86_INS_CMOVNE: return conditionForId(X86_INS_JNE, builder);
        case X86_INS_CMOVNO: return conditionForId(X86_INS_JNO, builder);
        case X86_INS_CMOVNP: return conditionForId(X86_INS_JNP, builder);
        case X86_INS_CMOVNS: return conditionForId(X86_INS_JNS, builder);
        case X86_INS_CMOVO: return conditionForId(X86_INS_JO, builder);
        case X86_INS_CMOVP: return conditionForId(X86_INS_JP, builder);
        case X86_INS_CMOVS: return conditionForId(X86_INS_JS, builder);
        default: return {};
    }
}

Varnode setConditionFor(const cs_insn& insn, IrBuilder& builder) {
    const u16 id = insn.id;
    if (id == X86_INS_SETAE) return logicalNot(builder, flag(x86::kFlagCf));
    if (id == X86_INS_SETA) return conditionForId(X86_INS_JA, builder);
    if (id == X86_INS_SETBE) return conditionForId(X86_INS_JBE, builder);
    if (id == X86_INS_SETB) return flag(x86::kFlagCf);
    if (id == X86_INS_SETE) return flag(x86::kFlagZf);
    if (id == X86_INS_SETGE) return conditionForId(X86_INS_JGE, builder);
    if (id == X86_INS_SETG) return conditionForId(X86_INS_JG, builder);
    if (id == X86_INS_SETLE) return conditionForId(X86_INS_JLE, builder);
    if (id == X86_INS_SETL) return conditionForId(X86_INS_JL, builder);
    if (id == X86_INS_SETNE) return logicalNot(builder, flag(x86::kFlagZf));
    if (id == X86_INS_SETNO) return logicalNot(builder, flag(x86::kFlagOf));
    if (id == X86_INS_SETNP) return logicalNot(builder, flag(x86::kFlagPf));
    if (id == X86_INS_SETO) return flag(x86::kFlagOf);
    if (id == X86_INS_SETP) return flag(x86::kFlagPf);
    if (id == X86_INS_SETNS) return logicalNot(builder, flag(x86::kFlagSf));
    if (id == X86_INS_SETS) return flag(x86::kFlagSf);
    (void)insn;
    return {};
}

bool isConditionalJump(u16 id) {
    switch (id) {
        case X86_INS_JAE: case X86_INS_JA: case X86_INS_JBE: case X86_INS_JB:
        case X86_INS_JE: case X86_INS_JGE: case X86_INS_JG: case X86_INS_JLE:
        case X86_INS_JL: case X86_INS_JNE: case X86_INS_JNO: case X86_INS_JNP:
        case X86_INS_JNS: case X86_INS_JO: case X86_INS_JP: case X86_INS_JS:
            return true;
        default: return false;
    }
}

void setZeroFlag(IrBuilder& builder, const Varnode& result) {
    builder.assign(flag(x86::kFlagZf), builder.binary(MintOp::kEqual, result, zero(result.size)));
}

void setCommonFlags(IrBuilder& builder, const Varnode& result) {
    setZeroFlag(builder, result);
    const Varnode sign = builder.binary(
        MintOp::kShrU, result,
        Varnode::constant(unsigned(result.size) * 8 - 1, 1));
    builder.assign(flag(x86::kFlagSf), builder.resize(sign, 1, false));

    const Varnode lowByte = builder.resize(result, 1, false);
    const Varnode bitCount = builder.unary(MintOp::kPopCount, lowByte, 1);
    const Varnode odd = builder.binary(MintOp::kAnd, bitCount,
                                       Varnode::constant(1, 1));
    builder.assign(flag(x86::kFlagPf), logicalNot(builder, odd));
}

void setArithmeticFlags(IrBuilder& builder, MintOp operation,
                        const Varnode& left, const Varnode& right,
                        const Varnode& result) {
    setCommonFlags(builder, result);
    if (operation == MintOp::kAdd) {
        builder.assign(flag(x86::kFlagCf),
                       builder.binary(MintOp::kCarryAdd, left, right));
        builder.assign(flag(x86::kFlagOf),
                       builder.binary(MintOp::kOverflowAdd, left, right));
    } else if (operation == MintOp::kSub) {
        builder.assign(flag(x86::kFlagCf),
                       builder.binary(MintOp::kBorrowSub, left, right));
        builder.assign(flag(x86::kFlagOf),
                       builder.binary(MintOp::kOverflowSub, left, right));
    }
}

void setLogicalFlags(IrBuilder& builder, const Varnode& result) {
    setCommonFlags(builder, result);
    builder.assign(flag(x86::kFlagCf), Varnode::constant(0, 1));
    builder.assign(flag(x86::kFlagOf), Varnode::constant(0, 1));
}

bool isMoveInstruction(u16 id) {
    switch (id) {
        case X86_INS_MOV:
        case X86_INS_MOVABS:
        case X86_INS_MOVAPS:
        case X86_INS_MOVUPS:
        case X86_INS_MOVAPD:
        case X86_INS_MOVUPD:
        case X86_INS_MOVDQA:
        case X86_INS_MOVDQU:
        case X86_INS_MOVD:
        case X86_INS_MOVQ:
        case X86_INS_MOVSS:
        case X86_INS_MOVSD:
            return true;
        default:
            return false;
    }
}

}  // namespace

/// The packed integer instructions that are a lane-wise operation on two vectors.
///
/// A table rather than a switch because every entry is the same shape — operation
/// plus lane width — and the lane width is the only thing that distinguishes
/// members of a family. PADDB and PADDQ differ in nothing else, and writing them as
/// separate code paths invites one of them to drift.
struct PackedOp {
    unsigned id;
    MintOp op;
    u8 lane;
};

const PackedOp kPackedOps[] = {
    {X86_INS_PADDB, MintOp::kVectorAdd, 1},
    {X86_INS_PADDW, MintOp::kVectorAdd, 2},
    {X86_INS_PADDD, MintOp::kVectorAdd, 4},
    {X86_INS_PADDQ, MintOp::kVectorAdd, 8},
    {X86_INS_PSUBB, MintOp::kVectorSub, 1},
    {X86_INS_PSUBW, MintOp::kVectorSub, 2},
    {X86_INS_PSUBD, MintOp::kVectorSub, 4},
    {X86_INS_PSUBQ, MintOp::kVectorSub, 8},
    {X86_INS_PMULLW, MintOp::kVectorMul, 2},
    {X86_INS_PMULLD, MintOp::kVectorMul, 4},
    {X86_INS_PMULUDQ, MintOp::kVectorMulWideU, 4},
    {X86_INS_PMULDQ, MintOp::kVectorMulWideS, 4},
    {X86_INS_PCMPEQB, MintOp::kVectorCmpEq, 1},
    {X86_INS_PCMPEQW, MintOp::kVectorCmpEq, 2},
    {X86_INS_PCMPEQD, MintOp::kVectorCmpEq, 4},
    {X86_INS_PCMPGTB, MintOp::kVectorCmpGtS, 1},
    {X86_INS_PCMPGTW, MintOp::kVectorCmpGtS, 2},
    {X86_INS_PCMPGTD, MintOp::kVectorCmpGtS, 4},
    {X86_INS_PMINUB, MintOp::kVectorMinU, 1},
    {X86_INS_PMINUW, MintOp::kVectorMinU, 2},
    {X86_INS_PMINUD, MintOp::kVectorMinU, 4},
    {X86_INS_PMINSB, MintOp::kVectorMinS, 1},
    {X86_INS_PMINSW, MintOp::kVectorMinS, 2},
    {X86_INS_PMINSD, MintOp::kVectorMinS, 4},
    {X86_INS_PMAXUB, MintOp::kVectorMaxU, 1},
    {X86_INS_PMAXUD, MintOp::kVectorMaxU, 4},
    {X86_INS_PMAXSW, MintOp::kVectorMaxS, 2},
    {X86_INS_PSLLW, MintOp::kVectorShl, 2},
    {X86_INS_PSLLD, MintOp::kVectorShl, 4},
    {X86_INS_PSLLQ, MintOp::kVectorShl, 8},
    {X86_INS_PSRLW, MintOp::kVectorShrU, 2},
    {X86_INS_PSRLD, MintOp::kVectorShrU, 4},
    {X86_INS_PSRLQ, MintOp::kVectorShrU, 8},
    {X86_INS_PSRAW, MintOp::kVectorShrS, 2},
    {X86_INS_PSRAD, MintOp::kVectorShrS, 4},
    // Pack narrows two vectors into one; the lane width recorded is the source's,
    // since that is what the saturation range is taken from.
    {X86_INS_PACKSSWB, MintOp::kVectorPackS, 2},
    {X86_INS_PACKSSDW, MintOp::kVectorPackS, 4},
    {X86_INS_PACKUSWB, MintOp::kVectorPackU, 2},
    {X86_INS_PACKUSDW, MintOp::kVectorPackU, 4},
};

/// Widening lane extends. Lane width here is the source lane — the destination's
/// follows from how many lanes survive, which the mnemonic already fixes.
const PackedOp kExtendOps[] = {
    {X86_INS_PMOVSXBW, MintOp::kVectorExtendS, 1},
    {X86_INS_PMOVSXBD, MintOp::kVectorExtendS, 1},
    {X86_INS_PMOVSXWD, MintOp::kVectorExtendS, 2},
    {X86_INS_PMOVZXBW, MintOp::kVectorExtendU, 1},
    {X86_INS_PMOVZXBD, MintOp::kVectorExtendU, 1},
    {X86_INS_PMOVZXWD, MintOp::kVectorExtendU, 2},
};

const PackedOp* findIn(const PackedOp* table, size_t count, unsigned id) {
    for (size_t i = 0; i < count; ++i) {
        if (table[i].id == id) return &table[i];
    }
    return nullptr;
}

/// True when the instruction was a packed-integer form this lifter models.
///
/// Kept in one place so the two-operand and three-operand SIMD shapes cannot
/// disagree about which register view an XMM operand has.
bool liftPacked(const cs_insn& insn, const cs_x86_op* ops, u8 count,
                IrBuilder& builder) {
    if (count < 2 || ops[0].type != X86_OP_REG) return false;
    const Varnode target = registerView(ops[0].reg, ops[0].size);
    if (!target.valid() || target.size != 16) return false;

    if (const PackedOp* packed =
            findIn(kPackedOps, sizeof(kPackedOps) / sizeof(kPackedOps[0]), insn.id)) {
        Operand left = readOperand(insn, ops[0], builder);
        Operand right = readOperand(insn, ops[1], builder);
        if (!left.value.valid() || !right.value.valid()) return false;
        builder.assign(target, builder.vector(packed->op, packed->lane, left.value,
                                              right.value, Varnode::invalid(), 16));
        return true;
    }

    if (const PackedOp* extend =
            findIn(kExtendOps, sizeof(kExtendOps) / sizeof(kExtendOps[0]), insn.id)) {
        Operand source = readOperand(insn, ops[1], builder);
        if (!source.value.valid()) return false;
        builder.assign(target, builder.vector(extend->op, extend->lane, source.value,
                                              Varnode::invalid(), Varnode::invalid(), 16));
        return true;
    }

    if (insn.id == X86_INS_PSHUFD && count >= 3) {
        Operand source = readOperand(insn, ops[1], builder);
        Operand control = readOperand(insn, ops[2], builder);
        if (!source.value.valid() || !control.value.valid()) return false;
        builder.assign(target, builder.vector(MintOp::kVectorPermute, 4, source.value,
                                              control.value, Varnode::invalid(), 16));
        return true;
    }

    if (insn.id == X86_INS_PBLENDVB) {
        // The mask is architecturally XMM0 and the non-VEX encoding leaves it
        // implicit. Whether Capstone materialises it as a third operand is a
        // decoder detail, so take it when it is there and name XMM0 directly when
        // it is not, rather than depending on which way it goes.
        Operand base = readOperand(insn, ops[0], builder);
        Operand other = readOperand(insn, ops[1], builder);
        const Varnode mask = count >= 3 ? readOperand(insn, ops[2], builder).value
                                        : Varnode::reg(x86::kXmm0, 16);
        if (!base.value.valid() || !other.value.valid() || !mask.valid()) {
            return false;
        }
        builder.assign(target, builder.vector(MintOp::kVectorSelect, 1, base.value,
                                              other.value, mask, 16));
        return true;
    }

    if ((insn.id == X86_INS_PINSRB || insn.id == X86_INS_PINSRD) && count >= 3) {
        Operand base = readOperand(insn, ops[0], builder);
        Operand value = readOperand(insn, ops[1], builder);
        Operand index = readOperand(insn, ops[2], builder);
        if (!base.value.valid() || !value.value.valid() || !index.value.valid()) {
            return false;
        }
        const u8 lane = insn.id == X86_INS_PINSRB ? 1 : 4;
        builder.assign(target, builder.vector(MintOp::kVectorInsert, lane, base.value,
                                              value.value, index.value, 16));
        return true;
    }
    return false;
}

void liftX86(const cs_insn& insn, IrBuilder& builder) {
    builder.setAddress(insn.address);
    if (insn.detail == nullptr) {
        builder.emitIntrinsic(static_cast<u16>(insn.id));
        return;
    }
    const cs_x86& x86Insn = insn.detail->x86;
    const auto& ops = x86Insn.operands;
    const u8 count = x86Insn.op_count;

    if (insn.id == X86_INS_NOP || insn.id == X86_INS_ENDBR64) return;
    if (insn.id == X86_INS_UCOMISS || insn.id == X86_INS_UCOMISD ||
        insn.id == X86_INS_COMISS || insn.id == X86_INS_COMISD) {
        // Scalar floating-point compare. The three flags encode a four-way result,
        // and the fourth case is the reason the instruction exists: with a NaN
        // operand nothing is equal, less or greater, and x86 signals that by setting
        // all three at once. Written out from the three predicates rather than from
        // a single compare, so unordered stays distinguishable from equal.
        //
        //   unordered : ZF=1 PF=1 CF=1        equal : ZF=1 PF=0 CF=0
        //   less      : ZF=0 PF=0 CF=1      greater : ZF=0 PF=0 CF=0
        //
        // COMIS* differs from UCOMIS* only in which NaN raises an exception, which
        // is not modelled here, so both lift the same way.
        if (count < 2) {
            builder.emitIntrinsic(u16(insn.id));
            return;
        }
        const u8 width = (insn.id == X86_INS_UCOMISD || insn.id == X86_INS_COMISD) ? 8 : 4;
        Operand left = readOperand(insn, ops[0], builder);
        Operand right = readOperand(insn, ops[1], builder);
        if (!left.value.valid() || !right.value.valid()) {
            builder.emitIntrinsic(u16(insn.id));
            return;
        }
        // Only the low element takes part; the rest of the register is untouched.
        const Varnode a = builder.resize(left.value, width, false);
        const Varnode b = builder.resize(right.value, width, false);

        const Varnode unordered = builder.binary(MintOp::kFloatUnordered, a, b);
        const Varnode equal = builder.binary(MintOp::kFloatEqual, a, b);
        const Varnode less = builder.binary(MintOp::kFloatLess, a, b);
        builder.assign(flag(x86::kFlagPf), unordered);
        builder.assign(flag(x86::kFlagZf),
                       builder.binary(MintOp::kOr, unordered, equal));
        builder.assign(flag(x86::kFlagCf),
                       builder.binary(MintOp::kOr, unordered, less));
        builder.assign(flag(x86::kFlagOf), Varnode::constant(0, 1));
        builder.assign(flag(x86::kFlagSf), Varnode::constant(0, 1));
        builder.assign(flag(x86::kFlagAf), Varnode::constant(0, 1));
        return;
    }
    if (insn.id == X86_INS_INT3 || insn.id == X86_INS_UD2 || insn.id == X86_INS_HLT) {
        builder.emit(MintOp::kTrap, Varnode::invalid());
        return;
    }
    if (insn.id == X86_INS_RET || insn.id == X86_INS_RETF || insn.id == X86_INS_IRETQ) {
        // x86 has no link register: `ret` reads the return address from the top of
        // the stack and pops it. Modelling that is not optional — kReturn declares a
        // source, so emitting none produced structurally invalid IR for every
        // function in the image, and the stack adjustment is real state the caller
        // observes. `ret imm16` pops that many extra bytes.
        const Varnode stack = Varnode::reg(x86::kRsp, 8);
        const Varnode target = builder.unary(MintOp::kLoad, stack, 8);
        u64 popped = 8;
        if (count > 0 && ops[0].type == X86_OP_IMM) {
            popped += static_cast<u64>(ops[0].imm);
        }
        builder.assign(stack,
                       builder.binary(MintOp::kAdd, stack, Varnode::constant(popped, 8)));
        builder.emit(MintOp::kReturn, Varnode::invalid(), target);
        return;
    }
    if (insn.id == X86_INS_JMP && count > 0) {
        Operand target = readOperand(insn, ops[0], builder);
        builder.emit(target.value.isConstant() ? MintOp::kBranch : MintOp::kBranchInd,
                     Varnode::invalid(), target.value);
        return;
    }
    if (isConditionalJump(insn.id) && count > 0) {
        const Varnode condition = conditionFor(insn, builder);
        Operand target = readOperand(insn, ops[0], builder);
        if (condition.valid()) {
            if (target.value.isConstant()) {
                builder.emit(MintOp::kCondBranch, Varnode::invalid(), condition, target.value);
            } else {
                builder.emitIntrinsic(static_cast<u16>(insn.id));
            }
            return;
        }
    }
    if (insn.id == X86_INS_CALL && count > 0) {
        Operand target = readOperand(insn, ops[0], builder);
        builder.emit(target.value.isConstant() ? MintOp::kCall : MintOp::kCallInd,
                     Varnode::invalid(), target.value);
        return;
    }

    if (insn.id == X86_INS_PUSH && count > 0) {
        Operand source = readOperand(insn, ops[0], builder);
        if (source.value.valid()) {
            const u8 slot = ops[0].size == 2 ? 2 : 8;
            const Varnode stack = Varnode::reg(x86::kRsp, 8);
            const Varnode next = builder.binary(
                MintOp::kSub, stack, Varnode::constant(slot, 8));
            builder.assign(stack, next);
            Varnode value = source.value;
            if (value.size != slot) {
                value = builder.resize(value, slot, ops[0].type == X86_OP_IMM);
            }
            builder.emit(MintOp::kStore, Varnode::invalid(), next, value);
            return;
        }
    }
    if (insn.id == X86_INS_POP && count > 0) {
        Operand destination = writeTarget(insn, ops[0], builder);
        if (destination.value.valid() || destination.address.valid()) {
            const u8 slot = ops[0].size == 2 ? 2 : 8;
            const Varnode stack = Varnode::reg(x86::kRsp, 8);
            const Varnode value = builder.unary(MintOp::kLoad, stack, slot);
            builder.assign(stack, builder.binary(
                MintOp::kAdd, stack, Varnode::constant(slot, 8)));
            writeOperand(ops[0], destination, value, builder);
            return;
        }
    }

    if (liftPacked(insn, ops, count, builder)) return;

    if (count >= 2) {
        if (isMoveInstruction(insn.id)) {
            Operand destination = writeTarget(insn, ops[0], builder);
            Operand src = readOperand(insn, ops[1], builder);
            if (src.value.valid() &&
                (destination.value.valid() || destination.address.valid())) {
                writeOperand(ops[0], destination, src.value, builder);
                return;
            }
        }
        if (insn.id == X86_INS_LEA) {
            if (ops[1].type == X86_OP_MEM) {
                Operand destination = writeTarget(insn, ops[0], builder);
                writeOperand(ops[0], destination,
                             effectiveAddress(insn, ops[1], builder), builder);
            }
            return;
        }
        Operand dst = readOperand(insn, ops[0], builder);
        Operand src = readOperand(insn, ops[1], builder);
        const Varnode cmovCondition = cmovConditionFor(insn.id, builder);
        if (cmovCondition.valid() && dst.value.valid() && src.value.valid()) {
            Varnode source = src.value;
            if (source.size != dst.value.size) {
                source = builder.resize(source, dst.value.size, false);
            }
            const Varnode selected = builder.newTemp(dst.value.size);
            builder.emit(MintOp::kSelect, selected, cmovCondition, source, dst.value);
            writeOperand(ops[0], dst, selected, builder);
            return;
        }
        if (insn.id == X86_INS_IMUL) {
            Operand left = count >= 3 ? readOperand(insn, ops[1], builder) : dst;
            Operand right = count >= 3 ? readOperand(insn, ops[2], builder) : src;
            if (dst.value.valid() && left.value.valid() && right.value.valid()) {
                Varnode a = left.value;
                Varnode b = right.value;
                if (a.size != dst.value.size) a = builder.resize(a, dst.value.size, true);
                if (b.size != dst.value.size) b = builder.resize(b, dst.value.size, true);
                writeOperand(ops[0], dst, builder.binary(MintOp::kMul, a, b), builder);
                return;
            }
        }
        if (insn.id == X86_INS_XADD && dst.value.valid() && src.value.valid()) {
            Varnode source = src.value;
            if (source.size != dst.value.size) {
                source = builder.resize(source, dst.value.size, false);
            }
            const Varnode result = builder.binary(
                MintOp::kAdd, dst.value, source);
            writeOperand(ops[0], dst, result, builder);
            writeOperand(ops[1], src, dst.value, builder);
            setArithmeticFlags(builder, MintOp::kAdd, dst.value, source, result);
            return;
        }
        if ((insn.id == X86_INS_ADC || insn.id == X86_INS_SBB) &&
            dst.value.valid() && src.value.valid()) {
            // Add or subtract with the carry flag folded in. The flags are computed
            // from the two-step carry rather than from the single-operation opcodes,
            // because those cannot see an incoming carry — and this is how
            // multi-word arithmetic and 128-bit comparisons are built, so a wrong
            // carry or overflow bit here turns a correct wide comparison into a
            // plausible wrong one. On x86 the carry flag means borrow for
            // subtraction, so unlike AArch64 it is used directly rather than
            // complemented.
            const bool subtract = insn.id == X86_INS_SBB;
            Varnode source = src.value;
            if (source.size != dst.value.size) {
                source = builder.resize(source, dst.value.size, false);
            }
            const Varnode carryIn =
                builder.resize(flag(x86::kFlagCf), dst.value.size, false);
            const MintOp step = subtract ? MintOp::kSub : MintOp::kAdd;
            const Varnode partial = builder.binary(step, dst.value, source);
            const Varnode result = builder.binary(step, partial, carryIn);
            writeOperand(ops[0], dst, result, builder);
            setCommonFlags(builder, result);

            const MintOp carryOp = subtract ? MintOp::kBorrowSub : MintOp::kCarryAdd;
            const Varnode firstStep = builder.binary(carryOp, dst.value, source);
            const Varnode secondStep = builder.binary(carryOp, partial, carryIn);
            builder.assign(flag(x86::kFlagCf),
                           builder.binary(MintOp::kOr, firstStep, secondStep));

            // Signed overflow stated from the operand signs: an addition needs both
            // inputs to share a sign and the result to differ; a subtraction needs
            // the inputs to differ and the result to differ from the first.
            const Varnode signLeft =
                builder.binary(MintOp::kLessS, dst.value, zero(dst.value.size));
            const Varnode signRight =
                builder.binary(MintOp::kLessS, source, zero(source.size));
            const Varnode signResult =
                builder.binary(MintOp::kLessS, result, zero(result.size));
            const Varnode related = builder.binary(
                subtract ? MintOp::kNotEqual : MintOp::kEqual, signLeft, signRight);
            const Varnode turned =
                builder.binary(MintOp::kNotEqual, signResult, signLeft);
            builder.assign(flag(x86::kFlagOf),
                           builder.binary(MintOp::kAnd, related, turned));
            return;
        }
        if ((insn.id == X86_INS_BSR || insn.id == X86_INS_BSF) &&
            dst.value.valid() && src.value.valid()) {
            // Bit scan: the index of the highest or lowest set bit. Expressible
            // exactly from the count-leading and count-trailing-zeros opcodes, so
            // there is no reason for these to stay unmodelled. With a zero source
            // the destination is architecturally undefined and only the zero flag
            // carries meaning, which is why the flag is set from the source.
            const unsigned bits = unsigned(src.value.size) * 8;
            Varnode result;
            if (insn.id == X86_INS_BSF) {
                result = builder.unary(MintOp::kCtz, src.value, src.value.size);
            } else {
                const Varnode leading =
                    builder.unary(MintOp::kClz, src.value, src.value.size);
                result = builder.binary(MintOp::kSub,
                                        Varnode::constant(bits - 1, src.value.size),
                                        leading);
            }
            writeOperand(ops[0], dst, result, builder);
            builder.assign(flag(x86::kFlagZf),
                           builder.binary(MintOp::kEqual, src.value,
                                          zero(src.value.size)));
            return;
        }
        MintOp op = MintOp::kInvalid;
        if (insn.id == X86_INS_ADD) op = MintOp::kAdd;
        else if (insn.id == X86_INS_SUB) op = MintOp::kSub;
        else if (insn.id == X86_INS_AND) op = MintOp::kAnd;
        else if (insn.id == X86_INS_OR) op = MintOp::kOr;
        else if (insn.id == X86_INS_XOR) op = MintOp::kXor;
        else if (insn.id == X86_INS_ANDPS || insn.id == X86_INS_ANDPD ||
                 insn.id == X86_INS_PAND) op = MintOp::kAnd;
        else if (insn.id == X86_INS_ORPS || insn.id == X86_INS_ORPD ||
                 insn.id == X86_INS_POR) op = MintOp::kOr;
        else if (insn.id == X86_INS_XORPS || insn.id == X86_INS_XORPD ||
                 insn.id == X86_INS_PXOR) op = MintOp::kXor;
        else if (insn.id == X86_INS_SHL || insn.id == X86_INS_SAL) op = MintOp::kShl;
        else if (insn.id == X86_INS_SHR) op = MintOp::kShrU;
        else if (insn.id == X86_INS_SAR) op = MintOp::kShrS;
        else if (insn.id == X86_INS_ROL) op = MintOp::kRotL;
        else if (insn.id == X86_INS_ROR) op = MintOp::kRotR;
        if (op != MintOp::kInvalid && dst.value.valid() && src.value.valid()) {
            Varnode source = src.value;
            if (source.size != dst.value.size && op != MintOp::kShl &&
                op != MintOp::kShrU && op != MintOp::kShrS) {
                source = builder.resize(source, dst.value.size, false);
            }
            const Varnode result = builder.binary(op, dst.value, source);
            writeOperand(ops[0], dst, result, builder);
            if (insn.id == X86_INS_ADD || insn.id == X86_INS_SUB) {
                setArithmeticFlags(builder, op, dst.value, source, result);
            } else if (insn.id == X86_INS_AND || insn.id == X86_INS_OR ||
                       insn.id == X86_INS_XOR) {
                setLogicalFlags(builder, result);
            }
            return;
        }
        if (insn.id == X86_INS_CMP || insn.id == X86_INS_TEST) {
            const Varnode result = builder.newTemp(dst.value.size);
            Varnode source = src.value;
            if (source.size != dst.value.size) {
                source = builder.resize(source, dst.value.size, false);
            }
            const MintOp compareOp =
                insn.id == X86_INS_CMP ? MintOp::kSub : MintOp::kAnd;
            builder.emit(compareOp, result, dst.value, source);
            if (insn.id == X86_INS_CMP) {
                setArithmeticFlags(builder, compareOp, dst.value, source, result);
            } else {
                setLogicalFlags(builder, result);
            }
            return;
        }
        if (insn.id == X86_INS_MOVZX || insn.id == X86_INS_MOVSX || insn.id == X86_INS_MOVSXD) {
            const bool sign = insn.id == X86_INS_MOVSX || insn.id == X86_INS_MOVSXD;
            Operand destination = writeTarget(insn, ops[0], builder);
            writeOperand(ops[0], destination,
                         builder.resize(src.value, destination.value.size, sign), builder);
            return;
        }
    }

    if (count >= 1) {
        Operand dst = readOperand(insn, ops[0], builder);
        if ((insn.id == X86_INS_MUL || insn.id == X86_INS_IMUL) &&
            count == 1 && dst.value.valid()) {
            const bool signedMultiply = insn.id == X86_INS_IMUL;
            const u8 width = dst.value.size;
            if (width == 1) {
                const Varnode accumulator = Varnode::reg(x86::kRax, 1);
                const Varnode left = builder.resize(accumulator, 2, signedMultiply);
                const Varnode right = builder.resize(dst.value, 2, signedMultiply);
                builder.assign(Varnode::reg(x86::kRax, 2),
                               builder.binary(MintOp::kMul, left, right));
            } else {
                const Varnode accumulator = Varnode::reg(x86::kRax, width);
                const Varnode low = builder.binary(
                    MintOp::kMul, accumulator, dst.value);
                const Varnode high = builder.binary(
                    signedMultiply ? MintOp::kMulHiS : MintOp::kMulHiU,
                    accumulator, dst.value);
                builder.assign(Varnode::reg(x86::kRax, width), low);
                builder.assign(Varnode::reg(x86::kRdx, width), high);
            }
            // CF/OF encode whether the upper half is significant. Preserve the
            // arithmetic value even when that predicate is not yet represented.
            builder.emit(MintOp::kUndefined, flag(x86::kFlagCf));
            builder.emit(MintOp::kUndefined, flag(x86::kFlagOf));
            return;
        }
        if ((insn.id == X86_INS_DIV || insn.id == X86_INS_IDIV) &&
            count == 1 && dst.value.valid()) {
            // The mirror of the one-operand multiply above: that one writes RDX:RAX,
            // this one reads it. The dividend is twice the operand width, which is
            // why these need the wide opcodes rather than kDivU — a 64-bit DIV
            // divides 128 bits, and expressing it as a 64-bit divide would quietly
            // drop RDX and compute a different number.
            const bool signedDivide = insn.id == X86_INS_IDIV;
            const u8 width = dst.value.size;
            if (width == 1) {
                // Byte form is the odd one out: the dividend is AX, a single
                // register rather than a pair, and the results land in AL and AH.
                const Varnode dividend = Varnode::reg(x86::kRax, 2);
                const Varnode divisor = builder.resize(dst.value, 2, signedDivide);
                const Varnode quotient = builder.binary(
                    signedDivide ? MintOp::kDivS : MintOp::kDivU, dividend, divisor);
                const Varnode remainder = builder.binary(
                    signedDivide ? MintOp::kRemS : MintOp::kRemU, dividend, divisor);
                builder.assign(Varnode::reg(x86::kRax, 1),
                               builder.resize(quotient, 1, false));
                builder.assign(Varnode::reg(x86::kRax + 1, 1),
                               builder.resize(remainder, 1, false));
            } else {
                const Varnode low = Varnode::reg(x86::kRax, width);
                const Varnode high = Varnode::reg(x86::kRdx, width);
                const Varnode quotient = builder.ternary(
                    signedDivide ? MintOp::kDivWideS : MintOp::kDivWideU,
                    low, high, dst.value);
                const Varnode remainder = builder.ternary(
                    signedDivide ? MintOp::kRemWideS : MintOp::kRemWideU,
                    low, high, dst.value);
                // Both reads happen before either write, so the temporaries above
                // must be produced first — assigning RAX before building the
                // remainder would feed it the quotient.
                builder.assign(Varnode::reg(x86::kRax, width), quotient);
                builder.assign(Varnode::reg(x86::kRdx, width), remainder);
            }
            // Every arithmetic flag is architecturally undefined after a divide.
            builder.emit(MintOp::kUndefined, flag(x86::kFlagCf));
            builder.emit(MintOp::kUndefined, flag(x86::kFlagOf));
            builder.emit(MintOp::kUndefined, flag(x86::kFlagSf));
            builder.emit(MintOp::kUndefined, flag(x86::kFlagZf));
            builder.emit(MintOp::kUndefined, flag(x86::kFlagAf));
            builder.emit(MintOp::kUndefined, flag(x86::kFlagPf));
            return;
        }
        if (insn.id == X86_INS_NOT && dst.value.valid()) {
            writeOperand(ops[0], dst,
                         builder.unary(MintOp::kNot, dst.value, dst.value.size),
                         builder);
            return;
        }
        if (insn.id == X86_INS_INC || insn.id == X86_INS_DEC) {
            const MintOp operation =
                insn.id == X86_INS_INC ? MintOp::kAdd : MintOp::kSub;
            const Varnode one = Varnode::constant(1, dst.value.size);
            const Varnode result = builder.binary(operation, dst.value, one);
            writeOperand(ops[0], dst, result, builder);
            // INC/DEC preserve CF, but update the remaining arithmetic flags.
            setCommonFlags(builder, result);
            builder.assign(flag(x86::kFlagOf), builder.binary(
                operation == MintOp::kAdd ? MintOp::kOverflowAdd
                                          : MintOp::kOverflowSub,
                dst.value, one));
            return;
        }
        if (insn.id == X86_INS_NEG) {
            writeOperand(ops[0], dst, builder.unary(MintOp::kNeg, dst.value, dst.value.size), builder);
            return;
        }
        if (insn.id >= X86_INS_SETAE && insn.id <= X86_INS_SETS) {
            const Varnode condition = setConditionFor(insn, builder);
            if (condition.valid()) { writeOperand(ops[0], dst, condition, builder); return; }
        }
    }

    builder.emitIntrinsic(static_cast<u16>(insn.id));
}

}  // namespace mint
