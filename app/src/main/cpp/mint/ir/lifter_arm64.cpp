// AArch64 -> MintIR.
//
// The guiding rule is that flag effects are always explicit. AArch64 code decides
// almost everything through NZCV, and a lifter that summarised "this instruction
// sets the flags" would push the hard part onto every consumer. Writing the four
// flags as ordinary values means recovering `if (a < b)` from a `cmp` plus a
// `b.lt` later is a dataflow query and nothing more.
//
// Anything not modelled becomes kIntrinsic rather than nothing, and the count is
// reported, so lifter coverage is a number we measure rather than a claim.

#include "mint/ir/lifter_internal.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <unordered_map>

#include "mint/ir/registers.h"

namespace mint {
namespace {

class Arm64Lifter {
public:
    Arm64Lifter(const cs_insn& insn, IrBuilder& builder)
        : insn_(insn), detail_(insn.detail->aarch64), b_(builder) {}

    void lift();

private:
    const cs_insn& insn_;
    const cs_aarch64& detail_;
    IrBuilder& b_;

    const cs_aarch64_op& op(unsigned index) const { return detail_.operands[index]; }
    unsigned opCount() const { return detail_.op_count; }
    Address nextAddress() const { return insn_.address + insn_.size; }

    static Varnode zero(u8 size) { return Varnode::constant(0, size); }
    static Varnode trueValue() { return Varnode::constant(1, 1); }
    static Varnode flag(u64 offset) { return Varnode::reg(offset, 1); }
    static Varnode flagN() { return flag(arm64::kFlagN); }
    static Varnode flagZ() { return flag(arm64::kFlagZ); }
    static Varnode flagC() { return flag(arm64::kFlagC); }
    static Varnode flagV() { return flag(arm64::kFlagV); }

    /// Width of the destination register, which is what sets the operation width
    /// for nearly every AArch64 data-processing instruction.
    u8 operationWidth() const {
        if (opCount() == 0) return 8;
        const Varnode dest = op(0).type == AARCH64_OP_REG
                                 ? registerFromCapstone(Arch::kAArch64, op(0).reg)
                                 : Varnode::invalid();
        if (op(0).type == AARCH64_OP_REG && dest.valid()) return dest.size;
        // `cmp wN, ...` discards into wzr, so the width has to come from the
        // second operand instead.
        if (opCount() > 1 && op(1).type == AARCH64_OP_REG) {
            const Varnode other = registerFromCapstone(Arch::kAArch64, op(1).reg);
            if (other.valid()) return other.size;
        }
        return 8;
    }

    Varnode readReg(unsigned reg, u8 fallbackSize) {
        const Varnode node = registerFromCapstone(Arch::kAArch64, reg);
        // xzr and wzr are not storage; reading one yields zero.
        if (!node.valid()) return zero(fallbackSize);
        return node;
    }

    void writeReg(unsigned reg, const Varnode& value) {
        const Varnode dest = registerFromCapstone(Arch::kAArch64, reg);
        if (!dest.valid()) return;  // A write to the zero register is discarded.
        const Varnode sized = b_.resize(value, dest.size, false);

        // Writing a W register zeroes the upper half of the X register. Modelling
        // this is not optional: without it, dataflow believes the top 32 bits
        // survive, and a value built in x0 and then partly rewritten through w0
        // decompiles to nonsense. Only general-purpose registers behave this way,
        // hence the range check rather than a bare width test.
        const bool isGpr = dest.offset <= arm64::kSp;
        if (isGpr && dest.size == 4) {
            b_.emit(MintOp::kZeroExt, Varnode::reg(dest.offset, 8), sized);
        } else {
            b_.assign(dest, sized);
        }
    }

    Varnode applyShift(const Varnode& value, aarch64_shifter type, unsigned amount) {
        // For the register-shift forms Capstone stores a *register id* in the shift
        // value rather than a count. The header says so in passing and it is very
        // easy to miss: read as a literal, a register id becomes a shift of some
        // hundreds of bits, which is not an error anything downstream can detect.
        bool amountIsRegister = false;
        switch (type) {
            case AARCH64_SFT_LSL_REG:
            case AARCH64_SFT_LSR_REG:
            case AARCH64_SFT_ASR_REG:
            case AARCH64_SFT_ROR_REG:
            case AARCH64_SFT_MSL_REG:
                amountIsRegister = true;
                break;
            default:
                break;
        }
        const Varnode count = amountIsRegister ? readReg(amount, value.size)
                                               : Varnode::constant(amount, 1);

        switch (type) {
            case AARCH64_SFT_LSL:
            case AARCH64_SFT_LSL_REG: return b_.binary(MintOp::kShl, value, count);
            case AARCH64_SFT_LSR:
            case AARCH64_SFT_LSR_REG: return b_.binary(MintOp::kShrU, value, count);
            case AARCH64_SFT_ASR:
            case AARCH64_SFT_ASR_REG: return b_.binary(MintOp::kShrS, value, count);
            case AARCH64_SFT_ROR:
            case AARCH64_SFT_ROR_REG: return b_.binary(MintOp::kRotR, value, count);
            case AARCH64_SFT_MSL:
            case AARCH64_SFT_MSL_REG:
                // Only used by SIMD immediate forms, which are not modelled yet.
                return Varnode::invalid();
            default:
                return value;
        }
    }

    /// All-ones mask for the low `bits` bits, at `width` bytes.
    static u64 lowMask(unsigned bits, u8 width) {
        const u64 widthMask =
            width >= 8 ? ~u64(0) : ((u64(1) << (unsigned(width) * 8)) - 1);
        if (bits == 0) return 0;
        if (bits >= 64) return widthMask;
        return ((u64(1) << bits) - 1) & widthMask;
    }

    Varnode applyExtend(const Varnode& value, aarch64_extender ext, u8 destSize) {
        u8 fromBytes = destSize;
        bool signExtend = false;
        switch (ext) {
            case AARCH64_EXT_UXTB: fromBytes = 1; break;
            case AARCH64_EXT_UXTH: fromBytes = 2; break;
            case AARCH64_EXT_UXTW: fromBytes = 4; break;
            case AARCH64_EXT_UXTX: fromBytes = 8; break;
            case AARCH64_EXT_SXTB: fromBytes = 1; signExtend = true; break;
            case AARCH64_EXT_SXTH: fromBytes = 2; signExtend = true; break;
            case AARCH64_EXT_SXTW: fromBytes = 4; signExtend = true; break;
            case AARCH64_EXT_SXTX: fromBytes = 8; signExtend = true; break;
            default: return b_.resize(value, destSize, false);
        }
        const Varnode narrowed =
            b_.resize(value, std::min<u8>(fromBytes, value.size), false);
        return b_.resize(narrowed, destSize, signExtend);
    }

    /// Reads a register or immediate operand at `size`, applying any extend and
    /// shift the encoding carries.
    Varnode readOperand(unsigned index, u8 size) {
        const cs_aarch64_op& o = op(index);
        Varnode value;
        switch (o.type) {
            case AARCH64_OP_REG:
                value = readReg(o.reg, size);
                break;
            case AARCH64_OP_IMM:
                value = Varnode::constant(static_cast<u64>(o.imm), 8);
                break;
            default:
                return Varnode::invalid();
        }

        // Extension comes before shift: that is the order the extended-register
        // encoding applies them, and `add x0, x1, w2, sxtw #2` means shift the
        // sign-extended value, not sign-extend the shifted one.
        if (o.ext != AARCH64_EXT_INVALID) {
            value = applyExtend(value, o.ext, size);
        } else {
            value = b_.resize(value, size, false);
        }
        if (!value.valid()) return value;
        if (o.shift.type != AARCH64_SFT_INVALID) {
            value = applyShift(value, o.shift.type, o.shift.value);
        }
        return value;
    }

    /// Computes the effective address of a memory operand.
    Varnode memoryAddress(const cs_aarch64_op& o, bool includeDisplacement) {
        const aarch64_op_mem& mem = o.mem;
        Varnode address = readReg(mem.base, 8);
        address = b_.resize(address, 8, false);

        if (mem.index != AARCH64_REG_INVALID) {
            Varnode index = readReg(mem.index, 8);
            if (o.ext != AARCH64_EXT_INVALID) {
                index = applyExtend(index, o.ext, 8);
            } else {
                index = b_.resize(index, 8, false);
            }
            if (o.shift.type != AARCH64_SFT_INVALID) {
                index = applyShift(index, o.shift.type, o.shift.value);
            }
            address = b_.binary(MintOp::kAdd, address, index);
        }
        if (includeDisplacement && mem.disp != 0) {
            address = b_.binary(MintOp::kAdd, address,
                                Varnode::constant(static_cast<u64>(mem.disp), 8));
        }
        return address;
    }

    bool hasVectorOperand() const {
        for (unsigned i = 0; i < opCount(); ++i) {
            const cs_aarch64_op& operand = op(i);
            const Varnode node = operand.type == AARCH64_OP_REG
                                     ? registerFromCapstone(Arch::kAArch64, operand.reg)
                                     : Varnode::invalid();
            // Capstone uses a 16-byte Q register for both `vN.4s` and `qN`.
            // Arrangement values with a lane count have bits above the scalar
            // element width, so they are vector operands even when the register
            // view itself is narrower.
            if ((node.valid() && node.size == 16) ||
                (static_cast<unsigned>(operand.vas) >> 8) != 0) {
                return true;
            }
        }
        return false;
    }

    bool hasScalarFpOperand() const {
        for (unsigned i = 0; i < opCount(); ++i) {
            if (op(i).type != AARCH64_OP_REG) continue;
            const Varnode node = registerFromCapstone(Arch::kAArch64, op(i).reg);
            if (node.valid() && node.offset >= arm64::kV0 && node.offset < arm64::kFpsr &&
                node.size < 16) {
                return true;
            }
        }
        return false;
    }

    bool isFloatingMnemonic() const {
        const std::string mnemonic(insn_.mnemonic);
        return mnemonic.rfind("f", 0) == 0 || mnemonic.rfind("scvtf", 0) == 0 ||
               mnemonic.rfind("ucvtf", 0) == 0;
    }

    Varnode readFpOperand(unsigned index, u8 size) {
        if (index >= opCount()) return Varnode::invalid();
        const cs_aarch64_op& operand = op(index);
        if (operand.type == AARCH64_OP_FP) {
            if (size == 4) {
                const float value = static_cast<float>(operand.fp);
                u32 bits = 0;
                std::memcpy(&bits, &value, sizeof(bits));
                return Varnode::constant(bits, 4);
            }
            if (size == 8) {
                u64 bits = 0;
                std::memcpy(&bits, &operand.fp, sizeof(bits));
                return Varnode::constant(bits, 8);
            }
            return Varnode::invalid();
        }
        if (operand.type != AARCH64_OP_REG) return Varnode::invalid();
        return b_.resize(readReg(operand.reg, size), size, false);
    }

    Varnode vectorRegister(unsigned reg) const {
        const Varnode view = registerFromCapstone(Arch::kAArch64, reg);
        if (!view.valid() || view.offset < arm64::kV0 || view.offset >= arm64::kFpsr) {
            return Varnode::invalid();
        }
        const u64 base = arm64::kV0 + ((view.offset - arm64::kV0) / 16) * 16;
        return Varnode::reg(base, 16);
    }

    void writeVectorReg(unsigned reg, const Varnode& value) {
        const Varnode dest = vectorRegister(reg);
        if (!dest.valid()) return b_.emitIntrinsic(u16(insn_.id));
        b_.assign(dest, b_.resize(value, 16, false));
    }

    void setFloatCompareFlags(const Varnode& packed) {
        auto bit = [&](unsigned shift) {
            const Varnode shifted = shift == 0
                                        ? packed
                                        : b_.binary(MintOp::kShrU, packed,
                                                    Varnode::constant(shift, 1));
            const Varnode masked = b_.binary(MintOp::kAnd, shifted,
                                             Varnode::constant(1, 4));
            return b_.unary(MintOp::kTrunc, masked, 1);
        };
        b_.assign(flagN(), bit(31));
        b_.assign(flagZ(), bit(30));
        b_.assign(flagC(), bit(29));
        b_.assign(flagV(), bit(28));
    }

    void liftFloating() {
        const std::string mnemonic(insn_.mnemonic);
        const u8 width = operationWidth();

        if ((mnemonic == "ldr" || mnemonic == "ldur" || mnemonic == "ldp") &&
            opCount() >= 2) {
            loadStore(true, width, false);
            return;
        }
        if ((mnemonic == "str" || mnemonic == "stur" || mnemonic == "stp") &&
            opCount() >= 2) {
            loadStore(false, width, false);
            return;
        }
        if (mnemonic == "fcmp" || mnemonic == "fcmpe") {
            if (opCount() < 2) return b_.emitIntrinsic(u16(insn_.id));
            const Varnode a = readFpOperand(0, width);
            const Varnode c = readFpOperand(1, width);
            if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));
            const Varnode packed = b_.newTemp(4);
            b_.emit(MintOp::kFloatCmp, packed, a, c);
            setFloatCompareFlags(packed);
            return;
        }
        if (mnemonic == "fmov") {
            if (opCount() < 2) return b_.emitIntrinsic(u16(insn_.id));
            const Varnode value = readFpOperand(1, width);
            if (!value.valid()) return b_.emitIntrinsic(u16(insn_.id));
            writeReg(op(0).reg, value);
            return;
        }
        if (mnemonic == "movi" && opCount() >= 2 && op(1).type == AARCH64_OP_IMM) {
            writeReg(op(0).reg, Varnode::constant(static_cast<u64>(op(1).imm), width));
            return;
        }

        MintOp binaryOp = MintOp::kInvalid;
        if (mnemonic == "fadd") binaryOp = MintOp::kFloatAdd;
        if (mnemonic == "fsub") binaryOp = MintOp::kFloatSub;
        if (mnemonic == "fmul") binaryOp = MintOp::kFloatMul;
        if (mnemonic == "fdiv") binaryOp = MintOp::kFloatDiv;
        if (binaryOp != MintOp::kInvalid && opCount() >= 3) {
            const Varnode a = readFpOperand(1, width);
            const Varnode c = readFpOperand(2, width);
            if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));
            writeReg(op(0).reg, b_.binary(binaryOp, a, c));
            return;
        }

        MintOp unaryOpCode = MintOp::kInvalid;
        if (mnemonic == "fsqrt") unaryOpCode = MintOp::kFloatSqrt;
        if (mnemonic == "fabs") unaryOpCode = MintOp::kFloatAbs;
        if (mnemonic == "fneg") unaryOpCode = MintOp::kFloatNeg;
        if (unaryOpCode != MintOp::kInvalid && opCount() >= 2) {
            const Varnode value = readFpOperand(1, width);
            if (!value.valid()) return b_.emitIntrinsic(u16(insn_.id));
            writeReg(op(0).reg, b_.unary(unaryOpCode, value, width));
            return;
        }

        MintOp conversion = MintOp::kInvalid;
        if (mnemonic == "scvtf" || mnemonic == "ucvtf") conversion = MintOp::kIntToFloat;
        if (mnemonic.rfind("fcvtz", 0) == 0 || mnemonic.rfind("fcvta", 0) == 0 ||
            mnemonic.rfind("fcvtm", 0) == 0 || mnemonic.rfind("fcvtp", 0) == 0 ||
            mnemonic.rfind("fcvtn", 0) == 0) {
            conversion = MintOp::kFloatToInt;
        }
        if (conversion != MintOp::kInvalid && opCount() >= 2) {
            const Varnode source = readFpOperand(1, width);
            if (!source.valid()) return b_.emitIntrinsic(u16(insn_.id));
            writeReg(op(0).reg, b_.unary(conversion, source, width));
            return;
        }
        // `fcvt s0, d1` is a representation conversion, not an integer
        // conversion. The bit-precise cast is intentionally kept as a copy at
        // this IR layer; width recovery still sees the destination width.
        if (mnemonic == "fcvt" && opCount() >= 2) {
            const Varnode source = readFpOperand(1, width);
            if (!source.valid()) return b_.emitIntrinsic(u16(insn_.id));
            writeReg(op(0).reg, source);
            return;
        }
        b_.emitIntrinsic(u16(insn_.id));
    }

    void vectorMemory(bool isLoad) {
        unsigned memIndex = opCount();
        for (unsigned i = 0; i < opCount(); ++i) {
            if (op(i).type == AARCH64_OP_MEM) {
                memIndex = i;
                break;
            }
        }
        if (memIndex >= opCount()) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode address = memoryAddress(op(memIndex), true);
        for (unsigned i = 0; i < memIndex; ++i) {
            const Varnode reg = vectorRegister(op(i).reg);
            if (!reg.valid()) return b_.emitIntrinsic(u16(insn_.id));
            Varnode slotAddress = address;
            if (i != 0) {
                slotAddress = b_.binary(MintOp::kAdd, address,
                                        Varnode::constant(u64(i) * 16, 8));
            }
            if (isLoad) {
                const Varnode value = b_.newTemp(16);
                b_.emit(MintOp::kVectorLoad, value, slotAddress);
                writeVectorReg(op(i).reg, value);
            } else {
                b_.emit(MintOp::kVectorStore, Varnode::invalid(), slotAddress,
                        reg);
            }
        }
    }

    void liftVector() {
        const std::string mnemonic(insn_.mnemonic);
        if (mnemonic == "ldr" || mnemonic == "ldur" || mnemonic == "ldp" ||
            mnemonic == "ld1" ||
            mnemonic.rfind("ld1", 0) == 0 || mnemonic.rfind("ld2", 0) == 0 ||
            mnemonic.rfind("ld3", 0) == 0 || mnemonic.rfind("ld4", 0) == 0) {
            vectorMemory(true);
            return;
        }
        if (mnemonic == "str" || mnemonic == "stur" || mnemonic == "stp" ||
            mnemonic == "st1" ||
            mnemonic.rfind("st1", 0) == 0 || mnemonic.rfind("st2", 0) == 0 ||
            mnemonic.rfind("st3", 0) == 0 || mnemonic.rfind("st4", 0) == 0) {
            vectorMemory(false);
            return;
        }
        if ((mnemonic == "add" || mnemonic == "sub" || mnemonic == "mul" ||
             mnemonic == "fadd" || mnemonic == "fsub" || mnemonic == "fmul") &&
            opCount() >= 3) {
            const Varnode a = vectorRegister(op(1).reg);
            const Varnode c = vectorRegister(op(2).reg);
            if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));
            const MintOp operation = mnemonic == "add" || mnemonic == "fadd"
                                         ? MintOp::kVectorAdd
                                         : (mnemonic == "sub" || mnemonic == "fsub"
                                                ? MintOp::kVectorSub
                                                               : MintOp::kVectorMul);
            writeVectorReg(op(0).reg, b_.binary(operation, a, c));
            return;
        }
        if (mnemonic == "dup" || mnemonic == "movi") {
            if (opCount() < 2) return b_.emitIntrinsic(u16(insn_.id));
            Varnode source;
            if (op(1).type == AARCH64_OP_REG) source = readReg(op(1).reg, 8);
            if (op(1).type == AARCH64_OP_IMM) source = Varnode::constant(
                static_cast<u64>(op(1).imm), 8);
            if (!source.valid()) return b_.emitIntrinsic(u16(insn_.id));
            writeVectorReg(op(0).reg, b_.unary(MintOp::kVectorSplat, source, 16));
            return;
        }
        if (mnemonic == "tbl" || mnemonic == "tbx" || mnemonic == "uzp1" ||
            mnemonic == "uzp2" || mnemonic == "zip1" || mnemonic == "zip2") {
            if (opCount() < 3 || op(1).type != AARCH64_OP_REG ||
                op(2).type != AARCH64_OP_REG) {
                return b_.emitIntrinsic(u16(insn_.id));
            }
            const Varnode first = vectorRegister(op(1).reg);
            const Varnode second = vectorRegister(op(2).reg);
            if (!first.valid() || !second.valid()) return b_.emitIntrinsic(u16(insn_.id));
            const Varnode selector = Varnode::constant(
                mnemonic == "uzp2" || mnemonic == "zip2" ? 1 : 0, 16);
            const Varnode dest = vectorRegister(op(0).reg);
            if (!dest.valid()) return b_.emitIntrinsic(u16(insn_.id));
            b_.emit(MintOp::kVectorShuffle, dest, first, second, selector);
            return;
        }
        if (mnemonic == "bit" || mnemonic == "bif") {
            if (opCount() < 3) return b_.emitIntrinsic(u16(insn_.id));
            const Varnode dest = vectorRegister(op(0).reg);
            const Varnode first = vectorRegister(op(1).reg);
            const Varnode second = vectorRegister(op(2).reg);
            if (!dest.valid() || !first.valid() || !second.valid()) {
                return b_.emitIntrinsic(u16(insn_.id));
            }
            const Varnode output = vectorRegister(op(0).reg);
            b_.emit(mnemonic == "bit" ? MintOp::kVectorBit : MintOp::kVectorBif,
                    output, dest, first, second);
            return;
        }
        if ((mnemonic == "and" || mnemonic == "orr" || mnemonic == "eor" ||
             mnemonic == "bic") && opCount() >= 3) {
            const Varnode a = vectorRegister(op(1).reg);
            const Varnode c = vectorRegister(op(2).reg);
            if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));
            const MintOp operation = mnemonic == "and" || mnemonic == "bic"
                                         ? MintOp::kAnd
                                         : (mnemonic == "orr" ? MintOp::kOr : MintOp::kXor);
            const Varnode source = mnemonic == "bic"
                                       ? b_.unary(MintOp::kNot, c, 16)
                                       : c;
            writeVectorReg(op(0).reg, b_.binary(operation, a, source));
            return;
        }
        if ((mnemonic == "mov" || mnemonic == "orr") && opCount() == 2) {
            const Varnode source = vectorRegister(op(1).reg);
            if (!source.valid()) return b_.emitIntrinsic(u16(insn_.id));
            writeVectorReg(op(0).reg, source);
            return;
        }
        b_.emitIntrinsic(u16(insn_.id));
    }

    Varnode notBool(const Varnode& value) {
        // Bitwise not is wrong here: these are 0-or-1 bytes, and ~1 is 0xfe.
        return b_.binary(MintOp::kEqual, value, zero(1));
    }

    Varnode condition(AArch64CC_CondCode cc) {
        switch (cc) {
            case AArch64CC_EQ: return flagZ();
            case AArch64CC_NE: return notBool(flagZ());
            case AArch64CC_HS: return flagC();
            case AArch64CC_LO: return notBool(flagC());
            case AArch64CC_MI: return flagN();
            case AArch64CC_PL: return notBool(flagN());
            case AArch64CC_VS: return flagV();
            case AArch64CC_VC: return notBool(flagV());
            case AArch64CC_HI:
                return b_.binary(MintOp::kAnd, flagC(), notBool(flagZ()));
            case AArch64CC_LS:
                return notBool(b_.binary(MintOp::kAnd, flagC(), notBool(flagZ())));
            case AArch64CC_GE: return b_.binary(MintOp::kEqual, flagN(), flagV());
            case AArch64CC_LT: return b_.binary(MintOp::kNotEqual, flagN(), flagV());
            case AArch64CC_GT: {
                const Varnode sameSign = b_.binary(MintOp::kEqual, flagN(), flagV());
                return b_.binary(MintOp::kAnd, notBool(flagZ()), sameSign);
            }
            case AArch64CC_LE: {
                const Varnode sameSign = b_.binary(MintOp::kEqual, flagN(), flagV());
                return notBool(b_.binary(MintOp::kAnd, notBool(flagZ()), sameSign));
            }
            default:
                return trueValue();
        }
    }

    void setNZ(const Varnode& result) {
        b_.emit(MintOp::kEqual, flagZ(), result, zero(result.size));
        b_.emit(MintOp::kLessS, flagN(), result, zero(result.size));
    }

    void setFlagsLogical(const Varnode& result) {
        setNZ(result);
        b_.assign(flagC(), zero(1));
        b_.assign(flagV(), zero(1));
    }

    void setFlagsAdd(const Varnode& a, const Varnode& c, const Varnode& result) {
        setNZ(result);
        b_.emit(MintOp::kCarryAdd, flagC(), a, c);
        b_.emit(MintOp::kOverflowAdd, flagV(), a, c);
    }

    void setFlagsSub(const Varnode& a, const Varnode& c, const Varnode& result) {
        setNZ(result);
        // On AArch64 the carry flag after a subtraction means "no borrow", so it is
        // the negation of the borrow rather than the borrow itself.
        b_.assign(flagC(), notBool(b_.binary(MintOp::kBorrowSub, a, c)));
        b_.emit(MintOp::kOverflowSub, flagV(), a, c);
    }

    // ---------------------------------------------------------------- handlers

    /// dest = a <op> b, optionally setting flags. `discardResult` covers cmp, cmn
    /// and tst, which compute into the zero register purely for their flags.
    void arithmetic(MintOp irOp, bool setsFlags, bool discardResult) {
        const u8 width = operationWidth();
        const unsigned firstSource = discardResult ? 0 : 1;
        if (opCount() <= firstSource) return b_.emitIntrinsic(u16(insn_.id));

        const Varnode a = readOperand(firstSource, width);
        const Varnode c = opCount() > firstSource + 1
                              ? readOperand(firstSource + 1, width)
                              : zero(width);
        if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));

        const Varnode result = b_.binary(irOp, a, c);
        if (!discardResult) writeReg(op(0).reg, result);
        if (setsFlags) {
            switch (irOp) {
                case MintOp::kAdd: setFlagsAdd(a, c, result); break;
                case MintOp::kSub: setFlagsSub(a, c, result); break;
                default: setFlagsLogical(result); break;
            }
        }
    }

    void unaryOp(MintOp irOp, bool setsFlags) {
        const u8 width = operationWidth();
        if (opCount() < 2) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode a = readOperand(1, width);
        if (!a.valid()) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode result = b_.unary(irOp, a, width);
        writeReg(op(0).reg, result);
        if (setsFlags) {
            if (irOp == MintOp::kNeg) {
                setFlagsSub(zero(width), a, result);
            } else {
                setFlagsLogical(result);
            }
        }
    }

    /// mul, madd, msub and mneg, which all reduce to a multiply plus an optional
    /// accumulate.
    void multiplyAccumulate(bool subtract, bool negate) {
        const u8 width = operationWidth();
        if (opCount() < 3) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode a = readOperand(1, width);
        const Varnode c = readOperand(2, width);
        if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));

        Varnode result = b_.binary(MintOp::kMul, a, c);
        if (opCount() >= 4) {
            const Varnode addend = readOperand(3, width);
            if (!addend.valid()) return b_.emitIntrinsic(u16(insn_.id));
            result = subtract ? b_.binary(MintOp::kSub, addend, result)
                              : b_.binary(MintOp::kAdd, addend, result);
        } else if (negate) {
            result = b_.unary(MintOp::kNeg, result, width);
        }
        writeReg(op(0).reg, result);
    }

    /// The widening multiplies: operands are 32-bit, the result 64-bit.
    void multiplyLong(bool signedOperands) {
        if (opCount() < 3) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode a = b_.resize(readOperand(1, 4), 8, signedOperands);
        const Varnode c = b_.resize(readOperand(2, 4), 8, signedOperands);
        if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));
        Varnode result = b_.binary(MintOp::kMul, a, c);
        if (opCount() >= 4) {
            const Varnode addend = readOperand(3, 8);
            result = b_.binary(MintOp::kAdd, addend, result);
        }
        writeReg(op(0).reg, result);
    }

    void extend(u8 fromBytes, bool signExtend) {
        if (opCount() < 2) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode dest = registerFromCapstone(Arch::kAArch64, op(0).reg);
        const u8 width = dest.valid() ? dest.size : 8;
        const Varnode source = readReg(op(1).reg, width);
        const Varnode narrowed =
            b_.resize(source, std::min<u8>(fromBytes, source.size), false);
        writeReg(op(0).reg, b_.resize(narrowed, width, signExtend));
    }

    void shift(MintOp irOp) {
        const u8 width = operationWidth();
        if (opCount() < 2) return b_.emitIntrinsic(u16(insn_.id));

        if (opCount() >= 3) {
            const Varnode a = readOperand(1, width);
            const Varnode amount = readOperand(2, width);
            if (!a.valid() || !amount.valid()) return b_.emitIntrinsic(u16(insn_.id));
            writeReg(op(0).reg, b_.binary(irOp, a, amount));
            return;
        }

        // The two-operand form. `lsr x12, x9, #2` reaches us as two operands with
        // the count folded into the source operand's shift field — which readOperand
        // already applies — so there is nothing further to do here. Requiring three
        // operands is what previously turned every immediate shift in the library
        // into an intrinsic.
        const Varnode value = readOperand(1, width);
        if (!value.valid()) return b_.emitIntrinsic(u16(insn_.id));
        writeReg(op(0).reg, value);
    }

    /// The bitfield instructions: ubfx, sbfx, ubfiz, sbfiz, bfi and bfxil.
    ///
    /// All six are "take `fieldWidth` bits and put them somewhere else", differing
    /// only in which end they come from, whether the result is sign-extended, and
    /// whether the untouched bits of the destination survive.
    void bitfield(bool insertForm, bool signExtend, bool preserveDestination) {
        if (opCount() < 4) return b_.emitIntrinsic(u16(insn_.id));
        const u8 width = operationWidth();
        const unsigned registerBits = unsigned(width) * 8;
        const Varnode source = readOperand(1, width);
        if (!source.valid()) return b_.emitIntrinsic(u16(insn_.id));

        const unsigned position = unsigned(op(2).imm);
        const unsigned fieldWidth = unsigned(op(3).imm);
        if (fieldWidth == 0 || position >= registerBits ||
            fieldWidth > registerBits) {
            return b_.emitIntrinsic(u16(insn_.id));
        }

        Varnode field;
        if (insertForm) {
            // ubfiz / sbfiz / bfi: the low bits of the source move up to `position`.
            const Varnode masked =
                b_.binary(MintOp::kAnd, source,
                          Varnode::constant(lowMask(fieldWidth, width), width));
            field = position == 0
                        ? masked
                        : b_.binary(MintOp::kShl, masked,
                                    Varnode::constant(position, 1));
        } else {
            // ubfx / sbfx / bfxil: the field is extracted down to bit zero.
            const Varnode shifted =
                position == 0 ? source
                              : b_.binary(MintOp::kShrU, source,
                                          Varnode::constant(position, 1));
            field = b_.binary(MintOp::kAnd, shifted,
                              Varnode::constant(lowMask(fieldWidth, width), width));
        }

        if (signExtend && fieldWidth < registerBits) {
            // Sign-extending an arbitrary bit width means shifting the field's top
            // bit up to the register's top bit and back down arithmetically; there
            // is no byte-aligned extension that would do it.
            const unsigned slack = registerBits - fieldWidth;
            const Varnode up = b_.binary(MintOp::kShl, field,
                                         Varnode::constant(slack, 1));
            field = b_.binary(MintOp::kShrS, up, Varnode::constant(slack, 1));
        }

        if (preserveDestination) {
            const u64 keepMask =
                insertForm ? ~(lowMask(fieldWidth, width) << position)
                           : ~lowMask(fieldWidth, width);
            const Varnode current = readReg(op(0).reg, width);
            const Varnode kept =
                b_.binary(MintOp::kAnd, current,
                          Varnode::constant(keepMask & lowMask(registerBits, width),
                                            width));
            field = b_.binary(MintOp::kOr, kept, field);
        }
        writeReg(op(0).reg, field);
    }

    /// adc, adcs, sbc and sbcs — add or subtract with the carry flag folded in.
    ///
    /// These are how multi-word arithmetic and 128-bit comparisons are built, so the
    /// flags have to come out exactly right rather than approximately: a wrong
    /// overflow bit here turns a correct 128-bit comparison into a plausible wrong
    /// one. Both flags are therefore computed from the two-step carry rather than
    /// reusing the single-operation opcodes, which cannot see the incoming carry.
    void addWithCarry(bool subtract, bool setsFlags) {
        if (opCount() < 3) return b_.emitIntrinsic(u16(insn_.id));
        const u8 width = operationWidth();
        const Varnode a = readOperand(1, width);
        const Varnode c = readOperand(2, width);
        if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));

        // On AArch64 the carry flag means "no borrow" for subtraction, so what gets
        // subtracted is its complement.
        const Varnode carryIn =
            subtract ? notBool(flagC()) : Varnode(flagC());
        const Varnode carryWide = b_.resize(carryIn, width, false);

        const MintOp step = subtract ? MintOp::kSub : MintOp::kAdd;
        const Varnode partial = b_.binary(step, a, c);
        const Varnode result = b_.binary(step, partial, carryWide);
        writeReg(op(0).reg, result);
        if (!setsFlags) return;

        setNZ(result);

        // Carry out of the whole operation is carry out of either step.
        const MintOp carryOp = subtract ? MintOp::kBorrowSub : MintOp::kCarryAdd;
        const Varnode first = b_.binary(carryOp, a, c);
        const Varnode second = b_.binary(carryOp, partial, carryWide);
        const Varnode combined = b_.binary(MintOp::kOr, first, second);
        b_.assign(flagC(), subtract ? notBool(combined) : combined);

        // Signed overflow, stated directly from the operand signs: for an addition
        // it needs both inputs to share a sign and the result to differ; for a
        // subtraction, the inputs to differ and the result to differ from the first.
        const Varnode signA = b_.binary(MintOp::kLessS, a, zero(width));
        const Varnode signB = b_.binary(MintOp::kLessS, c, zero(width));
        const Varnode signR = b_.binary(MintOp::kLessS, result, zero(width));
        const Varnode inputsRelated =
            b_.binary(subtract ? MintOp::kNotEqual : MintOp::kEqual, signA, signB);
        const Varnode resultTurned = b_.binary(MintOp::kNotEqual, signR, signA);
        b_.emit(MintOp::kAnd, flagV(), inputsRelated, resultTurned);
    }

    /// umulh and smulh: the high half of a full-width product.
    void multiplyHigh(bool signedOperands) {
        if (opCount() < 3) return b_.emitIntrinsic(u16(insn_.id));
        const u8 width = operationWidth();
        const Varnode a = readOperand(1, width);
        const Varnode c = readOperand(2, width);
        if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));
        writeReg(op(0).reg,
                 b_.binary(signedOperands ? MintOp::kMulHiS : MintOp::kMulHiU, a, c));
    }

    /// One load or store. `accessBytes` is the width touched in memory, which for
    /// the signed and zero-extending forms is narrower than the register.
    void loadStore(bool isLoad, u8 accessBytes, bool signExtend) {
        // The memory operand is last; the value registers come first, which is what
        // makes ldp and stp fall out of the same code.
        unsigned memIndex = opCount();
        for (unsigned i = 0; i < opCount(); ++i) {
            if (op(i).type == AARCH64_OP_MEM) {
                memIndex = i;
                break;
            }
        }
        if (memIndex >= opCount()) return b_.emitIntrinsic(u16(insn_.id));

        const cs_aarch64_op& memOperand = op(memIndex);
        const bool writeback = insn_.detail->writeback;
        const bool postIndex = writeback && detail_.post_index;

        // Post-indexed forms use the base register as the address and update it
        // afterwards; pre-indexed forms use base+displacement for both.
        Varnode address = memoryAddress(memOperand, !postIndex);

        for (unsigned i = 0; i < memIndex; ++i) {
            Varnode slotAddress = address;
            if (i != 0) {
                slotAddress = b_.binary(MintOp::kAdd, address,
                                        Varnode::constant(u64(i) * accessBytes, 8));
            }
            if (isLoad) {
                const Varnode dest = registerFromCapstone(Arch::kAArch64, op(i).reg);
                const u8 registerWidth = dest.valid() ? dest.size : accessBytes;
                const Varnode loaded = b_.newTemp(accessBytes);
                b_.emit(MintOp::kLoad, loaded, slotAddress);
                writeReg(op(i).reg, b_.resize(loaded, registerWidth, signExtend));
            } else {
                Varnode value = readReg(op(i).reg, accessBytes);
                value = b_.resize(value, accessBytes, false);
                b_.emit(MintOp::kStore, Varnode::invalid(), slotAddress, value);
            }
        }

        if (writeback && memOperand.mem.base != AARCH64_REG_INVALID) {
            if (!postIndex) {
                // Pre-indexed: the updated base is exactly the address already
                // computed above, so reusing it saves recomputing base+disp. Worth
                // doing rather than leaving to a later simplifier — every function
                // prologue and epilogue in the library is a pre-indexed stp or ldp.
                writeReg(memOperand.mem.base, address);
            } else {
                // Post-indexed: the address was the unmodified base, so the update
                // has to be computed.
                const Varnode base = readReg(memOperand.mem.base, 8);
                const Varnode updated = b_.binary(
                    MintOp::kAdd, base,
                    Varnode::constant(static_cast<u64>(memOperand.mem.disp), 8));
                writeReg(memOperand.mem.base, updated);
            }
        }
    }

    /// csel, csinc, csinv, csneg and the cset family, all of which are a select.
    void conditionalSelect(MintOp transform, bool allOnesWhenTrue) {
        const u8 width = operationWidth();
        const Varnode cond = condition(detail_.cc);

        Varnode whenTrue;
        Varnode whenFalse;
        if (opCount() >= 3) {
            whenTrue = readOperand(1, width);
            Varnode other = readOperand(2, width);
            whenFalse = transform == MintOp::kInvalid
                            ? other
                            : (transform == MintOp::kAdd
                                   ? b_.binary(MintOp::kAdd, other,
                                               Varnode::constant(1, width))
                                   : b_.unary(transform, other, width));
        } else {
            // cset / csetm: the arms are constants rather than registers.
            whenTrue = Varnode::constant(1, width);
            whenFalse = zero(width);
            if (allOnesWhenTrue) {
                // csetm writes all-ones rather than one.
                whenTrue = Varnode::constant(~u64(0) >> ((8 - width) * 8), width);
            }
        }
        if (!whenTrue.valid() || !whenFalse.valid()) {
            return b_.emitIntrinsic(u16(insn_.id));
        }
        const Varnode result = b_.newTemp(width);
        b_.emit(MintOp::kSelect, result, cond, whenTrue, whenFalse);
        writeReg(op(0).reg, result);
    }

    /// ccmp and ccmn: compare when the condition holds, otherwise load NZCV from
    /// an immediate. clang emits these constantly for short-circuit `&&` and `||`,
    /// so leaving them unmodelled would put a hole in the middle of most real
    /// conditionals.
    void conditionalCompare(bool isNegated) {
        if (opCount() < 3) return b_.emitIntrinsic(u16(insn_.id));
        const u8 width = operationWidth();
        const Varnode a = readOperand(0, width);
        const Varnode c = readOperand(1, width);
        if (!a.valid() || !c.valid()) return b_.emitIntrinsic(u16(insn_.id));

        const u64 immediateFlags = static_cast<u64>(op(2).imm);
        const Varnode cond = condition(detail_.cc);

        // Compute both the comparison flags and the immediate ones, then select.
        const Varnode result = isNegated ? b_.binary(MintOp::kAdd, a, c)
                                         : b_.binary(MintOp::kSub, a, c);
        const Varnode computedZ = b_.binary(MintOp::kEqual, result, zero(width));
        const Varnode computedN = b_.binary(MintOp::kLessS, result, zero(width));
        const Varnode computedC =
            isNegated ? b_.binary(MintOp::kCarryAdd, a, c)
                      : notBool(b_.binary(MintOp::kBorrowSub, a, c));
        const Varnode computedV = isNegated ? b_.binary(MintOp::kOverflowAdd, a, c)
                                            : b_.binary(MintOp::kOverflowSub, a, c);

        struct FlagSlot {
            Varnode target;
            Varnode computed;
            unsigned bit;
        };
        const FlagSlot slots[4] = {
            {flagN(), computedN, 3},
            {flagZ(), computedZ, 2},
            {flagC(), computedC, 1},
            {flagV(), computedV, 0},
        };
        for (const FlagSlot& slot : slots) {
            const Varnode fallback =
                Varnode::constant((immediateFlags >> slot.bit) & 1, 1);
            b_.emit(MintOp::kSelect, slot.target, cond, slot.computed, fallback);
        }
    }

    void compareAndBranch(bool branchIfZero) {
        if (opCount() < 2) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode value = readOperand(0, operationWidth());
        if (!value.valid()) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode isZero =
            b_.binary(MintOp::kEqual, value, zero(value.size));
        const Varnode cond = branchIfZero ? isZero : notBool(isZero);
        b_.emit(MintOp::kCondBranch, Varnode::invalid(), cond,
                Varnode::constant(static_cast<u64>(op(1).imm), 8));
    }

    void testAndBranch(bool branchIfZero) {
        if (opCount() < 3) return b_.emitIntrinsic(u16(insn_.id));
        const u8 width = operationWidth();
        const Varnode value = readOperand(0, width);
        if (!value.valid()) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode shifted =
            b_.binary(MintOp::kShrU, value,
                      Varnode::constant(static_cast<u64>(op(1).imm), 1));
        const Varnode bit =
            b_.binary(MintOp::kAnd, shifted, Varnode::constant(1, width));
        const Varnode isZero = b_.binary(MintOp::kEqual, bit, zero(width));
        const Varnode cond = branchIfZero ? isZero : notBool(isZero);
        b_.emit(MintOp::kCondBranch, Varnode::invalid(), cond,
                Varnode::constant(static_cast<u64>(op(2).imm), 8));
    }

    void branch() {
        if (opCount() < 1) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode target = Varnode::constant(static_cast<u64>(op(0).imm), 8);
        const bool conditional = detail_.cc != AArch64CC_Invalid &&
                                 detail_.cc != AArch64CC_AL &&
                                 detail_.cc != AArch64CC_NV;
        if (conditional) {
            b_.emit(MintOp::kCondBranch, Varnode::invalid(), condition(detail_.cc),
                    target);
        } else {
            b_.emit(MintOp::kBranch, Varnode::invalid(), target);
        }
    }

    /// cinc, cinv and cneg: two operands plus a condition, where the false arm is
    /// the source unchanged. Distinct from the cs* forms, which name both arms.
    void conditionalUnary(MintOp transform) {
        if (opCount() < 2) return b_.emitIntrinsic(u16(insn_.id));
        const u8 width = operationWidth();
        const Varnode source = readOperand(1, width);
        if (!source.valid()) return b_.emitIntrinsic(u16(insn_.id));
        const Varnode transformed =
            transform == MintOp::kAdd
                ? b_.binary(MintOp::kAdd, source, Varnode::constant(1, width))
                : b_.unary(transform, source, width);
        const Varnode result = b_.newTemp(width);
        b_.emit(MintOp::kSelect, result, condition(detail_.cc), transformed, source);
        writeReg(op(0).reg, result);
    }

    void call(bool indirect) {
        // bl and blr set the link register to the return address. Emitting that is
        // what lets the return site be recognised later without special-casing.
        b_.assign(Varnode::reg(arm64::kXn(30), 8),
                  Varnode::constant(nextAddress(), 8));
        if (indirect) {
            const Varnode target = opCount() > 0 ? readReg(op(0).reg, 8) : zero(8);
            b_.emit(MintOp::kCallInd, Varnode::invalid(), target);
        } else {
            b_.emit(MintOp::kCall, Varnode::invalid(),
                    Varnode::constant(static_cast<u64>(op(0).imm), 8));
        }
    }
};

/// The mnemonics this front-end models.
///
/// Dispatch is by mnemonic rather than by Capstone instruction id, and that is a
/// deliberate correction rather than a shortcut. Capstone v6 reports a *real*
/// instruction id plus an *alias* id, and hands over the alias's operand list
/// whenever an alias applies — which is almost always, because even `add x0, x1, x2`
/// is recorded as an alias of the shifted form. Switching on ids therefore means
/// enumerating both a real id and one or more alias ids for every instruction, and
/// getting a pair wrong reads the wrong operand slots and silently produces IR that
/// verifies but computes something else.
///
/// The mnemonic has the property the ids lack: it and the operand list always come
/// from the same level, so `cmp` is two operands and `subs` is three, every time.
enum class A64Mnemonic {
    kUnknown = 0,
    kMov, kMovz, kMovk, kMovn, kMvn,
    kAdd, kAdds, kSub, kSubs, kCmp, kCmn, kNeg, kNegs,
    kAnd, kAnds, kOrr, kEor, kTst, kBic, kBics, kOrn, kEon,
    kLsl, kLsr, kAsr, kRor,
    kMul, kMadd, kMsub, kMneg, kSmull, kUmull, kSmaddl, kUmaddl, kSdiv, kUdiv,
    kUmulh, kSmulh, kAdc, kAdcs, kSbc, kSbcs,
    kUbfx, kSbfx, kUbfiz, kSbfiz, kBfi, kBfxil,
    kSxtb, kSxth, kSxtw, kUxtb, kUxth, kClz,
    kAdr, kAdrp,
    kLdr, kLdrb, kLdrh, kLdrsb, kLdrsh, kLdrsw, kLdp,
    kStr, kStrb, kStrh, kStp,
    kCsel, kCsinc, kCsinv, kCsneg, kCset, kCsetm, kCinc, kCinv, kCneg, kCcmp, kCcmn,
    kB, kBl, kBr, kBlr, kRet, kCbz, kCbnz, kTbz, kTbnz,
    kNoEffect,
};

A64Mnemonic lookupMnemonic(const char* text) {
    // Conditional branches carry the condition in the mnemonic ("b.eq"), while the
    // condition itself is already available in the detail, so only the part before
    // the dot is meaningful for dispatch.
    std::string key;
    for (const char* c = text; *c != '\0' && *c != '.'; ++c) key.push_back(*c);

    static const std::unordered_map<std::string, A64Mnemonic> kTable = {
        {"mov", A64Mnemonic::kMov},     {"movz", A64Mnemonic::kMovz},
        {"movk", A64Mnemonic::kMovk},   {"movn", A64Mnemonic::kMovn},
        {"mvn", A64Mnemonic::kMvn},
        {"add", A64Mnemonic::kAdd},     {"adds", A64Mnemonic::kAdds},
        {"sub", A64Mnemonic::kSub},     {"subs", A64Mnemonic::kSubs},
        {"cmp", A64Mnemonic::kCmp},     {"cmn", A64Mnemonic::kCmn},
        {"neg", A64Mnemonic::kNeg},     {"negs", A64Mnemonic::kNegs},
        {"and", A64Mnemonic::kAnd},     {"ands", A64Mnemonic::kAnds},
        {"orr", A64Mnemonic::kOrr},     {"eor", A64Mnemonic::kEor},
        {"tst", A64Mnemonic::kTst},     {"bic", A64Mnemonic::kBic},
        {"bics", A64Mnemonic::kBics},   {"orn", A64Mnemonic::kOrn},
        {"eon", A64Mnemonic::kEon},
        {"lsl", A64Mnemonic::kLsl},     {"lsr", A64Mnemonic::kLsr},
        {"asr", A64Mnemonic::kAsr},     {"ror", A64Mnemonic::kRor},
        {"mul", A64Mnemonic::kMul},     {"madd", A64Mnemonic::kMadd},
        {"msub", A64Mnemonic::kMsub},   {"mneg", A64Mnemonic::kMneg},
        {"smull", A64Mnemonic::kSmull}, {"umull", A64Mnemonic::kUmull},
        {"smaddl", A64Mnemonic::kSmaddl}, {"umaddl", A64Mnemonic::kUmaddl},
        {"sdiv", A64Mnemonic::kSdiv},   {"udiv", A64Mnemonic::kUdiv},
        {"umulh", A64Mnemonic::kUmulh}, {"smulh", A64Mnemonic::kSmulh},
        {"adc", A64Mnemonic::kAdc},     {"adcs", A64Mnemonic::kAdcs},
        {"sbc", A64Mnemonic::kSbc},     {"sbcs", A64Mnemonic::kSbcs},
        {"ubfx", A64Mnemonic::kUbfx},   {"sbfx", A64Mnemonic::kSbfx},
        {"ubfiz", A64Mnemonic::kUbfiz}, {"sbfiz", A64Mnemonic::kSbfiz},
        {"bfi", A64Mnemonic::kBfi},     {"bfxil", A64Mnemonic::kBfxil},
        {"sxtb", A64Mnemonic::kSxtb},   {"sxth", A64Mnemonic::kSxth},
        {"sxtw", A64Mnemonic::kSxtw},   {"uxtb", A64Mnemonic::kUxtb},
        {"uxth", A64Mnemonic::kUxth},   {"clz", A64Mnemonic::kClz},
        {"adr", A64Mnemonic::kAdr},     {"adrp", A64Mnemonic::kAdrp},
        // The unscaled (ldur/stur) forms differ only in encoding, so they share a
        // handler with the scaled ones.
        {"ldr", A64Mnemonic::kLdr},     {"ldur", A64Mnemonic::kLdr},
        {"ldrb", A64Mnemonic::kLdrb},   {"ldurb", A64Mnemonic::kLdrb},
        {"ldrh", A64Mnemonic::kLdrh},   {"ldurh", A64Mnemonic::kLdrh},
        {"ldrsb", A64Mnemonic::kLdrsb}, {"ldursb", A64Mnemonic::kLdrsb},
        {"ldrsh", A64Mnemonic::kLdrsh}, {"ldursh", A64Mnemonic::kLdrsh},
        {"ldrsw", A64Mnemonic::kLdrsw}, {"ldursw", A64Mnemonic::kLdrsw},
        {"ldp", A64Mnemonic::kLdp},
        // The acquire and exclusive-load forms differ from a plain load only in
        // memory ordering, which the IR does not model and which does not change
        // any value a decompilation would show. The store-exclusive forms are
        // deliberately left unmodelled instead: they write a success flag that
        // retry loops branch on, so treating them as plain stores would silently
        // change control flow.
        {"ldar", A64Mnemonic::kLdr},    {"ldaxr", A64Mnemonic::kLdr},
        {"ldxr", A64Mnemonic::kLdr},    {"ldarb", A64Mnemonic::kLdrb},
        {"ldaxrb", A64Mnemonic::kLdrb}, {"ldxrb", A64Mnemonic::kLdrb},
        {"ldarh", A64Mnemonic::kLdrh},  {"ldaxrh", A64Mnemonic::kLdrh},
        {"ldxrh", A64Mnemonic::kLdrh},
        {"str", A64Mnemonic::kStr},     {"stur", A64Mnemonic::kStr},
        {"strb", A64Mnemonic::kStrb},   {"sturb", A64Mnemonic::kStrb},
        {"strh", A64Mnemonic::kStrh},   {"sturh", A64Mnemonic::kStrh},
        {"stp", A64Mnemonic::kStp},
        {"stlr", A64Mnemonic::kStr},    {"stlrb", A64Mnemonic::kStrb},
        {"stlrh", A64Mnemonic::kStrh},
        {"csel", A64Mnemonic::kCsel},   {"csinc", A64Mnemonic::kCsinc},
        {"csinv", A64Mnemonic::kCsinv}, {"csneg", A64Mnemonic::kCsneg},
        {"cset", A64Mnemonic::kCset},   {"csetm", A64Mnemonic::kCsetm},
        {"cinc", A64Mnemonic::kCinc},   {"cinv", A64Mnemonic::kCinv},
        {"cneg", A64Mnemonic::kCneg},   {"ccmp", A64Mnemonic::kCcmp},
        {"ccmn", A64Mnemonic::kCcmn},
        {"b", A64Mnemonic::kB},         {"bl", A64Mnemonic::kBl},
        {"br", A64Mnemonic::kBr},       {"braa", A64Mnemonic::kBr},
        {"brab", A64Mnemonic::kBr},     {"blr", A64Mnemonic::kBlr},
        {"blraa", A64Mnemonic::kBlr},   {"blrab", A64Mnemonic::kBlr},
        {"ret", A64Mnemonic::kRet},     {"retaa", A64Mnemonic::kRet},
        {"retab", A64Mnemonic::kRet},
        {"cbz", A64Mnemonic::kCbz},     {"cbnz", A64Mnemonic::kCbnz},
        {"tbz", A64Mnemonic::kTbz},     {"tbnz", A64Mnemonic::kTbnz},
        // Instructions with no effect on any value the IR tracks. Pointer
        // authentication is modelled as identity: for well-formed code the
        // signature is invisible to program semantics, and treating paciasp and
        // autiasp as opaque would sever the link register's dataflow through the
        // prologue of every function in a modern Android library.
        {"nop", A64Mnemonic::kNoEffect},     {"hint", A64Mnemonic::kNoEffect},
        {"bti", A64Mnemonic::kNoEffect},     {"paciasp", A64Mnemonic::kNoEffect},
        {"pacibsp", A64Mnemonic::kNoEffect}, {"autiasp", A64Mnemonic::kNoEffect},
        {"autibsp", A64Mnemonic::kNoEffect}, {"dmb", A64Mnemonic::kNoEffect},
        {"dsb", A64Mnemonic::kNoEffect},     {"isb", A64Mnemonic::kNoEffect},
    };

    const auto found = kTable.find(key);
    return found == kTable.end() ? A64Mnemonic::kUnknown : found->second;
}

void Arm64Lifter::lift() {
    b_.setAddress(insn_.address);

    // SIMD and scalar floating point share several mnemonics with the integer
    // forms. Route them before the integer switch so `add v0.4s, ...` cannot be
    // mistaken for a scalar add, while `fadd s0, ...` still gets its FP opcode.
    if (hasVectorOperand()) {
        liftVector();
        return;
    }
    if (isFloatingMnemonic() || hasScalarFpOperand()) {
        liftFloating();
        return;
    }

    const u8 width = operationWidth();

    switch (lookupMnemonic(insn_.mnemonic)) {
        // -- moves ---------------------------------------------------------
        case A64Mnemonic::kMov:
        case A64Mnemonic::kMovz:
            if (opCount() >= 2) {
                const Varnode value = readOperand(1, width);
                if (value.valid()) {
                    writeReg(op(0).reg, value);
                    break;
                }
            }
            b_.emitIntrinsic(u16(insn_.id));
            break;

        case A64Mnemonic::kMovn:
            if (opCount() >= 2) {
                const Varnode value = readOperand(1, width);
                if (value.valid()) {
                    writeReg(op(0).reg, b_.unary(MintOp::kNot, value, width));
                    break;
                }
            }
            b_.emitIntrinsic(u16(insn_.id));
            break;

        case A64Mnemonic::kMovk: {
            // Inserts a 16-bit field and leaves the rest of the register alone —
            // the one move that reads its own destination.
            if (opCount() < 2) {
                b_.emitIntrinsic(u16(insn_.id));
                break;
            }
            const unsigned shiftAmount =
                op(1).shift.type != AARCH64_SFT_INVALID ? op(1).shift.value : 0;
            // Both masks have to be narrowed to the operation width, or a 32-bit
            // movk would build a constant wider than the register it goes into.
            const u64 widthMask =
                width >= 8 ? ~u64(0) : ((u64(1) << (unsigned(width) * 8)) - 1);
            const u64 immediate =
                (static_cast<u64>(op(1).imm) << shiftAmount) & widthMask;
            const u64 clearMask = ~(u64(0xffff) << shiftAmount) & widthMask;
            const Varnode current = readReg(op(0).reg, width);
            const Varnode cleared =
                b_.binary(MintOp::kAnd, current, Varnode::constant(clearMask, width));
            writeReg(op(0).reg,
                     b_.binary(MintOp::kOr, cleared,
                               Varnode::constant(immediate & ~clearMask & widthMask,
                                                 width)));
            break;
        }

        case A64Mnemonic::kMvn: unaryOp(MintOp::kNot, false); break;

        // -- arithmetic ----------------------------------------------------
        case A64Mnemonic::kAdd: arithmetic(MintOp::kAdd, false, false); break;
        case A64Mnemonic::kAdds: arithmetic(MintOp::kAdd, true, false); break;
        case A64Mnemonic::kSub: arithmetic(MintOp::kSub, false, false); break;
        case A64Mnemonic::kSubs: arithmetic(MintOp::kSub, true, false); break;
        // The compare forms discard their result and exist purely for the flags.
        case A64Mnemonic::kCmp: arithmetic(MintOp::kSub, true, true); break;
        case A64Mnemonic::kCmn: arithmetic(MintOp::kAdd, true, true); break;
        case A64Mnemonic::kNeg: unaryOp(MintOp::kNeg, false); break;
        case A64Mnemonic::kNegs: unaryOp(MintOp::kNeg, true); break;

        // -- logic ---------------------------------------------------------
        case A64Mnemonic::kAnd: arithmetic(MintOp::kAnd, false, false); break;
        case A64Mnemonic::kAnds: arithmetic(MintOp::kAnd, true, false); break;
        case A64Mnemonic::kOrr: arithmetic(MintOp::kOr, false, false); break;
        case A64Mnemonic::kEor: arithmetic(MintOp::kXor, false, false); break;
        case A64Mnemonic::kTst: arithmetic(MintOp::kAnd, true, true); break;

        case A64Mnemonic::kBic:
        case A64Mnemonic::kBics:
        case A64Mnemonic::kOrn:
        case A64Mnemonic::kEon: {
            // The inverted-operand forms: the second source is complemented first.
            if (opCount() < 3) {
                b_.emitIntrinsic(u16(insn_.id));
                break;
            }
            const Varnode a = readOperand(1, width);
            const Varnode raw = readOperand(2, width);
            if (!a.valid() || !raw.valid()) {
                b_.emitIntrinsic(u16(insn_.id));
                break;
            }
            const A64Mnemonic which = lookupMnemonic(insn_.mnemonic);
            const Varnode inverted = b_.unary(MintOp::kNot, raw, width);
            const MintOp irOp = which == A64Mnemonic::kOrn
                                    ? MintOp::kOr
                                    : (which == A64Mnemonic::kEon ? MintOp::kXor
                                                                  : MintOp::kAnd);
            const Varnode result = b_.binary(irOp, a, inverted);
            writeReg(op(0).reg, result);
            if (which == A64Mnemonic::kBics) setFlagsLogical(result);
            break;
        }

        // -- shifts --------------------------------------------------------
        case A64Mnemonic::kLsl: shift(MintOp::kShl); break;
        case A64Mnemonic::kLsr: shift(MintOp::kShrU); break;
        case A64Mnemonic::kAsr: shift(MintOp::kShrS); break;
        case A64Mnemonic::kRor: shift(MintOp::kRotR); break;

        // -- multiply and divide -------------------------------------------
        case A64Mnemonic::kMul: multiplyAccumulate(false, false); break;
        case A64Mnemonic::kMadd: multiplyAccumulate(false, false); break;
        case A64Mnemonic::kMsub: multiplyAccumulate(true, false); break;
        case A64Mnemonic::kMneg: multiplyAccumulate(false, true); break;
        case A64Mnemonic::kSmull:
        case A64Mnemonic::kSmaddl: multiplyLong(true); break;
        case A64Mnemonic::kUmull:
        case A64Mnemonic::kUmaddl: multiplyLong(false); break;
        case A64Mnemonic::kSdiv: arithmetic(MintOp::kDivS, false, false); break;
        case A64Mnemonic::kUdiv: arithmetic(MintOp::kDivU, false, false); break;
        case A64Mnemonic::kAdc:  addWithCarry(false, false); break;
        case A64Mnemonic::kAdcs: addWithCarry(false, true);  break;
        case A64Mnemonic::kSbc:  addWithCarry(true,  false); break;
        case A64Mnemonic::kSbcs: addWithCarry(true,  true);  break;
        case A64Mnemonic::kUmulh: multiplyHigh(false); break;
        case A64Mnemonic::kSmulh: multiplyHigh(true); break;

        // -- bitfields -----------------------------------------------------
        //                     insert  signExtend  preserveDest
        case A64Mnemonic::kUbfx:  bitfield(false, false, false); break;
        case A64Mnemonic::kSbfx:  bitfield(false, true,  false); break;
        case A64Mnemonic::kUbfiz: bitfield(true,  false, false); break;
        case A64Mnemonic::kSbfiz: bitfield(true,  true,  false); break;
        case A64Mnemonic::kBfi:   bitfield(true,  false, true);  break;
        case A64Mnemonic::kBfxil: bitfield(false, false, true);  break;

        // -- extends and bit counting --------------------------------------
        case A64Mnemonic::kSxtb: extend(1, true); break;
        case A64Mnemonic::kSxth: extend(2, true); break;
        case A64Mnemonic::kSxtw: extend(4, true); break;
        case A64Mnemonic::kUxtb: extend(1, false); break;
        case A64Mnemonic::kUxth: extend(2, false); break;
        case A64Mnemonic::kClz: unaryOp(MintOp::kClz, false); break;

        // -- addresses -----------------------------------------------------
        case A64Mnemonic::kAdr:
        case A64Mnemonic::kAdrp:
            // Capstone has already folded the program counter and the page shift
            // into the immediate, so this is just a constant move.
            if (opCount() >= 2) {
                writeReg(op(0).reg, Varnode::constant(static_cast<u64>(op(1).imm), 8));
            } else {
                b_.emitIntrinsic(u16(insn_.id));
            }
            break;

        // -- memory --------------------------------------------------------
        case A64Mnemonic::kLdr: loadStore(true, width, false); break;
        case A64Mnemonic::kLdrb: loadStore(true, 1, false); break;
        case A64Mnemonic::kLdrh: loadStore(true, 2, false); break;
        case A64Mnemonic::kLdrsb: loadStore(true, 1, true); break;
        case A64Mnemonic::kLdrsh: loadStore(true, 2, true); break;
        case A64Mnemonic::kLdrsw: loadStore(true, 4, true); break;
        case A64Mnemonic::kLdp: loadStore(true, width, false); break;
        case A64Mnemonic::kStr: loadStore(false, width, false); break;
        case A64Mnemonic::kStrb: loadStore(false, 1, false); break;
        case A64Mnemonic::kStrh: loadStore(false, 2, false); break;
        case A64Mnemonic::kStp: loadStore(false, width, false); break;

        // -- conditional selects -------------------------------------------
        case A64Mnemonic::kCsel: conditionalSelect(MintOp::kInvalid, false); break;
        case A64Mnemonic::kCsinc: conditionalSelect(MintOp::kAdd, false); break;
        case A64Mnemonic::kCsinv: conditionalSelect(MintOp::kNot, false); break;
        case A64Mnemonic::kCsneg: conditionalSelect(MintOp::kNeg, false); break;
        case A64Mnemonic::kCset: conditionalSelect(MintOp::kInvalid, false); break;
        case A64Mnemonic::kCsetm: conditionalSelect(MintOp::kInvalid, true); break;
        case A64Mnemonic::kCinc: conditionalUnary(MintOp::kAdd); break;
        case A64Mnemonic::kCinv: conditionalUnary(MintOp::kNot); break;
        case A64Mnemonic::kCneg: conditionalUnary(MintOp::kNeg); break;
        case A64Mnemonic::kCcmp: conditionalCompare(false); break;
        case A64Mnemonic::kCcmn: conditionalCompare(true); break;

        // -- control flow --------------------------------------------------
        case A64Mnemonic::kB: branch(); break;
        case A64Mnemonic::kBl: call(false); break;
        case A64Mnemonic::kBlr: call(true); break;
        case A64Mnemonic::kBr:
            b_.emit(MintOp::kBranchInd, Varnode::invalid(),
                    opCount() > 0 ? readReg(op(0).reg, 8) : zero(8));
            break;
        case A64Mnemonic::kRet:
            b_.emit(MintOp::kReturn, Varnode::invalid(),
                    opCount() > 0 ? readReg(op(0).reg, 8)
                                  : Varnode::reg(arm64::kXn(30), 8));
            break;
        case A64Mnemonic::kCbz: compareAndBranch(true); break;
        case A64Mnemonic::kCbnz: compareAndBranch(false); break;
        case A64Mnemonic::kTbz: testAndBranch(true); break;
        case A64Mnemonic::kTbnz: testAndBranch(false); break;

        case A64Mnemonic::kNoEffect:
            break;

        case A64Mnemonic::kUnknown:
        default:
            b_.emitIntrinsic(u16(insn_.id));
            break;
    }
}

}  // namespace

void liftAArch64(const cs_insn& insn, IrBuilder& builder) {
    if (insn.detail == nullptr) {
        builder.setAddress(insn.address);
        builder.emitIntrinsic(static_cast<u16>(insn.id));
        return;
    }
    Arm64Lifter lifter(insn, builder);
    lifter.lift();
}

}  // namespace mint
