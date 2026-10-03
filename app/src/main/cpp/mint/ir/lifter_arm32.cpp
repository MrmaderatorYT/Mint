#include "mint/ir/lifter_internal.h"
#include "mint/ir/registers.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace mint {
namespace {
class Arm32Lifter {
public:
    Arm32Lifter(const cs_insn& instruction, IrBuilder& builder, bool thumb)
        : i_(instruction), d_(instruction.detail->arm), b_(builder), thumb_(thumb) {}
    void lift();
    Varnode predicate() {return condition();}
private:
    const cs_insn& i_; const cs_arm& d_; IrBuilder& b_; bool thumb_;
    const cs_arm_op& op(unsigned index) const { return d_.operands[index]; }
    Varnode imm(i64 value, u8 width = 4) const { return Varnode::constant(static_cast<u64>(value) & ((u64{1} << (width * 8)) - 1), width); }
    Varnode flag(u64 offset) const { return Varnode::reg(offset, 1); }
    Varnode negateBool(const Varnode& value) { return b_.binary(MintOp::kEqual, value, imm(0,1)); }
    void fail() { b_.emitIntrinsic(static_cast<u16>(i_.id)); }
    Varnode readReg(unsigned reg) {
        if (reg == ARM_REG_PC) return imm(static_cast<u32>(i_.address + (thumb_ ? 4 : 8)));
        const auto value = registerFromCapstone(thumb_ ? Arch::kThumb : Arch::kArm32, reg);
        return value.valid() && value.size == 4 && value.offset <= arm32::kPc ? value : Varnode::invalid();
    }
    bool scalarReg(unsigned reg) const {
        const auto value = registerFromCapstone(Arch::kArm32, reg);
        return value.valid() && value.size == 4 && value.offset <= arm32::kPc;
    }
    void writeReg(unsigned reg, const Varnode& value) {
        if (reg == ARM_REG_PC) { b_.emit(MintOp::kBranchInd, {}, b_.binary(MintOp::kAnd, value, imm(-2))); return; }
        b_.assign(registerFromCapstone(Arch::kArm32, reg), b_.resize(value, 4, false));
    }
    Varnode select(const Varnode& condition, const Varnode& yes, const Varnode& no) {
        auto output = b_.newTemp(yes.size); b_.emit(MintOp::kSelect, output, condition, yes, no); return output;
    }
    Varnode bit(const Varnode& value, const Varnode& count) {
        return b_.resize(b_.binary(MintOp::kAnd, b_.binary(MintOp::kShrU, value, count), imm(1)), 1, false);
    }
    Varnode shift(const Varnode& value, arm_shifter type, unsigned amount, bool carry) {
        if (type == ARM_SFT_INVALID) return value;
        const bool byRegister = type == ARM_SFT_ASR_REG || type == ARM_SFT_LSL_REG || type == ARM_SFT_LSR_REG || type == ARM_SFT_ROR_REG;
        const auto rawCount = byRegister ? readReg(amount) : imm(amount);
        if (!rawCount.valid()) return Varnode::invalid();
        const auto count = byRegister ? b_.binary(MintOp::kAnd, rawCount, imm(255)) : rawCount;
        const auto noShift = b_.binary(MintOp::kEqual, count, imm(0));
        const auto tooLarge = b_.binary(MintOp::kLessU, imm(32), count);
        const auto atLeast32 = b_.binary(MintOp::kLessEqU, imm(32), count);
        Varnode result, newCarry;
        if (type == ARM_SFT_LSL || type == ARM_SFT_LSL_REG) {
            result = select(atLeast32, imm(0), b_.binary(MintOp::kShl, value, count));
            newCarry = select(tooLarge, imm(0,1), bit(value, b_.binary(MintOp::kSub, imm(32), count)));
        } else if (type == ARM_SFT_LSR || type == ARM_SFT_LSR_REG) {
            result = select(atLeast32, imm(0), b_.binary(MintOp::kShrU, value, count));
            newCarry = select(tooLarge, imm(0,1), bit(value, b_.binary(MintOp::kSub, count, imm(1))));
        } else if (type == ARM_SFT_ASR || type == ARM_SFT_ASR_REG) {
            const auto sign = bit(value, imm(31));
            const auto filled = b_.unary(MintOp::kNeg, b_.resize(sign,4,false),4);
            result = select(atLeast32, filled, b_.binary(MintOp::kShrS, value, count));
            newCarry = select(atLeast32, sign, bit(value, b_.binary(MintOp::kSub, count, imm(1))));
        } else if (type == ARM_SFT_ROR || type == ARM_SFT_ROR_REG) {
            const auto rotation = b_.binary(MintOp::kAnd, count, imm(31));
            result = b_.binary(MintOp::kRotR, value, rotation);
            newCarry = bit(result, imm(31));
        } else if (type == ARM_SFT_RRX) {
            result = b_.binary(MintOp::kOr, b_.binary(MintOp::kShrU, value, imm(1)),
                b_.binary(MintOp::kShl, b_.resize(flag(arm32::kFlagC),4,false), imm(31)));
            newCarry = bit(value, imm(0));
            if (carry) b_.assign(flag(arm32::kFlagC), newCarry);
            return result;
        } else return Varnode::invalid();
        if (carry) b_.assign(flag(arm32::kFlagC), select(noShift, flag(arm32::kFlagC), newCarry));
        return select(noShift, value, result);
    }
    Varnode read(unsigned index, bool carry = false) {
        if (index >= d_.op_count) return Varnode::invalid();
        const auto& operand = op(index);
        Varnode value = operand.type == ARM_OP_REG ? readReg(operand.reg) :
            (operand.type == ARM_OP_IMM ? imm(operand.imm) : Varnode::invalid());
        if (!value.valid()) return value;
        if (operand.shift.type != ARM_SFT_INVALID) return shift(value, operand.shift.type, operand.shift.value, carry);
        if (carry && operand.type == ARM_OP_IMM && !thumb_) {
            u32 word = 0; std::memcpy(&word, i_.bytes, 4);
            if ((word & (1u << 25)) && ((word >> 8) & 15)) b_.assign(flag(arm32::kFlagC), bit(value, imm(31)));
        } else if (carry && operand.type == ARM_OP_IMM && thumb_ && i_.size == 4) {
            // Thumb modified-immediate expansion may rotate. Its carry is not
            // present in operand detail, so do not assert a preserved C flag.
            b_.emit(MintOp::kUndefined, flag(arm32::kFlagC));
        }
        return value;
    }
    Varnode condition() {
        const auto n=flag(arm32::kFlagN), z=flag(arm32::kFlagZ), c=flag(arm32::kFlagC), v=flag(arm32::kFlagV);
        switch (d_.cc) {
            case ARMCC_EQ:return z; case ARMCC_NE:return negateBool(z);
            case ARMCC_HS:return c; case ARMCC_LO:return negateBool(c);
            case ARMCC_MI:return n; case ARMCC_PL:return negateBool(n);
            case ARMCC_VS:return v; case ARMCC_VC:return negateBool(v);
            case ARMCC_HI:return b_.binary(MintOp::kAnd,c,negateBool(z));
            case ARMCC_LS:return negateBool(b_.binary(MintOp::kAnd,c,negateBool(z)));
            case ARMCC_GE:return b_.binary(MintOp::kEqual,n,v);
            case ARMCC_LT:return b_.binary(MintOp::kNotEqual,n,v);
            case ARMCC_GT:return b_.binary(MintOp::kAnd,negateBool(z),b_.binary(MintOp::kEqual,n,v));
            case ARMCC_LE:return negateBool(b_.binary(MintOp::kAnd,negateBool(z),b_.binary(MintOp::kEqual,n,v)));
            default:return imm(1,1);
        }
    }
    void nz(const Varnode& value) {
        b_.emit(MintOp::kEqual,flag(arm32::kFlagZ),value,imm(0));
        b_.emit(MintOp::kLessS,flag(arm32::kFlagN),value,imm(0));
    }
    void arithmetic(MintOp operation, bool compare = false, bool reverse = false, bool carryInput = false);
    void logical(MintOp operation, bool compare = false, bool invert = false);
    void memory(bool load, u8 size, bool signedValue = false);
    void multiple(bool load, bool pushPop = false);
};

void Arm32Lifter::arithmetic(MintOp operation, bool compare, bool reverse, bool carryInput) {
    if (d_.op_count < 2 || (!compare && (op(0).type != ARM_OP_REG || !scalarReg(op(0).reg)))) return fail();
    if (!compare && op(0).reg == ARM_REG_PC && d_.update_flags) return fail();
    const unsigned leftIndex = compare ? 0 : (d_.op_count >= 3 ? 1 : 0), rightIndex = compare ? 1 : d_.op_count - 1;
    auto left = read(leftIndex), right = read(rightIndex);
    if (!left.valid() || !right.valid()) return fail();
    if (reverse) std::swap(left,right);
    const auto partial = b_.binary(operation,left,right);
    auto result = partial;
    Varnode carry = Varnode::invalid();
    if (carryInput) {
        carry = b_.resize(operation == MintOp::kSub ? negateBool(flag(arm32::kFlagC)) : flag(arm32::kFlagC),4,false);
        result = b_.binary(operation,partial,carry);
    }
    if (compare || d_.update_flags) {
        nz(result);
        if (operation == MintOp::kAdd || operation == MintOp::kSub) {
        const auto first = b_.binary(operation == MintOp::kAdd ? MintOp::kCarryAdd : MintOp::kBorrowSub,left,right);
        const auto combined = carryInput ? b_.binary(MintOp::kOr,first,b_.binary(operation == MintOp::kAdd ? MintOp::kCarryAdd : MintOp::kBorrowSub,partial,carry)) : first;
        b_.assign(flag(arm32::kFlagC), operation == MintOp::kSub ? negateBool(combined) : combined);
        const auto signs = operation == MintOp::kSub ? b_.binary(MintOp::kXor,left,right) : b_.unary(MintOp::kNot,b_.binary(MintOp::kXor,left,right),4);
        b_.assign(flag(arm32::kFlagV), bit(b_.binary(MintOp::kAnd,signs,b_.binary(MintOp::kXor,left,result)),imm(31)));
        }
    }
    if (!compare) writeReg(op(0).reg,result);
}

void Arm32Lifter::logical(MintOp operation, bool compare, bool invert) {
    if (d_.op_count < 2 || (!compare && (op(0).type != ARM_OP_REG || !scalarReg(op(0).reg)))) return fail();
    if (!compare && op(0).reg == ARM_REG_PC && d_.update_flags) return fail();
    const bool flags = compare || d_.update_flags;
    const unsigned leftIndex = compare ? 0 : (d_.op_count >= 3 ? 1 : 0), rightIndex = compare ? 1 : d_.op_count - 1;
    auto left = read(leftIndex), right = read(rightIndex,flags);
    if (!left.valid() || !right.valid()) return fail();
    if (invert) right = b_.unary(MintOp::kNot,right,4);
    const auto result = b_.binary(operation,left,right);
    if (flags) nz(result);
    if (!compare) writeReg(op(0).reg,result);
}

void Arm32Lifter::memory(bool load, u8 size, bool signedValue) {
    unsigned index = d_.op_count;
    for (unsigned n=0;n<d_.op_count;++n) if(op(n).type==ARM_OP_MEM){index=n;break;}
    if (index != 1 || d_.op_count < 2 || op(0).type != ARM_OP_REG || !scalarReg(op(0).reg) || !scalarReg(op(index).mem.base)) return fail();
    const auto& operand = op(index);
    const auto& mem = operand.mem;
    if (i_.detail->writeback && (mem.base == op(0).reg || mem.base == ARM_REG_PC)) return fail();
    auto base = readReg(mem.base);
    if (mem.base == ARM_REG_PC && thumb_) base = imm(static_cast<u32>((i_.address + 4) & ~Address{3}));
    auto displacement = imm(mem.disp);
    if (mem.index != ARM_REG_INVALID) {
        auto indexValue = readReg(mem.index);
        if (!indexValue.valid()) return fail();
        if (operand.shift.type != ARM_SFT_INVALID) indexValue=shift(indexValue,operand.shift.type,operand.shift.value,false);
        if (!indexValue.valid()) return fail();
        displacement=b_.binary(operand.subtracted || mem.scale < 0 ? MintOp::kSub : MintOp::kAdd,displacement,indexValue);
    }
    if (d_.post_index && index + 1 < d_.op_count) {
        displacement=read(index+1);
        if (!displacement.valid()) return fail();
        if(op(index+1).subtracted)displacement=b_.unary(MintOp::kNeg,displacement,4);
    }
    const auto updated=b_.binary(MintOp::kAdd,base,displacement);
    const auto address=d_.post_index ? b_.unary(MintOp::kCopy,base,4) : updated;
    if (load) {
        auto value=b_.newTemp(size);b_.emit(MintOp::kLoad,value,address);
        value=b_.resize(value,4,signedValue);
        if(i_.detail->writeback)writeReg(mem.base,updated);
        writeReg(op(0).reg,value);
    } else {
        const auto value=readReg(op(0).reg);if(!value.valid() || op(0).reg==ARM_REG_PC)return fail();
        b_.emit(MintOp::kStore,{},address,b_.resize(value,size,false));
        if(i_.detail->writeback)writeReg(mem.base,updated);
    }
}

void Arm32Lifter::multiple(bool load, bool pushPop) {
    const unsigned first=pushPop ? 0 : 1;
    if(d_.op_count<=first || (!pushPop && (op(0).type!=ARM_OP_REG || !scalarReg(op(0).reg))))return fail();
    const unsigned baseReg=pushPop ? ARM_REG_SP : op(0).reg;
    std::vector<unsigned> registers;
    for(unsigned n=first;n<d_.op_count;++n){
        if(op(n).type!=ARM_OP_REG || !scalarReg(op(n).reg) || (!load && op(n).reg==ARM_REG_PC) || op(n).reg==baseReg)return fail();
        registers.push_back(op(n).reg);
    }
    std::sort(registers.begin(),registers.end(),[](unsigned a,unsigned c){return registerFromCapstone(Arch::kArm32,a).offset<registerFromCapstone(Arch::kArm32,c).offset;});
    const bool decrement=(pushPop && !load) || i_.id==ARM_INS_LDMDB || i_.id==ARM_INS_STMDB || i_.id==ARM_INS_LDMDA || i_.id==ARM_INS_STMDA;
    const bool before=(pushPop && !load) || i_.id==ARM_INS_LDMDB || i_.id==ARM_INS_STMDB || i_.id==ARM_INS_LDMIB || i_.id==ARM_INS_STMIB;
    const auto base=b_.unary(MintOp::kCopy,readReg(baseReg),4);
    const i64 firstOffset=decrement ? -static_cast<i64>(4*(registers.size()-(before?0:1))) : (before?4:0);
    Varnode pc=Varnode::invalid();
    for(size_t n=0;n<registers.size();++n){
        const auto address=b_.binary(MintOp::kAdd,base,imm(firstOffset+static_cast<i64>(n*4)));
        if(load){auto value=b_.newTemp(4);b_.emit(MintOp::kLoad,value,address);if(registers[n]==ARM_REG_PC)pc=value;else writeReg(registers[n],value);}
        else b_.emit(MintOp::kStore,{},address,readReg(registers[n]));
    }
    if(pushPop || i_.detail->writeback)writeReg(baseReg,b_.binary(MintOp::kAdd,base,imm((decrement?-1:1)*static_cast<i64>(registers.size()*4))));
    if(pc.valid())b_.emit(baseReg==ARM_REG_SP ? MintOp::kReturn : MintOp::kBranchInd,{},b_.binary(MintOp::kAnd,pc,imm(-2)));
}

void Arm32Lifter::lift() {
    const bool conditional=thumb_ ? d_.cc!=ARMCC_Invalid && d_.cc!=ARMCC_UNDEF && d_.cc!=ARMCC_AL : (i_.bytes[3]>>4)<14;
    if(conditional && i_.id!=ARM_INS_B)return fail();
    if(std::strcmp(i_.mnemonic,"nop")==0)return;
    switch(i_.id){
        case ARM_INS_HINT:if(d_.op_count==1 && op(0).type==ARM_OP_IMM && op(0).imm==0)return;return fail();
        case ARM_INS_IT:return fail();
        case ARM_INS_MOV:case ARM_INS_MOVS:case ARM_INS_MVN:case ARM_INS_MOVW:case ARM_INS_MOVT:{
            if(d_.op_count<2 || op(0).type!=ARM_OP_REG || !scalarReg(op(0).reg))return fail();
            if(op(0).reg==ARM_REG_PC && d_.update_flags)return fail();
            auto value=read(1,d_.update_flags);if(!value.valid())return fail();
            if(i_.id==ARM_INS_MVN)value=b_.unary(MintOp::kNot,value,4);
            if(i_.id==ARM_INS_MOVT)value=b_.binary(MintOp::kOr,b_.binary(MintOp::kAnd,readReg(op(0).reg),imm(0xffff)),b_.binary(MintOp::kShl,value,imm(16)));
            if(d_.update_flags)nz(value);
            if(op(0).reg==ARM_REG_PC && op(1).type==ARM_OP_REG && op(1).reg==ARM_REG_LR)b_.emit(MintOp::kReturn,{},b_.binary(MintOp::kAnd,value,imm(-2)));
            else writeReg(op(0).reg,value);
            return;
        }
        case ARM_INS_ADD:case ARM_INS_ADDW:arithmetic(MintOp::kAdd);return;
        case ARM_INS_SUB:case ARM_INS_SUBS:case ARM_INS_SUBW:arithmetic(MintOp::kSub);return;
        case ARM_INS_ADC:arithmetic(MintOp::kAdd,false,false,true);return;
        case ARM_INS_SBC:arithmetic(MintOp::kSub,false,false,true);return;
        case ARM_INS_RSB:arithmetic(MintOp::kSub,false,true);return;
        case ARM_INS_CMP:arithmetic(MintOp::kSub,true);return;
        case ARM_INS_CMN:arithmetic(MintOp::kAdd,true);return;
        case ARM_INS_AND:logical(MintOp::kAnd);return;
        case ARM_INS_ORR:logical(MintOp::kOr);return;
        case ARM_INS_EOR:logical(MintOp::kXor);return;
        case ARM_INS_BIC:logical(MintOp::kAnd,false,true);return;
        case ARM_INS_TST:logical(MintOp::kAnd,true);return;
        case ARM_INS_TEQ:logical(MintOp::kXor,true);return;
        case ARM_INS_MUL:arithmetic(MintOp::kMul);return;
        case ARM_INS_LSL:case ARM_INS_LSR:case ARM_INS_ASR:case ARM_INS_ROR:{
            if(d_.op_count<2 || op(0).type!=ARM_OP_REG || !scalarReg(op(0).reg))return fail();
            const unsigned input=d_.op_count>=3?1:0,index=d_.op_count-1;
            auto value=read(input);if(!value.valid())return fail();
            const bool byReg=op(index).type==ARM_OP_REG;
            if(!byReg && op(index).type!=ARM_OP_IMM)return fail();
            arm_shifter type=ARM_SFT_LSL;
            if(i_.id==ARM_INS_LSR)type=ARM_SFT_LSR;
            else if(i_.id==ARM_INS_ASR)type=ARM_SFT_ASR;
            else if(i_.id==ARM_INS_ROR)type=ARM_SFT_ROR;
            if(byReg){if(type==ARM_SFT_LSL)type=ARM_SFT_LSL_REG;else if(type==ARM_SFT_LSR)type=ARM_SFT_LSR_REG;else if(type==ARM_SFT_ASR)type=ARM_SFT_ASR_REG;else type=ARM_SFT_ROR_REG;}
            value=shift(value,type,byReg?op(index).reg:static_cast<unsigned>(op(index).imm),d_.update_flags);
            if(!value.valid())return fail();if(d_.update_flags)nz(value);writeReg(op(0).reg,value);return;
        }
        case ARM_INS_UXTB:case ARM_INS_UXTH:case ARM_INS_SXTB:case ARM_INS_SXTH:{
            if(d_.op_count<2 || op(0).type!=ARM_OP_REG || !scalarReg(op(0).reg))return fail();
            auto value=read(1);if(!value.valid())return fail();
            const bool byte=i_.id==ARM_INS_UXTB || i_.id==ARM_INS_SXTB;
            writeReg(op(0).reg,b_.resize(b_.resize(value,byte?1:2,false),4,i_.id==ARM_INS_SXTB || i_.id==ARM_INS_SXTH));return;
        }
        case ARM_INS_LDR:memory(true,4);return;case ARM_INS_STR:memory(false,4);return;
        case ARM_INS_LDRB:memory(true,1);return;case ARM_INS_STRB:memory(false,1);return;
        case ARM_INS_LDRH:memory(true,2);return;case ARM_INS_STRH:memory(false,2);return;
        case ARM_INS_LDRSB:memory(true,1,true);return;case ARM_INS_LDRSH:memory(true,2,true);return;
        case ARM_INS_PUSH:multiple(false,true);return;case ARM_INS_POP:multiple(true,true);return;
        case ARM_INS_LDM:case ARM_INS_LDMDA:case ARM_INS_LDMDB:case ARM_INS_LDMIB:multiple(true);return;
        case ARM_INS_STM:case ARM_INS_STMDA:case ARM_INS_STMDB:case ARM_INS_STMIB:multiple(false);return;
        case ARM_INS_ADR:{
            if(d_.op_count<2 || op(0).type!=ARM_OP_REG || op(1).type!=ARM_OP_IMM || !scalarReg(op(0).reg))return fail();
            const Address pc=thumb_ ? (i_.address+4)&~Address{3} : i_.address+8;
            writeReg(op(0).reg,imm(static_cast<i64>(pc)+op(1).imm));return;
        }
        case ARM_INS_B:case ARM_INS_BL:case ARM_INS_BLX:case ARM_INS_BX:{
            if(!d_.op_count)return fail();
            const bool call=i_.id==ARM_INS_BL || i_.id==ARM_INS_BLX;
            auto address=read(0);if(!address.valid())return fail();
            if(call){if(op(0).type!=ARM_OP_IMM)address=b_.unary(MintOp::kCopy,address,4);writeReg(ARM_REG_LR,imm(static_cast<u32>(i_.address+i_.size)|(thumb_?1u:0u)));}
            address=op(0).type==ARM_OP_IMM ? imm(op(0).imm&~i64{1}) : b_.binary(MintOp::kAnd,address,imm(-2));
            if(i_.id==ARM_INS_B && conditional)b_.emit(MintOp::kCondBranch,{},condition(),address);
            else if(!call && op(0).type==ARM_OP_REG && op(0).reg==ARM_REG_LR)b_.emit(MintOp::kReturn,{},address);
            else b_.emit(call?(op(0).type==ARM_OP_IMM?MintOp::kCall:MintOp::kCallInd):(op(0).type==ARM_OP_IMM?MintOp::kBranch:MintOp::kBranchInd),{},address);
            return;
        }
        case ARM_INS_CBZ:case ARM_INS_CBNZ:{
            if(d_.op_count<2 || op(1).type!=ARM_OP_IMM)return fail();auto value=read(0);if(!value.valid())return fail();
            b_.emit(MintOp::kCondBranch,{},b_.binary(i_.id==ARM_INS_CBZ?MintOp::kEqual:MintOp::kNotEqual,value,imm(0)),imm(op(1).imm&~i64{1}));return;
        }
        case ARM_INS_BKPT:case ARM_INS_UDF:b_.emit(MintOp::kTrap,{});return;
        default:return fail();
    }
}
}
void liftArm32(const cs_insn& instruction, IrBuilder& builder, bool thumb) {
    builder.setAddress(instruction.address);
    if(!instruction.detail){builder.emitIntrinsic(static_cast<u16>(instruction.id));return;}
    const auto cc=instruction.detail->arm.cc;
    const bool conditional=thumb ? cc!=ARMCC_Invalid && cc!=ARMCC_UNDEF && cc!=ARMCC_AL : (instruction.bytes[3]>>4)<14;
    if(!conditional || instruction.id==ARM_INS_B) {Arm32Lifter(instruction,builder,thumb).lift();return;}
    // Predicated register/flag operations can be modeled without splitting the
    // machine CFG. Do not speculate memory, calls, traps or PC writes: skipping
    // a faulting load is observably different from selecting its result.
    cs_insn unconditional=instruction;cs_detail detail=*instruction.detail;
    detail.arm.cc=ARMCC_AL;unconditional.detail=&detail;
    if(!thumb)unconditional.bytes[3]=(unconditional.bytes[3]&15)|0xe0;
    IrFunction fragment;fragment.arch=thumb ? Arch::kThumb : Arch::kArm32;
    IrBuilder scratch(&fragment);scratch.setAddress(instruction.address);
    Arm32Lifter(unconditional,scratch,thumb).lift();
    bool safe=fragment.intrinsicCount==0;
    for(const auto& insn:fragment.insns)
        safe &= insn.dest.valid() && !opInfo(insn.op).terminator && insn.op!=MintOp::kLoad && insn.op!=MintOp::kStore && insn.op!=MintOp::kCall && insn.op!=MintOp::kCallInd && insn.op!=MintOp::kIntrinsic && insn.op!=MintOp::kTrap;
    if(!safe){builder.emitIntrinsic(static_cast<u16>(instruction.id));return;}
    const auto predicate=builder.unary(MintOp::kCopy,Arm32Lifter(instruction,builder,thumb).predicate(),1);
    const auto temporaryBase=builder.function()->tempCount;
    builder.function()->tempCount+=fragment.tempCount;
    auto remap=[&](Varnode value){if(value.isTemp())value.offset+=temporaryBase;return value;};
    for(const auto& insn:fragment.insns) {
        const auto dest=remap(insn.dest),a=remap(insn.a),b=remap(insn.b),c=remap(insn.c);
        if(dest.isRegister()) {
            const auto computed=builder.newTemp(dest.size);builder.emit(insn.op,computed,a,b,c);
            builder.emit(MintOp::kSelect,dest,predicate,computed,dest);
        } else builder.emit(insn.op,dest,a,b,c);
    }
}
}  // namespace mint
