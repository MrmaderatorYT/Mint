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
    Varnode imm(i64 value, u8 width = 4) const { return Varnode::constant(static_cast<u64>(value) & (width==8?~u64{0}:(u64{1} << (width * 8)) - 1), width); }
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
    void floating();
    bool neon();
    Varnode fpReg(unsigned reg) const {
        const auto value=registerFromCapstone(Arch::kArm32,reg);
        return value.valid() && value.offset>=arm32::kV0 && value.offset+value.size<=arm32::kFileSize && (value.size==4||value.size==8) ? value : Varnode::invalid();
    }
    void fpMemory(bool load);
    void fpMultiple(bool load,bool decrement);
};

bool Arm32Lifter::neon() {
    auto view=[&](unsigned n){
        if(n>=d_.op_count || op(n).type!=ARM_OP_REG)return Varnode::invalid();
        const auto value=registerFromCapstone(Arch::kArm32,op(n).reg);
        return value.valid() && value.offset>=arm32::kV0 && (value.size==8||value.size==16) && value.offset+value.size<=arm32::kFileSize ? value : Varnode::invalid();
    };
    const auto destination=view(0);if(!destination.valid())return false;
    const bool bitSelect=i_.id==ARM_INS_VBSL||i_.id==ARM_INS_VBIT||i_.id==ARM_INS_VBIF;
    const bool integer=d_.vector_data>=ARM_VECTORDATA_I8&&d_.vector_data<=ARM_VECTORDATA_U64;
    const bool untyped=d_.vector_data==ARM_VECTORDATA_INVALID&&(i_.id==ARM_INS_VDUP||i_.id==ARM_INS_VEXT||i_.id==ARM_INS_VREV16||i_.id==ARM_INS_VREV32||i_.id==ARM_INS_VREV64||i_.id==ARM_INS_VTST);
    if(!integer&&!untyped&&!bitSelect)return false;
    for(unsigned n=0;n<d_.op_count;++n)if(op(n).vector_index>=0 || op(n).neon_lane>=0 || op(n).shift.type!=ARM_SFT_INVALID){fail();return true;}
    auto source=[&](unsigned n){const auto value=view(n);return value.valid()&&value.size==destination.size?value:Varnode::invalid();};
    auto bad=[&](){fail();return true;};
    if(bitSelect) {
        const auto left=source(1),right=source(2);if(d_.op_count!=3||!left.valid()||!right.valid())return bad();
        const auto mask=i_.id==ARM_INS_VBSL?destination:right;
        const auto yes=left,no=i_.id==ARM_INS_VBSL?right:destination;
        const auto bits=i_.id==ARM_INS_VBIF?b_.unary(MintOp::kNot,mask,mask.size):mask;
        b_.assign(destination,b_.binary(MintOp::kOr,b_.binary(MintOp::kAnd,bits,yes),b_.binary(MintOp::kAnd,b_.unary(MintOp::kNot,bits,bits.size),no)));return true;
    }
    u8 lane=0;
    if(integer)lane=u8(1u<<((static_cast<unsigned>(d_.vector_data)-ARM_VECTORDATA_I8)%4));
    else if(d_.vector_size==8||d_.vector_size==16||d_.vector_size==32||d_.vector_size==64)lane=u8(d_.vector_size/8);
    if(!lane)return bad();
    const bool signedData=d_.vector_data>=ARM_VECTORDATA_S8&&d_.vector_data<=ARM_VECTORDATA_S64;
    const bool unsignedData=d_.vector_data>=ARM_VECTORDATA_U8&&d_.vector_data<=ARM_VECTORDATA_U64;
    auto full=[&](const Varnode& value){return b_.resize(value,16,false);};
    auto zero=[&](){return b_.resize(imm(0,8),16,false);};
    auto write=[&](const Varnode& value){b_.assign(destination,b_.resize(value,destination.size,false));};
    auto vector=[&](MintOp op,const Varnode& a,const Varnode& c){return b_.vector(op,lane,a,c);};
    if(i_.id==ARM_INS_VDUP) {
        if(d_.op_count!=2||op(1).type!=ARM_OP_REG||!scalarReg(op(1).reg)||op(1).reg==ARM_REG_PC||op(1).reg==ARM_REG_SP||lane>4)return bad();
        write(b_.vector(MintOp::kVectorSplat,lane,b_.resize(readReg(op(1).reg),lane,false)));return true;
    }
    const auto rawLeft=source(1);if(!rawLeft.valid())return bad();const auto left=full(rawLeft);
    if(i_.id==ARM_INS_VREV16||i_.id==ARM_INS_VREV32||i_.id==ARM_INS_VREV64) {
        const unsigned group=i_.id==ARM_INS_VREV16?2:i_.id==ARM_INS_VREV32?4:8;
        if(d_.op_count!=2 || lane>=group)return bad();
        auto output=zero();for(unsigned n=0;n<destination.size/lane;++n){
            const auto element=b_.vector(MintOp::kVectorExtract,lane,left,imm(n^(group/lane-1),1),{},lane);
            output=b_.vector(MintOp::kVectorInsert,lane,output,element,imm(n,1));}
        write(output);return true;
    }
    if(i_.id==ARM_INS_VEXT) {
        const auto rawRight=source(2);
        // Capstone chooses the widest equivalent VEXT element suffix and scales
        // its immediate accordingly (for example, .8 #4 becomes .32 #1).
        if(d_.op_count!=4||!rawRight.valid()||op(3).type!=ARM_OP_IMM||op(3).imm<0||u64(op(3).imm)*lane>=destination.size)return bad();
        const unsigned offset=unsigned(op(3).imm)*lane;
        const auto right=full(rawRight);auto output=zero();
        for(unsigned n=0;n<destination.size;++n){const unsigned index=n+offset;
            const auto element=b_.vector(MintOp::kVectorExtract,1,index<destination.size?left:right,imm(index%destination.size,1),{},1);
            output=b_.vector(MintOp::kVectorInsert,1,output,element,imm(n,1));}
        write(output);return true;
    }
    if(i_.id==ARM_INS_VABS||i_.id==ARM_INS_VNEG) {
        if(d_.op_count!=2||!signedData||lane>4)return bad();
        const auto negative=vector(MintOp::kVectorSub,zero(),left);
        if(i_.id==ARM_INS_VNEG)write(negative);
        else write(b_.vector(MintOp::kVectorSelect,lane,left,negative,vector(MintOp::kVectorCmpGtS,zero(),left)));
        return true;
    }
    if(i_.id==ARM_INS_VSHL||i_.id==ARM_INS_VSHR||i_.id==ARM_INS_VSRA) {
        if(d_.op_count!=3)return bad();
        const bool accumulate=i_.id==ARM_INS_VSRA;
        if(op(2).type==ARM_OP_IMM){
            const auto amount=op(2).imm;const bool shiftLeft=i_.id==ARM_INS_VSHL;
            if(amount<0 || (shiftLeft?amount>=lane*8:amount<1||amount>lane*8) || (!shiftLeft&&!signedData&&!unsignedData))return bad();
            auto value=b_.vector(shiftLeft?MintOp::kVectorShl:signedData?MintOp::kVectorShrS:MintOp::kVectorShrU,lane,left,imm(amount,1));
            if(accumulate)value=vector(MintOp::kVectorAdd,full(destination),value);write(value);return true;
        }
        const auto rawCounts=source(2);
        if(i_.id!=ARM_INS_VSHL||!rawCounts.valid()||(!signedData&&!unsignedData))return bad();
        const auto counts=full(rawCounts);auto output=zero();
        for(unsigned n=0;n<destination.size/lane;++n){
            const auto element=b_.vector(MintOp::kVectorExtract,lane,left,imm(n,1),{},lane);
            const auto rawCount=b_.vector(MintOp::kVectorExtract,lane,counts,imm(n,1),{},lane);
            const auto count=b_.resize(rawCount,1,false),negative=b_.binary(MintOp::kLessS,count,imm(0,1));
            const auto magnitude=select(negative,b_.unary(MintOp::kNeg,count,1),count);
            const auto large=b_.binary(MintOp::kLessEqU,imm(lane*8,1),magnitude);
            const auto shiftedLeft=select(large,imm(0,lane),b_.binary(MintOp::kShl,element,magnitude));
            const auto fill=signedData?b_.binary(MintOp::kShrS,element,imm(lane*8-1,1)):imm(0,lane);
            const auto shiftedRight=select(large,fill,b_.binary(signedData?MintOp::kShrS:MintOp::kShrU,element,magnitude));
            output=b_.vector(MintOp::kVectorInsert,lane,output,select(negative,shiftedRight,shiftedLeft),imm(n,1));
        }
        write(output);return true;
    }
    const bool compare=i_.id==ARM_INS_VCEQ||i_.id==ARM_INS_VCGT||i_.id==ARM_INS_VCGE||i_.id==ARM_INS_VCLT||i_.id==ARM_INS_VCLE||i_.id==ARM_INS_VTST;
    auto rawRight=source(2);Varnode right;
    if(d_.op_count==3&&rawRight.valid())right=full(rawRight);
    else if(d_.op_count==3&&compare&&op(2).type==ARM_OP_IMM&&op(2).imm==0&&(i_.id==ARM_INS_VCEQ||signedData))right=zero();
    else return bad();
    if(compare){
        if(lane>4)return bad();
        if(i_.id==ARM_INS_VCEQ)write(vector(MintOp::kVectorCmpEq,left,right));
        else if(i_.id==ARM_INS_VTST)write(b_.unary(MintOp::kNot,vector(MintOp::kVectorCmpEq,b_.binary(MintOp::kAnd,left,right),zero()),16));
        else {
            if(!signedData&&!unsignedData)return bad();
            const bool reverse=i_.id==ARM_INS_VCLT||i_.id==ARM_INS_VCGE;
            const auto a=reverse?right:left,c=reverse?left:right;
            auto value=signedData?vector(MintOp::kVectorCmpGtS,a,c):b_.unary(MintOp::kNot,vector(MintOp::kVectorCmpEq,vector(MintOp::kVectorMinU,a,c),a),16);
            if(i_.id==ARM_INS_VCGE||i_.id==ARM_INS_VCLE)value=b_.unary(MintOp::kNot,value,16);write(value);
        }
        return true;
    }
    MintOp operation=MintOp::kInvalid;
    switch(i_.id){case ARM_INS_VADD:operation=MintOp::kVectorAdd;break;case ARM_INS_VSUB:operation=MintOp::kVectorSub;break;
        case ARM_INS_VMUL:if(lane<=4)operation=MintOp::kVectorMul;break;
        case ARM_INS_VMIN:if(lane<=4&&(signedData||unsignedData))operation=signedData?MintOp::kVectorMinS:MintOp::kVectorMinU;break;
        case ARM_INS_VMAX:if(lane<=4&&(signedData||unsignedData))operation=signedData?MintOp::kVectorMaxS:MintOp::kVectorMaxU;break;
        default:break;}
    if(operation!=MintOp::kInvalid){write(vector(operation,left,right));return true;}
    if((i_.id==ARM_INS_VMLA||i_.id==ARM_INS_VMLS)&&lane<=4){write(vector(i_.id==ARM_INS_VMLA?MintOp::kVectorAdd:MintOp::kVectorSub,full(destination),vector(MintOp::kVectorMul,left,right)));return true;}
    return bad();
}

void Arm32Lifter::fpMemory(bool load) {
    if(d_.op_count!=2 || op(0).type!=ARM_OP_REG || op(1).type!=ARM_OP_MEM || i_.detail->writeback || d_.post_index)return fail();
    const auto data=fpReg(op(0).reg);const auto& memory=op(1).mem;
    if(!data.valid() || !scalarReg(memory.base) || memory.index!=ARM_REG_INVALID || (!load&&memory.base==ARM_REG_PC))return fail();
    auto base=readReg(memory.base);
    if(memory.base==ARM_REG_PC)base=imm(static_cast<u32>((i_.address+(thumb_?4:8))&~Address{3}));
    const auto displacement=op(1).subtracted && memory.disp>0 ? -memory.disp : memory.disp;
    const auto address=b_.binary(MintOp::kAdd,base,imm(displacement));
    if(load)b_.emit(MintOp::kLoad,data,address);else b_.emit(MintOp::kStore,{},address,data);
}

void Arm32Lifter::fpMultiple(bool load,bool decrement) {
    const bool pushPop=i_.alias_id==ARM_INS_ALIAS_VPUSH||i_.alias_id==ARM_INS_ALIAS_VPOP;
    const bool hiddenBase=pushPop && d_.op_count && op(0).type==ARM_OP_REG && !scalarReg(op(0).reg);
    const unsigned first=hiddenBase?0:1,baseReg=hiddenBase?ARM_REG_SP:op(0).reg;
    if(d_.op_count<=first || (!hiddenBase&&(op(0).type!=ARM_OP_REG || !scalarReg(baseReg) || baseReg==ARM_REG_PC)))return fail();
    std::vector<Varnode> registers;
    for(unsigned n=first;n<d_.op_count;++n) {
        if(op(n).type!=ARM_OP_REG)return fail();const auto reg=fpReg(op(n).reg);
        if(!reg.valid() || (!registers.empty()&&(reg.size!=registers[0].size || reg.offset!=registers.back().offset+reg.size)))return fail();
        registers.push_back(reg);
    }
    const u64 bytes=registers.size()*registers[0].size;
    const auto base=b_.unary(MintOp::kCopy,readReg(baseReg),4);
    for(size_t n=0;n<registers.size();++n) {
        const auto address=b_.binary(MintOp::kAdd,base,imm((decrement?-static_cast<i64>(bytes):0)+static_cast<i64>(n*registers[0].size)));
        if(load)b_.emit(MintOp::kLoad,registers[n],address);else b_.emit(MintOp::kStore,{},address,registers[n]);
    }
    if(pushPop||i_.detail->writeback)writeReg(baseReg,b_.binary(MintOp::kAdd,base,imm(decrement?-static_cast<i64>(bytes):static_cast<i64>(bytes))));
}

void Arm32Lifter::floating() {
    if(neon())return;
    if(i_.id==ARM_INS_VLDR){fpMemory(true);return;}
    if(i_.id==ARM_INS_VSTR){fpMemory(false);return;}
    if(i_.id==ARM_INS_VLDMIA||i_.id==ARM_INS_VLDMDB){fpMultiple(true,i_.id==ARM_INS_VLDMDB);return;}
    if(i_.id==ARM_INS_VSTMIA||i_.id==ARM_INS_VSTMDB){fpMultiple(false,i_.id==ARM_INS_VSTMDB);return;}
    if(i_.id==ARM_INS_VMRS) {
        if(d_.op_count!=2 || op(0).type!=ARM_OP_REG || op(1).type!=ARM_OP_REG || op(1).reg!=ARM_REG_FPSCR)return fail();
        const auto status=Varnode::reg(arm32::kFpscr,4);
        if(op(0).reg==ARM_REG_APSR_NZCV) {
            for(const auto pair:std::vector<std::pair<u64,unsigned>>{{arm32::kFlagN,31},{arm32::kFlagZ,30},{arm32::kFlagC,29},{arm32::kFlagV,28}})
                b_.assign(flag(pair.first),bit(status,imm(pair.second)));
        } else {if(!scalarReg(op(0).reg)||op(0).reg==ARM_REG_PC||op(0).reg==ARM_REG_SP)return fail();writeReg(op(0).reg,status);}
        return;
    }
    for(unsigned n=0;n<d_.op_count;++n)if(op(n).vector_index>=0 || op(n).neon_lane>=0 || op(n).shift.type!=ARM_SFT_INVALID)return fail();
    if(i_.id==ARM_INS_VAND||i_.id==ARM_INS_VORR||i_.id==ARM_INS_VEOR||i_.id==ARM_INS_VBIC||i_.id==ARM_INS_VMVN) {
        const bool unary=i_.id==ARM_INS_VMVN;if(d_.op_count!=(unary?2:3))return fail();
        std::vector<Varnode> values;
        for(unsigned n=0;n<d_.op_count;++n){if(op(n).type!=ARM_OP_REG)return fail();const auto reg=registerFromCapstone(Arch::kArm32,op(n).reg);
            if(!reg.valid()||reg.offset<arm32::kV0||(reg.size!=8&&reg.size!=16)||(!values.empty()&&reg.size!=values[0].size))return fail();values.push_back(reg);}
        const auto operation=i_.id==ARM_INS_VAND||i_.id==ARM_INS_VBIC?MintOp::kAnd:i_.id==ARM_INS_VEOR?MintOp::kXor:MintOp::kOr;
        auto value=unary?b_.unary(MintOp::kNot,values[1],values[0].size):b_.binary(operation,values[1],i_.id==ARM_INS_VBIC?b_.unary(MintOp::kNot,values[2],values[2].size):values[2]);
        b_.assign(values[0],value);return;
    }
    if(i_.id==ARM_INS_VMOV || (i_.id==ARM_INS_VORR&&i_.alias_id==ARM_INS_ALIAS_VMOV)) {
        if(d_.op_count==2 && op(0).type==ARM_OP_REG) {
            const auto destination=fpReg(op(0).reg);
            if(op(1).type==ARM_OP_REG) {
                const auto source=fpReg(op(1).reg);
                if(destination.valid()&&source.valid()&&destination.size==source.size){b_.assign(destination,source);return;}
                if(destination.valid()&&destination.size==4&&scalarReg(op(1).reg)&&op(1).reg!=ARM_REG_PC&&op(1).reg!=ARM_REG_SP){b_.assign(destination,readReg(op(1).reg));return;}
                if(source.valid()&&source.size==4&&scalarReg(op(0).reg)&&op(0).reg!=ARM_REG_PC&&op(0).reg!=ARM_REG_SP){writeReg(op(0).reg,source);return;}
            } else if(op(1).type==ARM_OP_FP && destination.valid()) {
                u64 bits=0;if(destination.size==4){const float number=static_cast<float>(op(1).fp);u32 raw=0;std::memcpy(&raw,&number,4);bits=raw;}
                else std::memcpy(&bits,&op(1).fp,8);
                b_.assign(destination,Varnode::constant(bits,destination.size));return;
            }
        } else if(d_.op_count==3 && op(0).type==ARM_OP_REG&&op(1).type==ARM_OP_REG&&op(2).type==ARM_OP_REG) {
            const auto first=fpReg(op(0).reg),last=fpReg(op(2).reg);
            if(first.valid()&&first.size==8&&scalarReg(op(1).reg)&&scalarReg(op(2).reg)&&op(1).reg!=ARM_REG_SP&&op(2).reg!=ARM_REG_SP&&op(1).reg!=ARM_REG_PC&&op(2).reg!=ARM_REG_PC) {
                const auto low=b_.resize(readReg(op(1).reg),8,false),high=b_.binary(MintOp::kShl,b_.resize(readReg(op(2).reg),8,false),imm(32,1));
                b_.assign(first,b_.binary(MintOp::kOr,low,high));return;
            }
            if(last.valid()&&last.size==8&&scalarReg(op(0).reg)&&scalarReg(op(1).reg)&&op(0).reg!=ARM_REG_SP&&op(1).reg!=ARM_REG_SP&&op(0).reg!=ARM_REG_PC&&op(1).reg!=ARM_REG_PC&&op(0).reg!=op(1).reg) {
                const auto source=b_.unary(MintOp::kCopy,last,8);writeReg(op(0).reg,b_.resize(source,4,false));
                writeReg(op(1).reg,b_.resize(b_.binary(MintOp::kShrU,source,imm(32,1)),4,false));return;
            }
        }
        return fail();
    }
    if(i_.id==ARM_INS_VCVT) {
        if(d_.op_count!=2 || op(0).type!=ARM_OP_REG || op(1).type!=ARM_OP_REG)return fail();
        const auto destination=fpReg(op(0).reg),source=fpReg(op(1).reg);
        MintOp operation=MintOp::kInvalid;u8 input=0,output=0;
        switch(d_.vector_data) {
            case ARM_VECTORDATA_F64F32:operation=MintOp::kFloatConvert;input=4;output=8;break;
            case ARM_VECTORDATA_F32F64:operation=MintOp::kFloatConvert;input=8;output=4;break;
            case ARM_VECTORDATA_F32S32:case ARM_VECTORDATA_F64S32:operation=MintOp::kIntToFloat;input=4;output=d_.vector_data==ARM_VECTORDATA_F32S32?4:8;break;
            case ARM_VECTORDATA_F32U32:case ARM_VECTORDATA_F64U32:operation=MintOp::kIntToFloatU;input=4;output=d_.vector_data==ARM_VECTORDATA_F32U32?4:8;break;
            case ARM_VECTORDATA_S32F32:case ARM_VECTORDATA_S32F64:operation=MintOp::kFloatToInt;output=4;input=d_.vector_data==ARM_VECTORDATA_S32F32?4:8;break;
            case ARM_VECTORDATA_U32F32:case ARM_VECTORDATA_U32F64:operation=MintOp::kFloatToIntU;output=4;input=d_.vector_data==ARM_VECTORDATA_U32F32?4:8;break;
            default:return fail();
        }
        if(!destination.valid()||!source.valid()||destination.size!=output||source.size!=input)return fail();
        const auto value=b_.unary(operation,source,output);b_.emit(MintOp::kUndefined,Varnode::reg(arm32::kFpscr,4));b_.assign(destination,value);return;
    }
    const u8 width=d_.vector_data==ARM_VECTORDATA_F32?4:d_.vector_data==ARM_VECTORDATA_F64?8:0;
    if(!width || d_.op_count<2 || op(0).type!=ARM_OP_REG)return fail();
    std::vector<Varnode> operands;
    for(unsigned n=0;n<d_.op_count;++n){if(op(n).type!=ARM_OP_REG)return fail();const auto reg=fpReg(op(n).reg);if(!reg.valid()||reg.size!=width)return fail();operands.push_back(reg);}
    MintOp operation=MintOp::kInvalid;
    switch(i_.id) {
        case ARM_INS_VADD:operation=MintOp::kFloatAdd;break;case ARM_INS_VSUB:operation=MintOp::kFloatSub;break;
        case ARM_INS_VMUL:case ARM_INS_VNMUL:operation=MintOp::kFloatMul;break;case ARM_INS_VDIV:operation=MintOp::kFloatDiv;break;
        case ARM_INS_VABS:operation=MintOp::kFloatAbs;break;case ARM_INS_VNEG:operation=MintOp::kFloatNeg;break;case ARM_INS_VSQRT:operation=MintOp::kFloatSqrt;break;
        default:break;
    }
    Varnode value;
    if(operation==MintOp::kFloatAbs||operation==MintOp::kFloatNeg||operation==MintOp::kFloatSqrt) {
        if(operands.size()!=2)return fail();value=b_.unary(operation,operands[1],width);
    } else if(operation!=MintOp::kInvalid) {
        if(operands.size()!=3)return fail();value=b_.binary(operation,operands[1],operands[2]);
        if(i_.id==ARM_INS_VNMUL)value=b_.unary(MintOp::kFloatNeg,value,width);
    } else if(i_.id==ARM_INS_VMLA||i_.id==ARM_INS_VMLS) {
        if(operands.size()!=3)return fail();value=b_.binary(i_.id==ARM_INS_VMLA?MintOp::kFloatAdd:MintOp::kFloatSub,operands[0],b_.binary(MintOp::kFloatMul,operands[1],operands[2]));
    } else if(i_.id==ARM_INS_VFMA||i_.id==ARM_INS_VFMS||i_.id==ARM_INS_VFNMA||i_.id==ARM_INS_VFNMS) {
        if(operands.size()!=3)return fail();auto left=operands[1],addend=operands[0];
        if(i_.id==ARM_INS_VFMS||i_.id==ARM_INS_VFNMA)left=b_.unary(MintOp::kFloatNeg,left,width);
        if(i_.id==ARM_INS_VFNMA||i_.id==ARM_INS_VFNMS)addend=b_.unary(MintOp::kFloatNeg,addend,width);
        value=b_.ternary(MintOp::kFloatFma,left,operands[2],addend);
    } else return fail();
    if(operation!=MintOp::kFloatAbs&&operation!=MintOp::kFloatNeg)b_.emit(MintOp::kUndefined,Varnode::reg(arm32::kFpscr,4));
    b_.assign(operands[0],value);
}

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
    // Capstone ARM detail represents #-imm as a positive displacement plus
    // `subtracted`, unlike backends which put the sign directly in mem.disp.
    // Consume the sign once; indexed forms below apply it to their index.
    auto displacement = imm(operand.subtracted && mem.disp>0 ? -mem.disp : mem.disp);
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
        case ARM_INS_VADD:case ARM_INS_VSUB:case ARM_INS_VMUL:case ARM_INS_VNMUL:case ARM_INS_VDIV:
        case ARM_INS_VABS:case ARM_INS_VNEG:case ARM_INS_VSQRT:case ARM_INS_VMLA:case ARM_INS_VMLS:
        case ARM_INS_VFMA:case ARM_INS_VFMS:case ARM_INS_VFNMA:case ARM_INS_VFNMS:case ARM_INS_VCVT:
        case ARM_INS_VMOV:case ARM_INS_VAND:case ARM_INS_VORR:case ARM_INS_VEOR:case ARM_INS_VBIC:case ARM_INS_VMVN:
        case ARM_INS_VMIN:case ARM_INS_VMAX:case ARM_INS_VCEQ:case ARM_INS_VCGT:case ARM_INS_VCGE:case ARM_INS_VCLT:case ARM_INS_VCLE:case ARM_INS_VTST:
        case ARM_INS_VSHL:case ARM_INS_VSHR:case ARM_INS_VSRA:case ARM_INS_VDUP:case ARM_INS_VREV16:case ARM_INS_VREV32:case ARM_INS_VREV64:case ARM_INS_VEXT:
        case ARM_INS_VBSL:case ARM_INS_VBIT:case ARM_INS_VBIF:
        case ARM_INS_VMRS:case ARM_INS_VLDR:case ARM_INS_VSTR:
        case ARM_INS_VLDMIA:case ARM_INS_VLDMDB:case ARM_INS_VSTMIA:case ARM_INS_VSTMDB:
            floating();return;
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
            const auto computed=builder.newTemp(dest.size);builder.emit(insn.op,computed,a,b,c);builder.function()->insns.back().laneWidth=insn.laneWidth;
            builder.emit(MintOp::kSelect,dest,predicate,computed,dest);
        } else {builder.emit(insn.op,dest,a,b,c);builder.function()->insns.back().laneWidth=insn.laneWidth;}
    }
}
}  // namespace mint
