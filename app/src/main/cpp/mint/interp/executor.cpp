#include "mint/interp/executor.h"

#include <cstring>
#include <limits>
#include <cmath>
#include <cfenv>
#include <algorithm>


#include "mint/ir/registers.h"

namespace mint {
namespace {

u64 maskFor(u8 width) {
    if (width >= 8) return ~u64(0);
    return (u64(1) << (width * 8)) - 1;
}

InterpValue unknownLike(const Varnode& node) { return InterpValue::unknown(node.size); }
using Wide=unsigned __int128;
Wide bits(const InterpValue& value){return (Wide(value.highBits)<<64)|value.bits;}
InterpValue wideValue(Wide value,u8 width){if(width<16)value&=(Wide{1}<<(width*8))-1;return InterpValue::wide(static_cast<u64>(value),static_cast<u64>(value>>64),width);}
long double floatingValue(const InterpValue& value) {
    if(value.width==4){u32 raw=static_cast<u32>(value.bits);float number;std::memcpy(&number,&raw,4);return number;}
    double number;std::memcpy(&number,&value.bits,8);return number;
}
InterpValue floatingBits(long double value,u8 width) {
    if(width==4){float number=static_cast<float>(value);u32 raw;std::memcpy(&raw,&number,4);return InterpValue::concrete(raw,4);}
    double number=static_cast<double>(value);u64 raw;std::memcpy(&raw,&number,8);return InterpValue::concrete(raw,8);
}
InterpValue floating(MintOp op,const InterpValue& a,const InterpValue& b,u8 width,bool assumed) {
    if(!a.concreteLike() || (a.width!=4&&a.width!=8))return InterpValue::unknown(width);
    if(op==MintOp::kFloatAbs)return InterpValue::concrete(a.bits & ~(u64{1}<<(a.width*8-1)),width);
    if(op==MintOp::kFloatNeg)return InterpValue::concrete(a.bits ^ (u64{1}<<(a.width*8-1)),width);
    if(!assumed || std::fegetround()!=FE_TONEAREST)return InterpValue::unknown(width);
    const long double x=floatingValue(a);
    if(op==MintOp::kFloatToInt || op==MintOp::kFloatToIntU) {
        if(width!=4&&width!=8)return InterpValue::unknown(width);
        const auto value=std::trunc(x);const bool unsign=op==MintOp::kFloatToIntU;
        const long double limit=std::ldexp(static_cast<long double>(1),width*8-(unsign?0:1));
        if(!std::isfinite(value) || value<(unsign?0:-limit) || value>=limit)return InterpValue::unknown(width);
        return InterpValue::concrete(unsign?static_cast<u64>(value):static_cast<u64>(static_cast<i64>(value)),width);
    }
    if(op==MintOp::kFloatConvert)return std::isnan(x)?InterpValue::unknown(width):floatingBits(x,width);
    if(op==MintOp::kFloatSqrt)return x<0||std::isnan(x)?InterpValue::unknown(width):floatingBits(width==4 ? std::sqrt(static_cast<float>(x)) : std::sqrt(static_cast<double>(x)),width);
    if(!b.concreteLike() || a.width!=b.width)return InterpValue::unknown(width);
    const long double y=floatingValue(b);const bool unordered=std::isnan(x)||std::isnan(y);
    if(op==MintOp::kFloatEqual)return InterpValue::concrete(!unordered&&x==y,1);
    if(op==MintOp::kFloatLess)return InterpValue::concrete(!unordered&&x<y,1);
    if(op==MintOp::kFloatUnordered)return InterpValue::concrete(unordered,1);
    if(op==MintOp::kFloatCmp)return InterpValue::concrete(unordered?0x30000000u:x==y?0x60000000u:x<y?0x80000000u:0x20000000u,4);
    if(unordered)return InterpValue::unknown(width); // Target NaN payload mode is not known.
    // Round the arithmetic at its declared precision, not long-double precision.
    // Volatile prevents extended intermediate contraction across IR operations.
    if(width==4) {
        volatile float left=static_cast<float>(x),right=static_cast<float>(y),answer;
        if(op==MintOp::kFloatAdd)answer=left+right;else if(op==MintOp::kFloatSub)answer=left-right;else if(op==MintOp::kFloatMul)answer=left*right;else if(op==MintOp::kFloatDiv)answer=left/right;else return InterpValue::unknown(width);
        return std::isnan(answer)?InterpValue::unknown(width):floatingBits(answer,width);
    }
    volatile double left=static_cast<double>(x),right=static_cast<double>(y),answer;
    if(op==MintOp::kFloatAdd)answer=left+right;else if(op==MintOp::kFloatSub)answer=left-right;else if(op==MintOp::kFloatMul)answer=left*right;else if(op==MintOp::kFloatDiv)answer=left/right;else return InterpValue::unknown(width);
    return std::isnan(answer)?InterpValue::unknown(width):floatingBits(answer,width);
}
InterpValue vector(MintOp op,const InterpValue& a,const InterpValue& b,const InterpValue& c,u8 lane,u8 width) {
    if(!a.concreteLike() || !lane || lane>8 || (width!=16&&op!=MintOp::kVectorExtract))return InterpValue::unknown(width);
    const u32 laneBits=lane*8,lanes=16/lane;const Wide mask=(Wide{1}<<laneBits)-1,av=bits(a),bv=bits(b),cv=bits(c);Wide output=0;
    if(op==MintOp::kVectorExtract) {if(!b.concreteLike()||b.bits>=lanes)return InterpValue::unknown(width);return wideValue((av>>(b.bits*laneBits))&mask,width);}
    if(op==MintOp::kVectorInsert) {if(!b.concreteLike()||!c.concreteLike()||c.bits>=lanes)return InterpValue::unknown(width);const unsigned shift=static_cast<unsigned>(c.bits*laneBits);return wideValue((av&~(mask<<shift))|((bv&mask)<<shift),16);}
    if(op==MintOp::kVectorSplat) {for(u32 n=0;n<lanes;++n)output|=(av&mask)<<(n*laneBits);return wideValue(output,16);}
    if(!b.concreteLike())return InterpValue::unknown(width);
    for(u32 n=0;n<lanes;++n) {
        const u64 x=static_cast<u64>((av>>(n*laneBits))&mask),y=static_cast<u64>((bv>>(n*laneBits))&mask),m=static_cast<u64>(mask);u64 value=0;
        const auto signedLane=[&](u64 v){return static_cast<i64>((v&(u64{1}<<(laneBits-1)))?v|~m:v);};
        switch(op) {
            case MintOp::kVectorAdd:value=x+y;break;case MintOp::kVectorSub:value=x-y;break;case MintOp::kVectorMul:value=x*y;break;
            case MintOp::kVectorCmpEq:value=x==y?m:0;break;case MintOp::kVectorCmpGtS:value=signedLane(x)>signedLane(y)?m:0;break;
            case MintOp::kVectorMinU:value=std::min(x,y);break;case MintOp::kVectorMaxU:value=std::max(x,y);break;
            case MintOp::kVectorMinS:value=static_cast<u64>(std::min(signedLane(x),signedLane(y)));break;case MintOp::kVectorMaxS:value=static_cast<u64>(std::max(signedLane(x),signedLane(y)));break;
            case MintOp::kVectorShl:value=b.highBits||b.bits>=laneBits?0:x<<b.bits;break;case MintOp::kVectorShrU:value=b.highBits||b.bits>=laneBits?0:x>>b.bits;break;
            case MintOp::kVectorShrS:value=static_cast<u64>(signedLane(x)>>(b.highBits||b.bits>=laneBits?laneBits-1:b.bits));break;
            case MintOp::kVectorSelect:if(!c.concreteLike())return InterpValue::unknown(width);value=((cv>>(n*laneBits+laneBits-1))&1)?y:x;break;
            case MintOp::kVectorPermute:value=static_cast<u64>((av>>(((b.bits>>(n*2))&3)*laneBits))&mask);break;
            default:return InterpValue::unknown(width);
        }
        output|=(Wide(value)&mask)<<(n*laneBits);
    }
    return wideValue(output,16);
}

InterpValue binary(MintOp op, const InterpValue& a, const InterpValue& b, u8 width) {
    if (!a.concreteLike() || !b.concreteLike()) return InterpValue::unknown(width);
    const bool predicate=op==MintOp::kEqual || op==MintOp::kNotEqual || op==MintOp::kLessU || op==MintOp::kLessS ||
        op==MintOp::kLessEqU || op==MintOp::kLessEqS || op==MintOp::kCarryAdd || op==MintOp::kBorrowSub || op==MintOp::kOverflowAdd || op==MintOp::kOverflowSub;
    // Predicates produce one byte but compare the original machine-width
    // operands. Truncating them to the result width loses high bits/signs.
    const u8 operandWidth=predicate?a.width:width;
    if(operandWidth==16) {
        const auto x=bits(a),y=bits(b);Wide value=0;const unsigned shift=static_cast<unsigned>(b.bits&127);
        switch(op) {
            case MintOp::kAdd:value=x+y;break;case MintOp::kSub:value=x-y;break;case MintOp::kMul:value=x*y;break;
            case MintOp::kAnd:value=x&y;break;case MintOp::kOr:value=x|y;break;case MintOp::kXor:value=x^y;break;
            case MintOp::kShl:value=x<<shift;break;case MintOp::kShrU:value=x>>shift;break;case MintOp::kShrS:value=static_cast<Wide>(static_cast<__int128>(x)>>shift);break;
            case MintOp::kEqual:return InterpValue::concrete(x==y,1);case MintOp::kNotEqual:return InterpValue::concrete(x!=y,1);
            case MintOp::kLessU:return InterpValue::concrete(x<y,1);case MintOp::kLessEqU:return InterpValue::concrete(x<=y,1);
            case MintOp::kLessS:return InterpValue::concrete(static_cast<__int128>(x)<static_cast<__int128>(y),1);case MintOp::kLessEqS:return InterpValue::concrete(static_cast<__int128>(x)<=static_cast<__int128>(y),1);
            default:return InterpValue::unknown(width);
        }
        return wideValue(value,width);
    }
    if(!operandWidth || operandWidth>8)return InterpValue::unknown(width);
    const u64 m = maskFor(operandWidth);
    const u64 av = a.bits & m;
    const u64 bv = b.bits & m;
    switch (op) {
        case MintOp::kAdd: return InterpValue::concrete((av + bv) & m, width);
        case MintOp::kSub: return InterpValue::concrete((av - bv) & m, width);
        case MintOp::kCarryAdd: return InterpValue::concrete(av>m-bv,1);
        case MintOp::kBorrowSub: return InterpValue::concrete(av<bv,1);
        case MintOp::kOverflowAdd: {
            const u64 sign=u64{1}<<(operandWidth*8-1),result=(av+bv)&m;
            return InterpValue::concrete((~(av^bv)&(av^result)&sign)!=0,1);
        }
        case MintOp::kOverflowSub: {
            const u64 sign=u64{1}<<(operandWidth*8-1),result=(av-bv)&m;
            return InterpValue::concrete(((av^bv)&(av^result)&sign)!=0,1);
        }
        case MintOp::kMul: return InterpValue::concrete((av * bv) & m, width);
        case MintOp::kMulHiU: return InterpValue::concrete(static_cast<u64>((static_cast<unsigned __int128>(av) * bv) >> (width * 8)), width);
        case MintOp::kDivU: return bv == 0 ? InterpValue::unknown(width) : InterpValue::concrete(av / bv, width);
        case MintOp::kRemU: return bv == 0 ? InterpValue::unknown(width) : InterpValue::concrete(av % bv, width);
        case MintOp::kDivS: {
            if (bv == 0) return InterpValue::unknown(width);
            const u64 sign = u64(1) << (width * 8 - 1);
            const i64 as = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            const i64 bs = (bv & sign) ? static_cast<i64>(bv | ~m) : static_cast<i64>(bv);
            // IR integer division does not assert an ISA's overflow policy.
            // Keep it unknown (RISC-V's lifter selects its architectural result
            // explicitly) instead of invoking undefined host arithmetic.
            if (as == std::numeric_limits<i64>::min() && bs == -1) return InterpValue::unknown(width);
            return InterpValue::concrete(static_cast<u64>(as / bs) & m, width);
        }
        case MintOp::kRemS: {
            if (bv == 0) return InterpValue::unknown(width);
            const u64 sign = u64(1) << (width * 8 - 1);
            const i64 as = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            const i64 bs = (bv & sign) ? static_cast<i64>(bv | ~m) : static_cast<i64>(bv);
            if (as == std::numeric_limits<i64>::min() && bs == -1) return InterpValue::unknown(width);
            return InterpValue::concrete(static_cast<u64>(as % bs) & m, width);
        }
        case MintOp::kAnd: return InterpValue::concrete(av & bv, width);
        case MintOp::kOr: return InterpValue::concrete(av | bv, width);
        case MintOp::kXor: return InterpValue::concrete(av ^ bv, width);
        case MintOp::kShl: return InterpValue::concrete((av << (bv & 63)) & m, width);
        case MintOp::kShrU: return InterpValue::concrete(av >> (bv & 63), width);
        case MintOp::kShrS: {
            const u64 sign = u64(1) << (width * 8 - 1);
            const i64 signedA = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            return InterpValue::concrete(static_cast<u64>(signedA >> (bv & 63)) & m, width);
        }
        case MintOp::kRotL: { const u32 shift = static_cast<u32>(bv & (width * 8 - 1)); return InterpValue::concrete(shift ? ((av << shift) | (av >> (width * 8 - shift))) & m : av, width); }
        case MintOp::kRotR: { const u32 shift = static_cast<u32>(bv & (width * 8 - 1)); return InterpValue::concrete(shift ? ((av >> shift) | (av << (width * 8 - shift))) & m : av, width); }
        case MintOp::kEqual: return InterpValue::concrete(av == bv, 1);
        case MintOp::kNotEqual: return InterpValue::concrete(av != bv, 1);
        case MintOp::kLessU: return InterpValue::concrete(av < bv, 1);
        case MintOp::kLessEqU: return InterpValue::concrete(av <= bv, 1);
        case MintOp::kLessS: {
            const u64 sign = u64(1) << (operandWidth * 8 - 1);
            const i64 as = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            const i64 bs = (bv & sign) ? static_cast<i64>(bv | ~m) : static_cast<i64>(bv);
            return InterpValue::concrete(as < bs, 1);
        }
        case MintOp::kLessEqS: {
            const u64 sign = u64(1) << (operandWidth * 8 - 1);
            const i64 as = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            const i64 bs = (bv & sign) ? static_cast<i64>(bv | ~m) : static_cast<i64>(bv);
            return InterpValue::concrete(as <= bs, 1);
        }
        default: return InterpValue::unknown(width);
    }
}

u32 blockForAddress(const IrFunction& function, Address address) {
    for (const IrBlock& block : function.blocks) if (block.start == address) return block.id;
    return ~u32(0);
}

}  // namespace

Status executeIr(const IrFunction& function, InterpState* state,
                 const InterpOptions& options, InterpResult* result) {
    if (!state || !result) return Status::error(ErrorCode::kInternalError, "null interpreter output");
    *result = {};
    if (function.blocks.empty()) return Status::error(ErrorCode::kBadFormat, "IR function has no blocks");
    if (state->arch() != function.arch) state->reset(function.arch);

    u32 blockId = 0;
    for (const IrBlock& block : function.blocks) if (block.start == function.entry) { blockId = block.id; break; }
    u32 steps = 0;
    while (steps++ < options.maxSteps && blockId < function.blocks.size()) {
        const IrBlock& block = function.blocks[blockId];
        bool advanced = false;
        for (u32 i = 0; i < block.insnCount; ++i) {
            const IrInsn& insn = function.insns[block.firstInsn + i];
            const InterpValue a = state->read(insn.a);
            const InterpValue b = state->read(insn.b);
            const InterpValue c = state->read(insn.c);
            InterpValue value = unknownLike(insn.dest);
            switch (insn.op) {
                case MintOp::kCopy: value = a; break;
                case MintOp::kLoad:
                case MintOp::kAtomicLoad:
                    value = a.concreteLike() ? state->memory().read(a.bits, insn.dest.size) : unknownLike(insn.dest);
                    break;
                case MintOp::kStore:
                case MintOp::kAtomicStore:
                    if (a.concreteLike()) state->memory().write(a.bits, b, insn.b.size);
                    break;
                case MintOp::kNeg:
                    value = a.concreteLike() ? wideValue(Wide{0}-bits(a),insn.dest.size) : unknownLike(insn.dest);
                    break;
                case MintOp::kNot:
                    value = a.concreteLike() ? wideValue(~bits(a),insn.dest.size) : unknownLike(insn.dest);
                    break;
                case MintOp::kZeroExt:
                    value = a.concreteLike() ? wideValue(bits(a), insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kSignExt: {
                    if (a.concreteLike()) {
                        auto raw=bits(a);
                        if(a.width<16 && (raw&(Wide{1}<<(a.width*8-1))))raw|=~((Wide{1}<<(a.width*8))-1);
                        value=wideValue(raw,insn.dest.size);
                    }
                    break;
                }
                case MintOp::kTrunc: value = a.concreteLike() ? wideValue(bits(a), insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kFloatAdd:case MintOp::kFloatSub:case MintOp::kFloatMul:case MintOp::kFloatDiv:case MintOp::kFloatSqrt:
                case MintOp::kFloatAbs:case MintOp::kFloatNeg:case MintOp::kFloatCmp:case MintOp::kFloatEqual:case MintOp::kFloatLess:case MintOp::kFloatUnordered:
                case MintOp::kFloatToInt:case MintOp::kFloatToIntU:case MintOp::kFloatConvert:
                    value=floating(insn.op,a,b,insn.dest.size,options.assumeDefaultFloatingPoint);break;
                case MintOp::kIntToFloat:case MintOp::kIntToFloatU:
                    if(a.concreteLike() && a.width<=8 && options.assumeDefaultFloatingPoint && std::fegetround()==FE_TONEAREST) {
                        const u64 mask=maskFor(a.width),raw=a.bits&mask;const u64 extended=(raw&(u64{1}<<(a.width*8-1)))?raw|~mask:raw;
                        value=floatingBits(insn.op==MintOp::kIntToFloatU ? static_cast<long double>(raw) : static_cast<long double>(static_cast<i64>(extended)),insn.dest.size);
                    }
                    break;
                case MintOp::kVectorAdd:case MintOp::kVectorSub:case MintOp::kVectorMul:case MintOp::kVectorCmpEq:case MintOp::kVectorCmpGtS:
                case MintOp::kVectorMinU:case MintOp::kVectorMinS:case MintOp::kVectorMaxU:case MintOp::kVectorMaxS:
                case MintOp::kVectorShl:case MintOp::kVectorShrU:case MintOp::kVectorShrS:case MintOp::kVectorSelect:case MintOp::kVectorSplat:
                case MintOp::kVectorInsert:case MintOp::kVectorExtract:case MintOp::kVectorPermute:
                    value=vector(insn.op,a,b,c,insn.laneWidth,insn.dest.size);break;
                case MintOp::kVectorLoad:value=a.concreteLike()?state->memory().read(a.bits,insn.dest.size):unknownLike(insn.dest);break;
                case MintOp::kVectorStore:if(a.concreteLike())state->memory().write(a.bits,b,insn.b.size);break;
                case MintOp::kMemoryFence:break;
                case MintOp::kAtomicExchange:case MintOp::kAtomicAdd:case MintOp::kAtomicCompareExchange: {
                    if(!a.concreteLike())break;
                    const auto previous=state->memory().read(a.bits,insn.dest.size);value=previous;
                    if(insn.op==MintOp::kAtomicExchange)state->memory().write(a.bits,b,insn.dest.size);
                    else if(insn.op==MintOp::kAtomicAdd)state->memory().write(a.bits,binary(MintOp::kAdd,previous,b,insn.dest.size),insn.dest.size);
                    else if(previous.concreteLike()&&b.concreteLike()) {if(previous.bits==b.bits)state->memory().write(a.bits,c,insn.dest.size);}
                    else state->memory().write(a.bits,InterpValue::unknown(insn.dest.size),insn.dest.size);
                    break;
                }
                case MintOp::kAnd: case MintOp::kOr: case MintOp::kXor: case MintOp::kAdd: case MintOp::kSub:
                case MintOp::kMul: case MintOp::kMulHiU: case MintOp::kDivU: case MintOp::kDivS: case MintOp::kRemU: case MintOp::kRemS:
                case MintOp::kShl: case MintOp::kShrU: case MintOp::kShrS: case MintOp::kRotL: case MintOp::kRotR:
                case MintOp::kEqual: case MintOp::kNotEqual: case MintOp::kLessU: case MintOp::kLessS:
                case MintOp::kLessEqU: case MintOp::kLessEqS:
                case MintOp::kCarryAdd: case MintOp::kBorrowSub: case MintOp::kOverflowAdd: case MintOp::kOverflowSub:
                    value = binary(insn.op, a, b, insn.dest.size); break;
                case MintOp::kDivWideU: case MintOp::kDivWideS:
                case MintOp::kRemWideU: case MintOp::kRemWideS: {
                    // Dividend is (b:a), one machine width per half, so the working
                    // type is twice the operand width and only __int128 covers the
                    // 64-bit case.
                    if (!a.concreteLike() || !b.concreteLike() || !c.concreteLike()) {
                        value = unknownLike(insn.dest);
                        break;
                    }
                    const u8 width = insn.dest.size;
                    const u64 m = maskFor(width);
                    const u64 divisor = c.bits & m;
                    if (divisor == 0) { value = unknownLike(insn.dest); break; }
                    const unsigned __int128 raw =
                        (static_cast<unsigned __int128>(b.bits & m) << (width * 8)) |
                        static_cast<unsigned __int128>(a.bits & m);
                    const bool wantRemainder = insn.op == MintOp::kRemWideU ||
                                               insn.op == MintOp::kRemWideS;
                    if (insn.op == MintOp::kDivWideS || insn.op == MintOp::kRemWideS) {
                        const unsigned bits = static_cast<unsigned>(width) * 16;
                        __int128 dividend = static_cast<__int128>(raw);
                        if (bits < 128) {
                            const unsigned __int128 one = 1;
                            const unsigned __int128 span = (one << bits) - 1;
                            dividend = (raw & (one << (bits - 1)))
                                           ? static_cast<__int128>(raw | ~span)
                                           : static_cast<__int128>(raw & span);
                        }
                        const u64 sign = u64(1) << (width * 8 - 1);
                        const i64 signedDivisor = (divisor & sign)
                                                      ? static_cast<i64>(divisor | ~m)
                                                      : static_cast<i64>(divisor);
                        // INT_MIN / -1 has no representable quotient and is undefined
                        // in C++, which is exactly the #DE case on hardware.
                        if (signedDivisor == -1 &&
                            dividend == (static_cast<__int128>(1) << 127)) {
                            value = unknownLike(insn.dest);
                            break;
                        }
                        const __int128 result = wantRemainder ? dividend % signedDivisor
                                                             : dividend / signedDivisor;
                        value = InterpValue::concrete(static_cast<u64>(result) & m, width);
                    } else {
                        const unsigned __int128 result =
                            wantRemainder ? raw % divisor : raw / divisor;
                        value = InterpValue::concrete(static_cast<u64>(result) & m, width);
                    }
                    break;
                }
                case MintOp::kSelect: {
                    bool known = false; const bool take = interpBool(a, &known);
                    value = known ? (take ? b : c) : unknownLike(insn.dest); break;
                }
                case MintOp::kCall: case MintOp::kCallInd: {
                    InterpCall call;
                    call.target = a.concreteLike() ? a.bits : kNoAddress;
                    call.address = insn.address;
                    call.arguments.push_back(state->registerValue(0, 8));
                    call.arguments.push_back(state->registerValue(8, 8));
                    result->calls.push_back(call);
                    if (options.stopOnCall) {
                        result->stoppedOnCall = true; result->stopReason = "call"; return Status::success();
                    }
                    break;
                }
                case MintOp::kPopCount:
                    value = a.concreteLike() ? InterpValue::concrete(static_cast<u64>(__builtin_popcountll(a.bits & maskFor(a.width))), insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kClz:
                    value = a.concreteLike() ? InterpValue::concrete(a.bits ? static_cast<u64>(__builtin_clzll(a.bits) - (8 - a.width) * 8) : a.width * 8, insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kCtz:
                    value = a.concreteLike() ? InterpValue::concrete(a.bits ? static_cast<u64>(__builtin_ctzll(a.bits)) : a.width * 8, insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kReturn:
                    result->returned = true; result->returnValue = insn.a.valid() ? state->read(insn.a) : state->registerValue(0, 8);
                    result->stopReason = "return"; return Status::success();
                case MintOp::kCondBranch: {
                    bool known = false; const bool take = interpBool(a, &known);
                    u32 target = b.concreteLike() ? blockForAddress(function, b.bits) : ~u32(0);
                    if (known && take && target != ~u32(0)) blockId = target;
                    else if (known && !take && !block.successors.empty()) blockId = block.successors.back();
                    else if (!known && !block.successors.empty()) { result->hitUnknownBranch = true; blockId = block.successors.back(); }
                    else { result->stopReason = "unresolved conditional branch"; return Status::success(); }
                    advanced = true; break;
                }
                case MintOp::kBranch: {
                    const u32 target = a.concreteLike() ? blockForAddress(function, a.bits) : ~u32(0);
                    if (target == ~u32(0)) { result->stopReason = "unresolved branch"; return Status::success(); }
                    blockId = target; advanced = true; break;
                }
                case MintOp::kBranchInd: {
                    const u32 target = a.concreteLike() ? blockForAddress(function, a.bits) : ~u32(0);
                    if (target == ~u32(0)) { result->stopReason = "indirect branch"; return Status::success(); }
                    blockId = target; advanced = true; break;
                }
                case MintOp::kIntrinsic:
                    if (!options.executeIntrinsics) {
                        result->stopReason = "unmodeled intrinsic";
                        return Status::success();
                    }
                    break;
                case MintOp::kUndefined:
                    result->stopReason = "undefined semantics";
                    return Status::success();
                default: break;
            }
            if (insn.dest.valid() && insn.dest.space != Space::kInvalid && insn.op != MintOp::kStore) state->write(insn.dest, value);
            if (advanced) break;
        }
        if (!advanced) {
            if (block.successors.empty()) { result->stopReason = "block exit"; return Status::success(); }
            blockId = block.successors.front();
        }
    }
    result->hitCycleLimit = true;
    result->stopReason = "step limit";
    return Status::success();
}

}  // namespace mint
