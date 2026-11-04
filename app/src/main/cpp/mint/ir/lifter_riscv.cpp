// RV32/RV64 integer, compressed scalar, FP transfers/sign/class and base AMOs.
// Unsupported rounding modes/vector, reservations and privileged state remain intrinsic.
#include "mint/ir/lifter_internal.h"
#include "mint/ir/registers.h"

#include <cstring>

namespace mint {
namespace {
class RiscVLifter {
public:
    RiscVLifter(const cs_insn& instruction, IrBuilder& builder, bool rv64)
        : i_(instruction), b_(builder), width_(rv64 ? 8 : 4) {}
    void lift();
private:
    const cs_insn& i_;
    IrBuilder& b_;
    u8 width_;
    static i64 sign(u32 value, unsigned bits) {
        return static_cast<i64>(value & ((u32{1} << bits) - 1)) -
            ((value & (u32{1} << (bits - 1))) ? i64{1} << bits : 0);
    }
    Varnode imm(i64 value, u8 width = 0) const {
        const u8 size = width ? width : width_;
        const u64 mask = size == 8 ? ~u64{0} : (u64{1} << (size * 8)) - 1;
        return Varnode::constant(static_cast<u64>(value) & mask, size);
    }
    Varnode reg(unsigned n, u8 width = 0) const { return n ? Varnode::reg(riscv::kXn(n), width ? width : width_) : imm(0, width); }
    void write(unsigned n, const Varnode& value, bool signedWord = false) {
        if (n) b_.assign(reg(n), b_.resize(value, width_, signedWord));
    }
    Address target(i64 delta) const {
        const Address result = i_.address + static_cast<Address>(delta);
        return width_ == 4 ? static_cast<u32>(result) : result;
    }
    void fail() { b_.emitIntrinsic(static_cast<u16>(i_.id)); }
    void jump(unsigned destination, Address address) {
        write(destination, imm(static_cast<i64>(i_.address + i_.size)));
        b_.emit(destination == 1 || destination == 5 ? MintOp::kCall : MintOp::kBranch, {}, imm(static_cast<i64>(address)));
    }
    void indirect(unsigned destination, unsigned source, i64 displacement) {
        // Materialize before updating link: jalr ra,ra,imm reads the old ra.
        const auto address = b_.binary(MintOp::kAnd, b_.binary(MintOp::kAdd, reg(source), imm(displacement)), imm(-2));
        write(destination, imm(static_cast<i64>(i_.address + i_.size)));
        const bool returning = destination == 0 && (source == 1 || source == 5) && displacement == 0;
        b_.emit(returning ? MintOp::kReturn : (destination == 1 || destination == 5 ? MintOp::kCallInd : MintOp::kBranchInd), {}, address);
    }
    void branch(unsigned left, unsigned right, MintOp predicate, i64 displacement, bool invert = false) {
        auto condition = b_.binary(predicate, reg(left), reg(right));
        if (invert) condition = b_.binary(MintOp::kEqual, condition, imm(0, 1));
        b_.emit(MintOp::kCondBranch, {}, condition, imm(static_cast<i64>(target(displacement))));
    }
    void load(unsigned destination, unsigned base, i64 displacement, u8 size, bool signedValue) {
        const auto address = b_.binary(MintOp::kAdd, reg(base), imm(displacement));
        const auto value = b_.newTemp(size); b_.emit(MintOp::kLoad, value, address);
        write(destination, b_.resize(value, width_, signedValue));
    }
    void store(unsigned source, unsigned base, i64 displacement, u8 size) {
        const auto address = b_.binary(MintOp::kAdd, reg(base), imm(displacement));
        b_.emit(MintOp::kStore, {}, address, b_.resize(reg(source), size, false));
    }
    Varnode fp(unsigned n, u8 size = 8) const { return Varnode::reg(riscv::kF0 + n * 8, size); }
    Varnode choose(const Varnode& condition, const Varnode& yes, const Varnode& no) {
        auto result = b_.newTemp(yes.size); b_.emit(MintOp::kSelect, result, condition, yes, no); return result;
    }
    Varnode fpValue(unsigned n, u8 size) {
        if (size == 8) return fp(n);
        // Computational F instructions treat an incorrectly NaN-boxed operand
        // as the canonical quiet NaN. Loads/stores and FMV preserve raw bits.
        const auto upper = b_.binary(MintOp::kShrU, fp(n), imm(32, 1));
        return choose(b_.binary(MintOp::kEqual, upper, imm(0xffffffffull, 8)), fp(n, 4), imm(0x7fc00000, 4));
    }
    void writeFp(unsigned n, const Varnode& value) {
        b_.assign(fp(n), value.size == 4 ? b_.binary(MintOp::kOr, b_.resize(value, 8, false), imm(-4294967296ll, 8)) : value);
    }
    void loadFp(unsigned n, unsigned base, i64 offset, u8 size) {
        auto value = b_.newTemp(size);
        b_.emit(MintOp::kLoad, value, b_.binary(MintOp::kAdd, reg(base), imm(offset)));
        writeFp(n, value);
    }
    void storeFp(unsigned n, unsigned base, i64 offset, u8 size) {
        b_.emit(MintOp::kStore, {}, b_.binary(MintOp::kAdd, reg(base), imm(offset)), fp(n, size));
    }
    void classify(unsigned destination, unsigned source, u8 size) {
        const auto value = fpValue(source, size);
        const u64 signMask = u64{1} << (size * 8 - 1);
        const u64 fractionMask = size == 4 ? 0x7fffffull : 0xfffffffffffffull;
        const u64 exponentMask = size == 4 ? 0x7f800000ull : 0x7ff0000000000000ull;
        auto test = [&](u64 mask, u64 expected) {
            return b_.binary(MintOp::kEqual, b_.binary(MintOp::kAnd, value, imm(mask, size)), imm(expected, size));
        };
        auto negative = test(signMask, signMask), zeroExp = test(exponentMask, 0), maxExp = test(exponentMask, exponentMask);
        auto zeroFrac = test(fractionMask, 0), quiet = test((fractionMask + 1) >> 1, (fractionMask + 1) >> 1);
        auto zero = choose(negative, imm(1 << 3), imm(1 << 4));
        auto subnormal = choose(negative, imm(1 << 2), imm(1 << 5));
        auto normal = choose(negative, imm(1 << 1), imm(1 << 6));
        auto infinity = choose(negative, imm(1), imm(1 << 7));
        auto nan = choose(quiet, imm(1 << 9), imm(1 << 8));
        write(destination, choose(maxExp, choose(zeroFrac, infinity, nan), choose(zeroExp, choose(zeroFrac, zero, subnormal), normal)));
    }
    void flagsUnknown() { b_.emit(MintOp::kUndefined, Varnode::reg(riscv::kFflags, 8)); }
    Varnode rounded(const Varnode& value, unsigned mode, unsigned supported = 0) {
        if (mode != 7) return value;
        auto unknown = b_.newTemp(value.size); b_.emit(MintOp::kUndefined, unknown);
        return choose(b_.binary(MintOp::kEqual, Varnode::reg(riscv::kFrm, 8), imm(supported, 8)), value, unknown);
    }
    bool floatCsr(unsigned csr, unsigned operation, unsigned destination, unsigned source) {
        if (csr < 1 || csr > 3 || operation == 0 || operation == 4) return false;
        const auto flags = Varnode::reg(riscv::kFflags, 8), rounding = Varnode::reg(riscv::kFrm, 8);
        auto old = csr == 1 ? flags : csr == 2 ? rounding :
            b_.binary(MintOp::kOr, flags, b_.binary(MintOp::kShl, rounding, imm(5, 1)));
        // Snapshot both old CSR and operand before publishing writes: rd may
        // alias rs1, and CSRRS/CSRRC must return the pre-update value.
        old = b_.unary(MintOp::kCopy, old, 8);
        auto input = operation >= 5 ? imm(source, 8) : b_.resize(reg(source), 8, false);
        auto value = (operation & 3) == 1 ? b_.unary(MintOp::kCopy, input, 8) :
            b_.binary((operation & 3) == 2 ? MintOp::kOr : MintOp::kAnd, old,
                (operation & 3) == 2 ? input : b_.binary(MintOp::kXor, input, imm(-1, 8)));
        if ((operation & 3) == 1 || source != 0) {
            if (csr != 2) b_.assign(flags, b_.binary(MintOp::kAnd, value, imm(31, 8)));
            if (csr != 1) b_.assign(rounding, b_.binary(MintOp::kAnd,
                csr == 3 ? b_.binary(MintOp::kShrU, value, imm(5, 1)) : value, imm(7, 8)));
        }
        write(destination, old); return true;
    }
    Varnode division(MintOp operation, const Varnode& left, const Varnode& right) {
        const bool remainder = operation == MintOp::kRemS || operation == MintOp::kRemU;
        const bool signedValue = operation == MintOp::kRemS || operation == MintOp::kDivS;
        auto result = b_.binary(operation, left, right);
        if (signedValue) {
            const auto minimum = Varnode::constant(u64{1} << (left.size * 8 - 1), left.size);
            const auto overflow = b_.binary(MintOp::kAnd, b_.binary(MintOp::kEqual, left, minimum),
                b_.binary(MintOp::kEqual, right, imm(-1,right.size)));
            auto selected = b_.newTemp(left.size);
            b_.emit(MintOp::kSelect, selected, overflow, remainder ? imm(0, left.size) : minimum, result);
            result = selected;
        }
        const auto zeroDivisor = b_.binary(MintOp::kEqual, right, imm(0, right.size));
        auto selected = b_.newTemp(left.size);
        b_.emit(MintOp::kSelect, selected, zeroDivisor, remainder ? left : imm(-1, left.size), result);
        return selected;
    }
    void compressed(u16 word);
};

void RiscVLifter::lift() {
    if (i_.size == 2) { u16 word = 0; std::memcpy(&word, i_.bytes, 2); compressed(word); return; }
    if (i_.size != 4) return fail();
    u32 word = 0; std::memcpy(&word, i_.bytes, 4);
    const unsigned opcode = word & 127, destination = (word >> 7) & 31, fn = (word >> 12) & 7;
    const unsigned source = (word >> 15) & 31, second = (word >> 20) & 31, extended = word >> 25;
    const i64 immediate = sign(word >> 20, 12);
    switch (opcode) {
        case 0x37: write(destination, imm(static_cast<i32>(word & 0xfffff000))); return;
        case 0x17: write(destination, imm(static_cast<i64>(target(static_cast<i32>(word & 0xfffff000))))); return;
        case 0x6f: {
            const u32 displacement = ((word >> 31) << 20) | (((word >> 12) & 255) << 12) |
                (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1);
            jump(destination, target(sign(displacement, 21))); return;
        }
        case 0x67: if (fn == 0) indirect(destination, source, immediate); else fail(); return;
        case 0x63: {
            const u32 displacement = ((word >> 31) << 12) | (((word >> 7) & 1) << 11) |
                (((word >> 25) & 63) << 5) | (((word >> 8) & 15) << 1);
            const MintOp predicate = fn <= 1 ? MintOp::kEqual : (fn <= 5 ? MintOp::kLessS : MintOp::kLessU);
            if (fn == 2 || fn == 3) fail();
            else branch(source, second, predicate, sign(displacement, 13), (fn & 1) != 0);
            return;
        }
        case 0x03: {
            const unsigned bytes = u32{1} << (fn & 3);
            if (fn == 7 || bytes > width_ || (fn == 3 && width_ == 4)) return fail();
            load(destination, source, immediate, static_cast<u8>(bytes), fn < 4); return;
        }
        case 0x23: {
            const unsigned bytes = u32{1} << fn;
            if (fn > 3 || bytes > width_) return fail();
            store(second, source, sign(((word >> 25) << 5) | ((word >> 7) & 31), 12), static_cast<u8>(bytes)); return;
        }
        case 0x07:
            if (fn != 2 && fn != 3) return fail();
            loadFp(destination, source, immediate, fn == 2 ? 4 : 8); return;
        case 0x27:
            if (fn != 2 && fn != 3) return fail();
            storeFp(second, source, sign(((word >> 25) << 5) | ((word >> 7) & 31), 12), fn == 2 ? 4 : 8); return;
        case 0x43:case 0x47:case 0x4b:case 0x4f: {
            const unsigned format=(word>>25)&3;
            if(format>1 || (fn!=0 && fn!=7))return fail();
            const u8 size=format?8:4;
            auto left=fpValue(source,size),right=fpValue(second,size),addend=fpValue(word>>27,size);
            if(opcode==0x4b || opcode==0x4f)left=b_.unary(MintOp::kFloatNeg,left,size);
            if(opcode==0x47 || opcode==0x4f)addend=b_.unary(MintOp::kFloatNeg,addend,size);
            const auto value=rounded(b_.ternary(MintOp::kFloatFma,left,right,addend),fn);
            flagsUnknown();writeFp(destination,value);return;
        }
        case 0x53: {
            const u8 size = (extended & 1) ? 8 : 4;
            if (extended <= 13 && (extended & ~1u) % 4 == 0) {
                if (fn != 0 && fn != 7) return fail();
                const auto op = extended < 4 ? MintOp::kFloatAdd : extended < 8 ? MintOp::kFloatSub : extended < 12 ? MintOp::kFloatMul : MintOp::kFloatDiv;
                auto value = rounded(b_.binary(op, fpValue(source, size), fpValue(second, size)), fn);
                flagsUnknown(); writeFp(destination, value); return;
            }
            if ((extended == 0x2c || extended == 0x2d) && second == 0) {
                if (fn != 0 && fn != 7) return fail();
                auto value = rounded(b_.unary(MintOp::kFloatSqrt, fpValue(source, size), size), fn);
                flagsUnknown(); writeFp(destination, value); return;
            }
            if ((extended == 0x50 || extended == 0x51) && fn <= 2) {
                const auto left=fpValue(source,size),right=fpValue(second,size);
                auto value = b_.binary(fn==2 ? MintOp::kFloatEqual : MintOp::kFloatLess,left,right);
                if(fn==0)value=b_.binary(MintOp::kOr,value,b_.binary(MintOp::kFloatEqual,left,right));
                flagsUnknown();write(destination,value);return;
            }
            if ((extended == 0x60 || extended == 0x61) && second <= 3 && (second < 2 || width_ == 8)) {
                if (fn != 1 && fn != 7) return fail(); // FloatToInt explicitly truncates.
                const u8 integerSize = second < 2 ? 4 : 8;
                auto value = b_.unary(second & 1 ? MintOp::kFloatToIntU : MintOp::kFloatToInt, fpValue(source,size), integerSize);
                value = rounded(value,fn,1); flagsUnknown();write(destination,value,integerSize==4);return;
            }
            if ((extended == 0x68 || extended == 0x69) && second <= 3 && (second < 2 || width_ == 8)) {
                if (fn != 0 && fn != 7) return fail();
                auto value = b_.unary(second & 1 ? MintOp::kIntToFloatU : MintOp::kIntToFloat, reg(source,second < 2 ? 4 : 8), size);
                value = rounded(value,fn);flagsUnknown();writeFp(destination,value);return;
            }
            if ((extended == 0x20 && second == 1) || (extended == 0x21 && second == 0)) {
                if (fn != 0 && fn != 7) return fail();
                auto value=rounded(b_.unary(MintOp::kFloatConvert,fpValue(source,size==4?8:4),size),fn);
                flagsUnknown();writeFp(destination,value);return;
            }
            if ((extended == 0x14 || extended == 0x15) && fn <= 1) {
                const auto left=fpValue(source,size),right=fpValue(second,size);
                const u64 signMask=u64{1}<<(size*8-1),inf=size==4?0x7f800000ull:0x7ff0000000000000ull;
                auto magnitude=[&](const Varnode& value){return b_.binary(MintOp::kAnd,value,imm(~signMask,size));};
                const auto lmag=magnitude(left),rmag=magnitude(right);
                const auto lnan=b_.binary(MintOp::kLessU,imm(inf,size),lmag),rnan=b_.binary(MintOp::kLessU,imm(inf,size),rmag);
                const auto zeros=b_.binary(MintOp::kEqual,b_.binary(MintOp::kOr,lmag,rmag),imm(0,size));
                const auto less=b_.binary(MintOp::kFloatLess,left,right);
                auto value=choose(zeros,b_.binary(fn?MintOp::kAnd:MintOp::kOr,left,right),choose(less,fn?right:left,fn?left:right));
                value=choose(lnan,choose(rnan,imm(inf|(size==4?0x400000ull:0x8000000000000ull),size),right),choose(rnan,left,value));
                flagsUnknown();writeFp(destination,value);return;
            }
            if (extended == 0x10 || extended == 0x11) {
                if (fn > 2) return fail();
                const u64 signMask = u64{1} << (size * 8 - 1);
                const auto left = fpValue(source, size), right = fpValue(second, size);
                auto signValue = fn == 2 ? b_.binary(MintOp::kXor, left, right) : right;
                if (fn == 1) signValue = b_.binary(MintOp::kXor, signValue, imm(signMask, size));
                writeFp(destination, b_.binary(MintOp::kOr, b_.binary(MintOp::kAnd, left, imm(~signMask, size)),
                    b_.binary(MintOp::kAnd, signValue, imm(signMask, size)))); return;
            }
            if ((extended == 0x70 || extended == 0x71) && second == 0) {
                if (fn == 1) { classify(destination, source, size); return; }
                if (fn == 0 && size <= width_) { write(destination, fp(source, size), true); return; }
            }
            if ((extended == 0x78 || extended == 0x79) && second == 0 && fn == 0 && size <= width_) {
                writeFp(destination, reg(source, size)); return;
            }
            return fail();
        }
        case 0x13:
        case 0x1b: {
            const bool narrow = opcode == 0x1b;
            if (narrow && width_ != 8) return fail();
            const u8 size = narrow ? 4 : width_;
            const auto left = reg(source, size);
            auto right = imm(immediate, size);
            MintOp operation = MintOp::kInvalid;
            if (fn == 0) operation = MintOp::kAdd;
            else if (fn == 1 || fn == 5) {
                const unsigned bits = narrow || width_ == 4 ? 5 : 6;
                const unsigned encoded = word >> (20 + bits);
                if (fn == 1 && encoded != 0) return fail();
                if (fn == 5 && encoded != 0 && encoded != (0x400u >> bits)) return fail();
                right = imm((word >> 20) & ((1u << bits) - 1), 1);
                operation = fn == 1 ? MintOp::kShl : (encoded ? MintOp::kShrS : MintOp::kShrU);
            } else if (!narrow) {
                if (fn == 2) operation = MintOp::kLessS;
                else if (fn == 3) operation = MintOp::kLessU;
                else if (fn == 4) operation = MintOp::kXor;
                else if (fn == 6) operation = MintOp::kOr;
                else if (fn == 7) operation = MintOp::kAnd;
            }
            if (operation == MintOp::kInvalid) return fail();
            write(destination, b_.binary(operation, left, right), narrow); return;
        }
        case 0x33:
        case 0x3b: {
            const bool narrow = opcode == 0x3b;
            if (narrow && width_ != 8) return fail();
            const u8 size = narrow ? 4 : width_;
            const auto left = reg(source, size), right = reg(second, size);
            MintOp operation = MintOp::kInvalid;
            if (extended == 1) {
                if (fn == 0) operation = MintOp::kMul;
                else if (fn == 1 && !narrow) operation = MintOp::kMulHiS;
                else if (fn == 2 && !narrow) {
                    const auto high = b_.binary(MintOp::kMulHiU, left, right);
                    const auto negative = b_.binary(MintOp::kLessS, left, imm(0, size));
                    const auto corrected = b_.binary(MintOp::kSub, high, right);
                    const auto result = b_.newTemp(size); b_.emit(MintOp::kSelect, result, negative, corrected, high);
                    write(destination, result); return;
                } else if (fn == 3 && !narrow) operation = MintOp::kMulHiU;
                else if (fn >= 4) {
                    operation = fn == 4 ? MintOp::kDivS : (fn == 5 ? MintOp::kDivU : (fn == 6 ? MintOp::kRemS : MintOp::kRemU));
                    write(destination, division(operation, left, right), narrow); return;
                }
            } else if (extended == 0 || extended == 0x20) {
                if (fn == 0) operation = extended ? MintOp::kSub : MintOp::kAdd;
                else if (fn == 5) operation = extended ? MintOp::kShrS : MintOp::kShrU;
                else if (!extended && fn == 1) operation = MintOp::kShl;
                else if (!extended && !narrow) {
                    if (fn == 2) operation = MintOp::kLessS;
                    else if (fn == 3) operation = MintOp::kLessU;
                    else if (fn == 4) operation = MintOp::kXor;
                    else if (fn == 6) operation = MintOp::kOr;
                    else if (fn == 7) operation = MintOp::kAnd;
                }
            }
            if (operation == MintOp::kInvalid) return fail();
            const bool shift = operation == MintOp::kShl || operation == MintOp::kShrS || operation == MintOp::kShrU;
            write(destination, b_.binary(operation, left, shift ? b_.binary(MintOp::kAnd, right, imm(size * 8 - 1, size)) : right), narrow); return;
        }
        case 0x2f: {
            if ((fn != 2 && fn != 3) || (fn == 3 && width_ != 8)) return fail();
            const u8 size = fn == 2 ? 4 : 8;
            MintOp operation;
            switch (word >> 27) {
                case 0: operation=MintOp::kAtomicAdd;break;
                case 1: operation=MintOp::kAtomicExchange;break;
                case 4: operation=MintOp::kAtomicXor;break;
                case 8: operation=MintOp::kAtomicOr;break;
                case 12: operation=MintOp::kAtomicAnd;break;
                case 16: operation=MintOp::kAtomicMinS;break;
                case 20: operation=MintOp::kAtomicMaxS;break;
                case 24: operation=MintOp::kAtomicMinU;break;
                case 28: operation=MintOp::kAtomicMaxU;break;
                default: return fail(); // LR/SC need an exclusive monitor model.
            }
            const auto previous=b_.newTemp(size);
            // Snapshot address/value before rd is changed; rd may alias rs1/rs2.
            b_.emit(operation,previous,reg(source),reg(second,size));
            write(destination,previous,true); // AMO.W sign-extends on RV64.
            return;
        }
        case 0x0f:
            // Only the standard memory FENCE and FENCE.TSO encodings. FENCE.I
            // and extensions carry instruction-cache/external semantics.
            if (fn==0 && destination==0 && source==0 &&
                ((word>>28)==0 || (word>>20)==0x833)) {
                b_.emit(MintOp::kMemoryFence,{});return;
            }
            return fail();
        case 0x73:
            if (word == 0x00100073) { b_.emit(MintOp::kTrap, {}); return; }
            if (floatCsr(word >> 20, fn, destination, source)) return;
            return fail(); // ECALL/CSRs/privileged state have external semantics.
        default: return fail();
    }
}

void RiscVLifter::compressed(u16 word) {
    const unsigned quadrant = word & 3, fn = word >> 13, destination = (word >> 7) & 31;
    const unsigned compactDestination = 8 + ((word >> 2) & 7), compactSource = 8 + ((word >> 7) & 7);
    const unsigned source = (word >> 2) & 31;
    const i64 immediate = sign(((word >> 12) & 1) << 5 | ((word >> 2) & 31), 6);
    auto jumpDelta = [&]() {
        const u32 encoded = (((word >> 12) & 1) << 11) | (((word >> 11) & 1) << 4) |
            (((word >> 9) & 3) << 8) | (((word >> 8) & 1) << 10) | (((word >> 7) & 1) << 6) |
            (((word >> 6) & 1) << 7) | (((word >> 3) & 7) << 1) | (((word >> 2) & 1) << 5);
        return sign(encoded, 12);
    };
    if (quadrant == 0) {
        if (fn == 1 || fn == 5 || (width_ == 4 && (fn == 3 || fn == 7))) {
            const bool wide = fn == 1 || fn == 5;
            const unsigned offset = wide ? (((word >> 10) & 7) << 3) | (((word >> 5) & 3) << 6) :
                (((word >> 10) & 7) << 3) | (((word >> 6) & 1) << 2) | (((word >> 5) & 1) << 6);
            if (fn < 4) loadFp(compactDestination, compactSource, offset, wide ? 8 : 4);
            else storeFp(compactDestination, compactSource, offset, wide ? 8 : 4);
            return;
        }
        if (fn == 0) {
            const unsigned encoded = (((word >> 7) & 15) << 6) | (((word >> 11) & 3) << 4) |
                (((word >> 5) & 1) << 3) | (((word >> 6) & 1) << 2);
            write(compactDestination, b_.binary(MintOp::kAdd, reg(2), imm(encoded))); return;
        }
        const bool wide = fn == 3 || fn == 7;
        if ((fn == 2 || fn == 6 || (wide && width_ == 8))) {
            const unsigned offset = wide ? (((word >> 10) & 7) << 3) | (((word >> 5) & 3) << 6) :
                (((word >> 10) & 7) << 3) | (((word >> 6) & 1) << 2) | (((word >> 5) & 1) << 6);
            if (fn < 4) load(compactDestination, compactSource, offset, wide ? 8 : 4, true);
            else store(compactDestination, compactSource, offset, wide ? 8 : 4);
            return;
        }
    } else if (quadrant == 1) {
        switch (fn) {
            case 0: write(destination, b_.binary(MintOp::kAdd, reg(destination), imm(immediate))); return;
            case 1:
                if (width_ == 4) jump(1, target(jumpDelta()));
                else write(destination, b_.binary(MintOp::kAdd, reg(destination, 4), imm(immediate, 4)), true);
                return;
            case 2: write(destination, imm(immediate)); return;
            case 3:
                if (destination == 2) {
                    const u32 encoded = (((word >> 12) & 1) << 9) | (((word >> 6) & 1) << 4) |
                        (((word >> 5) & 1) << 6) | (((word >> 3) & 3) << 7) | (((word >> 2) & 1) << 5);
                    write(2, b_.binary(MintOp::kAdd, reg(2), imm(sign(encoded, 10))));
                } else write(destination, imm(immediate * 4096));
                return;
            case 4: {
                const unsigned sub = (word >> 10) & 3;
                if (sub < 2) { write(compactSource, b_.binary(sub ? MintOp::kShrS : MintOp::kShrU, reg(compactSource), imm(((word >> 12) & 1) * 32 + ((word >> 2) & 31), 1))); return; }
                if (sub == 2) { write(compactSource, b_.binary(MintOp::kAnd, reg(compactSource), imm(immediate))); return; }
                const unsigned operation = (word >> 5) & 3;
                const bool narrow = (word & 0x1000) != 0;
                if (narrow && (width_ != 8 || operation >= 2)) return fail();
                const MintOp op = narrow ? (operation ? MintOp::kAdd : MintOp::kSub) :
                    (operation == 0 ? MintOp::kSub : (operation == 1 ? MintOp::kXor : (operation == 2 ? MintOp::kOr : MintOp::kAnd)));
                write(compactSource, b_.binary(op, reg(compactSource, narrow ? 4 : width_), reg(compactDestination, narrow ? 4 : width_)), narrow); return;
            }
            case 5: jump(0, target(jumpDelta())); return;
            case 6: case 7: {
                const u32 encoded = (((word >> 12) & 1) << 8) | (((word >> 10) & 3) << 3) |
                    (((word >> 5) & 3) << 6) | (((word >> 3) & 3) << 1) | (((word >> 2) & 1) << 5);
                branch(compactSource, 0, MintOp::kEqual, sign(encoded, 9), fn == 7); return;
            }
        }
    } else if (quadrant == 2) {
        if (fn == 1 || fn == 5 || (width_ == 4 && (fn == 3 || fn == 7))) {
            const bool wide = fn == 1 || fn == 5;
            if (fn < 4) {
                const unsigned offset = wide ? (((word >> 12) & 1) << 5) | (((word >> 5) & 3) << 3) | (((word >> 2) & 7) << 6) :
                    (((word >> 12) & 1) << 5) | (((word >> 4) & 7) << 2) | (((word >> 2) & 3) << 6);
                loadFp(destination, 2, offset, wide ? 8 : 4);
            } else {
                const unsigned offset = wide ? (((word >> 10) & 7) << 3) | (((word >> 7) & 7) << 6) :
                    (((word >> 9) & 15) << 2) | (((word >> 7) & 3) << 6);
                storeFp(source, 2, offset, wide ? 8 : 4);
            }
            return;
        }
        if (fn == 0) { write(destination, b_.binary(MintOp::kShl, reg(destination), imm(((word >> 12) & 1) * 32 + source, 1))); return; }
        if (fn == 2 || (fn == 3 && width_ == 8)) {
            const unsigned offset = fn == 2 ? (((word >> 12) & 1) << 5) | (((word >> 4) & 7) << 2) | (((word >> 2) & 3) << 6) :
                (((word >> 12) & 1) << 5) | (((word >> 5) & 3) << 3) | (((word >> 2) & 7) << 6);
            load(destination, 2, offset, fn == 2 ? 4 : 8, true); return;
        }
        if (fn == 4) {
            if (!source) {
                if (!destination && (word & 0x1000)) b_.emit(MintOp::kTrap, {});
                else indirect((word & 0x1000) ? 1 : 0, destination, 0);
            } else if (word & 0x1000) write(destination, b_.binary(MintOp::kAdd, reg(destination), reg(source)));
            else write(destination, reg(source));
            return;
        }
        if (fn == 6 || (fn == 7 && width_ == 8)) {
            const unsigned offset = fn == 6 ? (((word >> 9) & 15) << 2) | (((word >> 7) & 3) << 6) :
                (((word >> 10) & 7) << 3) | (((word >> 7) & 7) << 6);
            store(source, 2, offset, fn == 6 ? 4 : 8); return;
        }
    }
    fail();
}
}

void liftRiscV(const cs_insn& instruction, IrBuilder& builder, bool rv64) {
    builder.setAddress(instruction.address);
    RiscVLifter(instruction, builder, rv64).lift();
}
}  // namespace mint
