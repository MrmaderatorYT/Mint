// RV32/RV64 integer + compressed scalar instructions -> MintIR. Floating-point,
// vector, atomic and privileged state not modelled here remains an intrinsic.
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
        case 0x0f: return fail(); // Memory ordering is an explicit intrinsic barrier.
        case 0x73:
            if (word == 0x00100073) { b_.emit(MintOp::kTrap, {}); return; }
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
