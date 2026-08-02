#pragma once

#include <string>

#include "mint/base/types.h"

namespace mint {

/// Where a varnode's bits live.
enum class Space : u8 {
    /// An unused operand slot. Most ops take fewer than three sources.
    kInvalid = 0,
    /// A literal. `offset` holds the value, zero-extended to 64 bits.
    kConstant,
    /// A machine register, addressed as a byte offset into a flat per-architecture
    /// register file. See registers.h for why that is a byte offset rather than a
    /// register number.
    kRegister,
    /// A lifter-created temporary, numbered from zero within one lifted function.
    /// These are what let a machine instruction decompose into simple ops without
    /// inventing fake registers.
    kTemp,
    /// Main memory. Only ever the address operand of a load or store — the IR has
    /// one flat address space, because a Linux process does.
    kMemory,
};

const char* spaceName(Space space);

/// A typeless slice of bits: somewhere to read from or write to, plus a width.
///
/// This is the single currency of the IR. Every op reads and writes varnodes and
/// nothing else, which is what makes one set of analyses work across three
/// instruction sets: the passes above never learn what an `x86 lea` or an
/// `aarch64 ldp` is.
///
/// No type field, deliberately. At this level a 4-byte quantity is 4 bytes; only
/// the ops applied to it say whether it was meant as signed, unsigned, or a
/// pointer. Type recovery is a later pass that reads those ops back, and giving
/// the lifter a type field to fill in would only invite it to guess.
struct Varnode {
    Space space = Space::kInvalid;
    /// Width in bytes. 1..16 in practice; 16 covers a SIMD register.
    u8 size = 0;
    /// Constant value, register-file byte offset, or temporary number.
    u64 offset = 0;

    bool valid() const { return space != Space::kInvalid; }
    bool isConstant() const { return space == Space::kConstant; }
    bool isRegister() const { return space == Space::kRegister; }
    bool isTemp() const { return space == Space::kTemp; }

    /// True when the two varnodes name overlapping storage. Registers alias by
    /// construction — on x86-64, writing `al` changes `rax` — so a dataflow pass
    /// that only compared offsets for equality would miss real dependencies.
    bool overlaps(const Varnode& other) const {
        if (space != other.space) return false;
        if (space == Space::kConstant || space == Space::kInvalid) return false;
        return offset < other.offset + other.size && other.offset < offset + size;
    }

    bool operator==(const Varnode& other) const {
        return space == other.space && size == other.size && offset == other.offset;
    }
    bool operator!=(const Varnode& other) const { return !(*this == other); }

    static Varnode constant(u64 value, u8 size) {
        return Varnode{Space::kConstant, size, value};
    }
    static Varnode reg(u64 byteOffset, u8 size) {
        return Varnode{Space::kRegister, size, byteOffset};
    }
    static Varnode temp(u64 id, u8 size) { return Varnode{Space::kTemp, size, id}; }
    static Varnode invalid() { return Varnode{}; }
};

/// Renders a varnode for the IR listing. `arch` is needed only so registers can
/// be printed by their real names instead of as file offsets.
std::string describeVarnode(const Varnode& node, Arch arch);

}  // namespace mint
