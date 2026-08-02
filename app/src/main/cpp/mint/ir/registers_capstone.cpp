// Maps Capstone register ids onto MintIR register-file varnodes.
//
// Kept apart from registers.cpp — which only knows how to print — so that
// Capstone's headers reach exactly one translation unit per concern. Both
// architectures live here together because the two mappings are the same kind of
// table and reviewing them side by side is how discrepancies get noticed.

#include <capstone/capstone.h>

#include "mint/ir/registers.h"

namespace mint {
namespace {

// ----------------------------------------------------------------- AArch64
//
// Capstone's ids are not one contiguous run: w0..w30 and x0..x28 are contiguous,
// but x29 and x30 are the separate FP and LR ids, and sp and the zero registers
// sit in a low block of their own. Getting this wrong maps a frame pointer onto
// some unrelated register, so each range is handled explicitly rather than by
// arithmetic on a single base.
Varnode aarch64Register(unsigned reg) {
    if (reg >= AARCH64_REG_W0 && reg <= AARCH64_REG_W30) {
        return Varnode::reg(arm64::kXn(reg - AARCH64_REG_W0), 4);
    }
    if (reg >= AARCH64_REG_X0 && reg <= AARCH64_REG_X28) {
        return Varnode::reg(arm64::kXn(reg - AARCH64_REG_X0), 8);
    }
    switch (reg) {
        case AARCH64_REG_FP: return Varnode::reg(arm64::kXn(29), 8);  // x29
        case AARCH64_REG_LR: return Varnode::reg(arm64::kXn(30), 8);  // x30
        case AARCH64_REG_SP: return Varnode::reg(arm64::kSp, 8);
        case AARCH64_REG_WSP: return Varnode::reg(arm64::kSp, 4);
        // The zero registers are not storage. Returning an invalid varnode makes
        // the lifter substitute a literal zero on read and drop the write, which
        // is what the architecture actually does.
        case AARCH64_REG_XZR:
        case AARCH64_REG_WZR: return Varnode::invalid();
        case AARCH64_REG_NZCV: return Varnode::reg(arm64::kFlagN, 4);
        default: break;
    }

    // The SIMD registers are five nested views of the same sixteen bytes, which is
    // precisely what a byte-addressed register file expresses for free.
    if (reg >= AARCH64_REG_B0 && reg <= AARCH64_REG_B0 + 31) {
        return Varnode::reg(arm64::kVn(reg - AARCH64_REG_B0), 1);
    }
    if (reg >= AARCH64_REG_H0 && reg <= AARCH64_REG_H0 + 31) {
        return Varnode::reg(arm64::kVn(reg - AARCH64_REG_H0), 2);
    }
    if (reg >= AARCH64_REG_S0 && reg <= AARCH64_REG_S0 + 31) {
        return Varnode::reg(arm64::kVn(reg - AARCH64_REG_S0), 4);
    }
    if (reg >= AARCH64_REG_D0 && reg <= AARCH64_REG_D0 + 31) {
        return Varnode::reg(arm64::kVn(reg - AARCH64_REG_D0), 8);
    }
    if (reg >= AARCH64_REG_Q0 && reg <= AARCH64_REG_Q0 + 31) {
        return Varnode::reg(arm64::kVn(reg - AARCH64_REG_Q0), 16);
    }
    return Varnode::invalid();
}

// ------------------------------------------------------------------ x86-64
//
// Capstone numbers x86 registers alphabetically, so there is no arithmetic to
// exploit and the mapping is an explicit switch. Long, but each line is checkable
// against the register-file layout in registers.h, which a clever encoding would
// not be.
Varnode x86Register(unsigned reg) {
    switch (reg) {
        // 64-bit.
        case X86_REG_RAX: return Varnode::reg(x86::kGpr(0), 8);
        case X86_REG_RCX: return Varnode::reg(x86::kGpr(1), 8);
        case X86_REG_RDX: return Varnode::reg(x86::kGpr(2), 8);
        case X86_REG_RBX: return Varnode::reg(x86::kGpr(3), 8);
        case X86_REG_RSP: return Varnode::reg(x86::kGpr(4), 8);
        case X86_REG_RBP: return Varnode::reg(x86::kGpr(5), 8);
        case X86_REG_RSI: return Varnode::reg(x86::kGpr(6), 8);
        case X86_REG_RDI: return Varnode::reg(x86::kGpr(7), 8);
        case X86_REG_R8: return Varnode::reg(x86::kGpr(8), 8);
        case X86_REG_R9: return Varnode::reg(x86::kGpr(9), 8);
        case X86_REG_R10: return Varnode::reg(x86::kGpr(10), 8);
        case X86_REG_R11: return Varnode::reg(x86::kGpr(11), 8);
        case X86_REG_R12: return Varnode::reg(x86::kGpr(12), 8);
        case X86_REG_R13: return Varnode::reg(x86::kGpr(13), 8);
        case X86_REG_R14: return Varnode::reg(x86::kGpr(14), 8);
        case X86_REG_R15: return Varnode::reg(x86::kGpr(15), 8);

        // 32-bit: same offset, narrower window.
        case X86_REG_EAX: return Varnode::reg(x86::kGpr(0), 4);
        case X86_REG_ECX: return Varnode::reg(x86::kGpr(1), 4);
        case X86_REG_EDX: return Varnode::reg(x86::kGpr(2), 4);
        case X86_REG_EBX: return Varnode::reg(x86::kGpr(3), 4);
        case X86_REG_ESP: return Varnode::reg(x86::kGpr(4), 4);
        case X86_REG_EBP: return Varnode::reg(x86::kGpr(5), 4);
        case X86_REG_ESI: return Varnode::reg(x86::kGpr(6), 4);
        case X86_REG_EDI: return Varnode::reg(x86::kGpr(7), 4);
        case X86_REG_R8D: return Varnode::reg(x86::kGpr(8), 4);
        case X86_REG_R9D: return Varnode::reg(x86::kGpr(9), 4);
        case X86_REG_R10D: return Varnode::reg(x86::kGpr(10), 4);
        case X86_REG_R11D: return Varnode::reg(x86::kGpr(11), 4);
        case X86_REG_R12D: return Varnode::reg(x86::kGpr(12), 4);
        case X86_REG_R13D: return Varnode::reg(x86::kGpr(13), 4);
        case X86_REG_R14D: return Varnode::reg(x86::kGpr(14), 4);
        case X86_REG_R15D: return Varnode::reg(x86::kGpr(15), 4);

        // 16-bit.
        case X86_REG_AX: return Varnode::reg(x86::kGpr(0), 2);
        case X86_REG_CX: return Varnode::reg(x86::kGpr(1), 2);
        case X86_REG_DX: return Varnode::reg(x86::kGpr(2), 2);
        case X86_REG_BX: return Varnode::reg(x86::kGpr(3), 2);
        case X86_REG_SP: return Varnode::reg(x86::kGpr(4), 2);
        case X86_REG_BP: return Varnode::reg(x86::kGpr(5), 2);
        case X86_REG_SI: return Varnode::reg(x86::kGpr(6), 2);
        case X86_REG_DI: return Varnode::reg(x86::kGpr(7), 2);
        case X86_REG_R8W: return Varnode::reg(x86::kGpr(8), 2);
        case X86_REG_R9W: return Varnode::reg(x86::kGpr(9), 2);
        case X86_REG_R10W: return Varnode::reg(x86::kGpr(10), 2);
        case X86_REG_R11W: return Varnode::reg(x86::kGpr(11), 2);
        case X86_REG_R12W: return Varnode::reg(x86::kGpr(12), 2);
        case X86_REG_R13W: return Varnode::reg(x86::kGpr(13), 2);
        case X86_REG_R14W: return Varnode::reg(x86::kGpr(14), 2);
        case X86_REG_R15W: return Varnode::reg(x86::kGpr(15), 2);

        // 8-bit low.
        case X86_REG_AL: return Varnode::reg(x86::kGpr(0), 1);
        case X86_REG_CL: return Varnode::reg(x86::kGpr(1), 1);
        case X86_REG_DL: return Varnode::reg(x86::kGpr(2), 1);
        case X86_REG_BL: return Varnode::reg(x86::kGpr(3), 1);
        case X86_REG_SPL: return Varnode::reg(x86::kGpr(4), 1);
        case X86_REG_BPL: return Varnode::reg(x86::kGpr(5), 1);
        case X86_REG_SIL: return Varnode::reg(x86::kGpr(6), 1);
        case X86_REG_DIL: return Varnode::reg(x86::kGpr(7), 1);
        case X86_REG_R8B: return Varnode::reg(x86::kGpr(8), 1);
        case X86_REG_R9B: return Varnode::reg(x86::kGpr(9), 1);
        case X86_REG_R10B: return Varnode::reg(x86::kGpr(10), 1);
        case X86_REG_R11B: return Varnode::reg(x86::kGpr(11), 1);
        case X86_REG_R12B: return Varnode::reg(x86::kGpr(12), 1);
        case X86_REG_R13B: return Varnode::reg(x86::kGpr(13), 1);
        case X86_REG_R14B: return Varnode::reg(x86::kGpr(14), 1);
        case X86_REG_R15B: return Varnode::reg(x86::kGpr(15), 1);

        // The legacy high bytes: offset one, width one. These are the reason the
        // register file is addressed in bytes at all.
        case X86_REG_AH: return Varnode::reg(x86::kGpr(0) + 1, 1);
        case X86_REG_CH: return Varnode::reg(x86::kGpr(1) + 1, 1);
        case X86_REG_DH: return Varnode::reg(x86::kGpr(2) + 1, 1);
        case X86_REG_BH: return Varnode::reg(x86::kGpr(3) + 1, 1);

        case X86_REG_RIP: return Varnode::reg(x86::kRip, 8);

        // Segment registers stand in for their bases. Only fs and gs have a base
        // that matters in 64-bit mode, and fs is where the thread pointer lives —
        // stack guards and a good deal of anti-debug code read through it.
        case X86_REG_FS: return Varnode::reg(x86::kFsBase, 8);
        case X86_REG_GS: return Varnode::reg(x86::kGsBase, 8);

        default: break;
    }

    if (reg >= X86_REG_XMM0 && reg <= X86_REG_XMM15) {
        return Varnode::reg(x86::kXmmN(reg - X86_REG_XMM0), 16);
    }
    return Varnode::invalid();
}

}  // namespace

Varnode registerFromCapstone(Arch arch, unsigned capstoneReg) {
    if (capstoneReg == 0) return Varnode::invalid();
    switch (arch) {
        case Arch::kAArch64: return aarch64Register(capstoneReg);
        case Arch::kX86_64: return x86Register(capstoneReg);
        default: return Varnode::invalid();
    }
}

}  // namespace mint
