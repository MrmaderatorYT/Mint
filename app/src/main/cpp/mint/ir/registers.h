#pragma once

#include <string>

#include "mint/base/types.h"
#include "mint/ir/varnode.h"

namespace mint {

/// Register files, addressed as byte offsets rather than register numbers.
///
/// This is the one design choice in the IR worth explaining at length, because it
/// looks like an odd way to name a register and it is doing real work.
///
/// On x86-64, `rax`, `eax`, `ax`, `al` and `ah` are not five registers — they are
/// five overlapping windows onto the same eight bytes. If registers were numbered,
/// a dataflow pass would see a write to `al` and a read of `rax` as touching
/// unrelated storage, and would happily delete the write. Addressing by byte
/// offset and width makes the overlap fall out of arithmetic: `rax` is (0, 8),
/// `eax` is (0, 4), `al` is (0, 1), `ah` is (1, 1), and Varnode::overlaps answers
/// the aliasing question without a table of special cases.
///
/// The same applies on AArch64 to `x0`/`w0`, and to the SIMD registers where
/// `q0`, `d0`, `s0`, `h0` and `b0` are nested views of one 16-byte value.
///
/// Flags get one byte each instead of living packed inside a status register. That
/// costs a little space and buys precise dataflow: the decompiler can ask "what
/// wrote the zero flag that this branch reads" and get one answer, which is the
/// whole basis of turning a flag test back into `if (a == b)`.

// ----------------------------------------------------------------- AArch64
namespace arm64 {

constexpr u64 kX0 = 0;  ///< x0..x30 occupy 0..247, eight bytes each.
constexpr u64 kXn(unsigned n) { return kX0 + u64(n) * 8; }
constexpr u64 kSp = 248;
constexpr u64 kPc = 256;

/// NZCV, one byte each.
constexpr u64 kFlagN = 264;
constexpr u64 kFlagZ = 265;
constexpr u64 kFlagC = 266;
constexpr u64 kFlagV = 267;

/// v0..v31, sixteen bytes each.
constexpr u64 kV0 = 272;
constexpr u64 kVn(unsigned n) { return kV0 + u64(n) * 16; }

/// The floating-point status register, needed so FP comparisons have somewhere to
/// put their result once floats are modelled.
constexpr u64 kFpsr = 784;

constexpr u64 kFileSize = 792;

}  // namespace arm64

// ------------------------------------------------------------------ x86-64
namespace x86 {

/// The general-purpose registers, in the order the encoding numbers them, which
/// makes mapping from a ModRM field arithmetic rather than a lookup.
constexpr u64 kRax = 0;
constexpr u64 kRcx = 8;
constexpr u64 kRdx = 16;
constexpr u64 kRbx = 24;
constexpr u64 kRsp = 32;
constexpr u64 kRbp = 40;
constexpr u64 kRsi = 48;
constexpr u64 kRdi = 56;
constexpr u64 kR8 = 64;
constexpr u64 kGpr(unsigned n) { return u64(n) * 8; }  ///< n in 0..15
constexpr u64 kRip = 128;

/// One byte per flag.
constexpr u64 kFlagCf = 136;
constexpr u64 kFlagPf = 137;
constexpr u64 kFlagAf = 138;
constexpr u64 kFlagZf = 139;
constexpr u64 kFlagSf = 140;
constexpr u64 kFlagDf = 141;
constexpr u64 kFlagOf = 142;

/// Segment bases. `fs` is where the thread pointer lives on Android and Linux, so
/// anything touching TLS — stack guards, and much of the anti-debug code this tool
/// exists to read — goes through here. Leaving it unmodelled would turn every TLS
/// access into an intrinsic.
constexpr u64 kFsBase = 144;
constexpr u64 kGsBase = 152;

/// xmm0..xmm15, sixteen bytes each.
constexpr u64 kXmm0 = 160;
constexpr u64 kXmmN(unsigned n) { return kXmm0 + u64(n) * 16; }

constexpr u64 kFileSize = 416;

}  // namespace x86

/// Size of the register file for an architecture, which is how much storage an
/// emulator has to provide.
u64 registerFileSize(Arch arch);

/// The name of the register a (offset, size) pair denotes, or a synthetic
/// `r<offset>.<size>` when the pair does not line up with any architectural
/// register — which happens legitimately, for instance when a lifter reads the
/// upper half of a pair register.
std::string registerName(Arch arch, u64 offset, u8 size);

/// Maps a Capstone register id to a varnode. Returns an invalid varnode for
/// registers the IR does not model, and for Capstone's "no register" value.
///
/// Declared here but implemented per-architecture next to the lifter that needs
/// it, so that Capstone's headers stay out of the IR's public interface.
Varnode registerFromCapstone(Arch arch, unsigned capstoneReg);

}  // namespace mint
