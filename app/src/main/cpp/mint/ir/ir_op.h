#pragma once

#include "mint/base/types.h"

namespace mint {

/// The MintIR opcode set.
///
/// Kept small on purpose. Every op added here is an op that the SSA pass, the
/// dataflow pass, the emulator, the deobfuscator and the C emitter each have to
/// handle, so the cost of a new opcode is five implementations, not one. The rule
/// used throughout: if a machine instruction can be expressed as a short sequence
/// of existing ops, it is lifted into that sequence rather than given its own
/// opcode.
///
/// Two properties the whole pipeline relies on:
///
/// - **No implicit side effects.** A machine instruction that sets flags lifts to
///   explicit writes of the individual flag varnodes. Nothing downstream has to
///   know that `subs` touches NZCV, which is exactly what makes flag-based
///   condition recovery a plain dataflow query later.
/// - **Unmodelled is explicit.** An instruction the lifter does not understand
///   becomes kIntrinsic, never nothing. Silently dropping an instruction would
///   make the emulator and the decompiler confidently wrong, which is far worse
///   than a listing that admits a gap.
enum class MintOp : u8 {
    /// Placeholder; never emitted.
    kInvalid = 0,

    // -- movement ----------------------------------------------------------
    kCopy,   ///< dest = a
    kLoad,   ///< dest = *(a), reading dest.size bytes
    kStore,  ///< *(a) = b, writing b.size bytes. No dest.

    // -- integer arithmetic, wrapping at the operand width ------------------
    kAdd,
    kSub,
    kMul,
    /// The upper half of a full-width multiply. Present as its own opcode because
    /// it cannot be expressed at all in terms of the others — a 64x64 multiply's
    /// high word needs 128-bit intermediates — and because compilers emit it
    /// constantly for division by a constant, so leaving it out would put an
    /// intrinsic in the middle of every such division.
    kMulHiU,
    kMulHiS,
    kDivU,
    kDivS,
    kRemU,
    kRemS,
    /// Division of a double-width dividend: `dest = (b:a) / c`, with `a` the low
    /// half and `b` the high half. The remainder form is `dest = (b:a) % c`.
    ///
    /// These exist because x86's one-operand DIV and IDIV divide RDX:RAX — 128 bits
    /// over 64 — and no combination of the fixed-width opcodes says that. The
    /// alternative was a 128-bit Varnode, which would have reached into register
    /// windows, SSA, the interpreter's value type and the emitter to express
    /// something only this one instruction family needs. Passing the halves as two
    /// sources keeps every width in the IR a real machine width.
    ///
    /// The quotient can overflow `dest` — that is the #DE fault on real hardware —
    /// and is left wrapping here rather than modelled as a trap.
    kDivWideU,
    kDivWideS,
    kRemWideU,
    kRemWideS,
    kNeg,  ///< dest = -a

    // -- bitwise -----------------------------------------------------------
    kAnd,
    kOr,
    kXor,
    kNot,   ///< dest = ~a
    kShl,
    kShrU,  ///< logical right shift
    kShrS,  ///< arithmetic right shift
    kRotL,
    kRotR,

    // -- comparison. dest is always 1 byte holding 0 or 1 ------------------
    //
    // Only the less-than forms exist: `a > b` is `b < a`, and having one spelling
    // per relation means the simplifier and the C emitter each handle half as
    // many cases.
    kEqual,
    kNotEqual,
    kLessU,
    kLessS,
    kLessEqU,
    kLessEqS,

    // -- width changes -----------------------------------------------------
    kZeroExt,  ///< dest.size > a.size
    kSignExt,  ///< dest.size > a.size
    kTrunc,    ///< dest.size < a.size

    // -- flag computation. dest is 1 byte ----------------------------------
    //
    // These exist as opcodes rather than as lifted sequences because carry and
    // overflow are genuinely awkward to express in terms of the other ops, and
    // because recognising them by name is how the decompiler later turns a
    // flag comparison back into a signed or unsigned relational operator.
    kCarryAdd,     ///< unsigned carry out of a + b
    kBorrowSub,    ///< unsigned borrow out of a - b
    kOverflowAdd,  ///< signed overflow of a + b
    kOverflowSub,  ///< signed overflow of a - b

    // -- bit counting ------------------------------------------------------
    kPopCount,
    kClz,  ///< count leading zeros
    kCtz,  ///< count trailing zeros

    // -- floating point and SIMD ------------------------------------------
    // Scalar FP values use 4- or 8-byte varnodes. Vectors use a 16-byte
    // varnode, with arrangement/lane information retained by the producer.
    kFloatAdd,
    kFloatSub,
    kFloatMul,
    kFloatDiv,
    kFloatSqrt,
    kFloatAbs,
    kFloatNeg,
    /// Produces packed NZCV bits in a 4-byte value; the AArch64 lifter expands
    /// those bits to the ordinary flag varnodes used by integer branches.
    kFloatCmp,
    kIntToFloat,
    kFloatToInt,
    kVectorAdd,
    kVectorSub,
    kVectorMul,
    /// Widening multiply of alternating lanes: x86's PMULUDQ takes the even 32-bit
    /// lanes and produces 64-bit products. Distinct from kVectorMul because the
    /// result lanes are not the operand lanes.
    kVectorMulWideU,
    kVectorMulWideS,
    /// Lane-wise compare producing an all-ones or all-zeros mask per lane, which is
    /// how every SIMD compare reports and what the following blend consumes.
    kVectorCmpEq,
    kVectorCmpGtS,
    kVectorMinU,
    kVectorMinS,
    kVectorMaxU,
    kVectorMaxS,
    /// Lane-wise shifts by a scalar count in `b`.
    kVectorShl,
    kVectorShrU,
    kVectorShrS,
    /// Narrow two vectors into one of half-width lanes, clamping rather than
    /// truncating. Saturation is the whole point of the instruction, so it cannot
    /// be modelled as a truncating narrow.
    kVectorPackS,
    kVectorPackU,
    /// Widen the low lanes of `a` into fewer, wider lanes. laneWidth is the source
    /// lane; the destination lane is implied by the count.
    kVectorExtendS,
    kVectorExtendU,
    /// `dest = a` with lane `c` replaced by scalar `b`.
    kVectorInsert,
    /// `dest` = lane `b` of `a`, as a scalar.
    kVectorExtract,
    /// Per-lane select: `dest[i] = mask[i] ? b[i] : a[i]`, mask in `c`.
    kVectorSelect,
    /// Table-driven shuffle across three vectors, as AArch64's TBL does.
    kVectorShuffle,
    /// Lane permutation by an immediate control word, as x86's PSHUFD does. Kept
    /// apart from kVectorShuffle because it takes two sources rather than three,
    /// and the verifier holds every opcode to a fixed arity.
    kVectorPermute,
    kVectorSplat,
    kVectorLoad,
    kVectorStore,
    kVectorBit,
    kVectorBif,

    /// dest = a ? b : c — `a` is the 1-byte condition, `b` the value when it
    /// holds, `c` the value when it does not.
    ///
    /// The IR has no branching inside a single machine instruction, so predicated
    /// instructions — `csel`, `cmov`, `cset` — lift to this. That restriction is
    /// what keeps an IR basic block exactly a machine basic block, which in turn
    /// keeps every later CFG pass simple.
    kSelect,

    // -- control flow ------------------------------------------------------
    //
    // Each of these ends a block. `a` carries the destination: a constant for
    // direct forms, any varnode for indirect ones.
    kBranch,
    kCondBranch,  ///< if (a) goto b, with b constant
    kBranchInd,
    kCall,
    kCallInd,
    kReturn,  ///< a is the return address when known, otherwise invalid

    /// A machine instruction with no MintIR modelling yet.
    ///
    /// `intrinsicId` names the machine instruction. An intrinsic must be treated
    /// as "may read and write anything", which costs precision but never
    /// correctness. Counting these is how we measure how complete the lifter
    /// actually is, rather than guessing.
    kIntrinsic,

    /// dest holds a value that is architecturally undefined.
    ///
    /// Real instruction sets leave flags undefined after some operations, and
    /// saying so lets the decompiler drop a comparison it would otherwise have to
    /// treat as meaningful.
    kUndefined,

    /// Control does not continue past this instruction: a debugger trap, an
    /// undefined-instruction fault, a halt.
    ///
    /// Separate from kIntrinsic on purpose. An intrinsic means "the lifter does not
    /// know what this does", which is a gap in coverage; a trap is fully understood
    /// — it raises a signal and never returns — it simply has no effect expressible
    /// as values. Filing traps under intrinsic conflated the two, and on a real
    /// x86 library that single instruction accounted for 43% of the reported gap,
    /// which made coverage look far worse than it was. Being a terminator also
    /// stops later passes believing execution falls through into whatever padding
    /// follows.
    kTrap,

    // -- floating-point predicates -----------------------------------------
    //
    // Three separate ops rather than one compare returning a code, because IEEE
    // comparison is not a total order: two values can be neither equal, nor less,
    // nor greater, when either is a NaN. x86's `ucomis*` reports exactly that
    // distinction across three flags, and folding it into a single result would
    // lose the one case — unordered — that the flags exist to signal.
    /// dest = 1 when a and b are ordered and equal.
    kFloatEqual,
    /// dest = 1 when a and b are ordered and a < b.
    kFloatLess,
    /// dest = 1 when either operand is a NaN, so no ordering holds.
    kFloatUnordered,
    kIntToFloatU, ///< Unsigned integer -> IEEE scalar; distinct from signed.
    kFloatToIntU, ///< IEEE scalar -> unsigned integer, truncate toward zero.
    kFloatConvert, ///< IEEE32 <-> IEEE64 representation conversion, not a copy.
    kMemoryFence, ///< Ordering barrier; no single-thread value effect.
    kAtomicLoad,
    kAtomicStore,
    kAtomicExchange,
    kAtomicAdd,
    /// Returns original memory; write c iff original memory equals b.
    kAtomicCompareExchange,
};

/// Static facts about an opcode, for the printer, the verifier and the emulator.
struct OpInfo {
    const char* name;
    /// How many of the three source slots the op reads.
    u8 sources;
    bool hasDest;
    /// True when the op ends a basic block.
    bool terminator;
};

/// How many opcodes exist. Callers that enumerate them — a printer, a test that
/// declares a helper per opcode — need a bound that cannot go stale when an opcode
/// is appended, which naming the last one cannot give.
unsigned opCount();

const OpInfo& opInfo(MintOp op);

inline const char* opName(MintOp op) { return opInfo(op).name; }
inline bool isTerminator(MintOp op) { return opInfo(op).terminator; }

/// True for ops whose dest is a 1-byte boolean, which is the set the condition
/// recovery pass looks for.
bool producesBoolean(MintOp op);

}  // namespace mint
