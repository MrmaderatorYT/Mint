#pragma once

#include "mint/base/types.h"
#include "mint/ir/ir_function.h"

namespace mint {

/// What a normalization run had to do, and what it could not do.
///
/// The last field is the one that matters: an access left unnormalized is a place
/// where the SSA builder has to fall back on a conservative read-modify-write, and
/// the point of counting it is that "how much of this function is in exact SSA form"
/// stays a measured number rather than an assumption.
struct NormalizeStats {
    u32 narrowReads = 0;      ///< reads narrower than their unit, given an extract
    u32 narrowWrites = 0;     ///< writes narrower than their unit, given an insert
    u32 zeroingWrites = 0;    ///< partial writes that clear the rest of the unit
    u32 opsAdded = 0;
    u32 unnormalized = 0;     ///< accesses that could not be made whole-unit
};

/// Rewrites `function` so that every register operand is exactly one whole storage
/// unit, inserting explicit extracts and inserts around the accesses that are not.
///
/// This is what lets classic SSA be used on a byte-addressed register file. Reading
/// `w0` becomes "read x0, truncate"; writing `al` becomes "read rax, mask, splice,
/// write rax". Afterwards every operand names a whole variable, so renaming is the
/// textbook algorithm rather than a bespoke one that has to reason about partial
/// overlap at every step.
///
/// Doing it as an explicit rewrite rather than as a convention inside the SSA
/// builder is deliberate. The alternative — letting a narrow operand mean "the low
/// bytes of this unit" implicitly — pushes that rule into the emulator, the
/// decompiler and every future pass, and each of them would have to get it right.
/// Here it is paid for once, in ops that a later simplification can fold.
NormalizeStats normalizeRegisterAccesses(IrFunction* function);

}  // namespace mint
