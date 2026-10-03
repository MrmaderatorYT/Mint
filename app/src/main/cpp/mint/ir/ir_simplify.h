#pragma once

#include "mint/base/status.h"
#include "mint/ir/ir_function.h"
#include "mint/ssa/ssa_function.h"

namespace mint {

struct IrSimplifyStats {
    u32 constantsFolded = 0;
    u32 deadWritesRemoved = 0;
};

/// Performs conservative, architecture-independent simplification on raw IR.
/// Callers normally run normalizeRegisterAccesses before this pass; the pass never
/// invents partial-register semantics and never removes stores, calls or intrinsics.
/// Native returns also observe the ABI result register implicitly; those writes
/// are retained until SSA can determine the definition reaching each return.
Status simplifyIr(IrFunction* function, IrSimplifyStats* stats = nullptr);

struct SsaSimplifyStats {
    u32 deadInstructionsRemoved = 0;
    u32 copiesPropagated = 0;
    u32 trivialPhisRemoved = 0;
};

/// Removes pure SSA definitions whose values are unused and propagates copies.
/// Side-effecting operations remain even when they have no SSA destination.
Status simplifySsa(SsaFunction* function, SsaSimplifyStats* stats = nullptr);

}  // namespace mint
