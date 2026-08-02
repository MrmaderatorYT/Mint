#pragma once

#include "mint/base/status.h"
#include "mint/ir/ir_function.h"
#include "mint/ssa/ssa_function.h"

namespace mint {

struct SsaBuildStats {
    u32 variables = 0;
    u32 phisInserted = 0;
    /// Phis whose arguments all turned out to be the same value. These are pure
    /// bookkeeping and are removed; counting them is how the cost of the placement
    /// algorithm stays visible, since a large number here means phis are being put
    /// where they are not needed.
    u32 trivialPhisRemoved = 0;
    u32 entryValues = 0;
    /// Reads of a temporary that no earlier instruction wrote. A lifter that produces
    /// these has a bug — a temporary is created and consumed within one machine
    /// instruction — so this should be zero and is worth reporting when it is not.
    u32 undefinedTempReads = 0;
    u32 values = 0;
};

/// Builds SSA form from lifted IR.
///
/// `function` must already have been through normalizeRegisterAccesses: this expects
/// every register operand to name a whole storage unit, because renaming overlapping
/// windows independently would produce a form where a write through one is invisible
/// to a read through another.
Status buildSsa(const IrFunction& function, SsaFunction* out,
                SsaBuildStats* stats = nullptr);

}  // namespace mint
