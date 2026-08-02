#pragma once

#include <vector>

#include "mint/base/status.h"
#include "mint/analysis/cfg.h"
#include "mint/ir/ir_function.h"
#include "mint/loader/elf_image.h"

namespace mint {

struct JumpTable {
    u32 block = kNoBlock;
    Address table = 0;
    u32 entryWidth = 8;
    std::vector<Address> targets;
};

struct JumpTableRecovery {
    u32 indirectJumps = 0;
    u32 recoveredJumps = 0;
    std::vector<JumpTable> tables;
};

Status recoverJumpTables(const ElfImage& image, const IrFunction& function,
                         JumpTableRecovery* result);

/// Counts recovered target edges already represented by the IR CFG. Early
/// machine-level recovery adds these before lifting; late IR recovery adds only
/// the remainder through augmentIrCfg().
u32 recoveredIrCfgEdges(const IrFunction& function,
                        const JumpTableRecovery& recovery);

/// Adds recovered edges to an IR CFG and rebuilds predecessor lists. This is
/// intentionally separate from discovery so callers may display candidates
/// without mutating their cached function.
u32 augmentIrCfg(IrFunction* function, const JumpTableRecovery& recovery);

}  // namespace mint
