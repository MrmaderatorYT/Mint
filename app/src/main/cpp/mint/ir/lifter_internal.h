#pragma once

// Internal seam between the shared lifter plumbing and the per-architecture
// front-ends. Includes Capstone, so nothing above the IR may include this.

#include <capstone/capstone.h>

#include "mint/ir/ir_function.h"

namespace mint {

/// Lifts one decoded AArch64 instruction. Emits kIntrinsic when the instruction
/// has no modelling yet, so the caller never has to check whether anything
/// happened.
void liftAArch64(const cs_insn& insn, IrBuilder& builder);

/// Lifts one decoded x86-64 instruction, with the same contract.
void liftX86(const cs_insn& insn, IrBuilder& builder);
void liftArm32(const cs_insn& insn, IrBuilder& builder, bool thumb);
void liftRiscV(const cs_insn& insn, IrBuilder& builder, bool rv64);

}  // namespace mint
