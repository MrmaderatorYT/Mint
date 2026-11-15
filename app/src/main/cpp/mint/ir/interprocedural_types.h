#pragma once

#include "mint/ir/type_recovery.h"
#include "mint/ir/memory_analysis.h"
#include "mint/analysis/abi_model.h"

namespace mint {
struct InterproceduralTypeOptions {
    size_t maxFunctions=64, maxDepth=16, maxFields=64, maxIterations=64, maxWork=2000000;
    std::function<UserPrototype(Address)> prototypes;
    AbiTypeResolver typeLayouts;
};
// Fresh, bounded hypotheses from verified local AArch64/AAPCS64 direct calls.
// No authoritative declarations, object identity, alias or memory-effect proofs
// are synthesized. Unknown inputs are skipped; failed SCCs export no evidence.
Status recoverInterproceduralTypes(const SsaFunction& function,TypeRecovery* output,
    const MemoryAnalysis* memory,const MemoryFunctionResolver& functions,
    const InterproceduralTypeOptions& options={});
}
