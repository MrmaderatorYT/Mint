#pragma once

#include "mint/ir/memory_analysis.h"

namespace mint {
struct TailCallStateProof {
    bool complete=false;
    std::string reason;
};
struct TailCallAnalysisOptions {
    size_t maxValues=32768,maxInstructions=8192,maxBlocks=512,maxLinks=262144,
           maxWork=2000000;
};
// Machine-frame contract only for a terminal direct x86-64 branch/tail call in
// verified normalized SSA. All paths reaching the site must retain entry RSP,
// the original eight-byte return slot and RBX/RBP/R12-R15. Exact reaching-store
// evidence may prove stack spill/reload restoration; it never folds a load or
// strengthens alias evidence. Unknown effects, possible return-slot aliases,
// divergent states and exhausted budgets do not establish a complete proof.
// Callers independently validate target identity, current machine bytes and
// authoritative SysV prototypes/argument/result layouts before typed emission.
// Malformed/unsupported input leaves output unchanged; an ordinary failed
// proof returns success with complete=false and an explanatory reason.
Status proveX86SysvTailState(const SsaFunction& function,u32 branchInsn,
    const MemoryAnalysis* memory,TailCallStateProof* output,
    const TailCallAnalysisOptions& options={});
}
