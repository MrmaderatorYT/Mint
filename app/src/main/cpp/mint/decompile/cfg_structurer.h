#pragma once

#include <vector>

#include "mint/ir/dominance.h"
#include "mint/ssa/ssa_function.h"

namespace mint {

struct NaturalLoop {
    u32 header = 0;
    u32 latch = 0;
    std::vector<u32> body;
    std::vector<u32> exits;
};

struct ControlFlowStructure {
    Dominance dominance;
    std::vector<NaturalLoop> loops;
    std::vector<u32> switchBlocks;
};

/// Finds natural loops and switch-like blocks without pretending irreducible
/// graphs are structured. The emitter can fall back to labelled blocks for those
/// regions while still presenting all real edges to the reader.
ControlFlowStructure structureControlFlow(const SsaFunction& function);

}  // namespace mint
