#pragma once

#include <vector>

#include "mint/base/types.h"
#include "mint/ir/ir_function.h"

namespace mint {

/// Dominator tree and dominance frontiers for one lifted function.
///
/// Everything downstream needs this: SSA places its phi nodes on the frontier, loop
/// detection finds a back edge by asking whether the target dominates the source,
/// and control-flow structuring emits an `if` only where the join point is dominated
/// by the test. Computing it once and sharing it keeps those three from each
/// growing their own half-correct version.
struct Dominance {
    static constexpr u32 kUnreachable = ~0u;

    /// Blocks in reverse postorder from the entry. Iterating an analysis in this
    /// order means a block is visited after every predecessor that can reach it
    /// other than through a back edge, which is what makes the fixed point converge
    /// in a couple of passes rather than one pass per block.
    std::vector<u32> rpo;
    /// Block id to its position in `rpo`, or kUnreachable.
    std::vector<u32> rpoIndex;
    /// Immediate dominator per block. The entry is its own; unreachable blocks are
    /// kUnreachable.
    std::vector<u32> idom;
    /// Dominator-tree children, so a caller can walk the tree without inverting
    /// idom itself.
    std::vector<std::vector<u32>> children;
    /// Dominance frontier per block: the blocks this one dominates a predecessor of
    /// but does not itself dominate.
    std::vector<std::vector<u32>> frontier;
    /// Predecessors, recomputed from the successor lists rather than read from the
    /// block records. The lifter is not required to fill them in, and a dominator
    /// computation that silently believed an empty predecessor list would report
    /// every block as unreachable.
    std::vector<std::vector<u32>> predecessors;

    bool reachable(u32 block) const {
        return block < rpoIndex.size() && rpoIndex[block] != kUnreachable;
    }

    /// True when `a` dominates `b`, by walking up from `b`. Fine for the occasional
    /// query; a caller testing this in a loop over all pairs wants depth numbers
    /// instead.
    bool dominates(u32 a, u32 b) const;
};

/// Works from a bare successor list so that the same computation serves the machine
/// IR and the SSA form, which have different block types but the same graph.
Dominance computeDominance(const std::vector<std::vector<u32>>& successors);

Dominance computeDominance(const IrFunction& function);

}  // namespace mint
