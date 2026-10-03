#pragma once

#include <functional>
#include <ostream>
#include <string>
#include <vector>

#include "mint/base/status.h"
#include "mint/analysis/cfg.h"
#include "mint/ssa/ssa_function.h"

namespace mint {
constexpr u32 kNoAstNode = ~u32(0);
enum class ControlFlowAstKind { kSequence, kBlock, kIf, kLoop, kSwitch, kEdge, kBreak, kContinue, kGoto, kFallback };
struct AstCondition { u32 block = kNoBlock; SsaId value = kNoValue; bool negated = false; };
struct AstSwitchArm { Address targetAddress = 0; u32 target = kNoBlock, body = kNoAstNode; };
struct ControlFlowAstNode {
    ControlFlowAstKind kind = ControlFlowAstKind::kSequence;
    u32 block = kNoBlock, from = kNoBlock, target = kNoBlock;
    AstCondition condition;
    std::vector<u32> children;
    std::vector<AstSwitchArm> arms;
    std::vector<u32> loopBlocks, latches;
    bool postTest = false;
};
struct ControlFlowAst {
    u32 root = kNoAstNode;
    std::vector<ControlFlowAstNode> nodes;
    std::vector<u32> blockOwner; // Every original block owns exactly one kBlock.
    std::vector<std::string> diagnostics;
    bool structured = false;
    size_t ifCount = 0, loopCount = 0, switchCount = 0;
};

// Dominance/postdominance-proven, single-entry, disjoint regions. Original block
// statements are never hoisted, duplicated, or reordered within a block. Every
// real edge retains a kEdge for parallel phi copies. Header instructions execute
// inside while(true), on every iteration. Conditions are not merged into &&/||:
// such a transformation additionally requires purity and edge-copy proofs.
// Irreducible, overlapping or unproven regions fall back to exact labelled CFG.
// Fatal invalid input never changes the output. Resource limits are explicit.
Status buildControlFlowAst(const SsaFunction&, ControlFlowAst* out);

struct ControlFlowAstCallbacks {
    // Emit instructions in original order, except branch/conditional/indirect
    // branch terminators. Keep returns/stores/calls/intrinsics and materialized
    // loads/assignments. The renderer writes the original label first.
    std::function<void(u32)> block;
    std::function<void(u32, u32)> edge; // Existing parallel phi-copy emitter.
    std::function<std::string(u32)> condition; // Original terminator use[0].
    std::function<std::string(u32)> indirectTarget;
    std::function<std::string(u32)> label;
};
// A switch dispatches the computed *target address*, with actual block-address
// cases, not invented source-language case values. Unmatched targets stay
// unresolved. Loop exits use the original exit label, so nested switch breaks
// cannot accidentally break the switch instead of the loop.
Status emitControlFlowAst(const ControlFlowAst&, std::ostream&, const ControlFlowAstCallbacks&);
std::string controlFlowAstText(const ControlFlowAst&);
}  // namespace mint
