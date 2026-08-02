#include "mint/decompile/cfg_structurer.h"

#include <algorithm>
#include <set>

namespace mint {

ControlFlowStructure structureControlFlow(const SsaFunction& function) {
    ControlFlowStructure out;
    std::vector<std::vector<u32>> successors(function.blocks.size());
    for (const SsaBlock& block : function.blocks) successors[block.id] = block.successors;
    out.dominance = computeDominance(successors);
    for (const SsaBlock& block : function.blocks) {
        if (block.successors.size() > 2) out.switchBlocks.push_back(block.id);
        for (u32 target : block.successors) {
            if (target >= out.dominance.idom.size() || !out.dominance.dominates(target, block.id)) continue;
            std::set<u32> body{target, block.id};
            std::vector<u32> work{block.id};
            while (!work.empty()) {
                const u32 node = work.back(); work.pop_back();
                if (node >= out.dominance.predecessors.size()) continue;
                for (u32 pred : out.dominance.predecessors[node]) {
                    if (body.insert(pred).second && pred != target) work.push_back(pred);
                }
            }
            NaturalLoop loop;
            loop.header = target;
            loop.latch = block.id;
            loop.body.assign(body.begin(), body.end());
            for (u32 member : loop.body) {
                for (u32 succ : successors[member]) {
                    if (!body.count(succ)) loop.exits.push_back(succ);
                }
            }
            std::sort(loop.exits.begin(), loop.exits.end());
            loop.exits.erase(std::unique(loop.exits.begin(), loop.exits.end()), loop.exits.end());
            out.loops.push_back(std::move(loop));
        }
    }
    return out;
}

}  // namespace mint
