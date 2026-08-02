#include "mint/obfuscation/ollvm_unroll.h"

#include <queue>

namespace mint {

OllvmUnrollResult unrollOllvm(IrFunction* function) {
    OllvmUnrollResult result;
    if (!function || function->blocks.empty()) return result;
    std::vector<bool> reachable(function->blocks.size(), false);
    std::queue<u32> work;
    work.push(0);
    while (!work.empty()) {
        const u32 id = work.front(); work.pop();
        if (id >= reachable.size() || reachable[id]) continue;
        reachable[id] = true;
        for (u32 succ : function->blocks[id].successors) work.push(succ);
    }
    for (IrBlock& block : function->blocks) {
        if (block.successors.size() >= 4) ++result.dispatcherBlocks;
        if (!reachable[block.id]) { ++result.unreachableBlocks; result.removedBlocks.push_back(block.id); }
    }
    // Keep block indices stable for cached IR. Consumers can skip removed ids and
    // the caller may rebuild a compact function when it is safe to invalidate UI
    // references; this pass therefore never corrupts range indexes in-place.
    return result;
}

}  // namespace mint
