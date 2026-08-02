#include "mint/ir/dominance.h"

#include <algorithm>

namespace mint {
namespace {

/// Iterative postorder, so that a function with a few thousand blocks in a chain
/// cannot overflow the stack. Obfuscated code reaches those shapes routinely, and a
/// recursive walk here would turn a hostile input into a crash.
std::vector<u32> postorder(const std::vector<std::vector<u32>>& graph) {
    const size_t count = graph.size();
    std::vector<u32> order;
    if (count == 0) return order;

    std::vector<u8> state(count, 0);  // 0 = new, 1 = on stack, 2 = emitted
    std::vector<std::pair<u32, size_t>> stack;  // block, next successor to try
    stack.push_back({0, 0});
    state[0] = 1;

    while (!stack.empty()) {
        auto& [block, next] = stack.back();
        const std::vector<u32>& successors = graph[block];
        if (next < successors.size()) {
            const u32 successor = successors[next++];
            if (successor < count && state[successor] == 0) {
                state[successor] = 1;
                stack.push_back({successor, 0});
            }
            continue;
        }
        state[block] = 2;
        order.push_back(block);
        stack.pop_back();
    }
    return order;
}

}  // namespace

bool Dominance::dominates(u32 a, u32 b) const {
    if (!reachable(a) || !reachable(b)) return false;
    while (b != idom[b]) {
        if (b == a) return true;
        b = idom[b];
    }
    return b == a;
}

Dominance computeDominance(const IrFunction& function) {
    std::vector<std::vector<u32>> graph(function.blocks.size());
    for (size_t i = 0; i < function.blocks.size(); ++i) {
        graph[i] = function.blocks[i].successors;
    }
    return computeDominance(graph);
}

Dominance computeDominance(const std::vector<std::vector<u32>>& graph) {
    Dominance result;
    const size_t count = graph.size();
    result.rpoIndex.assign(count, Dominance::kUnreachable);
    result.idom.assign(count, Dominance::kUnreachable);
    result.children.assign(count, {});
    result.frontier.assign(count, {});
    result.predecessors.assign(count, {});
    if (count == 0) return result;

    for (u32 block = 0; block < count; ++block) {
        for (u32 successor : graph[block]) {
            if (successor < count) result.predecessors[successor].push_back(block);
        }
    }

    result.rpo = postorder(graph);
    std::reverse(result.rpo.begin(), result.rpo.end());
    for (size_t i = 0; i < result.rpo.size(); ++i) {
        result.rpoIndex[result.rpo[i]] = static_cast<u32>(i);
    }

    // Cooper, Harvey and Kennedy: walk in reverse postorder repeatedly, setting each
    // block's dominator to the meet of its already-processed predecessors, until
    // nothing changes. Chosen over Lengauer-Tarjan because it is a page of code
    // instead of several and converges in two or three passes on real control flow,
    // and dominance is not where this tool spends its time.
    const u32 entry = result.rpo.empty() ? 0 : result.rpo.front();
    result.idom[entry] = entry;

    auto meet = [&](u32 a, u32 b) {
        // Climb the partially built tree in lockstep by reverse-postorder number
        // until both sides land on the same block.
        while (a != b) {
            while (result.rpoIndex[a] > result.rpoIndex[b]) a = result.idom[a];
            while (result.rpoIndex[b] > result.rpoIndex[a]) b = result.idom[b];
        }
        return a;
    };

    bool changed = true;
    while (changed) {
        changed = false;
        for (u32 block : result.rpo) {
            if (block == entry) continue;
            u32 candidate = Dominance::kUnreachable;
            for (u32 predecessor : result.predecessors[block]) {
                if (result.idom[predecessor] == Dominance::kUnreachable) continue;
                candidate = candidate == Dominance::kUnreachable
                                ? predecessor
                                : meet(predecessor, candidate);
            }
            if (candidate != Dominance::kUnreachable && result.idom[block] != candidate) {
                result.idom[block] = candidate;
                changed = true;
            }
        }
    }

    for (u32 block : result.rpo) {
        if (block != entry && result.idom[block] != Dominance::kUnreachable) {
            result.children[result.idom[block]].push_back(block);
        }
    }

    // A block sits on the frontier of everything from its predecessor up to, but not
    // including, its own dominator: those are precisely the blocks that reach it
    // without dominating it, which is where a value defined in them stops being the
    // only definition that can arrive.
    for (u32 block : result.rpo) {
        if (result.predecessors[block].size() < 2) continue;
        for (u32 predecessor : result.predecessors[block]) {
            if (!result.reachable(predecessor)) continue;
            u32 runner = predecessor;
            while (runner != result.idom[block] && runner != Dominance::kUnreachable) {
                std::vector<u32>& into = result.frontier[runner];
                if (std::find(into.begin(), into.end(), block) == into.end()) {
                    into.push_back(block);
                }
                const u32 next = result.idom[runner];
                if (next == runner) break;  // reached the entry
                runner = next;
            }
        }
    }

    return result;
}

}  // namespace mint
