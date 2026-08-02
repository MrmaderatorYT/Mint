#include "mint/analysis/cfg.h"

#include <algorithm>
#include <unordered_set>

#include "mint/analysis/code_map.h"

namespace mint {

const char* edgeKindName(EdgeKind kind) {
    switch (kind) {
        case EdgeKind::kFallthrough: return "fallthrough";
        case EdgeKind::kTaken: return "taken";
        case EdgeKind::kNotTaken: return "not-taken";
        case EdgeKind::kJump: return "jump";
        case EdgeKind::kResolvedIndirect: return "resolved-indirect";
    }
    return "?";
}

u32 ControlFlowGraph::blockAt(Address addr) const {
    auto it = blockByStart_.find(addr);
    return it == blockByStart_.end() ? kNoBlock : it->second;
}

void ControlFlowGraph::addEdge(u32 from, u32 to, EdgeKind kind) {
    if (from >= blocks_.size() || to >= blocks_.size()) return;
    // Duplicate edges arise legitimately — a conditional branch whose target is
    // also its fall-through — but the decompiler wants one edge per successor
    // with the more specific kind, so collapse them.
    for (CfgEdge& edge : blocks_[from].successors) {
        if (edge.target == to) return;
    }
    blocks_[from].successors.push_back(CfgEdge{to, kind});
}

void ControlFlowGraph::computePredecessors() {
    for (BasicBlock& block : blocks_) block.predecessors.clear();
    for (const BasicBlock& block : blocks_) {
        for (const CfgEdge& edge : block.successors) {
            if (edge.target < blocks_.size()) {
                blocks_[edge.target].predecessors.push_back(block.id);
            }
        }
    }
}

ControlFlowGraph ControlFlowGraph::build(const CodeMap& code,
                                        std::vector<Address> addresses,
                                        Address entryAddress,
                                        const std::vector<ResolvedIndirectJump>&
                                            resolvedIndirects) {
    ControlFlowGraph cfg;
    if (addresses.empty()) return cfg;

    std::sort(addresses.begin(), addresses.end());
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());

    const std::unordered_set<Address> owned(addresses.begin(), addresses.end());

    // A leader starts a basic block. Three things make an address a leader: it is
    // the function entry, it is branched to, or it follows an instruction that
    // ends a block.
    //
    // Calls are not leaders. A call returns to the following instruction, so
    // splitting there would double the block count for no structural gain — the
    // decompiler treats a call as an expression, not a control transfer.
    std::unordered_set<Address> leaders;
    leaders.insert(entryAddress);
    for (const ResolvedIndirectJump& recovered : resolvedIndirects) {
        for (Address target : recovered.targets) {
            if (owned.count(target) != 0) leaders.insert(target);
        }
    }

    for (Address addr : addresses) {
        const InsnRecord* insn = code.find(addr);
        if (insn == nullptr) continue;

        if (terminatesBlock(insn->flow)) {
            if (fallsThrough(insn->flow) && owned.count(insn->next()) != 0) {
                leaders.insert(insn->next());
            }
            // An unconditional branch's fall-through is not reachable, but the
            // address after it still starts a block if anything else reaches it —
            // which the branch-target pass below decides.
            if (!fallsThrough(insn->flow) && owned.count(insn->next()) != 0) {
                leaders.insert(insn->next());
            }
        }
        if (insn->hasKnownTarget() && owned.count(insn->target) != 0 &&
            (insn->flow == FlowKind::kJump || insn->flow == FlowKind::kCondJump)) {
            leaders.insert(insn->target);
        }
    }

    // Walk the sorted addresses, closing a block whenever the next address is a
    // leader or the current instruction ends one.
    for (size_t i = 0; i < addresses.size();) {
        const Address start = addresses[i];
        const InsnRecord* first = code.find(start);
        if (first == nullptr) {
            ++i;
            continue;
        }

        BasicBlock block;
        block.id = static_cast<u32>(cfg.blocks_.size());
        block.start = start;
        block.firstInsn = static_cast<u32>(code.lowerBound(start));

        size_t j = i;
        const InsnRecord* last = first;
        while (j < addresses.size()) {
            const InsnRecord* insn = code.find(addresses[j]);
            if (insn == nullptr) break;
            last = insn;
            ++j;

            if (terminatesBlock(insn->flow)) break;
            // Stop before the next leader, and also stop if the instruction
            // stream is not contiguous — a gap means the bytes between were never
            // decoded, so they are not part of this block.
            if (j < addresses.size() &&
                (leaders.count(addresses[j]) != 0 || addresses[j] != insn->next())) {
                break;
            }
        }

        block.insnCount = static_cast<u32>(j - i);
        block.end = last->next();
        block.terminator = last->flow;
        cfg.blockByStart_[start] = block.id;
        cfg.blocks_.push_back(std::move(block));
        i = j;
    }

    cfg.entry_ = cfg.blockAt(entryAddress);
    if (cfg.entry_ == kNoBlock && !cfg.blocks_.empty()) cfg.entry_ = 0;

    // Now that every block exists, wire the edges.
    for (BasicBlock& block : cfg.blocks_) {
        // The terminating instruction is the last one in the block.
        const InsnRecord* last = nullptr;
        if (block.insnCount > 0) {
            const size_t index = block.firstInsn + block.insnCount - 1;
            if (index < code.instructions().size()) {
                last = &code.instructions()[index];
            }
        }
        if (last == nullptr) continue;

        const u32 from = block.id;
        switch (last->flow) {
            case FlowKind::kCondJump: {
                const u32 taken = last->hasKnownTarget() ? cfg.blockAt(last->target)
                                                         : kNoBlock;
                const u32 notTaken = cfg.blockAt(last->next());
                if (taken != kNoBlock) cfg.addEdge(from, taken, EdgeKind::kTaken);
                if (notTaken != kNoBlock) {
                    cfg.addEdge(from, notTaken, EdgeKind::kNotTaken);
                }
                break;
            }
            case FlowKind::kJump: {
                if (last->hasKnownTarget()) {
                    const u32 target = cfg.blockAt(last->target);
                    if (target != kNoBlock) cfg.addEdge(from, target, EdgeKind::kJump);
                }
                break;
            }
            case FlowKind::kNormal:
            case FlowKind::kCall:
            case FlowKind::kIndirectCall: {
                const u32 next = cfg.blockAt(last->next());
                if (next != kNoBlock) cfg.addEdge(from, next, EdgeKind::kFallthrough);
                break;
            }
            case FlowKind::kIndirectJump: {
                for (const ResolvedIndirectJump& recovered : resolvedIndirects) {
                    if (recovered.branch != last->address) continue;
                    for (Address address : recovered.targets) {
                        const u32 target = cfg.blockAt(address);
                        if (target != kNoBlock) {
                            cfg.addEdge(from, target, EdgeKind::kResolvedIndirect);
                        }
                    }
                    break;
                }
                break;
            }
            case FlowKind::kReturn:
            case FlowKind::kTrap:
            case FlowKind::kInvalid:
                // No statically known successor. Indirect jumps get their edges
                // later, once a jump table is recovered or the dispatcher is
                // emulated.
                break;
        }
    }

    cfg.computePredecessors();
    return cfg;
}

size_t ControlFlowGraph::edgeCount() const {
    size_t total = 0;
    for (const BasicBlock& block : blocks_) total += block.successors.size();
    return total;
}

std::vector<u32> ControlFlowGraph::exitBlocks() const {
    std::vector<u32> exits;
    for (const BasicBlock& block : blocks_) {
        if (block.successors.empty()) exits.push_back(block.id);
    }
    return exits;
}

}  // namespace mint
