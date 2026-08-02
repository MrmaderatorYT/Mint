#pragma once

#include <unordered_map>
#include <vector>

#include "mint/base/types.h"
#include "mint/disasm/instruction.h"

namespace mint {

class CodeMap;

/// Invalid block id. Blocks are referenced by index, so a sentinel is needed for
/// "no such block".
constexpr u32 kNoBlock = ~static_cast<u32>(0);

enum class EdgeKind : u8 {
    /// Control reaches the next block because the previous one ran off its end.
    kFallthrough = 0,
    /// The taken side of a conditional branch.
    kTaken,
    /// The not-taken side of a conditional branch. Distinguished from
    /// kFallthrough because the decompiler has to know which side a condition
    /// guards in order to emit the right sense of an `if`.
    kNotTaken,
    /// An unconditional branch.
    kJump,
    /// A resolved indirect branch — a recovered jump-table entry, or a target
    /// proved by emulating an OLLVM dispatcher. Kept distinct so the UI can show
    /// which edges were recovered rather than read directly.
    kResolvedIndirect,
};

const char* edgeKindName(EdgeKind kind);

struct CfgEdge {
    u32 target = kNoBlock;
    EdgeKind kind = EdgeKind::kFallthrough;
};

/// Targets recovered while recursive descent was still building the function.
/// Keeping the branch address lets CFG construction mark every target as a leader
/// and attach the edges after block IDs are known.
struct ResolvedIndirectJump {
    Address branch = 0;
    std::vector<Address> targets;
};

struct BasicBlock {
    u32 id = kNoBlock;
    Address start = 0;
    /// One past the last byte of the last instruction.
    Address end = 0;

    /// Index into CodeMap::instructions() of this block's first instruction, and
    /// how many follow. Blocks do not own their instructions; the code map does.
    u32 firstInsn = 0;
    u32 insnCount = 0;

    FlowKind terminator = FlowKind::kNormal;

    std::vector<CfgEdge> successors;
    std::vector<u32> predecessors;

    bool contains(Address addr) const { return addr >= start && addr < end; }
};

/// The control-flow graph of one function.
///
/// Blocks are stored in ascending address order, which makes the common
/// "render the function" and "walk in address order" cases trivial, and is also
/// the order the dominator computation wants as a starting point.
class ControlFlowGraph {
public:
    const std::vector<BasicBlock>& blocks() const { return blocks_; }
    std::vector<BasicBlock>& mutableBlocks() { return blocks_; }
    size_t size() const { return blocks_.size(); }
    bool empty() const { return blocks_.empty(); }

    u32 entry() const { return entry_; }
    void setEntry(u32 id) { entry_ = id; }

    const BasicBlock* block(u32 id) const {
        return id < blocks_.size() ? &blocks_[id] : nullptr;
    }
    /// The block starting exactly at `addr`.
    u32 blockAt(Address addr) const;

    /// Builds the graph for the instructions listed in `addresses`, which must all
    /// be present in `code`. `entryAddress` becomes the entry block.
    ///
    /// `addresses` is taken by value and sorted: a function's instruction list
    /// arrives in discovery order, which is depth-first and not useful here.
    static ControlFlowGraph build(const CodeMap& code, std::vector<Address> addresses,
                                  Address entryAddress,
                                  const std::vector<ResolvedIndirectJump>&
                                      resolvedIndirects = {});

    /// Number of edges, for reporting and for the flattening heuristic — an
    /// OLLVM-flattened function has an unusually high edge-to-block ratio
    /// concentrated on one dispatcher block.
    size_t edgeCount() const;

    /// Blocks with no successors. A function with none is either an infinite loop
    /// or a failed analysis.
    std::vector<u32> exitBlocks() const;

private:
    void addEdge(u32 from, u32 to, EdgeKind kind);
    void computePredecessors();

    std::vector<BasicBlock> blocks_;
    std::unordered_map<Address, u32> blockByStart_;
    u32 entry_ = kNoBlock;
};

}  // namespace mint
