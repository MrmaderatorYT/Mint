#include "mint/ssa/ssa_builder.h"

#include <algorithm>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "mint/ir/dominance.h"
#include "mint/ir/registers.h"
#include "mint/ir/storage.h"

namespace mint {
namespace {

struct VarKey {
    Space space = Space::kInvalid;
    u64 offset = 0;
    u8 size = 0;

    bool operator==(const VarKey& other) const {
        return space == other.space && offset == other.offset && size == other.size;
    }
};

struct VarKeyHash {
    size_t operator()(const VarKey& key) const {
        size_t result = static_cast<size_t>(key.space);
        result = result * 1315423911u + static_cast<size_t>(key.offset);
        result = result * 1315423911u + key.size;
        return result;
    }
};

struct ConstantKey {
    u64 value = 0;
    u8 size = 0;

    bool operator==(const ConstantKey& other) const {
        return value == other.value && size == other.size;
    }
};

struct ConstantKeyHash {
    size_t operator()(const ConstantKey& key) const {
        return static_cast<size_t>(key.value ^ (key.value >> 32) ^
                                   (u64(key.size) * 0x9e3779b9u));
    }
};

/// The register a value is returned in, or an invalid varnode when the convention
/// for this architecture is not modelled.
Varnode resultRegister(Arch arch) {
    switch (arch) {
        case Arch::kAArch64: return Varnode::reg(arm64::kXn(0), 8);
        case Arch::kX86_64: return Varnode::reg(x86::kRax, 8);
        default: return Varnode::invalid();
    }
}

/// The register units a call destroys, as whole storage units.
///
/// Calling conventions are modelled here rather than in the lifter on purpose. A
/// `bl` as an *instruction* writes the link register and nothing else; that a callee
/// also flattens x0..x17 is a property of the platform's convention, not of the
/// encoding. Keeping it out of the lifter means the lifter stays a faithful model of
/// the machine, and means a function with a hand-written or non-standard convention
/// can later be given its own clobber set without the IR having to be re-lifted.
///
/// The list errs towards clobbering. Believing a register survives when the callee
/// destroyed it produces a silently wrong dependency; believing it was destroyed
/// when it survived costs one redundant value and nothing else. Only the direction
/// that cannot produce a wrong answer is acceptable as a default.
std::vector<Varnode> callerSavedUnits(Arch arch) {
    std::vector<Varnode> units;
    if (arch == Arch::kAArch64) {
        // x0..x18: arguments, results and scratch, plus the platform register, which
        // Android's runtime is free to use. x19..x28 are callee-saved and survive.
        for (unsigned n = 0; n <= 18; ++n) units.push_back(Varnode::reg(arm64::kXn(n), 8));
        units.push_back(Varnode::reg(arm64::kXn(30), 8));  // the link register itself
        units.push_back(Varnode::reg(arm64::kFlagN, 1));
        units.push_back(Varnode::reg(arm64::kFlagZ, 1));
        units.push_back(Varnode::reg(arm64::kFlagC, 1));
        units.push_back(Varnode::reg(arm64::kFlagV, 1));
        for (unsigned n = 0; n < 32; ++n) units.push_back(Varnode::reg(arm64::kVn(n), 16));
        return units;
    }
    if (arch == Arch::kX86_64) {
        for (u64 offset : {x86::kRax, x86::kRcx, x86::kRdx, x86::kRsi, x86::kRdi,
                           x86::kGpr(8), x86::kGpr(9), x86::kGpr(10), x86::kGpr(11)}) {
            units.push_back(Varnode::reg(offset, 8));
        }
        for (u64 offset : {x86::kFlagCf, x86::kFlagPf, x86::kFlagAf, x86::kFlagZf,
                           x86::kFlagSf, x86::kFlagOf}) {
            units.push_back(Varnode::reg(offset, 1));
        }
        for (unsigned n = 0; n < 16; ++n) units.push_back(Varnode::reg(x86::kXmmN(n), 16));
        return units;
    }
    return units;
}

bool isCall(MintOp op) { return op == MintOp::kCall || op == MintOp::kCallInd; }

class Builder {
public:
    Builder(const IrFunction& input, SsaFunction* output, SsaBuildStats* stats)
        : input_(input), output_(output), stats_(stats) {}

    Status run();

private:
    const IrFunction& input_;
    SsaFunction* output_;
    SsaBuildStats localStats_;
    SsaBuildStats* stats_ = nullptr;

    Dominance dominance_;
    std::vector<u32> variableForBlock_;
    std::vector<VarKey> variables_;
    std::unordered_map<VarKey, u32, VarKeyHash> variableIds_;
    std::vector<std::unordered_set<u32>> defBlocks_;
    std::vector<std::vector<u32>> phiVariables_;
    std::vector<std::vector<SsaId>> stacks_;
    std::unordered_map<VarKey, SsaId, VarKeyHash> entryValues_;
    std::unordered_map<ConstantKey, SsaId, ConstantKeyHash> constants_;
    /// Variable indices a call destroys — only those the function mentions at all.
    std::vector<u32> callerSaved_;
    /// Per block, whether each variable is live on entry. Phis go only where a
    /// variable is live, which is what keeps the form from filling up with phis for
    /// values nobody reads.
    std::vector<std::vector<u8>> liveIn_;

    SsaBuildStats* statsOut();
    u32 variableFor(const Varnode& node, bool create);
    Status validateInput() const;
    SsaId newValue(const Varnode& storage, SsaDef def, u32 defIndex);
    SsaId constant(const Varnode& node);
    SsaId entryValue(u32 variable);
    SsaId currentValue(u32 variable, bool temporaryRead);
    SsaId read(const Varnode& node);
    void collectCallClobbers();
    void computeVariableLiveness();
    void placePhis();
    void materializePhis();
    void renameBlock(u32 block, std::vector<u8>* visited);
    void fillPhiArgument(u32 from, u32 successor, u32 edgeOrdinal);
    void simplifyAliases();
    void recalculateUses();

    SsaId findAlias(SsaId id, std::vector<SsaId>* parent) const;
};

SsaBuildStats* Builder::statsOut() { return stats_ != nullptr ? stats_ : &localStats_; }

Status Builder::validateInput() const {
    const std::vector<std::string> problems = input_.verify();
    if (!problems.empty()) {
        return Status::error(ErrorCode::kBadFormat,
                             "cannot build SSA from invalid IR: " + problems.front());
    }
    for (const IrInsn& insn : input_.insns) {
        auto check = [&](const Varnode& node) -> bool {
            if (!node.valid() || !node.isRegister()) return true;
            return accessIsWholeUnit(input_.arch, node.offset, node.size);
        };
        if (!check(insn.dest) || !check(insn.a) || !check(insn.b) || !check(insn.c)) {
            return Status::error(
                ErrorCode::kBadFormat,
                "register access is not a whole storage unit; normalize before SSA");
        }
    }
    return Status::success();
}

u32 Builder::variableFor(const Varnode& node, bool create) {
    if (!node.valid() || node.isConstant()) return Dominance::kUnreachable;
    const VarKey key{node.space, node.offset, node.size};
    auto found = variableIds_.find(key);
    if (found != variableIds_.end()) return found->second;
    if (!create) return Dominance::kUnreachable;
    const u32 id = static_cast<u32>(variables_.size());
    variables_.push_back(key);
    variableIds_.emplace(key, id);
    defBlocks_.emplace_back();
    phiVariables_.resize(input_.blocks.size());
    stacks_.resize(variables_.size());
    return id;
}

SsaId Builder::newValue(const Varnode& storage, SsaDef def, u32 defIndex) {
    SsaValue value;
    value.storage = storage;
    value.def = def;
    value.defIndex = defIndex;
    output_->values.push_back(value);
    return static_cast<SsaId>(output_->values.size() - 1);
}

SsaId Builder::constant(const Varnode& node) {
    const ConstantKey key{node.offset, node.size};
    const auto found = constants_.find(key);
    if (found != constants_.end()) return found->second;
    const SsaId id = newValue(node, SsaDef::kConstant, 0);
    constants_.emplace(key, id);
    return id;
}

SsaId Builder::entryValue(u32 variable) {
    const VarKey& key = variables_[variable];
    const auto found = entryValues_.find(key);
    if (found != entryValues_.end()) return found->second;
    const Varnode storage{key.space, key.size, key.offset};
    const SsaId id = newValue(storage, SsaDef::kEntry, 0);
    entryValues_.emplace(key, id);
    ++statsOut()->entryValues;
    return id;
}

SsaId Builder::currentValue(u32 variable, bool temporaryRead) {
    if (!stacks_[variable].empty()) return stacks_[variable].back();
    if (temporaryRead) ++statsOut()->undefinedTempReads;
    return entryValue(variable);
}

SsaId Builder::read(const Varnode& node) {
    if (!node.valid()) return kNoValue;
    if (node.isConstant()) return constant(node);
    const u32 variable = variableFor(node, true);
    return currentValue(variable, node.isTemp());
}

void Builder::collectCallClobbers() {
    // Only registers the function already mentions are worth clobbering: a register
    // never read or written anywhere has no variable, and inventing one would place
    // phis for a value nothing can observe.
    for (const Varnode& unit : callerSavedUnits(input_.arch)) {
        const VarKey key{unit.space, unit.offset, unit.size};
        const auto found = variableIds_.find(key);
        if (found != variableIds_.end()) callerSaved_.push_back(found->second);
    }
    if (callerSaved_.empty()) return;

    // A call defines these, so phi placement has to see the definition. Missing this
    // would leave a stale value reaching a join, which is the same wrong answer the
    // clobbers exist to prevent.
    for (const IrBlock& block : input_.blocks) {
        for (u32 i = 0; i < block.insnCount; ++i) {
            if (!isCall(input_.insns[block.firstInsn + i].op)) continue;
            for (u32 variable : callerSaved_) defBlocks_[variable].insert(block.id);
            break;
        }
    }
}

void Builder::computeVariableLiveness() {
    const size_t blockCount = input_.blocks.size();
    const size_t variableCount = variables_.size();
    liveIn_.assign(blockCount, std::vector<u8>(variableCount, 0));
    std::vector<std::vector<u8>> upwardExposed(blockCount, std::vector<u8>(variableCount, 0));
    std::vector<std::vector<u8>> killed(blockCount, std::vector<u8>(variableCount, 0));

    for (size_t b = 0; b < blockCount; ++b) {
        const IrBlock& block = input_.blocks[b];
        for (u32 i = 0; i < block.insnCount; ++i) {
            const IrInsn& insn = input_.insns[block.firstInsn + i];
            for (unsigned slot = 0; slot < 3; ++slot) {
                const Varnode& source = insn.source(slot);
                if (!source.valid() || source.isConstant()) continue;
                const u32 variable = variableFor(source, false);
                // Read before this block wrote it, so it must arrive from outside.
                if (variable != Dominance::kUnreachable && !killed[b][variable]) {
                    upwardExposed[b][variable] = 1;
                }
            }
            if (insn.op == MintOp::kReturn) {
                // A return reads the result register even though the instruction's
                // own operand is the link register. Without this the register looks
                // dead in the epilogue, pruned placement drops the phi that merges
                // the values the branches computed, and the function is reported as
                // returning nothing at all.
                const Varnode result = resultRegister(input_.arch);
                const u32 variable =
                    result.valid() ? variableFor(result, false) : Dominance::kUnreachable;
                if (variable != Dominance::kUnreachable && !killed[b][variable]) {
                    upwardExposed[b][variable] = 1;
                }
            }
            if (isCall(insn.op)) {
                for (u32 variable : callerSaved_) killed[b][variable] = 1;
            }
            if (insn.dest.valid() && !insn.dest.isConstant()) {
                const u32 variable = variableFor(insn.dest, false);
                if (variable != Dominance::kUnreachable) killed[b][variable] = 1;
            }
        }
    }

    // Backward fixed point. Reverse postorder reversed is close enough to optimal
    // ordering that this settles in a couple of rounds on real control flow.
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto it = dominance_.rpo.rbegin(); it != dominance_.rpo.rend(); ++it) {
            const u32 b = *it;
            std::vector<u8> out(variableCount, 0);
            for (u32 successor : input_.blocks[b].successors) {
                if (successor >= blockCount) continue;
                for (size_t v = 0; v < variableCount; ++v) {
                    if (liveIn_[successor][v]) out[v] = 1;
                }
            }
            for (size_t v = 0; v < variableCount; ++v) {
                const u8 live = upwardExposed[b][v] || (out[v] && !killed[b][v]);
                if (live && !liveIn_[b][v]) {
                    liveIn_[b][v] = 1;
                    changed = true;
                }
            }
        }
    }
}

void Builder::placePhis() {
    phiVariables_.assign(input_.blocks.size(), {});
    for (u32 variable = 0; variable < variables_.size(); ++variable) {
        std::vector<u32> worklist(defBlocks_[variable].begin(), defBlocks_[variable].end());
        std::sort(worklist.begin(), worklist.end());
        std::unordered_set<u32> inWorklist(worklist.begin(), worklist.end());
        std::unordered_set<u32> hasPhi;

        while (!worklist.empty()) {
            const u32 block = worklist.back();
            worklist.pop_back();
            for (u32 frontier : dominance_.frontier[block]) {
                // Pruned SSA: without this test the textbook placement puts a phi at
                // every frontier of every definition, including for temporaries that
                // never outlive the machine instruction that made them. On a real
                // library that was 422k phis, nearly all of them joining values no
                // instruction ever reads.
                if (frontier < liveIn_.size() && variable < liveIn_[frontier].size() &&
                    liveIn_[frontier][variable] == 0) {
                    continue;
                }
                if (!hasPhi.insert(frontier).second) continue;
                phiVariables_[frontier].push_back(variable);
                ++statsOut()->phisInserted;
                if (defBlocks_[variable].find(frontier) == defBlocks_[variable].end() &&
                    inWorklist.insert(frontier).second) {
                    worklist.push_back(frontier);
                }
            }
        }
    }
    for (std::vector<u32>& variables : phiVariables_) {
        std::sort(variables.begin(), variables.end());
    }
}

void Builder::materializePhis() {
    for (u32 block = 0; block < phiVariables_.size(); ++block) {
        for (u32 variable : phiVariables_[block]) {
            const VarKey& key = variables_[variable];
            const Varnode storage{key.space, key.size, key.offset};
            const u32 phiIndex = static_cast<u32>(output_->phis.size());
            SsaPhi phi;
            phi.block = block;
            phi.args.assign(dominance_.predecessors[block].size(), kNoValue);
            phi.dest = newValue(storage, SsaDef::kPhi, phiIndex);
            output_->phis.push_back(std::move(phi));
            output_->blocks[block].phis.push_back(phiIndex);
        }
    }
}

void Builder::fillPhiArgument(u32 from, u32 successor, u32 edgeOrdinal) {
    if (successor >= output_->blocks.size()) return;
    const std::vector<u32>& predecessors = dominance_.predecessors[successor];
    size_t occurrence = 0;
    size_t slot = predecessors.size();
    for (size_t i = 0; i < predecessors.size(); ++i) {
        if (predecessors[i] != from) continue;
        if (occurrence++ == edgeOrdinal) {
            slot = i;
            break;
        }
    }
    if (slot >= predecessors.size()) return;

    for (u32 phiIndex : output_->blocks[successor].phis) {
        SsaPhi& phi = output_->phis[phiIndex];
        if (slot >= phi.args.size() || phi.dest >= output_->values.size()) continue;
        const VarKey key{phi.dest == kNoValue ? Space::kInvalid
                                               : output_->values[phi.dest].storage.space,
                         phi.dest == kNoValue ? 0 : output_->values[phi.dest].storage.offset,
                         static_cast<u8>(phi.dest == kNoValue
                                             ? 0
                                             : output_->values[phi.dest].storage.size)};
        const auto variable = variableIds_.find(key);
        if (variable == variableIds_.end()) continue;
        phi.args[slot] = currentValue(variable->second, key.space == Space::kTemp);
    }
}

void Builder::renameBlock(u32 block, std::vector<u8>* visited) {
    if (block >= input_.blocks.size() || (*visited)[block] != 0) return;
    (*visited)[block] = 1;

    std::vector<size_t> stackSizes(stacks_.size());
    for (size_t i = 0; i < stacks_.size(); ++i) stackSizes[i] = stacks_[i].size();

    for (u32 variable : phiVariables_[block]) {
        // Phis are materialized for every block before renaming starts. This is
        // important for a DFS order: a predecessor can fill the incoming edge of
        // a successor before the successor itself is visited.
        const VarKey& key = variables_[variable];
        for (u32 phiIndex : output_->blocks[block].phis) {
            const SsaPhi& phi = output_->phis[phiIndex];
            if (phi.dest == kNoValue || phi.dest >= output_->values.size()) continue;
            const Varnode& storage = output_->values[phi.dest].storage;
            if (storage.space == key.space && storage.offset == key.offset &&
                storage.size == key.size) {
                stacks_[variable].push_back(phi.dest);
                break;
            }
        }
    }

    const IrBlock& inputBlock = input_.blocks[block];
    SsaBlock& outputBlock = output_->blocks[block];
    outputBlock.firstInsn = static_cast<u32>(output_->insns.size());
    for (u32 i = 0; i < inputBlock.insnCount; ++i) {
        const IrInsn& inputInsn = input_.insns[inputBlock.firstInsn + i];
        SsaInsn insn;
        insn.op = inputInsn.op;
        insn.address = inputInsn.address;
        insn.intrinsicId = inputInsn.intrinsicId;
        insn.laneWidth = inputInsn.laneWidth;
        insn.block = block;
        for (unsigned slot = 0; slot < 3; ++slot) {
            const SsaId use = read(inputInsn.source(slot));
            insn.use[slot] = use;
            if (use != kNoValue) ++output_->values[use].uses;
        }
        const u32 instructionIndex = static_cast<u32>(output_->insns.size());
        if (inputInsn.dest.valid() && !inputInsn.dest.isConstant()) {
            const u32 variable = variableFor(inputInsn.dest, true);
            const SsaId dest = newValue(inputInsn.dest, SsaDef::kInsn, instructionIndex);
            insn.dest = dest;
            stacks_[variable].push_back(dest);
        }
        if (insn.op == MintOp::kReturn) {
            const Varnode result = resultRegister(input_.arch);
            const u32 variable =
                result.valid() ? variableFor(result, false) : Dominance::kUnreachable;
            if (variable != Dominance::kUnreachable) {
                const SsaId value = currentValue(variable, false);
                output_->returnValues.push_back({instructionIndex, value});
                ++output_->values[value].uses;
            }
        }
        if (isCall(insn.op)) {
            for (u32 variable : callerSaved_) {
                const VarKey& key = variables_[variable];
                const Varnode storage{key.space, key.size, key.offset};
                const SsaId value = newValue(storage, SsaDef::kInsn, instructionIndex);
                insn.clobbers.push_back(value);
                stacks_[variable].push_back(value);
            }
        }
        output_->insns.push_back(insn);
    }
    outputBlock.insnCount = static_cast<u32>(output_->insns.size()) - outputBlock.firstInsn;

    for (size_t edge = 0; edge < inputBlock.successors.size(); ++edge) {
        const u32 successor = inputBlock.successors[edge];
        if (successor >= input_.blocks.size()) continue;
        size_t occurrence = 0;
        for (size_t prior = 0; prior < edge; ++prior) {
            if (inputBlock.successors[prior] == successor) ++occurrence;
        }
        fillPhiArgument(block, successor, static_cast<u32>(occurrence));
    }

    for (u32 child : dominance_.children[block]) renameBlock(child, visited);
    for (size_t i = 0; i < stacks_.size(); ++i) stacks_[i].resize(stackSizes[i]);
}

SsaId Builder::findAlias(SsaId id, std::vector<SsaId>* parent) const {
    if (id == kNoValue || id >= parent->size()) return id;
    SsaId root = id;
    while ((*parent)[root] != root) root = (*parent)[root];
    while ((*parent)[id] != id) {
        const SsaId next = (*parent)[id];
        (*parent)[id] = root;
        id = next;
    }
    return root;
}

void Builder::simplifyAliases() {
    std::vector<SsaId> parent(output_->values.size());
    for (SsaId i = 0; i < parent.size(); ++i) parent[i] = i;

    // A copy is a pure name change in SSA. It is safe to remove even when the
    // destination is a register: the machine-level partial-register semantics
    // have already been made explicit by normalizeRegisterAccesses().
    for (SsaInsn& insn : output_->insns) {
        if (insn.op != MintOp::kCopy || insn.dest == kNoValue || insn.use[0] == kNoValue) {
            continue;
        }
        parent[insn.dest] = findAlias(insn.use[0], &parent);
        insn.dead = true;
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (SsaPhi& phi : output_->phis) {
            if (phi.dead || phi.dest == kNoValue) continue;
            SsaId replacement = kNoValue;
            bool allSame = true;
            for (SsaId arg : phi.args) {
                if (arg == kNoValue) {
                    allSame = false;
                    break;
                }
                const SsaId canonical = findAlias(arg, &parent);
                if (canonical == phi.dest) continue;
                if (replacement == kNoValue) replacement = canonical;
                if (replacement != canonical) {
                    allSame = false;
                    break;
                }
            }
            if (allSame && replacement != kNoValue) {
                parent[phi.dest] = findAlias(replacement, &parent);
                phi.dead = true;
                ++statsOut()->trivialPhisRemoved;
                changed = true;
            }
        }
    }

    for (SsaInsn& insn : output_->insns) {
        for (SsaId& use : insn.use) use = findAlias(use, &parent);
    }
    for (SsaPhi& phi : output_->phis) {
        for (SsaId& arg : phi.args) arg = findAlias(arg, &parent);
    }
}

void Builder::recalculateUses() {
    for (SsaValue& value : output_->values) value.uses = 0;
    for (const SsaInsn& insn : output_->insns) {
        for (SsaId use : insn.use) {
            if (use != kNoValue && use < output_->values.size()) ++output_->values[use].uses;
        }
    }
    for (const SsaPhi& phi : output_->phis) {
        for (SsaId arg : phi.args) {
            if (arg != kNoValue && arg < output_->values.size()) ++output_->values[arg].uses;
        }
    }
    // A returned value is a use even though no instruction operand names it: the
    // caller reads it. Leaving it out here would undo the record the builder kept and
    // let dead-code elimination delete the definition the function exists to produce.
    for (const auto& entry : output_->returnValues) {
        if (entry.second != kNoValue && entry.second < output_->values.size()) {
            ++output_->values[entry.second].uses;
        }
    }
}

Status Builder::run() {
    if (output_ == nullptr) {
        return Status::error(ErrorCode::kInternalError, "no SSA output");
    }
    *output_ = SsaFunction();
    if (stats_ != nullptr) *stats_ = {};
    const Status inputStatus = validateInput();
    if (!inputStatus.ok()) return inputStatus;

    output_->entry = input_.entry;
    output_->name = input_.name;
    output_->arch = input_.arch;
    output_->machineInsnCount = input_.machineInsnCount;
    output_->intrinsicCount = input_.intrinsicCount;
    output_->blocks.resize(input_.blocks.size());

    for (size_t i = 0; i < input_.blocks.size(); ++i) {
        const IrBlock& inBlock = input_.blocks[i];
        SsaBlock& outBlock = output_->blocks[i];
        outBlock.id = static_cast<u32>(i);
        outBlock.start = inBlock.start;
        outBlock.end = inBlock.end;
        outBlock.successors = inBlock.successors;
    }
    std::vector<std::vector<u32>> graph(input_.blocks.size());
    for (size_t i = 0; i < input_.blocks.size(); ++i) graph[i] = input_.blocks[i].successors;
    dominance_ = computeDominance(graph);
    for (size_t i = 0; i < output_->blocks.size(); ++i) {
        output_->blocks[i].predecessors = dominance_.predecessors[i];
    }

    for (const IrBlock& block : input_.blocks) {
        for (u32 i = 0; i < block.insnCount; ++i) {
            const IrInsn& insn = input_.insns[block.firstInsn + i];
            if (insn.dest.valid() && !insn.dest.isConstant()) {
                const u32 variable = variableFor(insn.dest, true);
                defBlocks_[variable].insert(block.id);
            }
            for (unsigned slot = 0; slot < 3; ++slot) {
                if (insn.source(slot).valid() && !insn.source(slot).isConstant()) {
                    variableFor(insn.source(slot), true);
                }
            }
        }
    }
    collectCallClobbers();
    computeVariableLiveness();
    statsOut()->variables = static_cast<u32>(variables_.size());
    placePhis();
    materializePhis();

    std::vector<u8> visited(input_.blocks.size(), 0);
    if (!dominance_.rpo.empty()) renameBlock(dominance_.rpo.front(), &visited);
    for (u32 block = 0; block < input_.blocks.size(); ++block) {
        if (!visited[block]) renameBlock(block, &visited);
    }
    simplifyAliases();
    recalculateUses();
    statsOut()->values = static_cast<u32>(output_->values.size());
    return Status::success();
}

}  // namespace

Status buildSsa(const IrFunction& function, SsaFunction* out, SsaBuildStats* stats) {
    Builder builder(function, out, stats);
    return builder.run();
}

}  // namespace mint
