#include "mint/ssa/ssa_function.h"

#include <algorithm>
#include <cstdio>
#include <unordered_map>

#include "mint/ir/dominance.h"

namespace mint {
namespace {

std::string formatAddress(Address address) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx",
                  static_cast<unsigned long long>(address));
    return buffer;
}

bool isDefinition(SsaDef def) {
    return def == SsaDef::kInsn || def == SsaDef::kPhi;
}

bool dominatesValue(const SsaFunction& function, const Dominance& dominance,
                    SsaId id, u32 useBlock, u32 useInsn, u32 edgeBlock,
                    bool isPhiArgument) {
    if (id == kNoValue || id >= function.values.size()) return false;
    const SsaValue& value = function.values[id];
    if (!isDefinition(value.def)) return true;

    u32 defBlock = Dominance::kUnreachable;
    if (value.def == SsaDef::kInsn) {
        if (value.defIndex >= function.insns.size()) return false;
        defBlock = function.insns[value.defIndex].block;
        if (defBlock >= function.blocks.size()) return false;
        if (!isPhiArgument && defBlock == useBlock && value.defIndex >= useInsn) {
            return false;
        }
    } else {
        if (value.defIndex >= function.phis.size()) return false;
        defBlock = function.phis[value.defIndex].block;
        if (defBlock >= function.blocks.size()) return false;
    }

    const u32 location = isPhiArgument ? edgeBlock : useBlock;
    return dominance.dominates(defBlock, location);
}

}  // namespace

bool hasSideEffect(MintOp op) {
    switch (op) {
        case MintOp::kStore:
        case MintOp::kBranch:
        case MintOp::kCondBranch:
        case MintOp::kBranchInd:
        case MintOp::kCall:
        case MintOp::kCallInd:
        case MintOp::kReturn:
        case MintOp::kIntrinsic:
            return true;
        default:
            return false;
    }
}

u32 SsaFunction::liveInsnCount() const {
    u32 count = 0;
    for (const SsaInsn& insn : insns) {
        if (!insn.dead) ++count;
    }
    return count;
}

u32 SsaFunction::livePhiCount() const {
    u32 count = 0;
    for (const SsaPhi& phi : phis) {
        if (!phi.dead) ++count;
    }
    return count;
}

std::vector<std::string> SsaFunction::verify() const {
    std::vector<std::string> problems;
    auto report = [&](const std::string& message) {
        if (problems.size() < 128) problems.push_back(message);
    };

    std::vector<std::vector<u32>> successors(blocks.size());
    for (size_t i = 0; i < blocks.size(); ++i) {
        successors[i] = blocks[i].successors;
        for (u32 successor : blocks[i].successors) {
            if (successor >= blocks.size()) {
                report("block " + std::to_string(i) +
                       " has out-of-range successor " + std::to_string(successor));
            }
        }
    }
    const Dominance dominance = computeDominance(successors);

    std::vector<u8> covered(insns.size(), 0);
    for (size_t bi = 0; bi < blocks.size(); ++bi) {
        const SsaBlock& block = blocks[bi];
        if (block.id != bi) {
            report("block " + std::to_string(bi) + " has id " +
                   std::to_string(block.id));
        }
        if (u64(block.firstInsn) + block.insnCount > insns.size()) {
            report("block " + std::to_string(bi) + " runs past the instruction list");
            break;
        }
        for (u32 i = 0; i < block.insnCount; ++i) {
            const u32 index = block.firstInsn + i;
            if (covered[index] != 0) {
                report("instruction " + std::to_string(index) + " belongs to multiple blocks");
            }
            covered[index] = 1;
        }
        if (block.predecessors.size() != dominance.predecessors[bi].size()) {
            report("block " + std::to_string(bi) + " predecessor list disagrees with CFG");
        }
        for (u32 phiIndex : block.phis) {
            if (phiIndex >= phis.size()) {
                report("block " + std::to_string(bi) + " has an out-of-range phi");
                continue;
            }
            const SsaPhi& phi = phis[phiIndex];
            if (phi.block != bi || phi.dest == kNoValue || phi.dest >= values.size()) {
                report("phi " + std::to_string(phiIndex) + " has an invalid destination");
            }
            if (phi.args.size() != dominance.predecessors[bi].size()) {
                report("phi " + std::to_string(phiIndex) + " has " +
                       std::to_string(phi.args.size()) + " arguments for " +
                       std::to_string(dominance.predecessors[bi].size()) + " edges");
            }
        }
    }
    for (u32 index = 0; index < covered.size(); ++index) {
        if (covered[index] == 0) {
            report("instruction " + std::to_string(index) + " is not in a block");
        }
    }

    for (size_t i = 0; i < values.size(); ++i) {
        const SsaValue& value = values[i];
        if (!value.storage.valid()) {
            report("value " + std::to_string(i) + " has invalid storage");
        }
        if (value.def == SsaDef::kInsn && value.defIndex >= insns.size()) {
            report("value " + std::to_string(i) + " points past the instruction list");
        }
        if (value.def == SsaDef::kPhi && value.defIndex >= phis.size()) {
            report("value " + std::to_string(i) + " points past the phi list");
        }
    }

    std::vector<u32> observedUses(values.size(), 0);
    // The value handed back at a return is used by the caller, which is off the end
    // of this function and so appears in no operand list. It still has to be counted,
    // or the recorded totals disagree with what is observable here.
    for (const auto& entry : returnValues) {
        if (entry.second != kNoValue && entry.second < observedUses.size()) {
            ++observedUses[entry.second];
        }
    }
    for (size_t index = 0; index < insns.size(); ++index) {
        const SsaInsn& insn = insns[index];
        if (insn.block >= blocks.size()) {
            report("instruction " + std::to_string(index) + " has an invalid block");
        }
        if (insn.dest != kNoValue) {
            if (insn.dest >= values.size()) {
                report("instruction " + std::to_string(index) + " has an invalid destination");
            } else if (values[insn.dest].def != SsaDef::kInsn ||
                       values[insn.dest].defIndex != index) {
                report("instruction " + std::to_string(index) +
                       " destination does not point back to its definition");
            }
        }
        for (unsigned slot = 0; slot < 3; ++slot) {
            const SsaId use = insn.use[slot];
            if (use == kNoValue) continue;
            if (use >= values.size()) {
                report("instruction " + std::to_string(index) + " has an invalid use");
                continue;
            }
            ++observedUses[use];
            if (!dominatesValue(*this, dominance, use, insn.block,
                                static_cast<u32>(index), 0, false)) {
                report("value " + std::to_string(use) + " does not dominate instruction " +
                       std::to_string(index));
            }
        }
    }

    for (size_t pi = 0; pi < phis.size(); ++pi) {
        const SsaPhi& phi = phis[pi];
        if (phi.dest == kNoValue || phi.dest >= values.size()) continue;
        if (values[phi.dest].def != SsaDef::kPhi || values[phi.dest].defIndex != pi) {
            report("phi " + std::to_string(pi) + " destination does not point back");
        }
        const std::vector<u32>& predecessors =
            phi.block < dominance.predecessors.size()
                ? dominance.predecessors[phi.block]
                : std::vector<u32>();
        const size_t count = std::min(phi.args.size(), predecessors.size());
        for (size_t edge = 0; edge < count; ++edge) {
            const SsaId arg = phi.args[edge];
            if (arg == kNoValue) {
                report("phi " + std::to_string(pi) + " has an unset argument");
                continue;
            }
            if (arg >= values.size()) {
                report("phi " + std::to_string(pi) + " has an invalid argument");
                continue;
            }
            ++observedUses[arg];
            if (!dominatesValue(*this, dominance, arg, phi.block, 0,
                                predecessors[edge], true)) {
                report("value " + std::to_string(arg) + " does not dominate phi " +
                       std::to_string(pi) + " incoming edge");
            }
        }
    }

    for (size_t i = 0; i < values.size(); ++i) {
        if (values[i].uses != observedUses[i]) {
            report("value " + std::to_string(i) + " records " +
                   std::to_string(values[i].uses) + " uses, observed " +
                   std::to_string(observedUses[i]));
        }
    }
    return problems;
}

std::string SsaFunction::toText() const {
    std::string out = name.empty() ? formatAddress(entry) : name;
    out += "  (" + std::to_string(machineInsnCount) + " machine insns -> " +
           std::to_string(insns.size()) + " ssa ops)\n";

    auto valueText = [&](SsaId id) {
        if (id == kNoValue || id >= values.size()) return std::string("-");
        const SsaValue& value = values[id];
        return "v" + std::to_string(id) + "=" + describeVarnode(value.storage, arch);
    };
    auto defText = [&](SsaId id) {
        return id == kNoValue ? std::string("-") : valueText(id);
    };

    for (const SsaBlock& block : blocks) {
        char header[128];
        std::snprintf(header, sizeof(header), "  block %u [0x%llx..0x%llx)", block.id,
                      static_cast<unsigned long long>(block.start),
                      static_cast<unsigned long long>(block.end));
        out += header;
        if (!block.successors.empty()) {
            out += " ->";
            for (u32 successor : block.successors) out += " " + std::to_string(successor);
        }
        out += "\n";
        for (u32 phiIndex : block.phis) {
            if (phiIndex >= phis.size()) continue;
            const SsaPhi& phi = phis[phiIndex];
            out += "    ";
            if (phi.dead) out += "dead ";
            out += defText(phi.dest) + " = phi(";
            for (size_t i = 0; i < phi.args.size(); ++i) {
                if (i != 0) out += ", ";
                out += valueText(phi.args[i]);
            }
            out += ")\n";
        }
        for (u32 i = 0; i < block.insnCount; ++i) {
            const u32 index = block.firstInsn + i;
            if (index >= insns.size()) break;
            const SsaInsn& insn = insns[index];
            out += "    ";
            if (insn.dead) out += "dead ";
            if (insn.dest != kNoValue) out += defText(insn.dest) + " = ";
            out += opName(insn.op);
            for (unsigned slot = 0; slot < 3; ++slot) {
                if (insn.use[slot] == kNoValue) break;
                out += slot == 0 ? " " : ", ";
                out += valueText(insn.use[slot]);
            }
            if (insn.op == MintOp::kIntrinsic) {
                out += " #" + std::to_string(insn.intrinsicId);
            }
            out += "\n";
        }
    }
    return out;
}

}  // namespace mint
