#include "mint/analysis/jump_table_recovery.h"

#include <algorithm>
#include <limits>

namespace mint {
namespace {

bool findDefinition(const std::vector<IrInsn>& insns, u32 before,
                    const Varnode& node, u32* index) {
    if (!node.valid() || node.isConstant()) return false;
    before = std::min<u32>(before, static_cast<u32>(insns.size()));
    for (u32 i = before; i > 0; --i) {
        if (insns[i - 1].dest == node) {
            *index = i - 1;
            return true;
        }
    }
    return false;
}

bool resolveConstant(const std::vector<IrInsn>& insns, u32 before,
                     const Varnode& node, Address* value, u32 depth = 0) {
    if (depth > 32) return false;
    if (node.isConstant()) { *value = node.offset; return true; }
    u32 index = 0;
    if (!findDefinition(insns, before, node, &index)) return false;
    const IrInsn& insn = insns[index];
    if (insn.op == MintOp::kCopy || insn.op == MintOp::kZeroExt ||
        insn.op == MintOp::kSignExt || insn.op == MintOp::kTrunc) {
        return resolveConstant(insns, index, insn.a, value, depth + 1);
    }
    if (insn.op == MintOp::kAdd || insn.op == MintOp::kSub) {
        Address left = 0;
        Address right = 0;
        if (resolveConstant(insns, index, insn.a, &left, depth + 1) &&
            resolveConstant(insns, index, insn.b, &right, depth + 1)) {
            *value = insn.op == MintOp::kAdd ? left + right : left - right;
            return true;
        }
    }
    return false;
}

bool splitBaseAndDynamic(const std::vector<IrInsn>& insns, u32 before,
                         const Varnode& node, Address* base, Varnode* dynamic,
                         u32* definition, u32 depth = 0) {
    if (depth > 32) return false;
    u32 index = 0;
    if (!findDefinition(insns, before, node, &index)) return false;
    const IrInsn& insn = insns[index];
    if (insn.op == MintOp::kCopy || insn.op == MintOp::kZeroExt ||
        insn.op == MintOp::kSignExt || insn.op == MintOp::kTrunc) {
        return splitBaseAndDynamic(
            insns, index, insn.a, base, dynamic, definition, depth + 1);
    }
    if (insn.op != MintOp::kAdd) return false;

    if (resolveConstant(insns, index, insn.a, base)) {
        *dynamic = insn.b;
        *definition = index;
        return true;
    }
    if (resolveConstant(insns, index, insn.b, base)) {
        *dynamic = insn.a;
        *definition = index;
        return true;
    }
    return false;
}

bool peelToLoad(const std::vector<IrInsn>& insns, u32 before, Varnode node,
                const IrInsn** load, u64* scale, bool* signedEntry,
                u32 depth = 0) {
    if (depth > 32) return false;
    u32 index = 0;
    if (!findDefinition(insns, before, node, &index)) return false;
    const IrInsn& insn = insns[index];
    if (insn.op == MintOp::kLoad) {
        *load = &insn;
        return true;
    }
    if (insn.op == MintOp::kCopy || insn.op == MintOp::kZeroExt ||
        insn.op == MintOp::kSignExt || insn.op == MintOp::kTrunc) {
        if (insn.op == MintOp::kSignExt) *signedEntry = true;
        return peelToLoad(
            insns, index, insn.a, load, scale, signedEntry, depth + 1);
    }
    if (insn.op == MintOp::kShl && insn.b.isConstant() &&
        insn.b.offset < 63) {
        const u64 factor = u64(1) << insn.b.offset;
        if (*scale > std::numeric_limits<u64>::max() / factor) return false;
        *scale *= factor;
        return peelToLoad(
            insns, index, insn.a, load, scale, signedEntry, depth + 1);
    }
    return false;
}

bool peelIndex(const std::vector<IrInsn>& insns, u32 before, Varnode node,
               Varnode* indexNode, u32 depth = 0) {
    if (depth > 32) return false;
    // Keep the architectural register view used by the range check. Following
    // x12 back through its defining zext would turn it into a temporary, while
    // the preceding CMP reads w12; those are the same storage but not the same
    // temporary definition.
    if (node.isRegister()) {
        *indexNode = node;
        return true;
    }
    u32 index = 0;
    if (!findDefinition(insns, before, node, &index)) {
        *indexNode = node;
        return node.valid();
    }
    const IrInsn& insn = insns[index];
    if (insn.op == MintOp::kCopy || insn.op == MintOp::kZeroExt ||
        insn.op == MintOp::kSignExt || insn.op == MintOp::kTrunc) {
        return peelIndex(insns, index, insn.a, indexNode, depth + 1);
    }
    if (insn.op == MintOp::kShl && insn.b.isConstant()) {
        return peelIndex(insns, index, insn.a, indexNode, depth + 1);
    }
    *indexNode = node;
    return true;
}

bool sameStorage(const Varnode& a, const Varnode& b) {
    if (a == b) return true;
    return a.isRegister() && b.isRegister() && a.overlaps(b);
}

u32 guardedEntryCount(const IrFunction& function, u32 before,
                      const Varnode& indexNode) {
    before = std::min<u32>(before, static_cast<u32>(function.insns.size()));
    for (u32 i = before; i > 0; --i) {
        const IrInsn& insn = function.insns[i - 1];
        if (insn.op != MintOp::kSub) continue;
        if (sameStorage(insn.a, indexNode) && insn.b.isConstant() &&
            insn.b.offset < 256) {
            return static_cast<u32>(insn.b.offset + 1);
        }
    }
    return 0;
}

bool targetInFunction(const IrFunction& function, Address target) {
    for (const IrBlock& block : function.blocks) {
        if (target >= block.start && target < block.end) return true;
    }
    return false;
}

bool readUnsigned(const MemoryMap& memory, Address address, u32 width, u64* out) {
    *out = 0;
    return width != 0 && width <= sizeof(*out) &&
           memory.read(address, out, width);
}

i64 signExtend(u64 value, u32 width) {
    if (width == 0 || width >= 8) return static_cast<i64>(value);
    const unsigned bits = width * 8;
    const u64 sign = u64(1) << (bits - 1);
    const u64 mask = (u64(1) << bits) - 1;
    value &= mask;
    return static_cast<i64>((value ^ sign) - sign);
}

bool recoverRelativeTable(const ElfImage& image, const IrFunction& function,
                          u32 terminatorIndex, const Varnode& target,
                          JumpTable* table) {
    Address targetBase = 0;
    Varnode targetDynamic;
    u32 targetDefinition = 0;
    if (!splitBaseAndDynamic(function.insns, terminatorIndex, target,
                             &targetBase, &targetDynamic, &targetDefinition)) {
        return false;
    }

    const IrInsn* load = nullptr;
    u64 targetScale = 1;
    bool signedEntry = false;
    if (!peelToLoad(function.insns, targetDefinition, targetDynamic,
                    &load, &targetScale, &signedEntry) ||
        load == nullptr || load->dest.size == 0 || load->dest.size > 8) {
        return false;
    }

    Address tableBase = 0;
    Varnode tableDynamic;
    u32 tableDefinition = 0;
    u32 loadIndex = static_cast<u32>(load - function.insns.data());
    if (!splitBaseAndDynamic(function.insns, loadIndex, load->a,
                             &tableBase, &tableDynamic, &tableDefinition)) {
        return false;
    }
    Varnode indexNode;
    if (!peelIndex(function.insns, tableDefinition, tableDynamic, &indexNode)) {
        return false;
    }
    const u32 count = guardedEntryCount(function, terminatorIndex, indexNode);
    if (count < 2 || count > 256) return false;

    table->table = tableBase;
    table->entryWidth = load->dest.size;
    for (u32 index = 0; index < count; ++index) {
        u64 raw = 0;
        const Address slot = tableBase + u64(index) * table->entryWidth;
        if (!readUnsigned(image.memory(), slot, table->entryWidth, &raw)) {
            return false;
        }
        const i64 entry = signedEntry ? signExtend(raw, table->entryWidth)
                                      : static_cast<i64>(raw);
        const Address recovered = static_cast<Address>(
            static_cast<i64>(targetBase) + entry * static_cast<i64>(targetScale));
        if (!image.memory().isExecutable(recovered) ||
            !targetInFunction(function, recovered)) {
            return false;
        }
        if (std::find(table->targets.begin(), table->targets.end(), recovered) ==
            table->targets.end()) {
            table->targets.push_back(recovered);
        }
    }
    return table->targets.size() >= 2;
}

}  // namespace

Status recoverJumpTables(const ElfImage& image, const IrFunction& function,
                         JumpTableRecovery* result) {
    if (!result) return Status::error(ErrorCode::kInternalError, "null jump-table result");
    *result = {};
    for (const IrBlock& block : function.blocks) {
        if (!block.insnCount) continue;
        const IrInsn& terminator = function.insns[block.firstInsn + block.insnCount - 1];
        if (terminator.op != MintOp::kBranchInd) continue;
        ++result->indirectJumps;
        const u32 terminatorIndex =
            block.firstInsn + block.insnCount - 1;

        JumpTable table;
        table.block = block.id;
        if (recoverRelativeTable(
                image, function, terminatorIndex, terminator.a, &table)) {
            ++result->recoveredJumps;
            result->tables.push_back(std::move(table));
            continue;
        }

        Address tableAddress = 0;
        if (!resolveConstant(function.insns, terminatorIndex,
                             terminator.a, &tableAddress)) continue;
        // A direct constant branch is not a jump table. The useful pattern is a
        // load whose address expression resolved to a read-only table; the final
        // value is recovered below by trying the candidate as a table start.
        table = {};
        table.block = block.id;
        table.table = tableAddress;
        for (u32 index = 0; index < 256; ++index) {
            Address target = 0;
            const Address slot = tableAddress + index * table.entryWidth;
            bool pointerRead = image.resolvePointer(slot, &target) || image.memory().readInt(slot, &target);
            if (!pointerRead || !image.memory().isExecutable(target)) {
                // Compilers often use signed 32-bit offsets in read-only jump
                // tables, especially for PIEs where an absolute pointer would
                // need a relocation per case.
                i32 relative = 0;
                if (!image.memory().readInt(tableAddress + index * 4, &relative)) break;
                const Address relativeTarget = tableAddress + static_cast<i64>(relative);
                if (!image.memory().isExecutable(relativeTarget)) break;
                target = relativeTarget;
                table.entryWidth = 4;
            }
            if (!image.memory().isExecutable(target) ||
                !targetInFunction(function, target)) break;
            if (std::find(table.targets.begin(), table.targets.end(), target) == table.targets.end()) table.targets.push_back(target);
        }
        if (table.targets.size() >= 2) {
            ++result->recoveredJumps;
            result->tables.push_back(std::move(table));
        }
    }
    return Status::success();
}

u32 recoveredIrCfgEdges(const IrFunction& function,
                        const JumpTableRecovery& recovery) {
    u32 represented = 0;
    for (const JumpTable& table : recovery.tables) {
        if (table.block >= function.blocks.size()) continue;
        const IrBlock& source = function.blocks[table.block];
        for (Address target : table.targets) {
            u32 targetId = kNoBlock;
            for (const IrBlock& candidate : function.blocks) {
                if (target >= candidate.start && target < candidate.end) {
                    targetId = candidate.id;
                    break;
                }
            }
            if (targetId != kNoBlock &&
                std::find(source.successors.begin(), source.successors.end(),
                          targetId) != source.successors.end()) {
                ++represented;
            }
        }
    }
    return represented;
}

u32 augmentIrCfg(IrFunction* function, const JumpTableRecovery& recovery) {
    if (!function) return 0;
    u32 added = 0;
    for (const JumpTable& table : recovery.tables) {
        IrBlock* block = table.block < function->blocks.size() ? &function->blocks[table.block] : nullptr;
        if (!block) continue;
        for (Address target : table.targets) {
            u32 targetId = ~u32(0);
            for (const IrBlock& candidate : function->blocks) {
                if (candidate.start == target ||
                    (target >= candidate.start && target < candidate.end)) {
                    targetId = candidate.id;
                    break;
                }
            }
            if (targetId == ~u32(0) || std::find(block->successors.begin(), block->successors.end(), targetId) != block->successors.end()) continue;
            block->successors.push_back(targetId);
            ++added;
        }
    }
    for (IrBlock& block : function->blocks) block.predecessors.clear();
    for (const IrBlock& block : function->blocks) for (u32 target : block.successors) if (target < function->blocks.size()) function->blocks[target].predecessors.push_back(block.id);
    return added;
}

}  // namespace mint
