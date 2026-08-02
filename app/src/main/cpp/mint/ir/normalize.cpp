#include "mint/ir/normalize.h"

#include <vector>

#include "mint/ir/storage.h"

namespace mint {
namespace {

u64 lowMask(unsigned bits) {
    if (bits == 0) return 0;
    if (bits >= 64) return ~u64(0);
    return (u64(1) << bits) - 1;
}

/// Rebuilds a function one instruction at a time, letting each original instruction
/// expand into several.
///
/// Block boundaries are recomputed from the expansion rather than adjusted in place,
/// because the invariant the verifier checks — that blocks tile the instruction list
/// exactly — is easy to preserve by construction and fiddly to patch after the fact.
class Normalizer {
public:
    explicit Normalizer(IrFunction* function) : in_(function) {}

    NormalizeStats run();

private:
    IrFunction* in_;
    std::vector<IrInsn> out_;
    NormalizeStats stats_;
    Address address_ = 0;

    Varnode newTemp(u8 size) { return Varnode::temp(in_->tempCount++, size); }

    void emit(MintOp op, const Varnode& dest, const Varnode& a,
              const Varnode& b = Varnode::invalid()) {
        IrInsn insn;
        insn.op = op;
        insn.dest = dest;
        insn.a = a;
        insn.b = b;
        insn.address = address_;
        out_.push_back(insn);
        ++stats_.opsAdded;
    }

    bool needsWork(const Varnode& node) const {
        if (!node.isRegister()) return false;
        return !accessIsWholeUnit(in_->arch, node.offset, node.size);
    }

    /// Reads a narrow register field by reading its whole unit and cutting the field
    /// out of it.
    Varnode extract(const Varnode& node) {
        const StorageUnit unit = canonicalUnit(in_->arch, node);
        if (accessSpansUnits(in_->arch, node.offset, node.size)) {
            ++stats_.unnormalized;
            return node;
        }
        const Varnode whole = Varnode::reg(unit.offset, unit.size);
        Varnode value = whole;
        const unsigned shift = static_cast<unsigned>(node.offset - unit.offset) * 8;
        if (shift != 0) {
            // The shift count is a constant of its own width, which the verifier
            // permits precisely because a shift amount is a count and not a value in
            // the same domain as the operand.
            Varnode shifted = newTemp(unit.size);
            emit(MintOp::kShrU, shifted, value, Varnode::constant(shift, 1));
            value = shifted;
        }
        if (node.size < unit.size) {
            Varnode narrowed = newTemp(node.size);
            emit(MintOp::kTrunc, narrowed, value);
            value = narrowed;
        }
        ++stats_.narrowReads;
        return value;
    }

    /// Splices a narrow value back into its unit, preserving the bytes around it.
    void insert(const Varnode& field, const Varnode& value) {
        const StorageUnit unit = canonicalUnit(in_->arch, field);
        if (accessSpansUnits(in_->arch, field.offset, field.size)) {
            ++stats_.unnormalized;
            emit(MintOp::kCopy, field, value);
            return;
        }
        const Varnode whole = Varnode::reg(unit.offset, unit.size);
        const unsigned shift = static_cast<unsigned>(field.offset - unit.offset) * 8;

        // A unit wider than eight bytes cannot be masked, because a mask would have
        // to be a constant wider than the 64 bits a varnode's value field holds.
        // AArch64 makes that harmless: writing a scalar floating-point register
        // zeroes the rest of the vector register, exactly as writing a W register
        // zeroes the top of an X register, so the write is a zero-extension and no
        // mask is needed. Anywhere else it would be a real gap, so it is counted
        // rather than guessed at.
        if (unit.size > 8) {
            if (in_->arch == Arch::kAArch64 && shift == 0) {
                emit(MintOp::kZeroExt, whole, value);
                ++stats_.zeroingWrites;
                return;
            }
            ++stats_.unnormalized;
            emit(MintOp::kCopy, field, value);
            return;
        }

        Varnode widened = value;
        if (value.size < unit.size) {
            widened = newTemp(unit.size);
            emit(MintOp::kZeroExt, widened, value);
        }
        if (shift != 0) {
            Varnode shifted = newTemp(unit.size);
            emit(MintOp::kShl, shifted, widened, Varnode::constant(shift, 1));
            widened = shifted;
        }
        const u64 fieldMask = lowMask(unsigned(field.size) * 8) << shift;
        const u64 keepMask = ~fieldMask & lowMask(unsigned(unit.size) * 8);
        Varnode kept = newTemp(unit.size);
        emit(MintOp::kAnd, kept, whole, Varnode::constant(keepMask, unit.size));
        emit(MintOp::kOr, whole, kept, widened);
        ++stats_.narrowWrites;
    }
};

NormalizeStats Normalizer::run() {
    // Walking by block rather than over the flat list would drop anything the blocks
    // do not cover, so the one case that is not safe to rewrite this way is a
    // function with no blocks at all.
    if (in_->blocks.empty()) return stats_;

    out_.reserve(in_->insns.size());
    std::vector<u32> blockStart(in_->blocks.size(), 0);
    std::vector<u32> blockCount(in_->blocks.size(), 0);

    for (size_t bi = 0; bi < in_->blocks.size(); ++bi) {
        const IrBlock& block = in_->blocks[bi];
        blockStart[bi] = static_cast<u32>(out_.size());
        for (u32 j = 0; j < block.insnCount; ++j) {
            IrInsn insn = in_->insns[block.firstInsn + j];
            address_ = insn.address;

            for (unsigned slot = 0; slot < 3; ++slot) {
                Varnode& operand = slot == 0 ? insn.a : (slot == 1 ? insn.b : insn.c);
                if (needsWork(operand)) operand = extract(operand);
            }

            // An insert has to follow the instruction that produced the value, and
            // nothing may follow a terminator, so a partial destination on one is
            // left alone. No opcode in the IR both terminates a block and writes a
            // register, so this is a guard against a future opcode rather than a
            // case that arises today.
            const Varnode originalDest = insn.dest;
            const bool splitDest = needsWork(originalDest) && !isTerminator(insn.op);
            if (splitDest) insn.dest = newTemp(originalDest.size);
            if (needsWork(originalDest) && !splitDest) ++stats_.unnormalized;

            out_.push_back(insn);
            if (splitDest) insert(originalDest, insn.dest);
        }
        blockCount[bi] = static_cast<u32>(out_.size()) - blockStart[bi];
    }

    for (size_t bi = 0; bi < in_->blocks.size(); ++bi) {
        in_->blocks[bi].firstInsn = blockStart[bi];
        in_->blocks[bi].insnCount = blockCount[bi];
    }
    in_->insns = std::move(out_);
    return stats_;
}

}  // namespace

NormalizeStats normalizeRegisterAccesses(IrFunction* function) {
    if (function == nullptr) return {};
    Normalizer normalizer(function);
    return normalizer.run();
}

}  // namespace mint
