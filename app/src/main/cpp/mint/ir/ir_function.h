#pragma once

#include <string>
#include <vector>

#include "mint/base/types.h"
#include "mint/ir/ir_op.h"
#include "mint/ir/varnode.h"

namespace mint {

/// One IR operation.
///
/// Three source slots because kSelect needs three and nothing needs four. Slots
/// past an op's arity are left invalid, and the verifier checks that.
struct IrInsn {
    MintOp op = MintOp::kInvalid;
    Varnode dest;
    Varnode a;
    Varnode b;
    Varnode c;
    /// The machine instruction this came from. Several IR ops share one address,
    /// which is what lets the UI show machine and IR views side by side and lets a
    /// breakpoint on an address mean something.
    Address address = 0;
    /// For kIntrinsic: the Capstone instruction id, so the listing can name what
    /// was not modelled instead of just admitting defeat.
    u16 intrinsicId = 0;

    const Varnode& source(unsigned index) const {
        switch (index) {
            case 0: return a;
            case 1: return b;
            default: return c;
        }
    }
};

/// A straight-line run of IR ops, mirroring one machine basic block.
///
/// IR blocks are deliberately one-to-one with machine blocks. Because no machine
/// instruction lifts to something that branches internally — predication becomes
/// kSelect instead — a machine block never needs splitting, so every CFG pass can
/// be written once and used on either level.
struct IrBlock {
    u32 id = 0;
    Address start = 0;
    Address end = 0;  ///< exclusive
    /// Half-open range into IrFunction::insns.
    u32 firstInsn = 0;
    u32 insnCount = 0;
    std::vector<u32> successors;
    std::vector<u32> predecessors;
};

/// The lifted form of one function.
///
/// **Lifting is per function and on demand, never program-wide.** A large
/// obfuscated library holds a few hundred thousand machine instructions; at the
/// four-to-six IR ops each that real code averages, lifting everything at once
/// would cost tens of megabytes of a phone's heap for data that is only needed for
/// the function currently being decompiled. So this is the unit of work, and
/// whoever holds these is expected to bound how many it keeps.
struct IrFunction {
    Address entry = 0;
    std::string name;
    Arch arch = Arch::kUnknown;

    std::vector<IrInsn> insns;
    std::vector<IrBlock> blocks;

    /// How many temporaries the lifter allocated. An emulator or SSA pass needs
    /// this to size its temporary storage.
    u32 tempCount = 0;

    /// Machine instructions that had to be lifted as kIntrinsic. Kept as a count
    /// rather than inferred, because "how much of this function do we actually
    /// understand" is the first thing to check when a decompilation looks wrong.
    u32 intrinsicCount = 0;
    /// Machine instructions covered, for the same reason.
    u32 machineInsnCount = 0;

    const IrBlock* blockAt(Address address) const;
    /// Structural self-check: operand widths agree, arities match, terminators
    /// only ever appear last in a block, block ranges tile insns exactly. Returns
    /// an empty vector when the function is well formed.
    ///
    /// Worth having as a first-class function rather than a test helper: a lifter
    /// bug produces IR that looks plausible and then poisons every pass above it,
    /// and the cheapest place to catch that is the moment the IR is built.
    std::vector<std::string> verify() const;

    /// The IR listing, for the UI and for diffing lifter output in tests.
    std::string toText() const;
};

/// Accumulates IR ops for one function.
///
/// Lifters talk to this rather than pushing onto the vector directly, so that
/// temporary allocation and the current machine address are handled in one place
/// instead of in every instruction handler.
class IrBuilder {
public:
    explicit IrBuilder(IrFunction* function) : function_(function) {}

    /// Sets the machine instruction subsequent ops are attributed to.
    void setAddress(Address address) { address_ = address; }
    Address address() const { return address_; }

    /// A fresh temporary of the given width.
    Varnode newTemp(u8 size) {
        return Varnode::temp(function_->tempCount++, size);
    }

    void emit(MintOp op, const Varnode& dest, const Varnode& a = Varnode::invalid(),
              const Varnode& b = Varnode::invalid(),
              const Varnode& c = Varnode::invalid());

    /// kIntrinsic, for an instruction with no modelling. Separate from emit() so
    /// that every unmodelled instruction is counted without the caller having to
    /// remember to.
    void emitIntrinsic(u16 capstoneId);

    /// Convenience wrappers that read at the call site the way the operation reads
    /// in the machine listing.
    Varnode binary(MintOp op, const Varnode& a, const Varnode& b);
    Varnode unary(MintOp op, const Varnode& a, u8 destSize);
    void assign(const Varnode& dest, const Varnode& value);
    /// Widens or narrows `value` to `size`, emitting nothing when it already fits.
    Varnode resize(const Varnode& value, u8 size, bool signExtend);

    u32 insnCount() const { return static_cast<u32>(function_->insns.size()); }
    IrFunction* function() { return function_; }

private:
    IrFunction* function_;
    Address address_ = 0;
};

}  // namespace mint
