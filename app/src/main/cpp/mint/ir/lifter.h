#pragma once

#include "mint/analysis/function.h"
#include "mint/base/byte_view.h"
#include "mint/base/status.h"
#include "mint/ir/ir_function.h"
#include "mint/loader/memory_map.h"

namespace mint {

/// Translates machine instructions into MintIR.
///
/// One lifter per architecture front-end, all producing the same IR, which is the
/// entire point of having an IR: SSA construction, type recovery, the emulator, the
/// OLLVM passes and the C emitter are written once and work on AArch64, x86-64 and
/// later Dalvik without knowing which they are looking at.
///
/// Lifting is per function and on demand. See IrFunction for why that limit
/// matters on a phone.
class Lifter {
public:
    Lifter() = default;
    ~Lifter();
    Lifter(const Lifter&) = delete;
    Lifter& operator=(const Lifter&) = delete;

    Status open(Arch arch);
    bool ready() const { return handle_ != 0 || customReady_; }
    Arch arch() const { return arch_; }

    /// Lifts a whole function, producing IR blocks that mirror the machine CFG
    /// one-to-one.
    Status liftFunction(const Function& function, const MemoryMap& memory,
                        IrFunction* out);

    /// Lifts one machine instruction into an open builder, for the UI's
    /// instruction-level IR view. Returns the instruction's length, or 0 when the
    /// bytes do not decode.
    u32 liftInstruction(Address address, ByteView bytes, IrBuilder* builder);

    /// The mnemonic behind an instruction id, so an unmodelled instruction can be
    /// named rather than reported as a bare number. The lifter is the natural owner
    /// of this: it is what records the ids in the first place.
    const char* instructionName(u16 id) const;

private:
    /// Capstone's csh is a size_t typedef; holding it as one keeps Capstone's
    /// headers out of this interface, which every pass above the IR includes.
    size_t handle_ = 0;
    Arch arch_ = Arch::kUnknown;
    bool customReady_ = false;
    u8 thumbItRemaining_ = 0;
    u8 thumbItState_ = 0;
    Address thumbItNextAddress_ = kNoAddress;
};

}  // namespace mint
