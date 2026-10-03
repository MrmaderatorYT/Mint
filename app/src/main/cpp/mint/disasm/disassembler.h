#pragma once

#include <string>
#include <vector>

#include "mint/base/byte_view.h"
#include "mint/base/status.h"
#include "mint/base/types.h"
#include "mint/disasm/instruction.h"

namespace mint {

// Seven builtins plus the complete immutable custom ID range128..254.
constexpr size_t kMaxArchitectureDescriptions = 134;

/// Builtin architecture metadata and the narrow external-decoder ABI. A custom
/// callback owns no input bytes and must return a canonical, bounded record.
/// Callback code must remain loaded while any decoder using it exists.
using ArchitectureDecode = bool (*)(Address, ByteView, DecodedInsn*);
struct ArchitectureDescription {
    Arch architecture = Arch::kUnknown;
    std::string id;
    std::string name;
    u8 pointerSize = 0;
    u8 minInstructionSize = 0;
    u8 maxInstructionSize = 0;
    u8 instructionAlignment = 0;
    u16 elfMachine = 0;
    u8 elfClass = 0;
    bool thumbAddressTag = false;
    ArchitectureDecode decode = nullptr;
};

std::vector<ArchitectureDescription> architectureDescriptions();
bool architectureDescription(Arch architecture, ArchitectureDescription* output);
/// Stable builtin spelling, or the registered custom decoder ID.
std::string architectureName(Arch architecture);
/// Custom IDs are128..254 (maximum134 total descriptors including7 builtins).
/// Builtins and duplicate IDs/names cannot be replaced.
/// Registration is process-local and thread-safe; descriptors are copied.
Status registerArchitectureDescription(const ArchitectureDescription& description);
/// All-or-nothing publication under the same registry lock. A failed batch
/// never leaves a subset of permanent callback registrations behind.
Status registerArchitectureDescriptions(const std::vector<ArchitectureDescription>& descriptions);

/// Decodes machine code for one architecture.
///
/// Wraps a Capstone handle. Detail mode is on, because the flow classification
/// that everything above depends on needs operand and condition-code
/// information, not just a mnemonic string.
///
/// Not thread-safe: a Capstone handle carries mutable state, so each analysis
/// thread gets its own instance. That is cheap — the expensive part is the
/// static decoder tables, which are shared.
class Disassembler {
public:
    Disassembler() = default;
    ~Disassembler();

    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;

    Status open(Arch arch);
    void close();
    bool isOpen() const { return handle_ != 0 || description_.decode != nullptr; }
    Arch arch() const { return arch_; }

    /// Decodes one instruction at `addr` from the bytes in `code`, which must
    /// start at `addr`. Returns false only when the bytes do not decode; the
    /// caller still gets a record with FlowKind::kInvalid and the architecture's
    /// minimum instruction size, so a linear sweep can step past bad bytes.
    bool decode(Address addr, ByteView code, InsnRecord* out);

    /// As above, plus mnemonic, operand text and raw bytes. Used for the listing
    /// and by the lifter; costs a string format, so not for bulk sweeps.
    bool decodeVerbose(Address addr, ByteView code, DecodedInsn* out);

    /// The smallest instruction on this architecture: 4 on AArch64, 1 on x86-64.
    /// This is how far a sweep advances after undecodable bytes.
    u8 minInstructionSize() const;

    /// The largest instruction, which bounds how many bytes a decode attempt
    /// needs to see.
    u8 maxInstructionSize() const;

private:
    /// Fills in flow kind and branch target from Capstone's detail. Split per
    /// architecture because the generic groups tell us "this is a jump" but not
    /// whether it is conditional, which is the distinction the CFG turns on.
    void classify(const void* insn, InsnRecord* out) const;
    void classifyAArch64(const void* insn, InsnRecord* out) const;
    void classifyX86(const void* insn, InsnRecord* out) const;
    void classifyArm(const void* insn, InsnRecord* out) const;
    void classifyRiscV(const void* insn, InsnRecord* out) const;
    bool decodePlugin(Address addr, ByteView code, DecodedInsn* out) const;

    /// Capstone's csh, held as a uintptr so this header does not drag the
    /// Capstone headers into every translation unit that analyses code.
    size_t handle_ = 0;
    Arch arch_ = Arch::kUnknown;
    ArchitectureDescription description_;

    /// Reused across decodes; allocating a cs_insn per instruction would dominate
    /// the cost of a sweep over half a million of them.
    void* scratch_ = nullptr;
};

}  // namespace mint
