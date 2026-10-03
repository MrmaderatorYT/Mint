#pragma once

#include <string>
#include <vector>

#include "mint/base/types.h"
#include "mint/ir/ir_function.h"
#include "mint/ir/varnode.h"

namespace mint {

/// Identifier of an SSA value. Values are numbered from zero within one function.
using SsaId = u32;
constexpr SsaId kNoValue = ~0u;

/// Where a value comes from.
enum class SsaDef : u8 {
    /// A literal. Interned, so the same constant used twice is one value — which
    /// makes constant folding and common-subexpression elimination cheaper later.
    kConstant,
    /// Live in to the function: read before anything in the function wrote it.
    ///
    /// These are the raw material for recovering a signature. An entry value in `x0`
    /// that gets dereferenced is a pointer parameter; one that is never read is not a
    /// parameter at all. Naming the category explicitly, rather than letting an
    /// undefined read fall through as a zero or an error, is what makes that later
    /// inference possible.
    kEntry,
    kInsn,
    kPhi,
};

/// One value: the result of exactly one definition.
struct SsaValue {
    /// The storage this value passed through before renaming — a whole register unit,
    /// a temporary, or a constant. Kept because the decompiler wants to call a value
    /// `x0` when naming a parameter, and because an emulator writing back to the
    /// machine state needs to know where it goes.
    Varnode storage;
    SsaDef def = SsaDef::kConstant;
    /// Index into SsaFunction::insns or ::phis, depending on `def`.
    u32 defIndex = 0;
    /// How many live operands reference this value. Maintained during construction so
    /// dead-code elimination is a worklist over counts rather than a full rebuild.
    u32 uses = 0;
};

struct SsaInsn {
    MintOp op = MintOp::kInvalid;
    SsaId dest = kNoValue;
    SsaId use[3] = {kNoValue, kNoValue, kNoValue};
    /// Extra values this instruction defines beyond `dest`.
    ///
    /// This exists for calls. A `bl` writes only the link register as an
    /// instruction, but as a *call* it destroys every caller-saved register, and the
    /// first of those is where the return value appears. Without these defs the
    /// renamer keeps whatever was in x0 before the call — so a `cbz w0` after a
    /// `bl memcmp` reads back the argument that was passed in rather than the result
    /// that came out. That is a wrong answer the SSA verifier cannot see, because the
    /// form stays perfectly well shaped either way.
    std::vector<SsaId> clobbers;
    Address address = 0;
    u16 intrinsicId = 0;
    /// Bytes per lane, carried through from the IR so the SSA listing can show
    /// which arithmetic a vector op actually performs.
    u8 laneWidth = 0;
    u32 block = 0;
    bool dead = false;
};

/// A phi: the value of a variable at a join, one argument per predecessor edge.
///
/// Arguments are positional and parallel to the block's predecessor list, so an
/// argument is meaningless without knowing which edge it arrived on. That is why the
/// predecessor list is stored on the block rather than recomputed on demand.
struct SsaPhi {
    SsaId dest = kNoValue;
    std::vector<SsaId> args;
    u32 block = 0;
    bool dead = false;
};

struct SsaBlock {
    u32 id = 0;
    Address start = 0;
    Address end = 0;
    u32 firstInsn = 0;
    u32 insnCount = 0;
    std::vector<u32> phis;  ///< indices into SsaFunction::phis
    std::vector<u32> successors;
    std::vector<u32> predecessors;
};

/// A function in SSA form.
///
/// **General memory is not versioned in this core register SSA.** The bounded
/// StackAnalysis sidecar versions exact stack stores and checks reaching loads;
/// it invalidates facts across unknown aliases/calls rather than deleting stores.
/// Loads and stores here carry their address and value as
/// ordinary SSA values, but the memory they touch is a single unnamed state that no
/// value names. So a load cannot yet be told which store it reads, and a store is
/// never dead. That is a deliberate first step: register SSA is what unlocks
/// expression building, control-flow structuring and constant propagation, while
/// memory SSA needs an alias analysis to be worth anything, and a wrong alias
/// analysis silently deletes stores. It is called out here so no later pass assumes
/// otherwise.
struct SsaFunction {
    Address entry = 0;
    std::string name;
    Arch arch = Arch::kUnknown;

    std::vector<SsaValue> values;
    std::vector<SsaInsn> insns;
    std::vector<SsaPhi> phis;
    std::vector<SsaBlock> blocks;

    u32 machineInsnCount = 0;
    u32 intrinsicCount = 0;

    /// The value each return site hands back, as (instruction index, value).
    ///
    /// A `ret` reads the link register, so as an instruction it says nothing about
    /// the result: the value returned is whatever the convention's result register
    /// holds there. Recording it during renaming — where the reaching definition is
    /// already on the stack — both answers that question exactly and keeps the value
    /// live, which matters because otherwise nothing references it and dead-code
    /// elimination removes the one definition the caller actually wanted.
    std::vector<std::pair<u32, SsaId>> returnValues;
    struct AbiReturnValue {u32 instruction;Varnode storage;SsaId value;};
    // Additional possible ABI result registers, with storage retained after copy
    // aliases are removed. Recorded only for units already mentioned by IR.
    std::vector<AbiReturnValue> abiReturnValues;

    /// Checks the property that makes SSA worth building: every use is reached by
    /// exactly one definition, and that definition dominates the use.
    ///
    /// This is a much stronger statement than the machine-level verifier makes, and
    /// it is the one worth checking, because every pass above assumes it. A phi
    /// argument is checked against the predecessor edge it arrives on rather than
    /// against the phi's own block, since that is where the value has to be live.
    std::vector<std::string> verify() const;

    std::string toText() const;

    u32 liveInsnCount() const;
    u32 livePhiCount() const;
};

/// True for operations whose effect is not captured by their destination value, and
/// which therefore may never be deleted just because nothing reads them.
///
/// Stores and calls change state this form does not model; an intrinsic is by
/// definition an instruction whose effect is unknown, so deleting one would be
/// claiming knowledge the lifter explicitly said it did not have.
bool hasSideEffect(MintOp op);

}  // namespace mint
