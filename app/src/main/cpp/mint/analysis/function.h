#pragma once

#include <string>
#include <vector>

#include "mint/analysis/cfg.h"
#include "mint/base/types.h"

namespace mint {

/// How a function came to the analyser's attention. Worth keeping: a function
/// only reachable through an indirect call is far more interesting than one named
/// in the symbol table, and the UI should be able to say which is which.
enum class FunctionOrigin : u8 {
    kEntryPoint = 0,
    kSymbol,        ///< Named by .symtab or .dynsym.
    kInitializer,   ///< Reached from DT_INIT / .init_array — packer territory.
    kCallTarget,    ///< Discovered as the target of a direct call.
    kPltStub,
    kJniExport,     ///< Named Java_* or JNI_OnLoad.
};

const char* functionOriginName(FunctionOrigin origin);

struct Function {
    Address entry = 0;
    std::string name;
    FunctionOrigin origin = FunctionOrigin::kCallTarget;

    /// Address span actually covered by decoded instructions. Not necessarily
    /// contiguous — obfuscated code is routinely scattered — so this is a hull,
    /// not an extent.
    Address lowAddress = 0;
    Address highAddress = 0;

    /// Instruction addresses belonging to this function, ascending.
    std::vector<Address> instructions;

    ControlFlowGraph cfg;

    /// Direct call targets, deduplicated. The call graph is built from these.
    std::vector<Address> callees;

    /// Set when the descent could not follow something: an indirect branch with
    /// no recovered targets, or undecodable bytes reached through a live path.
    /// The decompiler must know this, because output for an incomplete function
    /// is a partial view and should be labelled as one rather than quietly
    /// presented as the whole thing.
    bool incomplete = false;

    /// Count of indirect branches. A function whose body is one big switch on a
    /// state variable — the shape OLLVM's control-flow flattening produces — shows
    /// up here first.
    u32 indirectJumps = 0;

    /// Indirect branches whose table targets were recovered during descent.
    /// CFG construction consumes these after every target has been decoded.
    std::vector<ResolvedIndirectJump> resolvedIndirectJumps;

    /// Bytes that failed to decode inside the function's span, which usually means
    /// data inlined into code.
    u32 undecodableSites = 0;

    size_t instructionCount() const { return instructions.size(); }
};

}  // namespace mint
