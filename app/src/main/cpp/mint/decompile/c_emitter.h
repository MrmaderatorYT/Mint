#pragma once

#include <functional>
#include <string>

#include "mint/decompile/cfg_structurer.h"
#include "mint/decompile/expr_builder.h"
#include "mint/analysis/user_prototype.h"
#include "mint/types/data_type_manager.h"
#include "mint/analysis/local_variables.h"

namespace mint {

struct CEmitterOptions {
    bool includeComments = true;
    bool foldExpressions = true;
    bool useAST = true; // Proven regions; exact labelled CFG on unsupported shapes.
    // Promote proven leaf stack slots and name exact memory-backed slots when
    // aliasing/escapes prevent promotion. Unknown addresses stay explicit.
    bool recoverStackVariables = true;
    /// Turns a call target into a name. Without it a call prints as its address,
    /// which is correct but says nothing: `memcmp(...)` and `call(0x129210)` carry
    /// very different amounts of information about what a function does.
    std::function<std::string(Address)> names;
    /// Turns a data address into a C string literal, or returns empty when the
    /// address does not hold one. Injected for the same reason as `names`: the IR
    /// knows nothing about the image it came from, and only the loader can read
    /// .rodata.
    std::function<std::string(Address)> strings;
    /// Reads a table of 32-bit offsets at `base`, each relative to `base`, and
    /// resolves the entries that point at strings. Returns one "index -> literal"
    /// line per entry, or empty when `base` does not hold such a table.
    ///
    /// This is how a compiler selects one of several string constants: a bounds
    /// check, then an offset table indexed by the discriminant. Recognising it is
    /// what turns "returns 0x5b4 + something" into a named set of cases.
    std::function<std::string(Address)> offsetTable;
    std::function<UserPrototype(Address)> prototypes;
    // Authoritative declared layouts only. No callback leaves memory accesses
    // numeric; inferred layout hypotheses never authorize field expressions.
    std::function<Status(const std::string&, DataTypeLayout*)> typeLayouts;
    std::function<std::vector<LocalVariableEdit>(Address)> locals;
};

std::string emitC(const SsaFunction& function, const ControlFlowStructure& structure,
                  const CEmitterOptions& options = {});

}  // namespace mint
