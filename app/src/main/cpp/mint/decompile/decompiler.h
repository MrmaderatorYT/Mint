#pragma once

#include <functional>
#include <string>

#include "mint/base/status.h"
#include "mint/decompile/cfg_structurer.h"
#include "mint/ir/normalize.h"
#include "mint/ssa/ssa_builder.h"

namespace mint {

struct DecompileResult {
    SsaFunction ssa;
    ControlFlowStructure structure;
    std::string cSource;
    NormalizeStats normalize;
    SsaBuildStats ssaStats;
};

/// Resolves a code address to a symbol name, or returns empty when there is none.
///
/// Passed in rather than looked up here because the IR deliberately knows nothing
/// about the image it came from: a lifted function is just blocks and values. The
/// loader owns the symbol table, so it supplies this.
using SymbolNamer = std::function<std::string(Address)>;

Status decompileSsa(const SsaFunction& function, DecompileResult* result,
                    const SymbolNamer& names = {});
Status decompileIr(const IrFunction& input, DecompileResult* result,
                   const SymbolNamer& names = {});

}  // namespace mint
