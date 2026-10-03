#pragma once

#include <functional>
#include <string>

#include "mint/base/status.h"
#include "mint/decompile/cfg_structurer.h"
#include "mint/ir/normalize.h"
#include "mint/ssa/ssa_builder.h"
#include "mint/analysis/user_prototype.h"
#include "mint/types/data_type_manager.h"
#include "mint/analysis/local_variables.h"

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

/// Resolves a data address to a C string literal, already quoted and escaped, or
/// returns empty when the address does not hold printable text. Same reasoning as
/// SymbolNamer: the loader owns the image, the IR does not.
using StringResolver = std::function<std::string(Address)>;
using PrototypeResolver = std::function<UserPrototype(Address)>;
using TypeLayoutResolver = std::function<Status(const std::string&, DataTypeLayout*)>;
using LocalResolver = std::function<std::vector<LocalVariableEdit>(Address)>;

Status decompileSsa(const SsaFunction& function, DecompileResult* result,
                    const SymbolNamer& names = {},
                    const StringResolver& strings = {},
                    const StringResolver& offsetTable = {},
                    const PrototypeResolver& prototypes = {},
                    const TypeLayoutResolver& typeLayouts = {},
                    const LocalResolver& locals = {});
Status decompileIr(const IrFunction& input, DecompileResult* result,
                   const SymbolNamer& names = {},
                   const StringResolver& strings = {},
                   const StringResolver& offsetTable = {},
                   const PrototypeResolver& prototypes = {},
                   const TypeLayoutResolver& typeLayouts = {},
                   const LocalResolver& locals = {});

}  // namespace mint
