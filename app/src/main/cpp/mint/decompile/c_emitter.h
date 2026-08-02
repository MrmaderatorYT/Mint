#pragma once

#include <functional>
#include <string>

#include "mint/decompile/cfg_structurer.h"
#include "mint/decompile/expr_builder.h"

namespace mint {

struct CEmitterOptions {
    bool includeComments = true;
    bool foldExpressions = true;
    /// Turns a call target into a name. Without it a call prints as its address,
    /// which is correct but says nothing: `memcmp(...)` and `call(0x129210)` carry
    /// very different amounts of information about what a function does.
    std::function<std::string(Address)> names;
};

std::string emitC(const SsaFunction& function, const ControlFlowStructure& structure,
                  const CEmitterOptions& options = {});

}  // namespace mint
