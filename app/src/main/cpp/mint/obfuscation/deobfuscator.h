#pragma once

#include "mint/obfuscation/ollvm_unroll.h"

namespace mint {

struct DeobfuscationResult {
    std::vector<OllvmFinding> findings;
    OllvmUnrollResult unroll;
};

DeobfuscationResult deobfuscate(IrFunction* function);

}  // namespace mint
