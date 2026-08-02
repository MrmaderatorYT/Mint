#pragma once

#include <vector>

#include "mint/ir/ir_function.h"
#include "mint/obfuscation/ollvm_detect.h"

namespace mint {

struct OllvmUnrollResult {
    u32 dispatcherBlocks = 0;
    u32 unreachableBlocks = 0;
    std::vector<u32> removedBlocks;
};

OllvmUnrollResult unrollOllvm(IrFunction* function);

}  // namespace mint
