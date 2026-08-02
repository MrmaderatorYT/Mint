#pragma once

#include "mint/base/status.h"
#include "mint/ir/ir_function.h"
#include "mint/loader/dex_image.h"

namespace mint {

Status liftDalvik(const DexMethod& method, IrFunction* out);

}  // namespace mint
