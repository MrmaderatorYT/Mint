#include "mint/obfuscation/deobfuscator.h"

namespace mint {

DeobfuscationResult deobfuscate(IrFunction* function) {
    DeobfuscationResult result;
    if (!function) return result;
    result.findings = detectOllvm(*function);
    result.unroll = unrollOllvm(function);
    return result;
}

}  // namespace mint
