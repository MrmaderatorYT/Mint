#pragma once

#include <vector>

#include "mint/ir/ir_function.h"

namespace mint {

enum class OllvmPattern : u8 { kOpaquePredicate, kFlattenedDispatcher, kSuspiciousDeadLoop };

struct OllvmFinding {
    OllvmPattern pattern = OllvmPattern::kOpaquePredicate;
    u32 block = 0;
    Address address = 0;
    u8 confidence = 0;
};

std::vector<OllvmFinding> detectOllvm(const IrFunction& function);

/// Constant identities that are safe to simplify even when the surrounding
/// function is obfuscated. Returns the known predicate when one was found.
bool recoverOpaquePredicate(MintOp op, const Varnode& a, const Varnode& b, bool* result);

}  // namespace mint
