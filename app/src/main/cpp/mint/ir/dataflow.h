#pragma once

#include <unordered_set>
#include <vector>

#include "mint/base/status.h"
#include "mint/ssa/ssa_function.h"

namespace mint {

enum class SsaUseKind : u8 { kInstruction, kPhi };

struct SsaUseSite {
    SsaUseKind kind = SsaUseKind::kInstruction;
    u32 index = 0;       ///< instruction or phi index
    u8 operand = 0;      ///< source slot for an instruction, argument for a phi
    u32 predecessor = kNoValue;  ///< the incoming block for a phi argument
};

struct SsaDefUse {
    std::vector<std::vector<SsaUseSite>> uses;
};

/// Builds the use list for every SSA value. `SsaValue::uses` is only a count;
/// this index preserves the exact instruction/phi site needed by type recovery,
/// liveness and later expression building.
Status buildDefUse(const SsaFunction& function, SsaDefUse* out);

struct SsaLiveness {
    std::vector<std::unordered_set<SsaId>> liveIn;
    std::vector<std::unordered_set<SsaId>> liveOut;
};

/// Computes block live-in/live-out sets. Phi arguments are attached to the edge
/// carrying them, rather than to the phi block itself, which is the distinction
/// that makes liveness around loops and joins correct.
Status computeLiveness(const SsaFunction& function, SsaLiveness* out);

}  // namespace mint
