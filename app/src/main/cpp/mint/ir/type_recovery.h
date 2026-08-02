#pragma once

#include <vector>

#include "mint/base/status.h"
#include "mint/ssa/ssa_function.h"

namespace mint {

enum class RecoveredTypeKind : u8 {
    kUnknown,
    kBoolean,
    kUnsignedInteger,
    kSignedInteger,
    kFloat,
    kPointer,
    kStruct,
};

struct RecoveredType {
    RecoveredTypeKind kind = RecoveredTypeKind::kUnknown;
    u8 width = 0;
    u32 structId = kNoValue;
};

struct RecoveredField {
    u64 offset = 0;
    u8 width = 0;
    SsaId base = kNoValue;
    RecoveredType type;
};

struct RecoveredStruct {
    SsaId base = kNoValue;
    std::vector<RecoveredField> fields;
};

struct RecoveredParameter {
    SsaId value = kNoValue;
    RecoveredType type;
};

struct TypeRecovery {
    std::vector<RecoveredType> values;
    std::vector<RecoveredStruct> structs;
    std::vector<RecoveredParameter> parameters;
};

/// Infers the useful, architecture-independent type facts available directly
/// from SSA operations: widths, booleans, pointer arithmetic and repeated loads
/// from one base. It deliberately reports hypotheses, not source-level certainty.
Status recoverTypes(const SsaFunction& function, TypeRecovery* out);

}  // namespace mint
