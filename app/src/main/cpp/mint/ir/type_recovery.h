#pragma once

#include <vector>

#include "mint/base/status.h"
#include "mint/ssa/ssa_function.h"

namespace mint {
struct MemoryAnalysis;

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

struct TypeEvidenceOrigin {
    Address function=0, instruction=0;
    bool operator<(const TypeEvidenceOrigin& other) const {
        return function<other.function || (function==other.function && instruction<other.instruction);
    }
};
struct TypeCallEvidence {
    Address target=0, site=0;
    u32 argument=0;
    SsaId base=kNoValue;
    i64 displacement=0;
};

struct RecoveredField {
    u64 offset = 0;
    u8 width = 0;
    SsaId base = kNoValue;
    RecoveredType type;
    std::vector<TypeEvidenceOrigin> origins;
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
    std::vector<TypeCallEvidence> callEvidence;
    std::vector<SsaId> conflictingLayouts;
    bool interproceduralLimited=false;
};

/// Infers the useful, architecture-independent type facts available directly
/// from SSA operations: widths, booleans, pointer arithmetic and repeated loads
/// from one base. It deliberately reports hypotheses, not source-level certainty.
Status recoverTypes(const SsaFunction& function, TypeRecovery* out);
// Reuses a successful sidecar for this exact, unchanged SSA function.
Status recoverTypes(const SsaFunction& function,TypeRecovery* out,const MemoryAnalysis* memory);

}  // namespace mint
