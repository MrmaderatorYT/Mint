#pragma once

#include <string>

#include "mint/base/types.h"

namespace mint {

enum class InterpKind : u8 {
    kUnknown = 0,
    kConcrete,
    kPointer,
    kSymbolic,
};

/// A deliberately small value domain for IR execution. The bit pattern is kept
/// even for pointers, so pointer arithmetic remains ordinary wrapping integer
/// arithmetic while the kind lets callers distinguish a recovered address from
/// an opaque scalar.
struct InterpValue {
    InterpKind kind = InterpKind::kUnknown;
    u8 width = 8;
    u64 bits = 0;
    u32 symbolicId = 0;

    static InterpValue unknown(u8 width = 8) { return {InterpKind::kUnknown, width, 0, 0}; }
    static InterpValue concrete(u64 bits, u8 width = 8) {
        return {InterpKind::kConcrete, width, bits, 0};
    }
    static InterpValue pointer(Address address, u8 width = 8) {
        return {InterpKind::kPointer, width, address, 0};
    }
    static InterpValue symbolic(u32 id, u8 width = 8) {
        return {InterpKind::kSymbolic, width, 0, id};
    }

    bool known() const { return kind != InterpKind::kUnknown; }
    bool concreteLike() const { return kind == InterpKind::kConcrete || kind == InterpKind::kPointer; }
    bool isPointer() const { return kind == InterpKind::kPointer; }
    bool isConcrete() const { return kind == InterpKind::kConcrete; }
    bool isUnknown() const { return kind == InterpKind::kUnknown; }

    std::string toString() const;
};

/// Converts a value to a C-like boolean when possible. Unknown and symbolic
/// conditions intentionally return false through the out parameter.
bool interpBool(const InterpValue& value, bool* known);

}  // namespace mint
