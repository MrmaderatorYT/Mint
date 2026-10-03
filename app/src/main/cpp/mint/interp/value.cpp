#include "mint/interp/value.h"

#include <cstdio>

namespace mint {

std::string InterpValue::toString() const {
    char buffer[64];
    switch (kind) {
        case InterpKind::kConcrete:
            if(width>8)std::snprintf(buffer,sizeof(buffer),"0x%llx%016llx",static_cast<unsigned long long>(highBits),static_cast<unsigned long long>(bits));
            else std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(bits));
            return buffer;
        case InterpKind::kPointer:
            std::snprintf(buffer, sizeof(buffer), "ptr(0x%llx)", static_cast<unsigned long long>(bits));
            return buffer;
        case InterpKind::kSymbolic:
            std::snprintf(buffer, sizeof(buffer), "sym%u", symbolicId);
            return buffer;
        default:
            return "?";
    }
}

bool interpBool(const InterpValue& value, bool* known) {
    if (!value.concreteLike()) {
        *known = false;
        return false;
    }
    *known = true;
    return value.bits != 0 || value.highBits != 0;
}

}  // namespace mint
