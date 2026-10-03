#pragma once
#include <string>
#include <vector>
#include "mint/base/status.h"
namespace mint {
struct UserParameter { std::string type, name; };
struct UserPrototype {
    std::string returnType;
    std::vector<UserParameter> parameters;
    bool variadic = false;
    // Empty chooses the target's default; explicit @windows64 etc are persisted.
    std::string callingConvention;
    bool valid() const { return !returnType.empty(); }
};
// Type-only declaration, optionally prefixed by @calling-convention. Layout and
// target compatibility are validated by buildAbiModel, never guessed by parser.
Status parseUserPrototype(const std::string& text, UserPrototype* result);
bool userIdentifier(const std::string& text);
} // namespace mint
