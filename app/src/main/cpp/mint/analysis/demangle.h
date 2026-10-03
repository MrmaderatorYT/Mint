#pragma once

#include <string>

namespace mint {

// Itanium C++ ABI display name. Identity always stays the original ELF symbol;
// this helper is display-only and never changes linkage or reference keys.
// Unsupported, invalid, or over-budget names are returned unchanged.
std::string demangleSymbol(const std::string& symbol);

}  // namespace mint
