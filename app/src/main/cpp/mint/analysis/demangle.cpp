#include "mint/analysis/demangle.h"

#include <cstdlib>
#include <memory>

#if defined(__has_include)
#if __has_include(<cxxabi.h>)
#include <cxxabi.h>
#define MINT_HAS_CXXABI_DEMANGLER 1
#endif
#endif

namespace mint {

std::string demangleSymbol(const std::string& symbol) {
    // The ABI parser can expand repetitive encodings substantially. Bound its
    // input and output, and avoid invoking it for ordinary C/linker names.
    if (symbol.size() < 3 || symbol.size() > 4096 || symbol.compare(0, 2, "_Z") != 0 ||
        symbol.find('\0') != std::string::npos) return symbol;
#if defined(MINT_HAS_CXXABI_DEMANGLER)
    int status = -1;
    std::unique_ptr<char, decltype(&std::free)> display(
            abi::__cxa_demangle(symbol.c_str(), nullptr, nullptr, &status), &std::free);
    if (status == 0 && display) {
        const std::string result(display.get());
        if (result.size() <= 65536) return result;
    }
#endif
    return symbol;
}

}  // namespace mint
