#pragma once

#include <string>
#include <map>
#include <vector>

#include "mint/base/status.h"
#include "mint/base/types.h"

namespace mint {

// Built-in little-endian scalar patch assembler, not a compiler/tool launcher.
// At most 1024 output bytes, 1024 instructions and 64 KiB of input. Newlines or
// semicolons separate instructions; // starts a comment; labels are ASCII,
// case-sensitive identifiers. Decimal/0x literals, optional # and signed
// immediates are supported. Branch operands are absolute addresses or labels.
// Bounded .byte/.short/.word/.quad/.zero/.align/.org directives and absolute
// symbol relocation are supported. No macros or implicit truncation.
// Failure preserves *output exactly. arch chooses the precise instruction mode;
// a Thumb address must be even (it is not a tagged function pointer).
Status assemble(Arch arch, Address address, const std::string& source,
                std::vector<u8>* output);
Status assembleWithSymbols(Arch arch, Address address, const std::string& source,
                          const std::map<std::string,Address>& symbols,
                          std::vector<u8>* output);

// Describes the implemented operand forms, including pseudo-instruction
// expansion and deliberate exclusions. Suitable for the patch editor's help.
std::string assemblerSyntax(Arch arch);

}  // namespace mint
