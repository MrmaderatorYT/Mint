#pragma once

#include <map>
#include <string>
#include <vector>

#include "mint/analysis/user_prototype.h"
#include "mint/loader/elf_image.h"

namespace mint {
enum class SignatureAbi : u8 { kUnknown, kAapcs64, kSysV64, kAapcs32, kRiscV32, kRiscV64, kCdecl32, kWindows64, kStdcall32 };
const char* signatureAbiName(SignatureAbi abi);
struct SignatureDefinition { std::string symbol, declaration; UserPrototype prototype; };

// Authored linkage-symbol -> scalar prototype library. Exact symbol keys, no
// guessed signatures, regex matching, byte-pattern detector or auto rename.
// Text: "MINTSIG 1\nabi=aapcs64\n<symbol>\t<uint64_t(void)>\n".
// The prototype field is a type-only UserPrototype declaration, without a
// function name. Lines beginning # and blank lines are allowed after the header.
// Uses the authoritative ABI model for scalar FP, stack arguments, register
// pairs, named variadic arguments and Windows x64/stdcall. By-value names need
// known layout (this standalone library has no bundled type definitions).
// Unsupported storage conventions are rejected, not guessed. Architecture and
// container checks are separate from parsing so a library can be inspected
// before binding it.
class SignatureLibrary {
public:
    explicit SignatureLibrary(SignatureAbi abi = SignatureAbi::kUnknown) : abi_(abi) {}
    SignatureAbi abi() const { return abi_; }
    u8 pointerSize() const;
    Status validateFor(Arch architecture, ImageFormat format) const;
    Status validateFor(const ElfImage& image) const { return validateFor(image.arch(), image.format()); }
    Status define(const std::string& linkageSymbol, const std::string& declaration);
    Status erase(const std::string& linkageSymbol);
    UserPrototype prototypeFor(const std::string& linkageSymbol) const;
    std::string declarationFor(const std::string& linkageSymbol) const;
    std::vector<SignatureDefinition> definitions() const;
    std::string serialize() const;
    Status deserialize(const std::string& text);
    static constexpr size_t kMaxLibraryBytes = 1024 * 1024;
    static constexpr size_t kMaxDefinitions = 4096;
    static constexpr size_t kMaxSymbolBytes = 512;
    static constexpr size_t kMaxPrototypeBytes = 4096;
private:
    SignatureAbi abi_;
    std::map<std::string, SignatureDefinition> definitions_;
};
} // namespace mint
