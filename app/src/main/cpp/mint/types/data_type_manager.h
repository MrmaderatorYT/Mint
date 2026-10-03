#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "mint/base/status.h"
#include "mint/base/types.h"

namespace mint {

struct DataTypeCompiled;

enum class DataTypeKind { kPrimitive, kPointer, kArray, kStruct, kUnion, kEnum };

struct DataTypeField {
    std::string name;
    std::string type;
    u64 offset = 0;
    u64 size = 0;
    u32 alignment = 1;
};

struct DataTypeEnumerator { std::string name; i64 value = 0; };

// Layout is ABI-neutral except for pointer size and the usual natural alignment
// (primitive alignment equals its size, aggregate alignment is its maximum).
// Bitfields, target-specific C++ ABI classes and incomplete types are not guessed.
struct DataTypeLayout {
    DataTypeKind kind = DataTypeKind::kPrimitive;
    std::string expression;
    u64 size = 0;
    u32 alignment = 1;
    bool isSigned = false;
    bool isFloating = false;
    bool packed = false;
    std::vector<DataTypeField> fields;
    std::vector<DataTypeEnumerator> enumerators;
};

struct DataTypeDefinition {
    std::string name;
    std::string declaration;
    DataTypeLayout layout;
};

// A deliberately small, strict, one-line editor language. Examples:
//   Packet=struct{length:u32;bytes:u8[16];next:Packet*}
//   Wire=packed{tag:u8;value:u32}
//   Value=union{integer:u64;real:f64}
//   Sparse=struct{tag:u8;payload:u32@16}
//   Color=enum:i32{Red=-1;Green=2}
//   Handle=u64
// Names are case-sensitive ASCII identifiers. Arrays have a positive constant
// length. Explicit field offsets are decimal or 0x-prefixed. Enum values may be
// signed. Recursive pointers are legal; recursive by-value storage is rejected.
// All mutations and deserialization are atomic, including dependent validation.
class DataTypeManager {
public:
    explicit DataTypeManager(u8 pointerSize = 8) : pointerSize_(pointerSize) {}
    u8 pointerSize() const { return pointerSize_; }

    Status define(const std::string& declaration);
    Status erase(const std::string& name);
    Status resolve(const std::string& expression, DataTypeLayout* out) const;
    std::vector<DataTypeDefinition> definitions() const;
    std::string declarationFor(const std::string& name) const;
    std::string renderDefinitions() const;
    // Self-contained GNU C11 header with explicit target layout assertions.
    // Rejects non-C names/recursive typedef aliases rather than misrepresenting
    // them. A cross compiler must use this library's target pointer width.
    Status cHeader(std::string* output) const;

    // Versioned ASCII format, sorted by name, independent of host endianness.
    // deserialize accepts forward references and validates the whole library.
    std::string serialize() const;
    Status deserialize(const std::string& text);
    static bool validName(const std::string& name);
    static constexpr size_t kMaxDefinitions = 4096;
    static constexpr size_t kMaxDeclarationBytes = 16384;
    static constexpr size_t kMaxLibraryBytes = 1024 * 1024;
    static constexpr u64 kMaxTypeBytes = 1024ULL * 1024 * 1024;

private:
    Status validate();
    u8 pointerSize_;
    std::map<std::string, std::string> definitions_;
    // Immutable parsed/layout cache, shared across snapshots. Mutation prepares
    // a new cache before publishing it, so const reads perform no hidden writes.
    std::shared_ptr<const DataTypeCompiled> compiled_;
};

}  // namespace mint
