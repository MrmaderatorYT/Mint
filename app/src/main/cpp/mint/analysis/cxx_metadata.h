#pragma once

#include <string>
#include <vector>

#include "mint/base/types.h"

namespace mint {

class ElfImage;
enum class CxxMetadataKind { kVtable, kTypeInfo, kTypeName };

struct CxxVtableSlot {
    Address address = 0;
    Address target = kNoAddress;
    std::string symbol;
    bool executable = false;
};

struct CxxBaseClass {
    Address typeInfo = kNoAddress;
    std::string name;
    i64 offset = 0;
    bool isVirtual = false;
    bool isPublic = false;
    bool virtualOffsetResolved = false;
    i64 objectOffset = 0;
};

struct CxxVtableAddressPoint {
    Address header = 0, addressPoint = kNoAddress, typeInfo = kNoAddress;
    i64 offsetToTop = 0;
    std::vector<i64> prefixDisplacements;
    std::vector<CxxVtableSlot> slots;
    bool complete = false;
};

struct CxxMetadataRecord {
    CxxMetadataKind kind = CxxMetadataKind::kTypeInfo;
    Address address = 0;
    u64 size = 0;
    std::string symbol;       // Original linkage identity, never demangled.
    std::string display;
    std::string abiClass;
    std::string typeName;
    bool defined = false;
    bool complete = false;
    Address addressPoint = kNoAddress;
    Address typeInfo = kNoAddress;
    i64 offsetToTop = 0;
    std::vector<CxxVtableSlot> slots;
    std::vector<CxxBaseClass> bases;
    std::vector<CxxVtableAddressPoint> addressPoints;
    std::vector<std::string> notes;
};

struct CxxMetadataReport {
    std::vector<CxxMetadataRecord> records;
    bool truncated = false;
    std::vector<std::string> notes;
    struct Class {
        std::string name, linkage;
        Address typeInfo = kNoAddress, vtable = kNoAddress;
        std::vector<CxxBaseClass> bases;
        std::vector<CxxVtableAddressPoint> addressPoints;
        bool inheritanceComplete = false;
    };
    std::vector<Class> classes;
};

// Symbol/relocation-backed Itanium ABI inventory for little-endian ELF/Mach-O
// 32/64 native images. Separate primary/secondary address points, __si/__vmi
// RTTI and virtual-base object offsets require exact validating linkage/byte
// evidence. No stripped-class heuristic, Microsoft RTTI or invented field size
// is implied. LSDA groups protected regions and their ordered landing-pad
// dispatch actions, not reconstructed source-level try/catch.
CxxMetadataReport inspectCxxMetadata(const ElfImage& image, size_t limit = 1024);
std::string cxxMetadataText(const ElfImage& image, size_t limit = 1024);

}  // namespace mint
