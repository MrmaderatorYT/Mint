#pragma once

#include <string>
#include <vector>
#include <map>

#include "mint/base/byte_view.h"
#include "mint/base/status.h"
#include "mint/base/types.h"

namespace mint {
class ElfImage;

struct DwarfRange { Address low = 0, high = 0; };
struct DwarfFunction {
    u64 dieOffset = 0;
    Address entry = kNoAddress;
    std::string name, linkageName, prototype;
    std::string frameBaseExpression;
    std::vector<DwarfRange> ranges;
    bool declaration = false;
};
struct DwarfType {
    u64 dieOffset = 0;
    std::string name;
    // DataTypeManager DSL, empty when DWARF describes unsupported/ambiguous
    // storage. Do not turn an empty declaration into an invented opaque type.
    std::string declaration;
    u64 byteSize = 0;
};
struct DwarfLocation {
    enum class Kind { kUnknown, kAddress, kRegister, kFrameBaseOffset, kRegisterOffset, kValue, kComposite, kSymbolic };
    Kind kind = Kind::kUnknown;
    Address address = kNoAddress;
    u32 reg = 0;  // DWARF register numbering, not Capstone numbering.
    i64 offset = 0;
    std::string expression;
    struct Piece { u64 bitSize = 0, bitOffset = 0; std::string expression; bool available = false; };
    std::vector<Piece> pieces;
    bool needsRuntime = false;
};
struct DwarfVariable {
    u64 dieOffset = 0, scopeDie = 0;
    Address scope = kNoAddress;
    std::string name, type;
    bool parameter = false;
    DwarfLocation location;
    struct LocatedRange { DwarfRange range; DwarfLocation location; };
    std::vector<LocatedRange> locations;
};
struct DwarfSourceRow {
    Address address = 0;
    std::string file;
    u32 line = 0, column = 0;
    bool endSequence = false;
};
struct DwarfReport {
    std::string format = "DWARF";
    size_t units = 0, dies = 0;
    u8 addressSize = 0;
    std::vector<DwarfFunction> functions;
    std::vector<DwarfType> types;
    std::vector<DwarfVariable> variables;
    std::vector<DwarfSourceRow> sources;
    std::vector<std::string> warnings;
    bool partial = false;
    std::vector<u64> splitIds;
    std::map<u64, u64> splitAddressBases;
};

// Section-view overload makes hostile-format tests independent of ELF parsing.
// Views must remain alive for the duration of readDwarf; the report owns all text.
struct DwarfSections {
    ByteView info, abbrev, strings, line, lineStrings, stringOffsets, addresses;
    ByteView ranges, rangeLists, locations, locationLists;
    bool split = false;
    u64 splitAddressesBase = kNoAddress;
    std::map<u64, u64> splitAddressBases;
};

// Bounded little-endian DWARF 2--5 reader, including zlib-compressed sections
// and explicitly identity-bound external/split objects. Source/typed-storage
// metadata and symbolic/composite locations are decoded without evaluating a
// runtime register file, CFA, memory load or historical entry value. Unhandled
// supplementary references/expressions remain explicitly partial. Struct/enum
// declarations require exact representable DataTypeManager storage layouts.
// Fatal malformed input never mutates the caller's existing report.
Status readDwarf(const ElfImage& image, DwarfReport* out);
// Explicit user-selected debug object. Verifies GNU debuglink CRC, ELF build-ID
// or split-unit identity before combining sections; never follows a host path.
Status readDwarf(const ElfImage& image, const ElfImage& externalDebug, DwarfReport* out, bool allowUnverified = false);
Status readDwarf(const DwarfSections& sections, DwarfReport* out);
std::string dwarfReportText(const DwarfReport& report);

}  // namespace mint
