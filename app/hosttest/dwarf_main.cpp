#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "mint/base/mapped_file.h"
#include "mint/debug/dwarf_reader.h"
#include "mint/loader/elf_image.h"
#include "mint/types/data_type_manager.h"

using namespace mint;
namespace {
size_t checks = 0;
void require(bool condition, const std::string& message) {
    ++checks;
    if (!condition) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
struct Bytes : std::vector<u8> {
    void integer(u64 value, unsigned width) { for (unsigned i = 0; i < width; ++i) push_back(static_cast<u8>(value >> (i * 8))); }
    void patch(size_t offset, u64 value, unsigned width) { for (unsigned i = 0; i < width; ++i) at(offset + i) = static_cast<u8>(value >> (i * 8)); }
    void uleb(u64 value) { do { u8 byte = static_cast<u8>(value & 0x7f); value >>= 7; push_back(byte | (value ? 0x80 : 0)); } while (value); }
    void sleb(i64 value) {
        bool more = true;
        while (more) {
            const u8 byte = static_cast<u8>(value & 0x7f); value >>= 7;
            more = !((value == 0 && !(byte & 0x40)) || (value == -1 && (byte & 0x40)));
            push_back(byte | (more ? 0x80 : 0));
        }
    }
    void string(const std::string& value) { insert(end(), value.begin(), value.end()); push_back(0); }
    void expression(const Bytes& value) { uleb(value.size()); insert(end(), value.begin(), value.end()); }
    ByteView view() const { return ByteView(data(), size()); }
};
Bytes expression(u8 op, i64 offset) { Bytes bytes; bytes.push_back(op); bytes.sleb(offset); return bytes; }
void abbrev(Bytes& bytes, u64 code, u64 tag, bool children, std::initializer_list<std::pair<u64, u64>> attrs) {
    bytes.uleb(code); bytes.uleb(tag); bytes.push_back(children);
    for (const auto& attr : attrs) { bytes.uleb(attr.first); bytes.uleb(attr.second); }
    bytes.push_back(0); bytes.push_back(0);
}
struct Fixture {
    Bytes info, abbrevBytes, strings, line, lineStrings, stringOffsets, addresses, ranges, rangeLists, locations, locationLists;
    std::map<std::string, size_t> marks;
    std::vector<std::pair<size_t, std::string>> refs;
    DwarfSections sections() const {
        DwarfSections result;
        result.info = info.view(); result.abbrev = abbrevBytes.view(); result.strings = strings.view(); result.line = line.view();
        result.lineStrings = lineStrings.view(); result.stringOffsets = stringOffsets.view(); result.addresses = addresses.view();
        result.ranges = ranges.view(); result.rangeLists = rangeLists.view(); result.locations = locations.view(); result.locationLists = locationLists.view();
        return result;
    }
    void mark(const std::string& name) { marks[name] = info.size(); }
    void ref(const std::string& name) { refs.emplace_back(info.size(), name); info.integer(0, 4); }
    void finish() { for (const auto& ref : refs) info.patch(ref.first, marks.at(ref.second), 4); info.patch(0, info.size() - 4, 4); }
};

Bytes lineV4() {
    Bytes bytes; bytes.integer(0, 4); bytes.integer(4, 2); const auto length = bytes.size(); bytes.integer(0, 4);
    const auto header = bytes.size();
    bytes.push_back(1); bytes.push_back(1); bytes.push_back(1); bytes.push_back(0xfb); bytes.push_back(14); bytes.push_back(13);
    for (u8 count : {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1}) bytes.push_back(count);
    bytes.push_back(0); bytes.string("fixture.c"); bytes.uleb(0); bytes.uleb(0); bytes.uleb(0); bytes.push_back(0);
    bytes.patch(length, bytes.size() - header, 4);
    auto address = [&](u64 value) { bytes.push_back(0); bytes.uleb(9); bytes.push_back(2); bytes.integer(value, 8); };
    auto end = [&] { bytes.push_back(0); bytes.uleb(1); bytes.push_back(1); };
    address(0x1000); bytes.push_back(1); bytes.push_back(2); bytes.uleb(4); bytes.push_back(3); bytes.sleb(2); bytes.push_back(1);
    bytes.push_back(2); bytes.uleb(4); end();
    // The second sequence deliberately has lower addresses. Its end marker
    // must stay adjacent to its own rows, not be globally sorted with the first.
    address(0x800); bytes.push_back(1); bytes.push_back(2); bytes.uleb(4); end();
    bytes.patch(0, bytes.size() - 4, 4); return bytes;
}

Fixture fixtureV4(const Bytes& parameterLocation = expression(0x91, -32)) {
    Fixture f;
    abbrev(f.abbrevBytes, 1, 0x11, true, {{3, 8}, {0x1b, 8}, {0x11, 1}, {0x13, 0x0b}, {0x10, 0x17}});
    abbrev(f.abbrevBytes, 2, 0x2e, true, {{3, 8}, {0x11, 1}, {0x12, 6}, {0x49, 0x13}, {0x40, 0x18}});
    abbrev(f.abbrevBytes, 3, 5, false, {{3, 8}, {0x49, 0x13}, {2, 0x18}});
    abbrev(f.abbrevBytes, 4, 0x34, false, {{3, 8}, {0x49, 0x13}, {2, 0x18}});
    abbrev(f.abbrevBytes, 5, 0x24, false, {{3, 8}, {0x0b, 0x0b}, {0x3e, 0x0b}});
    abbrev(f.abbrevBytes, 6, 0x13, true, {{3, 8}, {0x0b, 0x0b}});
    abbrev(f.abbrevBytes, 7, 0x0d, false, {{3, 8}, {0x49, 0x13}, {0x38, 0x0b}});
    abbrev(f.abbrevBytes, 8, 0x0f, false, {{0x49, 0x13}});
    abbrev(f.abbrevBytes, 9, 1, true, {{0x49, 0x13}});
    abbrev(f.abbrevBytes, 10, 0x21, false, {{0x37, 0x0b}});
    abbrev(f.abbrevBytes, 11, 4, true, {{3, 8}, {0x49, 0x13}, {0x0b, 0x0b}});
    abbrev(f.abbrevBytes, 12, 0x28, false, {{3, 8}, {0x1c, 0x0d}});
    abbrev(f.abbrevBytes, 13, 0x2e, false, {{3, 8}, {0x3c, 0x19}});
    abbrev(f.abbrevBytes, 14, 0x2e, false, {{0x47, 0x13}, {0x11, 1}, {0x12, 6}, {0x49, 0x13}});
    abbrev(f.abbrevBytes, 15, 0x34, false, {{3, 8}, {0x49, 0x13}, {2, 0x17}});
    f.abbrevBytes.push_back(0);
    f.info.integer(0, 4); f.info.integer(4, 2); f.info.integer(0, 4); f.info.push_back(8);
    f.mark("root"); f.info.uleb(1); f.info.string("fixture.c"); f.info.string("src"); f.info.integer(0x1000, 8); f.info.push_back(2); f.info.integer(0, 4);
    f.mark("function"); f.info.uleb(2); f.info.string("fixture_entry"); f.info.integer(0x1000, 8); f.info.integer(0x20, 4);
    f.mark("returnRef"); f.ref("int"); Bytes cfa; cfa.push_back(0x9c); f.info.expression(cfa);
    f.mark("parameter"); f.info.uleb(3); f.info.string("value"); f.ref("int"); f.info.expression(parameterLocation);
    Bytes breg; breg.push_back(0x92); breg.uleb(35); breg.sleb(-128);
    f.info.uleb(4); f.info.string("local"); f.ref("int"); f.info.expression(breg); f.info.push_back(0);
    f.info.uleb(4); f.info.string("global"); f.ref("int"); Bytes addr; addr.push_back(3); addr.integer(0x4000, 8); f.info.expression(addr);
    f.info.uleb(4); f.info.string("register_value"); f.ref("int"); Bytes reg; reg.push_back(0x90); reg.uleb(128); f.info.expression(reg);
    f.info.uleb(4); f.info.string("constant"); f.ref("int"); Bytes value; value.push_back(0x11); value.sleb(-9); value.push_back(0x9f); f.info.expression(value);
    f.info.uleb(4); f.info.string("piece"); f.ref("int"); Bytes piece; piece.push_back(0x50); piece.push_back(0x93); piece.uleb(4); f.info.expression(piece);
    f.info.uleb(15); f.info.string("ranged"); f.ref("int"); f.info.integer(0, 4);
    f.locations.integer(0, 8); f.locations.integer(0x20, 8); const auto loc = expression(0x91, -64);
    f.locations.integer(loc.size(), 2); f.locations.insert(f.locations.end(), loc.begin(), loc.end()); f.locations.integer(0, 8); f.locations.integer(0, 8);
    f.mark("int"); f.info.uleb(5); f.info.string("Int32"); f.info.push_back(4); f.info.push_back(5);
    f.mark("node"); f.info.uleb(6); f.info.string("Node"); f.info.push_back(16);
    f.info.uleb(7); f.info.string("value"); f.ref("int"); f.info.push_back(0);
    f.info.uleb(7); f.info.string("next"); f.ref("node_pointer"); f.info.push_back(8); f.info.push_back(0);
    f.mark("node_pointer"); f.info.uleb(8); f.ref("node");
    f.mark("array"); f.info.uleb(9); f.ref("int"); f.info.uleb(10); f.info.push_back(3); f.info.push_back(0);
    f.mark("enum"); f.info.uleb(11); f.info.string("Color"); f.ref("int"); f.info.push_back(4);
    f.info.uleb(12); f.info.string("Negative"); f.info.sleb(-1); f.info.uleb(12); f.info.string("Positive"); f.info.sleb(2); f.info.push_back(0);
    f.mark("declaration"); f.info.uleb(13); f.info.string("Declared");
    f.info.uleb(14); f.ref("declaration"); f.info.integer(0x2000, 8); f.info.integer(8, 4); f.ref("int");
    f.info.push_back(0); f.finish(); f.line = lineV4(); return f;
}

Fixture fixtureV5() {
    Fixture f;
    abbrev(f.abbrevBytes, 1, 0x11, true, {{3, 0x25}, {0x72, 0x17}, {0x73, 0x17}, {0x74, 0x17}, {0x8c, 0x17}, {0x13, 0x0b}, {0x10, 0x17}});
    abbrev(f.abbrevBytes, 2, 0x2e, true, {{3, 0x25}, {0x11, 0x29}, {0x12, 6}, {0x55, 0x23}, {0x49, 0x13}});
    abbrev(f.abbrevBytes, 3, 5, false, {{3, 0x25}, {0x49, 0x13}, {2, 0x22}});
    // implicit_const belongs to the abbreviation, not the DIE byte stream.
    f.abbrevBytes.uleb(4); f.abbrevBytes.uleb(0x24); f.abbrevBytes.push_back(0);
    f.abbrevBytes.uleb(3); f.abbrevBytes.uleb(0x25); f.abbrevBytes.uleb(0x0b); f.abbrevBytes.uleb(0x21); f.abbrevBytes.sleb(4);
    f.abbrevBytes.uleb(0x3e); f.abbrevBytes.uleb(0x21); f.abbrevBytes.sleb(5); f.abbrevBytes.push_back(0); f.abbrevBytes.push_back(0); f.abbrevBytes.push_back(0);
    std::vector<u64> offsets;
    for (const auto* text : {"unit.c", "indexed_entry", "indexed_param", "Int32"}) { offsets.push_back(f.strings.size()); f.strings.string(text); }
    f.stringOffsets.integer(4 + offsets.size() * 4, 4); f.stringOffsets.integer(5, 2); f.stringOffsets.integer(0, 2);
    for (auto offset : offsets) f.stringOffsets.integer(offset, 4);
    f.addresses.integer(4 + 2 * 8, 4); f.addresses.integer(5, 2); f.addresses.push_back(8); f.addresses.push_back(0);
    f.addresses.integer(0x3000, 8); f.addresses.integer(0x3040, 8);
    auto listHeader = [](Bytes& bytes) { bytes.integer(0, 4); bytes.integer(5, 2); bytes.push_back(8); bytes.push_back(0); bytes.integer(1, 4); bytes.integer(4, 4); };
    listHeader(f.rangeLists); f.rangeLists.push_back(2); f.rangeLists.uleb(0); f.rangeLists.uleb(1); f.rangeLists.push_back(0); f.rangeLists.patch(0, f.rangeLists.size() - 4, 4);
    listHeader(f.locationLists); f.locationLists.push_back(2); f.locationLists.uleb(0); f.locationLists.uleb(1); f.locationLists.expression(expression(0x91, -129)); f.locationLists.push_back(0); f.locationLists.patch(0, f.locationLists.size() - 4, 4);
    f.info.integer(0, 4); f.info.integer(5, 2); f.info.push_back(1); f.info.push_back(8); f.info.integer(0, 4);
    f.info.uleb(1); f.info.push_back(0); f.info.integer(8, 4); f.info.integer(8, 4); f.info.integer(12, 4); f.info.integer(12, 4); f.info.push_back(2); f.info.integer(0, 4);
    f.mark("function"); f.info.uleb(2); f.info.push_back(1); f.info.push_back(0); f.info.integer(64, 4); f.info.uleb(0); f.ref("int");
    f.info.uleb(3); f.info.push_back(2); f.ref("int"); f.info.uleb(0); f.info.push_back(0);
    f.mark("int"); f.info.uleb(4); f.info.push_back(3); f.info.push_back(0); f.finish();
    f.lineStrings.string("/src"); const auto zero = f.lineStrings.size(); f.lineStrings.string("zero.c"); const auto one = f.lineStrings.size(); f.lineStrings.string("one.c");
    f.line.integer(0, 4); f.line.integer(5, 2); f.line.push_back(8); f.line.push_back(0);
    const auto length = f.line.size(); f.line.integer(0, 4); const auto header = f.line.size();
    f.line.push_back(1); f.line.push_back(1); f.line.push_back(1); f.line.push_back(0xfb); f.line.push_back(14); f.line.push_back(13);
    for (u8 count : {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1}) f.line.push_back(count);
    f.line.push_back(1); f.line.uleb(1); f.line.uleb(0x1f); f.line.uleb(1); f.line.integer(0, 4);
    f.line.push_back(2); f.line.uleb(1); f.line.uleb(0x1f); f.line.uleb(2); f.line.uleb(0x0f); f.line.uleb(2);
    f.line.integer(zero, 4); f.line.uleb(0); f.line.integer(one, 4); f.line.uleb(0);
    f.line.patch(length, f.line.size() - header, 4);
    f.line.push_back(0); f.line.uleb(9); f.line.push_back(2); f.line.integer(0x3000, 8); f.line.push_back(1);
    f.line.push_back(4); f.line.uleb(0); f.line.push_back(2); f.line.uleb(4); f.line.push_back(1); f.line.push_back(2); f.line.uleb(4);
    f.line.push_back(0); f.line.uleb(1); f.line.push_back(1); f.line.patch(0, f.line.size() - 4, 4); return f;
}

const DwarfVariable& variable(const DwarfReport& report, const std::string& name) {
    auto result = std::find_if(report.variables.begin(), report.variables.end(), [&](const auto& value) { return value.name == name; });
    require(result != report.variables.end(), "variable exists: " + name); return *result;
}
const DwarfFunction& function(const DwarfReport& report, const std::string& name, Address entry) {
    auto result = std::find_if(report.functions.begin(), report.functions.end(), [&](const auto& value) { return value.name == name && value.entry == entry; });
    require(result != report.functions.end(), "function exists: " + name); return *result;
}
const DwarfType& type(const DwarfReport& report, const std::string& name) {
    auto result = std::find_if(report.types.begin(), report.types.end(), [&](const auto& value) { return value.name == name; });
    require(result != report.types.end(), "type exists: " + name); return *result;
}
void validatedTypes(const DwarfReport& report) {
    std::string text = "MINT_TYPES 1 " + std::to_string(report.addressSize) + '\n';
    for (const auto& value : report.types) {
        require(!value.declaration.empty(), "supported type is importable: " + value.name);
        text += value.declaration + '\n';
    }
    DataTypeManager manager(report.addressSize); const auto status = manager.deserialize(text);
    require(status.ok(), "all imported declarations validate together: " + status.message());
    for (const auto& value : report.types) {
        DataTypeLayout layout; require(manager.resolve(value.name, &layout).ok(), "imported name resolves");
        require(layout.size == value.byteSize, "imported storage exactly matches DWARF size");
    }
}
void rejectUnchanged(const Fixture& fixture, const std::string& name) {
    DwarfReport report; report.units = 77; report.warnings.push_back("sentinel");
    const auto status = readDwarf(fixture.sections(), &report);
    require(!status.ok(), name + " rejects malformed input");
    require(report.units == 77 && report.warnings == std::vector<std::string>{"sentinel"}, name + " failure is atomic");
}

void synthetic() {
    auto fixture = fixtureV4(); DwarfReport report;
    auto status = readDwarf(fixture.sections(), &report); require(status.ok(), "DWARF4 synthetic parse: " + status.message());
    require(report.units == 1 && report.addressSize == 8 && report.dies >= 20, "DIE/unit inventory");
    const auto& entry = function(report, "fixture_entry", 0x1000);
    require(entry.ranges.size() == 1 && entry.ranges[0].high == 0x1020, "constant high_pc offset");
    require(entry.prototype == "int32_t(int32_t value)", "typed prototype");
    require(entry.frameBaseExpression == "DW_OP_call_frame_cfa", "CFA retained symbolic, not mistaken for SP");
    require(!function(report, "Declared", 0x2000).declaration, "declaration flag is not inherited into definition");
    const auto& parameter = variable(report, "value");
    require(parameter.parameter && parameter.scope == 0x1000, "parameter scope identity");
    require(parameter.location.kind == DwarfLocation::Kind::kFrameBaseOffset && parameter.location.offset == -32, "negative fbreg offset");
    const auto& local = variable(report, "local").location;
    require(local.kind == DwarfLocation::Kind::kRegisterOffset && local.reg == 35 && local.offset == -128, "bregx number and signed SLEB offset");
    require(variable(report, "global").location.address == 0x4000, "absolute variable address");
    require(variable(report, "register_value").location.kind == DwarfLocation::Kind::kRegister && variable(report, "register_value").location.reg == 128, "regx ULEB number");
    require(variable(report, "constant").location.kind == DwarfLocation::Kind::kValue, "stack_value is not editable memory");
    require(variable(report, "piece").location.kind == DwarfLocation::Kind::kComposite && variable(report, "piece").location.pieces.size() == 1 &&
        variable(report, "piece").location.pieces[0].bitSize == 32 && variable(report, "piece").location.pieces[0].available, "piece expression retains exact composite register storage");
    const auto& ranged = variable(report, "ranged");
    require(ranged.locations.size() == 1 && ranged.locations[0].range.low == 0x1000 && ranged.locations[0].range.high == 0x1020 && ranged.locations[0].location.offset == -64, "DWARF4 location list relative to CU base");
    require(type(report, "Node").declaration == "Node=struct{value:Int32@0;next:Node*@8}", "exact recursive struct layout");
    require(type(report, "Color").declaration == "Color=enum:Int32{Negative=-1;Positive=2}", "signed enum declaration");
    require(std::any_of(report.types.begin(), report.types.end(), [](const auto& value) { return value.byteSize == 12 && value.declaration.find("Int32[3]") != std::string::npos; }), "fixed array type");
    validatedTypes(report);
    require(report.sources.size() == 5, "two complete line sequences");
    require(report.sources[0].address == 0x1000 && report.sources[1].address == 0x1004 && report.sources[1].line == 3, "line VM address and signed line advance");
    require(report.sources[2].endSequence && report.sources[2].address == 0x1008 && report.sources[3].address == 0x800 && report.sources[4].endSequence, "line sequence ordering and boundaries retained");
    require(report.sources[0].file == "src/fixture.c", "relative compilation directory is not duplicated");
    require(dwarfReportText(report).find("frame-base -32") != std::string::npos, "report display contains signed stack expression");

    for (i64 signedOffset : {i64(0), i64(63), i64(64), i64(-1), i64(-64), i64(-65), i64(-129), std::numeric_limits<i64>::min(), std::numeric_limits<i64>::max()}) {
        auto variant = fixtureV4(expression(0x91, signedOffset)); DwarfReport decoded;
        const auto result = readDwarf(variant.sections(), &decoded); require(result.ok(), "all valid SLEB offsets parse");
        require(variable(decoded, "value").location.offset == signedOffset, "SLEB sign/range round trip");
    }
    Bytes registerOffset; registerOffset.push_back(0x7f); registerOffset.sleb(-256);
    auto registerFixture = fixtureV4(registerOffset); require(readDwarf(registerFixture.sections(), &report).ok(), "breg15 expression parse");
    require(variable(report, "value").location.reg == 15 && variable(report, "value").location.offset == -256, "breg0..31 signed offset");
    Bytes malformedSleb; malformedSleb.push_back(0x91); for (unsigned i = 0; i < 10; ++i) malformedSleb.push_back(0x80);
    auto badExpression = fixtureV4(malformedSleb); require(readDwarf(badExpression.sections(), &report).ok(), "unsupported expression is nonfatal");
    require(variable(report, "value").location.kind == DwarfLocation::Kind::kUnknown, "unterminated SLEB expression not invented");

    Bytes composite; composite.push_back(0x50); composite.push_back(0x93); composite.uleb(4);
    composite.push_back(0x91); composite.sleb(-16); composite.push_back(0x9d); composite.uleb(12); composite.uleb(3);
    auto compositeFixture = fixtureV4(composite); require(readDwarf(compositeFixture.sections(), &report).ok(), "register/stack bit-piece composite parse");
    const auto& pieces = variable(report, "value").location;
    require(pieces.kind == DwarfLocation::Kind::kComposite && pieces.pieces.size() == 2 && pieces.pieces[1].bitSize == 12 && pieces.pieces[1].bitOffset == 3 && pieces.needsRuntime, "composite exact piece widths/offsets and runtime dependence");
    Bytes unavailable; unavailable.push_back(0x93); unavailable.uleb(4);
    auto unavailableFixture = fixtureV4(unavailable); require(readDwarf(unavailableFixture.sections(), &report).ok() && !variable(report, "value").location.pieces[0].available, "optimized-out piece remains unavailable, never zero fabricated");
    Bytes runtime; runtime.push_back(0x9c); runtime.push_back(0x23); runtime.uleb(8); runtime.push_back(0x06);
    auto runtimeFixture = fixtureV4(runtime); require(readDwarf(runtimeFixture.sections(), &report).ok(), "CFA/dereference symbolic parse");
    require(variable(report, "value").location.kind == DwarfLocation::Kind::kSymbolic && variable(report, "value").location.needsRuntime && variable(report, "value").location.expression.find("load64") != std::string::npos, "runtime dereference is symbolic, not static memory lookup");
    Bytes entryValue; entryValue.push_back(0xa3); entryValue.uleb(1); entryValue.push_back(0x50); entryValue.push_back(0x9f);
    auto entryFixture = fixtureV4(entryValue); require(readDwarf(entryFixture.sections(), &report).ok() && variable(report, "value").location.kind == DwarfLocation::Kind::kValue && variable(report, "value").location.needsRuntime, "entry_value retains historical runtime requirement");
    Bytes implicit; implicit.push_back(0x9e); implicit.uleb(2); implicit.push_back(0xaa); implicit.push_back(0x55);
    auto implicitFixture = fixtureV4(implicit); require(readDwarf(implicitFixture.sections(), &report).ok() && variable(report, "value").location.kind == DwarfLocation::Kind::kValue && !variable(report, "value").location.needsRuntime, "implicit bytes represented as non-writable value");
    auto packedFixture = fixtureV4();
    // Change Node's second member offset from8to4 and its declared extent16to12.
    packedFixture.info.patch(packedFixture.marks.at("node") + 1 + 5, 12, 1);
    const auto nodePointer = packedFixture.marks.at("node_pointer"); packedFixture.info.patch(nodePointer - 2, 4, 1);
    require(readDwarf(packedFixture.sections(), &report).ok() && type(report, "Node").declaration.find("Node=packed{") == 0, "unaligned exact DWARF struct uses packed storage DSL");
    validatedTypes(report);

    auto indexed = fixtureV5(); status = readDwarf(indexed.sections(), &report); require(status.ok(), "DWARF5 indexed parse: " + status.message());
    const auto& indexedEntry = function(report, "indexed_entry", 0x3000);
    require(indexedEntry.ranges.size() == 1 && indexedEntry.ranges[0].high == 0x3040, "rnglistx, addrx and indexed contribution bases");
    require(indexedEntry.prototype == "int32_t(int32_t indexed_param)", "strx and implicit_const correct byte consumption");
    const auto& indexedParameter = variable(report, "indexed_param");
    require(indexedParameter.locations.size() == 1 && indexedParameter.locations[0].location.offset == -129 && indexedParameter.locations[0].range.low == 0x3000, "loclistx indexed range and signed offset");
    validatedTypes(report);
    require(report.sources.size() == 3 && report.sources[0].file == "/src/one.c" && report.sources[1].file == "/src/zero.c" && report.sources[2].endSequence, "DWARF5 zero-based file table and initial file1 register");
    auto crossContribution = indexed; crossContribution.addresses.resize(16); crossContribution.addresses.patch(0, 12, 4);
    crossContribution.addresses.integer(12, 4); crossContribution.addresses.integer(5, 2); crossContribution.addresses.push_back(8); crossContribution.addresses.push_back(0); crossContribution.addresses.integer(0x5000, 8);
    // The original unit asks for index1; only index0 belongs to its contribution.
    status = readDwarf(crossContribution.sections(), &report); require(!status.ok(), "address index cannot spill into another contribution");

    auto invalidReference = fixtureV4(); invalidReference.info.patch(invalidReference.marks.at("returnRef"), 5, 4);
    status = readDwarf(invalidReference.sections(), &report); require(status.ok(), "invalid DIE target is a partial report, not a crash");
    require(function(report, "fixture_entry", 0x1000).prototype.empty(), "bad type reference does not become void");
    auto outsideReference = fixtureV4(); outsideReference.info.patch(outsideReference.marks.at("returnRef"), outsideReference.info.size() + 5, 4); rejectUnchanged(outsideReference, "CU-relative reference bound");
    auto truncated = fixtureV4(); truncated.info.pop_back(); rejectUnchanged(truncated, "truncated CU");
    auto badLength = fixtureV4(); badLength.info.patch(0, 0xfffffff0U, 4); rejectUnchanged(badLength, "reserved initial length");
    auto badAbbrev = fixtureV4(); badAbbrev.info.at(badAbbrev.marks.at("root")) = 127; rejectUnchanged(badAbbrev, "unknown abbreviation");
    auto badString = fixtureV4(); badString.abbrevBytes.clear();
    // Independently truncated abbreviation attributes.
    badString.abbrevBytes.push_back(1); badString.abbrevBytes.push_back(0x11); badString.abbrevBytes.push_back(1); badString.abbrevBytes.push_back(3); rejectUnchanged(badString, "truncated abbreviation");
    auto unterminatedChildren = fixtureV4(); unterminatedChildren.info.pop_back(); unterminatedChildren.info.patch(0, unterminatedChildren.info.size() - 4, 4); rejectUnchanged(unterminatedChildren, "unclosed root children");
    auto missingEnd = fixtureV4(); missingEnd.line.resize(missingEnd.line.size() - 3); missingEnd.line.patch(0, missingEnd.line.size() - 4, 4); rejectUnchanged(missingEnd, "unterminated line sequence");
    auto reversedLoc = fixtureV4(); reversedLoc.locations.patch(0, 0x30, 8); rejectUnchanged(reversedLoc, "reversed location range");
    auto unknownUnit = fixtureV4(); unknownUnit.info.patch(4, 6, 2); status = readDwarf(unknownUnit.sections(), &report);
    require(status.ok() && report.units == 0 && report.partial && report.functions.empty(), "future DWARF version is explicitly skipped");
    DwarfSections empty; require(readDwarf(empty, &report).code() == ErrorCode::kNotFound, "missing DWARF distinguished from malformed");
    require(!readDwarf(fixture.sections(), nullptr).ok(), "null output rejected");
    // Every truncation is safe and never changes the caller on failure. A
    // complete shorter unit can legitimately be accepted; no crash is allowed.
    for (size_t length = 0; length < fixture.info.size(); ++length) {
        auto sections = fixture.sections(); sections.info = sections.info.subview(0, length);
        DwarfReport sentinel; sentinel.units = 99;
        const auto result = readDwarf(sections, &sentinel);
        require(result.ok() || sentinel.units == 99, "truncation failure atomicity");
    }
    std::cout << "DWARF synthetic: " << checks << " checks; passed\n";
}

constexpr const char* kRealFixture = R"C(
typedef enum MintColor { MintRed = -1, MintGreen = 2 } MintColor;
typedef struct MintNode { int value; struct MintNode* next; } MintNode;
MintNode mint_debug_global = {7, 0};
int mint_debug_array[3] = {1, 2, 3};
MintColor mint_debug_color = MintRed;
__attribute__((noinline)) int mint_debug_entry(int value, MintNode* node) {
    int local = value + mint_debug_array[1];
    node->value = local;
    return node->value + mint_debug_color;
}
)C";
void real(const std::string& path) {
    MappedFile file; auto status = file.open(path); require(status.ok(), "real fixture mapped: " + status.message());
    ElfImage image; status = image.load(file.view()); require(status.ok(), "real fixture ELF loaded: " + status.message());
    DwarfReport report; status = readDwarf(image, &report); require(status.ok(), "real clang DWARF parsed: " + status.message());
    require(report.units > 0 && report.dies > 10 && report.addressSize == 8, "real CU inventory");
    const auto found = std::find_if(report.functions.begin(), report.functions.end(), [](const auto& value) { return value.name == "mint_debug_entry" && value.entry != kNoAddress; });
    require(found != report.functions.end(), "real function name/range found");
    require(!found->prototype.empty() && found->prototype.find("int32_t") != std::string::npos && found->prototype.find("MintNode") != std::string::npos && found->prototype.find('*') != std::string::npos, "real typed function prototype");
    require(!found->frameBaseExpression.empty(), "real frame base retained");
    require(std::any_of(report.types.begin(), report.types.end(), [](const auto& value) { return value.name.find("MintNode") == 0 && value.byteSize == 16 && value.declaration.find("@8") != std::string::npos; }), "real recursive structure exact field offsets");
    require(type(report, "MintColor").byteSize == 4, "real enum imported");
    validatedTypes(report);
    const auto& parameter = variable(report, "value");
    require(parameter.parameter && parameter.scope == found->entry && !parameter.location.expression.empty(), "real parameter type/scope/location");
    const auto& local = variable(report, "local");
    require(local.scope == found->entry && local.location.kind != DwarfLocation::Kind::kUnknown, "unoptimized real local has supported simple location");
    require(!report.sources.empty() && std::any_of(report.sources.begin(), report.sources.end(), [](const auto& row) { return !row.endSequence && row.line && row.file.find("fixture.c") != std::string::npos; }), "real source line mapping");
    require(std::any_of(report.sources.begin(), report.sources.end(), [](const auto& row) { return row.endSequence; }), "real line sequence closure");
    const auto& global = variable(report, "mint_debug_global"); require(global.location.kind == DwarfLocation::Kind::kAddress && global.location.address != kNoAddress, "real global static address");
    for (const auto& warning : report.warnings) std::cout << "warning: " << warning << '\n';
    std::cout << "DWARF real clang fixture: " << report.units << " units, " << report.dies << " DIEs, " << report.types.size() << " types, " << report.variables.size() << " variables, " << report.sources.size() << " source rows; " << checks << " checks; passed\n";
}
}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--emit-fixture") { std::cout << kRealFixture; return 0; }
    if (argc == 3 && std::string(argv[1]) == "--real") { real(argv[2]); return 0; }
    require(argc == 1, "usage: mint_dwarf_test [--emit-fixture | --real ELF]"); synthetic();
}
