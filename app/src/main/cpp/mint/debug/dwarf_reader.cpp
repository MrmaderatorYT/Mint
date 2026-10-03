#include "mint/debug/dwarf_reader.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include <cstring>
#include <zlib.h>

#include "mint/loader/elf_image.h"
#include "mint/types/data_type_manager.h"
#include "mint/analysis/user_prototype.h"

namespace mint {
namespace {

// Encodings and semantics follow DWARF 5, Chapters 2/6/7 and its published
// errata (including indirect -> implicit_const). DWARF 2's ref_addr uses the
// address width; later versions use the DWARF32/64 offset width.
constexpr u64 kMaxSection = 128ULL * 1024 * 1024;
constexpr size_t kMaxDies = 200000, kMaxAttrs = 1000000, kMaxUnits = 4096;
constexpr size_t kMaxRows = 200000, kMaxTypes = 4096, kMaxText = 32 * 1024 * 1024;
constexpr size_t kNoParent = std::numeric_limits<size_t>::max();
constexpr size_t kBadType = kNoParent - 1;
constexpr u64 kName = 0x03, kLocation = 0x02, kType = 0x49, kByteSize = 0x0b;
constexpr u64 kLowPc = 0x11, kHighPc = 0x12, kRanges = 0x55, kEntryPc = 0x52;
constexpr u64 kStmtList = 0x10, kCompDir = 0x1b, kDeclaration = 0x3c;
constexpr u64 kEncoding = 0x3e, kMemberLocation = 0x38, kConstValue = 0x1c;
constexpr u64 kUpperBound = 0x2f, kLowerBound = 0x22, kCount = 0x37;
constexpr u64 kOrigin = 0x31, kSpecification = 0x47, kLinkage = 0x6e;
constexpr u64 kStrBase = 0x72, kAddrBase = 0x73, kRngBase = 0x74, kLocBase = 0x8c;
constexpr u64 kAlignment = 0x88, kBitSize = 0x0d, kBitOffset = 0x0c, kDataBitOffset = 0x6b;

bool typeTag(u64 tag) {
    return tag == 0x01 || tag == 0x02 || tag == 0x04 || tag == 0x0f || tag == 0x10 ||
           tag == 0x13 || tag == 0x16 || tag == 0x17 || tag == 0x24 || tag == 0x26 ||
           tag == 0x35 || tag == 0x37 || tag == 0x3b || tag == 0x42 || tag == 0x47;
}

Status malformed(const std::string& why) { return Status::error(ErrorCode::kBadFormat, "DWARF: " + why); }
Status tooLarge() { return Status::error(ErrorCode::kTooLarge, "DWARF resource budget exceeded"); }
std::string hex(u64 value) { std::ostringstream s; s << std::hex << value; return s.str(); }
bool add(u64 left, u64 right, u64* out) {
    if (right > std::numeric_limits<u64>::max() - left) return false;
    *out = left + right; return true;
}

struct Cursor {
    ByteView view;
    u64 pos = 0, end = 0;
    explicit Cursor(ByteView v, u64 start = 0) : view(v), pos(start), end(v.size()) {}
    bool integer(unsigned bytes, u64* value) {
        if (bytes > 8 || pos > end || bytes > end - pos) return false;
        *value = 0;
        for (unsigned i = 0; i < bytes; ++i) *value |= u64(view.data()[pos++]) << (i * 8);
        return true;
    }
    bool byte(u8* value) { u64 n = 0; if (!integer(1, &n)) return false; *value = static_cast<u8>(n); return true; }
    bool uleb(u64* value) {
        *value = 0;
        for (unsigned i = 0; i < 10; ++i) {
            u8 b = 0; if (!byte(&b) || (i == 9 && (b & 0x7f) > 1)) return false;
            *value |= u64(b & 0x7f) << (7 * i);
            if (!(b & 0x80)) return true;
        }
        return false;
    }
    bool sleb(i64* value) {
        u64 bits = 0;
        for (unsigned i = 0; i < 10; ++i) {
            u8 b = 0;
            if (!byte(&b) || (i == 9 && (b & 0x7f) != 0 && (b & 0x7f) != 0x7f)) return false;
            bits |= u64(b & (i == 9 ? 1 : 0x7f)) << (i * 7);
            if (!(b & 0x80)) {
                if (i < 9 && (b & 0x40)) bits |= ~u64(0) << (i * 7 + 7);
                *value = static_cast<i64>(bits); return true;
            }
        }
        return false;
    }
    bool string(std::string* value) {
        if (pos > end) return false;
        const auto start = pos;
        while (pos < end && view.data()[pos] && pos - start <= 4096) ++pos;
        if (pos == end || pos - start > 4096) return false;
        value->assign(reinterpret_cast<const char*>(view.data() + start), static_cast<size_t>(pos - start));
        ++pos; return true;
    }
    bool block(u64 length, ByteView* value) {
        if (length > 65536 || pos > end || length > end - pos) return false;
        *value = view.subview(pos, length); pos += length; return true;
    }
};

bool initialLength(Cursor* cursor, u64* finish, u8* offsetSize) {
    u64 length = 0;
    if (!cursor->integer(4, &length)) return false;
    *offsetSize = 4;
    if (length == 0xffffffffU) { *offsetSize = 8; if (!cursor->integer(8, &length)) return false; }
    else if (length >= 0xfffffff0U) return false;
    return add(cursor->pos, length, finish) && *finish <= cursor->end;
}

struct Attribute {
    enum Kind { kUnsigned, kSigned, kAddress, kString, kReference, kBlock,
                kStringIndex, kAddressIndex, kRangeIndex, kLocationIndex, kOffset, kTypeSignature, kUnsupported } kind = kUnsigned;
    u64 value = 0, form = 0;
    i64 signedValue = 0;
    std::string text;
    ByteView bytes;
};
struct AbbrevAttr { u64 name = 0, form = 0; i64 implicit = 0; };
struct Abbrev { u64 tag = 0; bool children = false; std::vector<AbbrevAttr> attrs; };
using Abbrevs = std::map<u64, Abbrev>;
struct Unit {
    u64 start = 0, end = 0, abbrev = 0;
    u8 addressSize = 8, offsetSize = 4;
    u16 version = 0;
    size_t root = kNoParent;
    u64 stringsBase = kNoAddress, addressesBase = kNoAddress, rangesBase = kNoAddress, locationsBase = kNoAddress;
    Address low = 0;
    std::string directory;
    u64 splitId = 0;
    u64 signature = 0, typeOffset = 0;
};
struct Die {
    u64 offset = 0, tag = 0;
    size_t unit = 0, parent = kNoParent;
    std::map<u64, Attribute> attrs;
    std::vector<size_t> children;
};
struct Contribution {
    u64 base = 0, data = 0, end = 0, entries = 0;
    u8 offsetSize = 4, addressSize = 0;
};

class Reader {
public:
    Reader(const DwarfSections& sections, DwarfReport* report) : s_(sections), report_(*report) {}
    Status run();
private:
    void warn(const std::string& message) {
        report_.partial = true;
        if (report_.warnings.size() < 256 && warnings_.insert(message).second) report_.warnings.push_back(message);
    }
    bool textBudget(size_t bytes) { if (bytes > kMaxText - textBytes_) return false; textBytes_ += bytes; return true; }
    Status abbreviations(u64 offset, Abbrevs* result);
    Status form(Cursor* cursor, const Unit& unit, u64 formCode, i64 implicit, Attribute* value, unsigned depth = 0);
    Status parseUnits();
    const Attribute* attribute(size_t die, u64 name, unsigned depth = 0) const;
    bool number(size_t die, u64 name, u64* value) const;
    bool signedNumber(size_t die, u64 name, i64* value) const;
    std::string string(size_t die, u64 name);
    bool address(size_t die, u64 name, Address* value);
    bool indexedAddress(const Unit& unit, u64 index, Address* value);
    const Contribution* contribution(unsigned section, const Unit& unit, u64 base, bool exactBase = true);
    bool listOffset(const Unit& unit, const Attribute& attr, bool locations, u64* offset);
    Status ranges(size_t die, std::vector<DwarfRange>* out);
    DwarfLocation expression(ByteView bytes, const Unit& unit);
    Status locations(size_t die, DwarfVariable* out);
    Status lineTable(const Unit& unit, u64 offset);
    Status buildReport();
    struct TypeInfo { std::string name, body, expression, cType; u64 size = 0; u32 alignment = 1; bool valid = false; };
    TypeInfo type(size_t die, unsigned depth = 0, bool behindPointer = false);
    std::string primitiveType(size_t die, u64 size) const;
    size_t referencedType(size_t die) const;
    std::string identifier(const std::string& name, const std::string& fallback) const;
    const DwarfSections& s_;
    DwarfReport& report_;
    std::vector<Unit> units_;
    std::vector<Die> dies_;
    std::map<u64, size_t> byOffset_;
    std::map<u64, u64> typeSignatures_;
    std::map<u64, Abbrevs> abbreviations_;
    std::map<size_t, TypeInfo> typeInfos_;
    std::map<size_t, std::string> typeNames_;
    std::set<size_t> activeTypes_;
    std::set<std::string> warnings_;
    std::set<u64> lineTables_;
    std::map<unsigned, std::vector<Contribution>> contributions_;
    size_t textBytes_ = 0, attributes_ = 0, seenUnits_ = 0, rangeOperations_ = 0, locationOperations_ = 0;
    unsigned expressionDepth_ = 0;
};

Status Reader::abbreviations(u64 offset, Abbrevs* out) {
    Cursor cursor(s_.abbrev, offset);
    for (size_t n = 0; n < 65536; ++n) {
        u64 code = 0;
        if (!cursor.uleb(&code)) return malformed("truncated abbreviation code");
        if (!code) return Status::success();
        Abbrev abbrev; u8 children = 0;
        if (!cursor.uleb(&abbrev.tag) || !abbrev.tag || !cursor.byte(&children) || children > 1)
            return malformed("invalid abbreviation tag/children");
        abbrev.children = children != 0;
        for (unsigned i = 0; i < 256; ++i) {
            AbbrevAttr attr;
            if (!cursor.uleb(&attr.name) || !cursor.uleb(&attr.form)) return malformed("truncated abbreviation attributes");
            if (!attr.name && !attr.form) break;
            if (!attr.name || !attr.form) return malformed("invalid abbreviation attribute terminator");
            if (attr.form == 0x21 && !cursor.sleb(&attr.implicit)) return malformed("truncated implicit_const");
            abbrev.attrs.push_back(attr);
            if (i == 255) return tooLarge();
        }
        if (!out->emplace(code, std::move(abbrev)).second) return malformed("duplicate abbreviation code");
    }
    return tooLarge();
}

Status Reader::form(Cursor* cursor, const Unit& unit, u64 code, i64 implicit, Attribute* out, unsigned depth) {
    if (depth > 8) return malformed("too many indirect attribute forms");
    out->form = code;
    unsigned width = 0;
    switch (code) {
        case 0x01: out->kind = Attribute::kAddress; width = unit.addressSize; break;
        case 0x05: width = 2; break; case 0x06: width = 4; break; case 0x07: width = 8; break;
        case 0x0b: case 0x0c: width = 1; break;
        case 0x0f: if (!cursor->uleb(&out->value)) return malformed("invalid udata"); return Status::success();
        case 0x0d: out->kind = Attribute::kSigned; if (!cursor->sleb(&out->signedValue)) return malformed("invalid sdata"); return Status::success();
        case 0x08: out->kind = Attribute::kString; if (!cursor->string(&out->text)) return malformed("invalid inline string"); break;
        case 0x0e: case 0x1f: {
            u64 offset = 0;
            if (!cursor->integer(unit.offsetSize, &offset)) return malformed("truncated string offset");
            Cursor strings(code == 0x1f ? s_.lineStrings : s_.strings, offset);
            out->kind = Attribute::kString;
            if (!strings.string(&out->text)) return malformed("string offset is out of bounds or unterminated");
            break;
        }
        case 0x10: out->kind = Attribute::kReference; width = unit.version == 2 ? unit.addressSize : unit.offsetSize; break;
        case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: {
            const unsigned sizes[] = {1, 2, 4, 8};
            if (code == 0x15 ? !cursor->uleb(&out->value) : !cursor->integer(sizes[code - 0x11], &out->value))
                return malformed("truncated CU-relative reference");
            if (!add(unit.start, out->value, &out->value) || out->value >= unit.end)
                return malformed("CU-relative reference exceeds compilation unit");
            out->kind = Attribute::kReference; return Status::success();
        }
        case 0x16: {
            u64 actual = 0; i64 constant = 0;
            if (!cursor->uleb(&actual) || (actual == 0x21 && !cursor->sleb(&constant))) return malformed("invalid indirect form");
            return form(cursor, unit, actual, constant, out, depth + 1);
        }
        case 0x17: out->kind = Attribute::kOffset; width = unit.offsetSize; break;
        case 0x19: out->value = 1; return Status::success();
        case 0x21: out->kind = Attribute::kSigned; out->signedValue = implicit; return Status::success();
        case 0x1a: case 0x1b: case 0x22: case 0x23:
            out->kind = code == 0x1a ? Attribute::kStringIndex : code == 0x1b ? Attribute::kAddressIndex :
                        code == 0x22 ? Attribute::kLocationIndex : Attribute::kRangeIndex;
            if (!cursor->uleb(&out->value)) return malformed("invalid indexed form"); return Status::success();
        case 0x25: case 0x26: case 0x27: case 0x28:
            out->kind = Attribute::kStringIndex; width = static_cast<unsigned>(code - 0x24); break;
        case 0x29: case 0x2a: case 0x2b: case 0x2c:
            out->kind = Attribute::kAddressIndex; width = static_cast<unsigned>(code - 0x28); break;
        case 0x03: case 0x04: case 0x09: case 0x0a: case 0x18: {
            u64 length = 0;
            const bool valid = code == 0x09 || code == 0x18 ? cursor->uleb(&length) :
                cursor->integer(code == 0x03 ? 2 : code == 0x04 ? 4 : 1, &length);
            out->kind = Attribute::kBlock;
            if (!valid || !cursor->block(length, &out->bytes)) return malformed("invalid block/exprloc length");
            return Status::success();
        }
        case 0x1e: {
            out->kind = Attribute::kUnsupported;
            if (cursor->pos > cursor->end || 16 > cursor->end - cursor->pos) return malformed("truncated data16");
            cursor->pos += 16; return Status::success();
        }
        case 0x20: out->kind = Attribute::kTypeSignature; width = 8; break;
        case 0x1c: case 0x24: case 0x1d:
            out->kind = Attribute::kUnsupported;
            width = code == 0x1c ? 4 : code == 0x24 ? 8 : unit.offsetSize;
            warn("Supplementary/signature references require an external debug object and are not resolved."); break;
        // GNU indexed string/address forms use the same unsigned index payload.
        case 0x1f01: case 0x1f02:
            out->kind = code == 0x1f01 ? Attribute::kAddressIndex : Attribute::kStringIndex;
            if (!cursor->uleb(&out->value)) return malformed("invalid GNU indexed form"); return Status::success();
        case 0x1f20: case 0x1f21:
            out->kind = Attribute::kUnsupported; width = unit.offsetSize;
            warn("GNU supplementary debug-object references are not resolved."); break;
        default: return Status::error(ErrorCode::kUnsupported, "unsupported DWARF form 0x" + hex(code));
    }
    if (width && !cursor->integer(width, &out->value)) return malformed("truncated fixed-width attribute");
    if (!textBudget(out->text.size())) return tooLarge();
    return Status::success();
}

Status Reader::parseUnits() {
    Cursor all(s_.info);
    while (all.pos < all.end) {
        if (++seenUnits_ > kMaxUnits) return tooLarge();
        Unit unit; unit.start = all.pos;
        if (!initialLength(&all, &unit.end, &unit.offsetSize)) return malformed("invalid compilation-unit length");
        Cursor cursor = all; cursor.end = unit.end;
        u64 version = 0, abbrev = 0; u8 addressSize = 0, unitType = 1;
        if (!cursor.integer(2, &version)) return malformed("truncated compilation-unit version");
        if (version < 2 || version > 5) { warn("Unsupported DWARF unit version " + std::to_string(version) + "; unit skipped."); all.pos = unit.end; continue; }
        unit.version = static_cast<u16>(version);
        if (version == 5) {
            if (!cursor.byte(&unitType) || !cursor.byte(&addressSize) || !cursor.integer(unit.offsetSize, &abbrev))
                return malformed("truncated DWARF5 compilation-unit header");
            if (unitType == 2 || unitType == 6) {
                if (!cursor.integer(8, &unit.signature) || !cursor.integer(unit.offsetSize, &unit.typeOffset)) return malformed("truncated type-unit header");
            } else if (unitType == 4 || unitType == 5) {
                if (!cursor.integer(8, &unit.splitId)) return malformed("truncated split-unit header");
            }
        } else if (!cursor.integer(unit.offsetSize, &abbrev) || !cursor.byte(&addressSize)) return malformed("truncated compilation-unit header");
        if (addressSize != 4 && addressSize != 8) { warn("Unsupported DWARF address size; unit skipped."); all.pos = unit.end; continue; }
        if (unitType < 1 || unitType > 6 || ((unitType == 5 || unitType == 6) && !s_.split)) { warn("Split or unknown DWARF unit requires matching external data; unit skipped."); all.pos = unit.end; continue; }
        unit.addressSize = addressSize; unit.abbrev = abbrev;
        if (!abbreviations_.count(abbrev)) {
            if (abbreviations_.size() >= 128) return tooLarge();
            auto status = abbreviations(abbrev, &abbreviations_[abbrev]); if (!status.ok()) return status;
        }
        const auto& table = abbreviations_.at(abbrev);
        const size_t unitIndex = units_.size(), firstDie = dies_.size();
        units_.push_back(unit);
        std::vector<size_t> parents;
        bool unsupported = false;
        while (cursor.pos < cursor.end) {
            const u64 offset = cursor.pos; u64 code = 0;
            if (!cursor.uleb(&code)) return malformed("truncated DIE abbreviation code");
            if (!code) {
                if (parents.empty()) {
                    while (cursor.pos < cursor.end) { u8 padding = 0; if (!cursor.byte(&padding) || padding) return malformed("nonzero bytes after unit root"); }
                    break;
                }
                parents.pop_back(); continue;
            }
            const auto found = table.find(code);
            if (found == table.end()) return malformed("unknown DIE abbreviation code");
            if (dies_.size() >= kMaxDies || found->second.attrs.size() > kMaxAttrs - attributes_) return tooLarge();
            Die die; die.offset = offset; die.tag = found->second.tag; die.unit = unitIndex;
            die.parent = parents.empty() ? kNoParent : parents.back();
            for (const auto& attr : found->second.attrs) {
                Attribute value;
                auto status = form(&cursor, unit, attr.form, attr.implicit, &value);
                if (status.code() == ErrorCode::kUnsupported) { warn(status.message() + "; containing unit skipped safely."); unsupported = true; break; }
                if (!status.ok()) return status;
                if (!die.attrs.emplace(attr.name, std::move(value)).second) return malformed("duplicate DIE attribute");
            }
            if (unsupported) break;
            attributes_ += die.attrs.size();
            const size_t index = dies_.size();
            if (die.parent != kNoParent) dies_[die.parent].children.push_back(index);
            else if (units_[unitIndex].root == kNoParent) units_[unitIndex].root = index;
            else return malformed("multiple roots in one compilation unit");
            byOffset_[offset] = index; dies_.push_back(std::move(die));
            if (found->second.children) { if (parents.size() >= 64) return tooLarge(); parents.push_back(index); }
        }
        if (unsupported) {
            for (size_t i = firstDie; i < dies_.size(); ++i) byOffset_.erase(dies_[i].offset);
            dies_.resize(firstDie); units_.pop_back();
        } else {
            if (!parents.empty()) return malformed("unterminated DIE children");
            if (units_[unitIndex].root == kNoParent) return malformed("compilation unit has no root DIE");
            Unit& saved = units_[unitIndex];
            number(saved.root, kStrBase, &saved.stringsBase); number(saved.root, kAddrBase, &saved.addressesBase);
            number(saved.root, kRngBase, &saved.rangesBase); number(saved.root, kLocBase, &saved.locationsBase);
            if (!saved.splitId) number(saved.root, 0x2131, &saved.splitId); // GNU DW_AT_dwo_id.
            if (saved.splitId) { report_.splitIds.push_back(saved.splitId); report_.splitAddressBases[saved.splitId] = saved.addressesBase; }
            if (saved.signature) {
                u64 target = 0;
                if (!add(saved.start, saved.typeOffset, &target) || target >= saved.end || !byOffset_.count(target) || !typeSignatures_.emplace(saved.signature, target).second) return malformed("invalid/duplicate DWARF type-unit signature");
            }
            if (s_.split) {
                if (saved.stringsBase == kNoAddress) saved.stringsBase = saved.version == 5 ? 8 : 0;
                if (saved.addressesBase == kNoAddress) {
                    const auto found = s_.splitAddressBases.find(saved.splitId);
                    saved.addressesBase = found != s_.splitAddressBases.end() ? found->second : s_.splitAddressesBase;
                }
            }
            saved.directory = string(saved.root, kCompDir); address(saved.root, kLowPc, &saved.low);
        }
        all.pos = unit.end;
    }
    return Status::success();
}

const Attribute* Reader::attribute(size_t die, u64 name, unsigned depth) const {
    if (die >= dies_.size() || depth >= 32) return nullptr;
    const auto& attrs = dies_[die].attrs;
    auto found = attrs.find(name);
    if (found != attrs.end()) return &found->second;
    if (name == kOrigin || name == kSpecification || name == kLowPc || name == kHighPc || name == kRanges || name == kLocation || name == kDeclaration) return nullptr;
    for (auto origin : {kOrigin, kSpecification}) {
        auto inherited = attrs.find(origin);
        if (inherited == attrs.end() || inherited->second.kind != Attribute::kReference) continue;
        auto target = byOffset_.find(inherited->second.value);
        if (target != byOffset_.end()) if (const auto* value = attribute(target->second, name, depth + 1)) return value;
    }
    return nullptr;
}
bool Reader::number(size_t die, u64 name, u64* out) const {
    const auto* value = attribute(die, name);
    if (!value) return false;
    if (value->kind == Attribute::kSigned) { if (value->signedValue < 0) return false; *out = static_cast<u64>(value->signedValue); return true; }
    if (value->kind != Attribute::kUnsigned && value->kind != Attribute::kOffset) return false;
    *out = value->value; return true;
}
bool Reader::signedNumber(size_t die, u64 name, i64* out) const {
    const auto* value = attribute(die, name);
    if (!value) return false;
    if (value->kind == Attribute::kSigned) { *out = value->signedValue; return true; }
    if (value->kind != Attribute::kUnsigned || value->value > static_cast<u64>(std::numeric_limits<i64>::max())) return false;
    *out = static_cast<i64>(value->value); return true;
}
std::string Reader::string(size_t die, u64 name) {
    const auto* value = attribute(die, name);
    if (!value) return {};
    if (value->kind == Attribute::kString) return value->text;
    if (value->kind != Attribute::kStringIndex) return {};
    const Unit& unit = units_[dies_[die].unit];
    u64 offset = 0, stringOffset = 0;
    if (unit.stringsBase == kNoAddress || value->value > (~u64(0) - unit.stringsBase) / unit.offsetSize)
        { warn("Indexed strings have no valid DW_AT_str_offsets_base."); return {}; }
    offset = unit.stringsBase + value->value * unit.offsetSize;
    const auto* table = contribution(0, unit, unit.stringsBase);
    if (!table || value->value >= table->entries) { warn("Indexed string refers outside its DWARF5 contribution."); return {}; }
    Cursor offsets(s_.stringOffsets, offset); offsets.end = table->end;
    if (!offsets.integer(unit.offsetSize, &stringOffset)) { warn("Indexed string offset is out of bounds."); return {}; }
    Cursor strings(s_.strings, stringOffset); std::string result;
    if (!strings.string(&result) || !textBudget(result.size())) { warn("Indexed string is out of bounds or exceeds budget."); return {}; }
    return result;
}
bool Reader::indexedAddress(const Unit& unit, u64 index, Address* out) {
    if (unit.addressesBase == kNoAddress || index > (~u64(0) - unit.addressesBase) / unit.addressSize) return false;
    const auto* table = contribution(1, unit, unit.addressesBase);
    if (!table || index >= table->entries) return false;
    Cursor cursor(s_.addresses, unit.addressesBase + index * unit.addressSize); cursor.end = table->end;
    return cursor.integer(unit.addressSize, out);
}

const Contribution* Reader::contribution(unsigned section, const Unit& unit, u64 base, bool exactBase) {
    if (unit.version < 5) return nullptr; // GNU pre-v5 index tables have different contribution semantics.
    auto found = contributions_.find(section);
    if (found == contributions_.end()) {
        const ByteView views[] = {s_.stringOffsets, s_.addresses, s_.rangeLists, s_.locationLists};
        Cursor cursor(views[section]); std::vector<Contribution> tables;
        bool valid = true;
        while (cursor.pos < cursor.end) {
            Contribution item; u64 version = 0, padding = 0, count = 0;
            if (tables.size() >= 4096 || !initialLength(&cursor, &item.end, &item.offsetSize)) { valid = false; break; }
            const u64 sectionEnd = cursor.end; cursor.end = item.end;
            if (!cursor.integer(2, &version) || version != 5) { valid = false; break; }
            if (section == 0) {
                if (!cursor.integer(2, &padding) || padding) { valid = false; break; }
            } else {
                u8 segment = 0;
                if (!cursor.byte(&item.addressSize) || !cursor.byte(&segment) ||
                    (item.addressSize != 4 && item.addressSize != 8) || segment) { valid = false; break; }
                if (section >= 2 && !cursor.integer(4, &count)) { valid = false; break; }
            }
            item.base = cursor.pos;
            if (section < 2) {
                const u64 width = section ? item.addressSize : item.offsetSize;
                if ((item.end - item.base) % width) { valid = false; break; }
                item.entries = (item.end - item.base) / width; item.data = item.base;
            } else {
                if (count > (item.end - item.base) / item.offsetSize) { valid = false; break; }
                item.entries = count; item.data = item.base + count * item.offsetSize;
            }
            tables.push_back(item); cursor.pos = item.end; cursor.end = sectionEnd;
        }
        if (!valid) { warn("Malformed/segmented DWARF5 index-table contribution; dependent indexed metadata omitted."); tables.clear(); }
        found = contributions_.emplace(section, std::move(tables)).first;
    }
    for (const auto& item : found->second) {
        if ((exactBase ? base == item.base : base >= item.data && base < item.end) &&
            item.offsetSize == unit.offsetSize && (section == 0 || item.addressSize == unit.addressSize)) return &item;
    }
    return nullptr;
}
bool Reader::address(size_t die, u64 name, Address* out) {
    const auto* value = attribute(die, name);
    if (!value) return false;
    if (value->kind == Attribute::kAddress) { *out = value->value; return true; }
    if (value->kind == Attribute::kAddressIndex) {
        if (indexedAddress(units_[dies_[die].unit], value->value, out)) return true;
        warn("Indexed address has no valid DW_AT_addr_base/table entry.");
    }
    return false;
}

bool Reader::listOffset(const Unit& unit, const Attribute& attr, bool location, u64* offset) {
    const unsigned section = location ? 3 : 2;
    if (attr.kind == Attribute::kOffset || attr.kind == Attribute::kUnsigned) {
        *offset = attr.value;
        return unit.version < 5 || contribution(section, unit, *offset, false);
    }
    if (attr.kind != (location ? Attribute::kLocationIndex : Attribute::kRangeIndex)) return false;
    const auto base = location ? unit.locationsBase : unit.rangesBase;
    if (base == kNoAddress || attr.value > (~u64(0) - base) / unit.offsetSize) return false;
    const auto* table = contribution(section, unit, base);
    if (!table || attr.value >= table->entries) return false;
    Cursor cursor(location ? s_.locationLists : s_.rangeLists, base + attr.value * unit.offsetSize); cursor.end = table->data;
    u64 relative = 0;
    return cursor.integer(unit.offsetSize, &relative) && add(base, relative, offset) && *offset >= table->data && *offset < table->end;
}

Status Reader::ranges(size_t die, std::vector<DwarfRange>* out) {
    const Unit& unit = units_[dies_[die].unit];
    Address low = 0, high = 0;
    if (address(die, kLowPc, &low)) {
        if (!address(die, kHighPc, &high)) {
            u64 length = 0;
            if (unit.version >= 4 && number(die, kHighPc, &length) && !add(low, length, &high)) return malformed("high_pc overflow");
        }
        if (high > low) out->push_back({low, high});
    }
    const auto* attr = attribute(die, kRanges);
    if (!attr) return Status::success();
    out->clear(); u64 offset = 0;
    if (!listOffset(unit, *attr, false, &offset)) { warn("Range-list index/base is unsupported or invalid."); return Status::success(); }
    Cursor cursor(unit.version >= 5 ? s_.rangeLists : s_.ranges, offset);
    if (unit.version >= 5) cursor.end = contribution(2, unit, offset, false)->end;
    Address base = unit.low;
    for (size_t count = 0; count < 65536; ++count) {
        if (++rangeOperations_ > 1000000) return tooLarge();
        u64 begin = 0, end = 0;
        if (unit.version < 5) {
            if (!cursor.integer(unit.addressSize, &begin) || !cursor.integer(unit.addressSize, &end)) return malformed("truncated debug_ranges");
            if (!begin && !end) return Status::success();
            const u64 sentinel = unit.addressSize == 8 ? ~u64(0) : 0xffffffffU;
            if (begin == sentinel) { base = end; continue; }
            if (!add(base, begin, &begin) || !add(base, end, &end)) return malformed("range address overflow");
        } else {
            u8 kind = 0; if (!cursor.byte(&kind)) return malformed("truncated range-list entry");
            if (!kind) return Status::success();
            if (kind == 1) { u64 index = 0; if (!cursor.uleb(&index) || !indexedAddress(unit, index, &base)) return malformed("invalid range base index"); continue; }
            if (kind == 5) { if (!cursor.integer(unit.addressSize, &base)) return malformed("truncated range base"); continue; }
            if (kind == 2 || kind == 3) {
                u64 first = 0, second = 0;
                if (!cursor.uleb(&first) || !cursor.uleb(&second) || !indexedAddress(unit, first, &begin)) return malformed("invalid indexed range");
                if (kind == 2 ? !indexedAddress(unit, second, &end) : !add(begin, second, &end)) return malformed("invalid indexed range end");
            } else if (kind == 4) {
                if (!cursor.uleb(&begin) || !cursor.uleb(&end) || !add(base, begin, &begin) || !add(base, end, &end)) return malformed("invalid offset range");
            } else if (kind == 6) {
                if (!cursor.integer(unit.addressSize, &begin) || !cursor.integer(unit.addressSize, &end)) return malformed("truncated absolute range");
            } else if (kind == 7) {
                u64 length = 0;
                if (!cursor.integer(unit.addressSize, &begin) || !cursor.uleb(&length) || !add(begin, length, &end)) return malformed("invalid start/length range");
            } else { warn("Unknown range-list entry opcode; range list omitted."); out->clear(); return Status::success(); }
        }
        if (end < begin) return malformed("reversed range-list entry");
        if (end > begin) out->push_back({begin, end});
    }
    return tooLarge();
}

DwarfLocation Reader::expression(ByteView bytes, const Unit& unit) {
    // Composite locations and runtime-dependent operations are represented as
    // bounded symbolic expressions. Never read a register/dereference from
    // static input bytes and report it as a concrete local storage address.
    bool extended = false;
    for (size_t i = 0; i < bytes.size(); ++i) {
        const u8 op = bytes.data()[i];
        if (op == 0x93 || op == 0x9d || op == 0x06 || op == 0x94 || op == 0x9e || op == 0xa3 || op == 0xf3 ||
            (op >= 0x12 && op <= 0x22) || (op >= 0x24 && op <= 0x2f)) { extended = true; break; }
    }
    if (extended && expressionDepth_ < 8) {
        struct Term { std::string text; DwarfLocation location; bool numeric = false; u64 number = 0; };
        Cursor cursor(bytes); std::vector<Term> stack; DwarfLocation result;
        bool valid = bytes.size() <= 65536; size_t operations = 0; u64 totalBits = 0;
        ++expressionDepth_;
        while (valid && cursor.pos < cursor.end && ++operations <= 4096) {
            u8 op = 0; u64 value = 0; i64 signedValue = 0; valid = cursor.byte(&op);
            Term term;
            if (!valid) break;
            if (op == 0x03 || op == 0x10 || op == 0x11 || (op >= 0x08 && op <= 0x0f) || (op >= 0x30 && op <= 0x4f)) {
                if (op == 3) valid = cursor.integer(unit.addressSize, &value);
                else if (op == 0x10) valid = cursor.uleb(&value);
                else if (op == 0x11) { valid = cursor.sleb(&signedValue); value = static_cast<u64>(signedValue); }
                else if (op >= 0x30) value = op - 0x30;
                else {
                    const unsigned width = 1u << ((op - 8) / 2); valid = cursor.integer(width, &value);
                    if ((op & 1) && width < 8 && (value & (u64{1} << (width * 8 - 1)))) value |= ~u64{0} << (width * 8);
                }
                if (unit.addressSize == 4) value = static_cast<u32>(value);
                term.numeric = true; term.number = value; term.text = "0x" + hex(value);
                term.location.kind = DwarfLocation::Kind::kAddress; term.location.address = value; stack.push_back(std::move(term));
            } else if ((op >= 0x50 && op <= 0x6f) || op == 0x90) {
                value = op - 0x50; if (op == 0x90) valid = cursor.uleb(&value) && value <= 65535;
                term.text = "reg(" + std::to_string(value) + ')'; term.location.kind = DwarfLocation::Kind::kRegister; term.location.reg = static_cast<u32>(value);
                term.location.needsRuntime = true; stack.push_back(std::move(term));
            } else if ((op >= 0x70 && op <= 0x8f) || op == 0x91 || op == 0x92) {
                value = op - 0x70;
                if (op == 0x92) valid = cursor.uleb(&value) && value <= 65535;
                valid = valid && cursor.sleb(&signedValue);
                term.location.kind = op == 0x91 ? DwarfLocation::Kind::kFrameBaseOffset : DwarfLocation::Kind::kRegisterOffset;
                term.location.reg = static_cast<u32>(value); term.location.offset = signedValue; term.location.needsRuntime = true;
                term.text = op == 0x91 ? "frame_base" : "reg(" + std::to_string(value) + ')';
                term.text += (signedValue < 0 ? "" : "+") + std::to_string(signedValue); stack.push_back(std::move(term));
            } else if (op == 0x9c) {
                term.text = "CFA"; term.location.kind = DwarfLocation::Kind::kSymbolic; term.location.needsRuntime = true; stack.push_back(std::move(term));
            } else if (op == 0x93 || op == 0x9d) {
                u64 bitOffset = 0; valid = cursor.uleb(&value); if (op == 0x9d) valid = valid && cursor.uleb(&bitOffset);
                else if (value > ~u64{0} / 8) valid = false; else value *= 8;
                if (value > 1024 * 1024 || totalBits > 1024 * 1024 - value || result.pieces.size() >= 256 || stack.size() > 1) { valid = false; break; }
                DwarfLocation::Piece piece; piece.bitSize = value; piece.bitOffset = bitOffset; piece.available = !stack.empty();
                if (!stack.empty()) { piece.expression = stack.back().text; result.needsRuntime = result.needsRuntime || stack.back().location.needsRuntime; stack.clear(); }
                else piece.expression = "unavailable";
                totalBits += value; result.pieces.push_back(std::move(piece));
            } else if (op == 0x9e) {
                ByteView implicit; valid = cursor.uleb(&value) && value <= 256 && cursor.block(value, &implicit);
                term.text = "implicit_value("; for (size_t i = 0; i < implicit.size(); ++i) term.text += hex(implicit.data()[i]) + ' '; term.text += ')';
                term.location.kind = DwarfLocation::Kind::kValue; stack.push_back(std::move(term));
            } else if (op == 0xa3 || op == 0xf3) {
                ByteView nested; valid = cursor.uleb(&value) && value && cursor.block(value, &nested);
                if (valid) {
                    const auto entry = expression(nested, unit); valid = entry.kind != DwarfLocation::Kind::kUnknown && entry.pieces.empty();
                    term.text = "entry_value(" + entry.expression + ')'; term.location.kind = DwarfLocation::Kind::kValue; term.location.needsRuntime = true; stack.push_back(std::move(term));
                }
            } else if (op == 0x06 || op == 0x94) {
                value = unit.addressSize; if (op == 0x94) { u8 size = 0; valid = cursor.byte(&size); value = size; }
                valid = valid && !stack.empty() && value && value <= 8;
                if (valid) { auto& top = stack.back(); top.text = "load" + std::to_string(value * 8) + '(' + top.text + ')'; top.numeric = false; top.location.kind = DwarfLocation::Kind::kSymbolic; top.location.address = kNoAddress; top.location.needsRuntime = true; }
            } else if (op == 0x9f) {
                valid = !stack.empty(); if (valid) stack.back().location.kind = DwarfLocation::Kind::kValue;
            } else if (op == 0x12) { valid = !stack.empty(); if (valid) stack.push_back(stack.back()); }
            else if (op == 0x13) { valid = !stack.empty(); if (valid) stack.pop_back(); }
            else if (op == 0x14) { valid = stack.size() >= 2; if (valid) stack.push_back(stack[stack.size() - 2]); }
            else if (op == 0x15) { u8 index = 0; valid = cursor.byte(&index) && index < stack.size(); if (valid) stack.push_back(stack[stack.size() - 1 - index]); }
            else if (op == 0x16) { valid = stack.size() >= 2; if (valid) std::swap(stack[stack.size() - 1], stack[stack.size() - 2]); }
            else if (op == 0x17) { valid = stack.size() >= 3; if (valid) std::rotate(stack.end() - 3, stack.end() - 1, stack.end()); }
            else if (op == 0x23) {
                valid = cursor.uleb(&value) && !stack.empty();
                if (valid) { Term constant; constant.numeric = true; constant.number = value; constant.text = "0x" + hex(value); stack.push_back(std::move(constant)); op = 0x22; }
            } else if (op == 0x96) continue;
            else if (op < 0x19 || op > 0x27) valid = false;
            if (valid && op >= 0x19 && op <= 0x27) {
                const bool unary = op == 0x19 || op == 0x1f || op == 0x20;
                if (stack.size() < (unary ? 1 : 2)) { valid = false; break; }
                Term right = std::move(stack.back()); stack.pop_back(); Term left;
                if (!unary) { left = std::move(stack.back()); stack.pop_back(); }
                if (right.location.kind == DwarfLocation::Kind::kRegister || (!unary && left.location.kind == DwarfLocation::Kind::kRegister)) { valid = false; break; }
                const char* token = op == 0x1a ? "&" : op == 0x1b ? "/" : op == 0x1c ? "-" : op == 0x1d ? "%" : op == 0x1e ? "*" : op == 0x21 ? "|" : op == 0x22 ? "+" : op == 0x24 ? "<<" : op == 0x25 || op == 0x26 ? ">>" : op == 0x27 ? "^" : "unary";
                term.text = unary ? std::string(token) + '(' + right.text + ')' : '(' + left.text + token + right.text + ')';
                term.location.kind = DwarfLocation::Kind::kSymbolic; term.location.needsRuntime = left.location.needsRuntime || right.location.needsRuntime;
                // Exact affine offsets survive addition/subtraction of a literal.
                if (!unary && (op == 0x22 || op == 0x1c) && right.numeric && right.number <= static_cast<u64>(std::numeric_limits<i64>::max()) &&
                    (left.location.kind == DwarfLocation::Kind::kFrameBaseOffset || left.location.kind == DwarfLocation::Kind::kRegisterOffset)) {
                    const i64 delta = op == 0x1c ? -static_cast<i64>(right.number) : static_cast<i64>(right.number);
                    if ((delta >= 0 && left.location.offset <= std::numeric_limits<i64>::max() - delta) || (delta < 0 && left.location.offset >= std::numeric_limits<i64>::min() - delta)) { term.location = left.location; term.location.offset += delta; }
                }
                stack.push_back(std::move(term));
            }
            if (stack.size() > 64) valid = false;
            size_t text = 0; for (const auto& value : stack) text += value.text.size(); if (text > 65536) valid = false;
        }
        --expressionDepth_;
        if (valid && cursor.pos == cursor.end && (!result.pieces.empty() ? stack.empty() : stack.size() == 1)) {
            if (!result.pieces.empty()) {
                result.kind = DwarfLocation::Kind::kComposite; result.expression = "composite{";
                for (const auto& piece : result.pieces) result.expression += piece.expression + ":" + std::to_string(piece.bitSize) + "bits@" + std::to_string(piece.bitOffset) + ';';
                result.expression += '}';
            } else { result = stack.back().location; result.expression = stack.back().text; }
            return result;
        }
        // Failed composite parses remain unknown, with no usable partial pieces.
    }
    DwarfLocation result;
    Cursor cursor(bytes); u8 op = 0; u64 value = 0; i64 offset = 0;
    if (!cursor.byte(&op)) { result.expression = "unavailable"; return result; }
    bool valid = true;
    if (op == 0x03) {
        valid = cursor.integer(unit.addressSize, &result.address);
        result.kind = DwarfLocation::Kind::kAddress;
    } else if (op >= 0x50 && op <= 0x6f) {
        result.kind = DwarfLocation::Kind::kRegister; result.reg = op - 0x50;
    } else if (op >= 0x70 && op <= 0x8f) {
        valid = cursor.sleb(&offset); result.kind = DwarfLocation::Kind::kRegisterOffset;
        result.reg = op - 0x70; result.offset = offset;
    } else if (op == 0x90) {
        valid = cursor.uleb(&value) && value <= 65535;
        result.kind = DwarfLocation::Kind::kRegister; result.reg = static_cast<u32>(value);
    } else if (op == 0x91) {
        valid = cursor.sleb(&offset); result.kind = DwarfLocation::Kind::kFrameBaseOffset; result.offset = offset;
    } else if (op == 0x92) {
        valid = cursor.uleb(&value) && value <= 65535 && cursor.sleb(&offset);
        result.kind = DwarfLocation::Kind::kRegisterOffset; result.reg = static_cast<u32>(value); result.offset = offset;
    } else if (op == 0xa1) {
        valid = cursor.uleb(&value) && indexedAddress(unit, value, &result.address);
        result.kind = DwarfLocation::Kind::kAddress;
    } else if (op == 0x9c) {
        // CFA is not an absolute SP offset without the unwind program. Preserve
        // this symbolic distinction instead of claiming a concrete stack slot.
        result.expression = "DW_OP_call_frame_cfa";
        valid = cursor.pos == cursor.end;
        if (valid) return result;
    } else if (op == 0x10 || op == 0x11 || (op >= 0x30 && op <= 0x4f)) {
        if (op == 0x10) valid = cursor.uleb(&value);
        else if (op == 0x11) { valid = cursor.sleb(&offset); value = static_cast<u64>(offset); }
        else value = op - 0x30;
        result.kind = DwarfLocation::Kind::kAddress; result.address = value;
    } else valid = false;
    while (valid && cursor.pos < cursor.end) {
        if (!cursor.byte(&op)) { valid = false; break; }
        if (op == 0x96) continue; // nop
        if (op == 0x23) {
            valid = cursor.uleb(&value);
            if (result.kind == DwarfLocation::Kind::kAddress) valid = valid && add(result.address, value, &result.address);
            else if (result.kind == DwarfLocation::Kind::kFrameBaseOffset || result.kind == DwarfLocation::Kind::kRegisterOffset) {
                valid = valid && value <= static_cast<u64>(std::numeric_limits<i64>::max()) &&
                        result.offset <= std::numeric_limits<i64>::max() - static_cast<i64>(value);
                if (valid) result.offset += static_cast<i64>(value);
            } else valid = false;
        } else if (op == 0x9f && cursor.pos == cursor.end) {
            // Preserve expression meaning; a register/stack_value is a value,
            // not an addressable memory location.
            result.kind = DwarfLocation::Kind::kValue;
        } else valid = false;
    }
    std::ostringstream text;
    if (valid) {
        switch (result.kind) {
            case DwarfLocation::Kind::kAddress: text << "address 0x" << std::hex << result.address; break;
            case DwarfLocation::Kind::kRegister: text << "DWARF register " << result.reg; break;
            case DwarfLocation::Kind::kFrameBaseOffset: text << "frame-base " << std::showpos << result.offset; break;
            case DwarfLocation::Kind::kRegisterOffset: text << "DWARF register " << result.reg << ' ' << std::showpos << result.offset; break;
            case DwarfLocation::Kind::kValue: text << "stack value (register/frame/address expression, not writable storage)"; break;
            default: break;
        }
    } else {
        result.kind = DwarfLocation::Kind::kUnknown; result.address = kNoAddress;
        text << "unsupported expression:";
        for (size_t i = 0; i < std::min<size_t>(bytes.size(), 32); ++i)
            text << ' ' << std::hex << std::setw(2) << std::setfill('0') << unsigned(bytes.data()[i]);
        if (bytes.size() > 32) text << " ...";
        warn("Complex/piece/dereference/typed DWARF expressions are retained as unsupported, not evaluated without runtime state.");
    }
    result.expression = text.str();
    return result;
}

Status Reader::locations(size_t die, DwarfVariable* out) {
    const Unit& unit = units_[dies_[die].unit];
    const auto* attr = attribute(die, kLocation);
    if (!attr) { out->location.expression = "not available (declaration or optimized-out value)"; return Status::success(); }
    if (attr->kind == Attribute::kBlock) { out->location = expression(attr->bytes, unit); return Status::success(); }
    u64 offset = 0;
    if (!listOffset(unit, *attr, true, &offset)) { warn("Unsupported location-list form/base."); return Status::success(); }
    Cursor cursor(unit.version >= 5 ? s_.locationLists : s_.locations, offset);
    if (unit.version >= 5) cursor.end = contribution(3, unit, offset, false)->end;
    Address base = unit.low;
    for (size_t n = 0; n < 4096; ++n) {
        if (++locationOperations_ > 200000) return tooLarge();
        u64 begin = 0, end = 0, length = 0;
        bool isDefault = false;
        if (unit.version < 5) {
            if (!cursor.integer(unit.addressSize, &begin) || !cursor.integer(unit.addressSize, &end)) return malformed("truncated debug_loc");
            if (!begin && !end) return Status::success();
            const u64 sentinel = unit.addressSize == 8 ? ~u64(0) : 0xffffffffU;
            if (begin == sentinel) { base = end; continue; }
            if (!add(base, begin, &begin) || !add(base, end, &end) || !cursor.integer(2, &length)) return malformed("invalid debug_loc range/length");
        } else {
            u8 kind = 0; if (!cursor.byte(&kind)) return malformed("truncated location-list entry");
            if (!kind) return Status::success();
            if (kind == 1) { u64 index = 0; if (!cursor.uleb(&index) || !indexedAddress(unit, index, &base)) return malformed("invalid indexed location base"); continue; }
            if (kind == 6) { if (!cursor.integer(unit.addressSize, &base)) return malformed("truncated location base"); continue; }
            if (kind == 2 || kind == 3) {
                u64 first = 0, second = 0;
                if (!cursor.uleb(&first) || !cursor.uleb(&second) || !indexedAddress(unit, first, &begin)) return malformed("invalid indexed location range");
                if (kind == 2 ? !indexedAddress(unit, second, &end) : !add(begin, second, &end)) return malformed("invalid location range end");
            } else if (kind == 4) {
                if (!cursor.uleb(&begin) || !cursor.uleb(&end) || !add(base, begin, &begin) || !add(base, end, &end)) return malformed("invalid offset location range");
            } else if (kind == 5) isDefault = true;
            else if (kind == 7) {
                if (!cursor.integer(unit.addressSize, &begin) || !cursor.integer(unit.addressSize, &end)) return malformed("truncated absolute location range");
            } else if (kind == 8) {
                if (!cursor.integer(unit.addressSize, &begin) || !cursor.uleb(&length) || !add(begin, length, &end)) return malformed("invalid start/length location range");
            } else { warn("Unknown location-list entry opcode; remaining list omitted."); return Status::success(); }
            if (!cursor.uleb(&length)) return malformed("truncated location expression length");
        }
        if (!isDefault && end < begin) return malformed("reversed location-list range");
        ByteView bytes;
        if (!cursor.block(length, &bytes)) return malformed("truncated location expression");
        auto decoded = expression(bytes, unit);
        if (isDefault) out->location = std::move(decoded);
        else if (end > begin) {
            if (!textBudget(decoded.expression.size())) return tooLarge();
            out->locations.push_back({{begin, end}, std::move(decoded)});
        }
    }
    return tooLarge();
}

std::string Reader::identifier(const std::string& source, const std::string& fallback) const {
    // DWARF base names such as "int" are valid DSL identifiers but cannot be
    // declared as C typedefs. Keep their exact storage under a safe DIE name;
    // the report still retains the original debug names where appropriate.
    return DataTypeManager::validName(source) && userIdentifier(source) ? source : fallback;
}
size_t Reader::referencedType(size_t die) const {
    const auto* attr = attribute(die, kType);
    if (!attr) return kNoParent;
    u64 target = attr->value;
    if (attr->kind == Attribute::kTypeSignature) {
        const auto signature = typeSignatures_.find(target);
        if (signature == typeSignatures_.end()) return kBadType;
        target = signature->second;
    } else if (attr->kind != Attribute::kReference) return kBadType;
    auto found = byOffset_.find(target);
    return found == byOffset_.end() || !typeTag(dies_[found->second].tag) ? kBadType : found->second;
}
std::string Reader::primitiveType(size_t die, u64 size) const {
    u64 encoding = 0;
    if (!number(die, kEncoding, &encoding)) return {};
    if (encoding == 2 && size == 1) return "bool";
    if (encoding == 4 && (size == 4 || size == 8)) return size == 4 ? "f32" : "f64";
    if ((encoding == 5 || encoding == 6 || encoding == 7 || encoding == 8 || encoding == 1) &&
        (size == 1 || size == 2 || size == 4 || size == 8))
        return std::string(encoding == 5 || encoding == 6 ? "i" : "u") + std::to_string(size * 8);
    return {};
}

Reader::TypeInfo Reader::type(size_t die, unsigned depth, bool behindPointer) {
    if (die == kNoParent) { TypeInfo info; info.valid = true; info.expression = info.body = info.cType = "void"; return info; }
    if (die >= dies_.size() || depth >= 64 || !typeNames_.count(die)) return {};
    auto existing = typeInfos_.find(die);
    if (existing != typeInfos_.end()) return existing->second;
    const Die& node = dies_[die];
    TypeInfo info; info.name = typeNames_.at(die); info.expression = info.name;
    if (behindPointer && (node.tag == 0x13 || node.tag == 0x02 || node.tag == 0x17 || activeTypes_.count(die))) {
        info.valid = true; number(die, kByteSize, &info.size); info.cType = info.name;
        return info; // Complete storage/alias validity is checked after recursion.
    }
    if (!activeTypes_.insert(die).second) { warn("By-value or typedef DWARF type cycle omitted."); return {}; }
    const Unit& unit = units_[node.unit];
    u64 statedSize = 0; const bool hasSize = number(die, kByteSize, &statedSize);
    if (node.tag == 0x24) { // base_type
        info.body = primitiveType(die, statedSize); info.size = statedSize;
        info.alignment = static_cast<u32>(std::max<u64>(1, statedSize)); info.valid = !info.body.empty();
        if (info.body == "f32") info.cType = "float";
        else if (info.body == "f64") info.cType = "double";
        else if (info.body == "bool") info.cType = "bool";
        else if (!info.body.empty()) info.cType = std::string(info.body[0] == 'i' ? "int" : "uint") + std::to_string(statedSize * 8) + "_t";
        if (info.valid && string(die, kName) == "char") info.cType = "char";
    } else if (node.tag == 0x0f || node.tag == 0x10 || node.tag == 0x42) { // pointer/reference/rvalue_reference
        const auto child = type(referencedType(die), depth + 1, true);
        info.size = hasSize ? statedSize : unit.addressSize; info.alignment = unit.addressSize;
        info.valid = child.valid && info.size == unit.addressSize;
        if (info.valid) {
            info.body = child.expression + '*'; info.expression = info.body;
            info.cType = child.cType.empty() ? "" : child.cType + (node.tag == 0x0f ? "*" : node.tag == 0x10 ? "&" : "&&");
        }
    } else if (node.tag == 0x16 || node.tag == 0x26 || node.tag == 0x35 || node.tag == 0x37 || node.tag == 0x47) { // aliases/qualifiers
        const auto child = type(referencedType(die), depth + 1, behindPointer);
        info = child; info.name = typeNames_.at(die); info.body = child.expression; info.expression = info.name;
        if (node.tag == 0x26 && !info.cType.empty()) info.cType = "const " + info.cType;
        if (node.tag == 0x35 && !info.cType.empty()) info.cType = "volatile " + info.cType;
    } else if (node.tag == 0x01) { // array_type
        const auto child = type(referencedType(die), depth + 1);
        info.valid = child.valid && child.size; info.size = child.size; info.alignment = child.alignment; info.body = child.expression;
        std::vector<u64> dimensions;
        for (size_t index : node.children) if (dies_[index].tag == 0x21) {
            u64 count = 0;
            if (!number(index, kCount, &count)) {
                i64 upper = 0, lower = 0;
                if (!signedNumber(index, kUpperBound, &upper)) { info.valid = false; break; }
                if (!signedNumber(index, kLowerBound, &lower)) {
                    u64 language = 0; number(unit.root, 0x13, &language);
                    if (language == 7 || language == 8 || language == 0x0e || language == 0x22 || language == 0x23) lower = 1;
                    else if (language != 1 && language != 2 && language != 4 && language != 0x0c && language != 0x19 && language != 0x1a && language != 0x1d && language != 0x21 && language != 0x2a && language != 0x2b) {
                        info.valid = false; break;
                    }
                }
                if (upper < lower || (lower < 0 && upper > std::numeric_limits<i64>::max() + lower)) { info.valid = false; break; }
                count = static_cast<u64>(upper - lower) + 1;
            }
            if (!count || count > DataTypeManager::kMaxTypeBytes || info.size > DataTypeManager::kMaxTypeBytes / count) { info.valid = false; break; }
            dimensions.push_back(count); info.size *= count;
        }
        // DWARF subranges are outermost first. The storage DSL wraps the
        // previous expression with each suffix, so emit innermost first.
        for (auto dimension = dimensions.rbegin(); dimension != dimensions.rend(); ++dimension) info.body += '[' + std::to_string(*dimension) + ']';
        info.valid = info.valid && !dimensions.empty() && (!hasSize || info.size == statedSize);
        // A fixed array's storage is exact, but C parameter/return declarators
        // require declarator binding rather than concatenating "T[N] arg".
    } else if (node.tag == 0x13 || node.tag == 0x02 || node.tag == 0x17) { // struct/class/union
        const bool isUnion = node.tag == 0x17;
        info.valid = hasSize && statedSize && statedSize <= DataTypeManager::kMaxTypeBytes;
        info.body = isUnion ? "union{" : "struct{";
        u64 end = 0; size_t fields = 0; std::set<std::string> fieldNames; bool packed = false;
        for (size_t index : node.children) {
            const bool baseClass = dies_[index].tag == 0x1c;
            if (dies_[index].tag != 0x0d && !baseClass) continue;
            u64 virtuality = 0;
            if (baseClass && number(index, 0x4c, &virtuality) && virtuality) { info.valid = false; break; }
            u64 declaration = 0; if (number(index, kDeclaration, &declaration) && declaration) continue; // static member declaration.
            if (attribute(index, kBitSize) || attribute(index, kBitOffset) || attribute(index, kDataBitOffset)) { info.valid = false; break; }
            auto child = type(referencedType(index), depth + 1);
            u64 offset = 0;
            const auto* at = attribute(index, kMemberLocation);
            if (at && !number(index, kMemberLocation, &offset)) {
                Cursor expression(at->bytes); u8 op = 0;
                if (at->kind != Attribute::kBlock || !expression.byte(&op) || op != 0x23 || !expression.uleb(&offset) || expression.pos != expression.end) { info.valid = false; break; }
            }
            if (!child.valid || !child.size || (isUnion ? offset != 0 : offset < end) ||
                offset > statedSize || child.size > statedSize - offset || fields >= 256) { info.valid = false; break; }
            packed = packed || offset % child.alignment;
            std::string field = identifier(string(index, kName), (baseClass ? "base_" : "field_") + std::to_string(fields));
            if (!fieldNames.insert(field).second) { info.valid = false; break; }
            if (fields++) info.body += ';';
            info.body += field + ':' + child.expression + '@' + std::to_string(offset);
            end = std::max(end, offset + child.size); info.alignment = std::max(info.alignment, child.alignment);
        }
        info.body += '}';
        u64 alignment = 0;
        const bool statedAlignment = number(die, kAlignment, &alignment);
        packed = packed || (statedAlignment && alignment == 1 && info.alignment > 1);
        if (packed && !isUnion) {
            info.body.replace(0, 6, "packed"); info.alignment = 1;
            if (end < statedSize) info.body.insert(info.body.size() - 1, ";__dwarf_tail:u8[" + std::to_string(statedSize - end) + "]@" + std::to_string(end));
            end = statedSize;
        }
        const u64 naturalSize = (end + info.alignment - 1) / info.alignment * info.alignment;
        if (!fields || naturalSize != statedSize || (statedAlignment && alignment != info.alignment)) info.valid = false;
        info.size = statedSize; info.cType = info.name;
    } else if (node.tag == 0x04) { // enumeration_type
        auto base = type(referencedType(die), depth + 1);
        if (referencedType(die) == kNoParent) {
            base.body = primitiveType(die, statedSize); base.expression = base.body; base.size = statedSize;
            base.alignment = static_cast<u32>(std::max<u64>(1, statedSize)); base.valid = !base.body.empty();
        }
        info.valid = base.valid && base.size && (base.body.size() && (base.body[0] == 'i' || base.body[0] == 'u'));
        info.size = base.size; info.alignment = base.alignment; info.body = "enum:" + base.expression + '{';
        size_t values = 0; std::set<std::string> names;
        for (size_t index : node.children) if (dies_[index].tag == 0x28) {
            i64 value = 0; auto name = identifier(string(index, kName), "value_" + std::to_string(values));
            if (!signedNumber(index, kConstValue, &value) || !names.insert(name).second || values >= 1024) { info.valid = false; break; }
            if (values++) info.body += ';'; info.body += name + '=' + std::to_string(value);
        }
        info.body += '}'; info.valid = info.valid && values && (!hasSize || statedSize == info.size); info.cType = info.name;
    } else if (node.tag == 0x3b && string(die, kName) == "void") {
        info.body = info.cType = "void"; info.valid = true;
    }
    if (hasSize && info.valid && info.size != statedSize) info.valid = false;
    if (!info.valid || info.body.size() > DataTypeManager::kMaxDeclarationBytes - info.name.size() - 1) {
        info.valid = false; info.body.clear(); info.cType.clear();
        warn("Some DWARF types have unsupported, incomplete, bitfield, virtual/overlapping inheritance or nonrepresentable layouts; no replacement type is invented.");
    }
    activeTypes_.erase(die); typeInfos_[die] = info; return info;
}

Status Reader::lineTable(const Unit& unit, u64 offset) {
    if (!lineTables_.insert(offset).second) return Status::success();
    Cursor cursor(s_.line, offset);
    u64 finish = 0, version = 0, headerLength = 0; u8 offsetSize = 4;
    if (!initialLength(&cursor, &finish, &offsetSize) || !cursor.integer(2, &version)) return malformed("truncated line-table header");
    cursor.end = finish;
    if (version < 2 || version > 5) { warn("Unsupported line-table version; source rows omitted."); return Status::success(); }
    Unit lineUnit = unit; lineUnit.offsetSize = offsetSize; lineUnit.version = static_cast<u16>(version);
    if (version == 5) {
        u8 addressSize = 0, segmentSize = 0;
        if (!cursor.byte(&addressSize) || !cursor.byte(&segmentSize)) return malformed("truncated DWARF5 line addressing");
        if ((addressSize != 4 && addressSize != 8) || segmentSize) { warn("Segmented/unsupported line-table addressing omitted."); return Status::success(); }
        lineUnit.addressSize = addressSize;
    }
    if (!cursor.integer(offsetSize, &headerLength) || headerLength > finish - cursor.pos) return malformed("invalid line-table prologue length");
    const u64 headerEnd = cursor.pos + headerLength;
    const u64 programEnd = cursor.end; cursor.end = headerEnd;
    u8 minLength = 0, maxOps = 1, defaultStmt = 0, rawBase = 0, lineRange = 0, opcodeBase = 0;
    if (!cursor.byte(&minLength) || (version >= 4 && !cursor.byte(&maxOps)) || !cursor.byte(&defaultStmt) ||
        !cursor.byte(&rawBase) || !cursor.byte(&lineRange) || !cursor.byte(&opcodeBase) || !minLength || !maxOps || !lineRange || !opcodeBase)
        return malformed("invalid line-table machine parameters");
    const i64 lineBase = rawBase < 128 ? rawBase : static_cast<i64>(rawBase) - 256;
    std::vector<u8> operandCounts(opcodeBase);
    for (unsigned i = 1; i < opcodeBase; ++i) if (!cursor.byte(&operandCounts[i])) return malformed("truncated standard opcode lengths");
    std::vector<std::string> directories, files;
    auto joined = [&](const std::string& path, u64 directory) {
        if (!path.empty() && (path[0] == '/' || (path.size() > 1 && path[1] == ':'))) return path;
        std::string prefix;
        if (directory < directories.size()) prefix = directories[static_cast<size_t>(directory)];
        if (prefix.empty()) prefix = unit.directory;
        if (!prefix.empty() && prefix != unit.directory && prefix[0] != '/' && !(prefix.size() > 1 && prefix[1] == ':') && !unit.directory.empty()) prefix = unit.directory + '/' + prefix;
        return prefix.empty() ? path : prefix + '/' + path;
    };
    auto oldFile = [&](std::string* path) {
        std::string name; u64 directory = 0, time = 0, size = 0;
        if (!cursor.string(&name) || !cursor.uleb(&directory) || !cursor.uleb(&time) || !cursor.uleb(&size)) return false;
        *path = joined(name, directory); return true;
    };
    if (version < 5) {
        directories.push_back(unit.directory); files.emplace_back();
        for (size_t n = 0; n <= 10000; ++n) {
            std::string directory; if (!cursor.string(&directory)) return malformed("unterminated line include directories");
            if (directory.empty()) break;
            if (n == 10000) return tooLarge();
            directories.push_back(std::move(directory));
        }
        for (size_t n = 0; n <= 10000; ++n) {
            if (cursor.pos >= cursor.end) return malformed("unterminated line file table");
            if (!cursor.view.data()[cursor.pos]) { ++cursor.pos; break; }
            std::string path;
            if (!oldFile(&path)) return malformed("invalid line file entry");
            if (n == 10000 || !textBudget(path.size())) return tooLarge(); files.push_back(std::move(path));
        }
    } else {
        auto table = [&](bool fileTable) -> Status {
            u8 count = 0; if (!cursor.byte(&count) || count > 32) return malformed("invalid line entry-format count");
            std::vector<std::pair<u64, u64>> formats;
            for (unsigned i = 0; i < count; ++i) {
                u64 content = 0, formCode = 0;
                if (!cursor.uleb(&content) || !cursor.uleb(&formCode)) return malformed("truncated line entry-format");
                formats.emplace_back(content, formCode);
            }
            u64 entries = 0; if (!cursor.uleb(&entries) || entries > 10000) return tooLarge();
            for (u64 i = 0; i < entries; ++i) {
                std::string name; u64 directory = 0;
                for (const auto& format : formats) {
                    Attribute value;
                    auto status = form(&cursor, lineUnit, format.second, 0, &value);
                    if (!status.ok()) return status;
                    if (format.first == 1) {
                        if (value.kind != Attribute::kString) return Status::error(ErrorCode::kUnsupported, "indexed/non-string line-table path is unsupported");
                        name = value.text;
                    } else if (format.first == 2) {
                        if (value.kind != Attribute::kUnsigned) return malformed("invalid line directory index");
                        directory = value.value;
                    }
                }
                if (fileTable) { auto path = joined(name, directory); if (!textBudget(path.size())) return tooLarge(); files.push_back(std::move(path)); }
                else directories.push_back(std::move(name));
            }
            return Status::success();
        };
        auto status = table(false); if (!status.ok()) { if (status.code() == ErrorCode::kUnsupported) { warn(status.message()); return Status::success(); } return status; }
        status = table(true); if (!status.ok()) { if (status.code() == ErrorCode::kUnsupported) { warn(status.message()); return Status::success(); } return status; }
    }
    if (cursor.pos != headerEnd) return malformed("line-table prologue size mismatch");
    cursor.end = programEnd;
    Address address = 0; u64 opIndex = 0, file = 1, column = 0; i64 line = 1;
    bool sequence = false;
    auto advance = [&](u64 operations) {
        u64 total = 0, bytes = 0;
        if (!add(opIndex, operations, &total) || total / maxOps > ~u64(0) / minLength) return false;
        bytes = minLength * (total / maxOps); opIndex = total % maxOps;
        return add(address, bytes, &address);
    };
    auto emit = [&](bool end) -> Status {
        if (report_.sources.size() >= kMaxRows || line < 0 || static_cast<u64>(line) > std::numeric_limits<u32>::max() || column > std::numeric_limits<u32>::max()) return tooLarge();
        std::string path = file < files.size() ? files[static_cast<size_t>(file)] : std::string();
        if (path.empty() && !end) warn("A line row references an unknown file index.");
        if (!textBudget(path.size())) return tooLarge();
        report_.sources.push_back({address, std::move(path), end ? 0U : static_cast<u32>(line), end ? 0U : static_cast<u32>(column), end});
        sequence = !end; return Status::success();
    };
    size_t instructions = 0;
    while (cursor.pos < cursor.end) {
        if (++instructions > 2000000) return tooLarge();
        u8 opcode = 0; if (!cursor.byte(&opcode)) return malformed("truncated line opcode");
        if (opcode >= opcodeBase) {
            const u64 adjusted = opcode - opcodeBase;
            if (!advance(adjusted / lineRange)) return malformed("line address overflow");
            const i64 delta = lineBase + static_cast<i64>(adjusted % lineRange);
            if ((delta > 0 && line > std::numeric_limits<i64>::max() - delta) ||
                (delta < 0 && line < std::numeric_limits<i64>::min() - delta)) return malformed("special opcode line-number overflow");
            line += delta;
            auto status = emit(false); if (!status.ok()) return status;
        } else if (opcode == 0) {
            u64 length = 0; u8 extended = 0;
            if (!cursor.uleb(&length) || !length || length > cursor.end - cursor.pos) return malformed("invalid extended line opcode length");
            const u64 finishExtended = cursor.pos + length;
            const u64 savedEnd = cursor.end; cursor.end = finishExtended;
            if (!cursor.byte(&extended)) return malformed("truncated extended line opcode");
            if (extended == 1) {
                auto status = emit(true); if (!status.ok()) return status;
                address = 0; opIndex = 0; file = 1; column = 0; line = 1;
            } else if (extended == 2) {
                if (!cursor.integer(lineUnit.addressSize, &address)) return malformed("truncated line set_address"); opIndex = 0;
            } else if (extended == 3 && version < 5) {
                std::string path; if (!oldFile(&path) || files.size() >= 10000 || !textBudget(path.size())) return malformed("invalid define_file opcode"); files.push_back(std::move(path));
            } else if (extended == 4) {
                u64 discriminator = 0; if (!cursor.uleb(&discriminator)) return malformed("invalid discriminator opcode");
            } else { warn("Unknown extended line opcode skipped."); cursor.pos = finishExtended; }
            if (cursor.pos != finishExtended) return malformed("extended line opcode size mismatch");
            cursor.end = savedEnd;
        } else {
            u64 value = 0; i64 delta = 0;
            switch (opcode) {
                case 1: { auto status = emit(false); if (!status.ok()) return status; break; }
                case 2: if (!cursor.uleb(&value) || !advance(value)) return malformed("invalid line advance_pc"); break;
                case 3:
                    if (!cursor.sleb(&delta) || (delta > 0 && line > std::numeric_limits<i64>::max() - delta) ||
                        (delta < 0 && line < std::numeric_limits<i64>::min() - delta)) return malformed("line-number overflow");
                    line += delta; break;
                case 4: if (!cursor.uleb(&file)) return malformed("invalid line file index"); break;
                case 5: if (!cursor.uleb(&column)) return malformed("invalid line column"); break;
                case 6: case 7: case 10: case 11: break; // Flags do not change address/file/line mapping.
                case 8: if (!advance((255 - opcodeBase) / lineRange)) return malformed("line const_add_pc overflow"); break;
                case 9: if (!cursor.integer(2, &value) || !add(address, value, &address)) return malformed("line fixed_advance_pc overflow"); opIndex = 0; break;
                case 12: if (!cursor.uleb(&value)) return malformed("invalid line ISA value"); break;
                default:
                    for (unsigned i = 0; i < operandCounts[opcode]; ++i) if (!cursor.uleb(&value)) return malformed("truncated vendor standard line opcode");
                    warn("Vendor standard line opcode operands skipped; semantics may be incomplete."); break;
            }
        }
    }
    if (sequence) return malformed("line sequence lacks end_sequence");
    return Status::success();
}

Status Reader::buildReport() {
    report_.units = units_.size(); report_.dies = dies_.size();
    if (!units_.empty()) report_.addressSize = units_.front().addressSize;
    std::set<std::string> names;
    for (size_t i = 0; i < dies_.size(); ++i) if (typeTag(dies_[i].tag)) {
        if (typeNames_.size() >= kMaxTypes) { warn("DWARF type limit reached (4096); remaining types omitted."); break; }
        auto name = identifier(string(i, kName), "dwarf_t_" + hex(dies_[i].offset));
        if (!names.insert(name).second) { name += "_dwarf_" + hex(dies_[i].offset); names.insert(name); }
        typeNames_[i] = name;
    }
    for (const auto& item : typeNames_) type(item.first);
    // A recursive pointer may have referred to a forward/incomplete aggregate.
    // Remove dependent declarations transitively instead of importing fake void
    // storage or an unresolved alias. Supported pointer cycles remain intact.
    for (size_t pass = 0; pass < typeInfos_.size(); ++pass) {
        bool changed = false;
        for (auto& item : typeInfos_) if (item.second.valid) {
            std::vector<size_t> dependencies;
            const auto own = referencedType(item.first);
            if (own != kNoParent) dependencies.push_back(own);
            for (auto child : dies_[item.first].children) if (dies_[child].tag == 0x0d) {
                const auto dependency = referencedType(child); if (dependency != kNoParent) dependencies.push_back(dependency);
            }
            for (auto dependency : dependencies) {
                auto found = typeInfos_.find(dependency);
                if (found == typeInfos_.end() || !found->second.valid) { item.second.valid = false; item.second.body.clear(); item.second.cType.clear(); changed = true; break; }
            }
        }
        if (!changed) break;
    }
    std::string library = "MINT_TYPES 1 " + std::to_string(report_.addressSize ? report_.addressSize : 8) + '\n';
    for (const auto& item : typeInfos_) if (item.second.valid) {
        const auto declaration = item.second.name + '=' + item.second.body;
        if (library.size() + declaration.size() + 1 > DataTypeManager::kMaxLibraryBytes) { warn("Imported DWARF type-library byte budget reached."); break; }
        library += declaration + '\n';
        report_.types.push_back({dies_[item.first].offset, item.second.name, declaration, item.second.size});
    }
    DataTypeManager check(report_.addressSize ? report_.addressSize : 8);
    const auto typesStatus = check.deserialize(library);
    if (!typesStatus.ok()) {
        warn("DWARF type declarations cannot form an exact validated library: " + typesStatus.message());
        for (auto& type : report_.types) type.declaration.clear();
    }
    std::map<size_t, Address> functionEntries;
    for (size_t i = 0; i < dies_.size(); ++i) if (dies_[i].tag == 0x2e) {
        DwarfFunction function; function.dieOffset = dies_[i].offset;
        function.name = string(i, kName); function.linkageName = string(i, kLinkage);
        if (function.linkageName.empty()) function.linkageName = string(i, 0x2007); // DW_AT_MIPS_linkage_name
        u64 declaration = 0; function.declaration = number(i, kDeclaration, &declaration) && declaration;
        auto status = ranges(i, &function.ranges); if (!status.ok()) return status;
        if (!function.ranges.empty()) {
            function.entry = function.ranges.front().low;
            if (!address(i, kEntryPc, &function.entry)) {
                u64 delta = 0;
                if (number(i, kEntryPc, &delta) && !add(function.entry, delta, &function.entry)) return malformed("entry_pc overflow");
            }
        }
        const auto returnType = type(referencedType(i));
        bool prototype = returnType.valid && !returnType.cType.empty();
        std::string parameters; size_t parameterCount = 0; std::set<std::string> parameterNames;
        for (auto child : dies_[i].children) {
            if (dies_[child].tag == 0x18) { if (!parameters.empty()) parameters += ", "; parameters += "..."; continue; }
            if (dies_[child].tag != 0x05) continue;
            auto argument = attribute(child, kType) ? type(referencedType(child)) : TypeInfo();
            auto name = identifier(string(child, kName), "arg" + std::to_string(parameterCount));
            if (!argument.valid || argument.cType.empty() || parameterCount >= 64 || !parameterNames.insert(name).second) prototype = false;
            if (parameterCount++) parameters += ", "; parameters += argument.cType + ' ' + name;
        }
        if (prototype && parameters.size() < 16384) function.prototype = returnType.cType + '(' + (parameters.empty() ? "void" : parameters) + ')';
        else if (!function.declaration) warn("Some DWARF prototypes use unsupported types/declarators; the prototype is omitted, not guessed.");
        const auto* frame = attribute(i, 0x40);
        if (frame && frame->kind == Attribute::kBlock) function.frameBaseExpression = expression(frame->bytes, units_[dies_[i].unit]).expression;
        functionEntries[i] = function.entry;
        if (!textBudget(function.name.size() + function.linkageName.size() + function.prototype.size())) return tooLarge();
        report_.functions.push_back(std::move(function));
    }
    for (size_t i = 0; i < dies_.size(); ++i) if (dies_[i].tag == 0x34 || dies_[i].tag == 0x05) {
        DwarfVariable variable; variable.dieOffset = dies_[i].offset; variable.parameter = dies_[i].tag == 0x05;
        variable.name = string(i, kName); const auto storage = attribute(i, kType) ? type(referencedType(i)) : TypeInfo();
        if (storage.valid) variable.type = storage.expression;
        size_t scope = dies_[i].parent;
        for (unsigned depth = 0; scope != kNoParent && depth < 64; ++depth) {
            variable.scopeDie = dies_[scope].offset;
            auto function = functionEntries.find(scope);
            if (function != functionEntries.end()) { variable.scope = function->second; break; }
            scope = dies_[scope].parent;
        }
        auto status = locations(i, &variable); if (!status.ok()) return status;
        if (!textBudget(variable.name.size() + variable.type.size() + variable.location.expression.size())) return tooLarge();
        report_.variables.push_back(std::move(variable));
    }
    for (const auto& unit : units_) {
        u64 offset = 0;
        if (number(unit.root, kStmtList, &offset)) {
            if (s_.line.empty()) warn("Compilation unit refers to missing .debug_line section.");
            else { auto status = lineTable(unit, offset); if (!status.ok()) return status; }
        }
    }
    return Status::success();
}

Status Reader::run() {
    for (const auto section : {s_.info, s_.abbrev, s_.strings, s_.line, s_.lineStrings, s_.stringOffsets, s_.addresses, s_.ranges, s_.rangeLists, s_.locations, s_.locationLists})
        if (section.size() > kMaxSection) return tooLarge();
    if (s_.info.empty()) return Status::error(ErrorCode::kNotFound, "DWARF .debug_info is absent");
    if (s_.abbrev.empty()) return malformed(".debug_abbrev is absent");
    auto status = parseUnits(); if (!status.ok()) return status;
    return buildReport();
}

}  // namespace

Status readDwarf(const DwarfSections& sections, DwarfReport* out) {
    if (!out) return malformed("null report output");
    DwarfReport candidate;
    auto status = Reader(sections, &candidate).run();
    if (status.ok()) *out = std::move(candidate);
    return status;
}

namespace {
struct OwnedDwarfSections {
    DwarfSections sections;
    std::map<std::string, std::vector<u8>> storage;
    u64 total = 0;
};
Status dwarfSections(const ElfImage& image, OwnedDwarfSections* out) {
    const bool split = image.findSection(".debug_info.dwo") != nullptr;
    out->sections.split = split;
    auto get = [&](const std::string& base, ByteView* result) -> Status {
        const std::string name = base + (split ? ".dwo" : "");
        const ElfSection* section = image.findSection(name);
        bool gnu = false;
        if (!section) { section = image.findSection(".z" + name.substr(1)); gnu = section != nullptr; }
        if (!section && !split) section = image.findSection("__DWARF,__" + base.substr(1));
        if (!section) { *result = {}; return Status::success(); }
        ByteView bytes = section->data;
        if (bytes.size() > kMaxSection) return tooLarge();
        if (!gnu && !(section->flags & 0x800)) { *result = bytes; return Status::success(); }
        u64 length = 0, offset = 0;
        if (gnu) {
            u32 marker = 0; if (!bytes.read(0, &marker) || marker != 0x42494c5a || !bytes.covers(4, 8)) return malformed("invalid GNU ZLIB section header");
            for (size_t i = 4; i < 12; ++i) length = (length << 8) | bytes.data()[i];
            offset = 12;
        } else {
            u32 kind = 0; if (!bytes.read(0, &kind)) return malformed("truncated ELF compressed-section header");
            if (kind != 1) return Status::error(ErrorCode::kUnsupported, "DWARF compression format is not zlib");
            if (image.format() == ImageFormat::kElf32) { u32 small = 0; if (!bytes.read(4, &small)) return malformed("truncated ELF32 compression header"); length = small; offset = 12; }
            else if (!bytes.read(8, &length)) return malformed("truncated ELF64 compression header");
            else offset = 24;
        }
        if (!length || length > kMaxSection || length > kMaxSection - out->total || !bytes.covers(offset, bytes.size() - std::min<u64>(offset, bytes.size()))) return tooLarge();
        std::vector<u8> decoded(static_cast<size_t>(length));
        z_stream stream{}; stream.next_in = const_cast<Bytef*>(bytes.data() + offset); stream.avail_in = static_cast<uInt>(bytes.size() - offset);
        stream.next_out = decoded.data(); stream.avail_out = static_cast<uInt>(decoded.size());
        if (inflateInit(&stream) != Z_OK) return malformed("zlib initialization failed");
        const int status = inflate(&stream, Z_FINISH);
        const bool valid = status == Z_STREAM_END && !stream.avail_in && stream.total_out == length;
        inflateEnd(&stream);
        if (!valid) return malformed("invalid/truncated/trailing compressed DWARF stream");
        out->total += length; auto inserted = out->storage.emplace(name, std::move(decoded));
        *result = ByteView(inserted.first->second.data(), inserted.first->second.size()); return Status::success();
    };
    for (auto pair : {std::pair<const char*, ByteView*>{".debug_info", &out->sections.info}, {".debug_abbrev", &out->sections.abbrev},
        {".debug_str", &out->sections.strings}, {".debug_line", &out->sections.line}, {".debug_line_str", &out->sections.lineStrings},
        {".debug_str_offsets", &out->sections.stringOffsets}, {".debug_addr", &out->sections.addresses}, {".debug_ranges", &out->sections.ranges},
        {".debug_rnglists", &out->sections.rangeLists}, {".debug_loc", &out->sections.locations}, {".debug_loclists", &out->sections.locationLists}}) {
        Status status = get(pair.first, pair.second); if (!status.ok()) return status;
    }
    return Status::success();
}
std::vector<u8> buildId(const ElfImage& image) {
    const auto* section = image.findSection(".note.gnu.build-id"); if (!section) return {};
    ByteView bytes = section->data;
    for (u64 offset = 0; bytes.covers(offset, 12);) {
        u32 names = 0, length = 0, kind = 0; bytes.read(offset, &names); bytes.read(offset + 4, &length); bytes.read(offset + 8, &kind);
        const u64 nameSize = (u64(names) + 3) & ~u64{3}, descSize = (u64(length) + 3) & ~u64{3};
        if (!bytes.covers(offset + 12, nameSize + descSize)) break;
        if (kind == 3 && names == 4 && length && length <= 64 && std::memcmp(bytes.data() + offset + 12, "GNU\0", 4) == 0)
            return std::vector<u8>(bytes.data() + offset + 12 + nameSize, bytes.data() + offset + 12 + nameSize + length);
        offset += 12 + nameSize + descSize;
    }
    return {};
}
} // namespace

Status readDwarf(const ElfImage& image, DwarfReport* out) {
    OwnedDwarfSections owned; Status status = dwarfSections(image, &owned);
    return status.ok() ? readDwarf(owned.sections, out) : status;
}

Status readDwarf(const ElfImage& image, const ElfImage& externalDebug, DwarfReport* out, bool allowUnverified) {
    if (!out) return malformed("null report output");
    if (image.arch() != externalDebug.arch() || image.pointerSize() != externalDebug.pointerSize()) return malformed("external debug object has different target architecture");
    OwnedDwarfSections primary, external;
    Status status = dwarfSections(image, &primary); if (!status.ok()) return status;
    status = dwarfSections(externalDebug, &external); if (!status.ok()) return status;
    bool verified = false; std::string evidence;
    if (const auto* link = !external.sections.split ? image.findSection(".gnu_debuglink") : nullptr) {
        std::string name;
        if (!link->data.cString(0, &name, 4096) || name.empty() || name.size() >= link->data.size() || link->data.data()[name.size()] != 0) return malformed("invalid GNU debuglink name");
        const u64 offset = (name.size() + 1 + 3) & ~u64{3}; u32 expected = 0;
        if (!link->data.read(offset, &expected)) return malformed("missing GNU debuglink checksum");
        const ByteView bytes = externalDebug.originalFile(); uLong actual = crc32(0, Z_NULL, 0);
        for (u64 at = 0; at < bytes.size();) { const uInt count = static_cast<uInt>(std::min<u64>(bytes.size() - at, 1024 * 1024)); actual = crc32(actual, bytes.data() + at, count); at += count; }
        if (static_cast<u32>(actual) != expected) return malformed("external debug object fails GNU debuglink CRC");
        verified = true; evidence = "GNU debuglink CRC";
    }
    const auto firstId = buildId(image), secondId = buildId(externalDebug);
    if (!external.sections.split && !firstId.empty() && !secondId.empty()) {
        if (firstId != secondId) return malformed("external debug object build-ID mismatch");
        verified = true; evidence = "ELF build-ID";
    }
    if (external.sections.split) {
        DwarfReport skeletonReport; status = readDwarf(primary.sections, &skeletonReport); if (!status.ok()) return status;
        DwarfReport dwoReport; status = readDwarf(external.sections, &dwoReport); if (!status.ok()) return status;
        const auto skeleton = skeletonReport.splitIds, dwo = dwoReport.splitIds;
        if (skeleton.empty() || skeleton != dwo) return malformed("split DWARF unit identity mismatch or unavailable");
        // Skeleton owns .debug_addr and its base. Split-unit DIEs own the rest.
        external.sections.addresses = primary.sections.addresses;
        external.sections.splitAddressBases = skeletonReport.splitAddressBases;
        verified = true; evidence = "DWARF5 skeleton/split unit ID";
    }
    if (!verified && !allowUnverified) return malformed("external debug object has no matching debuglink, build-ID or split-unit identity; explicit unverified acknowledgement required");
    DwarfReport candidate; status = readDwarf(external.sections, &candidate);
    if (!status.ok()) return status;
    candidate.warnings.push_back(verified ? "External debug object explicitly selected and verified by " + evidence + "; no filesystem path was followed automatically." :
        "UNVERIFIED external debug object: explicit user acknowledgement; no target identity is available and metadata must not be treated as proven.");
    if (!verified) candidate.partial = true;
    *out = std::move(candidate); return Status::success();
}

std::string dwarfReportText(const DwarfReport& report) {
    std::ostringstream out;
    out << report.format << ' ' << report.units << " units / " << report.dies << (report.format == "DWARF" ? " DIEs" : " records") << (report.partial ? " [partial]" : "") << '\n';
    for (const auto& function : report.functions) {
        out << "\nfunction " << function.name;
        if (function.entry != kNoAddress) out << " @ 0x" << std::hex << function.entry << std::dec;
        if (function.declaration) out << " [declaration]";
        out << '\n'; if (!function.prototype.empty()) out << "  " << function.prototype << '\n';
        for (const auto& range : function.ranges) out << "  [0x" << std::hex << range.low << ",0x" << range.high << ")" << std::dec << '\n';
    }
    for (const auto& type : report.types) out << "\ntype " << type.name << " size=" << type.byteSize << " " << (type.declaration.empty() ? "[not importable]" : type.declaration) << '\n';
    for (const auto& variable : report.variables) {
        out << "\n" << (variable.parameter ? "parameter " : "variable ") << variable.name << ": " << variable.type << " " << variable.location.expression << '\n';
        for (const auto& location : variable.locations) out << "  [0x" << std::hex << location.range.low << ",0x" << location.range.high << ") " << std::dec << location.location.expression << '\n';
    }
    for (const auto& row : report.sources) out << "\n0x" << std::hex << row.address << std::dec << ' ' << row.file << ':' << row.line << ':' << row.column << (row.endSequence ? " [end sequence]" : "");
    for (const auto& warning : report.warnings) out << "\nwarning: " << warning;
    out << '\n'; return out.str();
}

}  // namespace mint
