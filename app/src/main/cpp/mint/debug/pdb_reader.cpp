#include "mint/debug/pdb_reader.h"
#include "mint/loader/elf_image.h"
#include "mint/types/data_type_manager.h"
#include "mint/analysis/user_prototype.h"
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

namespace mint {
namespace {
Status bad(const std::string& text) { return Status::error(ErrorCode::kBadFormat, "PDB7: " + text); }
bool stringAt(ByteView bytes, u64 offset, std::string* text, u64* next = nullptr) {
    if (!bytes.cString(offset, text, 4096) || offset + text->size() >= bytes.size() || bytes.data()[offset + text->size()] != 0) return false;
    if (next) *next = offset + text->size() + 1; return true;
}
bool numeric(ByteView bytes, u64* offset, u64* value) {
    u16 leaf = 0; if (!bytes.read(*offset, &leaf)) return false; *offset += 2;
    if (leaf < 0x8000) { *value = leaf; return true; }
    const unsigned size = leaf == 0x8000 ? 1 : leaf == 0x8001 || leaf == 0x8002 ? 2 : leaf == 0x8003 || leaf == 0x8004 ? 4 : leaf == 0x8009 || leaf == 0x800a ? 8 : 0;
    if (!size || !bytes.covers(*offset, size)) return false;
    *value = 0; for (unsigned i = 0; i < size; ++i) *value |= u64(bytes.data()[(*offset)++]) << (i * 8);
    if ((leaf == 0x8000 || leaf == 0x8001 || leaf == 0x8003 || leaf == 0x8009) && (*value & (u64{1} << (size * 8 - 1)))) return false;
    return true;
}
class Streams {
public:
    Status load(ByteView file) {
        static constexpr char magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
        if (!file.covers(0, 56) || std::memcmp(file.data(), magic, 32)) return bad("MSF7 signature absent");
        file_ = file; u32 directoryBytes = 0, blockMap = 0;
        if (!file.read(32, &blockSize_) || !file.read(40, &blocks_) || !file.read(44, &directoryBytes) || !file.read(52, &blockMap) ||
            blockSize_ < 512 || blockSize_ > 65536 || (blockSize_ & (blockSize_ - 1)) || blocks_ > file.size() / blockSize_ || !blocks_ || directoryBytes > 16 * 1024 * 1024)
            return bad("invalid MSF superblock");
        const u64 count = (u64(directoryBytes) + blockSize_ - 1) / blockSize_;
        if (count > blockSize_ / 4 || blockMap >= blocks_ || !file.covers(u64(blockMap) * blockSize_, count * 4)) return bad("invalid MSF directory block map");
        std::vector<u8> directory(directoryBytes); std::set<u32> used;
        for (u64 i = 0; i < count; ++i) {
            u32 block = 0; file.read(u64(blockMap) * blockSize_ + i * 4, &block);
            if (block >= blocks_ || !used.insert(block).second) return bad("invalid/repeated MSF directory block");
            const u64 length = std::min<u64>(blockSize_, directoryBytes - i * blockSize_);
            std::memcpy(directory.data() + i * blockSize_, file.data() + u64(block) * blockSize_, length);
        }
        ByteView view(directory.data(), directory.size()); u32 streams = 0;
        if (!view.read(0, &streams) || streams > 65536 || !view.covers(4, u64(streams) * 4)) return bad("invalid MSF stream count");
        u64 cursor = 4 + u64(streams) * 4, totalBlocks = 0;
        for (u32 i = 0; i < streams; ++i) {
            Stream stream; view.read(4 + u64(i) * 4, &stream.size);
            const u64 count = stream.size == ~u32{0} ? 0 : (u64(stream.size) + blockSize_ - 1) / blockSize_;
            if (count > blocks_ || totalBlocks + count > blocks_ * 2ULL || !view.covers(cursor, count * 4)) return bad("invalid MSF stream block list");
            used.clear();
            for (u64 n = 0; n < count; ++n) { u32 block = 0; view.read(cursor, &block); cursor += 4; if (block >= blocks_ || !used.insert(block).second) return bad("invalid/repeated stream block"); stream.blocks.push_back(block); }
            totalBlocks += count; streams_.push_back(std::move(stream));
        }
        if (cursor != view.size()) return bad("trailing MSF stream-directory data");
        return Status::success();
    }
    ByteView stream(u32 index) {
        if (index >= streams_.size() || streams_[index].size == ~u32{0} || streams_[index].size > 32 * 1024 * 1024) return {};
        auto found = copies_.find(index);
        if (found == copies_.end()) {
            const auto& source = streams_[index]; if (source.size > 128 * 1024 * 1024 - copied_) return {};
            std::vector<u8> bytes(source.size);
            for (u64 i = 0; i < source.blocks.size(); ++i) { const u64 length = std::min<u64>(blockSize_, source.size - i * blockSize_); std::memcpy(bytes.data() + i * blockSize_, file_.data() + u64(source.blocks[i]) * blockSize_, length); }
            copied_ += source.size; found = copies_.emplace(index, std::move(bytes)).first;
        }
        return ByteView(found->second.data(), found->second.size());
    }
private:
    struct Stream { u32 size = 0; std::vector<u32> blocks; };
    ByteView file_; u32 blockSize_ = 0, blocks_ = 0; u64 copied_ = 0;
    std::vector<Stream> streams_; std::map<u32, std::vector<u8>> copies_;
};
struct Storage { std::string expression, ctype; u64 size = 0; u32 alignment = 1; bool valid = false; };
class Types {
public:
    Types(u8 width, DwarfReport* report) : width_(width), report_(*report) {}
    Status load(ByteView bytes) {
        if (bytes.empty()) { warn("TPI stream absent"); return Status::success(); }
        u32 header = 0, begin = 0, end = 0, size = 0;
        if (!bytes.read(4, &header) || header < 56 || !bytes.read(8, &begin) || !bytes.read(12, &end) || !bytes.read(16, &size) ||
            begin < 0x1000 || end < begin || end - begin > 65536 || !bytes.covers(header, size)) return bad("invalid TPI header");
        u64 cursor = header;
        for (u32 index = begin; index < end; ++index) {
            u16 length = 0; if (!bytes.read(cursor, &length) || length < 2 || !bytes.covers(cursor + 2, length) || cursor + 2 + length > u64(header) + size) return bad("truncated TPI record");
            records_[index] = bytes.subview(cursor + 2, length); cursor += 2 + length;
        }
        if (cursor != u64(header) + size) return bad("TPI record count/extent mismatch");
        for (const auto& pair : records_) {
            u16 kind = 0; pair.second.read(0, &kind);
            if (kind != 0x1504 && kind != 0x1505 && kind != 0x1506 && kind != 0x1507) continue;
            u64 offset = kind == 0x1506 ? 10 : kind == 0x1507 ? 14 : 18, size = 0;
            if (kind != 0x1507 && !numeric(pair.second, &offset, &size)) continue;
            std::string name; if (!stringAt(pair.second, offset, &name)) continue;
            if (!DataTypeManager::validName(name) || !userIdentifier(name)) name = "PdbType_" + std::to_string(pair.first);
            names_[pair.first] = name; u16 flags = 0; pair.second.read(4, &flags);
            if (!(flags & 0x80)) definitions_[name] = pair.first;
        }
        for (const auto& pair : definitions_) storage(pair.second);
        for (const auto& pair : declarations_) report_.types.push_back({pair.first, names_[pair.first], pair.second, storage(pair.first).size});
        return Status::success();
    }
    Storage storage(u32 index, unsigned depth = 0, bool pointerTarget = false) {
        if (depth > 32) return {};
        if (index < 0x1000) {
            const u32 base = index & 0xff, mode = index & 0x700;
            static const std::map<u32, std::pair<const char*, u64>> primitives = {{3,{"void",0}},{0x10,{"i8",1}},{0x20,{"u8",1}},{0x30,{"bool",1}},{0x40,{"f32",4}},{0x41,{"f64",8}},{0x68,{"i8",1}},{0x69,{"u8",1}},{0x70,{"char",1}},{0x71,{"u16",2}},{0x72,{"i16",2}},{0x73,{"u16",2}},{0x74,{"i32",4}},{0x75,{"u32",4}},{0x76,{"i64",8}},{0x77,{"u64",8}}};
            const auto found = primitives.find(base); if (found == primitives.end()) return {};
            Storage result; result.expression = found->second.first; result.size = found->second.second; result.alignment = std::max<u64>(1, result.size); result.valid = true;
            static const std::map<std::string, std::string> cNames = {{"void","void"},{"bool","uint8_t"},{"char","char"},{"i8","int8_t"},{"u8","uint8_t"},{"i16","int16_t"},{"u16","uint16_t"},{"i32","int32_t"},{"u32","uint32_t"},{"i64","int64_t"},{"u64","uint64_t"},{"f32","float"},{"f64","double"}};
            result.ctype = cNames.at(result.expression);
            if (mode) { if (mode != (width_ == 8 ? 0x600 : 0x400)) return {}; result.expression += '*'; result.ctype += '*'; result.size = result.alignment = width_; }
            return result;
        }
        const auto found = records_.find(index); if (found == records_.end()) return {};
        u16 kind = 0; found->second.read(0, &kind); const ByteView bytes = found->second;
        if (pointerTarget && names_.count(index)) return {names_[index], names_[index], 0, 1, true};
        const auto cached = cache_.find(index); if (cached != cache_.end()) return cached->second;
        if (!active_.insert(index).second) return {};
        Storage result; u32 childIndex = 0;
        if (kind == 0x1001) { if (bytes.read(2, &childIndex)) result = storage(childIndex, depth + 1); }
        else if (kind == 0x1002) {
            u32 attributes = 0; if (bytes.read(2, &childIndex) && bytes.read(6, &attributes) && ((attributes >> 5) & 7) <= 1 && ((attributes >> 13) & 0x3f) == width_) {
                result = storage(childIndex, depth + 1, true); if (result.valid) { result.expression += '*'; result.ctype += '*'; result.size = result.alignment = width_; }
            }
        } else if (kind == 0x1503) {
            u64 offset = 10, size = 0;
            if (bytes.read(2, &childIndex) && numeric(bytes, &offset, &size)) { result = storage(childIndex, depth + 1); if (!result.valid || !result.size || !size || size % result.size || size > DataTypeManager::kMaxTypeBytes) result = {}; else { result.expression += '[' + std::to_string(size / result.size) + ']'; result.ctype.clear(); result.size = size; } }
        } else if (kind == 0x1504 || kind == 0x1505 || kind == 0x1506) {
            const auto name = names_.find(index); u16 flags = 0; bytes.read(4, &flags);
            if (name != names_.end() && (flags & 0x80) && definitions_.count(name->second)) result = storage(definitions_[name->second], depth + 1);
            else if (name != names_.end() && !(flags & 0x80)) {
                u32 fieldList = 0; bytes.read(6, &fieldList); u64 offset = kind == 0x1506 ? 10 : 18, size = 0;
                std::string body; u64 end = 0; u32 alignment = 1; bool packed = false;
                if (numeric(bytes, &offset, &size) && size && size <= DataTypeManager::kMaxTypeBytes && fields(fieldList, kind == 0x1506, depth + 1, &body, &end, &alignment, &packed) && !body.empty()) {
                    if (end <= size) {
                        if (packed) alignment = 1;
                        if (kind != 0x1506 && (end + alignment - 1) / alignment * alignment < size) body += ";pdb_tail:u8[" + std::to_string(size - end) + "]@" + std::to_string(end);
                        const u64 computed = (std::max(end, kind != 0x1506 ? size : end) + alignment - 1) / alignment * alignment;
                        if (computed == size) {
                            const std::string declaration = name->second + '=' + (kind == 0x1506 ? "union{" : packed ? "packed{" : "struct{") + body + '}';
                            declarations_[index] = declaration; result = {name->second, name->second, size, alignment, true};
                        }
                    }
                }
            }
        } else if (kind == 0x1507) {
            // Enum storage is authoritative even when an enumerator uses a
            // numeric leaf not represented by the editing DSL.
            if (bytes.read(6, &childIndex)) result = storage(childIndex, depth + 1);
        }
        if (!result.valid && (kind == 0x1504 || kind == 0x1505 || kind == 0x1506)) warn("Some TPI aggregate layouts are forward/bitfield/virtual/overlapping or unsupported; no replacement object layout was invented");
        active_.erase(index); cache_[index] = result; return result;
    }
    std::string prototype(u32 index, bool x86) {
        const auto found = records_.find(index); if (found == records_.end()) return {};
        ByteView bytes = found->second; u16 kind = 0, count = 0; u32 resultIndex = 0, arguments = 0; u8 convention = 0;
        bytes.read(0, &kind); if (kind != 0x1008) return {};
        if (!bytes.read(2, &resultIndex) || !bytes.byteAt(6, &convention) || !bytes.read(8, &count) || !bytes.read(10, &arguments) || count > 64 || (x86 && convention != 0)) return {};
        const auto result = storage(resultIndex); if (!result.valid || result.ctype.empty()) return {};
        auto list = records_.find(arguments); if (list == records_.end()) return {}; u16 listKind = 0; u32 listCount = 0;
        list->second.read(0, &listKind); if (listKind != 0x1201 || !list->second.read(2, &listCount) || listCount > 65 || !list->second.covers(6, u64(listCount) * 4)) return {};
        std::string text = result.ctype + '(';
        for (u32 i = 0; i < listCount; ++i) {
            u32 type = 0; list->second.read(6 + i * 4, &type); if (i) text += ", ";
            if (!type && i + 1 == listCount) text += "...";
            else { const auto argument = storage(type); if (!argument.valid || argument.ctype.empty()) return {}; text += argument.ctype + " arg" + std::to_string(i); }
        }
        if (!listCount) text += "void";
        if (listCount < count || listCount > count + 1) return {};
        return text + ')';
    }
private:
    bool fields(u32 index, bool isUnion, unsigned depth, std::string* body, u64* end, u32* alignment, bool* packed) {
        if (depth > 32) return false;
        const auto found = records_.find(index); if (found == records_.end()) return false;
        ByteView bytes = found->second; u16 kind = 0; bytes.read(0, &kind); if (kind != 0x1203) return false;
        std::set<std::string> names; u64 cursor = 2; size_t count = 0;
        while (cursor < bytes.size() && ++count <= 256) {
            if (bytes.data()[cursor] >= 0xf0) { const u8 padding = bytes.data()[cursor] & 15; if (!padding || !bytes.covers(cursor, padding)) return false; cursor += padding; continue; }
            const u64 start = cursor; u16 leaf = 0, attrs = 0; u32 type = 0; u64 offset = 0; std::string name;
            if (!bytes.read(cursor, &leaf)) return false;
            if (leaf == 0x150d || leaf == 0x1400) {
                if (!bytes.read(cursor + 2, &attrs) || !bytes.read(cursor + 4, &type)) return false;
                cursor += 8; if (!numeric(bytes, &cursor, &offset)) return false;
                if (leaf == 0x150d) { if (!stringAt(bytes, cursor, &name, &cursor)) return false; }
                else name = "base_" + std::to_string(count);
                const auto field = storage(type, depth + 1);
                if (!field.valid || !field.size || !DataTypeManager::validName(name) || !userIdentifier(name) || !names.insert(name).second ||
                    (isUnion ? offset != 0 : offset < *end) || offset > DataTypeManager::kMaxTypeBytes || field.size > DataTypeManager::kMaxTypeBytes - offset) return false;
                *packed = *packed || offset % field.alignment; *alignment = std::max(*alignment, field.alignment); *end = std::max(*end, offset + field.size);
                if (!body->empty()) *body += ';'; *body += name + ':' + field.expression + '@' + std::to_string(offset);
            } else if (leaf == 0x1404) { if (!bytes.read(cursor + 4, &type) || cursor + 8 != bytes.size()) return false; return fields(type, isUnion, depth + 1, body, end, alignment, packed); }
            else if (leaf == 0x150e || leaf == 0x150f || leaf == 0x1510 || leaf == 0x1511) {
                if (!bytes.read(cursor + 2, &attrs)) return false;
                cursor += 8;
                if (leaf == 0x1511 && (((attrs >> 2) & 7) == 4 || ((attrs >> 2) & 7) == 6)) cursor += 4;
                if (!stringAt(bytes, cursor, &name, &cursor)) return false;
            } else return false;
            if (cursor <= start || body->size() > 12000) return false;
        }
        return cursor == bytes.size();
    }
    void warn(const std::string& text) { report_.partial = true; if (std::find(report_.warnings.begin(), report_.warnings.end(), text) == report_.warnings.end() && report_.warnings.size() < 128) report_.warnings.push_back(text); }
    u8 width_; DwarfReport& report_; std::map<u32, ByteView> records_; std::map<u32, std::string> names_, declarations_;
    std::map<std::string, u32> definitions_; std::map<u32, Storage> cache_; std::set<u32> active_;
};
} // namespace

Status readPdb(const ElfImage& image, ByteView pdb, DwarfReport* out, bool allowUnverified) {
    if (!out || image.format() != ImageFormat::kPe64 || pdb.size() > 128 * 1024 * 1024) return bad("requires a PE image, output and bounded explicit PDB object");
    Streams streams; Status status = streams.load(pdb); if (!status.ok()) return status;
    ByteView identity = streams.stream(1); u32 age = 0; std::array<u8, 16> guid{};
    if (!identity.read(8, &age) || !identity.covers(12, 16)) return bad("truncated PDB identity stream"); std::copy(identity.data() + 12, identity.data() + 28, guid.begin());
    bool matched = false;
    for (const auto& record : image.peCodeViewRecords()) if (record.guid == guid && record.age == age) matched = true;
    if (!matched && (!image.peCodeViewRecords().empty() || !allowUnverified)) return bad("PDB GUID/age differs from PE RSDS identity or explicit unverified acknowledgement is absent");
    ByteView dbi = streams.stream(3); u32 signature = 0, dbiAge = 0; u16 machine = 0, symbolStream = 0;
    if (!dbi.read(0, &signature) || signature != ~u32{0} || !dbi.read(8, &dbiAge) || dbiAge != age || !dbi.read(20, &symbolStream) || !dbi.read(58, &machine) ||
        machine != (image.arch() == Arch::kX86_64 ? 0x8664 : image.arch() == Arch::kAArch64 ? 0xaa64 : 0x14c)) return bad("DBI identity/target machine mismatch");
    DwarfReport report; report.format = "PDB7/CodeView"; report.addressSize = image.pointerSize(); report.units = 1;
    report.warnings.push_back(matched ? "PDB explicitly selected and verified by PE RSDS GUID/age; recorded PDB path was not opened" : "UNVERIFIED PDB explicitly acknowledged; metadata identity is not proven");
    report.partial = !matched; Types types(image.pointerSize(), &report); status = types.load(streams.stream(2)); if (!status.ok()) return status;
    auto address = [&](u16 section, u32 offset, Address* value) {
        if (!section || section > image.sections().size()) return false; const auto& target = image.sections()[section - 1];
        if (offset >= target.size || target.addr > ~Address{0} - offset) return false; *value = target.addr + offset; return image.memory().isMapped(*value);
    };
    std::set<std::pair<Address, std::string>> seen;
    auto symbols = [&](ByteView bytes) -> Status {
        u64 cursor = 0;
        while (cursor < bytes.size()) {
            if (++report.dies > 200000) return Status::error(ErrorCode::kTooLarge, "PDB symbol budget exceeded");
            u16 length = 0, kind = 0;
            if (!bytes.read(cursor, &length) || length < 2 || !bytes.covers(cursor + 2, length)) return bad("truncated CodeView symbol record");
            ByteView record = bytes.subview(cursor + 2, length); record.read(0, &kind); cursor += 2 + length;
            u32 offset = 0, type = 0, size = 0, flags = 0; u16 segment = 0; u64 nameOffset = 0; bool function = false, data = false;
            if (kind == 0x110e) { if (!record.read(2, &flags) || !record.read(6, &offset) || !record.read(10, &segment)) return bad("truncated PUB32"); nameOffset = 12; function = (flags & 3) != 0; }
            else if (kind == 0x110f || kind == 0x1110) { if (!record.read(14, &size) || !record.read(26, &type) || !record.read(30, &offset) || !record.read(34, &segment)) return bad("truncated PROC32"); nameOffset = 37; function = true; }
            else if (kind == 0x110c || kind == 0x110d) { if (!record.read(2, &type) || !record.read(6, &offset) || !record.read(10, &segment)) return bad("truncated DATA32"); nameOffset = 12; data = true; }
            else continue;
            std::string name; Address at = 0;
            if (!stringAt(record, nameOffset, &name) || !address(segment, offset, &at)) return bad("invalid CodeView symbol address/name");
            if (!function && !data) continue;
            if (function && (!image.memory().isExecutable(at) || (size && (size > image.sections()[segment - 1].size - offset || !image.memory().isExecutable(at + size - 1))))) return bad("PDB function range is not executable in its bound PE");
            if (!seen.emplace(at, name + (function ? ":fn" : ":data")).second) {
                // Publics establish identity; richer module PROC32 metadata
                // supplies ranges/prototypes for that same exact binding.
                if (function && (type || size)) for (auto& fn : report.functions) if (fn.entry == at && fn.name == name) {
                    if (type) fn.prototype = types.prototype(type, image.arch() == Arch::kX86_32);
                    if (size) fn.ranges = {{at, at + size}}; break;
                }
                continue;
            }
            if (function) {
                DwarfFunction fn; fn.entry = at; fn.name = fn.linkageName = name; fn.dieOffset = report.dies;
                if (size) fn.ranges.push_back({at, at + size}); if (type) fn.prototype = types.prototype(type, image.arch() == Arch::kX86_32);
                report.functions.push_back(std::move(fn));
            } else if (data) {
                DwarfVariable variable; variable.name = name; variable.location.kind = DwarfLocation::Kind::kAddress; variable.location.address = at; variable.location.expression = "PE address 0x" + std::to_string(at);
                const auto storage = types.storage(type); if (storage.valid) variable.type = storage.expression;
                report.variables.push_back(std::move(variable));
            }
            if (report.functions.size() > 100000 || report.variables.size() > 100000) return Status::error(ErrorCode::kTooLarge, "PDB metadata budget exceeded");
        }
        return Status::success();
    };
    status = symbols(streams.stream(symbolStream)); if (!status.ok()) return status;
    u32 moduleBytes = 0, contributionBytes = 0, sectionMapBytes = 0, fileBytes = 0, serverBytes = 0, optionalBytes = 0, ecBytes = 0;
    dbi.read(24, &moduleBytes); dbi.read(28, &contributionBytes); dbi.read(32, &sectionMapBytes); dbi.read(36, &fileBytes); dbi.read(40, &serverBytes); dbi.read(48, &optionalBytes); dbi.read(52, &ecBytes);
    const u64 optional = 64 + u64(moduleBytes) + contributionBytes + sectionMapBytes + fileBytes + serverBytes + ecBytes;
    if (!dbi.covers(64, moduleBytes) || !dbi.covers(optional, optionalBytes) || optionalBytes % 2) return bad("invalid DBI substream extent");
    // OMAP rewrites addresses; do not publish a wrong old-layout symbol index.
    u16 omap = 0xffff;
    if ((optionalBytes >= 8 && dbi.read(optional + 6, &omap) && omap != 0xffff) || (optionalBytes >= 10 && dbi.read(optional + 8, &omap) && omap != 0xffff)) return Status::error(ErrorCode::kUnsupported, "PDB OMAP address transformation requires an explicit remapping model");
    for (u64 cursor = 64; cursor < 64 + u64(moduleBytes);) {
        if (!dbi.covers(cursor, 64)) return bad("truncated DBI module header");
        u16 stream = 0xffff; u32 symbolBytes = 0; dbi.read(cursor + 34, &stream); dbi.read(cursor + 36, &symbolBytes);
        std::string module, object; u64 next = cursor + 64;
        if (!stringAt(dbi, next, &module, &next) || !stringAt(dbi, next, &object, &next)) return bad("unterminated DBI module names");
        cursor = (next + 3) & ~u64{3}; if (cursor > 64 + u64(moduleBytes)) return bad("DBI module extent mismatch");
        if (stream == 0xffff || !symbolBytes) continue;
        ByteView moduleStream = streams.stream(stream); u32 signature = 0;
        if (symbolBytes < 4 || !moduleStream.covers(0, symbolBytes) || !moduleStream.read(0, &signature) || signature != 4) return bad("invalid module CodeView symbol signature");
        status = symbols(moduleStream.subview(4, symbolBytes - 4)); if (!status.ok()) return status;
    }
    report.partial = true;
    report.warnings.push_back("Imported bounded DBI public/procedure/data symbols and exact TPI layouts; source C13 lines, type servers, virtual/bitfield object layouts and unhandled CodeView record families are not inferred");
    *out = std::move(report); return Status::success();
}
} // namespace mint
