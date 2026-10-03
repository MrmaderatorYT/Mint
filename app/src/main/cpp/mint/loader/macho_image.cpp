#include "mint/loader/elf_image.h"

#include <algorithm>
#include <limits>
#include <set>
#include <functional>
#include <zlib.h>

namespace mint {
namespace {
std::string fixedMachName(ByteView view, u64 offset) {
    ByteView bytes = view.subview(offset, 16);
    if (bytes.empty()) return {};
    size_t count = 0;
    while (count < bytes.size() && bytes.data()[count] != 0) ++count;
    return std::string(reinterpret_cast<const char*>(bytes.data()), count);
}

bool machString(ByteView view, u64 offset, std::string* out) {
    if (!view.cString(offset, out, 4096)) return false;
    u8 terminator = 1;
    return view.byteAt(offset + out->size(), &terminator) && terminator == 0;
}

bool readDelta(ByteView data, u64* offset, u64* result) {
    *result = 0;
    for (unsigned shift = 0; shift < 70; shift += 7) {
        u8 byte = 0;
        if (!data.byteAt(*offset, &byte)) return false;
        ++*offset;
        if (shift == 63 && (byte & 0x7e) != 0) return false;
        *result |= static_cast<u64>(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) return true;
    }
    return false;
}
bool readSigned(ByteView data, u64* offset, i64* result) {
    u64 bits = 0;
    for (unsigned i = 0; i < 10; ++i) {
        u8 b = 0; if (!data.byteAt((*offset)++, &b) || (i == 9 && (b & 0x7f) != 0 && (b & 0x7f) != 0x7f)) return false;
        bits |= u64(b & (i == 9 ? 1 : 0x7f)) << (i * 7);
        if (!(b & 0x80)) { if (i < 9 && (b & 0x40)) bits |= ~u64{0} << (i * 7 + 7); *result = static_cast<i64>(bits); return true; }
    }
    return false;
}
}  // namespace

Status ElfImage::loadMachOSlice(ByteView file, Arch architecture) {
    *this = ElfImage(); originalFile_ = file;
    return loadMachOFat(file, architecture);
}

Status ElfImage::loadMachOFat(ByteView file, Arch preferred) {
    u32 magic = 0; file.read(0, &magic);
    const bool big = magic == 0xbebafeca || magic == 0xbfbafeca;
    const bool wide = magic == 0xcafebabf || magic == 0xbfbafeca;
    if (!big && magic != 0xcafebabe && magic != 0xcafebabf)
        return Status::error(ErrorCode::kBadFormat, "not a universal Mach-O");
    auto integer = [&](u64 offset, unsigned width, u64* value) {
        if (!file.covers(offset, width)) return false; *value = 0;
        for (unsigned i = 0; i < width; ++i) *value |= u64(file.data()[offset + i]) << ((big ? width - 1 - i : i) * 8);
        return true;
    };
    u64 count = 0; if (!integer(4, 4, &count) || !count || count > 64 || !file.covers(8, count * (wide ? 32 : 20)))
        return Status::error(ErrorCode::kBadFormat, "invalid universal Mach-O slice table");
    struct Slice { u64 offset, size; Arch arch; };
    std::vector<Slice> slices;
    for (u64 i = 0; i < count; ++i) {
        const u64 at = 8 + i * (wide ? 32 : 20); u64 cpu = 0, offset = 0, size = 0, alignment = 0;
        integer(at, 4, &cpu); integer(at + 8, wide ? 8 : 4, &offset); integer(at + (wide ? 16 : 12), wide ? 8 : 4, &size);
        integer(at + (wide ? 24 : 16), 4, &alignment);
        if (!size || alignment > 30 || (offset & ((u64{1} << alignment) - 1)) || offset < 8 + count * (wide ? 32 : 20) || !file.covers(offset, size))
            return Status::error(ErrorCode::kBadFormat, "invalid universal Mach-O slice extent/alignment");
        for (const auto& old : slices) if (offset < old.offset + old.size && old.offset < offset + size)
            return Status::error(ErrorCode::kBadFormat, "overlapping universal Mach-O slices");
        const Arch arch = cpu == 0x0100000c ? Arch::kAArch64 : cpu == 0x01000007 ? Arch::kX86_64 : cpu == 7 ? Arch::kX86_32 : cpu == 12 ? Arch::kArm32 : Arch::kUnknown;
        slices.push_back({offset, size, arch});
    }
    for (const auto& slice : slices) {
        if (slice.arch == Arch::kUnknown || (preferred != Arch::kUnknown && slice.arch != preferred)) continue;
        u32 innerMagic = 0; file.read(slice.offset, &innerMagic);
        if (innerMagic != 0xfeedface && innerMagic != 0xfeedfacf)
            return Status::error(ErrorCode::kBadFormat, "universal Mach-O slice is not a thin little-endian image");
        ElfImage candidate; Status status = candidate.load(file.subview(slice.offset, slice.size));
        if (!status.ok()) return status;
        if (candidate.format_ != ImageFormat::kMachO64 || candidate.arch_ != slice.arch)
            return Status::error(ErrorCode::kBadFormat, "universal Mach-O slice disagrees with its CPU descriptor");
        candidate.originalFile_ = file;
        for (auto& section : candidate.sections_) if (!section.data.empty()) section.fileOffset += slice.offset;
        candidate.addWarning("Universal Mach-O: selected " + std::string(archName(slice.arch)) + " slice at file offset " + std::to_string(slice.offset) + "; other slices remain unchanged on patch export");
        *this = std::move(candidate); return Status::success();
    }
    return Status::error(ErrorCode::kUnsupported, "universal Mach-O has no requested/supported little-endian native slice");
}

// The little-endian thin 64-bit layout is intentionally parsed without SDK
// structs so this loader also builds on Android and Linux.
Status ElfImage::loadMachO64(ByteView file) {
    format_ = ImageFormat::kMachO64;
    const auto bad = [](const char* message) {
        return Status::error(ErrorCode::kBadFormat, message);
    };
    u32 magic = 0, cpu = 0, subtype = 0, fileType = 0, commandCount = 0, commandBytes = 0, flags = 0;
    file.read(0, &magic); const bool narrow = magic == 0xfeedface; const u64 headerSize = narrow ? 28 : 32;
    if (!file.covers(0, headerSize) || !file.read(4, &cpu) || !file.read(8, &subtype) ||
        !file.read(12, &fileType) || !file.read(16, &commandCount) ||
        !file.read(20, &commandBytes) || !file.read(24, &flags))
        return bad("truncated Mach-O64 header");
    if (cpu == 0x01000007) arch_ = Arch::kX86_64;
    else if (cpu == 0x0100000c) arch_ = Arch::kAArch64;
    else if (cpu == 7 && narrow) arch_ = Arch::kX86_32;
    else if (cpu == 12 && narrow) arch_ = Arch::kArm32;
    else return Status::error(ErrorCode::kUnsupported, "Mach-O supports little-endian x86/ARM 32/64 slices only");
    if (narrow != ((cpu & 0x01000000) == 0)) return bad("Mach-O CPU and header width disagree");
    if (fileType != 2 && fileType != 6 && fileType != 7 && fileType != 8)
        return Status::error(ErrorCode::kUnsupported, "Mach-O relocatable objects/core files are not supported");
    if (commandCount > 8192 || commandBytes > 64 * 1024 * 1024 ||
        !file.covers(headerSize, commandBytes) || commandCount > commandBytes / 8)
        return bad("invalid Mach-O load command extent");
    positionIndependent_ = (flags & 0x200000) != 0 || fileType == 6 || fileType == 8;
    type_ = elf::kEtExec;
    struct FileSegment { Address address; u64 size; u64 offset; u64 fileSize; std::string name; };
    std::vector<FileSegment> fileSegments;
    u32 symbolOffset = 0, symbolCount = 0, stringsOffset = 0, stringsSize = 0;
    u32 startsOffset = 0, startsSize = 0;
    bool haveSymbols = false, haveEntryOffset = false;
    u64 entryOffset = 0;
    Address unixEntry = 0, textBase = 0;
    bool haveText = false;
    u32 rebaseOffset = 0, rebaseSize = 0, bindOffset = 0, bindSize = 0, weakOffset = 0, weakSize = 0, lazyOffset = 0, lazySize = 0, exportOffset = 0, exportSize = 0, chainOffset = 0, chainSize = 0;
    u64 offset = headerSize;
    const u64 commandEnd = headerSize + static_cast<u64>(commandBytes);
    for (u64 i = 0; i < commandCount; ++i) {
        u32 command = 0, size = 0;
        if (!file.read(offset, &command) || !file.read(offset + 4, &size) || size < 8 ||
            (size & (narrow ? 3 : 7)) != 0 || size > commandEnd - offset)
            return bad("invalid Mach-O load command size/alignment");
        ByteView view = file.subview(offset, size);
        if (command == (narrow ? 1u : 0x19u)) {  // LC_SEGMENT / LC_SEGMENT_64
            Address address = 0;
            u64 virtualSize = 0, fileOffset = 0, fileSize = 0;
            u32 protection = 0, sectionCount = 0, segmentFlags = 0;
            bool fields = true;
            if (narrow) {
                u32 a = 0, v = 0, f = 0, s = 0;
                fields = view.read(24, &a) && view.read(28, &v) && view.read(32, &f) && view.read(36, &s) &&
                    view.read(44, &protection) && view.read(48, &sectionCount) && view.read(52, &segmentFlags);
                address = a; virtualSize = v; fileOffset = f; fileSize = s;
            } else fields = view.read(24, &address) && view.read(32, &virtualSize) &&
                view.read(40, &fileOffset) && view.read(48, &fileSize) &&
                view.read(60, &protection) && view.read(64, &sectionCount) && view.read(68, &segmentFlags);
            const u64 segmentHeader = narrow ? 56 : 72, sectionStride = narrow ? 68 : 80;
            if (!fields || sectionCount > 65535 || !view.covers(segmentHeader, static_cast<u64>(sectionCount) * sectionStride))
                return bad("invalid Mach-O64 segment/section table");
            if ((segmentFlags & 1) != 0)
                return Status::error(ErrorCode::kUnsupported, "Mach-O SG_HIGHVM segments are not supported");
            if (fileSize > virtualSize || address > std::numeric_limits<Address>::max() - virtualSize ||
                (narrow && virtualSize > (u64{1} << 32) - address) ||
                !file.covers(fileOffset, fileSize))
                return bad("invalid Mach-O segment virtual/file range");
            const std::string name = fixedMachName(view, 8);
            if (name == "__TEXT") { textBase = address; haveText = true; }
            u32 permissions = 0;
            if ((protection & 1) != 0) permissions |= kMemRead;
            if ((protection & 2) != 0) permissions |= kMemWrite;
            if ((protection & 4) != 0) permissions |= kMemExec;
            // __PAGEZERO reserves invalid addresses; it is not readable memory.
            if (virtualSize != 0 && (permissions != 0 || fileSize != 0)) {
                for (const MemorySegment& existing : memory_.segments()) {
                    if (address < existing.end() && existing.start < address + virtualSize)
                        return bad("overlapping Mach-O segments");
                }
                memory_.addSegment(address, virtualSize, file.subview(fileOffset, fileSize), permissions, name);
            }
            // dyld opcodes index every segment command, including __PAGEZERO.
            fileSegments.push_back({address, virtualSize, fileOffset, fileSize, name});
            for (u64 sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
                const u64 at = segmentHeader + sectionIndex * sectionStride;
                ElfSection section;
                const std::string sectionName = fixedMachName(view, at);
                const std::string segmentName = fixedMachName(view, at + 16);
                section.name = segmentName + "," + sectionName;
                u32 rawOffset = 0, sectionFlags = 0;
                if (narrow) { u32 a = 0, s = 0; view.read(at + 32, &a); view.read(at + 36, &s); section.addr = a; section.size = s; }
                else { view.read(at + 32, &section.addr); view.read(at + 40, &section.size); }
                view.read(at + (narrow ? 40 : 48), &rawOffset);
                view.read(at + (narrow ? 56 : 64), &sectionFlags);
                if (section.addr < address || section.addr - address > virtualSize ||
                    section.size > virtualSize - (section.addr - address))
                    return bad("Mach-O section lies outside its segment");
                const u32 kind = sectionFlags & 0xff;
                const bool zeroFill = kind == 1 || kind == 0xc || kind == 0x12;
                section.type = zeroFill ? elf::kShtNoBits : elf::kShtProgBits;
                section.flags = permissions == 0 ? 0 : elf::kShfAlloc;
                if ((permissions & kMemWrite) != 0) section.flags |= elf::kShfWrite;
                if ((permissions & kMemExec) != 0 &&
                    ((sectionFlags & 0x80000400) != 0 || sectionName == "__text"))
                    section.flags |= elf::kShfExecInstr;
                section.fileOffset = rawOffset;
                if (!zeroFill && section.size != 0) {
                    if (rawOffset < fileOffset || static_cast<u64>(rawOffset) - fileOffset > fileSize ||
                        section.size > fileSize - (rawOffset - fileOffset) ||
                        section.addr - address != static_cast<u64>(rawOffset) - fileOffset ||
                        !file.covers(rawOffset, section.size))
                        return bad("invalid Mach-O section file mapping");
                    section.data = file.subview(rawOffset, section.size);
                }
                sections_.push_back(std::move(section));
            }
        } else if (command == 2) {  // LC_SYMTAB
            if (haveSymbols || !view.read(8, &symbolOffset) || !view.read(12, &symbolCount) ||
                !view.read(16, &stringsOffset) || !view.read(20, &stringsSize))
                return bad("invalid/duplicate Mach-O symbol table command");
            haveSymbols = true;
        } else if (command == 0x80000028) {  // LC_MAIN: entryoff is a file offset.
            if (haveEntryOffset || !view.read(8, &entryOffset)) return bad("invalid/duplicate Mach-O entry command");
            haveEntryOffset = true;
        } else if (command == 0x26) {  // LC_FUNCTION_STARTS
            if (!view.read(8, &startsOffset) || !view.read(12, &startsSize))
                return bad("truncated Mach-O function-starts command");
        } else if (command == 0x22 || command == 0x80000022) { // LC_DYLD_INFO[_ONLY]
            if (view.size() != 48 || !view.read(8, &rebaseOffset) || !view.read(12, &rebaseSize) ||
                !view.read(16, &bindOffset) || !view.read(20, &bindSize) || !view.read(24, &weakOffset) ||
                !view.read(28, &weakSize) || !view.read(32, &lazyOffset) || !view.read(36, &lazySize) ||
                !view.read(40, &exportOffset) || !view.read(44, &exportSize)) return bad("invalid dyld info command");
        } else if (command == 0x80000033 || command == 0x80000034) {
            if (view.size() != 16 || !view.read(8, command == 0x80000033 ? &exportOffset : &chainOffset) ||
                !view.read(12, command == 0x80000033 ? &exportSize : &chainSize)) return bad("invalid dyld linkedit command");
        } else if (command == 5) {  // LC_UNIXTHREAD: legacy executable entry.
            u64 cursor = 8;
            while (cursor < view.size()) {
                u32 flavor = 0, count = 0;
                if (!view.read(cursor, &flavor) || !view.read(cursor + 4, &count) ||
                    !view.covers(cursor + 8, static_cast<u64>(count) * 4))
                    return bad("invalid Mach-O thread state");
                const u64 state = cursor + 8;
                if (arch_ == Arch::kX86_64 && flavor == 4 && count >= 42) view.read(state + 128, &unixEntry);
                if (arch_ == Arch::kAArch64 && flavor == 6 && count >= 68) view.read(state + 256, &unixEntry);
                if (arch_ == Arch::kX86_32 && flavor == 1 && count >= 16) { u32 pc = 0; view.read(state + 40, &pc); unixEntry = pc; }
                if (arch_ == Arch::kArm32 && flavor == 1 && count >= 17) { u32 pc = 0; view.read(state + 60, &pc); unixEntry = pc & ~u32{1}; if (pc & 1) armModes_.emplace_back(unixEntry, true); }
                cursor = state + static_cast<u64>(count) * 4;
            }
        } else if (command == 0xc || command == 0x80000018 || command == 0x8000001f ||
                   command == 0x80000023 || command == 0xd) {  // dylib load/ID commands
            u32 nameOffset = 0;
            std::string name;
            if (view.size() < 24 || !view.read(8, &nameOffset) || nameOffset < 24 ||
                !machString(view, nameOffset, &name)) addWarning("invalid Mach-O dylib name");
            else if (command == 0xd) soname_ = name;
            else if (needed_.size() < 4096) needed_.push_back(std::move(name));
        }
        offset += size;
    }
    if (offset != commandEnd) return bad("Mach-O load command count/size mismatch");
    memory_.finalize();
    if (memory_.empty()) return bad("Mach-O has no mapped segments");
    imageBase_ = haveText ? textBase : memory_.minAddress();
    if (haveEntryOffset) {
        bool mapped = false;
        for (const FileSegment& segment : fileSegments) {
            if (entryOffset >= segment.offset && entryOffset - segment.offset < segment.fileSize) {
                entry_ = segment.address + entryOffset - segment.offset;
                mapped = true;
                break;
            }
        }
        if (!mapped || !memory_.isExecutable(entry_)) return bad("Mach-O entry is not in executable file-backed memory");
    } else if (unixEntry != 0) {
        if (!memory_.isExecutable(unixEntry)) return bad("Mach-O thread entry is not executable");
        entry_ = unixEntry;
    }
    if (haveSymbols) {
        const u64 symbolStride = narrow ? 12 : 16;
        if (symbolCount > 1000000 || !file.covers(symbolOffset, static_cast<u64>(symbolCount) * symbolStride) ||
            !file.covers(stringsOffset, stringsSize)) addWarning("invalid Mach-O symbol/string table; names ignored");
        else {
            ByteView strings = file.subview(stringsOffset, stringsSize);
            for (u64 i = 0; i < symbolCount; ++i) {
                const u64 at = symbolOffset + i * symbolStride;
                u32 nameOffset = 0;
                u8 kind = 0, sectionIndex = 0;
                Address value = 0;
                file.read(at, &nameOffset);
                file.read(at + 4, &kind);
                file.read(at + 5, &sectionIndex);
                if (narrow) { u32 low = 0; file.read(at + 8, &low); value = low; } else file.read(at + 8, &value);
                if ((kind & 0xe0) != 0 || ((kind & 0x0e) != 0 && (kind & 0x0e) != 0xe)) continue;
                ElfSymbol symbol;
                if (!machString(strings, nameOffset, &symbol.name) || symbol.name.empty()) continue;
                symbol.undefined = (kind & 0x0e) == 0;
                if (!symbol.undefined && (sectionIndex == 0 || sectionIndex > sections_.size() || !memory_.isMapped(value))) continue;
                symbol.value = symbol.undefined ? 0 : value;
                symbol.sectionIndex = sectionIndex;
                symbol.binding = (kind & 1) != 0 ? elf::kStbGlobal : elf::kStbLocal;
                symbol.type = symbol.undefined || sections_[sectionIndex - 1].executable()
                    ? elf::kSttFunc : elf::kSttObject;
                symbol.fromDynsym = (kind & 1) != 0;
                symbols_.push_back(std::move(symbol));
            }
            stripped_ = symbols_.empty();
        }
    }
    if (startsSize != 0) {
        ByteView starts = file.subview(startsOffset, startsSize);
        if (starts.empty() || !haveText) addWarning("invalid Mach-O function-starts table");
        else {
            u64 cursor = 0, delta = 0;
            Address address = textBase;
            bool terminated = false;
            for (u64 count = 0; count < 1000000; ++count) {
                if (!readDelta(starts, &cursor, &delta)) break;
                if (delta == 0) { terminated = true; break; }
                if (delta > std::numeric_limits<Address>::max() - address) break;
                address += delta;
                if (!memory_.isExecutable(address) || (arch_ == Arch::kAArch64 && (address & 3) != 0)) break;
                ElfSymbol symbol;
                symbol.name = "macho_function_" + std::to_string(address);
                symbol.value = address;
                symbol.type = elf::kSttFunc;
                symbols_.push_back(std::move(symbol));
            }
            if (!terminated) addWarning("Mach-O function-starts table is malformed or exceeds safety limit");
        }
    }
    const u64 pointerWidth = narrow ? 4 : 8;
    auto readPointer = [&](Address at, Address* value) {
        if (narrow) { u32 small = 0; if (!memory_.viewAt(at, 4).read(0, &small)) return false; *value = small; return true; }
        return memory_.viewAt(at, 8).read(0, value);
    };
    auto addImport = [&](const std::string& name) -> u32 {
        for (size_t i = 0; i < symbols_.size(); ++i) if (symbols_[i].name == name && symbols_[i].undefined) return static_cast<u32>(i);
        if (symbols_.size() >= 1000000) return ~u32{0};
        ElfSymbol symbol; symbol.name = name; symbol.undefined = true; symbol.fromDynsym = true;
        symbol.type = elf::kSttFunc; symbol.binding = elf::kStbGlobal; symbols_.push_back(std::move(symbol));
        return static_cast<u32>(symbols_.size() - 1);
    };
    auto bindStream = [&](u32 streamOffset, u32 streamSize, bool lazy) {
        if (!streamSize) return;
        ByteView stream = file.subview(streamOffset, streamSize);
        u64 cursor = 0, segment = ~u64{0}, segmentOffset = 0; u8 type = 1; i64 ordinal = 0, addend = 0;
        std::string symbol; std::vector<ElfRelocation> pending;
        bool valid = stream.size() == streamSize && streamSize <= 16 * 1024 * 1024, done = false;
        auto advance = [&](u64 delta) { if (delta > ~u64{0} - segmentOffset) return false; segmentOffset += delta; return true; };
        auto emit = [&]() {
            const u64 width = type == 1 ? pointerWidth : 4;
            if (segment >= fileSegments.size() || (type != 1 && type != 2 && type != 3) || symbol.empty() ||
                ordinal > static_cast<i64>(needed_.size()) || ordinal < -3 || pending.size() >= 131072) return false;
            const auto& mapped = fileSegments[segment];
            if (segmentOffset > mapped.fileSize || width > mapped.fileSize - segmentOffset ||
                !memory_.viewAt(mapped.address + segmentOffset, width).covers(0, width)) return false;
            ElfRelocation relocation; relocation.offset = mapped.address + segmentOffset; relocation.type = 0x80000200 | type;
            relocation.source = ElfRelocation::Source::kContainerBind; relocation.symbolName = symbol; relocation.addend = addend;
            pending.push_back(std::move(relocation)); return true;
        };
        size_t operations = 0;
        while (valid && cursor < stream.size() && ++operations <= 1000000) {
            const u8 byte = stream.data()[cursor++], opcode = byte & 0xf0, immediate = byte & 0x0f;
            u64 value = 0, count = 0, skip = 0;
            switch (opcode) {
                case 0: if (!lazy) { done = true; cursor = stream.size(); } else { segment = ~u64{0}; symbol.clear(); type = 1; ordinal = addend = 0; done = true; } break;
                case 0x10: ordinal = immediate; break;
                case 0x20: valid = readDelta(stream, &cursor, &value) && value <= static_cast<u64>(needed_.size()); ordinal = static_cast<i64>(value); break;
                case 0x30: ordinal = immediate ? static_cast<i8>(0xf0 | immediate) : 0; break;
                case 0x40: valid = machString(stream, cursor, &symbol); if (valid) cursor += symbol.size() + 1; break;
                case 0x50: type = immediate; break;
                case 0x60: valid = readSigned(stream, &cursor, &addend); break;
                case 0x70: segment = immediate; valid = readDelta(stream, &cursor, &segmentOffset); break;
                case 0x80: valid = readDelta(stream, &cursor, &value) && advance(value); break;
                case 0x90: valid = emit() && advance(pointerWidth); done = false; break;
                case 0xa0: valid = emit() && readDelta(stream, &cursor, &value) && value <= ~u64{0} - pointerWidth && advance(value + pointerWidth); done = false; break;
                case 0xb0: valid = emit() && advance((immediate + 1) * pointerWidth); done = false; break;
                case 0xc0:
                    valid = readDelta(stream, &cursor, &count) && readDelta(stream, &cursor, &skip) && count <= 131072 && skip <= ~u64{0} - pointerWidth;
                    for (u64 n = 0; valid && n < count; ++n) valid = emit() && advance(skip + pointerWidth);
                    done = false; break;
                default: valid = false; break;
            }
        }
        if (!valid || !done || operations > 1000000) { addWarning("invalid/unsupported Mach-O dyld bind stream; no partial bindings published"); return; }
        for (auto& relocation : pending) { relocation.symbolIndex = addImport(relocation.symbolName); if (relocation.symbolIndex == ~u32{0}) break; relocations_.push_back(std::move(relocation)); }
    };
    auto rebaseStream = [&]() {
        if (!rebaseSize) return;
        ByteView stream = file.subview(rebaseOffset, rebaseSize); u64 cursor = 0, segment = ~u64{0}, segmentOffset = 0;
        u8 type = 1; std::vector<ElfRelocation> pending; bool valid = stream.size() == rebaseSize && rebaseSize <= 16 * 1024 * 1024, done = false;
        auto advance = [&](u64 delta) { if (delta > ~u64{0} - segmentOffset) return false; segmentOffset += delta; return true; };
        auto emit = [&]() {
            if (segment >= fileSegments.size() || type != 1 || pending.size() >= 131072) return false;
            const auto& mapped = fileSegments[segment]; Address target = 0;
            if (segmentOffset > mapped.fileSize || pointerWidth > mapped.fileSize - segmentOffset || !readPointer(mapped.address + segmentOffset, &target)) return false;
            ElfRelocation relocation; relocation.offset = mapped.address + segmentOffset; relocation.type = 0x80000301;
            relocation.source = ElfRelocation::Source::kContainerRebase; relocation.addend = static_cast<i64>(target); pending.push_back(std::move(relocation)); return true;
        };
        size_t operations = 0;
        while (valid && cursor < stream.size() && ++operations <= 1000000) {
            const u8 byte = stream.data()[cursor++], opcode = byte & 0xf0, immediate = byte & 0x0f;
            u64 value = 0, count = 0, skip = 0;
            switch (opcode) {
                case 0: done = true; cursor = stream.size(); break;
                case 0x10: type = immediate; break;
                case 0x20: segment = immediate; valid = readDelta(stream, &cursor, &segmentOffset); break;
                case 0x30: valid = readDelta(stream, &cursor, &value) && advance(value); break;
                case 0x40: valid = advance(immediate * pointerWidth); break;
                case 0x50: for (u8 n = 0; valid && n < immediate; ++n) valid = emit() && advance(pointerWidth); break;
                case 0x60: valid = readDelta(stream, &cursor, &count) && count <= 131072; for (u64 n = 0; valid && n < count; ++n) valid = emit() && advance(pointerWidth); break;
                case 0x70: valid = emit() && readDelta(stream, &cursor, &value) && value <= ~u64{0} - pointerWidth && advance(value + pointerWidth); break;
                case 0x80: valid = readDelta(stream, &cursor, &count) && readDelta(stream, &cursor, &skip) && count <= 131072 && skip <= ~u64{0} - pointerWidth; for (u64 n = 0; valid && n < count; ++n) valid = emit() && advance(skip + pointerWidth); break;
                default: valid = false; break;
            }
        }
        if (!valid || !done || operations > 1000000) addWarning("invalid/unsupported Mach-O dyld rebase stream; no partial rebases published");
        else relocations_.insert(relocations_.end(), pending.begin(), pending.end());
    };
    rebaseStream(); bindStream(bindOffset, bindSize, false); bindStream(weakOffset, weakSize, false); bindStream(lazyOffset, lazySize, true);
    if (exportSize) {
        ByteView trie = file.subview(exportOffset, exportSize);
        struct Node { u64 offset; std::string prefix; u32 depth; };
        std::vector<Node> stack{{0, "", 0}}; std::set<u64> visited;
        std::vector<ElfSymbol> exports;
        bool valid = trie.size() == exportSize && exportSize <= 16 * 1024 * 1024; size_t textBytes = 0;
        while (valid && !stack.empty() && visited.size() < 131072) {
            Node node = std::move(stack.back()); stack.pop_back(); u64 cursor = node.offset, terminal = 0;
            if (node.depth > 128 || !visited.insert(node.offset).second || !readDelta(trie, &cursor, &terminal) || !trie.covers(cursor, terminal)) { valid = false; break; }
            const u64 children = cursor + terminal;
            if (terminal) {
                u64 flags = 0, value = 0; valid = readDelta(trie, &cursor, &flags);
                ElfSymbol symbol; symbol.name = node.prefix; symbol.fromDynsym = true; symbol.binding = elf::kStbGlobal;
                if (flags & 8) { std::string renamed; valid = valid && readDelta(trie, &cursor, &value) && value <= needed_.size() && machString(trie.subview(0, children), cursor, &renamed); if (valid) cursor += renamed.size() + 1; symbol.undefined = true; }
                else {
                    valid = valid && readDelta(trie, &cursor, &value);
                    if (!(flags & 2)) { if (value > ~Address{0} - imageBase_) valid = false; else value += imageBase_; }
                    symbol.value = value;
                    if (flags & 0x10) { u64 resolver = 0; valid = valid && readDelta(trie, &cursor, &resolver) && resolver <= ~Address{0} - imageBase_ && memory_.isExecutable(imageBase_ + resolver); }
                    valid = valid && ((flags & 3) == 2 || memory_.isMapped(value));
                }
                valid = valid && cursor == children && !symbol.name.empty() && !(flags & ~u64{0x3f});
                symbol.type = !symbol.undefined && memory_.isExecutable(symbol.value) ? elf::kSttFunc : elf::kSttObject;
                if (valid) exports.push_back(std::move(symbol));
            }
            cursor = children; u8 count = 0; if (!trie.byteAt(cursor++, &count)) { valid = false; break; }
            for (u32 child = 0; valid && child < count; ++child) {
                std::string suffix; u64 next = 0;
                valid = machString(trie, cursor, &suffix) && !suffix.empty(); if (valid) cursor += suffix.size() + 1;
                valid = valid && readDelta(trie, &cursor, &next) && next < trie.size() && suffix.size() <= 4096 - std::min<size_t>(node.prefix.size(), 4096);
                textBytes += suffix.size(); if (textBytes > 16 * 1024 * 1024) valid = false;
                if (valid) stack.push_back({next, node.prefix + suffix, node.depth + 1});
            }
        }
        if (!valid || !stack.empty()) addWarning("invalid/cyclic/excessive Mach-O export trie; exports ignored atomically");
        else symbols_.insert(symbols_.end(), exports.begin(), exports.end());
    }
    if (chainSize) {
        containerPointersEncoded_ = true;
        ByteView chains = file.subview(chainOffset, chainSize);
        u32 version = 0, starts = 0, imports = 0, names = 0, importCount = 0, importFormat = 0, namesFormat = 0;
        bool valid = chains.size() == chainSize && chainSize <= 64 * 1024 * 1024 &&
            chains.read(0, &version) && version == 0 && chains.read(4, &starts) && chains.read(8, &imports) &&
            chains.read(12, &names) && chains.read(16, &importCount) && chains.read(20, &importFormat) &&
            chains.read(24, &namesFormat) && importCount <= 131072 && names <= chains.size();
        const u64 importStride = importFormat == 1 ? 4 : importFormat == 2 ? 8 : importFormat == 3 ? 16 : 0;
        valid = valid && importStride && chains.covers(imports, importCount * importStride) && (namesFormat == 0 || namesFormat == 1);
        std::vector<u8> inflated;
        ByteView strings = names <= chains.size() ? chains.subview(names, chains.size() - names) : ByteView{};
        if (valid && namesFormat == 1) {
            z_stream stream{}; stream.next_in = const_cast<Bytef*>(strings.data()); stream.avail_in = static_cast<uInt>(strings.size());
            int status = inflateInit(&stream);
            if (status == Z_OK) {
                for (size_t block = 0; block < 256 && status == Z_OK; ++block) {
                    const size_t begin = inflated.size(); inflated.resize(begin + 65536);
                    stream.next_out = inflated.data() + begin; stream.avail_out = 65536;
                    status = inflate(&stream, Z_NO_FLUSH); inflated.resize(begin + 65536 - stream.avail_out);
                }
                valid = status == Z_STREAM_END && stream.avail_in == 0; inflateEnd(&stream);
            } else valid = false;
            strings = ByteView(inflated.data(), inflated.size());
        }
        struct Import { std::string name; i64 addend = 0; };
        std::vector<Import> importTable;
        for (u32 i = 0; valid && i < importCount; ++i) {
            const u64 at = imports + u64(i) * importStride; u64 word = 0, nameOffset = 0; i64 library = 0, addend = 0;
            if (importFormat == 3) {
                valid = chains.read(at, &word); library = static_cast<u16>(word); if (library > 0xfff0) library -= 65536;
                nameOffset = word >> 32; valid = valid && !(word & (u64{0x7fff} << 17)); chains.read(at + 8, &addend);
            } else {
                u32 small = 0; valid = chains.read(at, &small); word = small;
                library = small & 0xff; if (library > 0xf0) library -= 256; nameOffset = small >> 9;
                if (importFormat == 2) { i32 value = 0; chains.read(at + 4, &value); addend = value; }
            }
            Import entry; entry.addend = addend;
            valid = valid && library >= -3 && library <= static_cast<i64>(needed_.size()) && machString(strings, nameOffset, &entry.name) && !entry.name.empty();
            if (valid) importTable.push_back(std::move(entry));
        }
        u32 segmentCount = 0;
        valid = valid && chains.read(starts, &segmentCount) && segmentCount == fileSegments.size() && chains.covers(u64(starts) + 4, u64(segmentCount) * 4);
        std::vector<ElfRelocation> pending;
        for (u32 segmentIndex = 0; valid && segmentIndex < segmentCount; ++segmentIndex) {
            u32 relative = 0; chains.read(u64(starts) + 4 + segmentIndex * 4, &relative); if (!relative) continue;
            const u64 record = u64(starts) + relative; u32 size = 0, maxPointer = 0; u16 pageSize = 0, format = 0, pageCount = 0; u64 segmentOffset = 0;
            valid = chains.read(record, &size) && size >= 22 && chains.covers(record, size) && chains.read(record + 4, &pageSize) &&
                chains.read(record + 6, &format) && chains.read(record + 8, &segmentOffset) && chains.read(record + 16, &maxPointer) &&
                chains.read(record + 20, &pageCount) && (pageSize == 0x1000 || pageSize == 0x4000) && chains.covers(record + 22, u64(pageCount) * 2) &&
                u64(pageCount) * 2 <= size - 22;
            const auto& segment = fileSegments[segmentIndex];
            valid = valid && segment.address >= imageBase_ && segmentOffset == segment.address - imageBase_ &&
                pageCount <= (segment.size + pageSize - 1) / pageSize &&
                (format == 1 || format == 2 || format == 3 || format == 6 || format == 9 || format == 12) &&
                ((format == 3) == narrow);
            for (u32 page = 0; valid && page < pageCount; ++page) {
                u16 first = 0; chains.read(record + 22 + page * 2, &first); if (first == 0xffff) continue;
                std::vector<u16> startsOnPage;
                if (first & 0x8000) {
                    u64 index = first & 0x7fff; bool last = false;
                    for (size_t n = 0; valid && n < pageSize / 4; ++n, ++index) {
                        u16 start = 0; if (22 + index * 2 >= size || !chains.read(record + 22 + index * 2, &start)) { valid = false; break; }
                        startsOnPage.push_back(start & 0x7fff); if (start & 0x8000) { last = true; break; }
                    }
                    valid = valid && last;
                } else startsOnPage.push_back(first);
                std::set<u64> visited;
                for (u16 chainStart : startsOnPage) {
                    u64 at = u64(page) * pageSize + chainStart;
                    while (valid) {
                        const bool arm = format == 1 || format == 9 || format == 12;
                        const u64 width = format == 3 ? 4 : 8, stride = arm ? 8 : 4;
                        if (at / pageSize != page || at % stride || at > segment.fileSize || width > segment.fileSize - at ||
                            at % pageSize > pageSize - width || !visited.insert(at).second || pending.size() >= 131072) { valid = false; break; }
                        Address raw = 0; if (!readPointer(segment.address + at, &raw)) { valid = false; break; }
                        const bool bind = (raw >> (arm ? 62 : format == 3 ? 31 : 63)) & 1;
                        const bool auth = arm && (raw >> 63);
                        const u64 next = arm ? (raw >> 51) & 0x7ff : format == 3 ? (raw >> 26) & 0x1f : (raw >> 51) & 0xfff;
                        ElfRelocation relocation; relocation.offset = segment.address + at; relocation.type = 0x80000400 | format;
                        if (bind) {
                            const u64 ordinal = raw & (arm ? format == 12 ? 0xffffff : 0xffff : format == 3 ? 0xfffff : 0xffffff);
                            i64 addend = 0;
                            if (arm && !auth) { addend = (raw >> 32) & 0x7ffff; if (addend & 0x40000) addend -= 0x80000; }
                            else if (!arm) addend = format == 3 ? (raw >> 20) & 0x3f : (raw >> 24) & 0xff;
                            if (ordinal >= importTable.size() ||
                                (arm && (format == 12 ? (raw & (u64{0xff} << 24)) : (raw & (u64{0xffff} << 16)))) ||
                                (!arm && format != 3 && (raw & (u64{0x7ffff} << 32))) ||
                                (addend > 0 && importTable[ordinal].addend > std::numeric_limits<i64>::max() - addend) ||
                                (addend < 0 && importTable[ordinal].addend < std::numeric_limits<i64>::min() - addend)) { valid = false; break; }
                            relocation.source = ElfRelocation::Source::kContainerBind; relocation.symbolName = importTable[ordinal].name;
                            relocation.addend = importTable[ordinal].addend + addend;
                        } else {
                            Address target = 0;
                            if (arm) {
                                if (auth) target = raw & 0xffffffff;
                                else target = (raw & ((u64{1} << 43) - 1)) | (((raw >> 43) & 0xff) << 56);
                                if (auth || format != 1) { if (target > ~Address{0} - imageBase_) { valid = false; break; } target += imageBase_; }
                            } else if (format == 3) {
                                target = raw & 0x3ffffff;
                                if (target > maxPointer) { relocation.source = ElfRelocation::Source::kContainerBind; relocation.addend = 0; }
                            } else {
                                if (raw & (u64{0x7f} << 44)) { valid = false; break; }
                                target = (raw & ((u64{1} << 36) - 1)) | (((raw >> 36) & 0xff) << 56);
                                if (format == 6) { if (target > ~Address{0} - imageBase_) { valid = false; break; } target += imageBase_; }
                            }
                            if (!(format == 3 && target > maxPointer)) { relocation.source = ElfRelocation::Source::kContainerRebase; relocation.addend = static_cast<i64>(target); }
                        }
                        pending.push_back(std::move(relocation));
                        if (!next) break;
                        if (next * stride > ~u64{0} - at) { valid = false; break; } at += next * stride;
                    }
                }
            }
        }
        if (!valid) addWarning("invalid/unsupported Mach-O chained fixups; encoded words are not exposed as real pointers");
        else for (auto& relocation : pending) {
            if (!relocation.symbolName.empty()) { relocation.symbolIndex = addImport(relocation.symbolName); if (relocation.symbolIndex == ~u32{0}) break; }
            relocations_.push_back(std::move(relocation));
        }
    }
    // The two-level compact unwind index proves ranges even when .symtab and
    // .eh_frame are absent. Encoding/personality/LSDA remain ABI metadata;
    // callers must not pretend that a compact encoding is an evaluated CFA.
    for (const auto& section : sections_) {
        if (section.name != "__TEXT,__unwind_info") continue;
        const ByteView table = section.data;
        u32 version = 0, common = 0, commonCount = 0, personalities = 0, personalityCount = 0, index = 0, count = 0;
        bool valid = table.read(0, &version) && version == 1 && table.read(4, &common) && table.read(8, &commonCount) &&
            table.read(12, &personalities) && table.read(16, &personalityCount) && table.read(20, &index) && table.read(24, &count) &&
            commonCount <= 256 && personalityCount <= 3 && count >= 2 && count <= 131072 &&
            table.covers(common, u64(commonCount) * 4) && table.covers(personalities, u64(personalityCount) * 4) && table.covers(index, u64(count) * 12);
        std::vector<RuntimeFunction> frames;
        for (u32 page = 0; valid && page + 1 < count; ++page) {
            u32 first = 0, secondLevel = 0, lsdaStart = 0, next = 0, lsdaEnd = 0;
            table.read(index + u64(page) * 12, &first); table.read(index + u64(page) * 12 + 4, &secondLevel);
            table.read(index + u64(page) * 12 + 8, &lsdaStart); table.read(index + u64(page + 1) * 12, &next);
            table.read(index + u64(page + 1) * 12 + 8, &lsdaEnd);
            if (first >= next || lsdaEnd < lsdaStart || (lsdaEnd - lsdaStart) % 8 || !table.covers(lsdaStart, lsdaEnd - lsdaStart)) { valid = false; break; }
            if (!secondLevel) continue;
            u32 kind = 0; u16 entryOffset = 0, entryCount = 0, encodingOffset = 0, encodingCount = 0;
            valid = table.read(secondLevel, &kind) && table.read(u64(secondLevel) + 4, &entryOffset) && table.read(u64(secondLevel) + 6, &entryCount) &&
                (kind == 2 || kind == 3) && entryCount && table.covers(u64(secondLevel) + entryOffset, u64(entryCount) * (kind == 2 ? 8 : 4));
            if (kind == 3) valid = valid && table.read(u64(secondLevel) + 8, &encodingOffset) && table.read(u64(secondLevel) + 10, &encodingCount) &&
                encodingCount <= 256 - commonCount && table.covers(u64(secondLevel) + encodingOffset, u64(encodingCount) * 4);
            std::vector<std::pair<u32, u32>> rows;
            for (u32 row = 0; valid && row < entryCount; ++row) {
                const u64 at = u64(secondLevel) + entryOffset + u64(row) * (kind == 2 ? 8 : 4); u32 function = 0, encoding = 0;
                table.read(at, &function);
                if (kind == 2) table.read(at + 4, &encoding);
                else {
                    const u32 encodingIndex = function >> 24; const u32 delta = function & 0xffffff;
                    if (delta > ~u32{0} - first || encodingIndex >= commonCount + encodingCount) { valid = false; break; }
                    function = first + delta;
                    table.read(encodingIndex < commonCount ? common + encodingIndex * 4 : u64(secondLevel) + encodingOffset + (encodingIndex - commonCount) * 4, &encoding);
                }
                if (function < first || function >= next || (!rows.empty() && function <= rows.back().first)) { valid = false; break; }
                rows.emplace_back(function, encoding);
            }
            for (size_t row = 0; valid && row < rows.size(); ++row) {
                const u32 begin = rows[row].first, end = row + 1 < rows.size() ? rows[row + 1].first : next, encoding = rows[row].second;
                if (end > ~Address{0} - imageBase_ || !memory_.isExecutable(imageBase_ + begin) || !memory_.isExecutable(imageBase_ + end - 1) || frames.size() >= 131072) { valid = false; break; }
                RuntimeFunction frame; frame.start = imageBase_ + begin; frame.end = imageBase_ + end;
                frame.encoding = encoding; frame.source = "Mach-O compact unwind"; frame.unwindInfo = section.addr + secondLevel;
                const u32 personality = (encoding >> 28) & 3;
                if (personality) { u32 rva = 0; if (personality > personalityCount || !table.read(personalities + (personality - 1) * 4, &rva) || rva > ~Address{0} - imageBase_) { valid = false; break; } frame.personality = imageBase_ + rva; }
                if (encoding & 0x40000000) {
                    bool found = false;
                    for (u64 at = lsdaStart; at < lsdaEnd; at += 8) {
                        u32 function = 0, lsda = 0; table.read(at, &function); table.read(at + 4, &lsda);
                        if (function != begin) continue;
                        if (found || lsda > ~Address{0} - imageBase_ || memory_.viewAt(imageBase_ + lsda, 1).empty()) { valid = false; break; }
                        frame.lsda = imageBase_ + lsda; found = true;
                    }
                    if (!found) { valid = false; break; }
                }
                const u32 mode = encoding & 0x0f000000;
                const bool dwarfMode = (arch_ == Arch::kAArch64 && mode == 0x03000000) ||
                    ((arch_ == Arch::kX86_32 || arch_ == Arch::kX86_64 || arch_ == Arch::kArm32) && mode == 0x04000000);
                if (dwarfMode) {
                    const auto* eh = findSection("__TEXT,__eh_frame");
                    const u32 fde = encoding & 0xffffff;
                    if (eh && fde < eh->data.size()) frame.unwindInfo = eh->addr + fde;
                }
                frames.push_back(std::move(frame));
            }
        }
        if (valid) runtimeFunctions_.insert(runtimeFunctions_.end(), frames.begin(), frames.end());
        else addWarning("invalid/excessive Mach-O compact unwind index; no partial ranges published");
    }
    indexRelocations(); indexSymbols();
    loaded_ = true;
    return Status::success();
}
}  // namespace mint
