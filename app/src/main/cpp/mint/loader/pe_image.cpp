#include "mint/loader/elf_image.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace mint {
namespace {
constexpr u64 kMaxPeSymbols = 131072;
constexpr u64 kMaxPeImports = 4096;

bool terminatedString(ByteView view, u64 offset, std::string* out, size_t cap = 4096) {
    if (!view.cString(offset, out, cap)) return false;
    u8 terminator = 1;
    return view.byteAt(offset + out->size(), &terminator) && terminator == 0;
}

std::string shortName(ByteView view, u64 offset, size_t length) {
    ByteView name = view.subview(offset, length);
    if (name.empty()) return {};
    size_t count = 0;
    while (count < name.size() && name.data()[count] != 0) ++count;
    return std::string(reinterpret_cast<const char*>(name.data()), count);
}
}  // namespace

// PE32/PE32+ layouts follow the Microsoft PE/COFF specification. Metadata is always
// read through file-backed views; zero-filled .bss cannot fabricate a directory.
Status ElfImage::loadPe64(ByteView file) {
    format_ = ImageFormat::kPe64;
    const auto bad = [](const char* message) {
        return Status::error(ErrorCode::kBadFormat, message);
    };
    u32 peOffset = 0, signature = 0;
    if (!file.read(0x3c, &peOffset) || !file.read(peOffset, &signature) || signature != 0x4550)
        return bad("invalid or truncated PE signature");
    const u64 coff = static_cast<u64>(peOffset) + 4;
    u16 machine = 0, sectionCount = 0, optionalSize = 0, characteristics = 0;
    if (!file.read(coff, &machine) || !file.read(coff + 2, &sectionCount) ||
        !file.read(coff + 16, &optionalSize) || !file.read(coff + 18, &characteristics))
        return bad("truncated PE COFF header");
    if (machine == 0x14c) arch_ = Arch::kX86_32;
    else if (machine == 0x8664) arch_ = Arch::kX86_64;
    else if (machine == 0xaa64) arch_ = Arch::kAArch64;
    else return Status::error(ErrorCode::kUnsupported, "PE supports x86 PE32, AMD64 and ARM64 PE32+; ARM/Thumb and other Windows ABIs are unsupported");
    if (sectionCount == 0 || sectionCount > 4096) return bad("invalid PE section count");
    const u64 optional = coff + 20;
    ByteView header = file.subview(optional, optionalSize);
    u16 magic = 0, dllFlags = 0;
    u32 entryRva = 0, imageSize = 0, headersSize = 0, directoryCount = 0;
    if (!header.read(0, &magic)) return bad("truncated PE optional header");
    if (magic != 0x10b && magic != 0x20b)
        return Status::error(ErrorCode::kUnsupported, "PE optional header is neither PE32 nor PE32+");
    const bool pe32 = magic == 0x10b;
    if (pe32 != (machine == 0x14c)) return bad("PE machine and optional-header pointer width disagree");
    const size_t pointerWidth = pe32 ? 4 : 8;
    const u64 directoriesOffset = pe32 ? 96 : 112;
    if (pe32) { u32 base = 0; if (!header.read(28, &base)) return bad("truncated PE32 image base"); imageBase_ = base; }
    else if (!header.read(24, &imageBase_)) return bad("truncated PE32+ image base");
    if (!header.read(16, &entryRva) ||
        !header.read(56, &imageSize) || !header.read(60, &headersSize) ||
        !header.read(70, &dllFlags) || !header.read(pe32 ? 92 : 108, &directoryCount))
        return bad("truncated PE optional header");
    if (directoryCount > 16 || !header.covers(directoriesOffset, static_cast<u64>(directoryCount) * 8))
        return bad("excessive or truncated PE data-directory array");
    const u64 table = optional + optionalSize;
    const u64 tableSize = static_cast<u64>(sectionCount) * 40;
    if (imageSize == 0 || imageSize > 0x80000000u || headersSize == 0 || headersSize > imageSize ||
        imageBase_ > std::numeric_limits<Address>::max() - imageSize ||
        (pe32 && imageSize > (u64{1} << 32) - imageBase_) ||
        !file.covers(0, headersSize) || !file.covers(table, tableSize) ||
        table + tableSize > headersSize)
        return bad("invalid PE image/header extent or section table");
    positionIndependent_ = (dllFlags & 0x40) != 0;
    type_ = elf::kEtExec;  // Addresses are preferred VAs, not ELF relocation addends.
    entry_ = entryRva == 0 ? 0 : imageBase_ + entryRva;
    if (entryRva >= imageSize) return bad("PE entry RVA outside image");
    memory_.addSegment(imageBase_, headersSize, file.subview(0, headersSize), kMemRead, "headers");
    for (u64 i = 0; i < sectionCount; ++i) {
        const u64 at = table + i * 40;
        u32 virtualSize = 0, rva = 0, rawSize = 0, rawOffset = 0, flags = 0;
        file.read(at + 8, &virtualSize);
        file.read(at + 12, &rva);
        file.read(at + 16, &rawSize);
        file.read(at + 20, &rawOffset);
        file.read(at + 36, &flags);
        const u64 mappedSize = std::max(virtualSize, rawSize);
        if (mappedSize == 0) continue;
        if (rva < headersSize || rva >= imageSize || mappedSize > imageSize - rva ||
            (rawSize != 0 && (rawOffset < headersSize || !file.covers(rawOffset, rawSize))))
            return bad("PE section has invalid virtual/file range");
        const Address address = imageBase_ + rva;
        for (const MemorySegment& segment : memory_.segments()) {
            if (address < segment.end() && segment.start < address + mappedSize)
                return bad("overlapping PE sections");
        }
        u32 permissions = 0;
        if ((flags & 0x40000000) != 0) permissions |= kMemRead;
        if ((flags & 0x80000000) != 0) permissions |= kMemWrite;
        if ((flags & 0x20000000) != 0) permissions |= kMemExec;
        ElfSection section;
        section.name = shortName(file, at, 8);
        section.addr = address;
        section.size = mappedSize;
        section.fileOffset = rawOffset;
        section.type = rawSize == 0 ? elf::kShtNoBits : elf::kShtProgBits;
        section.flags = elf::kShfAlloc;
        if ((permissions & kMemWrite) != 0) section.flags |= elf::kShfWrite;
        if ((permissions & kMemExec) != 0) section.flags |= elf::kShfExecInstr;
        section.data = rawSize == 0 ? ByteView{} : file.subview(rawOffset, rawSize);
        memory_.addSegment(address, mappedSize, section.data, permissions, section.name);
        sections_.push_back(std::move(section));
    }
    memory_.finalize();
    if (sections_.empty()) return bad("PE has no mapped sections");
    if (entry_ != 0 && !memory_.isExecutable(entry_)) return bad("PE entry is not executable");
    auto rvaView = [this, imageSize](u64 rva, u64 length) -> ByteView {
        if (rva >= imageSize) return {};
        return memory_.viewAt(imageBase_ + rva, std::min<u64>(length, imageSize - rva));
    };
    auto stringAtRva = [&rvaView](u64 rva, std::string* out) {
        ByteView bytes = rvaView(rva, 4096);
        return terminatedString(bytes, 0, out);
    };
    auto directory = [this, &header, directoryCount, directoriesOffset, imageSize](u32 index, u32* rva, u32* size) {
        if (index >= directoryCount) return false;
        if (!header.read(directoriesOffset + static_cast<u64>(index) * 8, rva) ||
            !header.read(directoriesOffset + 4 + static_cast<u64>(index) * 8, size) || !*rva || !*size) return false;
        if (*rva >= imageSize || *size > imageSize - *rva) { addWarning("PE metadata directory has an out-of-image RVA range; ignored"); return false; }
        return true;
    };
    auto word = [pointerWidth](ByteView bytes, u64 offset, Address* value) {
        if (pointerWidth == 8) return bytes.read(offset, value);
        u32 small = 0; if (!bytes.read(offset, &small)) return false; *value = small; return true;
    };
    u32 exportRva = 0, exportSize = 0;
    if (directory(0, &exportRva, &exportSize)) {
        ByteView exports = rvaView(exportRva, 40);
        u32 name = 0, ordinalBase = 0, functionCount = 0, nameCount = 0;
        u32 functionsRva = 0, namesRva = 0, ordinalsRva = 0;
        if (exportSize < 40 || !exports.read(12, &name) || !exports.read(16, &ordinalBase) ||
            !exports.read(20, &functionCount) || !exports.read(24, &nameCount) ||
            !exports.read(28, &functionsRva) || !exports.read(32, &namesRva) ||
            !exports.read(36, &ordinalsRva) || functionCount > kMaxPeSymbols || nameCount > kMaxPeSymbols) {
            addWarning("invalid PE export directory; exports ignored");
        } else {
            stringAtRva(name, &soname_);
            ByteView functions = rvaView(functionsRva, static_cast<u64>(functionCount) * 4);
            ByteView names = rvaView(namesRva, static_cast<u64>(nameCount) * 4);
            ByteView ordinals = rvaView(ordinalsRva, static_cast<u64>(nameCount) * 2);
            if (functions.size() != static_cast<u64>(functionCount) * 4 ||
                names.size() != static_cast<u64>(nameCount) * 4 ||
                ordinals.size() != static_cast<u64>(nameCount) * 2) {
                addWarning("truncated PE export tables; exports ignored");
            } else {
                std::vector<std::string> exportNames(functionCount);
                for (u64 i = 0; i < nameCount; ++i) {
                    u32 nameRva = 0;
                    u16 ordinal = 0;
                    names.read(i * 4, &nameRva);
                    ordinals.read(i * 2, &ordinal);
                    if (ordinal < functionCount) stringAtRva(nameRva, &exportNames[ordinal]);
                }
                for (u64 i = 0; i < functionCount; ++i) {
                    u32 target = 0;
                    functions.read(i * 4, &target);
                    if (target == 0 || target >= imageSize) continue;
                    ElfSymbol symbol;
                    symbol.name = exportNames[i].empty()
                        ? "export_ordinal_" + std::to_string(static_cast<u64>(ordinalBase) + i)
                        : exportNames[i];
                    symbol.binding = elf::kStbGlobal;
                    symbol.fromDynsym = true;
                    // An export pointing into the export directory is a
                    // forwarder string, not a function body.
                    symbol.undefined = target >= exportRva && static_cast<u64>(target) - exportRva < exportSize;
                    symbol.value = symbol.undefined ? 0 : imageBase_ + target;
                    symbol.type = !symbol.undefined && memory_.isExecutable(symbol.value)
                        ? elf::kSttFunc : elf::kSttObject;
                    symbols_.push_back(std::move(symbol));
                }
            }
        }
    }
    u32 importRva = 0, importSize = 0;
    if (directory(1, &importRva, &importSize)) {
        const u64 count = std::min<u64>(importSize / 20, kMaxPeImports);
        bool terminated = false;
        for (u64 i = 0; i < count && symbols_.size() < kMaxPeSymbols; ++i) {
            ByteView descriptor = rvaView(static_cast<u64>(importRva) + i * 20, 20);
            u32 lookupRva = 0, timestamp = 0, forwarder = 0, nameRva = 0, iatRva = 0;
            if (!descriptor.read(0, &lookupRva) || !descriptor.read(4, &timestamp) ||
                !descriptor.read(8, &forwarder) || !descriptor.read(12, &nameRva) ||
                !descriptor.read(16, &iatRva)) break;
            if ((lookupRva | timestamp | forwarder | nameRva | iatRva) == 0) {
                terminated = true;
                break;
            }
            std::string library;
            if (!stringAtRva(nameRva, &library) || iatRva == 0) {
                addWarning("invalid PE import descriptor");
                continue;
            }
            needed_.push_back(library);
            if (lookupRva == 0) lookupRva = iatRva;
            bool thunkTerminated = false;
            for (u64 slot = 0; slot < 65536 && symbols_.size() < kMaxPeSymbols; ++slot) {
                ByteView lookup = rvaView(static_cast<u64>(lookupRva) + slot * pointerWidth, pointerWidth);
                ByteView iat = rvaView(static_cast<u64>(iatRva) + slot * pointerWidth, pointerWidth);
                u64 thunk = 0;
                if (iat.size() != pointerWidth || !word(lookup, 0, &thunk)) break;
                if (thunk == 0) { thunkTerminated = true; break; }
                std::string name;
                const u64 ordinalFlag = u64{1} << (pointerWidth * 8 - 1);
                if ((thunk & ordinalFlag) != 0) {
                    if ((thunk & ~(ordinalFlag | u64{0xffff})) != 0) break;
                    name = "ordinal_" + std::to_string(thunk & 0xffff);
                } else if (thunk > 0x7fffffffu || rvaView(thunk, 2).size() != 2 || !stringAtRva(thunk + 2, &name)) break;
                ElfSymbol symbol;
                symbol.name = library + "!" + name;
                symbol.type = elf::kSttFunc;
                symbol.binding = elf::kStbGlobal;
                symbol.undefined = true;
                symbol.fromDynsym = true;
                symbols_.push_back(std::move(symbol));
                ElfRelocation reference;
                reference.offset = imageBase_ + iatRva + slot * pointerWidth;
                reference.type = 0x80000001;  // Container import, never an ELF RELATIVE relocation.
                reference.symbolName = symbols_.back().name;
                reference.symbolIndex = static_cast<u32>(symbols_.size() - 1);
                relocations_.push_back(std::move(reference));
            }
            if (!thunkTerminated) addWarning("PE import thunk table is malformed, truncated or exceeds safety limit");
        }
        if (!terminated) addWarning("PE import descriptor table is truncated or exceeds safety limit");
    }
    // Delay descriptors contain RVAs when grAttrs bit 0 is set, otherwise
    // preferred VAs (legacy PE32). Never mistake a bound thunk for an import.
    u32 delayRva = 0, delaySize = 0;
    if (directory(13, &delayRva, &delaySize)) {
        bool terminated = false;
        for (u64 i = 0; i < std::min<u64>(delaySize / 32, kMaxPeImports); ++i) {
            ByteView descriptor = rvaView(static_cast<u64>(delayRva) + i * 32, 32);
            u32 fields[8] = {};
            bool valid = descriptor.size() == 32;
            for (size_t f = 0; f < 8 && valid; ++f) valid = descriptor.read(f * 4, &fields[f]);
            if (!valid) break;
            bool zero = true; for (u32 field : fields) zero = zero && field == 0;
            if (zero) { terminated = true; break; }
            if (fields[0] & ~u32{1}) { addWarning("unknown PE delay-import attributes; descriptor ignored"); continue; }
            auto toRva = [&](u32 value, u64* result) {
                if (!value) { *result = 0; return true; }
                if (fields[0] & 1) *result = value;
                else { if (imageBase_ > value) return false; *result = value - imageBase_; }
                return *result < imageSize;
            };
            u64 nameRva = 0, iatRva = 0, lookupRva = 0;
            std::string library;
            if (!toRva(fields[1], &nameRva) || !toRva(fields[3], &iatRva) ||
                !toRva(fields[4], &lookupRva) || !nameRva || !iatRva || !lookupRva ||
                !stringAtRva(nameRva, &library)) { addWarning("invalid PE delay-import descriptor"); continue; }
            if (needed_.size() < kMaxPeImports && std::find(needed_.begin(), needed_.end(), library) == needed_.end()) needed_.push_back(library);
            bool thunkTerminated = false;
            for (u64 slot = 0; slot < 65536 && symbols_.size() < kMaxPeSymbols; ++slot) {
                Address thunk = 0;
                if (!word(rvaView(lookupRva + slot * pointerWidth, pointerWidth), 0, &thunk) ||
                    rvaView(iatRva + slot * pointerWidth, pointerWidth).size() != pointerWidth) break;
                if (!thunk) { thunkTerminated = true; break; }
                std::string name;
                const u64 ordinalFlag = u64{1} << (pointerWidth * 8 - 1);
                if (thunk & ordinalFlag) {
                    if (thunk & ~(ordinalFlag | u64{0xffff})) break;
                    name = "ordinal_" + std::to_string(thunk & 0xffff);
                } else {
                    u64 hintRva = thunk;
                    if (!(fields[0] & 1)) { if (thunk < imageBase_) break; hintRva = thunk - imageBase_; }
                    if (hintRva >= imageSize || rvaView(hintRva, 2).size() != 2 || !stringAtRva(hintRva + 2, &name)) break;
                }
                ElfSymbol symbol; symbol.name = library + "!" + name; symbol.type = elf::kSttFunc;
                symbol.binding = elf::kStbGlobal; symbol.undefined = true; symbol.fromDynsym = true;
                symbols_.push_back(std::move(symbol));
                ElfRelocation reference; reference.offset = imageBase_ + iatRva + slot * pointerWidth;
                reference.type = 0x80000002; reference.source = ElfRelocation::Source::kContainerBind;
                reference.symbolName = symbols_.back().name; reference.symbolIndex = static_cast<u32>(symbols_.size() - 1);
                relocations_.push_back(std::move(reference));
            }
            if (!thunkTerminated) addWarning("PE delay-import thunk array is invalid or exceeds safety limit");
        }
        if (!terminated) addWarning("PE delay-import descriptors are unterminated or exceed safety limit");
    }
    u32 baseRva = 0, baseSize = 0;
    if (directory(5, &baseRva, &baseSize)) {
        ByteView bases = rvaView(baseRva, baseSize);
        u64 cursor = 0; size_t records = 0;
        std::vector<ElfRelocation> validated;
        bool valid = bases.size() == baseSize;
        while (valid && cursor < bases.size()) {
            u32 page = 0, blockSize = 0;
            valid = bases.read(cursor, &page) && bases.read(cursor + 4, &blockSize) &&
                blockSize >= 8 && !(blockSize & 1) && bases.covers(cursor, blockSize) && page < imageSize;
            if (!valid) break;
            for (u64 pos = cursor + 8; valid && pos < cursor + blockSize; pos += 2) {
                u16 item = 0; bases.read(pos, &item); const u32 kind = item >> 12; const u64 slot = u64(page) + (item & 0xfff);
                if (!kind) continue; // IMAGE_REL_BASED_ABSOLUTE is padding.
                const size_t width = kind == 10 ? 8 : kind == 3 ? 4 : kind == 1 || kind == 2 || kind == 4 ? 2 : 0;
                if (!width) { addWarning("unsupported PE base-relocation opcode retained as partial metadata"); continue; }
                if (++records > kMaxPeSymbols || slot >= imageSize || width > imageSize - slot || rvaView(slot, width).size() != width) { valid = false; break; }
                ElfRelocation relocation; relocation.offset = imageBase_ + slot; relocation.type = 0x80000100 | kind;
                relocation.source = ElfRelocation::Source::kRel;
                // Preferred VAs are already correct for link-time analysis.
                // HIGH/HIGHADJ words are not promoted into full pointers.
                if (kind == 10 || kind == 3) {
                    Address target = 0; if (kind == 10) rvaView(slot, width).read(0, &target);
                    else { u32 low = 0; rvaView(slot, width).read(0, &low); target = low; }
                    relocation.addend = static_cast<i64>(target);
                }
                validated.push_back(std::move(relocation));
                if (kind == 4) { if (pos + 4 > cursor + blockSize) { valid = false; break; } pos += 2; }
            }
            cursor += blockSize;
        }
        if (!valid) addWarning("malformed PE base-relocation table; no partial fixups published");
        else relocations_.insert(relocations_.end(), validated.begin(), validated.end());
    }
    u32 exceptionRva = 0, exceptionSize = 0;
    if (!pe32 && directory(3, &exceptionRva, &exceptionSize)) {
        const size_t stride = arch_ == Arch::kX86_64 ? 12 : 8;
        ByteView entries = rvaView(exceptionRva, exceptionSize);
        bool valid = entries.size() == exceptionSize && exceptionSize % stride == 0 && exceptionSize / stride <= kMaxPeSymbols;
        std::vector<RuntimeFunction> frames;
        for (u64 pos = 0; valid && pos < entries.size(); pos += stride) {
            u32 begin = 0, end = 0, unwind = 0; entries.read(pos, &begin);
            if (stride == 12) { entries.read(pos + 4, &end); entries.read(pos + 8, &unwind); }
            else {
                entries.read(pos + 4, &unwind);
                u32 length = 0;
                if (unwind & 3) length = ((unwind >> 2) & 0x7ff) * 4;
                else { u32 header = 0; if (!rvaView(unwind, 4).read(0, &header)) { valid = false; break; } length = (header & 0x3ffff) * 4; }
                if (length > imageSize - std::min(begin, imageSize)) { valid = false; break; } end = begin + length;
            }
            if (!begin || begin >= end || end > imageSize || !memory_.isExecutable(imageBase_ + begin) ||
                !memory_.isExecutable(imageBase_ + end - 1) ||
                (stride == 12 && (unwind >= imageSize || rvaView(unwind, 1).empty())) ||
                (!frames.empty() && begin < frames.back().end - imageBase_)) { valid = false; break; }
            RuntimeFunction frame; frame.start = imageBase_ + begin; frame.end = imageBase_ + end;
            frame.unwindInfo = (stride == 8 && (unwind & 3)) ? kNoAddress : imageBase_ + unwind;
            frame.encoding = unwind; frame.source = "PE exception directory";
            if (stride == 12) {
                ByteView info = rvaView(unwind, 4096); u8 versionFlags = 0, prolog = 0, codeCount = 0, frameRegister = 0;
                bool structural = info.byteAt(0, &versionFlags) && info.byteAt(1, &prolog) && info.byteAt(2, &codeCount) && info.byteAt(3, &frameRegister);
                const u8 version = versionFlags & 7, unwindFlags = versionFlags >> 3;
                structural = structural && (version == 1 || version == 2) && !(unwindFlags & ~u8{7}) &&
                    !((unwindFlags & 4) && (unwindFlags & 3)) && info.covers(4, u64(codeCount) * 2);
                u8 previous = 255;
                for (u32 code = 0; structural && code < codeCount;) {
                    const u8 codeOffset = info.data()[4 + code * 2], operation = info.data()[5 + code * 2];
                    const u8 opcode = operation & 15, argument = operation >> 4; u32 slots = 1;
                    if (opcode == 1) { if (argument > 1) structural = false; slots = argument ? 3 : 2; }
                    else if (opcode == 4 || opcode == 8) slots = 2;
                    else if (opcode == 5 || opcode == 9) slots = 3;
                    else if (opcode == 3) structural = argument == 0 && (frameRegister & 15);
                    else if (opcode == 10) structural = argument <= 1;
                    else if (opcode == 6) structural = version == 2;
                    else if (opcode != 0 && opcode != 2) structural = false;
                    if (codeOffset > previous || (opcode != 6 && codeOffset > prolog) || slots > codeCount - code) structural = false;
                    previous = codeOffset; code += slots;
                }
                const u64 trailing = 4 + ((u64(codeCount) * 2 + 3) & ~u64{3});
                if (structural && (unwindFlags & 3)) {
                    u32 handler = 0; structural = info.read(trailing, &handler) && handler < imageSize && memory_.isExecutable(imageBase_ + handler);
                    if (structural) { frame.handler = imageBase_ + handler; frame.personality = frame.handler; frame.handlerData = imageBase_ + unwind + trailing + 4; }
                } else if (structural && (unwindFlags & 4)) {
                    u32 chainedBegin = 0, chainedEnd = 0, chainedUnwind = 0;
                    structural = info.read(trailing, &chainedBegin) && info.read(trailing + 4, &chainedEnd) && info.read(trailing + 8, &chainedUnwind) &&
                        chainedBegin < chainedEnd && chainedEnd <= imageSize && memory_.isExecutable(imageBase_ + chainedBegin) &&
                        memory_.isExecutable(imageBase_ + chainedEnd - 1) && chainedUnwind != unwind && rvaView(chainedUnwind, 4).size() == 4;
                    if (structural) frame.chainedStart = imageBase_ + chainedBegin;
                }
                frame.unwindValidated = structural;
                if (!structural) addWarning("PE x64 function range retained, but its UNWIND_INFO opcode/handler/chain is malformed or unsupported");
            } else frame.unwindValidated = (unwind & 3) != 0; // packed ARM64 header is structurally self-contained.
            frames.push_back(std::move(frame));
        }
        if (valid) runtimeFunctions_.insert(runtimeFunctions_.end(), frames.begin(), frames.end());
        else addWarning("malformed PE exception directory; ranges ignored atomically");
    }
    u32 debugRva = 0, debugSize = 0;
    if (directory(6, &debugRva, &debugSize)) {
        const ByteView entries = rvaView(debugRva, debugSize);
        if (entries.size() != debugSize || debugSize % 28 || debugSize / 28 > 4096) addWarning("invalid PE debug directory extent");
        else for (u64 at = 0; at < entries.size(); at += 28) {
            u32 kind = 0, size = 0, rva = 0, raw = 0; entries.read(at + 12, &kind); entries.read(at + 16, &size); entries.read(at + 20, &rva); entries.read(at + 24, &raw);
            if (kind != 2) continue;
            if (size < 25 || size > 8192) { addWarning("invalid PE CodeView record extent"); continue; }
            ByteView record = raw ? file.subview(raw, size) : rvaView(rva, size); u32 signature = 0;
            if (record.size() != size || !record.read(0, &signature) || signature != 0x53445352) { addWarning("unsupported/truncated PE CodeView record (RSDS/PDB7 required)"); continue; }
            if (rva) {
                const ByteView mapped = rvaView(rva, size);
                if (mapped.size() != size || std::memcmp(record.data(), mapped.data(), size)) { addWarning("PE CodeView file/RVA views disagree; identity ignored"); continue; }
            }
            PeCodeViewRecord identity; std::copy(record.data() + 4, record.data() + 20, identity.guid.begin()); record.read(20, &identity.age);
            if (!identity.age || !terminatedString(record, 24, &identity.path) || identity.path.empty()) { addWarning("invalid PE RSDS age/path"); continue; }
            peCodeViewRecords_.push_back(std::move(identity));
        }
    }
    u32 tlsRva = 0, tlsSize = 0;
    if (directory(9, &tlsRva, &tlsSize)) {
        const size_t directorySize = pointerWidth * 4 + 8;
        const ByteView tls = rvaView(tlsRva, directorySize);
        Address rawStart = 0, rawEnd = 0, index = 0, callbacks = 0;
        u32 zeroFill = 0, tlsFlags = 0;
        bool valid = tlsSize >= directorySize && word(tls, 0, &rawStart) && word(tls, pointerWidth, &rawEnd) &&
            word(tls, pointerWidth * 2, &index) && word(tls, pointerWidth * 3, &callbacks) &&
            tls.read(pointerWidth * 4, &zeroFill) && tls.read(pointerWidth * 4 + 4, &tlsFlags);
        auto within = [this, imageSize](Address address, u64 size) {
            return address >= imageBase_ && address - imageBase_ < imageSize && size <= imageSize - (address - imageBase_);
        };
        if (valid) {
            valid = rawEnd >= rawStart && zeroFill <= 1024 * 1024 * 1024u &&
                ((rawStart == 0 && rawEnd == 0) || (within(rawStart, rawEnd - rawStart) &&
                  memory_.viewAt(rawStart, rawEnd - rawStart).size() == rawEnd - rawStart)) &&
                (!index || (within(index, 4) && memory_.isMapped(index) && memory_.isMapped(index + 3))) &&
                (tlsFlags & ~u32{0x00f00000}) == 0;
        }
        std::vector<Address> targets;
        bool callbackTerminated = callbacks == 0;
        if (valid && callbacks) {
            for (size_t slot = 0; slot < 4096; ++slot) {
                if (!within(callbacks, (slot + 1) * pointerWidth)) { valid = false; break; }
                Address target = 0;
                if (!word(memory_.viewAt(callbacks + slot * pointerWidth, pointerWidth), 0, &target)) { valid = false; break; }
                if (!target) { callbackTerminated = true; break; }
                if (!within(target, 1) || !memory_.isExecutable(target) || memory_.viewAt(target, 1).empty()) { valid = false; break; }
                targets.push_back(target);
            }
        }
        if (!valid || !callbackTerminated || targets.size() > kMaxPeSymbols - std::min<u64>(symbols_.size(), kMaxPeSymbols))
            addWarning("invalid/truncated/excessive PE TLS directory or callback array; TLS roots ignored");
        else for (size_t slot = 0; slot < targets.size(); ++slot) {
            ElfSymbol symbol; symbol.name = "tls_callback_" + std::to_string(slot); symbol.value = targets[slot];
            symbol.type = elf::kSttFunc; symbol.binding = elf::kStbLocal; symbols_.push_back(std::move(symbol));
        }
    }
    indexRelocations();
    indexSymbols();
    addWarning("PE analysis uses preferred VAs with validated imports/delay imports, base-fixup inventory and exception ranges; PDB7 is supported through explicit RSDS GUID/age-bound import, not automatic path following; execution of SEH unwind programs is not implied");
    loaded_ = true;
    return Status::success();
}
}  // namespace mint
