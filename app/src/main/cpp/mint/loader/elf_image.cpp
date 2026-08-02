#include "mint/loader/elf_image.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <utility>

#include "mint/base/log.h"

namespace mint {

// This translation unit is entirely about ELF constants; qualifying every one of
// them would bury the logic.
using namespace elf;  // NOLINT(google-build-using-namespace)

namespace {

/// Bounds on how much structure we will believe from a file we did not build.
/// These are not correctness limits — they are the line past which a "library"
/// is an attempt to exhaust memory rather than something to analyse.
constexpr u64 kMaxSections = 65535;
constexpr u64 kMaxSegments = 4096;
constexpr u64 kMaxSymbols = 4000000;
constexpr u64 kMaxRelocations = 8000000;
constexpr u64 kMaxNeeded = 4096;
constexpr u64 kMaxInitializers = 65536;

u32 segmentFlagsToMemoryFlags(u32 pFlags) {
    u32 flags = 0;
    if ((pFlags & kPfR) != 0) flags |= kMemRead;
    if ((pFlags & kPfW) != 0) flags |= kMemWrite;
    if ((pFlags & kPfX) != 0) flags |= kMemExec;
    return flags;
}

}  // namespace

void ElfImage::addWarning(std::string message) {
    // Cap it: a pathological file can otherwise generate a warning per entry and
    // the warning list becomes the memory-exhaustion vector the bounds above
    // were meant to close.
    if (warnings_.size() < 256) {
        warnings_.push_back(std::move(message));
    }
}

Status ElfImage::load(ByteView file) {
    *this = ElfImage();

    Status status = parseHeader(file);
    if (!status.ok()) return status;

    parseProgramHeaders(file);
    parseSectionHeaders(file);

    // The memory map must be complete before the dynamic table is read: every
    // pointer in that table is a virtual address that we resolve through the map.
    memory_.finalize();

    // Order matters and is not obvious. Relocations need .dynsym to name their
    // symbols, and the pointer arrays need relocations because in a
    // position-independent image their contents are relocation addends rather
    // than file bytes. So: tags, symbols, relocations, then anything that
    // follows a stored pointer.
    readDynamicTable(file);
    parseSymbolTables(file);
    parseRelocations(file);
    indexRelocations();
    resolvePointerArrays();
    reconstructPlt();
    indexSymbols();

    if (memory_.empty()) {
        return Status::error(ErrorCode::kBadFormat,
                            "no loadable segments; nothing to analyse");
    }

    loaded_ = true;
    MINT_LOGI("loaded ELF: %s, entry 0x%llx, %zu sections, %zu symbols, %zu relocs%s",
              archName(arch_), static_cast<unsigned long long>(entry_),
              sections_.size(), symbols_.size(), relocations_.size(),
              stripped_ ? ", stripped" : "");
    return Status::success();
}

Status ElfImage::parseHeader(ByteView file) {
    Ehdr header{};
    if (!file.readPod(0, &header)) {
        return Status::error(ErrorCode::kTruncated, "file smaller than an ELF header");
    }
    if (std::memcmp(header.ident, kMagic, sizeof(kMagic)) != 0) {
        return Status::error(ErrorCode::kBadFormat, "not an ELF file");
    }
    if (header.ident[kEiClass] != kElfClass64) {
        return Status::error(ErrorCode::kUnsupported,
                             "32-bit ELF; this engine analyses 64-bit images only");
    }
    if (header.ident[kEiData] != kElfData2Lsb) {
        return Status::error(ErrorCode::kUnsupported, "big-endian ELF is not supported");
    }

    switch (header.machine) {
        case kEmAArch64: arch_ = Arch::kAArch64; break;
        case kEmX86_64: arch_ = Arch::kX86_64; break;
        default:
            return Status::error(
                ErrorCode::kUnsupported,
                "unsupported machine type " + std::to_string(header.machine));
    }

    type_ = header.type;
    entry_ = header.entry;
    return Status::success();
}

void ElfImage::parseProgramHeaders(ByteView file) {
    Ehdr header{};
    if (!file.readPod(0, &header)) return;

    if (header.phnum == 0 || header.phoff == 0) {
        addWarning("no program headers; falling back to section table for memory layout");
        return;
    }
    if (header.phentsize < sizeof(Phdr)) {
        addWarning("program header entry size is too small; ignoring segment table");
        return;
    }
    const u64 count = std::min<u64>(header.phnum, kMaxSegments);

    for (u64 i = 0; i < count; ++i) {
        const u64 offset = header.phoff + i * header.phentsize;
        Phdr segment{};
        if (!file.readPod(offset, &segment)) {
            addWarning("program header table is truncated");
            break;
        }
        if (segment.type != kPtLoad) continue;
        if (segment.memsz == 0) continue;

        // filesz can exceed the real file when a header has been tampered with;
        // clamp so the segment's backing view never runs past the mapping.
        ByteView data = file.subview(segment.offset, segment.filesz);
        if (data.size() != segment.filesz) {
            data = file.from(segment.offset);
            addWarning("segment at 0x" + std::to_string(segment.vaddr) +
                       " claims more file bytes than the file contains");
        }

        memory_.addSegment(segment.vaddr, segment.memsz, data,
                           segmentFlagsToMemoryFlags(segment.flags),
                           "seg" + std::to_string(i));
    }
}

void ElfImage::parseSectionHeaders(ByteView file) {
    Ehdr header{};
    if (!file.readPod(0, &header)) return;

    if (header.shnum == 0 || header.shoff == 0) {
        addWarning("section table absent (stripped or deliberately removed)");
        return;
    }
    if (header.shentsize < sizeof(Shdr)) {
        addWarning("section header entry size is too small; ignoring section table");
        return;
    }
    const u64 count = std::min<u64>(header.shnum, kMaxSections);

    std::vector<Shdr> raw;
    raw.reserve(static_cast<size_t>(count));
    for (u64 i = 0; i < count; ++i) {
        Shdr section{};
        if (!file.readPod(header.shoff + i * header.shentsize, &section)) {
            addWarning("section header table is truncated");
            break;
        }
        raw.push_back(section);
    }

    // Section names live in the section whose index the header points at. A
    // bogus shstrndx is a common trick, so a bad index costs names, not the load.
    ByteView shstrtab;
    if (header.shstrndx < raw.size()) {
        const Shdr& strings = raw[header.shstrndx];
        if (strings.type == kShtStrTab) {
            shstrtab = file.subview(strings.offset, strings.size);
        }
    }
    if (shstrtab.empty() && !raw.empty()) {
        addWarning("section name table is unusable; sections will be unnamed");
    }

    sections_.reserve(raw.size());
    for (const Shdr& section : raw) {
        ElfSection out;
        out.type = section.type;
        out.flags = section.flags;
        out.addr = section.addr;
        out.fileOffset = section.offset;
        out.size = section.size;
        out.entrySize = section.entsize;
        out.link = section.link;
        out.info = section.info;

        if (!shstrtab.empty()) {
            shstrtab.cString(section.name, &out.name, 256);
        }

        // SHT_NOBITS occupies address space only; anything else is file-backed.
        if (section.type != kShtNoBits) {
            out.data = file.subview(section.offset, section.size);
            if (out.data.size() != section.size && section.size != 0) {
                addWarning("section " + (out.name.empty() ? "<unnamed>" : out.name) +
                           " extends past the end of the file");
            }
        }
        sections_.push_back(std::move(out));
    }

    // A library with no PT_LOAD but a usable section table is unusual but
    // analysable: synthesise segments from the allocated sections.
    if (memory_.empty()) {
        for (const ElfSection& section : sections_) {
            if (!section.allocated() || section.size == 0) continue;
            u32 flags = kMemRead;
            if ((section.flags & kShfWrite) != 0) flags |= kMemWrite;
            if ((section.flags & kShfExecInstr) != 0) flags |= kMemExec;
            memory_.addSegment(section.addr, section.size, section.data, flags,
                               section.name);
        }
    }
}

ByteView ElfImage::findDynamicView(ByteView file) const {
    // Prefer PT_DYNAMIC over .dynamic: the segment is what the runtime linker
    // actually reads, so it is the copy a protector has to keep honest.
    Ehdr header{};
    if (file.readPod(0, &header) && header.phnum != 0 &&
        header.phentsize >= sizeof(Phdr)) {
        const u64 count = std::min<u64>(header.phnum, kMaxSegments);
        for (u64 i = 0; i < count; ++i) {
            Phdr segment{};
            if (!file.readPod(header.phoff + i * header.phentsize, &segment)) break;
            if (segment.type != kPtDynamic) continue;
            ByteView view = file.subview(segment.offset, segment.filesz);
            if (!view.empty()) return view;
        }
    }
    const ElfSection* section = findSection(".dynamic");
    if (section != nullptr) return section->data;
    return {};
}

void ElfImage::readDynamicTable(ByteView file) {
    ByteView dynamic = findDynamicView(file);
    if (dynamic.empty()) return;

    const u64 entries = dynamic.size() / sizeof(Dyn);
    dynamicEntries_.reserve(static_cast<size_t>(std::min<u64>(entries, 4096)));
    for (u64 i = 0; i < entries; ++i) {
        Dyn entry{};
        if (!dynamic.readPod(i * sizeof(Dyn), &entry)) break;
        if (entry.tag == kDtNull) break;
        dynamicEntries_.push_back(entry);
        if (dynamicEntries_.size() >= 4096) {
            addWarning("dynamic table is implausibly long; truncated at 4096 entries");
            break;
        }
    }
    const std::vector<Dyn>& table = dynamicEntries_;

    for (const Dyn& entry : table) {
        switch (entry.tag) {
            case kDtStrTab: dynStrTabAddr_ = entry.value; break;
            case kDtStrSz: dynStrTabSize_ = entry.value; break;
            case kDtSymTab: dynSymTabAddr_ = entry.value; break;
            case kDtPltGot: pltGotAddr_ = entry.value; break;
            case kDtJmpRel: jmpRelAddr_ = entry.value; break;
            case kDtPltRelSz: pltRelSize_ = entry.value; break;
            case kDtPltRel: pltRelType_ = static_cast<i64>(entry.value); break;
            default: break;
        }
    }

    ByteView strings;
    if (dynStrTabAddr_ != 0 && dynStrTabSize_ != 0) {
        strings = memory_.viewAt(dynStrTabAddr_, dynStrTabSize_);
    }
    if (strings.empty()) {
        const ElfSection* section = findSection(".dynstr");
        if (section != nullptr) strings = section->data;
    }

    for (const Dyn& entry : table) {
        switch (entry.tag) {
            case kDtNeeded: {
                if (needed_.size() >= kMaxNeeded) break;
                std::string name;
                if (!strings.empty() && strings.cString(entry.value, &name, 512) &&
                    !name.empty()) {
                    needed_.push_back(std::move(name));
                }
                break;
            }
            case kDtSoName: {
                if (!strings.empty()) strings.cString(entry.value, &soname_, 512);
                break;
            }
            case kDtInit: {
                if (entry.value != 0) initializers_.push_back(entry.value);
                break;
            }
            case kDtFini: {
                if (entry.value != 0) finalizers_.push_back(entry.value);
                break;
            }
            default: break;
        }
    }

}

void ElfImage::indexRelocations() {
    relocationByOffset_.reserve(relocations_.size());
    for (size_t i = 0; i < relocations_.size(); ++i) {
        // A slot can be named by more than one relocation in a malformed file;
        // the first wins, matching what a linker applying them in order sees.
        relocationByOffset_.emplace(relocations_[i].offset, i);
    }
}

bool ElfImage::resolvePointer(Address at, Address* out) const {
    auto it = relocationByOffset_.find(at);
    if (it != relocationByOffset_.end()) {
        const ElfRelocation& reloc = relocations_[it->second];

        const bool isRelative = reloc.type == kRAArch64Relative ||
                                reloc.type == kRX86_64Relative ||
                                reloc.type == kRAArch64IRelative ||
                                reloc.type == kRX86_64IRelative;
        if (isRelative) {
            // The link-time target is the addend. For RELR there is no addend
            // field at all, so the value has to come from the slot itself, which
            // for RELR is where the linker did store it.
            if (reloc.source == ElfRelocation::Source::kRelr) {
                u64 raw = 0;
                if (memory_.readInt(at, &raw) && raw != 0) {
                    *out = raw;
                    return true;
                }
                return false;
            }
            if (reloc.addend != 0) {
                *out = static_cast<Address>(reloc.addend);
                return true;
            }
        }

        // A symbol-bound slot points at something the dynamic linker supplies.
        // If the symbol is defined in this image we can still name a target;
        // if it is an import there is no address here to follow.
        if (!reloc.symbolName.empty()) {
            const ElfSymbol* symbol = findSymbol(reloc.symbolName);
            if (symbol != nullptr && !symbol->undefined && symbol->value != 0) {
                *out = symbol->value + static_cast<Address>(reloc.addend);
                return true;
            }
            return false;
        }
    }

    u64 raw = 0;
    if (!memory_.readInt(at, &raw)) return false;
    if (raw == 0 || raw == ~static_cast<u64>(0)) return false;
    *out = raw;
    return true;
}

void ElfImage::resolvePointerArrays() {
    // DT_INIT_ARRAY and friends hold function pointers. In a position-independent
    // image the slots are zero on disk and the addresses live in relocation
    // addends, so this has to go through resolvePointer() — reading the bytes
    // directly reports an empty initialiser list for almost every real Android
    // library, which is precisely the list a packer would want us to miss.
    auto readArray = [&](i64 addrTag, i64 sizeTag, std::vector<Address>* out) {
        Address arrayAddr = 0;
        u64 arraySize = 0;
        for (const Dyn& entry : dynamicEntries_) {
            if (entry.tag == addrTag) arrayAddr = entry.value;
            if (entry.tag == sizeTag) arraySize = entry.value;
        }
        if (arrayAddr == 0 || arraySize == 0) return;

        const u64 count = std::min<u64>(arraySize / sizeof(u64), kMaxInitializers);
        for (u64 i = 0; i < count; ++i) {
            Address target = 0;
            if (resolvePointer(arrayAddr + i * sizeof(u64), &target)) {
                out->push_back(target);
            }
        }
    };
    readArray(kDtPreInitArray, kDtPreInitArraySz, &initializers_);
    readArray(kDtInitArray, kDtInitArraySz, &initializers_);
    readArray(kDtFiniArray, kDtFiniArraySz, &finalizers_);

    // .init_array with no dynamic tag: happens in a static executable, and in
    // libraries whose dynamic table has been trimmed.
    if (initializers_.empty()) {
        const ElfSection* section = findSection(".init_array");
        if (section != nullptr && section->size != 0) {
            const u64 count =
                std::min<u64>(section->size / sizeof(u64), kMaxInitializers);
            for (u64 i = 0; i < count; ++i) {
                Address target = 0;
                if (resolvePointer(section->addr + i * sizeof(u64), &target)) {
                    initializers_.push_back(target);
                }
            }
        }
    }
}

void ElfImage::readSymbolTable(ByteView table, ByteView strings, bool fromDynsym) {
    if (table.empty()) return;

    const u64 count = std::min<u64>(table.size() / sizeof(Sym), kMaxSymbols);
    if (symbols_.size() + count > kMaxSymbols) {
        addWarning("symbol tables exceed the supported entry count; truncated");
    }

    for (u64 i = 0; i < count; ++i) {
        if (symbols_.size() >= kMaxSymbols) break;

        Sym entry{};
        if (!table.readPod(i * sizeof(Sym), &entry)) break;

        ElfSymbol symbol;
        symbol.value = entry.value;
        symbol.size = entry.size;
        symbol.type = symbolType(entry.info);
        symbol.binding = symbolBinding(entry.info);
        symbol.visibility = symbolVisibility(entry.other);
        symbol.sectionIndex = entry.shndx;
        symbol.undefined = entry.shndx == kShnUndef;
        symbol.fromDynsym = fromDynsym;

        if (!strings.empty()) {
            strings.cString(entry.name, &symbol.name, 1024);
        }

        // Index 0 is the reserved null symbol; STT_FILE and STT_SECTION carry no
        // code or data of their own. Keeping them would pad the function list
        // with entries the user cannot navigate to.
        if (i == 0 || symbol.type == kSttFile || symbol.type == kSttSection) {
            if (fromDynsym) {
                // .dynsym indices must stay dense: relocations reference symbols
                // by index, so a placeholder has to occupy the slot.
                symbols_.push_back(std::move(symbol));
            }
            continue;
        }
        symbols_.push_back(std::move(symbol));
    }
}

void ElfImage::parseSymbolTables(ByteView file) {
    // .dynsym first, and contiguously, so relocation symbol indices map to
    // positions in symbols_ by simple addition.
    const ElfSection* dynsym = nullptr;
    const ElfSection* symtab = nullptr;
    for (const ElfSection& section : sections_) {
        if (section.type == kShtDynSym && dynsym == nullptr) dynsym = &section;
        if (section.type == kShtSymTab && symtab == nullptr) symtab = &section;
    }

    auto linkedStrings = [&](const ElfSection* section) -> ByteView {
        if (section == nullptr) return {};
        if (section->link < sections_.size()) {
            return sections_[section->link].data;
        }
        return {};
    };

    dynsymBegin_ = symbols_.size();
    if (dynsym != nullptr) {
        ByteView strings = linkedStrings(dynsym);
        if (strings.empty()) {
            const ElfSection* dynstr = findSection(".dynstr");
            if (dynstr != nullptr) strings = dynstr->data;
        }
        readSymbolTable(dynsym->data, strings, /*fromDynsym=*/true);
    } else if (dynSymTabAddr_ != 0 && dynStrTabAddr_ != 0) {
        // Section table gone. The dynamic segment gives us the symbol table's
        // address but no count, because the count lives in the hash table. The
        // linker lays .dynsym immediately before .dynstr in every toolchain we
        // care about, so the gap between them bounds the table. This is a
        // heuristic and is recorded as one.
        ByteView strings = memory_.viewAt(dynStrTabAddr_, dynStrTabSize_);
        if (dynStrTabAddr_ > dynSymTabAddr_) {
            const u64 span = dynStrTabAddr_ - dynSymTabAddr_;
            ByteView table = memory_.viewAt(dynSymTabAddr_, span);
            addWarning(
                "section table missing; .dynsym size inferred from the gap to "
                ".dynstr");
            readSymbolTable(table, strings, /*fromDynsym=*/true);
        } else {
            addWarning("section table missing and .dynsym extent could not be inferred");
        }
    }
    dynsymCount_ = symbols_.size() - dynsymBegin_;

    if (symtab != nullptr) {
        stripped_ = false;
        readSymbolTable(symtab->data, linkedStrings(symtab), /*fromDynsym=*/false);
    }
}

void ElfImage::readRelaArray(ByteView data, ElfRelocation::Source source) {
    const u64 count = data.size() / sizeof(Rela);
    for (u64 i = 0; i < count; ++i) {
        if (relocations_.size() >= kMaxRelocations) return;
        Rela entry{};
        if (!data.readPod(i * sizeof(Rela), &entry)) return;

        ElfRelocation reloc;
        reloc.offset = entry.offset;
        reloc.type = relocType(entry.info);
        reloc.symbolIndex = relocSymbol(entry.info);
        reloc.addend = entry.addend;
        reloc.source = source;
        reloc.symbolName = dynamicSymbolName(reloc.symbolIndex);
        relocations_.push_back(std::move(reloc));
    }
}

void ElfImage::readRelArray(ByteView data, ElfRelocation::Source source) {
    const u64 count = data.size() / sizeof(Rel);
    for (u64 i = 0; i < count; ++i) {
        if (relocations_.size() >= kMaxRelocations) return;
        Rel entry{};
        if (!data.readPod(i * sizeof(Rel), &entry)) return;

        ElfRelocation reloc;
        reloc.offset = entry.offset;
        reloc.type = relocType(entry.info);
        reloc.symbolIndex = relocSymbol(entry.info);
        reloc.addend = 0;  // Implicit: stored at the patch site.
        reloc.source = source;
        reloc.symbolName = dynamicSymbolName(reloc.symbolIndex);
        relocations_.push_back(std::move(reloc));
    }
}

void ElfImage::readAndroidPackedRelocations(ByteView data) {
    // APS2: a group-compressed SLEB128 stream produced by the NDK linker to cut
    // relocation size. A loader that skips it sees a library with essentially no
    // relocations and resolves none of its imports, so this is not optional for
    // Android targets.
    if (data.size() < 4) return;
    u8 magic[4] = {};
    for (size_t i = 0; i < 4; ++i) {
        if (!data.byteAt(i, &magic[i])) return;
    }
    if (magic[0] != 'A' || magic[1] != 'P' || magic[2] != 'S' || magic[3] != '2') {
        addWarning("packed relocation section has an unrecognised encoding");
        return;
    }

    constexpr u64 kGroupedByInfo = 1;
    constexpr u64 kGroupedByOffsetDelta = 2;
    constexpr u64 kGroupedByAddend = 4;
    constexpr u64 kGroupHasAddend = 8;

    ByteCursor cursor(data, 4);
    const i64 totalCount = cursor.nextSleb128();
    Address offset = static_cast<Address>(cursor.nextSleb128());
    i64 addend = 0;

    if (!cursor.ok() || totalCount < 0 ||
        static_cast<u64>(totalCount) > kMaxRelocations) {
        addWarning("packed relocation header is malformed");
        return;
    }

    u64 emitted = 0;
    while (emitted < static_cast<u64>(totalCount) && cursor.ok()) {
        const i64 groupSize = cursor.nextSleb128();
        const u64 groupFlags = static_cast<u64>(cursor.nextSleb128());
        if (!cursor.ok() || groupSize <= 0) break;
        if (static_cast<u64>(groupSize) > static_cast<u64>(totalCount) - emitted) {
            addWarning("packed relocation group overruns the declared count");
            break;
        }

        i64 groupOffsetDelta = 0;
        if ((groupFlags & kGroupedByOffsetDelta) != 0) {
            groupOffsetDelta = cursor.nextSleb128();
        }
        u64 groupInfo = 0;
        if ((groupFlags & kGroupedByInfo) != 0) {
            groupInfo = static_cast<u64>(cursor.nextSleb128());
        }
        i64 groupAddendDelta = 0;
        if ((groupFlags & kGroupedByAddend) != 0 && (groupFlags & kGroupHasAddend) != 0) {
            groupAddendDelta = cursor.nextSleb128();
        }

        for (i64 i = 0; i < groupSize && cursor.ok(); ++i) {
            offset += static_cast<Address>((groupFlags & kGroupedByOffsetDelta) != 0
                                              ? groupOffsetDelta
                                              : cursor.nextSleb128());

            const u64 info = (groupFlags & kGroupedByInfo) != 0
                                 ? groupInfo
                                 : static_cast<u64>(cursor.nextSleb128());

            if ((groupFlags & kGroupHasAddend) != 0) {
                addend += (groupFlags & kGroupedByAddend) != 0 ? groupAddendDelta
                                                              : cursor.nextSleb128();
            } else {
                addend = 0;
            }

            if (relocations_.size() >= kMaxRelocations) return;

            ElfRelocation reloc;
            reloc.offset = offset;
            reloc.type = relocType(info);
            reloc.symbolIndex = relocSymbol(info);
            reloc.addend = addend;
            reloc.source = ElfRelocation::Source::kAndroidPacked;
            reloc.symbolName = dynamicSymbolName(reloc.symbolIndex);
            relocations_.push_back(std::move(reloc));
            ++emitted;
        }
    }

    if (!cursor.ok()) {
        addWarning("packed relocation stream ended mid-group");
    }
}

void ElfImage::readRelrRelocations(ByteView data) {
    // RELR encodes runs of relative relocations as a bitmap: an even entry is an
    // address, and each following odd entry's bits mark further words relative
    // to it. All of them are implicitly "add the load bias", so they carry no
    // symbol — but they do tell us which words hold pointers, which is what lets
    // the analyser tell a pointer table from data.
    const u64 count = data.size() / sizeof(u64);
    Address where = 0;

    for (u64 i = 0; i < count; ++i) {
        u64 entry = 0;
        if (!data.readPod(i * sizeof(u64), &entry)) return;

        if ((entry & 1) == 0) {
            where = entry;
            if (relocations_.size() >= kMaxRelocations) return;
            ElfRelocation reloc;
            reloc.offset = where;
            reloc.type = arch_ == Arch::kAArch64 ? kRAArch64Relative : kRX86_64Relative;
            reloc.source = ElfRelocation::Source::kRelr;
            relocations_.push_back(std::move(reloc));
            where += sizeof(u64);
            continue;
        }

        Address bitmapBase = where;
        for (int bit = 1; bit < 64; ++bit) {
            if ((entry & (static_cast<u64>(1) << bit)) == 0) continue;
            if (relocations_.size() >= kMaxRelocations) return;
            ElfRelocation reloc;
            reloc.offset = bitmapBase + static_cast<Address>(bit - 1) * sizeof(u64);
            reloc.type = arch_ == Arch::kAArch64 ? kRAArch64Relative : kRX86_64Relative;
            reloc.source = ElfRelocation::Source::kRelr;
            relocations_.push_back(std::move(reloc));
        }
        where = bitmapBase + 63 * sizeof(u64);
    }
}

void ElfImage::parseRelocations(ByteView file) {
    bool sawAny = false;

    for (const ElfSection& section : sections_) {
        switch (section.type) {
            case kShtRela:
                readRelaArray(section.data, ElfRelocation::Source::kRela);
                sawAny = true;
                break;
            case kShtRel:
                readRelArray(section.data, ElfRelocation::Source::kRel);
                sawAny = true;
                break;
            case kShtAndroidRela:
            case kShtAndroidRel:
                readAndroidPackedRelocations(section.data);
                sawAny = true;
                break;
            case kShtRelr:
            case kShtAndroidRelr:
                readRelrRelocations(section.data);
                sawAny = true;
                break;
            default:
                break;
        }
    }

    if (sawAny) return;

    // No usable section table: fall back to the dynamic table's own pointers.
    // This is the normal path for a library whose sections were stripped.
    if (dynamicEntries_.empty()) return;

    Address relaAddr = 0, packedAddr = 0, relrAddr = 0;
    u64 relaSize = 0, packedSize = 0, relrSize = 0;

    for (const Dyn& entry : dynamicEntries_) {
        switch (entry.tag) {
            case kDtRela: relaAddr = entry.value; break;
            case kDtRelaSz: relaSize = entry.value; break;
            case kDtAndroidRela: packedAddr = entry.value; break;
            case kDtAndroidRelaSz: packedSize = entry.value; break;
            case kDtAndroidRel: packedAddr = entry.value; break;
            case kDtAndroidRelSz: packedSize = entry.value; break;
            case kDtRelr:
            case kDtAndroidRelr: relrAddr = entry.value; break;
            case kDtRelrSz:
            case kDtAndroidRelrSz: relrSize = entry.value; break;
            default: break;
        }
    }

    if (packedAddr != 0 && packedSize != 0) {
        readAndroidPackedRelocations(memory_.viewAt(packedAddr, packedSize));
    }
    if (relaAddr != 0 && relaSize != 0) {
        readRelaArray(memory_.viewAt(relaAddr, relaSize), ElfRelocation::Source::kRela);
    }
    if (relrAddr != 0 && relrSize != 0) {
        readRelrRelocations(memory_.viewAt(relrAddr, relrSize));
    }
    if (jmpRelAddr_ != 0 && pltRelSize_ != 0) {
        readRelaArray(memory_.viewAt(jmpRelAddr_, pltRelSize_),
                      ElfRelocation::Source::kRela);
    }
}

void ElfImage::reconstructPlt() {
    const ElfSection* plt = findSection(".plt");
    if (plt == nullptr || plt->size == 0) return;

    // Only JUMP_SLOT relocations correspond to PLT stubs, and they appear in the
    // same order as the stubs themselves. That ordering is the whole basis for
    // this recovery; a non-standard linker would break it, which is why the
    // result is advisory naming rather than anything analysis depends on.
    const u32 jumpSlot =
        arch_ == Arch::kAArch64 ? kRAArch64JumpSlot : kRX86_64JumpSlot;

    std::vector<const ElfRelocation*> jumpSlots;
    for (const ElfRelocation& reloc : relocations_) {
        if (reloc.type == jumpSlot && !reloc.symbolName.empty()) {
            jumpSlots.push_back(&reloc);
        }
    }
    if (jumpSlots.empty()) return;

    // Stub size is not a constant per architecture, so it is solved for rather
    // than assumed. AArch64 uses 16-byte stubs normally but 24 when branch
    // target identification is enabled, which is the default in current NDKs —
    // guessing 16 there puts every recovered name at the wrong address, and the
    // result still looks plausible because the addresses stay inside .plt.
    //
    // The JUMP_SLOT count is known exactly, so the layout that divides the
    // section evenly is the layout the linker used.
    struct Layout {
        u64 header;
        u64 stride;
    };
    static const Layout kAArch64Layouts[] = {{32, 16}, {32, 24}, {0, 16}, {0, 24}};
    static const Layout kX86Layouts[] = {{16, 16}, {0, 16}};

    const Layout* candidates =
        arch_ == Arch::kAArch64 ? kAArch64Layouts : kX86Layouts;
    const size_t candidateCount =
        arch_ == Arch::kAArch64 ? std::size(kAArch64Layouts) : std::size(kX86Layouts);

    const u64 slots = jumpSlots.size();
    const Layout* chosen = nullptr;
    for (size_t i = 0; i < candidateCount; ++i) {
        if (candidates[i].header + slots * candidates[i].stride == plt->size) {
            chosen = &candidates[i];
            break;
        }
    }

    if (chosen == nullptr) {
        // No exact fit: the PLT holds something beyond plain JUMP_SLOT stubs, or
        // a non-standard linker produced it. Naming would be guesswork, and a
        // wrong name in a listing is worse than no name, so stop here and say so.
        addWarning(".plt is " + std::to_string(plt->size) + " bytes with " +
                   std::to_string(slots) +
                   " JUMP_SLOT relocations, which matches no known stub layout; "
                   "external call names were not recovered");
        return;
    }

    pltStride_ = chosen->stride;
    for (u64 i = 0; i < slots; ++i) {
        pltStubs_[plt->addr + chosen->header + i * chosen->stride] =
            jumpSlots[i]->symbolName;
    }
}

void ElfImage::indexSymbols() {
    symbolByName_.reserve(symbols_.size());
    for (size_t i = 0; i < symbols_.size(); ++i) {
        const ElfSymbol& symbol = symbols_[i];
        if (symbol.name.empty()) continue;
        // First definition wins, and a defined symbol always beats an undefined
        // one of the same name — otherwise an import shadows the real function.
        auto existing = symbolByName_.find(symbol.name);
        if (existing == symbolByName_.end()) {
            symbolByName_.emplace(symbol.name, i);
        } else if (symbols_[existing->second].undefined && !symbol.undefined) {
            existing->second = i;
        }
    }
    buildAddressIndex();
}

void ElfImage::buildAddressIndex() {
    auto betterExact = [&](size_t candidate, size_t current) {
        const ElfSymbol& a = symbols_[candidate];
        const ElfSymbol& b = symbols_[current];
        if (a.isFunction() != b.isFunction()) return a.isFunction();
        if ((a.size != 0) != (b.size != 0)) return a.size != 0;
        return a.size > b.size;
    };

    addressIntervals_.clear();
    intervalPrefixMaxEnd_.clear();
    exactSymbolByAddress_.clear();
    addressIntervals_.reserve(symbols_.size());
    for (size_t i = 0; i < symbols_.size(); ++i) {
        const ElfSymbol& symbol = symbols_[i];
        if (symbol.undefined || symbol.name.empty() || symbol.value == 0 ||
            symbol.isMappingSymbol()) {
            continue;
        }
        auto exact = exactSymbolByAddress_.find(symbol.value);
        if (exact == exactSymbolByAddress_.end() || betterExact(i, exact->second)) {
            exactSymbolByAddress_[symbol.value] = i;
        }
        if (symbol.size == 0 || symbol.size > ~symbol.value) continue;
        const Address end = symbol.value + symbol.size;
        if (end <= symbol.value) continue;
        addressIntervals_.push_back(AddressInterval{symbol.value, end, i});
    }
    std::sort(addressIntervals_.begin(), addressIntervals_.end(),
              [&](const AddressInterval& a, const AddressInterval& b) {
                  if (a.start != b.start) return a.start < b.start;
                  if (a.end != b.end) return a.end < b.end;
                  return a.symbolIndex < b.symbolIndex;
              });
    intervalPrefixMaxEnd_.resize(addressIntervals_.size(), 0);
    Address maxEnd = 0;
    for (size_t i = 0; i < addressIntervals_.size(); ++i) {
        maxEnd = std::max(maxEnd, addressIntervals_[i].end);
        intervalPrefixMaxEnd_[i] = maxEnd;
    }
}

std::string ElfImage::dynamicSymbolName(u32 index) const {
    if (index == 0) return {};
    if (index >= dynsymCount_) return {};
    return symbols_[dynsymBegin_ + index].name;
}

const ElfSection* ElfImage::findSection(const std::string& name) const {
    for (const ElfSection& section : sections_) {
        if (section.name == name) return &section;
    }
    return nullptr;
}

const ElfSymbol* ElfImage::findSymbol(const std::string& name) const {
    auto it = symbolByName_.find(name);
    if (it == symbolByName_.end()) return nullptr;
    return &symbols_[it->second];
}

std::string ElfImage::describeAddress(Address addr) const {
    auto stub = pltStubs_.find(addr);
    if (stub != pltStubs_.end()) return stub->second + "@plt";

    const auto exact = exactSymbolByAddress_.find(addr);
    if (exact != exactSymbolByAddress_.end()) return symbols_[exact->second].name;

    // The prefix maximum lets the backwards walk stop as soon as no earlier
    // interval can reach the queried address. In the normal ELF case symbols are
    // nearly disjoint, so this is one binary search plus a handful of cache-local
    // checks; aliases and nested symbols remain correct because the smallest range
    // wins.
    const auto upper = std::upper_bound(
        addressIntervals_.begin(), addressIntervals_.end(), addr,
        [](Address value, const AddressInterval& interval) { return value < interval.start; });
    const size_t first = static_cast<size_t>(upper - addressIntervals_.begin());
    const ElfSymbol* best = nullptr;
    for (size_t cursor = first; cursor != 0;) {
        --cursor;
        if (intervalPrefixMaxEnd_[cursor] <= addr) break;
        const AddressInterval& interval = addressIntervals_[cursor];
        if (interval.start > addr || addr >= interval.end) continue;
        const ElfSymbol& symbol = symbols_[interval.symbolIndex];
        if (best == nullptr || symbol.size < best->size ||
            (symbol.size == best->size && symbol.isFunction() && !best->isFunction())) {
            best = &symbol;
        }
    }
    if (best != nullptr) {
        return best->name + "+0x" + [&] {
            char buffer[32];
            snprintf(buffer, sizeof(buffer), "%llx",
                     static_cast<unsigned long long>(addr - best->value));
            return std::string(buffer);
        }();
    }
    return {};
}

}  // namespace mint
