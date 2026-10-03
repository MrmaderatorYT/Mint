#include "mint/loader/elf_image.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <tuple>

namespace mint {
namespace {
struct Header32 {
    u8 ident[16]; u16 type, machine; u32 version, entry, phoff, shoff, flags;
    u16 ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct Segment32 { u32 type, offset, vaddr, paddr, filesz, memsz, flags, align; };
struct Section32 { u32 name, type, flags, addr, offset, size, link, info, align, entsize; };
struct Symbol32 { u32 name, value, size; u8 info, other; u16 shndx; };
struct Rel32 { u32 offset, info; };
struct Rela32 { u32 offset, info; i32 addend; };
struct Dynamic32 { i32 tag; u32 value; };
static_assert(sizeof(Header32) == 52 && sizeof(Segment32) == 32 && sizeof(Section32) == 40 &&
              sizeof(Symbol32) == 16 && sizeof(Rel32) == 8 && sizeof(Rela32) == 12 && sizeof(Dynamic32) == 8,
              "ELF32 on-disk widths must not depend on host ABI");
constexpr u64 kAddressEnd32 = u64{1} << 32;
constexpr size_t kSymbolsLimit = 4000000, kRelocationsLimit = 8000000;

bool tableFits(ByteView file, u64 offset, u64 stride, u64 count, u64 minimum) {
    return stride >= minimum && offset <= file.size() && count <= (file.size() - offset) / stride;
}
u32 flags32(u32 flags) {
    return ((flags & elf::kPfR) ? kMemRead : 0) | ((flags & elf::kPfW) ? kMemWrite : 0) |
           ((flags & elf::kPfX) ? kMemExec : 0);
}
}

Status ElfImage::loadElf32(ByteView file) {
    Header32 header{};
    if (!file.readPod(0, &header)) return Status::error(ErrorCode::kTruncated, "ELF32 header is truncated");
    if (std::memcmp(header.ident, elf::kMagic, 4) != 0 || header.ident[elf::kEiClass] != 1 ||
        header.ident[elf::kEiVersion] != 1 || header.version != 1 || header.ehsize < sizeof(header) || header.ehsize > file.size())
        return Status::error(ErrorCode::kBadFormat, "invalid ELF32 identification/header");
    if (header.ident[elf::kEiData] != elf::kElfData2Lsb)
        return Status::error(ErrorCode::kUnsupported, "big-endian ELF32 is not supported");
    switch (header.machine) {
        case 3: arch_ = Arch::kX86_32; break;
        case 40: arch_ = Arch::kArm32; break;
        case 243: arch_ = Arch::kRiscV32; break;
        default: return Status::error(ErrorCode::kUnsupported, "unsupported ELF32 machine " + std::to_string(header.machine));
    }
    if (header.type != elf::kEtExec && header.type != elf::kEtDyn && header.type != elf::kEtRel)
        return Status::error(ErrorCode::kUnsupported, "ELF32 object type is not executable/shared/relocatable");
    format_ = ImageFormat::kElf32;
    type_ = header.type;
    entry_ = canonicalAddress(header.entry);
    if (arch_ == Arch::kArm32 && (header.entry & 1)) armModes_.emplace_back(entry_, true);

    std::vector<Segment32> segments;
    if (header.phnum) {
        if (header.phnum > 4096 || !tableFits(file, header.phoff, header.phentsize, header.phnum, sizeof(Segment32)))
            addWarning("invalid/truncated ELF32 program table; trying allocated sections instead");
        else {
            segments.reserve(header.phnum);
            for (u64 i = 0; i < header.phnum; ++i) {
                Segment32 segment{};
                if (!file.readPod(u64{header.phoff} + i * header.phentsize, &segment)) break;
                segments.push_back(segment);
                if (segment.type != elf::kPtLoad || segment.memsz == 0) continue;
                if (segment.filesz > segment.memsz || u64{segment.vaddr} + segment.memsz > kAddressEnd32 ||
                    segment.offset > file.size() || segment.filesz > file.size() - segment.offset ||
                    (segment.align > 1 && ((segment.align & (segment.align - 1)) != 0 ||
                     (segment.vaddr % segment.align) != (segment.offset % segment.align)))) {
                    addWarning("invalid ELF32 load segment " + std::to_string(i) + " was omitted");
                    continue;
                }
                memory_.addSegment(segment.vaddr, segment.memsz, file.subview(segment.offset, segment.filesz),
                                   flags32(segment.flags), "seg" + std::to_string(i));
            }
        }
    }

    std::vector<Section32> rawSections;
    u64 sectionCount = header.shnum, namesIndex = header.shstrndx;
    // Extended section count/name index are stored in section zero.
    if (header.shoff && (!sectionCount || namesIndex == 0xffff) && header.shentsize >= sizeof(Section32)) {
        Section32 first{};
        if (file.readPod(header.shoff, &first)) {
            if (!sectionCount) sectionCount = first.size;
            if (namesIndex == 0xffff) namesIndex = first.link;
        }
    }
    if (header.shoff && sectionCount) {
        if (sectionCount > 65535 || !tableFits(file, header.shoff, header.shentsize, sectionCount, sizeof(Section32)))
            addWarning("invalid/truncated ELF32 section table was omitted");
        else {
            rawSections.resize(static_cast<size_t>(sectionCount));
            for (u64 i = 0; i < sectionCount; ++i)
                file.readPod(u64{header.shoff} + i * header.shentsize, &rawSections[static_cast<size_t>(i)]);
        }
    } else addWarning("ELF32 section table is absent");
    ByteView sectionNames;
    if (namesIndex < rawSections.size() && rawSections[static_cast<size_t>(namesIndex)].type == elf::kShtStrTab) {
        const auto& strings = rawSections[static_cast<size_t>(namesIndex)];
        sectionNames = file.subview(strings.offset, strings.size);
    }
    Address objectNext = 0x10000;
    for (const auto& section : rawSections) {
        ElfSection output;
        output.type = section.type; output.flags = section.flags; output.addr = section.addr;
        output.fileOffset = section.offset; output.size = section.size; output.entrySize = section.entsize;
        output.link = section.link; output.info = section.info;
        sectionNames.cString(section.name, &output.name, 256);
        if (section.type != elf::kShtNoBits && section.size) {
            output.data = file.subview(section.offset, section.size);
            if (output.data.size() != section.size) addWarning("ELF32 section " + output.name + " has invalid file bounds");
        }
        if (type_ == elf::kEtRel && output.allocated()) {
            const u64 alignment = std::max<u64>(section.align, 1);
            if ((alignment & (alignment - 1)) != 0 || alignment > 0x100000 ||
                objectNext > kAddressEnd32 - alignment || section.size > kAddressEnd32 - objectNext - alignment) {
                output.flags &= ~elf::kShfAlloc;
                addWarning("ELF32 relocatable section cannot be assigned a bounded address");
            } else {
                objectNext = (objectNext + alignment - 1) & ~(alignment - 1);
                output.addr = objectNext;
                objectNext += output.size;
            }
        }
        if (output.allocated() && output.size && u64{output.addr} + output.size > kAddressEnd32) {
            output.flags &= ~elf::kShfAlloc;
            addWarning("ELF32 section virtual range overflows 32-bit address space");
        }
        sections_.push_back(std::move(output));
    }
    if (memory_.empty()) {
        for (const auto& section : sections_) {
            if (!section.allocated() || !section.size ||
                (section.type != elf::kShtNoBits && section.data.size() != section.size)) continue;
            const u32 flags = kMemRead | ((section.flags & elf::kShfWrite) ? kMemWrite : 0) |
                (section.executable() ? kMemExec : 0);
            memory_.addSegment(section.addr, section.size, section.data, flags, section.name);
        }
    }
    memory_.finalize();
    if (memory_.empty()) return Status::error(ErrorCode::kBadFormat, "ELF32 contains no usable mapped segments or sections");
    imageBase_ = memory_.minAddress();
    if (memory_.hasOverlaps()) addWarning("ELF32 mapped segments overlap; patching requires a unique mapping");
    if (type_ == elf::kEtRel) addWarning("ELF32 relocatable sections use synthetic link-time addresses; instruction relocations are metadata, not applied patches");

    ByteView dynamic;
    for (const auto& segment : segments) {
        if (segment.type != elf::kPtDynamic) continue;
        dynamic = file.subview(segment.offset, segment.filesz);
        if (!dynamic.empty()) break;
    }
    if (dynamic.empty()) for (const auto& section : sections_) if (section.type == elf::kShtDynamic) { dynamic = section.data; break; }
    for (size_t i = 0, count = std::min<size_t>(dynamic.size() / sizeof(Dynamic32), 4096); i < count; ++i) {
        Dynamic32 value{}; dynamic.readPod(i * sizeof(value), &value);
        if (value.tag == elf::kDtNull) break;
        dynamicEntries_.push_back({value.tag, value.value});
    }
    auto tag = [&](i64 wanted) -> u64 {
        for (const auto& value : dynamicEntries_) if (value.tag == wanted) return value.value;
        return 0;
    };
    dynStrTabAddr_ = tag(elf::kDtStrTab); dynStrTabSize_ = tag(elf::kDtStrSz);
    dynSymTabAddr_ = tag(elf::kDtSymTab); pltGotAddr_ = tag(elf::kDtPltGot);
    jmpRelAddr_ = tag(elf::kDtJmpRel); pltRelSize_ = tag(elf::kDtPltRelSz); pltRelType_ = static_cast<i64>(tag(elf::kDtPltRel));
    ByteView dynStrings = memory_.viewAt(dynStrTabAddr_, dynStrTabSize_);
    if (dynStrings.size() != dynStrTabSize_) dynStrings = {};
    if (dynStrings.empty()) { const auto* strings = findSection(".dynstr"); if (strings) dynStrings = strings->data; }
    for (const auto& value : dynamicEntries_) {
        std::string name;
        if (value.tag == elf::kDtNeeded && needed_.size() < 4096 && dynStrings.cString(value.value, &name, 512) && !name.empty())
            needed_.push_back(std::move(name));
        else if (value.tag == elf::kDtSoName && dynStrings.cString(value.value, &name, 512)) soname_ = std::move(name);
        else if (value.tag == elf::kDtInit && value.value) initializers_.push_back(value.value);
        else if (value.tag == elf::kDtFini && value.value) finalizers_.push_back(value.value);
    }

    std::unordered_map<size_t, std::vector<size_t>> symbolTables;
    auto readSymbols = [&](ByteView table, u64 stride, ByteView strings, bool dynamicTable, size_t sectionIndex) {
        if (stride < sizeof(Symbol32) || table.size() % stride != 0) { addWarning("invalid ELF32 symbol entry size/table length"); return; }
        const size_t count = std::min<size_t>(table.size() / stride, kSymbolsLimit - symbols_.size());
        auto& indexes = symbolTables[sectionIndex]; indexes.reserve(count);
        if (dynamicTable && !dynsymCount_) dynsymBegin_ = symbols_.size();
        for (size_t i = 0; i < count; ++i) {
            Symbol32 value{}; if (!table.readPod(i * stride, &value)) break;
            ElfSymbol output;
            strings.cString(value.name, &output.name, 1024);
            output.value = value.value; output.size = value.size; output.type = elf::symbolType(value.info);
            output.binding = elf::symbolBinding(value.info); output.visibility = elf::symbolVisibility(value.other);
            output.sectionIndex = value.shndx; output.undefined = value.shndx == elf::kShnUndef; output.fromDynsym = dynamicTable;
            if (type_ == elf::kEtRel && !output.undefined && value.shndx < sections_.size())
                output.value += sections_[value.shndx].addr;
            if (arch_ == Arch::kArm32 && !output.undefined) {
                if (output.isFunction()) {
                    armModes_.emplace_back(canonicalAddress(output.value), (output.value & 1) != 0);
                    output.value = canonicalAddress(output.value);
                } else if (output.isMappingSymbol() && (output.name[1] == 'a' || output.name[1] == 't'))
                    armModes_.emplace_back(canonicalAddress(output.value), output.name[1] == 't');
            }
            indexes.push_back(symbols_.size()); symbols_.push_back(std::move(output));
        }
        if (dynamicTable && !dynsymCount_) dynsymCount_ = count;
    };
    for (size_t i = 0; i < sections_.size(); ++i) {
        const auto& table = sections_[i];
        if (table.type != elf::kShtSymTab && table.type != elf::kShtDynSym) continue;
        if (table.link >= sections_.size() || sections_[table.link].type != elf::kShtStrTab) {
            addWarning("ELF32 symbol table has invalid string-table link"); continue;
        }
        if (table.type == elf::kShtSymTab) stripped_ = false;
        readSymbols(table.data, table.entrySize, sections_[table.link].data, table.type == elf::kShtDynSym, i);
    }
    constexpr size_t kDynamicTable = std::numeric_limits<size_t>::max();
    if (!dynsymCount_ && dynSymTabAddr_) {
        u32 symbolCount = 0;
        if (tag(elf::kDtHash)) memory_.readInt(tag(elf::kDtHash) + 4, &symbolCount);
        if (!symbolCount && tag(elf::kDtGnuHash)) {
            const Address hash = tag(elf::kDtGnuHash);
            u32 buckets = 0, firstSymbol = 0, bloomCount = 0;
            if (memory_.readInt(hash, &buckets) && memory_.readInt(hash + 4, &firstSymbol) &&
                memory_.readInt(hash + 8, &bloomCount) && buckets <= 1000000 && bloomCount <= 1000000 && firstSymbol <= kSymbolsLimit) {
                const Address bucketTable = hash + 16 + u64{bloomCount} * 4;
                u32 maximum = 0;
                for (u32 i = 0; i < buckets; ++i) { u32 bucket = 0; if (!memory_.readInt(bucketTable + u64{i} * 4, &bucket)) break; maximum = std::max(maximum, bucket); }
                if (maximum >= firstSymbol && maximum < kSymbolsLimit) {
                    const Address chains = bucketTable + u64{buckets} * 4;
                    for (u32 index = maximum; index < kSymbolsLimit; ++index) {
                        u32 chain = 0;
                        if (!memory_.readInt(chains + u64{index - firstSymbol} * 4, &chain)) break;
                        if (chain & 1) { symbolCount = index + 1; break; }
                    }
                } else if (maximum == 0) symbolCount = firstSymbol;
            }
        }
        const u64 stride = tag(elf::kDtSymEnt) ? tag(elf::kDtSymEnt) : sizeof(Symbol32);
        if (symbolCount && symbolCount <= kSymbolsLimit && stride == sizeof(Symbol32)) {
            const auto table = memory_.viewAt(dynSymTabAddr_, u64{symbolCount} * stride);
            if (table.size() == u64{symbolCount} * stride) readSymbols(table, stride, dynStrings, true, kDynamicTable);
        } else addWarning("sectionless ELF32 dynamic symbols lack a bounded hash table/entry size");
    }

    std::set<std::tuple<Address, u32, u32>> seen;
    auto append = [&](Address offset, u32 info, i64 addend, ElfRelocation::Source source, size_t linkedSymbols) {
        const u32 symbol = info >> 8, type = info & 255;
        if (offset >= kAddressEnd32 || relocations_.size() >= kRelocationsLimit || !seen.emplace(offset, type, symbol).second) return;
        ElfRelocation output; output.offset = offset; output.type = type; output.symbolIndex = symbol; output.addend = addend; output.source = source;
        const auto table = symbolTables.find(linkedSymbols);
        if (table != symbolTables.end() && symbol < table->second.size()) output.symbolName = symbols_[table->second[symbol]].name;
        else output.symbolName = dynamicSymbolName(symbol);
        relocations_.push_back(std::move(output));
    };
    auto readRelocations = [&](ByteView table, u64 stride, bool rela, size_t linkedSymbols, Address sectionBase) {
        const size_t minimum = rela ? sizeof(Rela32) : sizeof(Rel32);
        if (stride < minimum || table.size() % stride != 0) { addWarning("invalid ELF32 relocation table stride/length"); return; }
        const size_t count = std::min<size_t>(table.size() / stride, kRelocationsLimit - relocations_.size());
        for (size_t i = 0; i < count; ++i) {
            if (rela) {
                Rela32 value{}; table.readPod(i * stride, &value);
                append(sectionBase + value.offset, value.info, value.addend, ElfRelocation::Source::kRela, linkedSymbols);
            } else {
                Rel32 value{}; table.readPod(i * stride, &value);
                u32 addend = 0; memory_.readInt(sectionBase + value.offset, &addend);
                append(sectionBase + value.offset, value.info, static_cast<i32>(addend), ElfRelocation::Source::kRel, linkedSymbols);
            }
        }
    };
    for (const auto& section : sections_) {
        if (section.type != elf::kShtRel && section.type != elf::kShtRela) continue;
        Address targetBase = 0;
        if (type_ == elf::kEtRel) {
            if (section.info >= sections_.size()) { addWarning("ELF32 relocation target section link is invalid"); continue; }
            targetBase = sections_[section.info].addr;
        }
        readRelocations(section.data, section.entrySize, section.type == elf::kShtRela, section.link, targetBase);
    }
    auto dynamicRelocs = [&](i64 addressTag, i64 sizeTag, bool rela) {
        const u64 address = tag(addressTag), size = tag(sizeTag), minimum = rela ? sizeof(Rela32) : sizeof(Rel32);
        if (!address || !size) return;
        const u64 configured = tag(rela ? elf::kDtRelaEnt : elf::kDtRelEnt);
        if (configured && configured != minimum) { addWarning("ELF32 dynamic relocation entry size is invalid"); return; }
        const auto table = memory_.viewAt(address, size);
        if (table.size() != size) { addWarning("ELF32 dynamic relocation virtual mapping is truncated"); return; }
        readRelocations(table, minimum, rela, kDynamicTable, 0);
    };
    dynamicRelocs(elf::kDtRel, elf::kDtRelSz, false);
    dynamicRelocs(elf::kDtRela, elf::kDtRelaSz, true);
    if (jmpRelAddr_ && pltRelSize_) {
        const auto table = memory_.viewAt(jmpRelAddr_, pltRelSize_);
        if (table.size() == pltRelSize_ && (pltRelType_ == elf::kDtRel || pltRelType_ == elf::kDtRela))
            readRelocations(table, pltRelType_ == elf::kDtRel ? sizeof(Rel32) : sizeof(Rela32), pltRelType_ == elf::kDtRela, kDynamicTable, 0);
        else addWarning("ELF32 PLT relocation mapping/type is invalid");
    }
    const u32 relativeType = arch_ == Arch::kArm32 ? 23 : (arch_ == Arch::kX86_32 ? 8 : 3);
    auto readRelr = [&](ByteView table) {
        if (table.size() % 4) { addWarning("ELF32 RELR table is not word-aligned"); return; }
        Address where = 0; bool haveAddress = false;
        const size_t count = std::min<size_t>(table.size() / 4, kRelocationsLimit);
        for (size_t i = 0; i < count && relocations_.size() < kRelocationsLimit; ++i) {
            u32 value = 0; table.readPod(i * 4, &value);
            if (!(value & 1)) {
                if ((value & 3) || u64{value} + 4 > kAddressEnd32) { addWarning("ELF32 RELR address is invalid"); break; }
                where = value; haveAddress = true;
                append(where, relativeType, 0, ElfRelocation::Source::kRelr, kDynamicTable); where += 4;
            } else {
                if (!haveAddress || where > kAddressEnd32 - 31 * 4) { addWarning("ELF32 RELR bitmap has no valid base"); break; }
                for (unsigned bit = 1; bit < 32; ++bit) if (value & (u32{1} << bit))
                    append(where + (bit - 1) * 4, relativeType, 0, ElfRelocation::Source::kRelr, kDynamicTable);
                where += 31 * 4;
            }
        }
    };
    for (const auto& section : sections_) if (section.type == elf::kShtRelr || section.type == elf::kShtAndroidRelr) readRelr(section.data);
    for (const auto pair : {std::pair<i64, i64>{elf::kDtRelr, elf::kDtRelrSz}, {elf::kDtAndroidRelr, elf::kDtAndroidRelrSz}}) {
        if (tag(pair.first) && tag(pair.second)) {
            const auto table = memory_.viewAt(tag(pair.first), tag(pair.second));
            if (table.size() == tag(pair.second)) readRelr(table); else addWarning("ELF32 RELR virtual mapping is truncated");
        }
    }
    bool packedSections = false;
    for (const auto& section : sections_) if (section.type == elf::kShtAndroidRel || section.type == elf::kShtAndroidRela) {
        packedSections = true; readAndroidPackedRelocations(section.data);
    }
    if (!packedSections) for (const auto pair : {std::pair<i64, i64>{elf::kDtAndroidRel, elf::kDtAndroidRelSz}, {elf::kDtAndroidRela, elf::kDtAndroidRelaSz}}) {
        if (!tag(pair.first) || !tag(pair.second)) continue;
        const auto table = memory_.viewAt(tag(pair.first), tag(pair.second));
        if (table.size() == tag(pair.second)) readAndroidPackedRelocations(table);
        else addWarning("ELF32 packed relocation virtual mapping is truncated");
    }
    indexRelocations();
    resolvePointerArrays();
    reconstructPlt();
    std::stable_sort(armModes_.begin(), armModes_.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    std::vector<std::pair<Address, bool>> modes;
    for (const auto& item : armModes_) {
        if (!modes.empty() && modes.back().first == item.first) modes.back() = item;
        else modes.push_back(item);
    }
    armModes_ = std::move(modes);
    indexSymbols();
    loaded_ = true;
    return Status::success();
}
}  // namespace mint
