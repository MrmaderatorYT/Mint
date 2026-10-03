#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include <array>

#include "mint/base/byte_view.h"
#include "mint/base/status.h"
#include "mint/base/types.h"
#include "mint/loader/elf_types.h"
#include "mint/loader/memory_map.h"

namespace mint {

struct ElfSection {
    std::string name;
    u32 type = 0;
    u64 flags = 0;
    Address addr = 0;
    u64 fileOffset = 0;
    u64 size = 0;
    u64 entrySize = 0;
    u32 link = 0;
    u32 info = 0;
    ByteView data;  ///< Empty for SHT_NOBITS (.bss) and for truncated sections.

    bool executable() const { return (flags & elf::kShfExecInstr) != 0; }
    bool allocated() const { return (flags & elf::kShfAlloc) != 0; }
};

struct ElfSymbol {
    std::string name;
    Address value = 0;
    u64 size = 0;
    u8 type = 0;
    u8 binding = 0;
    u8 visibility = 0;
    u16 sectionIndex = 0;

    /// True when the symbol is referenced but not defined here — an import that
    /// the dynamic linker fills in. These carry no address, so treating them as
    /// functions to disassemble would send the recursive descent to address 0.
    bool undefined = false;

    /// Whether this came from .symtab (full, usually absent in shipped
    /// libraries) or .dynsym (exported interface only). Worth surfacing: a
    /// library with only .dynsym is stripped, which changes what the user should
    /// expect from the function list.
    bool fromDynsym = false;

    bool isFunction() const {
        return type == elf::kSttFunc || type == elf::kSttGnuIFunc;
    }

    /// ARM mapping symbols — `$x`, `$d`, `$a`, `$t`, optionally suffixed — mark
    /// where code changes to data and back. They sit at the same addresses as
    /// real functions and carry no meaning for a reader, so they must never win
    /// as an address's name: `bl $x.1` instead of `bl _Unwind_RaiseException`
    /// makes a listing actively misleading.
    ///
    /// They are still worth keeping in the symbol list, because a `$d` inside an
    /// executable section is exactly where a compiler put a constant pool, which
    /// tells the disassembler to stop treating those bytes as instructions.
    bool isMappingSymbol() const {
        if (name.size() < 2 || name[0] != '$') return false;
        const char kind = name[1];
        if (kind != 'a' && kind != 'd' && kind != 't' && kind != 'x') return false;
        return name.size() == 2 || name[2] == '.';
    }
};

struct ElfRelocation {
    Address offset = 0;   ///< Virtual address being patched.
    u32 type = 0;
    u32 symbolIndex = 0;
    i64 addend = 0;
    std::string symbolName;  ///< Empty for relative relocations.

    /// Where the relocation was found. Packed and RELR relocations are the norm
    /// in modern Android libraries, and knowing which encoding a library uses
    /// is itself a fingerprint worth keeping.
    enum class Source : u8 { kRela, kRel, kAndroidPacked, kRelr, kContainerRebase, kContainerBind } source = Source::kRela;
};

/// Container-proven function ranges, with opaque ABI-specific unwind encoding.
/// Recording a range does not imply that the runtime unwind program is evaluated.
struct RuntimeFunction {
    Address start = 0, end = 0, unwindInfo = kNoAddress;
    Address lsda = kNoAddress, personality = kNoAddress;
    u32 encoding = 0;
    std::string source;
    Address handler = kNoAddress, handlerData = kNoAddress, chainedStart = kNoAddress;
    bool unwindValidated = false;
};
struct PeCodeViewRecord {
    std::array<u8, 16> guid{};
    u32 age = 0;
    std::string path; // Display only; never followed automatically.
};

struct AddressInterval {
    Address start = 0;
    Address end = 0;
    size_t symbolIndex = 0;
};

/// A parsed ELF64 image: an Android shared library, or a native executable
/// pulled out of an APK.
///
/// Parsing never trusts the file. Section and segment tables are validated
/// against the mapped size before use, entry counts are bounded, and a
/// structure that does not fit is dropped with a recorded warning rather than
/// aborting the load — a protected library with a deliberately broken section
/// table is still worth disassembling through its program headers.
enum class ImageFormat : u8 { kElf64, kPe64, kMachO64, kRaw, kElf32 };

class ElfImage {
public:
    /// Sniffs native containers only. Unrecognised bytes require explicit raw
    /// import parameters and are never interpreted as executable code silently.
    Status load(ByteView file);
    /// A explicitly selected debug-only ELF may be relocatable and have no
    /// loadable segments (.dwo/objcopy --only-keep-debug). This does not create
    /// a Program/code image; only validated section views may be consumed.
    Status loadDebugObject(ByteView file);
    /// Explicit slice selection for a universal Mach-O. Normal load chooses the
    /// first supported slice in table order, recorded in warnings.
    Status loadMachOSlice(ByteView file, Arch architecture);
    Status loadRaw(ByteView file, Arch architecture, Address base, Address entry);

    ImageFormat format() const { return format_; }
    const char* formatName() const;
    Address imageBase() const { return imageBase_; }
    u8 pointerSize() const;
    /// ARM/Thumb share a byte-addressed memory map. Thumb's pointer tag is not
    /// part of the memory address or instruction-index key.
    Address canonicalAddress(Address address) const;
    Arch architectureAt(Address address) const;
    Arch architectureAt(Address address, Address functionEntry, Arch fallback) const;
    /// In-memory overlays only: never writes the input file. A patch must fit
    /// entirely in one unambiguous file-backed segment and is capped at 4 KiB.
    Status applyPatch(Address address, ByteView bytes);
    void resetPatches();
    bool fileOffsetAt(Address address, size_t length, u64* offset) const;

    bool loaded() const { return loaded_; }

    Arch arch() const { return arch_; }
    u16 objectType() const { return type_; }
    Address entryPoint() const { return entry_; }
    const std::string& soname() const { return soname_; }

    /// Position-independent, i.e. every Android .so and modern executable. When
    /// true, the addresses here are link-time addresses that the runtime will
    /// rebase; analysis works entirely in link-time space.
    bool isPositionIndependent() const {
        return (format_ == ImageFormat::kElf64 || format_ == ImageFormat::kElf32)
            ? type_ == elf::kEtDyn : positionIndependent_;
    }

    /// No .symtab, so only exported names are known.
    bool isStripped() const { return stripped_; }

    const MemoryMap& memory() const { return memory_; }
    const std::vector<ElfSection>& sections() const { return sections_; }
    const std::vector<ElfSymbol>& symbols() const { return symbols_; }
    const std::vector<ElfRelocation>& relocations() const { return relocations_; }
    const std::vector<RuntimeFunction>& runtimeFunctions() const { return runtimeFunctions_; }
    const std::vector<PeCodeViewRecord>& peCodeViewRecords() const { return peCodeViewRecords_; }

    /// DT_NEEDED entries, in link order.
    const std::vector<std::string>& neededLibraries() const { return needed_; }

    /// Code that runs before anything else in the library: DT_INIT, then
    /// DT_INIT_ARRAY in order. Packers and anti-analysis code overwhelmingly
    /// live here, so these are seeded as analysis roots and reported to the user
    /// even when nothing else about the library looks unusual.
    const std::vector<Address>& initializers() const { return initializers_; }
    const std::vector<Address>& finalizers() const { return finalizers_; }

    /// Maps a PLT stub's address to the imported symbol it calls. Without this,
    /// every external call in the listing is an unnamed jump into .plt; with it
    /// the disassembly reads `bl <dlopen>`.
    const std::unordered_map<Address, std::string>& pltStubs() const { return pltStubs_; }

    /// Structural problems found while parsing. Non-fatal by design, but shown
    /// to the user: a library whose section table disagrees with its program
    /// headers has usually been processed by a protector.
    const std::vector<std::string>& warnings() const { return warnings_; }
    ByteView originalFile() const { return originalFile_; }

    const ElfSection* findSection(const std::string& name) const;
    const ElfSymbol* findSymbol(const std::string& name) const;

    /// Reads a pointer-sized value at `at`, taking relocations into account.
    ///
    /// In a position-independent image most pointer slots are zero on disk and
    /// filled in by the dynamic linker, so reading the raw bytes yields nothing.
    /// The real target sits in the addend of the R_*_RELATIVE relocation that
    /// covers the slot. Anything that follows a pointer stored in the image —
    /// initialiser arrays, vtables, jump tables, the function-pointer tables
    /// that packers build — has to go through here rather than through
    /// MemoryMap::readInt, or it will read a file full of zeroes and conclude
    /// there is nothing there.
    bool resolvePointer(Address at, Address* out) const;

    /// The PLT stub stride recovered for this image, or 0 if there is no PLT.
    /// Not a constant: a BTI-enabled AArch64 library uses 24-byte stubs where a
    /// plain one uses 16.
    u64 pltStubStride() const { return pltStride_; }

    /// Best available name for `addr`: an exact symbol match, else a
    /// `symbol+offset` form when the address is inside a sized symbol, else
    /// empty.
    std::string describeAddress(Address addr) const;

private:
    Status loadElf32(ByteView file);
    Status loadPe64(ByteView file);
    Status loadMachO64(ByteView file);
    Status loadMachOFat(ByteView file, Arch preferred = Arch::kUnknown);
    Status parseHeader(ByteView file);
    void parseProgramHeaders(ByteView file);
    void parseSectionHeaders(ByteView file);
    void parseSymbolTables(ByteView file);
    void readDynamicTable(ByteView file);
    void parseRelocations(ByteView file);
    void indexRelocations();

    /// DT_INIT_ARRAY and friends. Runs after relocations because in a PIE the
    /// array contents only exist as relocation addends.
    void resolvePointerArrays();

    void reconstructPlt();
    void indexSymbols();
    void buildAddressIndex();

    /// Locates the PT_DYNAMIC contents, preferring the segment over the
    /// .dynamic section.
    ByteView findDynamicView(ByteView file) const;

    /// Reads a symbol table of `count` entries and appends to symbols_.
    void readSymbolTable(ByteView table, ByteView strings, bool fromDynsym);

    /// Standard SHT_RELA / SHT_REL arrays.
    void readRelaArray(ByteView data, ElfRelocation::Source source);
    void readRelArray(ByteView data, ElfRelocation::Source source);

    /// Android's APS2 packed relocation stream, emitted by the NDK linker.
    void readAndroidPackedRelocations(ByteView data);

    /// SHT_RELR / DT_RELR bitmap-encoded relative relocations.
    void readRelrRelocations(ByteView data);

    void addWarning(std::string message);

    /// The dynamic-symbol name for index `index`, resolved through whichever
    /// string table we managed to locate.
    std::string dynamicSymbolName(u32 index) const;

    bool loaded_ = false;
    ImageFormat format_ = ImageFormat::kElf64;
    Address imageBase_ = 0;
    bool positionIndependent_ = false;
    bool containerPointersEncoded_ = false;
    ByteView originalFile_;
    MemoryMap originalMemory_;
    std::vector<ElfSection> originalSections_;
    std::unordered_map<Address, std::shared_ptr<std::vector<u8>>> patchStorage_;
    Arch arch_ = Arch::kUnknown;
    /// Sorted ARM mapping/function mode changes: true is Thumb, false is ARM.
    std::vector<std::pair<Address, bool>> armModes_;
    u16 type_ = 0;
    Address entry_ = 0;
    bool stripped_ = true;
    std::string soname_;

    MemoryMap memory_;
    std::vector<ElfSection> sections_;
    std::vector<ElfSymbol> symbols_;
    std::vector<ElfRelocation> relocations_;
    std::vector<RuntimeFunction> runtimeFunctions_;
    std::vector<PeCodeViewRecord> peCodeViewRecords_;
    std::vector<std::string> needed_;
    std::vector<Address> initializers_;
    std::vector<Address> finalizers_;
    std::unordered_map<Address, std::string> pltStubs_;
    std::vector<std::string> warnings_;

    /// Index into symbols_ of the .dynsym range, so relocations can name their
    /// symbol without a second parse.
    size_t dynsymBegin_ = 0;
    size_t dynsymCount_ = 0;

    std::unordered_map<std::string, size_t> symbolByName_;
    std::unordered_map<Address, size_t> exactSymbolByAddress_;
    std::vector<AddressInterval> addressIntervals_;
    std::vector<Address> intervalPrefixMaxEnd_;

    /// The dynamic table, kept because it is read in two passes: tags first, then
    /// the pointer arrays once relocations are known.
    std::vector<elf::Dyn> dynamicEntries_;

    /// Patch address to relocation, for resolvePointer().
    std::unordered_map<Address, size_t> relocationByOffset_;

    u64 pltStride_ = 0;

    /// Addresses recovered from the dynamic segment, used when the section table
    /// is missing or untrustworthy.
    Address dynStrTabAddr_ = 0;
    u64 dynStrTabSize_ = 0;
    Address dynSymTabAddr_ = 0;
    Address pltGotAddr_ = 0;
    Address jmpRelAddr_ = 0;
    u64 pltRelSize_ = 0;
    i64 pltRelType_ = 0;
};

}  // namespace mint
