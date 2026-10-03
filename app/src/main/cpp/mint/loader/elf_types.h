#pragma once

#include "mint/base/types.h"

/// ELF64 on-disk layout.
///
/// Declared here rather than taken from the NDK's <elf.h> for two reasons: the
/// engine must build on a host toolchain for unit tests, where <elf.h> may be
/// absent or differently spelled, and pinning the field widths ourselves means
/// a platform header change can never silently alter how we parse a file.
///
/// These are the ELF64 little-endian forms. ELF32 disk records are decoded in
/// elf32_image.cpp into the same architecture-independent image model. The APK
/// host ABI does not restrict the architecture of the binary being analyzed.
namespace mint::elf {

// ---------------------------------------------------------------- identification

constexpr u8 kMagic[4] = {0x7f, 'E', 'L', 'F'};

constexpr size_t kEiNIdent = 16;
constexpr size_t kEiClass = 4;
constexpr size_t kEiData = 5;
constexpr size_t kEiVersion = 6;
constexpr size_t kEiOsAbi = 7;

constexpr u8 kElfClass64 = 2;
constexpr u8 kElfData2Lsb = 1;

// e_type
constexpr u16 kEtRel = 1;
constexpr u16 kEtExec = 2;
constexpr u16 kEtDyn = 3;   ///< Every Android .so, and every PIE executable.
constexpr u16 kEtCore = 4;

// e_machine
constexpr u16 kEmX86_64 = 62;
constexpr u16 kEmAArch64 = 183;

// ---------------------------------------------------------------------- segments

constexpr u32 kPtNull = 0;
constexpr u32 kPtLoad = 1;
constexpr u32 kPtDynamic = 2;
constexpr u32 kPtInterp = 3;
constexpr u32 kPtNote = 4;
constexpr u32 kPtPhdr = 6;
constexpr u32 kPtTls = 7;
constexpr u32 kPtGnuEhFrame = 0x6474e550;
constexpr u32 kPtGnuStack = 0x6474e551;
constexpr u32 kPtGnuRelro = 0x6474e552;

constexpr u32 kPfX = 1;
constexpr u32 kPfW = 2;
constexpr u32 kPfR = 4;

// ---------------------------------------------------------------------- sections

constexpr u32 kShtNull = 0;
constexpr u32 kShtProgBits = 1;
constexpr u32 kShtSymTab = 2;
constexpr u32 kShtStrTab = 3;
constexpr u32 kShtRela = 4;
constexpr u32 kShtHash = 5;
constexpr u32 kShtDynamic = 6;
constexpr u32 kShtNote = 7;
constexpr u32 kShtNoBits = 8;   ///< .bss: address space with no file bytes.
constexpr u32 kShtRel = 9;
constexpr u32 kShtDynSym = 11;
constexpr u32 kShtInitArray = 14;
constexpr u32 kShtFiniArray = 15;
constexpr u32 kShtPreInitArray = 16;
constexpr u32 kShtRelr = 19;
constexpr u32 kShtGnuHash = 0x6ffffff6;

// Android's packed-relocation sections, emitted by the NDK linker to shrink
// shared libraries. A loader that ignores these sees a library with almost no
// relocations and therefore resolves none of its imports.
constexpr u32 kShtAndroidRel = 0x60000001;
constexpr u32 kShtAndroidRela = 0x60000002;
constexpr u32 kShtAndroidRelr = 0x6fffff00;

constexpr u64 kShfWrite = 0x1;
constexpr u64 kShfAlloc = 0x2;
constexpr u64 kShfExecInstr = 0x4;

constexpr u16 kShnUndef = 0;
constexpr u16 kShnAbs = 0xfff1;
constexpr u16 kShnCommon = 0xfff2;

// ----------------------------------------------------------------------- symbols

constexpr u8 kSttNoType = 0;
constexpr u8 kSttObject = 1;
constexpr u8 kSttFunc = 2;
constexpr u8 kSttSection = 3;
constexpr u8 kSttFile = 4;
constexpr u8 kSttCommon = 5;
constexpr u8 kSttTls = 6;
constexpr u8 kSttGnuIFunc = 10;

constexpr u8 kStbLocal = 0;
constexpr u8 kStbGlobal = 1;
constexpr u8 kStbWeak = 2;

constexpr u8 kStvDefault = 0;
constexpr u8 kStvHidden = 2;

constexpr u8 symbolType(u8 info) { return info & 0x0f; }
constexpr u8 symbolBinding(u8 info) { return static_cast<u8>(info >> 4); }
constexpr u8 symbolVisibility(u8 other) { return other & 0x03; }

// ------------------------------------------------------------- dynamic table tags

constexpr i64 kDtNull = 0;
constexpr i64 kDtNeeded = 1;
constexpr i64 kDtPltRelSz = 2;
constexpr i64 kDtPltGot = 3;
constexpr i64 kDtHash = 4;
constexpr i64 kDtStrTab = 5;
constexpr i64 kDtSymTab = 6;
constexpr i64 kDtRela = 7;
constexpr i64 kDtRelaSz = 8;
constexpr i64 kDtRelaEnt = 9;
constexpr i64 kDtStrSz = 10;
constexpr i64 kDtSymEnt = 11;
constexpr i64 kDtInit = 12;
constexpr i64 kDtFini = 13;
constexpr i64 kDtSoName = 14;
constexpr i64 kDtRPath = 15;
constexpr i64 kDtSymbolic = 16;
constexpr i64 kDtRel = 17;
constexpr i64 kDtRelSz = 18;
constexpr i64 kDtRelEnt = 19;
constexpr i64 kDtPltRel = 20;
constexpr i64 kDtTextRel = 22;
constexpr i64 kDtJmpRel = 23;
constexpr i64 kDtBindNow = 24;
constexpr i64 kDtInitArray = 25;
constexpr i64 kDtFiniArray = 26;
constexpr i64 kDtInitArraySz = 27;
constexpr i64 kDtFiniArraySz = 28;
constexpr i64 kDtRunPath = 29;
constexpr i64 kDtFlags = 30;
constexpr i64 kDtPreInitArray = 32;
constexpr i64 kDtPreInitArraySz = 33;
constexpr i64 kDtRelrSz = 0x23;
constexpr i64 kDtRelr = 0x24;
constexpr i64 kDtRelrEnt = 0x25;
constexpr i64 kDtGnuHash = 0x6ffffef5;
constexpr i64 kDtRelaCount = 0x6ffffff9;
constexpr i64 kDtRelCount = 0x6ffffffa;
constexpr i64 kDtFlags1 = 0x6ffffffb;
constexpr i64 kDtAndroidRel = 0x6000000f;
constexpr i64 kDtAndroidRelSz = 0x60000010;
constexpr i64 kDtAndroidRela = 0x60000011;
constexpr i64 kDtAndroidRelaSz = 0x60000012;
constexpr i64 kDtAndroidRelr = 0x6fffe000;
constexpr i64 kDtAndroidRelrSz = 0x6fffe001;
constexpr i64 kDtAndroidRelrEnt = 0x6fffe003;

// ------------------------------------------------------------- relocation types

// AArch64. JUMP_SLOT is what binds a PLT stub to an imported function, which is
// how a call to an external symbol gets a name instead of a bare address.
constexpr u32 kRAArch64Abs64 = 257;
constexpr u32 kRAArch64GlobDat = 1025;
constexpr u32 kRAArch64JumpSlot = 1026;
constexpr u32 kRAArch64Relative = 1027;
constexpr u32 kRAArch64IRelative = 1032;

constexpr u32 kRX86_64_64 = 1;
constexpr u32 kRX86_64GlobDat = 6;
constexpr u32 kRX86_64JumpSlot = 7;
constexpr u32 kRX86_64Relative = 8;
constexpr u32 kRX86_64IRelative = 37;

constexpr u32 relocSymbol(u64 info) { return static_cast<u32>(info >> 32); }
constexpr u32 relocType(u64 info) { return static_cast<u32>(info & 0xffffffffu); }

// ------------------------------------------------------------------- on-disk PODs

struct Ehdr {
    u8 ident[kEiNIdent];
    u16 type;
    u16 machine;
    u32 version;
    u64 entry;
    u64 phoff;
    u64 shoff;
    u32 flags;
    u16 ehsize;
    u16 phentsize;
    u16 phnum;
    u16 shentsize;
    u16 shnum;
    u16 shstrndx;
};
static_assert(sizeof(Ehdr) == 64, "ELF64 header is 64 bytes");

struct Phdr {
    u32 type;
    u32 flags;
    u64 offset;
    u64 vaddr;
    u64 paddr;
    u64 filesz;
    u64 memsz;
    u64 align;
};
static_assert(sizeof(Phdr) == 56, "ELF64 program header is 56 bytes");

struct Shdr {
    u32 name;
    u32 type;
    u64 flags;
    u64 addr;
    u64 offset;
    u64 size;
    u32 link;
    u32 info;
    u64 addralign;
    u64 entsize;
};
static_assert(sizeof(Shdr) == 64, "ELF64 section header is 64 bytes");

struct Sym {
    u32 name;
    u8 info;
    u8 other;
    u16 shndx;
    u64 value;
    u64 size;
};
static_assert(sizeof(Sym) == 24, "ELF64 symbol is 24 bytes");

struct Rela {
    u64 offset;
    u64 info;
    i64 addend;
};
static_assert(sizeof(Rela) == 24, "ELF64 Rela is 24 bytes");

struct Rel {
    u64 offset;
    u64 info;
};
static_assert(sizeof(Rel) == 16, "ELF64 Rel is 16 bytes");

struct Dyn {
    i64 tag;
    u64 value;
};
static_assert(sizeof(Dyn) == 16, "ELF64 Dyn is 16 bytes");

}  // namespace mint::elf
