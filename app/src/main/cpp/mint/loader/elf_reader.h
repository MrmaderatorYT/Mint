#pragma once
#include <cstddef>
#include <type_traits>
#include "mint/base/byte_view.h"
#include "mint/loader/elf_types.h"

namespace mint {
// Decode named ELF64 fields instead of byte-swapping a struct's padding or
// treating its mixed-width fields as uniform machine words.
template<class T> bool readElfRecord(ByteView bytes,u64 offset,T* out) {
    if constexpr(std::is_integral<T>::value)return bytes.read(offset,out);
    else {
        if(!bytes.covers(offset,sizeof(T)))return false;
        const auto record=bytes.subview(offset,sizeof(T));T value{};
#define MINT_ELF_FIELD(field) if(!record.read(offsetof(T,field),&value.field))return false
        if constexpr(std::is_same<T,elf::Ehdr>::value) {
            std::memcpy(value.ident,record.data(),sizeof(value.ident));
            MINT_ELF_FIELD(type);MINT_ELF_FIELD(machine);MINT_ELF_FIELD(version);
            MINT_ELF_FIELD(entry);MINT_ELF_FIELD(phoff);MINT_ELF_FIELD(shoff);MINT_ELF_FIELD(flags);
            MINT_ELF_FIELD(ehsize);MINT_ELF_FIELD(phentsize);MINT_ELF_FIELD(phnum);
            MINT_ELF_FIELD(shentsize);MINT_ELF_FIELD(shnum);MINT_ELF_FIELD(shstrndx);
        } else if constexpr(std::is_same<T,elf::Phdr>::value) {
            MINT_ELF_FIELD(type);MINT_ELF_FIELD(flags);MINT_ELF_FIELD(offset);MINT_ELF_FIELD(vaddr);
            MINT_ELF_FIELD(paddr);MINT_ELF_FIELD(filesz);MINT_ELF_FIELD(memsz);MINT_ELF_FIELD(align);
        } else if constexpr(std::is_same<T,elf::Shdr>::value) {
            MINT_ELF_FIELD(name);MINT_ELF_FIELD(type);MINT_ELF_FIELD(flags);MINT_ELF_FIELD(addr);
            MINT_ELF_FIELD(offset);MINT_ELF_FIELD(size);MINT_ELF_FIELD(link);MINT_ELF_FIELD(info);
            MINT_ELF_FIELD(addralign);MINT_ELF_FIELD(entsize);
        } else if constexpr(std::is_same<T,elf::Sym>::value) {
            MINT_ELF_FIELD(name);MINT_ELF_FIELD(info);MINT_ELF_FIELD(other);MINT_ELF_FIELD(shndx);
            MINT_ELF_FIELD(value);MINT_ELF_FIELD(size);
        } else if constexpr(std::is_same<T,elf::Dyn>::value) {
            MINT_ELF_FIELD(tag);MINT_ELF_FIELD(value);
        } else if constexpr(std::is_same<T,elf::Rel>::value||std::is_same<T,elf::Rela>::value) {
            MINT_ELF_FIELD(offset);MINT_ELF_FIELD(info);
            if constexpr(std::is_same<T,elf::Rela>::value){MINT_ELF_FIELD(addend);}
        } else { static_assert(std::is_same<T,void>::value,"missing ELF disk record decoder"); }
#undef MINT_ELF_FIELD
        *out=value;return true;
    }
}
}
