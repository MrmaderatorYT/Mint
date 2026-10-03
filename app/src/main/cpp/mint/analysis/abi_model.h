#pragma once

#include <functional>
#include "mint/analysis/user_prototype.h"
#include "mint/ir/varnode.h"
#include "mint/types/data_type_manager.h"

namespace mint {
enum class AbiStorageKind : u8 { kRegister, kStack, kIndirect };
struct AbiStoragePiece {
    AbiStorageKind kind=AbiStorageKind::kRegister;
    Varnode storage;
    // Callee entry SP offset (includes return address / Windows shadow space).
    i64 stackOffset=0;
    u64 valueOffset=0;
    u8 width=0;
    bool floating=false;
};
struct AbiValue {
    std::string type;
    std::vector<AbiStoragePiece> pieces;
    u64 size=0;
    bool indirect=false;
};
struct AbiModel {
    std::string convention;
    u8 pointerWidth=0;
    std::vector<AbiValue> parameters;
    AbiValue result;
    // Hidden result pointer, not a fabricated source-level argument.
    std::vector<AbiStoragePiece> hiddenResult;
    u64 stackBytes=0;
    u32 shadowBytes=0;
    bool variadic=false;
    std::vector<std::string> diagnostics;
    std::string toText() const;
};
using AbiTypeResolver=std::function<Status(const std::string&,DataTypeLayout*)>;
Status buildAbiModel(Arch architecture,const UserPrototype& prototype,AbiModel* output,
                     const AbiTypeResolver& types={});
bool prototypeUsesSimpleIntegerRegisters(const UserPrototype& prototype,Arch architecture);
} // namespace mint
