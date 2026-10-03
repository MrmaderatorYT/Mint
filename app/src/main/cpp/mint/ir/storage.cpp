#include "mint/ir/storage.h"

#include "mint/ir/registers.h"
#include "mint/plugin/architecture_bridge.h"

namespace mint {
namespace {

/// Rounds `offset` down to a multiple of `stride` relative to `base`.
StorageUnit alignedUnit(u64 base, u64 offset, u64 stride) {
    const u64 index = (offset - base) / stride;
    return StorageUnit{base + index * stride, static_cast<u8>(stride)};
}

StorageUnit arm64Unit(u64 offset) {
    // x0..x30, sp and pc are eight-byte units; the flags are a byte each; the SIMD
    // registers are sixteen. The boundaries come straight from the layout in
    // registers.h, and the ordering of these tests follows it.
    if (offset < arm64::kFlagN) return alignedUnit(0, offset, 8);
    if (offset <= arm64::kFlagV) return StorageUnit{offset, 1};
    if (offset < arm64::kFpsr) return alignedUnit(arm64::kV0, offset, 16);
    return StorageUnit{arm64::kFpsr, 8};
}

StorageUnit x86Unit(u64 offset) {
    if (offset < x86::kFlagCf) return alignedUnit(0, offset, 8);
    if (offset <= x86::kFlagOf) return StorageUnit{offset, 1};
    if (offset < x86::kXmm0) return alignedUnit(x86::kFsBase, offset, 8);
    return alignedUnit(x86::kXmm0, offset, 16);
}

}  // namespace

StorageUnit canonicalUnit(Arch arch, u64 offset, u8 size) {
    switch (arch) {
        case Arch::kAArch64: return arm64Unit(offset);
        case Arch::kX86_64: return x86Unit(offset);
        case Arch::kX86_32:
            if(offset<x86::kFlagCf)return {offset-offset%8,4};
            if(offset<=x86::kFlagOf)return {offset,1};
            if(offset<x86::kXmm0)return {x86::kFsBase+((offset-x86::kFsBase)/8)*8,4};
            return alignedUnit(x86::kXmm0,offset,16);
        case Arch::kArm32:case Arch::kThumb:
            if(offset<64)return alignedUnit(0,offset,4);
            if(offset<=arm32::kFlagV)return {offset,1};
            return alignedUnit(arm32::kV0,offset,16);
        case Arch::kRiscV32:case Arch::kRiscV64:
            if(offset<=riscv::kPc)return {offset-offset%8,static_cast<u8>(arch==Arch::kRiscV32?4:8)};
            return alignedUnit(riscv::kF0,offset,8);
        default:
            if(static_cast<u8>(arch)>=128) {
                MintArchitectureSemanticsV2 custom{};StorageUnit best{offset,size};
                if(architecturePluginAbi(arch,&custom))for(u32 n=0;n<custom.register_count;++n) {
                    const auto& reg=custom.registers[n];
                    if(reg.byte_offset<=offset && offset+size<=u64(reg.byte_offset)+reg.width && reg.width>=best.size)best={reg.byte_offset,reg.width};
                }
                return best;
            }
            // With no layout to consult, treating the access as its own unit keeps
            // every caller working: SSA then renames exactly what the lifter wrote,
            // which is the best available answer for an architecture we do not model.
            return StorageUnit{offset, size};
    }
}

bool accessSpansUnits(Arch arch, u64 offset, u8 size) {
    const StorageUnit unit = canonicalUnit(arch, offset, size);
    return offset + size > unit.end();
}

bool accessIsWholeUnit(Arch arch, u64 offset, u8 size) {
    const StorageUnit unit = canonicalUnit(arch, offset, size);
    return unit.offset == offset && unit.size == size;
}

}  // namespace mint
