#include "mint/ir/registers.h"

#include <cstdio>
#include "mint/plugin/architecture_bridge.h"

namespace mint {
std::vector<Varnode> abiResultRegisters(Arch arch) {
    std::vector<Varnode> result;
    if(arch==Arch::kAArch64) {result={Varnode::reg(arm64::kXn(0),8),Varnode::reg(arm64::kXn(1),8)};for(unsigned n=0;n<4;++n)result.push_back(Varnode::reg(arm64::kVn(n),16));}
    else if(arch==Arch::kX86_64 || arch==Arch::kX86_32) {const u8 word=arch==Arch::kX86_32?4:8;result={Varnode::reg(x86::kRax,word),Varnode::reg(x86::kRdx,word),Varnode::reg(x86::kXmmN(0),16),Varnode::reg(x86::kXmmN(1),16)};}
    else if(arch==Arch::kArm32 || arch==Arch::kThumb)result={Varnode::reg(arm32::kRn(0),4),Varnode::reg(arm32::kRn(1),4)};
    else if(arch==Arch::kRiscV32 || arch==Arch::kRiscV64){const u8 word=arch==Arch::kRiscV32?4:8;result={Varnode::reg(riscv::kXn(10),word),Varnode::reg(riscv::kXn(11),word),Varnode::reg(riscv::kF0+80,8),Varnode::reg(riscv::kF0+88,8)};}
    else {MintArchitectureSemanticsV2 custom{};if(architecturePluginAbi(arch,&custom)&&custom.return_register_offset!=UINT32_MAX)result.push_back(Varnode::reg(custom.return_register_offset,custom.pointer_size));}
    return result;
}
/// The register units a call destroys, as whole storage units.
///
/// Calling conventions are modelled here rather than in the lifter on purpose. A
/// `bl` as an *instruction* writes the link register and nothing else; that a callee
/// also flattens x0..x17 is a property of the platform's convention, not of the
/// encoding. Keeping it out of the lifter means the lifter stays a faithful model of
/// the machine, and means a function with a hand-written or non-standard convention
/// can later be given its own clobber set without the IR having to be re-lifted.
///
/// The list errs towards clobbering. Believing a register survives when the callee
/// destroyed it produces a silently wrong dependency; believing it was destroyed
/// when it survived costs one redundant value and nothing else. Only the direction
/// that cannot produce a wrong answer is acceptable as a default.
std::vector<Varnode> abiCallerSavedRegisters(Arch arch) {
    std::vector<Varnode> units;
    if(static_cast<u8>(arch)>=128) {
        MintArchitectureSemanticsV2 custom{};
        if(architecturePluginAbi(arch,&custom))for(u32 n=0;n<custom.register_count;++n)if(custom.registers[n].byte_offset!=custom.stack_pointer_offset)units.push_back(Varnode::reg(custom.registers[n].byte_offset,custom.registers[n].width));
        return units;
    }
    if (arch == Arch::kAArch64) {
        // x0..x18: arguments, results and scratch, plus the platform register, which
        // Android's runtime is free to use. x19..x28 are callee-saved and survive.
        for (unsigned n = 0; n <= 18; ++n) units.push_back(Varnode::reg(arm64::kXn(n), 8));
        units.push_back(Varnode::reg(arm64::kXn(30), 8));  // the link register itself
        units.push_back(Varnode::reg(arm64::kFlagN, 1));
        units.push_back(Varnode::reg(arm64::kFlagZ, 1));
        units.push_back(Varnode::reg(arm64::kFlagC, 1));
        units.push_back(Varnode::reg(arm64::kFlagV, 1));
        for (unsigned n = 0; n < 32; ++n) units.push_back(Varnode::reg(arm64::kVn(n), 16));
        return units;
    }
    if (arch == Arch::kX86_64) {
        for (u64 offset : {x86::kRax, x86::kRcx, x86::kRdx, x86::kRsi, x86::kRdi,
                           x86::kGpr(8), x86::kGpr(9), x86::kGpr(10), x86::kGpr(11)}) {
            units.push_back(Varnode::reg(offset, 8));
        }
        for (u64 offset : {x86::kFlagCf, x86::kFlagPf, x86::kFlagAf, x86::kFlagZf,
                           x86::kFlagSf, x86::kFlagOf}) {
            units.push_back(Varnode::reg(offset, 1));
        }
        for (unsigned n = 0; n < 16; ++n) units.push_back(Varnode::reg(x86::kXmmN(n), 16));
        return units;
    }
    if(arch==Arch::kX86_32) {
        for(auto offset:{x86::kRax,x86::kRcx,x86::kRdx})units.push_back(Varnode::reg(offset,4));
        for(u64 offset=x86::kFlagCf;offset<=x86::kFlagOf;++offset)units.push_back(Varnode::reg(offset,1));
        for(unsigned n=0;n<8;++n)units.push_back(Varnode::reg(x86::kXmmN(n),16));
    } else if(arch==Arch::kArm32 || arch==Arch::kThumb) {
        for(unsigned n:{0,1,2,3,12,14})units.push_back(Varnode::reg(arm32::kRn(n),4));
        for(u64 flag=arm32::kFlagN;flag<=arm32::kFlagV;++flag)units.push_back(Varnode::reg(flag,1));
        units.push_back(Varnode::reg(arm32::kFpscr,4));
        // Whole Q units, conservatively including ABI-dependent VFP argument state.
        for(unsigned n=0;n<16;++n)units.push_back(Varnode::reg(arm32::kV0+n*16,16));
    } else if(arch==Arch::kRiscV32 || arch==Arch::kRiscV64) {
        const u8 word=arch==Arch::kRiscV32?4:8;
        for(unsigned n:{1,5,6,7,10,11,12,13,14,15,16,17,28,29,30,31})units.push_back(Varnode::reg(riscv::kXn(n),word));
        for(unsigned n=0;n<32;++n)units.push_back(Varnode::reg(riscv::kF0+n*8,8));
        units.push_back(Varnode::reg(riscv::kFflags,8));
        units.push_back(Varnode::reg(riscv::kFrm,8));
    }
    return units;
}

namespace {

std::string synthetic(u64 offset, u8 size) {
    char buffer[48];
    std::snprintf(buffer, sizeof(buffer), "r%llu.%u",
                  static_cast<unsigned long long>(offset), unsigned(size));
    return buffer;
}

std::string numbered(const char* prefix, unsigned index) {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "%s%u", prefix, index);
    return buffer;
}

std::string arm64Name(u64 offset, u8 size) {
    if (offset < arm64::kSp && offset % 8 == 0) {
        const unsigned index = unsigned(offset / 8);
        if (size == 8) return numbered("x", index);
        if (size == 4) return numbered("w", index);
        return synthetic(offset, size);
    }
    if (offset == arm64::kSp) return size == 4 ? "wsp" : "sp";
    if (offset == arm64::kPc) return "pc";
    if (offset == arm64::kFlagN) return "N";
    if (offset == arm64::kFlagZ) return "Z";
    if (offset == arm64::kFlagC) return "C";
    if (offset == arm64::kFlagV) return "V";
    if (offset == arm64::kFpsr) return "fpsr";

    if (offset >= arm64::kV0 && offset < arm64::kFpsr) {
        const u64 relative = offset - arm64::kV0;
        if (relative % 16 == 0) {
            const unsigned index = unsigned(relative / 16);
            switch (size) {
                case 16: return numbered("q", index);
                case 8: return numbered("d", index);
                case 4: return numbered("s", index);
                case 2: return numbered("h", index);
                case 1: return numbered("b", index);
                default: break;
            }
        }
    }
    return synthetic(offset, size);
}

constexpr const char* kGpr64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                                   "rsi", "rdi", "r8",  "r9",  "r10", "r11",
                                   "r12", "r13", "r14", "r15"};
constexpr const char* kGpr32[16] = {"eax",  "ecx",  "edx",  "ebx",  "esp",  "ebp",
                                    "esi",  "edi",  "r8d",  "r9d",  "r10d", "r11d",
                                    "r12d", "r13d", "r14d", "r15d"};
constexpr const char* kGpr16[16] = {"ax",   "cx",   "dx",   "bx",   "sp",   "bp",
                                    "si",   "di",   "r8w",  "r9w",  "r10w", "r11w",
                                    "r12w", "r13w", "r14w", "r15w"};
constexpr const char* kGpr8[16] = {"al",   "cl",   "dl",   "bl",   "spl",  "bpl",
                                   "sil",  "dil",  "r8b",  "r9b",  "r10b", "r11b",
                                   "r12b", "r13b", "r14b", "r15b"};

std::string x86Name(u64 offset, u8 size) {
    if (offset < x86::kRip) {
        const unsigned index = unsigned(offset / 8);
        const u64 within = offset % 8;
        if (within == 0) {
            switch (size) {
                case 8: return kGpr64[index];
                case 4: return kGpr32[index];
                case 2: return kGpr16[index];
                case 1: return kGpr8[index];
                default: break;
            }
        }
        // ah, ch, dh, bh — the legacy high-byte registers, which are the reason
        // this file is addressed by byte offset in the first place.
        if (within == 1 && size == 1 && index < 4) {
            static constexpr const char* kHigh[4] = {"ah", "ch", "dh", "bh"};
            return kHigh[index];
        }
        return synthetic(offset, size);
    }
    if (offset == x86::kRip) return "rip";
    if (offset == x86::kFlagCf) return "CF";
    if (offset == x86::kFlagPf) return "PF";
    if (offset == x86::kFlagAf) return "AF";
    if (offset == x86::kFlagZf) return "ZF";
    if (offset == x86::kFlagSf) return "SF";
    if (offset == x86::kFlagDf) return "DF";
    if (offset == x86::kFlagOf) return "OF";
    if (offset == x86::kFsBase) return "fs_base";
    if (offset == x86::kGsBase) return "gs_base";

    if (offset >= x86::kXmm0 && offset < x86::kFileSize) {
        const u64 relative = offset - x86::kXmm0;
        if (relative % 16 == 0) {
            const unsigned index = unsigned(relative / 16);
            switch (size) {
                case 16: return numbered("xmm", index);
                case 8: return numbered("xmm", index) + ".q0";
                case 4: return numbered("xmm", index) + ".d0";
                default: break;
            }
        }
    }
    return synthetic(offset, size);
}

}  // namespace

u64 registerFileSize(Arch arch) {
    switch (arch) {
        case Arch::kAArch64: return arm64::kFileSize;
        case Arch::kX86_64: return x86::kFileSize;
        case Arch::kX86_32:return x86::kFileSize;
        case Arch::kArm32:case Arch::kThumb:return arm32::kFileSize;
        case Arch::kRiscV32:case Arch::kRiscV64:return riscv::kFileSize;
        case Arch::kDalvik: return 4096;
        default:{MintArchitectureSemanticsV2 custom{};return architecturePluginAbi(arch,&custom)?custom.register_file_bytes:0;}
    }
}

std::string registerName(Arch arch, u64 offset, u8 size) {
    if(static_cast<u8>(arch)>=128) {
        MintArchitectureSemanticsV2 custom{};
        if(architecturePluginAbi(arch,&custom))for(u32 n=0;n<custom.register_count;++n)if(custom.registers[n].byte_offset==offset && custom.registers[n].width==size)return custom.registers[n].name;
        return synthetic(offset,size);
    }
    switch (arch) {
        case Arch::kAArch64: return arm64Name(offset, size);
        case Arch::kX86_64: return x86Name(offset, size);
        case Arch::kX86_32:return offset==x86::kRip?"eip":x86Name(offset,size);
        case Arch::kArm32:case Arch::kThumb:
            if(offset<64 && offset%4==0 && size==4) {
                if(offset==arm32::kSp)return "sp";if(offset==arm32::kLr)return "lr";if(offset==arm32::kPc)return "pc";
                return numbered("r",static_cast<unsigned>(offset/4));
            }
            if(offset==arm32::kFlagN)return "N";if(offset==arm32::kFlagZ)return "Z";
            if(offset==arm32::kFlagC)return "C";if(offset==arm32::kFlagV)return "V";
            if(offset==arm32::kFpscr&&size==4)return "fpscr";
            if(offset>=arm32::kV0 && offset<arm32::kFileSize) {
                const auto rel=offset-arm32::kV0;
                if(size==4 && rel%4==0)return numbered("s",rel/4);
                if(size==8 && rel%8==0)return numbered("d",rel/8);
                if(size==16 && rel%16==0)return numbered("q",rel/16);
            }
            return synthetic(offset,size);
        case Arch::kRiscV32:case Arch::kRiscV64:
            if(offset<riscv::kPc && offset%8==0) {
                static const char* names[]={"zero","ra","sp","gp","tp","t0","t1","t2","s0","s1","a0","a1","a2","a3","a4","a5","a6","a7","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11","t3","t4","t5","t6"};
                return names[offset/8];
            }
            if(offset==riscv::kPc)return "pc";
            if(offset==riscv::kFflags)return "fflags";
            if(offset==riscv::kFrm)return "frm";
            if(offset>=riscv::kF0 && offset<riscv::kFflags && (offset-riscv::kF0)%8==0)return numbered("f",(offset-riscv::kF0)/8);
            return synthetic(offset,size);
        default: return synthetic(offset, size);
    }
}

}  // namespace mint
