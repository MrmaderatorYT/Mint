#include "mint/disasm/disassembler.h"

#include <capstone/capstone.h>

#include <cstring>
#include <algorithm>
#include <mutex>

#include "mint/base/log.h"

namespace mint {
namespace {

/// AArch64 is fixed-width; x86-64 is not, and 15 is the architectural maximum.
constexpr u8 kX86MinInsnSize = 1;
constexpr u8 kX86MaxInsnSize = 15;

std::mutex& registryMutex() { static std::mutex value; return value; }
std::vector<ArchitectureDescription>& registry() {
    static std::vector<ArchitectureDescription> value{
        {Arch::kAArch64, "aarch64", "AArch64", 8, 4, 4, 4, 183, 2, false, nullptr},
        {Arch::kX86_64, "x86-64", "x86-64", 8, 1, 15, 1, 62, 2, false, nullptr},
        {Arch::kArm32, "arm", "ARM (A32)", 4, 4, 4, 4, 40, 1, true, nullptr},
        {Arch::kThumb, "thumb", "ARM Thumb/Thumb-2", 4, 2, 4, 2, 40, 1, true, nullptr},
        {Arch::kX86_32, "x86-32", "x86 (IA-32)", 4, 1, 15, 1, 3, 1, false, nullptr},
        {Arch::kRiscV32, "riscv32", "RISC-V RV32GC", 4, 2, 4, 2, 243, 1, false, nullptr},
        {Arch::kRiscV64, "riscv64", "RISC-V RV64GC", 8, 2, 4, 2, 243, 2, false, nullptr}
    };
    return value;
}

bool hasGroup(const cs_insn* insn, u8 group) {
    if (insn->detail == nullptr) return false;
    for (u8 i = 0; i < insn->detail->groups_count; ++i) {
        if (insn->detail->groups[i] == group) return true;
    }
    return false;
}

}  // namespace

std::vector<ArchitectureDescription> architectureDescriptions() {
    std::lock_guard<std::mutex> guard(registryMutex());
    return registry();
}

bool architectureDescription(Arch architecture, ArchitectureDescription* output) {
    if (!output) return false;
    std::lock_guard<std::mutex> guard(registryMutex());
    for (const auto& item : registry()) if (item.architecture == architecture) { *output = item; return true; }
    return false;
}

std::string architectureName(Arch architecture) {
    if (static_cast<u8>(architecture) < 128) return archName(architecture);
    ArchitectureDescription description;
    return architectureDescription(architecture, &description) ? description.id : archName(architecture);
}

namespace {
bool validArchitectureDescription(const ArchitectureDescription& description) {
    const auto id = static_cast<u8>(description.architecture);
    if (id < 128 || id == 255 || !description.decode || description.id.empty() || description.id.size() > 64 ||
        description.name.empty() || description.name.size() > 128 ||
        (description.pointerSize != 4 && description.pointerSize != 8) ||
        description.minInstructionSize == 0 || description.minInstructionSize > description.maxInstructionSize ||
        description.maxInstructionSize > 16 || description.instructionAlignment == 0 ||
        (description.instructionAlignment & (description.instructionAlignment - 1)) != 0 ||
        description.instructionAlignment > description.minInstructionSize || description.thumbAddressTag ||
        description.id.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-_") != std::string::npos ||
        description.name.find('\0') != std::string::npos) {
        return false;
    }
    return true;
}
}  // namespace

Status registerArchitectureDescriptions(const std::vector<ArchitectureDescription>& descriptions) {
    if (descriptions.empty() || descriptions.size() > 127)
        return Status::error(ErrorCode::kBadFormat, "invalid architecture batch count");
    for (const auto& description : descriptions) if (!validArchitectureDescription(description))
        return Status::error(ErrorCode::kBadFormat, "invalid external architecture descriptor");
    std::lock_guard<std::mutex> guard(registryMutex());
    if (descriptions.size() > kMaxArchitectureDescriptions - registry().size()) return Status::error(ErrorCode::kTooLarge, "architecture registry is full");
    try {
        auto candidate = registry();
        for (const auto& description : descriptions) {
            for (const auto& item : candidate) if (item.architecture == description.architecture || item.id == description.id)
                return Status::error(ErrorCode::kBadFormat, "architecture ID already registered");
            candidate.push_back(description);
        }
        registry().swap(candidate);
    } catch (...) {
        return Status::error(ErrorCode::kInternalError, "cannot allocate architecture registry batch");
    }
    return Status::success();
}

Status registerArchitectureDescription(const ArchitectureDescription& description) {
    return registerArchitectureDescriptions({description});
}

const char* flowKindName(FlowKind kind) {
    switch (kind) {
        case FlowKind::kNormal: return "normal";
        case FlowKind::kJump: return "jump";
        case FlowKind::kCondJump: return "cond-jump";
        case FlowKind::kCall: return "call";
        case FlowKind::kIndirectJump: return "indirect-jump";
        case FlowKind::kIndirectCall: return "indirect-call";
        case FlowKind::kReturn: return "return";
        case FlowKind::kTrap: return "trap";
        case FlowKind::kInvalid: return "invalid";
    }
    return "?";
}

Disassembler::~Disassembler() { close(); }

Status Disassembler::open(Arch arch) {
    close();
    ArchitectureDescription description;
    if (!architectureDescription(arch, &description))
        return Status::error(ErrorCode::kUnsupported, "architecture has no registered decoder");
    if (description.decode) { description_ = std::move(description); arch_ = arch; return Status::success(); }

    cs_arch csArch;
    cs_mode csMode;
    switch (arch) {
        case Arch::kAArch64:
            csArch = CS_ARCH_AARCH64;
            csMode = CS_MODE_LITTLE_ENDIAN;
            break;
        case Arch::kX86_64:
            csArch = CS_ARCH_X86;
            csMode = static_cast<cs_mode>(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN);
            break;
        case Arch::kX86_32:
            csArch = CS_ARCH_X86;
            csMode = static_cast<cs_mode>(CS_MODE_32 | CS_MODE_LITTLE_ENDIAN);
            break;
        case Arch::kArm32:
        case Arch::kThumb:
            csArch = CS_ARCH_ARM;
            csMode = static_cast<cs_mode>((arch == Arch::kThumb ? CS_MODE_THUMB : CS_MODE_ARM) | CS_MODE_LITTLE_ENDIAN);
            break;
        case Arch::kRiscV32:
        case Arch::kRiscV64:
            csArch = CS_ARCH_RISCV;
            csMode = static_cast<cs_mode>((arch == Arch::kRiscV32 ? CS_MODE_RISCV32 : CS_MODE_RISCV64) |
                                         CS_MODE_RISCV_C | CS_MODE_LITTLE_ENDIAN);
            break;
        default:
            return Status::error(ErrorCode::kUnsupported,
                                 std::string("no decoder for architecture ") +
                                     archName(arch));
    }

    csh handle = 0;
    const cs_err err = cs_open(csArch, csMode, &handle);
    if (err != CS_ERR_OK) {
        return Status::error(ErrorCode::kInternalError,
                             std::string("cs_open failed: ") + cs_strerror(err));
    }

    // Detail is required, not a nicety: without operands we cannot read a branch
    // target, and without the condition code we cannot tell b.eq from b.
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON |
        ((arch == Arch::kArm32 || arch == Arch::kThumb) ? CS_OPT_DETAIL_REAL : 0));

    // Skipdata off. We want undecodable bytes reported as undecodable so the
    // caller can record them as data; letting Capstone invent .byte directives
    // would hide inline data, which is exactly what obfuscators put in .text.
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);

    cs_insn* scratch = cs_malloc(handle);
    if (scratch == nullptr) {
        cs_close(&handle);
        return Status::error(ErrorCode::kInternalError, "cs_malloc failed");
    }

    handle_ = static_cast<size_t>(handle);
    scratch_ = scratch;
    arch_ = arch;
    description_ = std::move(description);
    return Status::success();
}

void Disassembler::close() {
    if (scratch_ != nullptr) {
        cs_free(static_cast<cs_insn*>(scratch_), 1);
        scratch_ = nullptr;
    }
    if (handle_ != 0) {
        csh handle = static_cast<csh>(handle_);
        cs_close(&handle);
        handle_ = 0;
    }
    arch_ = Arch::kUnknown;
    description_ = {};
}

u8 Disassembler::minInstructionSize() const {
    return description_.minInstructionSize ? description_.minInstructionSize : kX86MinInsnSize;
}

u8 Disassembler::maxInstructionSize() const {
    return description_.maxInstructionSize ? description_.maxInstructionSize : kX86MaxInsnSize;
}

bool Disassembler::decodePlugin(Address addr, ByteView code, DecodedInsn* out) const {
    if (!description_.decode || (addr % description_.instructionAlignment) != 0) return false;
    DecodedInsn decoded;
    if (!description_.decode(addr, code.subview(0, std::min<size_t>(code.size(), maxInstructionSize())), &decoded) ||
        decoded.record.address != addr || decoded.record.size < minInstructionSize() ||
        decoded.record.size > maxInstructionSize() || decoded.record.size > code.size() ||
        decoded.record.flow == FlowKind::kInvalid || static_cast<u8>(decoded.record.flow) > static_cast<u8>(FlowKind::kInvalid) ||
        decoded.mnemonic.size() > 128 || decoded.operands.size() > 1024) return false;
    std::memcpy(decoded.bytes, code.data(), decoded.record.size);
    *out = std::move(decoded);
    return true;
}

bool Disassembler::decode(Address addr, ByteView code, InsnRecord* out) {
    if (!out) return false;
    if (description_.thumbAddressTag) addr &= ~Address{1};
    *out = InsnRecord();
    out->address = addr;
    out->size = minInstructionSize();
    out->flow = FlowKind::kInvalid;

    if (description_.decode) {
        DecodedInsn decoded;
        if (!decodePlugin(addr, code, &decoded)) return false;
        *out = decoded.record;
        return true;
    }
    if (handle_ == 0 || code.empty() || (addr % description_.instructionAlignment) != 0) return false;

    const u8* bytes = code.data();
    size_t size = code.size();
    u64 address = addr;
    auto* insn = static_cast<cs_insn*>(scratch_);

    if (!cs_disasm_iter(static_cast<csh>(handle_), &bytes, &size, &address, insn)) {
        return false;
    }

    out->address = insn->address;
    out->size = static_cast<u8>(insn->size);
    out->id = static_cast<u16>(insn->id);
    classify(insn, out);
    return true;
}

bool Disassembler::decodeVerbose(Address addr, ByteView code, DecodedInsn* out) {
    if (!out) return false;
    if (description_.thumbAddressTag) addr &= ~Address{1};
    *out = DecodedInsn();
    out->record.address = addr;
    out->record.size = minInstructionSize();
    out->record.flow = FlowKind::kInvalid;

    if (description_.decode) return decodePlugin(addr, code, out);
    if (handle_ == 0 || code.empty() || (addr % description_.instructionAlignment) != 0) return false;

    const u8* bytes = code.data();
    size_t size = code.size();
    u64 address = addr;
    auto* insn = static_cast<cs_insn*>(scratch_);

    if (!cs_disasm_iter(static_cast<csh>(handle_), &bytes, &size, &address, insn)) {
        // Still hand back the bytes we could not decode so the listing can show
        // them as data rather than a blank line.
        const size_t available = code.size() < sizeof(out->bytes) ? code.size()
                                                                 : sizeof(out->bytes);
        std::memcpy(out->bytes, code.data(), available);
        out->mnemonic = "(bad)";
        return false;
    }

    out->record.address = insn->address;
    out->record.size = static_cast<u8>(insn->size);
    out->record.id = static_cast<u16>(insn->id);
    classify(insn, &out->record);

    out->mnemonic = insn->mnemonic;
    out->operands = insn->op_str;
    const size_t copy = insn->size < sizeof(out->bytes) ? insn->size : sizeof(out->bytes);
    std::memcpy(out->bytes, insn->bytes, copy);
    return true;
}

void Disassembler::classify(const void* insn, InsnRecord* out) const {
    switch (arch_) {
        case Arch::kAArch64: classifyAArch64(insn, out); break;
        case Arch::kX86_64:
        case Arch::kX86_32: classifyX86(insn, out); break;
        case Arch::kArm32:
        case Arch::kThumb: classifyArm(insn, out); break;
        case Arch::kRiscV32:
        case Arch::kRiscV64: classifyRiscV(insn, out); break;
        default: out->flow = FlowKind::kNormal; break;
    }
}

void Disassembler::classifyAArch64(const void* raw, InsnRecord* out) const {
    const auto* insn = static_cast<const cs_insn*>(raw);
    out->flow = FlowKind::kNormal;
    out->target = kNoAddress;

    // The first immediate operand is the branch target for every direct branch
    // form on this architecture, including cbz/tbz where it follows a register.
    auto directTarget = [&]() -> Address {
        if (insn->detail == nullptr) return kNoAddress;
        const cs_aarch64& detail = insn->detail->aarch64;
        for (u8 i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == AARCH64_OP_IMM) {
                return static_cast<Address>(detail.operands[i].imm);
            }
        }
        return kNoAddress;
    };

    switch (insn->id) {
        case AARCH64_INS_B: {
            // Capstone reports both `b` and `b.cond` under this id; the condition
            // code is what separates them. AL and NV are the unconditional
            // encodings, and Invalid means the field was not applicable.
            const bool conditional =
                insn->detail != nullptr &&
                insn->detail->aarch64.cc != AArch64CC_Invalid &&
                insn->detail->aarch64.cc != AArch64CC_AL &&
                insn->detail->aarch64.cc != AArch64CC_NV;
            out->flow = conditional ? FlowKind::kCondJump : FlowKind::kJump;
            out->target = directTarget();
            return;
        }
        case AARCH64_INS_CBZ:
        case AARCH64_INS_CBNZ:
        case AARCH64_INS_TBZ:
        case AARCH64_INS_TBNZ:
            out->flow = FlowKind::kCondJump;
            out->target = directTarget();
            return;

        case AARCH64_INS_BL:
            out->flow = FlowKind::kCall;
            out->target = directTarget();
            return;

        // Pointer-authenticated indirect branches. Treated exactly like their
        // unauthenticated forms: the target is still a register.
        case AARCH64_INS_BLR:
        case AARCH64_INS_BLRAA:
        case AARCH64_INS_BLRAB:
            out->flow = FlowKind::kIndirectCall;
            return;

        case AARCH64_INS_BR:
        case AARCH64_INS_BRAA:
        case AARCH64_INS_BRAB:
            out->flow = FlowKind::kIndirectJump;
            return;

        case AARCH64_INS_RET:
        case AARCH64_INS_RETAA:
        case AARCH64_INS_RETAB:
        case AARCH64_INS_ERET:
            out->flow = FlowKind::kReturn;
            return;

        case AARCH64_INS_BRK:
        case AARCH64_INS_HLT:
            out->flow = FlowKind::kTrap;
            return;

        default:
            break;
    }

    // Anything the id switch did not name but Capstone still groups as control
    // flow. Reaching here means a branch form we have not enumerated, so it is
    // treated as indirect — pessimistic, which keeps the CFG sound.
    if (hasGroup(insn, AARCH64_GRP_RET)) {
        out->flow = FlowKind::kReturn;
    } else if (hasGroup(insn, AARCH64_GRP_CALL)) {
        out->flow = FlowKind::kIndirectCall;
    } else if (hasGroup(insn, AARCH64_GRP_JUMP)) {
        out->flow = FlowKind::kIndirectJump;
    }
}

void Disassembler::classifyX86(const void* raw, InsnRecord* out) const {
    const auto* insn = static_cast<const cs_insn*>(raw);
    out->flow = FlowKind::kNormal;
    out->target = kNoAddress;

    // On x86 a branch is direct only when its single operand is an immediate;
    // `jmp rax` and `call [rip+0x1234]` are the indirect forms, and the second is
    // how every call through the PLT and every vtable dispatch looks.
    auto immediateTarget = [&]() -> Address {
        if (insn->detail == nullptr) return kNoAddress;
        const cs_x86& detail = insn->detail->x86;
        if (detail.op_count >= 1 && detail.operands[0].type == X86_OP_IMM) {
            return static_cast<Address>(detail.operands[0].imm);
        }
        return kNoAddress;
    };

    switch (insn->id) {
        case X86_INS_JMP:
        case X86_INS_LJMP: {
            const Address target = immediateTarget();
            out->flow = target == kNoAddress ? FlowKind::kIndirectJump : FlowKind::kJump;
            out->target = target;
            return;
        }
        case X86_INS_CALL:
        case X86_INS_LCALL: {
            const Address target = immediateTarget();
            out->flow = target == kNoAddress ? FlowKind::kIndirectCall : FlowKind::kCall;
            out->target = target;
            return;
        }
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
        case X86_INS_IRET:
            out->flow = FlowKind::kReturn;
            return;

        case X86_INS_UD0:
        case X86_INS_UD1:
        case X86_INS_UD2:
        case X86_INS_HLT:
        case X86_INS_INT3:
            out->flow = FlowKind::kTrap;
            return;

        default:
            break;
    }

    // Every Jcc has its own instruction id, as do loop and jrcxz, so anything
    // left in the jump group after the switch above is conditional.
    if (hasGroup(insn, X86_GRP_JUMP)) {
        out->flow = FlowKind::kCondJump;
        out->target = immediateTarget();
        if (out->target == kNoAddress) out->flow = FlowKind::kIndirectJump;
        return;
    }
    if (hasGroup(insn, X86_GRP_CALL)) {
        const Address target = immediateTarget();
        out->flow = target == kNoAddress ? FlowKind::kIndirectCall : FlowKind::kCall;
        out->target = target;
        return;
    }
    if (hasGroup(insn, X86_GRP_RET)) {
        out->flow = FlowKind::kReturn;
    }
}

void Disassembler::classifyArm(const void* raw, InsnRecord* out) const {
    const auto* insn = static_cast<const cs_insn*>(raw);
    out->flow = FlowKind::kNormal;
    out->target = kNoAddress;
    if (!insn->detail) return;
    const auto& detail = insn->detail->arm;
    // The public detail of unconditional BX is ARMCC_UNDEF in this pinned
    // Capstone build. ARM's actual condition bits are authoritative; Thumb has
    // no such field and an unspecified detail condition is not predication.
    const bool conditional = arch_ == Arch::kArm32 ? (insn->bytes[3] >> 4) < 14 :
        detail.cc != ARMCC_Invalid && detail.cc != ARMCC_UNDEF && detail.cc != ARMCC_AL;
    auto immediate = [&]() -> Address {
        for (u8 i = 0; i < detail.op_count; ++i) if (detail.operands[i].type == ARM_OP_IMM)
            return static_cast<u32>(detail.operands[i].imm);
        return kNoAddress;
    };
    auto tagged = [&](Address target, bool exchange) -> Address {
        if (target == kNoAddress) return target;
        const bool thumb = (arch_ == Arch::kThumb) != exchange;
        return (target & ~Address{1}) | (thumb ? 1 : 0);
    };
    auto hasRegister = [&](unsigned reg) {
        for (u8 i = 0; i < detail.op_count; ++i)
            if (detail.operands[i].type == ARM_OP_REG && static_cast<unsigned>(detail.operands[i].reg) == reg) return true;
        return false;
    };
    switch (insn->id) {
        case ARM_INS_B:
            out->flow = conditional ? FlowKind::kCondJump : FlowKind::kJump;
            out->target = tagged(immediate(), false);
            return;
        case ARM_INS_CBZ:
        case ARM_INS_CBNZ:
            out->flow = FlowKind::kCondJump;
            out->target = tagged(immediate(), false);
            return;
        case ARM_INS_BL:
        case ARM_INS_BLX:
            out->target = tagged(immediate(), insn->id == ARM_INS_BLX);
            out->flow = out->target == kNoAddress ? FlowKind::kIndirectCall : FlowKind::kCall;
            return;
        case ARM_INS_BX:
        case ARM_INS_BXJ:
            // Conditional returns also have a fallthrough edge. Represent them
            // as unresolved conditional jumps, never as unconditional returns.
            out->flow = conditional ? FlowKind::kCondJump :
                (hasRegister(ARM_REG_LR) ? FlowKind::kReturn : FlowKind::kIndirectJump);
            return;
        case ARM_INS_POP:
        case ARM_INS_LDM:
        case ARM_INS_LDMDA:
        case ARM_INS_LDMDB:
        case ARM_INS_LDMIB:
            if (hasRegister(ARM_REG_PC)) {
                out->flow = conditional ? FlowKind::kCondJump :
                    (insn->id == ARM_INS_POP || (detail.op_count && detail.operands[0].type == ARM_OP_REG && detail.operands[0].reg == ARM_REG_SP) ? FlowKind::kReturn : FlowKind::kIndirectJump);
                return;
            }
            break;
        case ARM_INS_MOV:
        case ARM_INS_MOVS:
            if (detail.op_count >= 2 && detail.operands[0].type == ARM_OP_REG && detail.operands[0].reg == ARM_REG_PC) {
                const bool returning = detail.operands[1].type == ARM_OP_REG && detail.operands[1].reg == ARM_REG_LR;
                out->flow = conditional ? FlowKind::kCondJump : (returning ? FlowKind::kReturn : FlowKind::kIndirectJump);
                return;
            }
            break;
        case ARM_INS_TBB:
        case ARM_INS_TBH:
            out->flow = FlowKind::kIndirectJump;
            return;
        case ARM_INS_BKPT:
        case ARM_INS_UDF:
            out->flow = FlowKind::kTrap;
            return;
        default: break;
    }
    if (hasGroup(insn, ARM_GRP_RET)) out->flow = conditional ? FlowKind::kCondJump : FlowKind::kReturn;
    else if (hasGroup(insn, ARM_GRP_CALL)) out->flow = FlowKind::kIndirectCall;
    else if (hasGroup(insn, ARM_GRP_JUMP)) out->flow = conditional ? FlowKind::kCondJump : FlowKind::kIndirectJump;
    else {
        // ARM permits many data-processing instructions to write PC. Such a
        // write must terminate descent even if Capstone does not group it.
        for (u8 i = 0; i < detail.op_count; ++i) {
            const auto& operand = detail.operands[i];
            if (operand.type == ARM_OP_REG && operand.reg == ARM_REG_PC && (operand.access & CS_AC_WRITE)) {
                out->flow = conditional ? FlowKind::kCondJump : FlowKind::kIndirectJump;
                return;
            }
        }
    }
}

void Disassembler::classifyRiscV(const void* raw, InsnRecord* out) const {
    const auto* insn = static_cast<const cs_insn*>(raw);
    out->flow = FlowKind::kNormal;
    out->target = kNoAddress;
    auto signExtend = [](u32 value, unsigned bits) -> i64 {
        return static_cast<i64>(value & ((u32{1} << bits) - 1)) -
            ((value & (u32{1} << (bits - 1))) ? (i64{1} << bits) : 0);
    };
    auto target = [&](i64 displacement) -> Address {
        const Address result = insn->address + static_cast<Address>(displacement);
        return arch_ == Arch::kRiscV32 ? static_cast<u32>(result) : result;
    };
    if (insn->size == 4) {
        u32 word = 0; std::memcpy(&word, insn->bytes, sizeof(word));
        const u32 opcode = word & 0x7f, rd = (word >> 7) & 31, rs1 = (word >> 15) & 31;
        if (opcode == 0x6f) { // JAL, including aliases j/call-like jal.
            const u32 immediate = ((word >> 31) << 20) | (((word >> 12) & 255) << 12) |
                (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1);
            out->target = target(signExtend(immediate, 21));
            out->flow = rd == 1 || rd == 5 ? FlowKind::kCall : FlowKind::kJump;
            return;
        }
        if (opcode == 0x67) {
            const bool returning = rd == 0 && (rs1 == 1 || rs1 == 5) && (word >> 20) == 0;
            out->flow = returning ? FlowKind::kReturn : (rd == 1 || rd == 5 ? FlowKind::kIndirectCall : FlowKind::kIndirectJump);
            return;
        }
        if (opcode == 0x63) {
            const u32 immediate = ((word >> 31) << 12) | (((word >> 7) & 1) << 11) |
                (((word >> 25) & 63) << 5) | (((word >> 8) & 15) << 1);
            out->target = target(signExtend(immediate, 13));
            out->flow = FlowKind::kCondJump;
            return;
        }
        if (word == 0x00100073) { out->flow = FlowKind::kTrap; return; } // EBREAK
        if (word == 0x30200073 || word == 0x10200073 || word == 0x00200073) {
            out->flow = FlowKind::kReturn; return; // MRET/SRET/URET
        }
    } else if (insn->size == 2) {
        u16 word = 0; std::memcpy(&word, insn->bytes, sizeof(word));
        const unsigned quadrant = word & 3, funct = word >> 13;
        if (quadrant == 1 && (funct == 5 || (funct == 1 && arch_ == Arch::kRiscV32))) {
            const u32 immediate = (((word >> 12) & 1) << 11) | (((word >> 11) & 1) << 4) |
                (((word >> 9) & 3) << 8) | (((word >> 8) & 1) << 10) | (((word >> 7) & 1) << 6) |
                (((word >> 6) & 1) << 7) | (((word >> 3) & 7) << 1) | (((word >> 2) & 1) << 5);
            out->target = target(signExtend(immediate, 12));
            out->flow = funct == 1 ? FlowKind::kCall : FlowKind::kJump;
            return;
        }
        if (quadrant == 1 && (funct == 6 || funct == 7)) {
            const u32 immediate = (((word >> 12) & 1) << 8) | (((word >> 10) & 3) << 3) |
                (((word >> 5) & 3) << 6) | (((word >> 3) & 3) << 1) | (((word >> 2) & 1) << 5);
            out->target = target(signExtend(immediate, 9));
            out->flow = FlowKind::kCondJump;
            return;
        }
        if (quadrant == 2 && funct == 4 && (word & 0x7c) == 0) {
            const unsigned rs1 = (word >> 7) & 31;
            if (rs1 != 0) out->flow = (word & 0x1000) ? FlowKind::kIndirectCall :
                (rs1 == 1 || rs1 == 5 ? FlowKind::kReturn : FlowKind::kIndirectJump);
            else if (word == 0x9002) out->flow = FlowKind::kTrap;
            return;
        }
    }
    if (hasGroup(insn, RISCV_GRP_RET) || hasGroup(insn, RISCV_GRP_IRET)) out->flow = FlowKind::kReturn;
    else if (hasGroup(insn, RISCV_GRP_CALL)) out->flow = FlowKind::kIndirectCall;
    else if (hasGroup(insn, RISCV_GRP_JUMP)) out->flow = FlowKind::kIndirectJump;
}

}  // namespace mint
