#include "mint/disasm/disassembler.h"

#include <capstone/capstone.h>

#include <cstring>

#include "mint/base/log.h"

namespace mint {
namespace {

/// AArch64 is fixed-width; x86-64 is not, and 15 is the architectural maximum.
constexpr u8 kAArch64InsnSize = 4;
constexpr u8 kX86MinInsnSize = 1;
constexpr u8 kX86MaxInsnSize = 15;

bool hasGroup(const cs_insn* insn, u8 group) {
    if (insn->detail == nullptr) return false;
    for (u8 i = 0; i < insn->detail->groups_count; ++i) {
        if (insn->detail->groups[i] == group) return true;
    }
    return false;
}

}  // namespace

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
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

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
}

u8 Disassembler::minInstructionSize() const {
    return arch_ == Arch::kAArch64 ? kAArch64InsnSize : kX86MinInsnSize;
}

u8 Disassembler::maxInstructionSize() const {
    return arch_ == Arch::kAArch64 ? kAArch64InsnSize : kX86MaxInsnSize;
}

bool Disassembler::decode(Address addr, ByteView code, InsnRecord* out) {
    *out = InsnRecord();
    out->address = addr;
    out->size = minInstructionSize();
    out->flow = FlowKind::kInvalid;

    if (handle_ == 0 || code.empty()) return false;

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
    *out = DecodedInsn();
    out->record.address = addr;
    out->record.size = minInstructionSize();
    out->record.flow = FlowKind::kInvalid;

    if (handle_ == 0 || code.empty()) return false;

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
        case Arch::kX86_64: classifyX86(insn, out); break;
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

}  // namespace mint
