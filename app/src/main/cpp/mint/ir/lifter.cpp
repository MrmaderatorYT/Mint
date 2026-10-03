#include "mint/ir/lifter.h"

#include "mint/base/log.h"
#include "mint/ir/lifter_internal.h"
#include "mint/plugin/architecture_bridge.h"
#include "mint/disasm/disassembler.h"

namespace mint {
namespace {

/// Longest instruction either architecture can produce. x86-64 tops out at 15
/// bytes; AArch64 is always 4.
constexpr size_t kMaxInstructionBytes = 16;

}  // namespace

Lifter::~Lifter() {
    if (handle_ != 0) {
        csh handle = static_cast<csh>(handle_);
        cs_close(&handle);
        handle_ = 0;
    }
}

Status Lifter::open(Arch arch) {
    if(static_cast<u8>(arch)>=128&&architecturePluginHasLifter(arch)){if(handle_){csh previous=static_cast<csh>(handle_);cs_close(&previous);handle_=0;}arch_=arch;customReady_=true;thumbItRemaining_=0;thumbItNextAddress_=kNoAddress;return Status::success();}
    static_assert(sizeof(csh) <= sizeof(size_t),
                  "the opaque handle must be able to hold a csh");

    cs_arch capstoneArch;
    cs_mode mode;
    switch (arch) {
        case Arch::kAArch64:
            capstoneArch = CS_ARCH_AARCH64;
            mode = CS_MODE_LITTLE_ENDIAN;
            break;
        case Arch::kX86_64:
            capstoneArch = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        case Arch::kX86_32:capstoneArch=CS_ARCH_X86;mode=CS_MODE_32;break;
        case Arch::kArm32:capstoneArch=CS_ARCH_ARM;mode=CS_MODE_ARM;break;
        case Arch::kThumb:capstoneArch=CS_ARCH_ARM;mode=CS_MODE_THUMB;break;
        case Arch::kRiscV32:capstoneArch=CS_ARCH_RISCV;mode=static_cast<cs_mode>(CS_MODE_RISCV32|CS_MODE_RISCV_C);break;
        case Arch::kRiscV64:capstoneArch=CS_ARCH_RISCV;mode=static_cast<cs_mode>(CS_MODE_RISCV64|CS_MODE_RISCV_C);break;
        default:
            return Status::error(ErrorCode::kUnsupported,
                                 "no lifter for this architecture");
    }

    csh handle = 0;
    if (cs_open(capstoneArch, mode, &handle) != CS_ERR_OK) {
        return Status::error(ErrorCode::kInternalError, "cs_open failed");
    }
    // Operand detail is not optional here: without it there is nothing to lift
    // from, only mnemonic text.
    // Capstone 6 keeps the real opcode id for ARM aliases such as push/pop,
    // while alias-detail operands omit the base register. Mixing those two
    // views would interpret the first saved register as the stack pointer.
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON |
        ((arch == Arch::kArm32 || arch == Arch::kThumb) ? CS_OPT_DETAIL_REAL : 0));

    if(handle_!=0) {csh previous=static_cast<csh>(handle_);cs_close(&previous);}
    handle_ = static_cast<size_t>(handle);
    arch_ = arch;
    customReady_ = false;
    thumbItRemaining_ = 0;
    thumbItState_ = 0;
    thumbItNextAddress_ = kNoAddress;
    return Status::success();
}

u32 Lifter::liftInstruction(Address address, ByteView bytes, IrBuilder* builder) {
    if (!ready() || builder == nullptr || bytes.empty()) return 0;
    if(customReady_)return liftArchitecturePlugin(arch_,address,bytes,builder);

    const csh handle = static_cast<csh>(handle_);
    cs_insn* insn = nullptr;
    const size_t count = cs_disasm(handle, bytes.data(), bytes.size(), address, 1, &insn);
    if (count == 0 || insn == nullptr) return 0;

    const u32 size = insn->size;
    if (arch_ == Arch::kThumb) {
        if (address != thumbItNextAddress_) {thumbItRemaining_ = 0;thumbItState_=0;}
        if (thumbItRemaining_) {
            const auto currentCondition=static_cast<ARMCC_CondCodes>(thumbItState_>>4);
            --thumbItRemaining_;
            thumbItNextAddress_ = address + size;
            thumbItState_=(thumbItState_&7)==0 ? 0 : static_cast<u8>((thumbItState_&0xe0)|((thumbItState_<<1)&0x1f));
            if(insn->detail) {
                insn->detail->arm.cc=currentCondition;
                // Narrow Thumb opcodes with implicit S suppress flag writes in
                // IT blocks. CMP/CMN/TST and explicit 32-bit S preserve theirs.
                if(size==2 && insn->id!=ARM_INS_CMP && insn->id!=ARM_INS_CMN && insn->id!=ARM_INS_TST)
                    insn->detail->arm.update_flags=false;
            }
        }
        if (insn->id == ARM_INS_IT && size == 2) {
            const unsigned mask = bytes.data()[0] & 15;
            unsigned trailing = 0;
            while (trailing < 4 && ((mask >> trailing) & 1) == 0) ++trailing;
            thumbItRemaining_ = static_cast<u8>(4 - trailing);
            thumbItState_=bytes.data()[0];
            thumbItNextAddress_ = address + size;
            builder->setAddress(address);
            if(mask && (thumbItState_>>4)<14) {cs_free(insn,count);return size;}
            thumbItRemaining_=0;thumbItState_=0;
        }
    }
    switch (arch_) {
        case Arch::kAArch64:
            liftAArch64(*insn, *builder);
            break;
        case Arch::kX86_64:
        case Arch::kX86_32:
            liftX86(*insn, *builder);
            break;
        case Arch::kArm32:
        case Arch::kThumb:
            liftArm32(*insn, *builder, arch_ == Arch::kThumb);
            break;
        case Arch::kRiscV32:
        case Arch::kRiscV64:
            liftRiscV(*insn, *builder, arch_ == Arch::kRiscV64);
            break;
        default:
            builder->setAddress(address);
            builder->emitIntrinsic(static_cast<u16>(insn->id));
            break;
    }
    cs_free(insn, count);
    return size;
}

const char* Lifter::instructionName(u16 id) const {
    if (!ready() || id == 0) return "(undecodable)";
    if(customReady_)return "(architecture plugin)";
    const char* name = cs_insn_name(static_cast<csh>(handle_), id);
    return name != nullptr ? name : "(unknown)";
}

Status Lifter::liftFunction(const Function& function, const MemoryMap& memory,
                            IrFunction* out) {
    if(function.decodeArch!=Arch::kUnknown && function.decodeArch!=arch_) {
        const auto status=open(function.decodeArch);if(!status.ok())return status;
    }
    if (!ready()) {
        return Status::error(ErrorCode::kInternalError, "lifter is not open");
    }
    if (out == nullptr) {
        return Status::error(ErrorCode::kInternalError, "no output function");
    }

    *out = IrFunction();
    out->entry = function.entry;
    out->name = function.name;
    out->arch = arch_;

    IrBuilder builder(out);
    thumbItRemaining_ = 0;
    thumbItState_ = 0;
    thumbItNextAddress_ = kNoAddress;

    // One IR block per machine block, in the same order and with the same ids, so
    // that an IR block index and a machine block index mean the same thing. Every
    // pass above relies on that correspondence.
    for (const BasicBlock& machineBlock : function.cfg.blocks()) {
        IrBlock block;
        block.id = machineBlock.id;
        block.start = machineBlock.start;
        block.end = machineBlock.end;
        block.firstInsn = builder.insnCount();

        Address cursor = machineBlock.start;
        while (cursor < machineBlock.end) {
            const size_t want = std::min<size_t>(
                kMaxInstructionBytes, static_cast<size_t>(machineBlock.end - cursor));
            const ByteView view = memory.viewAt(cursor, want);
            if (view.empty()) break;

            const u32 consumed = liftInstruction(cursor, view, &builder);
            if (consumed == 0) {
                // Bytes that will not decode still get an op, so the IR admits the
                // gap instead of silently skipping over it.
                builder.setAddress(cursor);
                builder.emitIntrinsic(0);
                ++out->machineInsnCount;
                break;
            }
            cursor += consumed;
            ++out->machineInsnCount;
        }

        block.insnCount = builder.insnCount() - block.firstInsn;
        for (const CfgEdge& edge : machineBlock.successors) {
            block.successors.push_back(edge.target);
        }
        out->blocks.push_back(std::move(block));
    }

    for (IrBlock& block : out->blocks) {
        for (u32 successor : block.successors) {
            if (successor < out->blocks.size()) {
                out->blocks[successor].predecessors.push_back(block.id);
            }
        }
    }

    return Status::success();
}

}  // namespace mint
