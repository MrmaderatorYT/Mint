#include "mint/ir/lifter.h"

#include "mint/base/log.h"
#include "mint/ir/lifter_internal.h"

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
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    handle_ = static_cast<size_t>(handle);
    arch_ = arch;
    return Status::success();
}

u32 Lifter::liftInstruction(Address address, ByteView bytes, IrBuilder* builder) {
    if (!ready() || builder == nullptr || bytes.empty()) return 0;

    const csh handle = static_cast<csh>(handle_);
    cs_insn* insn = nullptr;
    const size_t count = cs_disasm(handle, bytes.data(), bytes.size(), address, 1, &insn);
    if (count == 0 || insn == nullptr) return 0;

    const u32 size = insn->size;
    switch (arch_) {
        case Arch::kAArch64:
            liftAArch64(*insn, *builder);
            break;
        case Arch::kX86_64:
            liftX86(*insn, *builder);
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
    const char* name = cs_insn_name(static_cast<csh>(handle_), id);
    return name != nullptr ? name : "(unknown)";
}

Status Lifter::liftFunction(const Function& function, const MemoryMap& memory,
                            IrFunction* out) {
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
