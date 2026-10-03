#include "mint/ir/ir_function.h"

#include <cstdio>

#include "mint/ir/registers.h"
#include "mint/plugin/architecture_bridge.h"

namespace mint {
namespace {

std::string formatAddress(Address address) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx",
                  static_cast<unsigned long long>(address));
    return buffer;
}

/// Sign-extends the low `fromBytes` bytes of `value` to 64 bits.
u64 signExtendValue(u64 value, u8 fromBytes) {
    if (fromBytes >= 8) return value;
    const unsigned bits = unsigned(fromBytes) * 8;
    const u64 signBit = u64(1) << (bits - 1);
    const u64 mask = (u64(1) << bits) - 1;
    value &= mask;
    return (value & signBit) != 0 ? value | ~mask : value;
}

u64 truncateValue(u64 value, u8 toBytes) {
    if (toBytes >= 8) return value;
    return value & ((u64(1) << (unsigned(toBytes) * 8)) - 1);
}

}  // namespace

// ------------------------------------------------------------------ IrBuilder

void IrBuilder::emit(MintOp op, const Varnode& dest, const Varnode& a,
                     const Varnode& b, const Varnode& c) {
    IrInsn insn;
    insn.op = op;
    insn.dest = dest;
    insn.a = a;
    insn.b = b;
    insn.c = c;
    insn.address = address_;
    function_->insns.push_back(insn);
}

void IrBuilder::emitIntrinsic(u16 capstoneId) {
    IrInsn insn;
    insn.op = MintOp::kIntrinsic;
    insn.address = address_;
    insn.intrinsicId = capstoneId;
    function_->insns.push_back(insn);
    ++function_->intrinsicCount;
}

Varnode IrBuilder::binary(MintOp op, const Varnode& a, const Varnode& b) {
    const u8 size = producesBoolean(op) ? 1 : a.size;
    Varnode dest = newTemp(size);
    emit(op, dest, a, b);
    return dest;
}

Varnode IrBuilder::ternary(MintOp op, const Varnode& a, const Varnode& b,
                           const Varnode& c) {
    Varnode dest = newTemp(producesBoolean(op) ? 1 : a.size);
    emit(op, dest, a, b, c);
    return dest;
}

Varnode IrBuilder::vector(MintOp op, u8 laneWidth, const Varnode& a, const Varnode& b,
                          const Varnode& c, u8 destSize) {
    Varnode dest = newTemp(destSize);
    emit(op, dest, a, b, c);
    function_->insns.back().laneWidth = laneWidth;
    return dest;
}

void IrBuilder::vectorVoid(MintOp op, u8 laneWidth, const Varnode& a, const Varnode& b) {
    emit(op, Varnode::invalid(), a, b);
    function_->insns.back().laneWidth = laneWidth;
}

Varnode IrBuilder::unary(MintOp op, const Varnode& a, u8 destSize) {
    Varnode dest = newTemp(destSize);
    emit(op, dest, a);
    return dest;
}

void IrBuilder::assign(const Varnode& dest, const Varnode& value) {
    emit(MintOp::kCopy, dest, value);
}

Varnode IrBuilder::resize(const Varnode& value, u8 size, bool signExtend) {
    if (value.size == size) return value;

    // Folding constants here rather than emitting a widening op keeps a lot of
    // noise out of the listing: immediates get resized constantly during lifting,
    // and every folded case is one less op for every later pass to walk.
    if (value.isConstant()) {
        const u64 folded = value.size < size
                               ? (signExtend ? signExtendValue(value.offset, value.size)
                                             : truncateValue(value.offset, value.size))
                               : truncateValue(value.offset, size);
        return Varnode::constant(truncateValue(folded, size), size);
    }

    const MintOp op = value.size < size
                          ? (signExtend ? MintOp::kSignExt : MintOp::kZeroExt)
                          : MintOp::kTrunc;
    return unary(op, value, size);
}

// ----------------------------------------------------------------- IrFunction

const IrBlock* IrFunction::blockAt(Address address) const {
    for (const IrBlock& block : blocks) {
        if (address >= block.start && address < block.end) return &block;
    }
    return nullptr;
}

std::vector<std::string> IrFunction::verify() const {
    std::vector<std::string> problems;
    const u64 fileSize = registerFileSize(arch);

    auto report = [&](size_t index, const std::string& what) {
        if (problems.size() >= 64) return;  // A broken lifter would flood this.
        const char* name = index < insns.size() ? opName(insns[index].op) : "?";
        const Address at = index < insns.size() ? insns[index].address : 0;
        problems.push_back("insn[" + std::to_string(index) + "] @" +
                           formatAddress(at) + " " + name + ": " + what);
    };

    // A vector op carrying no lane width is only half-lifted: it says something
    // happened to sixteen bytes without saying how those bytes divide, and adding
    // bytes is not adding words. The mistake is invisible downstream — the IR still
    // reads plausibly — so it has to be caught where the IR is checked.
    auto checkLaneWidth = [&](const IrInsn& insn, size_t index) {
        if (insn.laneWidth == 0 || 16 % insn.laneWidth != 0) {
            report(index, "vector op has no usable lane width");
        }
    };

    for (size_t i = 0; i < insns.size(); ++i) {
        const IrInsn& insn = insns[i];
        if (insn.op == MintOp::kInvalid) {
            report(i, "opcode is kInvalid");
            continue;
        }
        const OpInfo& info = opInfo(insn.op);

        if (info.hasDest != insn.dest.valid()) {
            report(i, info.hasDest ? "missing destination" : "unexpected destination");
        }
        for (unsigned slot = 0; slot < 3; ++slot) {
            const bool wanted = slot < info.sources;
            if (insn.source(slot).valid() != wanted) {
                report(i, "source slot " + std::to_string(slot) +
                              (wanted ? " is missing" : " should be unused"));
            }
        }

        auto checkStorage = [&](const Varnode& node, const char* role) {
            if (!node.valid()) return;
            if (node.size == 0 || node.size > 16) {
                report(i, std::string(role) + " has width " + std::to_string(node.size));
            }
            if (node.isTemp() && node.offset >= tempCount) {
                report(i, std::string(role) + " uses temp " +
                              std::to_string(node.offset) + " but only " +
                              std::to_string(tempCount) + " were allocated");
            }
            if (node.isRegister() && fileSize != 0 && node.offset + node.size > fileSize) {
                report(i, std::string(role) + " reaches past the register file");
            }
            // A constant wider than its declared width means the lifter computed
            // an immediate at the wrong size, which silently produces wrong
            // arithmetic rather than a crash.
            if (node.isConstant() && node.size < 8 &&
                truncateValue(node.offset, node.size) != node.offset) {
                report(i, std::string(role) + " constant does not fit its width");
            }
        };
        checkStorage(insn.dest, "dest");
        checkStorage(insn.a, "a");
        checkStorage(insn.b, "b");
        checkStorage(insn.c, "c");

        const Varnode& d = insn.dest;
        const Varnode& a = insn.a;
        const Varnode& b = insn.b;
        const Varnode& c = insn.c;

        MintArchitectureSemanticsV2 custom{};
        const u8 pointerWidth=architecturePluginAbi(arch,&custom) ? custom.pointer_size : (arch==Arch::kArm32 || arch==Arch::kThumb || arch==Arch::kX86_32 || arch==Arch::kRiscV32?4:8);
        switch (insn.op) {
            case MintOp::kCopy:
                if (d.size != a.size) report(i, "copy changes width");
                break;
            case MintOp::kLoad:
                if (a.size != pointerWidth) report(i, "load address width differs from target pointer width");
                break;
            case MintOp::kStore:
                if (a.size != pointerWidth) report(i, "store address width differs from target pointer width");
                break;
            case MintOp::kAtomicLoad:
            case MintOp::kAtomicExchange:
            case MintOp::kAtomicAdd:
            case MintOp::kAtomicCompareExchange:
                if(a.size!=pointerWidth || (d.size!=1&&d.size!=2&&d.size!=4&&d.size!=8)) report(i,"invalid scalar atomic widths");
                if(insn.op!=MintOp::kAtomicLoad && b.size!=d.size) report(i,"atomic value width differs from destination");
                if(insn.op==MintOp::kAtomicCompareExchange && c.size!=d.size) report(i,"atomic replacement width differs from destination");
                break;
            case MintOp::kAtomicStore:
                if(a.size!=pointerWidth || (b.size!=1&&b.size!=2&&b.size!=4&&b.size!=8)) report(i,"invalid scalar atomic store widths");
                break;
            case MintOp::kAdd:
            case MintOp::kSub:
            case MintOp::kMul:
            case MintOp::kMulHiU:
            case MintOp::kMulHiS:
            case MintOp::kDivU:
            case MintOp::kDivS:
            case MintOp::kRemU:
            case MintOp::kRemS:
            case MintOp::kAnd:
            case MintOp::kOr:
            case MintOp::kXor:
                if (d.size != a.size || a.size != b.size) {
                    report(i, "operand widths disagree");
                }
                break;
            // Lane-wise over two full vectors. Both sources are 128 bits and the
            // lane width says how those bits divide.
            case MintOp::kVectorAdd:
            case MintOp::kVectorSub:
            case MintOp::kVectorMul:
            case MintOp::kVectorMulWideU:
            case MintOp::kVectorMulWideS:
            case MintOp::kVectorCmpEq:
            case MintOp::kVectorCmpGtS:
            case MintOp::kVectorMinU:
            case MintOp::kVectorMinS:
            case MintOp::kVectorMaxU:
            case MintOp::kVectorMaxS:
            case MintOp::kVectorPackS:
            case MintOp::kVectorPackU:
            case MintOp::kVectorSelect:
                if (d.size != 16 || a.size != 16 || b.size != 16) {
                    report(i, "vector arithmetic is not 128 bits");
                }
                checkLaneWidth(insn, i);
                break;
            // Same family, but the second source is a scalar: a shift count, an
            // inserted element, a lane index. Only the destination and the first
            // source are guaranteed to be vectors — and not even the first, for a
            // widening extend reading four bytes of memory.
            case MintOp::kVectorShl:
            case MintOp::kVectorShrU:
            case MintOp::kVectorShrS:
            case MintOp::kVectorExtendS:
            case MintOp::kVectorExtendU:
            case MintOp::kVectorInsert:
                if (d.size != 16) report(i, "vector result is not 128 bits");
                checkLaneWidth(insn, i);
                break;
            case MintOp::kDivWideU:
            case MintOp::kDivWideS:
            case MintOp::kRemWideU:
            case MintOp::kRemWideS:
                // All four are one machine width: the dividend is double-width only
                // as a pair of same-width halves, never as a wider varnode.
                if (d.size != a.size || a.size != b.size || b.size != insn.c.size) {
                    report(i, "wide division operand widths disagree");
                }
                break;
            case MintOp::kNeg:
            case MintOp::kNot:
            case MintOp::kPopCount:
            case MintOp::kClz:
            case MintOp::kCtz:
                if (d.size != a.size) report(i, "operand widths disagree");
                break;
            case MintOp::kShl:
            case MintOp::kShrU:
            case MintOp::kShrS:
            case MintOp::kRotL:
            case MintOp::kRotR:
                // The shift amount is free: machine encodings supply it at all
                // sorts of widths and it is a count, not a value in the same
                // domain as the operand.
                if (d.size != a.size) report(i, "shift changes operand width");
                break;
            case MintOp::kEqual:
            case MintOp::kNotEqual:
            case MintOp::kLessU:
            case MintOp::kLessS:
            case MintOp::kLessEqU:
            case MintOp::kLessEqS:
            case MintOp::kCarryAdd:
            case MintOp::kBorrowSub:
            case MintOp::kOverflowAdd:
            case MintOp::kOverflowSub:
            case MintOp::kFloatEqual:
            case MintOp::kFloatLess:
            case MintOp::kFloatUnordered:
                if (d.size != 1) report(i, "boolean result is not 1 byte");
                if (a.size != b.size) report(i, "compared operands differ in width");
                break;
            case MintOp::kFloatAdd:
            case MintOp::kFloatSub:
            case MintOp::kFloatMul:
            case MintOp::kFloatDiv:
                if (d.size != a.size || a.size != b.size) {
                    report(i, "floating-point operand widths disagree");
                }
                break;
            case MintOp::kFloatSqrt:
            case MintOp::kFloatAbs:
            case MintOp::kFloatNeg:
                if (d.size != a.size) report(i, "floating-point unary width disagrees");
                break;
            case MintOp::kFloatCmp:
                if (d.size != 4) report(i, "packed floating-point flags are not 4 bytes");
                if (a.size != b.size) report(i, "floating-point compare widths disagree");
                break;
            case MintOp::kIntToFloat:
            case MintOp::kIntToFloatU:
            case MintOp::kFloatToInt:
            case MintOp::kFloatToIntU:
            case MintOp::kFloatConvert:
                if (d.size == 0 || a.size == 0) report(i, "invalid conversion width");
                break;
            case MintOp::kVectorShuffle:
                if (d.size != 16 || a.size != 16 || b.size != 16 || c.size != 16) {
                    report(i, "vector shuffle operands are not 128 bits");
                }
                break;
            case MintOp::kVectorPermute:
                if (d.size != 16 || a.size != 16) {
                    report(i, "vector permute operands are not 128 bits");
                }
                checkLaneWidth(insn, i);
                break;
            case MintOp::kVectorSplat:
                if (d.size != 16) report(i, "vector splat destination is not 128 bits");
                break;
            case MintOp::kVectorLoad:
                if (d.size != 16 || a.size != pointerWidth) report(i, "invalid vector load widths");
                break;
            case MintOp::kVectorStore:
                if (a.size != pointerWidth || b.size != 16) report(i, "invalid vector store widths");
                break;
            case MintOp::kVectorBit:
            case MintOp::kVectorBif:
                if (d.size != 16 || a.size != 16 || b.size != 16 || c.size != 16) {
                    report(i, "vector bitwise operands are not 128 bits");
                }
                break;
            case MintOp::kZeroExt:
            case MintOp::kSignExt:
                if (d.size <= a.size) report(i, "extension does not widen");
                break;
            case MintOp::kTrunc:
                if (d.size >= a.size) report(i, "truncation does not narrow");
                break;
            case MintOp::kSelect:
                if (a.size != 1) report(i, "condition is not 1 byte");
                if (d.size != b.size || b.size != c.size) {
                    report(i, "select arms differ in width");
                }
                break;
            case MintOp::kBranch:
            case MintOp::kCall:
                if (!a.isConstant()) report(i, "direct transfer target is not constant");
                break;
            case MintOp::kCondBranch:
                if (a.size != 1) report(i, "branch condition is not 1 byte");
                if (!b.isConstant()) report(i, "branch target is not constant");
                break;
            default:
                break;
        }
    }

    // Blocks must tile the instruction list exactly. A gap or an overlap means the
    // lifter and the CFG disagree about what it produced, and every pass above
    // walks blocks rather than the flat list, so the mismatch would show up as
    // quietly missing code.
    u32 expected = 0;
    for (size_t bi = 0; bi < blocks.size(); ++bi) {
        const IrBlock& block = blocks[bi];
        if (block.firstInsn != expected) {
            problems.push_back("block " + std::to_string(bi) + " starts at insn " +
                               std::to_string(block.firstInsn) + ", expected " +
                               std::to_string(expected));
        }
        if (u64(block.firstInsn) + block.insnCount > insns.size()) {
            problems.push_back("block " + std::to_string(bi) + " runs past the end");
            break;
        }
        for (u32 j = 0; j < block.insnCount; ++j) {
            const u32 index = block.firstInsn + j;
            if (isTerminator(insns[index].op) && j + 1 != block.insnCount) {
                problems.push_back("block " + std::to_string(bi) + " has a " +
                                   opName(insns[index].op) +
                                   " before its last instruction");
            }
        }
        for (u32 successor : block.successors) {
            if (successor >= blocks.size()) {
                problems.push_back("block " + std::to_string(bi) +
                                   " has out-of-range successor " +
                                   std::to_string(successor));
            }
        }
        expected += block.insnCount;
    }
    if (!blocks.empty() && expected != insns.size()) {
        problems.push_back("blocks cover " + std::to_string(expected) + " of " +
                           std::to_string(insns.size()) + " instructions");
    }

    return problems;
}

std::string IrFunction::toText() const {
    std::string out;
    out += name.empty() ? formatAddress(entry) : name;
    out += "  (" + std::to_string(machineInsnCount) + " machine insns -> " +
           std::to_string(insns.size()) + " ir ops";
    if (intrinsicCount != 0) {
        out += ", " + std::to_string(intrinsicCount) + " unmodelled";
    }
    out += ")\n";

    auto renderInsn = [&](const IrInsn& insn) {
        const OpInfo& info = opInfo(insn.op);
        std::string line = "    ";
        if (info.hasDest) {
            line += describeVarnode(insn.dest, arch);
            line += " = ";
        }
        line += info.name;
        for (unsigned slot = 0; slot < info.sources; ++slot) {
            line += slot == 0 ? " " : ", ";
            line += describeVarnode(insn.source(slot), arch);
        }
        if (insn.op == MintOp::kIntrinsic) {
            line += " #" + std::to_string(insn.intrinsicId);
        }
        return line;
    };

    if (blocks.empty()) {
        for (const IrInsn& insn : insns) out += renderInsn(insn) + "\n";
        return out;
    }

    Address lastAddress = kNoAddress;
    for (const IrBlock& block : blocks) {
        char header[128];
        std::snprintf(header, sizeof(header), "  block %u [0x%llx..0x%llx)",
                      block.id, static_cast<unsigned long long>(block.start),
                      static_cast<unsigned long long>(block.end));
        out += header;
        if (!block.successors.empty()) {
            out += " ->";
            for (u32 successor : block.successors) {
                out += " " + std::to_string(successor);
            }
        }
        out += "\n";

        for (u32 j = 0; j < block.insnCount; ++j) {
            const IrInsn& insn = insns[block.firstInsn + j];
            // Print the machine address once per group, so the mapping between a
            // machine instruction and the ops it expanded to stays readable.
            if (insn.address != lastAddress) {
                out += "   " + formatAddress(insn.address) + ":\n";
                lastAddress = insn.address;
            }
            out += renderInsn(insn) + "\n";
        }
    }
    return out;
}

}  // namespace mint
