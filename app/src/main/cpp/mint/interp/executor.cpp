#include "mint/interp/executor.h"

#include <cstring>


#include "mint/ir/registers.h"

namespace mint {
namespace {

u64 maskFor(u8 width) {
    if (width >= 8) return ~u64(0);
    return (u64(1) << (width * 8)) - 1;
}

InterpValue unknownLike(const Varnode& node) { return InterpValue::unknown(node.size); }

InterpValue binary(MintOp op, const InterpValue& a, const InterpValue& b, u8 width) {
    if (!a.concreteLike() || !b.concreteLike()) return InterpValue::unknown(width);
    const u64 m = maskFor(width);
    const u64 av = a.bits & m;
    const u64 bv = b.bits & m;
    switch (op) {
        case MintOp::kAdd: return InterpValue::concrete((av + bv) & m, width);
        case MintOp::kSub: return InterpValue::concrete((av - bv) & m, width);
        case MintOp::kMul: return InterpValue::concrete((av * bv) & m, width);
        case MintOp::kMulHiU: return InterpValue::concrete(static_cast<u64>((static_cast<unsigned __int128>(av) * bv) >> (width * 8)), width);
        case MintOp::kDivU: return bv == 0 ? InterpValue::unknown(width) : InterpValue::concrete(av / bv, width);
        case MintOp::kRemU: return bv == 0 ? InterpValue::unknown(width) : InterpValue::concrete(av % bv, width);
        case MintOp::kDivS: {
            if (bv == 0) return InterpValue::unknown(width);
            const u64 sign = u64(1) << (width * 8 - 1);
            const i64 as = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            const i64 bs = (bv & sign) ? static_cast<i64>(bv | ~m) : static_cast<i64>(bv);
            return InterpValue::concrete(static_cast<u64>(as / bs) & m, width);
        }
        case MintOp::kRemS: {
            if (bv == 0) return InterpValue::unknown(width);
            const u64 sign = u64(1) << (width * 8 - 1);
            const i64 as = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            const i64 bs = (bv & sign) ? static_cast<i64>(bv | ~m) : static_cast<i64>(bv);
            return InterpValue::concrete(static_cast<u64>(as % bs) & m, width);
        }
        case MintOp::kAnd: return InterpValue::concrete(av & bv, width);
        case MintOp::kOr: return InterpValue::concrete(av | bv, width);
        case MintOp::kXor: return InterpValue::concrete(av ^ bv, width);
        case MintOp::kShl: return InterpValue::concrete((av << (bv & 63)) & m, width);
        case MintOp::kShrU: return InterpValue::concrete(av >> (bv & 63), width);
        case MintOp::kShrS: {
            const u64 sign = u64(1) << (width * 8 - 1);
            const i64 signedA = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            return InterpValue::concrete(static_cast<u64>(signedA >> (bv & 63)) & m, width);
        }
        case MintOp::kRotL: { const u32 shift = static_cast<u32>(bv & (width * 8 - 1)); return InterpValue::concrete(shift ? ((av << shift) | (av >> (width * 8 - shift))) & m : av, width); }
        case MintOp::kRotR: { const u32 shift = static_cast<u32>(bv & (width * 8 - 1)); return InterpValue::concrete(shift ? ((av >> shift) | (av << (width * 8 - shift))) & m : av, width); }
        case MintOp::kEqual: return InterpValue::concrete(av == bv, 1);
        case MintOp::kNotEqual: return InterpValue::concrete(av != bv, 1);
        case MintOp::kLessU: return InterpValue::concrete(av < bv, 1);
        case MintOp::kLessEqU: return InterpValue::concrete(av <= bv, 1);
        case MintOp::kLessS: {
            const u64 sign = u64(1) << (width * 8 - 1);
            const i64 as = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            const i64 bs = (bv & sign) ? static_cast<i64>(bv | ~m) : static_cast<i64>(bv);
            return InterpValue::concrete(as < bs, 1);
        }
        case MintOp::kLessEqS: {
            const u64 sign = u64(1) << (width * 8 - 1);
            const i64 as = (av & sign) ? static_cast<i64>(av | ~m) : static_cast<i64>(av);
            const i64 bs = (bv & sign) ? static_cast<i64>(bv | ~m) : static_cast<i64>(bv);
            return InterpValue::concrete(as <= bs, 1);
        }
        default: return InterpValue::unknown(width);
    }
}

u32 blockForAddress(const IrFunction& function, Address address) {
    for (const IrBlock& block : function.blocks) if (block.start == address) return block.id;
    return ~u32(0);
}

}  // namespace

Status executeIr(const IrFunction& function, InterpState* state,
                 const InterpOptions& options, InterpResult* result) {
    if (!state || !result) return Status::error(ErrorCode::kInternalError, "null interpreter output");
    *result = {};
    if (function.blocks.empty()) return Status::error(ErrorCode::kBadFormat, "IR function has no blocks");
    if (state->arch() != function.arch) state->reset(function.arch);

    u32 blockId = 0;
    for (const IrBlock& block : function.blocks) if (block.start == function.entry) { blockId = block.id; break; }
    u32 steps = 0;
    while (steps++ < options.maxSteps && blockId < function.blocks.size()) {
        const IrBlock& block = function.blocks[blockId];
        bool advanced = false;
        for (u32 i = 0; i < block.insnCount; ++i) {
            const IrInsn& insn = function.insns[block.firstInsn + i];
            const InterpValue a = state->read(insn.a);
            const InterpValue b = state->read(insn.b);
            const InterpValue c = state->read(insn.c);
            InterpValue value = unknownLike(insn.dest);
            switch (insn.op) {
                case MintOp::kCopy: value = a; break;
                case MintOp::kLoad:
                    value = a.concreteLike() ? state->memory().read(a.bits, insn.dest.size) : unknownLike(insn.dest);
                    break;
                case MintOp::kStore:
                    if (a.concreteLike()) state->memory().write(a.bits, b, insn.b.size);
                    break;
                case MintOp::kNeg:
                    value = a.concreteLike() ? InterpValue::concrete((~a.bits + 1) & maskFor(insn.dest.size), insn.dest.size) : unknownLike(insn.dest);
                    break;
                case MintOp::kNot:
                    value = a.concreteLike() ? InterpValue::concrete(~a.bits & maskFor(insn.dest.size), insn.dest.size) : unknownLike(insn.dest);
                    break;
                case MintOp::kZeroExt:
                    value = a.concreteLike() ? InterpValue::concrete(a.bits, insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kSignExt: {
                    if (a.concreteLike()) {
                        const u64 am = maskFor(a.width); const u64 sign = u64(1) << (a.width * 8 - 1);
                        value = InterpValue::concrete((a.bits & sign) ? (a.bits | ~am) : a.bits, insn.dest.size);
                    }
                    break;
                }
                case MintOp::kTrunc: value = a.concreteLike() ? InterpValue::concrete(a.bits, insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kAnd: case MintOp::kOr: case MintOp::kXor: case MintOp::kAdd: case MintOp::kSub:
                case MintOp::kMul: case MintOp::kMulHiU: case MintOp::kDivU: case MintOp::kDivS: case MintOp::kRemU: case MintOp::kRemS:
                case MintOp::kShl: case MintOp::kShrU: case MintOp::kShrS: case MintOp::kRotL: case MintOp::kRotR:
                case MintOp::kEqual: case MintOp::kNotEqual: case MintOp::kLessU: case MintOp::kLessS:
                case MintOp::kLessEqU: case MintOp::kLessEqS:
                    value = binary(insn.op, a, b, insn.dest.size); break;
                case MintOp::kSelect: {
                    bool known = false; const bool take = interpBool(a, &known);
                    value = known ? (take ? b : c) : unknownLike(insn.dest); break;
                }
                case MintOp::kCall: case MintOp::kCallInd: {
                    InterpCall call;
                    call.target = a.concreteLike() ? a.bits : kNoAddress;
                    call.address = insn.address;
                    call.arguments.push_back(state->registerValue(0, 8));
                    call.arguments.push_back(state->registerValue(8, 8));
                    result->calls.push_back(call);
                    if (options.stopOnCall) {
                        result->stoppedOnCall = true; result->stopReason = "call"; return Status::success();
                    }
                    break;
                }
                case MintOp::kPopCount:
                    value = a.concreteLike() ? InterpValue::concrete(static_cast<u64>(__builtin_popcountll(a.bits & maskFor(a.width))), insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kClz:
                    value = a.concreteLike() ? InterpValue::concrete(a.bits ? static_cast<u64>(__builtin_clzll(a.bits) - (8 - a.width) * 8) : a.width * 8, insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kCtz:
                    value = a.concreteLike() ? InterpValue::concrete(a.bits ? static_cast<u64>(__builtin_ctzll(a.bits)) : a.width * 8, insn.dest.size) : unknownLike(insn.dest); break;
                case MintOp::kReturn:
                    result->returned = true; result->returnValue = insn.a.valid() ? state->read(insn.a) : state->registerValue(0, 8);
                    result->stopReason = "return"; return Status::success();
                case MintOp::kCondBranch: {
                    bool known = false; const bool take = interpBool(a, &known);
                    u32 target = b.concreteLike() ? blockForAddress(function, b.bits) : ~u32(0);
                    if (known && take && target != ~u32(0)) blockId = target;
                    else if (known && !take && !block.successors.empty()) blockId = block.successors.back();
                    else if (!known && !block.successors.empty()) { result->hitUnknownBranch = true; blockId = block.successors.back(); }
                    else { result->stopReason = "unresolved conditional branch"; return Status::success(); }
                    advanced = true; break;
                }
                case MintOp::kBranch: {
                    const u32 target = a.concreteLike() ? blockForAddress(function, a.bits) : ~u32(0);
                    if (target == ~u32(0)) { result->stopReason = "unresolved branch"; return Status::success(); }
                    blockId = target; advanced = true; break;
                }
                case MintOp::kBranchInd: {
                    const u32 target = a.concreteLike() ? blockForAddress(function, a.bits) : ~u32(0);
                    if (target == ~u32(0)) { result->stopReason = "indirect branch"; return Status::success(); }
                    blockId = target; advanced = true; break;
                }
                case MintOp::kIntrinsic: case MintOp::kUndefined: break;
                default: break;
            }
            if (insn.dest.valid() && insn.dest.space != Space::kInvalid && insn.op != MintOp::kStore) state->write(insn.dest, value);
            if (advanced) break;
        }
        if (!advanced) {
            if (block.successors.empty()) { result->stopReason = "block exit"; return Status::success(); }
            blockId = block.successors.front();
        }
    }
    result->hitCycleLimit = true;
    result->stopReason = "step limit";
    return Status::success();
}

}  // namespace mint
