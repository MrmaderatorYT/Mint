#include "mint/decompile/expr_builder.h"

#include <cstdio>

#include "mint/ir/ir_op.h"
#include "mint/ir/registers.h"

namespace {
/// C has no `uint128_t`; the compiler builtin is the only spelling for the width a
/// vector register occupies.
std::string unsignedType(unsigned bytes) {
    return bytes == 16 ? "__uint128_t" : "uint" + std::to_string(bytes * 8) + "_t";
}
}  // namespace

namespace mint {
namespace {

const char* symbol(MintOp op) {
    switch (op) {
        case MintOp::kAdd: return "+"; case MintOp::kSub: return "-"; case MintOp::kMul: return "*";
        case MintOp::kAnd: return "&"; case MintOp::kOr: return "|"; case MintOp::kXor: return "^";
        case MintOp::kShl: return "<<"; case MintOp::kShrU: case MintOp::kShrS: return ">>";
        case MintOp::kEqual: return "=="; case MintOp::kNotEqual: return "!=";
        case MintOp::kLessU: case MintOp::kLessS: return "<";
        case MintOp::kLessEqU: case MintOp::kLessEqS: return "<=";
        default: return nullptr;
    }
}

/// Operations whose value depends only on their operands, and which can therefore be
/// moved to the point of use without changing what the program computes.
bool isPure(MintOp op) {
    switch (op) {
        case MintOp::kLoad:
        case MintOp::kStore:
        case MintOp::kCall:
        case MintOp::kCallInd:
        case MintOp::kIntrinsic:
        case MintOp::kUndefined:
        case MintOp::kAtomicLoad:case MintOp::kAtomicStore:case MintOp::kAtomicExchange:case MintOp::kAtomicAdd:case MintOp::kAtomicCompareExchange:
        case MintOp::kVectorLoad:case MintOp::kVectorStore:
            return false;
        default:
            return !isTerminator(op);
    }
}

}  // namespace

std::string ExprBuilder::name(SsaId id) const {
    if (id == kNoValue || id >= function_.values.size()) return "?";
    const auto override = names_.find(id);
    if (override != names_.end()) return override->second;
    const SsaValue& v = function_.values[id];
    if (v.def == SsaDef::kConstant) {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "0x%llx",
                      static_cast<unsigned long long>(v.storage.offset));
        return buffer;
    }
    if (v.def == SsaDef::kEntry) {
        // An incoming value is worth naming after the register it arrived in: `in_x30`
        // says "the caller's link register", where a bare offset says nothing.
        if (v.storage.space == Space::kRegister) {
            return "in_" + registerName(function_.arch, v.storage.offset, v.storage.size);
        }
        return "in_" + std::to_string(v.storage.offset);
    }
    return "v" + std::to_string(id);
}

bool ExprBuilder::needsStatement(SsaId id) const {
    if (id == kNoValue || id >= function_.values.size()) return false;
    const SsaValue& v = function_.values[id];
    if (v.def != SsaDef::kInsn) return false;
    if (v.uses == 0) return false;
    if (v.defIndex >= function_.insns.size()) return false;
    return materialized_.count(id) || v.uses > 1 || !isPure(function_.insns[v.defIndex].op);
}

std::string ExprBuilder::value(SsaId id) {
    if (id == kNoValue || id >= function_.values.size()) return "/*invalid*/0";
    const SsaValue& v = function_.values[id];
    if (v.def == SsaDef::kConstant || v.def == SsaDef::kEntry || v.def == SsaDef::kPhi) {
        // Machine address arithmetic counts bytes, not C pointed-to elements.
        if(numericPointers_.count(id))return "((uintptr_t)"+name(id)+")";
        return name(id);
    }
    if (needsStatement(id)) return numericPointers_.count(id) ? "((uintptr_t)"+name(id)+")" : name(id);
    // A cycle can only be reached through a phi, which is handled above, but the guard
    // stays: emitting an expression that contains itself would hang rather than fail.
    if (!visiting_.insert(id).second) return name(id);
    std::string result = name(id);
    if (v.def == SsaDef::kInsn && v.defIndex < function_.insns.size()) {
        result = operation(function_.insns[v.defIndex]);
    }
    visiting_.erase(id);
    return result;
}

std::string ExprBuilder::operation(const SsaInsn& insn) {
    const std::string a = value(insn.use[0]);
    const std::string b = value(insn.use[1]);
    const std::string c = value(insn.use[2]);
    if (insn.op == MintOp::kCopy) return a;
    if (insn.op == MintOp::kNeg) return "(-" + a + ")";
    if (insn.op == MintOp::kNot) return "(~" + a + ")";
    if (insn.op == MintOp::kLoad) {
        // A recovered field reads as itself; the cast and the arithmetic are what
        // the field name replaces.
        const std::string field = fieldAccess(insn.use[0]);
        if (!field.empty()) return field;
        const u8 width = insn.dest != kNoValue && insn.dest < function_.values.size()
                             ? function_.values[insn.dest].storage.size
                             : 8;
        return "*(" + unsignedType(width) + "*)" + a;
    }
    if(insn.op==MintOp::kAtomicLoad)return "__atomic_load_n(("+unsignedType(valueWidth(insn.dest))+"*)(uintptr_t)("+a+"), __ATOMIC_ACQUIRE)";
    if(insn.op==MintOp::kAtomicExchange || insn.op==MintOp::kAtomicAdd)return std::string(insn.op==MintOp::kAtomicExchange?"__atomic_exchange_n((":"__atomic_fetch_add((")+unsignedType(valueWidth(insn.dest))+"*)(uintptr_t)("+a+"), "+b+", __ATOMIC_SEQ_CST)";
    if (insn.op == MintOp::kSelect) return "(" + a + " ? " + b + " : " + c + ")";
    if (insn.op == MintOp::kSignExt) {
        return "((int64_t)(int" + std::to_string(unsigned(valueWidth(insn.use[0])) * 8) +
               "_t)" + a + ")";
    }
    if (insn.op == MintOp::kZeroExt || insn.op == MintOp::kTrunc) {
        const u8 width = insn.dest != kNoValue && insn.dest < function_.values.size()
                             ? function_.values[insn.dest].storage.size
                             : 8;
        return "((" + unsignedType(width) + ")" + a + ")";
    }
    if (const char* op = symbol(insn.op)) return "(" + a + " " + op + " " + b + ")";
    if (insn.op == MintOp::kCall || insn.op == MintOp::kCallInd) return "call(" + a + ")";

    // Everything with no operator spelling — carry and overflow tests, rotates,
    // count-leading-zeros, the multiply-high pair — becomes a named helper rather
    // than a bare identifier. Returning the destination's name here was silently
    // producing C that referenced a variable nothing declared or assigned.
    std::string call = "op_" + std::string(opName(insn.op)) + "(";
    const unsigned arity = opInfo(insn.op).sources;
    for (unsigned slot = 0; slot < arity; ++slot) {
        if (slot != 0) call += ", ";
        call += slot == 0 ? a : (slot == 1 ? b : c);
    }
    return call + ")";
}

u8 ExprBuilder::valueWidth(SsaId id) const {
    if (id == kNoValue || id >= function_.values.size()) return 8;
    return function_.values[id].storage.size;
}

std::string ExprBuilder::instruction(const SsaInsn& insn) { return operation(insn); }

}  // namespace mint
