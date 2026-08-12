#include "mint/ir/ir_op.h"

namespace mint {
namespace {

// name, sources, hasDest, terminator
constexpr OpInfo kTable[] = {
    {"invalid", 0, false, false},

    {"copy", 1, true, false},
    {"load", 1, true, false},
    {"store", 2, false, false},

    {"add", 2, true, false},
    {"sub", 2, true, false},
    {"mul", 2, true, false},
    {"mulhiu", 2, true, false},
    {"mulhis", 2, true, false},
    {"divu", 2, true, false},
    {"divs", 2, true, false},
    {"remu", 2, true, false},
    {"rems", 2, true, false},
    {"divwideu", 3, true, false},
    {"divwides", 3, true, false},
    {"remwideu", 3, true, false},
    {"remwides", 3, true, false},
    {"neg", 1, true, false},

    {"and", 2, true, false},
    {"or", 2, true, false},
    {"xor", 2, true, false},
    {"not", 1, true, false},
    {"shl", 2, true, false},
    {"shru", 2, true, false},
    {"shrs", 2, true, false},
    {"rotl", 2, true, false},
    {"rotr", 2, true, false},

    {"eq", 2, true, false},
    {"ne", 2, true, false},
    {"ltu", 2, true, false},
    {"lts", 2, true, false},
    {"leu", 2, true, false},
    {"les", 2, true, false},

    {"zext", 1, true, false},
    {"sext", 1, true, false},
    {"trunc", 1, true, false},

    {"carry", 2, true, false},
    {"borrow", 2, true, false},
    {"ovfadd", 2, true, false},
    {"ovfsub", 2, true, false},

    {"popcount", 1, true, false},
    {"clz", 1, true, false},
    {"ctz", 1, true, false},

    {"fadd", 2, true, false},
    {"fsub", 2, true, false},
    {"fmul", 2, true, false},
    {"fdiv", 2, true, false},
    {"fsqrt", 1, true, false},
    {"fabs", 1, true, false},
    {"fneg", 1, true, false},
    {"fcmp", 2, true, false},
    {"inttof", 1, true, false},
    {"ftoint", 1, true, false},
    {"vadd", 2, true, false},
    {"vsub", 2, true, false},
    {"vmul", 2, true, false},
    {"vmulwideu", 2, true, false},
    {"vmulwides", 2, true, false},
    {"vcmpeq", 2, true, false},
    {"vcmpgts", 2, true, false},
    {"vminu", 2, true, false},
    {"vmins", 2, true, false},
    {"vmaxu", 2, true, false},
    {"vmaxs", 2, true, false},
    {"vshl", 2, true, false},
    {"vshru", 2, true, false},
    {"vshrs", 2, true, false},
    {"vpacks", 2, true, false},
    {"vpacku", 2, true, false},
    {"vextends", 1, true, false},
    {"vextendu", 1, true, false},
    {"vinsert", 3, true, false},
    {"vextract", 2, true, false},
    {"vselect", 3, true, false},
    {"vshuffle", 3, true, false},
    {"vpermute", 2, true, false},
    {"vsplat", 1, true, false},
    {"vload", 1, true, false},
    {"vstore", 2, false, false},
    {"vbit", 3, true, false},
    {"vbif", 3, true, false},

    {"select", 3, true, false},

    {"branch", 1, false, true},
    {"cbranch", 2, false, true},
    {"branchind", 1, false, true},
    // A call is not a terminator: flow returns and continues at the next
    // instruction, so a block does not end here. This matches the machine-level
    // FlowKind, and the two must agree or IR blocks would stop mirroring machine
    // blocks — which every pass above assumes.
    {"call", 1, false, false},
    {"callind", 1, false, false},
    {"return", 1, false, true},

    {"intrinsic", 0, false, false},
    {"undefined", 0, true, false},
    {"trap", 0, false, true},

    {"feq", 2, true, false},
    {"flt", 2, true, false},
    {"funord", 2, true, false},
};

static_assert(sizeof(kTable) / sizeof(kTable[0]) ==
                  static_cast<size_t>(MintOp::kFloatUnordered) + 1,
              "the opcode table must have exactly one entry per MintOp");

}  // namespace

unsigned opCount() {
    return static_cast<unsigned>(sizeof(kTable) / sizeof(kTable[0]));
}

const OpInfo& opInfo(MintOp op) {
    const auto index = static_cast<size_t>(op);
    if (index >= sizeof(kTable) / sizeof(kTable[0])) return kTable[0];
    return kTable[index];
}

bool producesBoolean(MintOp op) {
    switch (op) {
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
            return true;
        default:
            return false;
    }
}

}  // namespace mint
