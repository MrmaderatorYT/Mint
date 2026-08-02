#include "mint/decompile/c_emitter.h"

#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "mint/analysis/cfg.h"
#include "mint/ir/dominance.h"
#include "mint/ir/registers.h"
#include "mint/ir/type_recovery.h"

namespace mint {
namespace {

std::string blockLabel(u32 id) { return "block_" + std::to_string(id); }

/// A symbol name is not necessarily a C identifier — compiler-generated names such
/// as `__cxx_global_array_dtor.80` carry a dot — so anything outside the identifier
/// alphabet is replaced rather than passed through into the output.
std::string identifier(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_';
        out += ok ? c : '_';
    }
    if (out.empty() || (out[0] >= '0' && out[0] <= '9')) out.insert(out.begin(), '_');
    return out;
}

/// The registers a call's arguments arrive in, in convention order.
std::vector<Varnode> argumentRegisters(Arch arch) {
    std::vector<Varnode> out;
    if (arch == Arch::kAArch64) {
        for (unsigned n = 0; n <= 7; ++n) out.push_back(Varnode::reg(arm64::kXn(n), 8));
    } else if (arch == Arch::kX86_64) {
        for (u64 offset : {x86::kRdi, x86::kRsi, x86::kRdx, x86::kRcx,
                           x86::kGpr(8), x86::kGpr(9)}) {
            out.push_back(Varnode::reg(offset, 8));
        }
    }
    return out;
}

/// The register a return value comes back in.
Varnode returnRegister(Arch arch) {
    switch (arch) {
        case Arch::kAArch64: return Varnode::reg(arm64::kXn(0), 8);
        case Arch::kX86_64: return Varnode::reg(x86::kRax, 8);
        default: return Varnode::invalid();
    }
}

const char* typeName(RecoveredTypeKind kind, u8 width) {
    switch (kind) {
        case RecoveredTypeKind::kPointer: return "uintptr_t";
        case RecoveredTypeKind::kBoolean: return "bool";
        case RecoveredTypeKind::kFloat: return width == 4 ? "float" : "double";
        case RecoveredTypeKind::kSignedInteger:
            switch (width) {
                case 1: return "int8_t";
                case 2: return "int16_t";
                case 4: return "int32_t";
                default: return "int64_t";
            }
        default:
            switch (width) {
                case 1: return "uint8_t";
                case 2: return "uint16_t";
                case 4: return "uint32_t";
                case 16: return "__uint128_t";
                default: return "uint64_t";
            }
    }
}

/// The value of `unit` that reaches a point, by walking back through the block and
/// then up the dominator tree.
///
/// This is what a `ret` needs. The IR's return carries the return *address* — the
/// link register — because that is what the instruction reads; the return *value* is
/// whatever the convention's result register holds at that moment, and only a
/// reaching-definition query can say what that is. Printing the instruction's operand
/// instead produced `return in_x30`, which is the address the function returns to.
class ReachingDefs {
public:
    ReachingDefs(const SsaFunction& function, const Dominance& dominance)
        : function_(function), dominance_(dominance) {}

    SsaId at(u32 block, u32 insnLimit, const Varnode& unit) const {
        while (block < function_.blocks.size()) {
            const SsaBlock& current = function_.blocks[block];
            for (u32 i = insnLimit; i > current.firstInsn; --i) {
                const SsaInsn& insn = function_.insns[i - 1];
                if (matches(insn.dest, unit)) return insn.dest;
                for (SsaId clobber : insn.clobbers) {
                    if (matches(clobber, unit)) return clobber;
                }
            }
            for (u32 phiIndex : current.phis) {
                const SsaPhi& phi = function_.phis[phiIndex];
                if (!phi.dead && matches(phi.dest, unit)) return phi.dest;
            }
            if (!dominance_.reachable(block)) break;
            const u32 parent = dominance_.idom[block];
            if (parent == block || parent >= function_.blocks.size()) break;
            block = parent;
            insnLimit = function_.blocks[block].firstInsn + function_.blocks[block].insnCount;
        }
        return kNoValue;
    }

private:
    bool matches(SsaId id, const Varnode& unit) const {
        if (id == kNoValue || id >= function_.values.size()) return false;
        return function_.values[id].storage == unit;
    }

    const SsaFunction& function_;
    const Dominance& dominance_;
};

}  // namespace

std::string emitC(const SsaFunction& function, const ControlFlowStructure& structure,
                  const CEmitterOptions& options) {
    std::ostringstream out;
    ExprBuilder expr(function);

    std::vector<std::vector<u32>> graph(function.blocks.size());
    for (size_t i = 0; i < function.blocks.size(); ++i) {
        graph[i] = function.blocks[i].successors;
    }
    const Dominance dominance = computeDominance(graph);
    const ReachingDefs reaching(function, dominance);

    // A conservative structured subset is still valuable: only turn a natural
    // loop into `while` when its header/body/latch are contiguous in the SSA
    // block order and it has one exit. Irreducible and multi-exit regions keep
    // the labelled fallback below, so this pass never trades a real edge for a
    // pretty but incorrect loop.
    struct SimpleLoop { u32 body = kNoBlock; u32 exit = kNoBlock; };
    struct PostTestLoop {
        u32 header = kNoBlock;
        u32 exit = kNoBlock;
        bool takenReturnsToHeader = false;
    };
    std::unordered_map<u32, SimpleLoop> simpleLoops;
    std::unordered_map<u32, u32> simpleLatches;
    std::unordered_map<u32, PostTestLoop> postTestLatches;
    std::unordered_map<u32, u32> postTestHeaders;
    std::unordered_map<u32, u32> latchesPerHeader;
    for (const NaturalLoop& loop : structure.loops) ++latchesPerHeader[loop.header];
    for (const NaturalLoop& loop : structure.loops) {
        if (loop.body.size() < 2 || loop.exits.size() != 1 || loop.header >= function.blocks.size() ||
            loop.latch >= function.blocks.size()) continue;
        // Several back edges to one header form one multi-latch loop, not several
        // independently nestable do-while statements. Closing each candidate
        // separately produces unmatched braces and, worse, wrong edge semantics.
        if (latchesPerHeader[loop.header] != 1) continue;
        const u32 first = *std::min_element(loop.body.begin(), loop.body.end());
        const u32 last = *std::max_element(loop.body.begin(), loop.body.end());
        if (first != loop.header || last != loop.latch || last - first + 1 != loop.body.size()) continue;
        if (loop.exits.front() != last + 1) continue;
        bool contiguous = true;
        for (u32 id = first; id <= last; ++id) {
            if (std::find(loop.body.begin(), loop.body.end(), id) == loop.body.end()) { contiguous = false; break; }
        }
        if (!contiguous) continue;
        const SsaBlock& latchBlock = function.blocks[loop.latch];
        if (latchBlock.insnCount == 0) continue;
        const MintOp latchEnd =
                function.insns[latchBlock.firstInsn + latchBlock.insnCount - 1].op;

        // A conditional latch is the canonical post-test form:
        //
        //   do { body } while (condition);
        //
        // One successor returns to the header and the other is the single,
        // contiguous exit. Store it separately because the edge phi copies must
        // run before the next iteration/after the final iteration respectively.
        if (latchEnd == MintOp::kCondBranch &&
            latchBlock.successors.size() == 2) {
            const u32 taken = latchBlock.successors.front();
            const u32 fall = latchBlock.successors.back();
            const bool takenBack = taken == loop.header && fall == loop.exits.front();
            const bool fallBack = fall == loop.header && taken == loop.exits.front();
            if (takenBack || fallBack) {
                postTestLatches.emplace(
                    loop.latch,
                    PostTestLoop{loop.header, loop.exits.front(), takenBack});
                postTestHeaders.emplace(loop.header, loop.latch);
                continue;
            }
        }

        if (function.blocks[first].successors.size() != 2) continue;
        u32 body = kNoBlock;
        for (u32 successor : function.blocks[first].successors) {
            if (std::find(loop.body.begin(), loop.body.end(), successor) != loop.body.end() && successor != first) {
                body = successor;
            }
        }
        if (body != first + 1) continue;
        if (latchEnd != MintOp::kBranch) continue;
        simpleLoops.emplace(loop.header, SimpleLoop{body, loop.exits.front()});
        simpleLatches.emplace(loop.latch, loop.header);
    }

    TypeRecovery types;
    recoverTypes(function, &types);
    auto kindOf = [&](SsaId id) {
        return id < types.values.size() ? types.values[id].kind : RecoveredTypeKind::kUnknown;
    };
    auto widthOf = [&](SsaId id) {
        return id < function.values.size() ? function.values[id].storage.size : u8(8);
    };

    std::unordered_set<SsaId> parameters;
    for (size_t i = 0; i < types.parameters.size(); ++i) {
        const SsaId id = types.parameters[i].value;
        parameters.insert(id);
        expr.setName(id, "a_" + registerName(function.arch, function.values[id].storage.offset,
                                             function.values[id].storage.size));
    }

    // Does the function produce a value? Only a definition of the result register
    // that reaches a return says so; a function that never writes it returns nothing.
    const Varnode result = returnRegister(function.arch);

    // Recorded by the builder, which knew the reaching definition without having to
    // search for it. A value that is merely the caller's incoming register means the
    // function never set a result, so it is not returning one.
    bool returnsValue = false;
    auto returnValueAt = [&](u32 index) {
        for (const auto& entry : function.returnValues) {
            if (entry.first != index) continue;
            const SsaId id = entry.second;
            if (id == kNoValue || id >= function.values.size()) return kNoValue;
            if (function.values[id].def == SsaDef::kEntry) return kNoValue;
            return id;
        }
        return kNoValue;
    };
    for (const auto& entry : function.returnValues) {
        if (returnValueAt(entry.first) != kNoValue) returnsValue = true;
    }

    out << "/* Mint pseudo-C; irreducible edges remain explicit labels. */\n";
    if (options.includeComments) {
        out << "/* loops: " << structure.loops.size() << ", switch-like blocks: "
            << structure.switchBlocks.size() << " */\n";
    }

    const std::string returnType =
        returnsValue ? typeName(RecoveredTypeKind::kUnknown, 8) : "void";
    out << returnType << " "
        << (function.name.empty() ? "sub_" + std::to_string(function.entry)
                                  : identifier(function.name))
        << "(";
    if (types.parameters.empty()) {
        out << "void";
    } else {
        for (size_t i = 0; i < types.parameters.size(); ++i) {
            const SsaId id = types.parameters[i].value;
            if (i != 0) out << ", ";
            out << typeName(kindOf(id), widthOf(id)) << " " << expr.name(id);
        }
    }
    out << ") {\n";

    // Locals: everything that gets a statement, every phi result, and every incoming
    // value that is not a parameter — the last of those are reads of caller state the
    // convention does not define, so they are declared and left uninitialised on
    // purpose rather than quietly turned into zero.
    for (SsaId id = 0; id < function.values.size(); ++id) {
        const SsaValue& value = function.values[id];
        if (parameters.count(id) != 0) continue;
        const bool wanted = (value.def == SsaDef::kEntry && value.uses != 0) ||
                            (value.def == SsaDef::kPhi && value.uses != 0) ||
                            expr.needsStatement(id);
        if (!wanted) continue;
        out << "    " << typeName(kindOf(id), widthOf(id)) << " " << expr.name(id) << ";\n";
    }
    for (const auto& entry : postTestLatches) {
        out << "    bool loop_condition_" << entry.first << ";\n";
    }

    // Phi arguments are copied on the edge that carries them. Both halves run before
    // any destination is written, because phis at one join take effect together: a
    // pair that swaps two values would otherwise see the first copy clobber the input
    // the second one still needs.
    auto emitEdgeCopies = [&](const SsaBlock& from, u32 successor) {
        if (successor >= function.blocks.size()) return;
        const SsaBlock& target = function.blocks[successor];
        size_t slot = target.predecessors.size();
        for (size_t i = 0; i < target.predecessors.size(); ++i) {
            if (target.predecessors[i] == from.id) {
                slot = i;
                break;
            }
        }
        if (slot >= target.predecessors.size()) return;
        std::vector<std::pair<std::string, std::string>> copies;
        for (u32 phiIndex : target.phis) {
            const SsaPhi& phi = function.phis[phiIndex];
            if (phi.dead || phi.dest == kNoValue || slot >= phi.args.size()) continue;
            if (function.values[phi.dest].uses == 0) continue;
            copies.push_back({expr.name(phi.dest), expr.value(phi.args[slot])});
        }
        if (copies.empty()) return;
        for (size_t i = 0; i < copies.size(); ++i) {
            out << "    uint64_t phi" << i << "_" << from.id << "_" << successor << " = "
                << copies[i].second << ";\n";
        }
        for (size_t i = 0; i < copies.size(); ++i) {
            out << "    " << copies[i].first << " = phi" << i << "_" << from.id << "_"
                << successor << ";\n";
        }
    };

    for (const SsaBlock& block : function.blocks) {
        out << "\n" << blockLabel(block.id) << ":;\n";
        if (postTestHeaders.count(block.id) != 0) out << "    do {\n";
        for (u32 i = 0; i < block.insnCount; ++i) {
            const u32 index = block.firstInsn + i;
            const SsaInsn& insn = function.insns[index];
            // Skipping a dead instruction is only safe when nothing reads its
            // result. The builder marks propagated copies dead after rewriting their
            // uses, but an instruction marked dead with live uses would leave those
            // uses pointing at a variable no statement ever assigns.
            if (insn.dead && (insn.dest == kNoValue ||
                              insn.dest >= function.values.size() ||
                              function.values[insn.dest].uses == 0)) {
                continue;
            }

            switch (insn.op) {
                case MintOp::kReturn: {
                    const SsaId value = returnValueAt(index);
                    if (value != kNoValue) {
                        out << "    return " << expr.value(value) << ";\n";
                    } else {
                        out << (returnsValue ? "    return 0;\n" : "    return;\n");
                    }
                    continue;
                }
                case MintOp::kBranch: {
                    const u32 target =
                        block.successors.empty() ? kNoBlock : block.successors.front();
                    const auto latch = simpleLatches.find(block.id);
                    if (latch != simpleLatches.end() && target == latch->second) {
                        emitEdgeCopies(block, target);
                        out << "    continue;\n}\n";
                        const auto loop = simpleLoops.find(latch->second);
                        if (loop != simpleLoops.end()) {
                            emitEdgeCopies(function.blocks[latch->second],
                                           loop->second.exit);
                        }
                        continue;
                    }
                    if (target != kNoBlock) emitEdgeCopies(block, target);
                    out << "    goto "
                        << (target == kNoBlock ? "unresolved_indirect" : blockLabel(target))
                        << ";\n";
                    continue;
                }
                case MintOp::kCondBranch: {
                    const auto postTest = postTestLatches.find(block.id);
                    if (postTest != postTestLatches.end()) {
                        const PostTestLoop& loop = postTest->second;
                        const std::string condition =
                            "loop_condition_" + std::to_string(block.id);
                        out << "    " << condition << " = "
                            << (loop.takenReturnsToHeader ? "" : "!(")
                            << expr.value(insn.use[0])
                            << (loop.takenReturnsToHeader ? "" : ")") << ";\n";
                        out << "    if (" << condition << ") {\n";
                        emitEdgeCopies(block, loop.header);
                        out << "    } else {\n";
                        emitEdgeCopies(block, loop.exit);
                        out << "    }\n";
                        out << "    } while (" << condition << ");\n";
                        continue;
                    }
                    const auto loop = simpleLoops.find(block.id);
                    if (loop != simpleLoops.end()) {
                        const bool bodyTaken = !block.successors.empty() &&
                            block.successors.front() == loop->second.body;
                        out << "    while (" << (bodyTaken ? "" : "!") << "(" <<
                            expr.value(insn.use[0]) << ")) {\n";
                        emitEdgeCopies(block, loop->second.body);
                        continue;
                    }
                    const u32 taken =
                        block.successors.empty() ? kNoBlock : block.successors.front();
                    const u32 fall =
                        block.successors.size() > 1 ? block.successors.back() : kNoBlock;
                    // Edge copies have to sit inside each arm: a copy emitted before
                    // the test would run on both paths.
                    out << "    if (" << expr.value(insn.use[0]) << ") {\n";
                    if (taken != kNoBlock) emitEdgeCopies(block, taken);
                    out << "        goto "
                        << (taken == kNoBlock ? "unresolved_indirect" : blockLabel(taken))
                        << ";\n    } else {\n";
                    if (fall != kNoBlock) emitEdgeCopies(block, fall);
                    out << "        goto "
                        << (fall == kNoBlock ? "unresolved_indirect" : blockLabel(fall))
                        << ";\n    }\n";
                    continue;
                }
                case MintOp::kBranchInd:
                    out << "    goto unresolved_indirect;  /* " << expr.value(insn.use[0])
                        << " */\n";
                    continue;
                case MintOp::kStore:
                    out << "    *(" << (widthOf(insn.use[1]) == 16 ? "__uint128_t" 
                            : "uint" + std::to_string(unsigned(widthOf(insn.use[1])) * 8) + "_t") << "*)"
                        << expr.value(insn.use[0]) << " = " << expr.value(insn.use[1])
                        << ";\n";
                    continue;
                case MintOp::kCall:
                case MintOp::kCallInd: {
                    // Arguments are whatever the argument registers hold here. How
                    // many there are is not knowable without the callee's prototype,
                    // so the count is taken as the longest run from the first
                    // argument register in which every one has been given a value
                    // inside this function. A register the function never wrote is
                    // holding the caller's leftovers, not an argument being passed —
                    // and once one is missing, the ones after it cannot be arguments
                    // either, because the convention fills them in order.
                    std::string arguments;
                    for (const Varnode& reg : argumentRegisters(function.arch)) {
                        const SsaId value = reaching.at(block.id, index, reg);
                        if (value == kNoValue) break;
                        if (function.values[value].def == SsaDef::kEntry) break;
                        if (!arguments.empty()) arguments += ", ";
                        arguments += expr.value(value);
                    }
                    // The call's result is the definition it makes of the result
                    // register, so that clobber is what receives it. The other
                    // clobbers are registers the callee is free to destroy: where
                    // something still reads one, it reads an unknown value, and
                    // saying so is better than leaving a variable that is declared
                    // and never assigned.
                    SsaId produced = kNoValue;
                    for (SsaId clobber : insn.clobbers) {
                        if (clobber < function.values.size() &&
                            function.values[clobber].storage == result) {
                            produced = clobber;
                            break;
                        }
                    }
                    std::string callee;
                    const SsaId targetValue = insn.use[0];
                    if (options.names && insn.op == MintOp::kCall
                            && targetValue != kNoValue
                            && targetValue < function.values.size()
                            && function.values[targetValue].storage.space
                                    == Space::kConstant) {
                        callee = identifier(options.names(
                                function.values[targetValue].storage.offset));
                    }
                    if (callee.empty()) {
                        // No symbol: keep the address, and keep it callable, rather
                        // than inventing a name that would collide across functions.
                        callee = "call";
                        arguments = arguments.empty()
                                ? expr.value(targetValue)
                                : expr.value(targetValue) + ", " + arguments;
                    }
                    // Called through a cast when arguments are passed. The number of
                    // arguments here comes from what this function loaded into the
                    // argument registers, while the callee's own parameter list comes
                    // from what that function was seen to read — and the two disagree
                    // whenever a callee forwards an argument it never touches. Neither
                    // side is wrong; recovering the true arity needs the callee's
                    // prototype, which nothing here has. The cast states that honestly
                    // instead of letting one guess silently override the other.
                    const bool wantsResult =
                            produced != kNoValue && produced < function.values.size()
                            && function.values[produced].uses != 0;
                    // The cast is needed for the arguments and, independently, for the
                    // result: a callee recovered as returning nothing cannot be
                    // assigned from, even when this function clearly reads what it
                    // left in the result register.
                    // Always through a cast. The emitter decompiles one function at a
                    // time and so never knows the callee's recovered signature, and
                    // the two disagree in both directions: a caller loads argument
                    // registers a callee was never seen to read, and a callee reads
                    // parameters its caller was never seen to set. The cast commits to
                    // neither guess.
                    const std::string site =
                            "((uint64_t(*)())" + callee + ")(" + arguments + ")";
                    if (wantsResult) {
                        out << "    " << expr.name(produced) << " = " << site << ";\n";
                    } else {
                        out << "    " << site << ";\n";
                    }
                    for (SsaId clobber : insn.clobbers) {
                        if (clobber == produced || clobber >= function.values.size()) continue;
                        if (function.values[clobber].uses == 0) continue;
                        out << "    " << expr.name(clobber) << " = op_undefined();\n";
                    }
                    continue;
                }
                case MintOp::kTrap:
                    // Reaching here ends the program, so nothing after it in this
                    // block can run — but the label stays, because another edge may
                    // still target the block.
                    out << "    op_trap();\n";
                    continue;
                case MintOp::kIntrinsic:
                    out << "    /* unmodelled instruction #" << insn.intrinsicId << " */\n";
                    continue;
                default:
                    break;
            }
            if (insn.dest != kNoValue && expr.needsStatement(insn.dest)) {
                out << "    " << expr.name(insn.dest) << " = " << expr.instruction(insn)
                    << ";\n";
            }
        }
        // A block whose last instruction is not a terminator falls through. C has no
        // fallthrough between labels once the phi copies have to run on the edge, so
        // the edge is made explicit here.
        const bool ends =
            block.insnCount != 0 &&
            isTerminator(function.insns[block.firstInsn + block.insnCount - 1].op);
        if (!ends && !block.successors.empty()) {
            emitEdgeCopies(block, block.successors.front());
            out << "    goto " << blockLabel(block.successors.front()) << ";\n";
        }
    }

    out << "\nunresolved_indirect:;\n";
    out << (returnsValue ? "    return 0;\n}\n" : "    return;\n}\n");
    return out.str();
}

}  // namespace mint
