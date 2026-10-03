#include "mint/decompile/c_emitter.h"
#include "mint/ir/memory_analysis.h"
#include "mint/analysis/abi_model.h"
#include "mint/plugin/architecture_bridge.h"

#include <algorithm>
#include <functional>
#include <map>
#include <set>

#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "mint/analysis/cfg.h"
#include "mint/decompile/control_flow_ast.h"
#include "mint/ir/dominance.h"
#include "mint/ir/registers.h"
#include "mint/ir/stack_analysis.h"
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
    } else if(arch==Arch::kArm32 || arch==Arch::kThumb) {
        for(unsigned n=0;n<4;++n)out.push_back(Varnode::reg(arm32::kRn(n),4));
    } else if(arch==Arch::kRiscV32 || arch==Arch::kRiscV64) {
        for(unsigned n=10;n<18;++n)out.push_back(Varnode::reg(riscv::kXn(n),arch==Arch::kRiscV32?4:8));
    }
    else {MintArchitectureSemanticsV2 custom{};if(architecturePluginAbi(arch,&custom))for(u32 n=0;n<custom.argument_count;++n)out.push_back(Varnode::reg(custom.argument_offsets[n],custom.pointer_size));}
    return out;
}

/// The register a return value comes back in.
Varnode returnRegister(Arch arch) {
    switch (arch) {
        case Arch::kAArch64: return Varnode::reg(arm64::kXn(0), 8);
        case Arch::kX86_64: return Varnode::reg(x86::kRax, 8);
        case Arch::kX86_32:return Varnode::reg(x86::kRax,4);
        case Arch::kArm32:case Arch::kThumb:return Varnode::reg(arm32::kRn(0),4);
        case Arch::kRiscV32:case Arch::kRiscV64:return Varnode::reg(riscv::kXn(10),arch==Arch::kRiscV32?4:8);
        default:{const auto candidates=abiResultRegisters(arch);return candidates.empty()?Varnode::invalid():candidates[0];}
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
        for(SsaId id=0;id<function_.values.size();++id)if(function_.values[id].def==SsaDef::kEntry && matches(id,unit))return id;
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
    StackAnalysis stack;
    MemoryAnalysis memory;
    const auto memoryStatus=analyzeMemory(function,&memory);
    const Status stackStatus = options.recoverStackVariables
        ? analyzeStackMemory(function, &stack) : Status::success();

    std::vector<std::vector<u32>> graph(function.blocks.size());
    for (size_t i = 0; i < function.blocks.size(); ++i) {
        graph[i] = function.blocks[i].successors;
    }
    const Dominance dominance = computeDominance(graph);
    const ReachingDefs reaching(function, dominance);

    ControlFlowAst ast;
    const Status astStatus = options.useAST ? buildControlFlowAst(function, &ast)
        : Status::error(ErrorCode::kUnsupported, "AST structuring disabled");

    TypeRecovery types;
    recoverTypes(function, &types);
    auto kindOf = [&](SsaId id) {
        return id < types.values.size() ? types.values[id].kind : RecoveredTypeKind::kUnknown;
    };
    auto widthOf = [&](SsaId id) {
        return id < function.values.size() ? function.values[id].storage.size : u8(8);
    };

    // A constant that points at printable text in the image is almost always a
    // string literal, and `0x4a1c8` says nothing that `"invalid argument"` does.
    //
    // Done by overriding the printed name rather than by teaching ExprBuilder about
    // the image: the override already exists for parameters, and a constant has no
    // defining instruction to intercept.
    if (options.strings) {
        for (SsaId id = 0; id < function.values.size(); ++id) {
            const SsaValue& value = function.values[id];
            if (value.def != SsaDef::kConstant) continue;
            if (value.storage.space != Space::kConstant) continue;
            const std::string literal = options.strings(value.storage.offset);
            if (!literal.empty()) expr.setName(id, literal);
        }
    }

    std::unordered_set<SsaId> parameters;
    const UserPrototype userPrototype = options.prototypes ? options.prototypes(function.entry) : UserPrototype{};
    AbiModel functionAbi;
    const Status abiStatus=userPrototype.valid() ? buildAbiModel(function.arch,userPrototype,&functionAbi,options.typeLayouts) : Status::error(ErrorCode::kNotFound,"no authoritative ABI");
    DataTypeManager builtinLayouts(function.arch==Arch::kArm32||function.arch==Arch::kThumb||function.arch==Arch::kX86_32||function.arch==Arch::kRiscV32?4:8);
    const auto declaredLayout=[&](const std::string& type,DataTypeLayout* layout){return options.typeLayouts?options.typeLayouts(localTypeExpression(type),layout):builtinLayouts.resolve(localTypeExpression(type),layout);};
    const auto compositeLayout=[](const DataTypeLayout& layout){return layout.kind==DataTypeKind::kStruct||layout.kind==DataTypeKind::kUnion||layout.kind==DataTypeKind::kArray;};
    DataTypeLayout functionResultLayout;
    const bool functionFloatingResult=userPrototype.valid()&&declaredLayout(userPrototype.returnType,&functionResultLayout).ok()&&functionResultLayout.isFloating;
    std::map<std::pair<i64,u8>,std::string> stackParameters;
    std::map<SsaId,std::string> editedTypes;
    std::map<std::pair<i64,u8>,LocalVariableEdit> editedStack;
    size_t staleLocalEdits=0;
    for (size_t i = 0; i < types.parameters.size(); ++i) {
        const SsaId id = types.parameters[i].value;
        parameters.insert(id);
        expr.setName(id, userPrototype.valid() ? "op_undefined() /* outside user prototype */"
                : "a_" + registerName(function.arch, function.values[id].storage.offset,
                                     function.values[id].storage.size));
    }
    if (userPrototype.valid()) {
        if(abiStatus.ok())for (size_t i=0;i<functionAbi.parameters.size();++i) {
            const auto& parameter=userPrototype.parameters[i];const auto& abiValue=functionAbi.parameters[i];
            DataTypeLayout parameterLayout;const bool knownLayout=declaredLayout(parameter.type,&parameterLayout).ok();
            const bool semanticFloat=knownLayout&&parameterLayout.isFloating,semanticAggregate=knownLayout&&compositeLayout(parameterLayout);
            for(const auto& piece:abiValue.pieces) {
                const bool simple=abiValue.pieces.size()==1 && !abiValue.indirect && !piece.floating && !semanticFloat && !semanticAggregate && abiValue.size<=piece.storage.size;
                const std::string component=abiValue.indirect ? "op_abi_indirect_copy_address("+parameter.name+")" : semanticFloat&&abiValue.pieces.size()==1 ? "op_abi_fp_bits("+parameter.name+", "+std::to_string(piece.width)+")" : "op_abi_piece("+parameter.name+", "+std::to_string(piece.valueOffset)+", "+std::to_string(piece.width)+")";
                if(!piece.storage.valid()) {
                    bool readonly=stack.barriers==0 && stack.unknownWrites==0 && !stack.escapedStackAddress;
                    for(const auto& access:stack.accesses)if(access.store && stack.slots[access.slot].offset==piece.stackOffset)readonly=false;
                    if(readonly && piece.kind==AbiStorageKind::kStack)
                        stackParameters[{piece.stackOffset,piece.width}]=abiValue.pieces.size()==1&&!semanticFloat&&!semanticAggregate ? parameter.name : component;
                    continue;
                }
                for (SsaId id=0;id<function.values.size();++id) {
                    const auto& value=function.values[id];
                    if (value.def==SsaDef::kEntry && value.storage==piece.storage) {
                        parameters.insert(id);
                        if(simple)expr.setName(id,parameter.name);
                        else expr.setName(id,component);
                        if(parameter.type.find('*')!=std::string::npos)expr.setNumericPointer(id);
                    }
                }
            }
        }
        // A user may legitimately call a parameter v42, which must not collide
        // with a generated SSA local of the same name.
        for (SsaId id=0;id<function.values.size();++id) {
            if (parameters.count(id) || function.values[id].storage.isConstant()) continue;
            for (const auto& parameter : userPrototype.parameters) if (expr.name(id)==parameter.name) {
                std::string name="mint_value_"+std::to_string(id);
                bool collision;
                do { collision=false; for (const auto& p:userPrototype.parameters) if (p.name==name) {name+="_";collision=true;} } while (collision);
                expr.setName(id,name);break;
            }
        }
    }

    if(options.locals) {
        const auto candidates=localVariables(function);
        std::map<std::string,LocalVariable> identities;
        for(const auto& candidate:candidates)identities.emplace(candidate.identity,candidate);
        std::set<std::string> reserved;
        for(SsaId id=0;id<function.values.size();++id)reserved.insert(expr.name(id));
        for(const auto& edit:options.locals(function.entry)) {
            const auto found=identities.find(edit.identity);if(found==identities.end()){++staleLocalEdits;continue;}
            const auto& local=found->second;
            // A prototype remains authoritative for its parameters. Local edits
            // never silently replace declarations or add new function arguments.
            if(!local.stack && parameters.count(local.value))continue;
            if(!edit.name.empty() && (!userIdentifier(edit.name) || (reserved.count(edit.name) && (!local.stack && expr.name(local.value)!=edit.name))))continue;
            if(local.stack) {editedStack[{local.stackOffset,local.width}]=edit;continue;}
            if(!edit.name.empty()){expr.setName(local.value,edit.name);reserved.insert(edit.name);}
            expr.materialize(local.value);
            if(!edit.type.empty() && options.typeLayouts) {
                DataTypeLayout layout;
                if(options.typeLayouts(localTypeExpression(edit.type),&layout).ok() && layout.size==local.width &&
                   (layout.kind==DataTypeKind::kPointer || layout.kind==DataTypeKind::kEnum || layout.kind==DataTypeKind::kPrimitive)) {
                    // Float interpretation is never applied to integer/bitwise
                    // operations merely because the user changed a display type.
                    const bool floating=layout.isFloating;
                    if(!floating || kindOf(local.value)==RecoveredTypeKind::kFloat) {
                        editedTypes[local.value]=localCType(edit.type);
                        if(layout.kind==DataTypeKind::kPointer)expr.setNumericPointer(local.value);
                    }
                }
            }
        }
    }

    // Does the function produce a value? Only a definition of the result register
    // that reaches a return says so; a function that never writes it returns nothing.
    const Varnode result = returnRegister(function.arch);

    // Recorded by the builder, which knew the reaching definition without having to
    // search for it. A value that is merely the caller's incoming register means the
    // function never set a result, so heuristic inference cannot claim a return.
    // An authoritative nonvoid prototype can establish an identity return of
    // that incoming register instead; rejecting it would invent a return zero.
    bool returnsValue = false;
    auto returnValueAt = [&](u32 index) {
        if(userPrototype.valid() && abiStatus.ok() && functionAbi.result.pieces.size()==1) {
            const auto storage=functionAbi.result.pieces[0].storage;
            if(storage!=result){for(const auto& entry:function.abiReturnValues)if(entry.instruction==index && entry.storage==storage)return entry.value;return kNoValue;}
        }
        for (const auto& entry : function.returnValues) {
            if (entry.first != index) continue;
            const SsaId id = entry.second;
            if (id == kNoValue || id >= function.values.size()) return kNoValue;
            if (function.values[id].def == SsaDef::kEntry &&
                !(userPrototype.valid() && userPrototype.returnType != "void")) return kNoValue;
            return id;
        }
        return kNoValue;
    };
    for (const auto& entry : function.returnValues) {
        if (returnValueAt(entry.first) != kNoValue) returnsValue = true;
    }
    if (userPrototype.valid()) returnsValue=userPrototype.returnType!="void";

    out << "/* Mint pseudo-C; irreducible edges remain explicit labels. */\n";
    if (options.includeComments) {
        if(userPrototype.valid()) {
            if(abiStatus.ok())out<<"/* Authoritative ABI: "<<functionAbi.convention<<"; stack extent "<<functionAbi.stackBytes<<"; hidden return pieces "<<functionAbi.hiddenResult.size()<<". Composite/FP storage conversions remain explicit op_abi helpers. */\n";
            else out<<"/* Authoritative ABI cannot be mapped: "<<abiStatus.message()<<". Storage kept explicit, no positional register guess. */\n";
        }
        if(staleLocalEdits)out<<"/* "<<staleLocalEdits<<" saved local edits do not match the current analysis; retained in project, not applied. */\n";
        if(memoryStatus.ok())out<<"/* General memory: "<<memory.exactDependencies<<" exact store/load dependencies; "<<memory.callBarriers<<" alias barriers; "<<memory.unresolvedAccesses<<" unresolved accesses. */\n";
        else out<<"/* General memory evidence unavailable; explicit loads/stores retained. */\n";
        out << "/* loops: " << structure.loops.size() << ", switch-like blocks: "
            << structure.switchBlocks.size() << " */\n";
        if (!stackStatus.ok()) {
            out << "/* Stack analysis unavailable: " << stackStatus.message() << "; raw addresses retained. */\n";
        } else if (options.recoverStackVariables) {
            out << "/* stack slots: " << stack.slots.size()
                << "; exact store/load dependencies: " << stack.storeLoadDependencies
                << "; alias/call barriers: " << stack.barriers + stack.unknownWrites
                << "; unresolved stack accesses: " << stack.unknownStackAccesses << " */\n";
        }
    }

    const std::string returnType =
        userPrototype.valid() ? localCType(userPrototype.returnType) : returnsValue ? typeName(RecoveredTypeKind::kUnknown, result.valid() ? result.size : u8(8)) : "void";
    out << returnType << " "
        << (function.name.empty() ? "sub_" + std::to_string(function.entry)
                                  : identifier(function.name))
        << "(";
    if (userPrototype.valid()) {
        if (userPrototype.parameters.empty()) out << "void";
        for (size_t i=0;i<userPrototype.parameters.size();++i) {
            if (i) out << ", ";
            out << localCType(userPrototype.parameters[i].type) << " " << userPrototype.parameters[i].name;
        }
        if(userPrototype.variadic)out<<", ...";
    } else if (types.parameters.empty()) {
        out << "void";
    } else {
        for (size_t i = 0; i < types.parameters.size(); ++i) {
            const SsaId id = types.parameters[i].value;
            if (i != 0) out << ", ";
            out << typeName(kindOf(id), widthOf(id)) << " " << expr.name(id);
        }
    }
    out << ") {\n";

    // Enum-shaped values: a discriminant compared against a set of constants.
    //
    // A value tested against several literals has a known domain, and that domain is
    // the useful half of "this is an enum". The other half — member names — cannot
    // be invented: nothing in a stripped binary says a 2 is called ARCHIVE.
    //
    // What can be offered is a candidate pairing, and only when the layout justifies
    // it: if the function also references exactly as many string literals, and those
    // literals sit in memory in ascending order, a compiler laying out one string per
    // case is by far the likeliest explanation. It is printed as a guess, in that
    // order, and never as fact — pairing them properly needs to follow which string
    // each case actually reaches, which is control flow this pass does not walk.
    {
        std::map<SsaId, std::set<u64>> domains;
        for (const SsaInsn& insn : function.insns) {
            if (insn.op != MintOp::kEqual && insn.op != MintOp::kNotEqual) continue;
            SsaId value = insn.use[0];
            SsaId literal = insn.use[1];
            if (value >= function.values.size() || literal >= function.values.size()) {
                continue;
            }
            if (function.values[value].storage.space == Space::kConstant) {
                std::swap(value, literal);
            }
            if (function.values[literal].storage.space != Space::kConstant) continue;
            if (function.values[value].storage.space == Space::kConstant) continue;
            domains[value].insert(function.values[literal].storage.offset);
        }

        // Strings the function mentions, in address order — the candidate names.
        std::set<Address> literals;
        if (options.strings) {
            for (SsaId id = 0; id < function.values.size(); ++id) {
                const SsaValue& value = function.values[id];
                if (value.def != SsaDef::kConstant) continue;
                if (value.storage.space != Space::kConstant) continue;
                if (!options.strings(value.storage.offset).empty()) {
                    literals.insert(value.storage.offset);
                }
            }
        }

        // The offset-table form, which is what compilers actually emit for a
        // switch that returns one of several strings: a 4-byte load from a constant
        // base, then that base added back to the loaded value. The table's own
        // contents say where it ends, so no bound needs recovering from the compare.
        if (options.offsetTable) {
            // A table base does not arrive as a constant varnode. On AArch64 it is
            // built by adrp+add into a register, so in SSA it is a value whose
            // defining chain is constant — which the plain space check missed, and
            // which is why this found nothing at first. Two levels of folding is
            // enough for every address-materialising sequence the lifters emit.
            const std::function<u64(SsaId, unsigned)> constantOf =
                [&](SsaId id, unsigned depth) -> u64 {
                    if (id == kNoValue || id >= function.values.size()) return 0;
                    const SsaValue& value = function.values[id];
                    if (value.storage.space == Space::kConstant) return value.storage.offset;
                    if (depth == 0) return 0;
                    if (value.def != SsaDef::kInsn ||
                        value.defIndex >= function.insns.size()) {
                        return 0;
                    }
                    const SsaInsn& def = function.insns[value.defIndex];
                    if (def.op == MintOp::kCopy || def.op == MintOp::kZeroExt ||
                        def.op == MintOp::kSignExt) {
                        return constantOf(def.use[0], depth - 1);
                    }
                    if (def.op == MintOp::kAdd) {
                        const u64 left = constantOf(def.use[0], depth - 1);
                        const u64 right = constantOf(def.use[1], depth - 1);
                        return (left != 0 && right != 0) ? left + right : 0;
                    }
                    return 0;
                };

            std::set<Address> bases;
            for (const SsaInsn& insn : function.insns) {
                if (insn.op != MintOp::kLoad) continue;
                const SsaId address = insn.use[0];
                if (address == kNoValue || address >= function.values.size()) continue;
                if (insn.dest == kNoValue || insn.dest >= function.values.size()) continue;
                if (function.values[insn.dest].storage.size != 4) continue;
                const SsaValue& value = function.values[address];
                if (value.def != SsaDef::kInsn || value.defIndex >= function.insns.size()) {
                    continue;
                }
                const SsaInsn& compute = function.insns[value.defIndex];
                if (compute.op != MintOp::kAdd) continue;
                for (unsigned slot = 0; slot < 2; ++slot) {
                    const u64 folded = constantOf(compute.use[slot], 3);
                    if (folded != 0) bases.insert(folded);
                }
            }
            for (const Address base : bases) {
                const std::string table = options.offsetTable(base);
                if (table.empty()) continue;
                out << "    /* string table at 0x" << std::hex << base << std::dec
                    << ", indexed by a discriminant:\n" << table
                    << "     * extent is inferred from the contents, so the last"
                       " entry or two may be\n"
                       "     * past the end — the real bound is in the range check"
                       " above.\n     */\n";
            }
        }

        for (const auto& entry : domains) {
            if (entry.second.size() < 2) continue;
            out << "    /* " << expr.value(entry.first) << " is tested against {";
            bool first = true;
            for (const u64 member : entry.second) {
                if (!first) out << ", ";
                out << member;
                first = false;
            }
            out << "} */\n";

            if (literals.size() != entry.second.size()) continue;
            out << "    /* possibly an enum — as many string literals as cases,"
                   " paired by address order:";
            auto member = entry.second.begin();
            for (const Address at : literals) {
                out << "\n     *   " << *member << " -> " << options.strings(at);
                ++member;
            }
            out << "\n     */\n";
        }
    }

    // Pattern-derived heap layouts are comments until a declared type proves
    // the field binding. Exact stack bindings below have independent evidence.
    // Overlapping widths deliberately keep raw memory expressions: independent
    // locals for overlapping bytes would silently break aliasing.
    std::set<std::string> localNames;
    for (SsaId id = 0; id < function.values.size(); ++id) localNames.insert(expr.name(id));
    for (const auto& parameter : userPrototype.parameters) localNames.insert(parameter.name);
    for (StackSlot& slot : stack.slots) {
        const auto edited=editedStack.find({slot.offset,slot.width});
        if(edited!=editedStack.end() && !edited->second.name.empty())slot.name=edited->second.name;
        while (localNames.count(slot.name)) slot.name += "_";
        localNames.insert(slot.name);
    }
    for (const StackAccess& access : stack.accesses) {
        const StackSlot& slot = stack.slots[access.slot];
        const SsaId address = function.insns[access.instruction].use[0];
        if (slot.overlaps) continue;
        const auto parameter=stackParameters.find({slot.offset,slot.width});
        expr.setFieldAccess(address,parameter==stackParameters.end() ? (slot.promoted ? slot.name : "*"+slot.name) : parameter->second);
    }

    // Bind declared integer fields only to an exact original parameter SSA
    // value (plus one constant add). A copy/phi/derived pointer is not assumed
    // to preserve that authoritative pointee type. One address SSA value may
    // have many accesses: all their widths must agree before ExprBuilder gets
    // a global binding. Loads remain materialized in their original order.
    if (options.typeLayouts && userPrototype.valid()) {
        struct Pointee { std::string name; DataTypeLayout layout; };
        std::map<SsaId, Pointee> pointees;
        const auto registers = argumentRegisters(function.arch);
        for (size_t i = 0; i < userPrototype.parameters.size() && abiStatus.ok() && i<functionAbi.parameters.size(); ++i) {
            if(functionAbi.parameters[i].pieces.size()!=1 || !functionAbi.parameters[i].pieces[0].storage.valid() || functionAbi.parameters[i].pieces[0].floating)continue;
            const auto parameterRegister=functionAbi.parameters[i].pieces[0].storage;
            std::string name = userPrototype.parameters[i].type;
            if (name.compare(0, 6, "const ") == 0) name.erase(0, 6);
            name.erase(std::remove_if(name.begin(), name.end(), [](char c) { return c == ' ' || c == '\t'; }), name.end());
            if (name.empty() || name.back() != '*') continue;
            name.pop_back();
            if (!DataTypeManager::validName(name) || !userIdentifier(name)) continue;
            DataTypeLayout layout, pointer;
            if (!options.typeLayouts(name, &layout).ok() || layout.kind != DataTypeKind::kStruct || layout.packed ||
                !options.typeLayouts(name + "*", &pointer).ok() || pointer.kind != DataTypeKind::kPointer || pointer.size != parameterRegister.size) continue;
            for (SsaId id = 0; id < function.values.size(); ++id) {
                const auto& value = function.values[id];
                if (value.def == SsaDef::kEntry && value.storage == parameterRegister) pointees.emplace(id, Pointee{name, layout});
            }
        }
        std::map<SsaId, std::set<u8>> accessWidths;
        for (const auto& insn : function.insns) {
            if (insn.op != MintOp::kLoad && insn.op != MintOp::kStore) continue;
            const SsaId address = insn.use[0];
            const SsaId value = insn.op == MintOp::kLoad ? insn.dest : insn.use[1];
            if (address >= function.values.size() || value >= function.values.size()) continue;
            accessWidths[address].insert(function.values[value].storage.size);
        }
        static const std::set<std::string> integerTypes = {"u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "char", "bool"};
        for (const auto& access : accessWidths) {
            const SsaId address = access.first;
            if (access.second.size() != 1 || !expr.fieldAccess(address).empty() ||
                (address < stack.values.size() && stack.values[address].mayBeStack)) continue;
            SsaId base = address; u64 offset = 0;
            auto pointee = pointees.find(base);
            if (pointee == pointees.end()) {
                const auto& addressValue = function.values[address];
                if (addressValue.def != SsaDef::kInsn || addressValue.defIndex >= function.insns.size()) continue;
                const auto& add = function.insns[addressValue.defIndex];
                if (add.op != MintOp::kAdd) continue;
                for (unsigned side = 0; side < 2; ++side) {
                    const auto candidate = pointees.find(add.use[side]);
                    const SsaId constant = add.use[1 - side];
                    if (candidate == pointees.end() || constant >= function.values.size() ||
                        !function.values[constant].storage.isConstant()) continue;
                    pointee = candidate; base = add.use[side]; offset = function.values[constant].storage.offset; break;
                }
                if (pointee == pointees.end() || addressValue.storage.size != function.values[base].storage.size) continue;
            }
            for (const auto& field : pointee->second.layout.fields) {
                if (field.offset != offset || field.size != *access.second.begin() || !userIdentifier(field.name)) continue;
                DataTypeLayout fieldLayout;
                if (!options.typeLayouts(field.type, &fieldLayout).ok() || fieldLayout.size != field.size ||
                    !(fieldLayout.kind == DataTypeKind::kEnum ||
                      (fieldLayout.kind == DataTypeKind::kPrimitive && integerTypes.count(field.type)))) continue;
                expr.setFieldAccess(address, "((" + pointee->second.name + "*)(uintptr_t)" + expr.name(base) + ")->" + field.name);
                break;
            }
        }
    }

    // The recovered layouts, as a comment ahead of the body.
    //
    // A comment and not a struct type with p->field accesses in the code: the field
    // expression would have to be re-materialised at each use, and a load is not
    // pure — an intervening store to the same object makes the second rendering a
    // different value than the first. Getting that wrong changes what the C says
    // the program does, silently. Stated as a layout, it is a hypothesis the reader
    // applies; woven into the expressions, it would be an assertion.
    for (const RecoveredStruct& layout : types.structs) {
        if (layout.fields.size() < 2) continue;
        if (layout.base < stack.values.size() && stack.values[layout.base].mayBeStack) continue;
        out << "    /* layout via " << expr.value(layout.base) << ":";
        for (const RecoveredField& field : layout.fields) {
            out << "\n     *   +0x" << std::hex << field.offset << std::dec << "  "
                << typeName(field.type.kind, field.width == 0 ? u8(8) : field.width)
                << "  field_" << std::hex << field.offset << std::dec;
        }
        out << "\n     */\n";
    }

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
        const auto edited=editedTypes.find(id);
        out << "    " << (edited==editedTypes.end() ? typeName(kindOf(id), widthOf(id)) : edited->second) << " " << expr.name(id) << ";\n";
    }
    for (const StackSlot& slot : stack.slots) {
        if (slot.overlaps || stack.entryStackValue == kNoValue) continue;
        if(stackParameters.count({slot.offset,slot.width}))continue;
        std::string type = slot.width == 16 ? "__uint128_t"
            : "uint" + std::to_string(unsigned(slot.width) * 8) + "_t";
        const auto edited=editedStack.find({slot.offset,slot.width});
        if(edited!=editedStack.end() && !edited->second.type.empty() && options.typeLayouts) {
            DataTypeLayout layout;
            if(options.typeLayouts(localTypeExpression(edited->second.type),&layout).ok() && layout.size==slot.width &&
               (layout.kind==DataTypeKind::kEnum || (layout.kind==DataTypeKind::kPrimitive && !layout.isFloating)))
                type=localCType(edited->second.type);
        }
        out << "    " << type << " ";
        if (slot.promoted) out << slot.name << ";";
        else {
            out << "*const " << slot.name << " = (" << type << "*)((uintptr_t)"
                << expr.name(stack.entryStackValue);
            const u64 magnitude = slot.offset < 0 ? static_cast<u64>(-(slot.offset + 1)) + 1 : static_cast<u64>(slot.offset);
            if (magnitude) out << (slot.offset < 0 ? " - " : " + ") << "0x" << std::hex << magnitude << std::dec;
            out << ");";
        }
        if (options.includeComments) {
            out << " /* entry SP " << (slot.offset < 0 ? "-" : "+") << " "
                << (slot.offset < 0 ? -slot.offset : slot.offset)
                << (slot.promoted ? "; nonescaping leaf local" : "; memory-backed alias") << " */";
        }
        out << "\n";
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

    auto emitBlockStatements = [&](const SsaBlock& block, bool controlFlow) {
        if (controlFlow) out << "\n" << blockLabel(block.id) << ":;\n";
        for (u32 i = 0; i < block.insnCount; ++i) {
            const u32 index = block.firstInsn + i;
            const SsaInsn& insn = function.insns[index];
            if (!controlFlow && (insn.op == MintOp::kBranch || insn.op == MintOp::kCondBranch || insn.op == MintOp::kBranchInd)) continue;
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
                    if(userPrototype.valid() && abiStatus.ok() && (functionAbi.result.indirect || functionAbi.result.pieces.size()>1)) {
                        out<<"    return "<<(functionFloatingResult?"op_abi_unpack_":"op_abi_aggregate_result_")<<identifier(userPrototype.returnType)<<"(";
                        bool first=true;
                        for(const auto& piece:functionAbi.result.pieces) {
                            SsaId id=kNoValue;
                            if(piece.storage==result)for(const auto& returned:function.returnValues)if(returned.first==index)id=returned.second;
                            for(const auto& returned:function.abiReturnValues)if(returned.instruction==index && returned.storage==piece.storage)id=returned.value;
                            if(!first)out<<", ";first=false;out<<(id==kNoValue ? "op_undefined()" : expr.value(id));
                        }
                        if(functionAbi.result.indirect)out<<"op_abi_hidden_result_pointer()";
                        out<<");\n";continue;
                    }
                    const SsaId value = returnValueAt(index);
                    if (value != kNoValue && returnsValue) {
                        const bool floating=userPrototype.valid() && abiStatus.ok() && functionAbi.result.pieces.size()==1 && functionFloatingResult;
                        out << "    return " << (floating ? "op_abi_float_result("+expr.value(value)+", "+std::to_string(functionAbi.result.pieces[0].width)+")" : userPrototype.valid() ? "("+returnType+")("+expr.value(value)+")" : expr.value(value)) << ";\n";
                    } else {
                        out << (returnsValue ? "    return op_undefined(); /* no proven ABI return value */\n" : "    return;\n");
                    }
                    continue;
                }
                case MintOp::kBranch: {
                    const u32 target =
                        block.successors.empty() ? kNoBlock : block.successors.front();
                    if (target != kNoBlock) emitEdgeCopies(block, target);
                    out << "    goto "
                        << (target == kNoBlock ? "unresolved_indirect" : blockLabel(target))
                        << ";\n";
                    continue;
                }
                case MintOp::kCondBranch: {
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
                case MintOp::kAtomicStore:
                    out << "    __atomic_store_n((uint" << unsigned(widthOf(insn.use[1]))*8 << "_t*)(uintptr_t)(" << expr.value(insn.use[0]) << "), " << expr.value(insn.use[1]) << ", __ATOMIC_RELEASE);\n";
                    continue;
                case MintOp::kMemoryFence:
                    out << "    __atomic_thread_fence(__ATOMIC_SEQ_CST);\n";
                    continue;
                case MintOp::kAtomicCompareExchange: {
                    // GNU compare-exchange updates expected with the previous
                    // value on failure and leaves it unchanged on success.
                    const auto type="uint"+std::to_string(unsigned(widthOf(insn.dest))*8)+"_t";
                    out << "    { " << type << " atomic_expected_" << index << " = " << expr.value(insn.use[1]) << ";\n";
                    out << "      __atomic_compare_exchange_n((" << type << "*)(uintptr_t)(" << expr.value(insn.use[0]) << "), &atomic_expected_" << index << ", " << expr.value(insn.use[2]) << ", 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);\n";
                    if(insn.dest!=kNoValue && function.values[insn.dest].uses)out << "      " << expr.name(insn.dest) << " = atomic_expected_" << index << ";\n";
                    out << "    }\n";continue;
                }
                case MintOp::kAtomicLoad:case MintOp::kAtomicExchange:case MintOp::kAtomicAdd:
                    if(insn.dest==kNoValue || !function.values[insn.dest].uses){out<<"    "<<expr.instruction(insn)<<";\n";continue;}
                    break;
                case MintOp::kVectorStore:
                case MintOp::kStore: {
                    const std::string field = expr.fieldAccess(insn.use[0]);
                    if (!field.empty()) {
                        out << "    " << field << " = " << expr.value(insn.use[1])
                            << ";\n";
                        continue;
                    }
                    out << "    *(" << (widthOf(insn.use[1]) == 16 ? "__uint128_t"
                            : "uint" + std::to_string(unsigned(widthOf(insn.use[1])) * 8) + "_t") << "*)"
                        << expr.value(insn.use[0]) << " = " << expr.value(insn.use[1])
                        << ";\n";
                    continue;
                }
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
                    UserPrototype calleePrototype;
                    if (options.prototypes && insn.op==MintOp::kCall && insn.use[0]<function.values.size() && function.values[insn.use[0]].storage.isConstant())
                        calleePrototype=options.prototypes(function.values[insn.use[0]].storage.offset);
                    AbiModel calleeAbi;
                    const auto calleeStatus=calleePrototype.valid() ? buildAbiModel(function.arch,calleePrototype,&calleeAbi,options.typeLayouts) : Status::error(ErrorCode::kNotFound,"unknown callee ABI");
                    size_t argumentIndex=0;
                    if(calleeStatus.ok()) {
                        for(size_t i=0;i<calleeAbi.parameters.size();++i) {
                            if(!arguments.empty())arguments+=", ";const auto& argument=calleeAbi.parameters[i];
                            std::vector<std::string> pieces;
                            std::set<std::pair<u64,u8>> seenComponents;
                            for(const auto& piece:argument.pieces) {
                                // Windows variadic scalar FP duplicates the same
                                // bytes in GP and SSE; this is one C argument.
                                if(!seenComponents.insert({piece.valueOffset,piece.width}).second)continue;
                                std::string value="op_undefined()";
                                if(piece.storage.valid()) {const auto id=reaching.at(block.id,index,piece.storage);if(id!=kNoValue)value=expr.value(id);}
                                else {
                                    u64 spOffset=function.arch==Arch::kAArch64 ? arm64::kSp : function.arch==Arch::kArm32||function.arch==Arch::kThumb ? arm32::kSp : function.arch==Arch::kRiscV32||function.arch==Arch::kRiscV64 ? riscv::kSp : x86::kRsp;
                                    const auto sp=reaching.at(block.id,index,Varnode::reg(spOffset,calleeAbi.pointerWidth));
                                    const i64 callSkew=function.arch==Arch::kX86_64 ? 8 : function.arch==Arch::kX86_32 ? 4 : 0;
                                    const auto displacement=piece.stackOffset-callSkew;
                                    if(sp!=kNoValue)value="*(uint"+std::to_string(unsigned(piece.width)*8)+"_t*)((uintptr_t)"+expr.value(sp)+(displacement<0 ? " - " : " + ")+std::to_string(displacement<0 ? -displacement : displacement)+")";
                                    else value="op_abi_stack_argument("+std::to_string(displacement)+", "+std::to_string(piece.width)+")";
                                }
                                pieces.push_back(value);
                            }
                            const auto type=localCType(calleePrototype.parameters[i].type);
                            DataTypeLayout argumentLayout;const bool known=declaredLayout(calleePrototype.parameters[i].type,&argumentLayout).ok();
                            if(argument.indirect && pieces.size()==1)arguments+="*("+type+"*)(uintptr_t)("+pieces[0]+")";
                            else if(pieces.size()==1 && known && argumentLayout.isFloating)arguments+="op_abi_float_argument("+pieces[0]+", "+std::to_string(argumentLayout.size)+")";
                            else if(pieces.size()==1 && !(known&&compositeLayout(argumentLayout)))arguments+="("+type+")("+pieces[0]+")";
                            else {arguments+="op_abi_unpack_"+identifier(type)+"(";for(size_t p=0;p<pieces.size();++p){if(p)arguments+=", ";arguments+=pieces[p];}arguments+=")";}
                        }
                    } else if(!calleePrototype.valid())for (const Varnode& reg : argumentRegisters(function.arch)) {
                        if (calleePrototype.valid() && argumentIndex>=calleePrototype.parameters.size()) break;
                        const SsaId value = reaching.at(block.id, index, reg);
                        if (!calleePrototype.valid() && (value==kNoValue || function.values[value].def==SsaDef::kEntry)) break;
                        if (!arguments.empty()) arguments += ", ";
                        const std::string expression=value==kNoValue ? "op_undefined()" : expr.value(value);
                        arguments += calleePrototype.valid() ? "("+calleePrototype.parameters[argumentIndex].type+")("+expression+")" : expression;
                        ++argumentIndex;
                    }
                    // The call's result is the definition it makes of the result
                    // register, so that clobber is what receives it. The other
                    // clobbers are registers the callee is free to destroy: where
                    // something still reads one, it reads an unknown value, and
                    // saying so is better than leaving a variable that is declared
                    // and never assigned.
                    SsaId produced = kNoValue;
                    const auto calleeResult=calleeStatus.ok() && calleeAbi.result.pieces.size()==1 ? calleeAbi.result.pieces[0].storage : result;
                    for (SsaId clobber : insn.clobbers) {
                        if (clobber < function.values.size() &&
                            function.values[clobber].storage == calleeResult) {
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
                    std::string parameterTypes;
                    if(calleePrototype.valid()) {
                        for(const auto& parameter:calleePrototype.parameters){if(!parameterTypes.empty())parameterTypes+=", ";parameterTypes+=localCType(parameter.type);}
                        if(calleePrototype.variadic)parameterTypes+=", ...";
                        else if(parameterTypes.empty())parameterTypes="void";
                    }
                    const std::string site =
                            "((" + (calleePrototype.valid() ? localCType(calleePrototype.returnType) : "uint64_t") + "(*)("+parameterTypes+"))" + callee + ")(" + arguments + ")";
                    DataTypeLayout calleeReturnLayout;
                    const bool knownReturnLayout=calleePrototype.valid()&&declaredLayout(calleePrototype.returnType,&calleeReturnLayout).ok();
                    const bool compositeReturn=calleeStatus.ok() && (calleeAbi.result.indirect || calleeAbi.result.pieces.size()>1 || (knownReturnLayout&&compositeLayout(calleeReturnLayout)));
                    std::set<SsaId> assignedResults;
                    if(compositeReturn) {
                        // Evaluate the call once. A returned C struct is not a
                        // scalar raw register; preserve each ABI storage piece
                        // through an explicit bit-extraction helper.
                        const std::string captured="abi_call_result_"+std::to_string(index);
                        out<<"    "<<localCType(calleePrototype.returnType)<<" "<<captured<<" = "<<site<<";\n";
                        for(const auto& piece:calleeAbi.result.pieces)for(SsaId clobber:insn.clobbers) {
                            if(clobber>=function.values.size() || function.values[clobber].storage!=piece.storage || !function.values[clobber].uses)continue;
                            out<<"    "<<expr.name(clobber)<<" = op_abi_extract("<<captured<<", "<<piece.valueOffset<<", "<<unsigned(piece.width)<<");\n";
                            assignedResults.insert(clobber);
                        }
                        // Indirect result writes are represented by the typed
                        // call. No hidden-pointer register return is fabricated.
                    } else if (wantsResult && !(calleePrototype.valid() && calleePrototype.returnType=="void")) {
                        const bool floating=calleeStatus.ok() && calleeAbi.result.pieces.size()==1 && knownReturnLayout && calleeReturnLayout.isFloating;
                        out << "    " << expr.name(produced) << " = " << (floating ? "op_abi_result_bits("+site+", "+std::to_string(calleeAbi.result.pieces[0].width)+")" : site) << ";\n";
                        assignedResults.insert(produced);
                    } else {
                        out << "    " << site << ";\n";
                        if (wantsResult) out << "    " << expr.name(produced) << " = op_undefined(); /* user prototype returns void */\n";
                    }
                    for (SsaId clobber : insn.clobbers) {
                        if (assignedResults.count(clobber) || (!compositeReturn && clobber==produced) || clobber >= function.values.size()) continue;
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
                const auto type=editedTypes.find(insn.dest);
                out << "    " << expr.name(insn.dest) << " = ";
                if(type!=editedTypes.end() && type->second.find('*')!=std::string::npos)
                    out<<"("<<type->second<<")(uintptr_t)("<<expr.instruction(insn)<<")";
                else out<<expr.instruction(insn);
                out<<";\n";
            }
        }
        // A block whose last instruction is not a terminator falls through. C has no
        // fallthrough between labels once the phi copies have to run on the edge, so
        // the edge is made explicit here.
        const bool ends =
            block.insnCount != 0 &&
            isTerminator(function.insns[block.firstInsn + block.insnCount - 1].op);
        if (controlFlow && !ends && !block.successors.empty()) {
            emitEdgeCopies(block, block.successors.front());
            out << "    goto " << blockLabel(block.successors.front()) << ";\n";
        }
    };

    bool emittedAst = false;
    if (astStatus.ok()) {
        ControlFlowAstCallbacks callbacks;
        callbacks.block = [&](u32 id) { emitBlockStatements(function.blocks[id], false); };
        callbacks.edge = [&](u32 from, u32 target) { emitEdgeCopies(function.blocks[from], target); };
        callbacks.condition = [&](u32 id) { const auto& block = function.blocks[id]; return expr.value(function.insns[block.firstInsn + block.insnCount - 1].use[0]); };
        callbacks.indirectTarget = callbacks.condition;
        callbacks.label = blockLabel;
        if (options.includeComments) for (const auto& diagnostic : ast.diagnostics) out << "    /* " << diagnostic << " */\n";
        emittedAst = emitControlFlowAst(ast, out, callbacks).ok();
    }
    if (!emittedAst) {
        if (options.includeComments) out << "    /* " << astStatus.message() << "; original labelled CFG retained. */\n";
        for (const auto& block : function.blocks) emitBlockStatements(block, true);
    }

    out << "\nunresolved_indirect:;\n";
    out << (returnsValue ? "    return 0;\n}\n" : "    return;\n}\n");
    return out.str();
}

}  // namespace mint
