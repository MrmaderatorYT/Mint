#include "mint/ir/type_recovery.h"

#include "mint/ir/registers.h"
#include "mint/ir/memory_analysis.h"
#include "mint/plugin/architecture_bridge.h"

#include <algorithm>
#include <map>

namespace mint {
namespace {

constexpr u32 kNotAnArgument = ~0u;

/// Where a register sits in the calling convention's argument sequence, or
/// kNotAnArgument.
///
/// Integer and floating-point arguments occupy separate register sequences, so the
/// floating ones are numbered after the integer ones rather than interleaved. That
/// ordering is a guess at the source-level order and is only used for display; what
/// matters for correctness is which registers count at all.
u32 argumentPosition(Arch arch, const Varnode& storage) {
    if(static_cast<u8>(arch)>=128) {
        MintArchitectureSemanticsV2 custom{};
        if(architecturePluginAbi(arch,&custom))for(u32 n=0;n<custom.argument_count;++n)if(storage.offset==custom.argument_offsets[n] && storage.size==custom.pointer_size)return n;
        return kNotAnArgument;
    }
    if(arch==Arch::kArm32 || arch==Arch::kThumb)return storage.size==4&&storage.offset<=arm32::kRn(3)&&storage.offset%4==0 ? static_cast<u32>(storage.offset/4) : kNotAnArgument;
    if(arch==Arch::kRiscV32 || arch==Arch::kRiscV64) {
        const u8 width=arch==Arch::kRiscV32?4:8;
        return storage.size==width&&storage.offset>=riscv::kXn(10)&&storage.offset<=riscv::kXn(17)&&storage.offset%8==0 ? static_cast<u32>(storage.offset/8-10) : kNotAnArgument;
    }
    if (arch == Arch::kAArch64) {
        if (storage.size == 8 && storage.offset <= arm64::kXn(7) &&
            storage.offset % 8 == 0) {
            return static_cast<u32>(storage.offset / 8);
        }
        if (storage.size == 16 && storage.offset >= arm64::kV0 &&
            storage.offset <= arm64::kVn(7) &&
            (storage.offset - arm64::kV0) % 16 == 0) {
            return 8 + static_cast<u32>((storage.offset - arm64::kV0) / 16);
        }
        return kNotAnArgument;
    }
    if (arch == Arch::kX86_64) {
        // The System V order, which is not the encoding order.
        static const u64 kSequence[] = {x86::kRdi, x86::kRsi, x86::kRdx,
                                        x86::kRcx, x86::kGpr(8), x86::kGpr(9)};
        if (storage.size == 8) {
            for (u32 i = 0; i < 6; ++i) {
                if (storage.offset == kSequence[i]) return i;
            }
        }
        if (storage.size == 16 && storage.offset >= x86::kXmm0 &&
            storage.offset <= x86::kXmmN(7) &&
            (storage.offset - x86::kXmm0) % 16 == 0) {
            return 6 + static_cast<u32>((storage.offset - x86::kXmm0) / 16);
        }
        return kNotAnArgument;
    }
    return kNotAnArgument;
}


bool valid(const SsaFunction& function, SsaId id) {
    return id != kNoValue && id < function.values.size();
}

bool isComparison(MintOp op) {
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
            return true;
        default:
            return false;
    }
}

void markKind(RecoveredType* type, RecoveredTypeKind kind) {
    if (type->kind == RecoveredTypeKind::kUnknown ||
        type->kind == RecoveredTypeKind::kUnsignedInteger ||
        type->kind == RecoveredTypeKind::kSignedInteger) {
        type->kind = kind;
    }
}

bool fieldBase(const SsaFunction& function,const std::vector<SsaId>& loadSources,const MemoryAnalysis* memory,SsaId address,SsaId* base,u64* offset) {
    // Resolve register copies and constant arithmetic to one object identity.
    // This is a local layout hypothesis; indexed accesses, casts, absolute
    // addresses and negative frame offsets do not establish object fields.
    __int128 displacement=0;
    for(unsigned depth=0;depth<512 && valid(function,address);++depth) {
        const auto& value=function.values[address];
        if(address<loadSources.size() && valid(function,loadSources[address]) && function.values[loadSources[address]].storage.size==value.storage.size) {
            address=loadSources[address];continue;
        }
        if(memory && address<memory->values.size()) {
            const auto& fact=memory->values[address];
            if(fact.kind==MemoryBaseKind::kAbsolute)return false;
            if((fact.kind==MemoryBaseKind::kSymbolic||fact.kind==MemoryBaseKind::kEntryStack) && fact.base!=address && valid(function,fact.base)) {
                displacement+=fact.offset;address=fact.base;continue;
            }
        }
        if(value.storage.space==Space::kConstant)return false;
        if(value.def!=SsaDef::kInsn || value.defIndex>=function.insns.size()) {
            if(displacement<0 || displacement>1024*1024)return false;
            *base=address;*offset=static_cast<u64>(displacement);return true;
        }
        const auto& insn=function.insns[value.defIndex];
        if(insn.op==MintOp::kCopy && valid(function,insn.use[0]) &&
            function.values[insn.use[0]].storage.size==value.storage.size) {address=insn.use[0];continue;}
        if(insn.op==MintOp::kAdd || insn.op==MintOp::kSub) {
            SsaId candidate=insn.use[0],constant=insn.use[1];
            if(!valid(function,candidate)||!valid(function,constant))return false;
            if(insn.op==MintOp::kAdd && function.values[candidate].storage.space==Space::kConstant)std::swap(candidate,constant);
            const auto& literal=function.values[constant].storage;
            if(literal.space!=Space::kConstant || literal.size>8 || !literal.size)return false;
            const unsigned bits=literal.size*8;const u64 signBit=u64{1}<<(bits-1);
            const __int128 amount=static_cast<__int128>(literal.offset)-((literal.offset&signBit)?(static_cast<__int128>(1)<<bits):0);
            displacement+=insn.op==MintOp::kAdd?amount:-amount;
            address=candidate;continue;
        }
        if(insn.op==MintOp::kZeroExt || insn.op==MintOp::kSignExt || insn.op==MintOp::kTrunc)return false;
        if(displacement<0 || displacement>1024*1024)return false;
        *base=address;*offset=static_cast<u64>(displacement);return true;
    }
    return false;
}

}  // namespace

Status recoverTypes(const SsaFunction& function, TypeRecovery* out) {
    return recoverTypes(function,out,nullptr);
}
Status recoverTypes(const SsaFunction& function,TypeRecovery* out,const MemoryAnalysis* suppliedMemory) {
    if (out == nullptr) {
        return Status::error(ErrorCode::kInternalError, "no type recovery output");
    }
    const std::vector<std::string> problems = function.verify();
    if (!problems.empty()) {
        return Status::error(ErrorCode::kBadFormat,
                             "cannot recover types from invalid SSA: " + problems.front());
    }
    *out = TypeRecovery();
    out->values.resize(function.values.size());
    for (size_t i = 0; i < function.values.size(); ++i) {
        out->values[i].width = function.values[i].storage.size;
    }

    // Memory evidence may identify a reloaded pointer with the exact SSA value
    // stored on every incoming path. A call/alias/partial write or disagreeing
    // store sources leaves this relation absent. Failure of the bounded memory
    // sidecar costs precision, never the ordinary local type reconstruction.
    std::vector<SsaId> loadSources(function.values.size(),kNoValue);
    MemoryAnalysis preparedMemory;
    const MemoryAnalysis* memory=suppliedMemory&&suppliedMemory->matches(function)?suppliedMemory:nullptr;
    if(!memory && analyzeMemory(function,&preparedMemory).ok())memory=&preparedMemory;
    if(memory && memory->values.size()==function.values.size() && memory->accessByInstruction.size()==function.insns.size())for(const auto& access:memory->accesses) {
        if(access.store || access.instruction>=function.insns.size() || !valid(function,access.reachingValue))continue;
        const auto& insn=function.insns[access.instruction];
        if(insn.op==MintOp::kLoad && valid(function,insn.dest) && function.values[insn.dest].storage.size==function.values[access.reachingValue].storage.size)
            loadSources[insn.dest]=access.reachingValue;
    }

    std::map<SsaId, std::vector<std::pair<u64, SsaId>>> structAccesses;
    for (u32 index = 0; index < function.insns.size(); ++index) {
        const SsaInsn& insn = function.insns[index];
        if (insn.dead) continue;
        const bool hasDest=valid(function,insn.dest);
        if (!hasDest && insn.op!=MintOp::kStore) continue;
        RecoveredType ignored;
        RecoveredType& dest = hasDest ? out->values[insn.dest] : ignored;
        switch (insn.op) {
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
                dest.kind = RecoveredTypeKind::kBoolean;
                dest.width = 1;
                break;
            case MintOp::kLoad:
                if (valid(function, insn.use[0])) {
                    markKind(&out->values[insn.use[0]], RecoveredTypeKind::kPointer);
                }
                break;
            case MintOp::kFloatAdd:
            case MintOp::kFloatSub:
            case MintOp::kFloatMul:
            case MintOp::kFloatDiv:
            case MintOp::kFloatFma:
            case MintOp::kFloatSqrt:
            case MintOp::kFloatAbs:
            case MintOp::kFloatNeg:
                dest.kind = RecoveredTypeKind::kFloat;
                break;
            case MintOp::kIntToFloat:
            case MintOp::kIntToFloatU:
            case MintOp::kFloatConvert:
                dest.kind = RecoveredTypeKind::kFloat;
                break;
            case MintOp::kFloatToInt:
                dest.kind=RecoveredTypeKind::kSignedInteger;
                break;
            case MintOp::kFloatToIntU:
                dest.kind = RecoveredTypeKind::kUnsignedInteger;
                break;
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
            case MintOp::kVectorShl:
            case MintOp::kVectorShrU:
            case MintOp::kVectorShrS:
            case MintOp::kVectorPackS:
            case MintOp::kVectorPackU:
            case MintOp::kVectorExtendS:
            case MintOp::kVectorExtendU:
            case MintOp::kVectorInsert:
            case MintOp::kVectorSelect:
            case MintOp::kVectorShuffle:
            case MintOp::kVectorPermute:
            case MintOp::kVectorSplat:
            case MintOp::kVectorLoad:
                // The aggregate is 16 bytes; how it divides into lanes now lives on
                // the instruction as laneWidth rather than only in the machine
                // instruction's arrangement operand.
                dest.width = 16;
                break;
            case MintOp::kStore:
                if (valid(function, insn.use[0])) {
                    markKind(&out->values[insn.use[0]], RecoveredTypeKind::kPointer);
                }
                break;
            case MintOp::kDivS:
            case MintOp::kRemS:
                markKind(&dest, RecoveredTypeKind::kSignedInteger);
                break;
            default: break;
        }

        if (isComparison(insn.op)) {
            for (unsigned slot = 0; slot < 2; ++slot) {
                if (valid(function, insn.use[slot]) && insn.op == MintOp::kLessS) {
                    markKind(&out->values[insn.use[slot]],
                             RecoveredTypeKind::kSignedInteger);
                }
            }
        }

        // Every access through a pointer is a field observation, whichever way the
        // data moves. Collecting only loads, as this used to, means a structure
        // written but never read looks like it has no fields at all — and an output
        // parameter is exactly that shape.
        if (insn.op == MintOp::kLoad || insn.op == MintOp::kStore) {
            // For a load the field's width is the loaded value's; for a store it is
            // the stored value's, since the destination is memory.
            const SsaId accessed = insn.op == MintOp::kLoad ? insn.dest : insn.use[1];
            if (valid(function, insn.use[0]) && valid(function, accessed)) {
                const SsaId address = insn.use[0];
                SsaId base = kNoValue;
                u64 offset = 0;
                const bool usable=fieldBase(function,loadSources,memory,address,&base,&offset);
                markKind(&out->values[address], RecoveredTypeKind::kPointer);
                if (usable) {
                    // A bare dereference is the field at offset zero. Leaving it out
                    // lost the first member of every structure whose head is read
                    // without arithmetic, which is the common case.
                    structAccesses[base].push_back({offset, accessed});
                    markKind(&out->values[base], RecoveredTypeKind::kPointer);
                }
            }
        }
    }

    // Propagate established evidence through a worklist rather than an arbitrary
    // four scans. Constant offsets preserve pointers; pointer differences and
    // arbitrary integer arithmetic do not. Phi results require agreement on every
    // incoming edge, so one pointer branch cannot type an unrelated integer branch.
    const u32 instructionCount=static_cast<u32>(function.insns.size());
    const size_t nodeCount=function.insns.size()+function.phis.size();
    std::vector<std::vector<u32>> users(function.values.size());
    for(u32 n=0;n<instructionCount;++n)if(!function.insns[n].dead)
        for(auto id:function.insns[n].use)if(valid(function,id))users[id].push_back(n);
    for(u32 n=0;n<instructionCount;++n) {
        const auto& insn=function.insns[n];
        if(!insn.dead && valid(function,insn.dest) && valid(function,loadSources[insn.dest]))users[loadSources[insn.dest]].push_back(n);
    }
    for(u32 n=0;n<function.phis.size();++n)if(!function.phis[n].dead)
        for(auto id:function.phis[n].args)if(valid(function,id))users[id].push_back(instructionCount+n);
    std::vector<u32> queue;std::vector<bool> queued(nodeCount,true);
    for(u32 n=0;n<nodeCount;++n)queue.push_back(n);
    auto adopt=[&](SsaId id,RecoveredTypeKind kind) {
        if(!valid(function,id) || kind==RecoveredTypeKind::kUnknown || function.values[id].storage.space==Space::kConstant)return;
        auto& target=out->values[id];
        if(target.kind==kind || target.kind!=RecoveredTypeKind::kUnknown)return;
        target.kind=kind;
        for(auto user:users[id])if(!queued[user]){queued[user]=true;queue.push_back(user);}
    };
    for(size_t cursor=0;cursor<queue.size();++cursor) {
        const u32 node=queue[cursor];queued[node]=false;
        if(node>=instructionCount) {
            const auto& phi=function.phis[node-instructionCount];
            if(phi.dead || phi.args.empty())continue;
            auto kind=RecoveredTypeKind::kUnknown;bool consistent=true;
            for(auto id:phi.args) {
                if(!valid(function,id)){consistent=false;break;}
                auto candidate=out->values[id].kind;
                if(candidate==RecoveredTypeKind::kUnknown || (kind!=RecoveredTypeKind::kUnknown&&candidate!=kind)){consistent=false;break;}
                kind=candidate;
            }
            if(consistent)adopt(phi.dest,kind);
            continue;
        }
        const auto& insn=function.insns[node];
        if(insn.dead || !valid(function,insn.dest))continue;
        if(insn.op==MintOp::kLoad && valid(function,loadSources[insn.dest])) {
            const auto source=loadSources[insn.dest];
            adopt(insn.dest,out->values[source].kind);
            if(out->values[insn.dest].kind==RecoveredTypeKind::kPointer)adopt(source,RecoveredTypeKind::kPointer);
        } else if(insn.op==MintOp::kCopy && valid(function,insn.use[0]) && out->values[insn.dest].width==out->values[insn.use[0]].width) {
            adopt(insn.dest,out->values[insn.use[0]].kind);
            if(out->values[insn.dest].kind==RecoveredTypeKind::kPointer)adopt(insn.use[0],RecoveredTypeKind::kPointer);
        } else if((insn.op==MintOp::kAdd || insn.op==MintOp::kSub) && valid(function,insn.use[0]) && valid(function,insn.use[1])) {
            auto base=insn.use[0],offset=insn.use[1];
            if(insn.op==MintOp::kAdd && function.values[base].storage.space==Space::kConstant)std::swap(base,offset);
            if(function.values[offset].storage.space==Space::kConstant && out->values[base].kind==RecoveredTypeKind::kPointer)
                adopt(insn.dest,RecoveredTypeKind::kPointer);
        }
    }

    for (auto& access : structAccesses) {
        if (access.second.size() < 2) continue;
        std::sort(access.second.begin(), access.second.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });

        // One field per offset. The same member is normally touched many times, and
        // each access used to become its own field, so a structure read in a loop
        // came out with the same offset repeated a dozen times. Where accesses at
        // one offset disagree about width the widest wins: a four-byte read of a
        // member is consistent with an eight-byte member, not the other way round.
        std::vector<std::pair<u64, SsaId>> merged;
        for (const auto& entry : access.second) {
            if (!valid(function, entry.second)) continue;
            if (!merged.empty() && merged.back().first == entry.first) {
                if (out->values[entry.second].width >
                    out->values[merged.back().second].width) {
                    merged.back().second = entry.second;
                }
                continue;
            }
            merged.push_back(entry);
        }
        // A single field is just a dereference; it takes two to be a layout.
        if (merged.size() < 2) continue;
        access.second = merged;

        RecoveredStruct structure;
        structure.base = access.first;
        const u32 structId = static_cast<u32>(out->structs.size());
        for (const auto& field : access.second) {
            RecoveredField recovered;
            recovered.offset = field.first;
            recovered.width = out->values[field.second].width;
            recovered.base = access.first;
            recovered.type = out->values[field.second];
            structure.fields.push_back(recovered);
        }
        if (structure.fields.empty()) continue;
        out->structs.push_back(std::move(structure));
        out->values[access.first].kind = RecoveredTypeKind::kPointer;
        out->values[access.first].structId = structId;
        for (const auto& field : out->structs.back().fields) {
            // The load result is the value recovered at this offset. Look it up
            // again rather than retaining a parallel index in the public result.
            for (const auto& original : access.second) {
                if (original.first == field.offset && valid(function, original.second)) {
                    out->values[original.second].structId = structId;
                }
            }
        }
    }

    // A parameter is an incoming value in a register the convention uses to pass
    // arguments. Not every incoming value qualifies: the stack pointer and the link
    // register are live on entry to every function, and callee-saved registers are
    // read on entry by any function that saves them in its prologue. Counting those
    // reported over five parameters for the average function in a real library,
    // where the true average is closer to two.
    std::vector<std::pair<u32, SsaId>> ordered;
    for (SsaId id = 0; id < function.values.size(); ++id) {
        const SsaValue& value = function.values[id];
        if (value.def != SsaDef::kEntry || value.uses == 0) continue;
        if (value.storage.space != Space::kRegister) continue;
        const u32 position = argumentPosition(function.arch, value.storage);
        if (position == kNotAnArgument) continue;
        ordered.push_back({position, id});
    }
    // Argument order, not value order: a signature is only useful in the order the
    // convention passes things.
    std::sort(ordered.begin(), ordered.end());
    for (const auto& entry : ordered) {
        out->parameters.push_back({entry.second, out->values[entry.second]});
    }
    return Status::success();
}

}  // namespace mint
