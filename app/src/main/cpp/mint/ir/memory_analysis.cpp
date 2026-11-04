#include "mint/ir/memory_analysis.h"

#include <algorithm>
#include <deque>
#include <limits>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include "mint/ir/registers.h"
#include "mint/ir/dominance.h"
#include "mint/plugin/architecture_bridge.h"

namespace mint {
namespace {
bool same(const MemoryAddress& a,const MemoryAddress& b) {
    return std::tie(a.kind,a.base,a.absolute,a.offset,a.pointerWidth)==std::tie(b.kind,b.base,b.absolute,b.offset,b.pointerWidth);
}
u8 pointerWidth(Arch arch) {MintArchitectureSemanticsV2 abi{};if(architecturePluginAbi(arch,&abi))return abi.pointer_size;return arch==Arch::kX86_32||arch==Arch::kArm32||arch==Arch::kThumb||arch==Arch::kRiscV32 ? 4 : 8;}
u64 stackOffset(Arch arch) {
    MintArchitectureSemanticsV2 abi{};if(architecturePluginAbi(arch,&abi))return abi.stack_pointer_offset;
    if(arch==Arch::kAArch64)return arm64::kSp;
    if(arch==Arch::kArm32||arch==Arch::kThumb)return arm32::kSp;
    if(arch==Arch::kRiscV32||arch==Arch::kRiscV64)return riscv::kSp;
    return x86::kRsp;
}
i64 signedBits(u64 bits,u8 width) {
    if(width<8) {const unsigned n=width*8;const u64 mask=(u64{1}<<n)-1;bits&=mask;if(bits&(u64{1}<<(n-1)))bits|=~mask;}
    return bits<=u64(std::numeric_limits<i64>::max()) ? static_cast<i64>(bits) : -1-static_cast<i64>(~bits);
}
bool add(i64 a,i64 b,i64* out) {
    if((b>0&&a>std::numeric_limits<i64>::max()-b)||(b<0&&a<std::numeric_limits<i64>::min()-b))return false;
    *out=a+b;return true;
}
MemoryAddress unknown() {return {};}
bool boundedGraph(const SsaFunction& function) {
    if(function.values.size()>250000 || function.insns.size()>250000 || function.phis.size()>250000 || function.blocks.size()>25000)return false;
    size_t links=0;
    auto take=[&](size_t count){if(count>4000000-links)return false;links+=count;return true;};
    for(const auto& insn:function.insns)if(!take(insn.clobbers.size()+3))return false;
    for(const auto& phi:function.phis)if(!take(phi.args.size()))return false;
    for(const auto& block:function.blocks)if(!take(block.successors.size())||!take(block.predecessors.size())||!take(block.phis.size()))return false;
    return true;
}
u64 fingerprint(const SsaFunction& function) {
    u64 hash=1469598103934665603ull;
    auto mix=[&](u64 value){for(unsigned n=0;n<8;++n){hash^=u8(value>>(n*8));hash*=1099511628211ull;}};
    mix(function.entry);mix(static_cast<u8>(function.arch));mix(static_cast<u8>(function.byteOrder));
    mix(function.values.size());mix(function.insns.size());mix(function.phis.size());mix(function.blocks.size());
    for(const auto& value:function.values){mix(static_cast<u8>(value.def));mix(value.defIndex);mix(static_cast<u8>(value.storage.space));mix(value.storage.offset);mix(value.storage.size);}
    for(const auto& insn:function.insns){mix(static_cast<u8>(insn.op));mix(insn.dest);for(auto use:insn.use)mix(use);mix(insn.dead);mix(insn.block);mix(insn.laneWidth);mix(insn.clobbers.size());for(auto clobber:insn.clobbers)mix(clobber);}
    for(const auto& phi:function.phis){mix(phi.dest);mix(phi.block);mix(phi.dead);mix(phi.args.size());for(auto arg:phi.args)mix(arg);}
    for(const auto& block:function.blocks){mix(block.id);mix(block.start);mix(block.firstInsn);mix(block.insnCount);mix(block.phis.size());for(auto phi:block.phis)mix(phi);mix(block.successors.size());for(auto successor:block.successors)mix(successor);mix(block.predecessors.size());for(auto predecessor:block.predecessors)mix(predecessor);}
    return hash;
}
bool readMemory(MintOp op){return op==MintOp::kLoad||op==MintOp::kVectorLoad;}
bool writeMemory(MintOp op){return op==MintOp::kStore||op==MintOp::kVectorStore;}
bool barrier(MintOp op){return op==MintOp::kCall||op==MintOp::kCallInd||op==MintOp::kIntrinsic||op==MintOp::kMemoryFence||isAtomicMemory(op);}
struct Slot {
    MemoryAddress address;u8 width;
    bool operator==(const Slot& other)const {return width==other.width && same(address,other.address);}
    bool operator<(const Slot& other)const {
        return std::tie(address.kind,address.base,address.absolute,address.offset,address.pointerWidth,width)<std::tie(other.address.kind,other.address.base,other.address.absolute,other.address.offset,other.address.pointerWidth,other.width);
    }
};
using Definitions=std::vector<u32>;
using State=std::map<Slot,Definitions>;
SsaId agreedValue(const SsaFunction& function,const Definitions& definitions) {
    SsaId value=kNoValue;
    for(auto definition:definitions) {
        if(definition>=function.insns.size())return kNoValue;
        const auto& store=function.insns[definition];
        if(!writeMemory(store.op)||store.use[1]>=function.values.size())return kNoValue;
        if(value==kNoValue)value=store.use[1];else if(value!=store.use[1])return kNoValue;
    }
    return value;
}
MemoryAddress evaluate(const SsaFunction& function,SsaId id,const std::vector<MemoryAddress>& facts,const std::vector<u8>& resolved) {
    const auto& value=function.values[id];const u8 width=pointerWidth(function.arch);
    if(value.def==SsaDef::kConstant && value.storage.size<=8)return {MemoryBaseKind::kAbsolute,kNoValue,value.storage.offset & (value.storage.size<8 ? ((u64{1}<<(value.storage.size*8))-1) : ~u64{0}),0,width};
    if(value.def==SsaDef::kEntry) {
        if(value.storage.size!=width)return unknown();
        return {value.storage.isRegister()&&value.storage.offset==stackOffset(function.arch) ? MemoryBaseKind::kEntryStack : MemoryBaseKind::kSymbolic,id,0,0,width};
    }
    if(value.def==SsaDef::kPhi) {
        if(value.defIndex>=function.phis.size() || function.phis[value.defIndex].dead)return unknown();
        MemoryAddress fact;bool first=true;
        for(auto arg:function.phis[value.defIndex].args) {
            if(arg>=facts.size())return unknown();if(!resolved[arg])continue;
            if(first){fact=facts[arg];first=false;}else if(!same(fact,facts[arg]))return unknown();
        }
        return first ? unknown() : fact;
    }
    if(value.defIndex>=function.insns.size())return unknown();
    const auto& insn=function.insns[value.defIndex];if(insn.dead)return unknown();
    // Results of loads/calls are distinct symbolic SSA pointer roots when used
    // as addresses. Different roots remain possible aliases, never heap objects.
    if(insn.op==MintOp::kLoad || insn.op==MintOp::kAtomicLoad || isAtomicRmw(insn.op) || insn.op==MintOp::kCall || insn.op==MintOp::kCallInd) {
        if(value.storage.size!=width)return unknown();
        return {MemoryBaseKind::kSymbolic,id,0,0,width};
    }
    if(insn.dest!=id || insn.use[0]>=facts.size())return unknown();
    const auto a=facts[insn.use[0]];
    if(insn.op==MintOp::kCopy)return value.storage.size==function.values[insn.use[0]].storage.size ? a : unknown();
    if(insn.op==MintOp::kSelect && insn.use[1]<facts.size() && insn.use[2]<facts.size()) {
        if(a.kind==MemoryBaseKind::kAbsolute)return facts[insn.use[a.absolute ? 1 : 2]];
        return same(facts[insn.use[1]],facts[insn.use[2]]) ? facts[insn.use[1]] : unknown();
    }
    if((insn.op!=MintOp::kAdd && insn.op!=MintOp::kSub)||insn.use[1]>=facts.size() || value.storage.size!=width)return unknown();
    const auto b=facts[insn.use[1]];auto base=a,delta=b;
    if(insn.op==MintOp::kAdd && a.kind==MemoryBaseKind::kAbsolute && b.kind!=MemoryBaseKind::kAbsolute){base=b;delta=a;}
    if(delta.kind!=MemoryBaseKind::kAbsolute || !base.exact())return unknown();
    if(base.kind==MemoryBaseKind::kAbsolute) {
        base.absolute=insn.op==MintOp::kSub ? base.absolute-delta.absolute : base.absolute+delta.absolute;
        if(width==4)base.absolute&=0xffffffffu;return base;
    }
    i64 displacement=signedBits(delta.absolute,width);
    if(insn.op==MintOp::kSub) {if(displacement==std::numeric_limits<i64>::min())return unknown();displacement=-displacement;}
    if(!add(base.offset,displacement,&base.offset) || base.offset < -16*1024*1024 || base.offset > 16*1024*1024)return unknown();
    return base;
}
Status addressFacts(const SsaFunction& function,std::vector<MemoryAddress>* facts,size_t* sharedWork=nullptr) {
    facts->assign(function.values.size(),{});
    std::vector<u8> resolved(function.values.size(),0),queued(function.values.size(),1);
    std::vector<std::vector<SsaId>> users(function.values.size());std::deque<SsaId> queue;
    for(SsaId id=0;id<function.values.size();++id) {
        const auto& v=function.values[id];if(!v.storage.size || v.storage.size>16)return Status::error(ErrorCode::kBadFormat,"invalid general memory value width");
        queue.push_back(id);
        if(v.def==SsaDef::kInsn && v.defIndex<function.insns.size())for(auto use:function.insns[v.defIndex].use)if(use<users.size())users[use].push_back(id);
        if(v.def==SsaDef::kPhi && v.defIndex<function.phis.size())for(auto use:function.phis[v.defIndex].args)if(use<users.size())users[use].push_back(id);
    }
    size_t work=0;
    while(!queue.empty()) {
        if(++work>4000000 || (sharedWork&&++*sharedWork>2000000))return Status::error(ErrorCode::kTooLarge,"general memory address convergence limit");
        auto id=queue.front();queue.pop_front();queued[id]=0;
        const auto next=evaluate(function,id,*facts,resolved);
        if(resolved[id] && same(next,(*facts)[id]))continue;
        (*facts)[id]=next;resolved[id]=1;
        for(auto user:users[id])if(!queued[user]){queue.push_back(user);queued[user]=1;}
    }
    return Status::success();
}

// Summaries describe writes in ordinary modeled memory, not source-level
// purity or operating-system effects. A pointer parameter is identified by its
// physical live-in register, avoiding a guessed source calling convention.
struct SummaryRange {
    bool absolute=false;u64 address=0;Varnode input;i64 offset=0;u8 width=0;
    bool operator<(const SummaryRange& other) const {
        return std::tie(absolute,address,input.space,input.offset,input.size,offset,width)<
            std::tie(other.absolute,other.address,other.input.space,other.input.offset,other.input.size,other.offset,other.width);
    }
};
struct CallSummary {bool complete=false;std::vector<SummaryRange> writes;};
struct CallContext {
    const SsaFunction& function;const std::vector<MemoryAddress>& facts;Dominance dominance;std::vector<u8> priorEffects;
    CallContext(const SsaFunction& f,const std::vector<MemoryAddress>& a):function(f),facts(a) {
        std::vector<std::vector<u32>> edges;for(const auto& block:f.blocks)edges.push_back(block.successors);dominance=computeDominance(edges);
        std::vector<u8> incoming(f.blocks.size(),0),hasEffect(f.blocks.size(),0),processed(f.blocks.size(),0),queued(f.blocks.size(),0);
        for(const auto& block:f.blocks)for(u32 i=block.firstInsn;i<block.firstInsn+block.insnCount;++i) {
            const auto& insn=f.insns[i];if(!insn.dead&&(insn.op==MintOp::kCall||insn.op==MintOp::kCallInd||insn.op==MintOp::kIntrinsic))hasEffect[block.id]=1;
        }
        std::deque<u32> queue;if(!f.blocks.empty()){queue.push_back(0);queued[0]=1;}
        while(!queue.empty()) {
            const auto block=queue.front();queue.pop_front();queued[block]=0;processed[block]=1;
            for(auto successor:f.blocks[block].successors) {
                const bool next=incoming[block]||hasEffect[block];
                const bool changed=next&&!incoming[successor];incoming[successor]|=next;
                if((changed||!processed[successor])&&!queued[successor]){queued[successor]=1;queue.push_back(successor);}
            }
        }
        priorEffects.assign(f.insns.size(),0);
        for(const auto& block:f.blocks) {
            bool prior=incoming[block.id];for(u32 i=block.firstInsn;i<block.firstInsn+block.insnCount;++i) {
                priorEffects[i]=prior;const auto& insn=f.insns[i];if(!insn.dead&&(insn.op==MintOp::kCall||insn.op==MintOp::kCallInd||insn.op==MintOp::kIntrinsic))prior=true;
            }
        }
    }
};
class CallSummaries {
public:
    explicit CallSummaries(const MemoryFunctionResolver& resolver):resolver_(resolver){}
    std::vector<MemoryDependencyBinding> dependencies;
    MemoryCallEffect call(const CallContext& context,u32 index) {
        MemoryCallEffect result;result.instruction=index;
        const auto& function=context.function;const auto& insn=function.insns[index];
        if(insn.op!=MintOp::kCall || insn.use[0]>=function.values.size())return result;
        const auto& target=function.values[insn.use[0]];
        if(target.def!=SsaDef::kConstant || !target.storage.isConstant() || target.storage.size>8)return result;
        if((function.arch==Arch::kX86_32||function.arch==Arch::kX86_64)&&target.storage.size!=pointerWidth(function.arch))return result;
        result.target=target.storage.offset;
        const auto summary=get(result.target,function.arch,function.byteOrder);
        if(!summary.complete)return result;
        const bool x86=function.arch==Arch::kX86_32||function.arch==Arch::kX86_64;
        MemoryAddress entryStack;
        if(x86) {
            // CALL writes its return address even when a leaf body itself is
            // read-only. The IR call does not explicitly contain that push.
            entryStack=at(context,index,Varnode::reg(stackOffset(function.arch),pointerWidth(function.arch)));
            if(!displace(&entryStack,-static_cast<i64>(pointerWidth(function.arch))))return result;
            result.writes.push_back({entryStack,pointerWidth(function.arch)});
        }
        for(const auto& write:summary.writes) {
            auto address=write.absolute?MemoryAddress{MemoryBaseKind::kAbsolute,kNoValue,write.address,0,pointerWidth(function.arch)}:
                x86&&write.input.offset==stackOffset(function.arch)?entryStack:at(context,index,write.input);
            if(!write.absolute && !displace(&address,write.offset))return result;
            if(!address.exact())return result;
            result.writes.push_back({address,write.width});
        }
        result.complete=true;return result;
    }
private:
    const MemoryFunctionResolver& resolver_;
    struct Cache {bool active=true;CallSummary summary;};
    std::map<Address,Cache> cache_;
    size_t depth_=0,values_=0,instructions_=0,work_=0;
    static bool forbiddenInput(Arch arch,const Varnode& input) {
        if(input.offset==stackOffset(arch))return true;
        if(arch==Arch::kAArch64)return input.offset==arm64::kXn(30)||input.offset==arm64::kPc;
        if(arch==Arch::kArm32||arch==Arch::kThumb)return input.offset==arm32::kLr||input.offset==arm32::kPc;
        if(arch==Arch::kRiscV32||arch==Arch::kRiscV64)return input.offset==riscv::kXn(1)||input.offset==riscv::kXn(5)||input.offset==riscv::kPc;
        return input.offset==x86::kRip;
    }
    bool tick(){return ++work_<=2000000;}
    MemoryAddress at(const CallContext& context,u32 index,const Varnode& storage,bool validatingReturn=false) {
        const auto& f=context.function;
        // Even a later ADD/COPY can retain stale SP/callee-saved facts from the
        // ABI-based register SSA. Do not use any of that graph as a hidden input
        // after a prior call, including one on another path or a backedge.
        // Return validation is local to a summary whose nested calls must all
        // pass the same ABI-preservation checks before it can become complete.
        if(!validatingReturn&&context.priorEffects[index])return unknown();
        auto matches=[&](SsaId id){return id<f.values.size()&&f.values[id].storage==storage;};
        auto scan=[&](u32 block,u32 limit,MemoryAddress* found) {
            const auto& cfg=f.blocks[block];
            for(u32 n=std::min<u32>(limit,cfg.firstInsn+cfg.insnCount);n>cfg.firstInsn;) {
                if(!tick()){*found=unknown();return true;}const auto& insn=f.insns[--n];
                for(auto id:insn.clobbers)if(matches(id)){*found=context.facts[id];return true;}
                if(matches(insn.dest)) {
                    // SSA copy/phi simplification drops names, not the original
                    // physical register assignment needed by an implicit input.
                    *found=insn.dead&&insn.op==MintOp::kCopy&&insn.use[0]<f.values.size()&&f.values[insn.use[0]].storage.size==storage.size?
                        context.facts[insn.use[0]]:context.facts[insn.dest];return true;
                }
                // The core SSA names ABI caller-saved clobbers, but a hidden
                // input may also be SP or a nonstandard callee-saved register.
                // No earlier call is evidence that either physical value
                // survived unchanged. An explicit later assignment is needed.
                if(!validatingReturn&&!insn.dead&&(insn.op==MintOp::kCall||insn.op==MintOp::kCallInd||insn.op==MintOp::kIntrinsic)){*found=unknown();return true;}
            }
            for(auto pi:cfg.phis) {
                if(!tick()){*found=unknown();return true;}const auto& phi=f.phis[pi];if(!matches(phi.dest))continue;
                if(!phi.dead){*found=context.facts[phi.dest];return true;}
                MemoryAddress joined;bool first=true;
                for(auto arg:phi.args) {
                    if(!tick()||arg>=context.facts.size()||!context.facts[arg].exact()||(!first&&!same(joined,context.facts[arg]))){*found=unknown();return true;}
                    joined=context.facts[arg];first=false;
                }
                *found=first?unknown():joined;return true;
            }
            return false;
        };
        MemoryAddress entry;
        for(SsaId id=0;id<f.values.size();++id){if(!tick())return unknown();if(f.values[id].def==SsaDef::kEntry&&matches(id)){entry=context.facts[id];break;}}
        // SP may be absent from a leaf/caller SSA because the explicit IR never
        // reads it. Its implicit entry identity is still a symbolic stack base,
        // not a disjoint address space or an invented concrete stack address.
        if(!entry.exact()&&storage.offset==stackOffset(f.arch)&&storage.size==pointerWidth(f.arch))entry={MemoryBaseKind::kEntryStack,kNoValue,0,0,storage.size};
        const u32 initial=f.insns[index].block;MemoryAddress result;
        if(scan(initial,index,&result))return result;
        // Calls have implicit physical inputs. Pruned SSA need not have a phi
        // for one that kCall never explicitly reads. Visit every predecessor
        // path instead of inferring agreement from an absent phi or an idom.
        std::deque<u32> queue;std::vector<u8> visited(f.blocks.size(),0);bool found=false;
        auto agree=[&](const MemoryAddress& next){if(!next.exact())return false;if(!found){result=next;found=true;return true;}return same(result,next);};
        auto predecessors=[&](u32 block){for(auto pred:context.dominance.predecessors[block])if(context.dominance.reachable(pred)&&!visited[pred]){visited[pred]=1;queue.push_back(pred);}};
        if(initial==0&&!agree(entry))return unknown();predecessors(initial);
        while(!queue.empty()) {
            if(!tick())return unknown();const u32 block=queue.front();queue.pop_front();MemoryAddress reaching;
            if(scan(block,f.blocks[block].firstInsn+f.blocks[block].insnCount,&reaching)){if(!agree(reaching))return unknown();continue;}
            if(block==0&&!agree(entry))return unknown();predecessors(block);
        }
        return found?result:unknown();
    }
    static bool displace(MemoryAddress* address,i64 offset) {
        if(!address->exact())return false;
        if(address->kind==MemoryBaseKind::kAbsolute){address->absolute+=static_cast<u64>(offset);if(address->pointerWidth==4)address->absolute&=0xffffffffu;return true;}
        return add(address->offset,offset,&address->offset)&&address->offset>=-16*1024*1024&&address->offset<=16*1024*1024;
    }
    bool record(const SsaFunction& f,const MemoryAddress& address,u8 width,std::set<SummaryRange>* writes) {
        SummaryRange write;write.width=width;
        if(!width || width>16 || !address.exact())return false;
        if(address.kind==MemoryBaseKind::kAbsolute){write.absolute=true;write.address=address.absolute;}
        else if(address.kind==MemoryBaseKind::kEntryStack) {
            write.input=Varnode::reg(stackOffset(f.arch),pointerWidth(f.arch));write.offset=address.offset;
        } else if(address.kind==MemoryBaseKind::kSymbolic && address.base<f.values.size()) {
            const auto& value=f.values[address.base];
            if(value.def!=SsaDef::kEntry || !value.storage.isRegister() || value.storage.size!=pointerWidth(f.arch) || forbiddenInput(f.arch,value.storage))return false;
            write.input=value.storage;write.offset=address.offset;
        } else return false;
        writes->insert(write);return writes->size()<=64;
    }
    bool internalBranch(const SsaFunction& f,const SsaInsn& insn) {
        const unsigned operand=insn.op==MintOp::kCondBranch?1:0;
        if(insn.use[operand]>=f.values.size())return false;
        const auto& target=f.values[insn.use[operand]];
        if(target.def!=SsaDef::kConstant)return false;
        for(auto successor:f.blocks[insn.block].successors)if(f.blocks[successor].start==target.storage.offset)return true;
        return false;
    }
    CallSummary get(Address target,Arch arch,ByteOrder order) {
        const auto cached=cache_.find(target);if(cached!=cache_.end())return cached->second.active?CallSummary{}:cached->second.summary;
        const bool native=arch==Arch::kAArch64||arch==Arch::kArm32||arch==Arch::kThumb||arch==Arch::kX86_32||arch==Arch::kX86_64||arch==Arch::kRiscV32||arch==Arch::kRiscV64;
        if(!resolver_ || cache_.size()>=64 || depth_>=16 || !native)return {};
        auto inserted=cache_.emplace(target,Cache{}).first;
        auto finish=[&](CallSummary summary){inserted->second.active=false;inserted->second.summary=summary;return summary;};
        std::shared_ptr<const SsaFunction> body;
        try{body=resolver_(target);}catch(...){return finish({});}
        if(!body || body->entry!=target || body->arch!=arch || body->byteOrder!=order || !boundedGraph(*body) || body->blocks.empty() ||
            body->values.size()>32768 || body->phis.size()>32768 || body->insns.size()>8192 || body->blocks.size()>512 ||
            body->values.size()>250000-values_ || body->insns.size()>250000-instructions_)return finish({});
        values_+=body->values.size();instructions_+=body->insns.size();
        if(!body->verify().empty())return finish({});
        dependencies.push_back({body,fingerprint(*body)});
        std::vector<MemoryAddress> facts;if(!addressFacts(*body,&facts,&work_).ok())return finish({});
        CallContext context(*body,facts);std::set<SummaryRange> writes;std::vector<Varnode> preservedWrites;
        const auto callerSaved=abiCallerSavedRegisters(arch);
        for(const auto& insn:body->insns)if(insn.dest<body->values.size()) {
            const auto storage=body->values[insn.dest].storage;
            if(storage.isRegister()&&std::find(callerSaved.begin(),callerSaved.end(),storage)==callerSaved.end()&&
                std::find(preservedWrites.begin(),preservedWrites.end(),storage)==preservedWrites.end())preservedWrites.push_back(storage);
        }
        const Varnode sp=Varnode::reg(stackOffset(arch),pointerWidth(arch));
        if((arch==Arch::kX86_32||arch==Arch::kX86_64)&&std::find(preservedWrites.begin(),preservedWrites.end(),sp)==preservedWrites.end())return finish({});
        ++depth_;struct Depth {size_t& depth;~Depth(){--depth;}} guard{depth_};
        for(const auto& block:body->blocks) {
            if(!context.dominance.reachable(block.id))continue;
            const SsaInsn* last=nullptr;
            for(u32 index=block.firstInsn;index<block.firstInsn+block.insnCount;++index) {
                if(!tick())return finish({});const auto& insn=body->insns[index];if(insn.dead)continue;last=&insn;
                if(writeMemory(insn.op)) {
                    if(insn.use[0]>=facts.size()||insn.use[1]>=body->values.size()||!record(*body,facts[insn.use[0]],body->values[insn.use[1]].storage.size,&writes))return finish({});
                } else if(insn.op==MintOp::kCall || insn.op==MintOp::kCallInd) {
                    const auto effect=call(context,index);if(!effect.complete)return finish({});
                    for(const auto& write:effect.writes)if(!record(*body,write.address,write.width,&writes))return finish({});
                } else if(barrier(insn.op)||insn.op==MintOp::kBranchInd||insn.op==MintOp::kTrap)return finish({});
                else if((insn.op==MintOp::kBranch||insn.op==MintOp::kCondBranch)&&!internalBranch(*body,insn))return finish({});
                if(insn.op==MintOp::kReturn)for(const auto& storage:preservedWrites) {
                    const auto value=at(context,index,storage,true);
                    if(storage==sp) {
                        const i64 expected=arch==Arch::kX86_32||arch==Arch::kX86_64?pointerWidth(arch):0;
                        if(value.kind!=MemoryBaseKind::kEntryStack||value.offset!=expected)return finish({});
                    } else if(value.kind!=MemoryBaseKind::kSymbolic||value.offset!=0||value.base>=body->values.size()||
                        body->values[value.base].def!=SsaDef::kEntry||body->values[value.base].storage!=storage)return finish({});
                }
            }
            if(!last || (last->op!=MintOp::kReturn&&last->op!=MintOp::kBranch&&last->op!=MintOp::kCondBranch))return finish({});
        }
        CallSummary result;result.complete=true;result.writes.assign(writes.begin(),writes.end());return finish(std::move(result));
    }
};

}
bool MemoryAnalysis::matches(const SsaFunction& function) const {
    if(dependencies.size()>64)return false;
    for(const auto& dependency:dependencies)if(!dependency.function || !boundedGraph(*dependency.function) || dependency.fingerprint!=fingerprint(*dependency.function))return false;
    return analyzedFunction==&function && values.size()==function.values.size() && accessByInstruction.size()==function.insns.size() && boundedGraph(function) && functionFingerprint==fingerprint(function);
}
bool memoryMayAlias(const MemoryAddress& a,u8 aWidth,const MemoryAddress& b,u8 bWidth) {
    if(!aWidth || !bWidth || !a.exact() || !b.exact() || a.pointerWidth!=b.pointerWidth || (a.pointerWidth!=4&&a.pointerWidth!=8))return true;
    if(a.kind==MemoryBaseKind::kAbsolute && b.kind==MemoryBaseKind::kAbsolute) {
        const u64 mask=a.pointerWidth==4 ? 0xffffffffu : ~u64{0};
        if(a.absolute>mask-(aWidth-1) || b.absolute>mask-(bWidth-1))return true;
        return a.absolute<=b.absolute ? b.absolute-a.absolute<aWidth : a.absolute-b.absolute<bWidth;
    }
    if(a.kind==b.kind && a.base==b.base && a.kind!=MemoryBaseKind::kAbsolute) {
        // Equal bases cancel modulo the target address space. Unsigned modular
        // distances handle signed extrema and RV32 wrap without host overflow.
        const u64 mask=a.pointerWidth==4?0xffffffffu:~u64{0};
        const u64 left=static_cast<u64>(a.offset)&mask,right=static_cast<u64>(b.offset)&mask;
        return ((right-left)&mask)<aWidth || ((left-right)&mask)<bWidth;
    }
    return true;
}
Status analyzeMemory(const SsaFunction& function,MemoryAnalysis* result) {
    return analyzeMemory(function,result,{});
}
Status analyzeMemory(const SsaFunction& function,MemoryAnalysis* result,const MemoryFunctionResolver& functions) {
    if(!result)return Status::error(ErrorCode::kInternalError,"null general memory output");
    *result={};
    if(!boundedGraph(function))
        return Status::error(ErrorCode::kTooLarge,"general memory analysis resource limit");
    if(function.blocks.empty()){result->values.resize(function.values.size());result->accessByInstruction.assign(function.insns.size(),kNoValue);result->analyzedFunction=&function;result->functionFingerprint=fingerprint(function);return Status::success();}
    for(size_t i=0;i<function.blocks.size();++i) {
        const auto& block=function.blocks[i];
        if(block.id!=i || block.firstInsn>function.insns.size() || block.insnCount>function.insns.size()-block.firstInsn)return Status::error(ErrorCode::kBadFormat,"invalid general memory CFG block");
        for(auto next:block.successors)if(next>=function.blocks.size())return Status::error(ErrorCode::kBadFormat,"invalid general memory CFG edge");
    }
    MemoryAnalysis prepared;prepared.values.resize(function.values.size());prepared.accessByInstruction.assign(function.insns.size(),kNoValue);
    auto addressStatus=addressFacts(function,&prepared.values);if(!addressStatus.ok())return addressStatus;
    std::vector<u32> callByInstruction(function.insns.size(),kNoValue);
    if(functions) {
        if(!function.verify().empty())return Status::error(ErrorCode::kBadFormat,"invalid caller SSA for interprocedural memory effects");
        CallContext context(function,prepared.values);CallSummaries summaries(functions);size_t effectRanges=0;
        for(u32 n=0;n<function.insns.size();++n)if(!function.insns[n].dead && (function.insns[n].op==MintOp::kCall||function.insns[n].op==MintOp::kCallInd)) {
            if(prepared.calls.size()>=4096)continue;
            auto effect=summaries.call(context,n);
            if(effect.writes.size()>65536-effectRanges){effect.complete=false;effect.writes.clear();}
            effectRanges+=effect.writes.size();callByInstruction[n]=static_cast<u32>(prepared.calls.size());prepared.calls.push_back(std::move(effect));
        }
        prepared.dependencies=std::move(summaries.dependencies);
    }
    std::vector<std::vector<u32>> predecessors(function.blocks.size());
    for(const auto& block:function.blocks)for(auto next:block.successors)predecessors[next].push_back(block.id);
    for(u32 index=0;index<function.insns.size();++index) {
        const auto& insn=function.insns[index];if(insn.dead)continue;
        if(barrier(insn.op)) {
            const auto call=callByInstruction[index];
            if(call<prepared.calls.size()&&prepared.calls[call].complete) {
                if(prepared.calls[call].writes.empty())++prepared.readOnlyCalls;else ++prepared.selectiveCalls;
            } else ++prepared.callBarriers;
        }
        if(!readMemory(insn.op) && !writeMemory(insn.op))continue;
        const auto value=readMemory(insn.op) ? insn.dest : insn.use[1];
        const auto address=insn.use[0]<prepared.values.size() ? prepared.values[insn.use[0]] : unknown();
        const u8 width=value<function.values.size() ? function.values[value].storage.size : 0;
        if(!width)return Status::error(ErrorCode::kBadFormat,"invalid general memory access width");
        prepared.accessByInstruction[index]=static_cast<u32>(prepared.accesses.size());
        MemoryAccess access;access.instruction=index;access.address=address;access.width=width;access.store=writeMemory(insn.op);
        prepared.accesses.push_back(std::move(access));
        if(!address.exact()){++prepared.unresolvedAccesses;if(writeMemory(insn.op))++prepared.unknownWrites;}
    }
    std::vector<State> outgoing(function.blocks.size());std::vector<u8> processed(function.blocks.size()),inQueue(function.blocks.size());
    std::deque<u32> blocks{0};inQueue[0]=1;
    auto incoming=[&](u32 block) {
        State state;bool first=block!=0;
        for(auto pred:predecessors[block]) {
            if(!processed[pred])continue;
            if(first){state=outgoing[pred];first=false;continue;}
            for(auto it=state.begin();it!=state.end();) {
                const auto found=outgoing[pred].find(it->first);
                if(found==outgoing[pred].end()){it=state.erase(it);continue;}
                Definitions merged;merged.reserve(it->second.size()+found->second.size());
                std::set_union(it->second.begin(),it->second.end(),found->second.begin(),found->second.end(),std::back_inserter(merged));
                // Too many reaching stores loses precision rather than selecting
                // a convenient predecessor or dropping an inconvenient path.
                if(merged.size()>32){it=state.erase(it);continue;}
                it->second=std::move(merged);++it;
            }
        }
        return state;
    };
    std::map<std::pair<Slot,Definitions>,u32> phiIds;
    size_t phiDefinitions=0;
    auto transfer=[&](u32 block,State state,bool record) {
        const auto& cfg=function.blocks[block];
        for(u32 i=cfg.firstInsn;i<cfg.firstInsn+cfg.insnCount;++i) {
            const auto& insn=function.insns[i];if(insn.dead)continue;
            const auto ai=prepared.accessByInstruction[i];
            if(ai!=kNoValue) {
                auto& access=prepared.accesses[ai];Slot slot{access.address,access.width};
                if(access.store) {
                    u32 killed=0;
                    for(auto it=state.begin();it!=state.end();) {
                        if(memoryMayAlias(it->first.address,it->first.width,slot.address,slot.width)){it=state.erase(it);++killed;}else ++it;
                    }
                    if(access.address.exact())state[slot]={i};
                    if(record){access.invalidatedDefinitions=killed;access.memoryVersion=i+1;}
                } else if(record && access.address.exact()) {
                    const auto reaching=state.find(slot);
                    if(reaching!=state.end()) {
                        access.reachingValue=agreedValue(function,reaching->second);
                        if(access.reachingValue!=kNoValue)++prepared.agreedValueDependencies;
                        if(reaching->second.size()==1) {
                            access.reachingStore=reaching->second[0];access.memoryVersion=access.reachingStore+1;++prepared.exactDependencies;
                        } else if(!reaching->second.empty()) {
                            const auto key=std::make_pair(slot,reaching->second);auto found=phiIds.find(key);
                            if(found==phiIds.end() && prepared.phis.size()<100000 && phiDefinitions+reaching->second.size()<=1000000) {
                                const u32 id=static_cast<u32>(prepared.phis.size());
                                const u32 version=static_cast<u32>(function.insns.size())+id+1;
                                prepared.phis.push_back({version,access.address,access.width,reaching->second,access.reachingValue});
                                phiDefinitions+=reaching->second.size();found=phiIds.emplace(key,id).first;
                            }
                            if(found!=phiIds.end()){access.reachingPhi=found->second;access.memoryVersion=prepared.phis[found->second].version;}
                        }
                    }
                }
            }
            if(barrier(insn.op)) {
                const auto call=callByInstruction[i];
                if(call<prepared.calls.size()&&prepared.calls[call].complete) {
                    for(const auto& write:prepared.calls[call].writes)for(auto it=state.begin();it!=state.end();) {
                        if(memoryMayAlias(it->first.address,it->first.width,write.address,write.width))it=state.erase(it);else ++it;
                    }
                } else state.clear();
            }
            if(state.size()>4096)state.clear(); // Lose precision safely, never stores.
        }
        return state;
    };
    size_t work=0,stateEntries=0;
    while(!blocks.empty()) {
        const auto block=blocks.front();blocks.pop_front();inQueue[block]=0;
        work+=function.blocks[block].insnCount+outgoing[block].size()+predecessors[block].size();
        if(work>8000000)return Status::error(ErrorCode::kTooLarge,"general memory state convergence limit");
        auto next=transfer(block,incoming(block),false);const bool changed=!processed[block] || next!=outgoing[block];
        stateEntries-=outgoing[block].size();stateEntries+=next.size();if(stateEntries>1000000)return Status::error(ErrorCode::kTooLarge,"general memory state resource limit");
        outgoing[block]=std::move(next);processed[block]=1;
        if(changed)for(auto successor:function.blocks[block].successors)if(!inQueue[successor]){blocks.push_back(successor);inQueue[successor]=1;}
    }
    for(u32 block=0;block<function.blocks.size();++block)if(processed[block])transfer(block,incoming(block),true);
    prepared.analyzedFunction=&function;prepared.functionFingerprint=fingerprint(function);
    *result=std::move(prepared);return Status::success();
}
std::string MemoryAnalysis::toText(const SsaFunction& function) const {
    std::ostringstream out;out<<"Memory SSA evidence: "<<exactDependencies<<" exact store/load dependencies; "<<phis.size()<<" all-path memory merges; "<<agreedValueDependencies<<" agreed-value dependencies; "<<callBarriers<<" call/intrinsic barriers; "<<readOnlyCalls<<" proven read-only calls; "<<selectiveCalls<<" bounded write-effect calls; "<<unknownWrites<<" unknown writes; "<<unresolvedAccesses<<" unresolved accesses\n";
    for(const auto& access:accesses) {
        if(out.tellp()>1024*1024){out<<"[truncated]\n";break;}
        out<<"0x"<<std::hex<<(access.instruction<function.insns.size()?function.insns[access.instruction].address:0)<<std::dec<<(access.store?" store ":" load ")<<unsigned(access.width)<<" bytes at ";
        if(access.address.kind==MemoryBaseKind::kAbsolute)out<<"absolute 0x"<<std::hex<<access.address.absolute<<std::dec;
        else if(access.address.exact())out<<(access.address.kind==MemoryBaseKind::kEntryStack?"entry-SP":"symbolic SSA")<<" v"<<access.address.base<<(access.address.offset<0?"":"+")<<access.address.offset;
        else out<<"unknown address";
        if(!access.store) {
            out<<"; reaching-store="<<(access.reachingStore==kNoValue ? "unknown" : std::to_string(access.reachingStore));
            if(access.reachingPhi<phis.size()){out<<"; memory-merge="<<phis[access.reachingPhi].version<<" stores={";bool first=true;for(auto store:phis[access.reachingPhi].stores){if(!first)out<<',';first=false;out<<store;}out<<'}';}
            if(access.reachingValue!=kNoValue)out<<"; agreed-value=v"<<access.reachingValue;
        }
        else out<<"; killed="<<access.invalidatedDefinitions;
        out<<'\n';
    }
    for(const auto& call:calls) {
        if(out.tellp()>1024*1024){out<<"[truncated]\n";break;}
        out<<"call insn "<<call.instruction<<" target=";
        if(call.target==kNoAddress)out<<"unknown";else out<<"0x"<<std::hex<<call.target<<std::dec;
        out<<(call.complete?" verified body effects; writes=":" unknown effects; writes=")<<call.writes.size()<<'\n';
    }
    return out.str();
}
} // namespace mint
