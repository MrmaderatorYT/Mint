#include "mint/ir/memory_analysis.h"

#include <algorithm>
#include <deque>
#include <limits>
#include <map>
#include <sstream>
#include <tuple>
#include "mint/ir/registers.h"
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
bool readMemory(MintOp op){return op==MintOp::kLoad||op==MintOp::kVectorLoad;}
bool writeMemory(MintOp op){return op==MintOp::kStore||op==MintOp::kVectorStore;}
bool barrier(MintOp op){return op==MintOp::kCall||op==MintOp::kCallInd||op==MintOp::kIntrinsic||op==MintOp::kMemoryFence||op==MintOp::kAtomicLoad||op==MintOp::kAtomicStore||op==MintOp::kAtomicExchange||op==MintOp::kAtomicAdd||op==MintOp::kAtomicCompareExchange;}
struct Slot {
    MemoryAddress address;u8 width;
    bool operator==(const Slot& other)const {return width==other.width && same(address,other.address);}
    bool operator<(const Slot& other)const {
        return std::tie(address.kind,address.base,address.absolute,address.offset,address.pointerWidth,width)<std::tie(other.address.kind,other.address.base,other.address.absolute,other.address.offset,other.address.pointerWidth,other.width);
    }
};
using State=std::map<Slot,u32>;
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
    if(insn.op==MintOp::kLoad || insn.op==MintOp::kAtomicLoad || insn.op==MintOp::kAtomicExchange || insn.op==MintOp::kAtomicCompareExchange || insn.op==MintOp::kCall || insn.op==MintOp::kCallInd) {
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
}
bool memoryMayAlias(const MemoryAddress& a,u8 aWidth,const MemoryAddress& b,u8 bWidth) {
    if(!a.exact() || !b.exact() || a.pointerWidth!=b.pointerWidth)return true;
    if(a.kind==MemoryBaseKind::kAbsolute && b.kind==MemoryBaseKind::kAbsolute) {
        const u64 mask=a.pointerWidth==4 ? 0xffffffffu : ~u64{0};
        if(a.absolute>mask-(aWidth-1) || b.absolute>mask-(bWidth-1))return true;
        return a.absolute<=b.absolute ? b.absolute-a.absolute<aWidth : a.absolute-b.absolute<bWidth;
    }
    if(a.kind==b.kind && a.base==b.base && a.kind!=MemoryBaseKind::kAbsolute)
        return a.offset<b.offset+static_cast<i64>(bWidth) && b.offset<a.offset+static_cast<i64>(aWidth);
    return true;
}
Status analyzeMemory(const SsaFunction& function,MemoryAnalysis* result) {
    if(!result)return Status::error(ErrorCode::kInternalError,"null general memory output");
    *result={};
    if(function.values.size()>250000 || function.insns.size()>250000 || function.blocks.size()>25000)
        return Status::error(ErrorCode::kTooLarge,"general memory analysis resource limit");
    if(function.blocks.empty())return Status::success();
    for(size_t i=0;i<function.blocks.size();++i) {
        const auto& block=function.blocks[i];
        if(block.id!=i || block.firstInsn>function.insns.size() || block.insnCount>function.insns.size()-block.firstInsn)return Status::error(ErrorCode::kBadFormat,"invalid general memory CFG block");
        for(auto next:block.successors)if(next>=function.blocks.size())return Status::error(ErrorCode::kBadFormat,"invalid general memory CFG edge");
    }
    MemoryAnalysis prepared;prepared.values.resize(function.values.size());prepared.accessByInstruction.assign(function.insns.size(),kNoValue);
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
        if(++work>4000000)return Status::error(ErrorCode::kTooLarge,"general memory address convergence limit");
        auto id=queue.front();queue.pop_front();queued[id]=0;
        const auto next=evaluate(function,id,prepared.values,resolved);
        if(resolved[id] && same(next,prepared.values[id]))continue;
        prepared.values[id]=next;resolved[id]=1;
        for(auto user:users[id])if(!queued[user]){queue.push_back(user);queued[user]=1;}
    }
    std::vector<std::vector<u32>> predecessors(function.blocks.size());
    for(const auto& block:function.blocks)for(auto next:block.successors)predecessors[next].push_back(block.id);
    for(u32 index=0;index<function.insns.size();++index) {
        const auto& insn=function.insns[index];if(insn.dead)continue;
        if(barrier(insn.op))++prepared.callBarriers;
        if(!readMemory(insn.op) && !writeMemory(insn.op))continue;
        const auto value=readMemory(insn.op) ? insn.dest : insn.use[1];
        const auto address=insn.use[0]<prepared.values.size() ? prepared.values[insn.use[0]] : unknown();
        const u8 width=value<function.values.size() ? function.values[value].storage.size : 0;
        if(!width)return Status::error(ErrorCode::kBadFormat,"invalid general memory access width");
        prepared.accessByInstruction[index]=static_cast<u32>(prepared.accesses.size());
        prepared.accesses.push_back({index,address,width,writeMemory(insn.op),0,kNoValue,0});
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
                if(found==outgoing[pred].end() || found->second!=it->second)it=state.erase(it);else ++it;
            }
        }
        return state;
    };
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
                    if(access.address.exact())state[slot]=i+1;
                    if(record){access.invalidatedDefinitions=killed;access.memoryVersion=i+1;}
                } else if(record && access.address.exact()) {
                    const auto reaching=state.find(slot);
                    if(reaching!=state.end()){access.memoryVersion=reaching->second;access.reachingStore=reaching->second-1;++prepared.exactDependencies;}
                }
            }
            if(barrier(insn.op))state.clear();
            if(state.size()>4096)state.clear(); // Lose precision safely, never stores.
        }
        return state;
    };
    work=0;size_t stateEntries=0;
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
    *result=std::move(prepared);return Status::success();
}
std::string MemoryAnalysis::toText(const SsaFunction& function) const {
    std::ostringstream out;out<<"Memory SSA evidence: "<<exactDependencies<<" exact store/load dependencies; "<<callBarriers<<" call/intrinsic barriers; "<<unknownWrites<<" unknown writes; "<<unresolvedAccesses<<" unresolved accesses\n";
    for(const auto& access:accesses) {
        if(out.tellp()>1024*1024){out<<"[truncated]\n";break;}
        out<<"0x"<<std::hex<<(access.instruction<function.insns.size()?function.insns[access.instruction].address:0)<<std::dec<<(access.store?" store ":" load ")<<unsigned(access.width)<<" bytes at ";
        if(access.address.kind==MemoryBaseKind::kAbsolute)out<<"absolute 0x"<<std::hex<<access.address.absolute<<std::dec;
        else if(access.address.exact())out<<(access.address.kind==MemoryBaseKind::kEntryStack?"entry-SP":"symbolic SSA")<<" v"<<access.address.base<<(access.address.offset<0?"":"+")<<access.address.offset;
        else out<<"unknown address";
        if(!access.store)out<<"; reaching-store="<<(access.reachingStore==kNoValue ? "unknown" : std::to_string(access.reachingStore));
        else out<<"; killed="<<access.invalidatedDefinitions;
        out<<'\n';
    }
    return out.str();
}
} // namespace mint
