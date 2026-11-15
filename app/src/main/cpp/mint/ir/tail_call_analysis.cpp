#include "mint/ir/tail_call_analysis.h"

#include "mint/ir/registers.h"
#include <algorithm>
#include <array>
#include <deque>
#include <limits>

namespace mint {
namespace {
constexpr i64 kMaxOffset=16*1024*1024;
enum class Kind : u8 { kBottom,kUnknown,kConstant,kEntryRegister };
struct Value {
    Kind kind=Kind::kBottom;
    u64 value=0;
    i64 offset=0;
};
Value unknown(){return {Kind::kUnknown,0,0};}
bool equal(const Value& a,const Value& b){return a.kind==b.kind&&a.value==b.value&&a.offset==b.offset;}
Value join(const Value& a,const Value& b) {
    if(a.kind==Kind::kBottom)return b;
    if(b.kind==Kind::kBottom)return a;
    return equal(a,b)?a:unknown();
}
i64 signedValue(u64 value) {
    return value<=static_cast<u64>(std::numeric_limits<i64>::max())?static_cast<i64>(value):-1-static_cast<i64>(~value);
}
bool shift(i64 a,i64 b,i64* result) {
    if((b>0&&a>std::numeric_limits<i64>::max()-b)||(b<0&&a<std::numeric_limits<i64>::min()-b))return false;
    *result=a+b;return *result>=-kMaxOffset&&*result<=kMaxOffset;
}
class Proof {
public:
    Proof(const SsaFunction& function,u32 instruction,const MemoryAnalysis& memory,const TailCallAnalysisOptions& options)
        :f_(function),instruction_(instruction),memory_(memory),options_(options){}
    std::string reason;
    bool run() {
        if(!paths()||!effects()||!values())return false;
        const std::array<u64,7> preserved={{x86::kRsp,x86::kRbx,x86::kRbp,x86::kGpr(12),x86::kGpr(13),x86::kGpr(14),x86::kGpr(15)}};
        for(auto storage:preserved)if(!restored(storage))return false;
        return true;
    }
private:
    const SsaFunction& f_;u32 instruction_;const MemoryAnalysis& memory_;const TailCallAnalysisOptions& options_;
    size_t work_=0;
    bool exhausted_=false;
    std::vector<std::vector<u32>> predecessors_;
    std::vector<u8> reachable_,relevant_;
    std::vector<Value> facts_;
    std::vector<SsaId> reloads_;
    bool fail(const char* why){reason=why;return false;}
    bool tick(){if(work_>=std::min<size_t>(options_.maxWork,2000000)){exhausted_=true;return fail("tail-state proof work limit exceeded");}++work_;return true;}
    bool valid(SsaId id)const{return id<f_.values.size();}
    u32 end(u32 block)const{return f_.blocks[block].firstInsn+f_.blocks[block].insnCount;}
    bool paths() {
        predecessors_.resize(f_.blocks.size());reachable_.assign(f_.blocks.size(),0);relevant_.assign(f_.blocks.size(),0);
        for(const auto& block:f_.blocks)for(auto next:block.successors){if(!tick())return false;predecessors_[next].push_back(block.id);}
        std::deque<u32> queue;queue.push_back(0);reachable_[0]=1;
        while(!queue.empty()) {
            if(!tick())return false;const auto block=queue.front();queue.pop_front();
            for(auto next:f_.blocks[block].successors){if(!tick())return false;if(!reachable_[next]){reachable_[next]=1;queue.push_back(next);}}
        }
        const auto target=f_.insns[instruction_].block;
        if(!reachable_[target])return fail("tail exit is unreachable");
        queue.push_back(target);relevant_[target]=1;
        while(!queue.empty()) {
            if(!tick())return false;const auto block=queue.front();queue.pop_front();
            for(auto prior:predecessors_[block]){if(!tick())return false;if(reachable_[prior]&&!relevant_[prior]){relevant_[prior]=1;queue.push_back(prior);}}
        }
        return true;
    }
    bool effects() {
        for(const auto& block:f_.blocks)if(relevant_[block.id]) {
            const u32 limit=block.id==f_.insns[instruction_].block?instruction_:end(block.id);
            for(u32 n=block.firstInsn;n<limit;++n) {
                if(!tick())return false;const auto& insn=f_.insns[n];
                // Physical machine effects remain relevant even when register
                // DCE has no ordinary SSA consumer for the original assignment.
                if(insn.op==MintOp::kCall||insn.op==MintOp::kCallInd||insn.op==MintOp::kTailCall||
                   insn.op==MintOp::kIntrinsic||insn.op==MintOp::kMemoryFence||isAtomicMemory(insn.op)||insn.op==MintOp::kTrap)
                    return fail("unknown call, ordering or register effect reaches the tail exit");
                if(insn.op!=MintOp::kStore&&insn.op!=MintOp::kVectorStore)continue;
                if(!valid(insn.use[0])||!valid(insn.use[1]))return fail("unresolved memory write reaches the tail exit");
                const auto& address=memory_.values[insn.use[0]];
                const u8 width=f_.values[insn.use[1]].storage.size;
                if(address.kind!=MemoryBaseKind::kEntryStack||address.pointerWidth!=8||!width||width>16||
                   address.offset < -kMaxOffset||address.offset>kMaxOffset||
                   !(address.offset>=8||(address.offset<0&&address.offset+width<=0)))
                    return fail("a write may modify the original return-address slot");
            }
        }
        return true;
    }
    Value evaluate(SsaId id) {
        const auto& value=f_.values[id];
        if(value.def==SsaDef::kConstant) {
            if(!value.storage.isConstant()||!value.storage.size||value.storage.size>8)return unknown();
            const u64 mask=value.storage.size==8?~u64{0}:(u64{1}<<(value.storage.size*8))-1;
            return {Kind::kConstant,value.storage.offset&mask,0};
        }
        if(value.storage.size!=8)return unknown();
        if(value.def==SsaDef::kEntry)return value.storage.isRegister()&&value.storage.offset<=x86::kGpr(15)&&value.storage.offset%8==0?
            Value{Kind::kEntryRegister,value.storage.offset,0}:unknown();
        if(value.def==SsaDef::kPhi) {
            if(value.defIndex>=f_.phis.size())return unknown();const auto& phi=f_.phis[value.defIndex];
            if(phi.args.empty())return unknown();Value result;
            for(auto arg:phi.args){if(!tick()||!valid(arg)||f_.values[arg].storage.size!=8)return unknown();result=join(result,facts_[arg]);}
            return result;
        }
        if(value.defIndex>=f_.insns.size())return unknown();const auto& insn=f_.insns[value.defIndex];
        if(insn.dest!=id)return unknown();
        if(insn.op==MintOp::kLoad)return valid(reloads_[id])?facts_[reloads_[id]]:unknown();
        if(insn.op==MintOp::kCopy)return valid(insn.use[0])&&f_.values[insn.use[0]].storage.size==8?facts_[insn.use[0]]:unknown();
        if(insn.op==MintOp::kSelect) {
            if(!valid(insn.use[0])||!valid(insn.use[1])||!valid(insn.use[2])||
               f_.values[insn.use[1]].storage.size!=8||f_.values[insn.use[2]].storage.size!=8)return unknown();
            const auto& condition=facts_[insn.use[0]];
            if(condition.kind==Kind::kConstant)return facts_[insn.use[condition.value?1:2]];
            const auto result=join(facts_[insn.use[1]],facts_[insn.use[2]]);
            return condition.kind==Kind::kBottom&&result.kind==Kind::kUnknown?Value{}:result;
        }
        if((insn.op!=MintOp::kAdd&&insn.op!=MintOp::kSub)||!valid(insn.use[0])||!valid(insn.use[1])||
           f_.values[insn.use[0]].storage.size!=8||f_.values[insn.use[1]].storage.size!=8)return unknown();
        auto base=facts_[insn.use[0]],delta=facts_[insn.use[1]];
        if(base.kind==Kind::kBottom||delta.kind==Kind::kBottom)return {};
        if(insn.op==MintOp::kAdd&&base.kind==Kind::kConstant&&delta.kind==Kind::kEntryRegister)std::swap(base,delta);
        if(delta.kind!=Kind::kConstant)return unknown();
        if(base.kind==Kind::kConstant)return {Kind::kConstant,insn.op==MintOp::kAdd?base.value+delta.value:base.value-delta.value,0};
        if(base.kind!=Kind::kEntryRegister)return unknown();
        i64 amount=signedValue(delta.value);
        if(insn.op==MintOp::kSub){if(amount==std::numeric_limits<i64>::min())return unknown();amount=-amount;}
        if(!shift(base.offset,amount,&base.offset))return unknown();return base;
    }
    bool values() {
        facts_.resize(f_.values.size());reloads_.assign(f_.values.size(),kNoValue);
        std::vector<std::vector<SsaId>> users(f_.values.size());
        for(const auto& access:memory_.accesses) {
            if(!tick())return false;
            if(access.store||access.instruction>=f_.insns.size()||access.width!=8||!valid(access.reachingValue)||f_.values[access.reachingValue].storage.size!=8)continue;
            const auto& load=f_.insns[access.instruction];
            if(load.op==MintOp::kLoad&&valid(load.dest)&&f_.values[load.dest].storage.size==8)reloads_[load.dest]=access.reachingValue;
        }
        for(SsaId id=0;id<f_.values.size();++id) {
            if(!tick())return false;const auto& value=f_.values[id];
            if(value.def==SsaDef::kInsn) {
                const auto& insn=f_.insns[value.defIndex];for(auto use:insn.use){if(!tick())return false;if(valid(use))users[use].push_back(id);}
                if(valid(reloads_[id]))users[reloads_[id]].push_back(id);
            } else if(value.def==SsaDef::kPhi)for(auto arg:f_.phis[value.defIndex].args){if(!tick())return false;users[arg].push_back(id);}
        }
        std::deque<SsaId> queue;std::vector<u8> queued(f_.values.size(),1);
        for(SsaId id=0;id<f_.values.size();++id)queue.push_back(id);
        auto solve=[&]() {
            while(!queue.empty()) {
                if(!tick())return false;const auto id=queue.front();queue.pop_front();queued[id]=0;
                const auto next=join(facts_[id],evaluate(id));if(exhausted_)return false;if(equal(next,facts_[id]))continue;
                facts_[id]=next;for(auto user:users[id])if(!queued[user]){queued[user]=1;queue.push_back(user);}
            }
            return true;
        };
        if(!solve())return false;
        // Seedless cyclic definitions do not prove an entry identity.
        for(SsaId id=0;id<f_.values.size();++id)if(facts_[id].kind==Kind::kBottom) {
            facts_[id]=unknown();for(auto user:users[id])if(!queued[user]){queued[user]=1;queue.push_back(user);}
        }
        return solve();
    }
    bool restored(u64 offset) {
        const Varnode storage=Varnode::reg(offset,8);const Value entry{Kind::kEntryRegister,offset,0};
        auto scan=[&](u32 block,u32 limit,bool* found) {
            *found=false;
            for(u32 n=limit;n>f_.blocks[block].firstInsn;) {
                if(!tick())return false;const auto& insn=f_.insns[--n];
                for(auto clobber:insn.clobbers){if(!tick())return false;if(f_.values[clobber].storage.overlaps(storage))return fail("a clobbered saved register reaches the tail exit");}
                if(!valid(insn.dest)||!f_.values[insn.dest].storage.overlaps(storage))continue;
                *found=true;
                if(f_.values[insn.dest].storage!=storage)return fail("partial saved-register restoration is unproven");
                const auto value=insn.dead&&insn.op==MintOp::kCopy&&valid(insn.use[0])&&f_.values[insn.use[0]].storage.size==8?
                    facts_[insn.use[0]]:facts_[insn.dest];
                return equal(value,entry)||fail(offset==x86::kRsp?"entry stack pointer is not restored":"callee-saved register is not restored");
            }
            return true;
        };
        const auto tail=f_.insns[instruction_].block;bool found=false;
        if(!scan(tail,instruction_,&found))return false;if(found)return true;
        std::deque<u32> queue;std::vector<u8> visited(f_.blocks.size());
        auto predecessors=[&](u32 block){for(auto prior:predecessors_[block]){if(!tick())return false;if(reachable_[prior]&&!visited[prior]){visited[prior]=1;queue.push_back(prior);}}return true;};
        // A missing entry-register SSA value is an unchanged implicit input,
        // never a fabricated source parameter. Check every backedge as well.
        if(!predecessors(tail))return false;
        while(!queue.empty()) {
            if(!tick())return false;const auto block=queue.front();queue.pop_front();
            if(!scan(block,end(block),&found))return false;if(!found&&!predecessors(block))return false;
        }
        return true;
    }
};
}
Status proveX86SysvTailState(const SsaFunction& function,u32 branchInsn,const MemoryAnalysis* memory,
    TailCallStateProof* output,const TailCallAnalysisOptions& options) {
    if(!output)return Status::error(ErrorCode::kBadFormat,"missing tail-state output");
    if(function.arch!=Arch::kX86_64||function.byteOrder!=ByteOrder::kLittle)return Status::error(ErrorCode::kUnsupported,"tail-state proof requires little-endian x86-64 SSA");
    if(function.values.size()>std::min<size_t>(options.maxValues,32768)||function.insns.size()>std::min<size_t>(options.maxInstructions,8192)||
       function.phis.size()>std::min<size_t>(options.maxValues,32768)||function.blocks.size()>std::min<size_t>(options.maxBlocks,512))
        return Status::error(ErrorCode::kTooLarge,"tail-state SSA bounds exceeded");
    size_t links=0;const size_t maxLinks=std::min<size_t>(options.maxLinks,262144);
    auto take=[&](size_t count){if(count>maxLinks-links)return false;links+=count;return true;};
    for(const auto& insn:function.insns)if(insn.switchCases.size()>256||insn.tailInputs.size()>6||!take(insn.clobbers.size()+3+insn.switchCases.size()*2+insn.tailInputs.size()))return Status::error(ErrorCode::kTooLarge,"tail-state instruction link bounds exceeded");
    for(const auto& phi:function.phis)if(!take(phi.args.size()))return Status::error(ErrorCode::kTooLarge,"tail-state phi link bounds exceeded");
    for(const auto& block:function.blocks)if(!take(block.successors.size())||!take(block.predecessors.size())||!take(block.phis.size()))return Status::error(ErrorCode::kTooLarge,"tail-state CFG link bounds exceeded");
    if(branchInsn>=function.insns.size()||function.blocks.empty()||function.blocks[0].start!=function.entry||!function.verify().empty())
        return Status::error(ErrorCode::kBadFormat,"invalid tail-state SSA");
    const auto& branch=function.insns[branchInsn];
    if((branch.op!=MintOp::kBranch&&branch.op!=MintOp::kTailCall)||branch.dead||branch.use[0]>=function.values.size())
        return Status::error(ErrorCode::kBadFormat,"tail-state site is not a live direct branch");
    const auto& target=function.values[branch.use[0]];const auto& block=function.blocks[branch.block];
    if(target.def!=SsaDef::kConstant||!target.storage.isConstant()||target.storage.size!=8||!block.successors.empty()||
       branchInsn!=block.firstInsn+block.insnCount-1)
        return Status::error(ErrorCode::kBadFormat,"tail-state site is not a terminal native-width direct exit");
    MemoryAnalysis computed;const MemoryAnalysis* facts=memory&&memory->matches(function)?memory:nullptr;
    if(!facts){const auto status=analyzeMemory(function,&computed);if(!status.ok())return status;facts=&computed;}
    TailCallStateProof prepared;Proof proof(function,branchInsn,*facts,options);prepared.complete=proof.run();
    prepared.reason=prepared.complete?"entry stack, return slot and SysV saved registers are preserved":proof.reason;
    *output=std::move(prepared);return Status::success();
}
}
