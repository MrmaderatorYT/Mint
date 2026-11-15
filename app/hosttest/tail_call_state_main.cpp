#include "mint/ir/tail_call_analysis.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"
#include "mint/ssa/ssa_builder.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>

using namespace mint;
namespace {
unsigned checks=0;
void require(bool value,const std::string& reason){++checks;if(!value){std::cerr<<"tail state: "<<reason<<'\n';std::exit(1);}}
struct Fixture {
    IrFunction ir;u32 current=0;
    explicit Fixture(u32 blocks=1){ir.arch=Arch::kX86_64;ir.entry=0x1000;ir.blocks.resize(blocks);for(u32 n=0;n<blocks;++n){ir.blocks[n].id=n;ir.blocks[n].start=0x1000+0x100*n;ir.blocks[n].end=ir.blocks[n].start+0x100;}}
    Varnode reg(u64 offset){return Varnode::reg(offset,8);}
    Varnode sp(){return reg(x86::kRsp);}
    Varnode constant(u64 value){return Varnode::constant(value,8);}
    Varnode temp(){return Varnode::temp(ir.tempCount++,8);}
    void block(u32 id){current=id;ir.blocks[id].firstInsn=ir.insns.size();}
    void op(MintOp code,Varnode dest={},Varnode a={},Varnode b={}){IrInsn insn;insn.op=code;insn.dest=dest;insn.a=a;insn.b=b;insn.address=ir.blocks[current].start+ir.blocks[current].insnCount*4;ir.insns.push_back(insn);++ir.blocks[current].insnCount;}
    Varnode address(i64 offset){auto result=temp();op(MintOp::kAdd,result,sp(),constant(static_cast<u64>(offset)));return result;}
    void adjust(i64 offset){op(MintOp::kAdd,sp(),sp(),constant(static_cast<u64>(offset)));}
    void store(Varnode address,Varnode value){op(MintOp::kStore,{},address,value);}
    Varnode load(Varnode address){auto result=temp();op(MintOp::kLoad,result,address);return result;}
    void tail(){op(MintOp::kBranch,{},constant(0x8000));}
    void jump(u32 block){op(MintOp::kBranch,{},constant(ir.blocks[block].start));}
    void condition(u32 taken){auto test=Varnode::temp(ir.tempCount++,1);op(MintOp::kNotEqual,test,reg(x86::kRdi),constant(0));op(MintOp::kCondBranch,{},test,constant(ir.blocks[taken].start));}
    SsaFunction finish(){for(auto& block:ir.blocks)for(auto successor:block.successors)ir.blocks[successor].predecessors.push_back(block.id);
        require(ir.verify().empty(),"fixture IR verifies");normalizeRegisterAccesses(&ir);SsaFunction result;require(buildSsa(ir,&result).ok()&&result.verify().empty(),"normalized fixture SSA verifies");return result;}
};
u32 exit(const SsaFunction& function){for(u32 n=0;n<function.insns.size();++n){const auto& insn=function.insns[n];if(insn.op==MintOp::kBranch&&insn.use[0]<function.values.size()&&function.values[insn.use[0]].storage.isConstant()&&function.values[insn.use[0]].storage.offset==0x8000)return n;}require(false,"fixture has tail exit");return 0;}
TailCallStateProof proof(const SsaFunction& function,const MemoryAnalysis* memory=nullptr){TailCallStateProof result;const auto status=proveX86SysvTailState(function,exit(function),memory,&result);require(status.ok(),status.message());return result;}
void frames(){
    Fixture leaf;leaf.block(0);leaf.tail();auto ssa=leaf.finish();require(proof(ssa).complete,"frameless absent saved-register inputs are unchanged");
    auto converted=ssa;converted.insns[exit(ssa)].op=MintOp::kTailCall;TailCallStateProof convertedProof;require(proveX86SysvTailState(converted,exit(ssa),nullptr,&convertedProof).ok()&&convertedProof.complete,"converted terminal tail-call retains machine proof");
    for(bool balance:{false,true}){Fixture frame;frame.block(0);frame.adjust(-32);if(balance)frame.adjust(32);frame.tail();require(proof(frame.finish()).complete==balance,"entry-SP restoration is exact");}
    Fixture saved;saved.block(0);saved.adjust(-8);saved.store(saved.sp(),saved.reg(x86::kRbp));saved.op(MintOp::kCopy,saved.reg(x86::kRbp),saved.sp());const auto restored=saved.load(saved.sp());saved.op(MintOp::kCopy,saved.reg(x86::kRbp),restored);saved.adjust(8);saved.tail();
    auto restoredSsa=saved.finish();MemoryAnalysis memory;require(analyzeMemory(restoredSsa,&memory).ok(),"spill reload memory evidence builds");
    require(proof(restoredSsa,&memory).complete,"exact PUSH/POP-style reaching store restores saved RBP");
    for(auto offset:{x86::kRbx,x86::kRbp,x86::kGpr(12),x86::kGpr(13),x86::kGpr(14),x86::kGpr(15)})for(bool restore:{false,true}) {
        Fixture save;save.block(0);auto before=save.temp();save.op(MintOp::kCopy,before,save.reg(offset));save.op(MintOp::kCopy,save.reg(offset),save.constant(0x1234));if(restore)save.op(MintOp::kCopy,save.reg(offset),before);save.tail();
        require(proof(save.finish()).complete==restore,"every saved GPR requires exact restoration, including dead copies");
    }
}
void effects(){
    for(i64 offset:{-8,0,4,8}){Fixture store;store.block(0);store.store(store.address(offset),store.constant(7));store.tail();require(proof(store.finish()).complete==(offset==-8||offset==8),"partial original return-slot overlap rejects");}
    Fixture unknown;unknown.block(0);unknown.store(unknown.reg(x86::kRdi),unknown.constant(7));unknown.tail();require(!proof(unknown.finish()).complete,"symbolic pointer writes may alias original return address");
    Fixture absolute;absolute.block(0);absolute.store(absolute.constant(0x4000),absolute.constant(7));absolute.tail();require(!proof(absolute.finish()).complete,"absolute address is not proved disjoint from dynamic entry SP");
    for(auto op:{MintOp::kCall,MintOp::kCallInd,MintOp::kIntrinsic,MintOp::kMemoryFence}){Fixture barrier;barrier.block(0);barrier.op(op,{},op==MintOp::kCall||op==MintOp::kCallInd?barrier.constant(0x9000):Varnode{});barrier.tail();require(!proof(barrier.finish()).complete,"unknown reaching side effect rejects tail contract");}
    Fixture volatileWrite;volatileWrite.block(0);volatileWrite.op(MintOp::kCopy,volatileWrite.reg(x86::kRax),volatileWrite.constant(3));volatileWrite.tail();require(proof(volatileWrite.finish()).complete,"volatile register changes do not claim saved-register damage");
}
void paths(){
    for(bool balanced:{false,true}) {
        Fixture diamond(4);diamond.ir.blocks[0].successors={1,2};diamond.ir.blocks[1].successors={3};diamond.ir.blocks[2].successors={3};
        diamond.block(0);diamond.condition(1);diamond.block(1);diamond.adjust(-8);if(balanced)diamond.adjust(8);diamond.jump(3);
        diamond.block(2);diamond.jump(3);diamond.block(3);diamond.tail();require(proof(diamond.finish()).complete==balanced,"all predecessor physical stack states must restore entry identity");
    }
    Fixture separate(3);separate.ir.blocks[0].successors={1,2};separate.block(0);separate.condition(1);
    separate.block(1);separate.op(MintOp::kCall,{},separate.constant(0x9000));separate.adjust(8);separate.op(MintOp::kReturn,{},separate.constant(0));
    separate.block(2);separate.tail();require(proof(separate.finish()).complete,"a call on a path unable to reach this tail does not invalidate it");
    Fixture loop(3);loop.ir.blocks[0].successors={1};loop.ir.blocks[1].successors={1,2};loop.block(0);loop.jump(1);
    loop.block(1);loop.op(MintOp::kCopy,loop.reg(x86::kRbx),loop.constant(9));loop.condition(1);loop.block(2);loop.tail();require(!proof(loop.finish()).complete,"backedge saved-register corruption is not skipped");
    Fixture stableLoop(3);stableLoop.ir.blocks[0].successors={1};stableLoop.ir.blocks[1].successors={1,2};stableLoop.block(0);stableLoop.jump(1);
    stableLoop.block(1);stableLoop.adjust(-8);stableLoop.adjust(8);stableLoop.condition(1);stableLoop.block(2);stableLoop.tail();require(proof(stableLoop.finish()).complete,"stable loop restores SP on every iteration");
    for(bool agree:{false,true}) {
        Fixture savedDiamond(4);savedDiamond.ir.blocks[0].successors={1,2};savedDiamond.ir.blocks[1].successors={3};savedDiamond.ir.blocks[2].successors={3};
        savedDiamond.block(0);auto saved=savedDiamond.temp();savedDiamond.op(MintOp::kCopy,saved,savedDiamond.reg(x86::kRbx));savedDiamond.condition(1);
        savedDiamond.block(1);savedDiamond.op(MintOp::kCopy,savedDiamond.reg(x86::kRbx),savedDiamond.constant(7));if(agree)savedDiamond.op(MintOp::kCopy,savedDiamond.reg(x86::kRbx),saved);savedDiamond.jump(3);
        savedDiamond.block(2);savedDiamond.jump(3);savedDiamond.block(3);savedDiamond.tail();
        require(proof(savedDiamond.finish()).complete==agree,"missing hidden saved-register phi never substitutes an idom value");
    }
}
void validation(){
    Fixture fixture;fixture.block(0);fixture.adjust(-8);fixture.adjust(8);fixture.tail();auto ssa=fixture.finish();const auto branch=exit(ssa);
    TailCallStateProof result;result.complete=true;result.reason="sentinel";TailCallAnalysisOptions bounds;bounds.maxInstructions=1;
    require(!proveX86SysvTailState(ssa,branch,nullptr,&result,bounds).ok()&&result.reason=="sentinel","preflight bounds leave output unchanged");
    bounds={};bounds.maxWork=0;require(proveX86SysvTailState(ssa,branch,nullptr,&result,bounds).ok()&&!result.complete&&!result.reason.empty(),"work exhaustion loses proof explicitly");
    auto malformed=ssa;malformed.blocks[0].successors={999};result.reason="sentinel";
    require(!proveX86SysvTailState(malformed,branch,nullptr,&result).ok()&&result.reason=="sentinel","malformed SSA rejects transactionally");
    auto foreign=ssa;foreign.arch=Arch::kAArch64;require(!proveX86SysvTailState(foreign,branch,nullptr,&result).ok(),"foreign architecture rejects");
    auto excessive=ssa;excessive.insns[branch].tailInputs.assign(7,excessive.insns[branch].use[0]);result.reason="sentinel";
    require(!proveX86SysvTailState(excessive,branch,nullptr,&result).ok()&&result.reason=="sentinel","oversized explicit tail operands reject before verification");
    Fixture safe;safe.block(0);safe.store(safe.address(-8),safe.constant(9));safe.tail();auto effective=safe.finish();MemoryAnalysis stale;
    require(analyzeMemory(effective,&stale).ok()&&proof(effective,&stale).complete,"safe stack write sidecar establishes a complete initial proof");
    Fixture corrupt;corrupt.block(0);corrupt.store(corrupt.address(0),corrupt.constant(9));corrupt.tail();effective=corrupt.finish();
    require(!proof(effective,&stale).complete,"same-object mutation cannot reuse stale return-slot alias facts");
    MemoryAnalysis foreignMemory;require(analyzeMemory(ssa,&foreignMemory).ok(),"foreign memory fixture builds");
    require(!proof(effective,&foreignMemory).complete,"foreign sidecar is recomputed before checking original return slot");
}
}
int main(){frames();effects();paths();validation();std::cout<<checks<<" tail-call state checks passed\n";}
