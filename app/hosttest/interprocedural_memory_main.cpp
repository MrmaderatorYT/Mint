#include "mint/ir/memory_analysis.h"
#include "mint/ir/type_recovery.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"
#include "mint/ssa/ssa_builder.h"
#include "mint/decompile/decompiler.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
using namespace mint;
namespace {
unsigned checks=0;
void require(bool yes,const std::string& label){++checks;if(!yes){std::cerr<<"interprocedural memory: "<<label<<'\n';std::exit(1);}}
struct Fixture {
    IrFunction ir;u32 current=0;
    Fixture(Arch arch,Address entry,u32 blocks=1){ir.arch=arch;ir.entry=entry;ir.name="memory_call";ir.blocks.resize(blocks);for(u32 n=0;n<blocks;++n){ir.blocks[n].id=n;ir.blocks[n].start=entry+n*0x100;ir.blocks[n].end=entry+(n+1)*0x100;}}
    u8 width()const{return ir.arch==Arch::kRiscV32||ir.arch==Arch::kArm32||ir.arch==Arch::kThumb||ir.arch==Arch::kX86_32?4:8;}
    Varnode arg(unsigned n)const{
        if(ir.arch==Arch::kAArch64)return Varnode::reg(arm64::kXn(n),width());
        if(ir.arch==Arch::kArm32||ir.arch==Arch::kThumb)return Varnode::reg(arm32::kRn(n),width());
        if(ir.arch==Arch::kRiscV32||ir.arch==Arch::kRiscV64)return Varnode::reg(riscv::kXn(10+n),width());
        return Varnode::reg(ir.arch==Arch::kX86_32?(n==0?x86::kRax:x86::kRcx):(n==0?x86::kRdi:x86::kRsi),width());
    }
    bool x86()const{return ir.arch==Arch::kX86_32||ir.arch==Arch::kX86_64;}
    Varnode sp()const{return Varnode::reg(ir.arch==Arch::kAArch64?arm64::kSp:ir.arch==Arch::kArm32||ir.arch==Arch::kThumb?arm32::kSp:ir.arch==Arch::kRiscV32||ir.arch==Arch::kRiscV64?riscv::kSp:x86::kRsp,width());}
    Varnode constant(u64 value,u8 size=0)const{const auto bytes=size?size:width();return Varnode::constant(bytes<8?value&((u64{1}<<(bytes*8))-1):value,bytes);}
    Varnode temp(u8 size=0){return Varnode::temp(ir.tempCount++,size?size:width());}
    void block(u32 n){current=n;ir.blocks[n].firstInsn=ir.insns.size();}
    void op(MintOp code,Varnode dest={},Varnode a={},Varnode b={}){IrInsn insn;insn.op=code;insn.dest=dest;insn.a=a;insn.b=b;insn.address=ir.blocks[current].start+4*ir.blocks[current].insnCount;ir.insns.push_back(insn);++ir.blocks[current].insnCount;}
    Varnode address(Varnode base,i64 offset){auto value=temp();op(MintOp::kAdd,value,base,constant(static_cast<u64>(offset)));return value;}
    void store(Varnode address,Varnode value){op(MintOp::kStore,{},address,value);}
    Varnode load(Varnode address){auto value=temp();op(MintOp::kLoad,value,address);return value;}
    void call(Address target,bool indirect=false){op(indirect?MintOp::kCallInd:MintOp::kCall,{},constant(target));}
    Varnode condition(){auto value=temp(1);op(MintOp::kNotEqual,value,arg(1),constant(0));return value;}
    void ret(){if(x86())op(MintOp::kAdd,sp(),sp(),constant(width()));op(MintOp::kReturn,{},constant(0x7000));}
    void branch(u32 next){op(MintOp::kBranch,{},constant(ir.blocks[next].start));}
    SsaFunction finish(){for(auto& b:ir.blocks)for(auto successor:b.successors)ir.blocks[successor].predecessors.push_back(b.id);
        const auto errors=ir.verify();for(const auto& error:errors)std::cerr<<error<<'\n';require(errors.empty(),"fixture IR verifies");normalizeRegisterAccesses(&ir);SsaFunction out;
        require(buildSsa(ir,&out).ok()&&out.verify().empty(),"fixture SSA verifies");return out;}
};
using Bodies=std::map<Address,std::shared_ptr<SsaFunction>>;
MemoryFunctionResolver resolver(Bodies& bodies){return [&](Address entry)->std::shared_ptr<const SsaFunction>{const auto found=bodies.find(entry);return found==bodies.end()?nullptr:found->second;};}
std::shared_ptr<SsaFunction> pure(Arch arch,Address entry){Fixture f(arch,entry);f.block(0);f.load(f.constant(0x6000));f.ret();return std::make_shared<SsaFunction>(f.finish());}
std::shared_ptr<SsaFunction> writer(Arch arch,Address entry,bool relative,i64 offset,u8 size=0){Fixture f(arch,entry);f.block(0);f.store(relative?f.address(f.arg(0),offset):f.constant(static_cast<u64>(offset)),f.constant(9,size));f.ret();return std::make_shared<SsaFunction>(f.finish());}
// Keep a real base return in each recursive fixture. Complete memory effects do
// not prove termination, but must include both paths and every body in a cycle.
std::shared_ptr<SsaFunction> recursiveBody(Arch arch,Address entry,Address target,const std::function<void(Fixture&)>& effects={},const std::function<void(Fixture&)>& after={}){
    Fixture f(arch,entry,3);f.ir.blocks[0].successors={1,2};
    f.block(0);f.op(MintOp::kCondBranch,{},f.condition(),f.constant(f.ir.blocks[1].start));
    f.block(1);f.ret();
    f.block(2);if(effects)effects(f);f.call(target);if(after)after(f);f.ret();return std::make_shared<SsaFunction>(f.finish());
}
SsaFunction caller(Arch arch,Address target,bool symbolic=false,bool indirect=false){Fixture f(arch,0x1000);f.block(0);if(f.x86())f.op(MintOp::kCopy,f.sp(),symbolic?f.address(f.arg(0),0x1000):f.constant(0x800000));f.op(MintOp::kCopy,f.temp(),f.arg(0));const auto address=symbolic?f.address(f.arg(0),0):f.constant(0x4000);f.store(address,f.arg(1));f.call(target,indirect);f.load(address);f.ret();return f.finish();}
const MemoryAccess& lastLoad(const MemoryAnalysis& m){const auto found=std::find_if(m.accesses.rbegin(),m.accesses.rend(),[](const auto& a){return !a.store;});require(found!=m.accesses.rend(),"load evidence exists");return *found;}
MemoryAnalysis analyze(const SsaFunction& f,const MemoryFunctionResolver& functions={}){MemoryAnalysis m;const auto status=analyzeMemory(f,&m,functions);require(status.ok(),status.toString());return m;}
void effects(Arch arch){
    Bodies bodies;auto read=pure(arch,0x2000);bodies[read->entry]=read;const auto functions=resolver(bodies);const auto f=caller(arch,0x2000);
    const auto opaque=analyze(f);require(lastLoad(opaque).reachingStore==kNoValue&&opaque.callBarriers==1,"default memory analysis treats unknown callees as barriers");
    const bool x86=arch==Arch::kX86_32||arch==Arch::kX86_64;auto m=analyze(f,functions);require(lastLoad(m).reachingStore!=kNoValue&&(x86?m.selectiveCalls==1:m.readOnlyCalls==1)&&m.callBarriers==0,"verified read-only body preserves exact reaching store");
    require(m.calls.size()==1&&m.calls[0].complete&&m.calls[0].writes.size()==(x86?1u:0u)&&m.matches(f),"read-only call evidence bound to caller and body snapshot");
    require(m.toText(f).find("proven read-only calls")!=std::string::npos,"read-only provenance visible");
    for(bool relative:{false,true})for(i64 offset:{0,16}) {
        bodies[0x2000]=writer(arch,0x2000,relative,relative?offset:0x4000+offset);
        const auto current=caller(arch,0x2000,relative);const auto effect=analyze(current,functions);
        require(effect.selectiveCalls==1&&effect.callBarriers==0&&effect.calls[0].writes.size()==(x86?2u:1u),"bounded write summary instantiated at caller");
        require((lastLoad(effect).reachingStore!=kNoValue)==(offset==16),"write through same pointer/global kills overlap and preserves disjoint bytes");
    }
    // Distinct symbolic roots may alias; an absolute address may alias a dynamic pointer.
    bodies[0x2000]=writer(arch,0x2000,true,16);m=analyze(f,functions);
    require(lastLoad(m).reachingStore==kNoValue&&m.selectiveCalls==1,"argument-relative write may alias an unrelated global");
    bodies[0x2000]=writer(arch,0x2000,false,0x4010,f.values[0].storage.size==4?2:4);
    m=analyze(f,functions);require(lastLoad(m).reachingStore!=kNoValue,"narrow disjoint global write preserves caller facts");
    bodies[0x2000]=writer(arch,0x2000,false,0x4002,2);m=analyze(f,functions);
    require(lastLoad(m).reachingStore==kNoValue,"partial overlapping callee store invalidates whole reaching range");
    bodies[0x2000]=read;
    require(lastLoad(analyze(caller(arch,0x2000,false,true),functions)).reachingStore==kNoValue,"indirect call is not guessed from a constant-valued operand");
    require(lastLoad(analyze(caller(arch,0x5555),functions)).reachingStore==kNoValue,"unavailable external body remains a barrier");
    auto wrong=pure(arch,0x9999);bodies[0x2000]=wrong;
    require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"resolver body must match exact target entry");
    bodies[0x2000]=pure(arch==Arch::kAArch64?Arch::kX86_64:Arch::kAArch64,0x2000);
    require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"foreign architecture body cannot establish effects");
    bodies[0x2000]=pure(arch,0x2000);bodies[0x2000]->byteOrder=ByteOrder::kBig;
    require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"foreign byte-order body cannot establish effects");
    const MemoryFunctionResolver throws=[](Address)->std::shared_ptr<const SsaFunction>{throw 7;};
    require(lastLoad(analyze(f,throws)).reachingStore==kNoValue,"resolver failure preserves conservative barrier");
}
void transitive(Arch arch){
    Bodies bodies;const auto functions=resolver(bodies);bodies[0x2000]=pure(arch,0x2000);
    Fixture wrapper(arch,0x3000);wrapper.block(0);wrapper.call(0x2000);wrapper.ret();bodies[0x3000]=std::make_shared<SsaFunction>(wrapper.finish());
    auto f=caller(arch,0x3000);auto m=analyze(f,functions);require((arch==Arch::kX86_32||arch==Arch::kX86_64?m.selectiveCalls==1:m.readOnlyCalls==1)&&lastLoad(m).reachingStore!=kNoValue&&m.dependencies.size()==2,"transitive read-only wrapper retains both body dependencies");
    bodies[0x2000]=writer(arch,0x2000,true,8);
    Fixture shifted(arch,0x3000);shifted.block(0);auto next=shifted.address(shifted.arg(0),16);shifted.op(MintOp::kCopy,shifted.arg(0),next);shifted.call(0x2000);shifted.ret();bodies[0x3000]=std::make_shared<SsaFunction>(shifted.finish());
    f=caller(arch,0x3000,true);m=analyze(f,functions);require(m.selectiveCalls==1&&std::any_of(m.calls[0].writes.begin(),m.calls[0].writes.end(),[](const auto& w){return w.address.kind==MemoryBaseKind::kSymbolic&&w.address.offset==24;})&&lastLoad(m).reachingStore!=kNoValue,"transitive pointer displacement composes using pre-call physical register value");
    Fixture tail(arch,0x2000);tail.block(0);tail.ret();auto jump=std::make_shared<SsaFunction>(tail.finish());jump->insns.back().op=MintOp::kBranch;bodies[0x3000]=jump;jump->entry=0x3000;
    require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"unrepresented external tail control remains unknown");
}
void recursion(Arch arch){
    Bodies bodies;const auto functions=resolver(bodies);const bool x86=Fixture(arch,0).x86();
    const auto f=caller(arch,0x2000);const auto symbolic=caller(arch,0x2000,true);
    bodies[0x2000]=recursiveBody(arch,0x2000,0x2000,[](Fixture& body){body.load(body.arg(0));});
    auto m=analyze(f,functions);
    require((lastLoad(m).reachingStore!=kNoValue)==!x86,"direct recursive read-only SCC preserves facts except unbounded x86 return-slot writes");
    require(m.calls.size()==1&&m.calls[0].complete==!x86,"recursive proof is published only after its complete bounded fixed point");
    if(!x86)require(m.readOnlyCalls==1&&m.dependencies.size()==1&&m.matches(f),"direct recursive read-only proof retains its exact body dependency");

    bodies[0x2000]=recursiveBody(arch,0x2000,0x3000,[](Fixture& body){body.load(body.arg(0));});
    bodies[0x3000]=recursiveBody(arch,0x3000,0x2000);
    m=analyze(f,functions);
    require((lastLoad(m).reachingStore!=kNoValue)==!x86,"mutually recursive read-only SCC reaches a joint fixed point");
    if(x86)return;
    require(m.readOnlyCalls==1&&m.dependencies.size()==2&&m.matches(f),"mutual recursion binds every participating body snapshot");

    const auto saved=*bodies[0x3000];
    *bodies[0x3000]=*recursiveBody(arch,0x3000,0x2000,[](Fixture& body){body.store(body.constant(0x4000),body.constant(9));});
    require(!m.matches(f),"mutating another SCC member invalidates the caller's read-only proof");
    require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"a write in another SCC member reaches the caller after recomputation");
    *bodies[0x3000]=saved;require(m.matches(f),"restoring exact SCC member contents restores dependency binding");

    for(i64 offset:{0,16}){
        bodies[0x2000]=recursiveBody(arch,0x2000,0x2000,[&](Fixture& body){body.store(body.address(body.arg(0),offset),body.constant(9));});
        m=analyze(symbolic,functions);
        require(m.selectiveCalls==1&&m.callBarriers==0&&m.calls[0].complete&&m.calls[0].writes.size()==1,"stable recursive argument-relative writes converge without duplicate effects");
        require((lastLoad(m).reachingStore!=kNoValue)==(offset==16),"recursive argument write kills overlapping bytes and preserves same-base disjoint bytes");
    }
    bodies[0x2000]=recursiveBody(arch,0x2000,0x3000,[](Fixture& body){body.store(body.address(body.arg(0),16),body.constant(9));});
    bodies[0x3000]=recursiveBody(arch,0x3000,0x2000,[](Fixture& body){body.store(body.address(body.arg(0),32),body.constant(9));});
    m=analyze(symbolic,functions);
    require(m.selectiveCalls==1&&m.calls[0].writes.size()==2&&lastLoad(m).reachingStore!=kNoValue,"mutual recursion unions stable writes from both bodies before publishing effects");
    bodies[0x3000]=recursiveBody(arch,0x3000,0x2000,[](Fixture& body){body.store(body.address(body.arg(0),0),body.constant(9));});
    require(lastLoad(analyze(symbolic,functions)).reachingStore==kNoValue,"overlapping write propagated around mutual recursion cannot be lost");

    bodies[0x2000]=recursiveBody(arch,0x2000,0x2000,[](Fixture& body){body.store(body.address(body.arg(1),16),body.constant(9));});
    m=analyze(symbolic,functions);
    require(m.selectiveCalls==1&&m.calls[0].complete&&lastLoad(m).reachingStore==kNoValue,"distinct recursive symbolic argument roots remain potentially aliased");
    bodies[0x2000]=recursiveBody(arch,0x2000,0x2000,[](Fixture& body){body.store(body.constant(0x5000),body.constant(9));});
    require(lastLoad(analyze(symbolic,functions)).reachingStore==kNoValue,"recursive absolute write may alias a dynamic caller pointer");

    for(i64 offset:{0,16}){
        bodies[0x2000]=recursiveBody(arch,0x2000,0x2000,{},[&](Fixture& body){body.store(body.constant(0x4000+offset),body.constant(9));});
        m=analyze(f,functions);
        require(m.selectiveCalls==1&&m.calls[0].complete&&m.calls[0].writes.size()==1&&(lastLoad(m).reachingStore!=kNoValue)==(offset==16),"recursive fixed point includes absolute writes after the recursive call");
    }
    const auto preserved=Varnode::reg(arch==Arch::kAArch64?arm64::kXn(19):arch==Arch::kArm32||arch==Arch::kThumb?arm32::kRn(4):riscv::kXn(8),Fixture(arch,0).width());
    Fixture stable(arch,0x1000);stable.block(0);const auto savedAddress=stable.address(preserved,0);stable.store(savedAddress,stable.constant(7));stable.call(0x2000);stable.load(savedAddress);stable.ret();const auto stableCaller=stable.finish();
    for(i64 offset:{0,16}){
        bodies[0x2000]=recursiveBody(arch,0x2000,0x2000,{},[&](Fixture& body){body.store(body.address(preserved,offset),body.constant(9));});
        m=analyze(stableCaller,functions);
        require(m.selectiveCalls==1&&m.calls[0].complete&&m.calls[0].writes.size()==1&&(lastLoad(m).reachingStore!=kNoValue)==(offset==16),"writes through an unchanged ABI-preserved register after recursion retain exact alias behavior");
    }

    auto poisonedCallers=[&](){
        for(Address target:{Address{0x2000},Address{0x3000}}){
            Fixture wrapper(arch,target+0x2000);wrapper.block(0);wrapper.call(target);wrapper.ret();bodies[wrapper.ir.entry]=std::make_shared<SsaFunction>(wrapper.finish());
        }
        for(bool reverse:{false,true}){
            Fixture outer(arch,0x1000);outer.block(0);outer.store(outer.constant(0x4000),outer.constant(7));outer.call(reverse?0x5000:0x4000);outer.call(reverse?0x4000:0x5000);outer.load(outer.constant(0x4000));outer.ret();const auto ssa=outer.finish();
            const auto result=analyze(ssa,functions);
            require(result.calls.size()==2&&!result.calls[0].complete&&!result.calls[1].complete&&result.callBarriers==2&&lastLoad(result).reachingStore==kNoValue,"outer callers to either poisoned SCC member never observe a provisional successful summary");
        }
    };
    for(bool stack:{false,true}){
        bodies[0x2000]=recursiveBody(arch,0x2000,0x3000);
        bodies[0x3000]=recursiveBody(arch,0x3000,0x2000,[&](Fixture& body){if(stack)body.op(MintOp::kAdd,body.sp(),body.sp(),body.constant(8));else body.op(MintOp::kCopy,preserved,body.constant(0x5000));});
        poisonedCallers();
    }
    bodies[0x2000]=recursiveBody(arch,0x2000,0x3000);
    bodies[0x3000]=recursiveBody(arch,0x3000,0x2000,[](Fixture& body){const auto pointer=body.load(body.constant(0x6000));body.store(pointer,body.constant(9));});
    poisonedCallers();

    for(auto effect:{MintOp::kCall,MintOp::kCallInd,MintOp::kIntrinsic}){
        bodies[0x2000]=recursiveBody(arch,0x2000,0x3000);
        bodies[0x3000]=recursiveBody(arch,0x3000,0x2000,[&](Fixture& body){if(effect==MintOp::kIntrinsic)body.op(effect);else body.call(0x5555,effect==MintOp::kCallInd);});
        m=analyze(f,functions);
        require(m.callBarriers==1&&!m.calls[0].complete&&lastLoad(m).reachingStore==kNoValue,"unknown external/indirect/intrinsic effect poisons every member of a recursive SCC");
    }
}
void barriersAndBindings(Arch arch){
    Bodies bodies;const auto functions=resolver(bodies);auto leaf=pure(arch,0x2000);bodies[0x2000]=leaf;auto f=caller(arch,0x2000);auto m=analyze(f,functions);
    const auto saved=std::make_shared<SsaFunction>(*leaf);*leaf=*writer(arch,0x2000,false,0x4000);
    require(!m.matches(f),"in-place callee mutation invalidates dependency-bound evidence");*leaf=*saved;require(m.matches(f),"exact immutable snapshot contents restore binding");
    for(auto op:{MintOp::kMemoryFence,MintOp::kIntrinsic,MintOp::kTrap}){
        Fixture unsafe(arch,0x2000);unsafe.block(0);unsafe.op(op);if(op!=MintOp::kTrap)unsafe.ret();bodies[0x2000]=std::make_shared<SsaFunction>(unsafe.finish());
        require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"fence/intrinsic/trap body effects remain barriers");
    }
    Fixture stack(arch,0x2000);stack.block(0);const auto sp=Varnode::reg(arch==Arch::kAArch64?arm64::kSp:arch==Arch::kRiscV32||arch==Arch::kRiscV64?riscv::kSp:arch==Arch::kArm32||arch==Arch::kThumb?arm32::kSp:x86::kRsp,stack.width());
    stack.store(stack.address(sp,-8),stack.constant(9));stack.ret();bodies[0x2000]=std::make_shared<SsaFunction>(stack.finish());
    require((lastLoad(analyze(f,functions)).reachingStore!=kNoValue)==stack.x86(),"callee frame writes use reaching caller SP and retain unknown-SP aliases");
    // Model also refuses a malformed borrowed body instead of publishing partial effects.
    bodies[0x2000]=pure(arch,0x2000);bodies[0x2000]->blocks[0].successors={999};
    require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"malformed body snapshot is not a memory proof");
}
void typesAndEmitter(Arch arch){
    Bodies bodies;bodies[0x2000]=pure(arch,0x2000);const auto functions=resolver(bodies);
    Fixture f(arch,0x1000);f.block(0);if(f.x86())f.op(MintOp::kCopy,f.sp(),f.constant(0x800000));f.store(f.arg(0),f.constant(7));f.store(f.constant(0x4000),f.arg(0));f.call(0x2000);
    const auto pointer=f.load(f.constant(0x4000));f.store(f.address(pointer,8),f.constant(9));f.ret();auto ssa=f.finish();
    const auto m=analyze(ssa,functions);TypeRecovery types;require(recoverTypes(ssa,&types,&m).ok(),"type recovery consumes bound interprocedural memory evidence");
    require(std::any_of(types.structs.begin(),types.structs.end(),[](const auto& shape){return shape.fields.size()==2&&shape.fields[0].offset==0&&shape.fields[1].offset==8;}),"pointer reload across verified read-only call joins original object layout");
    DecompileResult precise,opaque;require(decompileSsa(ssa,&precise,{},{},{},{},{},{},functions).ok()&&decompileSsa(ssa,&opaque).ok(),"decompiler accepts optional body resolver");
    require(precise.cSource.find("field_8")!=std::string::npos&&opaque.cSource.find("field_8")==std::string::npos,"emitted layout evidence actually benefits from call-effect integration");
    *bodies[0x2000]=*writer(arch,0x2000,false,0x4000);
    require(recoverTypes(ssa,&types,&m).ok()&&types.structs.empty(),"stale dependency sidecar is recomputed conservatively by type recovery");
}
void hiddenRegisters(Arch arch){
    Bodies bodies;const auto functions=resolver(bodies);bodies[0x2000]=writer(arch,0x2000,true,0);
    for(bool agree:{false,true}) {
        Fixture f(arch,0x1000,4);f.ir.blocks[0].successors={1,2};f.ir.blocks[1].successors={3};f.ir.blocks[2].successors={3};
        f.block(0);if(f.x86())f.op(MintOp::kCopy,f.sp(),f.constant(0x800000));f.op(MintOp::kCopy,f.arg(0),f.constant(0x5000));f.store(f.constant(0x4000),f.constant(7));f.op(MintOp::kCondBranch,{},f.condition(),f.constant(f.ir.blocks[1].start));
        f.block(1);f.op(MintOp::kCopy,f.arg(0),f.constant(agree?0x5000:0x4000));f.branch(3);
        f.block(2);f.branch(3);
        f.block(3);f.call(0x2000);f.load(f.constant(0x4000));f.ret();const auto ssa=f.finish();
        require(std::none_of(ssa.phis.begin(),ssa.phis.end(),[&](const auto& p){return !p.dead&&p.block==3&&ssa.values[p.dest].storage==f.arg(0);}),"implicit call input fixture has no live physical-register SSA phi");
        const auto m=analyze(ssa,functions);require((lastLoad(m).reachingStore!=kNoValue)==agree,"all predecessor paths must agree on a hidden physical call input");
    }
    // The definition after CALL reaches that same call on a later loop iteration.
    Fixture loop(arch,0x1000,3);loop.ir.blocks[0].successors={1};loop.ir.blocks[1].successors={1,2};
    loop.block(0);if(loop.x86())loop.op(MintOp::kCopy,loop.sp(),loop.constant(0x800000));loop.op(MintOp::kCopy,loop.arg(0),loop.constant(0x5000));loop.store(loop.constant(0x4000),loop.constant(7));loop.branch(1);
    loop.block(1);loop.call(0x2000);loop.op(MintOp::kCopy,loop.arg(0),loop.constant(0x4000));loop.op(MintOp::kCondBranch,{},loop.condition(),loop.constant(loop.ir.blocks[1].start));
    loop.block(2);loop.load(loop.constant(0x4000));loop.ret();const auto ssa=loop.finish();
    require(lastLoad(analyze(ssa,functions)).reachingStore==kNoValue,"backedge register definitions after CALL cannot be skipped by a partial-block scan");
    // A preserved-register write is an actual machine effect even if SSA aliases
    // its copy away and nobody explicitly consumes it in the callee.
    Fixture corrupt(arch,0x2000);corrupt.block(0);
    const Varnode saved=Varnode::reg(arch==Arch::kAArch64?arm64::kXn(19):arch==Arch::kArm32||arch==Arch::kThumb?arm32::kRn(4):arch==Arch::kRiscV32||arch==Arch::kRiscV64?riscv::kXn(8):x86::kRbx,corrupt.width());
    corrupt.op(MintOp::kCopy,saved,corrupt.constant(0x4000));corrupt.ret();bodies[0x2000]=std::make_shared<SsaFunction>(corrupt.finish());
    require(lastLoad(analyze(caller(arch,0x2000),functions)).reachingStore==kNoValue,"unrestored ABI-preserved register changes cannot establish a complete call summary");
    Fixture restored(arch,0x2000);restored.block(0);auto before=restored.temp();restored.op(MintOp::kCopy,before,saved);restored.op(MintOp::kCopy,saved,restored.constant(0x4000));restored.op(MintOp::kCopy,saved,before);restored.ret();bodies[0x2000]=std::make_shared<SsaFunction>(restored.finish());
    require(lastLoad(analyze(caller(arch,0x2000),functions)).reachingStore!=kNoValue,"dead copy aliases still prove exact restoration of a preserved physical register");
    Fixture unbalanced(arch,0x2000);unbalanced.block(0);unbalanced.op(MintOp::kAdd,unbalanced.sp(),unbalanced.sp(),unbalanced.constant(8));unbalanced.ret();bodies[0x2000]=std::make_shared<SsaFunction>(unbalanced.finish());
    require(lastLoad(analyze(caller(arch,0x2000),functions)).reachingStore==kNoValue,"unbalanced SP at any return rejects complete body effects");
}
void controlFlow(Arch arch){
    Bodies bodies;const auto functions=resolver(bodies);
    Fixture branch(arch,0x2000,4);branch.ir.blocks[0].successors={1,2};branch.ir.blocks[1].successors={3};branch.ir.blocks[2].successors={3};
    branch.block(0);branch.op(MintOp::kCondBranch,{},branch.condition(),branch.constant(branch.ir.blocks[1].start));
    branch.block(1);branch.store(branch.constant(0x5000),branch.constant(9));branch.branch(3);
    branch.block(2);branch.store(branch.constant(0x4000),branch.constant(9));branch.branch(3);
    branch.block(3);branch.ret();bodies[0x2000]=std::make_shared<SsaFunction>(branch.finish());
    auto f=caller(arch,0x2000);require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"callee write footprint includes every reachable branch");
    Fixture loop(arch,0x2000,3);loop.ir.blocks[0].successors={1};loop.ir.blocks[1].successors={1,2};
    loop.block(0);loop.branch(1);loop.block(1);loop.store(loop.constant(0x5000),loop.constant(9));loop.op(MintOp::kCondBranch,{},loop.condition(),loop.constant(loop.ir.blocks[1].start));loop.block(2);loop.ret();
    bodies[0x2000]=std::make_shared<SsaFunction>(loop.finish());require(lastLoad(analyze(f,functions)).reachingStore!=kNoValue,"bounded loop write footprint preserves provably disjoint caller bytes");
    auto m=analyze(f,functions);auto body=bodies[0x2000];const auto original=body->blocks[1].start;body->blocks[1].start+=4;
    require(!m.matches(f),"callee block-address mutation invalidates semantic fingerprint");body->blocks[1].start=original;
    body->blocks[1].phis.push_back(999);require(!m.matches(f),"callee block-phi interpretation is covered by semantic fingerprint");
}
void x86Stack(Arch arch){
    Bodies bodies;const auto functions=resolver(bodies);bodies[0x2000]=pure(arch,0x2000);
    for(i64 offset:{-static_cast<i64>(Fixture(arch,0).width()),static_cast<i64>(Fixture(arch,0).width())}) {
        Fixture f(arch,0x1000);f.block(0);const auto address=f.address(f.sp(),offset);f.store(address,f.constant(7));f.call(0x2000);f.load(address);f.ret();const auto ssa=f.finish();const auto m=analyze(ssa,functions);
        require(m.selectiveCalls==1&&m.calls[0].writes.size()==1&&(lastLoad(m).reachingStore!=kNoValue)==(offset>0),"implicit x86 CALL push invalidates return slot and preserves disjoint entry-SP range");
    }
    for(bool symbolic:{false,true}) {
        Fixture f(arch,0x1000);f.block(0);const auto address=symbolic?f.arg(0):f.constant(0x4000);f.store(address,f.constant(7));f.call(0x2000);f.load(address);f.ret();const auto ssa=f.finish();
        require(lastLoad(analyze(ssa,functions)).reachingStore==kNoValue,"implicit return-slot write may alias unrelated symbolic/global bytes when SP is not concrete");
    }
    Fixture wrapper(arch,0x3000);wrapper.block(0);wrapper.call(0x2000);wrapper.ret();bodies[0x3000]=std::make_shared<SsaFunction>(wrapper.finish());
    Fixture nested(arch,0x1000);nested.block(0);const auto address=nested.address(nested.sp(),-2*nested.width());nested.store(address,nested.constant(7));nested.call(0x3000);nested.load(address);nested.ret();auto ssa=nested.finish();auto m=analyze(ssa,functions);
    require(m.calls[0].complete&&m.calls[0].writes.size()==2&&lastLoad(m).reachingStore==kNoValue,"nested x86 CALL return slots compose from callee entry SP");
    Fixture frame(arch,0x2000);frame.block(0);frame.store(frame.address(frame.sp(),-2*frame.width()),frame.constant(9));frame.ret();bodies[0x2000]=std::make_shared<SsaFunction>(frame.finish());
    Fixture overlap(arch,0x1000);overlap.block(0);const auto slot=overlap.address(overlap.sp(),-3*overlap.width());overlap.store(slot,overlap.constant(7));overlap.call(0x2000);overlap.load(slot);overlap.ret();ssa=overlap.finish();
    require(lastLoad(analyze(ssa,functions)).reachingStore==kNoValue,"callee frame store translates from entry SP including caller CALL push");
    bodies[0x2000]=pure(arch,0x2000);
    Fixture twice(arch,0x1000);twice.block(0);twice.op(MintOp::kCopy,twice.sp(),twice.constant(0x8000));twice.store(twice.constant(0x8004),twice.constant(7));twice.call(0x2000);twice.call(0x2000);twice.load(twice.constant(0x8004));twice.ret();ssa=twice.finish();m=analyze(ssa,functions);
    require(m.calls[0].complete&&!m.calls[1].complete&&lastLoad(m).reachingStore==kNoValue,"SP evidence never silently flows across an earlier call");
    Fixture cleanup(arch,0x2000);cleanup.block(0);cleanup.op(MintOp::kAdd,cleanup.sp(),cleanup.sp(),cleanup.constant(8));cleanup.ret();bodies[0x2000]=std::make_shared<SsaFunction>(cleanup.finish());m=analyze(ssa,functions);
    require(!m.calls[0].complete&&lastLoad(m).reachingStore==kNoValue,"RET imm cleanup is not mistaken for an ordinary balanced return");
    bodies[0x3000]=pure(arch,0x3000);
    Fixture stale(arch,0x1000);stale.block(0);stale.op(MintOp::kCopy,stale.sp(),stale.constant(0x8000));stale.call(0x2000);stale.store(stale.constant(0x8004),stale.constant(7));stale.op(MintOp::kAdd,stale.sp(),stale.sp(),stale.constant(0));stale.call(0x3000);stale.load(stale.constant(0x8004));stale.ret();ssa=stale.finish();m=analyze(ssa,functions);
    require(!m.calls[1].complete&&lastLoad(m).reachingStore==kNoValue,"post-call SP arithmetic cannot disguise stale ABI-based SP provenance");
    if(arch==Arch::kX86_32) {
        bodies[0x2000]=pure(arch,0x2000);Fixture narrow(arch,0x1000);narrow.block(0);narrow.op(MintOp::kCopy,narrow.sp(),narrow.constant(0x8000));narrow.store(narrow.constant(0x4000),narrow.constant(7));narrow.op(MintOp::kCall,{},narrow.constant(0x2000,2));narrow.load(narrow.constant(0x4000));narrow.ret();ssa=narrow.finish();
        require(lastLoad(analyze(ssa,functions)).reachingStore==kNoValue,"operand-size CALL16 does not borrow native-width return-slot effects");
    }
}
void bounds(){
    const Arch arch=Arch::kAArch64;Bodies bodies;const auto functions=resolver(bodies);
    for(unsigned n=0;n<20;++n){Fixture chain(arch,0x2000+n*0x100);chain.block(0);if(n+1<20)chain.call(0x2000+(n+1)*0x100);chain.ret();bodies[chain.ir.entry]=std::make_shared<SsaFunction>(chain.finish());}
    auto f=caller(arch,0x2000);auto m=analyze(f,functions);require(lastLoad(m).reachingStore==kNoValue&&m.dependencies.size()<=16,"depth cap loses proof rather than treating truncated call graph as pure");
    bodies.clear();for(unsigned n=0;n<70;++n)bodies[0x2000+n*0x100]=pure(arch,0x2000+n*0x100);
    Fixture many(arch,0x1000);many.block(0);many.store(many.constant(0x4000),many.arg(0));for(unsigned n=0;n<70;++n)many.call(0x2000+n*0x100);many.load(many.constant(0x4000));many.ret();f=many.finish();m=analyze(f,functions);
    require(m.dependencies.size()<=64&&lastLoad(m).reachingStore==kNoValue,"function-cache cap retains unknown barriers beyond the bounded set");
    bodies.clear();Fixture writes(arch,0x2000);writes.block(0);for(unsigned n=0;n<65;++n)writes.store(writes.constant(0x5000+n*16),writes.constant(n));writes.ret();bodies[0x2000]=std::make_shared<SsaFunction>(writes.finish());
    f=caller(arch,0x2000);require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"too many distinct write ranges cannot create a partial summary");
    Fixture full(arch,0x2000);full.block(0);for(unsigned n=0;n<64;++n)full.store(full.constant(0x5000+n*16),full.constant(n));full.ret();bodies[0x2000]=std::make_shared<SsaFunction>(full.finish());
    require(lastLoad(analyze(f,functions)).reachingStore!=kNoValue,"maximum bounded write footprint still preserves disjoint bytes");
    Fixture ranges(arch,0x1000);ranges.block(0);ranges.store(ranges.constant(0x4000),ranges.constant(7));for(unsigned n=0;n<1025;++n)ranges.call(0x2000);ranges.load(ranges.constant(0x4000));ranges.ret();f=ranges.finish();m=analyze(f,functions);
    require(m.calls.size()==1025&&!m.calls.back().complete&&lastLoad(m).reachingStore==kNoValue,"combined instantiated write-range cap invalidates instead of publishing a partial last call");
    bodies[0x2000]=pure(arch,0x2000);Fixture calls(arch,0x1000);calls.block(0);calls.store(calls.constant(0x4000),calls.constant(7));for(unsigned n=0;n<4097;++n)calls.call(0x2000);calls.load(calls.constant(0x4000));calls.ret();f=calls.finish();m=analyze(f,functions);
    require(m.calls.size()==4096&&m.callBarriers==1&&lastLoad(m).reachingStore==kNoValue,"unrecorded calls beyond instruction budget remain conservative barriers");
    bodies[0x2000]=pure(arch,0x2000);bodies[0x2000]->values.resize(32769);
    require(lastLoad(analyze(f,functions)).reachingStore==kNoValue,"oversized body is rejected before expensive verification");

    bodies.clear();f=caller(arch,0x2000,true);
    bodies[0x2000]=recursiveBody(arch,0x2000,0x2000,[](Fixture& body){body.store(body.arg(0),body.constant(9));body.op(MintOp::kAdd,body.arg(0),body.arg(0),body.constant(16));});
    m=analyze(f,functions);
    require(!m.calls[0].complete&&lastLoad(m).reachingStore==kNoValue,"recursive pointer displacement exhausts the footprint bound instead of publishing a partial fixed point");
    for(unsigned count:{64,65}){
        bodies[0x2000]=recursiveBody(arch,0x2000,0x2000,[&](Fixture& body){for(unsigned n=0;n<count;++n)body.store(body.constant(0x5000+n*16),body.constant(n));});
        f=caller(arch,0x2000);m=analyze(f,functions);
        require(m.calls[0].complete==(count==64)&&(lastLoad(m).reachingStore!=kNoValue)==(count==64),"recursive SCC honors the exact write-range limit and never publishes truncated effects");
        if(count==64)require(m.calls[0].writes.size()==64,"recursive fixed point deduplicates maximum-size stable write footprint");
    }
}
}
int main(){for(auto arch:{Arch::kAArch64,Arch::kX86_64,Arch::kRiscV32,Arch::kRiscV64,Arch::kArm32,Arch::kThumb,Arch::kX86_32}){effects(arch);transitive(arch);recursion(arch);barriersAndBindings(arch);typesAndEmitter(arch);hiddenRegisters(arch);controlFlow(arch);if(arch==Arch::kX86_32||arch==Arch::kX86_64)x86Stack(arch);}bounds();std::cout<<checks<<" interprocedural memory checks passed\n";}
