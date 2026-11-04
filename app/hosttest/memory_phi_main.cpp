#include "mint/ir/memory_analysis.h"
#include "mint/ir/type_recovery.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"
#include "mint/ssa/ssa_builder.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>

using namespace mint;
namespace {
unsigned checks=0;
void require(bool yes,const std::string& label){++checks;if(!yes){std::cerr<<"memory phi: "<<label<<'\n';std::exit(1);}}
struct Fixture {
    IrFunction ir;u32 current=0;
    Fixture(Arch arch,u32 count){ir.arch=arch;ir.entry=0x1000;ir.name="memory_phi";ir.blocks.resize(count);
        for(u32 n=0;n<count;++n){ir.blocks[n].id=n;ir.blocks[n].start=0x1000+n*0x100;ir.blocks[n].end=ir.blocks[n].start+0x100;}}
    u8 width() const {return ir.arch==Arch::kRiscV32?4:8;}
    Varnode constant(u64 value,u8 size=0)const{return Varnode::constant(value,size?size:width());}
    Varnode arg(unsigned n)const{return Varnode::reg(ir.arch==Arch::kAArch64?arm64::kXn(n):ir.arch==Arch::kRiscV32?riscv::kXn(10+n):n==0?x86::kRdi:n==1?x86::kRsi:x86::kRdx,width());}
    Varnode temp(u8 size=0){return Varnode::temp(ir.tempCount++,size?size:width());}
    void block(u32 index){current=index;ir.blocks[index].firstInsn=ir.insns.size();}
    void op(MintOp code,Varnode dest={},Varnode a={},Varnode b={}){IrInsn insn;insn.op=code;insn.dest=dest;insn.a=a;insn.b=b;insn.address=ir.blocks[current].start+ir.blocks[current].insnCount*4;ir.insns.push_back(insn);++ir.blocks[current].insnCount;}
    void branch(u32 target){op(MintOp::kBranch,{},constant(ir.blocks[target].start));}
    void condition(u32 target){const auto test=temp(1);op(MintOp::kEqual,test,arg(2),constant(0));op(MintOp::kCondBranch,{},test,constant(ir.blocks[target].start));}
    Varnode address(Varnode base,u64 offset){const auto result=temp();op(MintOp::kAdd,result,base,constant(offset));return result;}
    void store(Varnode address,Varnode value){op(MintOp::kStore,{},address,value);}
    Varnode load(Varnode address){const auto value=temp();op(MintOp::kLoad,value,address);return value;}
    void ret(){op(MintOp::kReturn,{},constant(0x7000));}
    SsaFunction finish(){for(auto& block:ir.blocks)for(auto next:block.successors)ir.blocks[next].predecessors.push_back(block.id);
        const auto errors=ir.verify();for(const auto& error:errors)std::cerr<<error<<'\n';require(errors.empty(),"valid IR fixture");
        normalizeRegisterAccesses(&ir);SsaFunction out;require(buildSsa(ir,&out).ok()&&out.verify().empty(),"verified SSA fixture");return out;}
};
const MemoryAccess* absoluteLoad(const MemoryAnalysis& memory,u64 address){for(const auto& access:memory.accesses)if(!access.store&&access.address.kind==MemoryBaseKind::kAbsolute&&access.address.absolute==address)return &access;return nullptr;}
MemoryAnalysis analyze(const SsaFunction& function){MemoryAnalysis out;const auto status=analyzeMemory(function,&out);require(status.ok(),status.toString());return out;}
void diamond(Arch arch,unsigned mode){
    // 0 = agreeing sources, 1 = different sources, 2 = missing store,
    // 3 = partial overwrite, 4 = call, 5 = unknown alias, 6 = disjoint overwrite.
    Fixture f(arch,4);f.ir.blocks[0].successors={1,2};f.ir.blocks[1].successors={3};f.ir.blocks[2].successors={3};
    f.block(0);f.store(f.arg(0),f.constant(7));f.condition(1);
    f.block(1);f.store(f.constant(0x4000),f.arg(0));f.branch(3);
    f.block(2);if(mode!=2)f.store(f.constant(0x4000),mode==1?f.arg(1):f.arg(0));
    if(mode==3)f.store(f.constant(0x4000+f.width()/2),f.constant(9,f.width()/2));
    if(mode==4)f.op(MintOp::kCall,{},f.constant(0x6000));
    if(mode==5)f.store(f.arg(1),f.constant(19));
    if(mode==6)f.store(f.constant(0x4010),f.constant(21));
    f.branch(3);f.block(3);const auto pointer=f.load(f.constant(0x4000));f.store(f.address(pointer,8),f.constant(11));f.ret();
    const auto function=f.finish();const auto memory=analyze(function);const auto* load=absoluteLoad(memory,0x4000);require(load,"join load observed");
    const bool merge=mode==0||mode==1||mode==6,agree=mode==0||mode==6;
    require((load->reachingPhi!=kNoValue)==merge,"memory merge requires a reaching store on every path and no clobber");
    require(load->reachingStore==kNoValue,"different path stores never masquerade as one store");
    require((load->reachingValue!=kNoValue)==agree,"one stored SSA value must agree on every incoming path");
    if(merge){require(load->reachingPhi<memory.phis.size(),"valid memory merge index");const auto& phi=memory.phis[load->reachingPhi];
        require(phi.stores.size()==2&&std::is_sorted(phi.stores.begin(),phi.stores.end())&&phi.version==load->memoryVersion,"deterministic two-definition merge and memory version");
        require(phi.agreedValue==load->reachingValue,"merge and load agree about stored value");}
    TypeRecovery types;require(recoverTypes(function,&types,&memory).ok(),"types reuse memory sidecar");
    const auto incoming=std::find_if(function.values.begin(),function.values.end(),[&](const auto& value){return value.def==SsaDef::kEntry&&value.storage==f.arg(0);});require(incoming!=function.values.end(),"object argument entry exists");
    const SsaId id=incoming-function.values.begin();bool layout=false;
    for(const auto& shape:types.structs)if(shape.base==id&&shape.fields.size()==2&&shape.fields[0].offset==0&&shape.fields[1].offset==8)layout=true;
    require(layout==agree,"store/reload alias joins object fields only after exact all-path value proof");
    require(memory.toText(function).find("all-path memory merges")!=std::string::npos,"report distinguishes all-path memory evidence");
}
void loops(Arch arch,bool initialize,bool disagree){
    Fixture f(arch,3);f.ir.blocks[0].successors={1};f.ir.blocks[1].successors={1,2};
    f.block(0);if(initialize)f.store(f.constant(0x4000),f.arg(0));f.branch(1);
    f.block(1);f.load(f.constant(0x4000));f.store(f.constant(0x4000),disagree?f.arg(1):f.arg(0));f.condition(1);
    f.block(2);f.ret();const auto function=f.finish();const auto memory=analyze(function);const auto* load=absoluteLoad(memory,0x4000);require(load,"loop load observed");
    require((load->reachingPhi!=kNoValue)==initialize,"backedge cannot invent first-iteration initialization");
    require((load->reachingValue!=kNoValue)==(initialize&&!disagree),"loop merge requires same value before first iteration and on backedge");
    if(initialize)require(memory.phis[load->reachingPhi].stores.size()==2,"loop merges entry and backedge store");
}
void singleReload(Arch arch){
    Fixture f(arch,1);f.block(0);f.store(f.constant(0x4000),f.arg(0));const auto pointer=f.load(f.constant(0x4000));
    f.store(f.arg(0),f.constant(7));f.store(f.address(pointer,8),f.constant(9));f.ret();const auto function=f.finish();const auto memory=analyze(function);
    const auto* load=absoluteLoad(memory,0x4000);require(load&&load->reachingStore!=kNoValue&&load->reachingValue!=kNoValue&&load->reachingPhi==kNoValue,"singleton store preserves backward-compatible dependency and value proof");
    TypeRecovery with,without;require(recoverTypes(function,&with,&memory).ok()&&recoverTypes(function,&without).ok(),"shared and independently prepared memory evidence succeed");
    require(with.structs.size()==1&&without.structs.size()==with.structs.size()&&with.structs[0].fields.size()==2,"single reload and original pointer share one layout");
}
void pointerPhi(Arch arch,bool disagree){
    Fixture f(arch,4);f.ir.blocks[0].successors={1,2};f.ir.blocks[1].successors={3};f.ir.blocks[2].successors={3};
    const auto pointer=Varnode::reg(arch==Arch::kAArch64?arm64::kXn(3):arch==Arch::kRiscV32?riscv::kXn(13):x86::kRbx,f.width());
    f.block(0);f.store(f.arg(0),f.constant(7));f.condition(1);
    f.block(1);f.op(MintOp::kAdd,pointer,f.arg(0),f.constant(8));f.branch(3);
    f.block(2);f.op(MintOp::kAdd,pointer,f.arg(0),f.constant(disagree?16:8));f.branch(3);
    f.block(3);f.store(pointer,f.constant(11));f.ret();const auto function=f.finish();const auto memory=analyze(function);
    TypeRecovery types;require(recoverTypes(function,&types,&memory).ok(),"pointer phi type inference");
    bool layout=false;for(const auto& shape:types.structs)if(shape.fields.size()==2&&shape.fields[0].offset==0&&shape.fields[1].offset==8)layout=true;
    require(layout!=disagree,"equal pointer phi addresses share fields, conflicting phi addresses stay separate");
}
void resourceBound(){
    // Thirty-three branches each store one value. No arbitrary subset is kept.
    Fixture f(Arch::kAArch64,35);f.ir.blocks[0].successors.resize(33);for(u32 n=0;n<33;++n){f.ir.blocks[0].successors[n]=n+1;f.ir.blocks[n+1].successors={34};}
    f.block(0);f.op(MintOp::kBranchInd,{},f.arg(2));
    for(u32 n=1;n<=33;++n){f.block(n);f.store(f.constant(0x4000),f.arg(0));f.branch(34);}
    f.block(34);f.load(f.constant(0x4000));f.ret();const auto function=f.finish();const auto memory=analyze(function);const auto* load=absoluteLoad(memory,0x4000);
    require(load&&load->reachingStore==kNoValue&&load->reachingPhi==kNoValue&&load->reachingValue==kNoValue,"more than 32 reaching stores loses precision safely");
    SsaFunction oversized;oversized.phis.resize(1);oversized.phis[0].args.resize(4000001);MemoryAnalysis bounded;
    require(!analyzeMemory(oversized,&bounded).ok()&&bounded.values.empty()&&bounded.phis.empty(),"oversized operand graph rejected before allocating def-use state");
}
void aliasExtrema(){
    MemoryAddress a{MemoryBaseKind::kSymbolic,7,0,std::numeric_limits<i64>::max(),8},b=a;
    b.offset=std::numeric_limits<i64>::min();require(memoryMayAlias(a,8,b,8),"signed extrema overlap across target wrap without host overflow");
    a.pointerWidth=b.pointerWidth=4;a.offset=0;b.offset=i64{1}<<32;
    require(memoryMayAlias(a,8,b,8),"RV32 symbolic displacement aliases after address-width wrap");
    a.offset=-16;b.offset=0;require(!memoryMayAlias(a,8,b,8),"disjoint negative and zero offsets retain precision");
    require(memoryMayAlias(a,0,b,8),"zero access extent stays conservative");
}
SsaFunction storedAlias(bool other){
    Fixture f(Arch::kAArch64,1);f.block(0);f.op(MintOp::kEqual,f.temp(1),f.arg(0),f.arg(1));
    f.store(f.constant(0x4000),f.arg(other?1:0));const auto pointer=f.load(f.constant(0x4000));
    f.store(f.arg(0),f.constant(7));f.store(f.address(pointer,8),f.constant(9));f.ret();return f.finish();
}
void binding(){
    auto original=storedAlias(false);const auto memory=analyze(original);require(memory.matches(original),"sidecar bound to original immutable SSA");
    auto other=storedAlias(true);require(!memory.matches(other),"foreign function sidecar rejected even with similar shape");
    TypeRecovery types;require(recoverTypes(other,&types,&memory).ok()&&types.structs.empty(),"foreign sidecar cannot combine unrelated object fields");
    original=std::move(other);require(!memory.matches(original),"in-place SSA replacement invalidates stored fingerprint");
    require(recoverTypes(original,&types,&memory).ok()&&types.structs.empty(),"stale sidecar is recomputed before type alias use");
    const auto current=analyze(original);require(current.matches(original),"fresh sidecar binds to changed SSA");
}
}
int main(){for(auto arch:{Arch::kAArch64,Arch::kX86_64,Arch::kRiscV32}){for(unsigned mode=0;mode<7;++mode)diamond(arch,mode);loops(arch,true,false);loops(arch,true,true);loops(arch,false,false);singleReload(arch);pointerPhi(arch,false);pointerPhi(arch,true);}resourceBound();aliasExtrema();binding();std::cout<<checks<<" memory phi/type alias checks passed\n";}
