#include <algorithm>
#include <iostream>
#include <map>
#include <vector>
#include "mint/analysis/interprocedural_prototypes.h"
#include "mint/ir/registers.h"

namespace {
using namespace mint;unsigned checks=0,failures=0;
bool expect(bool value,const char* name){++checks;if(!value){++failures;std::cerr<<"FAIL "<<name<<'\n';}return value;}
u8 width(Arch arch){return arch==Arch::kArm32 || arch==Arch::kThumb || arch==Arch::kX86_32 || arch==Arch::kRiscV32?4:8;}
u64 argument(Arch arch,unsigned slot=0){if(arch==Arch::kAArch64)return arm64::kXn(slot);if(arch==Arch::kArm32 || arch==Arch::kThumb)return arm32::kRn(slot);if(arch==Arch::kRiscV32 || arch==Arch::kRiscV64)return riscv::kXn(10+slot);return slot==0?x86::kRdi:x86::kRsi;}
u64 result(Arch arch){return arch==Arch::kRiscV32 || arch==Arch::kRiscV64?riscv::kXn(10):0;}
SsaId entry(SsaFunction* f,u64 offset,u8 bytes){const auto id=static_cast<SsaId>(f->values.size());f->values.push_back({Varnode::reg(offset,bytes),SsaDef::kEntry,0,0});return id;}
SsaId literal(SsaFunction* f,u64 value,u8 bytes){const auto id=static_cast<SsaId>(f->values.size());f->values.push_back({Varnode::constant(value,bytes),SsaDef::kConstant,0,0});return id;}
SsaId operation(SsaFunction* f,MintOp op,SsaId a,u8 bytes,SsaId b=kNoValue){const auto id=static_cast<SsaId>(f->values.size());f->values.push_back({Varnode::temp(id,bytes),SsaDef::kInsn,static_cast<u32>(f->insns.size()),0});SsaInsn instruction;instruction.dest=id;instruction.op=op;instruction.use[0]=a;instruction.use[1]=b;instruction.address=f->entry+f->insns.size()*4;f->insns.push_back(instruction);return id;}
SsaId call(SsaFunction* f,Address target,bool indirect=false){SsaInsn instruction;instruction.op=indirect?MintOp::kCallInd:MintOp::kCall;instruction.address=f->entry+0x10;instruction.use[0]=literal(f,target,width(f->arch));const auto id=static_cast<SsaId>(f->values.size());f->values.push_back({Varnode::reg(result(f->arch),width(f->arch)),SsaDef::kInsn,static_cast<u32>(f->insns.size()),0});instruction.clobbers={id};f->insns.push_back(instruction);return id;}
void finish(SsaFunction* f,SsaId value){SsaInsn returned;returned.op=MintOp::kReturn;returned.address=f->entry+0x20;f->returnValues.push_back({static_cast<u32>(f->insns.size()),value});f->insns.push_back(returned);SsaBlock block;block.start=f->entry;block.end=f->entry+0x24;block.insnCount=f->insns.size();f->blocks={block};}
SsaFunction callee(Arch arch,Address at=0x2000){SsaFunction f;f.entry=at;f.arch=arch;const auto parameter=entry(&f,argument(arch),width(arch));const auto narrowed=operation(&f,MintOp::kTrunc,parameter,4);const auto one=literal(&f,1,4);const auto sum=operation(&f,MintOp::kAdd,narrowed,4,one);finish(&f,sum);return f;}
SsaFunction forwarding(Arch arch,Address at,Address target,bool indirect=false){SsaFunction f;f.entry=at;f.arch=arch;entry(&f,argument(arch),width(arch));const auto value=call(&f,target,indirect);finish(&f,value);return f;}
const FunctionPrototypeEvidence* find(const InterproceduralPrototypeReport& report,Address entry){const auto found=std::find_if(report.functions.begin(),report.functions.end(),[&](const auto& f){return f.entry==entry;});return found==report.functions.end()?nullptr:&*found;}

void fixedpoint(Arch arch){
    auto inner=callee(arch),middle=forwarding(arch,0x1800,0x2000),outer=forwarding(arch,0x1000,0x1800);InterproceduralPrototypeReport report;
    if(!expect(inferInterproceduralPrototypes({&outer,&inner,&middle},{},{},&report).ok() && report.converged,"deterministic interprocedural fixedpoint"))return;
    for(Address address:{Address{0x1000},Address{0x1800},Address{0x2000}}){const auto* f=find(report,address);if(!expect(f!=nullptr,"all functions represented"))continue;expect(f->result.width==4 && !f->returnsVoid && !f->authoritative && !f->parameterCountKnown && !f->declaration.valid(),"forwarded return width is observed, not an invented declaration");expect(!f->parameters.empty() && f->parameters[0].width==4,"callee argument width propagates across call graph");}
    expect(report.calls.size()==2 && report.calls[0].caller==0x1000 && report.calls[0].complete,"sorted direct call evidence");
    InterproceduralPrototypeReport reversed;expect(inferInterproceduralPrototypes({&inner,&middle,&outer},{},{},&reversed).ok() && reversed.converged && reversed.iterations==report.iterations && find(reversed,0x1000)->parameters[0].provenance==find(report,0x1000)->parameters[0].provenance,"input order cannot change inferred evidence");
}
void authoritative(){
    auto caller=forwarding(Arch::kAArch64,0x1000,0x9000);entry(&caller,arm64::kXn(1),8);
    UserPrototype declared;expect(parseUserPrototype("uint16_t(uint8_t count, void* buffer)",&declared).ok(),"authoritative declaration parser");InterproceduralPrototypeReport report;
    expect(inferInterproceduralPrototypes({&caller},{{0x9000,declared}},{},&report).ok() && report.converged,"imported signature fixedpoint");
    const auto* imported=find(report,0x9000);const auto* inferred=find(report,0x1000);
    expect(imported && imported->authoritative && imported->parameterCountKnown && imported->declaration.returnType==declared.returnType && imported->declaration.parameters[1].type=="void*" && imported->result.width==2,"authoritative imported declaration remains unchanged");
    expect(inferred && inferred->result.width==2 && inferred->parameters[0].width==1 && inferred->parameters[1].pointer && inferred->parameters[1].width==8,"imported result/scalar/pointer constraints propagate");
    UserPrototype pointerResult;parseUserPrototype("void*(void* buffer)",&pointerResult);
    expect(inferInterproceduralPrototypes({&caller},{{0x9000,pointerResult}},{},&report).ok() && report.converged && find(report,caller.entry)->result.width==8 && find(report,caller.entry)->result.pointer,"imported pointer return derives caller ABI width and propagates pointer evidence");
    auto local=callee(Arch::kAArch64);UserPrototype explicitLocal;parseUserPrototype("void(uint8_t narrow)",&explicitLocal);
    expect(inferInterproceduralPrototypes({&local},{{local.entry,explicitLocal}},{},&report).ok() && find(report,local.entry)->returnsVoid && find(report,local.entry)->result.width==0 && find(report,local.entry)->parameters[0].width==1,"user void and narrow parameter override observed machine carriers");
}
void unknownAndIndirect(){
    SsaFunction unknown;unknown.entry=0x3000;unknown.arch=Arch::kAArch64;finish(&unknown,entry(&unknown,arm64::kXn(0),8));InterproceduralPrototypeReport report;
    expect(inferInterproceduralPrototypes({&unknown},{},{},&report).ok() && report.converged && find(report,0x3000)->result.width==0 && find(report,0x3000)->parameters[0].width==0,"unused live-in does not invent a result or parameter");
    auto recursive=forwarding(Arch::kAArch64,0x4000,0x4000);
    expect(inferInterproceduralPrototypes({&recursive},{},{},&report).ok() && report.converged && find(report,0x4000)->result.width==0,"recursive unknown return remains unknown");
    auto target=callee(Arch::kAArch64),caller=forwarding(Arch::kAArch64,0x1000,0x2000,true);
    IndirectFlowReport recovered;recovered.functionEntry=caller.entry;IndirectFlowSite site;site.call=true;site.address=0x1010;site.complete=true;site.targets.push_back({target.entry,target.entry,Arch::kAArch64});recovered.sites={site};
    expect(inferInterproceduralPrototypes({&caller,&target},{},{recovered},&report).ok() && report.converged && find(report,caller.entry)->result.width==4 && find(report,caller.entry)->parameters[0].width==4,"proven recovered call participates in fixedpoint");
    recovered.sites[0].complete=false;
    expect(inferInterproceduralPrototypes({&caller,&target},{},{recovered},&report).ok() && report.converged && find(report,caller.entry)->result.width==0 && find(report,caller.entry)->parameters[0].width==0 && !report.calls[0].complete,"partial call targets are evidence only, not definitive constraints");
    auto stack=callee(Arch::kX86_32);
    expect(inferInterproceduralPrototypes({&stack},{},{},&report).ok() && find(report,stack.entry)->parameters.empty() && !find(report,stack.entry)->parameterCountKnown,"x86-32 stack ABI is not replaced with register argument guesses");
    InterproceduralPrototypeOptions limited;limited.maxWork=1;
    expect(inferInterproceduralPrototypes({&caller,&target},{},{},&report,limited).ok() && !report.converged,"work cutoff reports incomplete inference");
    report.iterations=0xdead;expect(!inferInterproceduralPrototypes({&target,&target},{},{},&report).ok() && report.iterations==0xdead,"duplicate function fails transactionally");
    auto broken=target;broken.insns[0].use[0]=0xfffffffe;
    expect(!inferInterproceduralPrototypes({&broken},{},{},&report).ok(),"malformed SSA rejected");
    SsaFunction pointerArithmetic;pointerArithmetic.entry=0x5000;pointerArithmetic.arch=Arch::kAArch64;
    const auto base=entry(&pointerArithmetic,arm64::kXn(0),8),offset=literal(&pointerArithmetic,8,8);
    const auto address=operation(&pointerArithmetic,MintOp::kAdd,base,8,offset);
    finish(&pointerArithmetic,operation(&pointerArithmetic,MintOp::kLoad,address,4));
    expect(inferInterproceduralPrototypes({&pointerArithmetic},{},{},&report).ok() && report.converged && find(report,0x5000)->parameters[0].pointer && find(report,0x5000)->parameters[0].width==8,"pointer-plus-literal memory address constrains only base parameter");
}
}
int main(){for(Arch arch:{Arch::kAArch64,Arch::kX86_64,Arch::kArm32,Arch::kThumb,Arch::kRiscV32,Arch::kRiscV64})fixedpoint(arch);authoritative();unknownAndIndirect();std::cout<<"Interprocedural prototype contracts: "<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;}
