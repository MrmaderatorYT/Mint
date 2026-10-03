#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

#include "mint/analysis/indirect_flow.h"
#include "mint/analysis/code_analyzer.h"
#include "mint/ir/lifter.h"
#include "mint/ir/normalize.h"
#include "mint/ssa/ssa_builder.h"

namespace {
using namespace mint;
unsigned checks=0,failures=0;
bool expect(bool condition,const std::string& name){++checks;if(!condition){++failures;std::cerr<<"FAIL "<<name<<'\n';}return condition;}
ByteView view(const std::vector<u8>& bytes){return ByteView(bytes.data(),bytes.size());}
void put32(std::vector<u8>* bytes,size_t at,u32 value){std::memcpy(bytes->data()+at,&value,4);}
std::vector<u8> words(std::initializer_list<u32> list){std::vector<u8> result;for(u32 v:list)for(unsigned n=0;n<4;++n)result.push_back(static_cast<u8>(v>>(n*8)));return result;}
SsaId literal(SsaFunction* function,u64 value,u8 width=8){const SsaId id=function->values.size();function->values.push_back({Varnode::constant(value,width),SsaDef::kConstant,0,0});return id;}
SsaId entry(SsaFunction* function,u64 offset=0,u8 width=8){const SsaId id=function->values.size();function->values.push_back({Varnode::reg(offset,width),SsaDef::kEntry,0,0});return id;}
SsaId op(SsaFunction* f,MintOp operation,SsaId a,SsaId b=kNoValue,SsaId c=kNoValue,u8 width=8){
    const SsaId id=f->values.size();f->values.push_back({Varnode::temp(id,width),SsaDef::kInsn,static_cast<u32>(f->insns.size()),0});
    SsaInsn instruction;instruction.op=operation;instruction.dest=id;instruction.use[0]=a;instruction.use[1]=b;instruction.use[2]=c;instruction.address=0x1000;f->insns.push_back(instruction);return id;
}
void site(SsaFunction* f,SsaId target,bool call=false){SsaInsn instruction;instruction.op=call?MintOp::kCallInd:MintOp::kBranchInd;instruction.address=0x1010;instruction.use[0]=target;f->insns.push_back(instruction);}
bool contains(const std::vector<std::string>& strings,const char* wanted){return std::find(strings.begin(),strings.end(),wanted)!=strings.end();}

void native(Arch arch,std::vector<u8> bytes,Arch targetMode){
    bytes.resize(64);
    if(arch==Arch::kAArch64)put32(&bytes,0x20,0xd65f03c0);
    else if(arch==Arch::kArm32 || arch==Arch::kThumb){bytes[0x20]=7;bytes[0x21]=0x20;bytes[0x22]=0x70;bytes[0x23]=0x47;}
    else if(arch==Arch::kRiscV32 || arch==Arch::kRiscV64)put32(&bytes,0x20,0x00008067);
    else bytes[0x20]=0xc3;
    ElfImage image;
    if(!expect(image.loadRaw(view(bytes),arch,0x1000,0x1000).ok(),std::string(archName(arch))+" raw fixture"))return;
    CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;
    if(!expect(analyzer.analyze(image,options).ok() && analyzer.functionAt(0x1000),std::string(archName(arch))+" indirect function discovery"))return;
    const auto* discovered=analyzer.functionAt(0x1000);
    expect(!discovered->incomplete && discovered->resolvedIndirectJumps.size()==1 && discovered->resolvedIndirectJumps[0].targets==std::vector<Address>{0x1020},std::string(archName(arch))+" proven SSA targets participate in discovery/CFG");
    if(arch==Arch::kArm32)expect(analyzer.functionAt(0x1020) && analyzer.functionAt(0x1020)->decodeArch==Arch::kThumb && discovered->callees==std::vector<Address>{0x1020},"ARM interworking tail callee discovered with Thumb mode");
    CodeAnalyzer restored;expect(restored.restore(image,options,analyzer.snapshot()).ok() && restored.indirectFlowReports().count(0x1000) && !restored.functionAt(0x1000)->incomplete,std::string(archName(arch))+" cache restore re-proves current native indirect flow");
    Lifter lifter;IrFunction ir;SsaFunction ssa;
    if(!expect(lifter.open(arch).ok() && lifter.liftFunction(*analyzer.functionAt(0x1000),image.memory(),&ir).ok(),std::string(archName(arch))+" indirect native lift"))return;
    normalizeRegisterAccesses(&ir);
    if(!expect(buildSsa(ir,&ssa).ok() && ssa.verify().empty(),std::string(archName(arch))+" indirect register SSA"))return;
    IndirectFlowReport report;
    if(!expect(recoverIndirectFlow(image,ssa,&report).ok() && report.converged && report.sites.size()==1,std::string(archName(arch))+" indirect pass")){std::cerr<<ssa.toText()<<"sites="<<report.sites.size()<<" converged="<<report.converged<<'\n';return;}
    const auto& found=report.sites.front();
    expect(found.complete && found.confidence==IndirectFlowConfidence::kProven && found.targets.size()==1 &&
           found.targets.front().address==0x1020 && found.targets.front().decodeArch==targetMode,std::string(archName(arch))+" proven native target/mode");
    if(arch==Arch::kArm32 || arch==Arch::kThumb)expect(found.targets.front().rawPointer==0x1021 && contains(found.provenance,"ARM interworking pointer tag"),"ARM interworking hint survives lifter address mask");
}

void finiteSets(){
    std::vector<u8> bytes(64);ElfImage image;expect(image.loadRaw(view(bytes),Arch::kX86_64,0x1000,0x1000).ok(),"finite-set image");
    SsaFunction f;f.entry=0x1000;f.arch=Arch::kX86_64;
    const auto a=literal(&f,0x1020),b=literal(&f,0x1030),condition=entry(&f,8,1);
    auto selected=op(&f,MintOp::kSelect,condition,a,b);site(&f,selected,true);IndirectFlowReport report;
    expect(recoverIndirectFlow(image,f,&report).ok() && report.sites[0].complete && report.sites[0].call && report.sites[0].targets.size()==2 && contains(report.sites[0].provenance,"bounded select"),"unknown condition over closed constants is a complete finite set");
    const SsaId phi=f.values.size();f.values.push_back({Varnode::temp(phi,8),SsaDef::kPhi,0,0});f.phis.push_back({phi,{a,b},0,false});f.insns.back().use[0]=phi;
    expect(recoverIndirectFlow(image,f,&report).ok() && report.sites[0].complete && report.sites[0].targets.size()==2 && contains(report.sites[0].provenance,"phi finite-set union"),"phi constant set");
    const auto live=entry(&f);f.phis[0].args={a,live};
    expect(recoverIndirectFlow(image,f,&report).ok() && !report.sites[0].complete && report.sites[0].confidence==IndirectFlowConfidence::kPartial && report.sites[0].targets.size()==1,"unknown phi arm retains partial evidence only");
    f.phis[0].args={a,phi};
    expect(recoverIndirectFlow(image,f,&report).ok() && report.sites[0].complete && report.sites[0].targets.size()==1,"loop phi whose only seed is a constant converges");
    const SsaId cyclic=f.values.size();f.values.push_back({Varnode::temp(cyclic,8),SsaDef::kPhi,1,0});f.phis.push_back({cyclic,{cyclic},0,false});f.phis[0].args={a,cyclic};
    expect(recoverIndirectFlow(image,f,&report).ok() && !report.sites[0].complete && report.sites[0].targets.size()==1,"seedless cycle cannot make mixed phi complete");
    f.phis[0].args={a,b};IndirectFlowOptions tiny;tiny.maxSetSize=1;
    expect(recoverIndirectFlow(image,f,&report,tiny).ok() && !report.sites[0].complete && report.sites[0].targets.size()==1,"set cap retains partial evidence");
    tiny={};tiny.maxIterations=1;
    expect(recoverIndirectFlow(image,f,&report,tiny).ok() && !report.converged && !report.sites[0].complete,"iteration cap never publishes proof");
    tiny={};tiny.maxWork=1;
    expect(recoverIndirectFlow(image,f,&report,tiny).ok() && !report.converged && !report.sites[0].complete,"Cartesian-product work cutoff never publishes proof");
    tiny={};tiny.maxSites=0;report.functionEntry=0xdead;
    expect(!recoverIndirectFlow(image,f,&report,tiny).ok() && report.functionEntry==0xdead,"failed bounds do not replace previous report");
    f.insns.back().use[0]=0xffffff00;
    expect(!recoverIndirectFlow(image,f,&report).ok(),"invalid SSA operand rejected");
    SsaFunction opaque;opaque.entry=0x1000;opaque.arch=Arch::kX86_64;const auto known=literal(&opaque,0x1020);
    SsaInsn intrinsic;intrinsic.op=MintOp::kIntrinsic;opaque.insns.push_back(intrinsic);site(&opaque,known);
    expect(recoverIndirectFlow(image,opaque,&report).ok() && !report.sites[0].complete && report.sites[0].targets.size()==1,"unmodeled instruction cannot preserve a confident register target");
    opaque.insns.erase(opaque.insns.begin());site(&opaque,entry(&opaque));
    expect(recoverIndirectFlow(image,opaque,&report).ok() && !report.sites[0].complete && report.sites[0].targets.size()==1,"unclosed branch predecessors prevent another site's closed-set claim");
}

// A sectionless native image with independent code and data segments permits
// checking immutable, mutable, virtual-only and relocated pointer slots.
std::vector<u8> elfFixture(bool writable,bool relocated,bool imported=false){
    std::vector<u8> bytes(0x380);const u8 ident[]={0x7f,'E','L','F',2,1,1};std::memcpy(bytes.data(),ident,sizeof(ident));
    elf::Ehdr header{};std::memcpy(header.ident,ident,sizeof(ident));header.type=elf::kEtDyn;header.machine=183;header.version=1;header.entry=0x1000;header.phoff=sizeof(header);header.ehsize=sizeof(header);header.phentsize=sizeof(elf::Phdr);header.phnum=relocated?3:2;
    std::memcpy(bytes.data(),&header,sizeof(header));
    elf::Phdr code{};code.type=elf::kPtLoad;code.flags=elf::kPfR|elf::kPfX;code.offset=0x200;code.vaddr=0x1000;code.filesz=64;code.memsz=64;code.align=1;
    elf::Phdr data{};data.type=elf::kPtLoad;data.flags=elf::kPfR|(writable?elf::kPfW:0);data.offset=0x280;data.vaddr=0x2000;data.filesz=0x100;data.memsz=0x120;data.align=1;
    std::memcpy(bytes.data()+sizeof(header),&code,sizeof(code));std::memcpy(bytes.data()+sizeof(header)+sizeof(code),&data,sizeof(data));
    const u64 pointer=relocated?0:0x1020;std::memcpy(bytes.data()+0x280,&pointer,8);
    put32(&bytes,0x200,0x10008010);put32(&bytes,0x204,0xf9400211);put32(&bytes,0x208,0xd61f0220);
    put32(&bytes,0x220,0xd65f03c0);put32(&bytes,0x230,0xd65f03c0);
    if(relocated){
        elf::Phdr dynamic{};dynamic.type=elf::kPtDynamic;dynamic.offset=0x2a0;dynamic.vaddr=0x2020;dynamic.filesz=7*sizeof(elf::Dyn);dynamic.memsz=dynamic.filesz;dynamic.flags=elf::kPfR;dynamic.align=1;
        std::memcpy(bytes.data()+sizeof(header)+2*sizeof(code),&dynamic,sizeof(dynamic));
        const elf::Dyn records[]={{elf::kDtRela,0x20a0},{elf::kDtRelaSz,sizeof(elf::Rela)},{elf::kDtRelaEnt,sizeof(elf::Rela)},{elf::kDtSymTab,0x20c0},{elf::kDtStrTab,0x20f0},{elf::kDtStrSz,16},{elf::kDtNull,0}};
        std::memcpy(bytes.data()+0x2a0,records,sizeof(records));
        elf::Rela relocation{};relocation.offset=0x2000;relocation.info=imported?(u64{1}<<32)|1026:1027;relocation.addend=0x1020;std::memcpy(bytes.data()+0x320,&relocation,sizeof(relocation));
        if(imported){elf::Sym symbol{};symbol.name=1;symbol.info=0x12;std::memcpy(bytes.data()+0x340+sizeof(symbol),&symbol,sizeof(symbol));const char strings[]="\0external\0";std::memcpy(bytes.data()+0x370,strings,sizeof(strings));}
    }
    return bytes;
}
void memoryProof(){
    for(bool writable:{false,true})for(bool relocated:{false,true}){
        auto bytes=elfFixture(writable,relocated);ElfImage image;if(!expect(image.load(view(bytes)).ok(),"indirect ELF fixture"))continue;
        SsaFunction f;f.entry=0x1000;f.arch=Arch::kAArch64;const auto slot=literal(&f,0x2000);site(&f,op(&f,MintOp::kLoad,slot));IndirectFlowReport report;
        if(!expect(recoverIndirectFlow(image,f,&report).ok() && report.sites.size()==1,"pointer load recovery"))continue;
        const auto& result=report.sites[0];expect(result.complete==!writable && (writable?result.targets.empty():result.targets.size()==1 && result.targets[0].address==0x1020),"only immutable pointer loads are proven");
        expect(result.dependencies.size()==1 && result.dependencies[0].start==0x2000 && result.dependencies[0].end==0x2008,"exact pointer dependency preserved");
        if(relocated && !writable)expect(contains(result.provenance,"loader relocation resolution"),"relative relocation evidence");
        if(!writable){
            CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;
            expect(analyzer.analyze(image,options).ok() && analyzer.functionAt(0x1000) && !analyzer.functionAt(0x1000)->incomplete,"readonly loaded SSA target opens complete native function");
            const auto snapshot=analyzer.snapshot();CodeAnalyzer restored;
            expect(restored.restore(image,options,snapshot).ok(),"readonly dependency cache proof validates");
            const u64 changed=0x1030;
            expect(image.applyPatch(0x2000,ByteView(reinterpret_cast<const u8*>(&changed),sizeof(changed))).ok(),"readonly pointer overlay");
            CodeAnalyzer::IncrementalResult incremental;
            expect(analyzer.reanalyzeChanged(image,options,{{0x2000,0x2008}},&incremental).ok() && !incremental.used && !incremental.reason.empty() && analyzer.functionAt(0x1000)->resolvedIndirectJumps[0].targets==std::vector<Address>{0x1030},"pointer dependency change forces safe full rediscovery");
            if(!relocated)expect(incremental.reason.find("indirect")!=std::string::npos,"non-root pointer dependency is invalidated by SSA evidence");
            CodeAnalyzer stale;
            expect(!stale.restore(image,options,snapshot).ok(),"stale saved target cannot be trusted after pointer overlay");
            image.resetPatches();
        }
        f.insns.front().use[0]=literal(&f,0x2100);
        expect(recoverIndirectFlow(image,f,&report).ok() && !report.sites[0].complete && report.sites[0].targets.empty(),"virtual zero-fill cannot prove a code pointer");
    }
    auto bytes=elfFixture(false,true,true);ElfImage image;expect(image.load(view(bytes)).ok(),"import relocation fixture");
    SsaFunction f;f.entry=0x1000;f.arch=Arch::kAArch64;site(&f,op(&f,MintOp::kLoad,literal(&f,0x2000)));IndirectFlowReport report;
    expect(recoverIndirectFlow(image,f,&report).ok() && !report.sites[0].complete && report.sites[0].targets.empty(),"unresolved import is not guessed from relocation addend");
}
}
int main(){
    native(Arch::kAArch64,words({0xd2820410,0xd61f0200}),Arch::kAArch64);
    native(Arch::kX86_64,{0x48,0xb8,0x20,0x10,0,0,0,0,0,0,0xff,0xe0},Arch::kX86_64);
    native(Arch::kX86_32,{0xb8,0x20,0x10,0,0,0xff,0xe0},Arch::kX86_32);
    native(Arch::kArm32,words({0xe59f3000,0xe12fff13,0x1021}),Arch::kThumb);
    native(Arch::kThumb,{0x01,0x4b,0x18,0x47,0,0,0,0,0x21,0x10,0,0},Arch::kThumb);
    native(Arch::kRiscV32,words({0x00001337,0x02030313,0x00030067}),Arch::kRiscV32);
    native(Arch::kRiscV64,words({0x00001337,0x02030313,0x00030067}),Arch::kRiscV64);
    finiteSets();memoryProof();
    std::cout<<"Indirect-flow proof contracts: "<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;
}
