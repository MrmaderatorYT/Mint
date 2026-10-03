#include <algorithm>
#include <array>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "mint/analysis/code_analyzer.h"
#include "mint/base/mapped_file.h"
#include "mint/decompile/decompiler.h"
#include "mint/interp/emulator.h"
#include "mint/ir/lifter.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"

namespace {
using namespace mint;
size_t checks=0,failures=0,files=0,libraries=0,lifted=0,intrinsics=0,incomplete=0,executed=0,unsupportedMath=0;
std::map<Arch,size_t> architectureFiles;
bool expect(bool condition,const std::string& label){++checks;if(!condition){++failures;std::cerr<<"FAIL "<<label<<'\n';}return condition;}
u64 spFor(Arch arch){if(arch==Arch::kAArch64)return arm64::kSp;if(arch==Arch::kArm32 || arch==Arch::kThumb)return arm32::kSp;if(arch==Arch::kRiscV32 || arch==Arch::kRiscV64)return riscv::kSp;return x86::kRsp;}
u64 resultFor(Arch arch){return arch==Arch::kRiscV32 || arch==Arch::kRiscV64?riscv::kXn(10):0;}
void arguments(InterpState* state,u64 a,u64 b,u8 width){
    const auto arch=state->arch();
    if(arch==Arch::kX86_32){state->memory().write(0x700004,InterpValue::concrete(a,4),4);state->memory().write(0x700008,InterpValue::concrete(b,4),4);}
    else if(arch==Arch::kX86_64){state->setRegister(x86::kRdi,a,8);state->setRegister(x86::kRsi,b,8);}
    else if(arch==Arch::kAArch64){state->setRegister(arm64::kXn(0),a,8);state->setRegister(arm64::kXn(1),b,8);}
    else if(arch==Arch::kArm32 || arch==Arch::kThumb){state->setRegister(arm32::kRn(0),a,4);state->setRegister(arm32::kRn(1),b,4);}
    else{state->setRegister(riscv::kXn(10),a,width);state->setRegister(riscv::kXn(11),b,width);}
}
bool execute(const IrFunction& ir,const ElfImage& image,u32 a,u32 b,u32 expected,const std::string& label,bool memory=false){
    const u8 width=image.pointerSize();Emulator emulator(ir.arch);auto& state=emulator.state();state.memory().map(image.memory());state.setRegister(spFor(ir.arch),0x700000,width);
    state.memory().write(0x700000,InterpValue::concrete(0x900000,width),width);
    if(ir.arch==Arch::kAArch64)state.setRegister(arm64::kXn(30),0x900000,8);
    else if(ir.arch==Arch::kArm32 || ir.arch==Arch::kThumb)state.setRegister(arm32::kLr,0x900001,4);
    else if(ir.arch==Arch::kRiscV32 || ir.arch==Arch::kRiscV64)state.setRegister(riscv::kXn(1),0x900000,width);
    arguments(&state,memory?0x710000:a,b,width);
    if(memory){const std::array<u32,4> data={11,23,37,53};for(size_t n=0;n<data.size();++n)state.memory().write(0x710000+n*4,InterpValue::concrete(data[n],4),4);}
    InterpOptions options;options.stopOnCall=true;options.maxSteps=4096;InterpResult result;
    const auto status=emulator.run(ir,options,&result);const auto actual=state.registerValue(resultFor(ir.arch),width);++executed;
    const bool correct=status.ok() && result.returned && !result.hitUnknownBranch && !result.hitCycleLimit && actual.concreteLike() && static_cast<u32>(actual.bits)==expected;
    if(!expect(correct,label+" supported scalar semantics"))std::cerr<<status.toString()<<" "<<result.stopReason<<" inputs=("<<a<<","<<b<<") actual="<<actual.toString()<<" expected="<<expected<<" returned="<<result.returned<<" unknown-branch="<<result.hitUnknownBranch<<" step-limit="<<result.hitCycleLimit<<'\n'<<ir.toText();
    return correct;
}
void file(const std::string& path,bool library){
    MappedFile mapping;ElfImage image;
    if(!expect(mapping.open(path).ok() && image.load(mapping.view()).ok(),path+" native load"))return;
    if(!library && !expect(!image.memory().hasOverlaps(),path+" generated fixture has an unambiguous linker memory layout"))return;
    if(library)++libraries;else{++files;++architectureFiles[image.arch()];}
    CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;
    if(library){options.maxFunctions=64;options.maxInstructions=20000;}
    if(!expect(analyzer.analyze(image,options).ok() && !analyzer.functions().empty() && !analyzer.code().empty(),path+" native discovery"))return;
    if(!library){expect(image.findSection(".debug_info")!=nullptr,path+" real compiler DWARF fixture");expect(analyzer.functions().size()>=10,path+" compiler symbols seed distinct functions");}
    if(!library){
        const auto* symbol=image.findSymbol("corpus_constant");const auto* constant=symbol?analyzer.functionAt(symbol->value):nullptr;
        expect(constant!=nullptr,path+" constant kernel discovered");
        if(constant && path.find("/thumb-")!=std::string::npos)expect(constant->decodeArch==Arch::kThumb,path+" actual Thumb compiler mode");
        if(constant && path.find("/arm-")!=std::string::npos)expect(constant->decodeArch==Arch::kArm32,path+" actual ARM compiler mode");
    }
    size_t sampled=0,modeled=0,unmodeled=0;
    for(const auto& function:analyzer.functions()){
        if(library && sampled>=4)break;
        if(function.instructions.empty())continue;
        ++sampled;incomplete+=function.incomplete;
        const std::string label=path+" "+function.name;
        expect(analyzer.functionContaining(function.entry)==&function,label+" entry-address ownership");
        const auto* first=analyzer.code().find(function.entry);
        expect(first && analyzer.code().covering(function.entry+first->size-1)==first,label+" listing covers instruction bytes");
        Disassembler decoder;expect(decoder.open(function.decodeArch).ok(),label+" listing decoder");
        for(Address address:function.instructions){const auto* record=analyzer.code().find(address);if(!expect(record && record->size && image.memory().viewAt(address,record->size).size()==record->size,label+" listing file-backed range"))break;if(record->flow==FlowKind::kInvalid)continue;DecodedInsn verbose;const auto mode=image.architectureAt(address,function.entry,function.decodeArch);if(decoder.arch()!=mode)decoder.open(mode);expect(decoder.decodeVerbose(address,image.memory().viewAt(address,16),&verbose) && verbose.record.size==record->size && !verbose.mnemonic.empty(),label+" synchronized listing decode");}
        Lifter lifter;IrFunction ir;
        if(!expect(lifter.open(function.decodeArch).ok() && lifter.liftFunction(function,image.memory(),&ir).ok(),label+" native lift"))continue;
        ++lifted;intrinsics+=ir.intrinsicCount;
        const auto issues=ir.verify();if(!expect(issues.empty(),label+" IR invariants")){for(const auto& issue:issues)std::cerr<<issue<<'\n';continue;}
        IrFunction normalized=ir;normalizeRegisterAccesses(&normalized);SsaFunction ssa;SsaBuildStats stats;
        if(!expect(buildSsa(normalized,&ssa,&stats).ok() && ssa.verify().empty() && stats.undefinedTempReads==0,label+" register SSA invariants"))continue;
        DecompileResult decompiled;if(!expect(decompileIr(ir,&decompiled,[&](Address address){return image.describeAddress(address);}).ok() && !decompiled.cSource.empty(),label+" structured C emission"))continue;
        if(ir.intrinsicCount)expect(decompiled.cSource.find("intrinsic")!=std::string::npos || decompiled.cSource.find("unmodelled instruction #")!=std::string::npos,label+" unsupported instruction disclosure");
        if(library)continue;
        const bool scalar=function.name=="corpus_constant" || function.name=="corpus_arithmetic" || function.name=="corpus_condition" || function.name=="corpus_memory";
        if(!scalar)continue;
        if(function.name=="corpus_constant")expect(ir.intrinsicCount==0 && !function.incomplete,label+" simple leaf constant is modeled");
        if(ir.intrinsicCount || function.incomplete){++unsupportedMath;++unmodeled;std::cout<<"COVERAGE unsupported "<<label<<" intrinsic="<<ir.intrinsicCount<<" incomplete="<<function.incomplete<<'\n';continue;}
        ++modeled;
        if(function.name=="corpus_constant")execute(ir,image,0,0,37,label);
        else for(const auto pair:{std::pair<u32,u32>{0,1},{7,3},{11,23},{0xfffffff0,9}}){
            const u32 expected=function.name=="corpus_arithmetic"?((pair.first+pair.second)*3u)^0x55u:
                function.name=="corpus_condition"?(pair.first<pair.second?pair.second-pair.first:pair.first-pair.second):std::array<u32,4>{11,23,37,53}[pair.second&3]+1;
            execute(ir,image,pair.first,pair.second,expected,label,function.name=="corpus_memory");
        }
    }
    if(!library)expect(modeled>=1,path+" at least one genuinely supported controlled scalar kernel");
    std::cout<<"CORPUS "<<path<<" arch="<<archName(image.arch())<<" format="<<image.formatName()<<" functions="<<analyzer.functions().size()<<" instructions="<<analyzer.code().size()<<" sampled="<<sampled<<" modeled-kernels="<<modeled<<" unsupported-kernels="<<unmodeled<<'\n';
}
}
int main(int argc,char** argv){
    bool library=false;for(int n=1;n<argc;++n){const std::string argument=argv[n];if(argument=="--library"){library=true;continue;}file(argument,library);library=false;}
    expect(!library,"library option requires an input path");expect(files>=49,"real compiler corpus contains at least 49 binaries");
    // ELF ARM images can contain Thumb mappings without a distinct container
    // architecture; require eight compiler binaries across the full ARM pair.
    for(Arch arch:{Arch::kAArch64,Arch::kX86_64,Arch::kX86_32,Arch::kRiscV32,Arch::kRiscV64})expect(architectureFiles[arch]>=7,std::string(archName(arch))+" six optimization levels plus LTO");
    expect(architectureFiles[Arch::kArm32]+architectureFiles[Arch::kThumb]>=14,"ARM and Thumb six optimization levels plus LTO each");
    expect(libraries>=2,"two real NDK libc++ native libraries");
    std::cout<<"Native compiler corpus: "<<files<<" binaries + "<<libraries<<" libraries, "<<lifted<<" lifted functions, "<<executed<<" controlled IR executions, "<<intrinsics<<" explicit intrinsics, "<<incomplete<<" incomplete functions, "<<unsupportedMath<<" unmodeled math kernels; "<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;
}
