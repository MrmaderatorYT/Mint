#include "mint/analysis/abi_model.h"
#include "mint/analysis/code_analyzer.h"
#include "mint/base/mapped_file.h"
#include "mint/decompile/decompiler.h"
#include "mint/interp/executor.h"
#include "mint/ir/lifter.h"
#include "mint/ir/registers.h"
#include "mint/session.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <unistd.h>

using namespace mint;
namespace {
unsigned checks=0;
void require(bool yes,const std::string& label){++checks;if(!yes){std::cerr<<"RISC-V ABI: "<<label<<'\n';std::exit(1);}}
UserPrototype parsed(const std::string& text){UserPrototype p;require(parseUserPrototype(text,&p).ok(),"prototype "+text);return p;}
void types(DataTypeManager& t){
    for(const auto& declaration:{"PairF=struct{first:f32;second:f32}","PairD=struct{first:f64;second:f64}",
        "Single=struct{real:f32}","FloatArray=f32[2]","Nested=struct{values:FloatArray}","Mixed=struct{real:f32;integer:u32}",
        "Reverse=struct{integer:u32;real:f32}","Packed=packed{tag:u8;real:f64}","Padded=struct{first:f32;second:f64@24}",
        "Choice=union{real:f32;integer:u32}","HasUnion=struct{choice:Choice;real:f32}","Triple=struct{first:f32;second:f32;third:f32}",
        "Large=struct{first:u64;second:u64;third:u64}","PairI=struct{first:u64;second:u64}"})require(t.define(declaration).ok(),declaration);
}
bool gp(const AbiStoragePiece& p,unsigned n,u8 word){return !p.floating&&p.storage==Varnode::reg(riscv::kXn(10+n),word);}
bool fp(const AbiStoragePiece& p,unsigned n,u8 width){return p.floating&&p.storage==Varnode::reg(riscv::kF0+(10+n)*8,8)&&p.width==width&&p.nanBoxed==(width==4);}
void matrix(){
    for(auto arch:{Arch::kRiscV32,Arch::kRiscV64}) {
        const u8 word=arch==Arch::kRiscV32?4:8;const std::string base=word==4?"riscv32":"riscv64";
        DataTypeManager t(word);types(t);const AbiTypeResolver resolver=[&](const auto& n,auto* l){return t.resolve(n,l);};
        for(const auto& mode:{std::string("f"),std::string("d")})for(unsigned ng=0;ng<=8;++ng)for(unsigned nf=0;nf<=8;++nf)for(bool wide:{false,true}) {
            UserPrototype p;p.returnType="void";p.callingConvention=base+mode;
            for(unsigned n=0;n<ng;++n)p.parameters.push_back({word==4?"u32":"u64","g"+std::to_string(n)});
            for(unsigned n=0;n<nf;++n)p.parameters.push_back({"f32","f"+std::to_string(n)});
            const size_t target=p.parameters.size();p.parameters.push_back({wide?"PairD":"PairF","value"});p.parameters.push_back({"f32","after"});
            AbiModel model;require(buildAbiModel(arch,p,&model,resolver).ok(),"bank exhaustion model");
            const auto& value=model.parameters[target];const bool eligible=(!wide||mode=="d")&&nf<=6;
            if(eligible) {
                require(value.pieces.size()==2&&!value.indirect&&fp(value.pieces[0],nf,wide?8:4)&&fp(value.pieces[1],nf+1,wide?8:4),"two independent FP fields survive GP exhaustion");
                require(value.pieces[1].valueOffset==(wide?8u:4u)&&!value.pieces[0].storage.overlaps(value.pieces[1].storage),"FP offsets and non-overlapping eight-byte storage units");
            } else {
                require(std::none_of(value.pieces.begin(),value.pieces.end(),[](const auto& piece){return piece.floating;}),"ineligible aggregate falls back atomically");
                const unsigned content=wide?16:8;const bool indirect=content>2u*word;
                require(value.indirect==indirect,"integer fallback chooses direct bytes or pointer by XLEN");
                if(ng<8)require(gp(value.pieces[0],ng,word),"fallback starts at next GPR without even-pair skip");
                else require(!value.pieces[0].storage.valid()&&value.pieces[0].stackOffset==0,"fully spilled fallback starts at entry SP");
                if(!indirect&&ng==7&&content>word)require(value.pieces.size()==2&&value.pieces[1].kind==AbiStorageKind::kStack&&value.pieces[1].stackOffset==0&&value.pieces[1].valueOffset==word,"last GPR and stack split exact aggregate bytes");
            }
            const auto& after=model.parameters[target+1];const unsigned nextFp=eligible?nf+2:nf;
            if(nextFp<8)require(after.pieces.size()==1&&fp(after.pieces[0],nextFp,4),"failed aggregate allocation preserves remaining FP bank");
            else require(std::none_of(after.pieces.begin(),after.pieces.end(),[](const auto& piece){return piece.floating&&piece.storage.valid();}),"scalar FP bank exhaustion falls back to GPR/stack");
        }
        for(const auto& name:{"Single","Nested","Mixed","Reverse","Packed","Padded"}) {
            AbiModel model;require(buildAbiModel(arch,parsed("@"+base+"d "+name+"("+name+" value)"),&model,resolver).ok(),"flattened aggregate "+std::string(name));
            require(model.result.pieces.size()==model.parameters[0].pieces.size()&&!model.result.indirect,"return classification matches first named argument");
            require(std::any_of(model.result.pieces.begin(),model.result.pieces.end(),[](const auto& piece){return piece.floating;}),"nested/packed/padded FP fields remain eligible");
            for(size_t n=0;n<model.result.pieces.size();++n)require(model.result.pieces[n].storage==model.parameters[0].pieces[n].storage&&model.result.pieces[n].valueOffset==model.parameters[0].pieces[n].valueOffset,"return classification does not consume incoming argument registers");
            if(std::string(name)=="Padded")require(model.result.pieces.size()==2&&model.result.pieces[1].valueOffset==24,"explicit padding preserved in flattened piece offsets");
            if(std::string(name)=="Nested")require(fp(model.result.pieces[1],1,4),"array typedef metadata survives recursive flattening");
        }
        for(const auto& name:{"Choice","HasUnion","Triple"}) {
            AbiModel model;require(buildAbiModel(arch,parsed("@"+base+"d void("+name+" value)"),&model,resolver).ok(),"noneligible aggregate model");
            require(std::none_of(model.parameters[0].pieces.begin(),model.parameters[0].pieces.end(),[](const auto& p){return p.floating;}),"unions and more than two leaves never flatten into FP registers");
        }
        for(const auto& suffix:{std::string(),std::string("f"),std::string("d")}) {
            AbiModel model;const auto p=parsed("@"+base+suffix+" u64(u32 prefix, u64 pair, ...)");
            require(buildAbiModel(arch,p,&model,resolver).ok()&&gp(model.parameters[1].pieces[0],1,word),"named u64 never skips odd GPR in a variadic declaration");
        }
        AbiModel hidden;require(buildAbiModel(arch,parsed("@"+base+"d Large(u32 integer, f32 real)"),&hidden,resolver).ok()&&hidden.result.indirect&&gp(hidden.hiddenResult[0],0,word)&&gp(hidden.parameters[0].pieces[0],1,word)&&fp(hidden.parameters[1].pieces[0],0,4),"hidden result pointer consumes only integer bank");
        AbiModel malformed;const AbiTypeResolver missing=[&](const std::string& name,DataTypeLayout* out){auto status=t.resolve(name,out);if(status.ok()&&out->kind==DataTypeKind::kArray){out->elementType.clear();out->elementCount=0;}return status;};
        require(!buildAbiModel(arch,parsed("@"+base+"d void(Nested value)"),&malformed,missing).ok()&&malformed.parameters.empty(),"missing array element evidence cannot silently choose integer ABI");
        require(prototypeUsesSimpleIntegerRegisters(parsed("@"+base+"d u32(u32 value)"),arch),"explicit hard-float convention retains integer-only call-graph constraints");
        require(!prototypeUsesSimpleIntegerRegisters(parsed("@"+base+"d f32(f32 value)"),arch),"FP arguments never enter integer-only prototype inference");
        if(word==4)require(!prototypeUsesSimpleIntegerRegisters(parsed("@riscv32 u64(void)"),arch),"register-pair return is not a simple integer-register prototype");
        for(u32 alignment:{0u,3u,32u}) {
            const AbiTypeResolver invalid=[&](const std::string& name,DataTypeLayout* out){auto status=t.resolve(name,out);if(status.ok())out->alignment=alignment;return status;};
            require(!buildAbiModel(arch,parsed("@"+base+"d void(u32 value)"),&malformed,invalid).ok(),"invalid resolver alignment is rejected before stack arithmetic");
        }
    }
}
void emission(){
    for(auto arch:{Arch::kRiscV32,Arch::kRiscV64})for(bool call:{false,true}) {
        const std::string abi=arch==Arch::kRiscV32?"riscv32d":"riscv64d";
        DataTypeManager t(arch==Arch::kRiscV32?4:8);types(t);
        IrFunction ir;ir.arch=arch;ir.entry=0x1000;ir.name="single_fp";IrBuilder b(&ir);b.setAddress(ir.entry);
        const u8 word=arch==Arch::kRiscV32?4:8;
        if(call)b.emit(MintOp::kCall,{},Varnode::constant(0x2000,word));
        b.emit(MintOp::kStore,{},Varnode::constant(0x9000,word),Varnode::reg(riscv::kF0+80,8));
        b.emit(MintOp::kReturn,{},Varnode::reg(riscv::kXn(1),arch==Arch::kRiscV32?4:8));
        IrBlock block;block.id=0;block.start=ir.entry;block.end=0x1008;block.insnCount=ir.insns.size();ir.blocks.push_back(block);
        DecompileResult result;const auto prototype=parsed("@"+abi+" Single(Single value)"),callee=parsed("@"+abi+" Single(void)");
        const auto status=decompileIr(ir,&result,[](Address){return "callee";},{},{},[&](Address address){return address==0x1000?prototype:callee;},[&](const auto& name,auto* out){return t.resolve(name,out);});
        require(status.ok(),"typed FP aggregate decompilation: "+status.toString());
        require(result.cSource.find("0xffffffff00000000ULL")!=std::string::npos,"NaN boxing survives typed parameter/call result conversion");
        require(result.cSource.find("return op_abi_aggregate_result_Single(")!=std::string::npos,"one-field aggregate return reconstructs its object instead of casting a scalar");
        if(call)require(result.cSource.find("Single abi_call_result_")!=std::string::npos&&result.cSource.find("op_abi_extract(abi_call_result_")!=std::string::npos,"single-field aggregate call is captured once and extracted into its real FP unit");
    }
}
std::vector<u8> bytes(u64 low,unsigned size,u64 high=0){std::vector<u8> out(size);for(unsigned n=0;n<size;++n)out[n]=u8((n<8?low:high)>>((n%8)*8));return out;}
void real(const std::string& abi,const char* path){
    MappedFile file;require(file.open(path).ok(),"map compiler corpus "+abi);ElfImage image;require(image.load(file.view()).ok(),"load real RISC-V ELF");
    const u8 word=image.arch()==Arch::kRiscV32?4:8;DataTypeManager t(word);types(t);const AbiTypeResolver resolver=[&](const auto& n,auto* out){return t.resolve(n,out);};
    CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;require(analyzer.analyze(image,options).ok(),"analyze compiler corpus");
    Lifter lifter;require(lifter.open(image.arch()).ok(),"open corpus lifter");
    require(image.defaultCallingConvention()==abi,"ELF e_flags identifies the real soft/F/D ABI");
    SignatureLibrary library;require(library.deserialize("MINTSIG 1\nabi="+abi+"\nidentity\tf32(f32 value)\n").ok()&&library.validateFor(image).ok(),"matching signature library binds to actual ELF float ABI");
    const std::string other=word==4?(abi=="riscv32"?"riscv32d":"riscv32"):(abi=="riscv64"?"riscv64d":"riscv64");
    SignatureLibrary mismatch;require(mismatch.deserialize("MINTSIG 1\nabi="+other+"\nidentity\tf32(f32 value)\n").ok()&&!mismatch.validateFor(image).ok(),"mismatched signature-library float ABI rejected against e_flags");
    struct Probe {std::string name,prototype;std::vector<std::vector<u8>> arguments;u64 expected;};
    const u64 payload=0xfff0000012345678ull;const u32 single=0xff812345;
    const std::string seven="u32 a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g, ";
    const std::vector<u8> packed={0x71,0x78,0x56,0x34,0x12,0,0,0xf0,0xff};
    std::vector<Probe> probes={
        {"mint_abi_named_pair","u64(u32 prefix, u64 value)",{bytes(17,4),bytes(payload,8)},payload},
        {"mint_abi_last_pair","u64("+seven+"u64 value)",{},payload},
        {"mint_abi_split_aggregate","u64("+seven+"PairI value)",{},payload},
        {"mint_abi_fp_overflow","u64(f32 a, f32 b, f32 c, f32 d, f32 e, f32 f, f32 g, f32 h, f64 value)",{},payload},
        {"mint_abi_mixed","u32(Mixed value)",{bytes(u64(single)|(u64{0x12345678}<<32),8)},single^0x12345678u},
        {"mint_abi_dpair","u64(PairD value)",{bytes(0x3ff0000000000000ull,16,payload)},payload},
        {"mint_abi_fpair","u32(PairF value)",{bytes(u64{0x3f800000}|(u64(single)<<32),8)},single},
        {"mint_abi_nested","u32(Nested value)",{bytes(u64{0x3f800000}|(u64(single)<<32),8)},single},
        {"mint_abi_packed","u64(Packed value)",{packed},payload},
        {"mint_abi_high_u32","u32(u32 value)",{bytes(0x80000001,4)},1},
    };
    for(unsigned n=0;n<7;++n){probes[1].arguments.push_back(bytes(n+11,4));probes[2].arguments.push_back(bytes(n+11,4));}
    probes[1].arguments.push_back(bytes(payload,8));probes[2].arguments.push_back(bytes(0x1122334455667788ull,16,payload));
    for(unsigned n=0;n<8;++n)probes[3].arguments.push_back(bytes(0x3f800000+n,4));probes[3].arguments.push_back(bytes(payload,8));
    for(const auto& probe:probes) {
        Address entry=kNoAddress;for(const auto& symbol:image.symbols())if(symbol.name==probe.name){entry=symbol.value;break;}
        require(entry!=kNoAddress&&analyzer.functionAt(entry),"compiler function discovered: "+probe.name);
        IrFunction ir;require(lifter.liftFunction(*analyzer.functionAt(entry),image.memory(),&ir).ok()&&ir.verify().empty()&&!ir.intrinsicCount,"compiler function has verified supported IR: "+probe.name);
        AbiModel model;const auto prototype=parsed("@"+abi+" "+probe.prototype);require(buildAbiModel(image.arch(),prototype,&model,resolver).ok(),"compiler probe ABI storage");
        require(model.parameters.size()==probe.arguments.size(),"compiler probe argument cardinality");
        InterpState state(image.arch());state.memory().map(image.memory());const Address sp=0x800000;state.setRegister(riscv::kSp,sp,word);
        for(size_t n=0;n<model.parameters.size();++n){const auto& argument=model.parameters[n];const auto& raw=probe.arguments[n];
            require(argument.size==raw.size(),"compiler probe exact object layout");const Address object=0x900000+n*0x1000;
            if(argument.indirect)for(size_t byte=0;byte<raw.size();++byte)state.memory().writeByte(object+byte,raw[byte]);
            for(const auto& piece:argument.pieces){u64 value=argument.indirect?object:0;
                if(!argument.indirect){require(piece.valueOffset+piece.width<=raw.size(),"ABI piece stays in object");for(unsigned byte=0;byte<piece.width;++byte)value|=u64(raw[piece.valueOffset+byte])<<(byte*8);}
                if(piece.nanBoxed)value|=0xffffffff00000000ull;
                DataTypeLayout layout;require(t.resolve(prototype.parameters[n].type,&layout).ok(),"resolve compiler probe source type");
                if(!argument.indirect&&!piece.floating&&piece.storage.valid()&&!layout.isFloating&&(layout.kind==DataTypeKind::kPrimitive||layout.kind==DataTypeKind::kEnum)&&layout.size<word&&
                    (layout.isSigned||layout.size==4)&&(value&(u64{1}<<(layout.size*8-1))))value|=~((u64{1}<<(layout.size*8))-1);
                if(piece.storage.valid())state.setRegister(piece.storage.offset,value,piece.storage.size);
                else state.memory().write(sp+piece.stackOffset,InterpValue::concrete(value,piece.width),piece.width);
            }
        }
        InterpOptions interp;interp.maxSteps=1000;interp.stopOnCall=true;interp.assumeDefaultFloatingPoint=true;InterpResult result;
        require(executeIr(ir,&state,interp,&result).ok()&&result.returned,"compiler probe executed as bounded IR: "+probe.name);
        const bool narrow=prototype.returnType=="u32";auto low=state.registerValue(riscv::kXn(10),narrow?4:word);
        require(low.concreteLike(),"compiler return bits remain concrete: "+probe.name);u64 actual=low.bits;
        if(!narrow&&word==4){const auto high=state.registerValue(riscv::kXn(11),4);require(high.concreteLike(),"compiler high return word concrete");actual|=high.bits<<32;}
        require(actual==probe.expected,"actual compiler calling convention matches model: "+abi+" "+probe.name);
        if(word==8&&probe.name=="mint_abi_high_u32") {
            DecompileResult text;require(decompileIr(ir,&text,{},{},{},[&](Address){return prototype;},resolver).ok()&&
                text.cSource.find("(uint64_t)(int32_t)(value)")!=std::string::npos,"decompiler preserves RV64 sign extension of unsigned 32-bit arguments");
        }
    }
    std::string project="/private/tmp/mint-riscv-abi-XXXXXX";const int descriptor=mkstemp(project.data());require(descriptor>=0,"owned temporary Program");close(descriptor);unlink(project.c_str());
    struct Cleanup {std::string path;~Cleanup(){unlink(path.c_str());unlink((path+".analysis").c_str());}} cleanup{project};
    Session session;require(session.openPath(path).ok()&&session.attachProject(project).ok()&&session.analyze().ok(),"Session analyzes ABI fixture");
    Address entry=kNoAddress;for(const auto& symbol:image.symbols())if(symbol.name=="mint_abi_named_pair")entry=symbol.value;
    const auto edited=session.editAnnotation(entry,"prototype","u64(u32 prefix, u64 value)");
    require(edited.ok(),"prototype without explicit ABI accepted in Session: "+edited.toString());
    require(session.prototypeAt(entry).callingConvention==abi&&session.abiText(entry).find("Calling convention: "+abi+";")!=std::string::npos,"Session prototype/ABI view automatically applies container-proven float ABI");
    Session reopened;require(reopened.openPath(path).ok()&&reopened.attachProject(project).ok()&&reopened.prototypeAt(entry).callingConvention==abi,"ELF-derived ABI survives persistent Program reopen");
    const std::string soft=word==4?"riscv32":"riscv64";
    require(session.editAnnotation(entry,"prototype","@"+soft+" u64(u32 prefix, u64 value)").ok()&&session.prototypeAt(entry).callingConvention==soft,"explicit user ABI overrides image default");
    for(u32 flags:{6u,8u}) {
        auto damaged=std::vector<u8>(file.view().data(),file.view().data()+file.size());const size_t position=word==4?36:48;
        for(unsigned n=0;n<4;++n)damaged[position+n]=u8(flags>>(n*8));
        ElfImage unsupported;require(unsupported.load(ByteView(damaged.data(),damaged.size())).ok(),"load ELF with unsupported ABI flags as analysis bytes");
        auto declaration=parsed("u32(u32 value)");declaration.callingConvention=unsupported.defaultCallingConvention();AbiModel rejected;
        require(!buildAbiModel(unsupported.arch(),declaration,&rejected).ok(),"unsupported E/Q ABI flags never become soft-float storage");
    }
}
}
int main(int argc,char** argv){matrix();emission();for(int n=1;n<argc;n+=3){require(n+2<argc&&std::string(argv[n])=="--real","usage: [--real ABI FILE]...");real(argv[n+1],argv[n+2]);}std::cout<<checks<<" RISC-V ABI checks passed\n";}
