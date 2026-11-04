#include "mint/analysis/abi_model.h"
#include "mint/analysis/code_analyzer.h"
#include "mint/base/mapped_file.h"
#include "mint/decompile/decompiler.h"
#include "mint/interp/executor.h"
#include "mint/ir/lifter.h"
#include "mint/ir/registers.h"
#include <cstdlib>
#include <iostream>
using namespace mint;
namespace {
unsigned checks=0;
void require(bool value,const std::string& label){++checks;if(!value){std::cerr<<"AAPCS aggregate: "<<label<<'\n';std::exit(1);}}
UserPrototype parsed(const std::string& text,ByteOrder order){UserPrototype p;require(parseUserPrototype(text,&p).ok(),"parse "+text);p.byteOrder=order;return p;}
void define(DataTypeManager& types){for(const auto* declaration:{"B3=packed{a:u8;b:u8;c:u8}","B9=packed{a:u64;b:u8}","P12=struct{a:u32;b:u32;c:u32}","Large=struct{a:u64;b:u64;c:u64}","FloatPair=f32[2]","HFA=struct{values:FloatPair}","UnionH=union{pair:FloatPair;one:f32}","PackedH=packed{a:f32;b:f32}","OneH=struct{value:f32}"})require(types.define(declaration).ok(),declaration);}
void modelTests(){
    DataTypeManager types;define(types);const AbiTypeResolver resolver=[&](const auto& type,auto* out){return types.resolve(type,out);};
    for(auto order:{ByteOrder::kLittle,ByteOrder::kBig})for(const auto* name:{"B3","B9","P12","HFA","UnionH","PackedH","Large"}) {
        AbiModel model;require(buildAbiModel(Arch::kAArch64,parsed(std::string(name)+"("+name+" value)",order),&model,resolver).ok(),"aggregate storage "+std::string(name));
        const auto& argument=model.parameters[0];
        if(std::string(name)=="Large")require(argument.indirect&&model.result.indirect&&model.hiddenResult[0].storage.offset==arm64::kXn(8),"large object uses x8 result and x0 indirect input");
        else for(size_t n=0;n<argument.pieces.size();++n){const auto& p=argument.pieces[n];
            require(p.registerShift==(order==ByteOrder::kBig&&!p.floating?(8-p.width)*8:0),"content position distinguishes composite bytes from narrow scalars");
            require(model.result.pieces[n].registerShift==p.registerShift&&model.result.pieces[n].valueOffset==p.valueOffset,"return and argument pieces agree");}
        if(std::string(name)=="HFA"||std::string(name)=="UnionH"||std::string(name)=="PackedH")require(argument.pieces.size()==2&&argument.pieces[1].floating&&argument.pieces[1].storage.offset==arm64::kVn(1),"array/union/packed HFA gets independent low scalar FP lanes");
    }
    for(const auto* name:{"B3","B9","P12"}) {
        const auto prototype=parsed(std::string("void(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,")+name+" value)",ByteOrder::kBig);
        AbiModel model;require(buildAbiModel(Arch::kAArch64,prototype,&model,resolver).ok()&&model.parameters.back().pieces[0].stackOffset==0,"stack composite retains byte-zero origin instead of scalar right justification");
    }
    IrFunction ir;ir.arch=Arch::kAArch64;ir.byteOrder=ByteOrder::kBig;ir.entry=0x1000;IrBuilder b(&ir);b.setAddress(ir.entry);
    b.emit(MintOp::kStore,{},Varnode::constant(0x9000,8),Varnode::reg(arm64::kXn(0),8));b.emit(MintOp::kReturn,{},Varnode::reg(arm64::kXn(30),8));
    IrBlock block;block.id=0;block.start=ir.entry;block.end=0x1008;block.insnCount=ir.insns.size();ir.blocks.push_back(block);DecompileResult text;
    require(decompileIr(ir,&text,{},{},{},[&](Address){return parsed("B3(B3 value)",ByteOrder::kBig);},resolver).ok(),"BE composite typed emission");
    require(text.cSource.find("op_abi_piece_be(value, 0, 3)")!=std::string::npos&&text.cSource.find("op_abi_register_piece(")!=std::string::npos&&text.cSource.find(", 3, 40)")!=std::string::npos,"typed input preserves BE bytes and unspecified register padding");
    require(text.cSource.find("op_abi_aggregate_result_be_B3(")!=std::string::npos&&text.cSource.find(">> 40")!=std::string::npos,"typed return extracts high content bits before reconstructing BE object");
}
u64 decode(const std::vector<u8>& bytes,size_t offset,u8 count,ByteOrder order){u64 value=0;for(unsigned n=0;n<count;++n)value|=u64(bytes[offset+n])<<((order==ByteOrder::kBig?count-1-n:n)*8);return value;}
void real(const char* path){
    MappedFile file;require(file.open(path).ok(),"map compiler ELF");ElfImage image;require(image.load(file.view()).ok(),"load compiler ELF");const auto order=image.memory().byteOrder();
    DataTypeManager types;define(types);const AbiTypeResolver resolver=[&](const auto& type,auto* out){return types.resolve(type,out);};
    CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;require(analyzer.analyze(image,options).ok(),"discover compiled functions");Lifter lifter;require(lifter.open(Arch::kAArch64).ok(),"open lifter");
    struct Probe {std::string name,declaration;std::vector<std::vector<u8>> arguments;std::vector<u8> expected;};
    const std::vector<u8> three={0x11,0x82,0xfe},nine={1,2,3,4,5,6,7,8,0xf1},twelve={1,2,3,4,5,6,7,8,9,10,11,12},large={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24};
    std::vector<u8> hfa=order==ByteOrder::kBig?std::vector<u8>{0x3f,0x80,0,0,0xff,0x81,0x23,0x45}:std::vector<u8>{0,0,0x80,0x3f,0x45,0x23,0x81,0xff};
    const auto field=std::vector<u8>(hfa.begin()+4,hfa.end());const std::string prefix="u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,";
    std::vector<Probe> probes={{"mint_be_b3","B3(B3 value)",{three},three},{"mint_be_b9","B9(B9 value)",{nine},nine},{"mint_be_p12","P12(P12 value)",{twelve},twelve},{"mint_be_large","Large(Large value)",{large},large},
        {"mint_be_stack_b3","u32("+prefix+"B3 value)",{},order==ByteOrder::kBig?std::vector<u8>{0,0,0,0xfe}:std::vector<u8>{0xfe,0,0,0}},
        {"mint_be_stack_scalar","u32("+prefix+"u8 value)",{},order==ByteOrder::kBig?std::vector<u8>{0,0,0,0xa7}:std::vector<u8>{0xa7,0,0,0}},
        {"mint_be_hfa","u32(HFA value)",{hfa},field},{"mint_be_union","u32(UnionH value)",{hfa},field},{"mint_be_packed_hfa","u32(PackedH value)",{hfa},field},
        {"mint_be_spilled_hfa","u32(f64 a,f64 b,f64 c,f64 d,f64 e,f64 f,f64 g,f64 h,HFA value)",{},field},
        {"mint_be_spilled_one","u32(f64 a,f64 b,f64 c,f64 d,f64 e,f64 f,f64 g,f64 h,OneH value)",{},field}};
    for(unsigned n=0;n<8;++n){probes[4].arguments.push_back(std::vector<u8>(8,n+1));probes[5].arguments.push_back(std::vector<u8>(8,n+1));probes[9].arguments.push_back(std::vector<u8>(8,0));probes[10].arguments.push_back(std::vector<u8>(8,0));}
    probes[4].arguments.push_back(three);probes[5].arguments.push_back({0xa7});probes[9].arguments.push_back(hfa);probes[10].arguments.push_back(field);
    for(const auto& probe:probes){Address entry=kNoAddress;for(const auto& symbol:image.symbols())if(symbol.name==probe.name)entry=symbol.value;
        require(entry!=kNoAddress&&analyzer.functionAt(entry),"discovered "+probe.name);IrFunction ir;require(lifter.liftFunction(*analyzer.functionAt(entry),image.memory(),&ir).ok()&&ir.verify().empty()&&!ir.intrinsicCount,"supported verified IR "+probe.name);
        const auto prototype=parsed(probe.declaration,order);AbiModel model;require(buildAbiModel(Arch::kAArch64,prototype,&model,resolver).ok(),"compiled probe ABI");InterpState state(Arch::kAArch64);state.memory().map(image.memory());state.setRegister(arm64::kSp,0x800000,8);
        // Real callers reserve rounded stack slots. Supply arbitrary concrete
        // padding so a compiler's full-slot LDR can be checked without assuming
        // those bytes belong to the source object or must be zero.
        for(u64 n=0;n<model.stackBytes+16;++n)state.memory().writeByte(0x800000+n,0xa5);
        for(size_t n=0;n<model.parameters.size();++n){const auto& value=model.parameters[n];const auto& raw=probe.arguments[n];require(raw.size()==value.size,"compiled source object extent");Address object=0x900000+n*0x1000;
            if(value.indirect)for(size_t byte=0;byte<raw.size();++byte)state.memory().writeByte(object+byte,raw[byte]);
            for(const auto& p:value.pieces){const auto content=value.indirect?object:decode(raw,p.valueOffset,p.width,order);const auto bits=(content<<p.registerShift)|(p.registerShift?0x55:0);
                if(p.storage.valid()){if(p.storage.size==16)state.setRegisterWide(p.storage.offset,bits,0);else state.setRegister(p.storage.offset,bits,p.storage.size);}
                else state.memory().write(0x800000+p.stackOffset,InterpValue::concrete(content,p.width),p.width);}
        }
        for(const auto& p:model.hiddenResult)state.setRegister(p.storage.offset,0xa00000,8);
        InterpOptions settings;settings.stopOnCall=true;settings.maxSteps=1000;InterpResult result;require(executeIr(ir,&state,settings,&result).ok()&&result.returned,"bounded compiler IR executes "+probe.name);
        std::vector<u8> actual(model.result.size);
        if(model.result.indirect){for(size_t n=0;n<actual.size();++n)require(state.memory().readByte(0xa00000+n,&actual[n]),"indirect return byte");}
        else for(const auto& p:model.result.pieces){const auto value=state.registerValue(p.storage.offset,p.storage.size);require(value.concreteLike(),"return register evidence "+probe.name);const auto bits=value.bits>>p.registerShift;for(unsigned n=0;n<p.width;++n)actual[p.valueOffset+n]=u8(bits>>((order==ByteOrder::kBig?p.width-1-n:n)*8));}
        require(actual==probe.expected,"actual Clang ABI agrees with modeled aggregate layout: "+probe.name);
    }
}
}
int main(int argc,char** argv){modelTests();for(int n=1;n<argc;++n)real(argv[n]);std::cout<<checks<<" AAPCS aggregate checks passed\n";}
