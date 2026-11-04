#include "mint/analysis/code_analyzer.h"
#include "mint/decompile/decompiler.h"
#include "mint/interp/executor.h"
#include "mint/ir/lifter.h"
#include "mint/ir/registers.h"
#include "mint/ir/storage.h"
#include <algorithm>
#include <cfenv>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <limits>

namespace {
using namespace mint;
#include "fixtures/arm_vfp_encodings.h"
unsigned checks=0;
void require(bool value,const std::string& label){++checks;if(!value){std::cerr<<"ARM VFP: "<<label<<'\n';std::exit(1);}}
u64 bits(double value){u64 result=0;std::memcpy(&result,&value,8);return result;}
u32 bits(float value){u32 result=0;std::memcpy(&result,&value,4);return result;}
u64 number(double value,u8 width){return width==4?bits(static_cast<float>(value)):bits(value);}
const VfpCase& fixture(const std::string& name){const auto found=std::find_if(cases.begin(),cases.end(),[&](const auto& c){return c.name==name;});require(found!=cases.end(),"fixture exists: "+name);return *found;}
std::vector<u8> encoding(const VfpCase& c,Arch arch){return arch==Arch::kThumb?c.thumb:c.arm;}
IrFunction lift(Arch arch,std::vector<u8> bytes,const std::string& label,unsigned expectedIntrinsics=0,u8 resultWidth=0){
    if(resultWidth){auto transfer=encoding(fixture(resultWidth==4?"move_to_r":"move_to_pair"),arch);bytes.insert(bytes.end(),transfer.begin(),transfer.end());}
    const std::vector<u8> ret=arch==Arch::kThumb?std::vector<u8>{0x70,0x47}:std::vector<u8>{0x1e,0xff,0x2f,0xe1};bytes.insert(bytes.end(),ret.begin(),ret.end());
    ElfImage image;require(image.loadRaw(ByteView(bytes.data(),bytes.size()),arch,0x1000,0x1000).ok(),label+" raw import");
    CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;
    require(analyzer.analyze(image,options).ok()&&analyzer.functionAt(0x1000),label+" discovery");
    Lifter lifter;IrFunction ir;require(lifter.open(arch).ok()&&lifter.liftFunction(*analyzer.functionAt(0x1000),image.memory(),&ir).ok(),label+" lift");
    auto problems=ir.verify();require(problems.empty(),label+" valid IR"+(problems.empty()?"":": "+problems.front()));
    require(ir.intrinsicCount==expectedIntrinsics,label+" explicit coverage, expected "+std::to_string(expectedIntrinsics)+", got "+std::to_string(ir.intrinsicCount));return ir;
}
IrFunction lift(Arch arch,const VfpCase& c,u8 resultWidth=0,unsigned intrinsic=0){return lift(arch,encoding(c,arch),c.assembly,intrinsic,resultWidth);}
void execute(const IrFunction& ir,InterpState& state,bool ieee=true,bool skipIntrinsics=false){InterpOptions options;options.assumeDefaultFloatingPoint=ieee;options.executeIntrinsics=skipIntrinsics;InterpResult result;require(executeIr(ir,&state,options,&result).ok()&&result.returned,"bounded interpreter returned");}
bool same(const InterpValue& value,u64 expected){return value.concreteLike()&&value.bits==expected;}
void setup(InterpState& state,u8 width,double old,double left,double right){
    for(unsigned n=0;n<4;++n)state.setRegisterWide(arm32::kV0+n*16,0xfeedfacefeedfaceull,0x123456789abcdef0ull);
    state.setRegister(arm32::kV0,number(old,width),width);state.setRegister(arm32::kV0+width*2,number(left,width),width);state.setRegister(arm32::kV0+width*4,number(right,width),width);
    state.setRegister(arm32::kFpscr,0x40000003,4);
    state.setRegister(arm32::kFlagN,1,1);state.setRegister(arm32::kFlagZ,0,1);state.setRegister(arm32::kFlagC,1,1);state.setRegister(arm32::kFlagV,0,1);
}
void arithmetic(){
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(u8 width:{4,8})for(const std::string operation:{"vadd","vsub","vmul","vdiv","vabs","vneg","vsqrt","vmla","vmls","vfma","vfms","vfnma","vfnms","vnmul"}){
        const auto ir=lift(arch,fixture(operation+std::to_string(width)),width);
        for(const auto values:std::vector<std::vector<double>>{{3,4,2},{-3,4,-2},{0,-0.0,1},{0,1,-1},{-0.0,0.0,0.0}}){
            const double old=values[0],left=values[1],right=values[2];long double answer=0;
            auto reference=[&](auto a,auto b,auto c){using F=decltype(a);volatile F product=b*c;
                if(operation=="vadd")return F(b+c);if(operation=="vsub")return F(b-c);if(operation=="vmul")return F(product);if(operation=="vdiv")return F(b/c);
                if(operation=="vabs")return F(std::fabs(b));if(operation=="vneg")return F(-b);if(operation=="vsqrt")return F(std::sqrt(b));
                if(operation=="vmla")return F(a+product);if(operation=="vmls")return F(a-product);if(operation=="vnmul")return F(-product);
                if(operation=="vfma")return F(std::fma(b,c,a));if(operation=="vfms")return F(std::fma(-b,c,a));
                if(operation=="vfnma")return F(std::fma(-b,c,-a));return F(std::fma(b,c,-a));};
            if(width==4)answer=reference(float(old),float(left),float(right));else answer=reference(old,left,right);
            InterpState state(arch);setup(state,width,old,left,right);const auto neighbor=state.registerValue(arm32::kV0+width,width);execute(ir,state);
            const auto result=state.registerValue(arm32::kV0,width);
            require(std::isnan(answer)?result.isUnknown():same(result,number(static_cast<double>(answer),width)),operation+" declared precision/sign result");
            const auto afterNeighbor=state.registerValue(arm32::kV0+width,width);require(afterNeighbor.concreteLike()&&afterNeighbor.bits==neighbor.bits,"scalar VFP writes preserve adjacent S/D aliases");
            require(same(state.registerValue(arm32::kFlagN,1),1)&&same(state.registerValue(arm32::kFlagZ,1),0)&&same(state.registerValue(arm32::kFlagC,1),1)&&same(state.registerValue(arm32::kFlagV,1),0),"VFP arithmetic preserves APSR flags");
            require(operation=="vabs"||operation=="vneg" ? same(state.registerValue(arm32::kFpscr,4),0x40000003) : state.registerValue(arm32::kFpscr,4).isUnknown(),"numeric operations invalidate unmodeled FPSCR exception evidence");
        }
        DecompileResult text;const auto decompiled=decompileIr(ir,&text);require(decompiled.ok(),operation+" normalizes through SSA/decompiler: "+decompiled.toString());
        IrFunction normalized=ir;const auto stats=normalizeRegisterAccesses(&normalized);
        require(!stats.unnormalized&&normalized.verify().empty(),"aligned S/D subfields fully normalize into whole Q units");
        InterpState normalizedState(arch);setup(normalizedState,width,3,4,2);const auto preserved=normalizedState.registerValue(arm32::kV0+width,width);
        execute(normalized,normalizedState);require(same(normalizedState.registerValue(arm32::kV0+width,width),preserved.bits),"normalized vector insert preserves neighboring scalar lanes");
        if(operation=="vfma"||operation=="vfms"||operation=="vfnma"||operation=="vfnms")require(text.cSource.find("ffma")!=std::string::npos,"fused operation remains explicit in pseudo-C");
        InterpState unknown(arch);setup(unknown,width,1,2,3);execute(ir,unknown,false);
        require(operation=="vabs"||operation=="vneg" ? unknown.registerValue(arm32::kV0,width).concreteLike() : unknown.registerValue(arm32::kV0,width).isUnknown(),"FP assumption required except exact sign-bit operations");
    }
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(u8 width:{4,8}) {
        const double delta=std::ldexp(1.0,width==4?-23:-52);
        for(bool fused:{false,true}){auto ir=lift(arch,fixture(std::string(fused?"vfma":"vmla")+std::to_string(width)),width);InterpState state(arch);setup(state,width,-1,1+delta,1-delta);execute(ir,state);
            const auto expected=fused?number(-delta*delta,width):number(0,width);require(same(state.registerValue(arm32::kV0,width),expected),"fused cancellation differs from two-rounding VMLA");}
    }
}
void conversions(){
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(const auto& c:cases){const std::string name=c.name;if(name.find("vcvt_")!=0)continue;
        const std::string type=name.substr(5);const auto split=type.find('_');const auto destination=type.substr(0,split),source=type.substr(split+1);
        const u8 input=source=="f64"?8:4,output=destination=="f64"?8:4;auto ir=lift(arch,c,output);
        for(double numberValue:{1.75,-1.75,7.0}){
            InterpState state(arch);const u64 inputBits=source[0]=='f'?number(numberValue,input):source[0]=='s'?u32(i32(numberValue)):u32(7);
            state.setRegister(arm32::kV0+16,inputBits,input);state.setRegister(arm32::kFpscr,0,4);execute(ir,state);
            bool known=true;u64 expected=0;if(destination[0]=='f')expected=number(source[0]=='f'?numberValue:source[0]=='s'?double(i32(numberValue)):7.0,output);
            else {known=destination[0]!='u'||numberValue>=0;expected=destination[0]=='u'?u32(numberValue<0?0:numberValue):u32(i32(std::trunc(numberValue)));}
            require(known?same(state.registerValue(arm32::kV0,output),expected):state.registerValue(arm32::kV0,output).isUnknown(),"VCVT precision/signedness/RTZ semantics: "+type);
            require(state.registerValue(arm32::kFpscr,4).isUnknown(),"VCVT exception evidence remains unknown");
        }
    }
}
void transfers(){
    const u64 payload=0xfff0000012345678ull;
    for(auto arch:{Arch::kArm32,Arch::kThumb}) {
        for(u8 width:{4,8}){auto ir=lift(arch,fixture(width==4?"move_s":"move_d"));InterpState state(arch);state.setRegister(arm32::kV0+width*2,width==4?u32(payload):payload,width);state.setRegister(arm32::kFpscr,0x12345678,4);execute(ir,state,false);
            require(same(state.registerValue(arm32::kV0,width),width==4?u32(payload):payload),"VMOV raw register NaN payload");require(same(state.registerValue(arm32::kFpscr,4),0x12345678),"VMOV never alters FPSCR");
            auto constant=lift(arch,fixture(width==4?"imm_s":"imm_d"));InterpState one(arch);execute(constant,one,false);require(same(one.registerValue(arm32::kV0,width),number(1,width)),"VMOV immediate materializes floating bit pattern");}
        auto toPair=encoding(fixture("move_to_pair"),arch),fromPair=encoding(fixture("move_from_pair"),arch);fromPair.insert(fromPair.end(),toPair.begin(),toPair.end());auto roundtrip=lift(arch,fromPair,"VMOV pair roundtrip");
        InterpState state(arch);state.setRegister(arm32::kRn(0),u32(payload),4);state.setRegister(arm32::kRn(1),payload>>32,4);execute(roundtrip,state,false);
        require(same(state.registerValue(arm32::kV0,8),payload)&&same(state.registerValue(arm32::kRn(0),4),u32(payload))&&same(state.registerValue(arm32::kRn(1),4),payload>>32),"VMOV D/core pair preserves low/high words");
        auto from=encoding(fixture("move_from_r"),arch),to=encoding(fixture("move_to_r"),arch);from.insert(from.end(),to.begin(),to.end());auto single=lift(arch,from,"VMOV S/core roundtrip");InterpState raw(arch);raw.setRegister(arm32::kRn(0),0xff812345,4);execute(single,raw,false);require(same(raw.registerValue(arm32::kV0,4),0xff812345)&&same(raw.registerValue(arm32::kRn(0),4),0xff812345),"VMOV S/core preserves signaling NaN bits");
    }
}
void memory(){
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(u8 width:{4,8})for(bool negative:{false,true}) {
        const std::string suffix=std::string(negative?"minus":"plus")+std::to_string(width);const Address address=negative?0x3000-12:0x3000+12;const u64 value=width==4?0xff812345:0xfff0000012345678ull;
        for(bool load:{false,true}){auto ir=lift(arch,fixture(std::string(load?"load_":"store_")+suffix));InterpState state(arch);state.setRegister(arm32::kRn(2),0x3000,4);
            if(load)state.memory().write(address,InterpValue::concrete(value,width),width);else state.setRegister(arm32::kV0,value,width);execute(ir,state,false);
            require(same(load?state.registerValue(arm32::kV0,width):state.memory().read(address,width),value),"VFP memory signed displacement/raw payload");require(same(state.registerValue(arm32::kRn(2),4),0x3000),"VFP single memory preserves base");}
        auto ir=lift(arch,fixture("literal"+std::to_string(width)));InterpState literal(arch);const Address pc=arch==Arch::kThumb?0x1004:0x1008;literal.memory().write(pc+16,InterpValue::concrete(value,width),width);execute(ir,literal,false);require(same(literal.registerValue(arm32::kV0,width),value),"VFP literal uses aligned architecture PC");
    }
    for(auto arch:{Arch::kArm32,Arch::kThumb}){
        auto bytes=encoding(fixture("push_d"),arch),pop=encoding(fixture("pop_d"),arch);bytes.insert(bytes.end(),pop.begin(),pop.end());auto ir=lift(arch,bytes,"VFP push/pop");InterpState state(arch);state.setRegister(arm32::kSp,0x4000,4);state.setRegister(arm32::kV0,0x123456789abcdef0ull,8);state.setRegister(arm32::kV0+8,0xfff0000000001234ull,8);execute(ir,state,false);
        require(same(state.registerValue(arm32::kSp,4),0x4000)&&same(state.registerValue(arm32::kV0+16,8),0x123456789abcdef0ull)&&same(state.registerValue(arm32::kV0+24,8),0xfff0000000001234ull),"VFP push/pop contiguous register order and stack restoration");
        for(const std::string name:{"stm_s","ldm_s","stmdb_d","ldmdb_d"}) {const bool load=name.find("ldm")==0,decrement=name.find("db")!=std::string::npos;const u8 width=name.back()=='s'?4:8;auto multiple=lift(arch,fixture(name));InterpState values(arch);values.setRegister(arm32::kRn(2),0x5000,4);const unsigned count=width==4?4:2;
            for(unsigned n=0;n<count;++n){const u64 value=0x87654321+n;if(load)values.memory().write((decrement?0x4ff0:0x5000)+n*width,InterpValue::concrete(value,width),width);else values.setRegister(arm32::kV0+n*width,value,width);}
            execute(multiple,values,false);require(same(values.registerValue(arm32::kRn(2),4),decrement?0x4ff0:0x5010),"VFP multiple writeback size");
            for(unsigned n=0;n<count;++n)require(same(load?values.registerValue(arm32::kV0+16+n*width,width):values.memory().read((decrement?0x4ff0:0x5000)+n*width,width),0x87654321+n),"VFP multiple ordered content");}
    }
}
void statusAndPredication(){
    for(auto arch:{Arch::kArm32,Arch::kThumb}){
        require(canonicalUnit(arch,arm32::kFpscr,4).offset==arm32::kFpscr&&canonicalUnit(arch,arm32::kFpscr,4).size==4,"FPSCR has non-overlapping canonical storage");
        require(registerName(arch,arm32::kFpscr,4)=="fpscr","FPSCR named register");
        auto read=lift(arch,fixture("status"));InterpState known(arch);known.setRegister(arm32::kFpscr,0xa0001234,4);execute(read,known,false);require(same(known.registerValue(arm32::kRn(0),4),0xa0001234),"VMRS reads exact known FPSCR");
        InterpState unknown(arch);execute(read,unknown,false);require(unknown.registerValue(arm32::kRn(0),4).isUnknown(),"unknown FPSCR stays unknown");
        auto nzcv=lift(arch,fixture("status_nzcv"));for(unsigned flags=0;flags<16;++flags){InterpState state(arch);state.setRegister(arm32::kFpscr,(u64(flags)<<28)|0x1234,4);execute(nzcv,state,false);
            require(same(state.registerValue(arm32::kFlagN,1),(flags>>3)&1)&&same(state.registerValue(arm32::kFlagZ,1),(flags>>2)&1)&&same(state.registerValue(arm32::kFlagC,1),(flags>>1)&1)&&same(state.registerValue(arm32::kFlagV,1),flags&1),"VMRS APSR_NZCV copies only floating status flags");}
        const auto clobbers=abiCallerSavedRegisters(arch);require(std::any_of(clobbers.begin(),clobbers.end(),[](const auto& n){return n==Varnode::reg(arm32::kFpscr,4);}),"opaque calls clobber unproven FPSCR evidence");
        for(const std::string name:{"vcvtr","fixed","neon","compare","status_write"})lift(arch,fixture(name),0,1);
    }
    auto bytes=fixture("vadd4").arm;bytes[3]&=15;auto predicated=lift(Arch::kArm32,bytes,"conditional VADD",0,4);
    for(bool taken:{false,true}){InterpState state(Arch::kArm32);setup(state,4,9,4,2);state.setRegister(arm32::kFlagZ,taken,1);execute(predicated,state);require(same(state.registerValue(arm32::kV0,4),bits(taken?6.0f:9.0f)),"ARM predicated VFP register result");require(taken?state.registerValue(arm32::kFpscr,4).isUnknown():same(state.registerValue(arm32::kFpscr,4),0x40000003),"untaken VFP instruction preserves floating status");}
    auto load=fixture("load_plus4").arm;load[3]&=15;lift(Arch::kArm32,load,"conditional VFP load remains nonspeculative",1);
    auto it=fixture("vadd4").thumb;it.insert(it.begin(),{0x08,0xbf});auto thumb=lift(Arch::kThumb,it,"Thumb IT guarded VADD",0,4);
    require(std::count_if(thumb.insns.begin(),thumb.insns.end(),[](const auto& i){return i.op==MintOp::kSelect;})>=2,"Thumb IT predicate retained on pure VFP writes");
    for(bool taken:{false,true}){InterpState state(Arch::kThumb);setup(state,4,9,4,2);state.setRegister(arm32::kFlagZ,taken,1);execute(thumb,state);require(same(state.registerValue(arm32::kV0,4),bits(taken?6.0f:9.0f)),"Thumb IT VFP result follows APSR predicate");}
}
void bitwiseAndHighAliases(){
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(unsigned width:{8u,16u})for(const std::string op:{"vand","vorr","veor","vbic","vmvn"}) {
        const auto ir=lift(arch,fixture(op+std::to_string(width)));InterpState state(arch);
        const u64 a=0xff00f0f00f0f00ffull,b=0x0ff00ff055aaaa55ull,ah=0x13579bdf2468ace0ull,bh=0x8888888877777777ull;
        state.setRegisterWide(arm32::kV0,0,0x7777777777777777ull);
        if(width==16){state.setRegisterWide(arm32::kV0+width*2,a,ah);state.setRegisterWide(arm32::kV0+width*4,b,bh);}
        else {state.setRegister(arm32::kV0+width*2,a,8);state.setRegister(arm32::kV0+width*4,b,8);}
        state.setRegister(arm32::kFpscr,0x12345678,4);execute(ir,state,false);
        auto answer=[&](u64 left,u64 right){return op=="vand"?left&right:op=="vorr"?left|right:op=="veor"?left^right:op=="vbic"?left&~right:~left;};
        const auto result=state.registerValue(arm32::kV0,width);
        require(result.concreteLike()&&result.bits==answer(a,b)&&(width==8||result.highBits==answer(ah,bh)),"D/Q bitwise operations preserve all 64/128 bits");
        require(same(state.registerValue(arm32::kFpscr,4),0x12345678),"SIMD logical operations preserve FPSCR");
        if(width==8)require(same(state.registerValue(arm32::kV0+8,8),0x7777777777777777ull),"D logical destination preserves adjacent D half");
    }
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(u8 width:{4,8}) {
        auto ir=lift(arch,fixture(width==4?"high_s":"high_d"));IrFunction normalized=ir;const auto stats=normalizeRegisterAccesses(&normalized);
        require(!stats.unnormalized&&normalized.verify().empty(),"highest S/D register alias normalizes");
        InterpState state(arch);
        if(width==4){state.setRegisterWide(arm32::kV0+7*16,u64{0xdeadbeef}|(u64(bits(3.0f))<<32),u64(bits(2.0f))|(u64(bits(9.0f))<<32));}
        else {state.setRegisterWide(arm32::kV0+14*16,0xdeadbeefdeadbeefull,bits(3.0));state.setRegisterWide(arm32::kV0+15*16,bits(2.0),bits(9.0));}
        execute(normalized,state);
        require(same(state.registerValue(arm32::kV0+31*width,width),number(5,width)),"highest S31/D31 receives correct result");
        require(same(state.registerValue(arm32::kV0+30*width,width),number(2,width)),"highest-register write preserves neighboring operand");
    }
}
void scalarNegativeMemory(){
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(const std::string name:{"ldr_neg","str_neg","ldrb_neg","strb_neg","ldrh_neg","strh_neg","ldrsb_neg","ldrsh_neg","ldr_pre","str_pre","ldr_post","str_post","ldr_alias","str_alias"}) {
        const bool load=name.find("ldr")==0,alias=name.find("alias")!=std::string::npos,post=name.find("post")!=std::string::npos,pre=name.find("pre")!=std::string::npos;
        const u8 width=name.find('b')!=std::string::npos?1:name.find('h')!=std::string::npos?2:4;
        const u32 displacement=width*3,base=0x6000,address=post?base:base-displacement;
        const u32 raw=width==1?0x80:width==2?0x8001:0x87654321;
        const bool sign=name=="ldrsb_neg"||name=="ldrsh_neg";
        const u32 expected=load?(sign?(width==1?0xffffff80:0xffff8001):raw):(alias?base:raw);
        auto ir=lift(arch,fixture(name));InterpState state(arch);state.setRegister(arm32::kRn(0),raw,4);state.setRegister(arm32::kRn(2),base,4);state.setRegister(arm32::kFpscr,0x12345678,4);
        if(load)state.memory().write(address,InterpValue::concrete(raw,width),width);
        state.memory().write(base+displacement,InterpValue::concrete(0x12345678,width),width);
        execute(ir,state,false);
        require(same(load?state.registerValue(arm32::kRn(alias?2:0),4):state.memory().read(address,width),expected),"scalar negative address/extension result: "+name);
        const u32 finalBase=alias&&load?expected:pre||post?base-displacement:base;
        require(same(state.registerValue(arm32::kRn(2),4),finalBase),"scalar negative offset alias/writeback: "+name);
        require(same(state.memory().read(base+displacement,width),0x12345678u&(width==1?0xffu:width==2?0xffffu:0xffffffffu)),"opposite positive address remains untouched: "+name);
        require(same(state.registerValue(arm32::kFpscr,4),0x12345678),"integer memory instructions preserve FPSCR");
    }
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(const std::string name:{"ldr_neg","str_neg"}) {
        auto bytes=encoding(fixture(name),arch);if(arch==Arch::kArm32)bytes[3]&=15;else bytes.insert(bytes.begin(),{0x08,0xbf});
        const auto ir=lift(arch,bytes,"predicated negative memory remains nonspeculative",1);
        require(std::none_of(ir.insns.begin(),ir.insns.end(),[](const auto& i){return i.op==MintOp::kLoad||i.op==MintOp::kStore;}),"predicated negative memory emits no speculative side effect");
    }
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(const std::string name:{"ldr_pre","str_pre"}) {
        auto bytes=encoding(fixture(name),arch);const unsigned index=arch==Arch::kArm32?1:3;
        bytes[index]=(bytes[index]&15)|0x20; // Rt = base r2: constrained-unpredictable writeback.
        lift(arch,bytes,"writeback/base-data alias remains unsupported",1);
    }
}
}
int main(){arithmetic();conversions();transfers();memory();statusAndPredication();bitwiseAndHighAliases();scalarNegativeMemory();std::cout<<checks<<" ARM/Thumb VFP checks passed\n";}
