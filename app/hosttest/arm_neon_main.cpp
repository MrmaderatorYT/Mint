#include "mint/analysis/code_analyzer.h"
#include "mint/decompile/decompiler.h"
#include "mint/interp/executor.h"
#include "mint/ir/lifter.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace mint;
namespace {
#include "fixtures/arm_neon_encodings.h"
unsigned checks=0;
void require(bool yes,const std::string& label){++checks;if(!yes){std::cerr<<"ARM NEON: "<<label<<'\n';std::exit(1);}}
using Bytes=std::array<u8,256>;
u64 mask(u8 width){return width==8?~u64{0}:(u64{1}<<(width*8))-1;}
u64 read(const Bytes& bytes,unsigned offset,u8 width){u64 value=0;for(unsigned n=0;n<width;++n)value|=u64(bytes[offset+n])<<(n*8);return value;}
void write(Bytes& bytes,unsigned offset,u8 width,u64 value){for(unsigned n=0;n<width;++n)bytes[offset+n]=u8(value>>(n*8));}
i64 sign(u64 value,u8 width){const auto m=mask(width);value&=m;return value&(u64{1}<<(width*8-1))?static_cast<i64>(value|~m):static_cast<i64>(value);}
u64 shift(u64 value,int count,u8 width,bool signedData){
    const auto m=mask(width);value&=m;const unsigned amount=count<0?unsigned(-count):unsigned(count),bits=width*8;
    if(count>=0)return amount>=bits?0:(value<<amount)&m;
    const bool negative=signedData&&(value&(u64{1}<<(bits-1)));
    if(amount>=bits)return negative?m:0;
    return (value>>amount)|(negative?(m^(m>>amount)):0);
}
Bytes expected(const NeonCase& c,const Bytes& input,u32 core){
    Bytes output=input;const std::string op=c.operation;const auto m=mask(c.lane);
    for(unsigned n=0;n<c.size/c.lane;++n){
        const auto a=read(input,c.left+n*c.lane,c.lane),b=c.right<0?0:read(input,c.right+n*c.lane,c.lane),old=read(input,c.destination+n*c.lane,c.lane);u64 value=0;
        if(op=="vadd")value=a+b;else if(op=="vsub")value=a-b;else if(op=="vmul")value=a*b;else if(op=="vmla")value=old+a*b;else if(op=="vmls")value=old-a*b;
        else if(op=="vmin")value=c.signedData?(sign(a,c.lane)<sign(b,c.lane)?a:b):std::min(a,b);
        else if(op=="vmax")value=c.signedData?(sign(a,c.lane)>sign(b,c.lane)?a:b):std::max(a,b);
        else if(op=="vceq")value=a==b?m:0;
        else if(op=="vcgt")value=(c.signedData?sign(a,c.lane)>sign(b,c.lane):a>b)?m:0;
        else if(op=="vcge")value=(c.signedData?sign(a,c.lane)>=sign(b,c.lane):a>=b)?m:0;
        else if(op=="vclt")value=(c.signedData?sign(a,c.lane)<sign(b,c.lane):a<b)?m:0;
        else if(op=="vcle")value=(c.signedData?sign(a,c.lane)<=sign(b,c.lane):a<=b)?m:0;
        else if(op=="vtst")value=(a&b)?m:0;
        else if(op=="vneg")value=0-a;
        else if(op=="vabs")value=sign(a,c.lane)<0?0-a:a;
        else if(op=="vshl"&&c.extra==-1)value=shift(a,static_cast<i8>(b&255),c.lane,c.signedData);
        else if(op=="vshl")value=shift(a,c.extra,c.lane,false);
        else if(op=="vshr"||op=="vsra"){value=shift(a,-(c.extra?c.extra:c.lane*8),c.lane,c.signedData);if(op=="vsra")value+=old;}
        else if(op=="vdup")value=core;
        else if(op.rfind("vrev",0)==0){const unsigned group=unsigned(std::strtoul(op.c_str()+4,nullptr,10))/8;value=read(input,c.left+(n^(group/c.lane-1))*c.lane,c.lane);}
        else if(op=="vext"){const unsigned index=n+unsigned(c.extra);value=input[(index<c.size?c.left:c.right)+index%c.size];}
        else if(op=="vbsl")value=(old&a)|(~old&b);
        else if(op=="vbit")value=(old&~b)|(a&b);
        else if(op=="vbif")value=(old&b)|(a&~b);
        else require(false,"reference operation exists: "+op);
        write(output,c.destination+n*c.lane,c.lane,value&m);
    }
    return output;
}
IrFunction lift(const NeonCase& c,Arch arch){
    const auto& bytes=arch==Arch::kThumb?c.thumb:c.arm;ElfImage image;
    require(image.loadRaw(ByteView(bytes.data(),bytes.size()),arch,0x1000,0x1000).ok(),c.name+std::string(" raw import"));
    CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;
    require(analyzer.analyze(image,options).ok()&&analyzer.functionAt(0x1000),c.name+std::string(" discovery"));
    Lifter lifter;IrFunction ir;require(lifter.open(arch).ok()&&lifter.liftFunction(*analyzer.functionAt(0x1000),image.memory(),&ir).ok(),c.name+std::string(" lift"));
    auto errors=ir.verify();require(errors.empty(),std::string(c.name)+" IR validation"+(errors.empty()?"":": "+errors.front()));
    require(ir.intrinsicCount==(std::string(c.operation)=="unsupported"?1u:0u),c.name+std::string(" honest coverage"));return ir;
}
void run(const NeonCase& c,const IrFunction& ir,const Bytes& before,const Bytes& after,bool normalized,bool zeroFlag=false){
    InterpState state(ir.arch);for(unsigned offset=0;offset<256;offset+=16)state.setRegisterWide(arm32::kV0+offset,read(before,offset,8),read(before,offset+8,8));
    state.setRegister(arm32::kRn(0),0x89abcdef,4);state.setRegister(arm32::kFpscr,0xa1234567,4);
    state.setRegister(arm32::kFlagN,1,1);state.setRegister(arm32::kFlagZ,zeroFlag,1);state.setRegister(arm32::kFlagC,1,1);state.setRegister(arm32::kFlagV,0,1);
    InterpOptions options;options.maxSteps=10000;InterpResult result;
    require(executeIr(ir,&state,options,&result).ok()&&result.returned,c.name+std::string(normalized?" normalized execution":" raw execution"));
    for(unsigned offset=0;offset<256;offset+=8){const auto value=state.registerValue(arm32::kV0+offset,8);require(value.concreteLike()&&value.bits==read(after,offset,8),std::string(c.name)+" exact vector bits / neighboring aliases at "+std::to_string(offset)+(normalized?" normalized":" raw"));}
    require(state.registerValue(arm32::kFpscr,4).bits==0xa1234567,"integer NEON preserves FPSCR status");
    require(state.registerValue(arm32::kFlagN,1).bits==1&&state.registerValue(arm32::kFlagZ,1).bits==zeroFlag&&state.registerValue(arm32::kFlagC,1).bits==1&&state.registerValue(arm32::kFlagV,1).bits==0,"integer NEON preserves APSR flags");
}
void matrix(){
    for(auto arch:{Arch::kArm32,Arch::kThumb})for(const auto& c:cases){const auto ir=lift(c,arch);if(std::string(c.operation)=="unsupported")continue;
        IrFunction normalized=ir;const auto stats=normalizeRegisterAccesses(&normalized);require(!stats.unnormalized&&normalized.verify().empty(),c.name+std::string(" normalize widths"));
        DecompileResult text;const auto decompiled=decompileIr(ir,&text);require(decompiled.ok(),std::string(c.name)+" SSA/decompiler: "+decompiled.toString());
        const bool variableShift=std::string(c.operation)=="vshl"&&c.extra==-1;
        for(unsigned iteration=0;iteration<(variableShift?16u:7u);++iteration){Bytes input;const auto pattern=iteration%7;
            for(unsigned n=0;n<input.size();++n)input[n]=pattern==0?0:pattern==1?255:pattern==2?u8(n*13+7):pattern==3?u8(n&1?0x80:0x7f):pattern==4?u8(n%8==7?0x80:0):pattern==5?u8(n%3?0xaa:0x55):u8(n*71+91);
            if(std::string(c.operation)=="vshl"&&c.extra==-1){
                const int values[]={0,1,7,8,15,16,31,32,63,64,127,-1,-7,-8,-64,-128};
                for(unsigned n=0;n<c.size/c.lane;++n)write(input,c.right+n*c.lane,c.lane,(0x123456789abcde00ull|u8(values[(n+iteration)%16]))&mask(c.lane));}
            const auto reference=expected(c,input,0x89abcdef);run(c,ir,input,reference,false);run(c,normalized,input,reference,true);
        }
    }
}
void predication(){
    for(const auto& c:cases){if(std::string(c.operation)=="unsupported")continue;
        // IT EQ is assembled by Clang as 08 bf. Its following NEON instruction
        // uses the same encoding and must retain vector lane metadata when the
        // conditional fragment is copied into the containing function.
        auto conditional=c;conditional.thumb.insert(conditional.thumb.begin(),{0x08,0xbf});
        const auto ir=lift(conditional,Arch::kThumb);IrFunction normalized=ir;
        const auto stats=normalizeRegisterAccesses(&normalized);require(!stats.unnormalized&&normalized.verify().empty(),c.name+std::string(" predicated normalization"));
        DecompileResult text;require(decompileIr(ir,&text).ok(),c.name+std::string(" predicated SSA/decompiler"));
        Bytes input;for(unsigned n=0;n<input.size();++n)input[n]=u8(n*19+37);
        const auto reference=expected(c,input,0x89abcdef);
        for(bool taken:{false,true}){run(c,ir,input,taken?reference:input,false,taken);run(c,normalized,input,taken?reference:input,true,taken);}
    }
}
}
int main(){matrix();predication();std::cout<<checks<<" ARM/Thumb NEON checks passed\n";}
