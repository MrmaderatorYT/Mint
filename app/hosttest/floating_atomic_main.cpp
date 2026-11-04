#include <algorithm>
#include <cfenv>
#include <cmath>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <vector>

#include "mint/analysis/code_analyzer.h"
#include "mint/decompile/decompiler.h"
#include "mint/interp/executor.h"
#include "mint/ir/lifter.h"
#include "mint/ir/memory_analysis.h"
#include "mint/ir/ir_simplify.h"
#include "mint/ir/registers.h"
#include "mint/ir/storage.h"
#include "mint/ssa/ssa_builder.h"

namespace {
using namespace mint;
int checks=0,failures=0;
bool expect(bool yes,const std::string& name){++checks;if(!yes){++failures;std::cerr<<"FAIL "<<name<<'\n';}return yes;}
u64 raw(double value){u64 bits;std::memcpy(&bits,&value,8);return bits;}
u32 raw(float value){u32 bits;std::memcpy(&bits,&value,4);return bits;}
std::vector<u8> words(std::initializer_list<u32> values){std::vector<u8> out;for(auto value:values)for(unsigned n=0;n<4;++n)out.push_back(u8(value>>(n*8)));return out;}
IrFunction lift(Arch arch,const std::vector<u8>& bytes,const std::string& name,unsigned intrinsics=0){
    ElfImage image;CodeAnalyzer analyzer;Lifter lifter;IrFunction ir;
    if(!expect(image.loadRaw(ByteView(bytes.data(),bytes.size()),arch,0x1000,0x1000).ok(),name+" import"))return ir;
    CodeAnalyzer::Options options;options.linearSweepFallback=false;
    if(!expect(analyzer.analyze(image,options).ok()&&analyzer.functionAt(0x1000),name+" discovery"))return ir;
    if(!expect(lifter.open(arch).ok()&&lifter.liftFunction(*analyzer.functionAt(0x1000),image.memory(),&ir).ok(),name+" lift"))return ir;
    const auto errors=ir.verify();expect(errors.empty(),name+" verified IR");for(const auto& error:errors)std::cerr<<error<<'\n';
    expect(ir.intrinsicCount==intrinsics,name+" honest coverage");return ir;
}
void execute(const IrFunction& ir,InterpState& state,bool ieee=true){if(ir.blocks.empty())return;InterpOptions options;options.assumeDefaultFloatingPoint=ieee;InterpResult result;expect(executeIr(ir,&state,options,&result).ok()&&result.returned,"execute supported IR");}
bool same(const InterpValue& value,u64 low,u64 high=0){return value.concreteLike()&&value.bits==low&&value.highBits==high;}

void scalarFloating(){
    const auto a64=lift(Arch::kAArch64,words({0x1e612800,0xd65f03c0}),"AArch64 fadd d0,d0,d1");
    const auto x64=lift(Arch::kX86_64,{0xf2,0x0f,0x58,0xc1,0xc3},"SSE addsd xmm0,xmm1");
    for(const auto pair:std::vector<std::pair<double,double>>{{1.25,2.5},{-9.75,3.5},{1e30,1},{-0.0,-0.0},{1e-300,-1e-300},{std::numeric_limits<double>::infinity(),1}}){
        volatile double left=pair.first,right=pair.second;const double reference=left+right;
        for(const auto* ir:{&a64,&x64}){
            InterpState state(ir->arch);const u64 base=ir->arch==Arch::kAArch64?arm64::kVn(0):x86::kXmm0;
            state.setRegisterWide(base,raw(pair.first),0xfeedfacefeedface);state.setRegisterWide(base+16,raw(pair.second),0xdeadbeefdeadbeef);
            execute(*ir,state);expect(same(state.registerValue(base,8),raw(reference)),"machine scalar FP matches host IEEE reference");
            if(ir->arch==Arch::kX86_64)expect(state.registerValue(base,16).highBits==0xfeedfacefeedface,"legacy SSE arithmetic preserves upper lanes");
            else expect(state.registerValue(base,16).highBits==0,"AArch64 scalar FP arithmetic clears upper lanes");
        }
    }
    InterpState noAssumption(Arch::kX86_64);noAssumption.setRegisterWide(x86::kXmm0,raw(1.0),2);noAssumption.setRegisterWide(x86::kXmm0+16,raw(2.0),3);
    execute(x64,noAssumption,false);expect(noAssumption.registerValue(x86::kXmm0,8).isUnknown(),"unknown target MXCSR does not invent FP result");
    InterpState nan(Arch::kX86_64);nan.setRegisterWide(x86::kXmm0,0x7ff8000000001234ull,2);nan.setRegisterWide(x86::kXmm0+16,raw(2.0),3);execute(x64,nan);
    expect(nan.registerValue(x86::kXmm0,8).isUnknown(),"NaN arithmetic payload remains unknown");
    const int oldRound=std::fegetround();std::fesetround(FE_DOWNWARD);
    InterpState nonNearest(Arch::kX86_64);nonNearest.setRegisterWide(x86::kXmm0,raw(1.0),2);nonNearest.setRegisterWide(x86::kXmm0+16,raw(2.0),3);execute(x64,nonNearest);
    expect(nonNearest.registerValue(x86::kXmm0,8).isUnknown(),"non-nearest host rounding cannot satisfy IEEE assumption");std::fesetround(oldRound);
    const auto convert=lift(Arch::kAArch64,words({0x1e624000,0xd65f03c0}),"AArch64 fcvt s0,d0");
    InterpState cast(Arch::kAArch64);cast.setRegisterWide(arm64::kVn(0),raw(1.75),0);execute(convert,cast);expect(same(cast.registerValue(arm64::kVn(0),4),raw(1.75f)),"FCVT numerically converts instead of bit truncation");
    for(bool unsignedInput:{false,true}){
        const auto intConvert=lift(Arch::kAArch64,words({unsignedInput?0x9e230000u:0x9e220000u,0xd65f03c0}),"AArch64 signed/unsigned integer-to-float");
        InterpState state(Arch::kAArch64);state.setRegister(arm64::kXn(0),~u64{0},8);execute(intConvert,state);
        expect(same(state.registerValue(arm64::kVn(0),4),unsignedInput?raw(static_cast<float>(~u64{0})):raw(-1.0f)),"integer conversion preserves source signedness and 64-bit width");
    }
    const auto trunc=lift(Arch::kAArch64,words({0x9e780000,0xd65f03c0}),"AArch64 fcvtzs x0,d0");
    for(double number:{-3.75,3.75,std::numeric_limits<double>::infinity(),std::numeric_limits<double>::quiet_NaN(),std::ldexp(1.0,63)}){
        InterpState state(Arch::kAArch64);state.setRegisterWide(arm64::kVn(0),raw(number),0);execute(trunc,state);
        const auto value=state.registerValue(arm64::kXn(0),8);
        expect(std::isfinite(number)&&std::fabs(number)<std::ldexp(1.0,63)?same(value,static_cast<u64>(static_cast<i64>(std::trunc(number)))):value.isUnknown(),"FP-to-integer truncation range/NaN is conservative");
    }
    lift(Arch::kAArch64,words({0x9e640000,0xd65f03c0}),"unsupported FCVTAS rounding is explicit intrinsic",1);
    const auto movss=lift(Arch::kX86_64,{0xf3,0x0f,0x10,0x07,0xc3},"SSE MOVSS memory zeroes high lanes");
    InterpState move(Arch::kX86_64);move.setRegister(x86::kRdi,0x3000,8);move.setRegisterWide(x86::kXmm0,~u64{0},~u64{0});move.memory().write(0x3000,InterpValue::concrete(raw(2.0f),4),4);execute(movss,move);
    expect(same(move.registerValue(x86::kXmm0,16),raw(2.0f),0),"MOVSS memory zeros bits127:32");
    lift(Arch::kX86_64,{0xa5,0xc3},"string MOVSD never confused with SSE MOVSD",1);
}

void simd(){
    const auto a64=lift(Arch::kAArch64,words({0x4ea18400,0xd65f03c0}),"AArch64 add v0.4s,v0.4s,v1.4s");
    const auto x64=lift(Arch::kX86_64,{0x66,0x0f,0xfe,0xc1,0xc3},"SSE paddd xmm0,xmm1");
    const u32 left[4]={0xffffffffu,0x7fffffffu,7,99},right[4]={1,2,23,0xfffffff0u};
    const u64 low=u64(left[0])|(u64(left[1])<<32),high=u64(left[2])|(u64(left[3])<<32);
    const u64 otherLow=u64(right[0])|(u64(right[1])<<32),otherHigh=u64(right[2])|(u64(right[3])<<32);
    const u64 expectedLow=u64(u32(left[0]+right[0]))|(u64(u32(left[1]+right[1]))<<32),expectedHigh=u64(u32(left[2]+right[2]))|(u64(u32(left[3]+right[3]))<<32);
    for(const auto* ir:{&a64,&x64}){InterpState state(ir->arch);const auto base=ir->arch==Arch::kAArch64?arm64::kVn(0):x86::kXmm0;state.setRegisterWide(base,low,high);state.setRegisterWide(base+16,otherLow,otherHigh);execute(*ir,state);expect(same(state.registerValue(base,16),expectedLow,expectedHigh),"128-bit lane arithmetic has no inter-lane carry and preserves high half");}
    InterpMemory memory;memory.write(0x3000,InterpValue::wide(low,high,16),16);expect(same(memory.read(0x3000,16),low,high),"128-bit memory round trip");
    memory.write(0x3000,InterpValue::unknown(16),16);expect(memory.read(0x3000,16).isUnknown(),"unknown write invalidates previous concrete memory");
    lift(Arch::kAArch64,words({0x4e21d400,0xd65f03c0}),"vector FP never disguised as integer lane arithmetic",1);
    lift(Arch::kAArch64,words({0x0ea18400,0xd65f03c0}),"64-bit vector arithmetic cannot masquerade as 128-bit lanes",1);
    for(const auto opcode:{0x4e040c00u,0x4e140420u,0x4f002420u}) {
        const auto dup=lift(Arch::kAArch64,words({opcode,0xd65f03c0}),"AArch64 explicit lane splat");InterpState state(Arch::kAArch64);state.setRegister(arm64::kXn(0),0x12345678,8);state.setRegisterWide(arm64::kVn(1),0,0x89abcdef);execute(dup,state);
        const u32 lane=opcode==0x4e040c00u?0x12345678u:opcode==0x4e140420u?0x89abcdefu:0x100;
        const u64 half=u64(lane)|(u64(lane)<<32);expect(same(state.registerValue(arm64::kVn(0),16),half,half),"DUP lane index and shifted MOVI preserve exact lane value");
    }
}

void simplification(){
    for(bool signedCompare:{false,true}) {
        IrFunction ir;ir.arch=Arch::kX86_64;ir.entry=0x1000;IrBuilder builder(&ir);builder.setAddress(0x1000);
        const auto compared=builder.binary(signedCompare?MintOp::kLessS:MintOp::kEqual,Varnode::constant(signedCompare?~u64{0}:0x100,8),Varnode::constant(0,8));builder.assign(Varnode::reg(x86::kRax,8),builder.resize(compared,8,false));builder.emit(MintOp::kReturn,{},Varnode::constant(0x8000,8));ir.blocks.push_back({0,0x1000,0x1004,0,u32(ir.insns.size()),{}, {}});
        expect(simplifyIr(&ir).ok(),"scalar comparison simplification succeeds");InterpState state(Arch::kX86_64);execute(ir,state);
        expect(same(state.registerValue(x86::kRax,8),signedCompare?1:0),"constant comparison uses full operand width and signed interpretation");
    }
    for(bool extend:{false,true}) {
        IrFunction ir;ir.arch=Arch::kX86_64;ir.entry=0x1000;IrBuilder builder(&ir);builder.setAddress(0x1000);
        builder.emit(extend?MintOp::kSignExt:MintOp::kNot,Varnode::reg(x86::kXmm0,16),Varnode::constant(extend?0xffffffffu:0,extend?4:16));builder.emit(MintOp::kReturn,{},Varnode::constant(0x8000,8));ir.blocks.push_back({0,0x1000,0x1004,0,u32(ir.insns.size()),{}, {}});
        expect(ir.verify().empty()&&simplifyIr(&ir).ok()&&ir.insns[0].op==(extend?MintOp::kSignExt:MintOp::kNot),"128-bit result never folded into truncated 64-bit constant payload");
        InterpState state(Arch::kX86_64);execute(ir,state);expect(same(state.registerValue(x86::kXmm0,16),~u64{0},~u64{0}),"128-bit complement/sign extension retain high all-one half after simplify");
    }
}

void riscvAtomics(){
    const std::vector<unsigned> operations={0,1,4,8,12,16,20,24,28};
    for(auto arch:{Arch::kRiscV32,Arch::kRiscV64})for(unsigned size:{4u,8u}) {
        if(arch==Arch::kRiscV32 && size==8)continue;
        const unsigned xlen=arch==Arch::kRiscV32?4:8;
        const u64 mask=size==4?0xffffffffull:~u64{0};
        const u64 signBit=u64{1}<<(size*8-1);
        for(auto operation:operations)for(unsigned ordering=0;ordering<4;++ordering)for(unsigned destination:{0u,5u,6u,7u}) {
            // rd=rs1/rs2 must read both original operands; rd=x0 still writes memory.
            const u32 encoded=(operation<<27)|(ordering<<25)|(6<<20)|(5<<15)|((size==4?2:3)<<12)|(destination<<7)|0x2f;
            const auto ir=lift(arch,words({encoded,0x00008067}),"RISC-V AMO width/order/alias matrix");
            for(const auto pair:std::vector<std::pair<u64,u64>>{{mask,3},{signBit,mask},{signBit-1,signBit},{0,0}}) {
                const u64 left=pair.first,right=pair.second;u64 expected=0;
                switch(operation){
                    case 0:expected=left+right;break;case 1:expected=right;break;
                    case 4:expected=left^right;break;case 8:expected=left|right;break;case 12:expected=left&right;break;
                    case 16:expected=(left^signBit)<(right^signBit)?left:right;break;
                    case 20:expected=(left^signBit)>(right^signBit)?left:right;break;
                    case 24:expected=std::min(left,right);break;case 28:expected=std::max(left,right);break;
                }
                InterpState state(arch);state.setRegister(riscv::kXn(5),0x3000,xlen);state.setRegister(riscv::kXn(6),right,xlen);
                state.memory().write(0x3000,InterpValue::concrete(left,size),size);execute(ir,state);
                expect(same(state.memory().read(0x3000,size),expected&mask),"AMO exact memory result");
                const u64 returned=size==4&&xlen==8&&(left&signBit)?left|0xffffffff00000000ull:left;
                if(destination)expect(same(state.registerValue(riscv::kXn(destination),xlen),returned),"AMO returns sign-extended old memory including aliased destination");
            }
            DecompileResult output;expect(decompileIr(ir,&output).ok()&&output.cSource.find("__atomic_")!=std::string::npos,"AMO side effect survives SSA and C emission even with rd=x0");
        }
    }
    for(auto arch:{Arch::kRiscV32,Arch::kRiscV64}) {
        lift(arch,words({0x0ff0000f,0x00008067}),"RISC-V memory fence");
        lift(arch,words({0x8330000f,0x00008067}),"RISC-V TSO fence");
        lift(arch,words({0x1002a3af,0x00008067}),"RISC-V LR reservation unsupported",1);
        lift(arch,words({0x1862a3af,0x00008067}),"RISC-V SC reservation unsupported",1);
        lift(arch,words({0x0000100f,0x00008067}),"RISC-V instruction fence unsupported",1);
        lift(arch,words({0x00102053,0x00008067}),"RISC-V unsupported explicit rounding stays intrinsic",1);
        lift(arch,words({0x02102053,0x00008067}),"RISC-V D unsupported explicit rounding stays intrinsic",1);
    }
}

void riscvFloatingTransfers(){
    for(auto arch:{Arch::kRiscV32,Arch::kRiscV64})for(unsigned size:{4u,8u}) {
        const unsigned xlen=arch==Arch::kRiscV32?4:8;
        const auto boxed=[&](u64 bits){return size==4 ? (bits&0xffffffffull)|0xffffffff00000000ull : bits;};
        const u64 signBit=u64{1}<<(size*8-1),inf=size==4?0x7f800000ull:0x7ff0000000000000ull;
        const u64 quiet=size==4?0x400000ull:0x8000000000000ull;
        const u64 normal=size==4?0x3f800000ull:0x3ff0000000000000ull;
        const unsigned format=size==4?0:1;
        for(unsigned opcode:{0x43u,0x47u,0x4bu,0x4fu})for(unsigned mode:{0u,7u}) {
            const auto ir=lift(arch,words({(6<<27)|(format<<25)|(4<<20)|(3<<15)|(mode<<12)|(10<<7)|opcode,0x00008067}),"RISC-V fused multiply add/subtract");
            const double delta=std::ldexp(1.0,size==4?-23:-52),a=1+delta,b=1-delta,c=opcode==0x43||opcode==0x4f?-1:1;
            InterpState state(arch);state.setRegister(riscv::kF0+3*8,boxed(size==4?u64(raw(float(a))):raw(a)),8);
            state.setRegister(riscv::kF0+4*8,boxed(size==4?u64(raw(float(b))):raw(b)),8);state.setRegister(riscv::kF0+6*8,boxed(size==4?u64(raw(float(c))):raw(c)),8);
            execute(ir,state);const double x=opcode==0x4b||opcode==0x4f?-a:a,z=opcode==0x47||opcode==0x4f?-c:c;
            const auto expected=boxed(size==4?u64(raw(std::fma(float(x),float(b),float(z)))):raw(std::fma(x,b,z)));
            expect(same(state.registerValue(riscv::kF0+10*8,8),expected),"FMA performs one rounding including cancellation residual");
            expect(std::count_if(ir.insns.begin(),ir.insns.end(),[](const auto& i){return i.op==MintOp::kFloatFma;})==1 &&
                std::none_of(ir.insns.begin(),ir.insns.end(),[](const auto& i){return i.op==MintOp::kFloatMul;}),"FMA remains fused in IR");
            DecompileResult output;expect(decompileIr(ir,&output).ok()&&output.cSource.find("ffma")!=std::string::npos,"fused operation survives SSA and C emission");
        }
        for(unsigned mode:{0u,1u}) {
            const auto ir=lift(arch,words({((0x14+format)<<25)|(4<<20)|(3<<15)|(mode<<12)|(5<<7)|0x53,0x00008067}),"RISC-V FMIN/FMAX");
            const u64 qnan=inf|quiet|123,snan=inf|1;
            for(const auto pair:std::vector<std::pair<u64,u64>>{{0,signBit},{signBit,0},{normal,normal|signBit},{qnan,normal},{normal,snan},{qnan,snan}}) {
                InterpState state(arch);state.setRegister(riscv::kF0+3*8,boxed(pair.first),8);state.setRegister(riscv::kF0+4*8,boxed(pair.second),8);
                execute(ir,state);const bool ln=(pair.first&~signBit)>inf,rn=(pair.second&~signBit)>inf;
                u64 expected=ln?(rn?inf|quiet:pair.second):rn?pair.first:pair.first==normal?(mode?normal:normal|signBit):(mode?0:signBit);
                expect(same(state.registerValue(riscv::kF0+5*8,8),boxed(expected)),"FMIN/FMAX NaN and signed-zero semantics");
            }
        }
        for(unsigned integerFormat=0;integerFormat<(xlen==8?4u:2u);++integerFormat) {
            const auto fromInt=lift(arch,words({((0x68+format)<<25)|(integerFormat<<20)|(5<<15)|(3<<7)|0x53,0x00008067}),"RISC-V integer to FP");
            InterpState state(arch);state.setRegister(riscv::kXn(5),integerFormat<2?0xffffffffull:~u64{0},xlen);execute(fromInt,state);
            const long double value=integerFormat&1?(integerFormat<2?4294967295.0L:18446744073709551615.0L):-1.0L;
            expect(same(state.registerValue(riscv::kF0+3*8,8),boxed(size==4?u64(raw(float(value))):raw(double(value)))),"FCVT signedness and integer width");
            if(size==4 && integerFormat>=2){
                InterpState midpoint(arch);const u64 input=integerFormat==3?(u64{1}<<63)+(u64{1}<<39)+1:(u64{1}<<62)+(u64{1}<<38)+1;
                midpoint.setRegister(riscv::kXn(5),input,8);execute(fromInt,midpoint);
                expect(same(midpoint.registerValue(riscv::kF0+3*8,8),boxed(integerFormat==3?0x5f000001:0x5e800001)),"integer-to-single avoids host double rounding above a midpoint");
            }
            const auto toInt=lift(arch,words({((0x60+format)<<25)|(integerFormat<<20)|(3<<15)|(1<<12)|(5<<7)|0x53,0x00008067}),"RISC-V FP to integer RTZ");
            InterpState trunc(arch);trunc.setRegister(riscv::kF0+3*8,boxed(size==4?u64(raw(1.75f)):raw(1.75)),8);execute(toInt,trunc);
            expect(same(trunc.registerValue(riscv::kXn(5),xlen),1),"FCVT RTZ truncation");
        }
        const auto precision=lift(arch,words({((0x20+format)<<25)|((size==4?1u:0u)<<20)|(3<<15)|(5<<7)|0x53,0x00008067}),"RISC-V FP precision conversion");
        InterpState cast(arch);cast.setRegister(riscv::kF0+3*8,size==4?raw(1.75):0xffffffff00000000ull|raw(1.75f),8);execute(precision,cast);
        expect(same(cast.registerValue(riscv::kF0+5*8,8),boxed(size==4?u64(raw(1.75f)):raw(1.75))),"FCVT.S.D/FCVT.D.S numerical conversion");
        for(unsigned operation:{0u,4u,8u,12u,44u})for(unsigned mode:{0u,7u}){
            const u32 instruction=((operation+format)<<25)|((operation==44?0:4)<<20)|(3<<15)|(mode<<12)|(5<<7)|0x53;
            const auto ir=lift(arch,words({instruction,0x00008067}),"RISC-V FP arithmetic static/dynamic RNE");
            InterpState state(arch);state.setRegister(riscv::kF0+3*8,boxed(size==4?u64(raw(4.0f)):raw(4.0)),8);
            state.setRegister(riscv::kF0+4*8,boxed(size==4?u64(raw(2.0f)):raw(2.0)),8);
            state.setRegister(riscv::kFflags,31,8);execute(ir,state);
            const double answer=operation==0?6:operation==4?2:operation==8?8:2;
            expect(same(state.registerValue(riscv::kF0+5*8,8),boxed(size==4?u64(raw(float(answer))):raw(answer))),"RISC-V FP declared precision numeric result");
            expect(state.registerValue(riscv::kFflags,8).isUnknown(),"FP arithmetic invalidates exception evidence");
            InterpState unsupported(arch);unsupported.setRegister(riscv::kFrm,2,8);
            unsupported.setRegister(riscv::kF0+3*8,boxed(size==4?u64(raw(4.0f)):raw(4.0)),8);
            unsupported.setRegister(riscv::kF0+4*8,boxed(size==4?u64(raw(2.0f)):raw(2.0)),8);execute(ir,unsupported);
            expect(mode==0 ? same(unsupported.registerValue(riscv::kF0+5*8,8),boxed(size==4?u64(raw(float(answer))):raw(answer))) : unsupported.registerValue(riscv::kF0+5*8,8).isUnknown(),"Static rounding overrides frm; unsupported dynamic mode stays unknown");
        }
        for(unsigned operation:{1u,2u,3u,5u,6u,7u})for(unsigned source:{0u,5u})for(unsigned csr:{1u,2u,3u}){
            const auto ir=lift(arch,words({(csr<<20)|(source<<15)|(operation<<12)|(5<<7)|0x73,0x00008067}),"RISC-V floating CSR update aliases");
            InterpState state(arch);state.setRegister(riscv::kFflags,17,8);state.setRegister(riscv::kFrm,2,8);state.setRegister(riscv::kXn(5),7,xlen);
            const u64 old=csr==1?17:csr==2?2:81,input=operation>=5?source:source?7:0;
            const u64 value=(operation&3)==1?input:source==0?old:(operation&3)==2?old|input:old&~input;
            execute(ir,state);expect(same(state.registerValue(riscv::kXn(5),xlen),old),"CSR rd=rs1 returns old state");
            expect(same(state.registerValue(riscv::kFflags,8),csr==2?17:value&31),"CSR flag mask and zero source semantics");
            expect(same(state.registerValue(riscv::kFrm,8),csr==1?2:csr==2?value&7:(value>>5)&7),"CSR rounding mode update");
        }
        const auto classify=lift(arch,words({((0x70+format)<<25)|(3<<15)|(1<<12)|(7<<7)|0x53,0x00008067}),"RISC-V FCLASS");
        const std::vector<u64> categories={inf|signBit,normal|signBit,signBit|1,signBit,0,1,normal,inf,inf|1,inf|quiet|123};
        for(unsigned n=0;n<categories.size();++n){
            InterpState state(arch);state.setRegister(riscv::kF0+3*8,boxed(categories[n]),8);execute(classify,state,false);
            expect(same(state.registerValue(riscv::kXn(7),xlen),u64{1}<<n),"FCLASS exact ten categories without host FP assumptions");
        }
        if(size==4){
            InterpState state(arch);state.setRegister(riscv::kF0+3*8,normal,8);execute(classify,state,false);
            expect(same(state.registerValue(riscv::kXn(7),xlen),1<<9),"FCLASS invalid NaN box becomes canonical qNaN");
        }
        for(unsigned operation=0;operation<3;++operation)for(unsigned destination:{3u,4u,5u}){
            const auto ir=lift(arch,words({((0x10+format)<<25)|(4<<20)|(3<<15)|(operation<<12)|(destination<<7)|0x53,0x00008067}),"RISC-V FSGNJ aliases");
            for(u64 left:{normal,normal|signBit,inf|quiet|123,signBit})for(u64 right:{normal,normal|signBit}){
                InterpState state(arch);state.setRegister(riscv::kF0+3*8,boxed(left),8);state.setRegister(riscv::kF0+4*8,boxed(right),8);
                execute(ir,state,false);const auto sign=(operation==2?left^right:operation==1?right^signBit:right)&signBit;
                expect(same(state.registerValue(riscv::kF0+destination*8,8),boxed((left&~signBit)|sign)),"FSGNJ preserves payload/sign with aliased operands");
            }
        }
        const auto memory=lift(arch,words({(5u<<15)|((size==4?2u:3u)<<12)|(3<<7)|0x07,
            (3u<<20)|(6<<15)|((size==4?2u:3u)<<12)|0x27,0x00008067}),"RISC-V FP load/store");
        for(u64 bits:{u64{0},signBit,inf|1,inf|quiet|321}){
            InterpState state(arch);state.setRegister(riscv::kXn(5),0x3000,xlen);state.setRegister(riscv::kXn(6),0x4000,xlen);
            state.memory().write(0x3000,InterpValue::concrete(bits,size),size);execute(memory,state,false);
            expect(same(state.registerValue(riscv::kF0+3*8,8),boxed(bits)),"FP load boxes single and preserves double");
            expect(same(state.memory().read(0x4000,size),bits),"FP store preserves signaling NaN payload");
        }
        if(size<=xlen){
            const auto moves=lift(arch,words({((0x78+format)<<25)|(5<<15)|(3<<7)|0x53,
                ((0x70+format)<<25)|(3<<15)|(6<<7)|0x53,0x00008067}),"RISC-V FMV round trip");
            InterpState state(arch);const u64 bits=inf|signBit|1;state.setRegister(riscv::kXn(5),bits,xlen);execute(moves,state,false);
            const u64 expected=size==4&&xlen==8 ? bits|0xffffffff00000000ull : bits;
            expect(same(state.registerValue(riscv::kXn(6),xlen),expected),"FMV.X.W sign extends and preserves raw payload");
            expect(same(state.registerValue(riscv::kF0+3*8,8),boxed(bits)),"FMV.W.X boxes single");
        }
        // Compressed register-relative and SP-relative transfers, including RV32 D.
        for(bool sp:{false,true}){
            const unsigned loadFn=size==8?1:3,storeFn=size==8?5:7;
            if(size==4&&xlen==8)continue; // These RV64 encodings are integer LD/SD.
            const u16 load=sp ? (loadFn<<13)|(3<<7)|(1<<12)|(1<<5)|(1<<2)|2 : (loadFn<<13)|(1<<10)|(1<<5)|(1<<2);
            const u16 store=sp ? (storeFn<<13)|(3<<2)|(1<<10)|(1<<7)|2 : (storeFn<<13)|(1<<10)|(1<<5)|(1<<2);
            const u64 loadOffset=sp ? 104 : 72;
            const u64 storeOffset=sp ? (size==8?72:72) : 72;
            std::vector<u8> bytes={u8(load),u8(load>>8),u8(store),u8(store>>8),0x67,0x80,0,0};
            const auto ir=lift(arch,bytes,"RISC-V compressed FP memory");InterpState state(arch);
            state.setRegister(riscv::kXn(sp?2:8),0x3000,xlen);state.memory().write(0x3000+loadOffset,InterpValue::concrete(inf|1,size),size);
            execute(ir,state,false);expect(same(state.memory().read(0x3000+storeOffset,size),inf|1),"compressed FP offset and raw NaN transfer");
        }
    }
}

void a64Lse(){
    for(unsigned size:{1u,2u,4u,8u})for(unsigned operation=1;operation<8;++operation) {
        const u64 mask=size==8?~u64{0}:(u64{1}<<(size*8))-1;
        const u64 signBit=u64{1}<<(size*8-1);
        const unsigned sizeCode=size==1?0:size==2?1:size==4?2:3;
        const u32 encoded=0x38e00022|(sizeCode<<30)|(operation<<12);
        const auto ir=lift(Arch::kAArch64,words({encoded,0xd65f03c0}),"AArch64 LSE bitwise/min/max width matrix");
        for(const auto pair:std::vector<std::pair<u64,u64>>{{mask,3},{signBit,mask},{signBit-1,signBit}}) {
            const auto left=pair.first,right=pair.second;u64 expected=0;
            switch(operation) {
                case 1:expected=left&~right;break;case 2:expected=left^right;break;case 3:expected=left|right;break;
                case 4:expected=(left^signBit)>(right^signBit)?left:right;break;
                case 5:expected=(left^signBit)<(right^signBit)?left:right;break;
                case 6:expected=std::max(left,right);break;case 7:expected=std::min(left,right);break;
            }
            InterpState state(Arch::kAArch64);state.setRegister(arm64::kXn(0),right,8);state.setRegister(arm64::kXn(1),0x3000,8);
            state.memory().write(0x3000,InterpValue::concrete(left,size),size);execute(ir,state);
            expect(same(state.memory().read(0x3000,size),expected&mask)&&same(state.registerValue(arm64::kXn(2),8),left),"LSE exact atomic value and zero-extended old result");
        }
        DecompileResult output;expect(decompileIr(ir,&output).ok()&&output.cSource.find("__atomic_")!=std::string::npos,"LSE bitwise/min/max survives C emission");
    }
}

void atomics(){
    for(const auto item:std::vector<std::pair<u32,MintOp>>{{0xc8dffc20,MintOp::kAtomicLoad},{0xc89ffc20,MintOp::kAtomicStore},{0xf8e00022,MintOp::kAtomicAdd},{0xf8e08022,MintOp::kAtomicExchange},{0xc8e0fc22,MintOp::kAtomicCompareExchange},{0xd5033bbf,MintOp::kMemoryFence}}){
        const auto ir=lift(Arch::kAArch64,words({item.first,0xd65f03c0}),"AArch64 explicit atomic/fence");
        bool found=false;for(const auto& insn:ir.insns)found|=insn.op==item.second;expect(found,"ordering/RMW survives as distinct IR effect");
        const bool replaced=item.second==MintOp::kAtomicStore||item.second==MintOp::kAtomicExchange;
        InterpState state(Arch::kAArch64);state.setRegister(arm64::kXn(0),replaced?7:5,8);state.setRegister(arm64::kXn(1),0x3000,8);state.setRegister(arm64::kXn(2),17,8);state.memory().write(0x3000,InterpValue::concrete(5,8),8);execute(ir,state);
        const auto after=state.memory().read(0x3000,8);
        expect(same(after,replaced?7:item.second==MintOp::kAtomicAdd?10:item.second==MintOp::kAtomicCompareExchange?17:5),"single-thread atomic memory effect");
        if(item.second==MintOp::kAtomicAdd||item.second==MintOp::kAtomicExchange)expect(same(state.registerValue(arm64::kXn(2),8),5),"LSE RMW returns previous memory in destination");
        if(item.second==MintOp::kAtomicLoad)expect(same(state.registerValue(arm64::kXn(0),8),5),"LDAR loads observed memory");
        DecompileResult result;expect(decompileIr(ir,&result).ok()&&result.cSource.find("__atomic_")!=std::string::npos,"atomic/fence remains explicit in decompiled source");
    }
    const auto cas=lift(Arch::kAArch64,words({0xc8e0fc22,0xd65f03c0}),"AArch64 CAS failure");
    InterpState state(Arch::kAArch64);state.setRegister(arm64::kXn(0),4,8);state.setRegister(arm64::kXn(1),0x3000,8);state.setRegister(arm64::kXn(2),17,8);state.memory().write(0x3000,InterpValue::concrete(5,8),8);execute(cas,state);
    expect(same(state.memory().read(0x3000,8),5)&&same(state.registerValue(arm64::kXn(0),8),5),"CAS failure returns old value without writing replacement");
    lift(Arch::kAArch64,words({0xc85f7c20,0xd65f03c0}),"exclusive monitor requires explicit unsupported intrinsic",1);
    const auto xadd=lift(Arch::kX86_64,{0xf0,0x48,0x0f,0xc1,0x07,0xc3},"LOCK XADD [rdi],rax");
    InterpState xstate(Arch::kX86_64);xstate.setRegister(x86::kRdi,0x3000,8);xstate.setRegister(x86::kRax,7,8);xstate.memory().write(0x3000,InterpValue::concrete(9,8),8);execute(xadd,xstate);
    expect(same(xstate.memory().read(0x3000,8),16)&&same(xstate.registerValue(x86::kRax,8),9),"LOCK XADD returns old memory and writes atomic sum");
    const auto cmp=lift(Arch::kX86_64,{0xf0,0x48,0x0f,0xb1,0x0f,0xc3},"LOCK CMPXCHG [rdi],rcx");
    for(bool success:{false,true}){InterpState x(Arch::kX86_64);x.setRegister(x86::kRdi,0x3000,8);x.setRegister(x86::kRax,success?9:8,8);x.setRegister(x86::kRcx,21,8);x.memory().write(0x3000,InterpValue::concrete(9,8),8);execute(cmp,x);expect(same(x.memory().read(0x3000,8),success?21:9)&&same(x.registerValue(x86::kRax,8),9)&&same(x.registerValue(x86::kFlagZf,1),success),"LOCK CMPXCHG success/failure updates accumulator and ZF");}
    lift(Arch::kX86_64,{0xf0,0x48,0x83,0x17,0x01,0xc3},"unsupported LOCK ADC is not nonatomic fake semantics",1);
    const auto fence=lift(Arch::kX86_64,{0x0f,0xae,0xf0,0xc3},"SSE MFENCE");
    DecompileResult output;expect(decompileIr(fence,&output).ok()&&output.cSource.find("__atomic_thread_fence")!=std::string::npos,"x86 MFENCE not silently dropped");
    // An atomic/fence may synchronize another thread's writes. Reaching-store
    // facts from before it must never become confident post-fence load facts.
    IrFunction rawIr;rawIr.arch=Arch::kAArch64;rawIr.entry=0x1000;IrBuilder builder(&rawIr);builder.setAddress(0x1000);
    const auto address=Varnode::constant(0x3000,8);builder.emit(MintOp::kStore,{},address,Varnode::constant(5,8));builder.emit(MintOp::kMemoryFence,{});const auto loaded=builder.newTemp(8);builder.emit(MintOp::kLoad,loaded,address);builder.assign(Varnode::reg(arm64::kXn(0),8),loaded);builder.emit(MintOp::kReturn,{},Varnode::reg(arm64::kXn(30),8));rawIr.blocks.push_back({0,0x1000,0x1004,0,u32(rawIr.insns.size()),{}, {}});
    normalizeRegisterAccesses(&rawIr);SsaFunction ssa;MemoryAnalysis memory;expect(buildSsa(rawIr,&ssa).ok()&&analyzeMemory(ssa,&memory).ok()&&memory.exactDependencies==0&&memory.callBarriers==1,"memory SSA invalidates facts across synchronization barrier");
    auto bad=rawIr;bad.insns[0].op=MintOp::kAtomicStore;bad.insns[0].a.size=4;expect(!bad.verify().empty(),"atomic verifier rejects wrong pointer width");
}

void x86LockedArithmetic(){
    for(auto arch:{Arch::kX86_32,Arch::kX86_64})for(unsigned size:{1u,2u,4u,8u}) {
        if(arch==Arch::kX86_32&&size==8)continue;
        const unsigned pointerWidth=arch==Arch::kX86_32?4:8;
        const u64 mask=size==8?~u64{0}:(u64{1}<<(size*8))-1;
        const u64 signBit=u64{1}<<(size*8-1);
        for(unsigned operation=0;operation<8;++operation) {
            std::vector<u8> bytes{0xf0};if(size==2)bytes.push_back(0x66);if(size==8)bytes.push_back(0x48);
            if(operation<5) {
                bytes.push_back(size==1?0x80:0x83);
                bytes.push_back(operation==0?0x07:operation==1?0x2f:operation==2?0x27:operation==3?0x0f:0x37);
                bytes.push_back(1);
            } else {
                bytes.push_back(operation==7?(size==1?0xf6:0xf7):(size==1?0xfe:0xff));
                bytes.push_back(operation==5?0x07:operation==6?0x0f:0x17);
            }
            bytes.push_back(0xc3);
            const auto ir=lift(arch,bytes,"x86 LOCK arithmetic width matrix");
            for(u64 original:{u64{0},u64{15},mask,signBit-1,signBit}) {
                const u64 expected=(operation==0||operation==5?original+1:
                    operation==1||operation==6?original-1:operation==2?original&1:
                    operation==3?original|1:operation==4?original^1:~original)&mask;
                InterpState state(arch);state.setRegister(x86::kRdi,0x3000,pointerWidth);
                for(auto offset:{x86::kFlagCf,x86::kFlagOf,x86::kFlagAf,x86::kFlagZf,x86::kFlagSf,x86::kFlagPf})state.setRegister(offset,1,1);
                state.memory().write(0x3000,InterpValue::concrete(original,size),size);execute(ir,state);
                expect(same(state.memory().read(0x3000,size),expected),"LOCK arithmetic updates memory atomically");
                if(operation==7) {
                    for(auto offset:{x86::kFlagCf,x86::kFlagOf,x86::kFlagAf,x86::kFlagZf,x86::kFlagSf,x86::kFlagPf})expect(same(state.registerValue(offset,1),1),"LOCK NOT preserves flags");
                } else {
                    expect(same(state.registerValue(x86::kFlagZf,1),expected==0)&&same(state.registerValue(x86::kFlagSf,1),bool(expected&signBit)),"LOCK result updates zero/sign flags");
                    if(operation==5||operation==6)expect(same(state.registerValue(x86::kFlagCf,1),1),"LOCK INC/DEC preserve carry");
                    if(operation==0||operation==1||operation==5||operation==6)expect(same(state.registerValue(x86::kFlagAf,1),((original^1^expected)>>4)&1),"arithmetic auxiliary carry is explicit");
                    else expect(state.registerValue(x86::kFlagAf,1).isUnknown(),"logical auxiliary carry is undefined");
                }
            }
            DecompileResult output;expect(decompileIr(ir,&output).ok()&&output.cSource.find("__atomic_")!=std::string::npos,"LOCK memory effect remains in decompiled source");
        }
    }
}
void unknownMemoryWrites(){
    for(auto operation:{MintOp::kStore,MintOp::kVectorStore,MintOp::kAtomicStore,MintOp::kAtomicAdd,
                       MintOp::kAtomicExchange,MintOp::kAtomicCompareExchange,MintOp::kAtomicAnd,
                       MintOp::kAtomicOr,MintOp::kAtomicXor,MintOp::kAtomicMinS,MintOp::kAtomicMaxU}) {
        IrFunction ir;ir.arch=Arch::kAArch64;ir.entry=0x1000;IrBuilder builder(&ir);builder.setAddress(ir.entry);
        const auto address=Varnode::reg(arm64::kXn(1),8);
        const auto width=operation==MintOp::kVectorStore?16:8;
        const auto value=Varnode::constant(3,width);
        if(isAtomicRmw(operation))builder.emit(operation,builder.newTemp(8),address,value,operation==MintOp::kAtomicCompareExchange?value:Varnode{});
        else builder.emit(operation,{},address,value);
        builder.emit(MintOp::kLoad,Varnode::reg(arm64::kXn(0),8),Varnode::constant(0x3000,8));
        builder.emit(MintOp::kReturn,{},Varnode::reg(arm64::kXn(30),8));ir.blocks.push_back({0,0x1000,0x1004,0,u32(ir.insns.size()),{}, {}});
        expect(ir.verify().empty(),"unknown-address write IR verifies");
        InterpState state(Arch::kAArch64);state.memory().write(0x3000,InterpValue::concrete(7,8),8);execute(ir,state);
        expect(state.registerValue(arm64::kXn(0),8).isUnknown(),"unknown-address write invalidates potentially aliased concrete memory");
    }
}
}
void opaqueCalls(){
    for(auto arch:{Arch::kAArch64,Arch::kX86_64,Arch::kX86_32,Arch::kArm32,Arch::kThumb,Arch::kRiscV32,Arch::kRiscV64}) {
        IrFunction ir;ir.arch=arch;ir.entry=0x1000;IrBuilder builder(&ir);builder.setAddress(ir.entry);
        builder.emit(MintOp::kCall,{},Varnode::constant(0x2000,8));builder.emit(MintOp::kReturn,{},Varnode::constant(0,8));
        IrBlock block;block.id=0;block.start=0x1000;block.end=0x1008;block.insnCount=ir.insns.size();ir.blocks.push_back(block);
        expect(ir.verify().empty(),"opaque call fixture verifies");
        InterpState state(arch);const auto units=abiCallerSavedRegisters(arch);
        for(const auto& unit:units)state.write(unit,InterpValue::wide(1,2,unit.size));
        state.memory().write(0x3000,InterpValue::concrete(123,8),8);
        InterpOptions stop;stop.stopOnCall=true;InterpResult result;
        expect(executeIr(ir,&state,stop,&result).ok()&&result.stoppedOnCall&&!result.returned,"stop-on-call preserves pre-call inspection point");
        expect(state.memory().knownByteCount()==8,"stopping before a call preserves memory evidence");
        execute(ir,state);
        for(const auto& unit:units)expect(state.read(unit).isUnknown(),"opaque callee invalidates ABI clobber evidence");
        expect(state.memory().knownByteCount()==0,"opaque callee invalidates aliased memory evidence");
    }
}
int main(){scalarFloating();simd();simplification();atomics();riscvAtomics();riscvFloatingTransfers();a64Lse();x86LockedArithmetic();unknownMemoryWrites();opaqueCalls();std::cout<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;}
