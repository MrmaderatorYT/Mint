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
    lift(Arch::kX86_64,{0xf0,0x48,0x83,0x07,0x01,0xc3},"unsupported LOCK ADD is not nonatomic fake semantics",1);
    const auto fence=lift(Arch::kX86_64,{0x0f,0xae,0xf0,0xc3},"SSE MFENCE");
    DecompileResult output;expect(decompileIr(fence,&output).ok()&&output.cSource.find("__atomic_thread_fence")!=std::string::npos,"x86 MFENCE not silently dropped");
    // An atomic/fence may synchronize another thread's writes. Reaching-store
    // facts from before it must never become confident post-fence load facts.
    IrFunction rawIr;rawIr.arch=Arch::kAArch64;rawIr.entry=0x1000;IrBuilder builder(&rawIr);builder.setAddress(0x1000);
    const auto address=Varnode::constant(0x3000,8);builder.emit(MintOp::kStore,{},address,Varnode::constant(5,8));builder.emit(MintOp::kMemoryFence,{});const auto loaded=builder.newTemp(8);builder.emit(MintOp::kLoad,loaded,address);builder.assign(Varnode::reg(arm64::kXn(0),8),loaded);builder.emit(MintOp::kReturn,{},Varnode::reg(arm64::kXn(30),8));rawIr.blocks.push_back({0,0x1000,0x1004,0,u32(rawIr.insns.size()),{}, {}});
    normalizeRegisterAccesses(&rawIr);SsaFunction ssa;MemoryAnalysis memory;expect(buildSsa(rawIr,&ssa).ok()&&analyzeMemory(ssa,&memory).ok()&&memory.exactDependencies==0&&memory.callBarriers==1,"memory SSA invalidates facts across synchronization barrier");
    auto bad=rawIr;bad.insns[0].op=MintOp::kAtomicStore;bad.insns[0].a.size=4;expect(!bad.verify().empty(),"atomic verifier rejects wrong pointer width");
}
}
int main(){scalarFloating();simd();simplification();atomics();std::cout<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;}
