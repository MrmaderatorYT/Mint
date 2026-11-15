#include "mint/decompile/decompiler.h"
#include "mint/decompile/tail_call.h"
#include "mint/ir/dataflow.h"
#include "mint/ir/ir_simplify.h"
#include "mint/ir/registers.h"
#include "mint/interp/executor.h"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace mint;
namespace {
unsigned checks=0;
std::ostringstream generated;
void require(bool value,const std::string& label){++checks;if(!value){std::cerr<<"tail IR: "<<label<<'\n';std::exit(1);}}
struct Fixture {
    IrFunction ir;u32 current=0;
    Fixture(const std::string& name,u32 blocks=1){ir.arch=Arch::kX86_64;ir.entry=0x1000;ir.name=name;ir.blocks.resize(blocks);for(u32 n=0;n<blocks;++n){ir.blocks[n].id=n;ir.blocks[n].start=0x1000+n*0x100;ir.blocks[n].end=0x1100+n*0x100;}}
    Varnode reg(u64 offset)const{return Varnode::reg(offset,8);}
    Varnode imm(u64 value)const{return Varnode::constant(value,8);}
    Varnode temp(u8 width=8){return Varnode::temp(ir.tempCount++,width);}
    void block(u32 n){current=n;ir.blocks[n].firstInsn=ir.insns.size();}
    void op(MintOp op,Varnode dest={},Varnode a={},Varnode b={}){IrInsn insn;insn.op=op;insn.dest=dest;insn.a=a;insn.b=b;insn.address=ir.blocks[current].start+4*ir.blocks[current].insnCount;ir.insns.push_back(insn);++ir.blocks[current].insnCount;}
    void tail(Address target=0x2000){op(MintOp::kTailCall,{},imm(target));}
    IrFunction finish(){for(const auto& block:ir.blocks)for(auto next:block.successors)ir.blocks[next].predecessors.push_back(block.id);require(ir.verify().empty(),"fixture IR verifies");return ir;}
};
PrototypeResolver prototypes(const std::string& caller="uint64_t(uint64_t selector, uint64_t value)",const std::string& callee="uint64_t(uint64_t value)"){
    UserPrototype first,second;require(parseUserPrototype(caller,&first).ok()&&parseUserPrototype(callee,&second).ok(),"fixture prototypes parse");
    return [first,second](Address target){return target==0x1000?first:second;};
}
SymbolNamer names=[](Address target){return target==0x3000?"leaf_zero":"leaf";};
DecompileResult decompile(const IrFunction& ir,const PrototypeResolver& declarations){DecompileResult result;const auto status=decompileIr(ir,&result,names,{},{},declarations);require(status.ok()&&result.ssa.verify().empty(),"tail IR builds valid SSA: "+status.toString());return result;}
u32 tailIndex(const SsaFunction& f){for(u32 n=0;n<f.insns.size();++n)if(f.insns[n].op==MintOp::kTailCall)return n;require(false,"tail instruction exists");return 0;}
void typed(const DecompileResult& result){require(result.cSource.find("return ((uint64_t(*)(uint64_t))leaf)")!=std::string::npos&&result.cSource.find("op_tail_transfer(")==std::string::npos,"proven input and scalar ABI emit typed terminal return");}
void simplified(const DecompileResult& result){auto ssa=result.ssa;const auto inputs=ssa.insns[tailIndex(ssa)].tailInputs;require(simplifySsa(&ssa).ok()&&ssa.verify().empty()&&ssa.insns[tailIndex(ssa)].tailInputs==inputs,"SSA simplification preserves explicit tail input aliases and live uses");DecompileResult out;require(decompileSsa(ssa,&out,names,{},{},prototypes()).ok(),"simplified tail SSA decompiles");typed(out);}
void opaque(const DecompileResult& result){require(result.cSource.find("op_tail_transfer(0x2000);")!=std::string::npos&&result.cSource.find("__builtin_unreachable();")!=std::string::npos,"unproven ABI/input retains original target and terminal helper");}
void forwarding(){
    Fixture f("tail_forward");f.block(0);f.op(MintOp::kCopy,f.reg(x86::kRdi),f.reg(x86::kRsi));f.tail();const auto ir=f.finish();const auto declarations=prototypes();const auto result=decompile(ir,declarations);typed(result);
    const auto& tail=result.ssa.insns[tailIndex(result.ssa)];require(tail.dest==kNoValue&&tail.clobbers.empty()&&result.ssa.returnValues.empty(),"tail transfer invents neither call result defs nor RET value");
    require(tail.tailInputs.size()==1&&result.ssa.values[tail.tailInputs[0]].def==SsaDef::kEntry&&result.ssa.values[tail.tailInputs[0]].storage==f.reg(x86::kRsi),"untouched caller RSI remains the exact forwarded argument");
    SsaDefUse uses;SsaLiveness live;require(buildDefUse(result.ssa,&uses).ok()&&computeLiveness(result.ssa,&live).ok(),"explicit tail arguments participate in dataflow");
    require(std::any_of(uses.uses[tail.tailInputs[0]].begin(),uses.uses[tail.tailInputs[0]].end(),[&](const auto& use){return use.kind==SsaUseKind::kInstruction&&use.index==tailIndex(result.ssa)&&use.operand==3;}),"tail argument has its own real instruction use site");
    generated<<result.cSource<<'\n';
    simplified(result);
    auto runtime=ir;runtime.insns.back().tailInputs={f.reg(x86::kRdi)};InterpState state(Arch::kX86_64);state.setRegister(x86::kRsp,0x8000,8);state.setRegister(x86::kRsi,123,8);state.memory().write(0x8000,InterpValue::concrete(0x7777,8),8);
    InterpResult execution;require(executeIr(runtime,&state,{},&execution).ok()&&execution.stoppedOnCall&&!execution.returned&&execution.stopReason=="tail transfer","interpreter stops at terminal transfer without pretending to return");
    require(state.registerValue(x86::kRsp,8).bits==0x8000&&state.memory().read(0x8000,8).bits==0x7777,"tail execution does not push or pop the return slot");
    require(execution.calls.size()==1&&execution.calls[0].target==0x2000&&execution.calls[0].arguments.size()==1&&execution.calls[0].arguments[0].bits==123,"interpreter retains transfer target and captured physical argument");
    auto noDeclarations=decompile(ir,{});opaque(noDeclarations);
    opaque(decompile(ir,prototypes("uint64_t(uint64_t selector, uint64_t value)","double(double value)")));
    opaque(decompile(ir,prototypes("uint64_t(uint64_t selector, uint64_t value)","uint64_t(uint64_t value, ...)")));
    opaque(decompile(ir,prototypes("uint64_t(uint64_t selector, uint64_t value)","uint64_t(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g)")));
}
void phiBindings(){
    Fixture f("tail_phi",4);f.ir.blocks[0].successors={1,2};f.ir.blocks[1].successors={3};f.ir.blocks[2].successors={3};f.block(0);const auto condition=f.temp(1);f.op(MintOp::kNotEqual,condition,f.reg(x86::kRdi),f.imm(0));f.op(MintOp::kCondBranch,{},condition,f.imm(0x1100));
    f.block(1);f.op(MintOp::kCopy,f.reg(x86::kRdi),f.reg(x86::kRsi));f.op(MintOp::kBranch,{},f.imm(0x1300));
    f.block(2);f.op(MintOp::kCopy,f.reg(x86::kRdi),f.imm(42));f.op(MintOp::kBranch,{},f.imm(0x1300));f.block(3);f.tail();
    const auto result=decompile(f.finish(),prototypes());typed(result);const auto input=result.ssa.insns[tailIndex(result.ssa)].tailInputs[0];
    require(result.ssa.values[input].def==SsaDef::kPhi&&!result.ssa.phis[result.ssa.values[input].defIndex].dead,"tail read retains the real argument phi from both predecessor paths");generated<<result.cSource<<'\n';simplified(result);
    auto forged=result.ssa;auto& tail=forged.insns[tailIndex(forged)];SsaId wrong=kNoValue;
    for(SsaId n=0;n<forged.values.size();++n)if(forged.values[n].def==SsaDef::kEntry&&forged.values[n].storage==f.reg(x86::kRdi))wrong=n;
    require(wrong!=kNoValue,"different declared caller input exists for forgery check");--forged.values[tail.tailInputs[0]].uses;tail.tailInputs[0]=wrong;++forged.values[wrong].uses;require(forged.verify().empty(),"substituted argument remains structurally valid SSA");
    DecompileResult rejected;require(decompileSsa(forged,&rejected,names,{},{},prototypes()).ok(),"direct SSA forgery is inspectable");opaque(rejected);
    auto missing=result.ssa;auto& noInput=missing.insns[tailIndex(missing)];--missing.values[noInput.tailInputs[0]].uses;noInput.tailInputs.clear();require(missing.verify().empty(),"empty argument list remains representable before ABI validation");require(decompileSsa(missing,&rejected,names,{},{},prototypes()).ok(),"direct SSA missing binding is inspectable");opaque(rejected);
}
void spillAndRejections(){
    Fixture f("tail_spill");f.block(0);const auto loaded=f.temp();f.op(MintOp::kSub,f.reg(x86::kRsp),f.reg(x86::kRsp),f.imm(16));f.op(MintOp::kStore,{},f.reg(x86::kRsp),f.reg(x86::kRsi));f.op(MintOp::kLoad,loaded,f.reg(x86::kRsp));f.op(MintOp::kAdd,f.reg(x86::kRsp),f.reg(x86::kRsp),f.imm(16));f.op(MintOp::kCopy,f.reg(x86::kRdi),loaded);f.tail();
    const auto result=decompile(f.finish(),prototypes());typed(result);require(result.cSource.find("mint_stack_")!=std::string::npos,"proof of spilled argument preserves emitted actual stack access");generated<<result.cSource<<'\n';
    MemoryAnalysis memory;require(analyzeMemory(result.ssa,&memory).ok()&&memory.matches(result.ssa),"fresh spill memory evidence binds exact SSA");auto changed=result.ssa;
    const auto store=std::find_if(changed.insns.begin(),changed.insns.end(),[](const auto& insn){return insn.op==MintOp::kStore;});require(store!=changed.insns.end(),"spill store exists");SsaId constant=kNoValue;for(SsaId n=0;n<changed.values.size();++n)if(changed.values[n].def==SsaDef::kConstant&&changed.values[n].storage.size==8)constant=n;
    --changed.values[store->use[1]].uses;store->use[1]=constant;++changed.values[constant].uses;TailCallContract contract;const auto declared=prototypes();require(buildTailCallContract(Arch::kX86_64,ByteOrder::kLittle,declared(0x1000),declared(0x2000),{},&contract).ok(),"spill declaration contract");
    require(!memory.matches(changed)&&!validateTailCallInputs(changed,changed.insns[tailIndex(changed)],contract,&memory),"stale store/reload evidence cannot authorize a tail input");
    Fixture frame("tail_frame");frame.block(0);frame.op(MintOp::kCopy,frame.reg(x86::kRdi),frame.reg(x86::kRsp));frame.tail();opaque(decompile(frame.finish(),prototypes("uint64_t(uint64_t selector)","uint64_t(uint64_t* pointer)")));
    Fixture unknown("tail_undeclared");unknown.block(0);unknown.op(MintOp::kCopy,unknown.reg(x86::kRdi),unknown.reg(x86::kRdx));unknown.tail();opaque(decompile(unknown.finish(),prototypes()));
    Fixture depth("tail_depth");depth.block(0);auto value=depth.reg(x86::kRsi);for(unsigned n=0;n<160;++n){const auto next=depth.temp();depth.op(MintOp::kAdd,next,value,depth.imm(1));value=next;}depth.op(MintOp::kCopy,depth.reg(x86::kRdi),value);depth.tail();opaque(decompile(depth.finish(),prototypes()));
}
void zeroArguments(){Fixture f("tail_zero");f.block(0);f.tail(0x3000);const auto result=decompile(f.finish(),prototypes("uint64_t(void)","uint64_t(void)"));require(result.cSource.find("return ((uint64_t(*)(void))leaf_zero)();")!=std::string::npos,"zero arguments are accepted only with explicit matching declarations");generated<<result.cSource<<'\n';}
}
int main(int argc,char** argv){
    generated<<"#include <stdint.h>\n#include <stdbool.h>\nstatic uint64_t leaf(uint64_t value){return value+7;}\nstatic uint64_t leaf_zero(void){return 42;}\n";
    forwarding();phiBindings();spillAndRejections();zeroArguments();
    generated<<"#ifdef MINT_TAIL_GENERATED_MAIN\nint main(void){return tail_forward(99,11)!=18 || tail_phi(1,11)!=18 || tail_phi(0,11)!=49 || tail_zero()!=42;}\n#endif\n";
    if(argc==3&&std::string(argv[1])=="--emit-c"){std::ofstream output(argv[2]);output<<generated.str();require(output.good(),"write generated tail C fixture");}else require(argc==1,"usage: mint_tail_call_ir_test [--emit-c output.c]");
    std::cout<<checks<<" tail-call IR checks passed\n";
}
