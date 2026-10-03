#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include "mint/analysis/abi_model.h"
#include "mint/analysis/program.h"
#include "mint/decompile/decompiler.h"
#include "mint/ir/memory_analysis.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"
#include "mint/ir/stack_analysis.h"

using namespace mint;
namespace {
size_t checks=0;
void require(bool condition,const char* message){++checks;if(!condition){std::fprintf(stderr,"analysis depth: %s\n",message);std::exit(1);}}
struct Fixture {
    IrFunction ir;IrBuilder b;
    explicit Fixture(Arch arch=Arch::kX86_64):b(&ir){ir.arch=arch;ir.entry=0x1000;ir.name="depth";b.setAddress(0x1000);}
    void emit(MintOp op,Varnode dest={},Varnode a={},Varnode right={}){b.emit(op,dest,a,right);b.setAddress(b.address()+4);}
    Varnode temp(u8 width=8){return b.newTemp(width);}
    SsaFunction finish(){IrBlock block;block.id=0;block.start=0x1000;block.end=b.address();block.insnCount=b.insnCount();ir.blocks.push_back(block);IrFunction normalized=ir;normalizeRegisterAccesses(&normalized);SsaFunction out;require(buildSsa(normalized,&out).ok(),"depth fixture SSA build");require(out.verify().empty(),"depth fixture SSA verify");return out;}
};
SsaFunction memoryFixture(bool otherRoot=false,bool overlap=false,bool barrier=false) {
    Fixture f;const auto first=Varnode::reg(x86::kRdi,8),second=Varnode::reg(x86::kRsi,8);
    const auto alias=f.temp(),offset=f.temp();f.emit(MintOp::kCopy,alias,first);f.emit(MintOp::kAdd,offset,otherRoot?second:alias,Varnode::constant(overlap?4:16,8));
    f.emit(MintOp::kStore,{},first,Varnode::constant(7,8));f.emit(MintOp::kStore,{},offset,Varnode::constant(9,8));
    if(barrier)f.emit(MintOp::kCall,{},Varnode::constant(0x9000,8));
    auto loaded=f.temp();f.emit(MintOp::kLoad,loaded,first);f.emit(MintOp::kCopy,Varnode::reg(x86::kRax,8),loaded);f.emit(MintOp::kReturn,{},Varnode::constant(0x8000,8));return f.finish();
}
void memoryTests() {
    for(unsigned mode=0;mode<4;++mode) {
        const auto function=memoryFixture(mode==1,mode==2,mode==3);MemoryAnalysis memory;require(analyzeMemory(function,&memory).ok(),"general memory analysis succeeds");
        const MemoryAccess* load=nullptr;for(const auto& access:memory.accesses)if(!access.store)load=&access;
        require(load!=nullptr,"load evidence exists");require((load->reachingStore!=kNoValue)==(mode==0),"same root disjoint store preserves dependency; aliases/overlap/call kill it");
        require(memory.toText(function).find("Memory SSA evidence")!=std::string::npos,"memory provenance report");
    }
    Fixture globals;globals.emit(MintOp::kStore,{},Varnode::constant(0x9000,8),Varnode::constant(5,4));globals.emit(MintOp::kStore,{},Varnode::constant(0xa000,8),Varnode::constant(6,4));
    const auto load=globals.temp(4);globals.emit(MintOp::kLoad,load,Varnode::constant(0x9000,8));globals.emit(MintOp::kZeroExt,Varnode::reg(x86::kRax,8),load);globals.emit(MintOp::kReturn,{},Varnode::constant(0x8000,8));
    auto function=globals.finish();MemoryAnalysis memory;require(analyzeMemory(function,&memory).ok()&&memory.exactDependencies==1,"absolute globals have exact non-aliasing memory versions");
    MemoryAddress a{MemoryBaseKind::kAbsolute,kNoValue,0xffffffffu,0,4},b{MemoryBaseKind::kAbsolute,kNoValue,0,0,4};
    require(memoryMayAlias(a,4,b,4),"wrapping absolute access never proves disjointness");
    function.blocks[0].successors={99};require(!analyzeMemory(function,&memory).ok(),"malformed CFG rejected transactionally");
}
void localTests() {
    auto function=memoryFixture();const auto variables=localVariables(function);const LocalVariable* loaded=nullptr;
    for(const auto& variable:variables)if(!variable.stack && function.values[variable.value].def==SsaDef::kInsn && function.insns[function.values[variable.value].defIndex].op==MintOp::kLoad)loaded=&variable;
    require(loaded!=nullptr,"editable load local discovered");DataTypeManager types;
    require(validateLocalVariableEdit(function,*loaded,types,"buffer_word","uint64_t").ok(),"exact-width scalar local type accepted");
    require(!validateLocalVariableEdit(function,*loaded,types,"buffer_word","uint32_t").ok(),"width-changing local edit rejected");
    require(!validateLocalVariableEdit(function,*loaded,types,"buffer_word","double").ok(),"float reinterpretation rejected");
    require(types.define("Real=f64").ok(),"floating alias defined");require(!validateLocalVariableEdit(function,*loaded,types,"buffer_word","Real").ok(),"floating alias cannot hide reinterpretation");
    std::string path="/private/tmp/mint-locals-test-XXXXXX";int fd=mkstemp(path.data());require(fd>=0,"local project temporary");close(fd);unlink(path.c_str());
    Program program;require(program.open(path,"source-depth").ok(),"local persistent project opened");require(program.editLocal(function.entry,loaded->identity,"buffer_word","uint64_t").ok(),"local edit persisted");
    Program reopened;require(reopened.open(path,"source-depth").ok()&&reopened.locals(function.entry).size()==1,"local edit survives reopen");
    DecompileResult result;require(decompileSsa(function,&result,{},{},{},{},[&](const auto& t,auto* out){return types.resolve(t,out);},[&](Address a){return program.locals(a);}).ok(),"decompile with persistent local resolver");
    require(result.cSource.find("uint64_t buffer_word;")!=std::string::npos,"renamed/retyped SSA local emitted as materialized declaration");
    require(result.cSource.find("buffer_word =")!=std::string::npos,"materialized local has defining statement");
    require(program.undo().ok()&&program.locals(function.entry).empty(),"local undo");require(program.redo().ok()&&program.locals(function.entry).size()==1,"local redo");
    function.name="user_rename";require(localVariables(function)[0].identity==variables[0].identity,"symbol rename does not invalidate identities");
    function.insns[0].address+=1;require(!validateLocalVariableEdit(function,*loaded,types,"buffer_word","uint64_t").ok(),"changed analysis invalidates guarded identity");
    require(decompileSsa(function,&result,{},{},{},{},[&](const auto& t,auto* out){return types.resolve(t,out);},[&](Address a){return program.locals(a);}).ok()&&result.cSource.find("not match the current analysis")!=std::string::npos,"stale bindings are explicit and never rebound");
    const auto before=program.locals(0x1000);require(!program.editLocal(0x1000,"ssa:bad","for","u64").ok()&&program.locals(0x1000).size()==before.size(),"invalid local transaction preserves state");
    unlink(path.c_str());
}
UserPrototype parsed(const std::string& text){UserPrototype result;require(parseUserPrototype(text,&result).ok(),"extended prototype parsed");return result;}
void abiTests() {
    DataTypeManager types;require(types.define("Mixed=struct{integer:u64;real:f64}").ok(),"mixed ABI aggregate type");require(types.define("Four=struct{a:f32;b:f32;c:f32;d:f32}").ok(),"HFA type");require(types.define("Large=struct{a:u64;b:u64;c:u64}").ok(),"indirect aggregate type");require(types.define("Wire=packed{tag:u8;payload:u64}").ok(),"unaligned aggregate type");
    const AbiTypeResolver resolver=[&](const auto& t,auto* out){return types.resolve(t,out);};AbiModel model;
    require(buildAbiModel(Arch::kX86_64,parsed("Mixed(Mixed value)"),&model,resolver).ok(),"SysV mixed aggregate ABI");
    require(model.parameters[0].pieces.size()==2&&model.parameters[0].pieces[0].storage.offset==x86::kRdi&&model.parameters[0].pieces[1].floating&&model.parameters[0].pieces[1].storage.offset==x86::kXmmN(0),"SysV INTEGER/SSE eightbytes allocated separately");
    require(model.result.pieces[0].storage.offset==x86::kRax&&model.result.pieces[1].storage.offset==x86::kXmmN(0),"SysV mixed aggregate return storage");
    require(buildAbiModel(Arch::kAArch64,parsed("Four(Four value)"),&model,resolver).ok()&&model.parameters[0].pieces.size()==4&&model.parameters[0].pieces[3].storage.offset==arm64::kVn(3),"AAPCS64 homogeneous float aggregates");
    require(buildAbiModel(Arch::kAArch64,parsed("Large(Large value, uint64_t other)"),&model,resolver).ok()&&model.hiddenResult[0].storage.offset==arm64::kXn(8)&&model.parameters[0].indirect&&model.parameters[1].pieces[0].storage.offset==arm64::kXn(1),"AAPCS64 hidden return x8 and indirect aggregate arguments");
    require(buildAbiModel(Arch::kX86_64,parsed("@windows64 double(uint32_t first, double second, void* third, uint64_t fourth, uint64_t fifth)"),&model,resolver).ok(),"Windows64 mixed scalar signature");
    require(model.parameters[1].pieces[0].storage.offset==x86::kXmmN(1)&&model.parameters[2].pieces[0].storage.offset==x86::kGpr(8)&&model.parameters[4].pieces[0].stackOffset==40&&model.shadowBytes==32,"Windows positional registers and shadow-stack offset");
    require(buildAbiModel(Arch::kX86_64,parsed("@windows64 void(double first, ...)"),&model,resolver).ok()&&model.parameters[0].pieces.size()==2&&model.parameters[0].pieces[1].storage.offset==x86::kRcx,"Windows varargs FP duplicated in GP register");
    require(buildAbiModel(Arch::kX86_64,parsed("uint64_t(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t g)"),&model,resolver).ok()&&model.parameters[6].pieces[0].stackOffset==8,"SysV overflow argument callee stack offset");
    require(buildAbiModel(Arch::kAArch64,parsed("uint64_t(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t g, uint64_t h, uint64_t i)"),&model,resolver).ok()&&model.parameters[8].pieces[0].stackOffset==0,"AAPCS64 stack overflow parameter");
    require(buildAbiModel(Arch::kX86_64,parsed("Wire(Wire value, uint64_t count)"),&model,resolver).ok()&&model.result.indirect&&model.hiddenResult[0].storage.offset==x86::kRdi&&model.parameters[1].pieces[0].storage.offset==x86::kRsi,"unaligned SysV aggregate memory class and hidden argument shift");
    DataTypeManager small(4);const AbiTypeResolver smallResolver=[&](const auto& t,auto* out){return small.resolve(t,out);};
    require(buildAbiModel(Arch::kArm32,parsed("uint64_t(uint32_t first, uint64_t pair)"),&model,smallResolver).ok()&&model.result.pieces.size()==2&&model.parameters[1].pieces.size()==2&&model.parameters[1].pieces[0].storage.offset==arm32::kRn(2),"AAPCS32 even-aligned scalar pair and pair return");
    require(small.define("Triple=struct{a:u32;b:u32;c:u32}").ok(),"AAPCS32 split aggregate layout");
    require(buildAbiModel(Arch::kArm32,parsed("void(uint32_t a, uint32_t b, uint32_t c, Triple split, uint32_t after)"),&model,smallResolver).ok()&&model.parameters[3].pieces.size()==3&&model.parameters[3].pieces[0].storage.offset==arm32::kRn(3)&&model.parameters[3].pieces[1].stackOffset==0&&model.parameters[3].pieces[1].valueOffset==4&&model.parameters[3].pieces[2].stackOffset==4&&model.parameters[4].pieces[0].stackOffset==8,"AAPCS32 first overflow splits exact r3/stack pieces, later argument stays stack");
    require(!buildAbiModel(Arch::kRiscV64,parsed("@riscv64d void(Mixed value)"),&model,resolver).ok(),"RISC-V hard-float mixed aggregate rejects unmodeled flattening");
    require(buildAbiModel(Arch::kX86_32,parsed("void(uint32_t count, double real)"),&model,smallResolver).ok()&&model.parameters[0].pieces[0].stackOffset==4&&model.parameters[1].pieces[0].stackOffset==8,"cdecl32 stack integer/floating arguments");
    require(!buildAbiModel(Arch::kX86_32,parsed("double(void)"),&model,smallResolver).ok(),"unmodeled x87 return rejected honestly");
    require(!buildAbiModel(Arch::kAArch64,parsed("@windows64 uint64_t(void)"),&model,resolver).ok(),"incompatible ABI rejected");
    UserPrototype invalid;require(!parseUserPrototype("uint64_t(...)",&invalid).ok(),"variadic prototype needs named arguments");
    Fixture caller;caller.emit(MintOp::kCall,{},Varnode::constant(0x2000,8));caller.emit(MintOp::kCopy,Varnode::reg(x86::kRbx,8),Varnode::reg(x86::kRax,8));caller.emit(MintOp::kCopy,Varnode::reg(x86::kXmmN(1),16),Varnode::reg(x86::kXmmN(0),16));caller.emit(MintOp::kAdd,Varnode::reg(x86::kRax,8),Varnode::reg(x86::kRbx,8),Varnode::constant(1,8));caller.emit(MintOp::kReturn,{},Varnode::constant(0x8000,8));
    const auto callerSsa=caller.finish();DecompileResult emitted;
    require(decompileSsa(callerSsa,&emitted,[](Address){return "returns_mixed";},{},{},[](Address address){return address==0x2000?parsed("Mixed(void)"):UserPrototype{};},resolver).ok(),"typed aggregate callee emission succeeds");
    require(emitted.cSource.find("Mixed abi_call_result_")!=std::string::npos&&emitted.cSource.find("op_abi_extract(abi_call_result_")!=std::string::npos,"aggregate return call evaluated once then extracted as register pieces");
    const auto callSite=emitted.cSource.find("((Mixed(*)(void))returns_mixed)");
    require(callSite!=std::string::npos&&emitted.cSource.find("((Mixed(*)(void))returns_mixed)",callSite+1)==std::string::npos,"aggregate call executes once even when multiple return registers are live");
    require(small.define("Real=f32").ok(),"soft-float alias layout");
    Fixture soft(Arch::kArm32);soft.emit(MintOp::kXor,Varnode::reg(arm32::kRn(0),4),Varnode::reg(arm32::kRn(0),4),Varnode::constant(1,4));soft.emit(MintOp::kReturn,{},Varnode::reg(arm32::kLr,4));const auto softSsa=soft.finish();
    require(decompileSsa(softSsa,&emitted,{},{},{},[](Address){return parsed("Real(Real real)");},smallResolver).ok()&&emitted.cSource.find("op_abi_fp_bits(real, 4)")!=std::string::npos&&emitted.cSource.find("return op_abi_float_result(")!=std::string::npos,"soft-float GP alias parameter/result use explicit bit reinterpretation, not numeric float cast");
    Fixture softCall(Arch::kArm32);softCall.emit(MintOp::kCopy,Varnode::reg(arm32::kRn(0),4),Varnode::constant(0x3f800000,4));softCall.emit(MintOp::kCall,{},Varnode::constant(0x2000,4));softCall.emit(MintOp::kReturn,{},Varnode::reg(arm32::kLr,4));const auto softCallSsa=softCall.finish();
    require(decompileSsa(softCallSsa,&emitted,[](Address){return "soft_callee";},{},{},[](Address address){return address==0x2000?parsed("Real(Real real)"):UserPrototype{};},smallResolver).ok()&&emitted.cSource.find("op_abi_float_argument(")!=std::string::npos&&emitted.cSource.find("op_abi_result_bits(")!=std::string::npos,"soft-float GP call passes semantic float and encodes raw return bits");
    Fixture hfa(Arch::kAArch64);hfa.emit(MintOp::kStore,{},Varnode::constant(0x9000,8),Varnode::reg(arm64::kVn(0),16));hfa.emit(MintOp::kStore,{},Varnode::constant(0x9010,8),Varnode::reg(arm64::kVn(1),16));hfa.emit(MintOp::kReturn,{},Varnode::reg(arm64::kXn(30),8));const auto hfaSsa=hfa.finish();
    require(decompileSsa(hfaSsa,&emitted,{},{},{},[](Address){return parsed("void(Four value)");},resolver).ok()&&emitted.cSource.find("op_abi_piece(value, 0, 4)")!=std::string::npos&&emitted.cSource.find("op_abi_piece(value, 4, 4)")!=std::string::npos&&emitted.cSource.find("op_abi_fp_bits(value,")==std::string::npos,"HFA entry registers extract distinct aggregate pieces, not scalar FP cast of whole struct");
    Fixture mixedEntry;mixedEntry.emit(MintOp::kStore,{},Varnode::constant(0x9000,8),Varnode::reg(x86::kXmmN(0),16));mixedEntry.emit(MintOp::kReturn,{},Varnode::constant(0x8000,8));const auto mixedSsa=mixedEntry.finish();
    require(decompileSsa(mixedSsa,&emitted,{},{},{},[](Address){return parsed("void(Mixed value)");},resolver).ok()&&emitted.cSource.find("op_abi_piece(value, 8, 8)")!=std::string::npos,"mixed SysV SSE aggregate extracts its nonzero offset piece");
}
}
int main(){memoryTests();localTests();abiTests();std::printf("PASS %zu analysis-depth checks\n",checks);return 0;}
