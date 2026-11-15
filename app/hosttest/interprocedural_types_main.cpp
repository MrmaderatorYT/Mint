#include "mint/ir/interprocedural_types.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"
#include "mint/ssa/ssa_builder.h"
#include "mint/decompile/decompiler.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>

using namespace mint;
namespace {
unsigned checks=0;
void require(bool condition,const std::string& label){++checks;if(!condition){std::cerr<<"interprocedural types: "<<label<<'\n';std::exit(1);}}
struct Fixture {
    IrFunction ir;u32 current=0;
    explicit Fixture(Address entry,u32 count=1){ir.arch=Arch::kAArch64;ir.entry=entry;ir.name="type_call";ir.blocks.resize(count);for(u32 n=0;n<count;++n){ir.blocks[n].id=n;ir.blocks[n].start=entry+0x100*n;ir.blocks[n].end=entry+0x100*(n+1);}}
    Varnode arg(unsigned n)const{return Varnode::reg(arm64::kXn(n),8);}
    Varnode constant(u64 value,u8 size=8)const{return Varnode::constant(value,size);}
    Varnode temp(u8 size=8){return Varnode::temp(ir.tempCount++,size);}
    void block(u32 n){current=n;ir.blocks[n].firstInsn=ir.insns.size();}
    void op(MintOp code,Varnode dest={},Varnode a={},Varnode b={}){IrInsn instruction;instruction.op=code;instruction.dest=dest;instruction.a=a;instruction.b=b;instruction.address=ir.blocks[current].start+4*ir.blocks[current].insnCount;ir.insns.push_back(instruction);++ir.blocks[current].insnCount;}
    Varnode address(Varnode base,i64 offset){const auto value=temp();op(MintOp::kAdd,value,base,constant(static_cast<u64>(offset)));return value;}
    Varnode load(Varnode address,u8 width=8){const auto value=temp(width);op(MintOp::kLoad,value,address);return value;}
    void store(Varnode address,u8 width=8){op(MintOp::kStore,{},address,constant(7,width));}
    void field(unsigned argument,i64 offset,u8 width=8){load(address(arg(argument),offset),width);}
    void call(Address target,bool indirect=false){op(indirect?MintOp::kCallInd:MintOp::kCall,{},constant(target));}
    void bind(unsigned source,i64 offset=0){op(MintOp::kCopy,arg(0),address(arg(source),offset));}
    void branch(u32 next){op(MintOp::kBranch,{},constant(ir.blocks[next].start));}
    void conditional(u32 next){const auto condition=temp(1);op(MintOp::kNotEqual,condition,arg(7),constant(0));op(MintOp::kCondBranch,{},condition,constant(ir.blocks[next].start));}
    void ret(){op(MintOp::kReturn,{},Varnode::reg(arm64::kXn(30),8));}
    SsaFunction finish(){for(const auto& block:ir.blocks)for(auto successor:block.successors)ir.blocks[successor].predecessors.push_back(block.id);require(ir.verify().empty(),"fixture IR verifies");normalizeRegisterAccesses(&ir);SsaFunction ssa;require(buildSsa(ir,&ssa).ok()&&ssa.verify().empty(),"fixture SSA verifies");return ssa;}
};
using Bodies=std::map<Address,std::shared_ptr<SsaFunction>>;
MemoryFunctionResolver resolver(Bodies& bodies){return [&](Address target)->std::shared_ptr<const SsaFunction>{const auto found=bodies.find(target);return found==bodies.end()?nullptr:found->second;};}
SsaId entry(const SsaFunction& function,unsigned argument){const auto storage=Varnode::reg(arm64::kXn(argument),8);for(SsaId id=0;id<function.values.size();++id)if(function.values[id].def==SsaDef::kEntry&&function.values[id].storage==storage)return id;require(false,"fixture entry argument exists");return kNoValue;}
std::shared_ptr<SsaFunction> layout(Address target,const std::vector<std::pair<i64,u8>>& fields){Fixture body(target);body.block(0);for(const auto& field:fields)body.field(0,field.first,field.second);body.ret();return std::make_shared<SsaFunction>(body.finish());}
SsaFunction forwarding(Address target,i64 displacement=0,unsigned argument=2){Fixture caller(0x1000);caller.block(0);caller.bind(argument,displacement);caller.call(target);caller.ret();return caller.finish();}
std::shared_ptr<SsaFunction> recursive(Address target,Address next,const std::vector<std::pair<i64,u8>>& fields,i64 displacement=0){Fixture body(target,3);body.ir.blocks[0].successors={1,2};body.block(0);for(const auto& field:fields)body.field(0,field.first,field.second);body.conditional(1);body.block(1);body.ret();body.block(2);if(displacement)body.bind(0,displacement);body.call(next);body.ret();return std::make_shared<SsaFunction>(body.finish());}
TypeRecovery recover(const SsaFunction& function,Bodies& bodies,const InterproceduralTypeOptions& options={},const MemoryAnalysis* memory=nullptr){TypeRecovery types;const auto status=recoverInterproceduralTypes(function,&types,memory,resolver(bodies),options);require(status.ok(),status.toString());return types;}
const RecoveredStruct* shape(const TypeRecovery& types,SsaId root){const auto found=std::find_if(types.structs.begin(),types.structs.end(),[&](const auto& item){return item.base==root;});return found==types.structs.end()?nullptr:&*found;}
bool fieldsEqual(const TypeRecovery& types,SsaId root,const std::vector<std::pair<u64,u8>>& expected){const auto* found=shape(types,root);if(!found||found->fields.size()!=expected.size())return false;for(size_t n=0;n<expected.size();++n)if(found->fields[n].offset!=expected[n].first||found->fields[n].width!=expected[n].second)return false;return true;}
bool conflict(const TypeRecovery& types,SsaId root){return std::find(types.conflictingLayouts.begin(),types.conflictingLayouts.end(),root)!=types.conflictingLayouts.end();}
void bindingAndOffsets(){
    Bodies bodies;bodies[0x2000]=layout(0x2000,{{0,4},{8,8}});const auto caller=forwarding(0x2000,16);const auto root=entry(caller,2);
    TypeRecovery local;require(recoverTypes(caller,&local).ok()&&local.structs.empty(),"forwarding alone has no local object layout");
    const auto types=recover(caller,bodies);
    require(fieldsEqual(types,root,{{16,4},{24,8}}),"callee field offsets bind to caller object plus its exact displacement");
    require(types.values[root].kind==RecoveredTypeKind::kPointer,"callee address uses provide pointer evidence for the original caller input");
    require(std::any_of(types.callEvidence.begin(),types.callEvidence.end(),[&](const auto& call){return call.target==0x2000&&call.argument==0&&call.base==root&&call.displacement==16&&call.site>=0x1000&&call.site<0x1100;}),"call evidence records target, call site, argument and caller binding");
    const auto* object=shape(types,root);require(object!=nullptr,"inferred object exists for provenance check");
    for(const auto& field:object->fields)require(std::any_of(field.origins.begin(),field.origins.end(),[](const auto& origin){return origin.function==0x2000&&origin.instruction>=0x2000&&origin.instruction<0x2100;}),"exported fields retain the instruction and function that observed them");

    Fixture wrapper(0x3000);wrapper.block(0);wrapper.bind(0,8);wrapper.call(0x2000);wrapper.ret();bodies[0x3000]=std::make_shared<SsaFunction>(wrapper.finish());
    const auto transitive=forwarding(0x3000,16);const auto nested=recover(transitive,bodies);
    require(fieldsEqual(nested,entry(transitive,2),{{24,4},{32,8}}),"pointer displacements compose across a direct-call chain");

    *bodies[0x2000]=*layout(0x2000,{{0,4},{16,8}});const auto changed=recover(caller,bodies);
    require(fieldsEqual(changed,root,{{16,4},{32,8}}),"fresh recovery follows changed callee observations without stale fields");
    require(fieldsEqual(types,root,{{16,4},{24,8}}),"returned hypotheses are independent snapshots");
}
SsaFunction splitCalls(){Fixture caller(0x1000,4);caller.ir.blocks[0].successors={1,2};caller.ir.blocks[1].successors={3};caller.ir.blocks[2].successors={3};caller.block(0);caller.conditional(1);caller.block(1);caller.bind(2);caller.call(0x2000);caller.branch(3);caller.block(2);caller.bind(2);caller.call(0x3000);caller.branch(3);caller.block(3);caller.ret();return caller.finish();}
void conflictingObservations(){
    Bodies bodies;const auto caller=splitCalls();const auto root=entry(caller,2);
    bodies[0x2000]=layout(0x2000,{{0,8},{16,4}});bodies[0x3000]=layout(0x3000,{{8,8},{24,4}});
    require(fieldsEqual(recover(caller,bodies),root,{{0,8},{8,8},{16,4},{24,4}}),"compatible observations through different direct calls accumulate on one input");
    bodies[0x3000]=layout(0x3000,{{0,4},{24,4}});auto types=recover(caller,bodies);
    require(conflict(types,root)&&!shape(types,root),"incompatible widths at the same offset suppress the entire inferred layout");
    bodies[0x3000]=layout(0x3000,{{4,8},{24,4}});types=recover(caller,bodies);
    require(conflict(types,root)&&!shape(types,root),"overlapping fields do not become a fabricated exact structure");
    auto typed=[&](Address target,MintOp operation){Fixture body(target);body.block(0);const auto value=body.temp(4);body.op(operation,value,body.constant(1,4),body.constant(2,4));body.op(MintOp::kStore,{},body.arg(0),value);body.field(0,8,4);body.ret();return std::make_shared<SsaFunction>(body.finish());};
    bodies[0x2000]=typed(0x2000,MintOp::kFloatAdd);bodies[0x3000]=typed(0x3000,MintOp::kDivS);types=recover(caller,bodies);
    require(conflict(types,root)&&!shape(types,root),"equal-width incompatible floating and signed field evidence remains a conflict");
    bodies[0x3000]=layout(0x3000,{{0,4},{8,4}});types=recover(caller,bodies);
    require(!conflict(types,root)&&fieldsEqual(types,root,{{0,4},{8,4}}),"unknown field kind is compatible with a known kind at identical width and offset");
}
void unknownBindings(){
    Bodies bodies;const auto caller=forwarding(0x2000);auto types=recover(caller,bodies);require(types.structs.empty()&&types.callEvidence.empty(),"missing callee body contributes no layout evidence");
    bodies[0x2000]=layout(0x2000,{{0,8},{8,8}});
    Fixture indirect(0x1000);indirect.block(0);indirect.bind(2);indirect.call(0x2000,true);indirect.ret();const auto unresolved=indirect.finish();types=recover(unresolved,bodies);
    require(types.structs.empty()&&types.callEvidence.empty(),"constant-looking indirect call is not silently treated as a direct binding");
    Fixture unknown(0x1000);unknown.block(0);unknown.op(MintOp::kCopy,unknown.arg(0),unknown.load(unknown.constant(0x6000)));unknown.call(0x2000);unknown.ret();types=recover(unknown.finish(),bodies);
    require(types.structs.empty()&&types.callEvidence.empty(),"unproven load-derived call pointer does not establish an object identity");

    Fixture joined(0x1000,4);joined.ir.blocks[0].successors={1,2};joined.ir.blocks[1].successors={3};joined.ir.blocks[2].successors={3};joined.block(0);joined.conditional(1);joined.block(1);joined.bind(2);joined.branch(3);joined.block(2);joined.bind(3);joined.branch(3);joined.block(3);joined.call(0x2000);joined.ret();const auto phi=joined.finish();types=recover(phi,bodies);
    require(!shape(types,entry(phi,2))&&!shape(types,entry(phi,3))&&types.callEvidence.empty(),"disagreeing call-input phi cannot merge unrelated caller objects");

    auto foreign=layout(0x2000,{{0,8},{8,8}});foreign->byteOrder=ByteOrder::kBig;bodies[0x2000]=foreign;types=recover(caller,bodies);
    require(types.structs.empty()&&types.callEvidence.empty(),"callee byte order must match the caller snapshot");

    Fixture stale(0x2000);stale.block(0);const auto saved=Varnode::reg(arm64::kXn(19),8);stale.op(MintOp::kCopy,saved,stale.arg(0));stale.call(0x5555);stale.load(saved);stale.load(stale.address(saved,8));stale.ret();bodies[0x2000]=std::make_shared<SsaFunction>(stale.finish());
    TypeRecovery local;require(recoverTypes(*bodies[0x2000],&local).ok()&&!local.structs.empty(),"local post-call saved-register layout remains only an unproven local hypothesis");
    types=recover(caller,bodies);
    require(types.structs.empty()&&types.callEvidence.empty(),"unknown earlier call prevents exporting stale saved-register entry-pointer observations");

    Fixture native(0x1000);native.ir.arch=Arch::kRiscV64;native.block(0);const auto nativeArgument=Varnode::reg(riscv::kXn(10),8);native.load(nativeArgument);native.load(native.address(nativeArgument,8));native.call(0x2000);native.op(MintOp::kReturn,{},Varnode::reg(riscv::kXn(1),8));const auto nativeSsa=native.finish();
    SsaId nativeRoot=kNoValue;for(SsaId id=0;id<nativeSsa.values.size();++id)if(nativeSsa.values[id].def==SsaDef::kEntry&&nativeSsa.values[id].storage==nativeArgument)nativeRoot=id;
    require(nativeRoot!=kNoValue,"non-AArch64 fixture has its native argument register");
    types=recover(nativeSsa,bodies);
    require(fieldsEqual(types,nativeRoot,{{0,8},{8,8}})&&types.callEvidence.empty()&&!types.interproceduralLimited,"unsupported root architecture retains ordinary local recovery without cross-call claims");
}
void recursiveEvidence(){
    Bodies bodies;const auto caller=forwarding(0x2000);const auto root=entry(caller,2);
    bodies[0x2000]=recursive(0x2000,0x2000,{{0,8},{8,4}});auto types=recover(caller,bodies);
    require(fieldsEqual(types,root,{{0,8},{8,4}})&&!types.interproceduralLimited,"stable recursive field observations converge and deduplicate");
    bodies[0x2000]=recursive(0x2000,0x3000,{{0,8}});bodies[0x3000]=recursive(0x3000,0x2000,{{8,4}});types=recover(caller,bodies);
    require(fieldsEqual(types,root,{{0,8},{8,4}})&&!types.interproceduralLimited,"mutual recursion unions single-field observations into a bounded hypothesis");
    const auto* object=shape(types,root);require(object&&object->fields.size()==2,"mutual layout available for origin check");
    require(std::any_of(object->fields[0].origins.begin(),object->fields[0].origins.end(),[](const auto& origin){return origin.function==0x2000;})&&std::any_of(object->fields[1].origins.begin(),object->fields[1].origins.end(),[](const auto& origin){return origin.function==0x3000;}),"recursive fields retain provenance from both SCC members");
    bodies[0x2000]=recursive(0x2000,0x2000,{{0,8},{8,8}},16);types=recover(caller,bodies);
    require(types.interproceduralLimited&&!shape(types,root),"unbounded recursive field growth exports no partial fixed point");
}
void limitsRetainLocalFacts(){
    Bodies bodies;bodies[0x2000]=layout(0x2000,{{0,8},{8,8}});
    Fixture caller(0x1000);caller.block(0);caller.field(3,0,4);caller.field(3,8,4);caller.bind(2);caller.call(0x2000);caller.ret();const auto ssa=caller.finish();
    const auto imported=entry(ssa,2),local=entry(ssa,3);
    for(unsigned budget=0;budget<3;++budget){InterproceduralTypeOptions options;if(budget==0)options.maxFields=1;else if(budget==1)options.maxWork=1;else options.maxFunctions=1;
        if(budget==2){Fixture wrapper(0x3000);wrapper.block(0);wrapper.bind(0);wrapper.call(0x2000);wrapper.ret();bodies[0x3000]=std::make_shared<SsaFunction>(wrapper.finish());bodies[0x2000]=recursive(0x2000,0x3000,{{0,8},{8,8}});}
        const auto types=recover(ssa,bodies,options);
        require(types.interproceduralLimited&&!shape(types,imported),"exhausted interprocedural budget exports no incomplete callee layout");
        require(fieldsEqual(types,local,{{0,4},{8,4}}),"bounded interprocedural failure retains independent local field observations");
    }
    bodies[0x2000]=recursive(0x2000,0x2000,{{0,8},{8,8}},16);InterproceduralTypeOptions rounds;rounds.maxIterations=1;const auto types=recover(ssa,bodies,rounds);
    require(types.interproceduralLimited&&!shape(types,imported)&&fieldsEqual(types,local,{{0,4},{8,4}}),"iteration exhaustion retains local facts without exporting a recursive approximation");
    bodies[0x2000]=layout(0x2000,{{0,8},{8,8}});Fixture wrapper(0x3000);wrapper.block(0);wrapper.bind(0);wrapper.call(0x2000);wrapper.ret();bodies[0x3000]=std::make_shared<SsaFunction>(wrapper.finish());
    const auto chain=forwarding(0x3000);InterproceduralTypeOptions depth;depth.maxDepth=1;const auto bounded=recover(chain,bodies,depth);
    require(bounded.interproceduralLimited&&!shape(bounded,entry(chain,2)),"depth-truncated call chain cannot export a partial callee layout");

    bodies.clear();
    // The backedge closing this SCC lies beyond the default depth bound. A
    // truncated prefix must not look like a complete acyclic source of fields.
    for(unsigned n=0;n<18;++n){const Address target=0x2000+n*0x1000,next=n+1<18?target+0x1000:0x2000;bodies[target]=recursive(target,next,n==0?std::vector<std::pair<i64,u8>>{{0,8},{8,8}}:std::vector<std::pair<i64,u8>>{});}
    const auto hiddenCycle=recover(ssa,bodies);
    require(hiddenCycle.interproceduralLimited&&!shape(hiddenCycle,imported)&&hiddenCycle.callEvidence.empty(),"depth-cutoff hidden cycle exports neither layout fields nor provisional call bindings");
    require(fieldsEqual(hiddenCycle,local,{{0,4},{8,4}}),"hidden-cycle cutoff preserves the caller's independent local layout");
}
void authoritativeAndAliasContracts(){
    Bodies bodies;bodies[0x2000]=layout(0x2000,{{16,8},{24,8}});
    Fixture scalar(0x1000);scalar.block(0);scalar.bind(0);scalar.call(0x2000);scalar.ret();const auto ssa=scalar.finish();UserPrototype declared;
    require(parseUserPrototype("uint64_t(uint64_t scalar)",&declared).ok(),"authoritative scalar declaration parses");
    InterproceduralTypeOptions options;options.prototypes=[&](Address address){return address==0x1000?declared:UserPrototype{};};const auto types=recover(ssa,bodies,options);
    require(!shape(types,entry(ssa,0))&&types.callEvidence.empty(),"authoritative scalar parameter blocks a conflicting inferred pointer layout");
    require(declared.parameters.size()==1&&declared.parameters[0].type=="uint64_t"&&declared.parameters[0].name=="scalar","inference leaves authoritative declaration contents unchanged");

    DataTypeManager calleeLayouts;require(calleeLayouts.define("Pair=struct{first:u64;second:u64}").ok(),"callee aggregate declaration fixture");
    InterproceduralTypeOptions calleeOptions;UserPrototype calleeDeclaration;calleeOptions.prototypes=[&](Address address){return address==0x2000?calleeDeclaration:UserPrototype{};};calleeOptions.typeLayouts=[&](const std::string& expression,DataTypeLayout* out){return calleeLayouts.resolve(expression,out);};
    const auto forwarded=forwarding(0x2000);
    for(const auto* text:{"uint64_t(uint64_t scalar)","uint64_t(f64 real)","uint64_t(Pair value)","uint64_t(void* object, ...)"}){
        require(parseUserPrototype(text,&calleeDeclaration).ok(),"callee authoritative declaration parses");
        const auto gated=recover(forwarded,bodies,calleeOptions);
        require(gated.structs.empty()&&gated.callEvidence.empty(),"scalar, FP, aggregate and variadic callee declarations never become guessed integer-pointer arguments");
    }

    DataTypeManager layouts;require(layouts.define("Record=struct{tag:u64;payload:u64}").ok(),"named authoritative layout fixture");const auto original=layouts.serialize();
    require(parseUserPrototype("uint64_t(Record* object)",&declared).ok(),"authoritative named pointer parses");options.typeLayouts=[&](const std::string& expression,DataTypeLayout* out){return layouts.resolve(expression,out);};
    Fixture named(0x1000);named.block(0);named.store(named.address(named.arg(0),8));named.bind(0);named.call(0x2000);named.ret();const auto namedSsa=named.finish();recover(namedSsa,bodies,options);
    DecompileResult emitted;require(decompileSsa(namedSsa,&emitted,{},{},{},options.prototypes,options.typeLayouts,{},resolver(bodies)).ok(),"declared layout decompiles with interprocedural hypotheses enabled");
    require(layouts.serialize()==original&&emitted.cSource.find("Record")!=std::string::npos&&emitted.cSource.find("->payload")!=std::string::npos,"named declaration and exact field rendering survive conflicting inferred extensions");

    bodies[0x2000]=layout(0x2000,{{0,8},{8,8}});Fixture aliases(0x1000);aliases.block(0);aliases.store(aliases.arg(0));aliases.call(0x2000);aliases.store(aliases.arg(1));aliases.load(aliases.arg(0));aliases.ret();const auto aliasSsa=aliases.finish();MemoryAnalysis memory;
    require(analyzeMemory(aliasSsa,&memory,resolver(bodies)).ok(),"alias-invariant fixture memory analysis");const auto before=memory.toText(aliasSsa);const auto last=std::find_if(memory.accesses.rbegin(),memory.accesses.rend(),[](const auto& access){return !access.store;});
    require(last!=memory.accesses.rend()&&last->reachingStore==kNoValue,"different symbolic pointer arguments may alias before type recovery");
    recover(aliasSsa,bodies,{},&memory);
    require(memory.matches(aliasSsa)&&memory.toText(aliasSsa)==before,"layout hypotheses neither modify SSA nor strengthen memory/alias proofs");
}
}
int main(){bindingAndOffsets();conflictingObservations();unknownBindings();recursiveEvidence();limitsRetainLocalFacts();authoritativeAndAliasContracts();std::cout<<checks<<" interprocedural type checks passed\n";}
