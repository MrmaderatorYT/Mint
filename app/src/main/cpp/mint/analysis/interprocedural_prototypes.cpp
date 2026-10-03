#include "mint/analysis/interprocedural_prototypes.h"
#include "mint/analysis/abi_model.h"
#include "mint/plugin/architecture_bridge.h"
#include "mint/disasm/disassembler.h"
#include "mint/ir/dominance.h"
#include "mint/ir/registers.h"

#include <algorithm>
#include <set>
#include <unordered_map>

namespace mint {
namespace {
struct Abi {u8 width=0;u64 result=0;std::vector<u64> arguments;};
Abi abiFor(Arch arch){
    Abi abi;ArchitectureDescription description;if(!architectureDescription(arch,&description))return abi;abi.width=description.pointerSize;
    if(arch==Arch::kAArch64){abi.result=arm64::kXn(0);for(unsigned n=0;n<8;++n)abi.arguments.push_back(arm64::kXn(n));}
    else if(arch==Arch::kArm32 || arch==Arch::kThumb){abi.result=arm32::kRn(0);for(unsigned n=0;n<4;++n)abi.arguments.push_back(arm32::kRn(n));}
    else if(arch==Arch::kRiscV32 || arch==Arch::kRiscV64){abi.result=riscv::kXn(10);for(unsigned n=10;n<18;++n)abi.arguments.push_back(riscv::kXn(n));}
    else if(arch==Arch::kX86_64){abi.result=x86::kRax;abi.arguments={x86::kRdi,x86::kRsi,x86::kRdx,x86::kRcx,x86::kR8,x86::kGpr(9)};}
    else if(arch==Arch::kX86_32)abi.result=x86::kRax;
    else {MintArchitectureSemanticsV2 custom{};if(architecturePluginAbi(arch,&custom)){abi.width=custom.pointer_size;abi.result=custom.return_register_offset;for(u32 n=0;n<custom.argument_count;++n)abi.arguments.push_back(custom.argument_offsets[n]);}else abi.width=0;}
    return abi;
}
bool scalar(u8 width){return width==1 || width==2 || width==4 || width==8;}
bool join(PrototypeScalarEvidence* destination,u8 width,bool pointer,const char* provenance){
    if(!scalar(width) && !pointer)return false;bool changed=false;
    if(scalar(width) && destination->width<width){destination->width=width;changed=true;}
    if(pointer && !destination->pointer){destination->pointer=true;changed=true;}
    if(provenance && std::find(destination->provenance.begin(),destination->provenance.end(),provenance)==destination->provenance.end()){destination->provenance.emplace_back(provenance);std::sort(destination->provenance.begin(),destination->provenance.end());changed=true;}
    return changed;
}
u8 typeWidth(const std::string& type,u8 pointerWidth){
    if(type.find('*')!=std::string::npos)return pointerWidth;
    if(type=="char" || type.find("int8_t")!=std::string::npos)return 1;
    if(type.find("int16_t")!=std::string::npos)return 2;
    if(type.find("int32_t")!=std::string::npos)return 4;
    if(type.find("int64_t")!=std::string::npos)return 8;return 0;
}
bool transparent(MintOp op){return op==MintOp::kCopy || op==MintOp::kTrunc || op==MintOp::kSignExt || op==MintOp::kZeroExt;}
struct Context {
    const SsaFunction* f=nullptr;Abi abi;Dominance dominance;
    std::vector<u16> origins; // Entry register parameter bits, not alias guesses.
    std::vector<std::vector<std::pair<u32,u8>>> uses;
};
struct Call {
    Address caller=0,site=0;u32 instruction=0;std::vector<Address> targets;bool complete=false;
    std::vector<SsaId> arguments;SsaId result=kNoValue;
};
class Inference {
public:
    Inference(const std::map<Address,UserPrototype>& declarations,const InterproceduralPrototypeOptions& options):declarations_(declarations),options_(options){}
    Status run(const std::vector<const SsaFunction*>& functions,const std::vector<IndirectFlowReport>& indirect,InterproceduralPrototypeReport* output);
private:
    const std::map<Address,UserPrototype>& declarations_;const InterproceduralPrototypeOptions& options_;
    std::map<Address,Context> contexts_;std::map<Address,FunctionPrototypeEvidence> evidence_;std::vector<Call> calls_;size_t work_=0;bool workLimit_=false;
    bool work(){if(work_>=options_.maxWork){workLimit_=true;return false;}++work_;return true;}
    SsaId reaching(const Context&,u32 block,u32 limit,u64 registerOffset);
    u8 definitionWidth(const Context&,SsaId,const std::map<Address,FunctionPrototypeEvidence>&,std::set<SsaId>* visiting);
    bool definitionPointer(const Context&,SsaId,const std::map<Address,FunctionPrototypeEvidence>&,std::set<SsaId>* visiting);
    bool constrain(Context&,SsaId,u8,bool,const char*);
    bool observed(Context&);
};
SsaId Inference::reaching(const Context& c,u32 block,u32 limit,u64 offset){
    const auto& f=*c.f;for(size_t depth=0;depth<=f.blocks.size() && block<f.blocks.size();++depth){
        const auto& current=f.blocks[block];
        for(u32 n=std::min<u32>(limit,current.firstInsn+current.insnCount);n>current.firstInsn;){if(!work())return kNoValue;const auto& instruction=f.insns[--n];if(instruction.dead)continue;
            for(SsaId id:instruction.clobbers)if(id<f.values.size() && f.values[id].storage.isRegister() && f.values[id].storage.offset==offset)return id;
            if(instruction.dest<f.values.size() && f.values[instruction.dest].storage.isRegister() && f.values[instruction.dest].storage.offset==offset)return instruction.dest;
        }
        for(u32 index:current.phis){const auto& phi=f.phis[index];if(!phi.dead && phi.dest<f.values.size() && f.values[phi.dest].storage.isRegister() && f.values[phi.dest].storage.offset==offset)return phi.dest;}
        if(!c.dominance.reachable(block))break;const auto parent=c.dominance.idom[block];if(parent==block || parent>=f.blocks.size())break;block=parent;limit=f.blocks[block].firstInsn+f.blocks[block].insnCount;
    }
    for(SsaId id=0;id<f.values.size();++id)if(f.values[id].def==SsaDef::kEntry && f.values[id].storage.isRegister() && f.values[id].storage.offset==offset)return id;
    return kNoValue;
}
bool Inference::constrain(Context& c,SsaId value,u8 width,bool pointer,const char* provenance){
    if(value>=c.origins.size())return false;auto& prototype=evidence_[c.f->entry];if(prototype.authoritative)return false;bool changed=false;
    for(size_t slot=0;slot<prototype.parameters.size();++slot)if(c.origins[value]&(1u<<slot))changed|=join(&prototype.parameters[slot],width,pointer,provenance);
    return changed;
}
bool Inference::observed(Context& c){
    const auto& f=*c.f;bool changed=false;
    for(const auto& instruction:f.insns){if(!work())break;if(instruction.dead)continue;
        if(instruction.op==MintOp::kCall || instruction.op==MintOp::kCallInd || instruction.op==MintOp::kReturn || instruction.op==MintOp::kBranch || instruction.op==MintOp::kBranchInd || instruction.op==MintOp::kIntrinsic)continue;
        for(unsigned operand=0;operand<3;++operand){const auto id=instruction.use[operand];if(id>=f.values.size())continue;
            if(transparent(instruction.op)){
                // Normalized wide-register carriers must not erase an explicit
                // narrow operand. Plain copies transfer origin without adding
                // a width demand; a truncation is an actual narrow observation.
                if(instruction.op==MintOp::kCopy)continue;
                const u8 width=instruction.op==MintOp::kTrunc && instruction.dest<f.values.size()?f.values[instruction.dest].storage.size:f.values[id].storage.size;
                changed|=constrain(c,id,width,false,"local narrow scalar use");continue;
            }
            const bool pointer=(instruction.op==MintOp::kLoad || instruction.op==MintOp::kStore) && operand==0;
            changed|=constrain(c,id,pointer?c.abi.width:f.values[id].storage.size,pointer,pointer?"used as memory address":"local scalar operation");
        }
    }
    return changed;
}
u8 Inference::definitionWidth(const Context& c,SsaId id,const std::map<Address,FunctionPrototypeEvidence>& known,std::set<SsaId>* visiting){
    if(id>=c.f->values.size() || !work() || visiting->size()>=128 || !visiting->insert(id).second)return 0;
    const auto& f=*c.f;const auto& value=f.values[id];u8 width=0;
    if(value.def==SsaDef::kConstant)width=value.storage.size;
    else if(value.def==SsaDef::kEntry){
        const auto found=known.find(f.entry);if(found!=known.end() && (!found->second.authoritative || prototypeUsesSimpleIntegerRegisters(found->second.declaration,f.arch)))for(size_t n=0;n<std::min<size_t>(16,found->second.parameters.size());++n)if(c.origins[id]&(1u<<n))width=std::max(width,found->second.parameters[n].width);
    }else if(value.def==SsaDef::kPhi && value.defIndex<f.phis.size()){
        bool all=true;for(SsaId argument:f.phis[value.defIndex].args){const u8 current=definitionWidth(c,argument,known,visiting);if(!current)all=false;width=std::max(width,current);}if(!all)width=0;
    }else if(value.def==SsaDef::kInsn && value.defIndex<f.insns.size()){
        const auto& instruction=f.insns[value.defIndex];
        if(instruction.op==MintOp::kCall || instruction.op==MintOp::kCallInd){
            for(const auto& call:calls_)if(call.caller==f.entry && call.instruction==value.defIndex && call.result==id && call.complete){
                bool all=!call.targets.empty();for(Address target:call.targets){const auto found=known.find(target);if(found==known.end() || (!found->second.result.width && !found->second.result.pointer)){all=false;break;}width=std::max(width,found->second.result.width?found->second.result.width:c.abi.width);}if(!all)width=0;break;
            }
        }else if(instruction.dest!=id || instruction.dead || instruction.op==MintOp::kIntrinsic || instruction.op==MintOp::kUndefined)width=0;
        else if(instruction.op==MintOp::kCopy || instruction.op==MintOp::kSignExt || instruction.op==MintOp::kZeroExt)width=definitionWidth(c,instruction.use[0],known,visiting);
        else width=value.storage.size;
    }
    visiting->erase(id);return scalar(width)?width:0;
}
bool Inference::definitionPointer(const Context& c,SsaId id,const std::map<Address,FunctionPrototypeEvidence>& known,std::set<SsaId>* visiting){
    if(id>=c.f->values.size() || !work() || visiting->size()>=128 || !visiting->insert(id).second)return false;
    const auto& f=*c.f;const auto& value=f.values[id];bool pointer=false;
    if(value.def==SsaDef::kEntry){
        const auto found=known.find(f.entry);if(found!=known.end() && (!found->second.authoritative || prototypeUsesSimpleIntegerRegisters(found->second.declaration,f.arch)))for(size_t n=0;n<std::min<size_t>(16,found->second.parameters.size());++n)if(c.origins[id]&(1u<<n))pointer|=found->second.parameters[n].pointer;
    }else if(value.def==SsaDef::kPhi && value.defIndex<f.phis.size()){
        pointer=!f.phis[value.defIndex].args.empty();for(SsaId argument:f.phis[value.defIndex].args)pointer&=definitionPointer(c,argument,known,visiting);
    }else if(value.def==SsaDef::kInsn && value.defIndex<f.insns.size()){
        const auto& instruction=f.insns[value.defIndex];
        if(instruction.op==MintOp::kCall || instruction.op==MintOp::kCallInd){
            for(const auto& call:calls_)if(call.caller==f.entry && call.instruction==value.defIndex && call.result==id && call.complete){pointer=!call.targets.empty();for(Address target:call.targets){const auto found=known.find(target);if(found==known.end() || !found->second.result.pointer){pointer=false;break;}}break;}
        }else if(instruction.dest==id && !instruction.dead && value.storage.size==c.abi.width){
            if(transparent(instruction.op))pointer=definitionPointer(c,instruction.use[0],known,visiting);
            else if(instruction.op==MintOp::kAdd || instruction.op==MintOp::kSub){
                const auto a=instruction.use[0],b=instruction.use[1];
                if(b<f.values.size() && f.values[b].def==SsaDef::kConstant)pointer=definitionPointer(c,a,known,visiting);
                else if(instruction.op==MintOp::kAdd && a<f.values.size() && f.values[a].def==SsaDef::kConstant)pointer=definitionPointer(c,b,known,visiting);
            }
        }
    }
    visiting->erase(id);return pointer;
}

Status Inference::run(const std::vector<const SsaFunction*>& functions,const std::vector<IndirectFlowReport>& indirect,InterproceduralPrototypeReport* output){
    size_t values=0,instructions=0;
    for(const auto* f:functions){
        if(!f || contexts_.count(f->entry))return Status::error(ErrorCode::kBadFormat,"duplicate or null prototype function");
        values+=f->values.size();instructions+=f->insns.size();if(values>options_.maxValues || instructions>options_.maxInstructions || f->blocks.size()>options_.maxInstructions || f->phis.size()>options_.maxValues)return Status::error(ErrorCode::kTooLarge,"prototype SSA bounds exceeded");
        Context c;c.f=f;c.abi=abiFor(f->arch);if(!c.abi.width)return Status::error(ErrorCode::kUnsupported,"prototype ABI is unsupported");c.origins.resize(f->values.size());c.uses.resize(f->values.size());
        std::vector<std::vector<u32>> successors;
        for(const auto& block:f->blocks){if(block.id!=successors.size() || block.firstInsn>f->insns.size() || block.insnCount>f->insns.size()-block.firstInsn)return Status::error(ErrorCode::kBadFormat,"prototype SSA block is invalid");for(u32 successor:block.successors)if(successor>=f->blocks.size())return Status::error(ErrorCode::kBadFormat,"prototype SSA edge is invalid");for(u32 phi:block.phis)if(phi>=f->phis.size())return Status::error(ErrorCode::kBadFormat,"prototype SSA phi is invalid");successors.push_back(block.successors);}
        c.dominance=computeDominance(successors);
        for(SsaId id=0;id<f->values.size();++id)if(f->values[id].def==SsaDef::kEntry && f->values[id].storage.isRegister())for(size_t n=0;n<c.abi.arguments.size();++n)if(f->values[id].storage.offset==c.abi.arguments[n])c.origins[id]|=1u<<n;
        for(u32 n=0;n<f->insns.size();++n){const auto& instruction=f->insns[n];if(instruction.block>=f->blocks.size())return Status::error(ErrorCode::kBadFormat,"prototype SSA instruction block is invalid");for(unsigned operand=0;operand<3;++operand){SsaId id=instruction.use[operand];if(id!=kNoValue && id>=f->values.size())return Status::error(ErrorCode::kBadFormat,"prototype SSA operand is invalid");if(id<f->values.size() && !instruction.dead)c.uses[id].push_back({n,operand});}for(SsaId id:instruction.clobbers)if(id>=f->values.size())return Status::error(ErrorCode::kBadFormat,"prototype SSA clobber is invalid");}
        for(const auto& phi:f->phis){if(phi.dest>=f->values.size() || phi.block>=f->blocks.size())return Status::error(ErrorCode::kBadFormat,"prototype SSA phi is invalid");for(SsaId id:phi.args)if(id>=f->values.size())return Status::error(ErrorCode::kBadFormat,"prototype SSA phi operand is invalid");}
        FunctionPrototypeEvidence prototype;prototype.entry=f->entry;prototype.architecture=f->arch;prototype.parameters.resize(c.abi.arguments.size());evidence_.emplace(f->entry,std::move(prototype));contexts_.emplace(f->entry,std::move(c));
    }
    for(const auto& declaration:declarations_){if(!declaration.second.valid() || declaration.second.returnType.size()>256 || declaration.second.parameters.size()>64)return Status::error(ErrorCode::kBadFormat,"authoritative prototype is empty or unbounded");for(const auto& parameter:declaration.second.parameters)if(parameter.type.size()>256 || parameter.name.size()>128)return Status::error(ErrorCode::kBadFormat,"authoritative parameter is unbounded");auto& result=evidence_[declaration.first];result.entry=declaration.first;result.authoritative=true;result.parameterCountKnown=!declaration.second.variadic;result.declaration=declaration.second;result.returnsVoid=result.declaration.returnType=="void";
        const auto context=contexts_.find(declaration.first);const u8 width=context==contexts_.end()?0:context->second.abi.width;result.parameters.resize(result.declaration.parameters.size());
        join(&result.result,typeWidth(result.declaration.returnType,width),result.declaration.returnType.find('*')!=std::string::npos,"authoritative declaration");
        for(size_t n=0;n<result.parameters.size();++n)join(&result.parameters[n],typeWidth(result.declaration.parameters[n].type,width),result.declaration.parameters[n].type.find('*')!=std::string::npos,"authoritative declaration");
    }
    std::map<std::pair<Address,Address>,const IndirectFlowSite*> indirectSites;
    for(const auto& report:indirect)for(const auto& site:report.sites)if(site.call){if(!indirectSites.emplace(std::make_pair(report.functionEntry,site.address),&site).second)return Status::error(ErrorCode::kBadFormat,"duplicate indirect call evidence");}
    for(auto& pair:contexts_){auto& c=pair.second;const auto& f=*c.f;
        // Entry-origin aliases propagate only through value-preserving carriers,
        // not arbitrary arithmetic. The latter gets its own observed use.
        bool changed=true;for(size_t iteration=0;changed && iteration<options_.maxIterations;++iteration){changed=false;for(SsaId id=0;id<f.values.size();++id){if(!work())break;const auto& value=f.values[id];u16 origin=c.origins[id];if(value.def==SsaDef::kPhi && value.defIndex<f.phis.size())for(SsaId argument:f.phis[value.defIndex].args)origin|=c.origins[argument];else if(value.def==SsaDef::kInsn && value.defIndex<f.insns.size() && f.insns[value.defIndex].dest==id){const auto& instruction=f.insns[value.defIndex];if(transparent(instruction.op) && instruction.use[0]<c.origins.size())origin|=c.origins[instruction.use[0]];else if(instruction.op==MintOp::kAdd || instruction.op==MintOp::kSub){const auto a=instruction.use[0],b=instruction.use[1];if(b<f.values.size() && f.values[b].def==SsaDef::kConstant && a<c.origins.size())origin|=c.origins[a];else if(instruction.op==MintOp::kAdd && a<f.values.size() && f.values[a].def==SsaDef::kConstant && b<c.origins.size())origin|=c.origins[b];}}if(origin!=c.origins[id]){c.origins[id]=origin;changed=true;}}if(workLimit_)break;}
        observed(c);
        for(u32 index=0;index<f.insns.size();++index){const auto& instruction=f.insns[index];if(instruction.dead || (instruction.op!=MintOp::kCall && instruction.op!=MintOp::kCallInd))continue;if(calls_.size()>=options_.maxCalls)return Status::error(ErrorCode::kTooLarge,"prototype call bounds exceeded");
            Call call;call.caller=f.entry;call.site=instruction.address;call.instruction=index;
            if(instruction.op==MintOp::kCall && instruction.use[0]<f.values.size() && f.values[instruction.use[0]].def==SsaDef::kConstant){Address target=f.values[instruction.use[0]].storage.offset;if(f.arch==Arch::kArm32 || f.arch==Arch::kThumb)target&=~Address{1};call.targets={target};call.complete=true;}
            else {const auto found=indirectSites.find({f.entry,instruction.address});if(found!=indirectSites.end()){call.complete=found->second->complete;for(const auto& target:found->second->targets)call.targets.push_back(target.address);}}
            std::sort(call.targets.begin(),call.targets.end());call.targets.erase(std::unique(call.targets.begin(),call.targets.end()),call.targets.end());
            for(u64 argument:c.abi.arguments)call.arguments.push_back(reaching(c,instruction.block,index,argument));
            for(SsaId id:instruction.clobbers)if(f.values[id].storage.isRegister() && f.values[id].storage.offset==c.abi.result)call.result=id;
            calls_.push_back(std::move(call));
        }
    }
    InterproceduralPrototypeReport report;bool changed=true;
    for(size_t iteration=0;changed && !workLimit_ && iteration<options_.maxIterations;++iteration){changed=false;
        for(auto& pair:contexts_){auto& c=pair.second;auto& prototype=evidence_[pair.first];if(prototype.authoritative)continue;
            for(const auto& returned:c.f->returnValues){std::set<SsaId> visiting;const u8 width=definitionWidth(c,returned.second,evidence_,&visiting);visiting.clear();const bool pointer=definitionPointer(c,returned.second,evidence_,&visiting);changed|=join(&prototype.result,width,pointer,"observed return definition");}
        }
        for(const auto& call:calls_){if(!work())break;if(!call.complete)continue;auto& caller=contexts_.at(call.caller);
            for(Address target:call.targets){auto callee=evidence_.find(target);if(callee==evidence_.end())continue;auto& signature=callee->second;
                if(signature.authoritative && !prototypeUsesSimpleIntegerRegisters(signature.declaration,caller.f->arch))continue;
                for(size_t n=0;n<std::min(call.arguments.size(),signature.parameters.size());++n){const auto& parameter=signature.parameters[n];u8 width=parameter.width;if(parameter.pointer && !width)width=caller.abi.width;changed|=constrain(caller,call.arguments[n],width,parameter.pointer,"callee parameter constraint");
                    // A known callee parameter is the only evidence this ABI
                    // position is actually consumed; a pre-call constant alone
                    // never invents an argument in an unknown declaration.
                    if(!signature.authoritative && parameter.width && call.arguments[n]<caller.f->values.size()){std::set<SsaId> visiting;changed|=join(&signature.parameters[n],definitionWidth(caller,call.arguments[n],evidence_,&visiting),false,"observed caller argument definition");}
                }
            }
            if(call.result<caller.uses.size())for(const auto& use:caller.uses[call.result]){const auto& instruction=caller.f->insns[use.first];if(instruction.dead || instruction.op==MintOp::kCopy || instruction.op==MintOp::kReturn)continue;const u8 width=instruction.op==MintOp::kTrunc && instruction.dest<caller.f->values.size()?caller.f->values[instruction.dest].storage.size:caller.f->values[call.result].storage.size;const bool pointer=(instruction.op==MintOp::kLoad || instruction.op==MintOp::kStore) && use.second==0;for(Address target:call.targets){auto found=evidence_.find(target);if(found!=evidence_.end() && !found->second.authoritative)changed|=join(&found->second.result,pointer?caller.abi.width:width,pointer,"caller result-use constraint");}}
        }
        report.iterations=iteration+1;
    }
    report.converged=!changed && !workLimit_;
    for(auto& pair:evidence_)report.functions.push_back(std::move(pair.second));
    for(const auto& call:calls_)report.calls.push_back({call.caller,call.site,call.targets,call.complete});
    std::sort(report.calls.begin(),report.calls.end(),[](const auto& a,const auto& b){return a.caller<b.caller || (a.caller==b.caller && a.site<b.site);});
    *output=std::move(report);return Status::success();
}
}
Status inferInterproceduralPrototypes(const std::vector<const SsaFunction*>& functions,const std::map<Address,UserPrototype>& authoritative,const std::vector<IndirectFlowReport>& indirect,InterproceduralPrototypeReport* output,const InterproceduralPrototypeOptions& options){
    if(!output)return Status::error(ErrorCode::kBadFormat,"prototype output is missing");
    if(functions.size()>options.maxFunctions || authoritative.size()>options.maxFunctions || options.maxFunctions>200000 || options.maxIterations==0 || options.maxIterations>4096 || options.maxWork==0 || options.maxValues>4000000 || options.maxInstructions>4000000 || options.maxCalls>1000000)return Status::error(ErrorCode::kTooLarge,"prototype analysis bounds exceeded");
    return Inference(authoritative,options).run(functions,indirect,output);
}
}
