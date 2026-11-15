#include "mint/ir/interprocedural_types.h"
#include "mint/ir/registers.h"
#include "mint/ir/dominance.h"
#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <tuple>

namespace mint {
namespace {
constexpr u64 kMaxOffset=1024*1024;
struct Observation {
    RecoveredTypeKind kind=RecoveredTypeKind::kUnknown;
    std::set<TypeEvidenceOrigin> origins;
};
struct Shape {
    bool conflict=false;
    std::map<std::pair<u64,u8>,Observation> fields;
};
using Summary=std::array<Shape,8>;
int argument(const SsaFunction& f,SsaId id) {
    if(id>=f.values.size())return -1;
    const auto& value=f.values[id];const auto& storage=value.storage;
    return value.def==SsaDef::kEntry&&storage.isRegister()&&storage.size==8&&storage.offset<=arm64::kXn(7)&&storage.offset%8==0?static_cast<int>(storage.offset/8):-1;
}
bool supportedRoot(const SsaFunction& f,const MemoryAddress& address) {
    return address.kind==MemoryBaseKind::kSymbolic&&address.pointerWidth==8&&address.base<f.values.size()&&
        f.values[address.base].def==SsaDef::kEntry&&f.values[address.base].storage.isRegister()&&
        f.values[address.base].storage.size==8&&f.values[address.base].storage.offset<=arm64::kXn(28)&&
        f.values[address.base].storage.offset%8==0&&address.offset>=0&&static_cast<u64>(address.offset)<=kMaxOffset;
}
bool same(const Shape& a,const Shape& b) {
    if(a.conflict!=b.conflict||a.fields.size()!=b.fields.size())return false;
    auto left=a.fields.begin(),right=b.fields.begin();
    for(;left!=a.fields.end();++left,++right) {
        if(left->first!=right->first||left->second.kind!=right->second.kind||left->second.origins.size()!=right->second.origins.size())return false;
        auto x=left->second.origins.begin(),y=right->second.origins.begin();
        for(;x!=left->second.origins.end();++x,++y)if(x->function!=y->function||x->instruction!=y->instruction)return false;
    }
    return true;
}
class Recovery {
public:
    Recovery(const SsaFunction& root,const MemoryFunctionResolver& functions,const InterproceduralTypeOptions& options)
        :root_(root),functions_(functions),options_(options){}
    bool limited=false;
    struct Node {
        std::shared_ptr<const SsaFunction> body;
        MemoryAnalysis memory;
        TypeRecovery types;
        std::vector<MemoryCallInputs> calls;
        std::vector<u8> priorEffects;
        std::map<SsaId,Shape> local;
        std::array<bool,8> allowed{};
        bool declared=false,ready=false,solved=false,complete=false;
        Summary summary;
    };
    std::map<Address,Node> nodes;
    bool tick(){if(work_>=std::min<size_t>(options_.maxWork,2000000)){limited=true;return false;}++work_;return true;}
    bool insert(Shape& shape,u64 offset,u8 width,const Observation& observation) {
        if(!tick())return false;
        if(shape.conflict)return true;
        if(!width||width>16||offset>kMaxOffset-width){limited=true;return false;}
        const auto key=std::make_pair(offset,width);
        for(const auto& field:shape.fields) {
            if(!tick())return false;
            if(field.first!=key&&offset<field.first.first+field.first.second&&field.first.first<offset+width){shape.conflict=true;shape.fields.clear();return true;}
        }
        auto found=shape.fields.find(key);
        if(found==shape.fields.end()) {
            if(shape.fields.size()>=std::min<size_t>(options_.maxFields,64)){limited=true;return false;}
            found=shape.fields.emplace(key,Observation{}).first;
        }
        auto& old=found->second;
        if(old.kind!=RecoveredTypeKind::kUnknown&&observation.kind!=RecoveredTypeKind::kUnknown&&old.kind!=observation.kind) {
            shape.conflict=true;shape.fields.clear();return true;
        }
        if(old.kind==RecoveredTypeKind::kUnknown)old.kind=observation.kind;
        old.origins.insert(observation.origins.begin(),observation.origins.end());
        if(old.origins.size()>64){limited=true;return false;}
        return true;
    }
    bool merge(Shape& target,const Shape& source,u64 displacement=0) {
        if(!tick())return false;
        if(source.conflict){target.conflict=true;target.fields.clear();return true;}
        for(const auto& field:source.fields) {
            if(displacement>kMaxOffset||field.first.first>kMaxOffset-displacement){limited=true;return false;}
            if(!insert(target,field.first.first+displacement,field.first.second,field.second))return false;
        }
        return true;
    }
    void discover(Address entry,size_t depth,const MemoryAnalysis* supplied=nullptr) {
        if(nodes.count(entry))return;
        if(nodes.size()>=std::min<size_t>(options_.maxFunctions,64)||depth>=std::min<size_t>(options_.maxDepth,16)||!tick()){limited=true;return;}
        auto& node=nodes[entry];node.solved=true;
        try {node.body=entry==root_.entry?std::shared_ptr<const SsaFunction>(&root_,[](const SsaFunction*){}):functions_(entry);}catch(...){return;}
        if(!node.body||node.body->entry!=entry||node.body->arch!=Arch::kAArch64||node.body->byteOrder!=root_.byteOrder)return;
        const auto& f=*node.body;
        if(f.blocks.empty()||f.values.size()>32768||f.insns.size()>8192||f.phis.size()>32768||f.blocks.size()>512||
            f.values.size()>250000-values_||f.insns.size()>250000-instructions_){limited=true;return;}
        size_t links=0;
        auto take=[&](size_t count){if(count>4000000-links){limited=true;return false;}links+=count;return true;};
        for(const auto& insn:f.insns)if(!take(insn.clobbers.size()))return;
        for(const auto& phi:f.phis)if(!take(phi.args.size()))return;
        for(const auto& block:f.blocks)if(!take(block.successors.size())||!take(block.predecessors.size())||!take(block.phis.size()))return;
        values_+=f.values.size();instructions_+=f.insns.size();
        // Charge graph size before verification/local recovery, independently of
        // the reused memory/binding analyses' own hard bounds.
        for(size_t i=0;i<f.values.size()+f.insns.size()+f.phis.size();++i)if(!tick())return;
        if(!f.verify().empty())return;
        if(supplied&&supplied->matches(f))node.memory=*supplied;
        else if(!analyzeMemory(f,&node.memory).ok())return;
        if(!recoverTypes(f,&node.types,&node.memory).ok())return;
        if(!bindAapcs64CallInputs(f,&node.memory,&node.calls,&node.priorEffects).ok()){limited=true;return;}
        node.allowed.fill(true);
        if(options_.prototypes) {
            UserPrototype declaration;
            try{declaration=options_.prototypes(entry);}catch(...){return;}
            node.declared=declaration.valid();
            if(node.declared) {
                node.allowed.fill(false);declaration.byteOrder=f.byteOrder;
                AbiModel abi;
                try {
                    if(!buildAbiModel(f.arch,declaration,&abi,options_.typeLayouts).ok()||abi.convention!="aapcs64"||abi.variadic)return;
                    DataTypeManager builtins(8);
                    for(size_t i=0;i<abi.parameters.size();++i) {
                        const auto& parameter=abi.parameters[i];DataTypeLayout layout;
                        const auto status=options_.typeLayouts?options_.typeLayouts(declaration.parameters[i].type,&layout):builtins.resolve(declaration.parameters[i].type,&layout);
                        if(!status.ok()||layout.kind!=DataTypeKind::kPointer||layout.size!=8||parameter.indirect||parameter.pieces.size()!=1)continue;
                        const auto& piece=parameter.pieces[0];
                        if(piece.kind==AbiStorageKind::kRegister&&!piece.floating&&piece.width==8&&piece.valueOffset==0&&piece.registerShift==0&&
                            piece.storage.isRegister()&&piece.storage.size==8&&piece.storage.offset<=arm64::kXn(7)&&piece.storage.offset%8==0)
                            node.allowed[piece.storage.offset/8]=true;
                    }
                }catch(...){return;}
            }
        }
        // Raw observations retain width/kind conflicts that local layout's
        // historical widest-access heuristic might otherwise hide.
        std::vector<std::vector<u32>> edges;for(const auto& block:f.blocks)edges.push_back(block.successors);
        const auto dominance=computeDominance(edges);
        for(const auto& access:node.memory.accesses) {
            if(!tick())return;
            const auto& address=access.address;
            if(!supportedRoot(f,address)||access.instruction>=f.insns.size())continue;
            const auto& insn=f.insns[access.instruction];
            if(!dominance.reachable(insn.block)||node.priorEffects[access.instruction]||(insn.op!=MintOp::kLoad&&insn.op!=MintOp::kStore))continue;
            const auto value=access.store?insn.use[1]:insn.dest;
            if(value>=node.types.values.size())continue;
            Observation observation;observation.kind=node.types.values[value].kind;
            observation.origins.insert({entry,insn.address});
            if(!insert(node.local[address.base],static_cast<u64>(address.offset),access.width,observation))return;
        }
        node.ready=true;node.solved=false;
        for(const auto& call:node.calls)discover(call.target,depth+1);
    }
    void solve() {
        std::map<Address,size_t> index,low;std::set<Address> active;std::vector<Address> stack;size_t next=0;
        std::function<void(Address)> visit=[&](Address target) {
            index[target]=low[target]=next++;stack.push_back(target);active.insert(target);
            for(const auto& call:nodes.at(target).calls) {
                const auto found=nodes.find(call.target);if(found==nodes.end()||found->second.solved)continue;
                if(!index.count(call.target)){visit(call.target);low[target]=std::min(low[target],low[call.target]);}
                else if(active.count(call.target))low[target]=std::min(low[target],index[call.target]);
            }
            if(low[target]!=index[target])return;
            std::vector<Address> component;
            do{component.push_back(stack.back());active.erase(stack.back());stack.pop_back();}while(component.back()!=target);
            solveComponent(component);
        };
        for(const auto& item:nodes)if(!item.second.solved&&!index.count(item.first))visit(item.first);
    }
    bool imported(const Node& node,std::map<SsaId,Shape>* shapes,std::vector<TypeCallEvidence>* provenance) {
        for(const auto& call:node.calls) {
            if(!tick())return false;
            const auto callee=nodes.find(call.target);if(callee==nodes.end()||!callee->second.complete)continue;
            for(unsigned input=0;input<8;++input) {
                const auto& source=callee->second.summary[input];if(source.fields.empty()&&!source.conflict)continue;
                const auto& binding=call.arguments[input];if(!supportedRoot(*node.body,binding))continue;
                // Authoritative caller parameters already have a display type;
                // cross-call hypotheses never add or replace that declaration.
                if(node.declared&&argument(*node.body,binding.base)>=0)continue;
                if(!merge((*shapes)[binding.base],source,static_cast<u64>(binding.offset)))return false;
                provenance->push_back({call.target,node.body->insns[call.instruction].address,input,binding.base,binding.offset});
            }
        }
        return true;
    }
private:
    const SsaFunction& root_;const MemoryFunctionResolver& functions_;const InterproceduralTypeOptions& options_;
    size_t work_=0,values_=0,instructions_=0;
    void solveComponent(const std::vector<Address>& component) {
        // Bottom is an empty set of observations, never an assertion that a
        // pointer has no other fields. Conflicts are absorbing. Origins are
        // finite source sites (not recursive call paths), so cycles deduplicate.
        std::map<Address,Summary> current;for(auto entry:component)current[entry]={};
        bool converged=false;
        for(size_t round=0;round<std::min<size_t>(options_.maxIterations,64);++round) {
            auto next=current;bool valid=true,changed=false;
            for(auto entry:component) {
                const auto& node=nodes.at(entry);auto& result=next[entry];const auto& f=*node.body;
                for(const auto& local:node.local) {
                    const int input=argument(f,local.first);
                    if(input>=0&&node.allowed[input]&&!merge(result[input],local.second)){valid=false;break;}
                }
                if(!valid)break;
                for(const auto& call:node.calls) {
                    if(!tick()){valid=false;break;}
                    const auto internal=current.find(call.target);const auto external=nodes.find(call.target);
                    const Summary* source=internal!=current.end()?&internal->second:
                        external!=nodes.end()&&external->second.complete?&external->second.summary:nullptr;
                    if(!source)continue; // Missing/indirect bodies provide no type evidence.
                    for(unsigned input=0;input<8;++input) {
                        const auto& binding=call.arguments[input];
                        if(!supportedRoot(f,binding))continue;
                        const int destination=argument(f,binding.base);
                        if(destination<0||!node.allowed[destination])continue;
                        if(!merge(result[destination],(*source)[input],static_cast<u64>(binding.offset))){valid=false;break;}
                    }
                    if(!valid)break;
                }
                if(!valid)break;
                for(unsigned input=0;input<8;++input)changed|=!same(result[input],current.at(entry)[input]);
            }
            if(!valid)break;
            current=std::move(next);
            if(!changed){converged=true;break;}
        }
        if(!converged)limited=true;
        for(auto entry:component) {
            auto& node=nodes.at(entry);node.solved=true;node.complete=converged;
            if(converged)node.summary=std::move(current.at(entry));
        }
    }
};
}

Status recoverInterproceduralTypes(const SsaFunction& function,TypeRecovery* output,
    const MemoryAnalysis* memory,const MemoryFunctionResolver& functions,const InterproceduralTypeOptions& options) {
    auto status=recoverTypes(function,output,memory);if(!status.ok())return status;
    if(function.arch!=Arch::kAArch64||!functions)return Status::success();
    Recovery recovery(function,functions,options);recovery.discover(function.entry,0,memory);
    // A truncated graph may hide the backedge that closes an SCC. Never solve
    // that prefix as an acyclic graph or export its provisional observations.
    if(recovery.limited){output->interproceduralLimited=true;return Status::success();}
    recovery.solve();
    if(recovery.limited){output->interproceduralLimited=true;return Status::success();}
    auto root=recovery.nodes.find(function.entry);
    if(root==recovery.nodes.end()||!root->second.ready||!root->second.complete) {output->interproceduralLimited=recovery.limited;return Status::success();}
    std::map<SsaId,Shape> imported;std::vector<TypeCallEvidence> calls;
    if(!recovery.imported(root->second,&imported,&calls)){output->interproceduralLimited=true;return Status::success();}
    if(imported.empty())return Status::success();
    TypeRecovery prepared=*output;
    for(auto& item:imported) {
        const SsaId base=item.first;auto& shape=item.second;
        if(base>=prepared.values.size())continue;
        const auto kind=prepared.values[base].kind;
        if(kind!=RecoveredTypeKind::kUnknown&&kind!=RecoveredTypeKind::kPointer){shape.conflict=true;shape.fields.clear();}
        const auto local=root->second.local.find(base);
        if(local!=root->second.local.end()&&!recovery.merge(shape,local->second)){output->interproceduralLimited=true;return Status::success();}
        // Preserve locally established reload/copy layout observations as well.
        for(const auto& layout:prepared.structs)if(layout.base==base)for(const auto& field:layout.fields) {
            Observation observation;observation.kind=field.type.kind;
            if(!recovery.insert(shape,field.offset,field.width,observation)){output->interproceduralLimited=true;return Status::success();}
        }
        prepared.structs.erase(std::remove_if(prepared.structs.begin(),prepared.structs.end(),[&](const auto& layout){return layout.base==base;}),prepared.structs.end());
        if(shape.conflict){prepared.conflictingLayouts.push_back(base);continue;}
        prepared.values[base].kind=RecoveredTypeKind::kPointer;
        // Reuse exact address facts for copies/constant offsets/agreeing phis.
        // This only changes display hints, never the memory sidecar itself.
        for(SsaId id=0;id<prepared.values.size();++id) {
            if(!recovery.tick()){output->interproceduralLimited=true;return Status::success();}
            const auto& fact=root->second.memory.values[id];
            if(fact.kind==MemoryBaseKind::kSymbolic&&fact.base==base&&prepared.values[id].width==8&&
                prepared.values[id].kind==RecoveredTypeKind::kUnknown)prepared.values[id].kind=RecoveredTypeKind::kPointer;
        }
        if(shape.fields.size()<2)continue;
        RecoveredStruct layout;layout.base=base;
        for(const auto& observation:shape.fields) {
            RecoveredField field;field.base=base;field.offset=observation.first.first;field.width=observation.first.second;
            field.type={observation.second.kind,field.width,kNoValue};
            field.origins.assign(observation.second.origins.begin(),observation.second.origins.end());layout.fields.push_back(std::move(field));
        }
        prepared.structs.push_back(std::move(layout));
    }
    // IDs belong to this caller only. Never retain a foreign or shifted index.
    for(auto& type:prepared.values)type.structId=kNoValue;
    for(u32 index=0;index<prepared.structs.size();++index) {
        prepared.values[prepared.structs[index].base].structId=index;
        for(auto& field:prepared.structs[index].fields)field.type.structId=kNoValue;
    }
    for(auto& parameter:prepared.parameters)parameter.type=prepared.values[parameter.value];
    prepared.callEvidence=std::move(calls);prepared.interproceduralLimited=recovery.limited;
    *output=std::move(prepared);return Status::success();
}
}
