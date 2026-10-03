#include "mint/analysis/indirect_flow.h"
#include "mint/disasm/disassembler.h"

#include <algorithm>
#include <limits>
#include <map>

namespace mint {
namespace {
enum Provenance : u32 { kLiteral=1,kPhi=2,kArithmetic=4,kReadOnly=8,kRelocation=16,kSelection=32,kInterworking=64 };
struct Fact {
    std::vector<u64> values;
    std::vector<IndirectFlowDependency> dependencies;
    u32 provenance=0;
    bool unknown=false;
};
u64 mask(u8 width){return width==8?~u64{0}:((u64{1}<<(width*8))-1);}
i64 signedValue(u64 value,u8 width){const u64 bit=u64{1}<<(width*8-1);return static_cast<i64>((value^bit)-bit);}
bool same(const Fact& a,const Fact& b){
    if(a.values!=b.values || a.unknown!=b.unknown || a.provenance!=b.provenance || a.dependencies.size()!=b.dependencies.size())return false;
    for(size_t i=0;i<a.dependencies.size();++i)if(a.dependencies[i].start!=b.dependencies[i].start || a.dependencies[i].end!=b.dependencies[i].end)return false;
    return true;
}
class Recovery {
public:
    Recovery(const ElfImage& image,const SsaFunction& function,const IndirectFlowOptions& options)
        :image_(image),f_(function),o_(options),facts_(function.values.size()){
        for(const auto& relocation:image.relocations())relocations_.emplace(relocation.offset,&relocation);
    }
    Status run(IndirectFlowReport* output);
private:
    const ElfImage& image_;const SsaFunction& f_;const IndirectFlowOptions& o_;
    std::vector<Fact> facts_;
    std::map<Address,const ElfRelocation*> relocations_;
    size_t work_=0;bool workLimit_=false;
    bool work(){if(work_>=o_.maxWork){workLimit_=true;return false;}++work_;return true;}
    void bound(Fact* fact){
        std::sort(fact->values.begin(),fact->values.end());fact->values.erase(std::unique(fact->values.begin(),fact->values.end()),fact->values.end());
        if(fact->values.size()>o_.maxSetSize){fact->values.resize(o_.maxSetSize);fact->unknown=true;}
        std::sort(fact->dependencies.begin(),fact->dependencies.end(),[](const auto& a,const auto& b){return a.start<b.start || (a.start==b.start && a.end<b.end);});
        std::vector<IndirectFlowDependency> merged;
        for(const auto& dep:fact->dependencies){if(!merged.empty() && merged.back().end>=dep.start)merged.back().end=std::max(merged.back().end,dep.end);else merged.push_back(dep);}
        if(merged.size()>o_.maxDependencies){merged.resize(o_.maxDependencies);fact->unknown=true;}
        fact->dependencies=std::move(merged);
    }
    void evidence(Fact* into,const Fact& from){
        into->unknown|=from.unknown;into->provenance|=from.provenance;
        into->dependencies.insert(into->dependencies.end(),from.dependencies.begin(),from.dependencies.end());
    }
    Fact value(SsaId id) const {return id<facts_.size()?facts_[id]:Fact{{},{},0,true};}
    Fact evaluate(SsaId id);
    Fact operation(const SsaInsn& instruction,u8 width);
    bool readOnly(Address at,u8 width,u64* output,bool* relocated);
    bool binary(MintOp operation,u64 a,u64 b,u8 inputWidth,u8 outputWidth,u64* result);
};
bool Recovery::readOnly(Address address,u8 width,u64* output,bool* relocated){
    if(!width || width>8 || address>std::numeric_limits<Address>::max()-width)return false;
    const auto* segment=image_.memory().segmentAt(address);
    if(!segment || segment->writable() || image_.memory().hasOverlaps() || image_.memory().viewAt(address,width).size()!=width)return false;
    *relocated=false;
    const auto relocation=relocations_.find(address);
    if(width==image_.pointerSize() && relocation!=relocations_.end()){
        const auto& record=*relocation->second;
        if(!record.symbolName.empty()){
            const auto* symbol=image_.findSymbol(record.symbolName);
            if(!symbol || symbol->undefined)return false;
        }
        Address target=0;
        if(image_.resolvePointer(address,&target)){*output=target&mask(width);*relocated=true;return true;}
        // A zero-valued RELATIVE slot can legitimately target VA zero. Imports
        // were excluded above; the ordinary raw read retains this exact value.
    }
    u64 result=0;if(!image_.memory().read(address,&result,width))return false;
    *output=result&mask(width);return true;
}
bool Recovery::binary(MintOp op,u64 a,u64 b,u8 width,u8 outputWidth,u64* result){
    a&=mask(width);b&=mask(width);u64 value=0;const unsigned bits=width*8;
    switch(op){
        case MintOp::kAdd:value=a+b;break;case MintOp::kSub:value=a-b;break;case MintOp::kMul:value=a*b;break;
        case MintOp::kAnd:value=a&b;break;case MintOp::kOr:value=a|b;break;case MintOp::kXor:value=a^b;break;
        case MintOp::kEqual:value=a==b;break;case MintOp::kNotEqual:value=a!=b;break;
        case MintOp::kLessU:value=a<b;break;case MintOp::kLessEqU:value=a<=b;break;
        case MintOp::kLessS:value=signedValue(a,width)<signedValue(b,width);break;
        case MintOp::kLessEqS:value=signedValue(a,width)<=signedValue(b,width);break;
        case MintOp::kShl:value=b>=bits?0:a<<b;break;case MintOp::kShrU:value=b>=bits?0:a>>b;break;
        case MintOp::kShrS:{const i64 s=signedValue(a,width);value=b>=bits?(s<0?~u64{0}:0):static_cast<u64>(s>>b);break;}
        case MintOp::kRotL:case MintOp::kRotR:{const unsigned shift=static_cast<unsigned>(b%bits);value=!shift?a:(op==MintOp::kRotL?(a<<shift)|(a>>(bits-shift)):(a>>shift)|(a<<(bits-shift)));break;}
        case MintOp::kDivU:if(!b)return false;value=a/b;break;case MintOp::kRemU:if(!b)return false;value=a%b;break;
        case MintOp::kDivS:case MintOp::kRemS:{const i64 sa=signedValue(a,width),sb=signedValue(b,width);if(!sb)return false;if(sa==std::numeric_limits<i64>::min() && sb==-1)return false;value=static_cast<u64>(op==MintOp::kDivS?sa/sb:sa%sb);break;}
        default:return false;
    }
    *result=value&mask(outputWidth);return true;
}
Fact Recovery::operation(const SsaInsn& instruction,u8 width){
    if(instruction.dead)return Fact{{},{},0,true};
    Fact a=value(instruction.use[0]),b=value(instruction.use[1]),c=value(instruction.use[2]),out;
    const auto sourceWidth=[&](SsaId id){return id<f_.values.size()?f_.values[id].storage.size:u8{0};};
    if(instruction.op==MintOp::kSelect){
        const bool yes=a.unknown || std::any_of(a.values.begin(),a.values.end(),[](u64 v){return v!=0;});
        const bool no=a.unknown || std::find(a.values.begin(),a.values.end(),0)!=a.values.end();
        // A live-in condition can select either of two completely known sets;
        // the union is still complete. Condition dependencies are retained.
        out.dependencies=a.dependencies;out.provenance=a.provenance|kSelection;
        if(yes){evidence(&out,b);out.values.insert(out.values.end(),b.values.begin(),b.values.end());}
        if(no){evidence(&out,c);out.values.insert(out.values.end(),c.values.begin(),c.values.end());}
        bound(&out);return out;
    }
    if(instruction.op==MintOp::kLoad){
        evidence(&out,a);out.provenance|=kReadOnly;
        for(u64 address:a.values){if(!work()){out.unknown=true;break;}u64 loaded=0;bool relocated=false;
            if(address<=std::numeric_limits<Address>::max()-width)out.dependencies.push_back({address,address+width});
            if(!readOnly(address,width,&loaded,&relocated)){out.unknown=true;continue;}
            out.values.push_back(loaded);if(relocated)out.provenance|=kRelocation;}
        bound(&out);return out;
    }
    switch(instruction.op){
        case MintOp::kCopy:case MintOp::kZeroExt:case MintOp::kSignExt:case MintOp::kTrunc:case MintOp::kNeg:case MintOp::kNot:{
            const u8 inputWidth=sourceWidth(instruction.use[0]);if(!inputWidth || inputWidth>8)return Fact{{},{},0,true};
            evidence(&out,a);out.provenance|=kArithmetic;
            for(u64 v:a.values){v&=mask(inputWidth);if(instruction.op==MintOp::kSignExt)v=static_cast<u64>(signedValue(v,inputWidth));else if(instruction.op==MintOp::kNeg)v=0-v;else if(instruction.op==MintOp::kNot)v=~v;out.values.push_back(v&mask(width));}
            bound(&out);return out;
        }
        case MintOp::kCall:case MintOp::kCallInd:case MintOp::kIntrinsic:case MintOp::kUndefined:return Fact{{},{},0,true};
        default:break;
    }
    const u8 inputWidth=sourceWidth(instruction.use[0]);
    if(!inputWidth || inputWidth>8 || !sourceWidth(instruction.use[1]) || sourceWidth(instruction.use[1])>8)return Fact{{},{},0,true};
    evidence(&out,a);evidence(&out,b);out.provenance|=kArithmetic;
    for(u64 left:a.values){for(u64 right:b.values){if(!work()){out.unknown=true;break;}u64 result=0;if(binary(instruction.op,left,right,inputWidth,width,&result))out.values.push_back(result);else out.unknown=true;}if(workLimit_)break;}
    bound(&out);return out;
}
Fact Recovery::evaluate(SsaId id){
    const auto& value=f_.values[id];const u8 width=value.storage.size;
    if(!width || width>8)return Fact{{},{},0,true};
    if(value.def==SsaDef::kConstant)return Fact{{value.storage.offset&mask(width)},{},kLiteral,false};
    if(value.def==SsaDef::kEntry)return Fact{{},{},0,true};
    if(value.def==SsaDef::kPhi){
        if(value.defIndex>=f_.phis.size() || f_.phis[value.defIndex].dest!=id || f_.phis[value.defIndex].dead)return Fact{{},{},0,true};
        Fact out;out.provenance=kPhi;
        for(SsaId argument:f_.phis[value.defIndex].args){const auto fact=this->value(argument);evidence(&out,fact);out.values.insert(out.values.end(),fact.values.begin(),fact.values.end());}
        bound(&out);return out;
    }
    if(value.def!=SsaDef::kInsn || value.defIndex>=f_.insns.size() || f_.insns[value.defIndex].dest!=id)return Fact{{},{},0,true};
    return operation(f_.insns[value.defIndex],width);
}
Status Recovery::run(IndirectFlowReport* output){
    IndirectFlowReport report;report.functionEntry=f_.entry;
    bool changed=true;
    for(size_t iteration=0;iteration<o_.maxIterations && changed;++iteration){
        changed=false;
        for(SsaId id=0;id<facts_.size();++id){if(!work())break;Fact next=evaluate(id);if(!same(next,facts_[id])){facts_[id]=std::move(next);changed=true;}}
        report.iterations=iteration+1;
        if(workLimit_)break;
    }
    report.converged=!changed && !workLimit_;
    // A seedless cyclic component is not a proven empty set. Promote bottom to
    // unknown, then propagate it into mixed known/unknown phi paths.
    bool seededUnknown=false;
    if(report.converged)for(auto& fact:facts_)if(fact.values.empty() && !fact.unknown){fact.unknown=true;seededUnknown=true;}
    if(seededUnknown){
        changed=true;
        while(changed && report.iterations<o_.maxIterations){
            changed=false;
            for(SsaId id=0;id<facts_.size();++id){if(!work())break;Fact next=evaluate(id);if(next.values.empty() && !next.unknown)next.unknown=true;if(!same(next,facts_[id])){facts_[id]=std::move(next);changed=true;}}
            ++report.iterations;
            if(workLimit_)break;
        }
        report.converged=!changed && !workLimit_;
    }
    for(const auto& instruction:f_.insns){
        if(instruction.dead || (instruction.op!=MintOp::kBranchInd && instruction.op!=MintOp::kCallInd))continue;
        if(report.sites.size()>=o_.maxSites)return Status::error(ErrorCode::kTooLarge,"too many indirect-flow sites");
        IndirectFlowSite site;site.address=instruction.address;site.call=instruction.op==MintOp::kCallInd;
        Fact fact=value(instruction.use[0]);Fact tagged=fact;
        const bool arm=f_.arch==Arch::kArm32 || f_.arch==Arch::kThumb;
        if(arm && instruction.use[0]<f_.values.size()){
            const auto& definition=f_.values[instruction.use[0]];
            if(definition.def==SsaDef::kInsn && definition.defIndex<f_.insns.size()){
                const auto& operation=f_.insns[definition.defIndex];
                if(operation.op==MintOp::kAnd){
                    const Fact left=value(operation.use[0]),right=value(operation.use[1]);
                    if(right.values.size()==1 && right.values.front()==(mask(image_.pointerSize())&~u64{1}) && !right.unknown){tagged=left;fact.provenance|=kInterworking;}
                    else if(left.values.size()==1 && left.values.front()==(mask(image_.pointerSize())&~u64{1}) && !left.unknown){tagged=right;fact.provenance|=kInterworking;}
                }
            }
        }
        site.complete=report.converged && !fact.unknown && !fact.values.empty();
        for(u64 raw:tagged.values){
            const Address address=image_.canonicalAddress(raw);const Arch mode=arm?((raw&1)?Arch::kThumb:Arch::kArm32):image_.architectureAt(address);
            ArchitectureDescription description;
            if(!image_.memory().isExecutable(address) || !architectureDescription(mode,&description) || address%description.instructionAlignment!=0){site.complete=false;continue;}
            site.targets.push_back({address,raw,mode});
        }
        std::sort(site.targets.begin(),site.targets.end(),[](const auto& a,const auto& b){return a.address<b.address || (a.address==b.address && static_cast<u8>(a.decodeArch)<static_cast<u8>(b.decodeArch));});
        site.targets.erase(std::unique(site.targets.begin(),site.targets.end(),[](const auto& a,const auto& b){return a.address==b.address && a.decodeArch==b.decodeArch;}),site.targets.end());
        for(size_t n=1;n<site.targets.size();++n)if(site.targets[n-1].address==site.targets[n].address && site.targets[n-1].decodeArch!=site.targets[n].decodeArch)site.complete=false;
        if(site.targets.empty())site.complete=false;
        site.dependencies=fact.dependencies;
        for(const auto pair:{std::pair<u32,const char*>{kLiteral,"constant"},{kPhi,"phi finite-set union"},{kArithmetic,"width-correct address arithmetic"},{kReadOnly,"immutable file-backed load"},{kRelocation,"loader relocation resolution"},{kSelection,"bounded select"},{kInterworking,"ARM interworking pointer tag"}})
            if(fact.provenance&pair.first)site.provenance.emplace_back(pair.second);
        site.confidence=site.complete?IndirectFlowConfidence::kProven:(site.targets.empty()?IndirectFlowConfidence::kUnknown:IndirectFlowConfidence::kPartial);
        site.reason=site.complete?"all paths have bounded proven executable targets":(!report.converged?"finite-set work limit reached":"unknown path, mutable memory, unsupported operation or invalid target");
        report.sites.push_back(std::move(site));
    }
    // Register SSA deliberately does not invent clobbers for unmodeled machine
    // instructions. A target definition surviving such an intrinsic is not a
    // proof of the runtime register value. Likewise an unresolved branch can
    // introduce predecessors omitted from this candidate CFG. Keep observations
    // as partial evidence until both the semantics and CFG are closed.
    bool opaque=false,unclosed=false;
    for(const auto& instruction:f_.insns)if(!instruction.dead){
        opaque|=instruction.op==MintOp::kIntrinsic || instruction.op==MintOp::kUndefined;
        if(instruction.op==MintOp::kCondBranch){const auto target=value(instruction.use[1]);if(target.unknown || target.values.empty())unclosed=true;}
    }
    for(const auto& site:report.sites)if(!site.call && !site.complete)unclosed=true;
    if(opaque || unclosed)for(auto& site:report.sites)if(site.complete){
        site.complete=false;site.confidence=IndirectFlowConfidence::kPartial;
        site.reason=opaque?"unmodeled side effects may invalidate reaching SSA registers":"unresolved control flow may introduce unknown reaching predecessors";
    }
    *output=std::move(report);return Status::success();
}
}

Status recoverIndirectFlow(const ElfImage& image,const SsaFunction& function,IndirectFlowReport* output,const IndirectFlowOptions& options){
    if(!output || !image.loaded())return Status::error(ErrorCode::kBadFormat,"indirect flow requires a loaded image and output");
    if(options.maxSetSize==0 || options.maxSetSize>256 || options.maxDependencies==0 || options.maxDependencies>4096 ||
       options.maxIterations==0 || options.maxIterations>4096 || options.maxWork==0 || function.values.size()>options.maxValues || function.insns.size()>options.maxInstructions ||
       function.values.size()>4000000 || function.insns.size()>4000000)return Status::error(ErrorCode::kTooLarge,"indirect-flow bounds exceeded");
    for(const auto& instruction:function.insns)for(SsaId id:instruction.use)if(id!=kNoValue && id>=function.values.size())
        return Status::error(ErrorCode::kBadFormat,"indirect-flow SSA operand is out of bounds");
    for(const auto& phi:function.phis){if(phi.args.size()>4000000)return Status::error(ErrorCode::kTooLarge,"indirect-flow phi bounds exceeded");for(SsaId id:phi.args)if(id>=function.values.size())return Status::error(ErrorCode::kBadFormat,"indirect-flow phi operand is out of bounds");}
    return Recovery(image,function,options).run(output);
}
}  // namespace mint
