#include "mint/session.h"
#include "mint/ir/normalize.h"
#include "mint/ssa/ssa_builder.h"
#include <sstream>
#include "mint/analysis/abi_model.h"

namespace mint {
std::string Session::abiText(Address function) const {
    const auto prototype=prototypeAt(function);if(!prototype.valid())return "No authoritative prototype at this function. Set a prototype or import debug/signature information first.\n";
    AbiModel model;const auto status=buildAbiModel(image_.architectureAt(function),prototype,&model,[this](const std::string& type,DataTypeLayout* layout){return program_.types().resolve(type,layout);});
    return status.ok()?model.toText():status.toString();
}
std::string Session::interproceduralText() {
    if(!analyzed_ || isDexLike())return "Prototype inference requires an analyzed native Program.\n";
    if(image_.format()==ImageFormat::kPe64)return "Authoritative Windows prototypes have an explicit ABI storage model (see Function ABI storage). Automatic call-graph inference currently uses the non-Windows register constraint engine; it is deliberately not applied to PE.\n";
    size_t excluded=0;
    if(!prototypeEvidenceBuilt_) {
        // Retain stable borrowed SSA addresses, and cap the whole program's
        // allocation before constructing a second analysis representation.
        std::vector<std::unique_ptr<SsaFunction>> owned;
        std::vector<const SsaFunction*> functions;
        std::map<Address,UserPrototype> authoritative;
        std::vector<IndirectFlowReport> indirect;
        Lifter lifter;size_t values=0,instructions=0;
        for(const auto& function:analyzer_.functions()) {
            if(cancel_.load())return "Prototype inference cancelled.\n";
            if(functions.size()>=2048 || function.instructions.size()>50000){++excluded;continue;}
            const auto mode=function.decodeArch==Arch::kUnknown?image_.arch():function.decodeArch;
            if(!lifter.ready() || lifter.arch()!=mode)if(!lifter.open(mode).ok()){++excluded;continue;}
            IrFunction ir;if(!lifter.liftFunction(function,image_.memory(),&ir).ok() || !ir.verify().empty()){++excluded;continue;}
            normalizeRegisterAccesses(&ir);auto ssa=std::make_unique<SsaFunction>();
            if(ir.insns.size()>200000 || !buildSsa(ir,ssa.get()).ok() || !ssa->verify().empty()){++excluded;continue;}
            if(values+ssa->values.size()>250000 || instructions+ssa->insns.size()>250000){++excluded;continue;}
            values+=ssa->values.size();instructions+=ssa->insns.size();
            IndirectFlowReport report;if(recoverIndirectFlow(image_,*ssa,&report).ok())indirect.push_back(std::move(report));
            const auto prototype=prototypeAt(function.entry);if(prototype.valid())authoritative[function.entry]=prototype;
            functions.push_back(ssa.get());owned.push_back(std::move(ssa));
        }
        // Include imported direct-call declarations even without a local body.
        for(const auto& function:analyzer_.functions())for(Address target:function.callees) {
            const auto declaration=prototypeAt(target);if(declaration.valid())authoritative[target]=declaration;
        }
        InterproceduralPrototypeOptions options;options.maxValues=250000;options.maxInstructions=250000;
        const auto status=inferInterproceduralPrototypes(functions,authoritative,indirect,&prototypeEvidence_,options);
        if(!status.ok())return status.toString();prototypeEvidenceExcluded_=excluded;prototypeEvidenceBuilt_=true;
    }
    std::ostringstream text;text<<"Call-graph prototype constraints; iterations="<<prototypeEvidence_.iterations<<" converged="<<(prototypeEvidence_.converged?"yes":"no")<<"\n";
    text<<"Unknown argument counts, stack arguments and absent results are not fabricated as signatures. Authoritative user/DWARF/library declarations win.\n";
    if(prototypeEvidenceExcluded_)text<<prototypeEvidenceExcluded_<<" functions excluded by lifting/resource limits.\n";
    auto scalar=[&](const PrototypeScalarEvidence& evidence) {
        if(evidence.width)text<<static_cast<unsigned>(evidence.width)*8<<"-bit";else text<<"unknown width";
        if(evidence.pointer)text<<" address/pointer evidence";
        for(const auto& provenance:evidence.provenance)text<<"; "<<provenance;
    };
    for(const auto& function:prototypeEvidence_.functions) {
        text<<"\n0x"<<std::hex<<function.entry<<std::dec<<' '<<displayNameAt(function.entry)<<" ["<<(function.authoritative?"authoritative":"inferred constraints")<<"]\n";
        text<<"  result: ";if(function.returnsVoid)text<<"declared void";else scalar(function.result);text<<'\n';
        for(size_t i=0;i<function.parameters.size();++i){text<<"  ABI argument "<<i<<": ";scalar(function.parameters[i]);text<<'\n';}
        if(text.tellp()>1024*1024){text<<"\nReport output limit reached.\n";break;}
    }
    return text.str();
}
} // namespace mint
