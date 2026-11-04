#include "mint/session.h"
#include "mint/ir/normalize.h"
#include "mint/ssa/ssa_builder.h"
#include <map>

namespace mint {
MemoryFunctionResolver Session::decompilerMemoryFunctions() {
    // Scoped to one decompilation on the serialized Session worker. The model
    // owns immutable body snapshots, never a pointer into mutable discovery IR.
    struct Bodies {
        std::map<Address,std::shared_ptr<const SsaFunction>> functions;
        size_t values=0,instructions=0;
    };
    auto bodies=std::make_shared<Bodies>();
    return [this,bodies](Address target)->std::shared_ptr<const SsaFunction> {
        if(cancel_.load())return {};
        const auto found=bodies->functions.find(target);
        if(found!=bodies->functions.end())return found->second;
        if(bodies->functions.size()>=1024)return {};
        auto& result=bodies->functions[target];
        const auto* function=analyzer_.functionAt(target);
        if(!function || function->incomplete || function->instructions.size()>10000)return {};
        Lifter lifter;const auto mode=function->decodeArch==Arch::kUnknown?image_.arch():function->decodeArch;
        if(!lifter.open(mode).ok())return {};
        IrFunction ir;
        if(!lifter.liftFunction(*function,image_.memory(),&ir).ok() || !ir.verify().empty() || ir.insns.size()>50000)return {};
        normalizeRegisterAccesses(&ir);
        if(ir.insns.size()>100000)return {};
        auto ssa=std::make_shared<SsaFunction>();
        if(!buildSsa(ir,ssa.get()).ok() || !ssa->verify().empty())return {};
        if(ssa->values.size()>250000-bodies->values || ssa->insns.size()>250000-bodies->instructions)return {};
        bodies->values+=ssa->values.size();bodies->instructions+=ssa->insns.size();
        result=std::move(ssa);return result;
    };
}
}
