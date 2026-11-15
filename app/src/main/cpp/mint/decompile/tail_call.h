#pragma once

#include "mint/analysis/abi_model.h"
#include "mint/ir/memory_analysis.h"

namespace mint {
struct TailCallContract {
    UserPrototype caller,callee;
    AbiModel callerAbi,calleeAbi;
};
// A source call/return is permitted only for matching authoritative SysV64
// scalar GP declarations. This contract says nothing about machine frame proof.
Status buildTailCallContract(Arch arch,ByteOrder order,const UserPrototype& caller,
    const UserPrototype& callee,const AbiTypeResolver& layouts,TailCallContract* out);
bool validateTailCallInputs(const SsaFunction& function,const SsaInsn& instruction,
    const TailCallContract& contract,const MemoryAnalysis* memory);
}
