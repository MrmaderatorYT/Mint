#pragma once

#include "mint/analysis/code_map.h"
#include "mint/analysis/function.h"
#include "mint/analysis/indirect_flow.h"

namespace mint {
struct X86SwitchTable {
    ResolvedIndirectJump jump;
    Address guard=0;
    bool fullyDiscovered=false;
    std::vector<IndirectFlowDependency> dependencies;
};
struct X86SwitchRecoveryOptions {
    size_t maxEntries=256, maxInstructions=4096, maxSites=64, maxBlocks=1024,
           maxWork=1000000;
};
// Narrow ELF64/x86-64 PIC signed-rel32 switch recognizer. A native unsigned
// CMP/JA or CMP/JBE guard must directly enter the sole-predecessor dispatcher.
// A 32-bit guard needs an explicit 32-bit copy after CMP or inherently
// zero-extended index defined in the guard block by a supported instruction.
// A 64-bit guard needs the unchanged index. Every table byte is uniquely
// mapped, immutable and file backed; targets are independently decoded.
// A result with fullyDiscovered=false is an INTERNAL DISCOVERY PROPOSAL only:
// it must not complete a CFG or authorize exported metadata. Re-run after all
// proposed case bodies/edges have been discovered. fullyDiscovered requires
// complete provisional function coverage, exact owned targets and represented
// switch edges, and rejects other unresolved indirect jumps and guard bypasses.
// Function.tailCalls must be fresh native-state proofs from CodeAnalyzer, never
// cache input. Only those exact unconditional exits may leave the owned CFG.
// Results are transactional on malformed/bounded-resource failure.
Status recoverX86RelativeSwitches(const ElfImage& image,const CodeMap& code,
    const Function& function,std::vector<X86SwitchTable>* output,
    const X86SwitchRecoveryOptions& options={});
}
