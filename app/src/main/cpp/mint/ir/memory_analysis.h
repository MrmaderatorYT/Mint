#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include "mint/base/status.h"
#include "mint/ssa/ssa_function.h"

namespace mint {
enum class MemoryBaseKind : u8 { kUnknown, kAbsolute, kEntryStack, kSymbolic };
struct MemoryAddress {
    MemoryBaseKind kind = MemoryBaseKind::kUnknown;
    SsaId base = kNoValue;
    u64 absolute = 0;
    i64 offset = 0;
    u8 pointerWidth = 0;
    bool exact() const {return kind==MemoryBaseKind::kAbsolute||kind==MemoryBaseKind::kEntryStack||kind==MemoryBaseKind::kSymbolic;}
};
struct MemoryAccess {
    u32 instruction = 0;
    MemoryAddress address;
    u8 width = 0;
    bool store = false;
    u32 memoryVersion = 0;
    u32 reachingStore = kNoValue;
    u32 reachingPhi = kNoValue;
    SsaId reachingValue = kNoValue;
    // Facts are killed by every possibly overlapping/unknown-alias write.
    u32 invalidatedDefinitions = 0;
};
// Bounded all-path reaching-definition merge for one exact byte range. This
// sidecar does not insert register phis, rewrite loads, or delete stores.
struct MemoryPhiEvidence {
    u32 version = 0;
    MemoryAddress address;
    u8 width = 0;
    std::vector<u32> stores;
    SsaId agreedValue = kNoValue;
};
// A resolver supplies immutable, verified local machine-code body snapshots.
// Missing/external targets stay unknown; linkage names and declarations alone
// never establish purity. The resolver must refer to the same image snapshot
// throughout one analysis/decompilation request.
using MemoryFunctionResolver=std::function<std::shared_ptr<const SsaFunction>(Address)>;
struct MemoryWriteEffect {MemoryAddress address;u8 width=0;};
struct MemoryCallEffect {
    u32 instruction=0;
    Address target=kNoAddress;
    bool complete=false;
    std::vector<MemoryWriteEffect> writes;
};
struct MemoryDependencyBinding {
    std::shared_ptr<const SsaFunction> function;
    u64 fingerprint=0;
};
struct MemoryAnalysis {
    std::vector<MemoryAddress> values;
    std::vector<MemoryAccess> accesses;
    std::vector<u32> accessByInstruction;
    std::vector<MemoryPhiEvidence> phis;
    std::vector<MemoryCallEffect> calls;
    std::vector<MemoryDependencyBinding> dependencies;
    u32 exactDependencies = 0;
    u32 agreedValueDependencies = 0;
    u32 callBarriers = 0;
    u32 unknownWrites = 0;
    u32 unresolvedAccesses = 0;
    u32 readOnlyCalls=0;
    u32 selectiveCalls=0;
    // Transient caller/dependency binding only; no serialized facts or reuse
    // after any bound function's memory semantics change.
    const SsaFunction* analyzedFunction = nullptr;
    u64 functionFingerprint = 0;
    bool matches(const SsaFunction& function) const;
    std::string toText(const SsaFunction& function) const;
};

// General memory sidecar: absolute globals, entry-SP-relative slots, and exact
// SSA symbolic base + constant displacement. Distinct symbolic bases MAY alias;
// equality is propagated through copies/equal phis, not guessed from register
// names. CFG joins retain at most 32 possible reaching stores per exact range.
// A reaching value is proven only when every reachable incoming path defines
// the same bytes with the same SSA value. Unknown aliases/barriers kill facts.
// This is evidence only: no stores are removed and loads are not folded.
Status analyzeMemory(const SsaFunction& function, MemoryAnalysis* result);
// Optional bounded native-body effects retain facts across verified local
// direct calls only when all possible ordinary-memory writes are modeled.
// Physical live-in register + constant offsets are instantiated on all paths;
// missing bodies, recursion, unknown effects and resource exhaustion stay
// barriers. x86 includes the implicit return-slot write. No heap allocation,
// ownership or private-frame/disjointness assumption follows from this model.
Status analyzeMemory(const SsaFunction& function, MemoryAnalysis* result,
                     const MemoryFunctionResolver& functions);
bool memoryMayAlias(const MemoryAddress& a,u8 aWidth,const MemoryAddress& b,u8 bWidth);
} // namespace mint
