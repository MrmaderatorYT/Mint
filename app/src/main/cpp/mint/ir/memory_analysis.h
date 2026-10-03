#pragma once

#include <string>
#include <vector>
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
    bool exact() const {return kind!=MemoryBaseKind::kUnknown;}
};
struct MemoryAccess {
    u32 instruction = 0;
    MemoryAddress address;
    u8 width = 0;
    bool store = false;
    u32 memoryVersion = 0;
    u32 reachingStore = kNoValue;
    // Facts are killed by every possibly overlapping/unknown-alias write.
    u32 invalidatedDefinitions = 0;
};
struct MemoryAnalysis {
    std::vector<MemoryAddress> values;
    std::vector<MemoryAccess> accesses;
    std::vector<u32> accessByInstruction;
    u32 exactDependencies = 0;
    u32 callBarriers = 0;
    u32 unknownWrites = 0;
    u32 unresolvedAccesses = 0;
    std::string toText(const SsaFunction& function) const;
};

// General memory sidecar: absolute globals, entry-SP-relative slots, and exact
// SSA symbolic base + constant displacement. Distinct symbolic bases MAY alias;
// equality is propagated through copies/equal phis, not guessed from register
// names. This is evidence only: no stores are removed and loads are not folded.
Status analyzeMemory(const SsaFunction& function, MemoryAnalysis* result);
bool memoryMayAlias(const MemoryAddress& a,u8 aWidth,const MemoryAddress& b,u8 bWidth);
} // namespace mint
