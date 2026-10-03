#pragma once

#include <string>
#include <vector>

#include "mint/base/status.h"
#include "mint/ssa/ssa_function.h"

namespace mint {

enum class StackValueKind : u8 { kUnknown, kConstant, kEntrySpRelative };

struct StackValue {
    StackValueKind kind = StackValueKind::kUnknown;
    // Signed byte displacement from the stack pointer on function entry, or
    // the constant's bit pattern for kConstant. Unknown is never offset zero.
    i64 offset = 0;
    bool mayBeStack = false;
    bool exact() const { return kind == StackValueKind::kEntrySpRelative; }
};

struct StackSlot {
    i64 offset = 0;
    u8 width = 0;
    std::string name;
    bool overlaps = false;
    bool initializedBeforeEveryRead = false;
    bool promoted = false;
};

struct StackAccess {
    u32 instruction = 0;
    u32 slot = 0;
    bool store = false;
    // Zero is an unknown/joined/initial memory version; a concrete version is
    // the defining store instruction index + 1. No folding is implied.
    u32 memoryVersion = 0;
    u32 reachingStore = kNoValue;
    bool initialized = false;
};

struct StackAnalysis {
    std::vector<StackValue> values;
    std::vector<StackSlot> slots;
    std::vector<StackAccess> accesses;
    // Index into accesses, or kNoValue for a non-exact/non-memory operation.
    std::vector<u32> accessByInstruction;
    SsaId entryStackValue = kNoValue;
    u32 barriers = 0;
    u32 unknownWrites = 0;
    u32 unknownAccesses = 0;
    u32 unknownStackAccesses = 0;
    u32 storeLoadDependencies = 0;
    bool escapedStackAddress = false;
};

// A bounded, conservative register-SSA affine analysis plus exact stack memory
// reaching-definition analysis. Equal SP-relative phi inputs remain exact;
// conflicting inputs, unsupported arithmetic and aliasing barriers become
// unknown. Partial overlapping writes invalidate dependencies. Calls and
// unknown-effect intrinsics conservatively invalidate all stack memory facts.
// Only non-overlapping negative-offset leaf slots with no escapes/barriers and
// writes before every read can be promoted into independent source C locals.
Status analyzeStackMemory(const SsaFunction& function, StackAnalysis* result);

}  // namespace mint
