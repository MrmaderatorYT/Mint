#pragma once

#include <string>
#include <vector>

#include "mint/base/status.h"
#include "mint/interp/state.h"
#include "mint/ir/ir_function.h"

namespace mint {

struct InterpCall {
    Address target = kNoAddress;
    std::vector<InterpValue> arguments;
    Address address = 0;
};

struct InterpResult {
    bool returned = false;
    bool stoppedOnCall = false;
    bool hitUnknownBranch = false;
    bool hitCycleLimit = false;
    InterpValue returnValue = InterpValue::unknown();
    std::vector<InterpCall> calls;
    std::string stopReason;
};

struct InterpOptions {
    u32 maxSteps = 100000;
    bool stopOnCall = false;
    bool executeIntrinsics = false;
    // Explicit assumption: IEEE32/64 nearest-even, no FTZ/default-NaN/traps.
    // Disabled by default because target FPCR/MXCSR are not generally known.
    bool assumeDefaultFloatingPoint = false;
};

Status executeIr(const IrFunction& function, InterpState* state,
                 const InterpOptions& options, InterpResult* result);

}  // namespace mint
