#pragma once

#include "mint/interp/executor.h"

namespace mint {

/// Small façade used by native callers and JNI adapters. It owns the execution
/// state but never owns an IR function, which keeps analysis results cacheable.
class Emulator {
public:
    explicit Emulator(Arch arch = Arch::kUnknown) : state_(arch) {}

    InterpState& state() { return state_; }
    const InterpState& state() const { return state_; }
    Status run(const IrFunction& function, const InterpOptions& options, InterpResult* result) {
        return executeIr(function, &state_, options, result);
    }

private:
    InterpState state_;
};

}  // namespace mint
