#pragma once

#include <vector>

#include "mint/base/types.h"
#include "mint/interp/memory.h"
#include "mint/ir/registers.h"
#include "mint/ir/varnode.h"

namespace mint {

class InterpState {
public:
    explicit InterpState(Arch arch = Arch::kUnknown);

    void reset(Arch arch);
    Arch arch() const { return arch_; }

    InterpValue read(const Varnode& node) const;
    void write(const Varnode& node, const InterpValue& value);

    void setRegister(u64 offset, u64 bits, u8 width);
    void setRegisterWide(u64 offset,u64 low,u64 high,u8 width=16);
    InterpValue registerValue(u64 offset, u8 width) const;

    InterpMemory& memory() { return memory_; }
    const InterpMemory& memory() const { return memory_; }
    std::vector<InterpValue>& temporaries() { return temporaries_; }
    const std::vector<InterpValue>& temporaries() const { return temporaries_; }

private:
    Arch arch_ = Arch::kUnknown;
    std::vector<u8> registerBytes_;
    std::vector<bool> registerKnown_;
    std::vector<InterpValue> temporaries_;
    InterpMemory memory_;
};

}  // namespace mint
