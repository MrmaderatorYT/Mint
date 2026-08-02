#include "mint/interp/state.h"

namespace mint {

InterpState::InterpState(Arch arch) { reset(arch); }

void InterpState::reset(Arch arch) {
    arch_ = arch;
    const size_t size = static_cast<size_t>(registerFileSize(arch));
    registerBytes_.assign(size, 0);
    registerKnown_.assign(size, false);
    temporaries_.clear();
    memory_.clear();
}

InterpValue InterpState::registerValue(u64 offset, u8 width) const {
    if (width == 0 || width > 8 || offset > registerBytes_.size() || width > registerBytes_.size() - offset) {
        return InterpValue::unknown(width);
    }
    u64 bits = 0;
    for (u8 i = 0; i < width; ++i) {
        if (!registerKnown_[offset + i]) return InterpValue::unknown(width);
        bits |= static_cast<u64>(registerBytes_[offset + i]) << (i * 8);
    }
    return InterpValue::concrete(bits, width);
}

void InterpState::setRegister(u64 offset, u64 bits, u8 width) {
    if (width == 0 || width > 8 || offset > registerBytes_.size() || width > registerBytes_.size() - offset) return;
    for (u8 i = 0; i < width; ++i) {
        registerBytes_[offset + i] = static_cast<u8>(bits >> (i * 8));
        registerKnown_[offset + i] = true;
    }
}

InterpValue InterpState::read(const Varnode& node) const {
    if (!node.valid()) return InterpValue::unknown();
    if (node.isConstant()) return InterpValue::concrete(node.offset, node.size);
    if (node.isRegister()) return registerValue(node.offset, node.size);
    if (node.isTemp()) {
        if (node.offset >= temporaries_.size()) return InterpValue::unknown(node.size);
        return temporaries_[node.offset];
    }
    return InterpValue::unknown(node.size);
}

void InterpState::write(const Varnode& node, const InterpValue& value) {
    if (!node.valid() || !node.size) return;
    if (node.isRegister()) {
        if (value.concreteLike()) setRegister(node.offset, value.bits, node.size);
        else if (node.offset <= registerBytes_.size() && node.size <= registerBytes_.size() - node.offset) {
            for (u8 i = 0; i < node.size; ++i) registerKnown_[node.offset + i] = false;
        }
    } else if (node.isTemp()) {
        if (node.offset >= temporaries_.size()) temporaries_.resize(node.offset + 1, InterpValue::unknown());
        temporaries_[node.offset] = value;
    }
}

}  // namespace mint
