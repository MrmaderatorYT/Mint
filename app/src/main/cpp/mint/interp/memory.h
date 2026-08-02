#pragma once

#include <unordered_map>

#include "mint/base/types.h"
#include "mint/interp/value.h"
#include "mint/loader/memory_map.h"

namespace mint {

/// Sparse, byte-addressed memory. Unknown bytes are different from zero: a
/// missing relocation or an uninitialised stack slot must not silently become a
/// concrete branch target.
class InterpMemory {
public:
    void clear();
    void map(const MemoryMap& image);

    void writeByte(Address address, u8 value);
    bool readByte(Address address, u8* value) const;
    void write(Address address, const InterpValue& value, u8 width);
    InterpValue read(Address address, u8 width) const;

    size_t knownByteCount() const { return bytes_.size(); }

private:
    std::unordered_map<Address, u8> bytes_;
};

}  // namespace mint
