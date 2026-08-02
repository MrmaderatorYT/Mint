#include "mint/interp/memory.h"

#include <vector>

namespace mint {

void InterpMemory::clear() { bytes_.clear(); }

void InterpMemory::map(const MemoryMap& image) {
    clear();
    for (const MemorySegment& segment : image.segments()) {
        const u64 count = segment.data.size() < segment.size ? segment.data.size() : segment.size;
        for (u64 i = 0; i < count; ++i) {
            u8 byte = 0;
            if (segment.data.byteAt(i, &byte)) bytes_[segment.start + i] = byte;
        }
    }
}

void InterpMemory::writeByte(Address address, u8 value) { bytes_[address] = value; }

bool InterpMemory::readByte(Address address, u8* value) const {
    const auto it = bytes_.find(address);
    if (it == bytes_.end()) return false;
    *value = it->second;
    return true;
}

void InterpMemory::write(Address address, const InterpValue& value, u8 width) {
    if (!value.concreteLike()) return;
    for (u8 i = 0; i < width && i < 8; ++i) {
        writeByte(address + i, static_cast<u8>(value.bits >> (i * 8)));
    }
}

InterpValue InterpMemory::read(Address address, u8 width) const {
    if (width == 0 || width > 8) return InterpValue::unknown(width);
    u64 bits = 0;
    for (u8 i = 0; i < width; ++i) {
        u8 byte = 0;
        if (!readByte(address + i, &byte)) return InterpValue::unknown(width);
        bits |= static_cast<u64>(byte) << (i * 8);
    }
    return InterpValue::concrete(bits, width);
}

}  // namespace mint
