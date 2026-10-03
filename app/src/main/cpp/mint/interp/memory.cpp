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
    if(!width || width>16)return;
    for (u8 i = 0; i < width; ++i) {
        if(!value.concreteLike())bytes_.erase(address+i);
        else writeByte(address + i, static_cast<u8>(i<8 ? value.bits >> (i * 8) : value.highBits>>((i-8)*8)));
    }
}

InterpValue InterpMemory::read(Address address, u8 width) const {
    if (width == 0 || width > 16) return InterpValue::unknown(width);
    u64 bits = 0,high=0;
    for (u8 i = 0; i < width; ++i) {
        u8 byte = 0;
        if (!readByte(address + i, &byte)) return InterpValue::unknown(width);
        if(i<8)bits |= static_cast<u64>(byte) << (i * 8);else high|=static_cast<u64>(byte)<<((i-8)*8);
    }
    return InterpValue::wide(bits,high,width);
}

}  // namespace mint
