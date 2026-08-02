#include "mint/loader/memory_map.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace mint {

void MemoryMap::addSegment(Address start, u64 size, ByteView data, u32 flags,
                           std::string name) {
    if (size == 0) return;

    // Refuse a segment whose address range wraps. A wrapped range would make
    // contains() nonsense and every bound check above it unsound, and it only
    // ever appears in hand-crafted files.
    if (start + size < start) return;

    MemorySegment segment;
    segment.start = start;
    segment.size = size;
    segment.data = data.size() > size ? data.subview(0, size) : data;
    segment.flags = flags;
    segment.name = std::move(name);
    segments_.push_back(std::move(segment));
    finalized_ = false;
}

void MemoryMap::finalize() {
    std::sort(segments_.begin(), segments_.end(),
              [](const MemorySegment& a, const MemorySegment& b) {
                  if (a.start != b.start) return a.start < b.start;
                  return a.size < b.size;
              });

    hasOverlaps_ = false;
    for (size_t i = 1; i < segments_.size(); ++i) {
        if (segments_[i].start < segments_[i - 1].end()) {
            hasOverlaps_ = true;
            break;
        }
    }

    if (segments_.empty()) {
        minAddress_ = 0;
        maxAddress_ = 0;
    } else {
        minAddress_ = segments_.front().start;
        maxAddress_ = 0;
        for (const MemorySegment& segment : segments_) {
            maxAddress_ = std::max(maxAddress_, segment.end());
        }
    }
    finalized_ = true;
}

const MemorySegment* MemoryMap::segmentAt(Address addr) const {
    if (segments_.empty()) return nullptr;

    if (!finalized_) {
        // A linear scan is wrong-but-correct here rather than silently using a
        // binary search on unsorted data.
        for (const MemorySegment& segment : segments_) {
            if (segment.contains(addr)) return &segment;
        }
        return nullptr;
    }

    // Last segment with start <= addr.
    auto it = std::upper_bound(segments_.begin(), segments_.end(), addr,
                               [](Address value, const MemorySegment& segment) {
                                   return value < segment.start;
                               });
    if (it == segments_.begin()) return nullptr;
    --it;

    if (it->contains(addr)) return &*it;

    // With overlapping segments the candidate found above may be a short one
    // sorted after a longer segment that does cover the address.
    if (hasOverlaps_) {
        while (it != segments_.begin()) {
            --it;
            if (it->contains(addr)) return &*it;
        }
    }
    return nullptr;
}

bool MemoryMap::isExecutable(Address addr) const {
    const MemorySegment* segment = segmentAt(addr);
    return segment != nullptr && segment->executable();
}

ByteView MemoryMap::viewAt(Address addr, u64 maxLength) const {
    const MemorySegment* segment = segmentAt(addr);
    if (segment == nullptr) return {};

    const u64 offset = addr - segment->start;
    if (offset >= segment->data.size()) return {};

    const u64 available = segment->data.size() - offset;
    return segment->data.subview(offset, std::min(available, maxLength));
}

bool MemoryMap::read(Address addr, void* out, size_t length) const {
    auto* dest = static_cast<u8*>(out);
    size_t done = 0;

    while (done < length) {
        const Address current = addr + done;
        const MemorySegment* segment = segmentAt(current);
        if (segment == nullptr) return false;

        const u64 offset = current - segment->start;
        const u64 chunk = std::min<u64>(length - done, segment->size - offset);

        // Split the chunk into the part backed by file bytes and the part that
        // is only address space (.bss, or a truncated segment), which reads as
        // zero exactly as it would at runtime.
        const u64 backed = offset < segment->data.size()
                               ? std::min(chunk, segment->data.size() - offset)
                               : 0;
        if (backed > 0) {
            std::memcpy(dest + done, segment->data.data() + offset,
                        static_cast<size_t>(backed));
        }
        if (chunk > backed) {
            std::memset(dest + done + backed, 0, static_cast<size_t>(chunk - backed));
        }
        done += static_cast<size_t>(chunk);
    }
    return true;
}

bool MemoryMap::readCString(Address addr, std::string* out, size_t maxLength) const {
    out->clear();
    const MemorySegment* segment = segmentAt(addr);
    if (segment == nullptr) return false;

    const u64 offset = addr - segment->start;
    if (offset >= segment->data.size()) return false;

    return segment->data.cString(offset, out, maxLength);
}

}  // namespace mint
