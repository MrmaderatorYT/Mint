#pragma once

#include <string>
#include <vector>

#include "mint/base/byte_view.h"
#include "mint/base/types.h"

namespace mint {

enum MemoryFlags : u32 {
    kMemRead = 1u << 0,
    kMemWrite = 1u << 1,
    kMemExec = 1u << 2,
};

/// One contiguous run of virtual address space backed by file bytes.
///
/// `size` can exceed `data.size()`: .bss occupies address space with no file
/// content behind it, and a truncated file can leave a segment partially
/// backed. Reads past `data` yield zero, matching what the loader would map,
/// which keeps a corrupt file from producing garbage instructions.
struct MemorySegment {
    Address start = 0;
    u64 size = 0;
    ByteView data;
    u32 flags = 0;
    std::string name;

    Address end() const { return start + size; }
    bool contains(Address addr) const { return addr >= start && addr < end(); }
    bool executable() const { return (flags & kMemExec) != 0; }
    bool writable() const { return (flags & kMemWrite) != 0; }
};

/// The address space of a loaded image.
///
/// Everything above the loaders — disassembler, lifter, emulator, string
/// scanner — addresses memory only through this, so none of them needs to know
/// whether the bytes came from an ELF segment, a DEX code item, or a synthetic
/// region we materialised ourselves.
class MemoryMap {
public:
    /// Segments must be added before any lookup. `name` is for display only.
    void addSegment(Address start, u64 size, ByteView data, u32 flags, std::string name);

    /// Sorts and validates. Overlapping segments are kept but flagged, since
    /// overlap is a real signal — several packers map the same address range
    /// twice so that a linear reader sees different bytes than the runtime.
    void finalize();

    bool hasOverlaps() const { return hasOverlaps_; }
    const std::vector<MemorySegment>& segments() const { return segments_; }
    bool empty() const { return segments_.empty(); }

    Address minAddress() const { return minAddress_; }
    Address maxAddress() const { return maxAddress_; }

    /// The segment covering `addr`, or nullptr. Binary search, so this is on
    /// the hot path of the disassembler without apology.
    const MemorySegment* segmentAt(Address addr) const;

    bool isMapped(Address addr) const { return segmentAt(addr) != nullptr; }
    bool isExecutable(Address addr) const;

    /// A view of up to `maxLength` bytes starting at `addr`, clipped to the end
    /// of file-backed content in the containing segment. The disassembler feeds
    /// this straight to Capstone, so it must never extend past real bytes.
    ByteView viewAt(Address addr, u64 maxLength) const;

    /// Copies `length` bytes, zero-filling any part that is mapped but not
    /// file-backed. Fails only if the range is not mapped at all.
    bool read(Address addr, void* out, size_t length) const;

    template <typename T>
    bool readInt(Address addr, T* out) const {
        return read(addr, out, sizeof(T));
    }

    /// A NUL-terminated string at `addr`, used for symbol names and for the
    /// string scanner.
    bool readCString(Address addr, std::string* out, size_t maxLength = 4096) const;

private:
    std::vector<MemorySegment> segments_;
    Address minAddress_ = 0;
    Address maxAddress_ = 0;
    bool hasOverlaps_ = false;
    bool finalized_ = false;
};

}  // namespace mint
