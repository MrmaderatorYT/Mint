#include "mint/loader/elf_image.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace mint {

bool ElfImage::fileOffsetAt(Address address, size_t length, u64* offset) const {
    if (offset == nullptr || length == 0 || length > ~Address{0} - address) return false;
    const MemoryMap& baseline = patchStorage_.empty() ? memory_ : originalMemory_;
    const MemorySegment* match = nullptr;
    for (const MemorySegment& segment : baseline.segments()) {
        if (address < segment.end() && segment.start < address + length) {
            if (match != nullptr) return false;
            match = &segment;
        }
    }
    if (match == nullptr || address < match->start || address - match->start > match->data.size() ||
        length > match->data.size() - (address - match->start)) return false;
    const uintptr_t input = reinterpret_cast<uintptr_t>(originalFile_.data());
    const uintptr_t backing = reinterpret_cast<uintptr_t>(match->data.data());
    if (backing < input || backing - input > originalFile_.size()) return false;
    const u64 at = static_cast<u64>(backing - input) + address - match->start;
    if (!originalFile_.covers(at, length)) return false;
    *offset = at;
    return true;
}

Status ElfImage::applyPatch(Address address, ByteView bytes) {
    u64 ignored = 0;
    if (!loaded_ || bytes.empty() || bytes.size() > 4096 ||
        !fileOffsetAt(address, bytes.size(), &ignored)) {
        return Status::error(ErrorCode::kBadFormat,
                             "patch must fit in one uniquely mapped, file-backed segment (1..4096 bytes)");
    }
    const MemorySegment* segment = memory_.segmentAt(address);
    if (segment == nullptr) return Status::error(ErrorCode::kBadFormat, "patch address is not mapped");
    // First edit owns a segment copy. Later edits reuse it unless a copied
    // ElfImage shares that storage; that case needs copy-on-write.
    std::shared_ptr<std::vector<u8>> storage;
    auto existing = patchStorage_.find(segment->start);
    if (existing != patchStorage_.end() && existing->second.use_count() == 1) storage = existing->second;
    else storage = std::make_shared<std::vector<u8>>(segment->data.data(),
                                                    segment->data.data() + segment->data.size());
    std::memmove(storage->data() + (address - segment->start), bytes.data(), bytes.size());
    if (patchStorage_.empty()) {
        originalMemory_ = memory_;
        originalSections_ = sections_;
    }
    const Address segmentStart = segment->start;
    MemoryMap patched;
    for (const MemorySegment& current : memory_.segments()) {
        const ByteView data = current.start == segmentStart
            ? ByteView(storage->data(), storage->size()) : current.data;
        patched.addSegment(current.start, current.size, data, current.flags, current.name);
    }
    patched.finalize();
    memory_ = std::move(patched);
    patchStorage_[segmentStart] = std::move(storage);
    for (ElfSection& section : sections_) {
        if (!section.allocated() || section.data.empty()) continue;
        ByteView backing = memory_.viewAt(section.addr, section.data.size());
        if (backing.size() == section.data.size()) section.data = backing;
    }
    return Status::success();
}

void ElfImage::resetPatches() {
    if (patchStorage_.empty()) return;
    memory_ = originalMemory_;
    sections_ = originalSections_;
    patchStorage_.clear();
    originalMemory_ = MemoryMap{};
    originalSections_.clear();
}
}  // namespace mint
