#pragma once

#include <string>
#include <vector>

#include "mint/base/byte_view.h"
#include "mint/base/status.h"
#include "mint/base/types.h"
#include "mint/loader/elf_image.h"

namespace mint {

struct UnwindFunctionRoot {
    Address entry = 0;
    Address fde = 0;
};

struct UnwindFrame {
    Address entry = 0;
    Address end = 0;  // Validated exclusive executable extent, not a CFG hull.
    Address fde = 0;
    Address cie = 0;
    Address lsda = 0;
    Address personality = 0; // May be zero for an unresolved dynamic import.
    bool signalFrame = false;
};

/// Decodes the ELF EH-frame binary-search table in link-time address space.
/// Output is transactional: malformed/unsupported tables produce no roots.
/// Fixed-size/LEB128 absolute, PC-relative and header-data-relative pointers
/// (including indirect pointers) are supported. Each FDE/CIE record is checked
/// against file-backed mapped bytes before its executable entry is accepted.
Status parseEhFrameHeader(ByteView header, Address headerAddress,
                          const MemoryMap& memory, size_t pointerWidth,
                          size_t maxEntries,
                          std::vector<UnwindFunctionRoot>* out);

/// Bounded .eh_frame framing/CIE/FDE inventory. The EH CIE ID/backward link is
/// four bytes even for an extended-length record. Versions 1/3/4 and empty,
/// zL/zP/zR/zS/B/G augmentations are supported; CFI is not executed. Unknown
/// augmentations, unsupported base encodings or invalid executable extents are
/// excluded with notes. Malformed record framing fails transactionally.
Status parseEhFrameSection(ByteView section, Address sectionAddress,
                           const MemoryMap& memory, size_t pointerWidth,
                           size_t maxEntries, std::vector<UnwindFrame>* out,
                           std::vector<std::string>* notes = nullptr);
std::vector<UnwindFrame> collectUnwindFrames(
    const ElfImage& image, size_t maxEntries, std::vector<std::string>* warnings);

/// Header roots when available, otherwise validated .eh_frame FDE roots.
/// Malformed metadata is reported, never converted into guessed code roots.
std::vector<UnwindFunctionRoot> collectUnwindRoots(
    const ElfImage& image, size_t maxEntries, std::vector<std::string>* warnings);

}  // namespace mint
