#pragma once

#include "mint/analysis/unwind_roots.h"

namespace mint {
struct ExceptionAction {
    Address record = 0;
    i64 filter = 0; // 0 cleanup, >0 catch type index, <0 exception specification.
    Address typeInfo = kNoAddress;
    Address indirectSlot = kNoAddress;
    bool catchAll = false;
    bool typeResolved = false;
    std::string typeSymbol;
};
struct ExceptionCallSite {
    Address start = 0, end = 0;
    Address landingPad = kNoAddress;
    u64 actionOffset = 0;
    std::vector<ExceptionAction> actions;
};
struct ExceptionLandingPad {
    Address address = kNoAddress;
    struct ProtectedRegion {
        Address start = 0, end = 0;
        u64 actionOffset = 0;
        bool cleanup = false, catchAll = false, exceptionSpecification = false;
        size_t callSiteIndex = 0; // Ordered actions live in callSites[index], no duplicated metadata.
    };
    std::vector<ProtectedRegion> regions;
};
struct ExceptionFunction {
    UnwindFrame frame;
    std::vector<ExceptionCallSite> callSites;
    std::vector<std::string> notes;
    std::vector<ExceptionLandingPad> landingPads;
};
struct ExceptionMetadataReport {
    std::vector<ExceptionFunction> functions;
    std::vector<std::string> notes;
    bool truncated = false;
};

// LLVM/GNU Itanium zero-cost EH LSDA, not ARM EHABI/SjLj/SEH. Bounded mapped
// function/call-site/landing-pad ranges and action chains; no runtime unwinding,
// exception-edge insertion, dynamic catch matching or inferred try/catch AST.
// Malformed metadata clears output. Fixed type-table encodings and nullable
// absolute/PC-relative pointers are decoded; unknown bases fail closed.
Status parseExceptionLsda(ByteView bytes, Address address, const MemoryMap& memory,
                          size_t pointerWidth, const UnwindFrame& frame,
                          size_t maxCallSites, ExceptionFunction* out);
ExceptionMetadataReport inspectExceptionMetadata(const ElfImage& image, size_t limit = 1024);
std::string exceptionMetadataText(const ExceptionMetadataReport& report);
std::string exceptionMetadataText(const ElfImage& image, size_t limit = 1024);
} // namespace mint
