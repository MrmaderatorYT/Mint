#include "mint/base/status.h"

#include "mint/base/types.h"

namespace mint {

const char* errorCodeName(ErrorCode code) {
    switch (code) {
        case ErrorCode::kOk: return "ok";
        case ErrorCode::kIoError: return "io-error";
        case ErrorCode::kNotFound: return "not-found";
        case ErrorCode::kBadFormat: return "bad-format";
        case ErrorCode::kTruncated: return "truncated";
        case ErrorCode::kUnsupported: return "unsupported";
        case ErrorCode::kTooLarge: return "too-large";
        case ErrorCode::kInternalError: return "internal-error";
    }
    return "unknown";
}

std::string Status::toString() const {
    if (ok()) return "ok";
    std::string out = errorCodeName(code_);
    if (!message_.empty()) {
        out += ": ";
        out += message_;
    }
    return out;
}

const char* archName(Arch arch) {
    switch (arch) {
        case Arch::kUnknown: return "unknown";
        case Arch::kAArch64: return "arm64";
        case Arch::kX86_64: return "x86-64";
        case Arch::kDalvik: return "dalvik";
    }
    return "unknown";
}

}  // namespace mint
