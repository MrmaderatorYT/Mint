#pragma once

#include <string>
#include <utility>

namespace mint {

/// Why an analysis step gave up.
///
/// Loaders return these rather than throwing: a truncated section header is an
/// ordinary outcome when the input is a protected APK, not an exceptional one,
/// and the UI needs to say *what* was wrong rather than show "analysis failed".
enum class ErrorCode {
    kOk = 0,
    kIoError,          ///< Could not read the file at all.
    kNotFound,         ///< No such symbol / function / section.
    kBadFormat,        ///< Header magic or structure did not match.
    kTruncated,        ///< Structure ran past the end of the file.
    kUnsupported,      ///< Well-formed, but not something we handle (e.g. 32-bit ELF).
    kTooLarge,         ///< Refused on resource grounds rather than correctness.
    kInternalError,
};

const char* errorCodeName(ErrorCode code);

class Status {
public:
    Status() = default;

    /// Not named `ok()`: that is the predicate, and a factory sharing the name
    /// would differ only in return type.
    static Status success() { return {}; }

    static Status error(ErrorCode code, std::string message) {
        Status s;
        s.code_ = code;
        s.message_ = std::move(message);
        return s;
    }

    bool ok() const { return code_ == ErrorCode::kOk; }
    ErrorCode code() const { return code_; }
    const std::string& message() const { return message_; }

    /// Human-readable form for the UI and the analysis log.
    std::string toString() const;

private:
    ErrorCode code_ = ErrorCode::kOk;
    std::string message_;
};

}  // namespace mint
