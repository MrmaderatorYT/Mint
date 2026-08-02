#pragma once

#include <string>

#include "mint/base/byte_view.h"
#include "mint/base/status.h"
#include "mint/base/types.h"

namespace mint {

/// A read-only mmap of an input file.
///
/// APKs routinely run to a few hundred megabytes and phones kill processes that
/// allocate that much heap, so nothing in this engine reads a file into a
/// buffer. Mapping also means the many loaders that only touch headers never
/// fault in the pages they do not look at.
///
/// The mapping is read-only and private: analysing a file can never modify it,
/// which is a property worth having structurally rather than by discipline.
class MappedFile {
public:
    MappedFile() = default;
    ~MappedFile();

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& other) noexcept;
    MappedFile& operator=(MappedFile&& other) noexcept;

    /// Maps `path`. On failure the object stays empty and the returned Status
    /// says why.
    Status open(const std::string& path);

    /// Maps an already-open file descriptor, which is how content received
    /// through the Android storage picker arrives — a SAF document has no path
    /// we are allowed to open directly. Does not take ownership of `fd`; the
    /// mapping stays valid after the caller closes it.
    Status openFd(int fd);

    void close();

    bool isOpen() const { return base_ != nullptr; }
    ByteView view() const { return ByteView(base_, size_); }
    size_t size() const { return size_; }
    const std::string& path() const { return path_; }

private:
    u8* base_ = nullptr;
    size_t size_ = 0;
    std::string path_;
};

}  // namespace mint
