#include "mint/base/mapped_file.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>

namespace mint {
namespace {

/// Above this we refuse rather than try. A 4 GiB "APK" is not a real input, and
/// mapping it on a phone would either fail confusingly or push the process into
/// the low-memory killer, which the user would see as the app crashing.
constexpr size_t kMaxMappedSize = static_cast<size_t>(3) * 1024 * 1024 * 1024;

Status errnoStatus(const std::string& what) {
    return Status::error(ErrorCode::kIoError, what + ": " + std::strerror(errno));
}

}  // namespace

MappedFile::~MappedFile() { close(); }

MappedFile::MappedFile(MappedFile&& other) noexcept
    : base_(other.base_), size_(other.size_), path_(std::move(other.path_)) {
    other.base_ = nullptr;
    other.size_ = 0;
}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
    if (this != &other) {
        close();
        base_ = other.base_;
        size_ = other.size_;
        path_ = std::move(other.path_);
        other.base_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

Status MappedFile::open(const std::string& path) {
    close();
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errnoStatus("open " + path);

    Status status = openFd(fd);
    ::close(fd);
    if (status.ok()) path_ = path;
    return status;
}

Status MappedFile::openFd(int fd) {
    close();

    struct stat st {};
    if (::fstat(fd, &st) != 0) return errnoStatus("fstat");

    if (!S_ISREG(st.st_mode)) {
        return Status::error(ErrorCode::kIoError, "not a regular file");
    }
    if (st.st_size <= 0) {
        return Status::error(ErrorCode::kBadFormat, "file is empty");
    }
    const auto size = static_cast<size_t>(st.st_size);
    if (size > kMaxMappedSize) {
        return Status::error(ErrorCode::kTooLarge, "file larger than 3 GiB");
    }

    void* base = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) return errnoStatus("mmap");

    // Loaders walk headers scattered across the file, then the disassembler
    // sweeps .text front to back. Random is the honest hint for the first part
    // and costs nothing for the second.
    ::madvise(base, size, MADV_RANDOM);

    base_ = static_cast<u8*>(base);
    size_ = size;
    return Status::success();
}

void MappedFile::close() {
    if (base_ != nullptr) {
        ::munmap(base_, size_);
        base_ = nullptr;
    }
    size_ = 0;
    path_.clear();
}

}  // namespace mint
