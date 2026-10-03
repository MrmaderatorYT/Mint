#include "mint/session.h"
#include "mint/base/sha256.h"
#include "mint/debug/pdb_reader.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>

namespace mint {
namespace {
constexpr u64 kMaxDebugObject = 128ULL * 1024 * 1024;
Status debugError(const std::string& text) { return Status::error(ErrorCode::kBadFormat, "external DWARF: " + text); }
bool digestText(const std::string& text) { return text.size() == 64 && text.find_first_not_of("0123456789abcdef") == std::string::npos; }
Status mapRegular(const std::string& path, u64 cap, MappedFile* file, bool missingAllowed = false) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return Status::error(missingAllowed && errno == ENOENT ? ErrorCode::kNotFound : ErrorCode::kIoError, "external DWARF: cannot open regular private file");
    struct stat info{}; Status status;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size <= 0 || static_cast<u64>(info.st_size) > cap)
        status = debugError("file must be a regular nonempty file within resource cap");
    else status = file->openFd(fd);
    close(fd); return status;
}
bool writeBytes(int fd, ByteView bytes) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t count = write(fd, bytes.data() + offset, std::min<size_t>(bytes.size() - offset, 1024 * 1024));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<size_t>(count);
    }
    return fsync(fd) == 0;
}
Status publishMetadata(const std::string& path, const std::string& text) {
    std::string pattern = path + ".tmp.XXXXXX"; std::vector<char> name(pattern.begin(), pattern.end()); name.push_back(0);
    const int fd = mkstemp(name.data()); if (fd < 0) return Status::error(ErrorCode::kIoError, "cannot create private debug metadata");
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    bool valid = writeBytes(fd, ByteView(reinterpret_cast<const u8*>(text.data()), text.size()));
    if (close(fd)) valid = false;
    if (!valid || rename(name.data(), path.c_str())) { unlink(name.data()); return Status::error(ErrorCode::kIoError, "cannot atomically save debug metadata"); }
    const auto slash = path.find_last_of('/'); const std::string parent = slash == std::string::npos ? "." : path.substr(0, slash);
    const int directory = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory >= 0) { fsync(directory); close(directory); }
    return Status::success();
}
Status parseMetadata(ByteView bytes, std::string* source, std::string* digest, bool* unverified) {
    if (bytes.size() > 256 || std::memchr(bytes.data(), 0, bytes.size())) return debugError("invalid private metadata extent");
    std::istringstream input(std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    std::string magic, flag, extra;
    if (!std::getline(input, magic) || magic != "MINT_DEBUG 1" || !std::getline(input, *source) || !digestText(*source) ||
        !std::getline(input, *digest) || !digestText(*digest) || !std::getline(input, flag) || (flag != "0" && flag != "1") || std::getline(input, extra))
        return debugError("invalid private metadata format");
    *unverified = flag == "1"; return Status::success();
}
Status readExternal(const ElfImage& image, ByteView bytes, DwarfReport* report, bool unverified) {
    static constexpr char pdbMagic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
    if (bytes.covers(0, 32) && !std::memcmp(bytes.data(), pdbMagic, 32)) return readPdb(image, bytes, report, unverified);
    ElfImage external; Status status = external.loadDebugObject(bytes);
    return status.ok() ? readDwarf(image, external, report, unverified) : status;
}
}

Status Session::restoreExternalDebug(const std::string& projectPath) {
    MappedFile metadata; Status status = mapRegular(projectPath + ".debug", 256, &metadata, true);
    if (status.code() == ErrorCode::kNotFound) {
        externalDebugDigest_.clear();
        DwarfReport embedded; const auto read = readDwarf(image_, &embedded);
        if (!read.ok()) { embedded.partial = true; embedded.warnings.push_back(read.toString()); }
        debugInfo_ = std::move(embedded); return Status::success();
    }
    if (!status.ok()) return status;
    std::string source, digest; bool unverified = false;
    status = parseMetadata(metadata.view(), &source, &digest, &unverified); if (!status.ok()) return status;
    if (sha256(file_.view()) != source) return debugError("private debug metadata belongs to another input binary");
    MappedFile external; status = mapRegular(projectPath + ".debug." + digest + ".bin", kMaxDebugObject, &external); if (!status.ok()) return status;
    if (sha256(external.view()) != digest) return debugError("private debug sidecar checksum mismatch; user annotations remain untouched");
    DwarfReport report; status = readExternal(image_, external.view(), &report, unverified); if (!status.ok()) return status;
    debugInfo_ = std::move(report); externalDebugDigest_ = digest; return Status::success();
}

Status Session::importExternalDebug(const std::string& path, bool allowUnverified) {
    if (!loaded_ || isDexLike() || program_.path().empty()) return debugError("attach a persistent native Program before importing external debug information");
    MappedFile selected; Status status = mapRegular(path, kMaxDebugObject, &selected); if (!status.ok()) return status;
    DwarfReport report; status = readExternal(image_, selected.view(), &report, allowUnverified); if (!status.ok()) return status;
    // Validate user's existing type/prototype/locals library against the new
    // baseline before any disk/live-state publication.
    DwarfReport previous = std::move(debugInfo_); debugInfo_ = report;
    const DataTypeManager types = importedDebugTypes(); debugInfo_ = std::move(previous);
    Program candidate = program_; status = candidate.setImportedTypes(types); if (!status.ok()) return status;
    const std::string digest = sha256(selected.view()), source = sha256(file_.view());
    const std::string destination = program_.path() + ".debug." + digest + ".bin";
    const int fd = open(destination.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        bool written = writeBytes(fd, selected.view()); if (close(fd)) written = false;
        if (!written) { unlink(destination.c_str()); return Status::error(ErrorCode::kIoError, "cannot save private external debug sidecar"); }
    } else if (errno != EEXIST) return Status::error(ErrorCode::kIoError, "cannot create private external debug sidecar");
    MappedFile saved; status = mapRegular(destination, kMaxDebugObject, &saved); if (!status.ok()) return status;
    if (sha256(saved.view()) != digest) return debugError("content-addressed debug sidecar collision/mutation; previous project remains active");
    const std::string metadata = "MINT_DEBUG 1\n" + source + '\n' + digest + '\n' + (allowUnverified ? "1\n" : "0\n");
    status = publishMetadata(program_.path() + ".debug", metadata); if (!status.ok()) return status;
    program_ = std::move(candidate); debugInfo_ = std::move(report); externalDebugDigest_ = digest;
    allowCacheRestore_ = false; prototypeEvidenceBuilt_ = false;
    if (analyzed_) return reanalyze();
    return Status::success();
}
} // namespace mint
