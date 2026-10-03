#include "mint/db/analysis_cache.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace mint {
namespace {

constexpr size_t kHeaderBytes = 32;
constexpr char kMagic[8] = {'M', 'I', 'N', 'T', 'A', 'C', '0', '1'};
constexpr u32 kVersion = 2;
constexpr u64 kMaxPayload = AnalysisCache::kMaxFileBytes - kHeaderBytes;
constexpr size_t kMaxMemberships = 8000000;
constexpr size_t kMaxCallees = 4000000;
constexpr size_t kMaxIndirectBranches = 200000;
constexpr size_t kMaxIndirectTargets = 4000000;
constexpr size_t kMaxWarnings = 256;
constexpr size_t kMaxNameBytes = 16384;
constexpr size_t kMaxWarningBytes = 16384;
constexpr size_t kMaxKeyBytes = 4096;
constexpr size_t kMaxReferenceKindBytes = 128;

Status bad(const std::string& message) {
    return Status::error(ErrorCode::kBadFormat, "analysis cache: " + message);
}
Status large(const std::string& message) {
    return Status::error(ErrorCode::kTooLarge, "analysis cache: " + message);
}
Status io(const char* action, int error) {
    return Status::error(ErrorCode::kIoError, std::string("analysis cache: ") + action + ": " + std::strerror(error));
}

u32 checksum(const u8* bytes, size_t size) {
    static const std::array<u32, 256> table = [] {
        std::array<u32, 256> values{};
        for (u32 i = 0; i < 256; ++i) {
            u32 crc = i;
            for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0U);
            values[i] = crc;
        }
        return values;
    }();
    u32 crc = 0xffffffffU;
    for (size_t i = 0; i < size; ++i) crc = table[(crc ^ bytes[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffffU;
}

class Writer {
public:
    bool integer(u64 value, size_t bytes) {
        if (data.size() > limit_ || bytes > limit_ - data.size()) return false;
        for (size_t i = 0; i < bytes; ++i) data.push_back(static_cast<u8>(value >> (i * 8)));
        return true;
    }
    bool string(const std::string& text, size_t max) {
        if (text.size() > max || text.find('\0') != std::string::npos ||
            !integer(text.size(), 4) || text.size() > limit_ - data.size()) return false;
        data.insert(data.end(), text.begin(), text.end());
        return true;
    }
    bool addresses(const std::vector<Address>& addresses, size_t max, size_t* total = nullptr) {
        if (addresses.size() > max || (total && addresses.size() > max - *total)) return false;
        if (total) *total += addresses.size();
        if (!integer(addresses.size(), 4)) return false;
        for (auto address : addresses) if (!integer(address, 8)) return false;
        return true;
    }
    std::vector<u8> data;
private:
    size_t limit_ = static_cast<size_t>(kMaxPayload);
};

class Reader {
public:
    Reader(const u8* bytes, size_t size) : bytes_(bytes), size_(size) {}
    bool integer(size_t bytes, u64* out) {
        if (bytes > 8 || bytes > remaining()) return false;
        u64 value = 0;
        for (size_t i = 0; i < bytes; ++i) value |= u64(bytes_[pos_++]) << (i * 8);
        *out = value;
        return true;
    }
    bool byte(u8* out) { u64 value = 0; if (!integer(1, &value)) return false; *out = static_cast<u8>(value); return true; }
    bool number(u32* out) { u64 value = 0; if (!integer(4, &value)) return false; *out = static_cast<u32>(value); return true; }
    bool address(Address* out) { return integer(8, out); }
    bool boolean(bool* out) {
        u8 value = 0;
        if (!byte(&value) || value > 1) return false;
        *out = value != 0;
        return true;
    }
    bool count(size_t max, size_t minimumBytes, u32* out) {
        if (!number(out) || *out > max || (minimumBytes && *out > remaining() / minimumBytes)) return false;
        return true;
    }
    bool string(size_t max, std::string* out) {
        u32 count = 0;
        if (!this->count(max, 1, &count)) return false;
        if (count && std::memchr(bytes_ + pos_, 0, count)) return false;
        out->assign(reinterpret_cast<const char*>(bytes_ + pos_), count);
        pos_ += count;
        return true;
    }
    bool addresses(size_t max, std::vector<Address>* out, size_t* total = nullptr) {
        u32 count = 0;
        if (!this->count(max, 8, &count) || (total && count > max - *total)) return false;
        if (total) *total += count;
        out->resize(count);
        for (auto& address : *out) if (!this->address(&address)) return false;
        return true;
    }
    size_t remaining() const { return size_ - pos_; }
private:
    const u8* bytes_;
    size_t size_;
    size_t pos_ = 0;
};

bool sortedUnique(const std::vector<Address>& addresses) {
    for (size_t i = 1; i < addresses.size(); ++i) if (addresses[i - 1] >= addresses[i]) return false;
    return true;
}

Status validateInstruction(const InsnRecord& instruction) {
    if (instruction.size == 0 || instruction.size > 24 ||
        static_cast<u8>(instruction.flow) > static_cast<u8>(FlowKind::kInvalid) ||
        instruction.address > kNoAddress - instruction.size)
        return bad("invalid instruction size, flow or address range");
    return Status::success();
}

Status encode(const std::string& key, const CachedAnalysis& cache, Writer* out) {
    if (key.empty() || !out->string(key, kMaxKeyBytes)) return bad("invalid dependency key");
    const auto& analysis = cache.analysis;
    if (analysis.instructions.size() > AnalysisCache::kMaxInstructions ||
        analysis.functions.size() > AnalysisCache::kMaxFunctions ||
        analysis.functionBoundaries.size() > AnalysisCache::kMaxInstructions ||
        analysis.warnings.size() > kMaxWarnings || cache.references.size() > AnalysisCache::kMaxReferences)
        return large("record counts exceed budget");
    if (!cache.referencesReady && !cache.references.empty()) return bad("references present without ready flag");
    if (!out->integer(analysis.instructions.size(), 4)) return large("payload exceeds 128 MiB");
    Address previous = 0;
    bool first = true;
    for (const auto& instruction : analysis.instructions) {
        auto status = validateInstruction(instruction);
        if (!status.ok()) return status;
        if (!first && instruction.address <= previous) return bad("instruction addresses are not strictly sorted");
        previous = instruction.address; first = false;
        if (!out->integer(instruction.address, 8) || !out->integer(instruction.target, 8) ||
            !out->integer(instruction.id, 2) || !out->integer(instruction.size, 1) ||
            !out->integer(static_cast<u8>(instruction.flow), 1)) return large("payload exceeds 128 MiB");
    }
    if (!out->integer(analysis.functions.size(), 4)) return large("payload exceeds 128 MiB");
    size_t memberships = 0, callees = 0, branches = 0, targets = 0;
    for (const auto& function : analysis.functions) {
        ArchitectureDescription architecture;
        if ((function.decodeArch!=Arch::kUnknown && !architectureDescription(function.decodeArch,&architecture)) ||
            static_cast<u8>(function.origin) > static_cast<u8>(FunctionOrigin::kDwarf) ||
            function.entry == kNoAddress || function.lowAddress > function.highAddress ||
            !sortedUnique(function.instructions)) return bad("invalid function metadata");
        if (!out->integer(function.entry, 8) || !out->string(function.name, kMaxNameBytes) ||
            !out->integer(static_cast<u8>(function.origin), 1) ||
            !out->integer(static_cast<u8>(function.decodeArch),1) ||
            !out->integer(function.lowAddress, 8) || !out->integer(function.highAddress, 8) ||
            !out->integer(function.incomplete ? 1 : 0, 1) ||
            !out->integer(function.indirectJumps, 4) || !out->integer(function.undecodableSites, 4) ||
            !out->addresses(function.instructions, kMaxMemberships, &memberships) ||
            !out->addresses(function.callees, kMaxCallees, &callees)) return large("function payload exceeds budget");
        if (function.resolvedIndirectJumps.size() > kMaxIndirectBranches - branches ||
            !out->integer(function.resolvedIndirectJumps.size(), 4)) return large("indirect branch count exceeds budget");
        branches += function.resolvedIndirectJumps.size();
        for (const auto& branch : function.resolvedIndirectJumps) {
            if (branch.branch == kNoAddress || branch.targets.empty()) return bad("invalid resolved indirect branch");
            if (!out->integer(branch.branch, 8) || !out->addresses(branch.targets, kMaxIndirectTargets, &targets))
                return large("indirect target payload exceeds budget");
        }
    }
    if (!out->integer(analysis.warnings.size(), 4)) return large("payload exceeds 128 MiB");
    for (const auto& warning : analysis.warnings) if (!out->string(warning, kMaxWarningBytes)) return large("warning payload exceeds budget");
    if (!sortedUnique(analysis.functionBoundaries)) return bad("function boundaries are not strictly sorted");
    if (!out->addresses(analysis.functionBoundaries, AnalysisCache::kMaxInstructions) ||
        !out->integer(analysis.reachedInstructionLimit ? 1 : 0, 1) ||
        !out->integer(cache.referencesReady ? 1 : 0, 1) ||
        !out->integer(cache.references.size(), 4)) return large("payload exceeds 128 MiB");
    for (const auto& reference : cache.references) {
        if (reference.from == kNoAddress || reference.to == kNoAddress || reference.kind.empty()) return bad("invalid reference");
        if (!out->integer(reference.from, 8) || !out->integer(reference.to, 8) ||
            !out->string(reference.kind, kMaxReferenceKindBytes)) return large("reference payload exceeds budget");
    }
    if(cache.referenceGroups.size()>AnalysisCache::kMaxFunctions+1 ||
       (!cache.referencesReady && !cache.referenceGroups.empty()))return bad("invalid reference group metadata");
    if(!out->integer(cache.referenceGroups.size(),4))return large("reference group payload exceeds budget");
    size_t referenceCount=0,dependencyCount=0;std::vector<Address> owners;
    for(const auto& group:cache.referenceGroups) {
        if(group.references.size()>AnalysisCache::kMaxReferences-referenceCount ||
           group.dependencies.size()>kMaxMemberships-dependencyCount)return large("reference dependencies exceed budget");
        referenceCount+=group.references.size();dependencyCount+=group.dependencies.size();owners.push_back(group.owner);
        if(!out->integer(group.owner,8) || !out->integer(group.conservative,1) ||
           !out->integer(group.references.size(),4))return large("reference group payload exceeds budget");
        for(const auto& reference:group.references) {
            if(reference.from==kNoAddress || reference.to==kNoAddress || reference.kind.empty())return bad("invalid group reference");
            if(!out->integer(reference.from,8) || !out->integer(reference.to,8) ||
               !out->string(reference.kind,kMaxReferenceKindBytes))return large("reference group payload exceeds budget");
        }
        if(!out->integer(group.dependencies.size(),4))return large("dependency payload exceeds budget");
        for(const auto& range:group.dependencies) {
            if(range.start>=range.end)return bad("invalid dependency range");
            if(!out->integer(range.start,8) || !out->integer(range.end,8))return large("dependency payload exceeds budget");
        }
    }
    std::sort(owners.begin(),owners.end());
    if(std::adjacent_find(owners.begin(),owners.end())!=owners.end())return bad("duplicate reference group owner");
    return Status::success();
}

Status decode(const u8* data, size_t size, const std::string& dependencyKey, CachedAnalysis* out) {
    Reader reader(data, size);
    std::string key;
    if (!reader.string(kMaxKeyBytes, &key)) return bad("invalid dependency key");
    if (key != dependencyKey) return Status::error(ErrorCode::kNotFound, "analysis cache dependency identity changed");
    auto& analysis = out->analysis;
    u32 count = 0;
    if (!reader.count(AnalysisCache::kMaxInstructions, 20, &count)) return bad("invalid instruction count");
    analysis.instructions.resize(count);
    Address previous = 0;
    bool first = true;
    for (auto& instruction : analysis.instructions) {
        u64 id = 0;
        u8 flow = 0;
        if (!reader.address(&instruction.address) || !reader.address(&instruction.target) ||
            !reader.integer(2, &id) || !reader.byte(&instruction.size) || !reader.byte(&flow)) return bad("truncated instruction");
        instruction.id = static_cast<u16>(id);
        instruction.flow = static_cast<FlowKind>(flow);
        auto status = validateInstruction(instruction);
        if (!status.ok()) return status;
        if (!first && instruction.address <= previous) return bad("instruction addresses are not strictly sorted");
        previous = instruction.address; first = false;
    }
    // Fixed fields plus three vector-length prefixes: minimum51 bytes/function.
    if (!reader.count(AnalysisCache::kMaxFunctions, 51, &count)) return bad("invalid function count");
    analysis.functions.resize(count);
    size_t memberships = 0, callees = 0, branches = 0, targets = 0;
    for (auto& function : analysis.functions) {
        u8 origin = 0,decodeArch=0;
        if (!reader.address(&function.entry) || !reader.string(kMaxNameBytes, &function.name) ||
            !reader.byte(&origin) || !reader.byte(&decodeArch) || !reader.address(&function.lowAddress) || !reader.address(&function.highAddress) ||
            !reader.boolean(&function.incomplete) || !reader.number(&function.indirectJumps) ||
            !reader.number(&function.undecodableSites) ||
            !reader.addresses(kMaxMemberships, &function.instructions, &memberships) ||
            !reader.addresses(kMaxCallees, &function.callees, &callees)) return bad("truncated/over-budget function");
        function.origin = static_cast<FunctionOrigin>(origin);
        function.decodeArch=static_cast<Arch>(decodeArch);ArchitectureDescription architecture;
        if ((function.decodeArch!=Arch::kUnknown && !architectureDescription(function.decodeArch,&architecture)) ||
            origin > static_cast<u8>(FunctionOrigin::kDwarf) || function.entry == kNoAddress ||
            function.lowAddress > function.highAddress || !sortedUnique(function.instructions)) return bad("invalid function metadata");
        if (!reader.count(kMaxIndirectBranches, 12, &count) || count > kMaxIndirectBranches - branches)
            return bad("invalid indirect branch count");
        branches += count;
        function.resolvedIndirectJumps.resize(count);
        for (auto& branch : function.resolvedIndirectJumps) {
            if (!reader.address(&branch.branch) || !reader.addresses(kMaxIndirectTargets, &branch.targets, &targets) ||
                branch.branch == kNoAddress || branch.targets.empty()) return bad("invalid resolved indirect branch");
        }
    }
    if (!reader.count(kMaxWarnings, 4, &count)) return bad("invalid warning count");
    analysis.warnings.resize(count);
    for (auto& warning : analysis.warnings) if (!reader.string(kMaxWarningBytes, &warning)) return bad("truncated/over-budget warning");
    if (!reader.addresses(AnalysisCache::kMaxInstructions, &analysis.functionBoundaries) ||
        !sortedUnique(analysis.functionBoundaries) || !reader.boolean(&analysis.reachedInstructionLimit) ||
        !reader.boolean(&out->referencesReady) || !reader.count(AnalysisCache::kMaxReferences, 21, &count))
        return bad("invalid boundary/reference metadata");
    if (!out->referencesReady && count) return bad("references present without ready flag");
    out->references.resize(count);
    for (auto& reference : out->references) {
        if (!reader.address(&reference.from) || !reader.address(&reference.to) ||
            !reader.string(kMaxReferenceKindBytes, &reference.kind) || reference.from == kNoAddress ||
            reference.to == kNoAddress || reference.kind.empty()) return bad("truncated/invalid reference");
    }
    if(!reader.count(AnalysisCache::kMaxFunctions+1,17,&count) || (!out->referencesReady && count))return bad("invalid reference group count");
    out->referenceGroups.resize(count);size_t references=0,dependencies=0;std::vector<Address> owners;
    for(auto& group:out->referenceGroups) {
        if(!reader.address(&group.owner) || !reader.boolean(&group.conservative) ||
           !reader.count(AnalysisCache::kMaxReferences-references,21,&count))return bad("invalid reference group");
        references+=count;group.references.resize(count);owners.push_back(group.owner);
        for(auto& reference:group.references) {
            if(!reader.address(&reference.from) || !reader.address(&reference.to) ||
               !reader.string(kMaxReferenceKindBytes,&reference.kind) || reference.from==kNoAddress ||
               reference.to==kNoAddress || reference.kind.empty())return bad("invalid group reference");
        }
        if(!reader.count(kMaxMemberships-dependencies,16,&count))return bad("invalid dependency count");
        dependencies+=count;group.dependencies.resize(count);
        for(auto& range:group.dependencies)if(!reader.address(&range.start) || !reader.address(&range.end) || range.start>=range.end)
            return bad("invalid dependency range");
    }
    std::sort(owners.begin(),owners.end());
    if(std::adjacent_find(owners.begin(),owners.end())!=owners.end())return bad("duplicate reference group owner");
    if (reader.remaining()) return bad("trailing bytes in payload");
    return Status::success();
}

class Descriptor {
public:
    explicit Descriptor(int descriptor) : fd(descriptor) {}
    ~Descriptor() { if (fd >= 0) ::close(fd); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int fd;
};

Status readFile(const std::string& path, std::vector<u8>* out) {
    Descriptor file(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK));
    if (file.fd < 0) return errno == ENOENT ? Status::error(ErrorCode::kNotFound, "analysis cache not found") : io("open", errno);
    struct stat info{};
    if (::fstat(file.fd, &info) != 0) return io("stat", errno);
    if (!S_ISREG(info.st_mode)) return bad("cache is not a regular file");
    if (info.st_size < static_cast<off_t>(kHeaderBytes)) return bad("truncated header");
    if (static_cast<u64>(info.st_size) > AnalysisCache::kMaxFileBytes) return large("file exceeds 128 MiB");
    out->resize(static_cast<size_t>(info.st_size));
    size_t position = 0;
    while (position < out->size()) {
        const auto amount = ::read(file.fd, out->data() + position, out->size() - position);
        if (amount < 0) { if (errno == EINTR) continue; return io("read", errno); }
        if (amount == 0) return bad("file changed/truncated while reading");
        position += static_cast<size_t>(amount);
    }
    u8 extra = 0;
    ssize_t amount;
    do { amount = ::read(file.fd, &extra, 1); } while (amount < 0 && errno == EINTR);
    if (amount < 0) return io("read EOF", errno);
    if (amount != 0) return bad("file changed/grew while reading");
    return Status::success();
}

Status writeAll(int fd, const u8* data, size_t size) {
    size_t position = 0;
    while (position < size) {
        const auto amount = ::write(fd, data + position, size - position);
        if (amount < 0) { if (errno == EINTR) continue; return io("write", errno); }
        if (amount == 0) return io("short write", EIO);
        position += static_cast<size_t>(amount);
    }
    return Status::success();
}

}  // namespace

Status AnalysisCache::load(const std::string& path, const std::string& dependencyKey, CachedAnalysis* out) {
    if (!out || path.empty() || path.find('\0') != std::string::npos || dependencyKey.empty() ||
        dependencyKey.size() > kMaxKeyBytes || dependencyKey.find('\0') != std::string::npos)
        return bad("invalid load arguments");
    std::vector<u8> bytes;
    auto status = readFile(path, &bytes);
    if (!status.ok()) return status;
    if (std::memcmp(bytes.data(), kMagic, sizeof(kMagic)) != 0) return bad("invalid magic");
    Reader header(bytes.data() + sizeof(kMagic), kHeaderBytes - sizeof(kMagic));
    u32 version = 0, flags = 0, crc = 0, reserved = 0;
    u64 length = 0;
    if (!header.number(&version) || !header.number(&flags) || !header.integer(8, &length) ||
        !header.number(&crc) || !header.number(&reserved) || version != kVersion || flags || reserved)
        return bad("unsupported header/version");
    if (length != bytes.size() - kHeaderBytes) return bad("payload size disagrees with file length");
    if (checksum(bytes.data() + kHeaderBytes, static_cast<size_t>(length)) != crc) return bad("checksum mismatch");
    CachedAnalysis candidate;
    status = decode(bytes.data() + kHeaderBytes, static_cast<size_t>(length), dependencyKey, &candidate);
    if (status.ok()) *out = std::move(candidate);
    return status;
}

Status AnalysisCache::save(const std::string& path, const std::string& dependencyKey, const CachedAnalysis& cache) {
    if (path.empty() || path.find('\0') != std::string::npos) return bad("invalid cache path");
    Writer payload;
    auto status = encode(dependencyKey, cache, &payload);
    if (!status.ok()) return status;
    Writer header;
    header.data.insert(header.data.end(), std::begin(kMagic), std::end(kMagic));
    header.integer(kVersion, 4); header.integer(0, 4); header.integer(payload.data.size(), 8);
    header.integer(checksum(payload.data.data(), payload.data.size()), 4); header.integer(0, 4);

    // Same-directory mkstemp gives an atomic rename and avoids following a
    // caller-supplied temporary-file symlink. The good cache is untouched until
    // every byte has been written and fsync has succeeded.
    std::string pattern = path + ".tmp.XXXXXX";
    std::vector<char> temporary(pattern.begin(), pattern.end());
    temporary.push_back('\0');
    Descriptor file(::mkstemp(temporary.data()));
    if (file.fd < 0) return io("create temporary", errno);
    ::fcntl(file.fd, F_SETFD, FD_CLOEXEC);
    status = writeAll(file.fd, header.data.data(), header.data.size());
    if (status.ok()) status = writeAll(file.fd, payload.data.data(), payload.data.size());
    if (status.ok() && ::fsync(file.fd) != 0) status = io("fsync", errno);
    if (::close(file.fd) != 0 && status.ok()) status = io("close", errno);
    file.fd = -1;
    if (status.ok() && ::rename(temporary.data(), path.c_str()) != 0) status = io("rename", errno);
    if (!status.ok()) ::unlink(temporary.data());
    else {
        // Persist the directory entry on ordinary filesystems as well. Rename
        // is already the commit point: a post-commit directory-sync failure
        // must not be reported as a failed transaction that preserved the old
        // file. This is a recoverable derived cache, so unsupported directory
        // fsync degrades to a cache miss after a crash, never lost user state.
        const auto slash = path.find_last_of('/');
        const auto parent = slash == std::string::npos ? std::string(".") :
                            slash == 0 ? std::string("/") : path.substr(0, slash);
        Descriptor directory(::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (directory.fd >= 0) ::fsync(directory.fd);
    }
    return status;
}

}  // namespace mint
