#include "mint/loader/zip_reader.h"

#include <algorithm>
#include <cstring>

#include <zlib.h>

namespace mint {
namespace {

constexpr u32 kEocd = 0x06054b50;
constexpr u32 kCentral = 0x02014b50;
constexpr u32 kLocal = 0x04034b50;

bool read16(ByteView view, u64 offset, u16* value) { return view.read(offset, value); }
bool read32(ByteView view, u64 offset, u32* value) { return view.read(offset, value); }

}  // namespace

Status ZipReader::open(ByteView file) {
    file_ = file; entries_.clear();
    const u64 search = std::min<u64>(file.size(), 0xffff + 22);
    u64 eocd = kNoAddress;
    for (u64 i = file.size() - search; i + 4 <= file.size(); ++i) {
        u32 signature = 0;
        if (read32(file, i, &signature) && signature == kEocd) { eocd = i; break; }
    }
    if (eocd == kNoAddress) return Status::error(ErrorCode::kBadFormat, "ZIP end-of-central-directory not found");
    u16 disk = 0, diskEntries = 0, entries = 0, comment = 0; u32 centralSize = 0, centralOffset = 0;
    if (!read16(file, eocd + 4, &disk) || !read16(file, eocd + 8, &diskEntries) || !read16(file, eocd + 10, &entries) ||
        !read32(file, eocd + 12, &centralSize) || !read32(file, eocd + 16, &centralOffset) || !read16(file, eocd + 20, &comment))
        return Status::error(ErrorCode::kTruncated, "truncated ZIP end record");
    if (disk != 0 || diskEntries != entries) return Status::error(ErrorCode::kUnsupported, "multi-disk ZIP is unsupported");
    if (!file.covers(centralOffset, centralSize)) return Status::error(ErrorCode::kTruncated, "ZIP central directory is truncated");
    u64 cursor = centralOffset;
    for (u32 i = 0; i < entries; ++i) {
        u32 signature = 0; u16 nameSize = 0, extraSize = 0, commentSize = 0; u16 method = 0; u32 crc = 0, compressed = 0, uncompressed = 0, local = 0;
        if (!read32(file, cursor, &signature) || signature != kCentral || !read16(file, cursor + 10, &method) ||
            !read32(file, cursor + 16, &crc) || !read32(file, cursor + 20, &compressed) || !read32(file, cursor + 24, &uncompressed) ||
            !read16(file, cursor + 28, &nameSize) || !read16(file, cursor + 30, &extraSize) || !read16(file, cursor + 32, &commentSize) ||
            !read32(file, cursor + 42, &local)) return Status::error(ErrorCode::kTruncated, "truncated ZIP central entry");
        if (!file.covers(cursor + 46, static_cast<u64>(nameSize) + extraSize + commentSize)) return Status::error(ErrorCode::kTruncated, "truncated ZIP entry name");
        std::string name(reinterpret_cast<const char*>(file.data() + cursor + 46), nameSize);
        entries_.push_back({std::move(name), method, crc, compressed, uncompressed, local});
        cursor += 46 + nameSize + extraSize + commentSize;
    }
    return Status::success();
}

const ZipEntry* ZipReader::find(const std::string& name) const {
    for (const ZipEntry& entry : entries_) if (entry.name == name) return &entry;
    return nullptr;
}

Status ZipReader::extract(const std::string& name, std::vector<u8>* output) const {
    const ZipEntry* entry = find(name);
    return entry ? extract(*entry, output) : Status::error(ErrorCode::kNotFound, "ZIP entry not found: " + name);
}

Status ZipReader::extract(const ZipEntry& entry, std::vector<u8>* output) const {
    if (!output) return Status::error(ErrorCode::kInternalError, "null ZIP output");
    u32 signature = 0; u16 nameSize = 0, extraSize = 0;
    if (!read32(file_, entry.localHeaderOffset, &signature) || signature != kLocal || !read16(file_, entry.localHeaderOffset + 26, &nameSize) || !read16(file_, entry.localHeaderOffset + 28, &extraSize))
        return Status::error(ErrorCode::kTruncated, "truncated ZIP local header");
    const u64 dataOffset = entry.localHeaderOffset + 30 + nameSize + extraSize;
    if (!file_.covers(dataOffset, entry.compressedSize) || entry.uncompressedSize > 256ull * 1024 * 1024)
        return Status::error(ErrorCode::kTooLarge, "invalid or oversized ZIP entry");
    ByteView compressed(file_.data() + dataOffset, static_cast<size_t>(entry.compressedSize));
    output->assign(static_cast<size_t>(entry.uncompressedSize), 0);
    if (entry.method == 0) {
        if (entry.compressedSize != entry.uncompressedSize) return Status::error(ErrorCode::kBadFormat, "stored ZIP size mismatch");
        std::memcpy(output->data(), compressed.data(), compressed.size());
    } else if (entry.method == 8) {
        z_stream stream{};
        stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(compressed.data()));
        stream.avail_in = static_cast<uInt>(compressed.size());
        stream.next_out = reinterpret_cast<Bytef*>(output->data());
        stream.avail_out = static_cast<uInt>(output->size());
        if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) return Status::error(ErrorCode::kInternalError, "zlib initialization failed");
        const int code = inflate(&stream, Z_FINISH);
        inflateEnd(&stream);
        if (code != Z_STREAM_END || stream.total_out != output->size()) return Status::error(ErrorCode::kBadFormat, "invalid deflated ZIP entry");
    } else return Status::error(ErrorCode::kUnsupported, "ZIP compression method unsupported");
    return Status::success();
}

}  // namespace mint
