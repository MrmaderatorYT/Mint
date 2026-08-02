#pragma once

#include <string>
#include <vector>

#include "mint/base/byte_view.h"
#include "mint/base/status.h"

namespace mint {

struct ZipEntry {
    std::string name;
    u32 method = 0;
    u32 crc32 = 0;
    u64 compressedSize = 0;
    u64 uncompressedSize = 0;
    u64 localHeaderOffset = 0;
};

class ZipReader {
public:
    Status open(ByteView file);
    const std::vector<ZipEntry>& entries() const { return entries_; }
    const ZipEntry* find(const std::string& name) const;
    Status extract(const ZipEntry& entry, std::vector<u8>* output) const;
    Status extract(const std::string& name, std::vector<u8>* output) const;

private:
    ByteView file_;
    std::vector<ZipEntry> entries_;
};

}  // namespace mint
