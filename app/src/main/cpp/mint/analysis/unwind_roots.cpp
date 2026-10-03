#include "mint/analysis/unwind_roots.h"

#include <limits>
#include <algorithm>
#include <map>

namespace mint {
namespace {

constexpr u8 kOmit = 0xff;

bool addUnsigned(Address base, u64 offset, Address* out) {
    if (offset > std::numeric_limits<Address>::max() - base) return false;
    *out = base + offset;
    return true;
}

bool addSigned(Address base, i64 offset, Address* out) {
    if (offset >= 0) return addUnsigned(base, static_cast<u64>(offset), out);
    const u64 magnitude = static_cast<u64>(-(offset + 1)) + 1;
    if (magnitude > base) return false;
    *out = base - magnitude;
    return true;
}

struct Reader {
    ByteView bytes;
    Address address;
    const MemoryMap& memory;
    size_t pointerWidth;
    size_t cursor = 0;

    template <typename T>
    bool fixed(T* out) {
        if (!bytes.read(cursor, out)) return false;
        cursor += sizeof(T);
        return true;
    }

    bool leb(bool isSigned, u64* out) {
        u64 bits = 0;
        for (unsigned i = 0; i < 10; ++i) {
            u8 byte = 0;
            if (!fixed(&byte)) return false;
            const u8 payload = byte & 0x7f;
            // The last group has one meaningful bit; reject overflows instead
            // of accepting a wrapped count or an attacker-chosen address.
            if (i == 9 && ((!isSigned && payload > 1) ||
                           (isSigned && payload != 0 && payload != 0x7f))) {
                return false;
            }
            bits |= u64(payload) << (i * 7);
            if ((byte & 0x80) == 0) {
                const unsigned used = (i + 1) * 7;
                if (isSigned && used < 64 && (byte & 0x40) != 0) {
                    bits |= ~u64(0) << used;
                }
                *out = bits;
                return true;
            }
        }
        return false;
    }

    bool encoded(u8 encoding, bool count, Address* out, bool nullable = false) {
        if (encoding == kOmit) return false;
        // A count is an integer, not a relocatable address. Unsupported base
        // encodings (textrel/funcrel/aligned) must not silently become absolute.
        const u8 application = encoding & 0x70;
        if ((count && (encoding & 0xf0) != 0) ||
            (application != 0 && application != 0x10 && application != 0x30)) {
            return false;
        }
        Address fieldAddress = 0;
        if (!addUnsigned(address, cursor, &fieldAddress)) return false;
        u64 raw = 0;
        bool isSigned = false;
        switch (encoding & 0x0f) {
            case 0x00:
                if (pointerWidth == 8) { if (!fixed(&raw)) return false; }
                else if (pointerWidth == 4) {
                    u32 value = 0; if (!fixed(&value)) return false; raw = value;
                } else return false;
                break;
            case 0x01: if (!leb(false, &raw)) return false; break;
            case 0x02: { u16 value = 0; if (!fixed(&value)) return false; raw = value; break; }
            case 0x03: { u32 value = 0; if (!fixed(&value)) return false; raw = value; break; }
            case 0x04: if (!fixed(&raw)) return false; break;
            case 0x09: isSigned = true; if (!leb(true, &raw)) return false; break;
            case 0x0a: { i16 value = 0; if (!fixed(&value)) return false; raw = static_cast<u64>(value); isSigned = true; break; }
            case 0x0b: { i32 value = 0; if (!fixed(&value)) return false; raw = static_cast<u64>(value); isSigned = true; break; }
            case 0x0c: isSigned = true; if (!fixed(&raw)) return false; break;
            default: return false;
        }
        if (nullable && raw == 0) { *out = 0; return true; }
        Address value = raw;
        if (application != 0) {
            const Address base = application == 0x10 ? fieldAddress : address;
            if (isSigned) {
                if (!addSigned(base, static_cast<i64>(raw), &value)) return false;
            } else if (!addUnsigned(base, raw, &value)) return false;
        } else if (isSigned && static_cast<i64>(raw) < 0) {
            return false;
        }
        if ((encoding & 0x80) != 0) {
            ByteView slot = memory.viewAt(value, pointerWidth);
            if (pointerWidth == 8) { if (!slot.read(0, &value)) return false; }
            else { u32 result = 0; if (!slot.read(0, &result)) return false; value = result; }
        }
        *out = value;
        return true;
    }
};

// Validate the record framing and the backwards CIE link. This does not execute
// CFI or infer stack variables: it establishes that a table entry points at an
// actual FDE, rather than arbitrary readable data presented as unwind metadata.
bool validFde(const MemoryMap& memory, Address fde, Address ehFrame) {
    const ByteView prefix = memory.viewAt(fde, 24);
    u32 length32 = 0;
    if (!prefix.read(0, &length32) || length32 == 0) return false;
    const bool extended = length32 == 0xffffffffu;
    const size_t headerSize = extended ? 12 : 4;
    const size_t idSize = 4; // EH frame IDs remain uint32 even with a 64-bit length.
    u64 length = length32;
    if (extended && !prefix.read(4, &length)) return false;
    constexpr u64 kMaxFrameBytes = 16 * 1024 * 1024;
    if (length < idSize + 2 || length > kMaxFrameBytes ||
        length > std::numeric_limits<u64>::max() - headerSize ||
        memory.viewAt(fde, length + headerSize).size() != length + headerSize) {
        return false;
    }
    Address ciePointerAt = 0;
    if (!addUnsigned(fde, headerSize, &ciePointerAt)) return false;
    u64 distance = 0;
    { u32 small = 0; if (!prefix.read(headerSize, &small)) return false; distance = small; }
    if (distance == 0 || distance > ciePointerAt) return false;
    const Address cie = ciePointerAt - distance;
    if (cie < ehFrame || cie >= fde) return false;
    const ByteView cieBytes = memory.viewAt(cie, 24);
    u32 cieLength = 0;
    if (!cieBytes.read(0, &cieLength) || cieLength == 0) return false;
    const bool cieExtended = cieLength == 0xffffffffu;
    const size_t cieHeader = cieExtended ? 12 : 4;
    const size_t cieIdSize = 4;
    u64 cieLength64 = cieLength;
    if (cieExtended && !cieBytes.read(4, &cieLength64)) return false;
    if (cieLength64 < cieIdSize + 2 || cieLength64 > kMaxFrameBytes ||
        memory.viewAt(cie, cieHeader + cieLength64).size() != cieHeader + cieLength64) {
        return false;
    }
    u64 cieId = 0;
    { u32 small = 0; if (!cieBytes.read(cieHeader, &small)) return false; cieId = small; }
    u8 version = 0;
    return cieId == 0 && cieBytes.byteAt(cieHeader + cieIdSize, &version) &&
           (version == 1 || version == 3 || version == 4);
}

Status malformed(const char* reason) {
    return Status::error(ErrorCode::kBadFormat,
                         std::string(".eh_frame_hdr: ") + reason);
}

struct Cie {
    bool valid = false, augmented = false, signal = false;
    u8 pointerEncoding = 0, lsdaEncoding = kOmit;
    Address personality = 0;
};
bool frameEncoding(u8 encoding) {
    // The header explicitly defines a data-relative base; an arbitrary CIE/FDE
    // does not. Without a validated GOT/text base, do not guess datarel/textrel.
    const u8 base = encoding & 0x70;
    return encoding != kOmit && (base == 0 || base == 0x10);
}
bool cieRecord(Reader reader, Cie* out) {
    u8 version = 0;
    if (!reader.fixed(&version) || (version != 1 && version != 3 && version != 4)) return false;
    std::string augmentation;
    for (unsigned i = 0; i < 64; ++i) {
        u8 byte = 0; if (!reader.fixed(&byte)) return false;
        if (!byte) break;
        if (byte < 0x20 || byte > 0x7e || i == 63) return false;
        augmentation.push_back(static_cast<char>(byte));
    }
    if (version == 4) {
        u8 width = 0, segment = 0;
        if (!reader.fixed(&width) || !reader.fixed(&segment) || width != reader.pointerWidth || segment != 0) return false;
    }
    u64 alignment = 0, dataAlignment = 0, returnRegister = 0;
    if (!reader.leb(false, &alignment) || !alignment || !reader.leb(true, &dataAlignment)) return false;
    if (version == 1) { u8 reg = 0; if (!reader.fixed(&reg)) return false; returnRegister = reg; }
    else if (!reader.leb(false, &returnRegister)) return false;
    if (returnRegister > 65535) return false;
    Cie result;
    if (augmentation.empty()) { result.valid = true; *out = result; return true; }
    if (augmentation[0] != 'z') return false; // Legacy "eh" has no validated interpretation here.
    result.augmented = true;
    u64 length = 0;
    if (!reader.leb(false, &length) || length > reader.bytes.size() - reader.cursor) return false;
    const size_t end = reader.cursor + static_cast<size_t>(length);
    reader.bytes = reader.bytes.subview(0, end);
    bool haveL = false, haveP = false, haveR = false;
    for (size_t i = 1; i < augmentation.size(); ++i) {
        switch (augmentation[i]) {
            case 'L':
                if (haveL || !reader.fixed(&result.lsdaEncoding) || (result.lsdaEncoding != kOmit && !frameEncoding(result.lsdaEncoding))) return false;
                haveL = true; break;
            case 'P': {
                u8 encoding = 0;
                if (haveP || !reader.fixed(&encoding) || !frameEncoding(encoding) || !reader.encoded(encoding, false, &result.personality, true)) return false;
                haveP = true; break;
            }
            case 'R':
                if (haveR || !reader.fixed(&result.pointerEncoding) || !frameEncoding(result.pointerEncoding)) return false;
                haveR = true; break;
            case 'S': result.signal = true; break;
            case 'B': case 'G': break; // A64 PAC B-key/MTE marker: no payload, no runtime interpretation.
            default: return false;
        }
    }
    if (reader.cursor > end) return false;
    result.valid = true; *out = result; return true;
}

bool executableExtent(const MemoryMap& memory, Address start, Address end) {
    const auto* segment = memory.segmentAt(start);
    return end > start && segment && segment->executable() && end <= segment->end() &&
           memory.viewAt(start, end - start).size() == end - start;
}

}  // namespace

Status parseEhFrameHeader(ByteView header, Address headerAddress,
                          const MemoryMap& memory, size_t pointerWidth,
                          size_t maxEntries,
                          std::vector<UnwindFunctionRoot>* out) {
    if (out == nullptr) return malformed("null output");
    out->clear();
    if (pointerWidth != 4 && pointerWidth != 8) return malformed("invalid pointer width");
    u8 version = 0, pointerEncoding = 0, countEncoding = 0, tableEncoding = 0;
    Reader reader{header, headerAddress, memory, pointerWidth};
    if (!reader.fixed(&version) || !reader.fixed(&pointerEncoding) ||
        !reader.fixed(&countEncoding) || !reader.fixed(&tableEncoding) || version != 1) {
        return malformed("invalid or truncated version-1 header");
    }
    Address ehFrame = 0;
    if (!reader.encoded(pointerEncoding, false, &ehFrame) ||
        memory.viewAt(ehFrame, 4).size() < 4) {
        return malformed("invalid EH-frame pointer or unsupported encoding");
    }
    if (countEncoding == kOmit || tableEncoding == kOmit) return Status::success();
    Address count = 0;
    if (!reader.encoded(countEncoding, true, &count) || count > maxEntries ||
        count > (header.size() - reader.cursor) / 2) {
        return malformed("invalid, truncated or excessive FDE count");
    }
    std::vector<UnwindFunctionRoot> roots;
    roots.reserve(static_cast<size_t>(count));
    Address previous = 0;
    for (Address i = 0; i < count; ++i) {
        Address entry = 0, fde = 0;
        if (!reader.encoded(tableEncoding, false, &entry) ||
            !reader.encoded(tableEncoding, false, &fde)) {
            return malformed("truncated table or unsupported pointer encoding");
        }
        if ((i != 0 && entry < previous) || !memory.isExecutable(entry) ||
            !validFde(memory, fde, ehFrame)) {
            return malformed("unsorted table or invalid executable/FDE target");
        }
        previous = entry;
        if (roots.empty() || roots.back().entry != entry) roots.push_back({entry, fde});
    }
    *out = std::move(roots);
    return Status::success();
}

Status parseEhFrameSection(ByteView section, Address sectionAddress,
                           const MemoryMap& memory, size_t pointerWidth,
                           size_t maxEntries, std::vector<UnwindFrame>* out,
                           std::vector<std::string>* notes) {
    auto bad = [](const char* reason) { return Status::error(ErrorCode::kBadFormat, std::string(".eh_frame: ") + reason); };
    if (!out) return bad("missing output");
    out->clear();
    if ((pointerWidth != 4 && pointerWidth != 8) || section.size() > 64 * 1024 * 1024 || maxEntries > 1000000) return bad("pointer width or inventory budget");
    std::vector<UnwindFrame> frames;
    std::map<size_t, Cie> cies;
    size_t cursor = 0, records = 0, rejected = 0;
    while (cursor < section.size()) {
        if (++records > 400000) return bad("record scan budget exceeded");
        const size_t start = cursor;
        u32 shortLength = 0;
        if (!section.read(cursor, &shortLength)) return bad("truncated record length");
        cursor += 4;
        if (shortLength == 0) break;
        u64 length = shortLength;
        if (shortLength == 0xffffffffu) { if (!section.read(cursor, &length)) return bad("truncated extended length"); cursor += 8; }
        else if (shortLength >= 0xfffffff0u) return bad("reserved record length");
        if (length < 4 || length > 16 * 1024 * 1024 || length > section.size() - cursor) return bad("invalid or truncated record body");
        const size_t body = cursor, end = cursor + static_cast<size_t>(length);
        u32 id = 0; if (!section.read(cursor, &id)) return bad("truncated CIE link");
        cursor = end;
        Reader reader{section.subview(0, end), sectionAddress, memory, pointerWidth, body + 4};
        if (id == 0) {
            Cie cie;
            if (!cieRecord(reader, &cie)) ++rejected;
            cies[start] = cie;
            continue;
        }
        if (id > body) { ++rejected; continue; }
        const size_t cieOffset = body - id;
        const auto found = cies.find(cieOffset);
        if (found == cies.end() || !found->second.valid || cieOffset >= start) { ++rejected; continue; }
        const Cie& cie = found->second;
        UnwindFrame frame; Address size = 0;
        if (!reader.encoded(cie.pointerEncoding, false, &frame.entry) ||
            !reader.encoded(cie.pointerEncoding & 0x0f, true, &size) || !size ||
            !addUnsigned(frame.entry, size, &frame.end) || !executableExtent(memory, frame.entry, frame.end) ||
            !addUnsigned(sectionAddress, start, &frame.fde) || !addUnsigned(sectionAddress, cieOffset, &frame.cie)) { ++rejected; continue; }
        if (cie.augmented) {
            u64 augmentationLength = 0;
            if (!reader.leb(false, &augmentationLength) || augmentationLength > end - reader.cursor) { ++rejected; continue; }
            const size_t augmentationEnd = reader.cursor + static_cast<size_t>(augmentationLength);
            reader.bytes = section.subview(0, augmentationEnd);
            if (cie.lsdaEncoding != kOmit && (!reader.encoded(cie.lsdaEncoding, false, &frame.lsda, true) ||
                (frame.lsda && memory.viewAt(frame.lsda, 1).empty()))) { ++rejected; continue; }
        }
        frame.personality = cie.personality; frame.signalFrame = cie.signal;
        if (frames.size() >= maxEntries) return bad("FDE inventory budget exceeded");
        frames.push_back(frame);
    }
    std::sort(frames.begin(), frames.end(), [](const UnwindFrame& a, const UnwindFrame& b) { return a.entry != b.entry ? a.entry < b.entry : a.fde < b.fde; });
    if (notes && rejected) notes->push_back(".eh_frame: excluded " + std::to_string(rejected) + " unsupported/invalid CIE/FDE records; no CFI execution or guessed roots");
    *out = std::move(frames);
    return Status::success();
}

std::vector<UnwindFrame> collectUnwindFrames(const ElfImage& image, size_t maxEntries, std::vector<std::string>* warnings) {
    std::vector<UnwindFrame> frames;
    const auto* section = image.findSection(".eh_frame");
    if (!section) section = image.findSection("__eh_frame"); // Mach-O section uses the same EH record format.
    if (!section) return frames;
    const ByteView bytes = image.memory().viewAt(section->addr, section->data.size());
    if (bytes.size() != section->data.size()) {
        if (warnings) warnings->push_back(".eh_frame: section is not fully file-backed in one mapped segment; excluded");
        return frames;
    }
    const auto status = parseEhFrameSection(bytes, section->addr, image.memory(), image.pointerSize(), maxEntries, &frames, warnings);
    if (!status.ok() && warnings) warnings->push_back(status.message());
    return frames;
}

std::vector<UnwindFunctionRoot> collectUnwindRoots(
    const ElfImage& image, size_t maxEntries, std::vector<std::string>* warnings) {
    std::vector<UnwindFunctionRoot> roots;
    const ElfSection* section = image.findSection(".eh_frame_hdr");
    if (section) {
        const ByteView bytes = image.memory().viewAt(section->addr, section->data.size());
        const Status status = bytes.size() == section->data.size()
            ? parseEhFrameHeader(bytes, section->addr, image.memory(), image.pointerSize(), maxEntries, &roots)
            : malformed("section is not fully file-backed in one mapped segment");
        if (!status.ok() && warnings) warnings->push_back(status.message());
        if (status.ok() && !roots.empty()) return roots;
    }
    for (const auto& frame : collectUnwindFrames(image, maxEntries, warnings)) {
        const Address entry = image.canonicalAddress(frame.entry);
        if (roots.empty() || roots.back().entry != entry) roots.push_back({entry, frame.fde});
    }
    return roots;
}

}  // namespace mint
