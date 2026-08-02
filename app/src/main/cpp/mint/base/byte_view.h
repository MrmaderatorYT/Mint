#pragma once

#include <cstring>
#include <string>
#include <type_traits>

#include "mint/base/types.h"

namespace mint {

/// A non-owning, bounds-checked view over bytes we did not produce.
///
/// Every byte this engine parses comes from a file a user found somewhere, and
/// a good share of those files are deliberately malformed — packers and
/// protectors emit broken headers specifically to crash naive tools. So there
/// is no unchecked accessor here at all: the only ways to get data out return
/// either `bool` or an out-parameter that is left untouched on failure. Code
/// that forgets to check therefore reads a zero, never past the buffer.
class ByteView {
public:
    ByteView() = default;

    ByteView(const u8* data, size_t size)
        : data_(size == 0 ? nullptr : data), size_(data == nullptr ? 0 : size) {}

    const u8* data() const { return data_; }
    size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

    /// True when [offset, offset + length) lies inside the view. Written with
    /// no additions on the left-hand side so it cannot itself overflow.
    bool covers(u64 offset, u64 length) const {
        if (offset > size_) return false;
        return length <= size_ - offset;
    }

    /// A sub-view, or an empty view if the range is out of bounds. Chaining
    /// subviews is safe: an empty view yields empty views.
    ByteView subview(u64 offset, u64 length) const {
        if (!covers(offset, length)) return {};
        return ByteView(data_ + offset, static_cast<size_t>(length));
    }

    /// Everything from `offset` onwards, or empty if `offset` is past the end.
    ByteView from(u64 offset) const {
        if (offset > size_) return {};
        return ByteView(data_ + offset, static_cast<size_t>(size_ - offset));
    }

    bool byteAt(u64 offset, u8* out) const {
        if (!covers(offset, 1)) return false;
        *out = data_[offset];
        return true;
    }

    /// Reads a fixed-width integer. `T` must be a trivial integral type; the
    /// bytes are interpreted little-endian, which covers every architecture
    /// this engine targets (AArch64 and x86-64 are both little-endian in every
    /// Android configuration, and DEX is little-endian by specification).
    template <typename T>
    bool read(u64 offset, T* out) const {
        static_assert(std::is_integral<T>::value || std::is_enum<T>::value,
                      "ByteView::read is for integral and enum types");
        if (!covers(offset, sizeof(T))) return false;
        T value;
        std::memcpy(&value, data_ + offset, sizeof(T));
        *out = value;
        return true;
    }

    /// Reads a whole fixed-layout record. Used for ELF and DEX tables, where
    /// reading field by field would turn every loop over thousands of entries
    /// into a wall of offset arithmetic nobody can review.
    ///
    /// Safe against misaligned input because it goes through memcpy: the mapped
    /// file offers no alignment guarantee, and an unaligned struct load is
    /// undefined behaviour even on architectures that tolerate it.
    template <typename T>
    bool readPod(u64 offset, T* out) const {
        static_assert(std::is_trivially_copyable<T>::value,
                      "readPod requires a trivially copyable record");
        if (!covers(offset, sizeof(T))) return false;
        std::memcpy(out, data_ + offset, sizeof(T));
        return true;
    }

    /// Reads a big-endian integer. Needed because ZIP and a few DEX-adjacent
    /// container formats mix endianness.
    template <typename T>
    bool readBE(u64 offset, T* out) const {
        static_assert(std::is_integral<T>::value, "readBE is for integral types");
        if (!covers(offset, sizeof(T))) return false;
        using U = typename std::make_unsigned<T>::type;
        U value = 0;
        for (size_t i = 0; i < sizeof(T); ++i) {
            value = static_cast<U>((value << 8) | data_[offset + i]);
        }
        *out = static_cast<T>(value);
        return true;
    }

    /// Copies out a NUL-terminated string starting at `offset`, stopping at the
    /// end of the view if the terminator is missing. `maxLength` caps the
    /// result so a view full of non-zero bytes cannot produce a huge string.
    bool cString(u64 offset, std::string* out, size_t maxLength = 4096) const {
        if (offset >= size_) return false;
        const size_t available = static_cast<size_t>(size_ - offset);
        const size_t limit = available < maxLength ? available : maxLength;
        const u8* start = data_ + offset;
        size_t length = 0;
        while (length < limit && start[length] != 0) ++length;
        out->assign(reinterpret_cast<const char*>(start), length);
        return true;
    }

private:
    const u8* data_ = nullptr;
    size_t size_ = 0;
};

/// Sequential cursor over a ByteView, for headers that are read field by field.
/// Once a read fails the cursor latches into a failed state, so a caller can
/// parse a whole structure and check `ok()` once at the end instead of testing
/// every field — which is what makes bounds-checked parsing readable enough
/// that nobody is tempted to bypass it.
class ByteCursor {
public:
    explicit ByteCursor(ByteView view, u64 offset = 0) : view_(view), offset_(offset) {}

    bool ok() const { return ok_; }
    u64 offset() const { return offset_; }
    void seek(u64 offset) { offset_ = offset; }

    template <typename T>
    T next() {
        T value{};
        if (!ok_ || !view_.read<T>(offset_, &value)) {
            ok_ = false;
            return T{};
        }
        offset_ += sizeof(T);
        return value;
    }

    void skip(u64 count) {
        if (!ok_) return;
        if (!view_.covers(offset_, count)) {
            ok_ = false;
            return;
        }
        offset_ += count;
    }

    /// Unsigned LEB128, as used throughout DEX.
    u64 nextUleb128() {
        u64 result = 0;
        int shift = 0;
        while (ok_) {
            u8 byte = 0;
            if (!view_.byteAt(offset_, &byte)) {
                ok_ = false;
                return 0;
            }
            ++offset_;
            if (shift < 64) {
                result |= static_cast<u64>(byte & 0x7f) << shift;
            }
            shift += 7;
            if ((byte & 0x80) == 0) return result;
            if (shift > 70) {  // Malformed: no terminator in a plausible span.
                ok_ = false;
                return 0;
            }
        }
        return 0;
    }

    /// Signed LEB128, as used by DEX debug info.
    i64 nextSleb128() {
        u64 result = 0;
        int shift = 0;
        u8 byte = 0;
        while (ok_) {
            if (!view_.byteAt(offset_, &byte)) {
                ok_ = false;
                return 0;
            }
            ++offset_;
            if (shift < 64) {
                result |= static_cast<u64>(byte & 0x7f) << shift;
            }
            shift += 7;
            if ((byte & 0x80) == 0) break;
            if (shift > 70) {
                ok_ = false;
                return 0;
            }
        }
        // Sign-extend from the last payload bit we consumed.
        if (shift < 64 && (byte & 0x40) != 0) {
            result |= ~static_cast<u64>(0) << shift;
        }
        return static_cast<i64>(result);
    }

private:
    ByteView view_;
    u64 offset_ = 0;
    bool ok_ = true;
};

}  // namespace mint
