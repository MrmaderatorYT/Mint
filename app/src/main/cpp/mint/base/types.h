#pragma once

#include <cstddef>
#include <cstdint>

namespace mint {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i8 = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

/// A virtual address inside the binary being analysed. Always 64-bit, even for
/// Dalvik front-ends, where the low bits hold a method-relative offset — a
/// single address type is what lets one decompiler backend serve every loader.
using Address = u64;

/// Sentinel for "no such address". Chosen over 0 because 0 is a legitimate
/// virtual address in a PIE image.
constexpr Address kNoAddress = ~static_cast<Address>(0);

/// A file offset. Distinct from Address on purpose: confusing the two is the
/// single most common bug in binary loaders, so the compiler should not help
/// you do it silently.
enum class FileOffset : u64 {};

constexpr u64 raw(FileOffset o) { return static_cast<u64>(o); }

enum class Arch : u8 {
    kUnknown = 0,
    kAArch64,
    kX86_64,
    kDalvik,
    kArm32,
    kThumb,
    kX86_32,
    kRiscV32,
    kRiscV64,
    /// External decoder descriptors may use values 128..254. Builtin IDs are
    /// stable because persisted Programs include the architecture byte.
    kPluginFirst = 128,
};

enum class Endian : u8 {
    kLittle = 0,
    kBig,
};

const char* archName(Arch arch);

}  // namespace mint
