// A small library that exists to be read, not run.
//
// Every function here is chosen to exercise one thing the analysis does, so that
// opening this file shows real output for each view rather than a wall of
// prologue. Kept deliberately short: a listing that fits on a phone screen is
// worth more as a demonstration than a realistic but unreadable one.

#include <stdint.h>
#include <string.h>

struct Header {
    uint32_t magic;
    uint32_t version;
    uint64_t length;
    const char *name;
};

// A post-test loop, which is the shape the control-flow structurer recognises.
uint64_t checksum(const uint8_t *data, uint64_t length) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < length; i++) {
        sum = sum * 31u + data[i];
    }
    return sum;
}

// Consecutive loads from one base: the pattern struct recovery looks for.
int header_is_valid(const struct Header *header) {
    if (header->magic != 0x4d494e54u) return 0;
    if (header->version == 0 || header->version > 3) return 0;
    return header->length != 0;
}

// A dense switch, which compilers turn into an indirect jump through a table.
const char *kind_name(int kind) {
    switch (kind) {
        case 0: return "elf";
        case 1: return "dex";
        case 2: return "apk";
        case 3: return "archive";
        case 4: return "unknown";
        case 5: return "empty";
        case 6: return "packed";
        default: return "?";
    }
}

// Carry-propagating arithmetic: two words added as one wide value.
void add_wide(uint64_t *high, uint64_t *low, uint64_t addend) {
    uint64_t sum = *low + addend;
    if (sum < *low) (*high)++;
    *low = sum;
}

// Floating point, including a comparison that has to handle unordered.
int closer_to_zero(double left, double right) {
    double a = left < 0 ? -left : left;
    double b = right < 0 ? -right : right;
    if (a < b) return -1;
    if (b < a) return 1;
    return 0;
}

// A call the symbol resolver can name, plus a forwarded argument.
int names_match(const struct Header *header, const char *expected, uint64_t length) {
    if (header->name == 0) return 0;
    return memcmp(header->name, expected, length) == 0;
}
