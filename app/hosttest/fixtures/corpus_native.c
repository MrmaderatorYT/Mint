/* Reproducible freestanding compiler corpus. No libc, startup or host execution.
 * Deliberately preserves real optimizer/ISA choices; unsupported instructions
 * must be reported as coverage, never treated as successfully modeled math. */
typedef unsigned int corpus_u32;
typedef corpus_u32 (*corpus_callback)(corpus_u32);
#define CORPUS __attribute__((noinline, used, visibility("default")))

CORPUS corpus_u32 corpus_constant(void) { return 37u; }
CORPUS corpus_u32 corpus_arithmetic(corpus_u32 a, corpus_u32 b) {
    return ((a + b) * 3u) ^ 0x55u;
}
CORPUS corpus_u32 corpus_condition(corpus_u32 a, corpus_u32 b) {
    if (a < b) return b - a;
    return a - b;
}
CORPUS corpus_u32 corpus_loop(corpus_u32 count) {
    corpus_u32 sum = 0;
    for (corpus_u32 n = 0; n < (count & 31u); ++n) sum += n * 3u + 1u;
    return sum;
}
CORPUS corpus_u32 corpus_memory(const corpus_u32* data, corpus_u32 index) {
    return data[index & 3u] + 1u;
}
CORPUS corpus_u32 corpus_switch(corpus_u32 value) {
    switch (value) {
        case 1: return 113u;
        case 3: return 227u;
        case 5: return 331u;
        case 7: return 449u;
        case 11: return 557u;
        default: return value ^ 17u;
    }
}
CORPUS corpus_u32 corpus_plus_one(corpus_u32 value) { return value + 1u; }
CORPUS corpus_u32 corpus_double(corpus_u32 value) { return value * 2u; }
CORPUS corpus_u32 corpus_indirect(corpus_callback callback, corpus_u32 value) {
    return callback(value) + 9u;
}
const corpus_u32 corpus_data[4] = {11u, 23u, 37u, 53u};
const corpus_callback corpus_callbacks[2] = {corpus_plus_one, corpus_double};
CORPUS corpus_u32 corpus_entry(corpus_u32 seed) {
    return corpus_constant() + corpus_arithmetic(seed, 7u) +
        corpus_condition(seed, 13u) + corpus_loop(seed) +
        corpus_memory(corpus_data, seed) + corpus_switch(seed) +
        corpus_indirect(corpus_callbacks[seed & 1u], seed);
}
