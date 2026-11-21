// Freestanding compiler fixture. Distinct noinline bodies prevent replacing
// the control-flow switch with a table of returned scalar constants.
#define CASE(N,VALUE) \
    __attribute__((noinline)) static long case_##N(long value) { \
        __asm__ volatile("" : "+r"(value)); return value + VALUE; \
    }
CASE(0,11) CASE(1,29) CASE(2,47) CASE(3,73) CASE(4,101) CASE(5,131)
__attribute__((visibility("default"),noinline))
#ifdef MINT_COPY_ELIDED
long pic_switch(unsigned selector,long value,unsigned salt) {
#else
long pic_switch(unsigned selector,long value) {
#endif
    // A live volatile frame on every path keeps stack setup before the guard,
    // rather than shrink-wrapping a push into the narrow dispatch sequence.
    volatile long saved=value;
#ifdef MINT_COPY_ELIDED
    // An ordinary 32-bit XOR computes the index and clears the high bits.
    // Clang can address the table with the same register after CMP/JA.
    switch(selector ^ salt) {
#else
    switch(selector) {
#endif
    case 0:return case_0(saved);case 1:return case_1(saved);
    case 2:return case_2(saved);case 3:return case_3(saved);
    case 4:return case_4(saved);case 5:return case_5(saved);
    default:return saved ^ -1L;
    }
}
