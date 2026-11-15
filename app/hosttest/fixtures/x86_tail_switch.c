#define CASE(N,VALUE) \
    __attribute__((noinline)) static long tail_case_##N(long value) { \
        __asm__ volatile("" : "+r"(value)); return value + VALUE; \
    }
CASE(0,11) CASE(1,29) CASE(2,47) CASE(3,73) CASE(4,101) CASE(5,131)
__attribute__((visibility("default"),noinline))
long pic_tail_switch(unsigned selector,long value) {
    switch(selector) {
    case 0:return tail_case_0(value);case 1:return tail_case_1(value);
    case 2:return tail_case_2(value);case 3:return tail_case_3(value);
    case 4:return tail_case_4(value);case 5:return tail_case_5(value);
    default:return -1;
    }
}
