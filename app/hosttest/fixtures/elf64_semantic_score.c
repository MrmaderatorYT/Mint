#include <stdint.h>

uint32_t mint_score(uint32_t input) {
    return (input ^ UINT32_C(53)) + UINT32_C(7);
}
