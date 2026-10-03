#include "mint/plugin/architecture_sdk.h"
#include <stdio.h>
#include <string.h>

/* Decoder-only C plugin. This tiny fixture ISA is not a new claimed production
 * architecture: 00=nop, FF=ret, 10=conditional branch followed by LEu64 target. */
static int decode(void* context, uint64_t address, const uint8_t* bytes, size_t size, MintArchitectureInstructionV1* out) {
    (void)context;
    if (!size) return -1;
    out->address = address; out->size = 1; out->flow = MINT_FLOW_NORMAL;
    out->target = MINT_ARCHITECTURE_NO_TARGET;
    if (bytes[0] == 0) { strcpy(out->mnemonic, "nop"); return 0; }
    if (bytes[0] == 255) { strcpy(out->mnemonic, "ret"); out->flow = MINT_FLOW_RETURN; return 0; }
    if (bytes[0] == 16 && size >= 9) {
        unsigned i; uint64_t target = 0;
        for (i = 0; i < 8; ++i) target |= (uint64_t)bytes[i + 1] << (i * 8);
        out->size = 9; out->flow = MINT_FLOW_CONDITIONAL_JUMP; out->target = target;
        strcpy(out->mnemonic, "jz"); snprintf(out->operands, sizeof(out->operands), "0x%llx", (unsigned long long)target); return 0;
    }
    return -1;
}
static const MintArchitectureDescriptorV1 architecture = {
    MINT_ARCHITECTURE_ABI_V1, sizeof(MintArchitectureDescriptorV1),
    180, 8, 1, 9, 1, 0, 0, "sdk-toy64", "SDK fixture toy64", {0}, NULL, decode
};
static const MintArchitecturePluginV1 plugin = {
    MINT_ARCHITECTURE_ABI_V1, sizeof(MintArchitecturePluginV1),
    "decoder-sample", "Decoder-only SDK fixture", 1, &architecture
};
MINT_ARCHITECTURE_EXPORT const MintArchitecturePluginV1* mint_architecture_plugin_v1(void) { return &plugin; }
