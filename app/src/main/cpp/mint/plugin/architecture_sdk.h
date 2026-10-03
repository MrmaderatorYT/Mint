#ifndef MINT_ARCHITECTURE_SDK_H
#define MINT_ARCHITECTURE_SDK_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define MINT_ARCHITECTURE_ABI_V1 1u
#define MINT_ARCHITECTURE_EXPORT __attribute__((visibility("default")))
#define MINT_ARCHITECTURE_NO_TARGET UINT64_MAX
enum MintArchitectureFlowV1 {
    MINT_FLOW_NORMAL = 0, MINT_FLOW_JUMP = 1, MINT_FLOW_CONDITIONAL_JUMP = 2,
    MINT_FLOW_CALL = 3, MINT_FLOW_INDIRECT_JUMP = 4,
    MINT_FLOW_INDIRECT_CALL = 5, MINT_FLOW_RETURN = 6, MINT_FLOW_TRAP = 7
};
typedef struct MintArchitectureInstructionV1 {
    uint32_t struct_size;
    uint16_t instruction_id;
    uint8_t size, flow;
    uint64_t address, target;
    char mnemonic[129], operands[1025]; /* Always NUL terminated. */
    uint8_t reserved[6]; /* Must remain zero. */
} MintArchitectureInstructionV1;
/* Input bytes are a borrowed bounded view, valid only for this call. Output
 * belongs to the host and is initialized with address, struct_size and no-target.
 * Return0 on a decoded instruction, nonzero for undecodable input. No allocator,
 * C++ exception or host object crosses ABI. A decoder must return exact address,
 * size and control-flow facts, not guesses. Raw instruction bytes are host-owned.
 * Calls for one decoder context are serialized; distinct contexts may run in
 * parallel. Context and callback must live for the remainder of the process.
 * No lifter, register ABI or decompiler semantics are claimed by this interface.
 */
typedef int (*MintArchitectureDecodeV1)(void* context, uint64_t address,
    const uint8_t* bytes, size_t byte_count, MintArchitectureInstructionV1* output);
typedef struct MintArchitectureDescriptorV1 {
    uint32_t abi_version, struct_size;
    uint8_t architecture; /*128..254; persistent, unique and never replaced.*/
    uint8_t pointer_size, minimum_instruction_size, maximum_instruction_size;
    uint8_t instruction_alignment, elf_class; /*ELFclass0(noELF),1,2.*/
    uint16_t elf_machine;
    char id[65], name[129];
    uint8_t reserved[6];
    void* context;
    MintArchitectureDecodeV1 decode;
} MintArchitectureDescriptorV1;
typedef struct MintArchitecturePluginV1 {
    uint32_t abi_version, struct_size;
    char id[65], title[129];
    uint32_t architecture_count; /*1..8, published atomically.*/
    const MintArchitectureDescriptorV1* architectures;
} MintArchitecturePluginV1;
typedef const MintArchitecturePluginV1* (*MintArchitecturePluginEntryV1)(void);
/* Optional export, independent of the unchanged command Plugin ABI1. Libraries
 * may export this alone. Loading is explicit unrestricted native-code trust,
 * not a security sandbox. Registered libraries stay pinned until process exit;
 * Session/Program replacement never unloads a live decoder callback. */
MINT_ARCHITECTURE_EXPORT const MintArchitecturePluginV1* mint_architecture_plugin_v1(void);
/* ABI2 adds verified MintIR semantics without changing ABI1 decoder layouts.
 * Ops and spaces below are stable C identifiers, not C++ enum ordinals. */
#define MINT_ARCHITECTURE_ABI_V2 2u
enum MintSemanticSpaceV2 { MINT_VALUE_NONE=0,MINT_VALUE_CONSTANT=1,MINT_VALUE_REGISTER=2,MINT_VALUE_TEMP=3 };
enum MintSemanticOpV2 {
    MINT_IR_COPY=1,MINT_IR_LOAD,MINT_IR_STORE,MINT_IR_ADD,MINT_IR_SUB,MINT_IR_MUL,
    MINT_IR_AND,MINT_IR_OR,MINT_IR_XOR,MINT_IR_NOT,MINT_IR_NEG,MINT_IR_SHL,MINT_IR_SHRU,MINT_IR_SHRS,
    MINT_IR_EQ,MINT_IR_NE,MINT_IR_LTU,MINT_IR_LTS,MINT_IR_LEU,MINT_IR_LES,
    MINT_IR_ZEXT,MINT_IR_SEXT,MINT_IR_TRUNC,MINT_IR_SELECT,
    MINT_IR_BRANCH,MINT_IR_COND_BRANCH,MINT_IR_BRANCH_IND,MINT_IR_CALL,MINT_IR_CALL_IND,MINT_IR_RETURN,MINT_IR_TRAP,MINT_IR_UNDEFINED
};
typedef struct MintSemanticValueV2 {uint64_t value;uint8_t space,width;uint8_t reserved[6];} MintSemanticValueV2;
typedef struct MintSemanticOperationV2 {uint32_t op,reserved;MintSemanticValueV2 destination,a,b,c;} MintSemanticOperationV2;
typedef struct MintSemanticFragmentV2 {
    uint32_t struct_size,operation_count,temporary_count;
    uint8_t instruction_size,reserved[3];
    MintSemanticOperationV2 operations[64];
} MintSemanticFragmentV2;
typedef int (*MintArchitectureLiftV2)(void*,uint64_t,const uint8_t*,size_t,MintSemanticFragmentV2*);
typedef struct MintArchitectureRegisterV2 {uint32_t byte_offset;uint8_t width,reserved[3];char name[65];} MintArchitectureRegisterV2;
typedef struct MintArchitectureSemanticsV2 {
    uint32_t abi_version,struct_size;uint8_t architecture,pointer_size;uint8_t reserved[2];
    uint32_t register_file_bytes,register_count;
    const MintArchitectureRegisterV2* registers;
    /* Exact ABI integer/pointer register slices; UINT32_MAX denotes unavailable. */
    uint32_t stack_pointer_offset,return_register_offset,argument_count,argument_offsets[16];
    void* context;MintArchitectureLiftV2 lift;
} MintArchitectureSemanticsV2;
typedef struct MintArchitecturePluginV2 {
    uint32_t abi_version,struct_size;
    const MintArchitecturePluginV1* decoders;
    uint32_t semantics_count;const MintArchitectureSemanticsV2* semantics;
} MintArchitecturePluginV2;
typedef const MintArchitecturePluginV2* (*MintArchitecturePluginEntryV2)(void);
MINT_ARCHITECTURE_EXPORT const MintArchitecturePluginV2* mint_architecture_plugin_v2(void);
#ifdef __cplusplus
}
#endif
#endif
