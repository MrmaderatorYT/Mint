#ifndef MINT_PLUGIN_SDK_H
#define MINT_PLUGIN_SDK_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define MINT_PLUGIN_ABI_V1 1u
#define MINT_PLUGIN_EXPORT __attribute__((visibility("default")))

// All buffers belong to the caller. Addresses retain all64 bits. Return0 is
// success; nonzero is failure. Host context and API pointers are valid only for
// the synchronous command invocation; plugins must not retain them or spawn
// workers using them. No C++ objects, allocator ownership or exceptions cross ABI.
typedef struct MintPluginFunctionV1 {
    uint64_t entry, instruction_count;
    uint32_t origin, incomplete;
    char name[256];
} MintPluginFunctionV1;
enum MintPluginQueryV1 {
    MINT_QUERY_ANNOTATION=0, MINT_QUERY_REFERENCES=1, MINT_QUERY_SEARCH=2,
    MINT_QUERY_DECOMPILE=3, MINT_QUERY_IR=4, MINT_QUERY_CFG=5,
    MINT_QUERY_TYPES=6, MINT_QUERY_MEMORY=7, MINT_QUERY_DWARF=8
};
typedef struct MintPluginHostV1 {
    uint32_t abi_version, struct_size;
    void* context;
    int (*function_count)(void*,uint64_t*);
    int (*function_at)(void*,uint64_t,MintPluginFunctionV1*);
    int (*read_memory)(void*,uint64_t,void*,size_t);
    // needed excludes NUL. Insufficient buffer reports needed without a partial
    // copy; capacity0/outputNULL is a size query. Results are capped at1 MiB.
    int (*query_text)(void*,uint32_t,uint64_t,const char*,char*,size_t,size_t*);
    int (*edit)(void*,uint64_t,const char*,const char*);
    int (*define_type)(void*,const char*);
    int (*output)(void*,const char*,size_t);
    const char* (*last_error)(void*);
    uint32_t allow_edits;
} MintPluginHostV1;
typedef int (*MintPluginRunV1)(const MintPluginHostV1*,const char* arguments);
typedef struct MintPluginCommandV1 { const char* id;const char* title;MintPluginRunV1 run; } MintPluginCommandV1;
typedef struct MintPluginV1 {
    uint32_t abi_version, struct_size;
    const char* id;const char* title;
    uint32_t command_count;
    const MintPluginCommandV1* commands;
} MintPluginV1;
// A dynamic library exports this function. Loading native code is an explicitly
// trusted operation, NOT a security sandbox. Use Lua for constrained extensions.
typedef const MintPluginV1* (*MintPluginEntryV1)(void);
MINT_PLUGIN_EXPORT const MintPluginV1* mint_plugin_v1(void);
// Optional ABI2 lifecycle observers and explicitly invoked analysis passes.
// Observers always receive a read-only host API. Pass edits require a separate
// user-authorized invocation; neither callback executes automatically on load.
#define MINT_PLUGIN_EXTENSION_ABI_V2 2u
enum MintPluginEventKindV2 {MINT_EVENT_ANALYSIS_COMPLETED=1,MINT_EVENT_ANNOTATION_CHANGED=2,MINT_EVENT_BEFORE_DECOMPILE=3,MINT_EVENT_AFTER_DECOMPILE=4};
typedef struct MintPluginEventV2 {uint32_t struct_size,kind;uint64_t address;const char* detail;} MintPluginEventV2;
typedef int (*MintPluginObserveV2)(void*,const MintPluginHostV1*,const MintPluginEventV2*);
typedef int (*MintPluginAnalyzeV2)(void*,const MintPluginHostV1*,const char*);
typedef struct MintPluginAnalysisPassV2 {const char* id;const char* title;MintPluginAnalyzeV2 run;} MintPluginAnalysisPassV2;
typedef struct MintPluginExtensionV2 {
    uint32_t abi_version,struct_size;const char* id;const char* title;void* context;
    MintPluginObserveV2 observe;uint32_t pass_count;const MintPluginAnalysisPassV2* passes;
} MintPluginExtensionV2;
typedef const MintPluginExtensionV2* (*MintPluginExtensionEntryV2)(void);
MINT_PLUGIN_EXPORT const MintPluginExtensionV2* mint_plugin_extension_v2(void);

#ifdef __cplusplus
}
#endif
#endif
