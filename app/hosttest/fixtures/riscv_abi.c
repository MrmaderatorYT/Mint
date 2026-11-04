// Freestanding ABI probes: no target execution and no platform headers/runtime.
typedef unsigned int u32;
typedef unsigned long long u64;
typedef union {float real;u32 bits;} BitsF;
typedef union {double real;u64 bits;} BitsD;
typedef struct {float first,second;} PairF;
typedef struct {double first,second;} PairD;
typedef struct {float real;u32 integer;} Mixed;
typedef struct {float values[2];} Nested;
typedef struct __attribute__((packed)) {unsigned char tag;double real;} Packed;
typedef struct {u64 first,second;} PairI;
u64 mint_abi_named_pair(u32 prefix,u64 value){(void)prefix;return value;}
u32 mint_abi_high_u32(u32 value){return value>=0x80000000u;}
u64 mint_abi_last_pair(u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g,u64 value){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;return value;}
u64 mint_abi_split_aggregate(u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g,PairI value){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;return value.second;}
u64 mint_abi_fp_overflow(float a,float b,float c,float d,float e,float f,float g,float h,double value){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;BitsD bits;bits.real=value;return bits.bits;}
u32 mint_abi_mixed(Mixed value){BitsF bits;bits.real=value.real;return bits.bits^value.integer;}
u64 mint_abi_dpair(PairD value){BitsD bits;bits.real=value.second;return bits.bits;}
u32 mint_abi_fpair(PairF value){BitsF bits;bits.real=value.second;return bits.bits;}
u32 mint_abi_nested(Nested value){BitsF bits;bits.real=value.values[1];return bits.bits;}
u64 mint_abi_packed(Packed value){BitsD bits;bits.real=value.real;return bits.bits;}
