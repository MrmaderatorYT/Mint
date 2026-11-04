typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef struct __attribute__((packed)) {u8 a,b,c;} B3;
typedef struct __attribute__((packed)) {u64 a;u8 b;} B9;
typedef struct {u32 a,b,c;} P12;
typedef struct {u64 a,b,c;} Large;
typedef float FloatPair[2];
typedef struct {FloatPair values;} HFA;
typedef struct {float value;} OneH;
typedef union {FloatPair pair;float one;} UnionH;
typedef struct __attribute__((packed)) {float a,b;} PackedH;
typedef union {float value;u32 bits;} FloatBits;
B3 mint_be_b3(B3 value){return value;}
B9 mint_be_b9(B9 value){return value;}
P12 mint_be_p12(P12 value){return value;}
Large mint_be_large(Large value){return value;}
u32 mint_be_stack_b3(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,B3 value){return value.c;}
u32 mint_be_stack_scalar(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,u8 value){return value;}
u32 mint_be_hfa(HFA value){FloatBits result;result.value=value.values[1];return result.bits;}
u32 mint_be_union(UnionH value){FloatBits result;result.value=value.pair[1];return result.bits;}
u32 mint_be_packed_hfa(PackedH value){FloatBits result;result.value=value.b;return result.bits;}
u32 mint_be_spilled_hfa(double a,double b,double c,double d,double e,double f,double g,double h,HFA value){FloatBits result;result.value=value.values[1];return result.bits;}
u32 mint_be_spilled_one(double a,double b,double c,double d,double e,double f,double g,double h,OneH value){FloatBits result;result.value=value.value;return result.bits;}
