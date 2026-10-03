#include "mint/plugin/architecture_sdk.h"
#include <string.h>
/* Toy native ISA: 0x10 IMM8 writes r0; 0xff returns. Real C ABI2 DSO fixture. */
static int decode(void* context,uint64_t address,const uint8_t* bytes,size_t count,MintArchitectureInstructionV1* output){
    (void)context;if(!count||(bytes[0]!=0x10&&bytes[0]!=0xff)||(bytes[0]==0x10&&count<2))return -1;
    output->address=address;output->instruction_id=bytes[0]==0xff?2:1;output->size=bytes[0]==0xff?1:2;output->flow=bytes[0]==0xff?MINT_FLOW_RETURN:MINT_FLOW_NORMAL;
    strcpy(output->mnemonic,bytes[0]==0xff?"ret":"mov");return 0;
}
static int lift(void* context,uint64_t address,const uint8_t* bytes,size_t count,MintSemanticFragmentV2* output){
    (void)context;(void)address;(void)count;output->operation_count=1;MintSemanticOperationV2* operation=&output->operations[0];
    if(bytes[0]==0xff){operation->op=MINT_IR_RETURN;operation->a.space=MINT_VALUE_CONSTANT;operation->a.width=8;}
    else{operation->op=MINT_IR_COPY;operation->destination.space=MINT_VALUE_REGISTER;operation->destination.width=8;operation->a.space=MINT_VALUE_CONSTANT;operation->a.width=8;operation->a.value=bytes[1];}return 0;
}
static const MintArchitectureRegisterV2 registers[]={{0,8,{0},"r0"},{8,8,{0},"sp"}};
static const MintArchitectureDescriptorV1 architecture={1,sizeof(MintArchitectureDescriptorV1),185,8,1,2,1,0,0,"sdk-toy-semantics64","Toy64 verified semantics",{0},0,decode};
static const MintArchitecturePluginV1 decoders={1,sizeof(MintArchitecturePluginV1),"toy-semantic-decoder","Toy semantic decoder",1,&architecture};
static const MintArchitectureSemanticsV2 semantics={2,sizeof(MintArchitectureSemanticsV2),185,8,{0},16,2,registers,8,0,1,{0},0,lift};
static const MintArchitecturePluginV2 plugin={2,sizeof(MintArchitecturePluginV2),&decoders,1,&semantics};
MINT_ARCHITECTURE_EXPORT const MintArchitecturePluginV2* mint_architecture_plugin_v2(void){return &plugin;}
