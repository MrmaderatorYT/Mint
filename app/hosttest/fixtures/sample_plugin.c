#include "mint/plugin/sdk.h"
#include <stdio.h>
#include <string.h>

static int inventory(const MintPluginHostV1* host,const char* arguments) {
    uint64_t count=0;if(!host || host->abi_version!=MINT_PLUGIN_ABI_V1 || host->function_count(host->context,&count))return -1;
    char line[512];int size=snprintf(line,sizeof(line),"sample inventory: %llu functions\n",(unsigned long long)count);
    if(size<0 || host->output(host->context,line,(size_t)size))return -1;
    for(uint64_t i=0;i<count && i<100;++i) {
        MintPluginFunctionV1 function;
        if(host->function_at(host->context,i,&function))return -1;
        size=snprintf(line,sizeof(line),"0x%llx\t%s\n",(unsigned long long)function.entry,function.name);
        if(size<0 || host->output(host->context,line,(size_t)size))return -1;
        if(arguments && strcmp(arguments,"rename")==0 && i==0)
            if(host->edit(host->context,function.entry,"name","plugin_entry"))return -1;
    }
    return 0;
}
static const MintPluginCommandV1 commands[]={{"inventory","List Program functions",inventory}};
static const MintPluginV1 plugin={MINT_PLUGIN_ABI_V1,sizeof(MintPluginV1),"sample","Mint SDK sample",1,commands};
MINT_PLUGIN_EXPORT const MintPluginV1* mint_plugin_v1(void){return &plugin;}
