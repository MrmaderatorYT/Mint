#include "mint/plugin/sdk.h"
static int observe(void* context,const MintPluginHostV1* api,const MintPluginEventV2* event){(void)context;(void)event;return api->output(api->context,"sample lifecycle observation\n",29);}
static int analyze(void* context,const MintPluginHostV1* api,const char* arguments){(void)context;(void)arguments;MintPluginFunctionV1 first;if(api->function_at(api->context,0,&first))return -1;return api->edit(api->context,first.entry,"comment","native analysis pass");}
static const MintPluginAnalysisPassV2 passes[]={{"annotate","Annotate first function with analysis evidence",analyze}};
static const MintPluginExtensionV2 plugin={2,sizeof(MintPluginExtensionV2),"sample-extension","Sample lifecycle / analyzer module",0,observe,1,passes};
MINT_PLUGIN_EXPORT const MintPluginExtensionV2* mint_plugin_extension_v2(void){return &plugin;}
