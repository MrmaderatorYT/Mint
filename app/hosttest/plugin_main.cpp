#include "mint/plugin/plugin_runtime.h"
#include "mint/session.h"
#include <cstdio>
#include <iostream>
#include <unistd.h>
using namespace mint;
namespace {
unsigned checks=0;bool okay=true;
void check(bool value,const char* message){++checks;if(!value){okay=false;std::cerr<<"FAIL SDK: "<<message<<'\n';}}
int mock(const MintPluginHostV1*,const char*){return 0;}
unsigned observed=0;
int observe(void*,const MintPluginHostV1* api,const MintPluginEventV2* event){++observed;return api->allow_edits||event->kind!=MINT_EVENT_ANALYSIS_COMPLETED?-1:api->output(api->context,"observed\n",9);}
int analyze(void*,const MintPluginHostV1* api,const char*){MintPluginFunctionV1 first{};if(api->function_at(api->context,0,&first))return -1;return api->edit(api->context,first.entry,"comment","extension analysis evidence");}
}
int main(int argc,char** argv) {
    if(argc!=2&&argc!=3)return 2;
    char path[]="/private/tmp/mint-sdk-input-XXXXXX";int fd=mkstemp(path);const u8 code[]={0xc3};
    check(fd>=0 && write(fd,code,sizeof(code))==sizeof(code),"create SDK fixture");if(fd>=0)close(fd);
    char project[]="/private/tmp/mint-sdk-project-XXXXXX";fd=mkstemp(project);if(fd>=0){close(fd);unlink(project);}
    Session session;check(session.openRawPath(path,Arch::kX86_64,0x8000000000001000ULL,0x8000000000001000ULL).ok() && session.attachProject(project).ok() && session.analyze().ok(),"open native Program");
    PluginManager plugins;std::string output="old";
    check(!plugins.load(argv[1],false).ok(),"no loading without explicit native trust");
    check(!plugins.load("relative-plugin.so",true).ok(),"absolute user-selected path only");
    check(plugins.load(argv[1],true).ok(),"load real locally built C-ABI shared plugin");
    check(plugins.commandsText().find("sample/inventory")!=std::string::npos,"discover command metadata");
    check(!plugins.load(argv[1],true).ok(),"reject duplicate plugin ID");
    check(plugins.run(session,"sample/inventory","",false,&output).ok() && output.find("0x8000000000001000")!=std::string::npos,"read-only API keeps exact64-bit addresses");
    const auto revision=session.program().revision();
    check(!plugins.run(session,"sample/inventory","rename",false,&output).ok() && session.program().revision()==revision,"host edit capability denied for read-only invocation");
    check(plugins.run(session,"sample/inventory","rename",true,&output).ok() && session.nameAt(0x8000000000001000ULL)=="plugin_entry","explicit Program edit through SDK");
    check(session.undoEdit(false).ok() && session.annotation(0x8000000000001000ULL,"name").empty(),"SDK edit uses normal undo transaction");
    check(!plugins.run(session,"missing/command","",false,&output).ok(),"unknown command rejected");
    const MintPluginCommandV1 command{"test","test",mock};
    MintPluginV1 descriptor{999,sizeof(MintPluginV1),"invalid","invalid",1,&command};
    check(!plugins.registerBuiltin(&descriptor).ok(),"ABI version checked");descriptor.abi_version=1;descriptor.struct_size=0;
    check(!plugins.registerBuiltin(&descriptor).ok(),"ABI layout size checked");descriptor.struct_size=sizeof(MintPluginV1);descriptor.id="unsafe/id";
    check(!plugins.registerBuiltin(&descriptor).ok(),"plugin identifiers bounded");
    const MintPluginAnalysisPassV2 pass{"tag","Tag first analyzed function",analyze};const MintPluginExtensionV2 extension{2,sizeof(MintPluginExtensionV2),"extension","Lifecycle fixture",nullptr,observe,1,&pass};
    check(plugins.registerBuiltinExtension(&extension).ok()&&plugins.commandsText().find("analysis-pass extension/tag")!=std::string::npos,"ABI2 observer/analysis pass registered");
    const MintPluginEventV2 event{sizeof(MintPluginEventV2),MINT_EVENT_ANALYSIS_COMPLETED,0,"fixture"};check(plugins.dispatchEvent(session,event,&output).ok()&&observed==1&&output=="observed\n","lifecycle event gets bounded read-only host API");
    check(!plugins.runAnalyzer(session,"extension/tag","",false,&output).ok()&&session.annotation(0x8000000000001000ULL,"comment").empty(),"analysis pass cannot mutate without explicit edit grant");
    check(plugins.run(session,"extension/tag","",true,&output).ok()&&session.annotation(0x8000000000001000ULL,"comment")=="extension analysis evidence","registered pass runs through existing command interface with normal Program transactions");check(session.undoEdit(false).ok()&&session.annotation(0x8000000000001000ULL,"comment").empty(),"analysis pass participates in ordinary undo");
    if(argc==3){check(plugins.load(argv[2],true).ok(),"load real ABI2 lifecycle/analyzer DSO");check(plugins.dispatchEvent(session,event,&output).ok()&&output.find("sample lifecycle observation")!=std::string::npos,"dynamic observer module receives lifecycle events");check(plugins.runAnalyzer(session,"sample-extension/annotate","",true,&output).ok()&&session.annotation(0x8000000000001000ULL,"comment")=="native analysis pass","dynamic analysis pass performs user-authorized Program edit");}
    unlink(path);unlink(project);unlink((std::string(project)+".analysis").c_str());
    std::cout<<"Plugin SDK: "<<checks<<" checks, "<<(okay?"passed":"failed")<<'\n';return okay?0:1;
}
