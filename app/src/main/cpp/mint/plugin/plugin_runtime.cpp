#include "mint/plugin/plugin_runtime.h"
#include "mint/plugin/architecture_bridge.h"
#include "mint/session.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <map>
#include <sys/stat.h>

namespace mint {
namespace {
constexpr size_t kMaxText=1024*1024;
bool bounded(const char* text,size_t limit){return text && strnlen(text,limit+1)<=limit;}
bool identifier(const char* text) {
    if(!bounded(text,64) || !*text)return false;
    for(const char* at=text;*at;++at)if(!((*at>='a' && *at<='z') || (*at>='A' && *at<='Z') || (*at>='0' && *at<='9') || *at=='_' || *at=='-'))return false;
    return true;
}
struct Context {
    Session& session;bool allowEdits;std::string& output;std::string error;unsigned calls=0;
    const char* fatal=nullptr;
    int fail(const std::string& message){error=message;return -1;}
    bool budget(){if(++calls>1000){fail("plugin native call budget exceeded");return false;}return true;}
};
int count(void* opaque,uint64_t* output){auto& c=*static_cast<Context*>(opaque);if(!output || !c.budget())return -1;*output=c.session.analyzer().functions().size();return 0;}
int function(void* opaque,uint64_t index,MintPluginFunctionV1* output) {
    auto& c=*static_cast<Context*>(opaque);if(!output || !c.budget())return -1;
    const auto& functions=c.session.analyzer().functions();if(index>=functions.size())return c.fail("function index is out of range");
    const auto& source=functions[index];MintPluginFunctionV1 candidate{};candidate.entry=source.entry;candidate.instruction_count=source.instructions.size();
    candidate.origin=static_cast<uint32_t>(source.origin);candidate.incomplete=source.incomplete;
    const auto name=c.session.nameAt(source.entry);std::snprintf(candidate.name,sizeof(candidate.name),"%s",name.c_str());*output=candidate;return 0;
}
int read(void* opaque,uint64_t address,void* output,size_t size) {
    auto& c=*static_cast<Context*>(opaque);if(!c.budget())return -1;
    if(!output || size>65536)return c.fail("read must use a caller buffer of at most64 KiB");
    std::vector<u8> candidate(size);
    if(!c.session.image().memory().read(address,candidate.data(),size))return c.fail("read crosses unmapped memory");
    std::memcpy(output,candidate.data(),size);return 0;
}
int query(void* opaque,uint32_t kind,uint64_t address,const char* argument,char* output,size_t capacity,size_t* needed) {
    auto& c=*static_cast<Context*>(opaque);if(!c.budget())return -1;
    if(!needed || !bounded(argument,65536) || capacity>kMaxText+1 || (capacity && !output))return c.fail("invalid text query buffer");
    std::string text;
    switch(kind) {
        case MINT_QUERY_ANNOTATION:text=c.session.annotation(address,argument);break;
        case MINT_QUERY_REFERENCES:text=c.session.referencesText(address);break;
        case MINT_QUERY_SEARCH:text=c.session.searchText(argument);break;
        case MINT_QUERY_DECOMPILE:text=c.session.decompiledCFor(address);break;
        case MINT_QUERY_IR:text=c.session.irTextFor(address);break;
        case MINT_QUERY_CFG:text=c.session.cfgTextFor(address);break;
        case MINT_QUERY_TYPES:text=c.session.typesText();break;
        case MINT_QUERY_MEMORY:text=c.session.memoryBlocksText();break;
        case MINT_QUERY_DWARF:text=c.session.debugInfoText();break;
        default:return c.fail("unknown query kind");
    }
    if(text.size()>kMaxText)return c.fail("query result exceeds1 MiB");
    *needed=text.size();if(!capacity)return 0;if(capacity<=text.size())return c.fail("query buffer too small");
    std::memcpy(output,text.c_str(),text.size()+1);return 0;
}
int edit(void* opaque,uint64_t address,const char* kind,const char* value) {
    auto& c=*static_cast<Context*>(opaque);if(!c.budget())return -1;
    if(!c.allowEdits)return c.fail("plugin invocation is read-only");
    if(!bounded(kind,32) || !bounded(value,65536))return c.fail("invalid edit arguments");
    const auto status=c.session.editAnnotation(address,kind,value);return status.ok()?0:c.fail(status.toString());
}
int type(void* opaque,const char* declaration) {
    auto& c=*static_cast<Context*>(opaque);if(!c.budget())return -1;
    if(!c.allowEdits)return c.fail("plugin invocation is read-only");
    if(!bounded(declaration,16384))return c.fail("invalid type declaration");
    const auto status=c.session.defineType(declaration);return status.ok()?0:c.fail(status.toString());
}
int output(void* opaque,const char* bytes,size_t length) {
    auto& c=*static_cast<Context*>(opaque);if(!c.budget())return -1;
    if(!bytes || length>kMaxText-c.output.size())return c.fail("plugin output exceeds1 MiB");
    c.output.append(bytes,length);return 0;
}
const char* error(void* opaque){const auto& c=*static_cast<Context*>(opaque);return c.fatal?c.fatal:c.error.c_str();}
template<class Function> int guarded(void* opaque,Function call) noexcept {
    try{return call();}catch(...){static_cast<Context*>(opaque)->fatal="host callback failed (allocation or native exception)";return -1;}
}
int safeCount(void* c,uint64_t* out) noexcept{return guarded(c,[&]{return count(c,out);});}
int safeFunction(void* c,uint64_t i,MintPluginFunctionV1* out) noexcept{return guarded(c,[&]{return function(c,i,out);});}
int safeRead(void* c,uint64_t a,void* out,size_t n) noexcept{return guarded(c,[&]{return read(c,a,out,n);});}
int safeQuery(void* c,uint32_t k,uint64_t a,const char* arg,char* out,size_t cap,size_t* need) noexcept{return guarded(c,[&]{return query(c,k,a,arg,out,cap,need);});}
int safeEdit(void* c,uint64_t a,const char* k,const char* value) noexcept{return guarded(c,[&]{return edit(c,a,k,value);});}
int safeType(void* c,const char* text) noexcept{return guarded(c,[&]{return type(c,text);});}
int safeOutput(void* c,const char* text,size_t n) noexcept{return guarded(c,[&]{return output(c,text,n);});}
}
struct PluginManager::Impl {
    struct Command {std::string title;MintPluginRunV1 run;};
    struct Pass {std::string title;MintPluginAnalyzeV2 run;void* context;};
    struct Observer {MintPluginObserveV2 run;void* context;};
    std::map<std::string,Command> commands;std::map<std::string,std::string> plugins;std::vector<void*> libraries;
    std::map<std::string,Pass> passes;std::map<std::string,Observer> observers;
    bool dispatching=false;
    ~Impl(){for(auto library:libraries)dlclose(library);}
    Status prepare(const MintPluginV1* descriptor, std::map<std::string,Command>* nextCommands,
                   std::map<std::string,std::string>* nextPlugins) const {
        auto bad=[](const std::string& text){return Status::error(ErrorCode::kBadFormat,"plugin: "+text);};
        if(!descriptor || descriptor->abi_version!=MINT_PLUGIN_ABI_V1 || descriptor->struct_size!=sizeof(MintPluginV1) ||
           !identifier(descriptor->id) || !bounded(descriptor->title,256) || !descriptor->command_count || descriptor->command_count>64 || !descriptor->commands)
            return bad("invalid descriptor/ABI");
        if(plugins.size()>=32 || plugins.count(descriptor->id))return bad("plugin budget exceeded or duplicate ID");
        *nextCommands=commands;*nextPlugins=plugins;
        for(uint32_t i=0;i<descriptor->command_count;++i) {
            const auto& command=descriptor->commands[i];
            if(!identifier(command.id) || !bounded(command.title,256) || !command.run)return bad("invalid command");
            const auto id=std::string(descriptor->id)+"/"+command.id;
            if(!nextCommands->emplace(id,Command{command.title,command.run}).second)return bad("duplicate command");
        }
        nextPlugins->emplace(descriptor->id,descriptor->title);return Status::success();
    }
    Status prepareExtension(const MintPluginExtensionV2* descriptor,std::map<std::string,Pass>* nextPasses,std::map<std::string,Observer>* nextObservers,std::map<std::string,std::string>* nextPlugins)const{
        if(!descriptor||descriptor->abi_version!=MINT_PLUGIN_EXTENSION_ABI_V2||descriptor->struct_size!=sizeof(*descriptor)||!identifier(descriptor->id)||!bounded(descriptor->title,256)||descriptor->pass_count>64||(descriptor->pass_count&&!descriptor->passes)||(!descriptor->observe&&!descriptor->pass_count))return Status::error(ErrorCode::kBadFormat,"plugin: invalid extension ABI2 descriptor");
        if(plugins.count(descriptor->id)||plugins.size()>=32)return Status::error(ErrorCode::kBadFormat,"plugin: duplicate extension ID or plugin limit");*nextPasses=passes;*nextObservers=observers;*nextPlugins=plugins;
        for(u32 i=0;i<descriptor->pass_count;++i){const auto& pass=descriptor->passes[i];if(!identifier(pass.id)||!bounded(pass.title,256)||!pass.run||!nextPasses->emplace(std::string(descriptor->id)+"/"+pass.id,Pass{pass.title,pass.run,descriptor->context}).second)return Status::error(ErrorCode::kBadFormat,"plugin: invalid/duplicate analysis pass");}
        if(descriptor->observe)nextObservers->emplace(descriptor->id,Observer{descriptor->observe,descriptor->context});nextPlugins->emplace(descriptor->id,descriptor->title);return Status::success();
    }
};
PluginManager::PluginManager():impl_(std::make_unique<Impl>()){}
PluginManager::~PluginManager()=default;
PluginManager::PluginManager(PluginManager&&) noexcept=default;
PluginManager& PluginManager::operator=(PluginManager&&) noexcept=default;
Status PluginManager::registerBuiltin(const MintPluginV1* descriptor) {
    std::map<std::string,Impl::Command> commands;std::map<std::string,std::string> plugins;
    try {const auto status=impl_->prepare(descriptor,&commands,&plugins);if(!status.ok())return status;}
    catch(...){return Status::error(ErrorCode::kInternalError,"plugin command registration allocation failed");}
    impl_->commands.swap(commands);impl_->plugins.swap(plugins);return Status::success();
}
Status PluginManager::registerBuiltinArchitecture(const MintArchitecturePluginV1* descriptor) { return registerArchitecturePlugin(descriptor); }
Status PluginManager::registerBuiltinExtension(const MintPluginExtensionV2* descriptor){std::map<std::string,Impl::Pass> passes;std::map<std::string,Impl::Observer> observers;std::map<std::string,std::string> plugins;try{auto status=impl_->prepareExtension(descriptor,&passes,&observers,&plugins);if(!status.ok())return status;}catch(...){return Status::error(ErrorCode::kInternalError,"plugin extension preparation allocation failed");}impl_->passes.swap(passes);impl_->observers.swap(observers);impl_->plugins.swap(plugins);return Status::success();}
Status PluginManager::load(const std::string& path,bool trustNativeCode) {
    if(!trustNativeCode)return Status::error(ErrorCode::kUnsupported,"native plugins are unrestricted code; explicit trust acknowledgement is required");
    if(path.empty() || path[0]!='/' || path.size()>4096 || path.find('\0')!=std::string::npos)return Status::error(ErrorCode::kBadFormat,"plugin requires an explicit absolute library path");
    struct stat info{};if(stat(path.c_str(),&info)!=0 || !S_ISREG(info.st_mode) || info.st_size<=0 || info.st_size>16*1024*1024)
        return Status::error(ErrorCode::kBadFormat,"plugin must be a regular library of at most16 MiB");
    void* library=dlopen(path.c_str(),RTLD_NOW|RTLD_LOCAL);
    if(!library){const char* failure=dlerror();return Status::error(ErrorCode::kUnsupported,failure?failure:"cannot load plugin for this host ABI");}
    const auto entry=reinterpret_cast<MintPluginEntryV1>(dlsym(library,"mint_plugin_v1"));
    const auto architectureEntry=reinterpret_cast<MintArchitecturePluginEntryV1>(dlsym(library,"mint_architecture_plugin_v1"));
    const auto semanticEntry=reinterpret_cast<MintArchitecturePluginEntryV2>(dlsym(library,"mint_architecture_plugin_v2"));
    const auto extensionEntry=reinterpret_cast<MintPluginExtensionEntryV2>(dlsym(library,"mint_plugin_extension_v2"));
    if(!entry && !architectureEntry && !semanticEntry&&!extensionEntry){dlclose(library);return Status::error(ErrorCode::kBadFormat,"plugin has no command or architecture entry");}
    Status status;
    std::map<std::string,Impl::Command> commands;std::map<std::string,std::string> plugins;
    std::map<std::string,Impl::Pass> passes;std::map<std::string,Impl::Observer> observers;std::map<std::string,std::string> extensionPlugins;
    try {
        // Prepare every allocation before decoder publication. After a permanent
        // callback is visible, only noexcept swaps/ownership transfer remain.
        if(entry)status=impl_->prepare(entry(),&commands,&plugins);
        if(status.ok()&&extensionEntry){status=impl_->prepareExtension(extensionEntry(),&passes,&observers,&extensionPlugins);if(status.ok()&&entry){for(const auto& item:plugins){const auto original=impl_->plugins.find(item.first);if(original==impl_->plugins.end()&&!extensionPlugins.emplace(item).second){status=Status::error(ErrorCode::kBadFormat,"plugin: command and extension IDs must be distinct");break;}}}}
        if(status.ok()&&extensionEntry&&extensionPlugins.size()>32)status=Status::error(ErrorCode::kTooLarge,"combined command/extension plugin count exceeds32");
        if(status.ok() && !architectureEntry && !semanticEntry)impl_->libraries.reserve(impl_->libraries.size()+1);
        if(status.ok() && semanticEntry)status=registerArchitecturePluginV2(semanticEntry(),library);
        else if(status.ok() && architectureEntry)status=registerArchitecturePlugin(architectureEntry(),library);
    } catch(...){status=Status::error(ErrorCode::kBadFormat,"plugin entry or preparation threw an exception");}
    if(!status.ok()){dlclose(library);return status;}
    if(entry){impl_->commands.swap(commands);impl_->plugins.swap(plugins);}
    if(extensionEntry){impl_->passes.swap(passes);impl_->observers.swap(observers);impl_->plugins.swap(extensionPlugins);}
    if(!architectureEntry&&!semanticEntry)impl_->libraries.push_back(library);
    return Status::success();
}
std::string PluginManager::commandsText() const {
    std::string result="Plugin SDK ABI1 (explicit trusted native code; not sandboxed)\n";
    for(const auto& command:impl_->commands)result+=command.first+"\t"+command.second.title+'\n';
    for(const auto& pass:impl_->passes)result+="analysis-pass "+pass.first+"\t"+pass.second.title+'\n';
    for(const auto& observer:impl_->observers)result+="observer "+observer.first+" (read-only lifecycle events)\n";
    result+=architecturePluginsText();
    return result;
}
Status PluginManager::run(Session& session,const std::string& command,const std::string& arguments,bool allowEdits,std::string* result) {
    if(impl_->passes.count(command))return runAnalyzer(session,command,arguments,allowEdits,result);
    const auto found=impl_->commands.find(command);
    if(!result || !session.analyzed() || session.isDexLike() || arguments.size()>65536 || arguments.find('\0')!=std::string::npos)
        return Status::error(ErrorCode::kBadFormat,"plugin command requires a native Program, bounded arguments and output");
    if(found==impl_->commands.end())return Status::error(ErrorCode::kNotFound,"unknown plugin command");
    result->clear();Context context{session,allowEdits,*result,{},0};
    const MintPluginHostV1 api{MINT_PLUGIN_ABI_V1,sizeof(MintPluginHostV1),&context,safeCount,safeFunction,safeRead,safeQuery,safeEdit,safeType,safeOutput,error,allowEdits?1u:0u};
    int code=-1;try{code=found->second.run(&api,arguments.c_str());}catch(...){context.error="plugin command threw an exception";}
    if(context.fatal)return Status::error(ErrorCode::kBadFormat,context.fatal);
    if(code || !context.error.empty())return Status::error(ErrorCode::kBadFormat,context.error.empty()?"plugin command failed":context.error);
    return Status::success();
}
Status PluginManager::runAnalyzer(Session& session,const std::string& id,const std::string& arguments,bool allowEdits,std::string* result){
    if(!result||!session.analyzed()||session.isDexLike()||arguments.size()>65536||arguments.find('\0')!=std::string::npos)return Status::error(ErrorCode::kBadFormat,"analysis pass requires native analyzed Program and bounded arguments");const auto found=impl_->passes.find(id);if(found==impl_->passes.end())return Status::error(ErrorCode::kNotFound,"unknown native analysis pass");result->clear();Context context{session,allowEdits,*result,{},0};const MintPluginHostV1 api{MINT_PLUGIN_ABI_V1,sizeof(MintPluginHostV1),&context,safeCount,safeFunction,safeRead,safeQuery,safeEdit,safeType,safeOutput,error,allowEdits?1u:0u};int code=-1;try{code=found->second.run(found->second.context,&api,arguments.c_str());}catch(...){context.error="analysis pass threw an exception";}if(code||context.fatal||!context.error.empty())return Status::error(ErrorCode::kBadFormat,context.fatal?context.fatal:context.error.empty()?"analysis pass failed":context.error);return Status::success();
}
Status PluginManager::dispatchEvent(Session& session,const MintPluginEventV2& event,std::string* result){
    if(!result||!session.analyzed()||session.isDexLike()||event.struct_size!=sizeof(event)||event.kind<MINT_EVENT_ANALYSIS_COMPLETED||event.kind>MINT_EVENT_AFTER_DECOMPILE||!bounded(event.detail,65536))return Status::error(ErrorCode::kBadFormat,"invalid native lifecycle event");result->clear();
    if(impl_->dispatching)return Status::success();impl_->dispatching=true;struct Guard{bool& value;~Guard(){value=false;}}guard{impl_->dispatching};
    for(const auto& observer:impl_->observers){Context context{session,false,*result,{},0};const MintPluginHostV1 api{MINT_PLUGIN_ABI_V1,sizeof(MintPluginHostV1),&context,safeCount,safeFunction,safeRead,safeQuery,safeEdit,safeType,safeOutput,error,0};int code=-1;try{code=observer.second.run(observer.second.context,&api,&event);}catch(...){context.error="native observer threw an exception";}if(code||context.fatal||!context.error.empty())return Status::error(ErrorCode::kBadFormat,"observer "+observer.first+": "+(context.fatal?context.fatal:context.error.empty()?"failed":context.error));}return Status::success();
}
} // namespace mint
