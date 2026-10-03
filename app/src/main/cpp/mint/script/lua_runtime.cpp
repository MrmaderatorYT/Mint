#include "mint/script/lua_runtime.h"
#include "mint/session.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <limits>

namespace mint {
namespace {
struct Context {
    Session* session;const ScriptOptions* options;std::string* output;
    size_t memory=0;u64 instructions=0;u32 calls=0;
    std::chrono::steady_clock::time_point deadline;
};
Context* context(lua_State* state) {return *static_cast<Context**>(lua_getextraspace(state));}
void* allocate(void* opaque,void* pointer,size_t oldSize,size_t newSize) {
    auto& ctx=*static_cast<Context*>(opaque);
    if(!pointer)oldSize=0;
    if(!newSize){std::free(pointer);ctx.memory-=oldSize;return nullptr;}
    const size_t remaining=ctx.options->memoryBytes-ctx.memory;
    if(newSize>oldSize && newSize-oldSize>remaining)return nullptr;
    void* result=std::realloc(pointer,newSize);
    if(result)ctx.memory=ctx.memory-oldSize+newSize;
    return result;
}
void checkBudget(lua_State* state) {
    const auto* ctx=context(state);
    if(ctx->options->cancel && ctx->options->cancel->load())luaL_error(state,"script cancelled");
    if(std::chrono::steady_clock::now()>ctx->deadline)luaL_error(state,"script time limit exceeded");
}
void hook(lua_State* state,lua_Debug*) {
    auto* ctx=context(state);ctx->instructions+=1000;
    if(ctx->instructions>ctx->options->instructionLimit)luaL_error(state,"script instruction limit exceeded");
    checkBudget(state);
}
std::string textArgument(lua_State* state,int index,size_t limit=65536) {
    size_t size=0;const char* value=luaL_checklstring(state,index,&size);
    if(size>limit || std::memchr(value,0,size))luaL_error(state,"invalid or oversized text argument");
    return std::string(value,size);
}
Address addressArgument(lua_State* state,int index) {
    // Reject floats and signed-overflow conversions. Hex strings retain all64 bits.
    if(lua_isinteger(state,index)) {
        const auto number=lua_tointeger(state,index);
        if(number<0)luaL_error(state,"address must be nonnegative or an exact hex string");
        return static_cast<Address>(number);
    }
    const auto text=textArgument(state,index,32);size_t pos=0;unsigned base=10;
    if(text.size()>2 && text[0]=='0' && (text[1]=='x' || text[1]=='X')){pos=2;base=16;}
    if(pos==text.size())luaL_error(state,"invalid address");
    Address result=0;
    for(;pos<text.size();++pos) {
        const auto c=text[pos];unsigned digit=c>='0' && c<='9'?c-'0':c>='a' && c<='f'?c-'a'+10:c>='A' && c<='F'?c-'A'+10:99;
        if(digit>=base || result>(std::numeric_limits<Address>::max()-digit)/base)luaL_error(state,"invalid or overflowing address");
        result=result*base+digit;
    }
    return result;
}
void pushAddress(lua_State* state,Address address) {
    char buffer[32];std::snprintf(buffer,sizeof(buffer),"0x%llx",static_cast<unsigned long long>(address));lua_pushstring(state,buffer);
}
void pushText(lua_State* state,const std::string& value) {
    if(value.size()>context(state)->options->outputBytes)luaL_error(state,"native result exceeds script output limit");
    lua_pushlstring(state,value.data(),value.size());
}
void textField(lua_State* state,const char* key,const std::string& value){pushText(state,value);lua_setfield(state,-2,key);}
void addressField(lua_State* state,const char* key,Address value){pushAddress(state,value);lua_setfield(state,-2,key);}
void numberField(lua_State* state,const char* key,u64 value){lua_pushinteger(state,static_cast<lua_Integer>(value));lua_setfield(state,-2,key);}
int print(lua_State* state) {
    auto* ctx=context(state);std::string line;
    for(int i=1;i<=lua_gettop(state);++i) {
        size_t size=0;const char* value=luaL_tolstring(state,i,&size);
        if(size>ctx->options->outputBytes || line.size()>ctx->options->outputBytes-size)luaL_error(state,"script output limit exceeded");
        if(i>1)line+='\t';line.append(value,size);lua_pop(state,1);
    }
    line+='\n';
    if(line.size()>ctx->options->outputBytes-ctx->output->size())luaL_error(state,"script output limit exceeded");
    *ctx->output+=line;checkBudget(state);return 0;
}
enum Operation {Functions,Listing,References,Search,Decompile,Ir,Cfg,Read,Annotation,Edit,Type,Undo,Redo,Types,Debug,Source,Architectures,Locals,Abi,EditLocal,Assemble,AssemblePreview};
int invoke(lua_State* state) {
    auto* ctx=context(state);checkBudget(state);
    if(++ctx->calls>ctx->options->nativeCallLimit)luaL_error(state,"native call limit exceeded");
    auto& session=*ctx->session;const auto operation=static_cast<Operation>(lua_tointeger(state,lua_upvalueindex(1)));
    if(operation==Edit || operation==Type || operation==Undo || operation==Redo || operation==EditLocal || operation==Assemble) {
        if(!ctx->options->allowEdits)luaL_error(state,"script is read-only; edits require explicit permission");
        Status status;
        if(operation==Edit)status=session.editAnnotation(addressArgument(state,1),textArgument(state,2,32),textArgument(state,3));
        else if(operation==Type)status=session.defineType(textArgument(state,1));
        else if(operation==EditLocal)status=session.editLocalVariable(addressArgument(state,1),textArgument(state,2,256),textArgument(state,3,64),textArgument(state,4,256));
        else if(operation==Assemble){std::string bytes;status=session.assembleAt(addressArgument(state,1),textArgument(state,2),true,&bytes);if(status.ok()){pushText(state,bytes);return 1;}}
        else status=session.undoEdit(operation==Redo);
        if(!status.ok())luaL_error(state,"%s",status.toString().c_str());
        lua_pushboolean(state,1);return 1;
    }
    if(operation==Functions) {
        const auto offset=static_cast<size_t>(std::max<lua_Integer>(0,luaL_optinteger(state,1,0)));
        const auto limit=static_cast<size_t>(std::clamp<lua_Integer>(luaL_optinteger(state,2,500),1,2000));
        const auto& functions=session.analyzer().functions();lua_newtable(state);
        for(size_t i=offset;i<functions.size() && i-offset<limit;++i) {
            const auto& function=functions[i];lua_newtable(state);
            addressField(state,"entry",function.entry);textField(state,"name",session.nameAt(function.entry));
            textField(state,"origin",functionOriginName(function.origin));numberField(state,"instructions",function.instructions.size());
            lua_pushboolean(state,function.incomplete);lua_setfield(state,-2,"incomplete");lua_rawseti(state,-2,static_cast<lua_Integer>(i-offset+1));
        }
        return 1;
    }
    if(operation==Listing) {
        const auto rows=session.programListing(addressArgument(state,1),static_cast<size_t>(std::clamp<lua_Integer>(luaL_optinteger(state,2,100),1,1000)));
        lua_newtable(state);size_t i=0;
        for(const auto& row:rows) {
            lua_newtable(state);addressField(state,"address",row.address);numberField(state,"size",row.size);
            textField(state,"text",row.text);textField(state,"comment",row.comment);
            if(row.target!=kNoAddress)addressField(state,"target",row.target);
            lua_rawseti(state,-2,static_cast<lua_Integer>(++i));
        }
        return 1;
    }
    if(operation==Architectures) {
        lua_newtable(state);size_t i=0;
        for(const auto& arch:architectureDescriptions()) {
            lua_newtable(state);textField(state,"id",arch.id);textField(state,"name",arch.name);numberField(state,"pointer_size",arch.pointerSize);
            lua_rawseti(state,-2,static_cast<lua_Integer>(++i));
        }
        return 1;
    }
    if(operation==Read) {
        const auto address=addressArgument(state,1);const auto length=luaL_checkinteger(state,2);
        if(length<0 || length>65536)luaL_error(state,"read length must be0..65536");
        const auto view=session.image().memory().viewAt(address,static_cast<size_t>(length));
        if(view.size()!=static_cast<size_t>(length))luaL_error(state,"read is not fully file-backed");
        lua_pushlstring(state,reinterpret_cast<const char*>(view.data()),view.size());return 1;
    }
    std::string result;
    switch(operation) {
        case References:result=session.referencesText(addressArgument(state,1));break;
        case Search:result=session.searchText(textArgument(state,1),500);break;
        case Decompile:result=session.decompiledCFor(addressArgument(state,1));break;
        case Ir:result=session.irTextFor(addressArgument(state,1));break;
        case Cfg:result=session.cfgTextFor(addressArgument(state,1));break;
        case Annotation:result=session.annotation(addressArgument(state,1),textArgument(state,2,32));break;
        case Types:result=session.typesText();break;case Debug:result=session.debugInfoText();break;
        case Source:result=session.sourceLocationText(addressArgument(state,1));break;
        case Locals:result=session.localVariablesText(addressArgument(state,1));break;
        case Abi:result=session.abiText(addressArgument(state,1));break;
        case AssemblePreview:{const auto status=session.assembleAt(addressArgument(state,1),textArgument(state,2),false,&result);if(!status.ok())luaL_error(state,"%s",status.toString().c_str());break;}
        default:luaL_error(state,"unknown native operation");break;
    }
    pushText(state,result);checkBudget(state);return 1;
}
int initialize(lua_State* state) {
    const struct {const char* name;lua_CFunction open;} libraries[]={{"_G",luaopen_base},{LUA_MATHLIBNAME,luaopen_math},{LUA_STRLIBNAME,luaopen_string},{LUA_TABLIBNAME,luaopen_table},{LUA_UTF8LIBNAME,luaopen_utf8}};
    for(const auto& library:libraries){luaL_requiref(state,library.name,library.open,1);lua_pop(state,1);}
    // Protected calls inside scripts can indefinitely catch resource-limit hook
    // errors. Only the host owns that boundary, so pcall/xpcall are unavailable.
    for(const auto* name:{"dofile","loadfile","load","collectgarbage","pcall","xpcall","setmetatable"}){lua_pushnil(state);lua_setglobal(state,name);}
    lua_pushcfunction(state,print);lua_setglobal(state,"print");lua_newtable(state);
    const struct {const char* name;Operation operation;} methods[]={
        {"functions",Functions},{"listing",Listing},{"references",References},{"search",Search},{"decompile",Decompile},
        {"ir",Ir},{"cfg",Cfg},{"read",Read},{"annotation",Annotation},{"edit",Edit},{"define_type",Type},
        {"undo",Undo},{"redo",Redo},{"types",Types},{"debug_info",Debug},{"source",Source},{"architectures",Architectures},
        {"locals",Locals},{"abi",Abi},{"edit_local",EditLocal},{"assemble",Assemble},{"assemble_preview",AssemblePreview}};
    for(const auto& method:methods){lua_pushinteger(state,method.operation);lua_pushcclosure(state,invoke,1);lua_setfield(state,-2,method.name);}
    lua_setglobal(state,"mint");return 0;
}
}
Status runLuaScript(Session& session,const std::string& source,const ScriptOptions& options,std::string* output) {
    if(!output || !session.analyzed() || session.isDexLike())return Status::error(ErrorCode::kBadFormat,"script requires an analyzed native Program and output");
    if(source.size()>256*1024 || options.memoryBytes<1024*1024 || options.memoryBytes>64*1024*1024 ||
       options.outputBytes>4*1024*1024 || !options.instructionLimit || options.instructionLimit>20000000 ||
       !options.nativeCallLimit || options.nativeCallLimit>10000)return Status::error(ErrorCode::kTooLarge,"script/resource options exceed limits");
    output->clear();Context ctx{&session,&options,output,0,0,0,std::chrono::steady_clock::now()+std::chrono::seconds(30)};
    lua_State* state=lua_newstate(allocate,&ctx,static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
    if(!state)return Status::error(ErrorCode::kTooLarge,"cannot allocate Lua state");
    *static_cast<Context**>(lua_getextraspace(state))=&ctx;
    lua_sethook(state,hook,LUA_MASKCOUNT,1000);
    lua_pushcfunction(state,initialize);int code=lua_pcall(state,0,0,0);
    if(code==LUA_OK)code=luaL_loadbufferx(state,source.data(),source.size(),"Mint user script","t");
    if(code==LUA_OK)code=lua_pcall(state,0,0,0);
    std::string error;
    if(code!=LUA_OK){const char* message=lua_tostring(state,-1);error=message?message:"Lua execution failed";}
    lua_close(state);
    if(!error.empty())return Status::error(code==LUA_ERRMEM?ErrorCode::kTooLarge:ErrorCode::kBadFormat,error);
    return Status::success();
}
} // namespace mint
