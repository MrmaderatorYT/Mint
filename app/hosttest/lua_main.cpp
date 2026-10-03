#include "mint/session.h"
#include "mint/script/lua_runtime.h"
#include <cstdio>
#include <iostream>
#include <unistd.h>

using namespace mint;
namespace {
unsigned checks=0;bool okay=true;
void check(bool condition,const char* message){++checks;if(!condition){okay=false;std::cerr<<"FAIL Lua: "<<message<<'\n';}}
struct Files {
    std::string source,project;
    Files(){char input[]="/private/tmp/mint-lua-test-XXXXXX";int fd=mkstemp(input);source=input;
        const u8 code[]={0xb8,7,0,0,0,0xc3};check(fd>=0 && write(fd,code,sizeof(code))==sizeof(code),"fixture created");if(fd>=0)close(fd);
        char overlay[]="/private/tmp/mint-lua-project-XXXXXX";fd=mkstemp(overlay);project=overlay;if(fd>=0){close(fd);unlink(overlay);}}
    ~Files(){unlink(source.c_str());unlink(project.c_str());unlink((project+".analysis").c_str());}
};
}
int main() {
    Files files;Session session;constexpr Address base=0x8000000000001000ULL;
    check(session.openRawPath(files.source,Arch::kX86_64,base,base).ok(),"open high-bit-address Program");
    check(session.attachProject(files.project).ok() && session.analyze().ok(),"attach and analyze");
    ScriptOptions options;std::string output;
    auto run=[&](const std::string& code){return runLuaScript(session,code,options,&output);};
    check(run("assert(os==nil and io==nil and package==nil and debug==nil and coroutine==nil and load==nil and dofile==nil and pcall==nil and xpcall==nil and setmetatable==nil); local f=mint.functions(); assert(#f==1); print(f[1].entry,f[1].name); local rows=mint.listing(f[1].entry,2); assert(#rows==2 and rows[1].size==5); assert(#mint.read(f[1].entry,6)==6); assert(#mint.architectures()>=7)").ok(),"structured API and forbidden capabilities");
    check(output.find("0x8000000000001000")!=std::string::npos,"addresses remain exact hexadecimal strings");
    const auto revision=session.program().revision();
    check(run("local bytes=mint.assemble_preview('0x8000000000001000','mov eax,9'); assert(bytes=='b8 09 00 00 00'); assert(type(mint.locals('0x8000000000001000'))=='string'); assert(type(mint.abi('0x8000000000001000'))=='string')").ok()&&session.program().revision()==revision,"read-only Lua assembler preview/locals/ABI preserve Program");
    check(!run("mint.assemble('0x8000000000001000','mov eax,9')").ok()&&session.program().revision()==revision&&session.annotation(base,"patch").empty(),"Lua assembler apply requires explicit edits grant");
    check(!run("mint.edit_local('0x8000000000001000','ssa:invalid:0','denied','u64')").ok()&&session.program().revision()==revision,"Lua local edit denied without Program mutation");
    check(!run("mint.edit('0x8000000000001000','name','denied')").ok() && session.program().revision()==revision,"read-only script cannot persist edits");
    check(!run("mint.read('0xfffffffffffffffff',1)").ok(),"reject64-bit overflow");
    check(!run("mint.read(1.5,1)").ok(),"reject floating address");
    check(!run("mint.read('0x8000000000001000',65537)").ok(),"read budget");
    check(!run(std::string("\x1bLua",4)).ok(),"text-only loader rejects bytecode");
    check(!run("this is not Lua").ok(),"syntax error is recoverable");
    options.instructionLimit=2000;
    auto status=run("while true do end");check(!status.ok() && status.message().find("instruction limit")!=std::string::npos,"infinite loop stopped");
    options.instructionLimit=2000000;options.outputBytes=16;
    check(!run("print(string.rep('x',17))").ok() && output.empty(),"oversized output is not partially appended");
    options.outputBytes=1024*1024;
    status=run("local a=string.rep('x',32*1024*1024)");check(!status.ok(),"Lua allocator memory limit");
    options.nativeCallLimit=1;check(!run("mint.functions();mint.functions()").ok(),"native-call budget");options.nativeCallLimit=1000;
    std::atomic_bool cancelled{true};options.cancel=&cancelled;
    check(!run("mint.functions()").ok(),"cooperative cancellation");options.cancel=nullptr;
    options.allowEdits=true;
    check(run("mint.edit('0x8000000000001000','name','script_entry'); mint.define_type('Node=struct{value:u32;next:Node*}'); mint.edit('0x8000000000001000','comment','lua review'); print(mint.annotation('0x8000000000001000','name'))").ok(),"explicitly authorized symbol/type/comment transactions");
    check(session.nameAt(base)=="script_entry" && output.find("script_entry")!=std::string::npos,"mutations visible in same Program");
    check(run("mint.undo(); assert(mint.annotation('0x8000000000001000','comment')==''); mint.redo()").ok(),"undo/redo API");
    Session reopened;check(reopened.openRawPath(files.source,Arch::kX86_64,base,base).ok() && reopened.attachProject(files.project).ok() && reopened.analyze().ok(),"cold reopen Lua edits");
    check(reopened.nameAt(base)=="script_entry" && reopened.annotation(base,"comment")=="lua review","script edits persist across reopen");
    check(run("mint.assemble('0x8000000000001000','mov eax,9'); assert(mint.annotation('0x8000000000001000','patch')~='')").ok()&&!session.annotation(base,"patch").empty(),"authorized Lua assembly uses normal persistent patch transaction");
    Session patched;check(patched.openRawPath(files.source,Arch::kX86_64,base,base).ok()&&patched.attachProject(files.project).ok()&&patched.analyze().ok()&&patched.irTextFor(base).find("9")!=std::string::npos,"Lua assembly patch survives native Program reopen");
    check(run("print('still alive')").ok(),"all resource failures leave session usable");
    std::cout<<"Lua runtime: "<<checks<<" checks, "<<(okay?"passed":"failed")<<'\n';return okay?0:1;
}
