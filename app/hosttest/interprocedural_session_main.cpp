#include "mint/session.h"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <unistd.h>
using namespace mint;
namespace {
unsigned checks=0;
void require(bool value,const char* text){++checks;if(!value){std::cerr<<"interprocedural Session: "<<text<<'\n';std::exit(1);}}
std::string temporary(){std::string path="/private/tmp/mint-memory-session-XXXXXX";int fd=mkstemp(path.data());require(fd>=0,"owned temporary");close(fd);return path;}
struct Files {std::string binary=temporary(),project=temporary();Files(){unlink(project.c_str());}~Files(){unlink(binary.c_str());unlink(project.c_str());unlink((project+".analysis").c_str());}};
void hiddenRegisterPaths(){
    Files files;
    // x20 is read only by the callee, so it has no ordinary caller SSA use.
    // One path points it at the caller's stored global; the other points away.
    // Pruned SSA need not insert an x20 phi, and copy aliases may be dead in SSA.
    const u32 code[]={0xa9bf7bf3,0xd2840013,0xd2860014,0xf9000260,0xb4000041,
        0xd2840014,0x9400000a,0xf9400260,0xa8c17bf3,0xd65f03c0,
        0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd503201f,
        0xf9000280,0xd65f03c0};
    {std::ofstream out(files.binary,std::ios::binary);for(auto word:code)for(unsigned n=0;n<4;++n)out.put(static_cast<char>(word>>(n*8)));require(out.good(),"write hidden register fixture");}
    Session session;require(session.openRawPath(files.binary,Arch::kAArch64,0x1000,0x1000).ok()&&session.attachProject(files.project).ok()&&session.analyze().ok(),"discover hidden register inputs");
    auto text=session.decompiledCFor(0x1000);
    require(text.find("0 exact store/load dependencies")!=std::string::npos,"one potentially aliasing incoming register path prevents a false dependency");
    // Both incoming x20 values are now the same concrete disjoint address.
    // Preserving hidden call-input writes through simplifyIr and SSA aliases
    // lets the bounded effect model prove that the x19 global survives.
    require(session.editAnnotation(0x1014,"patch","14 00 86 d2").ok(),"make hidden input paths agree");
    text=session.decompiledCFor(0x1000);
    require(text.find("1 exact store/load dependencies")!=std::string::npos&&text.find("1 selective write calls")!=std::string::npos,"matching hidden register paths establish disjoint callee write effects");
}
}
int main(){
    Files files;
    // Save/restore the real AAPCS link and callee-saved pointer. The leaf starts
    // read-only; a same-size patch then gives it an observable pointer write.
    const u32 code[]={0xa9bf7bf3,0xf9000260,0x94000006,0xf9400260,0xa8c17bf3,0xd65f03c0,0xd503201f,0xd503201f,0xd503201f,0xd65f03c0};
    {std::ofstream out(files.binary,std::ios::binary);for(auto word:code)for(unsigned n=0;n<4;++n)out.put(static_cast<char>(word>>(n*8)));require(out.good(),"write raw fixture");}
    Session session;require(session.openRawPath(files.binary,Arch::kAArch64,0x1000,0x1000).ok()&&session.attachProject(files.project).ok()&&session.analyze().ok(),"discover caller and leaf");
    auto text=session.decompiledCFor(0x1000);require(text.find("1 proven read-only calls")!=std::string::npos,"ordinary Session decompiler consumes verified callee summaries");
    require(session.editAnnotation(0x1020,"patch","60 02 00 f9").ok(),"patch leaf into pointer writer");
    text=session.decompiledCFor(0x1000);require(text.find("0 proven read-only calls")!=std::string::npos&&text.find("1 selective write calls")!=std::string::npos,"new request never reuses pre-patch purity evidence");
    require(session.undoEdit(false).ok(),"undo write patch");text=session.decompiledCFor(0x1000);require(text.find("1 proven read-only calls")!=std::string::npos,"undo recomputes effects from current bytes");
    Session reopened;require(reopened.openRawPath(files.binary,Arch::kAArch64,0x1000,0x1000).ok()&&reopened.attachProject(files.project).ok()&&reopened.analyze().ok(),"persistent reopen");
    require(reopened.decompiledCFor(0x1000).find("1 proven read-only calls")!=std::string::npos,"effect summaries rebuild after reopen rather than serializing trusted purity");
    hiddenRegisterPaths();
    std::cout<<checks<<" interprocedural Session checks passed\n";
}
