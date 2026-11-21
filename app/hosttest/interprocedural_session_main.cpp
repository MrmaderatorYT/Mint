#include "mint/session.h"
#include "program_fresh_oracle.h"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <unistd.h>
using namespace mint;
namespace {
unsigned checks=0;
void require(bool value,const std::string& text){++checks;if(!value){std::cerr<<"interprocedural Session: "<<text<<'\n';std::exit(1);}}
std::string temporary(){auto path=(std::filesystem::temp_directory_path()/"mint-memory-session-XXXXXX").string();int fd=mkstemp(path.data());require(fd>=0,"owned temporary");close(fd);return path;}
struct Files {std::string binary=temporary(),project=temporary();Files(){unlink(project.c_str());}~Files(){unlink(binary.c_str());unlink(project.c_str());unlink((project+".analysis").c_str());}};
void compareFresh(Session& session, const Files& files, const char* step) {
    const auto status = testing::matchesFreshAnalysis(session, files.project, [&](Session& oracle) {
        return oracle.openRawPath(files.binary, Arch::kAArch64, 0x1000, 0x1000);
    });
    require(status.ok(), std::string(step) + " matches full analysis: " + status.toString());
}
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
void recursiveFreshness(bool mutual){
    Files files;
    // These deliberately same-SP cycles test may-write summaries, not machine
    // termination or return-stack correctness. Each member also has a base RET.
    // A conventional LR-saving recursive frame is tested separately below.
    std::vector<u32> code(mutual?37:21,0xd503201f);
    const u32 caller[]={0xa9bf7bf3,0xd2840013,0xf9000260,0x9400000d,
        0xf9400260,0xa8c17bf3,0xd65f03c0};
    for(unsigned n=0;n<7;++n)code[n]=caller[n];
    code[16]=0xb4000081; // cbz x1, base
    code[18]=mutual?0x9400000e:0x97fffffe; // bl partner / self
    code[19]=code[20]=0xd65f03c0;
    if(mutual){
        code[32]=0xb4000081;
        code[34]=0x97ffffee; // bl first member
        code[35]=code[36]=0xd65f03c0;
    }
    {std::ofstream out(files.binary,std::ios::binary);for(auto word:code)for(unsigned n=0;n<4;++n)out.put(static_cast<char>(word>>(n*8)));require(out.good(),"write recursive fixture");}
    Session session;require(session.openRawPath(files.binary,Arch::kAArch64,0x1000,0x1000).ok()&&session.attachProject(files.project).ok()&&session.analyze().ok(),"discover recursive call graph");
    auto text=session.decompiledCFor(0x1000);
    require(text.find("1 proven read-only calls")!=std::string::npos&&text.find("1 exact store/load dependencies")!=std::string::npos,mutual?"ordinary decompiler consumes a read-only mutual cycle":"ordinary decompiler consumes a read-only self cycle");
    const Address patch=mutual?0x1084:0x1044;
    require(session.editAnnotation(patch,"patch","60 02 00 f9").ok(),"patch recursive member into overlapping pointer writer");
    text=session.decompiledCFor(0x1000);
    if(mutual){
        // The first member has no explicit x19 SSA input yet. Passing that
        // absent physical binding to a nested writer cannot establish effects.
        require(text.find("0 proven read-only calls")!=std::string::npos&&text.find("0 selective write calls")!=std::string::npos&&text.find("1 alias barriers")!=std::string::npos&&text.find("0 exact store/load dependencies")!=std::string::npos,"absent transitive pointer input stays unknown in a mutual cycle");
        require(session.undoEdit(false).ok(),"undo writer before supplying explicit recursive input");
        text=session.decompiledCFor(0x1000);
        require(text.find("1 proven read-only calls")!=std::string::npos&&text.find("1 exact store/load dependencies")!=std::string::npos,"missing write input does not prevent a read-only cycle proof");
        require(session.editAnnotation(0x1044,"patch","69 02 40 f9").ok(),"make first recursive member explicitly read its pointer input");
        text=session.decompiledCFor(0x1000);
        require(text.find("1 proven read-only calls")!=std::string::npos&&text.find("1 exact store/load dependencies")!=std::string::npos,"explicit pointer read retains read-only recursive effects");
        require(session.editAnnotation(patch,"patch","60 02 00 f9").ok(),"patch recursive writer with transitive physical input available");
        text=session.decompiledCFor(0x1000);
    }
    require(text.find("0 proven read-only calls")!=std::string::npos&&text.find("1 selective write calls")!=std::string::npos&&text.find("0 exact store/load dependencies")!=std::string::npos,"recursive writes reach ordinary decompiler without stale purity");
    compareFresh(session, files, "recursive writer patch");
    require(session.undoEdit(false).ok(),"undo recursive member write");
    text=session.decompiledCFor(0x1000);
    require(text.find("1 proven read-only calls")!=std::string::npos&&text.find("1 exact store/load dependencies")!=std::string::npos,"undo rebuilds recursive dependencies from effective bytes");
    compareFresh(session, files, "recursive writer undo");
    require(session.undoEdit(true).ok(),"redo recursive member write");
    text=session.decompiledCFor(0x1000);
    require(text.find("1 selective write calls")!=std::string::npos&&text.find("0 exact store/load dependencies")!=std::string::npos,"redo reapplies recursive write effects");
    compareFresh(session, files, "recursive writer redo");
    Session reopened;require(reopened.openRawPath(files.binary,Arch::kAArch64,0x1000,0x1000).ok()&&reopened.attachProject(files.project).ok()&&reopened.analyze().ok(),"reopen patched recursive project");
    text=reopened.decompiledCFor(0x1000);
    require(text.find("0 proven read-only calls")!=std::string::npos&&text.find("1 selective write calls")!=std::string::npos&&text.find("0 exact store/load dependencies")!=std::string::npos,"persistent recursive project rebuilds patched effect summaries");
    compareFresh(reopened, files, "reopened recursive write effects");
    require(reopened.editAnnotation(patch,"patch","40 00 3f d6").ok(),"replace recursive member write with opaque indirect call");
    text=reopened.decompiledCFor(0x1000);
    require(text.find("0 proven read-only calls")!=std::string::npos&&text.find("0 selective write calls")!=std::string::npos&&text.find("1 alias barriers")!=std::string::npos&&text.find("0 exact store/load dependencies")!=std::string::npos,"unknown effects anywhere in recursive component remain a barrier");
    compareFresh(reopened, files, "opaque recursive call patch");
}
void recursiveFramesRemainUnknown(){
    Files files;
    std::vector<u32> code(22,0xd503201f);
    const u32 caller[]={0xa9bf7bf3,0xd2840013,0xf9000260,0x9400000d,
        0xf9400260,0xa8c17bf3,0xd65f03c0};
    for(unsigned n=0;n<7;++n)code[n]=caller[n];
    code[16]=0xa9bf7bfd; // stp x29, x30, [sp, #-16]!
    code[17]=0xb4000061; // cbz x1, restore
    code[18]=0x97fffffe; // bl self
    code[20]=0xa8c17bfd; // ldp x29, x30, [sp], #16
    code[21]=0xd65f03c0;
    {std::ofstream out(files.binary,std::ios::binary);for(auto word:code)for(unsigned n=0;n<4;++n)out.put(static_cast<char>(word>>(n*8)));require(out.good(),"write recursive stack fixture");}
    Session session;require(session.openRawPath(files.binary,Arch::kAArch64,0x1000,0x1000).ok()&&session.analyze().ok(),"discover ordinary recursive stack frames");
    const auto text=session.decompiledCFor(0x1000);
    require(text.find("0 proven read-only calls")!=std::string::npos&&text.find("0 selective write calls")!=std::string::npos&&text.find("1 alias barriers")!=std::string::npos&&text.find("0 exact store/load dependencies")!=std::string::npos,"unbounded recursive stack displacement cannot imply private frames or purity");
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
    recursiveFreshness(false);
    recursiveFreshness(true);
    recursiveFramesRemainUnknown();
    std::cout<<checks<<" interprocedural Session checks passed\n";
}
