#include "mint/session.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <vector>

using namespace mint;
namespace {
unsigned checks=0;
void require(bool value,const char* label){++checks;if(!value){std::cerr<<"interprocedural type Session: "<<label<<'\n';std::exit(1);}}
std::string temporary(){std::string path="/private/tmp/mint-type-session-XXXXXX";const int fd=mkstemp(path.data());require(fd>=0,"owned temporary file");close(fd);return path;}
struct Files {
    std::string binary=temporary(),project=temporary();
    Files(){unlink(project.c_str());}
    ~Files(){unlink(binary.c_str());unlink(project.c_str());unlink((project+".analysis").c_str());}
};
void open(Session& session,const Files& files){require(session.openRawPath(files.binary,Arch::kAArch64,0x1000,0x1000).ok()&&session.attachProject(files.project).ok()&&session.analyze().ok(),"open persistent type fixture");}
void shape(const std::string& text,bool shifted){
    require(text.find("Interprocedural type evidence:")!=std::string::npos,"ordinary pseudo-C reports interprocedural type evidence");
    require(text.find("layout via")!=std::string::npos&&text.find("field_0")!=std::string::npos&&text.find("field_10")!=std::string::npos,"callee observations join the caller's single local field");
    require((text.find("field_8")!=std::string::npos)==!shifted&&(text.find("field_18")!=std::string::npos)==shifted,"caller layout reflects current callee access offsets");
    require(text.find("from 0x")!=std::string::npos,"imported fields retain native origin evidence");
}
void noImportedShape(const std::string& text,const char* label){require(text.find("field_8")==std::string::npos&&text.find("field_10")==std::string::npos&&text.find("field_18")==std::string::npos,label);}
void memoryContract(const std::string& text,bool transitive){
    // Layout hypotheses never authorize purity. The real wrapper saves LR in
    // memory, so its ordinary write summary remains selective rather than pure.
    require(text.find(transitive?"0 proven read-only calls":"1 proven read-only calls")!=std::string::npos&&text.find(transitive?"1 selective write calls":"0 selective write calls")!=std::string::npos,"type evidence preserves the independent memory-effect contract");
}
void propagatedLayouts(bool transitive){
    Files files;
    std::vector<u32> code(transitive?36:20,0xd503201f);
    // The caller has only field +0 locally. Keep the pointer in x19 across the
    // call and explicitly bind x0 at the call site. The other fields are visible
    // exclusively in the leaf, so their appearance proves cross-body recovery.
    const u32 caller[]={0xa9bf7bf3,0xaa0003f3,0xf9000261,0xaa1303e0,
        0x9400000c,0xf9400260,0xa8c17bf3,0xd65f03c0};
    for(unsigned n=0;n<8;++n)code[n]=caller[n];
    const unsigned leaf=transitive?32:16;
    if(transitive){
        code[16]=0xa9bf7bff; // stp xzr, x30, [sp, #-16]!
        code[17]=0xf9400009; // ldr x9, [x0]: explicit transitive pointer input
        code[18]=0x9400000e; // bl leaf
        code[19]=0xa8c17bff;
        code[20]=0xd65f03c0;
    }
    code[leaf]=0xf9400402; // ldr x2, [x0, #8]
    code[leaf+1]=0xf9400803; // ldr x3, [x0, #16]
    code[leaf+2]=0x8b030040; // add x0, x2, x3
    code[leaf+3]=0xd65f03c0;
    {std::ofstream out(files.binary,std::ios::binary);for(auto word:code)for(unsigned n=0;n<4;++n)out.put(static_cast<char>(word>>(n*8)));require(out.good(),"write native type fixture");}
    const Address leafEntry=0x1000+4*leaf;
    Session session;open(session,files);
    auto text=session.decompiledCFor(0x1000);shape(text,false);memoryContract(text,transitive);
    require(session.editAnnotation(leafEntry,"patch","02 0c 40 f9").ok(),"move callee field access from +8 to +24");
    text=session.decompiledCFor(0x1000);shape(text,true);memoryContract(text,transitive);
    require(session.undoEdit(false).ok(),"undo callee field patch");shape(session.decompiledCFor(0x1000),false);
    require(session.undoEdit(true).ok(),"redo callee field patch");shape(session.decompiledCFor(0x1000),true);
    Session reopened;open(reopened,files);shape(reopened.decompiledCFor(0x1000),true);

    require(reopened.editAnnotation(leafEntry,"prototype","uint64_t(uint64_t scalar)").ok(),"declare authoritative scalar callee input");
    text=reopened.decompiledCFor(0x1000);noImportedShape(text,"authoritative scalar callee declaration blocks inferred pointer fields");memoryContract(text,transitive);
    require(reopened.undoEdit(false).ok(),"undo callee scalar declaration");shape(reopened.decompiledCFor(0x1000),true);
    require(reopened.undoEdit(true).ok(),"redo callee scalar declaration");noImportedShape(reopened.decompiledCFor(0x1000),"redo reinstates authoritative callee suppression");
    Session declared;open(declared,files);noImportedShape(declared.decompiledCFor(0x1000),"callee declaration and inference suppression survive reopen");

    require(reopened.undoEdit(false).ok(),"restore inferred callee input before caller override");
    require(reopened.editAnnotation(0x1000,"prototype","uint64_t(uint64_t scalar, uint64_t value)").ok(),"declare authoritative scalar caller inputs");
    text=reopened.decompiledCFor(0x1000);
    require(text.find("_start(uint64_t scalar, uint64_t value)")!=std::string::npos,"authoritative caller signature wins over inferred pointer kind");
    noImportedShape(text,"authoritative caller parameters suppress imported field hypotheses");
    require(reopened.undoEdit(false).ok(),"undo caller declaration");shape(reopened.decompiledCFor(0x1000),true);
    require(reopened.undoEdit(true).ok(),"redo caller declaration");noImportedShape(reopened.decompiledCFor(0x1000),"redo restores authoritative caller field suppression");
    Session callerDeclared;open(callerDeclared,files);
    text=callerDeclared.decompiledCFor(0x1000);
    require(text.find("_start(uint64_t scalar, uint64_t value)")!=std::string::npos,"caller signature survives persistent reopening");
    noImportedShape(text,"caller declaration keeps imported fields suppressed after reopen");

    require(callerDeclared.defineType("Packet=struct{head:u64;middle:u64;tail:u64;last:u64}").ok(),"define authoritative named layout");
    require(callerDeclared.editAnnotation(0x1000,"prototype","uint64_t(Packet* packet, uint64_t value)").ok(),"bind caller to authoritative named pointer");
    text=callerDeclared.decompiledCFor(0x1000);
    require(text.find("Packet* packet")!=std::string::npos&&text.find("->head")!=std::string::npos,"named authoritative fields retain their existing decompiler rendering");
    noImportedShape(text,"inferred field names do not replace authoritative named layout");
}
}
int main(){propagatedLayouts(false);propagatedLayouts(true);std::cout<<checks<<" interprocedural type Session checks passed\n";}
