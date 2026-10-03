#include "mint/session.h"
#include "mint/loader/elf_types.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <iostream>

using namespace mint;
namespace {
size_t checks=0;
void require(bool value,const std::string& message){++checks;if(!value){std::cerr<<"Platform extensions: "<<message<<'\n';std::exit(1);}}
void okay(const Status& status,const std::string& message){require(status.ok(),message+": "+status.toString());}
struct Files {
    std::vector<std::string> paths;
    ~Files(){for(const auto& path:paths){::unlink(path.c_str());::unlink((path+".analysis").c_str());}}
    std::string make(const std::vector<u8>& bytes={},bool newFile=false) {
        std::string path="/private/tmp/mint-platform-extensions-XXXXXX";int fd=::mkstemp(path.data());require(fd>=0,"owned temporary");paths.push_back(path);
        size_t at=0;while(at<bytes.size()){auto n=::write(fd,bytes.data()+at,bytes.size()-at);require(n>0,"fixture write");at+=static_cast<size_t>(n);}
        require(::close(fd)==0,"fixture close");if(newFile)require(::unlink(path.c_str())==0,"new destination");return path;
    }
};
std::vector<u8> rawCode(){std::vector<u8> bytes(32);u32 instructions[]={0xd28000e0,0xd65f03c0,0xd503201f,0xd503201f,0xd2800100,0xd65f03c0};std::memcpy(bytes.data(),instructions,sizeof(instructions));return bytes;}
std::vector<u8> symbolicCode(){
    // A real linkage name, not a generated sub_ADDRESS label, is required for
    // signature matching. Raw input deliberately has no linkage symbol table.
    std::vector<u8> bytes(0x400);auto put=[&](size_t offset,const auto& value){std::memcpy(bytes.data()+offset,&value,sizeof(value));};
    elf::Ehdr header{};std::memcpy(header.ident,elf::kMagic,4);header.ident[elf::kEiClass]=2;header.ident[elf::kEiData]=1;header.ident[elf::kEiVersion]=1;
    header.type=elf::kEtExec;header.machine=elf::kEmAArch64;header.version=1;header.entry=0x1000;header.phoff=sizeof(header);header.ehsize=sizeof(header);header.phentsize=sizeof(elf::Phdr);header.phnum=1;header.shoff=0x280;header.shentsize=sizeof(elf::Shdr);header.shnum=4;put(0,header);
    elf::Phdr mapping{};mapping.type=elf::kPtLoad;mapping.flags=elf::kPfR|elf::kPfX;mapping.offset=0x100;mapping.vaddr=0x1000;mapping.filesz=mapping.memsz=32;mapping.align=4;put(header.phoff,mapping);
    const auto code=rawCode();std::memcpy(bytes.data()+0x100,code.data(),code.size());
    const char symbols[]="\0fixture_entry\0fixture_other\0";std::memcpy(bytes.data()+0x180,symbols,sizeof(symbols));
    elf::Sym entry{};entry.name=1;entry.info=(elf::kStbGlobal<<4)|elf::kSttFunc;entry.shndx=1;entry.value=0x1000;entry.size=8;put(0x1c0+sizeof(entry),entry);
    entry.name=15;entry.value=0x1010;put(0x1c0+2*sizeof(entry),entry);
    elf::Shdr text{};text.type=elf::kShtProgBits;text.flags=elf::kShfAlloc|elf::kShfExecInstr;text.addr=0x1000;text.offset=0x100;text.size=32;text.addralign=4;put(0x280+sizeof(text),text);
    elf::Shdr strings{};strings.type=elf::kShtStrTab;strings.offset=0x180;strings.size=sizeof(symbols);strings.addralign=1;put(0x280+2*sizeof(strings),strings);
    elf::Shdr table{};table.type=elf::kShtSymTab;table.offset=0x1c0;table.size=3*sizeof(elf::Sym);table.entsize=sizeof(elf::Sym);table.link=2;table.info=1;table.addralign=8;put(0x280+3*sizeof(table),table);
    return bytes;
}
void rawWorkflow() {
    Files files;const auto input=files.make(symbolicCode()),project=files.make({},true),otherInput=files.make(rawCode()),otherProject=files.make({},true);
    Session source;okay(source.openPath(input),"symbolic native open");okay(source.attachProject(project),"persistent Program");okay(source.analyze(),"analyze");
    okay(source.importLibrary("MINT_TYPES 1 8\nNode=struct{value:i32;next:Node*}\nAlias=Node*\n",false),"mutually linked type import");
    require(source.typesText().find("Node=struct")!=std::string::npos && source.typesCHeaderText().find("offsetof(Node, next)")!=std::string::npos,"type import reaches C header");
    auto before=source.typesText();require(!source.importLibrary("MINT_TYPES 1 4\nWrong=u32\n",false).ok() && source.typesText()==before,"ABI mismatch import atomic");
    const auto* original=source.image().findSymbol("fixture_entry");require(original && original->value==0x1000,"original linkage symbol");const auto symbol=original->name;
    require(source.nameAt(0x1000)==symbol,"entry-point provenance does not hide original linkage symbol");
    const auto library="MINTSIG 1\nabi=aapcs64\n"+symbol+"\tuint32_t(void)\n";
    okay(source.importLibrary(library,true),"signature import");require(source.prototypeAt(0x1000).returnType=="uint32_t","signature bound to original linkage name");
    okay(source.editAnnotation(0x1000,"name","edited_entry"),"user symbol override");require(source.prototypeAt(0x1000).returnType=="uint32_t","rename does not erase original linkage signature");
    okay(source.editAnnotation(0x1000,"prototype","int32_t(void)"),"explicit signature override");require(source.prototypeAt(0x1000).returnType=="int32_t","explicit prototype wins");
    okay(source.undoEdit(false),"undo prototype");require(source.prototypeAt(0x1000).returnType=="uint32_t","undo exposes imported signature");
    require(!source.importLibrary("MINTSIG 1\nabi=sysv64\n"+symbol+"\tvoid(void)\n",true).ok() && source.signatureLibraryText()==library,"foreign signature ABI rejected atomically");
    require(source.decompiledCFor(0x1000).find("uint32_t edited_entry(void)")!=std::string::npos,"imported signature reaches decompiler");
    require(source.interproceduralText().find("authoritative")!=std::string::npos,"call-graph report consumes authored signatures");
    std::string output;okay(source.assembleAt(0x1000,"mov x0, #9; ret",false,&output),"assembler preview");
    require(!output.empty() && source.annotation(0x1000,"patch").empty(),"preview does not patch");
    okay(source.runScript("print(mint.source('0x1000'))",false,&output),"Lua can inspect native source metadata");
    require(!source.loadPlugin("/missing-plugin",false).ok(),"native plugin requires trust");
    okay(source.debuggerCommand("status",0,0,&output),"disconnected debugger status");require(output.find("disconnected")!=std::string::npos,"no debugger auto-connect");
    require(!source.connectDebugger("example.com",3333,false,false).ok(),"DNS endpoint rejected before network");
    require(!source.openComparison(otherInput,project,Arch::kAArch64,0x2000,0x2000).ok(),"same project cannot have competing writers");
    okay(source.openComparison(otherInput,otherProject,Arch::kAArch64,0x2000,0x2000),"independent raw comparison");
    okay(source.comparisonCommand("preview",0,0,"",&output),"unauthorized transfer preview");require(output.find("0 applicable")!=std::string::npos,"diff candidates never grant transfer permission");
    okay(source.comparisonCommand("diff",0,0,"",&output),"semantic diff facade");require(output.find("0x1000")!=std::string::npos && output.find("0x2000")!=std::string::npos,"rebased function matching output");
    okay(source.editAnnotation(0x1000,"comment","transfer me"),"source comment");
    okay(source.comparisonCommand("confirm",0x1000,0x2000,"",&output),"manual pair confirmation");
    const auto tracking=files.make({},true);okay(source.comparisonCommand("save",0,0,tracking,&output),"confirmed pair persisted");
    require(!source.comparisonCommand("save",0,0,tracking,&output).ok(),"tracking save never overwrites");
    okay(source.comparisonCommand("load",0,0,tracking,&output),"confirmed pair reopen");
    okay(source.comparisonCommand("preview",0,0,"",&output),"annotation transfer preview");require(output.find("transfer me")!=std::string::npos,"preview names exact edits");
    okay(source.comparisonCommand("apply",0,0,"",&output),"confirmed transfer apply");
    require(source.annotation(0x1000,"comment")=="transfer me","source remains unchanged");
    Session target;okay(target.openRawPath(otherInput,Arch::kAArch64,0x2000,0x2000),"target reopen");okay(target.attachProject(otherProject),"target persisted project");okay(target.analyze(),"target reanalysis");require(target.annotation(0x2000,"comment")=="transfer me","transfer survives target reopen");
    Session reopened;okay(reopened.openPath(input),"source reopen");okay(reopened.attachProject(project),"source persisted project");okay(reopened.analyze(),"source analysis reopen");
    require(reopened.signatureLibraryText()==library && reopened.prototypeAt(0x1000).returnType=="uint32_t","signature library and linkage binding survive reopen");
}
void dwarfWorkflow(const std::string& path) {
    Session session;okay(session.openPath(path),"real DWARF Session open");okay(session.analyze(),"real DWARF function discovery");
    const auto* symbol=session.image().findSymbol("mint_debug_entry");require(symbol!=nullptr,"real function symbol");
    require(session.typesText().find("MintNode")!=std::string::npos,"DWARF types automatically in Program");
    require(session.prototypeAt(symbol->value).valid(),"DWARF prototype consumed");
    require(session.sourceLocationText(symbol->value).find("dwarf_fixture.c")!=std::string::npos,"Session source mapping consumed");
    const auto code=session.decompiledCFor(symbol->value);require(code.find("MintNode")!=std::string::npos && code.find("DWARF source:")!=std::string::npos && code.find("Mint field offset")!=std::string::npos,"DWARF Program types/source reach actual pseudo-C");
}
}
int main(int argc,char** argv){rawWorkflow();for(int i=1;i<argc;++i)dwarfWorkflow(argv[i]);std::cout<<"Platform extensions: "<<checks<<" checks passed\n";}
