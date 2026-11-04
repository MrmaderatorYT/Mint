#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include "mint/session.h"
#include "mint/base/mapped_file.h"
#include "mint/loader/elf_image.h"
#include "mint/analysis/code_analyzer.h"
#include "mint/analysis/abi_model.h"
#include "mint/analysis/cxx_metadata.h"
#include "mint/analysis/exception_metadata.h"
#include "mint/debug/dwarf_reader.h"
#include "mint/decompile/decompiler.h"
#include "mint/interp/executor.h"
#include "mint/ir/lifter.h"
#include "mint/ir/registers.h"

using namespace mint;
namespace {
unsigned checks=0;
void require(bool yes,const char* name){++checks;if(!yes){std::cerr<<"FAIL "<<name<<'\n';std::exit(1);}}
void put(std::vector<u8>& bytes,size_t at,u64 value,unsigned width,ByteOrder order) {
    for(unsigned i=0;i<width;++i)bytes.at(at+i)=u8(value>>((order==ByteOrder::kBig?width-1-i:i)*8));
}
std::vector<u8> fixture(ByteOrder order) {
    std::vector<u8> bytes(0x800);
    auto write=[&](size_t at,u64 value,unsigned width){put(bytes,at,value,width,order);};
    const u8 ident[]={0x7f,'E','L','F',2,u8(order==ByteOrder::kBig?2:1),1};
    std::copy(std::begin(ident),std::end(ident),bytes.begin());
    write(16,3,2);write(18,183,2);write(20,1,4);write(24,0x1200,8);write(32,64,8);write(40,0x600,8);
    write(52,64,2);write(54,56,2);write(56,1,2);write(58,64,2);write(60,8,2);write(62,6,2);
    write(64,1,4);write(68,5,4);write(80,0x1000,8);write(96,bytes.size(),8);write(104,0x900,8);write(112,0x1000,8);
    // A64 instructions always remain little-endian, independently of ELF data.
    put(bytes,0x200,0xf9400020,4,ByteOrder::kLittle); // ldr x0,[x1]
    put(bytes,0x204,0xf9000420,4,ByteOrder::kLittle); // str x0,[x1,#8]
    put(bytes,0x208,0xd65f03c0,4,ByteOrder::kLittle);
    write(0x300,0x0123456789abcdefull,8);
    write(0x400,0x1310,8);write(0x408,1027,8);write(0x410,0x1200,8); // RELATIVE
    write(0x450,12,8);write(0x458,0x1200,8); // DT_INIT, then DT_NULL
    write(0x518,1,4);write(0x51c,0x12,1);write(0x51e,1,2);write(0x520,0x1200,8);write(0x528,12,8);
    write(0x530,7,4);write(0x534,0x11,1);write(0x536,2,2);write(0x538,0x1300,8);write(0x540,24,8);
    const char names[]="\0entry\0target\0";std::memcpy(bytes.data()+0x560,names,sizeof(names));
    const char sections[]="\0.text\0.data\0.rela.data\0.symtab\0.strtab\0.shstrtab\0.dynamic\0";
    std::memcpy(bytes.data()+0x580,sections,sizeof(sections));
    auto section=[&](size_t n,u32 name,u32 type,u64 flags,u64 offset,u64 size,u32 link,u64 stride) {
        const auto at=0x600+n*64;write(at,name,4);write(at+4,type,4);write(at+8,flags,8);
        write(at+16,(flags&2)?0x1000+offset:0,8);write(at+24,offset,8);write(at+32,size,8);write(at+40,link,4);
        write(at+48,8,8);write(at+56,stride,8);
    };
    section(1,1,1,6,0x200,12,0,0);section(2,7,1,2,0x300,24,0,0);
    section(3,13,4,0,0x400,24,4,24);section(4,24,2,0,0x500,72,5,24);
    section(5,32,3,0,0x560,sizeof(names),0,0);section(6,40,3,0,0x580,sizeof(sections),0,0);
    section(7,50,6,2,0x450,32,5,16);
    return bytes;
}
void synthetic(ByteOrder order) {
    auto bytes=fixture(order);ElfImage image;
    require(image.load({bytes.data(),bytes.size()}).ok(),"ELF64 fixture loads");
    require(image.memory().byteOrder()==order,"target data order retained");
    require(image.entryPoint()==0x1200&&image.pointerSize()==8,"ELF header fields decoded");
    const auto* symbol=image.findSymbol("entry");require(symbol&&symbol->value==0x1200&&symbol->size==12,"symbol mixed-width fields decoded");
    require(image.initializers().size()==1&&image.initializers()[0]==0x1200,"dynamic DT_INIT decoded");
    Address target=0;require(image.resolvePointer(0x1310,&target)&&target==0x1200,"big-endian RELA pointer resolved");
    u64 value=0;require(image.memory().readInt(0x1300,&value)&&value==0x0123456789abcdefull,"target scalar memory read");
    CodeAnalyzer analyzer;require(analyzer.analyze(image).ok()&&analyzer.functionAt(0x1200),"A64 little-endian instruction discovery");
    IrFunction ir;Lifter lifter;require(lifter.open(image.arch()).ok()&&lifter.liftFunction(*analyzer.functionAt(0x1200),image.memory(),&ir).ok()&&ir.intrinsicCount==0,"A64 scalar load/store lift");
    require(ir.byteOrder==order&&ir.verify().empty(),"IR retains target byte order");
    InterpState state(image.arch());state.memory().map(image.memory());state.setRegister(arm64::kXn(1),0x1300,8);
    InterpResult result;require(executeIr(ir,&state,{},&result).ok()&&result.returned,"interpret target data order");
    require(state.registerValue(arm64::kXn(0),8).bits==value,"BE load does not byte-swap architectural value");
    for(unsigned i=0;i<8;++i){u8 byte=0;require(state.memory().readByte(0x1308+i,&byte)&&byte==bytes[0x300+i],"BE store writes exact target bytes");}
    DecompileResult c;require(decompileIr(ir,&c).ok()&&c.ssa.byteOrder==order,"SSA/decompiler retain data order");
    const u8 patch[]={0xaa,0xbb,0xcc,0xdd};require(image.applyPatch(0x1300,{patch,sizeof(patch)}).ok(),"patch BE data");
    require(image.memory().byteOrder()==order,"patch rebuild retains byte order");
    u32 word=0;require(image.memory().readInt(0x1300,&word)&&word==(order==ByteOrder::kBig?0xaabbccddu:0xddccbbaau),"patched scalar follows target order");
    image.resetPatches();require(image.memory().byteOrder()==order&&image.memory().readInt(0x1300,&value)&&value==0x0123456789abcdefull,"reset restores target order/data");
    if(order==ByteOrder::kBig) {
        auto bad=bytes;put(bad,18,62,2,order);ElfImage unsupported;
        require(!unsupported.load({bad.data(),bad.size()}).ok(),"impossible BE x86 target rejected");
        bad=bytes;bad[5]=3;require(!unsupported.load({bad.data(),bad.size()}).ok(),"invalid ELF data encoding rejected");
        auto little=fixture(ByteOrder::kLittle);ElfImage sidecar;
        require(sidecar.load({little.data(),little.size()}).ok(),"opposite-endian sidecar fixture loads");
        DwarfReport sentinel;sentinel.units=99;
        require(!readDwarf(image,sidecar,&sentinel,true).ok()&&sentinel.units==99,"unverified acknowledgement never bypasses external debug byte-order mismatch");
    }
}
void abi() {
    UserPrototype prototype;require(parseUserPrototype("uint32_t(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g,uint64_t h,uint8_t tail)",&prototype).ok(),"ABI declaration parses");
    prototype.byteOrder=ByteOrder::kBig;AbiModel model;require(buildAbiModel(Arch::kAArch64,prototype,&model).ok(),"big-endian scalar ABI");
    require(model.parameters.back().pieces[0].stackOffset==7&&model.stackBytes==8,"BE narrow stack scalar right-justified in its slot");
    DataTypeManager types;require(types.define("Pair=struct{a:u32;b:u32}").ok(),"aggregate fixture");
    require(parseUserPrototype("void(Pair value)",&prototype).ok(),"aggregate declaration parses");prototype.byteOrder=ByteOrder::kBig;
    require(buildAbiModel(Arch::kAArch64,prototype,&model,[&](const auto& name,auto* out){return types.resolve(name,out);}).ok()&&model.parameters[0].pieces.size()==1&&model.parameters[0].pieces[0].width==8,"BE aggregate ABI retains memory chunk layout");
}
void wideMemory() {
    for(auto order:{ByteOrder::kLittle,ByteOrder::kBig})for(unsigned width:{1u,2u,4u,8u,16u}) {
        InterpMemory memory;memory.setByteOrder(order);
        const u64 low=0x0123456789abcdefull,high=0xfedcba9876543210ull;
        memory.write(0x1000,InterpValue::wide(low,high,width),width);
        const auto value=memory.read(0x1000,width);
        const u64 mask=width>=8?~u64{0}:(u64{1}<<(width*8))-1;
        require(value.concreteLike()&&value.bits==(low&mask)&&value.highBits==(width==16?high:0),"interpreter memory widths preserve both halves");
        for(unsigned i=0;i<width;++i) {
            const auto index=order==ByteOrder::kBig?width-1-i:i;u8 byte=0;
            const auto expected=u8(index<8?low>>(index*8):high>>((index-8)*8));
            require(memory.readByte(0x1000+i,&byte)&&byte==expected,"memory byte positions follow explicit order");
        }
    }
}
void rawImport() {
    struct Temporary {std::string path="/tmp/mint-raw-endian-XXXXXX";Temporary(){if(!mkdtemp(path.data()))path.clear();}~Temporary(){if(!path.empty()){std::error_code ignored;std::filesystem::remove_all(path,ignored);}}} temp;
    require(!temp.path.empty(),"raw temp directory");
    const auto input=temp.path+"/input.bin",project=temp.path+"/program.mint",exported=temp.path+"/patched.bin";
    const u8 bytes[]={0x20,0x00,0x40,0xb9,0xc0,0x03,0x5f,0xd6,0x01,0x02,0x03,0x04};
    {std::ofstream out(input,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes),sizeof(bytes));require(out.good(),"write raw input");}
    for(auto order:{ByteOrder::kLittle,ByteOrder::kBig}) {
        Session session;require(session.openRawPath(input,Arch::kAArch64,0x1000,0x1000,order).ok(),"raw endian session open");
        u32 value=0;require(session.image().memory().readInt(0x1008,&value)&&value==(order==ByteOrder::kBig?0x01020304u:0x04030201u),"raw memory follows data byte order");
        require(session.analyze().ok()&&session.decompiledCFor(0x1000).find("decompiler failed")==std::string::npos,"raw A64 instructions decode little endian");
        CodeAnalyzer analyzer;require(analyzer.analyze(session.image()).ok()&&analyzer.functionAt(0x1000),"discover raw load");
        Lifter lifter;IrFunction ir;require(lifter.open(Arch::kAArch64).ok()&&lifter.liftFunction(*analyzer.functionAt(0x1000),session.image().memory(),&ir).ok()&&ir.byteOrder==order,"lift raw load with target order");
        InterpState state(Arch::kAArch64);state.memory().map(session.image().memory());state.setRegister(arm64::kXn(1),0x1008,8);InterpResult executed;
        require(executeIr(ir,&state,{},&executed).ok()&&executed.returned&&state.registerValue(arm64::kXn(0),8).bits==value,"raw IR load uses selected byte order");
    }
    Session bad;require(!bad.openRawPath(input,Arch::kX86_64,0x1000,0x1000,ByteOrder::kBig).ok(),"unsupported raw BE architecture rejected");
    {Session session;require(session.openRawPath(input,Arch::kAArch64,0x1000,0x1000,ByteOrder::kBig).ok()&&session.attachProject(project).ok()&&session.analyze().ok(),"raw BE project opens");
     require(session.editAnnotation(0x1008,"patch","11 22 33 44").ok(),"raw BE patch");
     u32 value=0;require(session.image().memory().readInt(0x1008,&value)&&value==0x11223344,"raw patch retains BE");
     require(session.exportPatchedCopy(exported).ok(),"raw patch exports");}
    {std::ifstream file(exported,std::ios::binary);std::vector<u8> contents((std::istreambuf_iterator<char>(file)),{});require(contents.size()==sizeof(bytes)&&contents[8]==0x11&&contents[11]==0x44,"raw export retains literal patched bytes");}
    {Session reopened;u32 value=0;require(reopened.openRawPath(input,Arch::kAArch64,0x1000,0x1000,ByteOrder::kBig).ok()&&reopened.attachProject(project).ok()&&reopened.analyze().ok()&&reopened.image().memory().readInt(0x1008,&value)&&value==0x11223344,"raw BE project reopens");}
    {Session wrong;require(wrong.openRawPath(input,Arch::kAArch64,0x1000,0x1000).ok()&&!wrong.attachProject(project).ok(),"raw LE cannot attach BE project");}
}
void real(const char* path) {
    MappedFile file;ElfImage image;require(file.open(path).ok()&&image.load(file.view()).ok(),"load real cross-compiled BE ELF");
    require(image.memory().byteOrder()==ByteOrder::kBig,"real ELF data order");
    DwarfReport report;require(readDwarf(image,&report).ok()&&report.units&&report.dies>10&&!report.sources.empty(),"real BE DWARF units/types/source mapping");
    require(std::any_of(report.types.begin(),report.types.end(),[](const auto& type){return type.name.find("MintNode")==0&&type.byteSize==16;}),"real BE recursive struct layout");
    const auto* entry=image.findSymbol("mint_debug_entry");const auto* data=image.findSymbol("mint_debug_array");
    require(entry&&data,"real BE Program fixture symbols");
    struct Temporary {
        std::string path="/tmp/mint-be-project-XXXXXX";
        Temporary(){if(!mkdtemp(path.data()))path.clear();}
        ~Temporary(){if(!path.empty()){std::error_code ignored;std::filesystem::remove_all(path,ignored);}}
    } temporary;
    require(!temporary.path.empty(),"create independent BE Program directory");
    const auto project=temporary.path+"/program.mint";
    {
        Session session;require(session.openPath(path).ok()&&session.attachProject(project).ok()&&session.analyze().ok(),"BE Session/Program analysis");
        require(session.editAnnotation(entry->value,"name","big_endian_entry").ok(),"BE Program rename");
        require(session.editAnnotation(data->value,"patch","11 22 33 44").ok(),"BE Program data patch");
        u32 value=0;require(session.image().memory().readInt(data->value,&value)&&value==0x11223344,"BE Program patch retains target memory interpretation");
        require(session.exportJsonText().find("\"data_byte_order\": \"big\"")!=std::string::npos,"BE JSON export labels target order");
    }
    Session reopened;require(reopened.openPath(path).ok()&&reopened.attachProject(project).ok()&&reopened.analyze().ok(),"cold reopen BE Program/cache");
    u32 patched=0;require(reopened.image().memory().byteOrder()==ByteOrder::kBig&&reopened.image().memory().readInt(data->value,&patched)&&patched==0x11223344&&reopened.displayNameAt(entry->value)=="big_endian_entry","cold BE restore preserves order, patch and annotation");
}
}
int main(int argc,char** argv) {
    synthetic(ByteOrder::kLittle);synthetic(ByteOrder::kBig);abi();wideMemory();rawImport();
    for(int i=1;i<argc;++i)real(argv[i]);
    std::cout<<"big-endian: "<<checks<<" checks passed\n";
}
