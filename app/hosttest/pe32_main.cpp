#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "mint/analysis/code_analyzer.h"
#include "mint/base/mapped_file.h"
#include "mint/disasm/disassembler.h"
#include "mint/loader/elf_image.h"

using namespace mint;
namespace {
size_t checks=0;
void require(bool good,const char* message){++checks;if(!good){std::fprintf(stderr,"PE32: %s\n",message);std::exit(1);}}
void success(const Status& status,const char* message){if(!status.ok())std::fprintf(stderr,"%s\n",status.toString().c_str());require(status.ok(),message);}
void put(std::vector<u8>* bytes,size_t offset,u64 value,size_t width){require(offset+width<=bytes->size(),"fixture bound");for(size_t i=0;i<width;++i)(*bytes)[offset+i]=static_cast<u8>(value>>(i*8));}
void string(std::vector<u8>* bytes,size_t offset,const char* value){const size_t size=std::strlen(value)+1;require(offset+size<=bytes->size(),"fixture string bound");std::memcpy(bytes->data()+offset,value,size);}
std::vector<u8> fixture(bool wide=false,Address base=0x400000){
    std::vector<u8> bytes(0xc00,0);const size_t optional=0x98,width=wide?8:4,optionalSize=wide?240:224,dirs=optional+(wide?112:96),section=optional+optionalSize;
    put(&bytes,0,0x5a4d,2);put(&bytes,0x3c,0x80,4);put(&bytes,0x80,0x4550,4);
    put(&bytes,0x84,wide?0x8664:0x14c,2);put(&bytes,0x86,2,2);put(&bytes,0x94,optionalSize,2);put(&bytes,0x96,0x102,2);
    put(&bytes,optional,wide?0x20b:0x10b,2);put(&bytes,optional+16,0x1000,4);put(&bytes,optional+(wide?24:28),base,width);
    put(&bytes,optional+32,0x1000,4);put(&bytes,optional+36,0x200,4);put(&bytes,optional+56,0x3000,4);put(&bytes,optional+60,0x200,4);
    put(&bytes,optional+70,0x40,2);put(&bytes,optional+(wide?108:92),16,4);
    put(&bytes,dirs,0x2000,4);put(&bytes,dirs+4,0x100,4);put(&bytes,dirs+8,0x2100,4);put(&bytes,dirs+12,40,4);
    put(&bytes,dirs+9*8,0x2400,4);put(&bytes,dirs+9*8+4,width*4+8,4);
    string(&bytes,section,".text");put(&bytes,section+8,0x200,4);put(&bytes,section+12,0x1000,4);put(&bytes,section+16,0x200,4);put(&bytes,section+20,0x200,4);put(&bytes,section+36,0x60000020,4);
    string(&bytes,section+40,".rdata");put(&bytes,section+48,0x800,4);put(&bytes,section+52,0x2000,4);put(&bytes,section+56,0x800,4);put(&bytes,section+60,0x400,4);put(&bytes,section+76,0xc0000040,4);
    bytes[0x200]=bytes[0x240]=0xb8;bytes[0x201]=7;bytes[0x241]=9;bytes[0x205]=bytes[0x245]=bytes[0x280]=0xc3;
    put(&bytes,0x40c,0x2080,4);put(&bytes,0x410,1,4);put(&bytes,0x414,2,4);put(&bytes,0x418,2,4);put(&bytes,0x41c,0x2030,4);put(&bytes,0x420,0x2040,4);put(&bytes,0x424,0x2048,4);
    put(&bytes,0x430,0x1000,4);put(&bytes,0x434,0x20a0,4);put(&bytes,0x440,0x2050,4);put(&bytes,0x444,0x2060,4);put(&bytes,0x44a,1,2);
    string(&bytes,0x450,"main32");string(&bytes,0x460,"forward_sleep");string(&bytes,0x480,"sample32.dll");string(&bytes,0x4a0,"KERNEL32.Sleep");
    put(&bytes,0x500,0x2300,4);put(&bytes,0x50c,0x2200,4);put(&bytes,0x510,0x2320,4);string(&bytes,0x600,"kernel32.dll");string(&bytes,0x642,"Sleep");
    put(&bytes,0x700,0x2240,width);put(&bytes,0x700+width,(u64{1}<<(width*8-1))|10,width);
    put(&bytes,0x720,0x2240,width);put(&bytes,0x720+width,(u64{1}<<(width*8-1))|10,width);
    put(&bytes,0x800+width*2,base+0x2600,width);put(&bytes,0x800+width*3,base+0x2500,width);
    put(&bytes,0x900,base+0x1040,width);put(&bytes,0x900+width,base+0x1080,width);return bytes;
}
bool warning(const ElfImage& image,const std::string& needle){for(const auto& text:image.warnings())if(text.find(needle)!=std::string::npos)return true;return false;}
void valid(bool wide,Address base){
    const auto bytes=fixture(wide,base);ElfImage image;success(image.load({bytes.data(),bytes.size()}),"load native PE image");
    require(image.arch()==(wide?Arch::kX86_64:Arch::kX86_32) && image.pointerSize()==(wide?8:4) && image.format()==ImageFormat::kPe64,"PE architecture/pointer width/generic format");
    require(image.imageBase()==base && image.entryPoint()==base+0x1000,"preferred image address arithmetic");
    const auto* main=image.findSymbol("main32");require(main && main->value==base+0x1000 && main->isFunction() && !main->undefined,"32-bit RVA export mapping");
    const auto* forward=image.findSymbol("forward_sleep");require(forward && forward->undefined && !forward->isFunction(),"forwarder is not code");
    require(image.findSymbol("kernel32.dll!Sleep") && image.findSymbol("kernel32.dll!ordinal_10") && image.relocations().size()==2,"named and ordinal imports");
    require(image.relocations()[0].offset==base+0x2320 && image.relocations()[1].offset==base+0x2320+(wide?8:4),"correct IAT thunk stride");
    require(image.findSymbol("tls_callback_0") && image.findSymbol("tls_callback_0")->value==base+0x1040 && image.findSymbol("tls_callback_1")->value==base+0x1080,"validated TLS callback VAs");
    CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;success(analyzer.analyze(image,options),"analyze loaded PE");
    require(analyzer.functions().size()==3 && analyzer.functionAt(base+0x1040) && analyzer.functionAt(base+0x1080),"TLS callbacks are real discovery roots");
    Disassembler decoder;success(decoder.open(image.arch()),"open architecture decoder");DecodedInsn instruction;
    require(decoder.decodeVerbose(base+0x1000,image.memory().viewAt(base+0x1000,16),&instruction) && instruction.record.size==5 && instruction.mnemonic=="mov","PE32 bytes decoded as x86-32, not x86-64 fallback");
    u64 offset=0;require(image.fileOffsetAt(base+0x1040,1,&offset) && offset==0x240,"TLS root source offset");
    const u8 patch=0x90;success(image.applyPatch(base+0x1000,{&patch,1}),"PE32 patch overlay");require(image.memory().viewAt(base+0x1000,1).data()[0]==0x90 && bytes[0x200]==0xb8,"patch preserves input bytes");
    image.resetPatches();require(image.memory().viewAt(base+0x1000,1).data()[0]==0xb8,"patch reset restores bytes");
    require(warning(image,"preferred VAs") && warning(image,"execution of SEH unwind"),"PE preferred-address and metadata-only unwind scope explicit");
}
void malformed(){
    const auto bytes=fixture();ElfImage image;
    for(size_t size=0;size<bytes.size();++size)require(!image.load({bytes.data(),size}).ok() && !image.loaded(),"every PE32 metadata/section truncation rejected");
    auto bad=bytes;put(&bad,0x84,0x8664,2);require(!image.load({bad.data(),bad.size()}).ok(),"AMD64 machine/PE32 magic mismatch rejected");
    bad=bytes;put(&bad,0x98,0x20b,2);require(!image.load({bad.data(),bad.size()}).ok(),"i386 machine/PE32+ magic mismatch rejected");
    bad=bytes;put(&bad,0x84,0x1c4,2);require(!image.load({bad.data(),bad.size()}).ok(),"ARM/Thumb PE unsupported rather than guessed");
    bad=bytes;put(&bad,0x94,95,2);require(!image.load({bad.data(),bad.size()}).ok(),"truncated optional header rejected");
    bad=bytes;put(&bad,0x98+92,17,4);require(!image.load({bad.data(),bad.size()}).ok(),"directory count bounded");
    bad=bytes;put(&bad,0x98+28,0xfffff000u,4);require(!image.load({bad.data(),bad.size()}).ok(),"32-bit image VA wrap rejected");
    bad=bytes;put(&bad,0x704,0x8001000a,4);success(image.load({bad.data(),bad.size()}),"malformed ordinal metadata does not discard valid code");require(!image.findSymbol("kernel32.dll!ordinal_10") && warning(image,"thunk table"),"reserved ordinal bits rejected");
    bad=bytes;put(&bad,0x500,0,4);success(image.load({bad.data(),bad.size()}),"OriginalFirstThunk fallback to IAT");require(image.relocations().size()==2,"fallback still uses 4-byte IAT stride");
    bad=bytes;put(&bad,0x900+4,0x402600,4);success(image.load({bad.data(),bad.size()}),"noncode TLS callback excluded safely");require(!image.findSymbol("tls_callback_0") && warning(image,"TLS roots ignored"),"TLS metadata is transactional, no partial invented roots");
    bad=bytes;put(&bad,0x80c,0xffffffffu,4);success(image.load({bad.data(),bad.size()}),"unmapped absolute TLS pointer excluded safely");require(!image.findSymbol("tls_callback_0"),"absolute TLS pointer is not treated as RVA");
    bad=bytes;for(size_t at=0x900;at<bad.size();at+=4)put(&bad,at,0x401040,4);success(image.load({bad.data(),bad.size()}),"unterminated TLS callback table bounded");require(!image.findSymbol("tls_callback_0") && warning(image,"TLS roots ignored"),"no TLS roots from unterminated table");
    bad=bytes;put(&bad,0x98+96+9*8+4,20,4);success(image.load({bad.data(),bad.size()}),"short declared TLS directory excluded safely");require(!image.findSymbol("tls_callback_0"),"PE32 TLS directory needs all 24 bytes");
    bad=bytes;put(&bad,0x98+96+8,0xfffffff0u,4);success(image.load({bad.data(),bad.size()}),"invalid import directory range excluded safely");require(image.relocations().empty() && warning(image,"out-of-image"),"no imports from wrapped directory");
    bad=bytes;put(&bad,0x98+96+4,20,4);success(image.load({bad.data(),bad.size()}),"short declared export directory excluded safely");require(!image.findSymbol("main32") && warning(image,"export directory"),"exports need a complete declared 40-byte directory");
    bad=bytes;const size_t sections=0x98+224;put(&bad,sections+52,0x1000,4);require(!image.load({bad.data(),bad.size()}).ok(),"overlapping sections rejected");
}
void real(const char* path){MappedFile file;success(file.open(path),"open real clang PE32 fixture");ElfImage image;success(image.load(file.view()),"load actual linked PE32");require(image.arch()==Arch::kX86_32 && image.pointerSize()==4 && image.memory().isExecutable(image.entryPoint()),"actual i386 linked image architecture and executable entry");CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;success(analyzer.analyze(image,options),"analyze actual PE32");require(!analyzer.functions().empty() && !analyzer.code().empty(),"actual PE32 produces code/functions");}
} // namespace
int main(int argc,char** argv){valid(false,0x400000);valid(false,0xffffd000u);valid(true,0x140000000);malformed();for(int i=1;i<argc;++i)real(argv[i]);std::printf("PE32: %zu checks passed\n",checks);return 0;}
