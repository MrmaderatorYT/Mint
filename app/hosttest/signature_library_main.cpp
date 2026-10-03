#include <cstdio>
#include <cstdlib>
#include <string>

#include "mint/types/signature_library.h"

using namespace mint;
namespace {
size_t checks=0;
void require(bool good,const char* message){++checks;if(!good){std::fprintf(stderr,"signature library: %s\n",message);std::exit(1);}}
void success(const Status& status,const char* message){if(!status.ok())std::fprintf(stderr,"%s\n",status.toString().c_str());require(status.ok(),message);}
void rejected(SignatureLibrary* library,const std::string& text){const auto before=library->serialize();require(!library->deserialize(text).ok(),"invalid library rejected");require(library->serialize()==before,"failed import is atomic");}
void rejectedDefine(SignatureLibrary* library,const std::string& symbol,const std::string& declaration){const auto before=library->serialize();require(!library->define(symbol,declaration).ok(),"unsupported definition rejected");require(library->serialize()==before,"failed definition is atomic");}
std::string parameters(size_t count,const std::string& type="uint32_t"){std::string out="uint32_t(";for(size_t i=0;i<count;++i){if(i)out+=", ";out+=type+" p"+std::to_string(i);}return out+")";}
void abiTests(SignatureAbi abi,Arch architecture,ImageFormat format,size_t slots,u8 width){
    SignatureLibrary library(abi);require(library.pointerSize()==width,"ABI pointer width");success(library.validateFor(architecture,format),"matching architecture/container accepted");
    success(library.define("scalar",parameters(slots)),"register scalar parameters accepted");
    success(library.define("stack",parameters(slots+1)),"overflow stack argument signature accepted");
    if(width==4){success(library.define("pairreturn","uint64_t(void)"),"32-bit register-pair return");success(library.define("pairparam","uint32_t(uint64_t pair)"),"32-bit register-pair/stack parameter");}
    else success(library.define("fullwidth","uint64_t(uint64_t value)"),"64-bit full-width scalar ABI");
    success(library.define("no_result","void(void)"),"void return");
    success(library.define("pointer_result","Packet*(void)"),"named pointer return in integer ABI");
    if(slots)success(library.define("pointer_arg","uint32_t(const Packet* packet)"),"const named pointer argument");
    require(!library.validateFor(Arch::kUnknown,format).ok(),"unknown architecture rejected");
    const bool windowsCompatible=abi==SignatureAbi::kWindows64||abi==SignatureAbi::kStdcall32||abi==SignatureAbi::kCdecl32||abi==SignatureAbi::kAapcs64;
    require(library.validateFor(architecture,ImageFormat::kPe64).ok()==windowsCompatible,"PE requires explicit compatible Windows convention");
    require(!library.validateFor(architecture,static_cast<ImageFormat>(255)).ok(),"unknown image container rejected");
    const auto text=library.serialize();SignatureLibrary restored;success(restored.deserialize(text),"ABI library roundtrip");require(restored.serialize()==text && restored.prototypeFor("scalar").valid() && restored.prototypeFor("scalar").parameters.size()==slots,"parsed prototypes retained");
    require(!restored.prototypeFor("Scalar").valid(),"symbol keys case-sensitive");
}
void parserTests(){
    SignatureLibrary library(SignatureAbi::kAapcs64);
    success(library.define("zeta"," uint64_t ( uint32_t count , void * buffer ) "),"spaced type-only prototype");
    success(library.define("_ZN3Foo3barEi","void(int32_t value)"),"original C++ linkage key");
    success(library.define("external@LIB_1.0","char*(void)"),"versioned linkage key");
    require(library.declarationFor("zeta")=="uint64_t(uint32_t count, void* buffer)","canonical prototype formatting");
    const auto definitions=library.definitions();require(definitions.size()==3 && definitions[0].symbol=="_ZN3Foo3barEi","deterministic symbol order");
    const std::string prefix="MINTSIG 1\nabi=aapcs64\n";
    rejected(&library,"MINTSIG 2\nabi=aapcs64\n");rejected(&library,"MINTSIG 1\nabi=win64\n");rejected(&library,"MINTSIG 1\nabi=unknown\n");
    rejected(&library,prefix+"same\tvoid(void)\nsame\tvoid(void)\n");
    rejected(&library,prefix+"same void(void)\n");rejected(&library,prefix+"same\tvoid(void)\textra\n");
    rejected(&library,prefix+"same\tvoid named(void)\n");rejected(&library,prefix+"same\tvoid(void);\n");
    rejected(&library,prefix+std::string("same\tvoid(void)\0",17));
    rejected(&library,prefix+"same\tvoid(\n");rejected(&library,prefix+"same\tuint64_t(uint32_t p@x0)\n");
    rejected(&library,std::string(SignatureLibrary::kMaxLibraryBytes+1,' '));
    rejectedDefine(&library,"zeta","void(void)");rejectedDefine(&library,"not a symbol","void(void)");
    rejectedDefine(&library,"control\tname","void(void)");rejectedDefine(&library,std::string(513,'x'),"void(void)");
    for(const std::string& bad:{"Packet(void)","uint64_t(Packet value)","uint64_t(void* (*callback)(void))","uint64_t(uint32_t same, uint32_t same)","uint64_t(uint32_t return)","uint64_t(void value)","@windows64 uint64_t(void)"})rejectedDefine(&library,"unsupported",bad);
    success(library.define("float_result","float(void)"),"AAPCS64 floating return signature");
    success(library.define("double_result","double(void)"),"AAPCS64 double return signature");
    success(library.define("float_parameter","uint64_t(float value)"),"AAPCS64 floating parameter signature");
    success(library.define("variadic","uint64_t(uint32_t n, ...)"),"variadic named-parameter signature");
    success(library.erase("zeta"),"explicit erase permits replacement");success(library.define("zeta","int32_t(void)"),"replacement after explicit erase");
    require(!library.erase("absent").ok(),"missing erase explicit failure");
    SignatureLibrary comments;success(comments.deserialize("MINTSIG 1\r\nabi=sysv64\r\n# authored test library\r\n\r\nlookup\tuint64_t(void)\r\n"),"CRLF and full-line comments accepted");
    require(comments.serialize()=="MINTSIG 1\nabi=sysv64\nlookup\tuint64_t(void)\n","portable canonical LF serialization");
    rejected(&comments,"MINTSIG 1\nabi=sysv64\nlookup\tuint64_t(void)\rnotline\n");
    rejected(&comments,"MINTSIG 1\nabi=sysv64\n#comment\x01\n");
    SignatureLibrary unknown;rejectedDefine(&unknown,"func","void(void)");require(!unknown.validateFor(Arch::kAArch64,ImageFormat::kElf64).ok(),"unknown ABI never silently defaulted");
    SignatureLibrary invalid(static_cast<SignatureAbi>(255));rejectedDefine(&invalid,"func","void(void)");require(invalid.pointerSize()==0,"invalid enum remains unsupported");
    SignatureLibrary bounded;std::string many=prefix;
    for(size_t i=0;i<SignatureLibrary::kMaxDefinitions;++i)many+="f"+std::to_string(i)+"\tvoid(void)\n";
    success(bounded.deserialize(many),"exact definition count limit");require(bounded.definitions().size()==SignatureLibrary::kMaxDefinitions,"all bounded authored definitions parsed");
    rejected(&bounded,many+"one_more\tvoid(void)\n");
}
} // namespace
int main(){
    abiTests(SignatureAbi::kAapcs64,Arch::kAArch64,ImageFormat::kElf64,8,8);
    abiTests(SignatureAbi::kSysV64,Arch::kX86_64,ImageFormat::kElf64,6,8);
    abiTests(SignatureAbi::kWindows64,Arch::kX86_64,ImageFormat::kPe64,4,8);
    abiTests(SignatureAbi::kStdcall32,Arch::kX86_32,ImageFormat::kPe64,0,4);
    abiTests(SignatureAbi::kAapcs32,Arch::kArm32,ImageFormat::kElf32,4,4);
    abiTests(SignatureAbi::kAapcs32,Arch::kThumb,ImageFormat::kRaw,4,4);
    abiTests(SignatureAbi::kRiscV32,Arch::kRiscV32,ImageFormat::kElf32,8,4);
    abiTests(SignatureAbi::kRiscV64,Arch::kRiscV64,ImageFormat::kElf64,8,8);
    abiTests(SignatureAbi::kCdecl32,Arch::kX86_32,ImageFormat::kElf32,0,4);
    parserTests();std::printf("signature library: %zu checks passed\n",checks);return 0;
}
