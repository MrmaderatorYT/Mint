#include "mint/analysis/cxx_metadata.h"
#include "mint/base/mapped_file.h"
#include "mint/loader/elf_image.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <cstring>
using namespace mint;
namespace {
unsigned checks=0;
void require(bool yes,const std::string& name){++checks;if(!yes){std::cerr<<"MS RTTI: "<<name<<'\n';std::exit(1);}}
void put(std::vector<u8>& bytes,u64 at,u64 value,unsigned width=4){require(at+width<=bytes.size(),"fixture write extent");for(unsigned n=0;n<width;++n)bytes[at+n]=u8(value>>(n*8));}
void text(std::vector<u8>& bytes,u64 at,const std::string& value){require(at+value.size()+1<=bytes.size(),"fixture string extent");std::copy(value.begin(),value.end(),bytes.begin()+at);bytes[at+value.size()]=0;}
u64 fileOffset(u64 rva){return rva>=0x2000?rva-0x2000+0x400:rva-0x1000+0x200;}
struct Fixture {
    unsigned width;Address base;std::vector<u8> bytes=std::vector<u8>(0x1400);
    explicit Fixture(unsigned w):width(w),base(w==8?0x140000000ull:0x400000) {
        put(bytes,0,0x5a4d,2);put(bytes,0x3c,0x80);put(bytes,0x80,0x4550);put(bytes,0x84,w==8?0x8664:0x14c,2);put(bytes,0x86,2,2);
        const unsigned optional=w==8?240:224;put(bytes,0x94,optional,2);put(bytes,0x96,0x22,2);put(bytes,0x98,w==8?0x20b:0x10b,2);
        put(bytes,0x98+16,0x1000);put(bytes,0x98+(w==8?24:28),base,w);put(bytes,0x98+32,0x1000);put(bytes,0x98+36,0x200);put(bytes,0x98+56,0x3000);put(bytes,0x98+60,0x200);
        put(bytes,0x98+(w==8?108:92),16);const auto directories=0x98+(w==8?112:96);put(bytes,directories,0x2800);put(bytes,directories+4,0x100);
        const unsigned sections=0x98+optional;text(bytes,sections,".text");put(bytes,sections+8,0x200);put(bytes,sections+12,0x1000);put(bytes,sections+16,0x200);put(bytes,sections+20,0x200);put(bytes,sections+36,0x60000020);
        text(bytes,sections+40,".rdata");put(bytes,sections+48,0x1000);put(bytes,sections+52,0x2000);put(bytes,sections+56,0x1000);put(bytes,sections+60,0x400);put(bytes,sections+76,0x40000040);
        bytes[0x200]=0xc3;bytes[0x210]=0xc3;
        pointer(0x2100,0x2300);pointer(0x2100+w,0x1000);pointer(0x2140,0x2330);pointer(0x2140+w,0x1010);pointer(0x2200,0x1000);
        for(const auto& entry:std::vector<std::pair<u32,std::string>>{{0x2220,".?AUDerived@@"},{0x2260,".?AUBase@@"},{0x22a0,".?AURight@@"}}){pointer(entry.first,0x2200);text(bytes,fileOffset(entry.first)+w*2,entry.second);}
        locator(0x2300,0);locator(0x2330,8);
        hierarchy(0x2380,3,0x2400);hierarchy(0x23a0,1,0x24e0);hierarchy(0x23c0,1,0x24f0);
        reference(0x2400,0x2420);reference(0x2404,0x2450);reference(0x2408,0x2480);reference(0x24e0,0x2450);reference(0x24f0,0x24b0);
        descriptor(0x2420,0x2220,2,0,0x2380);descriptor(0x2450,0x2260,0,0,0x23a0);descriptor(0x2480,0x22a0,0,8,0x23c0);descriptor(0x24b0,0x22a0,0,0,0x23c0);
        const auto e=fileOffset(0x2800);put(bytes,e+12,0x28e0);put(bytes,e+16,1);put(bytes,e+20,2);put(bytes,e+24,2);put(bytes,e+28,0x2840);put(bytes,e+32,0x2850);put(bytes,e+36,0x2860);
        put(bytes,fileOffset(0x2840),0x2100+w);put(bytes,fileOffset(0x2844),0x2140+w);put(bytes,fileOffset(0x2850),0x2880);put(bytes,fileOffset(0x2854),0x28b0);put(bytes,fileOffset(0x2860),0,2);put(bytes,fileOffset(0x2862),1,2);
        text(bytes,fileOffset(0x2880),"??_7Derived@@6BBase@@@");text(bytes,fileOffset(0x28b0),"??_7Derived@@6BRight@@@");text(bytes,fileOffset(0x28e0),"fixture.exe");
    }
    void pointer(u32 at,u32 target){put(bytes,fileOffset(at),base+target,width);}
    void reference(u32 at,u32 target){put(bytes,fileOffset(at),width==8?target:base+target);}
    void locator(u32 at,u32 offset){put(bytes,fileOffset(at),width==8?1:0);put(bytes,fileOffset(at)+4,offset);reference(at+12,0x2220);reference(at+16,0x2380);if(width==8)reference(at+20,at);}
    void hierarchy(u32 at,u32 count,u32 array){put(bytes,fileOffset(at)+4,count>1?1:0);put(bytes,fileOffset(at)+8,count);reference(at+12,array);}
    void descriptor(u32 at,u32 type,u32 contained,i32 member,u32 own){reference(at,type);put(bytes,fileOffset(at)+4,contained);put(bytes,fileOffset(at)+8,u32(member));put(bytes,fileOffset(at)+12,0xffffffff);put(bytes,fileOffset(at)+20,64);reference(at+24,own);}
};
CxxMetadataReport report(const std::vector<u8>& bytes,size_t limit=1024){ElfImage image;require(image.load(ByteView(bytes.data(),bytes.size())).ok(),"synthetic PE loads");return inspectCxxMetadata(image,limit);}
void synthetic(){for(unsigned width:{4u,8u}) {
    Fixture fixture(width);const auto decoded=report(fixture.bytes);require(decoded.records.size()==2&&decoded.classes.size()==1,"exact Microsoft exported vftables bind one class");
    const auto& klass=decoded.classes[0];require(klass.name=="Derived"&&klass.inheritanceComplete&&klass.bases.size()==2,"complete direct hierarchy recovered");
    require(klass.bases[0].name=="Base"&&klass.bases[0].objectOffset==0&&klass.bases[1].name=="Right"&&klass.bases[1].objectOffset==8,"nonvirtual direct base offsets retained");
    require(klass.addressPoints.size()==2&&klass.addressPoints[0].offsetToTop==0&&klass.addressPoints[1].offsetToTop==-8,"primary/secondary vfptr offsets separated");
    require(klass.addressPoints[0].slots.size()==1&&klass.addressPoints[1].slots.size()==1,"executable slot prefix recovered without metadata-as-method confusion");
    require(!decoded.records[0].complete&&!klass.addressPoints[0].complete,"unknown full vftable extent remains partial");
    auto virtualBytes=fixture.bytes;put(virtualBytes,fileOffset(0x2480)+8,0);put(virtualBytes,fileOffset(0x2480)+12,8);put(virtualBytes,fileOffset(0x2480)+16,4);put(virtualBytes,fileOffset(0x2480)+20,80);
    const auto virtualReport=report(virtualBytes);require(virtualReport.classes.size()==1&&virtualReport.classes[0].bases[1].isVirtual&&virtualReport.classes[0].bases[1].usesPmd&&virtualReport.classes[0].bases[1].vbptrOffset==8&&virtualReport.classes[0].bases[1].vbtableOffset==4&&!virtualReport.classes[0].bases[1].virtualOffsetResolved,"virtual PMD retained without inventing runtime object offset");
    auto privateBytes=fixture.bytes;put(privateBytes,fileOffset(0x2480)+20,64|13|2);const auto privateReport=report(privateBytes);
    require(privateReport.classes.size()==1&&!privateReport.classes[0].bases[1].isPublic&&privateReport.classes[0].bases[1].ambiguous,"private/ambiguous RTTI flags retained");
    ElfImage displayImage;require(displayImage.load({virtualBytes.data(),virtualBytes.size()}).ok(),"display fixture");const auto rendered=cxxMetadataText(displayImage);require(rendered.find("Microsoft ABI")!=std::string::npos&&rendered.find("PMD(0, 8, 4)")!=std::string::npos&&rendered.find("runtime object required")!=std::string::npos,"public C++ report exposes Microsoft semantics");
    const auto zero=report(fixture.bytes,0);require(zero.records.empty()&&zero.truncated,"zero inventory budget");const auto one=report(fixture.bytes,1);require(one.records.size()==1&&one.truncated,"bounded export inventory");
    auto rejected=[&](std::vector<u8> bytes,const char* message){const auto bad=report(bytes);require(bad.classes.empty(),message);};
    // Shared descriptors invalidate both address points; preserve a partial
    // inventory but publish no class relationship from the damaged graph.
    for(const auto& mutation:std::vector<std::pair<u64,u32>>{{fileOffset(0x2380),1},{fileOffset(0x2380)+4,8},{fileOffset(0x2380)+8,129},
        {fileOffset(0x2420)+4,0},{fileOffset(0x2480)+4,1},{fileOffset(0x2480)+12,0xfffffffe},{fileOffset(0x2480)+16,3},{fileOffset(0x2480)+20,0x80},
        {fileOffset(0x2220)+width,1}}){auto damaged=fixture.bytes;put(damaged,mutation.first,mutation.second);rejected(std::move(damaged),"malformed hierarchy/type storage never publishes classes");}
    auto cycle=fixture;cycle.reference(0x2480,0x2220);rejected(cycle.bytes,"cyclic class identity rejected");
    auto wrongType=fixture.bytes;text(wrongType,fileOffset(0x2220)+width*2,".?AUForeign@@");rejected(std::move(wrongType),"linkage/descriptor identity mismatch rejected");
    auto nonClass=fixture.bytes;text(nonClass,fileOffset(0x2220)+width*2,".H");rejected(std::move(nonClass),"non-class RTTI cannot authorize an exported class");
    auto noMethods=fixture;noMethods.pointer(0x2100+width,0x2200);noMethods.pointer(0x2140+width,0x2200);rejected(noMethods.bytes,"metadata pointer cannot become a virtual method");
    for(u32 flags:{0xc0000040u,0x60000020u}){auto permissions=fixture.bytes;put(permissions,0x98+(width==8?240:224)+76,flags);rejected(std::move(permissions),"writable or executable RTTI never authorizes hierarchy evidence");}
    auto conflicting=fixture;conflicting.hierarchy(0x2500,3,0x2520);conflicting.reference(0x2520,0x2540);conflicting.reference(0x2524,0x2450);conflicting.reference(0x2528,0x2480);conflicting.descriptor(0x2540,0x2220,2,0,0x2500);conflicting.reference(0x2330+16,0x2500);
    const auto conflict=report(conflicting.bytes);require(conflict.classes.empty()&&conflict.records[0].addressPoints.size()==1&&conflict.records[1].addressPoints.size()==1,"individually valid conflicting hierarchy identities are never merged");
    auto absent=fixture.bytes;const auto directories=0x98+(width==8?112:96);put(absent,directories,0);put(absent,directories+4,0);require(report(absent).records.empty(),"stripped metadata is not found by scanning plausible bytes");
    for(u32 col:{0x2300u,0x2330u}) {
        auto damaged=fixture.bytes;put(damaged,fileOffset(col),2);const auto partial=report(damaged);require(partial.classes.size()==1&&partial.classes[0].addressPoints.size()==1,"one malformed locator does not authorize a secondary point");
        if(width==8){damaged=fixture.bytes;put(damaged,fileOffset(col)+20,0x2310);const auto self=report(damaged);require(self.classes.size()==1&&self.classes[0].addressPoints.size()==1,"COL self-reference binds exact address point");}
    }
    auto construction=fixture.bytes;put(construction,fileOffset(0x2300)+8,4);put(construction,fileOffset(0x2330)+8,4);rejected(std::move(construction),"construction displacement remains unsupported instead of fixed offset");
    auto nullVptr=fixture;put(nullVptr.bytes,fileOffset(0x2220),0,width);rejected(nullVptr.bytes,"type_info vptr must have bounded target storage");
    auto missing=fixture;missing.pointer(0x2100,0x2ff8);missing.pointer(0x2140,0x2ff8);rejected(missing.bytes,"truncated locators reject zero-fill fabrication");
}}
void real(const char* path){MappedFile file;require(file.open(path).ok(),"real Microsoft PE open");ElfImage image;require(image.load(file.view()).ok(),"real Microsoft PE load");const auto found=inspectCxxMetadata(image);require(found.classes.size()==5&&found.records.size()==6,"compiler-produced five classes and six exported vftables recovered");
    bool single=false,multiple=false,virtualBase=false;
    size_t methods=0,points=0;
    for(const auto& klass:found.classes){require(klass.inheritanceComplete,"compiler hierarchy complete");require(!klass.addressPoints.empty(),"compiler class has verified address point");
        if(klass.name=="Derived")single=klass.bases.size()==1&&klass.bases[0].name=="Base";
        if(klass.name=="Multiple")multiple=klass.bases.size()==2&&klass.addressPoints.size()==2&&klass.addressPoints[1].offsetToTop==-i64(image.pointerSize());
        if(klass.name=="Virtual")virtualBase=klass.bases.size()==1&&klass.bases[0].isVirtual&&klass.bases[0].usesPmd&&!klass.bases[0].virtualOffsetResolved;
        for(size_t n=0;n<klass.addressPoints.size();++n){const auto& point=klass.addressPoints[n];++points;require(point.slots.size()==1,"fixture has exactly one verified method per address point");
            const std::string method=(klass.name=="Right"||(klass.name=="Multiple"&&n==1)?"?right@":"?base@")+klass.name+"@@";
            const auto expected=std::find_if(image.symbols().begin(),image.symbols().end(),[&](const auto& symbol){return symbol.name.compare(0,method.size(),method)==0;});
            require(expected!=image.symbols().end()&&point.slots.front().target==expected->value,"compiler vftable method identity agrees with exported implementation");
            for(const auto& slot:point.slots){++methods;require(slot.executable&&image.memory().isExecutable(slot.target),"compiler method target executable");}}}
    if(!single||!multiple||!virtualBase)std::cerr<<cxxMetadataText(image)<<'\n';
    require(single&&multiple&&virtualBase,"real single/multiple/virtual Microsoft inheritance");
    require(points==6&&methods==6,"compiler corpus has six verified address points and method targets");
    require(cxxMetadataText(image).find("runtime object required")!=std::string::npos,"real virtual-base uncertainty visible");
}
}
int main(int argc,char** argv){synthetic();for(int n=1;n<argc;++n)real(argv[n]);std::cout<<checks<<" Microsoft RTTI checks passed\n";}
