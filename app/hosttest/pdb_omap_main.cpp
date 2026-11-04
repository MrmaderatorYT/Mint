#include "mint/debug/pdb_omap.h"
#include "mint/debug/pdb_reader.h"
#include "mint/loader/elf_image.h"
#include "mint/session.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <unistd.h>

using namespace mint;
namespace {
unsigned checks=0;
void require(bool yes,const char* text){++checks;if(!yes){std::cerr<<"PDB OMAP: "<<text<<'\n';std::exit(1);}}
void put(std::vector<u8>& bytes,u64 at,u64 value,unsigned width=4){if(at+width>bytes.size())bytes.resize(at+width);for(unsigned n=0;n<width;++n)bytes[at+n]=u8(value>>(n*8));}
void text(std::vector<u8>& bytes,u64 at,const char* value){const auto size=std::strlen(value)+1;if(at+size>bytes.size())bytes.resize(at+size);std::memcpy(bytes.data()+at,value,size);}
ByteView view(const std::vector<u8>& bytes){return ByteView(bytes.data(),bytes.size());}
std::vector<u8> table(std::initializer_list<std::pair<u32,u32>> entries){std::vector<u8> bytes;for(auto pair:entries){const auto at=bytes.size();put(bytes,at,pair.first);put(bytes,at+4,pair.second);}return bytes;}
std::vector<u8> sections(){std::vector<u8> h(40,0);text(h,0,".before");put(h,8,0x200);put(h,12,0x5000);put(h,36,0x60000020);return h;}
std::vector<u8> forward(){return table({{0x5000,0x1000},{0x5010,0x1040},{0x5020,0},{0x5030,0x1020},{0x5040,0},{0x5050,0x2000},{0x5060,0x2010},{0x5064,0x2020},{0x5068,0}});}
std::vector<u8> pe(){
    std::vector<u8> bytes(0x600,0);put(bytes,0,0x5a4d,2);put(bytes,0x3c,0x80);put(bytes,0x80,0x4550);put(bytes,0x84,0x8664,2);put(bytes,0x86,2,2);put(bytes,0x94,240,2);put(bytes,0x96,0x22,2);
    const u64 opt=0x98;put(bytes,opt,0x20b,2);put(bytes,opt+16,0x1000);put(bytes,opt+24,0x140000000ull,8);put(bytes,opt+32,0x1000);put(bytes,opt+36,0x200);put(bytes,opt+56,0x3000);put(bytes,opt+60,0x200);put(bytes,opt+108,16);put(bytes,opt+160,0x2000);put(bytes,opt+164,28);
    text(bytes,0x188,".text");put(bytes,0x190,0x200);put(bytes,0x194,0x1000);put(bytes,0x198,0x200);put(bytes,0x19c,0x200);put(bytes,0x1ac,0x60000020);
    text(bytes,0x1b0,".rdata");put(bytes,0x1b8,0x200);put(bytes,0x1bc,0x2000);put(bytes,0x1c0,0x200);put(bytes,0x1c4,0x400);put(bytes,0x1d4,0x40000040);
    std::fill(bytes.begin()+0x200,bytes.begin()+0x400,0xc3);
    put(bytes,0x40c,2);put(bytes,0x410,34);put(bytes,0x414,0x2020);put(bytes,0x418,0x420);text(bytes,0x420,"RSDS");for(unsigned n=0;n<16;++n)bytes[0x424+n]=n+1;put(bytes,0x434,7);text(bytes,0x438,"bound.pdb");return bytes;
}
void subsection(std::vector<u8>& out,u32 kind,const std::vector<u8>& bytes){const auto at=out.size();put(out,at,kind);put(out,at+4,bytes.size());out.insert(out.end(),bytes.begin(),bytes.end());while(out.size()%4)out.push_back(0);}
std::vector<u8> lines(){
    std::vector<u8> strings={0,'o','m','a','p','.','c',0},checksum(8,0),fragment(12+12+5*8,0),out;
    put(checksum,0,1);put(fragment,0,0);put(fragment,4,1,2);put(fragment,8,0x40);put(fragment,16,5);put(fragment,20,12+5*8);
    unsigned n=0;for(u32 offset:{0u,8u,16u,32u,48u}){put(fragment,24+n*8,offset);put(fragment,28+n*8,10+n);++n;}
    subsection(out,0xf2,fragment);subsection(out,0xf4,checksum);subsection(out,0xf3,strings);return out;
}
void symbol(std::vector<u8>& out,u16 kind,u32 offset,const char* name,u32 size=0,u32 type=0){
    const bool proc=kind==0x1110,pub=kind==0x110e;const unsigned nameAt=proc?37:12;
    std::vector<u8> record(nameAt,0);put(record,0,kind,2);
    if(proc){put(record,14,size);put(record,26,type);put(record,30,offset);put(record,34,1,2);}
    else {put(record,2,pub?1:type);put(record,6,offset);put(record,10,1,2);}
    text(record,nameAt,name);while((record.size()+2)%4)record.push_back(0);const auto at=out.size();put(out,at,record.size(),2);out.insert(out.end(),record.begin(),record.end());
}
struct Fixture {
    std::vector<std::vector<u8>> streams;
    u64 optional=0;
    Fixture(){streams.resize(9);auto& identity=streams[1];identity.resize(28);put(identity,8,7);for(unsigned n=0;n<16;++n)identity[12+n]=n+1;
        auto& symbols=streams[4];symbol(symbols,0x110e,0,"mapped_function");symbol(symbols,0x1110,0,"mapped_function",0x40);symbol(symbols,0x110e,0x20,"removed_function");symbol(symbols,0x110d,0x50,"mapped_global",0,0x75);symbol(symbols,0x110d,0x60,"split_global",0,0x77);
        streams[5]=forward();streams[6]=sections();streams[8]=table({{0x1000,0x5000},{0x1010,0},{0x1020,0x5030},{0x1030,0},{0x1040,0x5010},{0x1050,0}});
        const auto c13=lines();auto& module=streams[7];put(module,0,4);module.insert(module.end(),c13.begin(),c13.end());
        std::vector<u8> modInfo(64,0);put(modInfo,34,7,2);put(modInfo,36,4);put(modInfo,44,c13.size());text(modInfo,64,"fixture");text(modInfo,72,"fixture.obj");while(modInfo.size()%4)modInfo.push_back(0);
        auto& dbi=streams[3];dbi.resize(64);put(dbi,0,0xffffffff);put(dbi,8,7);put(dbi,20,4,2);put(dbi,24,modInfo.size());put(dbi,48,22);put(dbi,58,0x8664,2);dbi.insert(dbi.end(),modInfo.begin(),modInfo.end());optional=dbi.size();dbi.resize(optional+22,0xff);put(dbi,optional+6,8,2);put(dbi,optional+8,5,2);put(dbi,optional+20,6,2);
    }
    std::vector<u8> msf()const{
        const unsigned blockSize=512;std::vector<u8> directory(4+streams.size()*4,0);put(directory,0,streams.size());u32 block=3;
        for(size_t n=0;n<streams.size();++n){put(directory,4+n*4,streams[n].size());for(size_t offset=0;offset<streams[n].size();offset+=blockSize){put(directory,directory.size(),block++);}}
        require(directory.size()<=blockSize,"fixture directory fits one block");std::vector<u8> out(u64(block)*blockSize,0);
        static constexpr char magic[]="Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";std::memcpy(out.data(),magic,32);put(out,32,blockSize);put(out,40,block);put(out,44,directory.size());put(out,52,1);put(out,512,2);std::copy(directory.begin(),directory.end(),out.begin()+1024);
        block=3;for(const auto& stream:streams)for(size_t offset=0;offset<stream.size();offset+=blockSize){const auto length=std::min<size_t>(blockSize,stream.size()-offset);std::copy_n(stream.begin()+offset,length,out.begin()+u64(block++)*blockSize);}return out;
    }
};
void helper(){
    PdbOmap map;const auto f=forward(),s=sections();require(map.load(view(f),view(s)).ok(),"forward map and original headers accepted");u32 source=0;require(map.source(1,0x30,16,&source).ok()&&source==0x5030,"original section coordinates");
    std::vector<PdbOmapRange> ranges;require(map.translate(0x5000,0x80,&ranges).ok()&&ranges.size()==6,"split/reordered/deleted mapping ranges");
    for(u32 delta=0;delta<0x80;++delta){u32 expected=delta<0x10?0x1000+delta:delta<0x20?0x1040+delta-0x10:delta<0x30?0:delta<0x40?0x1020+delta-0x30:delta<0x50?0:delta<0x60?0x2000+delta-0x50:delta<0x64?0x2010+delta-0x60:delta<0x68?0x2020+delta-0x64:0;
        std::vector<PdbOmapRange> point;require(map.translate(0x5000+delta,1,&point).ok()&&(expected?(point.size()==1&&point[0].target==expected):point.empty()),"dense affine reference including deleted blocks");}
    for(const auto invalid:{std::vector<u8>{},table({{1,2},{1,3}}),table({{2,2},{1,3}}),std::vector<u8>(7),std::vector<u8>(262145*8)})require(!map.load(view(invalid),view(s)).ok()&&map.active(),"malformed mapping load preserves old map");
    auto damaged=s;put(damaged,12,0xffffff00);require(!map.load(view(f),view(damaged)).ok(),"original section overflow rejected");
    PdbOmap overflow;const auto overflowing=table({{0x5000,0xfffffffe}});require(overflow.load(view(overflowing),view(s)).ok(),"last affine anchor validated at query extent");
    std::vector<PdbOmapRange> unchanged={{1,2,3}};require(!overflow.translate(0x5000,4,&unchanged).ok()&&unchanged[0].source==1,"mapped RVA wrap rejected transactionally");
    std::vector<PdbOmapRange> before;require(map.translate(0x4000,1,&before).ok()&&before.empty(),"prefix without source map has no invented identity");
}
void integration(){
    const auto raw=pe();ElfImage image;require(image.load(view(raw)).ok()&&image.peCodeViewRecords().size()==1,"bound PE fixture loads exact RSDS identity");Fixture fixture;const auto pdb=fixture.msf();DwarfReport report;
    auto status=readPdb(image,view(pdb),&report);if(!status.ok())std::cerr<<status.toString()<<'\n';require(status.ok(),"OMAP-bearing PDB imports");const Address base=image.imageBase();
    require(report.functions.size()==1&&report.functions[0].entry==base+0x1000,"removed function is omitted; duplicate public/procedure merged");const auto& ranges=report.functions[0].ranges;
    require(ranges.size()==3&&ranges[0].low==base+0x1000&&ranges[0].high==base+0x1010&&ranges[1].low==base+0x1040&&ranges[1].high==base+0x1050&&ranges[2].low==base+0x1020&&ranges[2].high==base+0x1030,"original function size splits across reordered/deleted blocks");
    require(report.variables.size()==2&&report.variables[0].location.address==base+0x2000&&report.variables[0].type=="u32"&&report.variables[1].location.address==base+0x2010&&report.variables[1].type.empty(),"data mappings preserve contiguous types and reject split-object layouts");
    auto coverage=[&](Address at){for(size_t n=0;n+1<report.sources.size();++n)if(!report.sources[n].endSequence&&report.sources[n].address<=at&&at<report.sources[n+1].address)return report.sources[n].line;return u32{0};};
    require(coverage(base+0x1004)==10&&coverage(base+0x100c)==11&&coverage(base+0x1045)==12&&coverage(base+0x1025)==14,"C13 source rows follow exact OMAP block translations");
    require(!coverage(base+0x1015)&&!coverage(base+0x1035)&&!coverage(base+0x1050),"inserted/gap bytes have no fabricated source coverage");
    auto rejects=[&](const Fixture& damaged){auto bytes=damaged.msf();DwarfReport untouched;untouched.units=99;require(!readPdb(image,view(bytes),&untouched).ok()&&untouched.units==99,"bad remapping metadata import is atomic");};
    {auto damaged=fixture;damaged.streams[5].pop_back();rejects(damaged);}
    {auto damaged=fixture;put(damaged.streams[5],12,0x5000);rejects(damaged);}
    {auto damaged=fixture;put(damaged.streams[5],4,0xfffffff8);rejects(damaged);}
    {auto damaged=fixture;put(damaged.streams[5],4,0x9000);rejects(damaged);}
    {auto damaged=fixture;put(damaged.streams[5],4,0x2000);rejects(damaged);}
    {auto damaged=fixture;put(damaged.streams[6],36,0x40000040);rejects(damaged);}
    {auto damaged=fixture;put(damaged.streams[4],12,2,2);rejects(damaged);}
    {auto damaged=fixture;put(damaged.streams[3],damaged.optional+20,0xffff,2);rejects(damaged);}
    {auto damaged=fixture;put(damaged.streams[3],damaged.optional+8,0xffff,2);rejects(damaged);}
    {auto damaged=fixture;put(damaged.streams[8],8,0x1000);rejects(damaged);}
    for(bool age:{false,true}){auto damaged=fixture;if(age)put(damaged.streams[1],8,8);else damaged.streams[1][12]^=1;auto bytes=damaged.msf();DwarfReport untouched;untouched.units=99;
        require(!readPdb(image,view(bytes),&untouched,true).ok()&&untouched.units==99,"OMAP never bypasses RSDS GUID/age binding even with unverified acknowledgement");}
    std::string directory="/private/tmp/mint-omap-XXXXXX";require(mkdtemp(directory.data())!=nullptr,"owned OMAP test directory");
    const auto binary=directory+"/bound.exe",debug=directory+"/bound.pdb",project=directory+"/program";
    {std::ofstream out(binary,std::ios::binary);out.write(reinterpret_cast<const char*>(raw.data()),raw.size());require(out.good(),"write bound PE");}
    {std::ofstream out(debug,std::ios::binary);out.write(reinterpret_cast<const char*>(pdb.data()),pdb.size());require(out.good(),"write bound PDB");}
    Session session;require(session.openPath(binary).ok()&&session.attachProject(project).ok()&&session.analyze().ok()&&session.importExternalDebug(debug).ok(),"Session imports remapped symbols and source rows");
    const auto source=session.sourceLocationText(base+0x1045);require(source=="omap.c:12"&&session.sourceLocationText(base+0x1015).empty(),"Session source mapping honors OMAP gaps");
    Session reopened;require(reopened.openPath(binary).ok()&&reopened.attachProject(project).ok()&&reopened.sourceLocationText(base+0x1045)==source,"remapping survives exact persistent reopen");
    unlink((project+".debug."+session.externalDebugDigest()+".bin").c_str());unlink((project+".debug").c_str());unlink((project+".analysis").c_str());unlink(project.c_str());unlink(binary.c_str());unlink(debug.c_str());rmdir(directory.c_str());
}
}
int main(){helper();integration();std::cout<<checks<<" OMAP checks passed\n";}
