#include "mint/debug/codeview_lines.h"
#include "mint/loader/elf_image.h"
#include <iostream>
using namespace mint;
namespace {
unsigned checks=0,failures=0;
void expect(bool value,const char* text){++checks;if(!value){++failures;std::cerr<<"FAIL "<<text<<'\n';}}
void put(std::vector<u8>& bytes,u64 offset,u64 value,unsigned width=4){if(bytes.size()<offset+width)bytes.resize(offset+width);for(unsigned n=0;n<width;++n)bytes[offset+n]=u8(value>>(n*8));}
void section(std::vector<u8>& bytes,u32 kind,const std::vector<u8>& payload){auto start=bytes.size();put(bytes,start,kind);put(bytes,start+4,payload.size());bytes.insert(bytes.end(),payload.begin(),payload.end());while(bytes.size()%4)bytes.push_back(0);}
ByteView view(const std::vector<u8>& bytes){return ByteView(bytes.data(),bytes.size());}
}
int main(){
    std::vector<u8> machine(256,0);ElfImage image;expect(image.loadRaw(view(machine),Arch::kAArch64,0x1000,0x1000).ok(),"mapped source fixture");
    std::vector<u8> strings={0,'f','.','c',0},checksum(8,0),lines(48,0),bytes;
    put(checksum,0,1); // no content hash: valid informational filename.
    put(lines,0,16);put(lines,4,1,2);put(lines,6,1,2);put(lines,8,32);
    put(lines,12,0);put(lines,16,2);put(lines,20,36);
    put(lines,24,0);put(lines,28,0x80000007);put(lines,32,8);put(lines,36,11);
    put(lines,40,2,2);put(lines,42,5,2);put(lines,44,1,2);put(lines,46,9,2);
    section(bytes,0xf2,lines);section(bytes,0xf4,checksum);const auto globalBytes=bytes;
    section(bytes,0xf3,strings);std::vector<DwarfSourceRow> rows;
    expect(readCodeViewLines(image,view(bytes),{},&rows).ok(),"out-of-order local C13 tables");
    expect(rows.size()==3&&rows[0].address==0x1010&&rows[0].file=="f.c"&&rows[0].line==7&&rows[0].column==2&&
        rows[1].address==0x1018&&rows[1].line==11&&rows[2].address==0x1030&&rows[2].endSequence,"exact source lines/columns and terminating contribution boundary");
    expect(readCodeViewLines(image,view(globalBytes),view(strings),&rows).ok()&&rows.size()==3,"global PDB string table fallback");
    auto rejects=[&](const std::vector<u8>& damaged){std::vector<DwarfSourceRow> previous={{0xbeef,"keep",99,0,false}};
        expect(!readCodeViewLines(image,view(damaged),{},&previous).ok()&&previous.size()==1&&previous[0].address==0xbeef,"malformed source import is atomic");};
    for(size_t size=1;size<bytes.size();++size)rejects(std::vector<u8>(bytes.begin(),bytes.begin()+size));
    for(auto mutation:std::vector<std::pair<u64,u32>>{{4,0xffffffff},{8+4,9},{8+8,0xffffffff},{8+12,4},{8+16,0xffffffff},
        {8+20,11},{8+24,32},{8+32,0xffffffff},{8+40,0x00010007}}){auto damaged=bytes;put(damaged,mutation.first,mutation.second);rejects(damaged);}
    auto unordered=bytes;put(unordered,8+24,8);put(unordered,8+32,4);rejects(unordered);
    auto duplicate=bytes;section(duplicate,0xf4,checksum);rejects(duplicate);
    auto ignored=bytes;put(ignored,0,0x800000f2);expect(readCodeViewLines(image,view(ignored),{},&rows).ok()&&rows.empty(),"ignored subsections never invent source rows");
    expect(readCodeViewLines(image,{}, {},&rows).ok()&&rows.empty(),"empty line stream is valid");
    std::cout<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;
}
