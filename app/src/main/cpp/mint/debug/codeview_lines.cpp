#include "mint/debug/codeview_lines.h"
#include "mint/loader/elf_image.h"
#include <map>

namespace mint {
namespace {
Status bad(const char* message){return Status::error(ErrorCode::kBadFormat,std::string("CodeView C13: ")+message);}
}
Status readCodeViewLines(const ElfImage& image,ByteView bytes,ByteView globalStrings,std::vector<DwarfSourceRow>* output,const std::vector<CodeViewSourceSection>* originalSections) {
    if(!output || bytes.size()>32*1024*1024 || globalStrings.size()>32*1024*1024 || (originalSections&&originalSections->size()>4096))return bad("invalid output or oversized source data");
    ByteView strings=globalStrings,checksums;bool localStrings=false,haveChecksums=false;
    std::vector<ByteView> fragments;
    // Collect first: producers need not put string/checksum tables before lines.
    for(u64 cursor=0;cursor<bytes.size();) {
        u32 kind=0,length=0;
        if(!bytes.read(cursor,&kind)||!bytes.read(cursor+4,&length)||!bytes.covers(cursor+8,length))return bad("truncated subsection");
        const auto payload=bytes.subview(cursor+8,length);
        if(!(kind&0x80000000u)) {
            if(kind==0xf2){if(fragments.size()>=100000)return bad("too many line fragments");fragments.push_back(payload);}
            else if(kind==0xf3){if(localStrings)return bad("duplicate string table");localStrings=true;strings=payload;}
            else if(kind==0xf4){if(haveChecksums)return bad("duplicate checksum table");haveChecksums=true;checksums=payload;}
        }
        const u64 next=cursor+8+((u64(length)+3)&~u64{3});
        if(next>bytes.size())return bad("truncated subsection padding");cursor=next;
    }
    if(fragments.empty()){output->clear();return Status::success();}
    if(!haveChecksums || strings.empty() || strings.data()[0]!=0)return bad("source tables absent");
    std::map<u32,std::string> files;
    u64 fileTextBytes=0;
    for(u64 cursor=0;cursor<checksums.size();) {
        u32 name=0;u8 length=0,kind=0;
        if(!checksums.read(cursor,&name)||!checksums.read(cursor+4,&length)||!checksums.read(cursor+5,&kind)||!checksums.covers(cursor+6,length))return bad("truncated checksum entry");
        if((kind==0&&length!=0)||(kind==1&&length!=16)||(kind==2&&length!=20)||(kind==3&&length!=32))return bad("invalid checksum extent");
        std::string file;
        if(!strings.cString(name,&file,4096)||file.empty()||!strings.covers(u64(name)+file.size(),1)||strings.data()[name+file.size()]!=0)return bad("invalid source filename");
        fileTextBytes+=file.size();if(fileTextBytes>8*1024*1024)return bad("filename table budget exceeded");
        files.emplace(static_cast<u32>(cursor),std::move(file));
        const auto next=(cursor+6+length+3)&~u64{3};if(next>checksums.size())return bad("truncated checksum padding");cursor=next;
        if(files.size()>100000)return bad("too many source files");
    }
    std::vector<DwarfSourceRow> rows;u64 textBytes=0;
    for(const auto fragment:fragments) {
        u32 offset=0,size=0;u16 section=0,flags=0;
        if(!fragment.read(0,&offset)||!fragment.read(4,&section)||!fragment.read(6,&flags)||!fragment.read(8,&size)||
           !section||section>(originalSections?originalSections->size():image.sections().size())||!size||(flags&~1u))return bad("invalid line contribution header");
        const Address address=originalSections?(*originalSections)[section-1].address:image.sections()[section-1].addr;
        const u64 extent=originalSections?(*originalSections)[section-1].size:image.sections()[section-1].size;
        if(offset>extent || size>extent-offset || address>~Address{0}-offset || address+offset>~Address{0}-size)return bad("line contribution outside section");
        const Address start=address+offset,end=start+size;
        if(originalSections?!(*originalSections)[section-1].executable:(!image.memory().isExecutable(start)||!image.memory().isExecutable(end-1)))return bad("source contribution is not executable");
        for(u64 cursor=12;cursor<fragment.size();) {
            u32 file=0,count=0,blockSize=0;
            if(!fragment.read(cursor,&file)||!fragment.read(cursor+4,&count)||!fragment.read(cursor+8,&blockSize)||
               blockSize<12 || !fragment.covers(cursor,blockSize) || u64(count)*(flags&1?12:8)>blockSize-12 || count>100000-rows.size())return bad("invalid line block extent");
            const auto filename=files.find(file);if(filename==files.end())return bad("line block references no checksum entry");
            u32 previous=0;
            for(u32 n=0;n<count;++n) {
                u32 code=0,lineFlags=0;u16 column=0,columnEnd=0;
                fragment.read(cursor+12+u64(n)*8,&code);fragment.read(cursor+16+u64(n)*8,&lineFlags);
                if(code>=size || (n&&code<previous))return bad("line offsets outside or out of order");previous=code;
                if(flags&1){fragment.read(cursor+12+u64(count)*8+u64(n)*4,&column);fragment.read(cursor+14+u64(count)*8+u64(n)*4,&columnEnd);
                    if(columnEnd && columnEnd<column)return bad("reversed source columns");}
                const u32 line=lineFlags&0xffffff;
                // Special CodeView step-control markers do not denote source lines.
                if(!line || line==0xfeefee || line==0xf00f00)continue;
                textBytes+=filename->second.size();if(textBytes>8*1024*1024)return bad("source text budget exceeded");
                rows.push_back({start+code,filename->second,line,column,false});
            }
            if(count){if(rows.size()>=100000)return bad("source row budget exceeded");rows.push_back({end,{},0,0,true});}
            cursor+=blockSize;
        }
    }
    *output=std::move(rows);return Status::success();
}
}
