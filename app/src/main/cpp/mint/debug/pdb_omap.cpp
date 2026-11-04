#include "mint/debug/pdb_omap.h"
#include <algorithm>

namespace mint {
namespace {Status bad(const char* text){return Status::error(ErrorCode::kBadFormat,std::string("PDB OMAP: ")+text);}}
Status PdbOmap::validateTable(ByteView bytes) {
    if(bytes.empty() || bytes.size()%8 || bytes.size()/8>262144)return bad("invalid mapping table extent");
    u32 previous=0;
    for(u64 cursor=0;cursor<bytes.size();cursor+=8){u32 source=0;bytes.read(cursor,&source);
        if(cursor && source<=previous)return bad("mapping sources must be strictly increasing");previous=source;}
    return Status::success();
}
Status PdbOmap::load(ByteView bytes,ByteView headers) {
    auto status=validateTable(bytes);if(!status.ok())return status;
    if(headers.empty() || headers.size()%40 || headers.size()/40>4096)return bad("original COFF section headers required");
    std::vector<PdbOriginalSection> sections;std::vector<std::pair<u64,u64>> extents;
    for(u64 offset=0;offset<headers.size();offset+=40){u32 virtualSize=0,rva=0,rawSize=0,flags=0;
        headers.read(offset+8,&virtualSize);headers.read(offset+12,&rva);headers.read(offset+16,&rawSize);headers.read(offset+36,&flags);
        const u64 size=std::max(virtualSize,rawSize);
        if(size>(u64{1}<<32)-rva)return bad("original section RVA overflow");
        sections.push_back({rva,size,(flags&0x20000000u)!=0});if(size)extents.push_back({rva,u64(rva)+size});}
    std::sort(extents.begin(),extents.end());
    for(size_t n=1;n<extents.size();++n)if(extents[n].first<extents[n-1].second)return bad("overlapping original sections");
    std::vector<Entry> entries;
    for(u64 cursor=0;cursor<bytes.size();cursor+=8){u32 source=0,target=0;bytes.read(cursor,&source);bytes.read(cursor+4,&target);entries.push_back({source,target});}
    entries_=std::move(entries);sections_=std::move(sections);return Status::success();
}
Status PdbOmap::source(u16 section,u32 offset,u64 size,u32* rva) const {
    if(!rva || !section || section>sections_.size() || !size)return bad("invalid original section query");
    const auto& s=sections_[section-1];
    if(offset>=s.size || size>s.size-offset || u64(s.rva)+offset>0xffffffffull)return bad("source range outside original section");
    *rva=s.rva+offset;return Status::success();
}
Status PdbOmap::translate(u32 source,u64 size,std::vector<PdbOmapRange>* output) const {
    if(!output || !active() || !size || size>(u64{1}<<32)-source)return bad("invalid source RVA extent");
    std::vector<PdbOmapRange> ranges;u64 cursor=source,end=u64(source)+size;
    auto next=std::upper_bound(entries_.begin(),entries_.end(),source,[](u32 value,const Entry& entry){return value<entry.source;});
    if(next==entries_.begin())cursor=std::min<u64>(end,next->source);
    while(cursor<end){
        while(next!=entries_.end() && next->source<=cursor)++next;
        if(next==entries_.begin())return bad("mapping lookup did not advance");
        const auto& entry=*(next-1);const u64 stop=next==entries_.end()?end:std::min<u64>(end,next->source);
        if(entry.target){const u64 target=u64(entry.target)+cursor-entry.source;
            if(target>0xffffffffull || stop-cursor>(u64{1}<<32)-target)return bad("mapped RVA overflow");
            if(ranges.size()>=100000)return bad("mapped range budget exceeded");
            ranges.push_back({static_cast<u32>(cursor),static_cast<u32>(target),stop-cursor});}
        cursor=stop;
    }
    *output=std::move(ranges);return Status::success();
}
}
