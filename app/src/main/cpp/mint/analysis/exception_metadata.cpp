#include "mint/analysis/exception_metadata.h"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <sstream>

namespace mint {
namespace {
void groupLandingPads(ExceptionFunction* function) {
    function->landingPads.clear(); std::map<Address, size_t> indices;
    for (size_t rowIndex = 0; rowIndex < function->callSites.size(); ++rowIndex) {
        const auto& row = function->callSites[rowIndex];
        if (row.landingPad == kNoAddress) continue;
        auto found = indices.find(row.landingPad);
        if (found == indices.end()) {
            found = indices.emplace(row.landingPad, function->landingPads.size()).first;
            ExceptionLandingPad pad; pad.address = row.landingPad; function->landingPads.push_back(std::move(pad));
        }
        ExceptionLandingPad::ProtectedRegion region; region.start = row.start; region.end = row.end;
        region.actionOffset = row.actionOffset; region.callSiteIndex = rowIndex;
        region.cleanup = row.actionOffset == 0;
        for (const auto& action : row.actions) {
            region.cleanup = region.cleanup || action.filter == 0;
            region.catchAll = region.catchAll || action.catchAll;
            region.exceptionSpecification = region.exceptionSpecification || action.filter < 0;
        }
        function->landingPads[found->second].regions.push_back(std::move(region));
    }
    std::sort(function->landingPads.begin(), function->landingPads.end(), [](const auto& a, const auto& b) { return a.address < b.address; });
}
}
namespace {
constexpr size_t kMaxBytes = 1024 * 1024, kMaxActions = 65536;
bool add(Address base, u64 offset, Address* result) {
    if (offset > std::numeric_limits<Address>::max() - base) return false;
    *result = base + offset; return true;
}
bool addSigned(Address base, i64 offset, Address* result) {
    if (offset >= 0) return add(base, static_cast<u64>(offset), result);
    const u64 magnitude = static_cast<u64>(-(offset + 1)) + 1;
    if (magnitude > base) return false;
    *result = base - magnitude; return true;
}
Status bad(const char* message) { return Status::error(ErrorCode::kBadFormat, std::string("LSDA: ") + message); }
struct Reader {
    ByteView bytes;
    Address address;
    const MemoryMap& memory;
    size_t pointerWidth, cursor = 0;
    template<typename T> bool fixed(T* result) {
        if (!bytes.read(cursor,result)) return false; cursor += sizeof(T); return true;
    }
    bool leb(bool signedValue, u64* result) {
        u64 bits = 0;
        for (unsigned i = 0; i < 10; ++i) {
            u8 byte = 0; if (!fixed(&byte)) return false;
            const u8 part = byte & 0x7f;
            if (i == 9 && (signedValue ? part != 0 && part != 0x7f : part > 1)) return false;
            bits |= u64(part) << (i*7);
            if (!(byte & 0x80)) {
                const unsigned used = (i+1)*7;
                if (signedValue && used < 64 && (byte & 0x40)) bits |= ~u64(0) << used;
                *result = bits; return true;
            }
        } return false;
    }
    bool encoded(u8 encoding, bool integer, Address* result, bool* isNull = nullptr, Address* indirectSlot = nullptr) {
        if (encoding == 0xff || (integer && (encoding & 0xf0)) ||
            ((encoding & 0x70) != 0 && (encoding & 0x70) != 0x10)) return false;
        Address field = 0; if (!add(address,cursor,&field)) return false;
        u64 raw = 0; bool signedValue = false;
        switch (encoding & 15) {
            case 0: if (pointerWidth == 8) { if (!fixed(&raw)) return false; }
                else { u32 value=0; if (!fixed(&value)) return false; raw=value; } break;
            case 1: if (!leb(false,&raw)) return false; break;
            case 2: { u16 value=0;if(!fixed(&value))return false;raw=value;break; }
            case 3: { u32 value=0;if(!fixed(&value))return false;raw=value;break; }
            case 4: if(!fixed(&raw))return false;break;
            case 9: signedValue=true;if(!leb(true,&raw))return false;break;
            case 10: { i16 value=0;if(!fixed(&value))return false;raw=static_cast<u64>(value);signedValue=true;break; }
            case 11: { i32 value=0;if(!fixed(&value))return false;raw=static_cast<u64>(value);signedValue=true;break; }
            case 12: signedValue=true;if(!fixed(&raw))return false;break;
            default:return false;
        }
        if (isNull) *isNull = !raw;
        if (!integer && !raw) { *result=0; return true; }
        Address value = raw;
        if (encoding & 0x70) {
            if (signedValue ? !addSigned(field,static_cast<i64>(raw),&value) : !add(field,raw,&value)) return false;
        } else if (signedValue && static_cast<i64>(raw) < 0) return false;
        if (encoding & 0x80) {
            if (indirectSlot) *indirectSlot = value;
            const auto slot = memory.viewAt(value,pointerWidth);
            if (pointerWidth == 8) { if (!slot.read(0,&value)) return false; }
            else { u32 small=0;if(!slot.read(0,&small))return false;value=small; }
        }
        *result = value; return true;
    }
};
size_t typeWidth(u8 encoding, size_t pointerWidth) {
    switch (encoding & 15) { case 0:return pointerWidth;case 2:case 10:return 2;case 3:case 11:return 4;case 4:case 12:return 8;default:return 0; }
}
bool codeRange(const MemoryMap& memory, Address start, Address end) {
    const auto* segment=memory.segmentAt(start);
    return end>start && segment && segment->executable() && end<=segment->end() && memory.viewAt(start,end-start).size()==end-start;
}
} // namespace

Status parseExceptionLsda(ByteView bytes, Address address, const MemoryMap& memory,
                          size_t pointerWidth, const UnwindFrame& frame,
                          size_t maxCallSites, ExceptionFunction* out) {
    if (!out) return bad("missing output"); *out={};
    if ((pointerWidth!=4 && pointerWidth!=8) || bytes.size()>kMaxBytes || maxCallSites>16384 || !codeRange(memory,frame.entry,frame.end)) return bad("pointer width/range/inventory budget");
    ExceptionFunction parsed; parsed.frame=frame;
    Reader reader{bytes,address,memory,pointerWidth};
    u8 lpEncoding=0,typeEncoding=0,callEncoding=0; Address lpStart=frame.entry;u64 typeOffset=0;
    if (!reader.fixed(&lpEncoding) || (lpEncoding!=0xff && !reader.encoded(lpEncoding,false,&lpStart)) || !reader.fixed(&typeEncoding)) return bad("truncated or unsupported landing-pad/type header");
    size_t typeBase=bytes.size();
    if (typeEncoding!=0xff) {
        if (!reader.leb(false,&typeOffset) || typeOffset>bytes.size()-reader.cursor) return bad("type table offset outside LSDA");
        typeBase=reader.cursor+static_cast<size_t>(typeOffset);
    }
    u64 tableBytes=0;
    if (!reader.fixed(&callEncoding) || !reader.leb(false,&tableBytes) || tableBytes>bytes.size()-reader.cursor) return bad("truncated call-site table length");
    const size_t tableEnd=reader.cursor+static_cast<size_t>(tableBytes),actionStart=tableEnd;
    if (typeEncoding!=0xff && typeBase<tableEnd) return bad("type table overlaps call-site table");
    reader.bytes=bytes.subview(0,tableEnd);
    Address previousEnd=frame.entry;
    while(reader.cursor<tableEnd) {
        if(parsed.callSites.size()>=maxCallSites) return bad("call-site budget exceeded");
        Address start=0,length=0,landing=0;u64 action=0;
        if(!reader.encoded(callEncoding,true,&start)||!reader.encoded(callEncoding,true,&length)||!reader.encoded(callEncoding,true,&landing)||!reader.leb(false,&action))return bad("truncated or unsupported call-site row");
        ExceptionCallSite row;row.actionOffset=action;
        if(!add(frame.entry,start,&row.start)||!add(row.start,length,&row.end)||row.start<previousEnd||row.end>frame.end||(!length && row.start>frame.end))return bad("unsorted/overlapping/out-of-function call-site range");
        previousEnd=row.end;
        if(landing && (!add(lpStart,landing,&row.landingPad)||!memory.isExecutable(row.landingPad)||memory.viewAt(row.landingPad,1).empty()))return bad("invalid landing-pad address");
        parsed.callSites.push_back(std::move(row));
    }
    size_t actionCount=0,lowestType=typeBase;
    std::vector<std::pair<size_t,size_t>> actionRanges;
    bool unsupportedType=false,negativeFilter=false;
    for(auto& row:parsed.callSites) {
        if(!row.actionOffset) continue;
        if(row.actionOffset-1>bytes.size()-actionStart)return bad("action offset outside LSDA");
        size_t position=actionStart+static_cast<size_t>(row.actionOffset-1);
        std::set<size_t> visited;
        for(;;) {
            if(++actionCount>kMaxActions || !visited.insert(position).second || position<actionStart || position>=typeBase)return bad("cyclic/out-of-bounds/excessive action chain");
            Reader actionReader{bytes.subview(0,typeBase),address,memory,pointerWidth,position};
            u64 filter=0,next=0;
            if(!actionReader.leb(true,&filter))return bad("truncated action filter");
            const size_t nextField=actionReader.cursor;
            if(!actionReader.leb(true,&next))return bad("truncated action displacement");
            actionRanges.push_back({position,actionReader.cursor});
            ExceptionAction action; if(!add(address,position,&action.record))return bad("action address overflow");action.filter=static_cast<i64>(filter);
            if(action.filter>0) {
                const size_t width=typeEncoding==0xff?0:typeWidth(typeEncoding,pointerWidth);
                if(!width || ((typeEncoding & 0x70)!=0 && (typeEncoding & 0x70)!=0x10)) unsupportedType=true;
                else {
                    const u64 index=static_cast<u64>(action.filter);
                    if(index>typeBase/width)return bad("type index outside LSDA");
                    const size_t typeAt=typeBase-static_cast<size_t>(index)*width;
                    if(typeAt<actionStart)return bad("type table overlaps call-site table");
                    lowestType=std::min(lowestType,typeAt);
                    Reader typeReader{bytes,address,memory,pointerWidth,typeAt}; bool isNull=false;Address type=0;
                    if(!typeReader.encoded(typeEncoding,false,&type,&isNull,&action.indirectSlot))return bad("invalid/unsupported encoded type pointer");
                    action.catchAll=isNull;action.typeResolved=isNull||(type&&memory.isMapped(type));
                    action.typeInfo=action.typeResolved?type:kNoAddress;
                }
            }else if(action.filter<0)negativeFilter=true;
            row.actions.push_back(std::move(action));
            if(static_cast<i64>(next)==0)break;
            Address nextPosition=0;
            if(!addSigned(nextField,static_cast<i64>(next),&nextPosition)||nextPosition>std::numeric_limits<size_t>::max())return bad("action displacement overflow");
            position=static_cast<size_t>(nextPosition);
        }
    }
    for(const auto& range:actionRanges)if(range.second>lowestType)return bad("action records overlap indexed type table");
    if(unsupportedType)parsed.notes.push_back("Type table uses an omitted/variable-width/unsupported-base encoding; positive catch filters are inventoried without inferred types.");
    if(negativeFilter)parsed.notes.push_back("Negative action filters identify legacy exception specifications; their lists and runtime matching are not decoded.");
    groupLandingPads(&parsed); *out=std::move(parsed);return Status::success();
}

ExceptionMetadataReport inspectExceptionMetadata(const ElfImage& image,size_t limit) {
    ExceptionMetadataReport report;
    const auto* section=image.findSection(".gcc_except_table");if(!section)section=image.findSection("__gcc_except_tab");
    if(!section)section=image.findSection("__TEXT,__gcc_except_tab");
    if(!section)return report;
    const ByteView sectionBytes=image.memory().viewAt(section->addr,section->data.size());
    if(sectionBytes.size()!=section->data.size()){report.notes.push_back("Exception section is not fully file-backed in one mapped segment; excluded.");return report;}
    limit=std::min<size_t>(limit,20000);
    auto frames=collectUnwindFrames(image,200000,&report.notes);
    std::set<std::pair<Address,Address>> frameIds;
    for(const auto& frame:frames)frameIds.emplace(frame.entry,frame.lsda);
    for(const auto& runtime:image.runtimeFunctions())if(runtime.lsda!=kNoAddress && runtime.lsda && frameIds.emplace(runtime.start,runtime.lsda).second) {
        UnwindFrame frame;frame.entry=runtime.start;frame.end=runtime.end;frame.fde=runtime.unwindInfo;frame.lsda=runtime.lsda;frames.push_back(frame);
    }
    std::set<Address> starts;
    for(const auto& frame:frames)if(frame.lsda>=section->addr && frame.lsda-section->addr<section->data.size())starts.insert(frame.lsda);
    std::map<Address,std::string> symbols;
    for(const auto& symbol:image.symbols())if(!symbol.undefined && symbol.name.compare(0,4,"_ZTI")==0)symbols[symbol.value]=symbol.name;
    std::map<Address,std::string> relocations;
    for(const auto& relocation:image.relocations())if(relocation.symbolName.compare(0,4,"_ZTI")==0)relocations[relocation.offset]=relocation.symbolName;
    size_t scannedBytes=0,totalRows=0,totalActions=0;
    for(const auto& frame:frames) {
        if(!frame.lsda)continue;
        if(frame.lsda<section->addr || frame.lsda-section->addr>=section->data.size()) { if(report.notes.size()<128)report.notes.push_back("FDE LSDA does not point into the mapped exception section; excluded.");continue; }
        if(report.functions.size()>=limit){report.truncated=true;break;}
        const size_t offset=static_cast<size_t>(frame.lsda-section->addr);
        size_t length=section->data.size()-offset;
        const auto next=starts.upper_bound(frame.lsda);if(next!=starts.end())length=std::min<u64>(length,*next-frame.lsda);
        if(length>kMaxBytes){if(report.notes.size()<128)report.notes.push_back("LSDA byte budget exceeded; excluded.");continue;}
        if(length>16*1024*1024-scannedBytes){report.truncated=true;break;}scannedBytes+=length;
        ExceptionFunction function;
        const Status status=parseExceptionLsda(sectionBytes.subview(offset,length),frame.lsda,image.memory(),image.pointerSize(),frame,16384,&function);
        if(!status.ok()){if(report.notes.size()<128)report.notes.push_back(status.message());continue;}
        size_t actions=0;for(const auto& row:function.callSites)actions+=row.actions.size();
        if(function.callSites.size()>65536-totalRows || actions>262144-totalActions){report.truncated=true;break;}
        totalRows+=function.callSites.size();totalActions+=actions;
        for(auto& row:function.callSites)for(auto& action:row.actions) {
            const auto direct=symbols.find(action.typeInfo);if(direct!=symbols.end())action.typeSymbol=direct->second;
            const auto indirect=relocations.find(action.indirectSlot);if(action.typeSymbol.empty() && indirect!=relocations.end())action.typeSymbol=indirect->second;
        }
        groupLandingPads(&function); report.functions.push_back(std::move(function));
    }
    report.notes.push_back("Evidence: validated CIE/FDE zL pointer, LSDA call-site rows and bounded action/type tables. Landing pads are metadata targets, not inferred CFG edges or reconstructed try/catch.");
    return report;
}
std::string exceptionMetadataText(const ExceptionMetadataReport& report) {
    std::ostringstream out;out<<"Exception metadata (LLVM/GNU Itanium LSDA inventory)\n";
    for(const auto& function:report.functions) {
        out<<"Function 0x"<<std::hex<<function.frame.entry<<"..0x"<<function.frame.end<<" FDE=0x"<<function.frame.fde<<" LSDA=0x"<<function.frame.lsda<<std::dec<<'\n';
        for(const auto& row:function.callSites) {
            out<<"  call-site 0x"<<std::hex<<row.start<<"..0x"<<row.end;
            if(row.landingPad!=kNoAddress)out<<" landing-pad=0x"<<row.landingPad;else out<<" no landing pad";
            out<<std::dec<<" action="<<row.actionOffset<<'\n';
            for(const auto& action:row.actions) {
                out<<"    filter="<<action.filter;
                if(!action.filter)out<<" cleanup";else if(action.filter<0)out<<" exception specification [not decoded]";else if(action.catchAll)out<<" catch(...)";else {
                    if(action.typeResolved)out<<" typeinfo=0x"<<std::hex<<action.typeInfo<<std::dec;
                    else out<<" typeinfo unresolved";
                    if(!action.typeSymbol.empty())out<<" "<<action.typeSymbol;
                }out<<'\n';
            }
        }
        for(const auto& note:function.notes)out<<"  note: "<<note<<'\n';
        for(const auto& pad:function.landingPads) {
            out<<"  dispatch landing-pad 0x"<<std::hex<<pad.address<<std::dec<<" protects "<<pad.regions.size()<<" region(s)\n";
            for(const auto& region:pad.regions)out<<"    protected 0x"<<std::hex<<region.start<<"..0x"<<region.end<<std::dec
                <<" ordered-actions="<<function.callSites[region.callSiteIndex].actions.size()<<(region.cleanup?" cleanup":"")<<(region.catchAll?" catch-all":"")
                <<(region.exceptionSpecification?" legacy-specification":"")<<'\n';
        }
    }
    if(report.functions.empty())out<<"No validated supported LSDA found; absence does not prove that exceptions are absent.\n";
    if(report.truncated)out<<"Function inventory budget reached; report is partial.\n";
    for(const auto& note:report.notes)out<<note<<'\n';return out.str();
}
std::string exceptionMetadataText(const ElfImage& image,size_t limit){return exceptionMetadataText(inspectExceptionMetadata(image,limit));}
} // namespace mint
