#include "mint/analysis/cxx_msvc_metadata.h"
#include "mint/loader/elf_image.h"
#include <algorithm>
#include <map>
#include <set>

namespace mint {
namespace {
bool tableIdentity(const std::string& symbol,std::string* type) {
    if(symbol.size()>4096 || symbol.compare(0,4,"??_7"))return false;
    const auto end=symbol.find("@@6B",4);
    if(end==std::string::npos || end==4 || symbol.back()!='@')return false;
    *type=symbol.substr(4,end-4);return *type!="type_info";
}
std::string display(const std::string& name) {
    if(name.size()<7)return name;
    auto encoded=name.substr(4,name.size()-6);std::vector<std::string> parts;
    for(size_t at=0;at<encoded.size();) {
        const auto next=encoded.find('@',at);const auto part=encoded.substr(at,next==std::string::npos?std::string::npos:next-at);
        if(part.empty() || !std::all_of(part.begin(),part.end(),[](unsigned char c){return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_';}))return name;
        parts.push_back(part);if(next==std::string::npos)break;at=next+1;
    }
    std::string text;for(auto it=parts.rbegin();it!=parts.rend();++it){if(!text.empty())text+="::";text+=*it;}return text.empty()?name:text;
}
struct Node {Address type=0;std::string name;u32 contained=0,attributes=0;i32 member=0,vbptr=-1,vbtable=0;};
class Decoder {
public:
    explicit Decoder(const ElfImage& image):image_(image),width_(image.pointerSize()),relative_(width_==8){}
    bool data(Address at,u64 size,bool readonly=true) const {
        if(!size || at>~Address{0}-size || image_.memory().hasOverlaps())return false;
        const auto* segment=image_.memory().segmentAt(at);
        return segment && !segment->executable() && (!readonly||!segment->writable()) && image_.memory().viewAt(at,size).size()==size;
    }
    bool reference(Address at,Address* value) const {
        u32 pointer=0;if(!data(at,4) || !image_.memory().readInt(at,&pointer) || !pointer)return false;
        if(relative_){if(image_.imageBase()>~Address{0}-pointer)return false;*value=image_.imageBase()+pointer;}
        else *value=pointer;
        return data(*value,1,false);
    }
    bool typeName(Address descriptor,std::string* name) const {
        if(!data(descriptor,width_*2+7,false))return false;
        u64 vptr=0,spare=1;
        if(!image_.memory().readUnsigned(descriptor,width_,&vptr)||!image_.memory().readUnsigned(descriptor+width_,width_,&spare)||spare||!data(vptr,width_))return false;
        const auto bytes=image_.memory().viewAt(descriptor+width_*2,4097);
        if(!bytes.cString(0,name,4096)||!bytes.covers(0,name->size()+1)||bytes.data()[name->size()]!=0||name->size()<7||
            (name->compare(0,4,".?AV")&&name->compare(0,4,".?AU")) || name->compare(name->size()-2,2,"@@"))return false;
        return std::all_of(name->begin(),name->end(),[](unsigned char c){return c>=0x21&&c<=0x7e;});
    }
    bool header(Address hierarchy,u32* count,Address* array) const {
        u32 signature=1,attributes=0;
        return data(hierarchy,16)&&image_.memory().readInt(hierarchy,&signature)&&signature==0&&
            image_.memory().readInt(hierarchy+4,&attributes)&&!(attributes&~7u)&&image_.memory().readInt(hierarchy+8,count)&&*count&&*count<=128&&reference(hierarchy+12,array)&&data(*array,u64(*count)*4);
    }
    bool bases(Address hierarchy,Address type,std::vector<CxxBaseClass>* output) {
        u32 count=0;Address array=0;if(!header(hierarchy,&count,&array)||count>4096-totalBases_)return false;
        std::vector<Node> nodes;
        for(u32 n=0;n<count;++n){Address descriptor=0;if(!reference(array+n*4,&descriptor)||!data(descriptor,24))return false;
            Node node;if(!reference(descriptor,&node.type)||!typeName(node.type,&node.name)||!image_.memory().readInt(descriptor+4,&node.contained)||node.contained>=count-n||
                !image_.memory().readInt(descriptor+8,&node.member)||!image_.memory().readInt(descriptor+12,&node.vbptr)||!image_.memory().readInt(descriptor+16,&node.vbtable)||
                !image_.memory().readInt(descriptor+20,&node.attributes)||(node.attributes&~127u)||node.member< -0x40000000||node.member>0x40000000||node.vbptr< -1||node.vbptr>0x40000000||node.vbtable<0||node.vbtable%4||
                ((node.attributes&16)&&node.vbptr<0)||(node.vbptr==-1&&node.vbtable))return false;
            if(node.attributes&64){Address own=0,ownArray=0,first=0,ownType=0;u32 ownCount=0;
                if(!data(descriptor,28)||!reference(descriptor+24,&own)||(n==0&&own!=hierarchy)||!header(own,&ownCount,&ownArray)||ownCount!=node.contained+1||!reference(ownArray,&first)||!reference(first,&ownType)||ownType!=node.type)return false;
                u32 rootContained=0; i32 rootMember=0,rootVbptr=0,rootVbtable=0;
                if(!data(first,24)||!image_.memory().readInt(first+4,&rootContained)||rootContained!=ownCount-1||!image_.memory().readInt(first+8,&rootMember)||rootMember||
                    !image_.memory().readInt(first+12,&rootVbptr)||rootVbptr!=-1||!image_.memory().readInt(first+16,&rootVbtable)||rootVbtable)return false;}
            nodes.push_back(std::move(node));}
        if(nodes[0].type!=type||nodes[0].contained!=count-1||nodes[0].member||nodes[0].vbptr!=-1||nodes[0].vbtable)return false;
        std::vector<std::pair<u32,Address>> ancestors={{count,type}};
        for(u32 n=1;n<count;++n){while(!ancestors.empty()&&n==ancestors.back().first)ancestors.pop_back();
            if(ancestors.empty()||n+1+nodes[n].contained>ancestors.back().first)return false;
            for(const auto& ancestor:ancestors)if(ancestor.second==nodes[n].type)return false;
            if(nodes[n].contained)ancestors.push_back({n+1+nodes[n].contained,nodes[n].type});}
        std::vector<CxxBaseClass> direct;
        for(u32 n=1;n<count;n+=1+nodes[n].contained){const auto& node=nodes[n];CxxBaseClass base;base.typeInfo=node.type;base.name=display(node.name);base.offset=node.member;base.objectOffset=node.member;
            base.isVirtual=node.vbptr>=0;base.isPublic=!(node.attributes&13);base.usesPmd=true;base.vbptrOffset=node.vbptr;base.vbtableOffset=node.vbtable;base.ambiguous=(node.attributes&2)!=0;direct.push_back(std::move(base));}
        totalBases_+=count;*output=std::move(direct);return true;
    }
    CxxMetadataRecord table(const ElfSymbol& symbol,const std::string& encoded,Address* classHierarchy) {
        *classHierarchy=kNoAddress;
        CxxMetadataRecord record;record.kind=CxxMetadataKind::kVtable;record.address=symbol.value;record.symbol=symbol.name;record.display=symbol.name;record.defined=!symbol.undefined;record.abiClass="Microsoft RTTI";
        auto fail=[&](const char* note){record.notes.push_back(note);return record;};
        if(!record.defined)return fail("Imported vftable has no in-image metadata.");
        if(symbol.value<width_ || symbol.value%width_ || !data(symbol.value-width_,width_*2))return fail("Vftable locator/first slot is not unique read-only file-backed data.");
        u64 locator=0;if(!image_.memory().readUnsigned(symbol.value-width_,width_,&locator)||!data(locator,relative_?24:20))return fail("Complete object locator is not bounded read-only storage.");
        u32 signature=0,offset=0,construction=0;Address type=0,hierarchy=0;
        if(!image_.memory().readInt(locator,&signature)||signature!=(relative_?1u:0u)||!image_.memory().readInt(locator+4,&offset)||offset>0x40000000||!image_.memory().readInt(locator+8,&construction)||
            !reference(locator+12,&type)||!reference(locator+16,&hierarchy))return fail("Unsupported/truncated complete object locator.");
        if(relative_){Address self=0;if(!reference(locator+20,&self)||self!=locator)return fail("Image-relative locator self binding differs from its address.");}
        std::string name;if(!typeName(type,&name)||(name!=".?AV"+encoded+"@@"&&name!=".?AU"+encoded+"@@"))return fail("Vftable linkage and RTTI type identity do not match.");
        if(construction)return fail("Construction/vtordisp locator needs runtime object displacement; no fixed address point was inferred.");
        std::vector<CxxBaseClass> direct;if(!bases(hierarchy,type,&direct))return fail("Class hierarchy is malformed, unsupported or exceeds the global base budget.");
        *classHierarchy=hierarchy;
        record.typeInfo=type;record.typeName=name;record.display="vftable for "+display(name);record.bases=std::move(direct);record.addressPoint=symbol.value;record.offsetToTop=-static_cast<i64>(offset);
        CxxVtableAddressPoint point;point.header=symbol.value-width_;point.addressPoint=symbol.value;point.typeInfo=type;point.offsetToTop=record.offsetToTop;
        for(u64 n=0;n<256&&totalSlots_<8192;++n){const Address address=symbol.value+n*width_;if(address<symbol.value||!data(address,width_))break;u64 target=0;
            if(!image_.memory().readUnsigned(address,width_,&target)||!image_.memory().isExecutable(target))break;
            point.slots.push_back({address,target,image_.describeAddress(target),true});++totalSlots_;}
        if(point.slots.empty())return fail("No executable vftable slot prefix was verified; hierarchy is not bound to an address point.");
        record.slots=point.slots;record.addressPoints.push_back(std::move(point));
        record.notes.push_back("Verified executable slot prefix only; PE exports do not establish the complete vftable extent.");
        record.notes.push_back("Hierarchy decoded; virtual base PMD offsets require a runtime object's vbptr/vbtable and are not static object offsets.");
        return record;
    }
private:
    const ElfImage& image_;u8 width_;bool relative_;size_t totalBases_=0,totalSlots_=0;
};
}
CxxMetadataReport inspectMicrosoftCxxMetadata(const ElfImage& image,size_t limit) {
    CxxMetadataReport report;limit=std::min<size_t>(limit,4096);
    if(image.format()!=ImageFormat::kPe64 || (image.pointerSize()!=4&&image.pointerSize()!=8) || image.memory().byteOrder()!=ByteOrder::kLittle){report.notes.push_back("Microsoft RTTI requires a supported little-endian PE target.");return report;}
    Decoder decoder(image);std::set<std::pair<Address,std::string>> seen;std::map<Address,size_t> classes;std::map<Address,Address> hierarchies;std::set<Address> conflicts;
    for(const auto& symbol:image.symbols()){std::string encoded;if(!tableIdentity(symbol.name,&encoded)||!seen.emplace(symbol.value,symbol.name).second)continue;
        if(report.records.size()>=limit){report.truncated=true;break;}
        Address hierarchy=kNoAddress;auto record=decoder.table(symbol,encoded,&hierarchy);
        if(record.typeInfo!=kNoAddress && !record.addressPoints.empty()) {
            auto found=classes.find(record.typeInfo);
            if(found==classes.end()){CxxMetadataReport::Class klass;klass.name=display(record.typeName);klass.linkage=record.symbol;klass.typeInfo=record.typeInfo;klass.vtable=record.address;klass.bases=record.bases;klass.inheritanceComplete=true;
                found=classes.emplace(record.typeInfo,report.classes.size()).first;hierarchies[record.typeInfo]=hierarchy;report.classes.push_back(std::move(klass));}
            if(hierarchies[record.typeInfo]!=hierarchy)conflicts.insert(record.typeInfo);
            auto& klass=report.classes[found->second];
            for(const auto& point:record.addressPoints)if(std::none_of(klass.addressPoints.begin(),klass.addressPoints.end(),[&](const auto& old){return old.addressPoint==point.addressPoint;}))klass.addressPoints.push_back(point);
        }
        report.records.push_back(std::move(record));
    }
    report.classes.erase(std::remove_if(report.classes.begin(),report.classes.end(),[&](const auto& klass){return conflicts.count(klass.typeInfo)!=0;}),report.classes.end());
    if(!conflicts.empty())report.notes.push_back("Conflicting hierarchy identities for one TypeDescriptor: their address points were not combined into a class.");
    for(auto& klass:report.classes){std::sort(klass.addressPoints.begin(),klass.addressPoints.end(),[](const auto& a,const auto& b){return a.offsetToTop>b.offsetToTop;});
        klass.vtable=klass.addressPoints.front().addressPoint;for(const auto& record:report.records)if(record.address==klass.vtable){klass.linkage=record.symbol;break;}}
    report.notes.push_back("Evidence: exact exported Microsoft vftable linkage, COL self/type identity and bounded CHD/base-descriptor bytes. No stripped scan or data-member size inference.");
    report.notes.push_back("Static Microsoft hierarchy/PMD evidence only; virtual object offsets, construction locators, complete slot extents and C++ exception-flow reconstruction remain partial.");
    return report;
}
}
