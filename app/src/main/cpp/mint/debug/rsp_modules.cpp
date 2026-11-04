#include "mint/debug/rsp_modules.h"

#include <cctype>
#include <map>
#include <set>

namespace mint {
namespace {
Status invalid() { return Status::error(ErrorCode::kBadFormat,"invalid/unsupported RSP SVR4 library XML"); }
bool space(char c) { return c==' ' || c=='\n' || c=='\r' || c=='\t'; }
bool number(const std::string& text,Address* out) {
    size_t at=0;unsigned base=10;Address value=0;
    if(text.rfind("0x",0)==0){at=2;base=16;}
    if(at==text.size())return false;
    for(;at<text.size();++at) {
        const auto c=text[at];const unsigned digit=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:99;
        if(digit>=base || value>(~Address{0}-digit)/base)return false;
        value=value*base+digit;
    }
    *out=value;return true;
}
bool decode(const std::string& text,std::string* out) {
    out->clear();
    for(size_t at=0;at<text.size();++at) {
        if(text[at]=='<')return false;
        if(text[at]!='&'){out->push_back(text[at]);continue;}
        const auto end=text.find(';',at);if(end==std::string::npos)return false;
        const auto entity=text.substr(at,end-at+1);
        if(entity=="&amp;")out->push_back('&');else if(entity=="&lt;")out->push_back('<');
        else if(entity=="&gt;")out->push_back('>');else if(entity=="&quot;")out->push_back('"');
        else if(entity=="&apos;")out->push_back('\'');else return false;
        at=end;
    }
    return true;
}
struct Reader {
    const std::string& xml;size_t at=0;
    void whitespace(){while(at<xml.size()&&space(xml[at]))++at;}
    bool tag(std::string* name,std::map<std::string,std::string>* attrs,bool* empty,bool* closing) {
        whitespace();if(at==xml.size()||xml[at++]!='<')return false;
        *closing=at<xml.size()&&xml[at]=='/';if(*closing)++at;
        const auto start=at;
        while(at<xml.size()&&(std::isalnum(static_cast<unsigned char>(xml[at]))||xml[at]=='-'||xml[at]=='_'))++at;
        *name=xml.substr(start,at-start);if(name->empty())return false;
        attrs->clear();*empty=false;
        while(at<xml.size()) {
            const auto before=at;whitespace();
            if(xml.compare(at,2,"/>")==0){at+=2;*empty=true;return !*closing;}
            if(at<xml.size()&&xml[at]=='>'){++at;return true;}
            if(*closing||at==before)return false;
            const auto keyStart=at;
            while(at<xml.size()&&(std::isalnum(static_cast<unsigned char>(xml[at]))||xml[at]=='-'||xml[at]=='_'))++at;
            const auto key=xml.substr(keyStart,at-keyStart);whitespace();
            if(key.empty()||at==xml.size()||xml[at++]!='=')return false;
            whitespace();if(at==xml.size()||(xml[at]!='\''&&xml[at]!='"'))return false;
            const char quote=xml[at++];const auto end=xml.find(quote,at);if(end==std::string::npos)return false;
            std::string value;if(!decode(xml.substr(at,end-at),&value)||!attrs->emplace(key,std::move(value)).second)return false;
            at=end+1;
        }
        return false;
    }
};
}
Status parseRspSvr4Modules(const std::string& xml,std::vector<DebuggerModule>* out) {
    if(!out||xml.size()>1024*1024)return invalid();
    for(unsigned char c:xml)if(c<32&&!space(c))return invalid();
    Reader reader{xml};reader.whitespace();
    if(xml.compare(reader.at,5,"<?xml")==0) {
        const auto end=xml.find("?>",reader.at);if(end==std::string::npos)return invalid();
        reader.at=end+2;reader.whitespace();
    }
    // Ignore an external DTD hint as inert text. Internal subsets/entities are
    // deliberately unsupported; no local or remote resource is ever opened.
    if(xml.compare(reader.at,9,"<!DOCTYPE")==0) {
        const auto end=xml.find('>',reader.at);if(end==std::string::npos)return invalid();
        const auto hint=xml.substr(reader.at,end-reader.at);
        if(hint.find('[')!=std::string::npos||hint.find("<!",2)!=std::string::npos)return invalid();
        reader.at=end+1;
    }
    std::string name;std::map<std::string,std::string> attrs;bool empty=false,closing=false;
    if(!reader.tag(&name,&attrs,&empty,&closing)||name!="library-list-svr4"||closing||attrs["version"]!="1.0")return invalid();
    for(const auto& attr:attrs) {
        Address unused;
        if(attr.first!="version"&&(attr.first!="main-lm"||!number(attr.second,&unused)))return invalid();
    }
    std::vector<DebuggerModule> candidate;std::set<std::pair<Address,Address>> identities;
    if(!empty)while(true) {
        if(!reader.tag(&name,&attrs,&empty,&closing))return invalid();
        if(closing){if(name!="library-list-svr4"||!attrs.empty())return invalid();break;}
        if(name!="library"||!empty||candidate.size()>=4096)return invalid();
        DebuggerModule module;module.hasSvr4=true;
        if(!attrs.count("name")||!attrs.count("lm")||!attrs.count("l_addr")||!attrs.count("l_ld"))return invalid();
        for(const auto& attr:attrs)if(attr.first!="name"&&attr.first!="lm"&&attr.first!="l_addr"&&attr.first!="l_ld"&&attr.first!="lmid")return invalid();
        if(!number(attrs["lm"],&module.linkMap)||!number(attrs["l_addr"],&module.loadBias)||
           !number(attrs["l_ld"],&module.dynamicAddress)||(attrs.count("lmid")&&!number(attrs["lmid"],&module.linkerNamespace))||
           !identities.emplace(module.linkerNamespace,module.linkMap).second)return invalid();
        module.id="svr4:"+std::to_string(module.linkerNamespace)+":"+std::to_string(module.linkMap);
        module.path=attrs["name"];const auto slash=module.path.find_last_of('/');module.name=module.path.substr(slash==std::string::npos?0:slash+1);
        candidate.push_back(std::move(module));
    }
    reader.whitespace();if(reader.at!=xml.size())return invalid();
    *out=std::move(candidate);return Status::success();
}
Status parseRspModules(const std::string& xml,std::vector<DebuggerModule>* out) {
    auto bad=[](){return Status::error(ErrorCode::kBadFormat,"invalid/unsupported RSP library XML");};
    if(!out || xml.size()>1024*1024)return bad();
    for(unsigned char c:xml)if(c<32&&!space(c))return bad();
    Reader reader{xml};reader.whitespace();
    if(xml.compare(reader.at,5,"<?xml")==0){const auto end=xml.find("?>",reader.at);if(end==std::string::npos)return bad();reader.at=end+2;reader.whitespace();}
    if(xml.compare(reader.at,9,"<!DOCTYPE")==0){const auto end=xml.find('>',reader.at);if(end==std::string::npos)return bad();const auto hint=xml.substr(reader.at,end-reader.at);
        if(hint.find('[')!=std::string::npos||hint.find("<!",2)!=std::string::npos)return bad();reader.at=end+1;}
    std::string name;std::map<std::string,std::string> attrs;bool empty=false,closing=false;
    if(!reader.tag(&name,&attrs,&empty,&closing)||name!="library-list"||closing)return bad();
    for(const auto& attr:attrs)if(attr.first!="version"||attr.second!="1.0")return bad();
    std::vector<DebuggerModule> candidate;size_t totalBases=0;
    if(!empty)while(true){
        if(!reader.tag(&name,&attrs,&empty,&closing))return bad();
        if(closing){if(name!="library-list"||!attrs.empty())return bad();break;}
        if(name!="library"||empty||attrs.size()!=1||!attrs.count("name")||attrs["name"].empty()||attrs["name"].size()>4096||candidate.size()>=4096)return bad();
        DebuggerModule module;module.path=attrs["name"];const auto slash=module.path.find_last_of("/\\");module.name=module.path.substr(slash==std::string::npos?0:slash+1);
        module.id="rsp-library:"+std::to_string(candidate.size());
        while(true){
            if(!reader.tag(&name,&attrs,&empty,&closing))return bad();
            if(closing){if(name!="library"||!attrs.empty())return bad();break;}
            Address address=0;
            if(!empty||(name!="segment"&&name!="section")||attrs.size()!=1||!attrs.count("address")||!number(attrs["address"],&address)||++totalBases>16384)return bad();
            if(name=="segment"){if(!module.sectionBases.empty()||module.segmentBases.size()>=4096)return bad();module.segmentBases.push_back(address);}
            else {if(!module.segmentBases.empty()||module.sectionBases.size()>=4096)return bad();module.sectionBases.push_back(address);}
        }
        if(module.segmentBases.empty()&&module.sectionBases.empty())return bad();
        candidate.push_back(std::move(module));
    }
    reader.whitespace();if(reader.at!=xml.size())return bad();
    *out=std::move(candidate);return Status::success();
}
}
