#include "mint/debug/rsp_target_description.h"

#include <algorithm>
#include <climits>
#include <map>
#include <set>

namespace mint {
namespace {
Status invalid() { return Status::error(ErrorCode::kBadFormat,"invalid/unsupported RSP target-description XML"); }
Status unsupported(const char* message) { return Status::error(ErrorCode::kUnsupported,message); }
bool space(char c) { return c==' '||c=='\t'||c=='\r'||c=='\n'; }
bool letter(char c) { return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||c==':'; }
bool nameChar(char c) { return letter(c)||(c>='0'&&c<='9')||c=='-'||c=='.'; }
bool number(const std::string& text,u64* out) {
    if(text.empty())return false;u64 n=0;
    for(char c:text){if(c<'0'||c>'9'||n>(~u64{0}-unsigned(c-'0'))/10)return false;n=n*10+unsigned(c-'0');}
    *out=n;return true;
}
bool validXmlText(const std::string& text) {
    for(size_t at=0;at<text.size();){
        u32 value=static_cast<u8>(text[at++]);unsigned count=0;u32 minimum=0;
        if(value>=0x80){
            if(value>=0xc2&&value<=0xdf){value&=31;count=1;minimum=0x80;}
            else if(value>=0xe0&&value<=0xef){value&=15;count=2;minimum=0x800;}
            else if(value>=0xf0&&value<=0xf4){value&=7;count=3;minimum=0x10000;}
            else return false;
            while(count--){if(at==text.size()||(static_cast<u8>(text[at])&0xc0)!=0x80)return false;value=(value<<6)|(static_cast<u8>(text[at++])&63);}
            if(value<minimum)return false;
        }
        if((value<32&&value!=9&&value!=10&&value!=13)||(value>=0xd800&&value<=0xdfff)||value==0xfffe||value==0xffff||value>0x10ffff)return false;
    }
    return true;
}
struct Token {
    std::string name,text;std::map<std::string,std::string> attrs;
    bool closing=false,empty=false,isText=false;
};
class Reader {
public:
    explicit Reader(const std::string& xml):xml_(xml){}
    bool prolog(){
        whitespace();
        if(xml_.compare(at_,5,"<?xml")==0){
            const auto end=xml_.find("?>",at_+5);
            if(at_+5==xml_.size()||!space(xml_[at_+5])||end==std::string::npos)return false;
            // Parse declaration attributes with the same quoted-attribute reader.
            const std::string declaration="<xml"+xml_.substr(at_+5,end-at_-5)+"/>";
            Reader nested(declaration);Token token;
            if(!nested.next(&token)||token.name!="xml"||!token.empty||token.attrs["version"]!="1.0")return false;
            for(const auto& attr:token.attrs)if(attr.first!="version"&&(attr.first!="encoding"||(attr.second!="UTF-8"&&attr.second!="utf-8"))&&(attr.first!="standalone"||(attr.second!="yes"&&attr.second!="no")))return false;
            at_=end+2;whitespace();
        }
        if(!misc())return false;
        if(xml_.compare(at_,9,"<!DOCTYPE")==0){
            if(at_+9==xml_.size()||!space(xml_[at_+9]))return false;
            // External DTD hints are inert. Internal subsets/entities cannot
            // influence the exact register names, sizes or include annexes.
            at_+=9;whitespace();if(!name(&doctypeRoot_))return false;
            const auto afterName=at_;whitespace();
            if(at_==xml_.size())return false;
            if(xml_[at_]!='>'){
                if(at_==afterName)return false;std::string kind;if(!name(&kind)||(kind!="SYSTEM"&&kind!="PUBLIC"))return false;
                const auto afterKind=at_;whitespace();if(at_==afterKind||!literal())return false;
                if(kind=="PUBLIC"){const auto afterPublic=at_;whitespace();if(at_==afterPublic||!literal())return false;}
                whitespace();if(at_==xml_.size()||xml_[at_]!='>')return false;
            }
            ++at_;
        }
        return true;
    }
    const std::string& doctypeRoot() const { return doctypeRoot_; }
    bool next(Token* out){
        *out=Token{};
        while(xml_.compare(at_,4,"<!--")==0){const auto end=xml_.find("--",at_+4);if(end==std::string::npos||xml_.compare(end,3,"-->")!=0)return false;at_=end+3;}
        if(at_==xml_.size())return false;
        if(xml_[at_]!='<'){
            const auto end=xml_.find('<',at_);out->isText=true;out->text=xml_.substr(at_,end==std::string::npos?end:end-at_);at_=end==std::string::npos?xml_.size():end;return out->text.find('&')==std::string::npos&&out->text.find("]]>")==std::string::npos;
        }
        ++at_;out->closing=at_<xml_.size()&&xml_[at_]=='/';if(out->closing)++at_;
        if(!name(&out->name))return false;
        while(at_<xml_.size()){
            const auto before=at_;whitespace();
            if(at_==xml_.size())return false;
            if(xml_.compare(at_,2,"/>")==0){at_+=2;out->empty=true;return !out->closing;}
            if(xml_[at_]=='>'){++at_;return true;}
            if(out->closing||at_==before)return false;
            std::string key,value;if(!name(&key))return false;whitespace();
            if(at_==xml_.size()||xml_[at_++]!='=')return false;whitespace();
            if(at_==xml_.size()||(xml_[at_]!='\''&&xml_[at_]!='"'))return false;
            const auto quote=xml_[at_++];const auto end=xml_.find(quote,at_);if(end==std::string::npos)return false;
            value=xml_.substr(at_,end-at_);if(value.find_first_of("<&")!=std::string::npos||!out->attrs.emplace(key,std::move(value)).second)return false;at_=end+1;
        }
        return false;
    }
    bool done(){
        whitespace();
        while(xml_.compare(at_,4,"<!--")==0){const auto end=xml_.find("--",at_+4);if(end==std::string::npos||xml_.compare(end,3,"-->")!=0)return false;at_=end+3;whitespace();}
        return at_==xml_.size();
    }
private:
    bool literal(){
        if(at_==xml_.size()||(xml_[at_]!='\''&&xml_[at_]!='"'))return false;
        const auto quote=xml_[at_++];const auto end=xml_.find(quote,at_);if(end==std::string::npos)return false;at_=end+1;return true;
    }
    bool misc(){
        whitespace();
        while(xml_.compare(at_,4,"<!--")==0){const auto end=xml_.find("--",at_+4);if(end==std::string::npos||xml_.compare(end,3,"-->")!=0)return false;at_=end+3;whitespace();}
        return true;
    }
    bool name(std::string* out){if(at_==xml_.size()||!letter(xml_[at_]))return false;const auto start=at_++;while(at_<xml_.size()&&nameChar(xml_[at_]))++at_;*out=xml_.substr(start,at_-start);return true;}
    void whitespace(){while(at_<xml_.size()&&space(xml_[at_]))++at_;}
    const std::string& xml_;size_t at_=0;std::string doctypeRoot_;
};
class Description {
public:
    explicit Description(const RspTargetXmlFetcher& fetch):fetch_(fetch){}
    Status read(std::vector<DebuggerRegisterSpec>* out){
        if(!out||!fetch_)return invalid();auto status=document("target.xml",{},0);if(!status.ok())return status;
        if(layout_.empty())return unsupported("Target XML contains no register definitions");
        std::sort(layout_.begin(),layout_.end(),[](const auto& a,const auto& b){return a.number<b.number;});
        // Gaps have architecture-specific packet semantics and are not guessed.
        for(size_t n=0;n<layout_.size();++n)if(layout_[n].number!=n)return unsupported("Non-contiguous XML register numbers need an explicit exact packet layout");
        *out=std::move(layout_);return Status::success();
    }
private:
    Status document(const std::string& annex,const std::string& parent,unsigned depth){
        if(depth>8||seenAnnexes_.size()>=16||annex.empty()||annex.size()>128||annex[0]=='/'||annex.find("..")!=std::string::npos||annex.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/")!=std::string::npos||!seenAnnexes_.insert(annex).second)return unsupported("Target XML include path/cycle/depth budget exceeded");
        std::string xml;auto status=fetch_(annex,&xml);if(!status.ok())return status;
        if(xml.size()>65536-totalBytes_||!validXmlText(xml))return invalid();totalBytes_+=xml.size();Reader reader(xml);if(!reader.prolog())return invalid();
        Token token;
        do {if(!reader.next(&token))return invalid();}while(token.isText&&whitespace(token.text));
        if(token.isText||token.closing)return invalid();
        if(!reader.doctypeRoot().empty()&&reader.doctypeRoot()!=token.name)return invalid();
        if(parent.empty()){
            if(token.name!="target"||(token.attrs.count("version")&&token.attrs["version"]!="1.0"))return invalid();
            if(!token.empty){status=contents(reader,token.name,depth,0);if(!status.ok())return status;}
        }else {status=element(reader,token,parent,depth,0);if(!status.ok())return status;}
        return reader.done()?Status::success():invalid();
    }
    static bool whitespace(const std::string& text){return std::all_of(text.begin(),text.end(),space);}
    Status reg(const Token& token){
        const auto& attrs=token.attrs;auto name=attrs.find("name"),size=attrs.find("bitsize"),numberIt=attrs.find("regnum");u64 bits=0,id=next_;
        if(name==attrs.end()||name->second.empty()||name->second.size()>128||size==attrs.end()||!number(size->second,&bits)||!bits||bits%8||bits>4096||(numberIt!=attrs.end()&&!number(numberIt->second,&id))||id>UINT_MAX||layout_.size()>=1024||bits/8>32768-registerBytes_||!names_.insert(name->second).second||!numbers_.insert(static_cast<u32>(id)).second)return invalid();
        layout_.push_back({name->second,static_cast<u32>(id),static_cast<u32>(bits)});registerBytes_+=bits/8;next_=id+1;return Status::success();
    }
    Status contents(Reader& reader,const std::string& parent,unsigned depth,unsigned nesting){
        if(nesting>32)return invalid();Token token;
        while(reader.next(&token)){
            if(++nodes_>16384)return invalid();
            if(token.isText){if(parent=="architecture"||parent=="osabi"||parent=="compatible"||whitespace(token.text))continue;return invalid();}
            if(token.closing)return token.name==parent&&token.attrs.empty()?Status::success():invalid();
            auto status=element(reader,token,parent,depth,nesting);if(!status.ok())return status;
        }
        return invalid();
    }
    Status element(Reader& reader,const Token& token,const std::string& parent,unsigned depth,unsigned nesting){
        if(token.name=="xi:include"){
            if((parent!="target"&&parent!="feature"&&parent!="union"&&parent!="struct"&&parent!="flags"&&parent!="enum")||!token.empty||token.attrs.size()!=1||!token.attrs.count("href"))return invalid();
            return document(token.attrs.at("href"),parent,depth+1);
        }
        if(token.name=="reg"){
            if(parent!="feature")return invalid();auto status=reg(token);if(!status.ok())return status;
        }else if(parent=="target"){
            if(token.name!="feature"&&token.name!="architecture"&&token.name!="osabi"&&token.name!="compatible")return invalid();
        }else if(parent=="feature"){
            if(token.name!="vector"&&token.name!="union"&&token.name!="struct"&&token.name!="flags"&&token.name!="enum")return invalid();
        }else if(parent=="union"||parent=="struct"||parent=="flags"){
            if(token.name!="field")return invalid();
        }else if(parent=="enum"){
            if(token.name!="evalue")return invalid();
        }else return invalid();
        return token.empty?Status::success():contents(reader,token.name,depth,nesting+1);
    }
    const RspTargetXmlFetcher& fetch_;size_t totalBytes_=0,registerBytes_=0,nodes_=0;u64 next_=0;
    std::set<std::string> seenAnnexes_,names_;std::set<u32> numbers_;std::vector<DebuggerRegisterSpec> layout_;
};
}
Status readRspTargetDescription(const RspTargetXmlFetcher& fetch,std::vector<DebuggerRegisterSpec>* out){return Description(fetch).read(out);}
}
