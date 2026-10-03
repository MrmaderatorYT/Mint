#include "mint/session.h"
#include "mint/script/lua_runtime.h"
#include "mint/patch/assembler.h"
#include <cstdio>
#include <set>

namespace mint {
Status Session::runScript(const std::string& source,bool allowEdits,std::string* output) {
    cancel_.store(false);ScriptOptions options;options.allowEdits=allowEdits;options.cancel=&cancel_;
    const auto status=runLuaScript(*this,source,options,output);cancel_.store(false);return status;
}
Status Session::assembleAt(Address address,const std::string& source,bool apply,std::string* output) {
    if(!output || !analyzed_ || isDexLike() || !image_.memory().isExecutable(image_.canonicalAddress(address)))
        return Status::error(ErrorCode::kBadFormat,"assembly requires an analyzed native executable address");
    const auto arch=image_.architectureAt(address);address=image_.canonicalAddress(address);
    // The assembler's external table is a strict, bounded expression namespace,
    // not the complete loader symbol inventory. Unexpressible mapping/linker
    // names and unrelated symbols must not prevent even a standalone NOP.
    // Scan only bounded ASCII identifier tokens, excluding // comments; this is
    // a conservative superset of operand references, never address guessing.
    const auto first=[](unsigned char c){return(c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_';};
    const auto rest=[&](unsigned char c){return first(c)||(c>='0'&&c<='9');};
    std::set<std::string> referenced,ambiguous;
    if(source.size()<=65536)for(size_t at=0;at<source.size();) {
        if(source[at]=='/'&&at+1<source.size()&&source[at+1]=='/') {while(at<source.size()&&source[at]!='\n')++at;continue;}
        if(!first(static_cast<unsigned char>(source[at]))){++at;continue;}
        const size_t begin=at++;while(at<source.size()&&rest(static_cast<unsigned char>(source[at])))++at;
        if(at-begin<=128)referenced.insert(source.substr(begin,at-begin));
    }
    std::map<std::string,Address> symbols;
    const auto add=[&](const std::string& name,Address value){
        if(!referenced.count(name)||ambiguous.count(name))return;
        if(value==kNoAddress){symbols.erase(name);ambiguous.insert(name);return;}
        const auto found=symbols.find(name);
        if(found!=symbols.end()&&found->second!=value){symbols.erase(found);ambiguous.insert(name);}
        else symbols.emplace(name,value);
    };
    for(const auto& symbol:image_.symbols())if(!symbol.undefined)add(symbol.name,symbol.value);
    for(const auto& annotation:program_.annotations())if(annotation.kind=="name")add(annotation.value,annotation.address);
    if(const auto* function=analyzer_.functionContaining(address)) {
        // Function mode may come from an interworking call rather than mapping symbols.
        const auto mode=function->decodeArch==Arch::kUnknown?arch:function->decodeArch;
        std::vector<u8> bytes;const auto status=assembleWithSymbols(mode,address,source,symbols,&bytes);if(!status.ok())return status;
        std::string text;char byte[4];for(auto value:bytes){std::snprintf(byte,sizeof(byte),"%02x ",value);text+=byte;}
        if(!text.empty())text.pop_back();
        if(apply){const auto status=editAnnotation(address,"patch",text);if(!status.ok())return status;}
        *output=std::move(text);return Status::success();
    }
    std::vector<u8> bytes;const auto status=assembleWithSymbols(arch,address,source,symbols,&bytes);if(!status.ok())return status;
    std::string text;char byte[4];for(auto value:bytes){std::snprintf(byte,sizeof(byte),"%02x ",value);text+=byte;}
    if(!text.empty())text.pop_back();
    if(apply){const auto status=editAnnotation(address,"patch",text);if(!status.ok())return status;}
    *output=std::move(text);return Status::success();
}
} // namespace mint
