#include "mint/types/signature_library.h"

#include <algorithm>
#include <sstream>
#include "mint/analysis/abi_model.h"

namespace mint {
namespace {
Status bad(const std::string& message) { return Status::error(ErrorCode::kBadFormat, "signature library: " + message); }
SignatureAbi parseAbi(const std::string& name) {
    for (SignatureAbi abi : {SignatureAbi::kAapcs64, SignatureAbi::kSysV64, SignatureAbi::kAapcs32,
         SignatureAbi::kRiscV32, SignatureAbi::kRiscV64, SignatureAbi::kCdecl32,SignatureAbi::kWindows64,SignatureAbi::kStdcall32}) if (name == signatureAbiName(abi)) return abi;
    return SignatureAbi::kUnknown;
}
size_t parameterSlots(SignatureAbi abi) {
    switch (abi) {
        case SignatureAbi::kAapcs64: case SignatureAbi::kRiscV32: case SignatureAbi::kRiscV64:return 8;
        case SignatureAbi::kSysV64:return 6;
        case SignatureAbi::kAapcs32:return 4;
        case SignatureAbi::kCdecl32:return 0;
        default:return 0;
    }
}
bool symbolName(const std::string& symbol) {
    if (symbol.empty() || symbol.size() > SignatureLibrary::kMaxSymbolBytes || symbol[0] == '#') return false;
    for (unsigned char byte : symbol) {
        if (byte <= 0x20 || byte >= 0x7f || byte == '\\' || byte == ';' || byte == '=' ||
            byte == '(' || byte == ')' || byte == ',' || byte == '[' || byte == ']' || byte == '{' || byte == '}') return false;
    }
    return true;
}
std::string trim(const std::string& text) {
    const size_t first=text.find_first_not_of(' ');if(first==std::string::npos)return {};
    return text.substr(first,text.find_last_not_of(' ')-first+1);
}
std::string canonicalType(const std::string& type) {
    std::string result;bool space=false;
    for(char byte:type) {
        if(byte==' '){space=true;continue;}
        if(space && !result.empty() && byte!='*' && result.back()!='*')result+=' ';
        result+=byte;space=false;
    }return result;
}
u8 scalarWidth(const std::string& type,u8 pointerWidth) {
    if(type.find('*')!=std::string::npos)return pointerWidth;
    if(type=="void")return 0;
    if(type=="char" || type=="int8_t" || type=="uint8_t")return 1;
    if(type=="int16_t" || type=="uint16_t")return 2;
    if(type=="int32_t" || type=="uint32_t")return 4;
    if(type=="int64_t" || type=="uint64_t")return 8;
    return 255;
}
Status prototype(SignatureAbi abi,const std::string& text,UserPrototype* output,std::string* canonical) {
    if(abi==SignatureAbi::kUnknown || parseAbi(signatureAbiName(abi))!=abi)return bad("explicit supported ABI is required");
    if(text.empty() || text.size()>SignatureLibrary::kMaxPrototypeBytes)return bad("prototype byte limit");
    for(unsigned char byte:text)if(byte<0x20 || byte>=0x7f)return bad("prototype must be single-line ASCII");
    UserPrototype parsed;const Status status=parseUserPrototype(trim(text),&parsed);
    if(!status.ok() || !parsed.valid())return bad("invalid type-only scalar prototype; no floats/aggregates/varargs/storage directives");
    const u8 width=(abi==SignatureAbi::kAapcs32 || abi==SignatureAbi::kRiscV32 || abi==SignatureAbi::kCdecl32||abi==SignatureAbi::kStdcall32)?4:8;
    parsed.returnType=canonicalType(parsed.returnType);
    if(!parsed.callingConvention.empty() && parsed.callingConvention!=signatureAbiName(abi))return bad("per-definition ABI conflicts with library ABI");
    const auto convention=signatureAbiName(abi);
    const Arch architecture=abi==SignatureAbi::kAapcs64?Arch::kAArch64:abi==SignatureAbi::kSysV64||abi==SignatureAbi::kWindows64?Arch::kX86_64:abi==SignatureAbi::kAapcs32?Arch::kArm32:abi==SignatureAbi::kRiscV32?Arch::kRiscV32:abi==SignatureAbi::kRiscV64?Arch::kRiscV64:Arch::kX86_32;
    for(auto& parameter:parsed.parameters) {
        parameter.type=canonicalType(parameter.type);
    }
    auto modeled=parsed;modeled.callingConvention=convention;AbiModel model;
    const auto modeledStatus=buildAbiModel(architecture,modeled,&model);
    if(!modeledStatus.ok())return bad(modeledStatus.message());
    // Preserve historical implicit defaults for existing ELF declarations;
    // Windows/stdcall must retain their explicit convention when returned alone.
    if(abi==SignatureAbi::kWindows64 || abi==SignatureAbi::kStdcall32)parsed.callingConvention=convention;
    std::ostringstream rendered;rendered<<parsed.returnType<<'(';
    if(parsed.parameters.empty())rendered<<"void";
    for(size_t i=0;i<parsed.parameters.size();++i){if(i)rendered<<", ";rendered<<parsed.parameters[i].type<<' '<<parsed.parameters[i].name;}
    if(parsed.variadic)rendered<<", ...";
    rendered<<')';*output=std::move(parsed);*canonical=rendered.str();return Status::success();
}
} // namespace

const char* signatureAbiName(SignatureAbi abi) {
    switch(abi) {
        case SignatureAbi::kAapcs64:return "aapcs64";case SignatureAbi::kSysV64:return "sysv64";
        case SignatureAbi::kAapcs32:return "aapcs32";case SignatureAbi::kRiscV32:return "riscv32";
        case SignatureAbi::kRiscV64:return "riscv64";case SignatureAbi::kCdecl32:return "cdecl32";
        case SignatureAbi::kWindows64:return "windows64";case SignatureAbi::kStdcall32:return "stdcall32";
        default:return "unknown";
    }
}
u8 SignatureLibrary::pointerSize() const {
    if(abi_==SignatureAbi::kUnknown || parseAbi(signatureAbiName(abi_))!=abi_)return 0;
    return abi_==SignatureAbi::kAapcs32 || abi_==SignatureAbi::kRiscV32 || abi_==SignatureAbi::kCdecl32||abi_==SignatureAbi::kStdcall32?4:8;
}
Status SignatureLibrary::validateFor(Arch architecture,ImageFormat format) const {
    if(!pointerSize())return bad("library has no supported ABI");
    if(format==ImageFormat::kPe64 && abi_!=SignatureAbi::kWindows64 && abi_!=SignatureAbi::kStdcall32 && abi_!=SignatureAbi::kCdecl32 && abi_!=SignatureAbi::kAapcs64)return bad("PE requires a Windows-compatible calling convention");
    if(format!=ImageFormat::kPe64 && format!=ImageFormat::kRaw && (abi_==SignatureAbi::kWindows64 || abi_==SignatureAbi::kStdcall32))return bad("Windows calling convention cannot silently bind a Unix container");
    const bool matching=(abi_==SignatureAbi::kAapcs64 && architecture==Arch::kAArch64) ||
        (abi_==SignatureAbi::kSysV64 && architecture==Arch::kX86_64) ||
        (abi_==SignatureAbi::kWindows64 && architecture==Arch::kX86_64) ||
        (abi_==SignatureAbi::kAapcs32 && (architecture==Arch::kArm32 || architecture==Arch::kThumb)) ||
        (abi_==SignatureAbi::kRiscV32 && architecture==Arch::kRiscV32) ||
        (abi_==SignatureAbi::kRiscV64 && architecture==Arch::kRiscV64) ||
        ((abi_==SignatureAbi::kCdecl32||abi_==SignatureAbi::kStdcall32) && architecture==Arch::kX86_32);
    if(!matching)return bad("ABI does not match the target architecture/mode");
    if(format==ImageFormat::kElf64 && pointerSize()!=8)return bad("ABI pointer width does not match the 64-bit native container");
    if(format==ImageFormat::kElf32 && pointerSize()!=4)return bad("ABI pointer width does not match the 32-bit native container");
    if(format!=ImageFormat::kElf64 && format!=ImageFormat::kElf32 && format!=ImageFormat::kMachO64 && format!=ImageFormat::kRaw&&format!=ImageFormat::kPe64)return bad("unknown native container");
    if(format==ImageFormat::kMachO64 && abi_!=SignatureAbi::kAapcs64 && abi_!=SignatureAbi::kSysV64 && abi_!=SignatureAbi::kAapcs32 && abi_!=SignatureAbi::kCdecl32)return bad("ABI is unsupported for this native container");
    return Status::success();
}
Status SignatureLibrary::define(const std::string& symbol,const std::string& declaration) {
    if(!symbolName(symbol))return bad("invalid original linkage symbol");
    if(definitions_.count(symbol))return bad("duplicate symbol; erase explicitly before replacing");
    if(definitions_.size()>=kMaxDefinitions)return Status::error(ErrorCode::kTooLarge,"signature library definition limit");
    SignatureDefinition entry;entry.symbol=symbol;
    const Status status=prototype(abi_,declaration,&entry.prototype,&entry.declaration);if(!status.ok())return status;
    const size_t size=serialize().size();
    if(entry.symbol.size()+entry.declaration.size()+2>kMaxLibraryBytes-size)return Status::error(ErrorCode::kTooLarge,"signature library byte limit");
    definitions_.emplace(symbol,std::move(entry));return Status::success();
}
Status SignatureLibrary::erase(const std::string& symbol) {
    if(!symbolName(symbol))return bad("invalid linkage symbol");
    if(!definitions_.erase(symbol))return Status::error(ErrorCode::kNotFound,"signature library symbol not found");return Status::success();
}
UserPrototype SignatureLibrary::prototypeFor(const std::string& symbol) const {
    const auto found=definitions_.find(symbol);return found==definitions_.end()?UserPrototype{}:found->second.prototype;
}
std::string SignatureLibrary::declarationFor(const std::string& symbol) const {
    const auto found=definitions_.find(symbol);return found==definitions_.end()?std::string{}:found->second.declaration;
}
std::vector<SignatureDefinition> SignatureLibrary::definitions() const {
    std::vector<SignatureDefinition> result;result.reserve(definitions_.size());for(const auto& entry:definitions_)result.push_back(entry.second);return result;
}
std::string SignatureLibrary::serialize() const {
    std::ostringstream out;out<<"MINTSIG 1\nabi="<<signatureAbiName(abi_)<<'\n';
    for(const auto& entry:definitions_)out<<entry.first<<'\t'<<entry.second.declaration<<'\n';return out.str();
}
Status SignatureLibrary::deserialize(const std::string& text) {
    if(text.empty() || text.size()>kMaxLibraryBytes)return bad("empty/excessive text library");
    for(unsigned char byte:text)if((byte<0x20 && byte!='\n' && byte!='\r' && byte!='\t') || byte>=0x7f)return bad("library must be ASCII without embedded controls");
    std::istringstream input(text);std::string line;
    auto next=[&](){if(!std::getline(input,line))return false;if(!line.empty()&&line.back()=='\r')line.pop_back();return line.find('\r')==std::string::npos;};
    if(!next() || line!="MINTSIG 1" || !next() || line.compare(0,4,"abi=")!=0)return bad("unsupported library version/header");
    const SignatureAbi abi=parseAbi(line.substr(4));if(abi==SignatureAbi::kUnknown)return bad("unknown/unsupported ABI");
    SignatureLibrary candidate(abi);
    while(std::getline(input,line)) {
        if(!line.empty()&&line.back()=='\r')line.pop_back();if(line.find('\r')!=std::string::npos)return bad("unexpected carriage return");
        if(line.empty() || line[0]=='#')continue;
        const size_t tab=line.find('\t');if(tab==std::string::npos || line.find('\t',tab+1)!=std::string::npos)return bad("expected one tab between symbol and type-only prototype");
        const std::string symbol=line.substr(0,tab),declaration=line.substr(tab+1);
        if(!symbolName(symbol) || candidate.definitions_.count(symbol) || candidate.definitions_.size()>=kMaxDefinitions)return bad("invalid/duplicate/excessive symbol records");
        SignatureDefinition entry;entry.symbol=symbol;const Status status=prototype(abi,declaration,&entry.prototype,&entry.declaration);if(!status.ok())return status;
        candidate.definitions_.emplace(symbol,std::move(entry));
    }
    if(candidate.serialize().size()>kMaxLibraryBytes)return bad("canonical library byte budget exceeded");
    *this=std::move(candidate);return Status::success();
}
} // namespace mint
