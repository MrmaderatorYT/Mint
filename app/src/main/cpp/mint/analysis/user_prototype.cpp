#include "mint/analysis/user_prototype.h"
#include <regex>
#include <set>
#include <sstream>
namespace mint {
namespace {
std::string trim(const std::string& text) {
    const auto first=text.find_first_not_of(" \t\r\n");
    return first==std::string::npos ? "" : text.substr(first,text.find_last_not_of(" \t\r\n")-first+1);
}
bool type(const std::string& value) {
    static const std::regex pattern("(void|char|float|double|bool|u?int(8|16|32|64)_t|[ui](8|16|32|64)|f(32|64))([ ]*\\*)?");
    // Named debug/user aggregate pointers still use the integer-register ABI.
    // By-value aggregates and floats remain unsupported rather than silently
    // applying that convention to incompatible storage.
    static const std::regex namedPointer("(const[ ]+)?[A-Za-z_][A-Za-z0-9_]*[ ]*\\*([ ]*\\*)*");
    return std::regex_match(value,pattern) || std::regex_match(value,namedPointer) || userIdentifier(value);
}
}
bool userIdentifier(const std::string& text) {
    static const std::regex identifier("[A-Za-z_][A-Za-z0-9_]*");
    static const std::set<std::string> keywords={"auto","break","case","char","const","continue","default","do","double","else","enum","extern","float","for","goto","if","inline","int","long","register","restrict","return","short","signed","sizeof","static","struct","switch","typedef","union","unsigned","void","volatile","while","_Bool","_Complex","_Atomic","_Alignas","_Alignof","_Generic","_Noreturn","_Static_assert","_Thread_local"};
    return std::regex_match(text,identifier) && !keywords.count(text);
}
Status parseUserPrototype(const std::string& text,UserPrototype* result) {
    if(!result)return Status::error(ErrorCode::kInternalError,"null prototype output");
    *result={}; if (text.empty()) return Status::success();
    auto bad=[] {return Status::error(ErrorCode::kBadFormat,"use [@abi] ReturnType(Type name, ...); scalar/declared aggregate types, at most 64 parameters");};
    if(text.size()>4096 || text.find('\0')!=std::string::npos)return bad();
    UserPrototype parsed;auto declaration=trim(text);
    if(!declaration.empty()&&declaration[0]=='@') {
        auto end=declaration.find_first_of(" \t");if(end==std::string::npos)return bad();
        parsed.callingConvention=declaration.substr(1,end-1);
        static const std::set<std::string> conventions={"aapcs64","sysv64","windows64","aapcs32","aapcs32-vfp","cdecl32","stdcall32","riscv32","riscv64","riscv32d","riscv64d"};
        if(!conventions.count(parsed.callingConvention))return bad();declaration=trim(declaration.substr(end));
    }
    auto open=declaration.find('('),close=declaration.find(')');
    if (open==std::string::npos || close!=declaration.size()-1 || close<open || !type(trim(declaration.substr(0,open)))) return bad();
    parsed.returnType=trim(declaration.substr(0,open));
    const auto args=trim(declaration.substr(open+1,close-open-1));
    if (args!="void" && !args.empty()) {
        std::istringstream input(args); std::string part; std::set<std::string> names;
        const std::regex parameter("(.+?)[ ]+([A-Za-z_][A-Za-z0-9_]*)");
        if (args.back()==',') return bad();
        while (std::getline(input,part,',')) {
            std::smatch match; part=trim(part);
            if(part=="...") {if(parsed.parameters.empty() || input.peek()!=std::char_traits<char>::eof())return bad();parsed.variadic=true;break;}
            if (!std::regex_match(part,match,parameter)) return bad();
            const auto t=trim(match[1].str()),n=match[2].str();
            if (!type(t) || t=="void" || !userIdentifier(n) || !names.insert(n).second || parsed.parameters.size()>=64) return bad();
            parsed.parameters.push_back({t,n});
        }
    }
    *result=std::move(parsed);return Status::success();
}
} // namespace mint
