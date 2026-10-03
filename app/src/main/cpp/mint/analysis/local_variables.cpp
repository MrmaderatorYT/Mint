#include "mint/analysis/local_variables.h"

#include <cstdio>
#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#include "mint/analysis/user_prototype.h"
#include "mint/ir/stack_analysis.h"
#include "mint/ir/type_recovery.h"

namespace mint {
namespace {
void mix(u64* hash, u64 value) {
    for(unsigned i=0;i<8;++i) { *hash ^= static_cast<u8>(value >> (i*8)); *hash *= 1099511628211ULL; }
}
std::string hex(u64 value) { char bytes[24];std::snprintf(bytes,sizeof(bytes),"%llx",static_cast<unsigned long long>(value));return bytes; }
u64 fingerprint(const SsaFunction& function) {
    u64 hash=1469598103934665603ULL;
    mix(&hash,1);mix(&hash,function.entry);mix(&hash,static_cast<u8>(function.arch));
    for(const auto& v:function.values) {
        mix(&hash,static_cast<u8>(v.def));mix(&hash,v.defIndex);mix(&hash,static_cast<u8>(v.storage.space));mix(&hash,v.storage.offset);mix(&hash,v.storage.size);
    }
    for(const auto& insn:function.insns) {
        mix(&hash,static_cast<u8>(insn.op));mix(&hash,insn.address);mix(&hash,insn.dest);mix(&hash,insn.block);mix(&hash,insn.dead);mix(&hash,insn.laneWidth);
        for(auto use:insn.use)mix(&hash,use);
        for(auto def:insn.clobbers)mix(&hash,def);
    }
    for(const auto& phi:function.phis) {mix(&hash,phi.dest);mix(&hash,phi.block);mix(&hash,phi.dead);for(auto arg:phi.args)mix(&hash,arg);}
    for(const auto& block:function.blocks) {mix(&hash,block.start);mix(&hash,block.end);for(auto next:block.successors)mix(&hash,next);}
    for(const auto& returned:function.abiReturnValues){mix(&hash,returned.instruction);mix(&hash,returned.storage.offset);mix(&hash,returned.storage.size);mix(&hash,returned.value);}
    return hash;
}
bool validIdentity(const std::string& text) {
    if(text.empty() || text.size()>160 || (text.compare(0,4,"ssa:") && text.compare(0,6,"stack:")))return false;
    for(unsigned char c:text)if(!(c>='0'&&c<='9') && !(c>='a'&&c<='z') && c!=':' && c!='-' && c!='_')return false;
    return true;
}
}
std::vector<LocalVariable> localVariables(const SsaFunction& function) {
    std::vector<LocalVariable> result;
    if(function.values.size()>2000000 || function.insns.size()>2000000)return result;
    const std::string guard=hex(fingerprint(function));
    for(SsaId id=0;id<function.values.size();++id) {
        const auto& value=function.values[id];
        if(!value.uses || value.def==SsaDef::kConstant)continue;
        if(value.def==SsaDef::kInsn && (value.defIndex>=function.insns.size() || function.insns[value.defIndex].dead))continue;
        if(value.def==SsaDef::kPhi && (value.defIndex>=function.phis.size() || function.phis[value.defIndex].dead))continue;
        result.push_back({"ssa:"+guard+":"+hex(id),"v"+std::to_string(id),value.storage.size,id,false,0});
    }
    StackAnalysis stack;
    if(analyzeStackMemory(function,&stack).ok())for(const auto& slot:stack.slots) {
        if(slot.overlaps)continue;
        const u64 magnitude=slot.offset<0 ? static_cast<u64>(-(slot.offset+1))+1 : static_cast<u64>(slot.offset);
        result.push_back({"stack:"+guard+":"+(slot.offset<0 ? "m" : "p")+hex(magnitude)+":"+hex(slot.width),slot.name,slot.width,kNoValue,true,slot.offset});
    }
    return result;
}
Status parseLocalVariableEdits(const std::string& text,std::vector<LocalVariableEdit>* out) {
    if(!out)return Status::error(ErrorCode::kInternalError,"null local edit output");
    if(text.size()>1024*1024)return Status::error(ErrorCode::kTooLarge,"local edits exceed 1 MiB");
    std::vector<LocalVariableEdit> parsed;std::set<std::string> identities,names;
    if(text.empty()){out->clear();return Status::success();}
    std::istringstream input(text);std::string line;
    if(!std::getline(input,line) || line!="MINTLOC1")return Status::error(ErrorCode::kBadFormat,"unsupported local edit format");
    while(std::getline(input,line)) {
        const auto first=line.find('\t'),second=first==std::string::npos ? first : line.find('\t',first+1);
        if(first==std::string::npos || second==std::string::npos || line.find('\t',second+1)!=std::string::npos || parsed.size()>=4096)
            return Status::error(ErrorCode::kBadFormat,"invalid local edit record");
        LocalVariableEdit edit{line.substr(0,first),line.substr(first+1,second-first-1),line.substr(second+1)};
        if(!validIdentity(edit.identity) || (!edit.name.empty()&&!userIdentifier(edit.name)) || edit.type.size()>256 || edit.type.find_first_of("\r\n;{}()")!=std::string::npos || edit.type.find('\0')!=std::string::npos ||
           (edit.name.empty()&&edit.type.empty()) || !identities.insert(edit.identity).second || (!edit.name.empty()&&!names.insert(edit.name).second))
            return Status::error(ErrorCode::kBadFormat,"invalid/duplicate local identity, name or type");
        parsed.push_back(std::move(edit));
    }
    *out=std::move(parsed);return Status::success();
}
std::string serializeLocalVariableEdits(const std::vector<LocalVariableEdit>& edits) {
    if(edits.empty())return {};
    auto ordered=edits;std::sort(ordered.begin(),ordered.end(),[](const auto& a,const auto& b){return a.identity<b.identity;});
    std::string result="MINTLOC1\n";
    for(const auto& edit:ordered)result+=edit.identity+'\t'+edit.name+'\t'+edit.type+'\n';
    return result;
}
std::string localTypeExpression(const std::string& type) {
    static const std::map<std::string,std::string> mappings={{"uint8_t","u8"},{"uint16_t","u16"},{"uint32_t","u32"},{"uint64_t","u64"},{"int8_t","i8"},{"int16_t","i16"},{"int32_t","i32"},{"int64_t","i64"},{"float","f32"},{"double","f64"}};
    std::string result=type;if(result.compare(0,6,"const ")==0)result.erase(0,6);result.erase(std::remove_if(result.begin(),result.end(),[](char c){return c==' '||c=='\t';}),result.end());
    size_t stars=result.find('*');std::string base=result.substr(0,stars);auto mapped=mappings.find(base);
    return (mapped==mappings.end()?base:mapped->second)+(stars==std::string::npos ? "" : result.substr(stars));
}
std::string localCType(const std::string& type) {
    static const std::map<std::string,std::string> mappings={{"u8","uint8_t"},{"u16","uint16_t"},{"u32","uint32_t"},{"u64","uint64_t"},{"i8","int8_t"},{"i16","int16_t"},{"i32","int32_t"},{"i64","int64_t"},{"f32","float"},{"f64","double"}};
    const auto expression=localTypeExpression(type);size_t stars=expression.find('*');const auto base=expression.substr(0,stars);auto mapped=mappings.find(base);
    return (type.compare(0,6,"const ")==0 ? "const " : "")+(mapped==mappings.end()?base:mapped->second)+(stars==std::string::npos ? "" : expression.substr(stars));
}
Status validateLocalVariableEdit(const SsaFunction& function,const LocalVariable& variable,const DataTypeManager& types,const std::string& name,const std::string& type) {
    const auto candidates=localVariables(function);
    if(std::none_of(candidates.begin(),candidates.end(),[&](const auto& local){return local.identity==variable.identity;}))
        return Status::error(ErrorCode::kNotFound,"local identity is stale; rediscover current function variables");
    if(!name.empty()&&!userIdentifier(name))return Status::error(ErrorCode::kBadFormat,"local name must be a non-keyword C identifier");
    TypeRecovery recovered;auto status=recoverTypes(function,&recovered);if(!status.ok())return status;
    if(!variable.stack)for(const auto& parameter:recovered.parameters)if(parameter.value==variable.value)
        return Status::error(ErrorCode::kUnsupported,"parameter names/types are edited through the function prototype");
    if(type.empty())return Status::success();
    const auto expression=localTypeExpression(type);DataTypeLayout layout;status=types.resolve(expression,&layout);if(!status.ok())return status;
    if(layout.size!=variable.width)return Status::error(ErrorCode::kBadFormat,"local type width differs from machine storage; use a cast instead");
    if(layout.kind!=DataTypeKind::kPrimitive && layout.kind!=DataTypeKind::kPointer && layout.kind!=DataTypeKind::kEnum)
        return Status::error(ErrorCode::kUnsupported,"aggregate/array local reinterpretation requires composite storage");
    const bool floating=layout.isFloating;
    if(variable.stack && (floating || layout.kind==DataTypeKind::kPointer))
        return Status::error(ErrorCode::kUnsupported,"stack pointer/floating reinterpretation is not modeled; integer/enum stack types supported");
    if(!variable.stack && variable.value<recovered.values.size()) {
        if(floating && recovered.values[variable.value].kind!=RecoveredTypeKind::kFloat)
            return Status::error(ErrorCode::kUnsupported,"floating type on integer bits would change semantics");
    }
    return Status::success();
}
} // namespace mint
