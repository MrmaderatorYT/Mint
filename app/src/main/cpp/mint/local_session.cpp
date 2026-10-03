#include "mint/session.h"
#include "mint/analysis/local_variables.h"
#include "mint/analysis/jump_table_recovery.h"
#include "mint/ir/ir_simplify.h"
#include "mint/obfuscation/deobfuscator.h"
#include <algorithm>
#include <set>
#include <sstream>

namespace mint {
Status Session::prepareLocalSsa(Address address,SsaFunction* output) {
    if(!output || !analyzed_ || isDexLike())return Status::error(ErrorCode::kBadFormat,"locals require an analyzed native function");
    const Function* function=analyzer_.functionContaining(address);
    if(!function)function=analyzer_.functionAt(address);
    if(!function)return Status::error(ErrorCode::kBadFormat,"no function at this address");
    if(function->instructionCount()>100000)return Status::error(ErrorCode::kTooLarge,"function exceeds interactive local-variable budget");
    if(!lifter_.ready()){auto status=lifter_.open(image_.arch());if(!status.ok())return status;}
    IrFunction ir;auto status=lifter_.liftFunction(*function,image_.memory(),&ir);if(!status.ok())return status;
    JumpTableRecovery recovery;recoverJumpTables(image_,ir,&recovery);augmentIrCfg(&ir,recovery);
    deobfuscate(&ir);ir.name=nameAt(ir.entry);
    normalizeRegisterAccesses(&ir);IrSimplifyStats simplified;status=simplifyIr(&ir,&simplified);if(!status.ok())return status;
    return buildSsa(ir,output);
}
std::string Session::localVariablesText(Address address) {
    SsaFunction function;auto status=prepareLocalSsa(address,&function);if(!status.ok())return status.toString();
    const auto candidates=localVariables(function);const auto edits=program_.locals(function.entry);
    std::set<std::string> identities;std::ostringstream text;
    text<<"identity\tname\ttype\tbytes\tstorage\n";size_t displayed=0;
    for(const auto& candidate:candidates) {
        identities.insert(candidate.identity);
        if(displayed++>=5000)continue;
        std::string name=candidate.name,type;
        for(const auto& edit:edits)if(edit.identity==candidate.identity){if(!edit.name.empty())name=edit.name;type=edit.type;break;}
        text<<candidate.identity<<'\t'<<name<<'\t'<<type<<'\t'<<static_cast<unsigned>(candidate.width)<<'\t';
        if(candidate.stack)text<<"stack "<<candidate.stackOffset;else text<<"ssa";
        text<<'\n';
    }
    size_t stale=0;for(const auto& edit:edits)if(!identities.count(edit.identity)) {
        ++stale;if(displayed++<5000)text<<edit.identity<<'\t'<<edit.name<<'\t'<<edit.type<<"\t0\tstale — remove override only\n";
    }
    if(stale)text<<"! "<<stale<<" stale local bindings retained but not applied after structural changes.\n";
    if(candidates.size()>5000)text<<"! "<<candidates.size()-5000<<" variables omitted by interactive display limit.\n";
    return text.str();
}
Status Session::editLocalVariable(Address address,const std::string& identity,const std::string& name,const std::string& type) {
    SsaFunction function;auto status=prepareLocalSsa(address,&function);if(!status.ok())return status;
    if(name.empty() && type.empty()) {
        const auto saved=program_.locals(function.entry);
        if(std::any_of(saved.begin(),saved.end(),[&](const auto& edit){return edit.identity==identity;})) {
            status=program_.editLocal(function.entry,identity,"","");if(status.ok())programReport_={};return status;
        }
    }
    const auto candidates=localVariables(function);
    const auto found=std::find_if(candidates.begin(),candidates.end(),[&](const auto& candidate){return candidate.identity==identity;});
    if(found==candidates.end())return Status::error(ErrorCode::kBadFormat,"local identity is stale or not in the current function");
    status=validateLocalVariableEdit(function,*found,program_.types(),name,type);if(!status.ok())return status;
    status=program_.editLocal(function.entry,identity,name,type);
    if(status.ok())programReport_={};return status;
}
} // namespace mint
