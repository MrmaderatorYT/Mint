#pragma once

#include <string>
#include <vector>
#include "mint/base/status.h"
#include "mint/ssa/ssa_function.h"
#include "mint/types/data_type_manager.h"

namespace mint {

struct LocalVariableEdit {
    std::string identity;
    std::string name;
    // DTM expression, not an arbitrary C fragment. Empty preserves inference.
    std::string type;
};
struct LocalVariable {
    std::string identity;
    std::string name;
    u8 width = 0;
    SsaId value = kNoValue;
    bool stack = false;
    i64 stackOffset = 0;
};

// Identities are guarded by the normalized SSA structure, never by a bare SSA
// number. A patch, different lifter, or changed control-flow invalidates bindings
// instead of silently applying an old edit to an unrelated value.
std::vector<LocalVariable> localVariables(const SsaFunction& function);
Status parseLocalVariableEdits(const std::string& text, std::vector<LocalVariableEdit>* out);
std::string serializeLocalVariableEdits(const std::vector<LocalVariableEdit>& edits);
std::string localTypeExpression(const std::string& type);
std::string localCType(const std::string& type);
Status validateLocalVariableEdit(const SsaFunction& function,const LocalVariable& variable,
                                const DataTypeManager& types,const std::string& name,
                                const std::string& type);

} // namespace mint
