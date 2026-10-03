#pragma once
#include <atomic>
#include <string>
#include "mint/base/status.h"
#include "mint/base/types.h"

namespace mint {
class Session;
struct ScriptOptions {
    bool allowEdits = false;
    size_t memoryBytes = 8*1024*1024;
    size_t outputBytes = 1024*1024;
    u64 instructionLimit = 2000000;
    u32 nativeCallLimit = 1000;
    const std::atomic_bool* cancel = nullptr;
};
// No filesystem, process, network, dynamic module or automatic execution API.
// Addresses cross the language boundary as exact hexadecimal strings. A failed
// script stops at its first uncaught error; already committed explicit edits
// remain undoable individual Program transactions, not a fabricated rollback.
Status runLuaScript(Session& session,const std::string& source,const ScriptOptions& options,
                    std::string* output);
} // namespace mint
