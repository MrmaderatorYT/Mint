#pragma once
#include "mint/debug/debugger.h"

namespace mint {
// Bounded, transactional SVR4 library-list reader. No DTD/network/entity loading.
Status parseRspSvr4Modules(const std::string& xml, std::vector<DebuggerModule>* out);
Status parseRspModules(const std::string& xml, std::vector<DebuggerModule>* out);
}
