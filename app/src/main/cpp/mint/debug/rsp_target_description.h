#pragma once

#include <functional>
#include "mint/debug/debugger.h"

namespace mint {
using RspTargetXmlFetcher = std::function<Status(const std::string&, std::string*)>;

// Reads only bounded target-description documents supplied by the debugger
// transport. Includes are annex names, never host paths or external resources.
// No caller layout is published until every document and register is valid.
Status readRspTargetDescription(const RspTargetXmlFetcher& fetch,
                               std::vector<DebuggerRegisterSpec>* out);
}
