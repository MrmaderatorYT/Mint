#pragma once
#include <memory>
#include <string>
#include "mint/base/status.h"
#include "mint/plugin/sdk.h"
#include "mint/plugin/architecture_sdk.h"
namespace mint {
class Session;
// Serialized with Session. No automatic discovery/loading and no persistent
// executable paths. Commands are synchronous; command-only libraries close
// with their manager/Session, decoder libraries remain pinned for process life.
class PluginManager {
public:
    PluginManager();~PluginManager();
    PluginManager(PluginManager&&) noexcept;PluginManager& operator=(PluginManager&&) noexcept;
    PluginManager(const PluginManager&)=delete;
    Status load(const std::string& path,bool trustNativeCode);
    Status registerBuiltin(const MintPluginV1* descriptor);
    Status registerBuiltinArchitecture(const MintArchitecturePluginV1* descriptor);
    Status registerBuiltinExtension(const MintPluginExtensionV2* descriptor);
    std::string commandsText() const;
    Status run(Session&,const std::string& command,const std::string& arguments,bool allowEdits,std::string* output);
    Status runAnalyzer(Session&,const std::string& pass,const std::string& arguments,bool allowEdits,std::string* output);
    Status dispatchEvent(Session&,const MintPluginEventV2&,std::string* output);
private:
    struct Impl;std::unique_ptr<Impl> impl_;
};
} // namespace mint
