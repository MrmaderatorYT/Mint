#pragma once
#include <string>
#include "mint/base/status.h"
#include "mint/base/byte_view.h"
#include "mint/plugin/architecture_sdk.h"
#include "mint/ir/ir_function.h"
namespace mint {
// A successful registration takes a process-lifetime pin on libraryHandle.
// Failure takes no ownership; the caller may close it. nullptr means builtin
// static callback/context whose lifetime is independently process-long.
Status registerArchitecturePlugin(const MintArchitecturePluginV1*, void* libraryHandle = nullptr);
Status registerArchitecturePluginV2(const MintArchitecturePluginV2*, void* libraryHandle = nullptr);
bool architecturePluginHasLifter(Arch);
u32 liftArchitecturePlugin(Arch,Address,ByteView,IrBuilder*);
bool architecturePluginAbi(Arch,MintArchitectureSemanticsV2*);
std::string architecturePluginsText();
} // namespace mint
