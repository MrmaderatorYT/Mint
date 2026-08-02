#pragma once

#include <string>
#include <vector>

#include "mint/base/byte_view.h"
#include "mint/base/status.h"

namespace mint {

struct DexMethod {
    u32 index = 0;
    std::string classDescriptor;
    std::string name;
    std::string prototype;
    u32 accessFlags = 0;
    u16 registersSize = 0;
    u16 insSize = 0;
    u16 outsSize = 0;
    std::vector<u16> code;
};

struct DexClass {
    std::string descriptor;
    std::string superclass;
    std::vector<std::string> interfaces;
    std::vector<u32> methodIndices;
};

class DexImage {
public:
    Status load(ByteView data);
    bool loaded() const { return loaded_; }
    const std::vector<std::string>& strings() const { return strings_; }
    const std::vector<DexMethod>& methods() const { return methods_; }
    const std::vector<DexClass>& classes() const { return classes_; }
    const DexMethod* findMethod(const std::string& classDescriptor, const std::string& name) const;

private:
    std::string stringAt(u32 index) const;
    std::string typeAt(u32 index) const;
    bool readCode(u32 codeOffset, DexMethod* method);

    ByteView data_;
    bool loaded_ = false;
    u32 stringIdsOff_ = 0, typeIdsOff_ = 0, protoIdsOff_ = 0, methodIdsOff_ = 0, classDefsOff_ = 0;
    std::vector<u32> stringOffsets_;
    std::vector<u32> typeIds_;
    std::vector<std::string> strings_;
    std::vector<DexMethod> methods_;
    std::vector<DexClass> classes_;
};

}  // namespace mint
