#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "mint/loader/dex_image.h"

namespace mint {

class ClassHierarchy {
public:
    void build(const DexImage& image);
    const std::string& superclass(const std::string& descriptor) const;
    bool isSubclassOf(const std::string& child, const std::string& parent) const;
    std::vector<const DexMethod*> resolveVirtual(const DexImage& image, const std::string& owner, const std::string& name) const;

private:
    std::unordered_map<std::string, std::string> parents_;
};

}  // namespace mint
