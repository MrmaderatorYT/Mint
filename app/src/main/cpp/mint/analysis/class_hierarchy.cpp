#include "mint/analysis/class_hierarchy.h"

namespace mint {

void ClassHierarchy::build(const DexImage& image) { parents_.clear(); for (const DexClass& klass : image.classes()) parents_[klass.descriptor] = klass.superclass; }
const std::string& ClassHierarchy::superclass(const std::string& descriptor) const { static const std::string empty; const auto it = parents_.find(descriptor); return it == parents_.end() ? empty : it->second; }
bool ClassHierarchy::isSubclassOf(const std::string& child, const std::string& parent) const { std::string current = child; for (u32 depth = 0; depth < 256 && !current.empty(); ++depth) { if (current == parent) return true; current = superclass(current); } return false; }
std::vector<const DexMethod*> ClassHierarchy::resolveVirtual(const DexImage& image, const std::string& owner, const std::string& name) const { std::vector<const DexMethod*> result; for (const DexClass& klass : image.classes()) if (isSubclassOf(klass.descriptor, owner)) if (const DexMethod* method = image.findMethod(klass.descriptor, name)) result.push_back(method); return result; }

}  // namespace mint
