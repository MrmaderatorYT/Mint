#include "mint/analysis/code_map.h"

#include <algorithm>

namespace mint {

bool CodeMap::insert(const InsnRecord& record) {
    if (finalized_) return false;
    if (!seen_.insert(record.address).second) return false;
    records_.push_back(record);
    return true;
}

bool CodeMap::contains(Address addr) const {
    if (!finalized_) return seen_.count(addr) != 0;
    return find(addr) != nullptr;
}

void CodeMap::finalize() {
    if (finalized_) return;
    std::sort(records_.begin(), records_.end(),
              [](const InsnRecord& a, const InsnRecord& b) {
                  return a.address < b.address;
              });
    records_.shrink_to_fit();

    // Release the discovery-time index; from here the sorted vector answers
    // everything.
    std::unordered_set<Address>().swap(seen_);
    finalized_ = true;
}

size_t CodeMap::lowerBound(Address addr) const {
    auto it = std::lower_bound(records_.begin(), records_.end(), addr,
                               [](const InsnRecord& record, Address value) {
                                   return record.address < value;
                               });
    return static_cast<size_t>(it - records_.begin());
}

const InsnRecord* CodeMap::find(Address addr) const {
    const size_t index = lowerBound(addr);
    if (index >= records_.size()) return nullptr;
    if (records_[index].address != addr) return nullptr;
    return &records_[index];
}

const InsnRecord* CodeMap::covering(Address addr) const {
    const size_t index = lowerBound(addr);
    if (index < records_.size() && records_[index].address == addr) {
        return &records_[index];
    }
    if (index == 0) return nullptr;
    const InsnRecord& previous = records_[index - 1];
    if (addr < previous.next()) return &previous;
    return nullptr;
}

}  // namespace mint
