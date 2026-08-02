#pragma once

#include <unordered_set>
#include <vector>

#include "mint/base/types.h"
#include "mint/disasm/instruction.h"

namespace mint {

/// Every instruction the analysis has decoded, once each, keyed by address.
///
/// Two-phase on purpose. During discovery, insertion and membership tests
/// dominate, so a hash set of addresses backs them. Once discovery finishes the
/// set is thrown away and only a sorted vector remains: from then on the access
/// patterns are "give me the instruction at this address" and "walk this address
/// range in order", both of which a sorted vector serves with far better cache
/// behaviour and a fraction of the memory. On a large obfuscated library the
/// difference is tens of megabytes on a device that will kill us for using them.
class CodeMap {
public:
    /// Records an instruction. Returns false if this address was already decoded,
    /// in which case the existing record is kept — the first decode of an address
    /// wins, which matters when overlapping instruction streams are involved.
    bool insert(const InsnRecord& record);

    bool contains(Address addr) const;

    /// Switches to the queryable, compact representation. Idempotent.
    void finalize();
    bool finalized() const { return finalized_; }

    size_t size() const { return records_.size(); }
    bool empty() const { return records_.empty(); }
    const std::vector<InsnRecord>& instructions() const { return records_; }

    /// The instruction starting exactly at `addr`, or nullptr. Requires finalize().
    const InsnRecord* find(Address addr) const;

    /// The instruction whose bytes span `addr`, which may be its second or later
    /// byte. Used when a branch lands mid-instruction — a real signal, since it
    /// is one of the ways obfuscated code hides an instruction stream inside
    /// another. Requires finalize().
    const InsnRecord* covering(Address addr) const;

    /// Index of the first instruction at or after `addr`, for range walks.
    /// Requires finalize().
    size_t lowerBound(Address addr) const;

private:
    std::vector<InsnRecord> records_;
    std::unordered_set<Address> seen_;
    bool finalized_ = false;
};

}  // namespace mint
