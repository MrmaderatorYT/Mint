#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>

#include "mint/ssa/ssa_function.h"

namespace mint {

/// Turns SSA values into C expressions.
///
/// The one rule worth stating is when a value becomes an inline subexpression rather
/// than its own statement. Inlining everything reads better but is not always sound:
/// a load moved past a store reads different memory, and this form does not version
/// memory, so it cannot tell whether that happened. A value is therefore folded into
/// its use only when it has exactly one use and its defining operation is pure.
/// Loads, calls and intrinsics always get a statement of their own and are referred
/// to afterwards by name, which keeps them in the order the machine had them.
class ExprBuilder {
public:
    explicit ExprBuilder(const SsaFunction& function) : function_(function) {}

    /// Overrides the printed name of a value — used to call the entry value of the
    /// first argument register `a0` rather than `arg_0`, which reads as an offset.
    void setName(SsaId id, const std::string& name) { names_[id] = name; }
    void setNumericPointer(SsaId id) { numericPointers_.insert(id); }
    void materialize(SsaId id) { materialized_.insert(id); }

    /// Renders an address value as a struct field access — `p->field_18` — instead
    /// of `(p + 0x18)`.
    ///
    /// Safe because a load is never re-materialised: it is impure, so it always gets
    /// a statement of its own and happens exactly once, where the machine had it.
    /// Inlining the field expression into several uses would be a different matter —
    /// an intervening store could make the second rendering a different value.
    void setFieldAccess(SsaId addressValue, const std::string& text) {
        fields_[addressValue] = text;
    }

    /// The field text for an address value, or empty when it is not a known field.
    std::string fieldAccess(SsaId addressValue) const {
        const auto found = fields_.find(addressValue);
        return found == fields_.end() ? std::string() : found->second;
    }

    std::string value(SsaId id);
    std::string instruction(const SsaInsn& insn);
    std::string name(SsaId id) const;

    /// True when `id` is emitted as its own statement rather than folded into its use.
    bool needsStatement(SsaId id) const;

private:
    std::string operation(const SsaInsn& insn);
    u8 valueWidth(SsaId id) const;

    const SsaFunction& function_;
    std::unordered_set<SsaId> visiting_;
    std::unordered_map<SsaId, std::string> names_;
    std::unordered_map<SsaId, std::string> fields_;
    std::unordered_set<SsaId> numericPointers_;
    std::unordered_set<SsaId> materialized_;
};

}  // namespace mint
