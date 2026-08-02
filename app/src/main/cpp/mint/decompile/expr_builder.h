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
};

}  // namespace mint
