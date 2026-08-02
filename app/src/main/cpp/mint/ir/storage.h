#pragma once

#include <vector>

#include "mint/base/types.h"
#include "mint/ir/varnode.h"

namespace mint {

/// One whole, non-overlapping piece of the register file.
///
/// The IR addresses registers as byte ranges precisely so that aliasing is visible
/// (see registers.h), but SSA needs the opposite property. SSA renames *variables*,
/// and `rax`/`eax`/`al`/`ah` are not four variables — they are four windows onto
/// one. Renaming them independently would produce a form where a write through one
/// window is invisible to a read through another, which is exactly the bug the
/// byte-addressed layout exists to prevent.
///
/// Canonical units are the bridge. They partition the register file so that every
/// register access falls inside exactly one unit, and SSA is then built over units
/// rather than over the accesses themselves. Accesses narrower than their unit
/// become explicit extracts and inserts, so nothing is implicit afterwards: each op
/// says what it reads and writes at full unit width, and a later pass never has to
/// remember that some operand secretly meant "the low four bytes of".
struct StorageUnit {
    u64 offset = 0;
    u8 size = 0;

    bool valid() const { return size != 0; }
    u64 end() const { return offset + size; }
    bool operator==(const StorageUnit& other) const {
        return offset == other.offset && size == other.size;
    }
    bool operator!=(const StorageUnit& other) const { return !(*this == other); }
};

/// The unit containing `offset`. Widths that reach past that unit are the caller's
/// problem to detect with `accessSpansUnits`; this returns the unit the access
/// starts in either way, because every caller needs somewhere to start.
StorageUnit canonicalUnit(Arch arch, u64 offset, u8 size);

inline StorageUnit canonicalUnit(Arch arch, const Varnode& node) {
    return canonicalUnit(arch, node.offset, node.size);
}

/// True when a register access crosses a unit boundary, e.g. a single 16-byte read
/// covering two 8-byte general-purpose registers.
///
/// Worth a separate query rather than folding into canonicalUnit: such an access
/// cannot be expressed as one SSA variable, so the SSA builder has to treat it as
/// touching several, and silently rounding it to one unit would drop a dependency.
bool accessSpansUnits(Arch arch, u64 offset, u8 size);

/// True when the access is exactly its own unit, which is the case SSA can rename
/// directly with no extract or insert around it.
bool accessIsWholeUnit(Arch arch, u64 offset, u8 size);

}  // namespace mint
