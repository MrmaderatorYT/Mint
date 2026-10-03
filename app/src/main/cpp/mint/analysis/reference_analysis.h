#pragma once
#include "mint/analysis/program.h"
#include "mint/loader/elf_image.h"
#include "mint/ssa/ssa_function.h"

namespace mint {
// Bounded, finite-value SSA address propagation. Memory folding only reads
// read-only file-backed bytes and records every consulted range. Unknown values
// remain unknown; a finite branch merge never silently chooses one predecessor.
void collectSsaReferences(const SsaFunction& function, const ElfImage& image,
                          Program::ReferenceGroup* result);
} // namespace mint
