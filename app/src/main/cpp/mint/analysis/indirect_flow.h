#pragma once
#include <string>
#include <vector>
#include "mint/base/status.h"
#include "mint/loader/elf_image.h"
#include "mint/ssa/ssa_function.h"

namespace mint {
struct IndirectFlowTarget {
    Address address = 0;
    Address rawPointer = 0;
    Arch decodeArch = Arch::kUnknown;
};
struct IndirectFlowDependency { Address start = 0, end = 0; };
enum class IndirectFlowConfidence : u8 { kUnknown, kPartial, kProven };
struct IndirectFlowSite {
    Address address = 0;
    bool call = false;
    bool complete = false;
    IndirectFlowConfidence confidence = IndirectFlowConfidence::kUnknown;
    std::vector<IndirectFlowTarget> targets;
    std::vector<IndirectFlowDependency> dependencies;
    std::vector<std::string> provenance;
    std::string reason;
};
struct IndirectFlowReport {
    Address functionEntry = 0;
    std::vector<IndirectFlowSite> sites;
    size_t iterations = 0;
    bool converged = false;
};
struct IndirectFlowOptions {
    size_t maxValues = 200000;
    size_t maxInstructions = 200000;
    size_t maxSites = 4096;
    size_t maxSetSize = 32;
    size_t maxDependencies = 128;
    size_t maxIterations = 256;
    size_t maxWork = 4000000; ///< Includes Cartesian products, not only SSA nodes.
};
/// Register-SSA finite-set dataflow, never an execution trace guess. Unknown
/// paths retain partial evidence but prohibit CFG completion. Reads are proved
/// only from uniquely mapped immutable bytes, with exact patch dependencies.
Status recoverIndirectFlow(const ElfImage& image, const SsaFunction& function,
                           IndirectFlowReport* output,
                           const IndirectFlowOptions& options = {});
}
