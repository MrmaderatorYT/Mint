#pragma once

#include <string>
#include <vector>

#include "mint/analysis/code_analyzer.h"
#include "mint/analysis/program.h"
#include "mint/base/status.h"

namespace mint {

struct CachedAnalysis {
    CodeAnalyzer::Snapshot analysis;
    std::vector<Program::Reference> references;
    std::vector<Program::ReferenceGroup> referenceGroups;
    bool referencesReady = false;
};

// Companion derived-state cache, separate from the authoritative user overlay.
// The caller supplies the dependency identity (input/model/engine version).
// No object layouts, pointer values or CFG implementation details are dumped.
// Load verifies version, checksum, identity, bounds/enums and strict EOF before
// publishing its result. Image/options validation and CFG reconstruction remain
// CodeAnalyzer::restore's responsibility. A corrupt/incompatible cache is a
// recoverable miss, not a reason to discard user annotations.
class AnalysisCache {
public:
    static Status load(const std::string& path, const std::string& dependencyKey,
                       CachedAnalysis* out);
    static Status save(const std::string& path, const std::string& dependencyKey,
                       const CachedAnalysis& analysis);
    static constexpr u64 kMaxFileBytes = 128ULL * 1024 * 1024;
    static constexpr size_t kMaxInstructions = 4000000;
    static constexpr size_t kMaxFunctions = 200000;
    static constexpr size_t kMaxReferences = 4000000;
};

}  // namespace mint
