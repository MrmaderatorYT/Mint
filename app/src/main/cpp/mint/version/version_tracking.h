#pragma once

#include <string>
#include <vector>

#include "mint/version/binary_diff.h"

namespace mint {
class Session;
struct ConfirmedFunctionMatch {
    Address source = 0, target = 0;
    std::string sourceCode, targetCode, sourceTopology, targetTopology;
};
struct TrackingState {
    std::string sourceIdentity, targetIdentity;
    std::vector<ConfirmedFunctionMatch> confirmed;
};
struct AnnotationTransfer {
    Address source = 0, target = 0;
    std::string kind, value;
};
struct TransferIssue {
    Address source = 0, target = kNoAddress;
    std::string kind, reason;
};
struct TransferPlan {
    std::string sourceIdentity, targetIdentity;
    TrackingState authorization;
    std::vector<AnnotationTransfer> edits;
    std::vector<TransferIssue> skipped;
};
struct TransferResult { size_t applied = 0; size_t skipped = 0; bool rolledBack = false; };

// Manual authorization: an automatic diff candidate is never a transfer grant.
// The caller must obtain this explicit decision from the user. Pairs are checked
// against current native functions and are always one-to-one.
Status confirmFunctionMatch(const Session& source, const Session& target,
                            Address sourceEntry, Address targetEntry, TrackingState* state);
Status validateTracking(const Session& source, const Session& target, const TrackingState& state);

// Portable little-endian, versioned, CRC-checked <=16 MiB file. save is create-only
// and publishes a complete fsync'ed candidate atomically; it never overwrites
// an input, an existing tracking file, a project or any other existing file.
Status saveTracking(const Session& source, const Session& target,
                    const TrackingState& state, const std::string& path);
Status loadTracking(const Session& source, const Session& target,
                    const std::string& path, TrackingState* state);

// Only name/comment/bookmark/prototype are eligible. Target edits always win.
// Instruction mapping uses unique exact decoded semantics/neighbourhoods and
// exact CFG block contexts and proved direct-branch targets, permitting NOP
// insertion and moved blocks without
// dropping scalar constants. Gaps, data, repeated-instruction ambiguity and
// unsupported prototype locations are explicitly skipped. Patches, types and
// structural user decisions are never transferred.
Status planAnnotationTransfer(const Session& source, const Session& target,
                              const TrackingState& state, TransferPlan* plan);
Status applyAnnotationTransfer(const Session& source, Session* target,
                               const TransferPlan& plan, TransferResult* result);
std::string trackingText(const TrackingState& state);
std::string transferPlanText(const TransferPlan& plan);

}  // namespace mint
