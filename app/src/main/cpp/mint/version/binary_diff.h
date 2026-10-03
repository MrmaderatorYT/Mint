#pragma once

#include <string>
#include <vector>

#include "mint/base/status.h"
#include "mint/base/types.h"

namespace mint {
class Session;

struct DiffInstruction { Address address = 0; u8 size = 0; };
struct FunctionFingerprint {
    Address entry = 0;
    Arch architecture = Arch::kUnknown;
    std::string name, symbol;
    std::string exactHash, normalizedHash, topologyHash;
    // Real decoded operands, constants retained. Only validated branch targets
    // are replaced with internal instruction ordinals or linkage symbols.
    std::string normalizedCode;
    std::vector<DiffInstruction> instructions;
    bool complete = false;
    bool eligible = false;
};
enum class FunctionMatchKind : u8 { kExactCode, kNormalizedCode, kSymbolChanged };
struct FunctionMatch {
    Address source = 0, target = 0;
    FunctionMatchKind kind = FunctionMatchKind::kNormalizedCode;
    std::string evidence;
};
struct AmbiguousFunctions {
    std::vector<Address> sources, targets;
    std::string reason;
};
struct BinaryDiff {
    std::string sourceIdentity, targetIdentity;
    std::vector<FunctionFingerprint> sourceFunctions, targetFunctions;
    std::vector<FunctionMatch> matches;
    std::vector<AmbiguousFunctions> ambiguous;
    std::vector<Address> unmatchedSource, unmatchedTarget;
};
struct InstructionCorrespondence {
    Address source = 0, target = 0;
    u8 size = 0;
    std::string evidence;
};
// Exact decoded semantics, including scalar constants, are retained. Unique
// instruction/context anchors in exact CFG block contexts (ignoring NOPs) may
// move across offsets; ambiguous repeated
// instructions and branch targets without a proved correspondence are omitted.
Status correspondInstructions(const Session& source, const Session& target,
                              Address sourceEntry, Address targetEntry,
                              std::vector<InstructionCorrespondence>* output);

// Identities bind file content, effective mapped bytes, decoder/engine mode,
// structural/user prototype configuration and every discovered CFG/record.
// SHA-256 fingerprints/checksums are integrity guards, not authentication.
Status binaryIdentity(const Session& session, std::string* result);
Status fingerprintFunction(const Session& session, Address entry, FunctionFingerprint* result);
Status compareBinaries(const Session& source, const Session& target, BinaryDiff* result,
                       size_t maxFunctions = 20000);
std::string binaryDiffText(const BinaryDiff& diff);

}  // namespace mint
