#pragma once
#include <map>
#include <string>
#include <vector>
#include "mint/analysis/indirect_flow.h"
#include "mint/analysis/user_prototype.h"

namespace mint {
struct PrototypeScalarEvidence {
    u8 width = 0; ///< Zero means unknown, not void. Bytes, never register count.
    bool pointer = false; ///< Used as an address, or required by an authoritative type.
    std::vector<std::string> provenance;
};
struct FunctionPrototypeEvidence {
    Address entry = 0;
    Arch architecture = Arch::kUnknown;
    bool authoritative = false;
    bool parameterCountKnown = false;
    bool returnsVoid = false; ///< Only an authoritative declaration can assert void.
    UserPrototype declaration; ///< Never synthesized from uncertain evidence.
    PrototypeScalarEvidence result;
    /// Register ABI position, including unknown holes. x86-32's stack arguments
    /// remain unknown rather than being misidentified as SysV64 register args.
    std::vector<PrototypeScalarEvidence> parameters;
};
struct PrototypeCallEvidence {
    Address caller = 0, site = 0;
    std::vector<Address> targets;
    bool complete = false;
};
struct InterproceduralPrototypeReport {
    std::vector<FunctionPrototypeEvidence> functions;
    std::vector<PrototypeCallEvidence> calls;
    size_t iterations = 0;
    bool converged = false;
};
struct InterproceduralPrototypeOptions {
    size_t maxFunctions = 20000;
    size_t maxValues = 1000000;
    size_t maxInstructions = 1000000;
    size_t maxCalls = 100000;
    size_t maxIterations = 64;
    size_t maxWork = 4000000;
};
/// Deterministic monotone call-graph fixedpoint over observed register SSA.
/// Authoritative imported/user declarations win. A missing result, unknown
/// argument count, partial indirect call or live runtime target stays unknown.
/// Borrowed functions need not be sorted; duplicates and malformed SSA fail
/// transactionally. The pass does not modify SSA or user declarations.
Status inferInterproceduralPrototypes(
    const std::vector<const SsaFunction*>& functions,
    const std::map<Address, UserPrototype>& authoritative,
    const std::vector<IndirectFlowReport>& indirectFlow,
    InterproceduralPrototypeReport* output,
    const InterproceduralPrototypeOptions& options = {});
}
