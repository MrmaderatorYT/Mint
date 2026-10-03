#pragma once

#include <string>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <map>

#include "mint/analysis/cfg.h"
#include "mint/analysis/code_map.h"
#include "mint/analysis/function.h"
#include "mint/analysis/indirect_flow.h"
#include "mint/base/status.h"
#include "mint/base/types.h"
#include "mint/disasm/disassembler.h"
#include "mint/loader/elf_image.h"

namespace mint {

/// Finds and disassembles the code in a loaded image.
///
/// Recursive descent from known entry points, not a linear sweep of .text. A
/// linear sweep over an obfuscated library produces garbage: constant pools,
/// jump tables and deliberately inserted junk bytes all sit inside .text, and on
/// x86-64 a sweep that starts one byte off stays wrong for a long stretch.
/// Descent only decodes bytes something actually branches to, which costs
/// coverage where targets are indirect — and that gap is recorded per function
/// rather than hidden, because knowing what was *not* reached is what tells the
/// user a dispatcher still needs resolving.
class CodeAnalyzer {
public:
    struct AddressRange {
        Address start = 0;
        Address end = 0;  ///< Exclusive; empty/reversed ranges are rejected.
    };

    struct Options {
        /// Whether a direct call seeds a new function. Off would leave the call
        /// graph empty, so this exists for isolating a single function on demand.
        bool followCalls = true;

        /// Hard ceiling on decoded instructions, so a hostile file cannot make
        /// analysis run until the process is killed. Roughly 100 MB of records.
        size_t maxInstructions = 4000000;

        /// Ceiling on discovered functions.
        size_t maxFunctions = 200000;

        /// Sweep executable sections linearly after descent, to pick up functions
        /// that nothing reachable calls. Finds more, at the cost of some false
        /// functions, so it is reported separately.
        bool linearSweepFallback = true;

        /// Explicit user entries take naming/provenance precedence and are
        /// installed as boundaries before any descent, independent of order.
        std::vector<Address> userFunctionEntries;
        /// Debug-information roots; explicit user entries retain precedence.
        std::vector<Address> debugFunctionEntries;

        /// Authoritative user-defined data: decoding cannot start in, or span
        /// across, these half-open ranges. Applies to every discovery source.
        std::vector<AddressRange> excludedRanges;

        /// Optional cooperative cancellation owned by the caller. Analysis is
        /// deliberately cancellable at worklist boundaries so a mobile UI can
        /// stop a scan without closing the mapped file underneath it.
        const std::atomic_bool* cancel = nullptr;
        std::atomic_int* progress = nullptr;
        size_t progressTotalBytes = 0;
    };

    // Two overloads rather than a defaulted argument: Options has default member
    // initialisers and is declared inside this class, so `= {}` here would need
    // the enclosing class to be complete.
    Status analyze(const ElfImage& image);
    Status analyze(const ElfImage& image, const Options& options);

    struct Snapshot {
        std::vector<InsnRecord> instructions;
        std::vector<Function> functions;
        std::vector<std::string> warnings;
        std::vector<Address> functionBoundaries;
        bool reachedInstructionLimit = false;
    };
    Snapshot snapshot() const;

    /// Validates persisted instruction/function ownership against the current
    /// image and options, then rebuilds derived CFGs, indexes and statistics.
    /// A rejected snapshot leaves the current analysis unchanged.
    Status restore(const ElfImage& image, const Options& options, const Snapshot& state);

    struct IncrementalResult {
        bool used = false;
        size_t functionsReanalyzed = 0;
        std::string reason;
    };
    /// Re-decodes all owners of patched instructions and reuses unaffected
    /// functions only when flow topology and authoritative metadata stay fixed.
    /// Unsupported/uncertain cases fall back to full analysis with a reason.
    Status reanalyzeChanged(const ElfImage& image, const Options& options,
                            const std::vector<AddressRange>& dirtyRanges,
                            IncrementalResult* result);

    const CodeMap& code() const { return code_; }
    const std::vector<Function>& functions() const { return functions_; }

    /// Functions by entry address.
    const Function* functionAt(Address entry) const;

    /// The function whose decoded instructions include `addr`, or nullptr. Built
    /// after analysis; an address can belong to more than one function when code
    /// is shared, in which case the one with the lowest entry wins.
    const Function* functionContaining(Address addr) const;

    /// Callers of each function, derived from every function's callee list.
    const std::vector<Address>& callersOf(Address entry) const;

    const std::vector<std::string>& warnings() const { return warnings_; }
    /// Derived SSA evidence. Cache restore re-proves it from current bytes;
    /// only complete sites contribute actual CFG edges or discovered callees.
    const std::map<Address, IndirectFlowReport>& indirectFlowReports() const { return indirectFlowReports_; }

    struct Stats {
        size_t instructions = 0;
        size_t functions = 0;
        size_t blocks = 0;
        size_t edges = 0;
        size_t indirectJumps = 0;
        size_t undecodableSites = 0;
        size_t incompleteFunctions = 0;
        size_t functionsFromSweep = 0;
        size_t reachedInstructionLimit = 0;
    };
    const Stats& stats() const { return stats_; }

private:
    /// A function entry waiting to be analysed, with why it is a candidate.
    struct Root {
        Address address;
        FunctionOrigin origin;
        std::string name;
        Arch decodeArch = Arch::kUnknown;
    };
    Status prepareState(const ElfImage& image, const Options& options,
                        std::vector<Root>* roots);

    void collectRoots(const ElfImage& image, const Options& options,
                      std::vector<Root>* roots);
    void seedRoot(Address addr, FunctionOrigin origin, std::string name,
                  std::vector<Root>* roots);

    /// Depth-first walk of one function's body. Appends newly found call targets
    /// to `pending`.
    void descend(const ElfImage& image, const Options& options, const Root& root,
                 std::vector<Root>* pending);

    void linearSweep(const ElfImage& image, const Options& options,
                     std::vector<Root>* pending);

    void buildIndexes();
    void addWarning(std::string message);

    bool excluded(Address address) const;
    size_t decodeLimit(Address address, size_t requested) const;
    bool decodeRecord(const ElfImage& image, Address address, InsnRecord* record,
                      Address functionEntry = kNoAddress, Arch functionArch = Arch::kUnknown);
    bool recoverBranchTargets(const ElfImage& image, Address functionEntry,
                              const InsnRecord& record, std::vector<Address>* targets);
    const IndirectFlowSite* provenIndirectSite(Address functionEntry, Address site, bool call) const;
    Status proveIndirectFlow(const ElfImage& image, const Function& function, IndirectFlowReport* report) const;
    Status analyzeDiscovery(const ElfImage& image, const Options& options,
                           const std::map<Address, IndirectFlowReport>& proven);
    static bool sameProvenFlow(const IndirectFlowReport& a, const IndirectFlowReport& b);
    void adoptState(CodeAnalyzer&& state);

    Disassembler disassembler_;
    CodeMap code_;
    std::vector<Function> functions_;

    /// Entry addresses already queued as roots, so a call seen a thousand times
    /// is only queued once.
    std::unordered_set<Address> knownEntries_;

    /// Entry addresses descent has already run on. Distinct from knownEntries_
    /// because descent appends new roots as it goes, and those arrive without
    /// having passed through seedRoot.
    std::unordered_set<Address> analyzed_;

    /// Addresses that authoritatively begin a function: symbol table entries, PLT
    /// stubs, initialiser-array targets, the entry point. Reaching one of these
    /// ends the current function instead of extending it, which is what turns a
    /// tail call into a call rather than a merge.
    ///
    /// Only pre-descent sources go in here. Call targets discovered while
    /// descending are function entries too, but adding them as we go would make
    /// the result depend on the order functions happened to be visited in.
    std::unordered_set<Address> functionBoundaries_;
    std::vector<Address> sortedFunctionBoundaries_;

    std::unordered_map<Address, size_t> functionByEntry_;
    std::unordered_map<Address, size_t> functionByInstruction_;
    std::unordered_map<Address, std::vector<Address>> callers_;

    std::vector<std::string> warnings_;
    std::vector<AddressRange> excludedRanges_;
    std::vector<Address> userFunctionEntries_;
    std::vector<Address> debugFunctionEntries_;
    Arch imageArch_ = Arch::kUnknown;
    std::unordered_map<Address, Arch> branchModeHints_;
    std::unordered_map<Address, Arch> instructionArchitectures_;
    std::map<Address, IndirectFlowReport> indirectFlowReports_;
    bool followedCalls_ = true;
    bool linearSweepEnabled_ = true;
    size_t instructionLimit_ = 4000000;
    size_t functionLimit_ = 200000;
    bool hasState_ = false;
    Stats stats_;
};

}  // namespace mint
