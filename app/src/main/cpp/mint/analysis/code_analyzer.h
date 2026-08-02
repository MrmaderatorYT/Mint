#pragma once

#include <string>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "mint/analysis/cfg.h"
#include "mint/analysis/code_map.h"
#include "mint/analysis/function.h"
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
    };

    void collectRoots(const ElfImage& image, std::vector<Root>* roots);
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

    std::unordered_map<Address, size_t> functionByEntry_;
    std::unordered_map<Address, size_t> functionByInstruction_;
    std::unordered_map<Address, std::vector<Address>> callers_;

    std::vector<std::string> warnings_;
    Stats stats_;
};

}  // namespace mint
