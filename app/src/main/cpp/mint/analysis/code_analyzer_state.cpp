#include "mint/analysis/code_analyzer.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace mint {
namespace {

constexpr size_t kMaxRecords = 4000000;
constexpr size_t kMaxFunctions = 200000;
constexpr size_t kMaxMemberships = 8000000;
constexpr size_t kMaxRelations = 4000000;

Status invalidState(const std::string& detail) {
    return Status::error(ErrorCode::kBadFormat, "analysis snapshot: " + detail);
}

bool cancelled(const CodeAnalyzer::Options& options) {
    return options.cancel != nullptr && options.cancel->load(std::memory_order_relaxed);
}

bool sameRecord(const InsnRecord& a, const InsnRecord& b, bool instructionId = true) {
    return a.address == b.address && a.size == b.size && a.flow == b.flow &&
           a.target == b.target && (!instructionId || a.id == b.id);
}

bool sameRanges(const std::vector<CodeAnalyzer::AddressRange>& a,
                const std::vector<CodeAnalyzer::AddressRange>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].start != b[i].start || a[i].end != b[i].end) return false;
    }
    return true;
}

bool strictlySorted(const std::vector<Address>& addresses) {
    for (size_t i = 1; i < addresses.size(); ++i) {
        if (addresses[i - 1] >= addresses[i]) return false;
    }
    return true;
}

std::string generatedName(Address entry) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "sub_%llx", static_cast<unsigned long long>(entry));
    return buffer;
}

}  // namespace

Status CodeAnalyzer::prepareState(const ElfImage& image, const Options& options,
                                  std::vector<Root>* roots) {
    if (!image.loaded()) return invalidState("image was not loaded");
    if (options.userFunctionEntries.size() > kMaxFunctions || options.debugFunctionEntries.size() > kMaxFunctions || options.excludedRanges.size() > 100000) {
        return Status::error(ErrorCode::kTooLarge, "too many user function entries/data ranges");
    }
    std::vector<AddressRange> ranges = options.excludedRanges;
    // ARM-family mapping symbols explicitly delimit inline data. They are
    // authoritative compiler metadata, not a heuristic linear sweep.
    std::vector<const ElfSymbol*> mappings;
    for (const auto& symbol : image.symbols()) if (!symbol.undefined && symbol.isMappingSymbol()) mappings.push_back(&symbol);
    std::sort(mappings.begin(), mappings.end(), [](const auto* a, const auto* b) { return a->value < b->value; });
    for (size_t i = 0; i < mappings.size(); ++i) {
        const auto& symbol = *mappings[i];
        if (symbol.name[1] != 'd' || !image.memory().isExecutable(symbol.value)) continue;
        const auto* segment = image.memory().segmentAt(symbol.value);
        if (!segment || segment->start > std::numeric_limits<Address>::max() - segment->size) continue;
        Address end = segment->end();
        for (const auto& section : image.sections()) if (section.executable() && section.addr <= symbol.value &&
            section.addr <= std::numeric_limits<Address>::max() - section.size && symbol.value < section.addr + section.size)
            end = std::min(end, section.addr + section.size);
        if (i + 1 < mappings.size()) end = std::min(end, mappings[i + 1]->value);
        if (symbol.value < end) ranges.push_back({symbol.value, end});
    }
    for (const AddressRange& range : ranges) {
        if (range.start >= range.end) return invalidState("excluded range must have start < end");
    }
    std::sort(ranges.begin(), ranges.end(), [](const AddressRange& a, const AddressRange& b) {
        return a.start < b.start;
    });
    std::vector<AddressRange> normalized;
    for (const AddressRange& range : ranges) {
        if (!normalized.empty() && normalized.back().end >= range.start) {
            normalized.back().end = std::max(normalized.back().end, range.end);
        } else normalized.push_back(range);
    }
    std::vector<Address> entries = options.userFunctionEntries;
    std::unordered_map<Address, Arch> entryModes;
    for (Address& entry : entries) {
        if (entry != kNoAddress) entryModes[image.canonicalAddress(entry)] = image.architectureAt(entry);
        entry = image.canonicalAddress(entry);
    }
    std::sort(entries.begin(), entries.end());
    entries.erase(std::unique(entries.begin(), entries.end()), entries.end());
    for (Address entry : entries) {
        ArchitectureDescription description;
        if (entry == kNoAddress || !image.memory().isExecutable(entry) ||
            !architectureDescription(entryModes[entry], &description) || entry % description.instructionAlignment != 0) {
            return invalidState("user function entry is not executable/aligned");
        }
        const auto next = std::upper_bound(normalized.begin(), normalized.end(), entry,
            [](Address value, const AddressRange& range) { return value < range.start; });
        if (next != normalized.begin() && entry < (next - 1)->end) {
            return invalidState("user function entry lies in an excluded range");
        }
    }
    Status status = disassembler_.open(image.arch());
    if (!status.ok()) return status;
    code_ = CodeMap{};
    functions_.clear(); knownEntries_.clear(); analyzed_.clear();
    functionBoundaries_.clear(); sortedFunctionBoundaries_.clear();
    functionByEntry_.clear(); functionByInstruction_.clear(); callers_.clear();
    warnings_.clear(); stats_ = Stats{}; hasState_ = false;
    imageArch_ = image.arch();
    branchModeHints_ = std::move(entryModes);
    instructionArchitectures_.clear();
    indirectFlowReports_.clear();
    excludedRanges_ = std::move(normalized);
    userFunctionEntries_ = std::move(entries);
    debugFunctionEntries_.clear();
    for (Address pointer : options.debugFunctionEntries) {
        const Address entry = image.canonicalAddress(pointer);
        ArchitectureDescription description;
        if (pointer == kNoAddress || !image.memory().isExecutable(entry) || excluded(entry) ||
            !architectureDescription(image.architectureAt(pointer), &description) || entry % description.instructionAlignment != 0) continue;
        debugFunctionEntries_.push_back(entry);
        if (!branchModeHints_.count(entry)) branchModeHints_[entry] = image.architectureAt(pointer);
    }
    std::sort(debugFunctionEntries_.begin(), debugFunctionEntries_.end());
    debugFunctionEntries_.erase(std::unique(debugFunctionEntries_.begin(), debugFunctionEntries_.end()), debugFunctionEntries_.end());
    followedCalls_ = options.followCalls;
    linearSweepEnabled_ = options.linearSweepFallback;
    instructionLimit_ = options.maxInstructions;
    functionLimit_ = options.maxFunctions;
    roots->clear();
    for (Address entry : userFunctionEntries_) {
        functionBoundaries_.insert(entry);
        seedRoot(entry, FunctionOrigin::kUser, image.describeAddress(entry), roots);
    }
    collectRoots(image, options, roots);
    for (Root& root : *roots) if (root.decodeArch == Arch::kUnknown) root.decodeArch = image.architectureAt(root.address);
    return Status::success();
}

CodeAnalyzer::Snapshot CodeAnalyzer::snapshot() const {
    Snapshot result;
    result.instructions = code_.instructions();
    result.functions = functions_;
    // CFG is derived and is intentionally not a persisted part of the model.
    for (Function& function : result.functions) function.cfg = ControlFlowGraph{};
    result.warnings = warnings_;
    result.functionBoundaries = sortedFunctionBoundaries_;
    result.reachedInstructionLimit = stats_.reachedInstructionLimit != 0;
    return result;
}

void CodeAnalyzer::adoptState(CodeAnalyzer&& state) {
    code_ = std::move(state.code_);
    functions_ = std::move(state.functions_);
    knownEntries_ = std::move(state.knownEntries_);
    analyzed_ = std::move(state.analyzed_);
    functionBoundaries_ = std::move(state.functionBoundaries_);
    sortedFunctionBoundaries_ = std::move(state.sortedFunctionBoundaries_);
    functionByEntry_ = std::move(state.functionByEntry_);
    functionByInstruction_ = std::move(state.functionByInstruction_);
    callers_ = std::move(state.callers_);
    warnings_ = std::move(state.warnings_);
    excludedRanges_ = std::move(state.excludedRanges_);
    userFunctionEntries_ = std::move(state.userFunctionEntries_);
    debugFunctionEntries_ = std::move(state.debugFunctionEntries_);
    imageArch_ = state.imageArch_;
    branchModeHints_ = std::move(state.branchModeHints_);
    instructionArchitectures_ = std::move(state.instructionArchitectures_);
    indirectFlowReports_ = std::move(state.indirectFlowReports_);
    followedCalls_ = state.followedCalls_;
    linearSweepEnabled_ = state.linearSweepEnabled_;
    instructionLimit_ = state.instructionLimit_;
    functionLimit_ = state.functionLimit_;
    hasState_ = state.hasState_;
    stats_ = state.stats_;
}

Status CodeAnalyzer::restore(const ElfImage& image, const Options& options, const Snapshot& state) {
    if (state.instructions.size() > std::min(kMaxRecords, options.maxInstructions) ||
        state.functions.size() > std::min(kMaxFunctions, options.maxFunctions) ||
        state.functionBoundaries.size() > kMaxRecords || state.warnings.size() > 256) {
        return invalidState("record/function/warning limit exceeded");
    }
    for (const auto& warning : state.warnings) {
        if (warning.size() > 4096 || warning.find('\0') != std::string::npos) return invalidState("invalid warning text");
    }
    CodeAnalyzer prepared;
    std::vector<Root> roots;
    Status status = prepared.prepareState(image, options, &roots);
    if (!status.ok()) return status;
    if (!strictlySorted(state.functionBoundaries) ||
        state.functionBoundaries != prepared.sortedFunctionBoundaries_) {
        return invalidState("authoritative function boundaries changed");
    }
    size_t modeMemberships = 0;
    for (const Function& function : state.functions) {
        const bool arm = image.arch() == Arch::kArm32 || image.arch() == Arch::kThumb;
        ArchitectureDescription descriptor;
        if (!architectureDescription(function.decodeArch, &descriptor) ||
            (arm ? function.decodeArch != Arch::kArm32 && function.decodeArch != Arch::kThumb : function.decodeArch != image.arch()) ||
            function.instructions.size() > kMaxMemberships - modeMemberships)
            return invalidState("function architecture/membership is incompatible with image");
        modeMemberships += function.instructions.size();
        for (Address address : function.instructions) {
            const Arch mode = image.architectureAt(address, function.entry, function.decodeArch);
            const auto previous = prepared.instructionArchitectures_.emplace(address, mode);
            if (!previous.second && previous.first->second != mode) return invalidState("shared instruction has conflicting decode modes");
        }
    }
    Address previous = 0;
    for (size_t i = 0; i < state.instructions.size(); ++i) {
        if (cancelled(options)) return invalidState("restore cancelled");
        const InsnRecord& record = state.instructions[i];
        if ((i != 0 && record.address <= previous) || record.address == kNoAddress ||
            record.size == 0 || record.size > 16 ||
            static_cast<u8>(record.flow) > static_cast<u8>(FlowKind::kInvalid) ||
            record.address > std::numeric_limits<Address>::max() - record.size ||
            !image.memory().isExecutable(record.address) || prepared.excluded(record.address) ||
            prepared.decodeLimit(record.address, record.size) != record.size ||
            image.memory().viewAt(record.address, record.size).size() != record.size) {
            return invalidState("invalid instruction address/range/flow");
        }
        InsnRecord decoded;
        prepared.decodeRecord(image, record.address, &decoded);
        if (!sameRecord(record, decoded)) return invalidState("instruction does not match current bytes");
        previous = record.address;
        prepared.code_.insert(record);
    }
    prepared.code_.finalize();
    std::unordered_map<Address, Root> automatic;
    for (const Root& root : roots) automatic.emplace(root.address, root);
    size_t memberships = 0, relations = 0, resolvedRecords = 0;
    std::vector<u8> owners(state.instructions.size(), 0);
    previous = 0;
    for (size_t fi = 0; fi < state.functions.size(); ++fi) {
        if (cancelled(options)) return invalidState("restore cancelled");
        Function function = state.functions[fi];
        if ((fi != 0 && function.entry <= previous) || function.entry == kNoAddress ||
            !image.memory().isExecutable(function.entry) || prepared.excluded(function.entry) ||
            static_cast<u8>(function.origin) > static_cast<u8>(FunctionOrigin::kDwarf) ||
            function.name.size() > 4096 || function.name.find('\0') != std::string::npos ||
            !strictlySorted(function.instructions) || !strictlySorted(function.callees) ||
            function.instructions.size() > kMaxMemberships - memberships ||
            function.callees.size() > kMaxRelations - relations ||
            function.resolvedIndirectJumps.size() > kMaxFunctions - resolvedRecords) {
            return invalidState("invalid function entry/origin/body/relations");
        }
        previous = function.entry;
        memberships += function.instructions.size(); relations += function.callees.size();
        resolvedRecords += function.resolvedIndirectJumps.size();
        const auto root = automatic.find(function.entry);
        if (root != automatic.end()) {
            const std::string expected = root->second.name.empty() ? generatedName(function.entry) : root->second.name;
            if (function.origin != root->second.origin || function.name != expected || function.decodeArch != root->second.decodeArch)
                return invalidState("function provenance/name/mode differs from roots");
        } else if (function.origin != FunctionOrigin::kCallTarget && function.origin != FunctionOrigin::kLinearSweep) {
            return invalidState("function has unsupported provenance");
        }
        const auto modeHint = prepared.branchModeHints_.find(function.entry);
        if (modeHint != prepared.branchModeHints_.end() && modeHint->second != function.decodeArch)
            return invalidState("function mode differs from encoded call/branch target");
        if (function.origin == FunctionOrigin::kLinearSweep &&
            (!options.linearSweepFallback || image.arch() != Arch::kAArch64)) return invalidState("disabled sweep provenance");
        if (function.instructions.empty()) {
            if (!function.incomplete || function.lowAddress != function.entry || function.highAddress != function.entry ||
                !function.callees.empty() || !function.resolvedIndirectJumps.empty() || function.indirectJumps || function.undecodableSites ||
                (!state.reachedInstructionLimit && !image.memory().viewAt(function.entry, 1).empty())) {
                return invalidState("empty function is not a bounded incomplete placeholder");
            }
            function.cfg = ControlFlowGraph{};
            prepared.functions_.push_back(std::move(function));
            continue;
        }
        if (!std::binary_search(function.instructions.begin(), function.instructions.end(), function.entry)) return invalidState("function does not own its entry");
        Address low = function.entry, high = function.entry;
        u32 indirectCount = 0, invalidCount = 0;
        std::map<Address, std::vector<Address>> resolved;
        for (const auto& jump : function.resolvedIndirectJumps) {
            if (jump.targets.size() > kMaxRelations - relations || !resolved.emplace(jump.branch, jump.targets).second) return invalidState("invalid resolved branch list");
            relations += jump.targets.size();
        }
        // Saved targets only describe a candidate CFG. Re-lift exact current
        // bytes and prove its finite target sets before any cached edge or
        // recovered call is trusted. A self-supporting seedless SSA cycle is
        // explicitly unknown in the finite-set pass.
        function.cfg = ControlFlowGraph::build(prepared.code_, function.instructions, function.entry, function.resolvedIndirectJumps);
        IndirectFlowReport proof;
        prepared.proveIndirectFlow(image, function, &proof);
        if (!proof.sites.empty()) {
            for (const auto& site : proof.sites) if (site.complete)
                for (const auto& target : site.targets) prepared.branchModeHints_[target.address] = target.decodeArch;
            prepared.indirectFlowReports_[function.entry] = std::move(proof);
        }
        for (Address address : function.instructions) {
            const InsnRecord* record = prepared.code_.find(address);
            if (record == nullptr) return invalidState("function owns a missing instruction");
            owners[prepared.code_.lowerBound(address)] = 1;
            low = std::min(low, address); high = std::max(high, record->next());
            invalidCount += record->flow == FlowKind::kInvalid;
            indirectCount += record->flow == FlowKind::kIndirectJump;
            const auto saved = resolved.find(address);
            if (record->flow == FlowKind::kIndirectJump) {
                std::vector<Address> targets;
                const bool found = prepared.recoverBranchTargets(image, function.entry, *record, &targets);
                if (found != (saved != resolved.end()) || (found && saved->second != targets)) return invalidState("indirect branch recovery differs from current image");
            } else if (saved != resolved.end()) return invalidState("resolved entry is not an indirect branch");
        }
        for (const auto& jump : resolved) if (!std::binary_search(function.instructions.begin(), function.instructions.end(), jump.first)) return invalidState("resolved branch is outside its function");
        if (function.lowAddress != low || function.highAddress != high || function.indirectJumps != indirectCount || function.undecodableSites != invalidCount) return invalidState("function extent/statistics mismatch");

        std::unordered_set<Address> reached, callees;
        std::vector<Address> pending{function.entry};
        bool incomplete = false, missing = false;
        auto follow = [&](Address address) {
            if (prepared.excluded(address)) return;
            const auto mode = prepared.branchModeHints_.find(address);
            const bool interworking = (function.decodeArch == Arch::kArm32 || function.decodeArch == Arch::kThumb) &&
                mode != prepared.branchModeHints_.end() && mode->second != function.decodeArch;
            if ((address != function.entry && prepared.functionBoundaries_.count(address)) || interworking) { callees.insert(address); return; }
            if (!std::binary_search(function.instructions.begin(), function.instructions.end(), address)) {
                if (!image.memory().isExecutable(address) || image.memory().viewAt(address, 1).empty() || state.reachedInstructionLimit) incomplete = true;
                else missing = true;
                return;
            }
            pending.push_back(address);
        };
        while (!pending.empty()) {
            const Address address = pending.back(); pending.pop_back();
            if (!reached.insert(address).second) continue;
            const InsnRecord& record = *prepared.code_.find(address);
            switch (record.flow) {
                case FlowKind::kNormal: follow(record.next()); break;
                case FlowKind::kCondJump:
                    follow(record.next());
                    if (record.hasKnownTarget()) follow(record.target); else incomplete = true;
                    break;
                case FlowKind::kJump:
                    if (record.hasKnownTarget()) follow(record.target); else incomplete = true;
                    break;
                case FlowKind::kCall: case FlowKind::kIndirectCall:
                    if (record.hasKnownTarget() && !prepared.excluded(record.target)) callees.insert(record.target);
                    if (record.flow == FlowKind::kIndirectCall)
                        if (const auto* site = prepared.provenIndirectSite(function.entry, address, true))
                            for (const auto& target : site->targets) if (!prepared.excluded(target.address)) callees.insert(target.address);
                    follow(record.next()); break;
                case FlowKind::kIndirectJump: {
                    const auto jump = resolved.find(address);
                    if (jump == resolved.end()) incomplete = true;
                    else for (Address target : jump->second) follow(target);
                    break;
                }
                case FlowKind::kInvalid: incomplete = true; break;
                case FlowKind::kReturn: case FlowKind::kTrap: break;
            }
        }
        std::vector<Address> expectedCallees(callees.begin(), callees.end());
        std::sort(expectedCallees.begin(), expectedCallees.end());
        if (missing || reached.size() != function.instructions.size() || expectedCallees != function.callees ||
            (incomplete && !function.incomplete) || (!incomplete && function.incomplete && !state.reachedInstructionLimit)) {
            return invalidState("function reachability/callees/completeness mismatch");
        }
        function.cfg = ControlFlowGraph::build(prepared.code_, function.instructions, function.entry, function.resolvedIndirectJumps);
        prepared.functions_.push_back(std::move(function));
    }
    if (std::find(owners.begin(), owners.end(), u8(0)) != owners.end()) return invalidState("unowned global code record");
    prepared.warnings_ = state.warnings;
    prepared.stats_ = Stats{};
    for (const Function& function : prepared.functions_) {
        prepared.knownEntries_.insert(function.entry); prepared.analyzed_.insert(function.entry);
        prepared.stats_.blocks += function.cfg.size(); prepared.stats_.edges += function.cfg.edgeCount();
        prepared.stats_.indirectJumps += function.indirectJumps; prepared.stats_.undecodableSites += function.undecodableSites;
        prepared.stats_.incompleteFunctions += function.incomplete;
        prepared.stats_.functionsFromSweep += function.origin == FunctionOrigin::kLinearSweep;
    }
    prepared.stats_.instructions = prepared.code_.size(); prepared.stats_.functions = prepared.functions_.size();
    prepared.stats_.reachedInstructionLimit = state.reachedInstructionLimit ? 1 : 0;
    prepared.hasState_ = true;
    prepared.buildIndexes();
    status = disassembler_.open(image.arch());
    if (!status.ok()) return status;
    adoptState(std::move(prepared));
    if (options.progress) options.progress->store(100, std::memory_order_relaxed);
    return Status::success();
}

Status CodeAnalyzer::reanalyzeChanged(const ElfImage& image, const Options& options,
                                      const std::vector<AddressRange>& dirtyRanges,
                                      IncrementalResult* result) {
    IncrementalResult local;
    if (result == nullptr) result = &local;
    *result = {};
    auto fallback = [&](const std::string& reason) {
        result->reason = reason; result->used = false;
        const Status status = analyze(image, options);
        result->functionsReanalyzed = functions_.size();
        return status;
    };
    if (!hasState_ || !code_.finalized() || imageArch_ != image.arch()) return fallback("no compatible prior analysis");
    if (stats_.reachedInstructionLimit || functions_.size() >= options.maxFunctions) return fallback("prior analysis reached a resource limit");
    if (dirtyRanges.empty() || dirtyRanges.size() > 100000) return fallback("no bounded instruction patch range");
    CodeAnalyzer prepared;
    std::vector<Root> roots;
    Status status = prepared.prepareState(image, options, &roots);
    if (!status.ok()) return status;
    if (userFunctionEntries_ != prepared.userFunctionEntries_ || debugFunctionEntries_ != prepared.debugFunctionEntries_ || !sameRanges(excludedRanges_, prepared.excludedRanges_) ||
        followedCalls_ != options.followCalls || linearSweepEnabled_ != options.linearSweepFallback ||
        instructionLimit_ != options.maxInstructions || functionLimit_ != options.maxFunctions ||
        sortedFunctionBoundaries_ != prepared.sortedFunctionBoundaries_) return fallback("analysis options or authoritative roots/data boundaries changed");

    std::vector<AddressRange> dirty = dirtyRanges;
    for (const auto& range : dirty) if (range.start >= range.end) return fallback("invalid dirty byte range");
    std::sort(dirty.begin(), dirty.end(), [](const AddressRange& a, const AddressRange& b) { return a.start < b.start; });
    std::vector<AddressRange> merged;
    for (const auto& range : dirty) {
        if (!merged.empty() && merged.back().end >= range.start) merged.back().end = std::max(merged.back().end, range.end);
        else merged.push_back(range);
    }
    std::unordered_set<Address> changedInstructions;
    auto knownData = [&](Address start, Address end) {
        if (start >= end) return true;
        const auto* segment = image.memory().segmentAt(start);
        if (!segment || end > segment->end() || image.memory().viewAt(start, end - start).size() != end - start ||
            image.memory().hasOverlaps()) return false;
        if (!segment->executable()) return true;
        const auto upper = std::upper_bound(excludedRanges_.begin(), excludedRanges_.end(), start,
            [](Address address, const AddressRange& range) { return address < range.start; });
        return upper != excludedRanges_.begin() && std::prev(upper)->end >= end;
    };
    for (const auto& range : merged) {
        Address covered = range.start;
        const Address earliest = range.start > 24 ? range.start - 24 : 0;
        for (size_t i = code_.lowerBound(earliest); i < code_.size(); ++i) {
            const InsnRecord& record = code_.instructions()[i];
            if (record.address >= range.end) break;
            if (record.next() <= range.start) continue;
            if (record.address > covered && !knownData(covered, record.address)) return fallback("patch includes unclassified code/data gap");
            changedInstructions.insert(record.address);
            covered = std::max(covered, record.next());
        }
        if (covered < range.end && !knownData(covered, range.end)) return fallback("patch includes bytes outside known instructions/authoritative data");
    }
    std::unordered_set<Address> affected;
    for (const Function& function : functions_) {
        for (Address address : function.instructions) {
            if (changedInstructions.count(address)) { affected.insert(function.entry); break; }
        }
    }
    if (affected.empty() && !changedInstructions.empty()) return fallback("patched instructions have no known function owners");
    prepared.indirectFlowReports_ = indirectFlowReports_;
    for (const auto& item : branchModeHints_) prepared.branchModeHints_.emplace(item);
    for (const Function& function : functions_) {
        const auto saved = indirectFlowReports_.find(function.entry);
        if (saved == indirectFlowReports_.end()) continue;
        bool dependent = affected.count(function.entry) != 0;
        if (!dependent) for (const auto& site : saved->second.sites) for (const auto& dependency : site.dependencies)
            for (const auto& range : merged) if (dependency.start < range.end && range.start < dependency.end) dependent = true;
        if (!dependent) continue;
        if (cancelled(options)) return invalidState("incremental indirect proof cancelled");
        IndirectFlowReport current;
        proveIndirectFlow(image, function, &current);
        if (!sameProvenFlow(saved->second, current)) return fallback("general indirect-flow target dependency changed");
        prepared.indirectFlowReports_[function.entry] = std::move(current);
    }
    for (const Function& old : functions_) {
        if (!affected.count(old.entry)) continue;
        if (old.incomplete || old.instructions.empty()) return fallback("affected function has unresolved/incomplete flow");
        std::vector<Root> pending;
        prepared.descend(image, options, Root{old.entry, old.origin, old.name, old.decodeArch}, &pending);
        if (cancelled(options)) return invalidState("incremental analysis cancelled");
        if (prepared.functions_.empty() || prepared.functions_.back().entry != old.entry) return fallback("affected function no longer decodes");
        const Function& replacement = prepared.functions_.back();
        if (replacement.decodeArch != old.decodeArch || replacement.instructions != old.instructions || replacement.callees != old.callees ||
            replacement.incomplete != old.incomplete || replacement.indirectJumps != old.indirectJumps ||
            replacement.undecodableSites != old.undecodableSites || replacement.lowAddress != old.lowAddress || replacement.highAddress != old.highAddress ||
            replacement.resolvedIndirectJumps.size() != old.resolvedIndirectJumps.size()) return fallback("patched function flow topology changed");
        std::map<Address, std::vector<Address>> oldTargets, newTargets;
        for (const auto& jump : old.resolvedIndirectJumps) oldTargets.emplace(jump.branch, jump.targets);
        for (const auto& jump : replacement.resolvedIndirectJumps) newTargets.emplace(jump.branch, jump.targets);
        if (oldTargets != newTargets) return fallback("patched indirect targets changed");
    }
    prepared.code_.finalize();
    for (const Function& function : prepared.functions_) {
        for (Address address : function.instructions) {
            const InsnRecord* old = code_.find(address);
            const InsnRecord* replacement = prepared.code_.find(address);
            if (old == nullptr || replacement == nullptr || !sameRecord(*old, *replacement, false)) return fallback("instruction size/flow/target changed");
        }
    }

    // Immutable pointer slots and switch tables may live outside their owning
    // function. Check every unaffected indirect dependency before reusing it.
    for (const Function& function : functions_) {
        if (affected.count(function.entry)) continue;
        std::map<Address, std::vector<Address>> saved;
        for (const auto& jump : function.resolvedIndirectJumps) saved.emplace(jump.branch, jump.targets);
        for (Address address : function.instructions) {
            const InsnRecord* old = code_.find(address);
            if (old->flow != FlowKind::kIndirectCall && old->flow != FlowKind::kIndirectJump) continue;
            InsnRecord current;
            prepared.decodeRecord(image, address, &current, function.entry, function.decodeArch);
            if (!sameRecord(*old, current)) return fallback("unaffected indirect pointer dependency changed");
            if (old->flow == FlowKind::kIndirectJump) {
                std::vector<Address> targets;
                const bool recovered = prepared.recoverBranchTargets(image, function.entry, current, &targets);
                const auto previous = saved.find(address);
                if (recovered != (previous != saved.end()) || (recovered && previous->second != targets)) return fallback("unaffected switch-table dependency changed");
            }
        }
    }
    CodeMap combined;
    for (const InsnRecord& old : code_.instructions()) {
        const InsnRecord* replacement = prepared.code_.find(old.address);
        combined.insert(replacement ? *replacement : old);
    }
    combined.finalize();
    std::unordered_map<Address, Function> replacements;
    for (Function& function : prepared.functions_) replacements.emplace(function.entry, std::move(function));
    prepared.code_ = std::move(combined);
    prepared.functions_ = functions_;
    for (const auto& item : instructionArchitectures_) prepared.instructionArchitectures_.emplace(item);
    for (Function& function : prepared.functions_) {
        const auto replacement = replacements.find(function.entry);
        if (replacement != replacements.end()) {
            // Address membership, instruction sizes and every flow target were
            // proved unchanged, so global CodeMap indexes and existing CFGs stay
            // valid. Only the instruction records/semantic lifting must change.
            const ControlFlowGraph cfg = function.cfg;
            function = std::move(replacement->second); function.cfg = cfg;
        }
        prepared.knownEntries_.insert(function.entry); prepared.analyzed_.insert(function.entry);
    }
    prepared.warnings_ = warnings_;
    prepared.stats_ = stats_;
    prepared.hasState_ = true;
    prepared.buildIndexes();
    adoptState(std::move(prepared));
    result->used = true; result->functionsReanalyzed = affected.size();
    result->reason = affected.empty() ? "authoritative data-only patch with unchanged indirect-flow dependencies" :
        "instruction-only patch with unchanged flow topology";
    if (options.progress) options.progress->store(100, std::memory_order_relaxed);
    return Status::success();
}

}  // namespace mint
