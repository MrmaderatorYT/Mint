#include "mint/session.h"

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <map>
#include <unordered_map>

#include "mint/analysis/jump_table_recovery.h"
#include "mint/base/log.h"
#include "mint/ir/lifter_dalvik.h"
#include "mint/ir/registers.h"
#include "mint/obfuscation/deobfuscator.h"

namespace mint {

void Session::beginOpen() {
    pluginEventWarnings_.clear();
    externalDebugDigest_.clear();
    // Opening replaces the file mapping. Never carry a project/cache identity or
    // borrowed memory blocks over to a different source, even after a failed open.
    loaded_=false;analyzed_=false;program_=Program{};programReport_={};
    // Explicitly trusted extensions belong to this Session, not its current
    // Program. Fresh Sessions never auto-load plugins from a project. Keeping
    // these here also allows decoder plugins to be loaded before raw import.
    debugger_.disconnect();comparison_.reset();tracking_={};
    prototypeEvidence_={};prototypeEvidenceBuilt_=false;
    signatures_=SignatureLibrary{};
    analysisCachePath_.clear();analysisCacheDiagnostic_.clear();
    analysisMode_="none";analysisReason_.clear();analysisFunctionsUpdated_=0;
    allowCacheRestore_=true;detectorFindings_.clear();debugInfo_={};referenceGroupsUpdated_=0;
    cancel_.store(false);progress_.store(0);kind_=InputKind::kElf;image_=ElfImage{};
}

Status Session::openPath(const std::string& path) {
    beginOpen();
    Status status = file_.open(path);
    if (!status.ok()) return status;
    return finishOpen();
}

Status Session::openFd(int fd) {
    beginOpen();
    Status status = file_.openFd(fd);
    if (!status.ok()) return status;
    return finishOpen();
}

Status Session::finishOpen() {
    const ByteView data = file_.view();
    if (data.size() >= 4 && std::memcmp(data.data(), "dex\n", 4) == 0) {
        Status status = dex_.load(data);
        if (!status.ok()) return status;
        kind_ = InputKind::kDex;
        loaded_ = true;
        return Status::success();
    }

    if (data.size() >= 4 && data.data()[0] == 'P' && data.data()[1] == 'K') {
        Status status = zip_.open(data);
        if (!status.ok()) return status;
        status = zip_.extract("classes.dex", &dexStorage_);
        if (!status.ok()) return Status::error(
            ErrorCode::kBadFormat, "APK has no readable classes.dex: " + status.toString());
        status = dex_.load(ByteView(dexStorage_.data(), dexStorage_.size()));
        if (!status.ok()) return status;
        kind_ = InputKind::kApk;
        loaded_ = true;
        return Status::success();
    }

    Status status = image_.load(data);
    if (!status.ok()) return status;

    // The renderer is opened here rather than lazily so a failure to get a
    // decoder surfaces at open time, when there is still a sensible error to
    // show, instead of as a blank listing later.
    status = renderer_.open(image_.arch());
    if (!status.ok()) return status;
    // A decoder plugin need not supply lifting semantics; listing remains usable.
    if(lifter_.ready() && lifter_.arch()!=image_.arch())lifter_.open(image_.arch());
    loadDebugInfo();

    loaded_ = true;
    return Status::success();
}

Status Session::analyze() {
    if (!loaded_) {
        return Status::error(ErrorCode::kInternalError, "session has no open file");
    }
    if (analyzed_) return Status::success();
    if (cancel_.load(std::memory_order_relaxed)) {
        return Status::error(ErrorCode::kInternalError, "analysis cancelled");
    }
    progress_.store(10, std::memory_order_relaxed);

    if (isDexLike()) {
        analyzed_ = true;
        progress_.store(100, std::memory_order_relaxed);
        return Status::success();
    }

    const auto options=analysisOptions();
    const bool restored=restoreAnalysisCache(options);
    if(!restored) {
        Status status=analyzer_.analyze(image_,options);
        if(!status.ok()) return status;
        analysisMode_="full";analysisFunctionsUpdated_=analyzer_.functions().size();
        analysisReason_="full native discovery";
    }
    // Existing detectors remain available for ELF, but never drive the program model.
    if (image_.format()==ImageFormat::kElf64) detectorFindings_ = runDetectors(image_);
    program_.bindMemory(image_.memory());
    analyzed_ = true;
    if(!restored) saveAnalysisCache();
    notifyPluginEvent(MINT_EVENT_ANALYSIS_COMPLETED,image_.entryPoint(),restored?"restored analysis":"native discovery");
    return Status::success();
}

bool Session::renderInstruction(Address addr, DecodedInsn* out) {
    if (!loaded_) return false;
    const auto mode=image_.architectureAt(addr);
    if(renderer_.arch()!=mode && !renderer_.open(mode).ok())return false;
    addr=image_.canonicalAddress(addr);
    ByteView bytes = image_.memory().viewAt(addr, renderer_.maxInstructionSize());
    if (bytes.empty()) return false;
    return renderer_.decodeVerbose(addr, bytes, out);
}

std::string Session::commentFor(const InsnRecord& record) const {
    if (!record.hasKnownTarget()) return {};
    std::string name = nameAt(record.target);
    if (name.empty()) return {};

    switch (record.flow) {
        case FlowKind::kCall:
            return name;
        case FlowKind::kJump:
        case FlowKind::kCondJump:
            // A branch inside the same function is noise in the comment column —
            // the target address is already on the line, and the graph view is
            // where intra-function flow belongs.
            if (analyzer_.functionContaining(record.target) ==
                analyzer_.functionContaining(record.address)) {
                return {};
            }
            return name;
        default:
            return name;
    }
}

std::string Session::irTextFor(Address address) {
    if (!analyzed_) return {};

    if (isDexLike()) {
        const u32 index = dexMethodIndex(address);
        if (index >= dex_.methods().size()) return {};
        IrFunction ir;
        const Status status = liftDalvik(dex_.methods()[index], &ir);
        return status.ok() ? ir.toText() : "Dalvik lifting failed: " + status.toString();
    }

    const Function* function = analyzer_.functionContaining(address);
    if (function == nullptr) function = analyzer_.functionAt(address);
    if (function == nullptr) return {};

    if (!lifter_.ready()) {
        const Status status = lifter_.open(image_.arch());
        if (!status.ok()) return "no lifter for " + std::string(archName(image_.arch()));
    }

    IrFunction ir;
    const Status status = lifter_.liftFunction(*function, image_.memory(), &ir);
    if (!status.ok()) return "lifting failed: " + status.toString();

    JumpTableRecovery recovery;
    recoverJumpTables(image_, ir, &recovery);
    augmentIrCfg(&ir, recovery);
    std::string out = ir.toText();

    // The verifier's findings belong in the UI, not just in tests: IR that fails
    // structural checks is a lifter bug, and anything shown above it — a
    // decompilation, an emulation result — should be read with that in mind.
    const std::vector<std::string> problems = ir.verify();
    if (!problems.empty()) {
        out += "\n! this IR failed " + std::to_string(problems.size()) +
               " structural checks; treat anything derived from it as unreliable\n";
        for (const std::string& problem : problems) out += "!   " + problem + "\n";
    }
    return out;
}

std::string Session::decompiledCFor(Address address) {
    if (!analyzed_) return {};
    notifyPluginEvent(MINT_EVENT_BEFORE_DECOMPILE,address,"requested pseudo-C");

    if (isDexLike()) {
        const u32 index = dexMethodIndex(address);
        if (index >= dex_.methods().size()) return {};
        IrFunction ir;
        Status status = liftDalvik(dex_.methods()[index], &ir);
        if (!status.ok()) return "decompiler lifting failed: " + status.toString();
        DecompileResult result;
        const DeobfuscationResult obfuscation = deobfuscate(&ir);
        status = decompileIr(ir, &result);
        if (!status.ok()) return "decompiler failed: " + status.toString();
        if (!obfuscation.findings.empty()) {
            result.cSource = "/* OLLVM findings: " + std::to_string(obfuscation.findings.size()) +
                             ", dispatcher blocks: " + std::to_string(obfuscation.unroll.dispatcherBlocks) +
                             " */\n" + result.cSource;
        }
        return result.cSource;
    }

    const Function* function = analyzer_.functionContaining(address);
    if (function == nullptr) function = analyzer_.functionAt(address);
    if (function == nullptr) return {};
    if (!lifter_.ready()) {
        const Status status = lifter_.open(image_.arch());
        if (!status.ok()) return "decompiler: no lifter for " + std::string(archName(image_.arch()));
    }
    IrFunction ir;
    Status status = lifter_.liftFunction(*function, image_.memory(), &ir);
    if (!status.ok()) return "decompiler lifting failed: " + status.toString();
    JumpTableRecovery recovery;
    recoverJumpTables(image_, ir, &recovery);
    augmentIrCfg(&ir, recovery);
    DecompileResult result;
    const DeobfuscationResult obfuscation = deobfuscate(&ir);
    ir.name = nameAt(ir.entry);
    status = decompileIr(
        ir, &result,
        [this](Address target) { return nameAt(target); },
        [this](Address data) { return stringAt(data); },
        [this](Address base) { return offsetTableText(base); },
        [this](Address target) { return prototypeAt(target); },
        [this](const std::string& type,DataTypeLayout* layout) {return program_.types().resolve(type,layout);},
        [this](Address entry) {return program_.locals(entry);});
    if (!status.ok()) return "decompiler failed: " + status.toString();
    std::string userComment=program_.get(function->entry,"comment");
    if (!userComment.empty()) {
        size_t at=0; while ((at=userComment.find("*/",at))!=std::string::npos) {userComment.replace(at,2,"* /");at+=3;}
        result.cSource="/* User comment: "+userComment+" */\n"+result.cSource;
    }
    if (!obfuscation.findings.empty()) {
        result.cSource = "/* OLLVM findings: " + std::to_string(obfuscation.findings.size()) +
                         ", dispatcher blocks: " + std::to_string(obfuscation.unroll.dispatcherBlocks) +
                         " */\n" + result.cSource;
    }
    if(image_.format()==ImageFormat::kPe64)result.cSource="/* PE: authoritative prototypes use explicit target ABI storage; undeclared signatures remain uncertain. Unmodeled instructions and exception semantics require listing/IR verification. */\n"+result.cSource;
    else if(image_.format()==ImageFormat::kMachO64)result.cSource="/* EXPERIMENTAL Mach-O: dyld fixups and platform exception/ABI metadata are incomplete. */\n"+result.cSource;
    const auto source=sourceLocationText(function->entry);
    if(!source.empty()) {
        std::string safe=source;size_t at=0;
        while((at=safe.find("*/",at))!=std::string::npos){safe.replace(at,2,"* /");at+=3;}
        result.cSource="/* DWARF source: "+safe+" */\n"+result.cSource;
    }
    if(!program_.types().definitions().empty()) {
        std::string header;const auto status=program_.types().cHeader(&header);
        if(status.ok())result.cSource=header+'\n'+result.cSource;
        else result.cSource="/* C type export unavailable; consult the Data Type Manager. */\n"+result.cSource;
    }
    notifyPluginEvent(MINT_EVENT_AFTER_DECOMPILE,address,"pseudo-C available");
    return result.cSource;
}

std::string Session::cfgTextFor(Address address) {
    if (!analyzed_) return {};

    IrFunction ir;
    if (isDexLike()) {
        const u32 index = dexMethodIndex(address);
        if (index >= dex_.methods().size()) return {};
        const Status status = liftDalvik(dex_.methods()[index], &ir);
        if (!status.ok()) return "CFG lifting failed: " + status.toString();
    } else {
        const Function* function = analyzer_.functionContaining(address);
        if (function == nullptr) function = analyzer_.functionAt(address);
        if (function == nullptr) return {};
        if (!lifter_.ready()) {
            const Status status = lifter_.open(image_.arch());
            if (!status.ok()) return "CFG: no lifter for " + std::string(archName(image_.arch()));
        }
        const Status status = lifter_.liftFunction(*function, image_.memory(), &ir);
        if (!status.ok()) return "CFG lifting failed: " + status.toString();
        JumpTableRecovery recovery;
        recoverJumpTables(image_, ir, &recovery);
        augmentIrCfg(&ir, recovery);
    }

    std::string out;
    for (const IrBlock& block : ir.blocks) {
        out += std::to_string(block.id) + " " + std::to_string(block.start) + " " +
               std::to_string(block.end);
        for (u32 successor : block.successors) out += " " + std::to_string(successor);
        out += "\n";
    }
    return out;
}

namespace {

/// One written slot: a byte offset from some base, its width, and how many store
/// instructions land on it.
struct WriteSlot {
    i64 offset = 0;
    u8 width = 0;
    u32 count = 0;
};

/// A density bar. Five levels rather than a number, because the point of the map is
/// to be scanned rather than read: the eye finds the tall bar before it finds the
/// largest integer in a column.
const char* densityBar(u32 count, u32 busiest) {
    if (busiest == 0) return "";
    // Bars are relative to the busiest slot in the group, so with no variation
    // there is nothing to show. Normalising anyway would draw every slot at full
    // height and make a uniform function look like a hot spot.
    if (busiest < 2) return "#";
    const u32 step = (count * 5 + busiest - 1) / busiest;
    switch (step) {
        case 0:
        case 1: return "#";
        case 2: return "##";
        case 3: return "###";
        case 4: return "####";
        default: return "#####";
    }
}

}  // namespace

/// Functions the whole-program pass will lift before it stops.
///
/// A cap because this runs while the user waits, and a large library is thousands
/// of functions. Whatever is skipped gets said out loud — a report that quietly
/// covers half a program reads as covering all of it.
static constexpr size_t kProgramReportLimit = 1500;

void Session::buildProgramReport() {
    if (programReport_.built) return;
    programReport_.built = true;
    if (!analyzed_ || isDexLike()) return;
    if (!lifter_.ready() && !lifter_.open(image_.arch()).ok()) return;

    const std::vector<Function>& functions = analyzer_.functions();
    const size_t examined = std::min(functions.size(), kProgramReportLimit);

    u64 machineInsns = 0;
    u64 intrinsics = 0;
    size_t fullyModelled = 0;
    size_t liftFailures = 0;
    // Count plus one example address per opcode: the id alone cannot be turned
    // back into a mnemonic, so the report decodes a real instruction to name it.
    std::map<u16, std::pair<u32, Address>> unmodelled;

    // name, slots, bytes — collected per function so the busiest writers can be
    // ranked without keeping every slot in memory.
    struct Writer {
        const Function* function;
        u32 slots;
        u64 bytes;
    };
    std::vector<Writer> writers;

    for (size_t i = 0; i < examined; ++i) {
        const Function& function = functions[i];
        IrFunction ir;
        if (!lifter_.liftFunction(function, image_.memory(), &ir).ok()) {
            ++liftFailures;
            continue;
        }
        machineInsns += function.instructionCount();
        intrinsics += ir.intrinsicCount;
        if (ir.intrinsicCount == 0) ++fullyModelled;
        for (const IrInsn& insn : ir.insns) {
            if (insn.op != MintOp::kIntrinsic) continue;
            auto& entry = unmodelled[insn.intrinsicId];
            ++entry.first;
            if (entry.second == 0) entry.second = insn.address;
        }

        u32 slots = 0;
        u64 bytes = 0;
        for (const IrInsn& insn : ir.insns) {
            if (insn.op != MintOp::kStore) continue;
            ++slots;
            bytes += insn.b.size;
        }
        if (slots != 0) writers.push_back(Writer{&function, slots, bytes});
    }

    char line[256];
    const auto note = [&](std::string& out) {
        if (examined < functions.size()) {
            std::snprintf(line, sizeof(line),
                          "\n/* covers the first %zu of %zu functions */\n", examined,
                          functions.size());
            out += line;
        }
        if (liftFailures != 0) {
            std::snprintf(line, sizeof(line), "/* %zu function(s) failed to lift */\n",
                          liftFailures);
            out += line;
        }
    };

    // ---- coverage, for the IR pane
    {
        std::string& out = programReport_.coverage;
        out = "/* lifter coverage */\n\n";
        std::snprintf(line, sizeof(line), "%-26s %12llu\n", "machine instructions",
                      static_cast<unsigned long long>(machineInsns));
        out += line;
        std::snprintf(line, sizeof(line), "%-26s %12llu\n", "lifted to intrinsics",
                      static_cast<unsigned long long>(intrinsics));
        out += line;
        std::snprintf(line, sizeof(line), "%-26s %11.2f%%\n", "of machine instructions",
                      machineInsns == 0 ? 0.0
                                        : 100.0 * double(intrinsics) / double(machineInsns));
        out += line;
        std::snprintf(line, sizeof(line), "%-26s %6zu / %zu\n", "fully modelled functions",
                      fullyModelled, examined);
        out += line;

        // The analysis counters live here rather than in a separate overview: how
        // many blocks were found, and how many functions the descent could not
        // finish, are the same question as coverage — how much of the program the
        // engine actually understood.
        const CodeAnalyzer::Stats& stats = analyzer_.stats();
        out += "\n/* analysis */\n";
        const auto counter = [&](const char* label, size_t value) {
            std::snprintf(line, sizeof(line), "%-26s %12zu\n", label, value);
            out += line;
        };
        counter("functions", stats.functions);
        counter("basic blocks", stats.blocks);
        counter("CFG edges", stats.edges);
        counter("indirect jumps", stats.indirectJumps);
        counter("undecodable sites", stats.undecodableSites);
        counter("incomplete functions", stats.incompleteFunctions);
        counter("found by sweep", stats.functionsFromSweep);

        std::vector<std::pair<u16, std::pair<u32, Address>>> ranked(unmodelled.begin(),
                                                                     unmodelled.end());
        std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
            return a.second.first > b.second.first;
        });
        if (!ranked.empty()) {
            out += "\n/* what is left, by payoff */\n";
            const size_t shown = std::min<size_t>(ranked.size(), 15);
            for (size_t i = 0; i < shown; ++i) {
                DecodedInsn decoded;
                const std::string name =
                    renderInstruction(ranked[i].second.second, &decoded)
                        ? decoded.mnemonic
                        : "id " + std::to_string(ranked[i].first);
                std::snprintf(line, sizeof(line), "  %5u  %s\n", ranked[i].second.first,
                              name.c_str());
                out += line;
            }
            std::snprintf(line, sizeof(line), "  (%zu distinct opcodes)\n", ranked.size());
            out += line;
        } else if (machineInsns != 0) {
            out += "\nEvery instruction in this program was modelled.\n";
        }
        note(out);
    }

    // ---- write ranking, for the Writes pane
    {
        std::string& out = programReport_.writes;
        std::sort(writers.begin(), writers.end(),
                  [](const Writer& a, const Writer& b) { return a.bytes > b.bytes; });
        u64 totalSlots = 0;
        u64 totalBytes = 0;
        for (const Writer& writer : writers) {
            totalSlots += writer.slots;
            totalBytes += writer.bytes;
        }

        out = "/* what this program writes */\n\n";
        std::snprintf(line, sizeof(line), "%-26s %12zu\n", "functions that write",
                      writers.size());
        out += line;
        std::snprintf(line, sizeof(line), "%-26s %12llu\n", "store sites",
                      static_cast<unsigned long long>(totalSlots));
        out += line;
        std::snprintf(line, sizeof(line), "%-26s %12llu\n", "bytes written per pass",
                      static_cast<unsigned long long>(totalBytes));
        out += line;

        if (writers.empty()) {
            out += "\nNo function in this program writes memory.\n";
        } else {
            out += "\n/* busiest writers */\n";
            const size_t shown = std::min<size_t>(writers.size(), 20);
            for (size_t i = 0; i < shown; ++i) {
                const Writer& writer = writers[i];
                std::string name = writer.function->name;
                if (name.empty()) {
                    char fallback[32];
                    std::snprintf(fallback, sizeof(fallback), "sub_%llx",
                                  static_cast<unsigned long long>(writer.function->entry));
                    name = fallback;
                }
                std::snprintf(line, sizeof(line), "  %-26.26s %4u sites %6llu B\n",
                              name.c_str(), writer.slots,
                              static_cast<unsigned long long>(writer.bytes));
                out += line;
            }
            out += "\nOpen a function to see the byte offsets it writes.\n";
        }
        note(out);
    }
}

/// Prototypes are capped lower than the other reports because each one costs a full
/// decompilation, not just a lift.
static constexpr size_t kPrototypeLimit = 400;

void Session::buildPrototypes() {
    if (programReport_.prototypesBuilt) return;
    programReport_.prototypesBuilt = true;
    if (!analyzed_ || isDexLike()) return;
    if (!lifter_.ready() && !lifter_.open(image_.arch()).ok()) return;

    const std::vector<Function>& functions = analyzer_.functions();
    const size_t examined = std::min(functions.size(), kPrototypeLimit);

    std::string& out = programReport_.prototypes;
    char line[128];
    std::snprintf(line, sizeof(line), "/* %s — %zu functions */\n\n",
                  image_.soname().empty() ? "program" : image_.soname().c_str(),
                  functions.size());
    out = line;

    size_t recovered = 0;
    for (size_t i = 0; i < examined; ++i) {
        const Function& function = functions[i];
        IrFunction ir;
        if (!lifter_.liftFunction(function, image_.memory(), &ir).ok()) continue;
        ir.name = nameAt(function.entry);

        DecompileResult result;
        const Status status = decompileIr(
            ir, &result, [this](Address target) { return nameAt(target); }, {}, {},
            [this](Address target) { return prototypeAt(target); });
        if (!status.ok()) continue;

        // The emitter's first line is the signature followed by " {". Reusing it
        // rather than rebuilding one from the recovered types keeps the header and
        // the bodies from ever disagreeing about a function's shape.
        const size_t brace = result.cSource.find('{');
        if (brace == std::string::npos) continue;
        // Only the line the brace sits on. Everything before it is the emitter's
        // per-function banner, which repeated once per prototype and buried the
        // header it was supposed to be.
        size_t begin = result.cSource.rfind('\n', brace);
        begin = begin == std::string::npos ? 0 : begin + 1;
        std::string signature = result.cSource.substr(begin, brace - begin);
        while (!signature.empty() &&
               (signature.back() == ' ' || signature.back() == '\n')) {
            signature.pop_back();
        }
        if (signature.empty()) continue;
        out += signature;
        out += ";\n";
        ++recovered;
    }

    if (recovered == 0) {
        out += "No function could be decompiled far enough to give a signature.\n";
    }
    if (examined < functions.size()) {
        std::snprintf(line, sizeof(line),
                      "\n/* first %zu of %zu functions; open one for its body */\n",
                      examined, functions.size());
        out += line;
    } else {
        out += "\n/* open a function for its body */\n";
    }
}

std::string Session::programPrototypesText() {
    if (!analyzed_) return {};
    if (isDexLike()) return "Prototypes are not available for DEX input yet.\n";
    buildPrototypes();
    return programReport_.prototypes.empty() ? "No functions were decompiled.\n"
                                             : programReport_.prototypes;
}

std::string Session::programCoverageText() {
    if (!analyzed_) return {};
    if (isDexLike()) return "Lifter coverage is not available for DEX input yet.\n";
    buildProgramReport();
    return programReport_.coverage.empty() ? "No functions were lifted.\n"
                                           : programReport_.coverage;
}

std::string Session::programWriteSummaryText() {
    if (!analyzed_) return {};
    if (isDexLike()) return "Write summaries are not available for DEX input yet.\n";
    buildProgramReport();
    return programReport_.writes.empty() ? "No functions were lifted.\n"
                                         : programReport_.writes;
}

std::string Session::writeMapText(Address address) {
    if (!analyzed_) return {};
    if (isDexLike()) return "Write maps are not available for DEX input yet.\n";

    const Function* function = analyzer_.functionContaining(address);
    if (function == nullptr) function = analyzer_.functionAt(address);
    if (function == nullptr) return {};
    if (!lifter_.ready()) {
        const Status opened = lifter_.open(image_.arch());
        if (!opened.ok()) return "no lifter for " + std::string(archName(image_.arch()));
    }

    IrFunction ir;
    Status status = lifter_.liftFunction(*function, image_.memory(), &ir);
    if (!status.ok()) return "lifting failed: " + status.toString();
    JumpTableRecovery recovery;
    recoverJumpTables(image_, ir, &recovery);
    augmentIrCfg(&ir, recovery);

    // Reuses the decompiler's path rather than calling buildSsa directly. Raw lifted
    // IR contains overlapping register windows that SSA construction rejects, and
    // normalisation is what removes them — building SSA straight off the lifter
    // failed on most real functions. Going through decompileIr costs one wasted C
    // emission and buys the guarantee that this cannot drift from the pipeline the
    // rest of the app uses.
    DecompileResult prepared;
    status = decompileIr(ir, &prepared);
    if (!status.ok()) return "analysis failed: " + status.toString();
    const SsaFunction& ssa = prepared.ssa;

    // Grouped by the SSA value the address is computed from, so writes through one
    // pointer collect together however far apart they are in the listing.
    std::map<SsaId, std::vector<WriteSlot>> byBase;
    u32 unresolved = 0;

    for (const SsaInsn& insn : ssa.insns) {
        if (insn.op != MintOp::kStore) continue;
        const SsaId addressValue = insn.use[0];
        const SsaId stored = insn.use[1];
        if (addressValue == kNoValue || addressValue >= ssa.values.size()) continue;

        SsaId base = addressValue;
        i64 offset = 0;
        const SsaValue& value = ssa.values[addressValue];
        if (value.def == SsaDef::kInsn && value.defIndex < ssa.insns.size()) {
            const SsaInsn& compute = ssa.insns[value.defIndex];
            if (compute.op == MintOp::kAdd || compute.op == MintOp::kSub) {
                SsaId candidate = compute.use[0];
                SsaId constant = compute.use[1];
                if (candidate < ssa.values.size() &&
                    ssa.values[candidate].storage.space == Space::kConstant) {
                    std::swap(candidate, constant);
                }
                if (constant < ssa.values.size() &&
                    ssa.values[constant].storage.space == Space::kConstant) {
                    base = candidate;
                    const auto raw = static_cast<i64>(ssa.values[constant].storage.offset);
                    offset = compute.op == MintOp::kSub ? -raw : raw;
                } else {
                    // A run-time index. Counted and reported rather than dropped: a
                    // map that silently omits the writes it could not place reads as
                    // a complete list of what the function touches.
                    ++unresolved;
                    continue;
                }
            }
        }

        const u8 width = stored < ssa.values.size() ? ssa.values[stored].storage.size : 0;
        std::vector<WriteSlot>& slots = byBase[base];
        auto found = std::find_if(slots.begin(), slots.end(), [&](const WriteSlot& slot) {
            return slot.offset == offset;
        });
        if (found == slots.end()) {
            slots.push_back(WriteSlot{offset, width, 1});
        } else {
            ++found->count;
            if (width > found->width) found->width = width;
        }
    }

    if (byBase.empty()) {
        return unresolved == 0
                   ? "This function writes no memory.\n"
                   : "This function's " + std::to_string(unresolved) +
                         " writes all use run-time indices, so none could be placed.\n";
    }

    std::string out = "/* memory written by this function */\n";
    char line[192];
    for (auto& group : byBase) {
        std::vector<WriteSlot>& slots = group.second;
        std::sort(slots.begin(), slots.end(),
                  [](const WriteSlot& a, const WriteSlot& b) { return a.offset < b.offset; });

        u32 busiest = 0;
        u64 bytes = 0;
        for (const WriteSlot& slot : slots) {
            busiest = std::max(busiest, slot.count);
            bytes += slot.width;
        }

        const SsaValue& baseValue = ssa.values[group.first];
        std::string label;
        if (baseValue.storage.space == Space::kConstant) {
            std::snprintf(line, sizeof(line), "absolute 0x%llx",
                          static_cast<unsigned long long>(baseValue.storage.offset));
            label = line;
        } else if (baseValue.storage.isRegister()) {
            label = "via " + registerName(ssa.arch, baseValue.storage.offset,
                                          baseValue.storage.size);
        } else {
            label = "via value " + std::to_string(group.first);
        }

        std::snprintf(line, sizeof(line), "\n  %s — %zu slots, %llu bytes\n",
                      label.c_str(), slots.size(),
                      static_cast<unsigned long long>(bytes));
        out += line;
        for (const WriteSlot& slot : slots) {
            std::snprintf(line, sizeof(line), "    %+-8lld %2u  %-5s %u\n",
                          static_cast<long long>(slot.offset), unsigned(slot.width),
                          densityBar(slot.count, busiest), slot.count);
            out += line;
        }
    }
    if (unresolved != 0) {
        std::snprintf(line, sizeof(line),
                      "\n  %u store%s used a run-time index and could not be placed.\n",
                      unresolved, unresolved == 1 ? "" : "s");
        out += line;
    }
    return out;
}

namespace {

/// Escapes a string for JSON. Symbol names carry characters a bare copy would
/// break the document with — quotes and backslashes appear in mangled C++ names.
std::string jsonString(const std::string& value) {
    std::string out = "\"";
    for (const char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                    out += buffer;
                } else {
                    out += c;
                }
        }
    }
    out += '"';
    return out;
}

}  // namespace

std::string Session::exportJsonText() {
    if (!analyzed_) return {};
    if (isDexLike()) return "{\"schema\":1,\"error\":\"DEX export is not supported yet\"}\n";

    const std::vector<Function>& functions = analyzer_.functions();
    std::unordered_map<Address, u32> position;
    position.reserve(functions.size() * 2);
    for (u32 i = 0; i < functions.size(); ++i) position.emplace(functions[i].entry, i);

    std::string out;
    out.reserve(functions.size() * 96);
    char line[192];
    std::snprintf(line, sizeof(line), "{\n  \"schema\": %d,\n  \"arch\": ",
                  kJsonSchema);
    out += line;
    out += jsonString(architectureName(image_.arch()));
    out += ",\n  \"format\": "+jsonString(image_.formatName())+",\n  \"revision\": "+std::to_string(program_.revision());
    out += ",\n  \"functions\": [\n";

    for (u32 i = 0; i < functions.size(); ++i) {
        const Function& function = functions[i];
        std::snprintf(line, sizeof(line),
                      "    {\"index\": %u, \"entry\": %llu, \"size\": %llu,"
                      " \"instructions\": %zu, \"blocks\": %zu, \"incomplete\": %s,"
                      " \"name\": ",
                      i, static_cast<unsigned long long>(function.entry),
                      static_cast<unsigned long long>(
                          function.highAddress - function.lowAddress),
                      function.instructionCount(), function.cfg.blocks().size(),
                      function.incomplete ? "true" : "false");
        out += line;
        out += jsonString(nameAt(function.entry));
        out += ", \"displayName\": "+jsonString(displayNameAt(function.entry))+", \"origin\": "+jsonString(functionOriginName(function.origin));
        out += ", \"calls\": [";
        bool first = true;
        for (const Address callee : function.callees) {
            const auto found = position.find(callee);
            if (found == position.end()) continue;
            if (!first) out += ", ";
            out += std::to_string(found->second);
            first = false;
        }
        out += "]}";
        if (i + 1 < functions.size()) out += ',';
        out += '\n';
    }
    out += "  ],\n  \"userAnnotations\": [";
    bool firstAnnotation=true;
    for (const auto& entry : program_.annotations()) {
        if (!firstAnnotation) out += ',';
        firstAnnotation=false;
        out += "\n    {\"address\": "+std::to_string(entry.address)+", \"kind\": "+jsonString(entry.kind)+", \"value\": "+jsonString(entry.value)+"}";
    }
    out += "\n  ]\n}\n";
    return out;
}

std::string Session::xrefsText(Address address) {
    if (!analyzed_) return {};
    if (isDexLike()) return "Cross-references are not available for DEX input yet.\n";

    const Function* target = analyzer_.functionContaining(address);
    if (target == nullptr) target = analyzer_.functionAt(address);
    if (target == nullptr) return {};

    const auto label = [this](const Function& function) {
        const auto name = nameAt(function.entry);
        if (!name.empty()) return name;
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "sub_%llx",
                      static_cast<unsigned long long>(function.entry));
        return std::string(buffer);
    };

    std::string out = "/* cross-references for " + label(*target) + " */\n";
    char line[192];

    // Callers, with the call site. Function::callees holds targets but not the
    // instruction that jumped there, so the site comes from walking the caller's own
    // instructions — the only place that pairing exists.
    const CodeMap& code = analyzer_.code();
    size_t callerCount = 0;
    std::string callers;
    for (const Function& candidate : analyzer_.functions()) {
        bool calls = false;
        for (const Address callee : candidate.callees) {
            if (callee == target->entry) { calls = true; break; }
        }
        if (!calls) continue;
        ++callerCount;
        size_t sitesHere = 0;
        for (const Address at : candidate.instructions) {
            const InsnRecord* record = code.find(at);
            if (record == nullptr) continue;
            if (record->target != target->entry) continue;
            // Not only kCall. A branch straight to another function's entry is a
            // tail call: the descent counts it as an edge, but its flow is a jump,
            // and matching on kCall alone found no site for most callers on AArch64,
            // where the compiler emits tail calls constantly. The kind is printed
            // rather than flattened, because a tail call does not return here.
            const char* kind = nullptr;
            switch (record->flow) {
                case FlowKind::kCall: kind = "call"; break;
                case FlowKind::kJump: kind = "tail call"; break;
                case FlowKind::kCondJump: kind = "conditional tail call"; break;
                default: continue;
            }
            // Built by concatenation, not into a fixed buffer. A mangled C++ name
            // runs to hundreds of characters, and snprintf into 192 bytes silently
            // cut the caller's name off the end of its own xref line.
            std::snprintf(line, sizeof(line), "  %08llx  %-21s in ",
                          static_cast<unsigned long long>(at), kind);
            callers += line;
            callers += label(candidate);
            callers += '\n';
            ++sitesHere;
        }
        // A caller with no site is not dropped. The edge came from the descent, so
        // something reaches this function from there — through a stub, or from a
        // relocation — and saying "0 callers" would be a stronger claim than the
        // analysis supports.
        if (sitesHere == 0) {
            callers += "  ????????  edge without a branch  in ";
            callers += label(candidate);
            callers += '\n';
        }
    }

    std::snprintf(line, sizeof(line), "\n/* called from %zu function(s) */\n", callerCount);
    out += line;
    out += callers.empty() ? "  no direct caller found\n" : callers;

    // Callees, so the pane answers both directions from one place.
    std::string callees;
    size_t calleeCount = 0;
    for (const Address callee : target->callees) {
        const Function* function = analyzer_.functionAt(callee);
        ++calleeCount;
        if (function != nullptr) {
            std::snprintf(line, sizeof(line), "  %08llx  %s\n",
                          static_cast<unsigned long long>(callee), label(*function).c_str());
        } else {
            const std::string named = image_.describeAddress(callee);
            std::snprintf(line, sizeof(line), "  %08llx  %s\n",
                          static_cast<unsigned long long>(callee),
                          named.empty() ? "(outside the function list)" : named.c_str());
        }
        callees += line;
    }
    std::snprintf(line, sizeof(line), "\n/* calls %zu target(s) */\n", calleeCount);
    out += line;
    out += callees.empty() ? "  calls nothing directly\n" : callees;

    // An indirect call reaches a target this cannot see, so say how many there are:
    // "no callers" means something different in a function full of vtable dispatch.
    if (target->indirectJumps != 0) {
        std::snprintf(line, sizeof(line),
                      "\n/* %u indirect branch(es) here; their targets are not in the"
                      " list above */\n",
                      target->indirectJumps);
        out += line;
    }
    return out;
}

std::string Session::stringsText(Address functionAddress) {
    if (!analyzed_) return {};
    if (isDexLike()) return "String listing is not available for DEX input yet.\n";

    // How many to list before stopping. A large library holds tens of thousands, and
    // past a few thousand the list stops being something anyone reads.
    constexpr size_t kLimit = 4000;

    std::string out;
    char line[64];
    size_t shown = 0;
    size_t total = 0;

    if (functionAddress != 0) {
        // Only what this function refers to. Constants in its IR are the addresses it
        // could be pointing at; the same strictness as everywhere else decides which
        // of them actually hold text.
        const Function* function = analyzer_.functionContaining(functionAddress);
        if (function == nullptr) function = analyzer_.functionAt(functionAddress);
        if (function == nullptr) return {};
        if (!lifter_.ready() && !lifter_.open(image_.arch()).ok()) {
            return "no lifter for " + std::string(archName(image_.arch()));
        }
        IrFunction ir;
        if (!lifter_.liftFunction(*function, image_.memory(), &ir).ok()) {
            return "lifting failed\n";
        }
        std::map<Address, std::string> found;
        for (const IrInsn& insn : ir.insns) {
            for (unsigned slot = 0; slot < 3; ++slot) {
                const Varnode& node = insn.source(slot);
                if (!node.isConstant()) continue;
                const std::string text = stringAt(node.offset);
                if (!text.empty()) found.emplace(node.offset, text);
            }
        }
        out = "/* strings referenced by this function */\n\n";
        for (const auto& entry : found) {
            std::snprintf(line, sizeof(line), "  %08llx  ",
                          static_cast<unsigned long long>(entry.first));
            out += line;
            out += entry.second;
            out += '\n';
            ++shown;
        }
        if (shown == 0) out += "  none\n";
        return out;
    }

    out = "/* strings in this image */\n";
    std::string lastSection;
    for (const MemorySegment& segment : image_.memory().segments()) {
        // Code segments are skipped rather than filtered afterwards: printable runs
        // inside instruction bytes are coincidences, and listing them would bury the
        // real strings in noise.
        if (segment.executable() || segment.data.empty()) continue;

        const u8* bytes = segment.data.data();
        const size_t length = segment.data.size();
        size_t i = 0;
        while (i < length) {
            // Walk to the end of a printable run, then decide whether it is long
            // enough and NUL-terminated — the same two conditions stringAt applies.
            size_t run = i;
            while (run < length && bytes[run] >= 0x20 && bytes[run] < 0x7f) ++run;
            const size_t runLength = run - i;
            const bool terminated = run < length && bytes[run] == 0;
            if (runLength >= 4 && terminated) {
                ++total;
                if (shown < kLimit) {
                    // Named by section, not by segment. Program headers carry no
                    // names, so segments come out as "seg1" — which fails to answer
                    // the only question a strings list raises about location: is
                    // this .rodata, or something less interesting.
                    const Address at = segment.start + i;
                    std::string where = "unnamed";
                    for (const ElfSection& section : image_.sections()) {
                        if (section.addr == 0 || section.size == 0) continue;
                        if (at >= section.addr && at < section.addr + section.size) {
                            where = section.name;
                            break;
                        }
                    }
                    if (where != lastSection) {
                        out += "\n/* " + where + " */\n";
                        lastSection = where;
                    }
                    std::snprintf(line, sizeof(line), "  %08llx  \"",
                                  static_cast<unsigned long long>(at));
                    out += line;
                    for (size_t at = i; at < run; ++at) {
                        const char c = static_cast<char>(bytes[at]);
                        if (c == '"' || c == '\\') out += '\\';
                        out += c;
                    }
                    out += "\"\n";
                    ++shown;
                }
            }
            i = run + 1;
        }
    }

    if (total == 0) return "/* strings in this image */\n\n  none found\n";
    std::snprintf(line, sizeof(line), "\n/* %zu of %zu */\n", shown, total);
    out += line;
    return out;
}

std::string Session::offsetTableText(Address base) const {
    // 64 is well past any switch a human wrote and bounds the scan on a base that
    // only looks like a table.
    constexpr unsigned kMaxEntries = 64;
    const MemoryMap& memory = image_.memory();
    if (base == 0 || !memory.isMapped(base) || memory.isExecutable(base)) return {};

    std::string out;
    char line[64];
    unsigned found = 0;
    for (unsigned i = 0; i < kMaxEntries; ++i) {
        i32 offset = 0;
        if (!memory.readInt(base + i * 4, &offset)) break;
        const std::string text = stringAt(static_cast<Address>(base + offset), 1);
        if (text.empty()) break;
        std::snprintf(line, sizeof(line), "     *   %u -> ", i);
        out += line;
        out += text;
        out += '\n';
        ++found;
    }
    // One entry is a coincidence; a table is at least two.
    return found >= 2 ? out : std::string();
}

std::string Session::stringAt(Address address, size_t minLength) const {
    constexpr size_t kMaxLength = 200;
    const size_t kMinLength = minLength == 0 ? 1 : minLength;

    if (address == 0) return {};
    const MemoryMap& memory = image_.memory();
    if (!memory.isMapped(address)) return {};
    // Text in an executable segment is almost always a coincidence in code bytes.
    if (memory.isExecutable(address)) return {};

    std::string raw;
    if (!memory.readCString(address, &raw, kMaxLength)) return {};
    if (raw.size() < kMinLength) return {};

    std::string out;
    out.reserve(raw.size() + 8);
    out += '"';
    for (const char c : raw) {
        const auto byte = static_cast<unsigned char>(c);
        switch (c) {
            case '\\': out += "\\\\"; continue;
            case '"': out += "\\\""; continue;
            case '\n': out += "\\n"; continue;
            case '\r': out += "\\r"; continue;
            case '\t': out += "\\t"; continue;
            default: break;
        }
        // One unprintable byte and this was not a string. Rejecting outright rather
        // than escaping it: \x1f in the middle of a "literal" means the guess was
        // wrong, and printing it anyway dresses a wrong guess as a finding.
        if (byte < 0x20 || byte >= 0x7f) return {};
        out += c;
    }
    out += '"';
    return out;
}

std::string Session::callGraphText() const {
    if (!analyzed_) return {};
    const std::vector<Function>& functions = analyzer_.functions();
    if (functions.empty()) return {};

    // Entry address to position, so a callee address can be turned into the index
    // the caller understands. Linear search per callee would be quadratic in the
    // function count, which a stripped library makes felt immediately.
    std::unordered_map<Address, u32> position;
    position.reserve(functions.size() * 2);
    for (u32 i = 0; i < functions.size(); ++i) {
        position.emplace(functions[i].entry, i);
    }

    std::string out;
    out.reserve(functions.size() * 24);
    for (u32 i = 0; i < functions.size(); ++i) {
        out += std::to_string(i);
        out += ' ';
        out += std::to_string(functions[i].entry);
        for (const Address callee : functions[i].callees) {
            const auto found = position.find(callee);
            // A call that lands outside the function list — a PLT thunk, or an
            // address the descent never promoted to a function — is dropped rather
            // than turned into a dangling edge.
            if (found == position.end()) continue;
            out += ' ';
            out += std::to_string(found->second);
        }
        out += '\n';
    }
    return out;
}

std::vector<std::string> Session::allWarnings() const {
    std::vector<std::string> all;
    for(const auto& warning:pluginEventWarnings_)all.push_back(warning);
    if(!isDexLike() && analyzed_) all.push_back("program: "+analysisStatusText());
    for (const std::string& warning : image_.warnings()) {
        all.push_back("loader: " + warning);
    }
    for (const std::string& warning : analyzer_.warnings()) {
        all.push_back("analysis: " + warning);
    }
    for(const auto& warning:debugInfo_.warnings)if(all.size()<256)all.push_back("DWARF: "+warning);
    for (const DetectorFinding& finding : detectorFindings_) {
        if (all.size() >= 256) break;
        all.push_back("detector: " + std::string(findingKindName(finding.kind)) +
                      " 0x" + [&] { char buffer[32]; std::snprintf(buffer, sizeof(buffer), "%llx", static_cast<unsigned long long>(finding.address)); return std::string(buffer); }() +
                      " " + finding.name + " (" + finding.detail + ")");
    }
    return all;
}

}  // namespace mint
