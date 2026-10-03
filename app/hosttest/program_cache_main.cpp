#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#include "mint/session.h"
#include "mint/db/analysis_cache.h"

namespace {
using namespace mint;
int checks = 0, failures = 0;

bool check(bool condition, const std::string& description) {
    ++checks;
    if (!condition) { ++failures; std::cerr << "FAIL: " << description << '\n'; }
    return condition;
}

bool success(const Status& status, const std::string& description) {
    return check(status.ok(), description + ": " + status.toString());
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        std::string name = "/private/tmp/mint-cache-contract-XXXXXX";
        if (::mkdtemp(name.data())) path_ = std::move(name);
    }
    ~TemporaryDirectory() {
        if (path_.empty()) return;
        std::error_code ignored;
        // All children belong to this freshly created test-only directory.
        for (const auto& entry : std::filesystem::directory_iterator(path_, ignored)) {
            if (!ignored) std::filesystem::remove(entry.path(), ignored);
        }
        ::rmdir(path_.c_str());
    }
    bool valid() const { return !path_.empty(); }
    std::string file(const std::string& name) const { return path_ + "/" + name; }
private:
    std::string path_;
};

std::vector<u8> contents(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

bool writeBytes(const std::string& path, const std::vector<u8>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    if (!bytes.empty()) output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    output.close();
    return !output.fail();
}

template <class T> void store(std::vector<u8>* bytes, size_t offset, T value) {
    if (offset + sizeof(T) > bytes->size()) std::abort();
    std::memcpy(bytes->data() + offset, &value, sizeof(value));
}

struct Fixture {
    Arch architecture;
    std::vector<u8> bytes;
    Address patchAddress;
    std::string immediatePatch;
    Address branchPatchAddress;
    std::string branchPatch;
};

Fixture fixture(Arch architecture) {
    Fixture result{architecture, std::vector<u8>(160, 0), 0, "", 0x1020, ""};
    if (architecture == Arch::kAArch64) {
        store<u32>(&result.bytes, 0, 0x94000008);   // bl 0x1020
        store<u32>(&result.bytes, 4, 0x9400000f);   // bl 0x1040
        store<u32>(&result.bytes, 8, 0xd65f03c0);
        store<u32>(&result.bytes, 0x20, 0xd28000e0); // mov x0,#7
        store<u32>(&result.bytes, 0x24, 0xd65f03c0);
        store<u32>(&result.bytes, 0x40, 0xd2800160); // mov x0,#11
        store<u32>(&result.bytes, 0x44, 0xd65f03c0);
        result.patchAddress = 0x1020;
        result.immediatePatch = "20 01 80 d2";      // mov x0,#9
        result.branchPatch = "08 00 00 14";        // b 0x1040
    } else {
        result.bytes[0] = 0xe8; store<u32>(&result.bytes, 1, 0x1b);
        result.bytes[5] = 0xe8; store<u32>(&result.bytes, 6, 0x36);
        result.bytes[10] = 0xc3;
        result.bytes[0x20] = 0xb8; store<u32>(&result.bytes, 0x21, 7); result.bytes[0x25] = 0xc3;
        result.bytes[0x40] = 0xb8; store<u32>(&result.bytes, 0x41, 11); result.bytes[0x45] = 0xc3;
        result.patchAddress = 0x1021;
        result.immediatePatch = "09";
        result.branchPatch = "e9 1b 00 00 00";     // jmp 0x1040
    }
    const std::string text = "cached binary";
    std::memcpy(result.bytes.data() + 0x70, text.c_str(), text.size() + 1);
    store<Address>(&result.bytes, 0x80, 0x1020);
    return result;
}

Fixture sharedOwnerFixture(Arch architecture) {
    auto result = fixture(architecture);
    if (architecture == Arch::kAArch64) {
        store<u32>(&result.bytes, 0x20, 0x14000010); // b 0x1060
        store<u32>(&result.bytes, 0x40, 0x14000008); // b 0x1060
        store<u32>(&result.bytes, 0x60, 0xd28000e0); // shared mov x0,#7
        store<u32>(&result.bytes, 0x64, 0xd65f03c0);
        result.patchAddress = 0x1060;
    } else {
        result.bytes[0x20] = 0xe9; store<u32>(&result.bytes, 0x21, 0x3b);
        result.bytes[0x40] = 0xe9; store<u32>(&result.bytes, 0x41, 0x1b);
        result.bytes[0x60] = 0xb8; store<u32>(&result.bytes, 0x61, 7);
        result.bytes[0x65] = 0xc3;
        result.patchAddress = 0x1061;
    }
    return result;
}

std::string statusField(const Session& session, const std::string& field) {
    const auto status = session.analysisStatusText();
    const std::string prefix = field + '=';
    const auto at = status.find(prefix);
    if (at == std::string::npos) return {};
    const auto begin = at + prefix.size();
    const auto end = status.find_first_of(" \r\n", begin);
    return status.substr(begin, end == std::string::npos ? end : end - begin);
}

bool mode(const Session& session, const std::string& expected, const std::string& description) {
    return check(statusField(session, "mode") == expected, description + " (" + session.analysisStatusText() + ")");
}

// Compare every publicly observable derived discovery field, not just counts.
// User display names intentionally are absent: metadata must not change this.
std::string analysisSnapshot(const CodeAnalyzer& analyzer) {
    std::ostringstream out;
    const auto& stats = analyzer.stats();
    out << "stats " << stats.instructions << ' ' << stats.functions << ' ' << stats.blocks << ' '
        << stats.edges << ' ' << stats.indirectJumps << ' ' << stats.undecodableSites << ' '
        << stats.incompleteFunctions << ' ' << stats.functionsFromSweep << ' ' << stats.reachedInstructionLimit << '\n';
    for (const auto& instruction : analyzer.code().instructions()) {
        out << "insn " << instruction.address << ' ' << instruction.target << ' ' << instruction.id << ' '
            << unsigned(instruction.size) << ' ' << unsigned(instruction.flow) << '\n';
    }
    for (const auto& function : analyzer.functions()) {
        out << "fn " << function.entry << ' ' << function.name << ' ' << unsigned(function.origin) << ' '
            << function.lowAddress << ' ' << function.highAddress << ' ' << function.incomplete << ' '
            << function.indirectJumps << ' ' << function.undecodableSites << ' ' << function.cfg.entry() << '\n';
        for (Address address : function.instructions) out << "owned " << address << '\n';
        for (Address callee : function.callees) out << "callee " << callee << '\n';
        for (Address caller : analyzer.callersOf(function.entry)) out << "caller " << caller << '\n';
        for (const auto& recovered : function.resolvedIndirectJumps) {
            out << "resolved " << recovered.branch;
            for (Address target : recovered.targets) out << ' ' << target;
            out << '\n';
        }
        for (const auto& block : function.cfg.blocks()) {
            out << "block " << block.id << ' ' << block.start << ' ' << block.end << ' '
                << block.firstInsn << ' ' << block.insnCount << ' ' << unsigned(block.terminator) << '\n';
            for (const auto& edge : block.successors) out << "edge " << edge.target << ' ' << unsigned(edge.kind) << '\n';
            for (u32 predecessor : block.predecessors) out << "predecessor " << predecessor << '\n';
        }
    }
    for (const auto& warning : analyzer.warnings()) out << "warning " << warning << '\n';
    return out.str();
}

std::string analysisSnapshot(const Session& session) { return analysisSnapshot(session.analyzer()); }

struct Snapshot { std::string analysis, views, references; };

Snapshot snapshot(Session& session) {
    Snapshot result;
    result.analysis = analysisSnapshot(session);
    std::ostringstream views;
    for (const auto& function : session.analyzer().functions()) {
        views << "function " << function.entry << '\n' << session.irTextFor(function.entry)
            << session.cfgTextFor(function.entry) << session.decompiledCFor(function.entry);
    }
    const Address base = session.image().imageBase();
    for (const auto& row : session.programListing(base, 4096)) {
        views << "row " << row.address << ' ' << row.size << ' ' << unsigned(row.flow) << ' '
            << row.target << ' ' << row.text << ' ' << row.comment << '\n';
    }
    result.views = views.str();
    for (Address address : {base, base + 0x20, base + 0x40, base + 0x80})
        result.references += std::to_string(address) + '\n' + session.referencesText(address);
    return result;
}

bool sameSnapshot(const Snapshot& actual, const Snapshot& expected, const std::string& description) {
    bool ok = check(actual.analysis == expected.analysis, description + " code/functions/CFG/stats/indexes");
    ok &= check(actual.views == expected.views, description + " listing/IR/decompiler views");
    ok &= check(actual.references == expected.references, description + " code/data references");
    return ok;
}

bool open(Session* session, const Fixture& fixture, const std::string& source, const std::string& project) {
    return success(session->openRawPath(source, fixture.architecture, 0x1000, 0x1000), "open fixture") &&
           success(session->attachProject(project), "attach persistent Program") &&
           success(session->analyze(), "analyze/restore Program");
}

bool equivalentFresh(Session& current, const Fixture& fixture, const std::string& source,
                     const std::string& project, const TemporaryDirectory& temporary,
                     unsigned* serial, const std::string& description) {
    const auto oracleProject = temporary.file("oracle-" + std::to_string((*serial)++) + ".mint");
    if (!check(writeBytes(oracleProject, contents(project)), "copy authoritative annotations for full oracle")) return false;
    Session oracle;
    if (!success(oracle.openRawPath(source, fixture.architecture, 0x1000, 0x1000), "open full oracle") ||
        !success(oracle.attachProject(oracleProject), "attach equivalent oracle overlay") ||
        !success(oracle.reanalyze(), "force fresh full discovery oracle") ||
        !mode(oracle, "full", "explicit reanalysis bypasses cache")) return false;
    return sameSnapshot(snapshot(current), snapshot(oracle), description);
}

u32 payloadCrc(const std::vector<u8>& bytes) {
    u32 crc = 0xffffffffU;
    for (size_t i = 32; i < bytes.size(); ++i) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0U);
    }
    return crc ^ 0xffffffffU;
}

void repairEnvelope(std::vector<u8>* bytes) {
    store<u64>(bytes, 16, bytes->size() - 32);
    store<u32>(bytes, 24, payloadCrc(*bytes));
}

bool serializerContracts() {
    TemporaryDirectory temporary;
    if (!check(temporary.valid(), "create serializer fixture directory")) return false;
    const auto raw = fixture(Arch::kAArch64);
    const auto source = temporary.file("codec-source.bin"), path = temporary.file("codec.analysis");
    const std::string key = "fixture-dependency-key";
    if (!check(writeBytes(source, raw.bytes), "write serializer native source")) return false;
    Session session;
    if (!success(session.openRawPath(source, raw.architecture, 0x1000, 0x1000), "open serializer source") ||
        !success(session.analyze(), "discover serializer source")) return false;
    CachedAnalysis cached;
    cached.analysis = session.analyzer().snapshot();
    cached.analysis.warnings.push_back("bounded codec diagnostic");
    cached.referencesReady = true;
    cached.references = {{0x1000, 0x1020, "call"}, {0x1080, 0x1020, "user pointer"}};
    if (!success(AnalysisCache::save(path, key, cached), "save portable derived-state cache")) return false;
    const auto valid = contents(path);
    CachedAnalysis loaded;
    if (!success(AnalysisCache::load(path, key, &loaded), "load portable derived-state cache") ||
        !check(loaded.analysis.instructions.size() == cached.analysis.instructions.size() &&
               loaded.analysis.functions.size() == cached.analysis.functions.size() &&
               loaded.analysis.functionBoundaries == cached.analysis.functionBoundaries &&
               loaded.analysis.warnings == cached.analysis.warnings &&
               loaded.analysis.reachedInstructionLimit == cached.analysis.reachedInstructionLimit,
               "portable cache preserves all snapshot collections") ||
        !check(loaded.referencesReady && loaded.references.size() == 2 &&
               loaded.references[1].from == 0x1080 && loaded.references[1].to == 0x1020 &&
               loaded.references[1].kind == "user pointer", "portable cache preserves ready reference index")) return false;
    CodeAnalyzer restored;
    auto restoredState = loaded.analysis;
    restoredState.warnings = session.analyzer().warnings();
    if (!success(restored.restore(session.image(), CodeAnalyzer::Options{}, restoredState), "restore validated snapshot into analyzer") ||
        !check(analysisSnapshot(restored) == analysisSnapshot(session), "restored analyzer rebuilds equivalent CFG, callers and statistics")) return false;

    auto rejectedLoad = [&](const std::vector<u8>& bytes, const std::string& dependency, const std::string& description) {
        if (!check(writeBytes(path, bytes), "write owned " + description + " fixture")) return false;
        CachedAnalysis output;
        output.analysis.warnings = {"keep output"};
        output.analysis.functionBoundaries = {23};
        output.referencesReady = true;
        output.references = {{17, 19, "existing reference"}};
        bool ok = check(!AnalysisCache::load(path, dependency, &output).ok(), description + " is rejected");
        ok &= check(output.analysis.warnings == std::vector<std::string>{"keep output"} &&
                    output.analysis.functionBoundaries == std::vector<Address>{23} &&
                    output.referencesReady && output.references.size() == 1 &&
                    output.references[0].from == 17 && output.references[0].kind == "existing reference",
                    description + " cannot publish partial decoded state");
        return ok;
    };
    if (!rejectedLoad(valid, key + "-changed", "wrong dependency identity")) return false;
    for (size_t length = 0; length < valid.size(); ++length) {
        const std::vector<u8> prefix(valid.begin(), valid.begin() + length);
        if (!rejectedLoad(prefix, key, "truncated-prefix " + std::to_string(length))) return false;
    }
    auto corrupted = valid; corrupted[corrupted.size() / 2] ^= 0x40;
    if (!rejectedLoad(corrupted, key, "payload checksum corruption")) return false;
    corrupted = valid; corrupted.push_back(0);
    if (!rejectedLoad(corrupted, key, "trailing file byte")) return false;
    repairEnvelope(&corrupted);
    if (!rejectedLoad(corrupted, key, "trailing decoded payload with valid checksum")) return false;
    for (size_t offset : {size_t{8}, size_t{12}, size_t{28}}) {
        corrupted = valid; store<u32>(&corrupted, offset, offset == 8 ? 0xffffffffU : 1);
        if (!rejectedLoad(corrupted, key, "unsupported header field at " + std::to_string(offset))) return false;
    }
    const size_t instructionCountOffset = 32 + 4 + key.size();
    corrupted = valid; store<u32>(&corrupted, instructionCountOffset, 0xffffffffU); repairEnvelope(&corrupted);
    if (!rejectedLoad(corrupted, key, "oversized instruction count with valid checksum")) return false;
    corrupted = valid; corrupted[instructionCountOffset + 4 + 19] = 255; repairEnvelope(&corrupted);
    if (!rejectedLoad(corrupted, key, "invalid flow enum with valid checksum")) return false;
    corrupted = valid; corrupted[instructionCountOffset + 4 + 18] = 0; repairEnvelope(&corrupted);
    if (!rejectedLoad(corrupted, key, "zero instruction size with valid checksum")) return false;

    if (!check(writeBytes(path, valid), "restore good cache before failed-save checks")) return false;
    auto rejectedSave = [&](const CachedAnalysis& candidate, const std::string& dependency, const std::string& description) {
        bool ok = check(!AnalysisCache::save(path, dependency, candidate).ok(), description + " is rejected before publication");
        ok &= check(contents(path) == valid, description + " preserves previous good cache byte-for-byte");
        return ok;
    };
    auto invalid = cached; invalid.analysis.instructions.front().size = 0;
    if (!rejectedSave(invalid, key, "zero-size instruction save")) return false;
    invalid = cached; invalid.analysis.instructions.front().flow = static_cast<FlowKind>(255);
    if (!rejectedSave(invalid, key, "invalid flow save")) return false;
    invalid = cached; invalid.analysis.instructions.push_back(invalid.analysis.instructions.back());
    if (!rejectedSave(invalid, key, "duplicate instruction save")) return false;
    invalid = cached; invalid.analysis.functions.front().origin = static_cast<FunctionOrigin>(255);
    if (!rejectedSave(invalid, key, "invalid function origin save")) return false;
    invalid = cached; invalid.analysis.functions.front().name = std::string("bad\0name", 8);
    if (!rejectedSave(invalid, key, "embedded-NUL symbol save")) return false;
    invalid = cached; invalid.analysis.functionBoundaries.push_back(invalid.analysis.functionBoundaries.back());
    if (!rejectedSave(invalid, key, "duplicate function boundary save")) return false;
    invalid = cached; invalid.referencesReady = false;
    if (!rejectedSave(invalid, key, "unready nonempty reference index save")) return false;
    invalid = cached; invalid.references.front().kind.clear();
    if (!rejectedSave(invalid, key, "empty reference kind save") ||
        !rejectedSave(cached, "", "empty dependency key save") ||
        !rejectedSave(cached, std::string(4097, 'x'), "oversized dependency key save")) return false;
    const auto directoryDestination = temporary.file("directory-destination");
    if (!check(std::filesystem::create_directory(directoryDestination), "create failed-rename fixture directory") ||
        !check(!AnalysisCache::save(directoryDestination, key, cached).ok(), "failed atomic rename is reported") ||
        !check(std::filesystem::is_directory(directoryDestination) && std::filesystem::is_empty(directoryDestination),
               "failed save preserves existing directory target") ||
        !check(contents(path) == valid, "failed unrelated save leaves good cache intact")) return false;

    const auto beforeRejectedRestore = analysisSnapshot(restored);
    auto forged = restoredState;
    forged.instructions.front().target = 0x1040; // Actual source bytes still call 0x1020.
    if (!check(!restored.restore(session.image(), CodeAnalyzer::Options{}, forged).ok(),
               "snapshot semantic validation rejects forged branch target") ||
        !check(analysisSnapshot(restored) == beforeRejectedRestore,
               "failed semantic snapshot restore leaves prior analyzer intact")) return false;
    std::cout << "portable AnalysisCache serializer contracts passed\n";
    return true;
}

bool boundedSnapshotContracts(Arch architecture) {
    TemporaryDirectory temporary;
    if (!check(temporary.valid(), "create bounded snapshot fixture directory")) return false;
    const auto raw = fixture(architecture);
    const auto source = temporary.file("bounded-source.bin");
    if (!check(writeBytes(source, raw.bytes), "write bounded native source")) return false;
    Session imageOwner;
    if (!success(imageOwner.openRawPath(source, architecture, 0x1000, 0x1000), "open bounded native image")) return false;
    for (bool instructionBound : {false, true}) {
        const std::string label = std::string(archName(architecture)) +
            (instructionBound ? " instruction-limit" : " function-limit");
        CodeAnalyzer::Options options;
        if (instructionBound) options.maxInstructions = 2;
        else options.maxFunctions = 1;
        CodeAnalyzer bounded;
        if (!success(bounded.analyze(imageOwner.image(), options), label + " bounded discovery")) return false;
        if (instructionBound) {
            if (!check(bounded.code().instructions().size() == 2 && bounded.stats().reachedInstructionLimit == 1,
                       label + " records the canonical reached-limit state")) return false;
        } else if (!check(bounded.functions().size() == 1 && bounded.stats().functions == 1,
                          label + " stops after one actual discovered function")) return false;
        const auto original = bounded.snapshot();
        CodeAnalyzer restored;
        if (!success(restored.restore(imageOwner.image(), options, original), label + " direct snapshot restore") ||
            !check(analysisSnapshot(restored) == analysisSnapshot(bounded),
                   label + " direct restore preserves code/functions/CFG/stats/warnings/indexes")) return false;
        CachedAnalysis cached;
        cached.analysis = original;
        const auto path = temporary.file(instructionBound ? "instructions.analysis" : "functions.analysis");
        if (!success(AnalysisCache::save(path, label, cached), label + " durable snapshot save")) return false;
        CachedAnalysis loaded;
        if (!success(AnalysisCache::load(path, label, &loaded), label + " durable snapshot load") ||
            !check(loaded.analysis.reachedInstructionLimit == original.reachedInstructionLimit &&
                   loaded.analysis.functionBoundaries == original.functionBoundaries &&
                   loaded.analysis.warnings == original.warnings,
                   label + " codec preserves resource state, boundaries and warnings")) return false;
        CodeAnalyzer durable;
        if (!success(durable.restore(imageOwner.image(), options, loaded.analysis), label + " durable snapshot restore") ||
            !check(analysisSnapshot(durable) == analysisSnapshot(bounded),
                   label + " durable restore remains exactly equivalent")) return false;
    }
    std::cout << archName(architecture) << " bounded snapshot contracts passed\n";
    return true;
}

bool sharedOwnerContract(Arch architecture) {
    TemporaryDirectory temporary;
    if (!check(temporary.valid(), "create shared-owner fixture directory")) return false;
    const auto raw = sharedOwnerFixture(architecture);
    const auto source = temporary.file("shared-source.bin"), project = temporary.file("shared.mint");
    if (!check(writeBytes(source, raw.bytes), "write shared-tail native fixture")) return false;
    Session session;
    if (!open(&session, raw, source, project) ||
        !check(session.analyzer().functions().size() == 3, "shared-tail fixture has entry and two direct-call roots")) return false;
    size_t owners = 0;
    for (const auto& function : session.analyzer().functions())
        owners += std::find(function.instructions.begin(), function.instructions.end(), 0x1060) != function.instructions.end();
    if (!check(owners == 2, "shared arithmetic instruction belongs to both direct-call roots")) return false;
    unsigned oracleSerial = 0;
    if (!success(session.editAnnotation(raw.patchAddress, "patch", raw.immediatePatch), "patch shared-tail arithmetic immediate") ||
        !mode(session, "incremental", "shared arithmetic patch preserves flow topology") ||
        !check(statusField(session, "functions") == "2", "shared patch reanalyzes every owning function") ||
        !check(session.decompiledCFor(0x1020).find("9") != std::string::npos &&
               session.decompiledCFor(0x1040).find("9") != std::string::npos,
               "shared patch reaches both callers' decompiled bodies") ||
        !equivalentFresh(session, raw, source, project, temporary, &oracleSerial, "shared-owner incremental vs full") ||
        !success(session.undoEdit(false), "undo shared-tail patch") ||
        !mode(session, "incremental", "shared-tail undo is incremental") ||
        !check(statusField(session, "functions") == "2", "shared-tail undo updates both owners") ||
        !equivalentFresh(session, raw, source, project, temporary, &oracleSerial, "shared-owner undo vs full") ||
        !success(session.undoEdit(true), "redo shared-tail patch") ||
        !mode(session, "incremental", "shared-tail redo is incremental") ||
        !check(statusField(session, "functions") == "2", "shared-tail redo updates both owners") ||
        !equivalentFresh(session, raw, source, project, temporary, &oracleSerial, "shared-owner redo vs full") ||
        !check(contents(source) == raw.bytes, "shared-owner reanalysis never changes original input")) return false;
    const auto expected = snapshot(session);
    Session reopened;
    if (!open(&reopened, raw, source, project) ||
        !mode(reopened, "restored", "shared-owner patched state restores without discovery") ||
        !sameSnapshot(snapshot(reopened), expected, "shared-owner warm restore vs patched state")) return false;
    std::cout << archName(architecture) << " shared-owner incremental contract passed\n";
    return true;
}

bool reusedSessionContract() {
    TemporaryDirectory temporary;
    if (!check(temporary.valid(), "create reused-session fixture directory")) return false;
    const auto first = fixture(Arch::kAArch64), second = fixture(Arch::kX86_64);
    const auto firstSource = temporary.file("first-arm64.bin"), secondSource = temporary.file("second-x86.bin");
    const auto firstProject = temporary.file("first.mint");
    if (!check(writeBytes(firstSource, first.bytes) && writeBytes(secondSource, second.bytes), "write reused-session inputs")) return false;
    Session reused;
    if (!open(&reused, first, firstSource, firstProject) ||
        !success(reused.editAnnotation(0x1000, "name", "first_project_entry"), "annotate first source") ||
        !check(reused.irTextFor(0x1020).find("x0") != std::string::npos, "initialize AArch64 lifter before reuse")) return false;
    snapshot(reused);
    const auto projectBefore = contents(firstProject), cacheBefore = contents(firstProject + ".analysis");
    if (!check(!projectBefore.empty() && !cacheBefore.empty(), "first source has durable user and derived project state")) return false;
    if (!success(reused.openRawPath(secondSource, second.architecture, 0x2000, 0x2000), "reuse Session for different source/ISA/base") ||
        !check(!reused.analyzed() && reused.program().annotations().empty() && reused.program().memory().empty(),
               "new open clears old analysis, authoritative project and bound Program memory") ||
        !success(reused.analyze(), "analyze reused x86 Session without attaching old project") ||
        !mode(reused, "full", "different source cannot reuse previous project cache") ||
        !check(reused.image().arch() == Arch::kX86_64 && reused.image().memory().minAddress() == 0x2000 &&
               reused.analyzer().functionAt(0x2020), "reused Session binds new ISA/address space") ||
        !check(reused.irTextFor(0x2020).find("rax") != std::string::npos,
               "lifter is reopened when reused Session changes architecture")) return false;
    Session fresh;
    if (!success(fresh.openRawPath(secondSource, second.architecture, 0x2000, 0x2000), "open independent second-source oracle") ||
        !success(fresh.reanalyze(), "fully analyze independent second-source oracle") ||
        !sameSnapshot(snapshot(reused), snapshot(fresh), "reused Session vs fresh second source") ||
        !check(contents(firstProject) == projectBefore && contents(firstProject + ".analysis") == cacheBefore,
               "reused Session cannot modify the first project's authoritative or derived files")) return false;
    std::cout << "cross-ISA reused Session contract passed\n";
    return true;
}

bool integration(Arch architecture) {
    TemporaryDirectory temporary;
    if (!check(temporary.valid(), "create owned temporary directory")) return false;
    const auto fixtureData = fixture(architecture);
    const auto source = temporary.file("source.bin"), project = temporary.file("program.mint");
    const auto cache = project + ".analysis";
    if (!check(writeBytes(source, fixtureData.bytes), "write test-only raw fixture")) return false;
    Session session;
    if (!open(&session, fixtureData, source, project) || !mode(session, "full", "cold Program discovery is full") ||
        !check(session.analyzer().functions().size() == 3, "entry and two direct callees are discovered") ||
        !success(session.editAnnotation(0x1080, "data", "pointer"), "define authoritative pointer data") ||
        !mode(session, "full", "structural data edit triggers full discovery")) return false;
    snapshot(session); // Builds and durably saves the lazily computed reference index.
    if (!check(session.program().referencesReady(), "reference index is ready before metadata edits") ||
        !check(!contents(cache).empty(), "derived Program Database companion is saved")) return false;

    const auto analysisBeforeMetadata = analysisSnapshot(session);
    for (const auto& item : std::vector<std::pair<std::string, std::string>>{
             {"name", "cache_entry"}, {"comment", "durable cache comment"}, {"bookmark", "cache bookmark"}}) {
        if (!success(session.editAnnotation(0x1000, item.first, item.second), "edit " + item.first + " metadata") ||
            !mode(session, "metadata", "metadata edit skips code rediscovery") ||
            !check(statusField(session, "functions") == "0", "metadata update affects zero discovered functions") ||
            !check(session.program().referencesReady(), "metadata edit preserves authoritative reference index") ||
            !check(analysisSnapshot(session) == analysisBeforeMetadata, "metadata edit preserves every discovery field")) return false;
    }
    const auto warmExpected = snapshot(session);
    const auto warmCache = contents(cache);
    if (!check(!warmCache.empty(), "warm native derived state is persisted")) return false;
    {
        Session reopened;
        if (!open(&reopened, fixtureData, source, project) || !mode(reopened, "restored", "warm reopen restores Program Database") ||
            !check(reopened.program().referencesReady(), "warm reopen restores ready code/data reference index") ||
            !sameSnapshot(snapshot(reopened), warmExpected, "warm derived state matches original")) return false;
    }

    // Invalid derived state cannot discard or reinterpret the user Program.
    auto truncated = warmCache; truncated.resize(warmCache.size() / 2);
    if (!check(writeBytes(cache, truncated), "truncate owned derived cache fixture")) return false;
    {
        Session reopened;
        if (!open(&reopened, fixtureData, source, project) || !mode(reopened, "full", "truncated cache falls back to full discovery") ||
            !check(reopened.annotation(0x1000, "comment") == "durable cache comment", "truncated cache keeps annotations") ||
            !sameSnapshot(snapshot(reopened), warmExpected, "truncated-cache fallback is equivalent")) return false;
    }
    auto corrupt = warmCache; corrupt[0] ^= 0x80;
    if (!check(writeBytes(cache, corrupt), "corrupt owned derived cache header")) return false;
    {
        Session reopened;
        if (!open(&reopened, fixtureData, source, project) || !mode(reopened, "full", "corrupt cache falls back to full discovery") ||
            !check(reopened.annotation(0x1000, "name") == "cache_entry", "corrupt cache keeps user symbol") ||
            !sameSnapshot(snapshot(reopened), warmExpected, "corrupt-cache fallback is equivalent")) return false;
    }

    unsigned oracleSerial = 0;
    if (!success(session.editAnnotation(fixtureData.patchAddress, "patch", fixtureData.immediatePatch), "patch arithmetic immediate") ||
        !mode(session, "incremental", "unchanged-flow arithmetic patch uses incremental update") ||
        !check(statusField(session, "functions") == "1", "safe arithmetic patch updates one owning function") ||
        !check(session.decompiledCFor(0x1020).find("9") != std::string::npos, "incremental bytes reach decompiler") ||
        !equivalentFresh(session, fixtureData, source, project, temporary, &oracleSerial, "incremental vs fresh full") ||
        !success(session.undoEdit(false), "undo arithmetic patch") ||
        !mode(session, "incremental", "safe patch undo uses incremental update") ||
        !equivalentFresh(session, fixtureData, source, project, temporary, &oracleSerial, "incremental undo vs full") ||
        !success(session.undoEdit(true), "redo arithmetic patch") ||
        !mode(session, "incremental", "safe patch redo uses incremental update") ||
        !equivalentFresh(session, fixtureData, source, project, temporary, &oracleSerial, "incremental redo vs full")) return false;

    // An older valid cache belongs to a different authoritative patch model.
    if (!check(writeBytes(cache, warmCache), "install structurally stale cache fixture")) return false;
    {
        Session reopened;
        if (!open(&reopened, fixtureData, source, project) || !mode(reopened, "full", "model-mismatched cache is not restored") ||
            !check(reopened.annotation(fixtureData.patchAddress, "patch") == fixtureData.immediatePatch,
                   "stale cache cannot discard persisted patch") ||
            !equivalentFresh(reopened, fixtureData, source, project, temporary, &oracleSerial, "model mismatch fallback vs full")) return false;
    }
    if (fixtureData.patchAddress != fixtureData.branchPatchAddress &&
        !success(session.editAnnotation(fixtureData.patchAddress, "patch", ""), "remove immediate-only overlay before replacing opcode")) return false;
    if (!success(session.editAnnotation(fixtureData.branchPatchAddress, "patch", fixtureData.branchPatch), "patch control-flow opcode") ||
        !mode(session, "full", "control-flow change safely falls back to full discovery") ||
        !equivalentFresh(session, fixtureData, source, project, temporary, &oracleSerial, "control-flow fallback vs full") ||
        !success(session.undoEdit(false), "undo control-flow patch") ||
        !mode(session, "full", "undo control-flow change performs full discovery") ||
        !equivalentFresh(session, fixtureData, source, project, temporary, &oracleSerial, "control-flow undo vs full") ||
        !success(session.undoEdit(true), "redo control-flow patch") ||
        !mode(session, "full", "redo control-flow change performs full discovery") ||
        !equivalentFresh(session, fixtureData, source, project, temporary, &oracleSerial, "control-flow redo vs full")) return false;
    if (!success(session.editAnnotation(0x1090, "patch", "a5"), "patch bytes without a known code owner") ||
        !mode(session, "full", "unknown data dependency safely falls back to full discovery") ||
        !equivalentFresh(session, fixtureData, source, project, temporary, &oracleSerial, "unknown-data fallback vs full") ||
        !check(contents(source) == fixtureData.bytes, "cache/reanalysis never changes source input") ||
        !check(session.annotation(0x1000, "bookmark") == "cache bookmark", "all reanalysis preserves authoritative annotations")) return false;
    std::cout << archName(architecture) << " Program cache/incremental integration passed\n";
    return true;
}
}  // namespace

int main() {
    bool ok = serializerContracts();
    ok = boundedSnapshotContracts(Arch::kAArch64) && ok;
    ok = boundedSnapshotContracts(Arch::kX86_64) && ok;
    ok = sharedOwnerContract(Arch::kAArch64) && ok;
    ok = sharedOwnerContract(Arch::kX86_64) && ok;
    ok = reusedSessionContract() && ok;
    ok = integration(Arch::kAArch64) && ok;
    ok = integration(Arch::kX86_64) && ok;
    std::cout << "Program cache contracts: " << checks << " checks, " << failures << " failures\n";
    return ok && failures == 0 ? 0 : 1;
}
