#include "mint/session.h"

#include <cstring>
#include <cstdio>
#include <unordered_map>

#include "mint/analysis/jump_table_recovery.h"
#include "mint/base/log.h"
#include "mint/ir/lifter_dalvik.h"
#include "mint/obfuscation/deobfuscator.h"

namespace mint {

Status Session::openPath(const std::string& path) {
    Status status = file_.open(path);
    if (!status.ok()) return status;
    return finishOpen();
}

Status Session::openFd(int fd) {
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

    CodeAnalyzer::Options options;
    options.cancel = &cancel_;
    options.progress = &progress_;
    Status status = analyzer_.analyze(image_, options);
    if (!status.ok()) return status;
    detectorFindings_ = runDetectors(image_);
    analyzed_ = true;
    return Status::success();
}

bool Session::renderInstruction(Address addr, DecodedInsn* out) {
    if (!loaded_) return false;
    ByteView bytes = image_.memory().viewAt(addr, renderer_.maxInstructionSize());
    if (bytes.empty()) return false;
    return renderer_.decodeVerbose(addr, bytes, out);
}

std::string Session::commentFor(const InsnRecord& record) const {
    if (!record.hasKnownTarget()) return {};
    std::string name = image_.describeAddress(record.target);
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
    status = decompileIr(ir, &result, [this](Address target) {
        return image_.describeAddress(target);
    });
    if (!status.ok()) return "decompiler failed: " + status.toString();
    if (!obfuscation.findings.empty()) {
        result.cSource = "/* OLLVM findings: " + std::to_string(obfuscation.findings.size()) +
                         ", dispatcher blocks: " + std::to_string(obfuscation.unroll.dispatcherBlocks) +
                         " */\n" + result.cSource;
    }
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
    for (const std::string& warning : image_.warnings()) {
        all.push_back("loader: " + warning);
    }
    for (const std::string& warning : analyzer_.warnings()) {
        all.push_back("analysis: " + warning);
    }
    for (const DetectorFinding& finding : detectorFindings_) {
        if (all.size() >= 256) break;
        all.push_back("detector: " + std::string(findingKindName(finding.kind)) +
                      " 0x" + [&] { char buffer[32]; std::snprintf(buffer, sizeof(buffer), "%llx", static_cast<unsigned long long>(finding.address)); return std::string(buffer); }() +
                      " " + finding.name + " (" + finding.detail + ")");
    }
    return all;
}

}  // namespace mint
