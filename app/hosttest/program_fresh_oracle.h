#pragma once

#include "mint/session.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unistd.h>

namespace mint::testing {

// A separate, cacheless project using only the persisted authoritative state.
// The snapshot includes the public views because an unchanged CFG alone would
// miss stale types, summaries and argument bindings rendered by the decompiler.
inline std::string analysisSnapshot(Session& session) {
    std::ostringstream output;
    const auto& analyzer = session.analyzer();
    output << session.program().types().serialize() << '\n' << session.interproceduralText();
    for (const auto& instruction : analyzer.code().instructions()) {
        DecodedInsn decoded;
        output << "instruction " << std::hex << instruction.address << ' ' << instruction.target << ' '
               << instruction.id << ' ' << unsigned(instruction.size) << ' ' << unsigned(instruction.flow)
               << ' ' << unsigned(session.image().architectureAt(instruction.address));
        if (session.renderInstruction(instruction.address, &decoded)) output << ' ' << decoded.text();
        output << '\n';
    }
    for (const auto& function : analyzer.functions()) {
        output << "function " << function.entry << ' ' << function.name << ' ' << unsigned(function.origin)
               << ' ' << unsigned(function.decodeArch) << ' ' << function.lowAddress << ' ' << function.highAddress
               << ' ' << function.incomplete << '\n';
        for (Address address : function.instructions) output << address << ' ';
        output << '\n';
        for (Address callee : function.callees) output << "callee " << callee << '\n';
        for (Address caller : analyzer.callersOf(function.entry)) output << "caller " << caller << '\n';
        for (const auto& jump : function.resolvedIndirectJumps) {
            output << "indirect " << jump.branch << ' ' << jump.selectorAddress << ' ' << jump.selectorRegister
                   << ' ' << unsigned(jump.selectorWidth) << ' ' << jump.table << '\n';
            for (Address target : jump.targets) output << target << '\n';
            for (const auto& arm : jump.switchCases) output << arm.value << ':' << arm.target << '\n';
        }
        for (const auto& tail : function.tailCalls)
            output << "tail " << tail.branch << ':' << tail.target << '\n';
        std::string anchors;
        const auto source = session.decompileReportFor(function.entry).text(&anchors);
        output << session.cfgTextFor(function.entry) << '\n'
               << session.irTextFor(function.entry) << '\n'
               << session.abiText(function.entry) << '\n'
               << source << '\n' << anchors << '\n'
               << session.referencesText(function.entry) << '\n';
    }
    for (const auto& reference : session.program().references())
        output << "reference " << reference.from << ' ' << reference.to << ' ' << reference.kind << '\n';
    return output.str();
}

inline bool hasAnalysisMode(const Session& session, const std::string& mode) {
    return session.analysisStatusText().rfind("mode=" + mode + " ", 0) == 0;
}

inline Status corruptDerivedCache(const std::string& project) {
    std::fstream cache(project + ".analysis", std::ios::in | std::ios::out | std::ios::binary);
    cache.seekg(-1, std::ios::end);
    char byte = 0;
    if (!cache.get(byte)) return Status::error(ErrorCode::kIoError, "read existing derived cache");
    cache.seekp(-1, std::ios::end);
    cache.put(static_cast<char>(byte ^ 0x01));
    cache.close();
    if (!cache) return Status::error(ErrorCode::kIoError, "corrupt test-owned derived cache");
    return Status::success();
}

inline std::string firstSnapshotDifference(const std::string& actual, const std::string& expected) {
    const auto mismatch = std::mismatch(actual.begin(), actual.end(), expected.begin(), expected.end());
    if (mismatch.first == actual.end() && mismatch.second == expected.end()) return {};
    const auto offset = static_cast<size_t>(mismatch.first - actual.begin());
    const auto line = std::count(actual.begin(), mismatch.first, '\n') + 1;
    const auto previousNewline = offset == 0 ? std::string::npos : actual.rfind('\n', offset - 1);
    const auto start = previousNewline == std::string::npos ? 0 : previousNewline + 1;
    const auto window = offset - start > 72 ? offset - 72 : start;
    const auto excerpt = [start, window](const std::string& text) {
        if (window >= text.size()) return std::string("<end of snapshot>");
        const auto end = text.find('\n', window);
        const auto length = end == std::string::npos ? text.size() - window : end - window;
        return (window > start ? "…" : "") + text.substr(window, std::min<size_t>(160, length));
    };
    return "line " + std::to_string(line) + ", column " + std::to_string(offset - start + 1) +
           "\n  current: " + excerpt(actual) + "\n  full:    " + excerpt(expected);
}

template <typename OpenInput, typename Snapshot = decltype(&analysisSnapshot)>
Status matchesFreshAnalysis(Session& current, const std::string& project, OpenInput openInput,
                            Snapshot snapshot = analysisSnapshot) {
    std::string oracle = project + ".oracle.XXXXXX";
    const int fd = mkstemp(oracle.data());
    if (fd < 0) return Status::error(ErrorCode::kIoError, "create an independent Program");
    ::close(fd);
    struct Cleanup {
        std::string project;
        ~Cleanup() {
            std::error_code ignored;
            std::filesystem::remove(project, ignored);
            std::filesystem::remove(project + ".analysis", ignored);
        }
    } cleanup{oracle};
    std::error_code error;
    std::filesystem::copy_file(project, oracle, std::filesystem::copy_options::overwrite_existing, error);
    if (error) return Status::error(ErrorCode::kIoError, "copy authoritative Program: " + error.message());
    Session fresh;
    auto status = openInput(fresh);
    if (status.ok()) status = fresh.attachProject(oracle);
    if (status.ok()) status = fresh.reanalyze();
    if (!status.ok()) return status;
    if (!hasAnalysisMode(fresh, "full"))
        return Status::error(ErrorCode::kInternalError, "oracle did not run full analysis");
    const auto difference = firstSnapshotDifference(snapshot(current), snapshot(fresh));
    if (!difference.empty())
        return Status::error(ErrorCode::kInternalError,
            "effective analysis differs from independent full analysis at " + difference);
    return Status::success();
}

} // namespace mint::testing
