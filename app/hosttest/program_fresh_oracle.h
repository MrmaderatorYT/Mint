#pragma once

#include "mint/session.h"

#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <unistd.h>

namespace mint::testing {

// A separate, cacheless project using only the persisted authoritative state.
// The snapshot includes the public views because an unchanged CFG alone would
// miss stale types, summaries and argument bindings rendered by the decompiler.
inline std::string analysisSnapshot(Session& session) {
    std::ostringstream output;
    output << session.program().types().serialize();
    for (const auto& function : session.analyzer().functions()) {
        output << function.entry << ' ' << function.incomplete << '\n';
        for (Address address : function.instructions) output << address << ' ';
        output << '\n';
        for (Address callee : function.callees) output << "callee " << callee << '\n';
        for (const auto& jump : function.resolvedIndirectJumps) {
            output << "indirect " << jump.branch << '\n';
            for (Address target : jump.targets) output << target << '\n';
            for (const auto& arm : jump.switchCases) output << arm.value << ':' << arm.target << '\n';
        }
        for (const auto& tail : function.tailCalls)
            output << "tail " << tail.branch << ':' << tail.target << '\n';
        output << session.cfgTextFor(function.entry) << '\n'
               << session.irTextFor(function.entry) << '\n'
               << session.decompiledCFor(function.entry) << '\n'
               << session.referencesText(function.entry) << '\n';
    }
    return output.str();
}

template <typename OpenInput>
Status matchesFreshAnalysis(Session& current, const std::string& project, OpenInput openInput) {
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
    if (analysisSnapshot(current) != analysisSnapshot(fresh))
        return Status::error(ErrorCode::kInternalError, "effective analysis differs from independent full analysis");
    return Status::success();
}

} // namespace mint::testing
