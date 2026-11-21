#include "mint/session.h"
#include "program_save_test_hook.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sys/wait.h>
#include <unistd.h>

using namespace mint;

namespace {
constexpr Address kEntry = 0x1000;
constexpr const char* kPatched = "20 01 80 d2";
constexpr const char* kUncommitted = "60 01 80 d2";

void require(bool value, const std::string& message) {
    if (!value) {
        std::cerr << "Program recovery: " << message << '\n';
        std::exit(1);
    }
}
void okay(const Status& status, const std::string& stage) {
    require(status.ok(), stage + ": " + status.toString());
}

class Fixture {
public:
    Fixture() {
        auto temporary = (std::filesystem::temp_directory_path() / "mint-recovery-XXXXXX").string();
        require(mkdtemp(temporary.data()) != nullptr, "create a private fixture directory");
        directory = temporary;
        source = directory / "source.bin";
        program = directory / "program.mint";
        cache = directory / "program.mint.analysis";
        write(source, {0xe0, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6});
    }
    ~Fixture() {
        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }
    static std::string read(const std::filesystem::path& path) {
        std::ifstream stream(path, std::ios::binary);
        require(stream.is_open(), "read " + path.filename().string());
        return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
    }
    static void write(const std::filesystem::path& path, std::initializer_list<unsigned char> bytes) {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        for (const auto byte : bytes) stream.put(static_cast<char>(byte));
        stream.close();
        require(!stream.fail(), "write " + path.filename().string());
    }
    void attach(Session& session, const std::filesystem::path& path, bool full = false) const {
        okay(session.openRawPath(source.string(), Arch::kAArch64, kEntry, kEntry), "open fixture input");
        okay(session.attachProject(path.string()), "attach fixture Program");
        okay(full ? session.reanalyze() : session.analyze(), "read fixture analysis");
    }
    size_t pendingTransactions() const {
        size_t count = 0;
        for (const auto& item : std::filesystem::directory_iterator(directory))
            if (item.path().filename().string().rfind("program.mint.tmp.", 0) == 0) ++count;
        return count;
    }
    std::filesystem::path directory, source, program, cache;
};

struct Snapshot {
    std::string pseudoC, ir, cfg, references, types;

    bool operator==(const Snapshot& other) const {
        return pseudoC == other.pseudoC && ir == other.ir && cfg == other.cfg &&
               references == other.references && types == other.types;
    }
};

Snapshot snapshot(Session& session) {
    return {session.decompiledCFor(kEntry), session.irTextFor(kEntry),
            session.cfgTextFor(kEntry), session.referencesText(kEntry),
            session.program().types().serialize()};
}

int writeAttempts = 0;
ssize_t failAfterPartialWrite(int fd, const void* data, size_t size) {
    if (++writeAttempts == 1) return ::write(fd, data, std::min(size, size_t{7}));
    errno = ENOSPC;
    return -1;
}

template <typename Operation>
void outOfSpace(Session& session, const Fixture& fixture, Operation operation) {
    const auto bytes = Fixture::read(fixture.program);
    const auto before = snapshot(session);
    const auto revision = session.program().revision();
    const auto patch = session.annotation(kEntry, "patch");
    writeAttempts = 0;
    testing::setProgramSaveHooks({failAfterPartialWrite, nullptr});
    const auto status = operation();
    testing::setProgramSaveHooks({});
    require(status.code() == ErrorCode::kIoError && writeAttempts == 2 &&
            status.message().find("write temporary file") != std::string::npos &&
            status.message().find(std::strerror(ENOSPC)) != std::string::npos,
            "partial write followed by ENOSPC gives an actionable failure");
    require(Fixture::read(fixture.program) == bytes && fixture.pendingTransactions() == 0,
            "ENOSPC leaves the committed file intact and removes the partial temporary file");
    require(session.program().revision() == revision && session.annotation(kEntry, "patch") == patch &&
            snapshot(session) == before, "ENOSPC leaves the live model and all derived views intact");
}

void abruptExit() {
    if (kill(getpid(), SIGKILL) != 0) _exit(2);
    _exit(3);
}

void runKilledChild(const Fixture& fixture, bool committed) {
    const auto child = fork();
    require(child >= 0, "fork an owned test worker");
    if (child == 0) {
        Session session;
        fixture.attach(session, fixture.program);
        if (committed) {
            okay(session.editAnnotation(kEntry, "bookmark", "acknowledged before death"), "commit child bookmark");
            abruptExit();
        }
        testing::setProgramSaveHooks({nullptr, abruptExit});
        session.editAnnotation(kEntry, "patch", kUncommitted);
        _exit(4);
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    require(waited == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
            "worker actually died at the requested transaction boundary");
}
} // namespace

int main() {
    Fixture fixture;
    const auto originalSource = Fixture::read(fixture.source);
    Session session;
    fixture.attach(session, fixture.program);
    okay(session.defineType("RecoveryRecord=struct{value:u64}"), "commit user type");
    okay(session.editAnnotation(kEntry, "prototype", "uint64_t(void)"), "commit prototype");
    okay(session.editAnnotation(kEntry, "comment", "acknowledged comment"), "commit comment");
    okay(session.editAnnotation(kEntry, "patch", kPatched), "commit first patch");
    const auto patched = snapshot(session);
    require(patched.ir.find("9:8") != std::string::npos, "committed patch changes effective instruction");

    outOfSpace(session, fixture, [&] { return session.editAnnotation(kEntry, "patch", kUncommitted); });
    outOfSpace(session, fixture, [&] { return session.undoEdit(false); });
    okay(session.undoEdit(false), "retry undo after ENOSPC");
    require(session.annotation(kEntry, "patch").empty(), "retry undo removes the last successful patch");
    require(Fixture::read(fixture.source) == originalSource &&
            session.irTextFor(kEntry).find("7:8") != std::string::npos,
            "undo restores the original effective bytes");
    outOfSpace(session, fixture, [&] { return session.undoEdit(true); });
    okay(session.undoEdit(true), "retry redo after ENOSPC");
    require(snapshot(session) == patched, "failed redo leaves history available for retry");

    const auto committedBytes = Fixture::read(fixture.program);
    runKilledChild(fixture, false);
    require(fixture.pendingTransactions() == 1 && Fixture::read(fixture.program) == committedBytes,
            "death after syncing the temporary file leaves only an unpublished transaction");
    Session recovered;
    fixture.attach(recovered, fixture.program);
    require(recovered.annotation(kEntry, "patch") == kPatched && snapshot(recovered) == patched,
            "reopen ignores the uncommitted temporary patch");
    runKilledChild(fixture, true);
    Fixture::write(fixture.cache, {0, 1, 2, 3});

    Session afterDeath;
    fixture.attach(afterDeath, fixture.program);
    require(afterDeath.analysisStatusText().find("mode=full") != std::string::npos,
            "corrupted derived cache is rebuilt by full discovery");
    require(afterDeath.annotation(kEntry, "bookmark") == "acknowledged before death" &&
            afterDeath.annotation(kEntry, "comment") == "acknowledged comment" &&
            afterDeath.annotation(kEntry, "prototype") == "uint64_t(void)" &&
            afterDeath.annotation(kEntry, "patch") == kPatched &&
            afterDeath.program().types().serialize().find("RecoveryRecord") != std::string::npos,
            "death after commit and unusable cache preserve all acknowledged user state");
    const auto oracleProgram = fixture.directory / "oracle.mint";
    std::filesystem::copy_file(fixture.program, oracleProgram);
    Session oracle;
    fixture.attach(oracle, oracleProgram, true);
    require(snapshot(afterDeath) == snapshot(oracle), "recovered Program equals independent full analysis");
    require(Fixture::read(fixture.source) == originalSource, "recovery never rewrites the imported binary");
    std::cout << "Program recovery passed: ENOSPC, failed undo/redo, pre/post-commit SIGKILL, corrupt cache\n";
}
