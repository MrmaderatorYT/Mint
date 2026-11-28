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

int failTemporarySync(int) {
    errno = ENOSPC;
    return -1;
}

int failPublication(const char*, const char*) {
    errno = ENOSPC;
    return -1;
}

enum class FailurePoint { Write, Sync, Rename };

template <typename Operation>
void outOfSpace(Session& session, const Fixture& fixture, Operation operation,
                FailurePoint point = FailurePoint::Write) {
    const auto bytes = Fixture::read(fixture.program);
    const auto before = snapshot(session);
    const auto revision = session.program().revision();
    const auto patch = session.annotation(kEntry, "patch");
    writeAttempts = 0;
    testing::ProgramSaveHooks hooks;
    const char* stage = nullptr;
    switch (point) {
        case FailurePoint::Write: hooks.write = failAfterPartialWrite; stage = "write temporary file"; break;
        case FailurePoint::Sync: hooks.syncTemporary = failTemporarySync; stage = "sync temporary file"; break;
        case FailurePoint::Rename: hooks.rename = failPublication; stage = "publish project"; break;
    }
    testing::setProgramSaveHooks(hooks);
    const auto status = operation();
    testing::setProgramSaveHooks({});
    require(status.code() == ErrorCode::kIoError && (point != FailurePoint::Write || writeAttempts == 2) &&
            status.message().find(stage) != std::string::npos &&
            status.message().find(std::strerror(ENOSPC)) != std::string::npos,
            std::string("ENOSPC gives an actionable failure at ") + stage);
    require(Fixture::read(fixture.program) == bytes && fixture.pendingTransactions() == 0,
            "ENOSPC leaves the committed file intact and removes the partial temporary file");
    require(session.program().revision() == revision && session.annotation(kEntry, "patch") == patch &&
            snapshot(session) == before, "ENOSPC leaves the live model and all derived views intact");
}

void reopenWithWriteFailure(const Fixture& fixture, Session& session) {
    const auto committed = Fixture::read(fixture.program);
    const auto pending = fixture.pendingTransactions();
    writeAttempts = 0;
    testing::setProgramSaveHooks({failAfterPartialWrite});
    fixture.attach(session, fixture.program);
    testing::setProgramSaveHooks({});
    require(writeAttempts == 0 && Fixture::read(fixture.program) == committed &&
            fixture.pendingTransactions() == pending,
            "opening the current bound Program never attempts an authoritative write");
}

void bindingAndUpgradeStillWrite(const Fixture& fixture, const Snapshot& patched) {
    const auto legacy = fixture.directory / "legacy.mint";
    std::filesystem::copy_file(fixture.program, legacy);
    std::fstream file(legacy, std::ios::binary | std::ios::in | std::ios::out);
    file.write("MINTPR03", 8);
    file.close();
    require(!file.fail(), "prepare a test-owned older Program header");
    const auto legacyBytes = Fixture::read(legacy);
    const auto unbound = fixture.directory / "unbound.mint";
    Fixture::write(unbound, {'M','I','N','T','P','R','0','4',0,0,0,0});
    const auto unboundBytes = Fixture::read(unbound);

    Session initial;
    okay(initial.openRawPath(fixture.source.string(), Arch::kAArch64, kEntry, kEntry), "open binding input");
    for (const auto& filePath : {legacy, unbound, fixture.directory / "new.mint"}) {
        writeAttempts = 0;
        testing::setProgramSaveHooks({failAfterPartialWrite});
        const auto status = initial.attachProject(filePath.string());
        testing::setProgramSaveHooks({});
        require(status.code() == ErrorCode::kIoError && writeAttempts == 2,
                "legacy migration and first source binding still require a durable write");
    }
    require(Fixture::read(legacy) == legacyBytes && Fixture::read(unbound) == unboundBytes &&
            !std::filesystem::exists(fixture.directory / "new.mint"),
            "failed upgrades and bindings leave all previous Program files intact");
    fixture.attach(initial, legacy);
    require(Fixture::read(legacy).rfind("MINTPR04", 0) == 0 && snapshot(initial) == patched,
            "retrying a legacy upgrade preserves the effective Program and writes the current format");
    fixture.attach(initial, unbound);
    require(Fixture::read(unbound) != unboundBytes && !initial.program().get(0, "source").empty(),
            "retrying an unbound Program establishes its source identity");
}

void abruptExit() {
    if (kill(getpid(), SIGKILL) != 0) _exit(2);
    _exit(3);
}

enum class DeathPoint { BeforeRename, AfterRename, AfterAcknowledgement };

void runKilledChild(const Fixture& fixture, DeathPoint point) {
    const auto child = fork();
    require(child >= 0, "fork an owned test worker");
    if (child == 0) {
        Session session;
        fixture.attach(session, fixture.program);
        if (point == DeathPoint::AfterAcknowledgement) {
            okay(session.editAnnotation(kEntry, "bookmark", "acknowledged before death"), "commit child bookmark");
            abruptExit();
        }
        testing::ProgramSaveHooks hooks;
        if (point == DeathPoint::BeforeRename) {
            hooks.beforeRename = abruptExit;
            testing::setProgramSaveHooks(hooks);
            session.editAnnotation(kEntry, "patch", kUncommitted);
        } else {
            hooks.afterRename = abruptExit;
            testing::setProgramSaveHooks(hooks);
            session.editAnnotation(kEntry, "bookmark", "published before acknowledgement");
        }
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
    outOfSpace(session, fixture, [&] { return session.editAnnotation(kEntry, "patch", kUncommitted); }, FailurePoint::Sync);
    outOfSpace(session, fixture, [&] { return session.editAnnotation(kEntry, "patch", kUncommitted); }, FailurePoint::Rename);
    outOfSpace(session, fixture, [&] { return session.undoEdit(false); });
    okay(session.undoEdit(false), "retry undo after ENOSPC");
    require(session.annotation(kEntry, "patch").empty(), "retry undo removes the last successful patch");
    require(Fixture::read(fixture.source) == originalSource &&
            session.irTextFor(kEntry).find("7:8") != std::string::npos,
            "undo restores the original effective bytes");
    outOfSpace(session, fixture, [&] { return session.editAnnotation(kEntry, "patch", kUncommitted); }, FailurePoint::Rename);
    outOfSpace(session, fixture, [&] { return session.undoEdit(true); });
    okay(session.undoEdit(true), "retry redo after ENOSPC");
    require(snapshot(session) == patched, "a failed divergent edit and failed redo both leave the redo available");
    bindingAndUpgradeStillWrite(fixture, patched);

    const auto committedBytes = Fixture::read(fixture.program);
    runKilledChild(fixture, DeathPoint::BeforeRename);
    require(fixture.pendingTransactions() == 1 && Fixture::read(fixture.program) == committedBytes,
            "death after syncing the temporary file leaves only an unpublished transaction");
    Session recovered;
    reopenWithWriteFailure(fixture, recovered);
    require(recovered.analysisStatusText().find("mode=restored") != std::string::npos &&
            recovered.annotation(kEntry, "patch") == kPatched && snapshot(recovered) == patched,
            "warm reopen during ENOSPC ignores the uncommitted temporary patch");
    runKilledChild(fixture, DeathPoint::AfterRename);
    Session published;
    reopenWithWriteFailure(fixture, published);
    require(fixture.pendingTransactions() == 1 &&
            published.annotation(kEntry, "bookmark") == "published before acknowledgement" &&
            published.annotation(kEntry, "patch") == kPatched,
            "process death just after rename leaves a complete, published transaction");

    runKilledChild(fixture, DeathPoint::AfterAcknowledgement);
    Fixture::write(fixture.cache, {0, 1, 2, 3});

    Session afterDeath;
    reopenWithWriteFailure(fixture, afterDeath);
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

    require(std::filesystem::remove(fixture.cache) && std::filesystem::create_directory(fixture.cache),
            "block publication at the test-owned cache path");
    Session withoutCache;
    reopenWithWriteFailure(fixture, withoutCache);
    require(withoutCache.analysisStatusText().find("mode=full") != std::string::npos &&
            withoutCache.analysisStatusText().find("derived cache could not be saved") != std::string::npos &&
            snapshot(withoutCache) == snapshot(oracle), "failed cache publication cannot hide or alter the authoritative state");
    require(Fixture::read(fixture.source) == originalSource, "recovery never rewrites the imported binary");
    std::cout << "Program recovery passed: ENOSPC write/sync/rename, failed edit/undo/redo, SIGKILL at publication, corrupt and unwritable cache\n";
}
