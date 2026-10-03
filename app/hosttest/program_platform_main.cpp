#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <unistd.h>

#include "mint/session.h"

using namespace mint;

namespace {

bool check(bool condition, const std::string& message) {
    if (!condition) std::cerr << "program platform integration: " << message << '\n';
    return condition;
}

bool success(const Status& status, const std::string& message) {
    return check(status.ok(), message + ": " + status.toString());
}

class TemporaryFiles {
public:
    ~TemporaryFiles() { for (const auto& path : paths_) {::unlink(path.c_str());::unlink((path+".analysis").c_str());} }

    std::string create(const std::vector<u8>& bytes, bool removeForNewFile = false) {
        std::string path = "/private/tmp/mint-platform-test-XXXXXX";
        const int fd = ::mkstemp(path.data());
        if (fd < 0) return {};
        paths_.push_back(path);
        size_t at = 0;
        bool ok = true;
        while (at < bytes.size()) {
            const auto count = ::write(fd, bytes.data() + at, bytes.size() - at);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { ok = false; break; }
            at += static_cast<size_t>(count);
        }
        if (::close(fd) != 0) ok = false;
        if (removeForNewFile && ::unlink(path.c_str()) != 0) ok = false;
        return ok ? path : std::string{};
    }

private:
    std::vector<std::string> paths_;
};

std::vector<u8> contents(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

template <typename T>
void store(std::vector<u8>* bytes, size_t offset, T value) {
    if (offset + sizeof(T) > bytes->size()) bytes->resize(offset + sizeof(T));
    std::memcpy(bytes->data() + offset, &value, sizeof(T));
}

template <typename T>
void append(std::vector<u8>* bytes, T value) {
    const size_t offset = bytes->size(); bytes->resize(offset + sizeof(T));
    std::memcpy(bytes->data() + offset, &value, sizeof(T));
}

std::vector<u8> projectWithInvalidSymbol() {
    std::vector<u8> bytes{'M', 'I', 'N', 'T', 'P', 'R', '0', '1'};
    append<u32>(&bytes, 1); append<Address>(&bytes, 0x1000);
    append<u32>(&bytes, 4); append<u32>(&bytes, 11);
    const std::string kind = "name", value = "not a label";
    bytes.insert(bytes.end(), kind.begin(), kind.end());
    bytes.insert(bytes.end(), value.begin(), value.end());
    return bytes;
}

std::vector<u8> fixture() {
    std::vector<u8> bytes(0x50, 0);
    constexpr u32 nop = 0xd503201f, ret = 0xd65f03c0;
    store<u32>(&bytes, 0x00, nop); store<u32>(&bytes, 0x04, nop);
    store<u32>(&bytes, 0x08, ret);
    store<u32>(&bytes, 0x10, nop); store<u32>(&bytes, 0x14, ret);
    bytes[0x20] = 'A'; store<u32>(&bytes, 0x24, 0x11223344);
    store<u32>(&bytes, 0x28, 0x55667788);
    const std::string string = "mint";
    std::memcpy(bytes.data() + 0x30, string.c_str(), string.size() + 1);
    store<u32>(&bytes, 0x40, 0x97fffff0); // bl 0x1000 from 0x1040
    store<u32>(&bytes, 0x44, ret);
    return bytes;
}

bool memoryWord(const Session& session, Address address, u32 expected) {
    u32 value = 0;
    return session.image().memory().readInt(address, &value) && value == expected;
}

bool constantReturnRegression() {
    TemporaryFiles temporary;
    struct Fixture {
        Arch architecture;
        std::vector<u8> bytes;
        Address patchAddress;
        std::string patch;
    };
    const std::vector<Fixture> fixtures{
        {Arch::kAArch64, {0xe0, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6}, 0x1000, "20 01 80 d2"},
        {Arch::kX86_64, {0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3}, 0x1001, "09"}
    };
    auto returnedConstant = [](Session& session, unsigned value) {
        const auto source = session.decompiledCFor(0x1000);
        return source.find("void sub_") == std::string::npos &&
               source.find("return;") == std::string::npos &&
               source.find("return ") != std::string::npos &&
               source.find(std::to_string(value)) != std::string::npos;
    };
    for (const auto& fixture : fixtures) {
        const auto source = temporary.create(fixture.bytes);
        const auto project = temporary.create({}, true);
        Session session;
        if (!success(session.openRawPath(source, fixture.architecture, 0x1000, 0x1000), "open constant-return native leaf") ||
            !success(session.attachProject(project), "attach constant-return project") ||
            !success(session.analyze(), "analyze constant-return native leaf") ||
            !check(returnedConstant(session, 7), std::string(archName(fixture.architecture)) +
                   " implicit ABI return value survives pre-SSA simplification") ||
            !success(session.editAnnotation(fixture.patchAddress, "patch", fixture.patch), "patch constant return from7 to9") ||
            !check(returnedConstant(session, 9), "patched return value reaches decompiler") ||
            !success(session.undoEdit(false), "undo constant-return patch") ||
            !check(returnedConstant(session, 7), "undo restores return semantics") ||
            !success(session.undoEdit(true), "redo constant-return patch") ||
            !check(returnedConstant(session, 9), "redo restores patched return semantics")) return false;
        Session reopened;
        if (!success(reopened.openRawPath(source, fixture.architecture, 0x1000, 0x1000), "reopen constant-return input") ||
            !success(reopened.attachProject(project), "reopen constant-return project") ||
            !success(reopened.analyze(), "analyze restored constant-return patch") ||
            !check(returnedConstant(reopened, 9) && contents(source) == fixture.bytes,
                   "persisted return-value patch survives reopen without modifying source")) return false;
    }
    return true;
}

bool tests() {
    TemporaryFiles temporary;
    const auto original = fixture();
    const auto source = temporary.create(original);
    const auto project = temporary.create({}, true);
    const auto exported = temporary.create({}, true);
    if (!check(!source.empty() && !project.empty() && !exported.empty(), "create unique test files")) return false;

    Session session;
    if (!success(session.openRawPath(source, Arch::kAArch64, 0x1000, 0x1000), "open explicit native raw input") ||
        !success(session.analyze(), "analyze original input") ||
        !success(session.attachProject(project), "attach new persistent project")) return false;
    if (!check(session.analyzed() && session.analyzer().functions().size() == 1 &&
               session.analyzer().code().size() == 3, "initial raw function discovery") ||
        !check(session.program().memory().segments().size() == 1 &&
               session.memoryBlocksText().find("raw") != std::string::npos,
               "central Program exposes bound native memory blocks")) return false;

    if (!success(session.editAnnotation(0x1000, "name", "entry_demo"), "rename function") ||
        !success(session.editAnnotation(0x1000, "comment", "owned review\nsecond line"), "persist multiline comment") ||
        !success(session.editAnnotation(0x1004, "bookmark", "review this data"), "persist bookmark") ||
        !success(session.defineType("Packet=struct{tag:u8;value:u32}"), "define aggregate type")) return false;
    DataTypeLayout layout;
    if (!success(session.program().types().resolve("Packet", &layout), "resolve custom type") ||
        !check(layout.size == 8 && layout.fields.size() == 2 && layout.fields[1].offset == 4,
               "aggregate layout reaches central Program")) return false;

    if (!success(session.editAnnotation(0x1020, "data", "Packet"), "define aggregate data") ||
        !success(session.editAnnotation(0x1028, "data", "u32"), "define adjacent data") ||
        !success(session.editAnnotation(0x1030, "data", "cstring"), "define terminated string") ||
        !success(session.editAnnotation(0x1035, "data", "u8"), "define data immediately after string terminator") ||
        !success(session.editAnnotation(0x1004, "data", "u32"), "reclassify former instruction as data")) return false;
    if (!check(session.analyzer().code().find(0x1004) == nullptr &&
               session.analyzer().code().find(0x1008) == nullptr &&
               session.analyzer().functionAt(0x1000)->instructions.size() == 1,
               "data definition changes authoritative descent and function bounds")) return false;
    const auto dataRows = session.programListing(0x1004, 1);
    if (!check(dataRows.size() == 1 && dataRows[0].address == 0x1004 && dataRows[0].size == 4 &&
               dataRows[0].text.find("u32") != std::string::npos &&
               dataRows[0].comment.find("review this data") != std::string::npos,
               "unified listing renders persisted data and bookmark")) return false;

    if (!success(session.editAnnotation(0x1010, "function", "code"), "seed unreachable function") ||
        !success(session.editAnnotation(0x1040, "function", "code"), "seed direct caller") ||
        !success(session.editAnnotation(0x1000, "prototype", "uint64_t(uint64_t context)"), "edit user prototype")) return false;
    if (!check(session.analyzer().functionAt(0x1010) &&
               session.analyzer().functionAt(0x1010)->origin == FunctionOrigin::kUser &&
               session.analyzer().functionAt(0x1010)->instructions.size() == 2,
               "user function seed is included with provenance") ||
        !check(session.provenanceText(0x1010).find("Origin: user") != std::string::npos,
               "provenance report exposes user authority")) return false;
    const auto pseudoC = session.decompiledCFor(0x1000);
    if (!check(pseudoC.find("entry_demo") != std::string::npos &&
               pseudoC.find("context") != std::string::npos &&
               pseudoC.find("owned review") != std::string::npos,
               "decompiler uses central symbol, signature and comment") ||
        !check(!session.cfgTextFor(0x1010).empty() && !session.irTextFor(0x1010).empty(),
               "CFG/IR address views resolve explicit function")) return false;
    const auto references = session.referencesText(0x1000);
    if (!check(session.program().referencesReady() &&
               references.find("1040") != std::string::npos && references.find("call") != std::string::npos,
               "reference index includes direct caller with navigable source") ||
        !check(session.searchText("entry_demo").find("1000") != std::string::npos &&
               session.searchText("review this data").find("1004") != std::string::npos &&
               session.searchText("bytes: 6d 69 6e 74").find("1030") != std::string::npos,
               "global symbol/comment/bookmark/byte searches use Program addresses")) return false;

    const auto revision = session.program().revision();
    const auto library = session.program().types().serialize();
    bool rejected = true;
    rejected &= check(!session.editAnnotation(0x1010, "name", "return").ok(), "reject keyword symbol");
    rejected &= check(!session.editAnnotation(0x1010, "name", "entry_demo").ok(), "reject duplicate symbol");
    rejected &= check(!session.editAnnotation(0x9999, "comment", "outside").ok(), "reject unmapped annotation");
    rejected &= check(!session.editAnnotation(0, "source", "replacement").ok(), "source identity is read-only");
    rejected &= check(!session.editAnnotation(0x1024, "data", "u64").ok(), "reject overlapping data object");
    rejected &= check(!session.defineType("Bad=struct{a:u32@0;b:u32@2}").ok(), "reject overlapping struct fields");
    rejected &= check(!session.defineType("Packet=struct{tag:u8;value:u64}").ok(), "reject type growth overlapping adjacent data");
    rejected &= check(!session.eraseType("Packet").ok(), "reject deletion of mapped data type");
    rejected &= check(!session.editAnnotation(0x1002, "function", "code").ok(), "reject unaligned AArch64 function");
    rejected &= check(!session.editAnnotation(0x1004, "function", "code").ok(), "reject function in defined data");
    rejected &= check(!session.editAnnotation(0x1010, "data", "u32").ok(), "reject data covering user function seed");
    rejected &= check(!session.editAnnotation(0x1034, "patch", "41").ok(),
                      "reject patched cstring terminator extending into adjacent data");
    u8 terminator = 1;
    rejected &= check(session.image().memory().read(0x1034, &terminator, 1) && terminator == 0 &&
                      session.annotation(0x1034, "patch").empty(),
                      "rejected terminator patch preserves original memory and patch model");
    rejected &= check(session.program().revision() == revision && session.analyzed() &&
                      session.program().types().serialize() == library &&
                      session.annotation(0x1002, "function").empty() &&
                      session.annotation(0x1004, "function").empty() &&
                      session.annotation(0x1010, "data").empty(),
                      "rejected edits preserve live analysis, revision, types and persistent decisions");
    if (!rejected) return false;

    if (!success(session.editAnnotation(0x1010, "patch", "c0 03 5f d6"), "persist instruction-byte patch") ||
        !check(memoryWord(session, 0x1010, 0xd65f03c0) &&
               session.analyzer().functionAt(0x1010)->instructions.size() == 1 &&
               !session.program().referencesReady(), "patch applies to bound memory, reanalysis and index invalidation") ||
        !success(session.undoEdit(false), "undo patch") ||
        !check(memoryWord(session, 0x1010, 0xd503201f) &&
               session.analyzer().functionAt(0x1010)->instructions.size() == 2,
               "patch undo restores original instruction and CFG") ||
        !success(session.undoEdit(true), "redo patch") ||
        !check(memoryWord(session, 0x1010, 0xd65f03c0), "redo reapplies bytes") ||
        !success(session.editAnnotation(0x1010, "patch", ""), "reset patch") ||
        !check(memoryWord(session, 0x1010, 0xd503201f), "reset removes overlay") ||
        !success(session.undoEdit(false), "undo reset to leave persistent patch")) return false;
    const auto patchRevision = session.program().revision();
    if (!check(!session.editAnnotation(0x1012, "patch", "00 00 00 00").ok() &&
               !session.editAnnotation(0x1010, "patch", "gg").ok() &&
               !session.editAnnotation(0x104f, "patch", "00 00").ok() &&
               session.program().revision() == patchRevision,
               "malformed/overlapping/non-file-backed patches are rejected atomically")) return false;

    if (!check(contents(source) == original, "patches never modify input file") ||
        !success(session.exportPatchedCopy(exported), "export new patched copy")) return false;
    auto expectedExport = original;
    store<u32>(&expectedExport, 0x10, 0xd65f03c0);
    if (!check(contents(exported) == expectedExport, "export contains only requested overlay") ||
        !check(!session.exportPatchedCopy(exported).ok() && contents(exported) == expectedExport,
               "O_EXCL refuses overwriting prior export") ||
        !check(!session.exportPatchedCopy(source).ok() && contents(source) == original,
               "O_EXCL refuses overwriting original source")) return false;

    const auto savedProject = contents(project);
    Session reopened;
    if (!success(reopened.openRawPath(source, Arch::kAArch64, 0x1000, 0x1000), "reopen original input") ||
        !success(reopened.attachProject(project), "restore project before analysis") ||
        !success(reopened.analyze(), "analyze restored Program") ||
        !check(reopened.nameAt(0x1000) == "entry_demo" &&
               reopened.annotation(0x1000, "comment") == "owned review\nsecond line" &&
               reopened.annotation(0x1004, "bookmark") == "review this data" &&
               reopened.annotation(0x1020, "data") == "Packet" &&
               reopened.annotation(0x1010, "function") == "code" &&
               reopened.annotation(0x1010, "patch") == "c0 03 5f d6" &&
               reopened.program().types().serialize() == library &&
               memoryWord(reopened, 0x1010, 0xd65f03c0) &&
               reopened.analyzer().code().find(0x1004) == nullptr &&
               reopened.analyzer().functionAt(0x1010)->origin == FunctionOrigin::kUser,
               "reopen preserves edits, aggregate types, exclusions, user roots and patched memory")) return false;

    Session wrongConfiguration;
    if (!success(wrongConfiguration.openRawPath(source, Arch::kAArch64, 0x2000, 0x2000), "open alternate raw configuration") ||
        !check(!wrongConfiguration.attachProject(project).ok() && contents(project) == savedProject,
               "source guard rejects alternate raw base without rewriting project")) return false;
    auto changed = original; changed.back() = 0x42;
    const auto changedSource = temporary.create(changed);
    Session wrongBinary;
    if (!success(wrongBinary.openRawPath(changedSource, Arch::kAArch64, 0x1000, 0x1000), "open different input") ||
        !check(!wrongBinary.attachProject(project).ok() && contents(project) == savedProject,
               "source guard rejects binary with a different fingerprint")) return false;

    const auto invalidProject = temporary.create(projectWithInvalidSymbol());
    const auto restoredRevision = reopened.program().revision();
    if (!check(!reopened.attachProject(invalidProject).ok() && reopened.analyzed() &&
               reopened.nameAt(0x1000) == "entry_demo" &&
               reopened.program().revision() == restoredRevision,
               "invalid persisted symbol cannot replace active Program")) return false;
    auto trailingProject = savedProject; trailingProject.push_back(0x42);
    const auto trailingPath = temporary.create(trailingProject);
    if (!check(!reopened.attachProject(trailingPath).ok() && contents(project) == savedProject,
               "trailing bytes reject malformed project without touching valid project")) return false;

    // The generic Program serializer cannot validate mapped-address semantics.
    // Build a syntactically valid but conflicting model and require Session's
    // native preflight to reject it before replacing the already-open project.
    const auto conflictingProject = temporary.create({}, true);
    Program conflicting;
    if (!success(conflicting.open(conflictingProject, session.annotation(0, "source")), "create semantically invalid project fixture") ||
        !success(conflicting.edit(0x1004, "data", "u32"), "persist conflicting data fixture") ||
        !success(conflicting.edit(0x1004, "function", "code"), "persist conflicting user seed fixture") ||
        !check(!reopened.attachProject(conflictingProject).ok() && reopened.analyzed() &&
               reopened.nameAt(0x1000) == "entry_demo" &&
               reopened.program().revision() == restoredRevision &&
               memoryWord(reopened, 0x1010, 0xd65f03c0) &&
               reopened.annotation(0x1010, "patch") == "c0 03 5f d6",
               "persisted code/data conflict cannot replace Program or reset active patched memory")) return false;

    const auto standaloneProject = temporary.create({}, true);
    Program standalone;
    if (!success(standalone.open(standaloneProject, "fixture identity"), "open standalone Program") ||
        !success(standalone.edit(0x1000, "comment", "standalone comment"), "persist direct Program edit")) return false;
    standalone.setReferences({{0x1000, 0x1020, "read"}, {0x1004, 0x1020, "address candidate"}});
    if (!check(standalone.referencesAt(0x1020).size() == 2 && standalone.referencesAt(0x1000).size() == 1,
               "bidirectional central reference index") ||
        !success(standalone.edit(0x1000, "bookmark", "direct review"), "edit after indexing") ||
        !check(standalone.referencesReady() && standalone.referencesAt(0x1020).size()==2,
               "metadata edits preserve structural reference indexes") ||
        !success(standalone.undo(), "standalone Program undo") ||
        !check(standalone.get(0x1000, "bookmark").empty() && standalone.referencesReady(),
               "metadata undo removes bookmark without discarding references") ||
        !success(standalone.redo(), "standalone Program redo")) return false;
    const auto standaloneRevision = standalone.revision();
    if (!check(!standalone.open(source + "/project", "fixture identity").ok() &&
               standalone.revision() == standaloneRevision &&
               standalone.get(0x1000, "comment") == "standalone comment",
               "failed project open preserves previous direct Program state")) return false;
    Program directReopen;
    if (!success(directReopen.open(standaloneProject, "fixture identity"), "reopen standalone Program") ||
        !check(directReopen.get(0x1000, "bookmark") == "direct review", "redo persists across Program reopen")) return false;
    if(!success(standalone.edit(0x1000,"patch","1f 20 03 d5"),"structural edit after indexing") ||
       !check(!standalone.referencesReady(),"structural mutations invalidate reference indexes"))return false;
    return true;
}

}  // namespace

int main() {
    if (!constantReturnRegression() || !tests()) return 1;
    std::cout << "Program/Session/type/data/function/patch/reopen/export integration tests passed\n";
    return 0;
}
