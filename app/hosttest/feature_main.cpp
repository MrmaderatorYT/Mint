#include <cstdlib>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <cstdio>
#include "mint/session.h"

#include "mint/db/database.h"
#include "mint/analysis/code_analyzer.h"
#include "mint/base/mapped_file.h"
#include "mint/decompile/decompiler.h"
#include "mint/detectors/detector.h"
#include "mint/interp/emulator.h"
#include "mint/ir/lifter.h"
#include "mint/ir/lifter_dalvik.h"
#include "mint/loader/zip_reader.h"
#include "mint/obfuscation/deobfuscator.h"
#include "mint/obfuscation/string_recovery.h"

using namespace mint;

namespace {

IrFunction liftX86Bytes(const std::vector<u8>& bytes) {
    IrFunction function;
    function.entry = 0x8000;
    function.name = "x86_regression";
    function.arch = Arch::kX86_64;

    Lifter lifter;
    if (!lifter.open(Arch::kX86_64).ok()) return function;
    IrBuilder builder(&function);
    size_t offset = 0;
    while (offset < bytes.size()) {
        const u32 consumed = lifter.liftInstruction(
            function.entry + offset,
            ByteView(bytes.data() + offset, bytes.size() - offset), &builder);
        if (consumed == 0) break;
        offset += consumed;
        ++function.machineInsnCount;
    }
    IrBlock block;
    block.id = 0;
    block.start = function.entry;
    block.end = function.entry + offset;
    block.firstInsn = 0;
    block.insnCount = static_cast<u32>(function.insns.size());
    function.blocks.push_back(block);
    return function;
}

IrFunction makeAddFunction() {
    IrFunction function;
    function.entry = 0x1000; function.name = "add_one"; function.arch = Arch::kX86_64;
    const Varnode result = Varnode::temp(0, 8);
    function.insns.push_back({MintOp::kAdd, result, Varnode::reg(0, 8), Varnode::constant(1, 8), {}, 0x1000, 0});
    function.insns.push_back({MintOp::kReturn, {}, result, {}, {}, 0x1004, 0});
    IrBlock block; block.id = 0; block.start = 0x1000; block.end = 0x1008; block.firstInsn = 0; block.insnCount = 2;
    function.blocks.push_back(block);
    function.tempCount = 1; function.machineInsnCount = 2;
    return function;
}

IrFunction makeCallerFunction() {
    IrFunction function;
    function.entry = 0x2000; function.name = "caller"; function.arch = Arch::kX86_64;
    function.insns.push_back({MintOp::kCall, Varnode::invalid(),
                              Varnode::constant(0x1234, 8), {}, {}, 0x2000, 0});
    function.insns.push_back({MintOp::kReturn, Varnode::invalid(), {}, {}, {}, 0x2005, 0});
    IrBlock block; block.id = 0; block.start = 0x2000; block.end = 0x2006;
    block.firstInsn = 0; block.insnCount = 2; function.blocks.push_back(block);
    function.machineInsnCount = 2;
    return function;
}

IrFunction makeLoopFunction() {
    IrFunction function;
    function.entry = 0x3000; function.name = "loop_sample"; function.arch = Arch::kX86_64;
    function.blocks.resize(3);
    for (u32 i = 0; i < 3; ++i) {
        function.blocks[i].id = i;
        function.blocks[i].start = 0x3000 + i * 0x10;
        function.blocks[i].end = function.blocks[i].start + 0x10;
    }
    function.blocks[0].successors = {1, 2};
    function.blocks[1].successors = {0};
    function.blocks[2].successors = {};
    const Varnode condition = Varnode::temp(0, 1);
    const Varnode value = Varnode::reg(x86::kRax, 8);
    function.insns = {
        {MintOp::kNotEqual, condition, Varnode::reg(x86::kRdi, 8), Varnode::constant(0, 8), {}, 0x3000, 0},
        {MintOp::kCondBranch, {}, condition, Varnode::constant(0x3010, 8), {}, 0x3004, 0},
        {MintOp::kAdd, value, value, Varnode::constant(1, 8), {}, 0x3010, 0},
        {MintOp::kBranch, {}, Varnode::constant(0x3000, 8), {}, {}, 0x3014, 0},
        {MintOp::kReturn, {}, value, {}, {}, 0x3020, 0},
    };
    function.blocks[0].firstInsn = 0; function.blocks[0].insnCount = 2;
    function.blocks[1].firstInsn = 2; function.blocks[1].insnCount = 2;
    function.blocks[2].firstInsn = 4; function.blocks[2].insnCount = 1;
    for (u32 from = 0; from < function.blocks.size(); ++from)
        for (u32 target : function.blocks[from].successors)
            function.blocks[target].predecessors.push_back(from);
    function.tempCount = 1; function.machineInsnCount = 5;
    return function;
}

IrFunction makeDoWhileFunction() {
    IrFunction function;
    function.entry = 0x4000; function.name = "post_test_loop"; function.arch = Arch::kX86_64;
    function.blocks.resize(3);
    for (u32 i = 0; i < 3; ++i) {
        function.blocks[i].id = i;
        function.blocks[i].start = 0x4000 + i * 0x10;
        function.blocks[i].end = function.blocks[i].start + 0x10;
    }
    function.blocks[0].successors = {1};
    function.blocks[1].successors = {0, 2};
    const Varnode value = Varnode::reg(x86::kRax, 8);
    const Varnode condition = Varnode::temp(0, 1);
    function.insns = {
        {MintOp::kAdd, value, value, Varnode::constant(1, 8), {}, 0x4000, 0},
        {MintOp::kBranch, {}, Varnode::constant(0x4010, 8), {}, {}, 0x4004, 0},
        {MintOp::kNotEqual, condition, Varnode::reg(x86::kRdi, 8),
         Varnode::constant(0, 8), {}, 0x4010, 0},
        {MintOp::kCondBranch, {}, condition, Varnode::constant(0x4000, 8), {},
         0x4014, 0},
        {MintOp::kReturn, {}, value, {}, {}, 0x4020, 0},
    };
    function.blocks[0].firstInsn = 0; function.blocks[0].insnCount = 2;
    function.blocks[1].firstInsn = 2; function.blocks[1].insnCount = 2;
    function.blocks[2].firstInsn = 4; function.blocks[2].insnCount = 1;
    for (u32 from = 0; from < function.blocks.size(); ++from)
        for (u32 target : function.blocks[from].successors)
            function.blocks[target].predecessors.push_back(from);
    function.tempCount = 1; function.machineInsnCount = 5;
    return function;
}

bool check(bool condition, const char* message) {
    if (!condition) std::cerr << "feature test: " << message << "\n";
    return condition;
}

void append16(std::vector<u8>* bytes, u16 value) { bytes->push_back(static_cast<u8>(value)); bytes->push_back(static_cast<u8>(value >> 8)); }
void append32(std::vector<u8>* bytes, u32 value) { for (int i = 0; i < 4; ++i) bytes->push_back(static_cast<u8>(value >> (i * 8))); }

std::vector<u8> storedZip(const std::string& name, const std::string& content) {
    std::vector<u8> zip;
    append32(&zip, 0x04034b50); append16(&zip, 20); append16(&zip, 0); append16(&zip, 0); append16(&zip, 0); append16(&zip, 0); append32(&zip, 0); append32(&zip, content.size()); append32(&zip, content.size()); append16(&zip, name.size()); append16(&zip, 0);
    zip.insert(zip.end(), name.begin(), name.end()); zip.insert(zip.end(), content.begin(), content.end());
    const u32 centralOffset = static_cast<u32>(zip.size());
    append32(&zip, 0x02014b50); append16(&zip, 20); append16(&zip, 20); append16(&zip, 0); append16(&zip, 0); append16(&zip, 0); append16(&zip, 0); append32(&zip, 0); append32(&zip, content.size()); append32(&zip, content.size()); append16(&zip, name.size()); append16(&zip, 0); append16(&zip, 0); append16(&zip, 0); append16(&zip, 0); append32(&zip, 0); append32(&zip, 0);
    zip.insert(zip.end(), name.begin(), name.end());
    append32(&zip, 0x06054b50); append16(&zip, 0); append16(&zip, 0); append16(&zip, 1); append16(&zip, 1); append32(&zip, static_cast<u32>(zip.size()) - centralOffset); append32(&zip, centralOffset); append16(&zip, 0);
    return zip;
}

}  // namespace

int main(int argc, char** argv) {
    char projectPath[] = "/tmp/mint-project-test-XXXXXX";
    int projectFd = mkstemp(projectPath);
    if (!check(projectFd >= 0,"project test temporary")) return 1;
    close(projectFd); std::remove(projectPath);
    Program program;
    if (!check(program.open(projectPath).ok(),"create persistent program")) return 1;
    if (!check(program.edit(0x1000,"name","renamed_fn").ok() && program.edit(0x1000,"comment","comment\nwith 'quotes'").ok(),"program edits persist")) return 1;
    if (!check(!program.edit(0x2000,"name","renamed_fn").ok() && !program.edit(0x1000,"data","bad_type").ok(),"reject duplicate names and unknown data types")) return 1;
    if (!check(program.undo().ok() && program.get(0x1000,"comment").empty() && program.redo().ok(),"undo/redo restores overlay")) return 1;
    Program reopened;
    if (!check(reopened.open(projectPath).ok() && reopened.get(0x1000,"name")=="renamed_fn" && reopened.get(0x1000,"comment")=="comment\nwith 'quotes'","program survives reopen")) return 1;
    if (!check(program.edit(0x1000,"name","").ok() && program.get(0x1000,"name").empty(),"empty edit removes override")) return 1;
    if (!check(program.undo().ok() && program.edit(0x1000,"bookmark","review").ok() && !program.redo().ok(),"new edit clears redo history")) return 1;
    Program failure;
    if (!check(!failure.edit(0x1000,"comment","unsaved").ok() && failure.get(0x1000,"comment").empty(),"failed save leaves live state unchanged")) return 1;
    if (argc >= 2) {
        // Generic Program tests used arbitrary addresses; a Session correctly
        // rejects restoring those into images where they are not mapped.
        std::remove(projectPath);
        Session session;
        if (!check(session.openPath(argv[1]).ok() && session.analyze().ok() && session.attachProject(projectPath).ok(),"native session project integrates")) return 1;
        const auto function = session.analyzer().functions().front();
        if (!check(session.editAnnotation(function.entry,"name","project_function").ok(),"rename native function")) return 1;
        if (!check(session.decompiledCFor(function.entry).find("project_function")!=std::string::npos,"rename reaches pseudo-C")) return 1;
        if (!check(session.editAnnotation(function.entry,"prototype","int32_t(uint64_t context)").ok(),"user function prototype")) return 1;
        if (!check(session.decompiledCFor(function.entry).find("int32_t project_function(uint64_t context)")!=std::string::npos,"user types and parameter names reach pseudo-C")) return 1;
        if (!check(!session.editAnnotation(function.entry,"prototype","@cdecl32 int32_t(int32_t arg)").ok(),"incompatible ABI prototype rejected")) return 1;
        if (!check(session.searchText("project_function").find("project_function")!=std::string::npos,"global symbol search")) return 1;
        auto rows=session.programListing(function.entry,8);
        if (!check(!rows.empty() && rows[0].address==function.entry && rows[0].text.find("project_function")!=std::string::npos,"listing includes user label")) return 1;
        if (!check(session.editAnnotation(function.entry,"function","code").ok() && !session.editAnnotation(function.entry,"data","u64").ok(),"data cannot hide an explicit function seed")) return 1;
        const auto segments=session.image().memory().segments(); // Edits replace the derived image.
        for (const auto& segment : segments) if (!segment.executable() && segment.size>=8) {
            if (!check(session.editAnnotation(segment.start,"data","u64").ok(),"define mapped data")) return 1;
            auto data=session.programListing(segment.start,1);
            if (!check(data.size()==1 && data[0].size==8 && data[0].text.find("u64")!=std::string::npos,"typed data in unified listing")) return 1;
            break;
        }
        if (!check(!session.searchText("bytes: 7f 45 4c 46").empty(),"mapped bytes search")) return 1;
        (void)session.referencesText(function.entry);
    }
    FILE* corrupt = std::fopen(projectPath,"ab");
    if (!check(corrupt != nullptr,"project corruption fixture")) return 1;
    std::fputc('!',corrupt); std::fclose(corrupt);
    Program invalid;
    if (!check(!invalid.open(projectPath).ok(),"corrupt project rejected without overwriting it")) return 1;
    std::remove(projectPath);
    const IrFunction narrowImmediate = liftX86Bytes({0x83, 0xc0, 0xff});  // add eax, -1
    if (!check(narrowImmediate.machineInsnCount == 1 &&
                   narrowImmediate.verify().empty(),
               "x86 signed immediate is truncated to the operand width")) return 1;

    const IrFunction zeroExtWrite =
        liftX86Bytes({0xb8, 0x01, 0x00, 0x00, 0x00});  // mov eax, 1
    bool writesWholeRax = false;
    for (const IrInsn& insn : zeroExtWrite.insns) {
        writesWholeRax |= insn.dest.isRegister() &&
                          insn.dest.offset == x86::kRax && insn.dest.size == 8;
    }
    if (!check(writesWholeRax, "x86 eax write clears the upper half of rax")) return 1;

    const IrFunction booleanCondition =
        liftX86Bytes({0x85, 0xc0, 0x75, 0x02});  // test eax, eax; jne +2
    bool hasBitwiseBooleanNot = false;
    for (const IrInsn& insn : booleanCondition.insns) {
        hasBitwiseBooleanNot |= insn.op == MintOp::kNot;
    }
    if (!check(!hasBitwiseBooleanNot,
               "x86 branch negation produces a 0/1 boolean")) return 1;

    IrFunction function = makeAddFunction();
    if (!check(function.verify().empty(), "synthetic IR verifies")) return 1;
    Emulator emulator(Arch::kX86_64); emulator.state().setRegister(0, 41, 8);
    InterpResult execution;
    if (!check(emulator.run(function, {}, &execution).ok(), "IR executes")) return 1;
    if (!check(execution.returned && execution.returnValue.concreteLike() && execution.returnValue.bits == 42, "emulator returns 42")) return 1;

    DecompileResult decompiled;
    if (!check(decompileIr(function, &decompiled).ok(), "decompiler accepts IR")) return 1;
    if (!check(decompiled.cSource.find("add_one") != std::string::npos, "C emitter prints function")) return 1;
    DecompileResult loopDecompiled;
    if (!check(decompileIr(makeLoopFunction(), &loopDecompiled).ok() &&
                   loopDecompiled.cSource.find("while") != std::string::npos,
               "structurer emits a canonical loop")) return 1;
    DecompileResult doWhileDecompiled;
    if (!check(decompileIr(makeDoWhileFunction(), &doWhileDecompiled).ok() &&
                   doWhileDecompiled.cSource.find("do {") != std::string::npos &&
                   doWhileDecompiled.cSource.find("} while (") != std::string::npos,
               "structurer emits a conditional-latch do-while")) return 1;

    std::vector<u8> encoded;
    for (char c : std::string("mint")) encoded.push_back(static_cast<u8>(c) ^ 0x5a);
    encoded.push_back(0x5a);
    RecoveredString recovered = decodeXorString(encoded, 0x5a);
    if (!check(recovered.text == "mint", "XOR string recovery")) return 1;

    DexMethod dalvik; dalvik.classDescriptor = "LTest;"; dalvik.name = "add"; dalvik.registersSize = 2;
    dalvik.code = {0x0112, 0x000f};
    IrFunction dalvikIr;
    if (!check(liftDalvik(dalvik, &dalvikIr).ok(), "Dalvik lifting")) return 1;
    if (!check(dalvikIr.arch == Arch::kDalvik && !dalvikIr.insns.empty(), "Dalvik IR exists")) return 1;
    if (!check(dalvikIr.verify().empty(), "Dalvik IR verifies")) return 1;

    std::vector<u8> zipBytes = storedZip("classes.dex", "dex-test"); ZipReader zip; std::vector<u8> extracted;
    if (!check(zip.open(ByteView(zipBytes.data(), zipBytes.size())).ok(), "ZIP opens")) return 1;
    if (!check(zip.extract("classes.dex", &extracted).ok() && std::string(extracted.begin(), extracted.end()) == "dex-test", "ZIP extracts entry")) return 1;

    Database database;
    if (!check(database.open(":memory:").ok(), "SQLite opens through runtime API")) return 1;
    std::vector<ProgramAnnotation> databaseAnnotations={{0x1000,"comment","quotes ' and newline\n"}};
    if (!check(database.writeAnnotations(databaseAnnotations).ok() && database.readAnnotations(&databaseAnnotations).ok() && databaseAnnotations.size()==1 && databaseAnnotations[0].value=="quotes ' and newline\n","SQLite annotation transaction uses bound values")) return 1;
    if (!check(database.execute("PRAGMA user_version=1").ok() && database.ensureSchema().ok() && database.readAnnotations(&databaseAnnotations).ok() && databaseAnnotations.size()==1,"cache schema rebuild preserves user annotations")) return 1;
    const Status persisted = database.persist(function, "feature-hash");
    if (!persisted.ok()) { std::cerr << persisted.toString() << "\n"; return 1; }
    if (!check(database.hasBinary("feature-hash"), "SQLite stores binary hash")) return 1;
    if (!check(database.hasBinary("missing") == false, "SQLite cache query")) return 1;
    IrFunction caller = makeCallerFunction();
    if (!check(database.persist(caller, "feature-hash").ok(), "SQLite stores call edges")) return 1;
    std::vector<DbFunction> callers;
    if (!check(database.functionsCalling("0x1234", &callers).ok() && callers.size() == 1,
               "SQLite resolves numeric call target")) return 1;

    // The small cases above pin down individual feature contracts. This second
    // half runs the same contracts through a real Android ELF when the runner
    // supplies one; a synthetic IR alone cannot catch loader/decoder/lifter
    // integration regressions.
    if (argc >= 2) {
        MappedFile file;
        if (!check(file.open(argv[1]).ok(), "real library maps")) return 1;
        ElfImage image;
        if (!check(image.load(file.view()).ok(), "real library ELF loads")) return 1;
        CodeAnalyzer analyzer;
        if (!check(analyzer.analyze(image).ok() && !analyzer.functions().empty(),
                   "real library analysis discovers functions")) return 1;
        u64 recoveredIndirectEdges = 0;
        for (const Function& candidate : analyzer.functions()) {
            for (const BasicBlock& block : candidate.cfg.blocks()) {
                for (const CfgEdge& edge : block.successors) {
                    recoveredIndirectEdges +=
                        edge.kind == EdgeKind::kResolvedIndirect ? 1 : 0;
                }
            }
        }
        if (image.arch() == Arch::kAArch64 &&
            analyzer.stats().indirectJumps >= 100 &&
            !check(recoveredIndirectEdges > 0,
                   "real ARM library recovers jump-table CFG edges")) return 1;
        Lifter lifter;
        if (!check(lifter.open(image.arch()).ok(), "real library lifter opens")) return 1;
        const Function* first = &analyzer.functions().front();
        IrFunction lifted;
        if (!check(lifter.liftFunction(*first, image.memory(), &lifted).ok(),
                   "real library function lifts")) return 1;
        if (!check(lifted.verify().empty(), "real library IR verifies")) return 1;
        DecompileResult realC;
        if (!check(decompileIr(lifted, &realC).ok() && !realC.cSource.empty(),
                   "real library decompiles")) return 1;
        if (!check(!first->cfg.empty(), "real library CFG is populated")) return 1;

        Emulator realEmulator(image.arch());
        InterpResult execution;
        if (!check(realEmulator.run(lifted, {}, &execution).ok(),
                   "real library function executes in the IR emulator")) return 1;

        Database realDatabase;
        if (!check(realDatabase.open(":memory:").ok(),
                   "real library database opens")) return 1;
        if (!check(realDatabase.persist(lifted, "real-library-feature-hash").ok() &&
                       realDatabase.hasBinary("real-library-feature-hash"),
                   "real library analysis persists to SQLite")) return 1;

        const std::vector<DetectorFinding> findings = runDetectors(image);
        (void)findings;  // The real scan is a no-crash/integration contract here.
        const DeobfuscationResult obfuscation = deobfuscate(&lifted);
        if (!check(lifted.verify().empty(), "real library OLLVM pass preserves valid IR")) return 1;
        (void)obfuscation;
    }
    std::cout << "feature tests passed\n";
    return 0;
}
