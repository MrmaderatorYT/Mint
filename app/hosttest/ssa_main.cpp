#include <cstdio>
#include <cstdlib>
#include <string>
#include <set>
#include <vector>

#include "mint/ir/dataflow.h"
#include "mint/ir/ir_simplify.h"
#include "mint/ir/lifter.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"
#include "mint/ir/type_recovery.h"
#include "mint/loader/elf_image.h"
#include "mint/base/mapped_file.h"
#include "mint/analysis/code_analyzer.h"
#include "mint/analysis/jump_table_recovery.h"
#include "mint/ssa/ssa_builder.h"
#include "mint/decompile/decompiler.h"
#include "mint/decompile/decompiler.h"

using namespace mint;

namespace {

void add(IrFunction* function, u32 block, MintOp op, const Varnode& dest,
         const Varnode& a = Varnode::invalid(), const Varnode& b = Varnode::invalid()) {
    IrInsn insn;
    insn.op = op;
    insn.dest = dest;
    insn.a = a;
    insn.b = b;
    insn.address = 0x1000 + function->insns.size();
    function->insns.push_back(insn);
    ++function->blocks[block].insnCount;
}

IrFunction makeDiamond() {
    IrFunction function;
    function.entry = 0x1000;
    function.name = "ssa_diamond";
    function.arch = Arch::kX86_64;
    function.machineInsnCount = 8;
    function.blocks.resize(4);
    for (u32 i = 0; i < function.blocks.size(); ++i) {
        function.blocks[i].id = i;
        function.blocks[i].start = 0x1000 + i * 0x10;
        function.blocks[i].end = function.blocks[i].start + 0x10;
        function.blocks[i].firstInsn = function.insns.size();
    }
    function.blocks[0].successors = {1, 2};
    function.blocks[1].successors = {3};
    function.blocks[2].successors = {3};

    const Varnode rdi = Varnode::reg(x86::kRdi, 8);
    const Varnode rax = Varnode::reg(x86::kRax, 8);
    const Varnode condition = Varnode::temp(0, 1);
    function.tempCount = 1;
    add(&function, 0, MintOp::kEqual, condition, rdi, Varnode::constant(0, 8));
    add(&function, 0, MintOp::kCondBranch, Varnode::invalid(), condition,
        Varnode::constant(0x1010, 8));
    add(&function, 1, MintOp::kCopy, rax, Varnode::constant(1, 8));
    add(&function, 1, MintOp::kBranch, Varnode::invalid(), Varnode::constant(0x1030, 8));
    add(&function, 2, MintOp::kCopy, rax, Varnode::constant(2, 8));
    add(&function, 2, MintOp::kBranch, Varnode::invalid(), Varnode::constant(0x1030, 8));
    add(&function, 3, MintOp::kAdd, rax, rax, Varnode::constant(3, 8));
    add(&function, 3, MintOp::kReturn, Varnode::invalid(), rax);

    // The helper appends in block order, so firstInsn values need a final pass.
    u32 cursor = 0;
    for (IrBlock& block : function.blocks) {
        block.firstInsn = cursor;
        cursor += block.insnCount;
    }
    return function;
}

}  // namespace

int main(int argc, char** argv) {
    IrFunction function = makeDiamond();
    if (!function.verify().empty()) {
        std::fprintf(stderr, "raw IR verification failed\n");
        return 1;
    }

    SsaFunction ssa;
    SsaBuildStats stats;
    const Status built = buildSsa(function, &ssa, &stats);
    if (!built.ok()) {
        std::fprintf(stderr, "SSA build failed: %s\n", built.toString().c_str());
        return 1;
    }
    const std::vector<std::string> problems = ssa.verify();
    if (!problems.empty()) {
        for (const std::string& problem : problems) std::fprintf(stderr, "%s\n", problem.c_str());
        return 1;
    }
    if (ssa.phis.empty() || stats.entryValues == 0 || stats.variables == 0) {
        std::fprintf(stderr, "SSA did not place the expected phi/entry values\n");
        return 1;
    }

    SsaDefUse defUse;
    SsaLiveness liveness;
    TypeRecovery types;
    if (!buildDefUse(ssa, &defUse).ok() || !computeLiveness(ssa, &liveness).ok() ||
        !recoverTypes(ssa, &types).ok()) {
        std::fprintf(stderr, "SSA analyses failed\n");
        return 1;
    }
    SsaSimplifyStats simplifyStats;
    if (!simplifySsa(&ssa, &simplifyStats).ok() || !ssa.verify().empty()) {
        std::fprintf(stderr, "SSA simplification failed verification\n");
        return 1;
    }
    // Diagnostics go to stderr so `--emit-c` keeps stdout as a compilable C
    // translation unit rather than prefixing it with a test-status sentence.
    std::fprintf(stderr,
                 "SSA checks passed: %zu values, %zu phis, %u entry values, %zu parameters\n",
                 ssa.values.size(), ssa.phis.size(), stats.entryValues,
                 types.parameters.size());

    if (argc < 2) return 0;

    // Everything above is a hand-built diamond, which proves the algorithm handles a
    // join but says nothing about real control flow. The sweep below is the number
    // that matters: every function in a real library, through the whole pipeline,
    // with the SSA verifier — which checks that every use is reached by exactly one
    // definition that dominates it — run on each one before and after simplification.
    MappedFile file;
    Status status = file.open(argv[1]);
    if (!status.ok()) {
        std::fprintf(stderr, "map failed: %s\n", status.toString().c_str());
        return 1;
    }
    ElfImage image;
    status = image.load(file.view());
    if (!status.ok()) {
        std::fprintf(stderr, "ELF load failed: %s\n", status.toString().c_str());
        return 1;
    }
    CodeAnalyzer analyzer;
    status = analyzer.analyze(image);
    if (!status.ok() || analyzer.functions().empty()) return 1;
    Lifter lifter;
    status = lifter.open(image.arch());
    if (!status.ok()) return 1;

    // "--emit-c <count>" writes decompiled C for that many functions. Whether a
    // C compiler accepts the result is the only check that catches a whole class of
    // emitter bugs — undeclared names, duplicate labels, redeclared temporaries —
    // that reading the output by eye slides straight past.
    const SymbolNamer namer = [&image](Address target) {
        return image.describeAddress(target);
    };

    if (argc >= 3 && std::string(argv[2]) == "--emit-c") {
        const size_t wanted = argc >= 4 ? std::strtoul(argv[3], nullptr, 10) : 200;
        std::printf("#include <stdint.h>\n#include <stdbool.h>\n");
        // Declare a helper for every opcode the emitter can spell as a call, taken
        // from the opcode table itself so the prelude cannot drift out of step with
        // what the emitter actually produces.
        for (unsigned op = 1; op < opCount(); ++op) {
            const char* name = opName(static_cast<MintOp>(op));
            if (name == nullptr || *name == 0) continue;
            std::printf("uint64_t op_%s();\n", name);
        }
        std::printf("uint64_t call();\n");
        std::set<std::string> emitted;
        std::vector<std::string> bodies;
        size_t count = 0, failed = 0;
        for (const Function& function : analyzer.functions()) {
            if (count >= wanted) break;
            IrFunction lifted;
            if (!lifter.liftFunction(function, image.memory(), &lifted).ok()) continue;
            DecompileResult decompiled;
            if (!decompileIr(lifted, &decompiled, namer).ok()) { ++failed; continue; }
            if (decompiled.ssa.name.empty() || !emitted.insert(decompiled.ssa.name).second) {
                continue;
            }
            bodies.push_back(decompiled.cSource);
            ++count;
        }
        // Resolved callees are real external symbols, so the file needs a
        // declaration for each one before it will compile. Collecting them from the
        // generated text keeps this in step with whatever the emitter decided to
        // name, rather than duplicating its naming rules here.
        // Take the defined names from the emitter's own header lines: the symbol
        // name and the C identifier differ whenever a symbol contains a character
        // an identifier cannot, and comparing against the wrong one declares a
        // function that is also defined, with a different signature.
        std::vector<std::string> prototypes;
        std::set<std::string> defined;
        for (const std::string& body : bodies) {
            const size_t brace = body.find(") {");
            if (brace == std::string::npos) continue;
            size_t start = body.rfind('\n', brace);
            start = start == std::string::npos ? 0 : start + 1;
            const std::string header = body.substr(start, brace - start);
            prototypes.push_back(header);
            const size_t open = header.find('(');
            if (open == std::string::npos) continue;
            size_t nameStart = open;
            while (nameStart > 0) {
                const char c = header[nameStart - 1];
                const bool word = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9') || c == '_';
                if (!word) break;
                --nameStart;
            }
            defined.insert(header.substr(nameStart, open - nameStart));
        }
        std::set<std::string> called;
        for (const std::string& body : bodies) {
            for (size_t i = 0; i < body.size(); ++i) {
                if (body[i] != '(') continue;
                size_t end = i;
                size_t start = i;
                while (start > 0) {
                    const char c = body[start - 1];
                    const bool word = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                            || (c >= '0' && c <= '9') || c == '_';
                    if (!word) break;
                    --start;
                }
                if (start == end) continue;
                std::string name = body.substr(start, end - start);
                if (name.empty() || (name[0] >= '0' && name[0] <= '9')) continue;
                called.insert(name);
            }
        }
        // Type names appear before a parenthesis inside a cast, so the scan above
        // sees them as callees.
        static const char* kKeywords[] = {"if", "while", "for", "switch", "return",
                                          "sizeof", "goto", "uint64_t", "uint32_t",
                                          "uint16_t", "uint8_t", "int64_t", "int32_t",
                                          "int16_t", "int8_t", "uintptr_t", "bool",
                                          "float", "double", "void", "__uint128_t"};
        for (const std::string& name : called) {
            if (defined.count(name) != 0) continue;
            if (name.rfind("op_", 0) == 0 || name == "call") continue;
            bool keyword = false;
            for (const char* k : kKeywords) keyword = keyword || name == k;
            if (keyword) continue;
            std::printf("uint64_t %s();\n", name.c_str());
        }
        // Forward declarations for the generated functions themselves: they call
        // each other, and a callee defined further down the file is a use before
        // declaration. The signature is lifted from the emitter's own header line
        // so the two cannot disagree.
        for (const std::string& header : prototypes) std::printf("%s);\n", header.c_str());
        for (const std::string& body : bodies) std::printf("\n%s\n", body.c_str());
        std::fprintf(stderr, "emitted %zu functions, %zu decompile failures\n", count, failed);
        return 0;
    }

    // A second argument dumps one function's SSA instead of sweeping. Reading the
    // form for a function whose machine code is known is the only way to tell a
    // structurally valid build from a correct one: the verifier is happy either way.
    if (argc >= 3) {
        const Address wanted = std::strtoull(argv[2], nullptr, 16);
        for (const Function& function : analyzer.functions()) {
            if (function.entry != wanted) continue;
            IrFunction lifted;
            if (!lifter.liftFunction(function, image.memory(), &lifted).ok()) return 1;
            const NormalizeStats normalized = normalizeRegisterAccesses(&lifted);
            SsaFunction ssa;
            SsaBuildStats build;
            if (!buildSsa(lifted, &ssa, &build).ok()) return 1;
            std::printf("normalize: %u narrow reads, %u narrow writes, %u unnormalized\n",
                        normalized.narrowReads, normalized.narrowWrites,
                        normalized.unnormalized);
            std::printf("build: %u vars, %u phis, %u entry, %u undefined temp reads\n",
                        build.variables, build.phisInserted, build.entryValues,
                        build.undefinedTempReads);
            std::printf("%s\n", ssa.toText().c_str());
            SsaSimplifyStats simplify;
            simplifySsa(&ssa, &simplify);
            std::printf("---- after simplification (%u dead, %u copies, %u phis) ----\n%s\n",
                        simplify.deadInstructionsRemoved, simplify.copiesPropagated,
                        simplify.trivialPhisRemoved, ssa.toText().c_str());
            IrFunction again;
            lifter.liftFunction(function, image.memory(), &again);
            DecompileResult decompiled;
            const Status d = decompileIr(again, &decompiled, namer);
            std::printf("---- decompiler: %s ----\n%s\n", d.toString().c_str(),
                        d.ok() ? decompiled.cSource.c_str() : "");
            return ssa.verify().empty() ? 0 : 1;
        }
        std::fprintf(stderr, "no function at that address\n");
        return 1;
    }

    struct Totals {
        u32 functions = 0, liftFailed = 0, rawVerifyFailed = 0, normVerifyFailed = 0;
        u32 ssaBuildFailed = 0, ssaVerifyFailed = 0, simplifyFailed = 0, postVerifyFailed = 0;
        u32 defUseFailed = 0, livenessFailed = 0, typeFailed = 0;
        u64 machineInsns = 0, rawOps = 0, normalizedOps = 0, liveOps = 0;
        u64 values = 0, phis = 0, entryValues = 0, undefinedTempReads = 0, unnormalized = 0;
        u64 parameters = 0, structs = 0, deadRemoved = 0, copies = 0, trivialPhis = 0;
        u64 indirectJumps = 0, recoveredJumps = 0;
        u64 representedJumpEdges = 0, recoveredEdges = 0;
    } t;
    std::vector<std::string> samples;
    auto sample = [&](const char* what, Address entry, const std::string& detail) {
        if (samples.size() >= 8) return;
        char buffer[256];
        std::snprintf(buffer, sizeof(buffer), "  %s @0x%llx: %s", what,
                      static_cast<unsigned long long>(entry), detail.c_str());
        samples.push_back(buffer);
    };

    for (const Function& function : analyzer.functions()) {
        IrFunction lifted;
        if (!lifter.liftFunction(function, image.memory(), &lifted).ok()) {
            ++t.liftFailed;
            continue;
        }
        ++t.functions;
        t.machineInsns += lifted.machineInsnCount;
        t.rawOps += lifted.insns.size();
        if (!lifted.verify().empty()) ++t.rawVerifyFailed;

        JumpTableRecovery jumpTables;
        recoverJumpTables(image, lifted, &jumpTables);
        t.indirectJumps += jumpTables.indirectJumps;
        t.recoveredJumps += jumpTables.recoveredJumps;
        t.representedJumpEdges += recoveredIrCfgEdges(lifted, jumpTables);
        t.recoveredEdges += augmentIrCfg(&lifted, jumpTables);

        const NormalizeStats normalized = normalizeRegisterAccesses(&lifted);
        t.unnormalized += normalized.unnormalized;
        t.normalizedOps += lifted.insns.size();
        {
            const std::vector<std::string> problems = lifted.verify();
            if (!problems.empty()) {
                ++t.normVerifyFailed;
                sample("normalize", function.entry, problems.front());
            }
        }

        SsaFunction ssa;
        SsaBuildStats build;
        if (!buildSsa(lifted, &ssa, &build).ok()) {
            ++t.ssaBuildFailed;
            continue;
        }
        t.values += ssa.values.size();
        t.phis += ssa.phis.size();
        t.entryValues += build.entryValues;
        t.undefinedTempReads += build.undefinedTempReads;
        {
            const std::vector<std::string> problems = ssa.verify();
            if (!problems.empty()) {
                ++t.ssaVerifyFailed;
                sample("ssa", function.entry, problems.front());
            }
        }

        SsaDefUse defUse;
        SsaLiveness liveness;
        TypeRecovery types;
        if (!buildDefUse(ssa, &defUse).ok()) ++t.defUseFailed;
        if (!computeLiveness(ssa, &liveness).ok()) ++t.livenessFailed;
        if (!recoverTypes(ssa, &types).ok()) ++t.typeFailed;
        t.parameters += types.parameters.size();
        t.structs += types.structs.size();

        SsaSimplifyStats simplify;
        if (!simplifySsa(&ssa, &simplify).ok()) {
            ++t.simplifyFailed;
        } else {
            const std::vector<std::string> problems = ssa.verify();
            if (!problems.empty()) {
                ++t.postVerifyFailed;
                sample("post-simplify", function.entry, problems.front());
            }
        }
        t.deadRemoved += simplify.deadInstructionsRemoved;
        t.copies += simplify.copiesPropagated;
        t.trivialPhis += simplify.trivialPhisRemoved;
        t.liveOps += ssa.liveInsnCount();
    }

    std::printf("\n==================== ssa sweep ====================\n");
    std::printf("functions           : %u  (lift failures %u)\n", t.functions, t.liftFailed);
    std::printf("machine insns       : %llu\n", (unsigned long long)t.machineInsns);
    std::printf("ir ops raw          : %llu\n", (unsigned long long)t.rawOps);
    std::printf("ir ops normalized   : %llu  (+%.1f%% for whole-unit access)\n",
                (unsigned long long)t.normalizedOps,
                t.rawOps ? 100.0 * double(t.normalizedOps - t.rawOps) / double(t.rawOps) : 0.0);
    std::printf("ssa ops after simp. : %llu  (%.1f%% of normalized)\n",
                (unsigned long long)t.liveOps,
                t.normalizedOps ? 100.0 * double(t.liveOps) / double(t.normalizedOps) : 0.0);
    std::printf("values / phis       : %llu / %llu\n", (unsigned long long)t.values,
                (unsigned long long)t.phis);
    std::printf("entry values        : %llu\n", (unsigned long long)t.entryValues);
    std::printf("parameters / structs: %llu / %llu\n", (unsigned long long)t.parameters,
                (unsigned long long)t.structs);
    std::printf("removed dead/copy/phi: %llu / %llu / %llu\n",
                (unsigned long long)t.deadRemoved, (unsigned long long)t.copies,
                (unsigned long long)t.trivialPhis);
    std::printf("jump tables         : %llu indirect, %llu recovered, "
                "%llu CFG edges present, %llu added late\n",
                (unsigned long long)t.indirectJumps,
                (unsigned long long)t.recoveredJumps,
                (unsigned long long)t.representedJumpEdges,
                (unsigned long long)t.recoveredEdges);
    std::printf("unnormalized access : %llu   undefined temp reads: %llu\n",
                (unsigned long long)t.unnormalized,
                (unsigned long long)t.undefinedTempReads);
    std::printf("FAILURES  raw %u  normalize %u  ssa-build %u  ssa-verify %u\n",
                t.rawVerifyFailed, t.normVerifyFailed, t.ssaBuildFailed, t.ssaVerifyFailed);
    std::printf("          simplify %u  post-verify %u  defuse %u  live %u  types %u\n",
                t.simplifyFailed, t.postVerifyFailed, t.defUseFailed, t.livenessFailed,
                t.typeFailed);
    for (const std::string& line : samples) std::printf("%s\n", line.c_str());

    const bool clean = t.rawVerifyFailed == 0 && t.normVerifyFailed == 0 &&
                       t.ssaBuildFailed == 0 && t.ssaVerifyFailed == 0 &&
                       t.simplifyFailed == 0 && t.postVerifyFailed == 0 &&
                       t.defUseFailed == 0 && t.livenessFailed == 0 && t.typeFailed == 0;
    std::printf("%s\n", clean ? "sweep clean" : "SWEEP FOUND FAILURES");
    return clean ? 0 : 1;
}
