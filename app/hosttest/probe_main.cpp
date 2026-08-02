// Command-line probe over the analysis engine.
//
// Prints what the loaders recovered from a file, so each layer can be checked
// against ground truth from readelf/objdump before anything above it is built on
// top of it.

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "mint/analysis/code_analyzer.h"
#include "mint/analysis/jump_table_recovery.h"
#include "mint/base/mapped_file.h"
#include "mint/disasm/disassembler.h"
#include "mint/ir/lifter.h"
#include "mint/loader/elf_image.h"

namespace {

const char* relocSourceName(mint::ElfRelocation::Source source) {
    switch (source) {
        case mint::ElfRelocation::Source::kRela: return "rela";
        case mint::ElfRelocation::Source::kRel: return "rel";
        case mint::ElfRelocation::Source::kAndroidPacked: return "android-packed";
        case mint::ElfRelocation::Source::kRelr: return "relr";
    }
    return "?";
}

void dumpElf(const mint::ElfImage& image) {
    printf("arch          : %s\n", mint::archName(image.arch()));
    printf("type          : %u%s\n", image.objectType(),
           image.isPositionIndependent() ? " (PIE/shared)" : "");
    printf("entry         : 0x%" PRIx64 "\n", image.entryPoint());
    printf("soname        : %s\n",
           image.soname().empty() ? "<none>" : image.soname().c_str());
    printf("stripped      : %s\n", image.isStripped() ? "yes (.dynsym only)" : "no");
    printf("sections      : %zu\n", image.sections().size());
    printf("symbols       : %zu\n", image.symbols().size());
    printf("relocations   : %zu\n", image.relocations().size());
    printf("plt stubs     : %zu\n", image.pltStubs().size());
    printf("needed libs   : %zu\n", image.neededLibraries().size());

    const mint::MemoryMap& memory = image.memory();
    printf("\nmemory map (%zu segments, span 0x%" PRIx64 "-0x%" PRIx64 "%s)\n",
           memory.segments().size(), memory.minAddress(), memory.maxAddress(),
           memory.hasOverlaps() ? ", OVERLAPPING" : "");
    for (const mint::MemorySegment& segment : memory.segments()) {
        printf("  0x%08" PRIx64 "-0x%08" PRIx64 "  %c%c%c  file-backed %zu\n",
               segment.start, segment.end(),
               (segment.flags & mint::kMemRead) ? 'r' : '-',
               (segment.flags & mint::kMemWrite) ? 'w' : '-',
               (segment.flags & mint::kMemExec) ? 'x' : '-', segment.data.size());
    }

    printf("\nallocated sections\n");
    for (const mint::ElfSection& section : image.sections()) {
        if (!section.allocated()) continue;
        printf("  %-22s 0x%08" PRIx64 " size %-10" PRIu64 " %s\n",
               section.name.empty() ? "<unnamed>" : section.name.c_str(), section.addr,
               section.size, section.executable() ? "X" : "");
    }

    if (!image.neededLibraries().empty()) {
        printf("\nDT_NEEDED\n");
        for (const std::string& library : image.neededLibraries()) {
            printf("  %s\n", library.c_str());
        }
    }

    printf("\ninitialisers (%zu) — where packers and anti-analysis code live\n",
           image.initializers().size());
    for (mint::Address addr : image.initializers()) {
        std::string name = image.describeAddress(addr);
        printf("  0x%08" PRIx64 "  %s\n", addr, name.empty() ? "" : name.c_str());
    }

    size_t functionCount = 0;
    for (const mint::ElfSymbol& symbol : image.symbols()) {
        if (symbol.isFunction() && !symbol.undefined) ++functionCount;
    }
    printf("\ndefined function symbols: %zu (first 15)\n", functionCount);
    size_t shown = 0;
    for (const mint::ElfSymbol& symbol : image.symbols()) {
        if (!symbol.isFunction() || symbol.undefined || symbol.name.empty()) continue;
        printf("  0x%08" PRIx64 "  size %-8" PRIu64 " %s\n", symbol.value, symbol.size,
               symbol.name.c_str());
        if (++shown >= 15) break;
    }

    // Relocation encoding is worth breaking down: an Android library using
    // packed relocations is the normal case, and a loader that missed them would
    // report a suspiciously round zero here.
    size_t bySource[4] = {0, 0, 0, 0};
    for (const mint::ElfRelocation& reloc : image.relocations()) {
        bySource[static_cast<int>(reloc.source)]++;
    }
    printf("\nrelocations by encoding\n");
    for (int i = 0; i < 4; ++i) {
        printf("  %-16s %zu\n",
               relocSourceName(static_cast<mint::ElfRelocation::Source>(i)), bySource[i]);
    }

    // Sorted by address so the output lines up with objdump's PLT listing; the
    // whole point of this table is to be checkable against one.
    printf("\nPLT stubs (stride %" PRIu64 ", first 6 by address)\n",
           image.pltStubStride());
    std::vector<std::pair<mint::Address, std::string>> stubs(image.pltStubs().begin(),
                                                             image.pltStubs().end());
    std::sort(stubs.begin(), stubs.end());
    shown = 0;
    for (const auto& entry : stubs) {
        printf("  0x%08" PRIx64 "  %s\n", entry.first, entry.second.c_str());
        if (++shown >= 6) break;
    }

    if (!image.warnings().empty()) {
        printf("\nwarnings (%zu)\n", image.warnings().size());
        for (const std::string& warning : image.warnings()) {
            printf("  ! %s\n", warning.c_str());
        }
    }
}

void dumpAnalysis(const mint::ElfImage& image, const mint::CodeAnalyzer& analyzer) {
    const mint::CodeAnalyzer::Stats& stats = analyzer.stats();
    printf("\n==================== code analysis ====================\n");
    printf("instructions        : %zu\n", stats.instructions);
    printf("functions           : %zu (%zu from linear sweep)\n", stats.functions,
           stats.functionsFromSweep);
    printf("basic blocks        : %zu\n", stats.blocks);
    printf("cfg edges           : %zu\n", stats.edges);
    printf("indirect jumps (raw): %zu  <- before IR/dataflow recovery\n",
           stats.indirectJumps);
    printf("undecodable sites   : %zu\n", stats.undecodableSites);
    printf("incomplete functions: %zu\n", stats.incompleteFunctions);

    // Coverage against .text is the honest measure of how much of the binary the
    // descent actually reached.
    const mint::ElfSection* text = image.findSection(".text");
    if (text != nullptr && text->size != 0) {
        size_t covered = 0;
        for (const mint::InsnRecord& insn : analyzer.code().instructions()) {
            if (insn.address >= text->addr && insn.address < text->addr + text->size) {
                covered += insn.size;
            }
        }
        printf(".text coverage      : %zu / %" PRIu64 " bytes (%.1f%%)\n", covered,
               text->size, 100.0 * static_cast<double>(covered) /
                               static_cast<double>(text->size));
    }

    printf("\nfunctions by origin\n");
    size_t byOrigin[6] = {};
    for (const mint::Function& function : analyzer.functions()) {
        byOrigin[static_cast<int>(function.origin)]++;
    }
    for (int i = 0; i < 6; ++i) {
        if (byOrigin[i] == 0) continue;
        printf("  %-14s %zu\n",
               mint::functionOriginName(static_cast<mint::FunctionOrigin>(i)),
               byOrigin[i]);
    }

    // The largest functions are where obfuscation shows up, so they are the most
    // useful sample to eyeball.
    std::vector<const mint::Function*> byBlocks;
    for (const mint::Function& function : analyzer.functions()) {
        byBlocks.push_back(&function);
    }
    std::sort(byBlocks.begin(), byBlocks.end(),
              [](const mint::Function* a, const mint::Function* b) {
                  return a->cfg.size() > b->cfg.size();
              });

    printf("\nlargest functions by block count\n");
    for (size_t i = 0; i < byBlocks.size() && i < 8; ++i) {
        const mint::Function* f = byBlocks[i];
        printf("  0x%08" PRIx64 "  %4zu blocks %5zu insns  ind=%u %s%.60s\n", f->entry,
               f->cfg.size(), f->instructionCount(), f->indirectJumps,
               f->incomplete ? "[partial] " : "", f->name.c_str());
    }
}

/// Checks recovered function extents against the sizes the symbol table declares.
///
/// This is the only oracle available at scale: for a non-stripped library the
/// linker already knows where every function begins and ends, so any instruction
/// we attribute to a function that falls outside its declared range is a
/// boundary bug. Spot-checking one function against objdump proves the decoder;
/// only this proves the descent.
void validateAgainstSymbols(const mint::ElfImage& image,
                            const mint::CodeAnalyzer& analyzer) {
    size_t checked = 0;
    size_t overruns = 0;
    size_t exactEnd = 0;
    double coverageSum = 0.0;
    std::vector<std::pair<mint::Address, mint::u64>> worst;

    for (const mint::ElfSymbol& symbol : image.symbols()) {
        if (!symbol.isFunction() || symbol.undefined) continue;
        if (symbol.size == 0 || symbol.value == 0) continue;

        const mint::Function* function = analyzer.functionAt(symbol.value);
        if (function == nullptr) continue;

        const mint::Address low = symbol.value;
        const mint::Address high = symbol.value + symbol.size;

        mint::u64 outside = 0;
        mint::u64 inside = 0;
        for (mint::Address addr : function->instructions) {
            const mint::InsnRecord* insn = analyzer.code().find(addr);
            if (insn == nullptr) continue;
            if (addr < low || addr >= high) {
                outside += insn->size;
            } else {
                inside += insn->size;
            }
        }

        ++checked;
        coverageSum += static_cast<double>(inside) / static_cast<double>(symbol.size);
        if (outside > 0) {
            ++overruns;
            if (worst.size() < 5) worst.emplace_back(symbol.value, outside);
        }
        if (function->highAddress == high) ++exactEnd;
    }

    printf("\n==================== symbol-extent validation ====================\n");
    printf("functions checked      : %zu\n", checked);
    printf("boundary overruns      : %zu (%.2f%%)\n", overruns,
           checked ? 100.0 * static_cast<double>(overruns) / static_cast<double>(checked)
                   : 0.0);
    printf("exact end match        : %zu (%.1f%%)\n", exactEnd,
           checked ? 100.0 * static_cast<double>(exactEnd) / static_cast<double>(checked)
                   : 0.0);
    printf("mean in-range coverage : %.1f%%\n",
           checked ? 100.0 * coverageSum / static_cast<double>(checked) : 0.0);
    for (const auto& entry : worst) {
        printf("  overrun at 0x%08" PRIx64 ": %" PRIu64 " bytes outside\n", entry.first,
               entry.second);
    }
}

/// Disassembles one function so the output can be diffed against objdump. This is
/// the only check that proves the flow classification is right rather than merely
/// self-consistent.
void dumpFunctionListing(const mint::ElfImage& image, const mint::CodeAnalyzer& analyzer,
                         mint::Address entry) {
    const mint::Function* function = analyzer.functionAt(entry);
    if (function == nullptr) {
        printf("\nno function at 0x%" PRIx64 "\n", entry);
        return;
    }

    mint::Disassembler disassembler;
    if (!disassembler.open(image.arch()).ok()) return;

    printf("\n==================== %s ====================\n", function->name.c_str());
    printf("entry 0x%" PRIx64 ", %zu blocks, %zu instructions%s\n", function->entry,
           function->cfg.size(), function->instructionCount(),
           function->incomplete ? " (INCOMPLETE)" : "");

    for (const mint::BasicBlock& block : function->cfg.blocks()) {
        printf("\n  block %u  0x%08" PRIx64 "-0x%08" PRIx64 "  term=%s  preds=[",
               block.id, block.start, block.end, mint::flowKindName(block.terminator));
        for (size_t i = 0; i < block.predecessors.size(); ++i) {
            printf("%s%u", i ? "," : "", block.predecessors[i]);
        }
        printf("]  succs=[");
        for (size_t i = 0; i < block.successors.size(); ++i) {
            printf("%s%u:%s", i ? "," : "", block.successors[i].target,
                   mint::edgeKindName(block.successors[i].kind));
        }
        printf("]\n");

        for (mint::u32 k = 0; k < block.insnCount; ++k) {
            const size_t index = block.firstInsn + k;
            if (index >= analyzer.code().instructions().size()) break;
            const mint::InsnRecord& record = analyzer.code().instructions()[index];

            mint::ByteView bytes =
                image.memory().viewAt(record.address, disassembler.maxInstructionSize());
            mint::DecodedInsn decoded;
            disassembler.decodeVerbose(record.address, bytes, &decoded);

            printf("    %08" PRIx64 "  %-32s", record.address, decoded.text().c_str());
            if (record.hasKnownTarget()) {
                std::string name = image.describeAddress(record.target);
                printf("  ; -> 0x%" PRIx64 " %s", record.target, name.c_str());
            }
            printf("\n");
        }
    }
}

/// Lifts every function and reports how much of the code is actually modelled.
///
/// Two things are being measured, and they are different. The verifier catches IR
/// that is structurally wrong — mismatched widths, missing operands, blocks that do
/// not tile — which is a lifter bug. The intrinsic count measures IR that is
/// structurally fine but semantically empty, which is a lifter *gap*. A gap is
/// honest and expected; a bug is not, and conflating the two would let real defects
/// hide behind a coverage number.
void dumpLifting(const mint::ElfImage& image, const mint::CodeAnalyzer& analyzer) {
    printf("\n==================== ir lifting ====================\n");

    mint::Lifter lifter;
    mint::Status status = lifter.open(image.arch());
    if (!status.ok()) {
        printf("no lifter for this architecture: %s\n", status.toString().c_str());
        return;
    }

    mint::u64 machineInsns = 0;
    mint::u64 irOps = 0;
    mint::u64 intrinsics = 0;
    mint::u64 temps = 0;
    size_t functionsLifted = 0;
    size_t functionsFullyModelled = 0;
    size_t functionsWithProblems = 0;
    mint::u64 indirectJumps = 0;
    mint::u64 recoveredJumps = 0;
    mint::u64 representedEdges = 0;
    mint::u64 recoveredEdges = 0;
    std::vector<std::string> firstProblems;

    // Which instructions are unmodelled, and how often. This is the work list for
    // the next round of lifter work, ordered by what would actually pay off.
    std::unordered_map<mint::u16, mint::u64> unmodelled;
    // A couple of concrete examples per opcode. Without these the work list says
    // "ldr is unmodelled" when the truth is "one addressing form of ldr is", and
    // those need completely different fixes.
    std::unordered_map<mint::u16, std::vector<mint::Address>> examples;

    mint::IrFunction ir;
    for (const mint::Function& function : analyzer.functions()) {
        if (function.instructions.empty()) continue;
        status = lifter.liftFunction(function, image.memory(), &ir);
        if (!status.ok()) continue;

        mint::JumpTableRecovery recovery;
        status = mint::recoverJumpTables(image, ir, &recovery);
        if (!status.ok()) continue;
        indirectJumps += recovery.indirectJumps;
        recoveredJumps += recovery.recoveredJumps;
        representedEdges += mint::recoveredIrCfgEdges(ir, recovery);
        recoveredEdges += mint::augmentIrCfg(&ir, recovery);

        ++functionsLifted;
        machineInsns += ir.machineInsnCount;
        irOps += ir.insns.size();
        intrinsics += ir.intrinsicCount;
        temps += ir.tempCount;
        if (ir.intrinsicCount == 0) ++functionsFullyModelled;

        for (const mint::IrInsn& insn : ir.insns) {
            if (insn.op != mint::MintOp::kIntrinsic) continue;
            ++unmodelled[insn.intrinsicId];
            std::vector<mint::Address>& seen = examples[insn.intrinsicId];
            if (seen.size() < 3) seen.push_back(insn.address);
        }

        const std::vector<std::string> problems = ir.verify();
        if (!problems.empty()) {
            ++functionsWithProblems;
            if (firstProblems.size() < 12) {
                for (const std::string& problem : problems) {
                    if (firstProblems.size() >= 12) break;
                    firstProblems.push_back(function.name + ": " + problem);
                }
            }
        }
    }

    printf("functions lifted    : %zu\n", functionsLifted);
    printf("machine insns       : %llu\n", (unsigned long long)machineInsns);
    printf("ir ops              : %llu", (unsigned long long)irOps);
    if (machineInsns != 0) {
        printf("  (%.2f ops per machine insn)", double(irOps) / double(machineInsns));
    }
    printf("\n");
    printf("temporaries         : %llu\n", (unsigned long long)temps);
    printf("unmodelled insns    : %llu", (unsigned long long)intrinsics);
    if (machineInsns != 0) {
        printf("  (%.2f%% of machine insns)",
               100.0 * double(intrinsics) / double(machineInsns));
    }
    printf("\n");
    printf("fully modelled fns  : %zu / %zu (%.1f%%)\n", functionsFullyModelled,
           functionsLifted,
           functionsLifted ? 100.0 * double(functionsFullyModelled) / double(functionsLifted)
                           : 0.0);
    printf("verifier failures   : %zu functions%s\n", functionsWithProblems,
           functionsWithProblems == 0 ? "  <- structurally clean" : "  <- LIFTER BUG");
    printf("jump tables         : %llu indirect, %llu recovered, "
           "%llu CFG edges present, %llu added late\n",
           (unsigned long long)indirectJumps,
           (unsigned long long)recoveredJumps,
           (unsigned long long)representedEdges,
           (unsigned long long)recoveredEdges);

    for (const std::string& problem : firstProblems) {
        printf("  ! %s\n", problem.c_str());
    }

    if (!unmodelled.empty()) {
        std::vector<std::pair<mint::u16, mint::u64>> ranked(unmodelled.begin(), unmodelled.end());
        std::sort(ranked.begin(), ranked.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        printf("\ntop unmodelled instructions (the work list, by payoff)\n");
        const size_t show = std::min<size_t>(15, ranked.size());
        mint::Disassembler renderer;
        const bool canRender = renderer.open(image.arch()).ok();
        for (size_t i = 0; i < show; ++i) {
            printf("  %-6llu  id=%-5u %-8s", (unsigned long long)ranked[i].second,
                   ranked[i].first, lifter.instructionName(ranked[i].first));
            if (canRender) {
                for (mint::Address at : examples[ranked[i].first]) {
                    mint::DecodedInsn decoded;
                    const mint::ByteView bytes = image.memory().viewAt(at, 16);
                    if (!bytes.empty() && renderer.decodeVerbose(at, bytes, &decoded)) {
                        printf("  | %s", decoded.text().c_str());
                    }
                }
            }
            printf("\n");
        }
        printf("  (%zu distinct unmodelled opcodes)\n", ranked.size());
    }
}

/// The IR for one function, next to nothing else. Used for eyeballing lifter
/// output against `llvm-objdump -d` on the same address, which is the only way to
/// tell correct IR from plausible IR.
void dumpFunctionIr(const mint::ElfImage& image, const mint::CodeAnalyzer& analyzer,
                    mint::Address entry) {
    const mint::Function* function = analyzer.functionAt(entry);
    if (function == nullptr) {
        printf("\nno function at 0x%llx\n", (unsigned long long)entry);
        return;
    }
    mint::Lifter lifter;
    if (!lifter.open(image.arch()).ok()) return;

    mint::IrFunction ir;
    if (!lifter.liftFunction(*function, image.memory(), &ir).ok()) return;

    printf("\n==================== ir listing ====================\n");
    printf("%s", ir.toText().c_str());

    const std::vector<std::string> problems = ir.verify();
    if (problems.empty()) {
        printf("\nverifier: clean\n");
    } else {
        printf("\nverifier found %zu problems:\n", problems.size());
        for (const std::string& problem : problems) printf("  ! %s\n", problem.c_str());
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: mint_probe <file> [function-address-hex]\n");
        return 2;
    }

    mint::MappedFile file;
    mint::Status status = file.open(argv[1]);
    if (!status.ok()) {
        fprintf(stderr, "map failed: %s\n", status.toString().c_str());
        return 1;
    }
    printf("file          : %s (%zu bytes)\n\n", argv[1], file.size());

    mint::ElfImage image;
    status = image.load(file.view());
    if (!status.ok()) {
        fprintf(stderr, "elf load failed: %s\n", status.toString().c_str());
        return 1;
    }
    dumpElf(image);

    mint::CodeAnalyzer analyzer;
    status = analyzer.analyze(image);
    if (!status.ok()) {
        fprintf(stderr, "analysis failed: %s\n", status.toString().c_str());
        return 1;
    }
    dumpAnalysis(image, analyzer);
    validateAgainstSymbols(image, analyzer);

    for (const std::string& warning : analyzer.warnings()) {
        printf("  ! %s\n", warning.c_str());
    }

    dumpLifting(image, analyzer);

    if (argc >= 3) {
        const mint::Address target = strtoull(argv[2], nullptr, 16);
        dumpFunctionListing(image, analyzer, target);
        dumpFunctionIr(image, analyzer, target);
    }
    return 0;
}
