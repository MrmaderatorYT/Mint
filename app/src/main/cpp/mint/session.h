#pragma once

#include <memory>
#include <atomic>
#include <string>
#include <vector>
#include <unordered_map>

#include "mint/analysis/code_analyzer.h"
#include "mint/analysis/program.h"
#include "mint/base/mapped_file.h"
#include "mint/base/status.h"
#include "mint/disasm/disassembler.h"
#include "mint/decompile/decompiler.h"
#include "mint/ir/lifter.h"
#include "mint/loader/elf_image.h"
#include "mint/loader/dex_image.h"
#include "mint/loader/zip_reader.h"
#include "mint/detectors/detector.h"
#include "mint/debug/dwarf_reader.h"
#include "mint/debug/debugger.h"
#include "mint/version/version_tracking.h"
#include "mint/analysis/interprocedural_prototypes.h"
#include "mint/types/signature_library.h"
#include "mint/plugin/plugin_runtime.h"

namespace mint {

/// One open binary and everything the analysis derived from it.
///
/// The Java side holds only an opaque handle to this. Nothing above the JNI layer
/// owns analysis state, which keeps ownership unambiguous: the session outlives
/// individual UI screens, and closing it is the single point where all of the
/// memory — including the file mapping — goes away.
class Session {
public:
    enum class InputKind { kElf, kDex, kApk };

    Status openPath(const std::string& path);
    Status openFd(int fd);
    Status openRawPath(const std::string& path, Arch arch, Address base, Address entry);
    Status openMachOPath(const std::string& path,Arch architecture);

    /// Runs loading and code discovery. Separate from open() because it is the
    /// expensive part and the UI wants to show file metadata first.
    Status analyze();

    bool analyzed() const { return analyzed_; }
    int progress() const { return progress_.load(std::memory_order_relaxed); }
    InputKind kind() const { return kind_; }
    bool isDexLike() const { return kind_ != InputKind::kElf; }

    /// Stable synthetic address space for Dalvik methods. It keeps the existing
    /// JNI arrays useful without pretending a DEX has ELF virtual addresses.
    static Address dexMethodAddress(u32 index) {
        return 0xd0000000ull + static_cast<Address>(index) * 0x00100000ull;
    }
    static u32 dexMethodIndex(Address address) {
        return address >= 0xd0000000ull
                   ? static_cast<u32>((address - 0xd0000000ull) / 0x00100000ull)
                   : kNoBlock;
    }

    const ElfImage& image() const { return image_; }
    const CodeAnalyzer& analyzer() const { return analyzer_; }
    const MappedFile& file() const { return file_; }
    const DexImage& dex() const { return dex_; }
    Status attachProject(const std::string& path);
    const Program& program() const { return program_; }
    Status reanalyze();
    /// Last discovery update and cache diagnostics, also shown in the analysis log.
    std::string analysisStatusText() const;
    Status defineType(const std::string& declaration);
    Status importLibrary(const std::string& text,bool signatures);
    std::string signatureLibraryText() const {return program_.get(0,"signature-library");}
    Status eraseType(const std::string& name);
    std::string typesText() const { return program_.types().renderDefinitions(); }
    std::string typesCHeaderText() const {std::string text;const auto status=program_.types().cHeader(&text);return status.ok()?text:status.toString();}
    std::string interproceduralText();
    std::string abiText(Address function) const;
    std::string localVariablesText(Address function);
    Status editLocalVariable(Address function,const std::string& identity,const std::string& name,const std::string& type);
    std::string memoryBlocksText() const;
    std::string provenanceText(Address address) const;
    Status exportPatchedCopy(const std::string& path) const;
    Status editAnnotation(Address address, const std::string& kind, const std::string& value);
    Status undoEdit(bool redo);
    std::string annotation(Address address, const std::string& kind) const { return program_.get(address, kind); }
    std::string nameAt(Address address) const;
    std::string displayNameAt(Address address) const;
    UserPrototype prototypeAt(Address address) const;
    struct ListingRow { Address address = 0; u32 size = 1; FlowKind flow = FlowKind::kNormal; Address target = kNoAddress; std::string text, comment; };
    std::vector<ListingRow> programListing(Address start, size_t limit);
    std::string searchText(const std::string& query, size_t limit = 500);
    std::string referencesText(Address address);
    std::string debugInfoText() const { return dwarfReportText(debugInfo_); }
    Status importExternalDebug(const std::string& path, bool allowUnverified = false);
    const std::string& externalDebugDigest() const { return externalDebugDigest_; }
    std::string sourceLocationText(Address address) const;
    Status runScript(const std::string& source,bool allowEdits,std::string* output);
    Status assembleAt(Address address,const std::string& source,bool apply,std::string* bytes);
    Status loadPlugin(const std::string& path,bool trustNativeCode) { return plugins_.load(path,trustNativeCode); }
    std::string pluginCommandsText() const { return plugins_.commandsText(); }
    Status runPlugin(const std::string& command,const std::string& arguments,bool allowEdits,std::string* output) { return plugins_.run(*this,command,arguments,allowEdits,output); }
    Status connectDebugger(const std::string& host,u32 port,bool dap,bool allowPlaintextRemote);
    Status debuggerCommand(const std::string& operation,Address address,u64 value,std::string* output);
    // The second Program stays independent; only explicitly confirmed pairs may
    // transfer annotations, and only after a separate preview/apply action.
    Status openComparison(const std::string& path,const std::string& projectPath,
                          Arch rawArch=Arch::kUnknown,Address base=0,Address entry=0,bool machOSlice=false);
    Status comparisonCommand(const std::string& operation,Address source,Address target,
                             const std::string& path,std::string* output);

    /// Renders one instruction's text. Uses a session-owned disassembler so the
    /// listing does not pay for opening a Capstone handle per screenful.
    bool renderInstruction(Address addr, DecodedInsn* out);

    /// A comment for the listing's right-hand column: the resolved name of a
    /// branch or call target, when there is one.
    std::string commentFor(const InsnRecord& record) const;

    /// All warnings from every stage, for the analysis log the user can read.
    std::vector<std::string> allWarnings() const;

    /// The MintIR listing for the function containing `address`, lifted on demand.
    ///
    /// Nothing is cached: lifting one function costs well under a millisecond, and
    /// holding IR for every function would cost tens of megabytes for data only one
    /// screen ever looks at. If a caller starts asking repeatedly for the same
    /// function, a small LRU belongs here — not a program-wide table.
    std::string irTextFor(Address address);
    /// Full on-demand SSA/pseudo-C view for the selected function.
    std::string decompiledCFor(Address address);
    /// A compact, line-oriented CFG representation consumed by the Android
    /// graph view. One line is `id start end successor...`.
    std::string cfgTextFor(Address address);

    /// Lifter coverage across the program: how much of it became real IR rather
    /// than intrinsics, and which opcodes account for the rest.
    ///
    /// This is the IR pane's whole-program view. It exists because "how far can I
    /// trust the output" is the first question about a decompiler, and the answer is
    /// a property of the program, not of one function.
    std::string programCoverageText();

    /// Which functions write the most, program-wide — the Writes pane's
    /// whole-program view.
    std::string programWriteSummaryText();

    /// The program as a C header: one prototype per function.
    ///
    /// This is the pseudo-C pane's whole-program view, and it is the only one that
    /// is actually C. Signatures come from the emitter rather than being rebuilt
    /// here, so a prototype says exactly what the decompiled body would say.
    ///
    /// Its own pass, not the one behind coverage and writes: this needs full
    /// decompilation per function, and folding that in would make the two cheap
    /// reports wait for it.
    std::string programPrototypesText();

    /// Where the function containing `address` writes, as a text map.
    ///
    /// Every store is decomposed into a base and a byte offset, grouped by base and
    /// rendered with a density bar per slot. What this answers is "what does this
    /// function actually modify" — the question that separates a pure helper from
    /// something with side effects, and that tells you which struct fields an
    /// initialiser fills in.
    ///
    /// Counts are static: how many store instructions target a slot, not how many
    /// times one executes. A store inside a loop counts once.
    std::string writeMapText(Address address);

    /// Who calls the function containing `address`, and who it calls.
    ///
    /// Callers come with the address of the call itself, not just the calling
    /// function's name: "reached from somewhere in sub_1234" is a much weaker answer
    /// than an address you can jump to. Direct calls only, so an indirect caller is
    /// absent rather than guessed — and the count of indirect calls in the program is
    /// reported so the absence is visible.
    std::string xrefsText(Address address);

    /// The analysis as JSON: functions, call edges and recovered types.
    ///
    /// Versioned on purpose. This is the format another tool reads, so its shape is a
    /// promise: `schema` is bumped whenever a field changes meaning, and a consumer
    /// that checks it can refuse a file it does not understand instead of
    /// misreading one. Addresses are decimal numbers rather than hex strings —
    /// every JSON parser agrees on numbers, none agree on how to unquote "0x1a".
    static constexpr int kJsonSchema = 1;
    std::string exportJsonText();

    /// Every printable string in the image, with its address and the segment it
    /// lives in — .rodata, mostly.
    ///
    /// Making strings resolvable inside pseudo-C is not the same as making them
    /// browsable, and reading the strings is the first thing anyone does to an
    /// unfamiliar binary. Pass a function's address to list only the strings that
    /// function refers to, or 0 for the whole image.
    std::string stringsText(Address functionAddress);

    /// Resolves a table of 32-bit self-relative offsets at `base` into the strings
    /// it points at, one "index -> literal" line each, or empty when `base` holds no
    /// such table. Stops at the first entry that is not a string, so the table's own
    /// contents decide its length.
    std::string offsetTableText(Address base) const;

    /// A C string literal for `address`, quoted and escaped, or empty when the
    /// address does not hold one.
    ///
    /// Deliberately strict. Any run of bytes can be read as text, so a loose test
    /// turns pointers and small integers into nonsense strings, which is worse than
    /// leaving them as numbers: a wrong literal reads as recovered information.
    /// Requires mapped, non-executable memory, a NUL terminator within a bounded
    /// distance, and every byte printable.
    /// `minLength` guards against reading noise as text, and belongs to the caller:
    /// four is right when hunting for strings among arbitrary bytes, but a table
    /// entry that already points somewhere deliberate needs no such help — "elf" and
    /// "apk" are three characters and perfectly real.
    std::string stringAt(Address address, size_t minLength = 4) const;

    /// The whole program's call graph, in the same line-oriented shape:
    /// `index entry callee...`, where `index` and each `callee` are positions in
    /// the function list the caller already holds.
    ///
    /// Indices rather than names or addresses because the UI has paged the function
    /// table across already; sending names again would put a megabyte of duplicated
    /// strings through JNI to say something the caller can look up locally.
    ///
    /// Built from `Function::callees`, so it covers direct calls only. An indirect
    /// call is absent from the graph rather than guessed at.
    std::string callGraphText() const;

    /// Requests cooperative cancellation. The mapped file and native object
    /// remain alive until the worker has returned, so cancellation cannot race
    /// a JNI call with Session destruction.
    void requestCancel() { cancel_.store(true, std::memory_order_relaxed); }

private:
    void notifyPluginEvent(u32 kind,Address address,const std::string& detail);
    std::vector<std::string> pluginEventWarnings_;
    Status prepareLocalSsa(Address function,SsaFunction* output);
    Program program_;
    PluginManager plugins_;
    DebuggerClient debugger_;
    std::unique_ptr<Session> comparison_;
    TrackingState tracking_;
    InterproceduralPrototypeReport prototypeEvidence_;
    bool prototypeEvidenceBuilt_ = false;
    size_t prototypeEvidenceExcluded_ = 0;
    SignatureLibrary signatures_;
    DwarfReport debugInfo_;
    std::string externalDebugDigest_;
    Status restoreExternalDebug(const std::string& projectPath);
    void loadDebugInfo();
    DataTypeManager importedDebugTypes() const;
    void buildReferences();
    Program::ReferenceGroup functionReferences(const Function& function);
    Program::ReferenceGroup globalReferences() const;
    void refreshReferences(const std::vector<CodeAnalyzer::AddressRange>& dirty);
    size_t referenceGroupsUpdated_ = 0;
    Status applyUserModel();
    CodeAnalyzer::Options analysisOptions();
    std::string analysisDependencyKey() const;
    bool restoreAnalysisCache(const CodeAnalyzer::Options& options);
    void saveAnalysisCache();
    Status updateAfterEdit(const std::vector<ProgramAnnotation>& before, ElfImage* prepared = nullptr);
    Status prepareUserImage(const std::vector<ProgramAnnotation>& annotations, const DataTypeManager& types, ElfImage* result) const;
    u64 dataSize(Address address, const std::string& type, const DataTypeManager& types) const;
    Status finishOpen();
    void beginOpen();

    MappedFile file_;
    ElfImage image_;
    CodeAnalyzer analyzer_;
    Disassembler renderer_;
    Lifter lifter_;
    DexImage dex_;
    ZipReader zip_;
    /// Both whole-program reports come from one pass over every function, because
    /// lifting the program is the expensive part and doing it twice to answer two
    /// questions about the same pass would be waste the user waits through.
    struct ProgramReport {
        bool built = false;
        std::string coverage;
        std::string writes;
        bool prototypesBuilt = false;
        std::string prototypes;
    };
    ProgramReport programReport_;
    void buildProgramReport();
    void buildPrototypes();

    std::vector<u8> dexStorage_;
    std::vector<DetectorFinding> detectorFindings_;
    InputKind kind_ = InputKind::kElf;
    std::atomic_bool cancel_{false};
    std::atomic_int progress_{0};
    bool loaded_ = false;
    bool analyzed_ = false;
    std::string analysisCachePath_;
    bool allowCacheRestore_ = true;
    std::string analysisMode_ = "none", analysisReason_, analysisCacheDiagnostic_;
    size_t analysisFunctionsUpdated_ = 0;
};

}  // namespace mint
