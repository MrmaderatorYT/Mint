#pragma once

#include <memory>
#include <atomic>
#include <string>
#include <vector>

#include "mint/analysis/code_analyzer.h"
#include "mint/base/mapped_file.h"
#include "mint/base/status.h"
#include "mint/disasm/disassembler.h"
#include "mint/decompile/decompiler.h"
#include "mint/ir/lifter.h"
#include "mint/loader/elf_image.h"
#include "mint/loader/dex_image.h"
#include "mint/loader/zip_reader.h"
#include "mint/detectors/detector.h"

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
    Status finishOpen();

    MappedFile file_;
    ElfImage image_;
    CodeAnalyzer analyzer_;
    Disassembler renderer_;
    Lifter lifter_;
    DexImage dex_;
    ZipReader zip_;
    std::vector<u8> dexStorage_;
    std::vector<DetectorFinding> detectorFindings_;
    InputKind kind_ = InputKind::kElf;
    std::atomic_bool cancel_{false};
    std::atomic_int progress_{0};
    bool loaded_ = false;
    bool analyzed_ = false;
};

}  // namespace mint
