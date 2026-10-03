# Mint

<p align="center">
  <img src="app/src/main/res/drawable/logo.png" alt="Mint logo" width="256">
</p>

Mint is an offline binary-analysis and decompilation workspace **running on Android**. Its primary purpose is reversing native binaries, not Android APK application analysis. The original targets are ELF64/AArch64 and ELF64/x86-64; ELF32/ARM/Thumb/x86-32/RISC-V32, ELF64/RISC-V64, explicit raw mappings, PE32/PE32+ and little-endian thin32/64 or validated universal Mach-O containers now use the same native engine. Analysis runs in C++ through JNI and exposes disassembly, MintIR, pseudo-C, control-flow graphs, functions, and diagnostics in a touch-oriented UI. Legacy DEX/APK parsing is present but is not the development priority.

The project is an independent, Ghidra-inspired implementation. It does not embed Ghidra, Sleigh, LLVM, or Unicorn, and it is no longer a mock-data simulator. Mint is currently a `0.3 preview`: the core pipeline is functional, but format, architecture, type-recovery, and control-structure coverage are narrower than a desktop reverse-engineering suite.

## What works today

- Defensive little-endian ELF32/ELF64 loading with sections, symbols, program headers, PLT entries, initializers, standard relocations, Android packed relocations, and RELR; ELF32 also maps allocated sections of relocatable objects at synthetic addresses.
- Capstone-backed AArch64, ARM, Thumb, x86-32, x86-64, RISC-V32 and RISC-V64 disassembly; a validated architecture-description registry with trusted external decoder, lifter and register-ABI extensions.
- Recursive-descent function and CFG discovery, with an AArch64 linear-sweep fallback.
- Bounded AArch64 PIC jump-table recovery integrated into analysis.
- General register-SSA finite-set indirect branch/call recovery through constants, phis, arithmetic, selections, immutable pointer loads and loader relocations, integrated into function discovery and CFG construction. Partial or unknown evidence never completes a CFG.
- MintIR with explicit flag operations and normalized overlapping register windows.
- AArch64/x86-64 lifting, width-aware x86-32 lifting, scalar ARM/Thumb and RISC-V32/64 integer/compressed lifting, and legacy partial Dalvik lifting; unsupported instructions remain explicit intrinsics.
- IR verification plus dominance, dominance-frontier, SSA, phi insertion, def-use, liveness, simplification, constant propagation, and basic type/structure recovery.
- Pseudo-C generation with expressions, `if`, `while`, `do-while`, and label/`goto` fallbacks.
- A MintIR interpreter for controlled emulation; no native target code is executed.
- APK/DEX parsing through the same Android file picker used for ELF files.
- Heuristic OLLVM, crypto, anti-tamper, packer, and string-recovery components.
- SQLite-backed cache/query components, plus a portable user Program overlay and versioned derived native analysis snapshots independent of system SQLite availability.
- SHA-256-keyed private projects with saved annotations and last-workspace restoration.
- Persistent user symbols, comments, bookmarks, code/data decisions, explicit function entries, type definitions, supported authoritative target-ABI prototypes, guarded local bindings and byte patches; transactional edits with bounded session undo/redo.
- Unified code/data listing with bytes, and global symbol/comment/string/byte-pattern search.
- Program-owned memory block view and bidirectional reference index: direct-flow, relocations, constant-SSA reads/writes, and separately labeled literal/address candidates. Unknown aliasing is not guessed.
- ELF EH-frame/FDE and executable-relocation function roots, supported PE runtime-function and Mach-O unwind metadata; deterministic user boundaries; conservative immutable x86 RIP-indirect flow recovery and discovery provenance.
- Bounded interprocedural register-ABI width/pointer evidence over direct and proven recovered calls; imported/user declarations remain authoritative and unknown argument counts/results remain unknown.
- Data Type Manager for primitive/pointer/array/alias/struct/packed/union/enum layouts, supported DWARF/PDB imports, Itanium demangling, evidence-backed primary/secondary vtable/RTTI inventory and bounded Itanium exception metadata.
- Headless commands and permission-gated Lua scripts, bounded scalar assembly, identity-bound version tracking, explicit external debugging and trusted native command/pass/event extensions.
- Versioned JSON export, mapped-byte comparison, independent project archives and patched-copy export without modifying the imported source.
- Host-side probes, feature tests, JNI tests, fuzzing, Android unit tests, and device instrumentation tests.

## Android workspace

The main screen is implemented by `WorkspaceActivity` and provides these panels:

- **Functions** — discovered functions and symbols.
- **Disasm** — paged disassembly with tappable branch targets and back navigation.
- **IR** — lifted MintIR for the selected function.
- **Pseudo-C** — decompiler output.
- **CFG** — the real control-flow graph rather than placeholder nodes.
- **Log** — loader and analysis diagnostics.

Analysis runs outside the UI thread, reports progress, and can be cancelled. `WorkspaceViewModel` retains the native session, selected address, active pane, listing position, and consumed `ACTION_VIEW` intent across activity recreation, so rotating the device does not restart analysis or discard navigation state. System-bar and display-cutout insets are handled in portrait and landscape.

Long functions are loaded in pages instead of being silently truncated at 4,096 instructions. A finite page limit remains as a safety guard and is reported in the UI when reached.

Long-press a function or listing row to rename a symbol, edit comments/bookmarks, define data with a type expression or `cstring`, set an authoritative prototype such as `int32_t(uint64_t context)` or an explicit convention such as `@windows64 uint64_t(uint64_t context)`, create a function entry (`code`), or patch hex bytes (`1f 20 03 d5`). Supported prototypes are checked against the target storage model, not assumed to be register-only. The project menu offers search, address navigation, references, memory blocks, Data Type Manager, provenance, C++ metadata, reanalysis, undo/redo/forward navigation and patched-copy export through the storage picker. Byte searches use `bytes: 7f 45 4c 46`. Search and reference results navigate to both code and data; pseudo-C links recognized identifiers/hex addresses back to the listing. Listing/decompiler/CFG share the selected function, and outdated asynchronous results are discarded after navigation.

The Project menu additionally exposes DWARF/source metadata and explicit external/split debug imports, call-graph prototype constraints and ABI storage, persistent SSA/stack local edits, assembly preview/patching, Lua scripts, semantic binary comparison/version tracking, external debugger connections and explicitly trusted native plugins. Version tracking saves/loads identity-bound function confirmations through the storage picker; annotations transfer only after preview and confirmation into an independent comparison Program. Instruction correspondence requires exact decoded operands and owning CFG context, using unique anchors or unique neighborhoods. It tolerates supported NOP insertion and physical basic-block movement; changed constants, ambiguous alignments and branches into unproven targets never authorize instruction annotation transfer. It does not prove equivalence across register allocation or compiler optimizations.

Complete project backups (`.mintproj`) include the original input, authoritative `Program`, user types/symbols/comments/bookmarks/prototypes/local bindings/patches, explicit raw mapping or Mach-O slice selection and current navigation. An explicitly imported external debug sidecar is included with its source/content SHA-256 binding. Restore checks exact allowed ZIP entries, decompressed resource bounds, checksums and the native Program before publishing a **new independent project**, never overwriting an existing project. Derived analysis caches and executable plugins are deliberately excluded. Limits are 512 MiB input, 16 MiB Program and 128 MiB external debug data. Backups contain the original binary and private research notes; choose a trusted destination.

Imports are copied into `files/projects/<sha256>/input.bin`. Raw imports require an explicit architecture/base/entry and get separate project identities for different mappings; explicit Mach-O CPU selections are likewise separate from the default first supported slice. Both configurations are restored on cold reopen. User state is stored in a versioned `program.mint` overlay with temporary-file write, fsync, and atomic rename, bound to the input/configuration fingerprint. Failed saves and invalid code/data/patch changes do not replace the live model. Data can replace discovered instructions; user function seeds cannot overlap data. Patches are copy-on-write memory overlays, never writes to the imported file; export requires a new file at the native boundary. A universal Mach-O export retains the complete original container and changes only mapped bytes in the selected slice. Loader mappings/metadata remain those of the original container after patches. Revision is a session invalidation counter, not durable version history; undo/redo is limited to the current session (64 edits).

Derived native instructions, function membership/provenance, recovered indirect targets, and the lazy-built reference index are stored separately in `program.mint.analysis`. This bounded, checksummed, versioned little-endian snapshot is atomically replaced and keyed by original source/configuration, structural user decisions, memory mappings, analysis options, and engine contract version plus an automatically generated SHA-256 native-source identity (including uncommitted source edits). CFGs and indexes are reconstructed on restore, and instruction metadata is checked against current decoded bytes. Missing, stale, truncated, or invalid snapshots fall back to full discovery without discarding user state; cache-save failure is a diagnostic, not failure of the already-committed user edit. Fingerprints/checksums detect accidental mismatch/corruption, not malicious authentication. IR, SSA, and pseudo-C remain on-demand, not persisted.

Flow-preserving patches have a conservative dependency-scoped discovery path: all affected functions (including shared-code owners) are re-decoded and their CFG/index data replaced only when coverage and topology remain valid. Changed control flow, indirect-pointer dependencies, changed code/data boundaries or type models, incomplete affected functions, and other unproven cases fall back to full discovery. Name/comment/bookmark/prototype edits preserve discovery and structural references. References are grouped by owning function plus global data/relocations; known code and immutable-memory dependencies invalidate affected groups, while unproven cases rebuild safely. Whole-program reports are invalidated. This is **not general incremental memory SSA/alias analysis**. Undo/redo uses the same update policy. Explicit Reanalyze always runs full discovery. The Log and memory-block report expose `mode=full|restored|incremental|metadata`, updated function/reference-group counts, and fallback/cache diagnostics. Restored indirect targets are re-proved against the effective bytes rather than trusted because they were cached.

All five stages have implemented engine features exposed through the workspace/headless interfaces; this remains a bounded preview rather than a claim of Ghidra parity. Stack analysis tracks exact entry-SP-relative slots, memory versions, escapes, overlaps and aliasing barriers. Only proven non-overlapping initialized leaf slots are promoted to C locals. A conservative general memory sidecar records absolute global, entry-stack and symbolic-base+offset accesses, memory versions and reaching-store evidence; different symbolic pointers may alias, and unknown writes/calls invalidate possibly affected evidence. This is not complete heap-object recovery or memory/alias SSA. It does not silently delete stores or fold unproven loads. AST generation structures reducible nested conditionals, loops and switches while retaining explicit fallbacks where edge effects or exit structure cannot be preserved.

Persisted local names/types use guarded normalized-SSA/stack identities. Exact supported width/type edits affect emitted declarations and uses; incompatible edits are rejected, and structural changes retain stale bindings without applying them to different values. Authoritative prototypes can describe stack parameters, supported floating/aggregate storage, hidden result pointers, register pairs and named variadic parameters. `@windows64`, `@cdecl32`, `@stdcall32` and other explicit target conventions are validated by a storage model; the ABI report distinguishes registers, entry-SP offsets and Windows shadow space. Unsupported ABI layouts fail explicitly. Complex aggregate/FP conversions remain explicit helpers where source reconstruction cannot be proven. Automatic call-graph inference is more limited than this authoritative storage model: automatic Windows prototype inference is disabled, and Windows binaries are never inferred under SysV assumptions.

Data type examples: `Packet=struct{length:u32;bytes:u8[16];next:Packet*}`, `Wire=packed{tag:u8;value:u32}`, `Value=union{integer:u64;real:f64}`, `Color=enum:i32{Red=-1;Green=2}`. The Data Type Manager imports mutually linked layout libraries and exports GNU C11 declarations with exact padding, alignment, size and field-offset assertions. Exact supported field accesses through authoritative named-struct pointer parameters can use field names; arbitrary aggregate propagation remains incomplete. Serialized user type and signature libraries are each limited to 1 MiB. DWARF 2–5 supplies representable types, functions/prototypes, source lines and simple variable locations, including bounded zlib-compressed sections and explicitly selected external/split objects. Available debuglink CRC/build IDs/split-unit IDs must agree; acknowledging absent identity never bypasses an actual mismatch. No debuglink/DWO filename is followed automatically. Unsupported expressions/supplementary layouts remain partial. User declarations override imported evidence. RTTI/vtable inspection groups evidence-backed classes, primary/secondary address points and direct/virtual bases; dynamic virtual-base offsets remain symbolic. Itanium exception metadata decodes bounded EH-frame/FDE/LSDA call-site/action/type tables and grouped try-region/landing-pad relationships, including stripped EH-frame-header fallbacks; it does not invent source-level try/catch or a complete C++ object model.

Projects written by this build use `MINTPR04`; older `MINTPR01`/`MINTPR02`/`MINTPR03` overlays are read and upgraded on the next successful write. Older apps reject the new version instead of silently dropping types/patches/libraries/local bindings.

## Supported inputs

| Input | Current support |
| --- | --- |
| ELF64 / AArch64 | Primary native target; loader, CFG, IR, SSA, pseudo-C, and emulation are available. |
| ELF64 / x86-64 | Loader and analysis pipeline are available; instruction modeling is less complete than AArch64. |
| Standalone DEX | Header/class/method parsing, Dalvik listing, partial lifting, verification, and pseudo-C. |
| APK | ZIP extraction and analysis of `classes.dex`; application resources and full package semantics are not reconstructed. |
| PE32+ / AArch64, x86-64 | Native sections/imports/exports/delay imports/base-relocation inventory, supported runtime-function/unwind/CodeView records, explicit Windows64 prototype storage and selected PDB7 import. Complete rebasing/runtime C++ exception semantics are not implied. |
| Little-endian Mach-O32/64 and universal / ARM, AArch64, x86-32, x86-64 | Segments, symbols, entry/function starts, bounded supported dyld rebase/bind/export/chained-fixup and compact-unwind metadata. Explicit CPU selection persists/reopens/archives separately; whole-container patch offsets preserve unselected slices. |
| PE32 / x86-32 | Defensive section/entry/export/import/delay-IAT/base-relocation inventory, x86-32 analysis and explicit cdecl/stdcall stack prototype storage. ARM/Thumb PE32 is rejected; unimplemented Windows debug/unwind encodings remain partial. |
| ELF32 / ARM, Thumb, x86-32, RISC-V32 | Four-byte pointers, REL/RELA/RELR/Android packed metadata, symbol/mapping roots, listing, CFG, scalar IR, SSA and pseudo-C. ARM/Thumb pointer tags preserve decode mode; stack ABI and uncommon instruction semantics remain incomplete. |
| ELF64 / RISC-V64 | Eight-byte pointers and the same native analysis pipeline; base integer/M and common compressed scalar instructions are modeled. Floating-point, vector, atomic and privileged families remain intrinsic fallbacks. |
| Raw / all seven native ISA modes | Explicit architecture/base/entry, including entry address zero, over a single executable mapping. Unknown input never silently becomes raw; unsupported architecture IDs are rejected unless a validated decoder is registered. |

Multidex APK analysis is not complete. Unsupported or partially modeled machine instructions are emitted as explicit intrinsics instead of being assigned invented semantics.

## Five-stage development status

| Stage | Implemented foundation | Still open |
| --- | --- | --- |
| 1 — Mobile CodeBrowser | Durable user Program/types/patches/local bindings, full project archives with independent restore, code/data listing, references/search/reopen, synchronized selection and dependency-scoped updates. | Comprehensive runtime references and broader production/device coverage. |
| 2 — Correctness | Metadata roots, bounded SSA indirect recovery, authoritative target ABI storage, register interprocedural evidence, stack analysis, conservative general memory dependencies, AST structuring and compiler corpus. | Complete alias/heap-object/type inference, arbitrary runtime indirect targets, every ABI/compiler pattern and production corpus coverage. |
| 3 — Types/C++ | Layouts/C declarations, compressed/external/split DWARF, field names, demangling, evidence-backed classes/secondary vtables/virtual bases, grouped LSDA relationships, type/signature libraries. | Complete class/exception/source reconstruction, supplementary debug formats and every compiler-specific type record. |
| 4 — Breadth | ELF32/64 seven modes, raw, PE32/32+, thin32/64 and universal Mach-O with explicit slice selection, bounded dyld/PE relocation/import/unwind metadata and architecture registry. | Big-endian targets, every platform fixup/ABI and exhaustive ISA semantics. |
| 5 — Power users | Expanded bounded scalar assembler/symbol expressions/directives, Lua/headless, exact instruction+CFG correspondence, explicit debugger mapping/PC/thread controls and DAP stack/modules, native command/lifter/ABI/pass/event SDK v1/v2. | Full FP/SIMD/atomic/system assembly and relaxation, portable RSP stack/module inventory, every backend capability, additional language bindings and native-code isolation (trusted plugins remain unrestricted). |

The implementation covers concrete capabilities in every stage; the remaining coverage limits are stated above, not hidden behind a completeness claim. Native Program correctness remains the priority over APK analysis, cosmetic effects or collaboration infrastructure.

## Analysis pipeline

```text
Android Storage Access Framework
        |
        v
Mapped input -> ELF / PE / Mach-O / raw (legacy ZIP / DEX) loader -> function and CFG analysis
        -> disassembly -> MintIR lifting -> normalization and verification
        -> SSA and data-flow passes -> pseudo-C / CFG / IR interpreter
        -> JNI -> Android workspace
```

The native engine is C++17. Capstone is vendored under `app/third_party/capstone`; Android zlib and SQLite facilities are used where applicable.

### Native coverage and correctness bounds

ARM/Thumb uses canonical even memory/instruction addresses and retains the raw low-bit pointer tag as decode-mode evidence. ELF `$a`/`$t`/`$d` mapping symbols distinguish ARM code, Thumb code and inline data. Cross-mode recovered branches seed a tail-callee with its own mode instead of lifting mixed ISA bytes under one decoder. Supported predicated register/flag writes, including Thumb IT conditions, preserve their predicate in IR; predicated memory, calls, traps or PC writes that cannot be safely represented remain intrinsic fallbacks rather than speculatively executing the operation. RISC-V includes modeled integer/M and common compressed scalar operations, width-correct XLEN32/64 values, `x0`, PC-relative addresses, loads/stores, branches and link/return semantics; it is not a claim of full floating-point/vector/atomic/privileged ISA coverage. The ARM and RISC-V decoder sources are pinned to the existing Capstone `6.0.0-Alpha10`; download identity and licenses are documented in `app/third_party/capstone/NATIVE_DECODERS.md`.

ELF32 supports ARM (`EM_ARM`), i386 and RISC-V; ELF64 supports AArch64, AMD64 and RISC-V. Relocatable ELF32 sections receive bounded synthetic addresses, but instruction relocations are metadata rather than a general static-linker implementation. Container metadata is read only through validated file-backed ranges: virtual zero-fill cannot fabricate symbol, import or relocation tables. PE addresses use the preferred image base; base relocations, delay imports and supported runtime unwind ranges are inventoried, not a general executable loader/rebaser. Mach-O supports little-endian thin32/64 and validated universal containers; default selection uses the first supported slice, while explicit architecture selection is available through the native/JNI factory, Android import configuration and headless `--macho` option. Whole-container file offsets are retained for patch export. Supported dyld rebase/bind/export/chained-fixup and compact-unwind metadata are bounded; unimplemented encodings are reported. Raw files require an explicit supported decoder, pointer-width-consistent address range, aligned base/entry and an entry inside the mapping.

General indirect-flow recovery uses bounded finite sets, not sampled execution. Defaults are 32 values per set, 128 merged byte dependencies, 256 dataflow iterations and four million work steps per function. Native discovery allows at most eight recovery/discovery rounds, limits SSA recovery to 65,536 decoded instructions per function and one million eligible machine instructions per round, and checks cancellation between functions/rounds. Runtime/live-in targets, mutable/unmapped/ambiguous memory, unsupported semantics and unresolved CFG predecessors remain unknown or partial. Imported pointer slots are not guessed from relocation addends. Complete ARM targets retain canonical address, raw pointer and mode; confidence, provenance and exact pointer-load dependencies are available per site.

Saved general indirect targets and recovered calls are re-proved with transient IR/SSA from current decoded bytes and modes when restoring a native snapshot. Cached candidate edges are not trusted merely because they were serialized. A patch changing a proven target set, pointer dependency, authoritative root or flow topology falls back to full discovery. A flow-preserving patch can retain discovery only after affected owners and dependent evidence remain equivalent. This does not provide general incremental memory SSA or alias analysis.

Interprocedural inference propagates observed scalar widths and pointer-address uses through a deterministic call-graph fixedpoint. It honors imported/user declarations, direct calls and only complete recovered indirect-call sets. It does not invent a C declaration from uncertain evidence: unknown return width is not `void`, absent register evidence is not a known zero-argument signature, and x86-32 stack arguments are not mislabeled as SysV64 register parameters. Automatic aggregate, float, variadic and complete stack-ABI recovery remain limited; automatic Windows inference is disabled. These inference limits do not remove the separate supported authoritative ABI-storage declarations described above.

## Requirements

- Android Studio with Android SDK 36.
- JDK 17.
- Android NDK `28.2.13676358`.
- CMake `3.22.1`.
- An Android 8.0 / API 26 or newer device or emulator.

The checked-in build uses Gradle 8.13 and Android Gradle Plugin 8.11.1. Native APKs are produced for `arm64-v8a` and `x86_64`, with 16 KiB page-size-compatible linker settings.

## Build and test

Open the repository root in Android Studio, allow Gradle to install the declared SDK/NDK/CMake components, or use the wrapper from a JDK 17 shell.

```bash
./gradlew testDebugUnitTest assembleDebug assembleDebugAndroidTest
```

For a compact debug build on a disk-constrained machine, add `-PmintCompactDebug=true`. This retains line-table debug information instead of full native debug records; it does not remove architectures or change analysis behavior.

Run instrumentation tests with a connected device or running emulator:

```bash
./gradlew connectedDebugAndroidTest
```

Connected tests retain the installed application/test APKs and do not uninstall
incompatible versions automatically (`gradle.properties`). This protects private
Mint projects from test-runner cleanup; do not override these settings on a device
containing user data. `PlatformDeviceTest` creates and removes only its own cache
fixtures and covers all seven target modes plus persistent edits/types/Lua/patches.

Build a deliberately unsigned, minified release APK without configuring a key:

```bash
./gradlew assembleUnsignedRelease
```

`assembleRelease` and `bundleRelease` fail early when release signing credentials are missing; this prevents accidentally treating an unsigned artifact as publishable.

## Host-side engine tests

On macOS with the default Android SDK location, the convenience runner builds the native probes with ASan and UBSan and executes the complete suite:

```bash
app/hosttest/run.sh all
```

Individual layers are also available:

```bash
app/hosttest/run.sh engine /path/to/lib.so
app/hosttest/run.sh feature /path/to/lib.so
app/hosttest/run.sh jni /path/to/lib.so
app/hosttest/run.sh platform /path/to/lib.so
app/hosttest/run.sh archive
app/hosttest/run.sh fuzz 200
```

The explicit `archive` mode builds its own unsanitized JNI library and generated external DWARF/PDB fixtures, then verifies portable archive restoration against real native Programs. It is not added to the default `all` run.

The convenience script currently assumes macOS, JDK 17 from `/usr/libexec/java_home`, and the default `$HOME/Library/Android/sdk` layout. On other hosts, configure and run the CMake targets directly:

```bash
cmake -S app/hosttest -B build/hosttest -DCMAKE_BUILD_TYPE=Debug
cmake --build build/hosttest --parallel

./build/hosttest/mint_probe /path/to/lib.so
./build/hosttest/mint_ssa_test /path/to/lib.so
./build/hosttest/mint_feature_test /path/to/lib.so
ctest --test-dir build/hosttest --output-on-failure
./build/hosttest/mint_cxx_metadata_test --inventory /path/to/lib.so
```

The CMake host suite shares one sanitized engine across type, unwind, malformed-container, Program integration and headless smoke tests. JNI is built separately without sanitizers so it can load into a system JVM. Cross-compiled C++ fixtures are in `app/hosttest/fixtures/cxx_metadata.cpp`.

The native compiler corpus is generated from `app/hosttest/fixtures/corpus_native.c` by NDK Clang/LLD: AArch64, ARM, Thumb, x86-32, x86-64, RISC-V32 and RISC-V64 at `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, `-Oz` and `-O2 -flto` (49 real ELF binaries), plus the real NDK AArch64/x86-64 `libc++_shared.so` files. Configure the NDK path explicitly outside the default macOS SDK layout:

```bash
cmake -S app/hosttest -B build/hosttest -DMINT_HOST_CORPUS=ON -DMINT_CORPUS_NDK=/path/to/android/ndk/28.2.13676358
cmake --build build/hosttest --target mint_corpus_test --parallel
ctest --test-dir build/hosttest -R native_compiler_corpus --output-on-failure
```

The corpus verifies file mappings, function/listing ownership, native lifting, IR/SSA invariants and structured C emission. Controlled scalar kernels run only in the IR interpreter, never by launching the input binaries. Unsupported instruction families and incomplete functions are printed as coverage gaps; a fully modeled kernel producing an incorrect result fails the test. This is a reproducible compiler matrix, not a claim of comprehensive real-world or malware coverage.

The same corpus option also provides `mint_dwarf_corpus_files` (AArch64 DWARF5 and x86-64 DWARF4 shared libraries), `mint_exception_corpus_files` (AArch64, x86-64 and x86-32 C++ throw/catch libraries), and `mint_debug_loader_corpus_files` (external/compressed/split DWARF, multiple/virtual inheritance, and actual Windows PE/PDB7 fixtures). The exception fixtures deliberately omit `.eh_frame_hdr` and local symbols, preserving dynamic imports/exports and allocated unwind/LSDA tables so that non-exported functions must be discovered from unwind metadata. These small freestanding fixtures do not bundle a C++ runtime or execute native code; the real DWARF/PDB tests verify identity matching and source/type/prototype propagation into Program and pseudo-C.

## Headless CodeBrowser

```bash
./build/hosttest/mint_headless input.so --project program.mint functions
./build/hosttest/mint_headless input.bin --project raw.mint --raw aarch64 0x1000 0x1000 listing 0x1000
./build/hosttest/mint_headless universal.dylib --project arm-slice.mint --macho aarch64 functions
./build/hosttest/mint_headless input.so --project program.mint --script commands.mint json
```

Scripts contain one command per line, with `#` comments. Inspection commands include `summary`, `functions`, `listing ADDRESS`, `decompile ADDRESS`, `ir ADDRESS`, `cfg ADDRESS`, `refs ADDRESS`, `provenance ADDRESS`, `search QUERY`, `types`, `types-c`, `prototypes`, `abi ADDRESS`, `locals ADDRESS`, `signatures`, `cxx`, `dwarf`, `source ADDRESS`, and `json`. Explicit editing commands include `type DECLARATION`, `erase-type NAME`, `import-library PATH`, `import-debug PATH` (or `import-debug ack-unverified PATH` for missing identity evidence only), `local ADDRESS ID NAME TYPE`, `local-clear ADDRESS ID`, `edit ADDRESS KIND VALUE`, `asm-preview ADDRESS SOURCE`, `asm ADDRESS SOURCE`, `undo`, `redo`, `reanalyze`, and `export-patched NEW_PATH`. Addresses are decimal or 0x-prefixed hex. Empty edit values remove an override. Persistent writes require `--project`; scripts fail at the first invalid command but do not roll back earlier committed edits.

`diff` remains a byte-level comparison at matching addresses (up to 256 MiB, first 10,000 changes shown). The separate `compare-open`, `compare-project`, `compare-diff`, `compare-confirm`, `compare-save`, `compare-load`, `compare-preview` and `compare-apply` commands provide decoded instruction/function fingerprints, candidate matching and identity-bound persisted confirmations. Only supported control-flow addresses are normalized; scalar constants and memory operands remain significant. Transfer requires explicit confirmed one-to-one function pairs and `--allow-edits`; symbols/comments/bookmarks follow proven matching instructions, preserving an annotation's byte offset inside an instruction, while supported authoritative prototypes require confirmed function entries. Target annotations win, and patches/types/type libraries never transfer. The Android version-tracking menu imports an independent target Program and saves/loads confirmations through the storage picker.

### Lua, libraries and trusted extensions

`--lua FILE` runs embedded Lua 5.5.1 with a bounded allocator, instruction/call/output budgets and cancellation. Only text source is accepted; os/io/package/debug libraries, process/network/file APIs and bytecode loading are absent. Read-only is the default; `--allow-edits` enables normal transactional Program edits, not an unrestricted OS API. For example:

```lua
for _, fn in ipairs(mint.functions()) do
    print(fn.address, fn.name)
end
print(mint.decompile("0x1000")) -- hex strings preserve exact unsigned 64-bit addresses
```

The Android script dialog and storage-picker import use the same API. Completed authorized edits remain committed and undoable if a later script error occurs; native analysis calls are cooperatively bounded, not preemptively sandboxed.
Lua additionally exposes `mint.locals(address)`, `mint.abi(address)`, `mint.assemble_preview(address,source)`, `mint.edit_local(address,id,name,type)` and `mint.assemble(address,source)`. The last two require explicit edit permission; preview does not mutate the Program. Assembly supports labels and exact symbol-plus/minus-offset expressions, bounded `.byte`/`.short`/`.word`/`.quad`/`.zero`/`.align`/`.org` directives, x86 memory operands and implemented scalar instruction families across the seven native modes. It is a patch assembler, not an object linker: no general relocation records, complete FP/SIMD/atomic/system instruction coverage, macros or far-branch relaxation are provided. Limits are 64 KiB source and 1,024 output bytes/instructions; invalid input does not publish partial output.

Type libraries use `MINT_TYPES 1 POINTER_BYTES` followed by one `Name=type` declaration per line. Signature libraries use `MINTSIG 1`, then `abi=aapcs64|sysv64|aapcs32|riscv32|riscv64|cdecl32|windows64|stdcall32`, followed by exact linkage names and supported declarations separated by a tab. Import validates the target ABI/storage and commits atomically. Signature matching uses original symbols/PLT names, not guessed generated labels; explicit user and supported debug prototypes take precedence. Unknown named by-value layouts are rejected; opaque pointer storage does not require a known pointee layout.

Explicit external debug import also accepts bounded MSF7/PDB data for PE. RSDS GUID and age must match when present. The reader imports supported DBI/public/procedure/data symbols and representable TPI primitive/pointer/array/struct/union layouts and procedure prototypes into the same authoritative Program baseline. Type servers, OMAP remapping, C13 source lines, bitfields and complete virtual/nontrivial C++ layouts are not silently synthesized; unsupported metadata remains partial or is rejected when using it would produce wrong addresses. The selected private debug copy and identity binding survive reopening and project archives.

The native C SDK is in `mint/plugin/sdk.h`, with architecture extensions in `mint/plugin/architecture_sdk.h` and real C fixture plugins under `app/hosttest/fixtures`. Use `--plugin ABSOLUTE_PATH --trust-native` only for trusted libraries built for the host/device ABI. Plugins are **unrestricted native code**, can access Mint's private projects and network, and are never a malware isolation boundary. The host API supports bounded queries, exact 64-bit addresses, output and explicitly enabled edits. ABI1 decoder extensions remain supported. ABI2 adds validated bounded semantic fragments and copied register/calling-convention descriptors; malformed fragments fall back to an explicit intrinsic without partial IR publication. ABI2 extension modules can register explicitly invoked analysis passes and read-only analysis/edit/decompilation lifecycle observers with recursion protection. Observer failures are diagnostics, not discarded Program edits. Registered architecture code is retained for its process-wide callback lifetime; derived cache reuse is disabled for external architecture IDs.

A minimal ABI2 semantics export below assumes an existing ABI1 table `my_decoders` for custom architecture `185`: a 64-bit toy ISA where `0x10 IMM8` writes `r0` and `0xff` returns. The complete C decoder/lifter module is [architecture_semantics_sample.c](app/hosttest/fixtures/architecture_semantics_sample.c). Register offsets and widths describe storage in bytes, not native CPU register numbers; the host initializes and validates the fragment against the decoder's size and flow before publication.

```c
#include "mint/plugin/architecture_sdk.h"
extern const MintArchitecturePluginV1 my_decoders;
static const MintArchitectureRegisterV2 regs[] = {
    {0, 8, {0}, "r0"}, {8, 8, {0}, "sp"}
};
static int lift(void *context, uint64_t pc, const uint8_t *b,
                size_t n, MintSemanticFragmentV2 *out) {
    (void)context; (void)pc;
    if (!n || (b[0] != 0xff && (b[0] != 0x10 || n != 2))) return -1;
    out->operation_count = 1;
    MintSemanticOperationV2 *op = &out->operations[0];
    op->a.space = MINT_VALUE_CONSTANT; op->a.width = 8;
    if (b[0] == 0xff) op->op = MINT_IR_RETURN;
    else { op->op = MINT_IR_COPY; op->destination.space = MINT_VALUE_REGISTER;
           op->destination.width = 8; op->a.value = b[1]; }
    return 0;
}
static const MintArchitectureSemanticsV2 semantics = {
    2, sizeof(MintArchitectureSemanticsV2), 185, 8, {0},
    16, 2, regs, 8, 0, 1, {0}, 0, lift
};
static const MintArchitecturePluginV2 plugin = {
    2, sizeof(MintArchitecturePluginV2), &my_decoders, 1, &semantics
};
MINT_ARCHITECTURE_EXPORT const MintArchitecturePluginV2 *
mint_architecture_plugin_v2(void) { return &plugin; }
```

ABI2 is a bounded scalar semantic interface, not a Sleigh-compatible architecture language or an arbitrary C++ IR escape hatch. Register metadata is copied; callback/context lifetime remains process-wide. Analysis-pass and lifecycle-observer exports are a separate interface in `sdk.h`, not implied by an architecture decoder alone.

### External debugging

The Project menu or `debug-connect NUMERIC_IP PORT rsp|dap [ack-plaintext]` connects explicitly to an existing GDB-remote/RSP server or LLDB-DAP TCP adapter. No target process or shell is launched. DAP can attach to an explicitly supplied existing PID; operations include status, registers/memory, breakpoint set/remove, step/continue/interrupt/bounded wait, threads/selection, stack frames and adapter-supported module inventory. RSP supports thread inventory/selection and can read bounded exact target register descriptions (including bounded feature includes; XML entities are never expanded). RSP PC reading requires a supported exact little-endian `pc`/`rip`/`eip` register layout; raw unknown layouts are never guessed. Portable RSP stack-frame and module inventory are **not implemented** and return unsupported; use DAP for those operations.

`map-image RUNTIME_BASE` explicitly maps the current binary's preferred image base and segments; unmapped image operations fail, and Mint never guesses an ASLR slide or derives one from a module name. `memory-image`, `break-image`, `unbreak-image` and `pc-image` use this checked mapping; legacy runtime-address operations remain explicit. The Android workspace follows mapped PC after step/stop when the backend provides an exact PC and exposes threads, stack, modules and mapping controls. Disconnect clears session-only mappings. Backend capabilities vary and unsupported operations fail explicitly. Non-loopback plaintext endpoints require acknowledgement; the connection is not TLS-authenticated. Synthetic and loopback mock coverage is not a claim of comprehensive real-device/server compatibility.

## Release signing

No release keystore or password is committed. Copy the example configuration and fill it with credentials for a key you control:

```bash
cp app/signing.properties.example signing.properties
```

```properties
storeFile=app/keystores/mint-release.jks
storePassword=change-me
keyAlias=mint
keyPassword=change-me
```

Then build a signed APK or Android App Bundle:

```bash
./gradlew assembleRelease
./gradlew bundleRelease
```

CI can provide the same values without a properties file:

```text
MINT_KEYSTORE_PATH
MINT_KEYSTORE_PASSWORD
MINT_KEY_ALIAS
MINT_KEY_PASSWORD
```

Keep `signing.properties`, `*.jks`, and `*.keystore` private. They are excluded by `.gitignore`.

## Project layout

```text
app/src/main/java/com/ccs/mint/
├── core/                     Java session and JNI boundary
└── ui/                       Workspace, retained state, navigation, and CFG view

app/src/main/cpp/
├── jni/                      Android/native bridge
├── mint/loader/              ELF, PE, Mach-O, raw, ZIP, and DEX loading
├── mint/disasm/              Capstone integration
├── mint/analysis/            Program, functions, CFGs, unwind, references and C++ metadata
├── mint/types/               Persistent data-type layout manager
├── mint/ir/ and mint/ssa/    MintIR, normalization, verification, and SSA
├── mint/decompile/            Pseudo-C and control-structure recovery
├── mint/patch/                Bounded scalar patch assembler
├── mint/version/              Binary correspondence and confirmed annotation transfer
├── mint/debug/                Explicit RSP/DAP client and image/runtime mapping
├── mint/plugin/               Trusted C command, architecture and lifecycle SDKs
├── mint/interp/               MintIR interpreter
├── mint/obfuscation/          OLLVM and string-recovery experiments
├── mint/detectors/            Heuristic binary detectors
└── mint/db/                   SQLite persistence and queries

app/hosttest/                  Native, JNI, feature, performance, and fuzz probes
```

## Known limitations

- Mint is a preview and should not be treated as a correctness-equivalent replacement for Ghidra, IDA, Binary Ninja, or a production malware sandbox.
- All seven native modes have intrinsic fallbacks; scalar coverage differs by ISA and compiler choices. SIMD, floating-point, atomic, system, predication and uncommon instruction families are not exhaustive.
- Dalvik lifting and APK support are partial, and multidex/resource/manifest analysis is not complete.
- Dedicated jump-table recognition targets bounded AArch64 PIC patterns. General SSA finite-set recovery covers proven arithmetic/phi/immutable-pointer targets across the native modes, but does not resolve arbitrary dynamic dispatchers, mutable tables or every compiler switch idiom.
- Imported/user type layouts, local bindings and supported authoritative ABI declarations are explicit and validated; automatic high-level type, calling-convention, exception and cross-function reconstruction remains incomplete.
- The general memory sidecar is conservative dependency evidence, not complete memory SSA, heap-object recovery or arbitrary alias inference.
- The assembler covers implemented scalar forms, not complete FP/SIMD/atomic/system ISA families or general object linking/branch relaxation.
- Exact instruction/CFG correspondence tolerates supported NOP insertion and block movement, not arbitrary compiler transformations; annotations never transfer from ambiguous alignment, and patches/types are excluded.
- External debugger capabilities depend on the connected backend; portable RSP stack/module inventory is unsupported. Native plugins are trusted unrestricted code, not an isolation boundary.
- The decompiler intentionally retains labels and `goto` for regions it cannot prove safe to structure.
- The interpreter models MintIR; it is not a full OS/process emulator, debugger, or isolation boundary.
- OLLVM recovery, string recovery, binary detectors, and optional SQLite analysis caching need broader real-world corpora. Durable user Programs use the independent overlay, not system SQLite.
- Cancellation is cooperative: a currently executing native stage may finish its bounded operation before stopping.


## Privacy and responsible use

Native binary analysis and Program storage run locally; opening or analyzing a binary does not upload it. The app now requests Internet permission for the explicitly initiated external-debugger TCP connections described above. No debugger connection is opened automatically. Trusted native plugins are not sandboxed and can use the app's permissions, including network and private files. This repository does not contain a store privacy-policy/listing artifact; these statements describe the implementation, not a published store policy.

Automatic app backup is disabled, and the backup/device-transfer rules explicitly exclude private imported binaries, Programs and analysis databases. A deliberate export through a selected document provider may write to cloud-backed storage chosen by the user.

Only analyze software and devices you own or are authorized to inspect. Treat all input binaries as untrusted. Mint parses and emulates data but does not make a hostile file safe.

## License

Copyright (c) 2026 Mint contributors.

Mint is released under the [GNU General Public License, version 3](LICENSE) (SPDX: `GPL-3.0-only`).

Mint is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3. Mint is distributed without any warranty; see LICENSE for the full terms.

Vendored Capstone, Lua, Gradle wrapper and other third-party components retain their upstream licenses and copyright notices. The app's third-party notices include Capstone and Lua.
