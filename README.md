# Mint

<p align="center">
  <img src="app/src/main/res/drawable/logo.png" alt="Mint logo" width="256">
</p>

Mint is an offline binary-analysis and decompilation workspace **running on Android**. Its primary purpose is reversing native binaries, not Android APK application analysis. The original targets are ELF64/AArch64 and ELF64/x86-64; ELF32/ARM/Thumb/x86-32/RISC-V32, ELF64/RISC-V64, explicit raw mappings, PE32/PE32+ and little-endian thin32/64 or validated universal Mach-O containers now use the same native engine. Analysis runs in C++ through JNI and exposes disassembly, MintIR, pseudo-C, control-flow graphs, functions, and diagnostics in a touch-oriented UI. Legacy DEX/APK parsing is present but is not the development priority.

The project is an independent, Ghidra-inspired implementation. It does not embed Ghidra, Sleigh, LLVM, or Unicorn, and it is no longer a mock-data simulator. Mint is currently a `0.3 preview`: the core pipeline is functional, but format, architecture, type-recovery, and control-structure coverage are narrower than a desktop reverse-engineering suite.

## What works today

- Defensive little-endian ELF32/ELF64 and big-endian AArch64 ELF64 loading with sections, symbols, program headers, PLT entries, initializers, standard relocations, Android packed relocations, and RELR; ELF32 also maps allocated sections of relocatable objects at synthetic addresses.
- Capstone-backed AArch64, ARM, Thumb, x86-32, x86-64, RISC-V32 and RISC-V64 disassembly; a validated architecture-description registry with trusted external decoder, lifter and register-ABI extensions.
- Recursive-descent function and CFG discovery, with an AArch64 linear-sweep fallback.
- Bounded AArch64 PIC jump-table recovery integrated into analysis.
- General register-SSA finite-set indirect branch/call recovery through constants, phis, arithmetic, selections, immutable pointer loads and loader relocations, integrated into function discovery and CFG construction. Partial or unknown evidence never completes a CFG.
- MintIR with explicit flag operations and normalized overlapping register windows.
- AArch64/x86-64 lifting, width-aware x86-32 lifting, ARM/Thumb scalar and selected VFP/integer NEON semantics, RISC-V32/64 integer/compressed and selected A/F/D semantics, and legacy partial Dalvik lifting; unsupported instructions remain explicit intrinsics.
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
- Bounded interprocedural register-ABI width/pointer evidence and verified local direct-call memory effects; imported/user declarations remain authoritative and unknown argument counts/results remain unknown.
- Data Type Manager for primitive/pointer/array/alias/struct/packed/union/enum layouts, supported DWARF/PDB imports, Itanium demangling, evidence-backed Itanium/Microsoft primary/secondary vtable/RTTI inventory and bounded Itanium exception metadata.
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

Flow-preserving patches have a conservative dependency-scoped discovery path: all affected functions (including shared-code owners) are re-decoded and their CFG/index data replaced only when coverage and topology remain valid. Local direct-branch retargeting can also preserve discovery when every owning function retains exactly the same instruction membership, decode modes and callees, with no affected indirect-flow proof context; affected CFGs and block/edge statistics are rebuilt. Other changed control flow, indirect-pointer dependencies, changed code/data boundaries or type models, incomplete affected functions, and unproven cases fall back to full discovery. Name/comment/bookmark/prototype edits preserve discovery and structural references. References are grouped by owning function plus global data/relocations; known code and immutable-memory dependencies invalidate affected groups, while unproven cases rebuild safely. Whole-program reports are invalidated. This is **not general incremental memory SSA/alias analysis**. Undo/redo uses the same update policy. Explicit Reanalyze always runs full discovery. The Log and memory-block report expose `mode=full|restored|incremental|metadata`, updated function/reference-group counts, and fallback/cache diagnostics. Restored indirect targets are re-proved against the effective bytes rather than trusted because they were cached.

All five stages have implemented engine features exposed through the workspace/headless interfaces; this remains a bounded preview rather than a claim of Ghidra parity. Stack analysis tracks exact entry-SP-relative slots, memory versions, escapes, overlaps and aliasing barriers. Only proven non-overlapping initialized leaf slots are promoted to C locals. A conservative general memory sidecar records absolute global, entry-stack and symbolic-base+offset accesses, memory versions and reaching-store evidence; different symbolic pointers may alias, and unknown writes/calls invalidate possibly affected evidence. This is not complete heap-object recovery or memory/alias SSA. It does not silently delete stores or fold unproven loads. AST generation structures reducible nested conditionals, loops and switches while retaining explicit fallbacks where edge effects or exit structure cannot be preserved.

Persisted local names/types use guarded normalized-SSA/stack identities. Exact supported width/type edits affect emitted declarations and uses; incompatible edits are rejected, and structural changes retain stale bindings without applying them to different values. Authoritative prototypes can describe stack parameters, supported floating/aggregate storage, hidden result pointers, register pairs and named variadic parameters. `@windows64`, `@cdecl32`, `@stdcall32` and other explicit target conventions are validated by a storage model; the ABI report distinguishes registers, entry-SP offsets and Windows shadow space. Unsupported ABI layouts fail explicitly. Complex aggregate/FP conversions remain explicit helpers where source reconstruction cannot be proven. Automatic call-graph inference is more limited than this authoritative storage model: automatic Windows prototype inference is disabled, and Windows binaries are never inferred under SysV assumptions.

RISC-V authoritative storage supports integer, single-float and double-float conventions (`riscv32`, `riscv64`, and their `f`/`d` variants). ELF `e_flags` selects the default for user/debug prototypes without an explicit convention; raw mappings retain the integer default. Explicit per-function declarations take precedence. E/Q ABI flags remain unsupported instead of silently selecting integer storage. Signature libraries preserve hard-float conventions and reject a float-ABI mismatch against a bound ELF image.

The RISC-V model flattens supported nested structs and array typedefs into one/two FP fields or one FP plus one integer field, preserving packed/explicit field offsets. Unions and ineligible aggregates use integer storage; bank exhaustion falls back without partially consuming FP registers. Named two-word values can use an odd GPR pair or split across the last GPR and entry-SP storage. Large fallback values use an indirect pointer, including hidden returns. FP storage uses eight-byte register units; single-precision values are NaN-boxed in typed decompiler conversions. RV64 narrow integer conversions preserve the ABI sign extension of `uint32_t`. A one-field aggregate return is reconstructed as an object. The placement rules follow the [RISC-V psABI](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_procedure_calling_convention). Nontrivial C++ object metadata, unsupported vector/E/Q conventions and unnamed variadic argument recovery remain outside this model.

`riscv_calling_conventions` tests bank exhaustion, flattening, spills and typed emission. With `MINT_HOST_CORPUS=ON`, `riscv_abi_compiler_corpus` adds six freestanding Clang ELFs (RV32/RV64 × soft/F/D). Their 60 probe functions are decoded/lifted and interpreted with modeled argument storage, including NaN payload transfers and signed upper register bits; no target binary executes natively. Session tests cover default ABI selection, exact persistent Program reopen and explicit overrides.


Data type examples: `Packet=struct{length:u32;bytes:u8[16];next:Packet*}`, `Wire=packed{tag:u8;value:u32}`, `Value=union{integer:u64;real:f64}`, `Color=enum:i32{Red=-1;Green=2}`. The Data Type Manager imports mutually linked layout libraries and exports GNU C11 declarations with exact padding, alignment, size and field-offset assertions. Exact supported field accesses through authoritative named-struct pointer parameters can use field names; arbitrary aggregate propagation remains incomplete. Serialized user type and signature libraries are each limited to 1 MiB. Little- and big-endian DWARF 2–5 with DWARF32/64 offsets supplies representable types, functions/prototypes, source lines and simple variable locations, including bounded zlib/GNU-compressed sections and explicitly selected external/split objects. Available debuglink CRC/build IDs/split-unit IDs must agree; acknowledging absent identity never bypasses an actual mismatch. No debuglink/DWO filename is followed automatically. Unsupported expressions/supplementary layouts remain partial. User declarations override imported evidence. RTTI/vtable inspection groups evidence-backed classes, primary/secondary address points and direct/virtual bases; dynamic virtual-base offsets remain symbolic. Itanium exception metadata decodes bounded EH-frame/FDE/LSDA call-site/action/type tables and grouped try-region/landing-pad relationships, including stripped EH-frame-header fallbacks; it does not invent source-level try/catch or a complete C++ object model.

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
| ELF32 / ARM, Thumb, x86-32, RISC-V32 | Four-byte pointers, REL/RELA/RELR/Android packed metadata, symbol/mapping roots, listing, CFG, IR with selected FP/SIMD/atomic families described below, SSA and pseudo-C. ARM/Thumb pointer tags preserve decode mode; stack ABI and uncommon instruction semantics remain incomplete. |
| ELF64 / RISC-V64 | Eight-byte pointers and the same native analysis pipeline; base integer/M, common compressed scalar instructions and base AMO word/doubleword operations are modeled. F/D transfers, sign/classification, selected arithmetic/conversions and fused operations are modeled as detailed below; unsupported rounding, vector, LR/SC reservations and privileged semantics retain explicit fallbacks. |
| Raw / all seven native ISA modes | Explicit architecture/base/entry, including entry address zero, over a single executable mapping. Unknown input never silently becomes raw; unsupported architecture IDs are rejected unless a validated decoder is registered. |

Multidex APK analysis is not complete. Unsupported or partially modeled machine instructions are emitted as explicit intrinsics instead of being assigned invented semantics.

## Five-stage development status

| Stage | Implemented foundation | Still open |
| --- | --- | --- |
| 1 — Mobile CodeBrowser | Durable user Program/types/patches/local bindings, full project archives with independent restore, code/data listing, references/search/reopen, synchronized selection and dependency-scoped updates. | Comprehensive runtime references and broader production/device coverage. |
| 2 — Correctness | Metadata roots, bounded SSA indirect recovery, authoritative target ABI storage, register interprocedural evidence, stack analysis, memory dependencies and bounded direct-call write summaries, AST structuring and compiler corpus. | Complete alias/heap-object/type inference, arbitrary runtime indirect targets, every ABI/compiler pattern and production corpus coverage. |
| 3 — Types/C++ | Layouts/C declarations, compressed/external/split DWARF, field names, demangling, Itanium classes and export-backed Microsoft RTTI hierarchies/secondary vftables/PMDs, grouped LSDA relationships, type/signature libraries. | Complete class/exception/source reconstruction, supplementary debug formats and every compiler-specific type record. |
| 4 — Breadth | ELF32/64 seven modes, raw, PE32/32+, thin32/64 and universal Mach-O with explicit slice selection, bounded dyld/PE relocation/import/unwind metadata and architecture registry. | Other big-endian targets, every platform fixup/ABI and exhaustive ISA semantics. |
| 5 — Power users | Expanded bounded scalar assembler/symbol expressions/directives, Lua/headless, exact instruction+CFG correspondence, explicit debugger mapping/PC/thread controls, RSP SVR4/generic modules and DAP stack/modules, native command/lifter/ABI/pass/event SDK v1/v2. | Full FP/SIMD/atomic/system assembly and relaxation, portable RSP stack unwinding, every backend capability, additional language bindings, portable isolation outside Android, hard resource quotas and marketplace infrastructure (trusted loading remains unrestricted). |

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
./build/hosttest/mint_headless input.bin --project raw-be.mint --raw aarch64 0x1000 0x1000 --raw-endian big summary
./build/hosttest/mint_headless universal.dylib --project arm-slice.mint --macho aarch64 functions
./build/hosttest/mint_headless input.so --project program.mint --script commands.mint json
```

Scripts contain one command per line, with `#` comments. Inspection commands include `summary`, `functions`, `listing ADDRESS`, `decompile ADDRESS`, `ir ADDRESS`, `cfg ADDRESS`, `refs ADDRESS`, `provenance ADDRESS`, `search QUERY`, `types`, `types-c`, `prototypes`, `abi ADDRESS`, `locals ADDRESS`, `signatures`, `cxx`, `dwarf`, `source ADDRESS`, and `json`. Explicit editing commands include `type DECLARATION`, `erase-type NAME`, `import-library PATH`, `import-debug PATH` (or `import-debug ack-unverified PATH` for missing identity evidence only), `local ADDRESS ID NAME TYPE`, `local-clear ADDRESS ID`, `edit ADDRESS KIND VALUE`, `asm-preview ADDRESS SOURCE`, `asm ADDRESS SOURCE`, `undo`, `redo`, `reanalyze`, and `export-patched NEW_PATH`. Addresses are decimal or 0x-prefixed hex. Empty edit values remove an override. Persistent writes require `--project`; scripts fail at the first invalid command but do not roll back earlier committed edits.

`diff` remains a byte-level comparison at matching addresses (up to 256 MiB, first 10,000 changes shown). The separate `compare-open`, `compare-project`, `compare-diff`, `compare-confirm`, `compare-save`, `compare-load`, `compare-preview` and `compare-apply` commands provide decoded instruction/function fingerprints, candidate matching and identity-bound persisted confirmations. Only supported control-flow addresses are normalized; scalar constants and memory operands remain significant. Transfer requires explicit confirmed one-to-one function pairs and `--allow-edits`; symbols/comments/bookmarks follow proven matching instructions, preserving an annotation's byte offset inside an instruction, while supported authoritative prototypes require confirmed function entries. Target annotations win, and patches/types/type libraries never transfer. The Android version-tracking menu imports an independent target Program and saves/loads confirmations through the storage picker.

### Batch analysis (0.4 Preview work)

The Python 3 host runner schedules independent read-only analyses without shell command interpolation:

```bash
python3 tools/mint_batch.py input.so "another binary.exe" \
  --tool ./build/hosttest/mint_headless --output batch-results \
  --jobs 2 --timeout 300 --command json
```

A new run requires a new output directory. Each input gets unique output and stderr files, including duplicate paths or filenames. `report.json` has `schema_version: 1` and input-ordered results with absolute input paths, relative artifact paths, `status` (`ok`, `failed`, `timeout`, `cancelled`, `output_limit`), `exit_code` and elapsed seconds. Failed or interrupted output retains a `.partial` suffix. The report is published by rename after the workers finish. One input failure does not stop other analyses; exit status is 0 for complete success, 1 for any failure/timeout, 2 for CLI errors and 130 for cancellation. SIGINT/SIGTERM stop active jobs and cancel queued jobs; POSIX termination also kills each job's process group.

`--jobs` accepts 1–64 (default 1); `--timeout` is a finite positive per-input wall-clock budget (default 300 seconds). Output streams to disk with a per-stream limit of 64 MiB by default, configurable with `--max-output-bytes`; exceeding either limit stops the job and retains partial output. Concurrency and time are bounded; per-process memory depends on the engine and input. Supported commands are `json` (default), `summary` and `functions`. Optional `--raw ARCH BASE ENTRY` or `--macho ARCH` applies to all inputs in that invocation; raw AArch64 additionally accepts `--raw-endian big` (or `little`). The runner creates no persistent Programs and loads no plugins. It is a host pipeline tool; this does not change Android analysis or claim completion of the broader 0.4 roadmap.

For large pipelines, `--input-list inputs.txt` reads a UTF-8 file with one path per line (up to 32 MiB and 100,000 total inputs). Relative entries resolve against the list's directory; empty lines are ignored, spaces are preserved and entries are never shell-expanded. Positional inputs, if present, run before the list entries. At most `--jobs` analyses are queued at once.

To resume, repeat the same input list, tool, command, mapping, timeout and output limit with `--resume` and the existing output directory. Concurrency (`--jobs`) may change. An SQLite checkpoint commits each finished job independently; a missing job row means that job has not completed in the checkpoint. `report.json` describes the last completed invocation and may predate an abruptly terminated resume. Successful jobs are reused only when input bytes, the tool and adjacent `libmint_engine` library, runner code, and output/stderr hashes still match. Changed inputs or engine files, missing or modified artifacts, and failed, timed-out, cancelled or output-limited jobs are run again. Each attempt uses new artifact names, preserving earlier files. Invalid or corrupted checkpoints and changed analysis parameters are rejected without replacing the report. A per-directory advisory lock prevents concurrent runners. This runner requires POSIX file locking. The engine binding covers the executable and adjacent Mint shared engine, not arbitrary dynamic libraries or environment-dependent behavior; external dependencies must remain stable. Inputs must not be modified concurrently with analysis. A hard-killed runner may leave a child process running briefly; attempts never share output files.

Run its regression tests with `python3 app/hosttest/batch_test.py`, or CTest's `headless_batch` test when a Python 3 interpreter is available at configure time. CTest also exercises the runner against the built engine and bundled native fixture.

### Offline team annotation merges

`tools/mint_merge.py` performs a three-way merge of **MINTPR04** Program snapshots. Team members start from a shared baseline, copy it for independent work, then exchange the Program overlays:

```bash
python3 tools/mint_merge.py base.mint ours.mint theirs.mint > preview.json
python3 tools/mint_merge.py base.mint ours.mint theirs.mint --output merged.mint > result.json
./build/hosttest/mint_headless original.so --project merged.mint json
```

The default is a read-only preview. Explicit `--output` creates a new independent Program; existing files and symlinks are never replaced. Input Programs are never changed. Source identity fields must match exactly, and all structural context (patches, code/data decisions, prototypes, local bindings and libraries) must agree across all three Programs. The merge supports names, comments and bookmarks, including deletion. Independent edits merge; identical concurrent edits agree; conflicting edits/deletions retain the baseline/local/incoming values in the JSON report. Independent renames creating duplicate symbols also block publication. Any conflict prevents the entire output from being published.

The JSON report uses `schema_version: 1`, `ready`, `published`, `changes` and `conflicts`; addresses are hex strings preserving all 64 bits. Exit status is 0 for a ready preview/successful publication, 1 for conflicts and 2 for invalid input/I/O. Parsing is bounded to 16 MiB and 100,000 records per Program, validates UTF-8 notes, duplicate keys, user symbols and per-value limits, and rejects unsupported versions/trailing/truncated data. Publication writes/fsyncs a temporary file and atomically links it to a new destination; the filesystem must support hard links. Source identity matching is not authentication, and the tool does not prove that snapshots share an actual historical baseline or validate addresses against the original binary. Reopen the merged Program with its original input in Mint for normal native validation. This is offline annotation collaboration, not an online account/permission service or a merge of structural analysis decisions.

Run `python3 app/hosttest/merge_test.py`; CTest's `annotation_merge` additionally verifies native-generated Programs and cold reopen through `mint_headless`.

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

Type libraries use `MINT_TYPES 1 POINTER_BYTES` followed by one `Name=type` declaration per line. Signature libraries use `MINTSIG 1`, then `abi=aapcs64|sysv64|aapcs32|riscv32|riscv64|riscv32f|riscv64f|riscv32d|riscv64d|cdecl32|windows64|stdcall32`, followed by exact linkage names and supported declarations separated by a tab. Import validates the target ABI/storage and commits atomically. Signature matching uses original symbols/PLT names, not guessed generated labels; explicit user and supported debug prototypes take precedence. Unknown named by-value layouts are rejected; opaque pointer storage does not require a known pointee layout.

Explicit external debug import also accepts bounded MSF7/PDB data for PE. RSDS GUID and age must match when present. The reader imports supported DBI/public/procedure/data symbols and representable TPI primitive/pointer/array/struct/union layouts and procedure prototypes into the same authoritative Program baseline. Type servers, OMAPTO-only inversion, legacy C11 source lines, bitfields and complete virtual/nontrivial C++ layouts are not silently synthesized; unsupported metadata remains partial or is rejected when using it would produce wrong addresses. The selected private debug copy and identity binding survive reopening and project archives. OMAPFROM mappings with original COFF section headers now remap symbols, globals, split/reordered/deleted function ranges and C13 source intervals into the bound PE. Source rows terminate at each mapped fragment, so deleted or inserted code does not inherit adjacent source locations. Split object storage does not adopt an invented contiguous variable type. OMAPTO-only tables cannot safely reconstruct a non-injective forward map and remain explicitly unsupported. GUID/age and source/mapped extent/permission checks remain mandatory; malformed input publishes no partial report. The representation follows [Microsoft OMAP](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap) and the [LLVM DBI stream](https://llvm.org/docs/PDB/DbiStream.html). C13 line/column subsections now resolve filenames from local tables or the PDB `/names` named stream. Named-stream hash bitmaps, checksum-entry boundaries, section/code extents, sorted line offsets, columns and row/text budgets are validated before publication. Contribution end markers prevent source mapping from leaking beyond its code range. Source paths are metadata only; no source contents are opened, and recorded checksums are not claimed to verify local files. The format follows LLVM's [PDB named-stream map](https://llvm.org/docs/PDB/PdbStream.html#named-stream-map) and [CodeView line layout](https://llvm.org/doxygen/DebugLinesSubsection_8h_source.html). Regression checks include a real linked PE/PDB and malformed/truncated C13 and named-stream metadata.

The native C SDK is in `mint/plugin/sdk.h`, with architecture extensions in `mint/plugin/architecture_sdk.h` and real C fixture plugins under `app/hosttest/fixtures`. Use `--plugin ABSOLUTE_PATH --trust-native` only for trusted libraries built for the host/device ABI. Plugins loaded through this trusted path are **unrestricted native code**, can access Mint's private projects and network, and are never a malware isolation boundary. The host API supports bounded queries, exact 64-bit addresses, output and explicitly enabled edits. ABI1 decoder extensions remain supported. ABI2 adds validated bounded semantic fragments and copied register/calling-convention descriptors; malformed fragments fall back to an explicit intrinsic without partial IR publication. ABI2 extension modules can register explicitly invoked analysis passes and read-only analysis/edit/decompilation lifecycle observers with recursion protection. Observer failures are diagnostics, not discarded Program edits. Registered architecture code is retained for its process-wide callback lifetime; derived cache reuse is disabled for external architecture IDs.

Android 10+ additionally offers **Native plugins → Run isolated plugin command**. It starts a unique non-exported `isolatedProcess` service for one invocation, verifies its UID/PID before loading code, and passes only read-only descriptors for the selected original binary and a bounded plugin copy. The worker constructs fresh analysis; current Program annotations, patches, external debug sidecars and private project files are not shared. No plugin code executes in the main application process. The worker copies the library into a sealed anonymous file before descriptor-based system-linker loading, since Android SELinux forbids executable mappings of private app-data files inside isolated services. Plugins must match the device ABI and resolve dependencies available to that isolated process. The mode never falls back to trusted loading.

Only bounded text returns across Binder; sender identity, interface, parcel size and trailing data are checked, and only one response is accepted before posting to the UI. Requests accept 16 MiB libraries, 512 MiB binaries, command IDs up to 160 characters and arguments up to 4096 characters; responses are capped at 24000 UTF-16 characters. The UI supports cancellation and a 60-second deadline. Unbinding normally destroys the single-use worker, whose service cleanup terminates residual native threads. The deadline bounds the caller's wait; this is not a kernel CPU/memory quota or a proof against resource exhaustion by hostile native code. Trusted command/architecture/pass/event loading remains separately available with its existing unrestricted privileges. There is no safe marketplace claim, package signing/repository service, or automatic in-process hook bridging.

Device instrumentation includes private-file/network/edit denial, separate UID/PID, native crash containment and a hanging worker deadline. Build the optional adversarial fixture with `./gradlew :app:connectedDebugAndroidTest -PmintSandboxTestPlugin=true -Pandroid.testInstrumentationRunnerArguments.class=com.ccs.mint.NativePluginSandboxTest`. The fixture is excluded by default. These five tests passed on a Pixel 7a; platform/vendor behavior elsewhere still requires verification. Isolation design follows Android's [isolated service SELinux policy](https://android.googlesource.com/platform/system/sepolicy/+/302919c289575007352d1b60f8766006184e3488/private/isolated_app.te).

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

The Project menu or `debug-connect NUMERIC_IP PORT rsp|dap [ack-plaintext]` connects explicitly to an existing GDB-remote/RSP server or LLDB-DAP TCP adapter. No target process or shell is launched. DAP can attach to an explicitly supplied existing PID; operations include status, registers/memory, breakpoint set/remove, step/continue/interrupt/bounded wait, threads/selection, stack frames and adapter-supported module inventory. RSP supports thread inventory/selection and can read bounded exact target register descriptions, including bounded feature includes. RSP PC reading requires a supported exact `pc`/`rip`/`eip` register layout and an explicit target byte order; Android Session connections use the current image's byte order, while native clients default to little-endian unless configured. Raw unknown layouts are never guessed. RSP can read advertised SVR4 or generic library lists. Portable RSP stack-frame unwinding remains unsupported; use DAP for unwind-backed frames.

RSP `modules` uses the advertised `qXfer:libraries-svr4:read+` capability and a bounded paged UTF-8 XML reader (1 MiB, 1,024 pages, 4,096 modules). It exposes path, linker namespace, link-map address, dynamic-section address and load displacement. The displacement is kept separate from mapped address ranges and never creates an image mapping automatically, following the [GDB SVR4 library-list specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Library-List-Format-for-SVR4-Targets.html). XML support accepts the version 1.0 library-list structure, quoted attributes, predefined XML escapes and an inert external DTD hint; internal DTD subsets, custom/numeric entities and other XML structures are rejected. Unsupported capabilities and invalid/partial replies preserve the caller's previous inventory; malformed protocol replies disconnect the session. Coverage includes paged fragmented transport, namespace identities, exact 64-bit values, malformed metadata and real loopback debugger tests, not broad compatibility with real remote servers.

When SVR4 is absent, an advertised `qXfer:libraries:read+` selects the [generic library-list format](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Library-List-Format.html). Each module retains the literal segment or section base addresses, including zero and exact 64-bit values. These addresses do not establish segment extents, relocations, an ASLR slide or an image mapping. Mixed segment/section entries and empty or malformed libraries fail transactionally. Both formats use the same transfer bounds and stopped-target state checks; unsupported capability never triggers an unadvertised query.

Target register XML is parsed structurally with bounded includes, UTF-8/XML character checks and transactional publication. Register/include spellings inside comments cannot create metadata; internal DTDs, unsupported structures, inexact layouts and hostile include paths are rejected. Discovered and explicitly supplied layouts are validated and ordered by register number before decoding the `g` packet. `debugger_portability` checks fragmented generic-module transfers, both PC byte orders, exact layout ordering and malformed target descriptions.

`map-image RUNTIME_BASE` explicitly maps the current binary's preferred image base and segments; unmapped image operations fail, and Mint never guesses an ASLR slide or derives one from a module name. `memory-image`, `break-image`, `unbreak-image` and `pc-image` use this checked mapping; legacy runtime-address operations remain explicit. The Android workspace follows mapped PC after step/stop when the backend provides an exact PC and exposes threads, stack, modules and mapping controls. Disconnect clears session-only mappings. Backend capabilities vary and unsupported operations fail explicitly. Non-loopback plaintext endpoints require acknowledgement; the connection is not TLS-authenticated. Synthetic and loopback mock coverage is not a claim of comprehensive real-device/server compatibility.

### Big-endian AArch64 ELF64

ELF64 now accepts `ELFDATA2MSB` for AArch64. Named-field ELF decoding covers headers, segments, sections, symbols, dynamic tags, REL/RELA/RELR and pointer arrays. Target data byte order propagates through memory views, relocated and immutable pointer recovery, scalar listing, C++ RTTI/vtable inspection, unwind/LSDA, DWARF fixed-width fields, compressed DWARF, IR/SSA and interpreter loads/stores. Patches preserve the image's byte order. A64 instructions continue to decode as little-endian, following the [Arm memory model](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Armv8-A%20memory%20model%20guide.pdf). Summary and JSON export expose the target data byte order.

AAPCS64 prototypes use the target byte order, including right-justified narrow stack scalars. By-value aggregates now preserve memory chunk ordering in GP registers: partial big-endian chunks occupy the high register bits, while stack composites start at their actual byte-zero origin. Supported nested array, union and packed homogeneous FP aggregates use scalar FP lanes in either byte order; larger aggregates retain indirect/hidden-return storage. Typed pseudo-C uses explicit BE piece/unpack helpers and records content bit offsets instead of treating composites as narrow scalars. Paired LE/BE Clang fixtures verify aggregate arguments/returns, padded stack slots, HFA spills, and indirect copies in the IR interpreter. External debug sidecars must match the image's byte order as well as its architecture/identity evidence. Big-endian ELF32, other ISA targets and big-endian Mach-O remain unsupported. Raw AArch64 imports support an explicit data byte order in the Android import dialog and with `--raw aarch64 BASE ENTRY --raw-endian big` in headless mode. Little-endian remains the default; the order is part of raw Program identity and survives project reopening and archives. A64 instruction bytes remain little-endian.

`big_endian` exercises both endian ELF fixtures, symbol/relocation/dynamic metadata, actual IR loads/stores, patch/reset and scalar ABI storage. DWARF synthetic tests cover versions **2, 3, 4 and 5**, both byte orders, four/eight-byte addresses and DWARF32/64 offset widths, including version-dependent `DW_FORM_ref_addr`, `high_pc`, exact signed legacy enums and transactional truncation failures. Ambiguous legacy enum signedness is left unknown. The DWARF report displays the actual versions, data byte order and offset formats found in decoded units.

Split imports support GNU DWARF4 headerless indexed strings/addresses, `DW_OP_GNU_addr_index`, optimized `.debug_loc.dwo` lists, and DWARF5 indexed tables with the correct implicit bases for DWARF32 and DWARF64. GNU location-list start/length uses a fixed four-byte range length and two-byte expression length, as described by the [LLVM DWARF location-list reader](https://llvm.org/doxygen/DWARFDebugLoc_8cpp_source.html). The initial DWO pass validates CU identities without prematurely evaluating locations requiring the skeleton's address table; full metadata is decoded after binding. Skeleton source rows are retained when absent from the DWO. CRC, build-ID, split-ID and endian mismatches remain fatal even with unverified acknowledgement.

With `MINT_HOST_CORPUS=ON`, `mint_big_endian_corpus_files` generates real big-endian AArch64 DWARF2/3/4/5, DWARF64 (versions 3–5), zlib/GNU-compressed DWARF, multiple/virtual inheritance and exception fixtures. Optimized GNU DWARF4 and standard DWARF5 split/external fixtures cover both offset widths, exact variable location ranges, linked global/function addresses, source mapping, identity rejection and persistent Program restoration. Run `ctest --test-dir build/hosttest --output-on-failure -R '^(dwarf|big_endian.*|external_debug_integration)$'` after building `mint_host_tools`. LLVM cannot emit DWARF2/DWARF64; that combination is covered synthetically. These checks inspect target code as bytes and never execute it. General unsupported supplementary references, DWP packages and unimplemented type/expression layouts remain partial in either byte order.

## Native engine work toward 0.4 Preview

RISC-V decoding enables Capstone's A and F/D extensions in both discovery and lifting. RV32/RV64 base AMOADD/AMOSWAP/AMOXOR/AMOAND/AMOOR/AMOMIN/AMOMAX/AMOMINU/AMOMAXU word forms and RV64 doubleword forms use explicit atomic IR. AMO.W returns sign-extended old memory on RV64, including overlapping source/destination registers; writes to `x0` still perform the memory operation. Standard memory FENCE and FENCE.TSO remain explicit ordering barriers. LR/SC reservations, instruction-cache fences and other privileged semantics remain unsupported intrinsics.

F/D lifting covers FLW/FLD/FSW/FSD, compressed FP register/SP-relative transfers, NaN boxing of single-precision values, FSGNJ/FSGNJN/FSGNJX, FCLASS and integer/FP bit moves. FCLASS uses exact bit classification of all ten categories, including signaling NaNs; raw moves/stores preserve payloads. Add/subtract/multiply/divide/square-root, FMIN/FMAX, ordered comparisons, selected integer/precision conversions and FMADD/FMSUB/FNMSUB/FNMADD have explicit IR semantics. FMA remains one fused operation throughout SSA and interpretation, preserving cancellation residuals. Invalid single-precision boxes become canonical quiet NaNs for computational operations.

RISC-V floating CSRs (`fflags`, `frm`, `fcsr`) support register/immediate read/write/set/clear with masks, zero-source suppression and aliased rd/rs1. Arithmetic invalidates exception evidence instead of fabricating precise flags. Floating interpretation requires the existing explicit nearest-even/default-FP assumption; dynamic rounding consults modeled `frm` and returns unknown for unsupported modes. Float-to-integer lifting currently supports explicit RTZ and dynamic RTZ; other explicit conversion/arithmetic rounding modes remain intrinsic. NaN arithmetic payloads and invalid/out-of-range conversions remain unknown, so this is not complete F/D exception/rounding emulation. Vector and other extension semantics remain incomplete.

ARM/Thumb VFP lifting now covers selected scalar arithmetic, exact bit transfers, FP32/64 and integer conversions, scalar/multiple memory operations, VPUSH/VPOP, VMRS and D/Q bitwise operations. Unfused VMLA/VMLS retain two rounds; fused variants use the fused IR operation. Pure register writes preserve ARM/Thumb IT predicates; unrepresented conditional memory effects stay intrinsic. Aligned S/D writes normalize through vector insert operations that preserve neighboring lanes. Arithmetic invalidates FPSCR exception evidence; VCMP/VCMPE, VMSR and unsupported rounding/fixed/half conversions remain incomplete. Numeric interpretation retains the explicit default-IEEE assumption. Raw ARM/Thumb regressions also verify negative immediate addressing, writeback/alias constraints and predicate fallbacks.

ARM/Thumb NEON adds D/Q integer VADD/VSUB, VMUL/VMLA/VMLS, signed/unsigned min/max and comparisons, compare-to-zero, VTST, VABS/VNEG, supported immediate and register shifts, VDUP from a core register, VREV16/32/64, VEXT and VBSL/VBIT/VBIF. Lane operations preserve modular width, signed shift behavior, overlapping source/destination snapshots and untouched register neighbors through raw IR, normalization and SSA. Pure Thumb IT register writes retain predicates. Saturating, widening/narrowing, polynomial, vector FP and scalar-lane multiply forms still use intrinsic fallbacks. Checked-in ARM/Thumb encodings are reproducible with `app/hosttest/fixtures/generate_arm_neon.py`; `arm_neon_semantics` compares interpreted results with an independent lane reference, including boundary shift counts and VEXT offsets.

General memory evidence now retains bounded all-path sets of reaching stores at CFG joins and loops. A common reaching SSA value is recorded only when every incoming path defines exactly the same bytes with that value. Unknown aliases, partial writes and barriers invalidate the proof; symbolic comparisons account for pointer-width wrap. Layout recovery can follow these proven store/reload aliases and agreeing pointer phis. Facts are tied to the same SSA object and semantic fingerprint; stale/foreign sidecars are recomputed. Limits include 32 reaching stores per range, 4096 active slots per block and bounded graph/state/convergence budgets. This sidecar does not eliminate stores or fold loads, and does not provide full heap lifetime/points-to analysis.

The native decompiler can now build bounded transitive memory-effect summaries from verified local direct-call bodies. Complete read-only bodies preserve reaching-memory evidence; exact write ranges invalidate every possibly aliased fact while retaining proven disjoint ranges. Register-relative writes bind through all-path pre-call physical register evidence, including definitions hidden from ordinary caller SSA uses; different symbolic bases are never assumed disjoint. x86 CALL's implicit return-address store is included and stack-relative effects compose with it. Unproven stack restoration, extra RET cleanup or preserved-register effects reject a summary. Hidden input binding is conservatively blocked when any prior call/intrinsic can reach the site, including through a loop; this also prevents later arithmetic from reusing stale ABI-preserved values. Unknown/external/indirect targets, recursion, tail calls, unsupported side effects and exhausted budgets retain conservative barriers. Summaries own immutable SSA bodies and validate semantic fingerprints; each Session decompilation rebuilds from the current effective image, so patches, undo and Program reopen cannot retain stale purity. Limits include 64 callee bodies, depth 16, 64 write ranges per body, 4096 call sites and 65536 instantiated ranges; individual bodies are capped at 8192 instructions, 32768 values/phis and 512 blocks. This is bounded effect analysis, not complete interprocedural heap, escape or allocation-lifetime recovery. `interprocedural_memory_effects` and `interprocedural_session_memory` cover these contracts and the ordinary decompiler path.

PE32/PE32+ C++ inspection follows exact exported Microsoft vftable identities through complete-object locators, TypeDescriptors and bounded class/base descriptors. It groups verified primary/secondary address points and records single/multiple/virtual inheritance, PMDs, access and ambiguity evidence. PE32 uses absolute references; PE32+ uses validated image-relative references and locator self identity. Virtual PMDs remain symbolic until a runtime object's vbptr/vbtable can establish an offset. No stripped-class scan, complete object size, construction/vtordisp layout, full vftable extent or Microsoft exception-flow reconstruction is claimed. `microsoft_rtti` covers malformed metadata; with `MINT_HOST_CORPUS=ON`, `microsoft_rtti_compiler_corpus` adds real freestanding Clang PE32/PE32+ fixtures.

Local layout recovery now includes store-only output structures and resolves bounded same-width copy/constant add/subtract chains to one object base. Absolute, runtime-indexed, negative and oversized offsets do not establish fields. Pointer propagation uses a def-use worklist across constant offsets/copies and agreeing phi inputs; pointer differences and pointer sums do not become pointers. This remains hypothesis recovery, not whole-program heap/alias proof. When interpretation continues past an opaque call, the same conservative ABI clobber set used by SSA clears register evidence, and potentially aliased memory evidence is invalidated; stop-on-call preserves the inspection point.

AArch64 LSE LDCLR/LDSET/LDEOR/LDSMIN/LDSMAX/LDUMIN/LDUMAX now use the same atomic IR for byte/halfword/word/doubleword forms. x86-32/x86-64 additionally lift memory LOCK ADD/SUB/AND/OR/XOR/INC/DEC/NOT with register/immediate operands where applicable. INC/DEC preserve carry, NOT preserves flags, arithmetic records auxiliary carry and logical operations mark it undefined. Other LOCK families retain intrinsic fallbacks.

Atomic bitwise/min/max operations remain side effects through SSA, memory/stack dependency analysis, interpretation and C emission, even when their return value is unused. Min/max C emission uses a compare-exchange loop. The IR conservatively treats synchronization as a memory-evidence barrier and renders RMW/fence operations with sequentially consistent ordering; it does not reconstruct exact weak-memory behavior or provide a multithreaded emulator. The single-thread interpreter also invalidates known memory after a store/RMW through an unknown address, rather than retaining possibly aliased concrete bytes.

Regression coverage includes RISC-V width/order/register-alias matrices, AArch64 LSE widths, x86 LOCK widths/flags and unknown-address writes. Local branch incremental reanalysis is compared with fresh full analysis for listing, IR, pseudo-C, CFGs, statistics, indexes, references, undo/redo and persistent cache restoration. These additions and the batch runner are implemented portions of the proposed 0.4 work; complete ISA coverage, additional big-endian targets, desktop decompiler/debugger parity, portable/plugin marketplace isolation and hard resource quotas remain open. Team workflows are excluded from the current implementation scope.

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
- External debugger capabilities depend on the connected backend; portable RSP stack unwinding remains unsupported. SVR4 and generic RSP module metadata require advertised capabilities and never imply automatic image mapping. Trusted native loading remains unrestricted; Android isolated commands have the separate restrictions described above.
- The decompiler intentionally retains labels and `goto` for regions it cannot prove safe to structure.
- The interpreter models MintIR; it is not a full OS/process emulator, debugger, or isolation boundary.
- OLLVM recovery, string recovery, binary detectors, and optional SQLite analysis caching need broader real-world corpora. Durable user Programs use the independent overlay, not system SQLite.
- Cancellation is cooperative: a currently executing native stage may finish its bounded operation before stopping.


## Privacy and responsible use

Native binary analysis and Program storage run locally; opening or analyzing a binary does not upload it. The app now requests Internet permission for the explicitly initiated external-debugger TCP connections described above. No debugger connection is opened automatically. Trusted native plugins are not sandboxed and can use the app's permissions, including network and private files. Explicit Android isolated commands instead execute under a separate isolated UID, with only the selected descriptors and arguments shared. This repository does not contain a store privacy-policy/listing artifact; these statements describe the implementation, not a published store policy.

Automatic app backup is disabled, and the backup/device-transfer rules explicitly exclude private imported binaries, Programs and analysis databases. A deliberate export through a selected document provider may write to cloud-backed storage chosen by the user.

Only analyze software and devices you own or are authorized to inspect. Treat all input binaries as untrusted. Mint parses and emulates data but does not make a hostile file safe.

## License

Copyright (c) 2026 Mint contributors.

Mint is released under the [GNU General Public License, version 3](LICENSE) (SPDX: `GPL-3.0-only`).

Mint is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3. Mint is distributed without any warranty; see LICENSE for the full terms.

Vendored Capstone, Lua, Gradle wrapper and other third-party components retain their upstream licenses and copyright notices. The app's third-party notices include Capstone and Lua.
