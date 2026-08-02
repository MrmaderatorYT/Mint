# Mint

<p align="center">
  <img src="app/src/main/res/drawable/logo.png" alt="Mint logo" width="256">
</p>

Mint is an offline binary-analysis and decompilation workspace for Android. It opens real ELF, DEX, and APK files, performs native analysis in C++ through JNI, and exposes disassembly, MintIR, pseudo-C, a control-flow graph, functions, and analysis logs in a touch-oriented UI.

The project is an independent, Ghidra-inspired implementation. It does not embed Ghidra, Sleigh, LLVM, or Unicorn, and it is no longer a mock-data simulator. Mint is currently a `0.1 preview`: the core pipeline is functional, but format, architecture, type-recovery, and control-structure coverage are intentionally narrower than a desktop reverse-engineering suite.

## What works today

- Defensive ELF64 loading with sections, symbols, program headers, PLT entries, initializers, standard relocations, Android packed relocations, and RELR.
- Capstone-backed AArch64 and x86-64 disassembly.
- Recursive-descent function and CFG discovery, with an AArch64 linear-sweep fallback.
- Bounded AArch64 PIC jump-table recovery integrated into analysis.
- MintIR with explicit flag operations and normalized overlapping register windows.
- AArch64, x86-64, and partial Dalvik lifting.
- IR verification plus dominance, dominance-frontier, SSA, phi insertion, def-use, liveness, simplification, constant propagation, and basic type/structure recovery.
- Pseudo-C generation with expressions, `if`, `while`, `do-while`, and label/`goto` fallbacks.
- A MintIR interpreter for controlled emulation; no native target code is executed.
- APK/DEX parsing through the same Android file picker used for ELF files.
- Heuristic OLLVM, crypto, anti-tamper, packer, and string-recovery components.
- SQLite-backed native program storage and query components.
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

## Supported inputs

| Input | Current support |
| --- | --- |
| ELF64 / AArch64 | Primary native target; loader, CFG, IR, SSA, pseudo-C, and emulation are available. |
| ELF64 / x86-64 | Loader and analysis pipeline are available; instruction modeling is less complete than AArch64. |
| Standalone DEX | Header/class/method parsing, Dalvik listing, partial lifting, verification, and pseudo-C. |
| APK | ZIP extraction and analysis of `classes.dex`; application resources and full package semantics are not reconstructed. |
| PE, Mach-O, ELF32, ARM32 | Not supported. |

Multidex APK analysis is not complete. Unsupported or partially modeled machine instructions are emitted as explicit intrinsics instead of being assigned invented semantics.

## Analysis pipeline

```text
Android Storage Access Framework
        |
        v
Mapped input -> ELF / ZIP / DEX loader -> function and CFG analysis
        -> disassembly -> MintIR lifting -> normalization and verification
        -> SSA and data-flow passes -> pseudo-C / CFG / IR interpreter
        -> JNI -> Android workspace
```

The native engine is C++17. Capstone is vendored under `app/third_party/capstone`; Android zlib and SQLite facilities are used where applicable.

## Validation snapshot

The following numbers are a reproducible development snapshot from the Android NDK r28 `libc++_shared.so` binaries. They are coverage indicators, not promises that every input is modeled correctly.

| Metric | AArch64 | x86-64 |
| --- | ---: | ---: |
| Discovered functions | 2,884 | 2,858 |
| Machine instructions | 130,843 | 134,116 |
| Unmodeled instructions | 134 (0.10%) | 1,292 (0.96%) |
| IR verifier failures | 0 | 0 |

Additional checks from the same corpus:

- The full x86-64 SSA sweep completed with zero failures in raw IR, normalization, SSA construction, verification, simplification, def-use, liveness, and type passes.
- All 2,884 AArch64 functions produced pseudo-C, and the combined generated translation unit passed `clang -std=c11 -fsyntax-only`.
- AArch64 jump-table recovery found six bounded PIC switch tables and represented 170 table-derived CFG edges. Compared with the earlier descent baseline, it exposed 3,202 additional instructions, 644 blocks, and 1,133 CFG edges.
- A real Mint debug APK crossed the APK -> DEX -> Dalvik IR -> verifier -> pseudo-C pipeline through JNI (6,392 classes and 64,849 methods in that build).
- A 200-mutation parser/analysis fuzz run completed with zero crashes and zero timeouts.

These results do not imply complete structuring: non-canonical and irreducible regions still fall back to labels and `goto` statements.

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

Run instrumentation tests with a connected device or running emulator:

```bash
./gradlew connectedDebugAndroidTest
```

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
app/hosttest/run.sh fuzz 200
```

The convenience script currently assumes macOS, JDK 17 from `/usr/libexec/java_home`, and the default `$HOME/Library/Android/sdk` layout. On other hosts, configure and run the CMake targets directly:

```bash
cmake -S app/hosttest -B build/hosttest -DCMAKE_BUILD_TYPE=Debug
cmake --build build/hosttest --parallel

./build/hosttest/mint_probe /path/to/lib.so
./build/hosttest/mint_ssa_test /path/to/lib.so
./build/hosttest/mint_feature_test /path/to/lib.so
```

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
├── mint/loader/              ELF, ZIP, and DEX loading
├── mint/disasm/              Capstone integration
├── mint/analysis/            Functions, CFGs, jump tables, and data flow
├── mint/ir/ and mint/ssa/    MintIR, normalization, verification, and SSA
├── mint/decompile/            Pseudo-C and control-structure recovery
├── mint/interp/               MintIR interpreter
├── mint/obfuscation/          OLLVM and string-recovery experiments
├── mint/detectors/            Heuristic binary detectors
└── mint/db/                   SQLite persistence and queries

app/hosttest/                  Native, JNI, feature, performance, and fuzz probes
playstore/                     Store listing and privacy-policy drafts
ROADMAP.md                     Detailed implementation roadmap and target scope
```

## Known limitations

- Mint is a preview and should not be treated as a correctness-equivalent replacement for Ghidra, IDA, Binary Ninja, or a production malware sandbox.
- x86-64 lifting still has more intrinsic fallbacks than AArch64. SIMD, system, and uncommon instruction families are incomplete.
- Dalvik lifting and APK support are partial, and multidex/resource/manifest analysis is not complete.
- Jump-table recovery currently targets bounded AArch64 PIC patterns rather than every compiler and architecture pattern.
- High-level types, calling conventions, variable names, exception handling, and cross-function structure recovery remain heuristic.
- The decompiler intentionally retains labels and `goto` for regions it cannot prove safe to structure.
- The interpreter models MintIR; it is not a full OS/process emulator, debugger, or isolation boundary.
- OLLVM recovery, string recovery, binary detectors, and SQLite project persistence are experimental and need broader real-world corpora.
- Cancellation is cooperative: a currently executing native stage may finish its bounded operation before stopping.

See [ROADMAP.md](ROADMAP.md) and [ROADMAP_DETAILED.md](ROADMAP_DETAILED.md) for implementation details and remaining work. Roadmap task descriptions define intended scope and may lag behind the exact implementation status; code and tests are authoritative.

## Privacy and responsible use

Mint requests no Internet permission and performs analysis on-device. See the [privacy policy](playstore/privacy-policy.md) and [store listing draft](playstore/store-listing.md).

Only analyze software and devices you own or are authorized to inspect. Treat all input binaries as untrusted. Mint parses and emulates data but does not make a hostile file safe.

## License

Mint is released under the [MIT License](LICENSE). Vendored Capstone code retains its upstream license notices.
