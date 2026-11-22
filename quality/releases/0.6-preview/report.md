# PROD-001 baseline · Mint 0.6 Preview

Captured on 2026-11-22. Source `d607c10a886c37fc94cc9bf64aeddaec77a6a920`, tag `0.6-preview`, Android application `com.ccs.mint`, version code 6. The analyzed source matched the tag. Production planning files added during this audit do not change the measured build. Engine ID `4c8ca044118b0035ad058508eb28c2b3141207b220edb65b8245faf6b2edf614`.

PROD-001 is the inventory and baseline package. Its output includes failed checks and open qualification items. Use the [support matrix](../../../docs/production/support-matrix.json) to distinguish supported combinations, the [acceptance journeys](../../../docs/production/acceptance-journeys.md) to reproduce the intended workflows and the [P0/P1 register](../../../docs/production/known-issues.md) to prioritize work. The 1.0 acceptance gates remain open.

## Environment and fresh runs

- Host macOS 15.8.3 (24H241), ARM64, Apple Clang 17.0.0 (`clang-1700.0.13.5`), CMake 4.4.4, Python 3.15.2, OpenJDK 17.0.20.1. Native compiler fixtures used Android NDK r28c `28.2.13676358` / Clang 19.0.1.
- Android build uses Gradle 8.13, AGP 8.11.1, SDK 36, NDK r28c, CMake 3.22.1. APK minimum API 26, target API 36. Host ABIs `arm64-v8a` and `x86_64` are distinct from the engine’s input ISAs.

| Check | Result on this revision |
| --- | --- |
| Corpus-enabled CTest, Debug + ASan/UBSan | **77/77**, 23.40 s. Production ELF corpus, native compiler matrix, copy-elided x86-64 switch and tail calls, DWARF/PDB, big-endian, Program recovery and native debugger loopback. Stock NDK corpus generation failed on the GNU-compressed big-endian fixture. Regenerated that fixture with host LLVM 23.1.3 and ran its tests as part of the 77. See BLK-04. |
| Android JVM unit tests | **54/54**, 0 failures, 0 skips. Reran without reusing cached test results. |
| JVM JNI | `JniProbe` passed. The separate `PlatformJniProbe` failed on permitted localhost due to the stale RSP mock. See BLK-03. |
| Archive JNI | **97 checks passed** with generated external DWARF/PDB fixtures. |
| Real AArch64 NDK library | `mint_feature_test` passed on NDK r28c `libc++_shared.so`. Standalone `mint_probe` stopped on a sanitizer finding in its report tally. See BLK-02. |
| ELF input robustness smoke | 200 deterministic mutations of the NDK library, 0 crashes, 0 timeouts. Broader parser and stateful campaigns remain open. |
| Headless/batch negative address | Reproduced a textual `error` with process exit 0 and batch `status: ok`. See BLK-01. |
| Switch smoke with and without debug info | Six recovered cases in both O2 tail-switch fixtures. DWARF version kept separate typed tail exits. The stripped variant recovered the handler instructions within the dispatcher. See J02 for the qualification boundary. |
| Signed release build and artifacts | Local rebuild succeeded. APK/AAB signature checks, APK 16 KiB ZIP alignment, bundle validation on the prepared AAB, version/manifest and both native payloads verified. Provenance mismatch identified in the original preview artifacts, see below. |
| Current device instrumentation, UI and migration | **Blocked in this run**. No Android device or emulator attached. Historical Pixel 7a checks from 0.6 covered an isolated ARM64 instrumentation project surviving process death, Pseudo-C line navigation and Back restoring the scroll position. The main app also launched after a 0.3 → 0.6 in-place update using the installed debug signing certificate. That update did not verify every old project or export. No claim of optimized release UI acceptance on both Android host ABIs. |

### Rerun

```sh
cmake -S app/hosttest -B build/host-corpus -DCMAKE_BUILD_TYPE=Debug \
  -DMINT_HOST_CORPUS=ON -DMINT_HOST_SANITIZE=ON \
  -DMINT_CORPUS_NDK="$ANDROID_NDK_HOME"
cmake --build build/host-corpus --target mint_host_tools -j 5
ctest --test-dir build/host-corpus --output-on-failure -j 5
app/hosttest/run.sh jni
app/hosttest/run.sh archive
./gradlew --offline --no-build-cache :app:cleanTestDebugUnitTest :app:testDebugUnitTest \
  -PmintCompactDebug=true
```

Set `ANDROID_NDK_HOME` to a local r28c installation. Permit localhost for the debugger and JNI mock server. On a stock NDK build affected by BLK-04, use the following generated-file workaround before retrying the build. It preserves the tracked fixture recipe and does not modify source.

```sh
objcopy=/path/to/llvm-23.1.3/bin/llvm-objcopy
corpus=build/host-corpus/corpus
"$objcopy" --dump-section ".debug_info=$corpus/aarch64-be-debug-info.bin" \
  "$corpus/aarch64-be-dwarf5.so" "$corpus/aarch64-be-gnu.so.dump"
python3 app/hosttest/compress_debug_section.py \
  "$corpus/aarch64-be-debug-info.bin" "$corpus/aarch64-be-debug-info.zlib"
"$objcopy" --update-section ".debug_info=$corpus/aarch64-be-debug-info.zlib" \
  "$corpus/aarch64-be-dwarf5.so" "$corpus/aarch64-be-gnu.so.intermediate"
"$objcopy" --rename-section .debug_info=.zdebug_info \
  "$corpus/aarch64-be-gnu.so.intermediate" "$corpus/aarch64-be-gnu.so"
```

Real-binary input was the NDK sysroot `usr/lib/aarch64-linux-android/libc++_shared.so` (9,236,352 bytes; SHA-256 `ab4e6c71b96b851de45a8a9bd86369e7dbc2130a44b3b4520564be94847910f2`). Run `UBSAN_OPTIONS=halt_on_error=1 build/host-corpus/mint_probe "$ndk_rt"` and `build/host-corpus/mint_feature_test "$ndk_rt"`, where `ndk_rt` is that file. Run the robustness smoke with `MINT_FUZZ_PROBE=./build/host-corpus/mint_probe python3 app/hosttest/fuzz.py "$ndk_rt" 200`. Host logs for this run are in the local ignored `build/prod-001-host/`.

## First host profile

Five independent processes per row with the corpus-enabled sanitized executable and `/usr/bin/time -lp`. Each run includes process startup, input discovery and rendering; files were already available on the host filesystem. The peak RSS includes the sanitizer runtime. These are tiny-fixture baselines. Device cold import, warm reopen, UI latency, PSS, cancellation and large binaries still belong to PROD-006.

| Debug ELF64 fixture | Command | All wall samples (s) | CPU user + system range (s) | Highest peak RSS (MiB) |
| --- | --- | --- | --- | ---: |
| AArch64 workspace demo, 9,432 bytes | `summary` | 0.08, 0.08, 0.14, 0.15, 0.09 | 0.07–0.12 | 43.2 |
| AArch64 workspace demo | `decompile 0x4894` | 0.12, 0.10, 0.09, 0.10, 0.10 | 0.08–0.09 | 49.2 |
| x86-64 workspace demo, 9,312 bytes | `summary` | 0.11, 0.09, 0.12, 0.16, 0.12 | 0.09–0.12 | 51.5 |
| x86-64 workspace demo | `decompile 0x4930` | 0.12, 0.12, 0.11, 0.11, 0.12 | 0.10–0.11 | 56.8 |

Generate the inputs and verify their SHA-256 using the [corpus manifest procedure](../../corpus/README.md). Execute `/usr/bin/time -lp build/host-corpus/mint_headless "$binary" summary`, or replace `summary` with the listed `decompile` command to compare against this baseline. Record the environment and all samples for small runs.

## Artifact verification

Both original artifacts have one signing certificate with SHA-256 `a895ce08fbecfc6357292ca087829a93a41377aa09bbeb0f5f161b110754aa9c`. The published output was a GitHub prerelease APK. The AAB was prepared for Play distribution.

| Artifact | SHA-256 | Embedded revision |
| --- | --- | --- |
| Original GitHub APK | `91c265829cf2e7690cc3b401c51d57a456a888213d60e6c37f2a4632a0387970` | `ac14fbd` |
| Originally prepared AAB | `b0742090e2d1fe91f1f61838dcbca3872210482522a3531e7e9c2230cc36c13a` | `ac14fbd` |
| Locally rebuilt baseline APK | `81cea1a1d18865d334f12ce887c1910450ab91b17af9184b1a0d24296db927b9` | `d607c10` |
| Locally rebuilt baseline AAB | `fd6215819ae52d4c965240bd2dba58ee6c464896958459becc1632f8b210a975` | `d607c10` |

Local command: `./gradlew --offline --no-build-cache :app:extractReleaseVersionControlInfo --rerun :app:assembleRelease :app:bundleRelease` with the existing release signing configuration. The rebuilt archives are retained locally under ignored `build/prod-001-release/`. The original preview artifacts were retained. For each original/rebuilt pair, ZIP paths and bytes matched for every functional payload entry after excluding `META-INF/`, `BUNDLE-METADATA/` and `base/root/META-INF/`. This includes the bytecode, manifests, resources, fixture assets and both native libraries. Follow BLK-05 to prevent release metadata created before the final source commit.
