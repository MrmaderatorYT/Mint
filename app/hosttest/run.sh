#!/usr/bin/env bash
# Host verification loop for the analysis engine.
#
# Three layers, because each catches what the others cannot:
#   engine  — runs the loaders and disassembler under ASan/UBSan, and validates
#             recovered function extents against the symbol table, which is the
#             only oracle available at scale.
#   jni     — drives the shipped JNI layer from a real JVM. The engine probe never
#             crosses JNI, and the marshalling is where the sharp edges are.
#   fuzz    — mutates a real library's headers and code to confirm that malformed
#             input fails an analysis rather than the process.
#
# Usage:
#   app/hosttest/run.sh                 # all layers, against a bundled NDK library
#   app/hosttest/run.sh engine [file]
#   app/hosttest/run.sh feature [file]
#   app/hosttest/run.sh jni    [file]
#   app/hosttest/run.sh platform [file]
#   app/hosttest/run.sh archive        # generated DWARF/PDB + real archive/JNI
#   app/hosttest/run.sh fuzz   [iterations]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

NDK_SYSROOT="$HOME/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/sysroot"
DEFAULT_LIB="$NDK_SYSROOT/usr/lib/aarch64-linux-android/libc++_shared.so"

JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 17)}"
export JAVA_HOME

run_engine() {
    local lib="${1:-$DEFAULT_LIB}"
    echo "=== engine (ASan + UBSan) : $(basename "$lib") ==="
    cmake -S app/hosttest -B build/hosttest -DCMAKE_BUILD_TYPE=Debug >/dev/null
    cmake --build build/hosttest --target mint_probe -j8 >/dev/null
    ./build/hosttest/mint_probe "$lib"
}

run_feature() {
    local lib="${1:-$DEFAULT_LIB}"
    echo "=== feature contracts + real-library pass : $(basename "$lib") ==="
    cmake -S app/hosttest -B build/hosttest -DCMAKE_BUILD_TYPE=Debug >/dev/null
    cmake --build build/hosttest --target mint_feature_test -j8 >/dev/null
    ./build/hosttest/mint_feature_test "$lib"
}

run_jni() {
    local lib="${1:-$DEFAULT_LIB}"
    echo "=== jni (real JVM) : $(basename "$lib") ==="
    cmake -S app/hosttest -B build/hostjni -DCMAKE_BUILD_TYPE=Debug \
          -DMINT_HOST_SANITIZE=OFF >/dev/null
    cmake --build build/hostjni --target mintcore -j8 >/dev/null

    local out=build/hostjni/classes
    mkdir -p "$out"
    "$JAVA_HOME/bin/javac" -nowarn -d "$out" \
        app/hosttest/jni/androidx/annotation/*.java \
        app/src/main/java/com/ccs/mint/core/*.java \
        app/hosttest/jni/JniProbe.java app/hosttest/jni/PlatformJniProbe.java
    "$JAVA_HOME/bin/java" -Djava.library.path=build/hostjni -cp "$out" JniProbe "$lib"
    "$JAVA_HOME/bin/java" -Djava.library.path=build/hostjni -cp "$out" PlatformJniProbe
}

run_platform() {
    local lib="${1:-$DEFAULT_LIB}"
    cmake -S app/hosttest -B build/hosttest -DCMAKE_BUILD_TYPE=Debug >/dev/null
    cmake --build build/hosttest --target mint_host_tools -j4 >/dev/null
    ctest --test-dir build/hosttest --output-on-failure
    ./build/hosttest/mint_cxx_metadata_test --inventory "$lib"
}

run_corpus() {
    cmake -S app/hosttest -B build/hosttest -DCMAKE_BUILD_TYPE=Debug -DMINT_HOST_CORPUS=ON >/dev/null
    cmake --build build/hosttest --target mint_corpus_test -j4 >/dev/null
    ctest --test-dir build/hosttest --output-on-failure -R '^native_compiler_corpus$'
}

run_archive() {
    local archive_build=build/hostarchive
    local archive_classes="$archive_build/classes"
    local archive_fixtures="$archive_build/corpus/debug-loader"
    echo "=== archive (real JVM + generated external DWARF/PDB fixtures) ==="
    cmake -S app/hosttest -B "$archive_build" -DCMAKE_BUILD_TYPE=Debug \
          -DMINT_HOST_CORPUS=ON -DMINT_HOST_SANITIZE=OFF >/dev/null
    cmake --build "$archive_build" --target mint_debug_loader_corpus_files mintcore -j4 >/dev/null
    mkdir -p "$archive_classes"
    "$JAVA_HOME/bin/javac" -nowarn -d "$archive_classes" \
        app/hosttest/jni/androidx/annotation/*.java \
        app/src/main/java/com/ccs/mint/core/*.java \
        app/src/main/java/com/ccs/mint/ui/RawImportConfig.java \
        app/src/main/java/com/ccs/mint/ui/ProjectArchive.java \
        app/hosttest/jni/ArchiveJniProbe.java
    "$JAVA_HOME/bin/java" -Djava.library.path="$archive_build" -cp "$archive_classes" \
        ArchiveJniProbe "$archive_fixtures/stripped.so" "$archive_fixtures/external.debug" \
        "$archive_fixtures/windows-types.exe" "$archive_fixtures/windows-types.pdb"
}

run_fuzz() {
    local iterations="${1:-300}"
    echo "=== fuzz ($iterations mutations, ASan + UBSan) ==="
    cmake -S app/hosttest -B build/hosttest -DCMAKE_BUILD_TYPE=Debug >/dev/null
    cmake --build build/hosttest --target mint_probe -j8 >/dev/null
    python3 app/hosttest/fuzz.py "$DEFAULT_LIB" "$iterations"
}

case "${1:-all}" in
    engine) run_engine "${2:-}" ;;
    feature) run_feature "${2:-}" ;;
    jni)    run_jni "${2:-}" ;;
    platform) run_platform "${2:-}" ;;
    corpus) run_corpus ;;
    archive) run_archive ;;
    fuzz)   run_fuzz "${2:-}" ;;
    all)
        run_platform
        run_engine
        echo
        run_feature
        echo
        run_jni
        echo
        run_fuzz 200
        ;;
    *)
        echo "usage: $0 [all|engine|feature|platform|corpus|archive|jni|fuzz] [arg]" >&2
        exit 2
        ;;
esac
