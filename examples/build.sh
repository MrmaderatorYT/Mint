#!/bin/sh
# Rebuilds the bundled example library. Checked in as a binary because the app
# ships it, and reproducible from here because a binary nobody can regenerate is
# a liability rather than a demo.
set -e
NDK="$HOME/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin"
OUT="$(dirname "$0")/../app/src/main/assets/libmintdemo.so"
"$NDK/aarch64-linux-android26-clang" -O2 -fPIC -shared -fvisibility=default \
    -Wl,-z,max-page-size=16384 -Wl,--build-id=none \
    -o "$OUT" "$(dirname "$0")/demo.c"
echo "wrote $OUT"
