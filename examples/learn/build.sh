#!/bin/sh
set -eu

# Pass the bin directory of Android NDK 28.2.13676358 if it is installed elsewhere.
ndk_bin=${1:-"${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin"}
sources=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output="$sources/../../app/src/main/assets/learn"
mkdir -p "$output"

build_lesson() {
    "$ndk_bin/aarch64-linux-android26-clang" -nostdlib -shared -fuse-ld=lld \
        -Wl,-z,max-page-size=16384 -Wl,--build-id=none \
        "-Wl,-e,$2" "-Wl,-soname,$1.elf" \
        -o "$output/$1.elf" "$sources/$1.S"
}

build_lesson arithmetic scale_score
build_lesson branch choose_level
build_lesson memory update_pair
build_lesson loop repeat_add
build_lesson calls boost_score
build_lesson strings label_address
