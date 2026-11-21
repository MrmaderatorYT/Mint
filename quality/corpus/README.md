# Production ELF64 corpus, first slice

This starting set covers two different programs on AArch64 and x86-64. Each
optimized ELF has a DWARF4 build and a `--strip-all` derivative. The workspace
demo is built from the library Mint ships as its example. The standalone record
counter adds a stripped entry point that reaches a separate local function by
direct call. Both inputs are built from repository source. The tests inspect
them through Mint's headless commands.

| Program | Expected behavior in Mint |
| --- | --- |
| Workspace demo shared library | Discover exported functions, recover multi-block bodies, resolve the call to `memcmp`, read the `Header` type and source locations from DWARF. |
| Record counter executable | Discover the ELF entry and its direct-call target, recover the record-processing loop, read the `Record` type and source locations from DWARF. |

[The corpus specification](manifest.json) records each source and its origin,
license, build flags and expected analysis properties. The generated
`corpus/production/manifest.json` in the host build directory records the exact
Clang, LLD and LLVM strip versions, source SHA-256, binary SHA-256, target triple
and flags for **each of the eight files**. Stripped entries also name their
unstripped parent. Generated binaries and the output manifest stay in the build
directory. Checksums can change with the toolchain or source. Keep the generated
manifest alongside any distributed copy of this corpus. The generator expands
`${NDK_TOOLCHAIN}` to the selected toolchain directory and maps it to the stable
`ndk` prefix in DWARF.

Use the NDK selected by the host compiler corpus. The first slice is exercised
with Android NDK `28.2.13676358`.

```sh
cmake -S app/hosttest -B build/hosttest -DMINT_HOST_CORPUS=ON \
  -DMINT_CORPUS_NDK=/path/to/ndk/28.2.13676358
cmake --build build/hosttest --target mint_headless
ctest --test-dir build/hosttest --output-on-failure -R '^production_elf64_corpus$'
```

The test rebuilds all samples in a separate output directory and compares the
binary digests and manifests. It checks that stripping removes DWARF and the
static symbol table while leaving the executable entry and `.text` bytes
unchanged. It checks Mint's normal headless function discovery, call graph,
pseudo-C and source mapping. For stripped inputs it queries the same function
addresses as the debug build. Each stripped image is analyzed in a separate
process using its own metadata.
