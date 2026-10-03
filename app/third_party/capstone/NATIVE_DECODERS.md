# Native decoder provenance

Mint's ARM/Thumb and RISC-V decoder sources and generated tables were copied
unmodified from the official Capstone `6.0.0-Alpha10` source archive, matching the
existing vendored core, public headers, AArch64 and x86 sources.

- Source: https://github.com/capstone-engine/capstone/releases/tag/6.0.0-Alpha10
- Archive: https://codeload.github.com/capstone-engine/capstone/tar.gz/refs/tags/6.0.0-Alpha10
- Archive SHA-256: `af09851f76656d97f12e44f7224bd1066ea441da6efa91dd9c8d53837e8e15d5`
- Copied directories: `arch/ARM`, `arch/RISCV`; existing module headers retained.
- Licenses: [BSD-3-Clause](LICENSES/LICENSE_BSD_3_CLAUSE.txt),
  [Apache-2.0 with LLVM exception](LICENSES/LICENSE_LLVM.TXT), and the
  [upstream license overview](LICENSES/LICENSE.TXT).

Builds use only these checked-in files. No dependency download occurs during
configuration or compilation.
