#!/usr/bin/env python3
"""Build optimized sibling-tail-call ELF64 with DWARF4: CLANG OUTPUT [O2|O3]."""
import pathlib
import subprocess
import sys

clang, output = sys.argv[1:3]
optimization = sys.argv[3] if len(sys.argv) > 3 else "O2"
if optimization not in ("O2", "O3"):
    raise SystemExit("optimization must be O2 or O3")
subprocess.run([
    clang, "--target=x86_64-linux-gnu", "-fuse-ld=lld", "-" + optimization,
    "-fPIC", "-g", "-gdwarf-4", "-fno-stack-protector", "-fno-unwind-tables",
    "-fno-asynchronous-unwind-tables", "-nostdlib", "-shared",
    "-Wl,--build-id=none", "-Wl,-e,pic_tail_switch",
    str(pathlib.Path(__file__).with_name("x86_tail_switch.c")), "-o", output,
], check=True)
