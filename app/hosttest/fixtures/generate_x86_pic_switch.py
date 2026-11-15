#!/usr/bin/env python3
"""Generate a real freestanding ELF64 PIC switch: CLANG OUTPUT_ELF [O2|O3]."""
import pathlib
import subprocess
import sys

clang, output = sys.argv[1:3]
optimization = sys.argv[3] if len(sys.argv) > 3 else "O2"
if optimization not in ("O2", "O3"):
    raise SystemExit("optimization must be O2 or O3")
source = pathlib.Path(__file__).with_name("x86_pic_switch.c")
subprocess.run([
    clang, "--target=x86_64-linux-gnu", "-fuse-ld=lld", "-" + optimization, "-fPIC",
    # Keep case CALL/return control flow inside the dispatching function. The
    # narrow switch proof does not yet validate tails across symbol boundaries.
    "-fno-optimize-sibling-calls",
    "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
    "-nostdlib", "-shared", "-Wl,--build-id=none", "-Wl,-e,pic_switch",
    str(source), "-o", output,
], check=True)
