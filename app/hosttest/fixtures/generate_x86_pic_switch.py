#!/usr/bin/env python3
"""Generate a freestanding ELF64 PIC switch: CLANG ELF [O2|O3] [copy-elided]."""
import pathlib
import subprocess
import sys

clang, output = sys.argv[1:3]
optimization = sys.argv[3] if len(sys.argv) > 3 else "O2"
if optimization not in ("O2", "O3"):
    raise SystemExit("optimization must be O2 or O3")
source = pathlib.Path(__file__).with_name("x86_pic_switch.c")
variant = sys.argv[4:]
if variant not in ([], ["copy-elided"]):
    raise SystemExit("the optional variant must be copy-elided")
defines = ["-DMINT_COPY_ELIDED"] if variant else []
subprocess.run([
    clang, "--target=x86_64-linux-gnu", "-fuse-ld=lld", "-" + optimization, "-fPIC", *defines,
    # Exercise ordinary case calls separately from the tail-call fixtures.
    "-fno-optimize-sibling-calls",
    "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
    "-nostdlib", "-shared", "-Wl,--build-id=none", "-Wl,-e,pic_switch",
    str(source), "-o", output,
], check=True)
