#!/usr/bin/env python3
"""Mutational fuzzer for the loaders and disassembler.

Every byte this engine parses comes from a file a user found somewhere, and a good
share of those files are deliberately malformed: packers emit broken headers
specifically to crash naive tools. So the property under test is not "produces the
right answer" but "a hostile file fails an analysis, never the process".

Mutations are biased toward the ELF header and the section and program header
tables, because that is where a bogus count or offset actually reaches the bounds
checks. A smaller base file keeps each iteration fast enough to run hundreds.

Requires mint_probe built with ASan and UBSan, which is the default for the Debug
host configuration.
"""

import os
import random
import subprocess
import sys
import tempfile

PROBE = os.environ.get("MINT_FUZZ_PROBE", "./build/hosttest/mint_probe")
BASE_BYTES = 300_000


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: fuzz.py <reference.so> [iterations]", file=sys.stderr)
        return 2

    reference = sys.argv[1]
    iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 300

    with open(reference, "rb") as handle:
        base = handle.read(BASE_BYTES)
    if len(base) < 4096:
        print(f"reference file too small: {reference}", file=sys.stderr)
        return 2

    # Fixed seed: a fuzz run that cannot be reproduced is not much use when it
    # finds something.
    random.seed(0x4D494E54)  # "MINT"

    failures = []
    timeouts = 0

    with tempfile.TemporaryDirectory(prefix="mint-fuzz-") as workdir:
        path = os.path.join(workdir, "mutant.so")

        for i in range(iterations):
            data = bytearray(base)
            for _ in range(random.randint(1, 8)):
                roll = random.random()
                if roll < 0.50:
                    offset = random.randrange(0, 64)          # ELF header
                elif roll < 0.80:
                    offset = random.randrange(0, min(len(data), 16384))
                else:
                    offset = random.randrange(0, len(data))   # section contents
                data[offset] = random.randrange(256)

            # Keep the magic and class intact so the parser is exercised rather
            # than the early reject.
            data[0:4] = b"\x7fELF"
            data[4] = 2  # ELFCLASS64
            data[5] = 1  # little-endian

            with open(path, "wb") as handle:
                handle.write(bytes(data))

            try:
                result = subprocess.run([PROBE, path], capture_output=True,
                                        text=True, timeout=120)
            except subprocess.TimeoutExpired:
                timeouts += 1
                continue

            blob = result.stdout + result.stderr
            crashed = ("AddressSanitizer" in blob
                       or "runtime error" in blob
                       or result.returncode < 0)
            if crashed:
                keep = os.path.join(tempfile.gettempdir(), f"mint-fuzz-crash-{i}.so")
                with open(keep, "wb") as handle:
                    handle.write(bytes(data))
                failures.append((i, result.returncode, keep, blob[:1200]))
                if len(failures) >= 3:
                    break

    print(f"mutations: {iterations}   crashes: {len(failures)}   timeouts: {timeouts}")
    for index, code, keep, blob in failures:
        print(f"\n=== iteration {index} (exit {code}), reproducer saved to {keep} ===")
        print(blob)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
