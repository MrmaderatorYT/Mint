"""Execute emitted C for repository-owned ELF64 fixtures against a scalar oracle."""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile


FIXTURES = {
    "aarch64": (183, ("a8 06 80 52", "08 00 08 4a", "00 1d 00 11", "c0 03 5f d6"), 2, "00 2d 00 11"),
    "x86_64": (62, ("83 f7 35", "8d 47 07", "c3"), 1, "8d 47 0b"),
}
INPUTS = (0, 1, 53, 0x12345678, 0x7FFFFFFF, 0x80000000, 0xFFFFFFC0, 0xFFFFFFCA, 0xFFFFFFFF)


def run(stage, *command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{stage}: exit {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def execute_report(compiler, directory, arch, stage, report, bonus):
    if not report.startswith("/* Decompilation status: complete */\n"):
        raise RuntimeError(f"{stage}: expected complete Pseudo-C\n{report}")
    if arch == "x86_64" and re.search(r"\bin_rsp\b", report):
        # The lifted x86 RET reads the return address from entry SP.
        # Supply that fixture ABI input as valid memory. Leave the emitted
        # control flow, arithmetic, and memory accesses unchanged.
        declaration = "    uintptr_t in_rsp;\n"
        if report.count(declaration) != 1:
            raise RuntimeError(f"{stage}: expected one modeled entry stack register\n{report}")
        report = report.replace(declaration,
                                "    uint64_t fixture_return_slot = 0;\n"
                                "    uintptr_t in_rsp = (uintptr_t)&fixture_return_slot;\n")
    input_list = ", ".join(f"UINT32_C({value})" for value in INPUTS)
    source = directory / f"{stage}.c"
    source.write_text("#include <stdint.h>\n#include <inttypes.h>\n#include <stdio.h>\n"
                      + report
                      + f"""
int main(void) {{
    const uint32_t inputs[] = {{{input_list}}};
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
        printf("%" PRIu32 "\\n", mint_score(inputs[i]));
    return 0;
}}
""", encoding="utf-8")
    executable = directory / stage
    run(f"{stage}: compile Pseudo-C", compiler, "-std=c11", "-O1", "-fsanitize=undefined",
        "-fno-sanitize-recover=undefined", str(source), "-o", str(executable))
    lines = run(f"{stage}: execute Pseudo-C", str(executable)).splitlines()
    if len(lines) != len(INPUTS):
        raise RuntimeError(f"{stage}: expected {len(INPUTS)} outputs, got {len(lines)}")
    for value, line in zip(INPUTS, lines):
        expected = ((value ^ 53) + bonus) & 0xFFFFFFFF
        if line != str(expected):
            raise RuntimeError(f"{stage}: mint_score(0x{value:08x}) expected {expected}, got {line!r}\n{report}")


def verify(tool, compiler, arch, fixture, directory):
    machine, instructions, patch_index, patch = FIXTURES[arch]
    original = fixture.read_bytes()
    if original[:6] != b"\x7fELF\x02\x01" or int.from_bytes(original[18:20], "little") != machine:
        raise RuntimeError(f"{arch}: fixture is not the expected little-endian ELF64")

    def mint(stage, *arguments):
        return run(f"{arch}/{stage}", tool, str(fixture), *arguments)

    functions = mint("find score function", "functions")
    matches = re.findall(r"^(0x[0-9a-f]+)\tmint_score\t", functions, re.MULTILINE)
    if len(matches) != 1:
        raise RuntimeError(f"{arch}: expected one mint_score function\n{functions}")
    entry = matches[0]
    listing = mint("verify patch preimage", "listing", entry).splitlines()
    address = int(entry, 16)
    patch_address = None
    for index, expected in enumerate(instructions):
        if index >= len(listing) or not listing[index].startswith(f"0x{address:x}\t{expected}   "):
            raise RuntimeError(f"{arch}: compiler fixture changed at 0x{address:x}; expected {expected}\n"
                               + "\n".join(listing[:len(instructions)]))
        if index == patch_index:
            patch_address = f"0x{address:x}"
        address += len(bytes.fromhex(expected))

    project = directory / "score.mint"
    mint("set authoritative ABI prototype", "--project", str(project), "edit", entry,
         "prototype", "uint32_t(uint32_t input)")
    before = mint("decompile before patch", "--project", str(project), "decompile", entry)
    execute_report(compiler, directory, arch, "before", before, 7)

    mint("apply score patch", "--project", str(project), "edit", patch_address, "patch", patch)
    after = mint("decompile after patch and reopen", "--project", str(project), "decompile", entry)
    execute_report(compiler, directory, arch, "after", after, 11)

    exported = directory / "export.elf"
    mint("export edited fixture", "--project", str(project), "export-patched", str(exported))
    preimage = bytes.fromhex(" ".join(instructions))
    offset = original.find(preimage)
    if offset < 0 or original.find(preimage, offset + 1) >= 0:
        raise RuntimeError(f"{arch}: expected a unique file-backed instruction sequence")
    offset += sum(len(bytes.fromhex(code)) for code in instructions[:patch_index])
    replacement = bytes.fromhex(patch)
    expected = original[:offset] + replacement + original[offset + len(replacement):]
    if exported.read_bytes() != expected or fixture.read_bytes() != original:
        raise RuntimeError(f"{arch}: export differs from the expected one-instruction patch or changed the input")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool")
    parser.add_argument("compiler")
    parser.add_argument("arch", choices=FIXTURES)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix=f"mint-elf64-{args.arch}-") as directory:
        try:
            verify(args.tool, args.compiler, args.arch, args.fixture, Path(directory))
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            parser.exit(1, f"{args.arch}: {error}\n")
    print(f"{args.arch}: emitted C matched the independent oracle on {len(INPUTS)} inputs before and after patch")


if __name__ == "__main__":
    main()
