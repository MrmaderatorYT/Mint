#!/usr/bin/env python3
"""Build the ELF64 corpus and record the inputs/stages behind each checksum."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


CORPUS = Path(__file__).resolve().parent
ROOT = CORPUS.parents[1]


def run(argv):
    return subprocess.run(argv, cwd=ROOT, text=True, check=True, timeout=60,
                          stdout=subprocess.PIPE).stdout


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(output, clang, linker, strip):
    config = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    output.mkdir(parents=True, exist_ok=True)
    toolchain = {
        "clang": run([clang, "--version"]).splitlines()[0],
        "lld": run([linker, "--version"]).splitlines()[0],
        "strip": run([strip, "--version"]).splitlines(),
    }
    samples = []
    for arch, target in config["targets"].items():
        for program in config["programs"]:
            stem = f"{program['id']}-{arch}"
            debug = output / f"{stem}-debug.elf"
            stripped = output / f"{stem}-stripped.elf"
            flags = [f"--target={target['triple']}", *config["compiler_flags"], *program["flags"]]
            expanded_flags = [flag.replace("${NDK_TOOLCHAIN}", str(clang.parent.parent)) for flag in flags]
            run([clang, f"--ld-path={linker}", *expanded_flags, program["source"], "-o", debug])
            run([strip, *config["strip_flags"], debug, "-o", stripped])
            common = {
                "program": program["id"], "origin": program["origin"],
                "license": program["license"], "source": program["source"],
                "source_sha256": sha256(ROOT / program["source"]),
                "architecture": arch, "target": target["triple"],
                "abi": target["abi"], "format": "ELF64 little-endian", "limits": config["limits"],
                "elf_machine": target["elf_machine"], "elf_type": program["elf_type"],
                "mint_arch": target["mint_arch"], "toolchain": toolchain,
                "compiler_flags": flags, "expect": program["expect"],
            }
            for variant, binary in (("debug", debug), ("stripped", stripped)):
                samples.append({
                    **common, "variant": variant, "file": binary.name,
                    "sha256": sha256(binary),
                    "strip_flags": config["strip_flags"] if variant == "stripped" else [],
                    "stripped_from": debug.name if variant == "stripped" else None,
                })
    generated = output / "manifest.json"
    temporary = generated.with_suffix(".tmp")
    temporary.write_text(json.dumps({"schema": config["schema"], "samples": samples}, indent=2)
                         + "\n", encoding="utf-8")
    temporary.replace(generated)


def add_build_arguments(parser):
    for tool in ("clang", "linker", "strip"):
        # LLD selects its driver from argv[0], so keep the ld.lld symlink name.
        parser.add_argument(f"--{tool}", required=True, type=lambda path: Path(path).absolute())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=lambda path: Path(path).resolve())
    add_build_arguments(parser)
    args = parser.parse_args()
    generate(args.output, args.clang, args.linker, args.strip)
