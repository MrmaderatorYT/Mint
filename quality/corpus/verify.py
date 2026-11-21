#!/usr/bin/env python3
"""Verify new corpus builds against source-level facts through mint_headless."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
from tempfile import TemporaryDirectory

from generate import ROOT, add_build_arguments, generate, sha256


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def inspect_elf(binary, sample):
    # Inspect these just-built, little-endian ELF64 fixtures independently of Mint.
    data = binary.read_bytes()
    require(data[:6] == b"\x7fELF\x02\x01", "not a little-endian ELF64 image")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    require(elf_type == sample["elf_type"] and machine == sample["elf_machine"],
            "unexpected ELF type or machine")
    entry = struct.unpack_from("<Q", data, 24)[0]
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    stride, count, names_index = struct.unpack_from("<HHH", data, 58)
    require(stride >= 64 and names_index < count and section_offset + stride * count <= len(data),
            "invalid section table")

    def section(index):
        at = section_offset + stride * index
        name, kind = struct.unpack_from("<II", data, at)
        offset, size = struct.unpack_from("<QQ", data, at + 24)
        return name, kind, data[offset:offset + size]

    _, _, names = section(names_index)
    sections = {}
    for index in range(count):
        name, kind, payload = section(index)
        end = names.index(b"\0", name)
        if kind != 8:  # SHT_NOBITS has no file payload.
            sections[names[name:end].decode("ascii")] = payload
    debug = sample["variant"] == "debug"
    require((".debug_info" in sections) == debug and (".symtab" in sections) == debug,
            "variant does not have the required DWARF and static-symbol presence")
    require(sections.get(".text"), "missing executable code")
    return entry, sections[".text"]


def check_sample(tool, binary, sample, debug_addresses):
    limits = sample["limits"]
    require(binary.stat().st_size <= limits["max_file_bytes"], "corpus sample exceeds its size limit")
    require(sha256(binary) == sample["sha256"], "binary hash does not match manifest")
    require(sha256(ROOT / sample["source"]) == sample["source_sha256"], "source hash does not match manifest")
    entry, code = inspect_elf(binary, sample)

    def headless(*args):
        result = subprocess.run([tool, binary, *args], text=True, capture_output=True,
                                timeout=limits["analysis_command_seconds"])
        require(result.returncode == 0, f"{' '.join(args)} failed: {result.stderr.strip()}")
        return result.stdout

    result = json.loads(headless("json"))
    require((result["format"], result["arch"], result["data_byte_order"]) ==
            ("ELF64", sample["mint_arch"], "little"), "Mint reported wrong format or architecture")
    functions = result["functions"]
    by_index = {fn["index"]: fn for fn in functions}
    by_entry = {fn["entry"]: fn for fn in functions}
    by_name = {fn["displayName"].removesuffix("@plt"): fn for fn in functions}
    expect = sample["expect"]
    debug = sample["variant"] == "debug"
    expected_names = set(expect["functions"]) | {name for edge in expect["calls"] for name in edge}
    if debug:
        for name in sorted(expected_names):
            require(name in by_name, f"missing function {name}")
            debug_addresses[name] = by_name[name]["entry"]
    for name in sorted(expected_names):
        require(debug_addresses[name] in by_entry, f"missing discovered address for {name}")

    for name in expect["functions"]:
        function = by_entry[debug_addresses[name]]
        require(function["instructions"] > 0 and not function["incomplete"], f"incomplete body for {name}")
    if "entry" in expect:
        require(debug_addresses[expect["entry"]] == entry, "ELF entry is not the expected function")
    for caller, callee in expect["calls"]:
        function = by_entry[debug_addresses[caller]]
        targets = {by_index[index]["entry"] for index in function["calls"]}
        require(debug_addresses[callee] in targets, f"missing call edge {caller} -> {callee}")

    for name in expect["multi_block"]:
        function = by_entry[debug_addresses[name]]
        require(function["blocks"] >= 2, f"expected a branch in {name}")
        address = hex(function["entry"])
        pseudo = headless("decompile", address)
        require(re.search(r"\breturn\b", pseudo) and "{" in pseudo, f"missing pseudo-C body for {name}")
        location = headless("source", address).strip()
        if debug:
            require(Path(sample["source"]).name + ":" in location, f"lost DWARF source location for {name}")
        else:
            require(not location, f"stripped image unexpectedly has a source location for {name}")
    for name in expect.get("loops", []):
        cfg = headless("cfg", hex(debug_addresses[name]))
        rows = [list(map(int, row.split())) for row in cfg.splitlines()]
        edges = {block: set(targets) for block, _, _, *targets in rows}
        require(all(targets <= edges.keys() for targets in edges.values()), f"dangling CFG edge in {name}")
        # Repeatedly remove exits. Only a graph with a cycle can retain nodes
        # when no exits remain, regardless of the compiler's block ordering.
        while exits := {block for block, targets in edges.items() if not targets}:
            edges = {block: targets - exits for block, targets in edges.items() if block not in exits}
        require(edges, f"missing CFG cycle in {name}")
    if debug:
        dwarf = headless("dwarf")
        layout = expect["debug_type"]
        require(f"\ntype {layout['name']} size={layout['size']} " in dwarf,
                f"missing or incorrect DWARF layout for {layout['name']}")
    return entry, code


def verify(directory, tool, clang, linker, strip):
    corpus = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    with TemporaryDirectory(prefix="mint-corpus-rebuild-") as temporary:
        rebuilt = Path(temporary)
        generate(rebuilt, clang, linker, strip)
        require((rebuilt / "manifest.json").read_bytes() == (directory / "manifest.json").read_bytes(),
                "rebuilding into a separate directory changed the corpus manifest")
        debug_addresses = {}
        debug_layouts = {}
        for sample in corpus["samples"]:
            name = sample["file"]
            pair = sample["architecture"], sample["program"]
            addresses = debug_addresses.setdefault(pair, {})
            try:
                require(sha256(rebuilt / name) == sample["sha256"], "rebuild checksum mismatch")
                entry, code = check_sample(tool, directory / name, sample, addresses)
                if sample["variant"] == "debug":
                    debug_layouts[pair] = entry, code
                else:
                    require(debug_layouts[pair] == (entry, code), "strip changed executable code or entry")
            except (RuntimeError, ValueError, KeyError) as error:
                raise RuntimeError(f"{name}: {error}") from error
            print(f"Verified {name} ({sample['sha256']})")
    print(f"Verified provenance, reproducibility and analysis for {len(corpus['samples'])} ELF64 inputs.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=lambda path: Path(path).resolve())
    parser.add_argument("--headless", required=True, type=lambda path: Path(path).resolve())
    add_build_arguments(parser)
    args = parser.parse_args()
    verify(args.directory, args.headless, args.clang, args.linker, args.strip)
