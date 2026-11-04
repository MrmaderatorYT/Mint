#!/usr/bin/env python3
"""Preview a three-way annotation merge or write a new independent Program."""
import argparse
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile

LIMIT = 16 * 1024 * 1024
KINDS = {"name", "comment", "bookmark", "data", "prototype", "type-library",
         "signature-library", "function", "patch", "source", "locals"}
SHARED = {"name", "comment", "bookmark"}
LARGE = {"type-library", "signature-library", "locals"}
KEYWORDS = set("auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Alignas _Alignof _Atomic _Bool _Complex _Generic _Noreturn _Static_assert _Thread_local".split())


def validate(records):
    if len(records) > 100000:
        raise ValueError("Program exceeds 100000 annotations")
    names = set()
    for (address, kind), value in records.items():
        if kind not in KINDS or not value or "\0" in value:
            raise ValueError("invalid annotation kind/value")
        if len(value.encode("utf-8")) > (1024 * 1024 if kind in LARGE else 4096):
            raise ValueError("annotation exceeds its value budget")
        if kind in {"source", "type-library", "signature-library"} and address != 0:
            raise ValueError("project annotation must have address zero")
        if kind == "name":
            if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", value) or value in KEYWORDS or value in names:
                raise ValueError("invalid or duplicate user symbol")
            names.add(value)
    if not records.get((0, "source")):
        raise ValueError("Program must have a source identity")


def read_program(path):
    with path.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT or len(data) < 12 or data[:8] != b"MINTPR04":
        raise ValueError("expected a MINTPR04 Program of at most 16 MiB")
    count, = struct.unpack_from("<I", data, 8)
    if count > 100000:
        raise ValueError("excessive Program record count")
    records, offset = {}, 12
    for _ in range(count):
        if len(data) - offset < 16:
            raise ValueError("truncated Program record header")
        address, kind_size, value_size = struct.unpack_from("<QII", data, offset)
        offset += 16
        if kind_size > 32 or value_size > 1024 * 1024 or kind_size + value_size > len(data) - offset:
            raise ValueError("invalid/truncated Program record extent")
        kind = data[offset:offset + kind_size].decode("ascii")
        offset += kind_size
        value = data[offset:offset + value_size].decode("utf-8")
        offset += value_size
        if (address, kind) in records:
            raise ValueError("duplicate Program key")
        records[address, kind] = value
    if offset != len(data):
        raise ValueError("trailing Program data")
    validate(records)
    return records


def encode_program(records):
    validate(records)
    chunks, size = [b"MINTPR04", struct.pack("<I", len(records))], 12
    for (address, kind), value in sorted(records.items()):
        key, text = kind.encode("ascii"), value.encode("utf-8")
        size += 16 + len(key) + len(text)
        if size > LIMIT:
            raise ValueError("merged Program exceeds 16 MiB")
        chunks.extend((struct.pack("<QII", address, len(key), len(text)), key, text))
    return b"".join(chunks)


def merge(base, ours, theirs):
    identity = base[0, "source"]
    if ours[0, "source"] != identity or theirs[0, "source"] != identity:
        raise ValueError("Programs belong to different binaries or import configurations")
    result, changes, conflicts = dict(ours), [], []
    for key in sorted(base.keys() | ours.keys() | theirs.keys()):
        before, local, incoming = base.get(key), ours.get(key), theirs.get(key)
        row = dict(address=f"0x{key[0]:x}", kind=key[1])
        if key[1] not in SHARED:
            # Even a local patch/type difference changes the context of notes.
            # Structural decisions must agree before annotations can be merged.
            if before != local or before != incoming:
                conflicts.append(dict(row, reason="structural context differs"))
            continue
        if incoming == before or incoming == local:
            continue
        if local != before:
            conflicts.append(dict(row, reason="concurrent annotation changes",
                                  base=before, ours=local, theirs=incoming))
            continue
        changes.append(dict(row, before=local, after=incoming))
        if incoming is None:
            result.pop(key, None)
        else:
            result[key] = incoming
    names = {}
    for (address, kind), value in sorted(result.items()):
        if kind == "name":
            if value in names:
                conflicts.append(dict(address=f"0x{address:x}", kind=kind,
                                      reason="merged symbols collide", name=value,
                                      other_address=f"0x{names[value]:x}"))
            names[value] = address
    if not conflicts:
        # Detect collisions created by independent renames at different addresses.
        encode_program(result)
    report = dict(schema_version=1, ready=not conflicts, source_identity=identity,
                  changes=changes, conflicts=conflicts)
    return result, report


def publish_new(path, data):
    # link publishes the fully written file atomically and fails if any existing
    # file/symlink wins the race. rename/replace would silently overwrite it.
    descriptor, temporary = tempfile.mkstemp(prefix=".mint-merge-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path, help="shared baseline Program")
    parser.add_argument("ours", type=Path, help="local branch Program")
    parser.add_argument("theirs", type=Path, help="incoming branch Program")
    parser.add_argument("--output", type=Path, help="publish to this new file; omitted for preview")
    args = parser.parse_args(argv)
    try:
        merged, report = merge(*(read_program(path) for path in (args.base, args.ours, args.theirs)))
        if report["ready"] and args.output:
            publish_new(args.output, encode_program(merged))
            report["output"] = str(args.output)
        report["published"] = bool(report["ready"] and args.output)
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return 0 if report["ready"] else 1
    except (OSError, ValueError, UnicodeError, struct.error) as error:
        print(f"mint_merge: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
