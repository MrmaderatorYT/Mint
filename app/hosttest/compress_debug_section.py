"""Generate the legacy GNU ZLIB section payload for the compiler corpus."""
from pathlib import Path
import sys
import zlib

with Path(sys.argv[1]).open("rb") as stream:
    data = stream.read(128 * 1024 * 1024 + 1)
if len(data) > 128 * 1024 * 1024:
    raise ValueError("debug section exceeds corpus budget")
Path(sys.argv[2]).write_bytes(b"ZLIB" + len(data).to_bytes(8, "big") + zlib.compress(data))
