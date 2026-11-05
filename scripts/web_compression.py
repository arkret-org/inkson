"""Precompress immutable web resources; keep HTML available for runtime metadata."""

import gzip
from pathlib import Path

COMPRESSIBLE_SUFFIXES = {".wasm", ".js", ".css", ".json", ".svg"}


def precompress_assets(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in COMPRESSIBLE_SUFFIXES:
            continue
        data = path.read_bytes()
        compressed = gzip.compress(data, compresslevel=9, mtime=0)
        if len(compressed) < len(data):
            path.with_name(path.name + ".gz").write_bytes(compressed)
