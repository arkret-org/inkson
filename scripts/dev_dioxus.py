#!/usr/bin/env python3
"""Run Dioxus while bridging changes from local path dependencies.

Dioxus 0.7 watches local path dependencies, but its hot-reload classifier skips
Rust files outside the Cargo workspace instead of scheduling a full rebuild.
Inkson intentionally consumes sibling Arkret SDK crates, so `dx serve` alone can
keep serving a bundle linked against an older generated SDK snapshot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time


PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent
SPEC_REGISTRY = (
    WORKSPACE_ROOT
    / "arkret-spec"
    / "spec"
    / "v1"
    / "artifacts"
    / "registry"
    / "event-kind-registry.json"
)
SDK_EVENT_KINDS = (
    WORKSPACE_ROOT
    / "arkret-rust-sdk"
    / "crates"
    / "wire"
    / "src"
    / "generated"
    / "event_kinds.rs"
)
REBUILD_STAMP = PROJECT_ROOT / "src" / "dev_dependency_rebuild.stamp"
REBUILD_STAMP_CONTENT = "inkson-dioxus-local-dependency-rebuild-bridge\n"
WATCHED_SUFFIXES = {".json", ".lock", ".rs", ".toml", ".yaml", ".yml"}
IGNORED_DIRECTORIES = {".git", "node_modules", "target"}
REGISTRY_DIGEST_PATTERN = re.compile(
    r'pub const EVENT_KIND_REGISTRY_SHA256: &str\s*=\s*"([0-9a-f]{64})";'
)


def registry_identities() -> tuple[str, str]:
    expected = hashlib.sha256(SPEC_REGISTRY.read_bytes()).hexdigest()
    generated = SDK_EVENT_KINDS.read_text(encoding="utf-8")
    match = REGISTRY_DIGEST_PATTERN.search(generated)
    if match is None:
        raise RuntimeError(
            f"cannot read EVENT_KIND_REGISTRY_SHA256 from {SDK_EVENT_KINDS}"
        )
    return expected, match.group(1)


def require_registry_alignment() -> None:
    expected, generated = registry_identities()
    if expected == generated:
        return
    raise RuntimeError(
        "Arkret SDK generated sources are stale: "
        f"spec={expected}, sdk={generated}. Run "
        "`powershell -File ../arkret-rust-sdk/tools/sync-spec.ps1 "
        "-ArtifactsDir ../arkret-spec/spec/v1/artifacts` before starting Dioxus."
    )


def git_root(path: Path) -> Path:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    )
    return Path(result.stdout.strip()).resolve()


def local_dependency_roots() -> list[Path]:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    roots: set[Path] = set()
    for package in metadata["packages"]:
        if package["source"] is not None:
            continue
        manifest_dir = Path(package["manifest_path"]).resolve().parent
        if manifest_dir == PROJECT_ROOT or PROJECT_ROOT in manifest_dir.parents:
            continue
        roots.add(git_root(manifest_dir))
    return sorted(roots)


def watched_files(roots: list[Path]) -> dict[Path, tuple[int, int]]:
    snapshot: dict[Path, tuple[int, int]] = {}
    for root in roots:
        for directory, child_directories, files in os.walk(root):
            child_directories[:] = [
                name for name in child_directories if name not in IGNORED_DIRECTORIES
            ]
            directory_path = Path(directory)
            for name in files:
                path = directory_path / name
                if path.suffix.lower() not in WATCHED_SUFFIXES:
                    continue
                try:
                    stat = path.stat()
                except FileNotFoundError:
                    continue
                snapshot[path] = (stat.st_mtime_ns, stat.st_size)
    try:
        stat = SPEC_REGISTRY.stat()
        snapshot[SPEC_REGISTRY] = (stat.st_mtime_ns, stat.st_size)
    except FileNotFoundError:
        pass
    return snapshot


def dependency_watch_loop(roots: list[Path], stop: threading.Event) -> None:
    snapshot = watched_files(roots)
    pending_since: float | None = None
    while not stop.wait(0.5):
        current = watched_files(roots)
        if current != snapshot:
            snapshot = current
            pending_since = time.monotonic()
            continue
        if pending_since is None or time.monotonic() - pending_since < 2.0:
            continue
        pending_since = None
        try:
            require_registry_alignment()
        except Exception as error:
            print(f"[inkson-dev] rebuild withheld: {error}", file=sys.stderr, flush=True)
            continue
        REBUILD_STAMP.write_text(REBUILD_STAMP_CONTENT, encoding="utf-8")
        print(
            "[inkson-dev] local dependency changed; requested a full Dioxus rebuild",
            flush=True,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", default="web")
    parser.add_argument("--port", type=int)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate registry identity and print watched dependency roots",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        require_registry_alignment()
        roots = local_dependency_roots()
    except Exception as error:
        print(f"[inkson-dev] {error}", file=sys.stderr)
        return 1

    if args.check:
        expected, _ = registry_identities()
        print(f"registry={expected}")
        for root in roots:
            print(f"watching={root}")
        return 0

    command = ["dx", "serve", "--platform", args.platform]
    if args.port is not None:
        command.extend(["--port", str(args.port)])

    stop = threading.Event()
    watcher = threading.Thread(
        target=dependency_watch_loop,
        args=(roots, stop),
        name="inkson-local-dependency-watch",
        daemon=True,
    )
    watcher.start()
    print(
        "[inkson-dev] registry aligned; watching sibling path dependencies",
        flush=True,
    )
    process = subprocess.Popen(command, cwd=PROJECT_ROOT)
    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        return process.wait()
    finally:
        stop.set()
        watcher.join(timeout=3)
        if process.poll() is None:
            process.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
