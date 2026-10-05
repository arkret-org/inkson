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
import shutil
import subprocess
import sys
import threading
import time

from web_bootstrap import normalize_web_bootstrap


PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent
SPEC_REGISTRY = (
    WORKSPACE_ROOT
    / "arkret-spec"
    / "spec"
    / "v1"
    / "artifacts"
    / "registry"
    / "contract-registry.json"
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


def ensure_registry_alignment() -> None:
    """Repair stale SDK projections before starting or rebuilding Dioxus."""
    # A missing canonical input cannot be repaired by the SDK generator.
    SPEC_REGISTRY.read_bytes()
    try:
        require_registry_alignment()
        return
    except (FileNotFoundError, RuntimeError):
        pass

    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        raise RuntimeError("PowerShell is required to synchronize Arkret SDK sources")
    print("[inkson-dev] SDK registry missing or stale; synchronizing from the local spec", flush=True)
    output = run_captured(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(WORKSPACE_ROOT / "arkret-rust-sdk" / "tools" / "sync-spec.ps1"),
            "-ArtifactsDir",
            str(SPEC_REGISTRY.parent.parent),
        ],
        cwd=PROJECT_ROOT,
    )
    if output.strip():
        print(output.rstrip(), flush=True)
    require_registry_alignment()
    print("[inkson-dev] Arkret SDK registry synchronized and verified", flush=True)


def run_captured(command: list[str], cwd: Path | None = None) -> str:
    """Run a command, reporting its own error text when it fails.

    `check=True` alongside `capture_output=True` raises a CalledProcessError
    whose message is only the command line and the exit status, so a failing
    `cargo metadata` reached the terminal as a bare "returned non-zero exit
    status 101" with the actual cargo diagnostic discarded.
    """
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        rendered = " ".join(command)
        raise RuntimeError(
            f"`{rendered}` failed with exit status {result.returncode}"
            + (f":\n{detail}" if detail else "")
        )
    return result.stdout


def cargo_metadata() -> dict:
    return json.loads(
        run_captured(["cargo", "metadata", "--format-version", "1"], cwd=PROJECT_ROOT)
    )


def git_root(path: Path) -> Path:
    return Path(
        run_captured(["git", "-C", str(path), "rev-parse", "--show-toplevel"]).strip()
    ).resolve()


def local_dependency_roots(metadata: dict) -> list[Path]:
    roots: set[Path] = set()
    for package in metadata["packages"]:
        if package["source"] is not None:
            continue
        manifest_dir = Path(package["manifest_path"]).resolve().parent
        if manifest_dir == PROJECT_ROOT or PROJECT_ROOT in manifest_dir.parents:
            continue
        roots.add(git_root(manifest_dir))
    return sorted(roots)


def build_directories(metadata: dict) -> set[Path]:
    """Directories cargo writes artifacts into, excluded from the watch walk.

    `IGNORED_DIRECTORIES` only knows the name `target`, which was enough while
    every repository built into its own `target/`. The workspace-level
    `../.cargo/config.toml` now points `build.target-dir` at one shared tree,
    so ask cargo where it writes rather than assuming the name. Walking a
    hundred-gigabyte artifact tree twice a second would stall the rebuild
    bridge without ever producing a useful change event.
    """
    directories: set[Path] = set()
    for key in ("target_directory", "build_directory"):
        value = metadata.get(key)
        if value:
            directories.add(Path(value))
    return directories


def watched_files(
    roots: list[Path], build_dirs: set[Path]
) -> dict[Path, tuple[int, int]]:
    snapshot: dict[Path, tuple[int, int]] = {}
    for root in roots:
        for directory, child_directories, files in os.walk(root):
            directory_path = Path(directory)
            child_directories[:] = [
                name
                for name in child_directories
                if name not in IGNORED_DIRECTORIES
                and directory_path / name not in build_dirs
            ]
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


def dependency_watch_loop(
    roots: list[Path], build_dirs: set[Path], stop: threading.Event
) -> None:
    snapshot = watched_files(roots, build_dirs)
    pending_since: float | None = None
    while not stop.wait(0.5):
        current = watched_files(roots, build_dirs)
        if current != snapshot:
            snapshot = current
            pending_since = time.monotonic()
            continue
        if pending_since is None or time.monotonic() - pending_since < 2.0:
            continue
        pending_since = None
        try:
            ensure_registry_alignment()
        except Exception as error:
            print(f"[inkson-dev] rebuild withheld: {error}", file=sys.stderr, flush=True)
            continue
        # Include generated writes in this rebuild instead of scheduling another.
        snapshot = watched_files(roots, build_dirs)
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


def web_bootstrap_watch_loop(path: Path, stop: threading.Event) -> None:
    previous: tuple[int, int] | None = None
    checked: tuple[int, int] | None = None
    while not stop.wait(0.5):
        try:
            stat = path.stat()
            current = (stat.st_mtime_ns, stat.st_size)
            if current != previous:
                previous = current
                continue
            if current == checked:
                continue
            checked = current
            if normalize_web_bootstrap(path):
                print("[inkson-dev] removed duplicate generated WASM bootstrap", flush=True)
        except FileNotFoundError:
            previous = None
        except Exception as error:
            print(f"[inkson-dev] web bootstrap validation failed: {error}", file=sys.stderr, flush=True)


def main() -> int:
    args = parse_args()
    try:
        if args.check:
            require_registry_alignment()
        else:
            ensure_registry_alignment()
        metadata = cargo_metadata()
        roots = local_dependency_roots(metadata)
        build_dirs = build_directories(metadata)
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
        args=(roots, build_dirs, stop),
        name="inkson-local-dependency-watch",
        daemon=True,
    )
    watcher.start()
    bootstrap_watcher = None
    if args.platform == "web":
        package = next(package for package in metadata["packages"] if Path(package["manifest_path"]).parent == PROJECT_ROOT)
        bootstrap_path = Path(metadata["target_directory"]) / "dx" / package["name"] / "debug" / "web" / "public" / "wasm" / f"{package['name']}.js"
        bootstrap_watcher = threading.Thread(
            target=web_bootstrap_watch_loop,
            args=(bootstrap_path, stop),
            name="inkson-web-bootstrap-watch",
            daemon=True,
        )
        bootstrap_watcher.start()
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
        if bootstrap_watcher is not None:
            bootstrap_watcher.join(timeout=3)
        if process.poll() is None:
            process.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
