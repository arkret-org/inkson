"""Registry freshness and local dependency discovery shared by client build tools."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

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
WATCHED_SUFFIXES = {".json", ".lock", ".rs", ".toml", ".yaml", ".yml", ".css", ".js", ".html", ".svg", ".woff", ".woff2", ".png", ".jpg", ".jpeg", ".py", ".list", ".ico"}
IGNORED_DIRECTORIES = {".git", "node_modules", "target", "artifacts", "release-assets", ".local", "dist"}
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
        "-ArtifactsDir ../arkret-spec/spec/v1/artifacts` before starting the client."
    )


def ensure_registry_alignment() -> None:
    """Repair stale SDK projections before starting or rebuilding the client."""
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
        run_captured(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=PROJECT_ROOT)
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
