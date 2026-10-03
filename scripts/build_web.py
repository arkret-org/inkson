"""Build and validate a single-start Dioxus web artifact."""

import argparse
from pathlib import Path
import subprocess

from dev_dioxus import PROJECT_ROOT, cargo_metadata, require_registry_alignment
from web_bootstrap import normalize_web_bootstrap


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--normalize-only", action="store_true")
    args = parser.parse_args()
    require_registry_alignment()
    metadata = cargo_metadata()
    package = next(package for package in metadata["packages"] if Path(package["manifest_path"]).parent == PROJECT_ROOT)
    profile = "release" if args.release else "debug"
    path = Path(metadata["target_directory"]) / "dx" / package["name"] / profile / "web" / "public" / "wasm" / f"{package['name']}.js"
    if not args.normalize_only:
        command = ["dx", "build", "--platform", "web"]
        if args.release:
            command.append("--release")
        result = subprocess.run(command, cwd=PROJECT_ROOT)
        if result.returncode:
            return result.returncode
    repaired = normalize_web_bootstrap(path)
    print(f"[inkson-web] single WASM bootstrap verified; repaired={repaired}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
