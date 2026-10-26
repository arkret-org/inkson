#!/usr/bin/env python3
"""Build the native Glory/Blitz application and stage its local asset directory."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from build_web import build_environment
from sdk_registry import require_registry_alignment
from ui_dependencies import cargo_metadata, ui_provenance

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', action='store_true')
    parser.add_argument('--target')
    args = parser.parse_args()
    env = build_environment()
    os.environ.update(env)
    require_registry_alignment()
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'],
        cwd=ROOT, env=env, text=True))
    target = Path(metadata['target_directory']).resolve()
    if os.name == 'nt' and target.drive.lower() != 'd:':
        raise SystemExit(f'Cargo output must be on D: {target}')
    print(f'Cargo target directory: {target}', flush=True)
    command = ['cargo', 'build', '--locked', '--features', 'desktop', '--bin', 'inkson']
    if args.release:
        command.append('--release')
    if args.target:
        command.extend(['--target', args.target])
    subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=3600)
    folder = target / (args.target or '') / ('release' if args.release else 'debug')
    shutil.copytree(ROOT / 'assets', folder / 'assets', dirs_exist_ok=True)
    (folder / 'inkson-ui-build-info.json').write_text(
        json.dumps(ui_provenance(cargo_metadata(ROOT, env)), indent=2) + '\n',
        encoding='utf-8')
    print(f'Native application: {folder / ("inkson.exe" if os.name == "nt" else "inkson")}')


if __name__ == '__main__':
    main()
