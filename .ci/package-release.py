#!/usr/bin/env python3
"""Stage Cargo and Glory/Sapid outputs and create a checksummed release archive."""

import argparse
import hashlib
import json
import os
import plistlib
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from ui_dependencies import cargo_metadata, ui_provenance, verify_web_provenance


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def copy(source, destination):
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=True)
    elif source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    else:
        raise FileNotFoundError(source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--binary', action='append', default=[])
    parser.add_argument('--resource', action='append', default=[])
    parser.add_argument('--web-dir', type=Path)
    parser.add_argument('--desktop-platform', choices=['linux','windows','macos'])
    parser.add_argument('--app', default='inkson')
    parser.add_argument('--crates', action='store_true')
    args = parser.parse_args()
    if os.name == "nt":
        cache = Path("D:/BuildCache/inkson-glory/tmp")
        cache.mkdir(parents=True, exist_ok=True)
        tempfile.tempdir = str(cache)
        os.environ["TEMP"] = os.environ["TMP"] = str(cache)
    root = Path.cwd()
    project = root.name
    tag = os.environ.get('GITHUB_REF_NAME', 'verification')
    tag = re.sub(r'[^A-Za-z0-9._-]', '-', tag)
    name = f'{project}-{tag}-{args.target}'
    metadata = cargo_metadata(root)
    ui_sources = ui_provenance(metadata)
    target = Path(metadata['target_directory']).resolve()
    if os.name == "nt" and target.drive.lower() != "d:":
        raise RuntimeError(f"Cargo build output must be on D: {target}")
    output = root / 'release-assets'
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='release-') as temporary:
        stage = Path(temporary) / name
        stage.mkdir()
        suffix = '.exe' if 'windows' in args.target else ''
        for binary in args.binary:
            source, _, destination = binary.partition('=')
            destination = destination or source
            copy(target / args.target / 'release' / (source + suffix),
                 stage / (destination + suffix))
        if args.web_dir:
            source = args.web_dir.resolve()
            for required in ['index.html', 'bootstrap.js', 'assets/app.css', 'assets/sapid.css',
                             'assets/pkg/inkson.js', 'assets/pkg/inkson_bg.wasm']:
                if not (source / required).is_file():
                    raise FileNotFoundError(source / required)
            verify_web_provenance(source, metadata)
            copy(source, stage)
        if args.desktop_platform:
            executable=target/args.target/'release'/(args.app+suffix)
            if not executable.is_file():raise FileNotFoundError(executable)
            if args.desktop_platform=='macos':
                app=stage/(args.app+'.app');contents=app/'Contents';binary=contents/'MacOS'/args.app
                copy(executable,binary);binary.chmod(0o755)
                copy(root/'assets',contents/'Resources'/'assets')
                version=next(p['version'] for p in metadata['packages'] if p['name']==args.app)
                info={'CFBundleExecutable':args.app,'CFBundleIdentifier':'com.arkret.'+args.app,'CFBundleName':args.app,'CFBundleVersion':version,'CFBundleShortVersionString':version,'LSMinimumSystemVersion':'11.0','NSHighResolutionCapable':True,'NSCameraUsageDescription':'Inkson uses the camera for video calls.','NSMicrophoneUsageDescription':'Inkson uses the microphone for calls.'}
                (contents/'Info.plist').write_bytes(plistlib.dumps(info))
            else:
                copy(executable,stage/(args.app+suffix));copy(root/'assets',stage/'assets')
        if args.crates:
            packages = [package for package in metadata['packages']
                        if package['id'] in metadata['workspace_members']
                        and package['publish'] != []]
            if not packages:
                raise RuntimeError('Cargo produced no source packages')
            for package in packages:
                crate = target / 'package' / f"{package['name']}-{package['version']}.crate"
                copy(crate, stage / crate.name)
        if not (args.binary or args.web_dir or args.desktop_platform or args.crates):
            parser.error('At least one build output is required')
        for resource in args.resource:
            source, _, destination = resource.partition('=')
            copy(root / source, stage / (destination or source))
        for pattern in ['README*', 'LICENSE*', 'NOTICE*', 'RELEASING.md']:
            for path in root.glob(pattern):
                if path.is_file():
                    copy(path, stage / path.name)
        repositories = {}
        local_roots = {root, *(Path(package['manifest_path']).parent for package in metadata['packages'] if package.get('source') is None)}
        for directory in sorted(local_roots):
            resolved = subprocess.run(['git', '-C', str(directory), 'rev-parse', '--show-toplevel'],
                                      capture_output=True, text=True)
            if resolved.returncode == 0:
                repository = Path(resolved.stdout.strip())
                repositories[repository.name] = run('git', '-C', str(repository), 'rev-parse', 'HEAD')
        provenance = {'repository': project, 'ref': os.environ.get('GITHUB_REF'),
                      'target': args.target, 'commits': repositories, 'ui_dependencies': ui_sources,
                      'lock_sha256': hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest()}
        (stage / 'build-info.json').write_text(json.dumps(provenance, indent=2) + '\n')
        if 'windows' in args.target:
            archive = output / (name + '.zip')
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
                for path in sorted(stage.rglob('*')):
                    if path.is_file():
                        bundle.write(path, path.relative_to(stage.parent))
        else:
            archive = output / (name + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as bundle:
                bundle.add(stage, arcname=name)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_name(archive.name + '.sha256').write_bytes(f'{digest}  {archive.name}\n'.encode('ascii'))
        print(archive)


if __name__ == '__main__':
    main()
