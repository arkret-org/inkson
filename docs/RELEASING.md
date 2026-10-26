# inkson Local Release Checklist

This checklist is intentionally local-only. It does not create git tags,
push commits, publish crates, push container images, upload to GHCR, submit
macOS notarization requests, staple tickets, contact timestamp authorities,
or upload Sigstore transparency-log entries.

## Inputs

- A clean inkson worktree except for deliberate release changes.
- Sibling `../arkret-rust-sdk`, `../garth`, and `../chime` checkouts matching
  the local release plan. Glory and Sapid are public Git dependencies from
  `glory-rs/glory` and `sapid-ui/sapid`, both on `main`; `Cargo.lock` pins
  the exact commits. Local sibling UI overrides are rejected by the build helper.
- Python 3 and the `wasm-bindgen-cli` version resolved by `Cargo.lock`.
- Docker for web image evidence.
- Optional local signing tools:
  - macOS: `codesign`, `xcrun`, `INKSON_MACOS_SIGN_IDENTITY`.
  - Windows: `signtool.exe`, `INKSON_WINDOWS_CERT_PATH`, optional
    `INKSON_WINDOWS_CERT_PASSWORD`.
  - Linux: `gpg`.
  - Web evidence: `trivy`, `syft`, `cosign`, optional `COSIGN_KEY`.

## Verification

```powershell
$env:CARGO_HOME = "D:/BuildCache/cargo"
$env:CARGO_TARGET_DIR = "D:/BuildCache/inkson-glory/target"
$env:TEMP = "D:/BuildCache/inkson-glory/tmp"
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
cargo +nightly fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
python scripts/build_web.py --release --out-dir dist/web
npm ci
$inksonMetadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
cargo build --locked --profile joint-e2e --no-default-features --features spec-conformance --bin inkson-wire
$env:INKSON_WIRE_BIN = Join-Path $inksonMetadata.target_directory "joint-e2e/inkson-wire.exe"
npm run e2e
```

Generate an optional Lighthouse report from a local web preview:

```powershell
python scripts/dev_glory.py --platform web --port 4528
powershell -ExecutionPolicy Bypass -File scripts/lighthouse-local.ps1 -Url http://127.0.0.1:4528
```

## Native artifacts

Build the native binary locally:

```powershell
python scripts/build_desktop.py --release
```

Generate signing evidence without remote submission:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/signing-dry-run.ps1
```

Platform notes:

- macOS: the script uses `codesign --timestamp=none` when a local identity is
  configured, verifies the signature, and records notarytool input presence.
  It never runs `notarytool submit` or `stapler`.
- Windows: the script uses `signtool sign /fd SHA256 /f <cert>` when a local
  certificate path is configured. It omits `/tr` and `/t`.
- Linux: the script creates `dist/signing/inkson-linux-x64.tar.gz` and a GPG
  detached signature when `gpg` is present.

## Linux package formats

The phase-3 Linux package script creates a local `.deb` when `dpkg-deb` is
installed and records availability for rpm/AppImage/Flatpak tooling:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/linux-package-local.ps1

# rpm, when rpmbuild is installed
# create a local spec under dist/rpm/SPECS/ and run rpmbuild -bb

# AppImage, when appimagetool is installed
# create dist/appimage/Inkson.AppDir and run appimagetool locally

# Flatpak, when flatpak-builder is installed
# use a local manifest and local build-dir; do not publish to Flathub
```

Record the exact command and resulting hashes in `dist/signing/`.

## Web image evidence

Build and scan the web image locally:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/web-image-evidence.ps1
```

The script builds `inkson-web:local`, saves a local image tar, writes a SHA-256
hash, runs Trivy when available, generates an SBOM through Syft or Trivy when
available, and signs the image tar as a blob through Cosign only when
`COSIGN_KEY` is set. Cosign is invoked with `--tlog-upload=false`.

## Final local milestone

Before recording a local `v0.9.0` milestone in notes:

- Confirm no release workflow has registry push, tag-triggered publish, or
  notarization submit semantics.
- Confirm `dist/signing/` and `dist/web-image/` contain evidence JSON files.
- Confirm unresolved items remain listed in `_inkson_todos.md`.
- Commit with a subject beginning `inkson:`.
