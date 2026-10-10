# inkson Local Release Checklist

This checklist is intentionally local-only. It does not create git tags,
push commits, publish crates, push container images, upload to GHCR, submit
macOS notarization requests, staple tickets, contact timestamp authorities,
or upload Sigstore transparency-log entries.

## Inputs

- A clean inkson worktree except for deliberate release changes.
- Sibling `../arkret-rust-sdk`, `../garth`, and `../chime` checkouts matching
  the local release plan. `yoface` is a private cargo git dependency, not a
  sibling checkout: git credentials for `github.com/arkret-org/yoface` are
  required instead, and the web image build additionally needs that token in
  `GITHUB_TOKEN` for the `github_token` build secret.
- Dioxus CLI `0.7.10`.
- Docker for web image evidence.
- Optional local signing tools:
  - macOS: `codesign`, `xcrun`, `INKSON_MACOS_SIGN_IDENTITY`.
  - Windows: `signtool.exe`, `INKSON_WINDOWS_CERT_PATH`, optional
    `INKSON_WINDOWS_CERT_PASSWORD`.
  - Linux: `gpg`.
  - Web evidence: `trivy`, `syft`, `cosign`, optional `COSIGN_KEY`.

## Verification

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
dx build --platform web --features web --release
npm ci
npm run e2e
```

Run the Lighthouse budget against a local web preview:

```powershell
dx serve --platform web --features web --port 4528 --open false
powershell -ExecutionPolicy Bypass -File scripts/lighthouse-local.ps1 -Url http://127.0.0.1:4528
```

## Native artifacts

Build the native binary locally:

```powershell
cargo build --release --features desktop
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
