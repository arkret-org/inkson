# inkson — Build per Platform

> Reproducible build instructions for macOS / Windows / Linux desktop and
> the web image. Codesign / notarization stay in **dry-run** mode — see
> [`scripts/codesign-dryrun.ps1`](../scripts/codesign-dryrun.ps1) and the
> POSIX sibling.

## 0. Prerequisites (all platforms)

| Tool | Version |
| --- | --- |
| Rust | `1.92` (matches `Cargo.toml::rust-version`) |
| `cargo` | bundled with the rustup toolchain |
| `wasm32-unknown-unknown` target | `rustup target add wasm32-unknown-unknown` |
| `dx` (Dioxus CLI) | `cargo install dioxus-cli@0.7` |
| Node | `>= 18` (Playwright + image assets) |
| Docker | `>= 24` (web image only) |

Clone the workspace and the sibling SDK:

```powershell
git clone <arkret> arkret
cd arkret
ls
# inkson/ chime/ soland/ floria/ arkret-rust-sdk/ ...
```

All commands below run from `arkret/inkson/`.

The `justfile` mirrors the same build plan for local use:

| Task | Purpose |
| --- | --- |
| `just web-build` | Dioxus web/WASM release build. |
| `just desktop-build` | Native desktop release build for the current host. |
| `just package-windows` | Local unsigned MSI wrapper around `scripts/windows-msi-local.ps1`. |
| `just package-macos` | Local unsigned `.app` bundle wrapper around `scripts/macos-bundle-local.ps1`. |
| `just package-linux` | Local Linux package evidence wrapper around `scripts/linux-package-local.ps1`. |
| `just check-linux` / `check-windows` / `check-macos` | Best-effort Rust cross-target checks after installing the target. |
| `just check-ios` / `check-android` / `check-mobile-stubs` | Rust-side mobile host-bridge stub checks; they do not produce app-store artifacts. |

---

## 1. macOS desktop

```bash
cargo build --release
./scripts/codesign-dryrun.sh
```

Outputs:

- `target/release/inkson` — universal-arch binary (set `CARGO_BUILD_TARGET`
  for explicit `aarch64-apple-darwin` / `x86_64-apple-darwin`).
- `dist/signing/codesign-dryrun.json` — codesign + notarytool plan.

The dry-run reports whether `codesign` / `xcrun notarytool` are present
and whether `APPLE_ID` / `APPLE_TEAM_ID` / `APPLE_APP_SPECIFIC_PASSWORD`
(or `APPLE_KEYCHAIN_PROFILE`) are set, but **never submits**. To produce
a real signed `.app`, run codesign manually against a paid Developer ID
certificate; the dry-run script is **NOT for production use**.

---

## 2. Windows desktop

```powershell
cargo build --release
powershell -ExecutionPolicy Bypass -File scripts/codesign-dryrun.ps1
```

Outputs:

- `target/release/inkson.exe`
- `dist/signing/codesign-dryrun.json` — signtool plan.

For an MSI you also need:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows-msi-local.ps1
```

The MSI build uses WiX 4 and lands at `dist/inkson-windows.msi`. It is
**unsigned**; the codesign dry-run never invokes a timestamp authority.

---

## 3. Linux desktop

```bash
cargo build --release
./scripts/codesign-dryrun.sh
```

Outputs:

- `target/release/inkson`
- `dist/signing/inkson-linux-x64.tar.gz` (+ optional `.asc` GPG
  signature if `gpg` is on PATH).

To produce distro packages locally:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/linux-package-local.ps1
```

The script wraps `cargo-deb` / `cargo-generate-rpm` / `appimagetool` /
`flatpak-builder` when present. None of them push to a public repository.

---

## 4. Web build (Dioxus → WebAssembly)

```bash
dx build --platform web --release
```

Outputs land under `target/dx/inkson/release/web/`. Serve with any static
host that preserves the Dioxus asset paths.

The web build uses the same in-tree OpenMLS patch as native builds for
persisted MLS snapshots and encrypted-history restore. It still relies on
browser storage for local long-lived material, so it is suitable for browser
compatibility and recovery testing but has a weaker local secret-storage tier
than desktop.

For a containerized build:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/prepare-docker-context.ps1
docker build -f docker-context/inkson/Dockerfile -t inkson-web:local docker-context
```

Run locally:

```bash
docker run --rm -p 4527:80 inkson-web:local
```

The Dockerfile sets a strict CSP:

```text
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:;
connect-src 'self' https:;
font-src 'self' data:;
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
```

`dangerous_inner_html` is **never** enabled in the Dioxus tree. The
`pulldown-cmark` markdown renderer keeps its `html` feature pass-through
disabled, so untrusted message bodies cannot inject arbitrary tags.

For evidence generation:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/web-image-evidence.ps1 -SkipBuild
```

The output lands under `dist/web-image/` (Trivy report + SBOM). The image
is **local-only**; do not push to GHCR or another registry under the
local 1.0 plan.

---

## 5. Cross-compile checks

Install targets before cross-checking:

```bash
rustup target add \
  wasm32-unknown-unknown \
  x86_64-unknown-linux-gnu \
  x86_64-pc-windows-gnu \
  aarch64-apple-darwin \
  aarch64-apple-ios \
  aarch64-linux-android
```

Then run the best-effort checks:

```bash
just check-linux
just check-windows
just check-macos
just check-mobile-stubs
```

The iOS and Android targets are **stubs only** — they install host-bridge wrappers
around the `HostSecretBridge` trait. There is no real JNI or
Security.framework FFI inside inkson. See
`docs/platform-stub-roadmap.md` for the path to real artifacts.

Gitea CI mirrors this shape in `.gitea/workflows/smoke.yml`: web/WASM
and Linux checks are required, while Windows, macOS, iOS, and Android
target checks are marked best-effort until dedicated runners/toolchains
exist. A separate responsive viewport job runs
`tests/e2e/viewport.spec.ts` against the Dioxus web build.

---

## 6. Verification

After any build:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo check --workspace --all-features
cargo test --workspace --lib
npm install
npx playwright install --with-deps chromium
npx playwright test
```

The release-gate wrapper bundles all of the above:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/release-gate.ps1
```

The gate also enforces the Lighthouse budget in
[`docs/lighthouse-budget.json`](lighthouse-budget.json).
