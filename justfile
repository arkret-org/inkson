# Cargo parallelism for the local gate. Windows and low-memory runners OOM the
# linker at full parallelism: rustc fails to mmap an rlib with `os error 1455`
# (the pagefile is too small), which surfaces as a *test* failure. One job
# removes it. Raise this on a machine with headroom.
gate_jobs := env_var_or_default("INKSON_GATE_JOBS", "1")
gate_dir := env_var_or_default("INKSON_GATE_DIR", "target/gate")

# Show available local tasks.
default:
    @just --list

# Start the Dioxus web dev server.
web:
    python scripts/dev_dioxus.py --platform web --port 8080

# Start the Dioxus desktop dev server.
desktop:
    python scripts/dev_dioxus.py --platform desktop

# Start the Dioxus mobile dev server.
mobile:
    python scripts/dev_dioxus.py --platform mobile

# Build the Dioxus web artifact.
web-build:
    dx build --platform web --release

# Build the native desktop binary for the current host.
desktop-build:
    cargo build --release

# Best-effort cross-target desktop checks. Install the listed Rust target first.
check-linux:
    cargo check --locked --target x86_64-unknown-linux-gnu

check-windows:
    cargo check --locked --target x86_64-pc-windows-gnu

check-macos:
    cargo check --locked --target aarch64-apple-darwin

# Best-effort mobile host-bridge checks. These validate the Rust-side stubs only.
check-ios:
    cargo check --locked --target aarch64-apple-ios --features mobile-ios

check-android:
    cargo check --locked --target aarch64-linux-android --features mobile-android

check-mobile-stubs: check-ios check-android

# Local unsigned packaging helpers.
package-linux: desktop-build
    powershell -ExecutionPolicy Bypass -File scripts/linux-package-local.ps1

package-macos: desktop-build
    powershell -ExecutionPolicy Bypass -File scripts/macos-bundle-local.ps1

package-windows: desktop-build
    powershell -ExecutionPolicy Bypass -File scripts/windows-msi-local.ps1

package-web-image:
    powershell -ExecutionPolicy Bypass -File scripts/web-image-evidence.ps1

signing-dry-run: desktop-build
    powershell -ExecutionPolicy Bypass -File scripts/signing-dry-run.ps1

# Run Rust tests.
test:
    cargo test

# Run the local test gate with bounded parallelism and saved artifacts.
#
# Prefer this over `just test` for a full run: `cargo test` prints a line per
# test and this suite has ~1800 of them, so the failure summary at the end is
# exactly what a truncated scrollback loses. The logic lives in
# `scripts/gate.sh` so it runs without `just` installed. Read
# `{{ gate_dir }}/summary.txt` for the verdict, never the terminal tail.
#
# Extra arguments go to `cargo test`:
#
#     just gate --lib recovery
gate *args:
    INKSON_GATE_JOBS={{ gate_jobs }} INKSON_GATE_DIR={{ gate_dir }} sh scripts/gate.sh {{ args }}

# Run the browser-only wasm-bindgen integration tests. Requires
# wasm-bindgen-test-runner 0.2.123 and a WebDriver-compatible Chrome install.
[env("CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER", "wasm-bindgen-test-runner")]
test-wasm:
    cargo test --locked --target wasm32-unknown-unknown --test mls_data_plane_wasm --test wasm_indexed_db_capacity

# Run Playwright e2e tests.
e2e:
    npm run e2e

# Run the local release gate.
release-check:
    npm run release:check
