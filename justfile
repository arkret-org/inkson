# Show available local tasks.
default:
    @just --list

# Start the Dioxus web dev server.
web:
    dx serve --platform web --port 8080

# Start the Dioxus desktop dev server.
desktop:
    dx serve --platform desktop

# Start the Dioxus mobile dev server.
mobile:
    dx serve --platform mobile

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
