//! Stamps a per-build identifier into the binary via `INKSON_BUILD_ID` so the
//! running wasm can print which bundle the browser actually loaded. Comparing
//! the printed id against the latest rebuild is the definitive way to spot a
//! stale cached wasm bundle (the recurring "is the browser running old wasm?"
//! question during MLS debugging).
//!
//! No `rerun-if-*` directives are emitted, so Cargo re-runs this script — and
//! re-stamps the id — whenever the package is recompiled. A no-change rebuild
//! keeps the previous id (the wasm is unchanged), which is exactly the signal
//! we want.

use std::process::Command;

fn main() {
    let built_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z");

    let git_short = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|hash| !hash.is_empty())
        .unwrap_or_else(|| "nogit".to_owned());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false);
    let dirty_suffix = if dirty { "+dirty" } else { "" };

    println!("cargo:rustc-env=INKSON_BUILD_ID={built_at} {git_short}{dirty_suffix}");
}
