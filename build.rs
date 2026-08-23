//! Stamps a per-build identifier into the binary via `INKSON_BUILD_ID` so the
//! running wasm can print which bundle the browser actually loaded. Comparing
//! the printed id against the latest rebuild is the definitive way to spot a
//! stale cached wasm bundle (the recurring "is the browser running old wasm?"
//! question during MLS debugging).
//!
//! Cargo does not treat Git metadata as a package input. Track HEAD and its
//! current loose ref explicitly so a commit-only change cannot leave a fresh
//! bundle stamped with the previous source identity.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git_output(manifest_dir: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|output| !output.is_empty())
}

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"),
    );
    if let Some(git_dir) = git_output(&manifest_dir, &["rev-parse", "--absolute-git-dir"]) {
        let git_dir = PathBuf::from(git_dir);
        let head_path = git_dir.join("HEAD");
        println!("cargo:rerun-if-changed={}", head_path.display());
        if let Ok(head) = fs::read_to_string(&head_path)
            && let Some(reference) = head.trim().strip_prefix("ref: ")
        {
            println!(
                "cargo:rerun-if-changed={}",
                git_dir.join(reference).display()
            );
        }
    }

    let built_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z");

    let git_short = git_output(&manifest_dir, &["rev-parse", "--short", "HEAD"])
        .unwrap_or_else(|| "nogit".to_owned());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&manifest_dir)
        .output()
        .ok()
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false);
    let dirty_suffix = if dirty { "+dirty" } else { "" };

    println!("cargo:rustc-env=INKSON_BUILD_ID={built_at} {git_short}{dirty_suffix}");
}
