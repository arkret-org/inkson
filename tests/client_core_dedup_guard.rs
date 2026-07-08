//! Static deduplication gates for client-core extraction.
//!
//! These guards pin surfaces that have already been removed from yougen. They
//! intentionally do not assert anything about `CokretApi`, which still has live
//! migration work.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_SOURCE_FILES: &[&str] = &["dpop.rs", "auth_dpop.rs"];

const FORBIDDEN_TOKENS: &[&str] = &[
    "CoauthApi",
    "crate::dpop",
    "crate::auth_dpop",
    "mod dpop",
    "mod auth_dpop",
    "pub mod dpop",
    "pub mod auth_dpop",
];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn removed_private_coauth_and_dpop_surfaces_stay_removed() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(src.is_dir(), "missing source directory: {}", src.display());

    let mut violations = Vec::new();
    for file_name in FORBIDDEN_SOURCE_FILES {
        let path = src.join(file_name);
        if path.exists() {
            violations.push(format!("removed source file exists: {}", path.display()));
        }
    }

    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    assert!(
        !files.is_empty(),
        "expected Rust source files under {}",
        src.display()
    );

    for file in files {
        let contents = match fs::read_to_string(&file) {
            Ok(contents) => contents,
            Err(_) => continue,
        };
        for token in FORBIDDEN_TOKENS {
            if contents.contains(token) {
                violations.push(format!("{} contains `{token}`", file.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "removed duplicate client-core surface reappeared. Keep CoauthApi and \
         private DPoP helpers in the shared client layer, and do not reintroduce \
         yougen-local src/dpop.rs or src/auth_dpop.rs. Violations:\n{}",
        violations.join("\n")
    );
}
