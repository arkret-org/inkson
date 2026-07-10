//! YOU-01-014 regression: the `ck.member.{invite,remove,role_change}` tokens are
//! inkson-local UI grouping placeholders only. They are NOT registered in
//! `capability-action-registry.json`, so they must never be sent on the
//! protocol authz wire (`authz_check_raw` → `AuthzCheckRequestBody.action` →
//! `POST /_arkret/self/authz/check`). A spec-conformant server fail-closes on
//! unregistered actions, which would permanently hide the member-management
//! controls; a lax server would accept a non-canonical action token across the
//! protocol boundary.
//!
//! This static guard scans `src/` and asserts the three placeholder literals
//! only ever appear in `src/capability.rs` (their definition site as UI
//! labels). If any other source file mentions them — most importantly an
//! `authz_check_raw(..)` call site — this test fails loudly.

use std::fs;
use std::path::{Path, PathBuf};

const PLACEHOLDER_ACTIONS: &[&str] = &[
    "ak.member.invite",
    "ak.member.remove",
    "ak.member.role_change",
];

/// Files allowed to mention the placeholder literals (their UI-label home and
/// this guard itself).
fn is_allowed_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(name, "capability.rs")
}

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
fn member_placeholder_actions_never_reach_protocol_wire() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find Rust source files under {}",
        src.display()
    );

    let mut violations = Vec::new();
    for file in &files {
        if is_allowed_file(file) {
            continue;
        }
        let contents = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for action in PLACEHOLDER_ACTIONS {
            // Match the quoted string literal so we only flag wire/probe usage,
            // not incidental substrings.
            if contents.contains(&format!("\"{action}\"")) {
                violations.push(format!("{}: {action}", file.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "unregistered member capability placeholder(s) leaked outside src/capability.rs \
         (likely sent on the authz wire). These tokens are not in \
         capability-action-registry.json and must stay UI-label-only. Use a registered \
         action such as `ak.realm.admin` for member-management authz probes. Violations:\n{}",
        violations.join("\n")
    );
}
