#![cfg(not(target_arch = "wasm32"))]

//! The Event digest preimage has one implementation, and it is not in this repo.
//!
//! `conformance/encoding.md` §6 excludes `proofs`, `unsigned`, `actor_kind` and
//! `event_id` from the digest preimage. `arkret_sdk::event_digest_preimage` is
//! the single implementation of that rule. Three sites here used to apply it by
//! hand, and each drifted at a different point:
//!
//! * `src/identity/agent_signer_evidence.rs` omitted `event_id`, so every
//!   well-formed Agent evidence Event was rejected as `SigningKeyMismatch`;
//! * `src/identity/device_directory.rs` carried its own full copy;
//! * `src/views/chat/tests.rs` had a fixture signer with a fourth copy.
//!
//! None failed loudly. A drifted preimage produces bytes no other
//! implementation reproduces, so a *valid* signature verifies as invalid — the
//! failure surfaces as an authorization or trust error somewhere else entirely.
//!
//! The SDK ships the same check as `tools/lint-event-preimage-authoring.py` for
//! CI that has both checkouts; this test is the copy that runs in inkson's own
//! gate, where the sibling SDK tree may be absent.

use std::fs;
use std::path::{Path, PathBuf};

/// Deleting either Event-only excluded member from a JSON map is the act of
/// building a preimage by hand. Removing `proofs` alone is deliberately absent:
/// non-Event signed objects legally strip their own `proofs` before signing and
/// have neither `event_id` nor `actor_kind` to drop.
const HAND_ROLLED_EXCLUSIONS: &[&str] = &[r#"remove("event_id")"#, r#"remove("actor_kind")"#];

/// Paths that delete one of those members for a reason unrelated to the digest
/// preimage. Each entry names what the field is there.
const ALLOWED: &[(&str, &str)] = &[(
    "state/to_device_raw.rs",
    "clears the `event_id` bookkeeping slot on a locally queued to-device \
     operation record; not an Event envelope",
)];

fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_source_file_hand_rolls_the_event_digest_preimage() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(src.is_dir(), "missing source directory: {}", src.display());
    let mut sources = Vec::new();
    rust_sources(&src, &mut sources);
    assert!(!sources.is_empty(), "found no Rust sources to scan");

    let mut violations = Vec::new();
    let mut used_exemptions = Vec::new();
    for path in &sources {
        let relative = path
            .strip_prefix(&src)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let source = fs::read_to_string(path).expect("read Rust source");
        let hand_rolled: Vec<&str> = HAND_ROLLED_EXCLUSIONS
            .iter()
            .copied()
            .filter(|needle| source.contains(needle))
            .collect();
        if hand_rolled.is_empty() {
            continue;
        }
        match ALLOWED.iter().find(|(allowed, _)| *allowed == relative) {
            Some((allowed, _)) => used_exemptions.push(*allowed),
            None => violations.push(format!("{relative} deletes {}", hand_rolled.join(", "))),
        }
    }

    assert!(
        violations.is_empty(),
        "call arkret_sdk::event_digest_preimage instead of deleting excluded members by hand \
         (encoding.md section 6):\n{}",
        violations.join("\n")
    );

    // A stale exemption is a standing licence to hand-roll the rule again.
    for (allowed, reason) in ALLOWED {
        assert!(
            used_exemptions.contains(allowed),
            "{allowed} no longer deletes an excluded member ({reason}); drop the exemption"
        );
    }
}
