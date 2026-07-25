#![cfg(not(target_arch = "wasm32"))]

//! Static deduplication gates for client-core extraction.
//!
//! These guards pin surfaces that have already been removed from inkson. They
//! intentionally do not assert that the `ArkretApi` struct itself is gone (its
//! remaining god-object methods + E8 orchestration are still live work), but
//! they DO pin the `src/api/**` submodules that have been fully extracted:
//! the durable/ephemeral event engine now lives in `crate::event_submit`
//! (`api::events`/`api::agent` deleted), and the applet/moderation surfaces
//! moved to the SDK http-client via the keystone. Reintroducing any of these
//! files would resurrect a duplicate of the client-core engine.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_SOURCE_FILES: &[&str] = &[
    "dpop.rs",
    "auth_dpop.rs",
    // Event-submission engine extracted to crate::event_submit; these
    // ArkretApi delegator modules were deleted and must stay deleted.
    "api/events.rs",
    "api/agent.rs",
    // Pure-passthrough surfaces migrated onto the SDK http-client keystone.
    "api/applet.rs",
    "api/moderation.rs",
];

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
         inkson-local src/dpop.rs or src/auth_dpop.rs. Violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn realm_runner_keeps_session_recovery_inside_transport_provider() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/realm_events_engine.rs");
    let source = fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", source_path.display()));
    assert!(
        source.contains("async fn recover_unauthorized(&self)")
            && source.contains("provide_authenticated_sdk_client")
            && source.contains("refresh_authenticated_session_after_unauthorized")
            && !source.contains("prepare_refresh_for_server_after_unauthorized")
            && !source.contains("exchange_refresh(&grant, &device_handle)")
            && !source.contains("self.ctx.token.set(session_credential)"),
        "Inkson Realm transport provider must own unauthorized refresh and credential rebuild"
    );
    assert!(
        !source.contains("run_realm_iteration"),
        "the removed host-owned Realm iteration loop must not return"
    );
    assert!(
        !source.contains("save_realm_events_cursor") && !source.contains("clear_cursor"),
        "Inkson Realm host must not clear a cursor after Garth scan/checkpoint recovery"
    );
}

#[test]
fn ordinary_event_submit_uses_garth_durable_outbound() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let submit_path = manifest.join("src/event_submit.rs");
    let submit = fs::read_to_string(&submit_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", submit_path.display()));
    assert!(
        submit.contains("OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open")
            && submit.contains(".enqueue(")
            && submit.contains("drain_outbound"),
        "ordinary Inkson SDK events must enter Garth's durable queue and resume after restart"
    );
    assert!(
        submit.contains("async fn submit_sdk_event_direct")
            && submit.contains(".submit_sdk_event_direct(")
            && submit.contains("&queued.transport_idempotency_key")
            && submit.contains("&queued.canonical_body_bytes")
            && submit.contains(
                "self.post_persisted_signed_sdk_event(event, idempotency_key, canonical_body_bytes)"
            )
            && submit.contains("mls-durable-post-accept"),
        "the exact-byte direct HTTP tail must remain private to the Garth queue submitter"
    );

    let composer_path = manifest.join("src/views/chat/composer.rs");
    let composer = fs::read_to_string(&composer_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", composer_path.display()));
    assert!(
        !composer.contains("chat_outbox.write().push(entry)"),
        "new offline chat sends must not create a second product-specific durable queue"
    );
}

#[test]
fn mls_snapshot_remains_post_accept() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let submit_path = manifest.join("src/event_submit.rs");
    let submit = fs::read_to_string(&submit_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", submit_path.display()));
    assert!(
        submit.contains("PostAcceptAction::MlsSnapshot")
            && submit.contains("submit_next_with_fence_and_hook")
            && submit.contains("drain_mls_outbound"),
        "MLS snapshot must be a generation-fenced durable post-accept action resumed by account sync"
    );

    let path = manifest.join("src/views/kanban/mls_encrypt.rs");
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    assert!(
        source.contains("submit_mls_event_with_snapshot")
            && !source.contains("save_mls_snapshot(realm_id.clone(), snapshot)"),
        "Kanban MLS commits must not persist the next snapshot outside the acceptance hook"
    );
}
