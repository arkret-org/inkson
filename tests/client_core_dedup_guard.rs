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
use std::path::Path;

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
            // The exact bytes come off the immutable authored attempt that the
            // queue persisted, never off a freshly re-serialized envelope.
            && submit.contains("&attempt.transport_idempotency_key")
            && submit.contains("&attempt.canonical_body_bytes")
            && submit.contains(
                "self.post_persisted_signed_sdk_event(event, idempotency_key, canonical_body_bytes)"
            ),
        "the exact-byte direct HTTP tail must remain private to the Garth queue submitter"
    );
    let outbound_store_path = manifest.join("src/outbound_store.rs");
    let outbound_store = fs::read_to_string(&outbound_store_path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", outbound_store_path.display())
    });
    assert!(
        outbound_store.contains("MlsDurablePostAccept")
            && outbound_store.contains("\"mls-durable-post-accept\""),
        "the durable MLS admission lane must remain distinct from ordinary outbound delivery"
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
fn mls_readiness_remains_checkpoint_proven() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let submit_path = manifest.join("src/event_submit.rs");
    let submit = fs::read_to_string(&submit_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", submit_path.display()));
    assert!(
        submit.contains("PostAcceptAction::MlsAdmission")
            && submit.contains("submit_next_with_fence_and_hook")
            && submit.contains("drain_mls_outbound")
            && submit.contains("checkpoint-proven accepted-artifact")
            && submit.contains("this queue never installs its staged snapshot"),
        "MLS admission must remain durable without treating ingress acceptance as group readiness"
    );

    let consumer_path = manifest.join("src/mls/runtime/artifact_consumer.rs");
    let consumer = fs::read_to_string(&consumer_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", consumer_path.display()));
    assert!(
        consumer.contains("garth::AcceptedMlsArtifactConsumer::new")
            && consumer.contains("frontier.target_checkpoint.accepted_events")
            && consumer.contains("compare_and_swap_accepted_mls_artifacts")
            && consumer.contains("converge_accepted_mls_artifacts"),
        "only the checkpoint-proven accepted-artifact consumer may publish ready MLS state"
    );

    let kanban_path = manifest.join("src/views/kanban/mls_encrypt.rs");
    let kanban = fs::read_to_string(&kanban_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", kanban_path.display()));
    assert!(
        kanban.contains("checkpoint-proven MLS group state is pending")
            && !kanban.contains("save_mls_snapshot("),
        "Kanban must wait for checkpoint-proven group state instead of installing a staged snapshot"
    );
}
