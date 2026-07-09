//! Tests for §2.9 E2EE reaction sealing and routing-tag derivation.

use crate::local_state::isolated_store_for_tests as temp_state_store;
use crate::mls::runtime::*;
use crate::secure_key_store::MemorySecureKeyStore;

#[test]
fn reaction_routing_tag_is_deterministic_and_wire_shaped() {
    let exporter = [0x11u8; 32];
    let tag = reaction_routing_tag_from_exporter(&exporter, "👍");
    // Stable for the same (exporter, emoji).
    assert_eq!(tag, reaction_routing_tag_from_exporter(&exporter, "👍"));
    // sha256:<64 lowercase hex> wire form.
    let hex = tag.strip_prefix("sha256:").expect("sha256: prefix");
    assert_eq!(hex.len(), 64);
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

#[test]
fn reaction_routing_tag_separates_emoji_and_exporter() {
    let exporter_a = [0x11u8; 32];
    let exporter_b = [0x22u8; 32];
    // Different emoji → different tag under the same exporter.
    assert_ne!(
        reaction_routing_tag_from_exporter(&exporter_a, "👍"),
        reaction_routing_tag_from_exporter(&exporter_a, "🎉"),
    );
    // Same emoji → different tag under a different epoch's exporter secret
    // (this is why the tag does not dedup across epochs).
    assert_ne!(
        reaction_routing_tag_from_exporter(&exporter_a, "👍"),
        reaction_routing_tag_from_exporter(&exporter_b, "👍"),
    );
}

#[test]
fn reaction_routing_tag_normalises_to_nfc() {
    let exporter = [0x33u8; 32];
    // "é" as precomposed U+00E9 vs decomposed "e" + U+0301 must agree
    // after NFC normalisation, so the chosen-emoji privacy + dedup hold
    // regardless of the sender's input form.
    let precomposed = "\u{00E9}";
    let decomposed = "e\u{0301}";
    assert_eq!(
        reaction_routing_tag_from_exporter(&exporter, precomposed),
        reaction_routing_tag_from_exporter(&exporter, decomposed),
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn minimal_metadata_reaction_forces_commit_when_epoch_overdue() {
    // SEC-08 end-to-end (native): a minimal-metadata Realm whose epoch is
    // older than 1h must force a `ck.mls.commit` (epoch advance) on the next
    // reaction, and MUST NOT persist the advanced snapshot internally
    // (X14 persist-on-accept) — the snapshot is handed back instead.
    use serde_json::json;

    let mut state = temp_state_store("minimal-reaction-force");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000002";

    // Declare the minimal-metadata profile on the cached projection.
    state.save_realm_tree_projection(
        realm,
        json!({ "active_profiles": [arkret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE] }),
    );
    assert!(state.realm_projection_is_minimal_metadata(realm));

    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device).unwrap();
    let base_epoch = state.mls_snapshot_for(realm).unwrap().epoch;

    // Backdate the persisted snapshot's epoch clock past the 1h cap.
    let mut overdue = state.mls_snapshot_for(realm).unwrap();
    overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, overdue);

    let sealed =
        encrypt_reaction_with_device_snapshot(&mut state, &secure, realm, actor, device, "👍")
            .unwrap();

    // A commit was forced and surfaced for persist-on-accept; the stored
    // snapshot epoch did NOT advance yet (caller persists on accept).
    assert!(sealed.forced_commit.is_some());
    let returned = sealed
        .forced_commit_snapshot
        .expect("forced commit returns its snapshot");
    assert!(returned.epoch > base_epoch);
    assert_eq!(state.mls_snapshot_for(realm).unwrap().epoch, base_epoch);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn non_minimal_reaction_never_forces_commit_and_persists_in_place() {
    // Control: a non-minimal Realm with an equally-old epoch never forces a
    // commit; the reaction rides the current epoch and persists immediately.
    let mut state = temp_state_store("non-minimal-reaction");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000003";

    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device).unwrap();
    let base_epoch = state.mls_snapshot_for(realm).unwrap().epoch;
    let mut overdue = state.mls_snapshot_for(realm).unwrap();
    overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, overdue);

    assert!(!state.realm_projection_is_minimal_metadata(realm));
    let sealed =
        encrypt_reaction_with_device_snapshot(&mut state, &secure, realm, actor, device, "👍")
            .unwrap();
    assert!(sealed.forced_commit.is_none());
    assert!(sealed.forced_commit_snapshot.is_none());
    // Same epoch persisted in place (no skew), epoch clock carried forward.
    let after = state.mls_snapshot_for(realm).unwrap();
    assert_eq!(after.epoch, base_epoch);
}
