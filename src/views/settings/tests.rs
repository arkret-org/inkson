use std::collections::BTreeMap;

use super::*;

/// F-BLOCKLIST-VALID-1: the live form validator should accept the
/// DID Core shapes the rest of inkson routinely round-trips through
/// soland (web, key, plc) and reject the obvious noise users paste
/// in by accident. The point is to give *fast* feedback while the
/// reducer remains the source of truth — so we don't try to be
/// exhaustive about method-specific rules here.
#[test]
fn is_likely_valid_did_accepts_canonical_shapes_and_rejects_garbage() {
    assert!(is_likely_valid_did("did:web:alice.example"));
    assert!(is_likely_valid_did(
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    ));
    assert!(is_likely_valid_did("did:plc:abc123"));
    assert!(is_likely_valid_did("  did:web:alice.example  "));

    // Empty / missing scheme.
    assert!(!is_likely_valid_did(""));
    assert!(!is_likely_valid_did("   "));
    assert!(!is_likely_valid_did("alice.example"));
    // Missing method or method-specific id.
    assert!(!is_likely_valid_did("did:"));
    assert!(!is_likely_valid_did("did::alice"));
    assert!(!is_likely_valid_did("did:web:"));
    assert!(!is_likely_valid_did("did:web:   "));
    // Non-alphanumeric method.
    assert!(!is_likely_valid_did("did:we b:alice"));
    assert!(!is_likely_valid_did("did:web-x:alice")); // DRIFT-ALLOW: negative test
    // Round 4 (spec a77b995) — `.`/`-`/`_`/`:` are forbidden in
    // the method segment; method MUST be lowercase ASCII alphanum.
    assert!(!is_likely_valid_did("did:web.x:alice")); // DRIFT-ALLOW: negative test
    assert!(!is_likely_valid_did("did:web_x:alice")); // DRIFT-ALLOW: negative test
    assert!(!is_likely_valid_did("did:WEB:alice"));
    // Whitespace inside method-specific id is rejected (round-4
    // regex `^did:[a-z0-9]+:[^\s]+$`).
    assert!(!is_likely_valid_did("did:web:alice example"));
    // The method-specific id may still contain `:` (the splitn(2)
    // keeps everything after the second `:`) — e.g. did:webvh nested
    // delegations.
    assert!(is_likely_valid_did("did:webvh:authority.example:zKey"));
}

/// The canonical `ck.read_receipt.preferences` body shape other devices
/// read via `/sync` account_data. Locks the SDK/spec field names so a
/// future rename can't silently desync devices.
#[test]
fn build_read_receipt_preferences_body_has_canonical_field_shape() {
    let mut realms = BTreeMap::new();
    realms.insert("ck:realm:demo".to_owned(), false);
    let mut realm_display = BTreeMap::new();
    realm_display.insert("ck:realm:display-only".to_owned(), false);
    let mut strands = BTreeMap::new();
    strands.insert("ck:strand:demo".to_owned(), true);
    let mut strand_display = BTreeMap::new();
    strand_display.insert("ck:strand:demo".to_owned(), false);
    let body = build_read_receipt_preferences_body(
        true,
        false,
        &realms,
        &realm_display,
        &strands,
        &strand_display,
    );
    assert_eq!(body["default"]["send"], serde_json::Value::Bool(true));
    assert_eq!(body["default"]["display"], serde_json::Value::Bool(false));
    assert_eq!(body["realms"]["ck:realm:demo"]["send"], false);
    assert_eq!(body["realms"]["ck:realm:display-only"]["display"], false);
    assert_eq!(body["strands"]["ck:strand:demo"]["send"], true);
    assert_eq!(body["strands"]["ck:strand:demo"]["display"], false);
    // Guard removed flat keys so devices don't drift back to the old shape.
    assert!(body.get("default_send").is_none());
    assert!(body.get("realm_overrides").is_none());
    assert!(body.get("strand_overrides").is_none());
    assert!(body.get("read_receipt_default_send").is_none());
}

/// account-data key is the exact spec key — same string the SDK uses
/// when reading the entry back from `/sync`.
#[test]
fn read_receipt_account_data_key_matches_spec() {
    assert_eq!(READ_RECEIPT_ACCOUNT_DATA_KEY, "ck.read_receipt.preferences");
}

#[test]
fn presence_visibility_account_data_matches_spec() {
    assert_eq!(
        PRESENCE_VISIBILITY_ACCOUNT_DATA_KEY,
        "ck.presence.visibility"
    );
    let hidden = build_presence_visibility_body(crate::local_state::PresenceVisibility::Nobody);
    assert_eq!(hidden["presence_visibility"], "nobody");
    let public = build_presence_visibility_body(crate::local_state::PresenceVisibility::Public);
    assert_eq!(public["presence_visibility"], "public");
}

#[test]
fn presence_preference_account_data_matches_spec() {
    assert_eq!(
        PRESENCE_PREFERENCE_ACCOUNT_DATA_KEY,
        "ck.presence.preference"
    );
    let body = build_presence_preference_body(&crate::local_state::PresencePreferenceState {
        manual_state: Some("dnd".to_owned()),
        status_message: Some("In a meeting".to_owned()),
        clears_at: Some("2026-07-03T12:00:00Z".to_owned()),
    });
    assert_eq!(body["manual_state"], "dnd");
    assert_eq!(body["status_message"], "In a meeting");
    assert_eq!(body["clears_at"], "2026-07-03T12:00:00Z");
    // Absent fields stay absent (delta-friendly payload).
    let empty = build_presence_preference_body(&Default::default());
    assert!(empty.as_object().unwrap().is_empty());
}

#[test]
fn presence_expiry_choice_resolves_to_future_clears_at() {
    assert_eq!(presence_expiry_to_clears_at("never"), None);
    for choice in ["30m", "1h", "today"] {
        let clears_at = presence_expiry_to_clears_at(choice)
            .unwrap_or_else(|| panic!("{choice} must resolve to a clears_at"));
        let parsed: chrono::DateTime<chrono::Utc> = clears_at
            .parse()
            .unwrap_or_else(|_| panic!("{choice} clears_at must be RFC 3339 UTC: {clears_at}"));
        assert!(
            parsed > chrono::Utc::now(),
            "{choice} must be in the future"
        );
    }
}

#[test]
fn blocklist_account_data_key_matches_spec() {
    assert_eq!(CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY, "ck.account.blocklist");
}

#[test]
fn default_avatar_initial_prefers_handle_then_did() {
    assert_eq!(
        default_avatar_initial(&["alice".to_owned()], "did:web:example.test"),
        "A"
    );
    assert_eq!(default_avatar_initial(&[], "did:web:bob.example"), "B");
    assert_eq!(
        default_avatar_initial(&[], "did:web:acme.example:users:bob"),
        "B"
    );
    assert_eq!(
        default_avatar_initial(&["org:example.com".to_owned()], "did:web:bob.example"),
        "B"
    );
    assert_eq!(
        default_avatar_initial(
            &["org:example.com".to_owned()],
            "did:web:acme.example:users:bob"
        ),
        "B"
    );
}

#[test]
fn default_avatar_tone_is_stable_and_bounded() {
    let handles = vec!["alice".to_owned()];
    let first = default_avatar_tone(&handles, "did:web:example.test");
    let second = default_avatar_tone(&handles, "did:web:example.test");
    assert_eq!(first, second);
    assert!((1..=6).contains(&first));
}
