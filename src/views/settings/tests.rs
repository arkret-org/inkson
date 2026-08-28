use std::collections::BTreeMap;

use arkret_wire::AccountDataKey;

use super::*;

/// The canonical `ak.read_receipt.preferences` body shape other devices
/// read via `/sync` account_data. Locks the SDK/spec field names so a
/// future rename can't silently desync devices.
#[test]
fn build_read_receipt_preferences_body_has_canonical_field_shape() {
    let mut realms = BTreeMap::new();
    realms.insert(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned(),
        false,
    );
    let mut realm_display = BTreeMap::new();
    realm_display.insert(
        "ak:realm:Amyag-8FjKfvmYVDNWCcq40yrNEySc6GQggxhVlZeI0w".to_owned(),
        false,
    );
    let mut strands = BTreeMap::new();
    strands.insert(
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q".to_owned(),
        true,
    );
    let mut strand_display = BTreeMap::new();
    strand_display.insert(
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q".to_owned(),
        false,
    );
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
    assert_eq!(
        body["realms"]["ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"]["send"],
        false
    );
    assert_eq!(
        body["realms"]["ak:realm:Amyag-8FjKfvmYVDNWCcq40yrNEySc6GQggxhVlZeI0w"]["display"],
        false
    );
    assert_eq!(
        body["strands"]["ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q"]["send"],
        true
    );
    assert_eq!(
        body["strands"]["ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q"]["display"],
        false
    );
}

/// account-data key is the exact spec key — same string the SDK uses
/// when reading the entry back from `/sync`.
#[test]
fn read_receipt_account_data_key_matches_spec() {
    assert_eq!(
        AccountDataKey::READ_RECEIPT_PREFERENCES,
        "ak.read_receipt.preferences"
    );
}

#[test]
fn presence_visibility_account_data_matches_spec() {
    assert_eq!(
        AccountDataKey::PRESENCE_VISIBILITY,
        "ak.presence.visibility"
    );
    let hidden = build_presence_visibility_body(crate::state::PresenceVisibility::Nobody);
    assert_eq!(hidden["presence_visibility"], "nobody");
    let public = build_presence_visibility_body(crate::state::PresenceVisibility::Public);
    assert_eq!(public["presence_visibility"], "public");
}

#[test]
fn presence_preference_account_data_matches_spec() {
    assert_eq!(
        AccountDataKey::PRESENCE_PREFERENCE,
        "ak.presence.preference"
    );
    let body = build_presence_preference_body(&crate::state::PresencePreference {
        manual_state: Some(arkret_sdk::PresenceStatus::Dnd),
        status_message: Some("In a meeting".to_owned()),
        clears_at: Some("2026-07-03T12:00:00.000Z".parse().unwrap()),
    });
    assert_eq!(body["manual_state"], "dnd");
    assert_eq!(body["status_message"], "In a meeting");
    assert_eq!(body["clears_at"], "2026-07-03T12:00:00.000Z");
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
        assert!(
            clears_at > chrono::Utc::now(),
            "{choice} must be in the future"
        );
    }
}

#[test]
fn blocklist_account_data_key_matches_spec() {
    assert_eq!(AccountDataKey::ACCOUNT_BLOCKLIST, "ak.account.blocklist");
}
