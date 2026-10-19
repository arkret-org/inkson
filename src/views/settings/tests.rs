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
        manual_state: Some(arkret_sdk::ManualPresenceState::Dnd),
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

#[cfg(not(target_arch = "wasm32"))]
fn picker_store() -> crate::state::LocalStateStore {
    crate::state::LocalStateStore::with_path(std::env::temp_dir().join(format!(
            "inkson-realm-picker-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )))
}

#[cfg(not(target_arch = "wasm32"))]
fn picker_realm(byte: u8) -> String {
    arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [byte; 32],
    ))
    .to_string()
}

#[cfg(not(target_arch = "wasm32"))]
fn apply_picker_rows(store: &mut crate::state::LocalStateStore, rows: Vec<Value>) {
    let frame = serde_json::from_value(json!({
        "kind": "delta", "cursor": "ak:cursor:YQ",
        "realm_list_changes": {"upserts": rows, "removals": []}
    }))
    .unwrap();
    let accepted = store.prepare_account_demand_frame(&frame).unwrap();
    store.finish_account_demand_frame(&accepted).unwrap();
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn realm_picker_uses_current_joined_rows_and_distinguishes_same_names() {
    let mut store = picker_store();
    let realm_a = picker_realm(1);
    let realm_b = picker_realm(2);
    let realm_historical = picker_realm(3);
    let (a, b, historical) = (
        realm_a.as_str(),
        realm_b.as_str(),
        realm_historical.as_str(),
    );
    store.set_realm_watch_level(historical.to_owned(), WatchLevel::Muted);
    store.set_read_receipt_realm_override(historical.to_owned(), Some(false));
    apply_picker_rows(
        &mut store,
        vec![a, b]
            .into_iter()
            .map(|id| {
                json!({
                    "realm_id": id, "revision": 1, "activity_position": 1,
                    "membership": "join", "title": "Engineering"
                })
            })
            .collect(),
    );
    let options = preference_realm_options(&store);
    assert_eq!(options.len(), 2);
    assert_ne!(options[0].1, options[1].1);
    for (id, label) in &options {
        assert!(label.contains("Engineering"));
        assert!(label.contains(id));
    }
    assert!(selected_realm_id(&options, historical).is_none());
    assert!(
        store
            .read_receipt_realm_overrides()
            .contains_key(historical)
    );
    assert!(selected_realm_id(&options, a).is_some());
    assert!(selected_realm_id(&options, "Engineering").is_none());
    assert!(selected_realm_id(&options, "0").is_none());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn realm_picker_does_not_replace_selection_after_membership_changes() {
    let mut store = picker_store();
    let realm_a = picker_realm(1);
    let realm_b = picker_realm(2);
    let (a, b) = (realm_a.as_str(), realm_b.as_str());
    apply_picker_rows(
        &mut store,
        vec![a, b]
            .into_iter()
            .map(|id| {
                json!({
                    "realm_id": id, "revision": 1, "activity_position": 1,
                    "membership": "join", "title": "Realm"
                })
            })
            .collect(),
    );
    assert!(selected_realm_id(&preference_realm_options(&store), a).is_some());
    apply_picker_rows(
        &mut store,
        vec![json!({
            "realm_id": a, "revision": 2, "activity_position": 1,
            "membership": "knock", "title": "Realm"
        })],
    );
    let options = preference_realm_options(&store);
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].0, b);
    assert!(selected_realm_id(&options, a).is_none());
    assert!(selected_realm_id(&options, "").is_none());
    assert!(preference_realm_options(&picker_store()).is_empty());
}
