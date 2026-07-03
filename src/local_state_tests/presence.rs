//! Presence visibility preference persistence.

use super::*;

#[test]
fn presence_visibility_defaults_to_public_and_persists() {
    let path = temp_state_path("presence-visibility");
    let mut store = LocalStateStore::with_path(path.clone());
    assert_eq!(store.presence_visibility(), PresenceVisibility::Public);
    assert!(store.presence_should_send());

    store.set_presence_visibility(PresenceVisibility::Nobody);
    assert!(!store.presence_should_send());

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.presence_visibility(), PresenceVisibility::Nobody);
    assert!(!reader.presence_should_send());
}

#[test]
fn presence_preference_persists_and_expires() {
    let path = temp_state_path("presence-preference");
    let mut store = LocalStateStore::with_path(path.clone());
    assert!(store.presence_preference().is_empty());

    store.set_presence_preference(PresencePreferenceState {
        manual_state: Some("dnd".to_owned()),
        status_message: Some("In a meeting".to_owned()),
        clears_at: Some("2026-07-03T12:00:00Z".to_owned()),
    });

    let reader = LocalStateStore::with_path(path);
    let preference = reader.presence_preference();
    let before: chrono::DateTime<chrono::Utc> = "2026-07-03T11:59:59Z".parse().unwrap();
    let after: chrono::DateTime<chrono::Utc> = "2026-07-03T12:00:00Z".parse().unwrap();
    assert_eq!(preference.effective_manual_state(before), Some("dnd"));
    assert_eq!(
        preference.effective_status_message(before),
        Some("In a meeting")
    );
    assert_eq!(preference.next_clears_at(before), Some(after));
    // Past clears_at the whole preference reads as absent.
    assert_eq!(preference.effective_manual_state(after), None);
    assert_eq!(preference.effective_status_message(after), None);
    assert_eq!(preference.next_clears_at(after), None);
}

#[test]
fn presence_preference_fails_closed_on_bad_values() {
    // `offline` is not a pinnable manual state.
    let offline = PresencePreferenceState {
        manual_state: Some("offline".to_owned()),
        ..Default::default()
    };
    let now = chrono::Utc::now();
    assert_eq!(offline.effective_manual_state(now), None);
    // A corrupted clears_at expires the preference instead of pinning it.
    let corrupted = PresencePreferenceState {
        manual_state: Some("dnd".to_owned()),
        status_message: None,
        clears_at: Some("not-a-timestamp".to_owned()),
    };
    assert_eq!(corrupted.effective_manual_state(now), None);
}
