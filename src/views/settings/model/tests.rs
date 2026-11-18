use super::*;
use crate::notification_rules::{DndPeriod, DndSchedule, DndSettings};
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    notification_rules::parse_dnd_settings, state::LocalStateStore,
    views::settings::account_data::save_dnd_edits,
};

#[test]
fn contact_permissions_are_available_in_privacy_settings() {
    assert_eq!(
        SettingsSection::from_slug(Some("contacts")),
        SettingsSection::Contacts
    );
    let groups = visible_nav_groups("Contact permissions");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].label_key, "settings.group.privacy");
    assert_eq!(groups[0].sections, vec![SettingsSection::Contacts]);
}

fn dnd(enabled: bool, periods: Vec<DndPeriod>) -> DndSettings {
    DndSettings {
        enabled,
        schedule: DndSchedule {
            timezone: "Europe/Berlin".to_owned(),
            tzdb_version: crate::notification_rules::DND_TZDB_VERSION.to_owned(),
            all_day: false,
            periods,
        },
        exceptions: Vec::new(),
    }
}

#[test]
fn empty_nav_query_keeps_every_group() {
    let groups = visible_nav_groups("");
    assert_eq!(groups.len(), SETTINGS_NAV_GROUPS.len());
    let total: usize = groups.iter().map(|group| group.sections.len()).sum();
    let expected: usize = SETTINGS_NAV_GROUPS
        .iter()
        .map(|(_, _, sections)| sections.len())
        .sum();
    assert_eq!(total, expected);
}

#[test]
fn nav_query_drops_groups_with_no_surviving_section() {
    let groups = visible_nav_groups("devices");
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0].sections,
        vec![SettingsSection::Devices, SettingsSection::Recovery]
    );
    assert_eq!(groups[0].label_key, "settings.group.security");
}

#[test]
fn nav_query_is_case_insensitive_and_trimmed() {
    // The search box matches the localized label the reader sees, so a
    // capitalized or padded query must behave like the plain one.
    let plain = visible_nav_groups("devices");
    for query in ["  Devices ", "DEVICES"] {
        let padded = visible_nav_groups(query);
        assert_eq!(padded.len(), plain.len(), "query {query:?}");
        assert_eq!(padded[0].sections, plain[0].sections, "query {query:?}");
    }
}

#[test]
fn nav_query_with_no_match_renders_no_groups() {
    assert!(visible_nav_groups("no-such-section").is_empty());
}

#[test]
fn nav_query_finds_localized_controls_inside_sections() {
    for (query, section) in [
        ("language", SettingsSection::Theme),
        ("dark", SettingsSection::Theme),
        ("display name", SettingsSection::Account),
        ("sound", SettingsSection::Notifications),
        ("recovery 24", SettingsSection::Recovery),
    ] {
        let groups = visible_nav_groups(query);
        assert!(
            groups.iter().any(|group| group.sections.contains(&section)),
            "{query}"
        );
    }
    assert!(visible_nav_groups("language sound").is_empty());
}

#[test]
fn expired_presence_preference_seeds_an_empty_editor() {
    // An expired manual state must not be re-offered: the server has already
    // stopped honouring it, so showing it would misreport the account.
    let preference = PresencePreference {
        manual_state: Some(arkret_sdk::ManualPresenceState::Dnd),
        status_message: Some("heads down".to_owned()),
        clears_at: Some("2026-01-01T00:00:00Z".parse().unwrap()),
    };
    let seed = presence_editor_seed(&preference, "2026-06-01T00:00:00Z".parse().unwrap());
    assert_eq!(seed.manual_state, "auto");
    assert_eq!(seed.status_message, "");
}

#[test]
fn unexpired_presence_preference_seeds_the_saved_state() {
    let preference = PresencePreference {
        manual_state: Some(arkret_sdk::ManualPresenceState::Dnd),
        status_message: Some("heads down".to_owned()),
        clears_at: Some("2026-12-01T00:00:00Z".parse().unwrap()),
    };
    let seed = presence_editor_seed(&preference, "2026-06-01T00:00:00Z".parse().unwrap());
    assert_eq!(
        seed.manual_state,
        arkret_sdk::ManualPresenceState::Dnd.as_wire()
    );
    assert_eq!(seed.status_message, "heads down");
}

#[test]
fn presence_preference_without_expiry_stays_active() {
    let preference = PresencePreference {
        manual_state: Some(arkret_sdk::ManualPresenceState::Dnd),
        ..Default::default()
    };
    let seed = presence_editor_seed(&preference, "2099-01-01T00:00:00Z".parse().unwrap());
    assert_eq!(
        seed.manual_state,
        arkret_sdk::ManualPresenceState::Dnd.as_wire()
    );
}

#[test]
fn absent_presence_preference_seeds_auto() {
    let seed = presence_editor_seed(
        &PresencePreference::default(),
        "2026-06-01T00:00:00Z".parse().unwrap(),
    );
    assert_eq!(seed.manual_state, "auto");
    assert_eq!(seed.status_message, "");
}

#[test]
fn dnd_seed_is_off_without_persisted_settings() {
    let seed = dnd_editor_seed(None);
    assert!(!seed.enabled);
    assert_eq!(seed.mode, "off");
}

#[test]
fn dnd_enabled_without_periods_is_still_mode_off() {
    let settings = dnd(true, Vec::new());
    let seed = dnd_editor_seed(Some(&settings));
    assert!(seed.enabled);
    assert_eq!(seed.mode, "off");
}

#[cfg(not(target_arch = "wasm32"))]
fn dnd_store() -> (tempfile::TempDir, LocalStateStore, arkret_sdk::AccountId) {
    let directory = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(directory.path().join("state.json"));
    store.switch_test_account("did:web:alice.example");
    let authority = store.active_authority().unwrap();
    (directory, store, authority)
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn saved_all_day_dnd_reopens_as_now() {
    let (_directory, mut store, authority) = dnd_store();
    let (body, _) = save_dnd_edits(&mut store, &authority, Some(true), Some(true))
        .unwrap()
        .unwrap();
    let saved = parse_dnd_settings(&body).unwrap();
    assert!(saved.schedule.all_day && saved.schedule.periods.is_empty());
    let seed = dnd_editor_seed(Some(&saved));
    assert!(seed.enabled);
    assert_eq!(seed.mode, "now");
    assert_eq!(
        save_dnd_edits(&mut store, &authority, None, None)
            .unwrap()
            .unwrap(),
        (body, true)
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn saving_dnd_preserves_current_account_periods_and_exceptions() {
    let (_directory, mut store, authority) = dnd_store();
    let initial = dnd(false, Vec::new());
    store.set_notification_dnd_settings(Some(initial));
    assert_eq!(
        dnd_editor_seed(store.notification_dnd_settings().as_ref()).mode,
        "off"
    );

    // The account sync refreshes the untouched schedule while the editor is open.
    let mut settings = dnd(
        true,
        vec![DndPeriod {
            start: "22:00".to_owned(),
            end: "07:00".to_owned(),
        }],
    );
    settings.exceptions = vec!["override.priority".to_owned()];
    store.set_notification_dnd_settings(Some(settings.clone()));
    let seed = dnd_editor_seed(store.notification_dnd_settings().as_ref());
    assert!(seed.enabled);
    assert_eq!(seed.mode, "scheduled");
    let mut expected = settings.clone();
    for enabled in [false, true] {
        let (body, _) = save_dnd_edits(&mut store, &authority, Some(enabled), None)
            .unwrap()
            .unwrap();
        let saved = parse_dnd_settings(&body).unwrap();
        expected.enabled = enabled;
        assert_eq!(saved, expected);
        assert_eq!(dnd_editor_seed(Some(&saved)).mode, "scheduled");
    }
    let (body, _) = save_dnd_edits(&mut store, &authority, None, Some(true))
        .unwrap()
        .unwrap();
    let changed = parse_dnd_settings(&body).unwrap();
    assert!(changed.schedule.all_day && changed.schedule.periods.is_empty());
    assert_eq!(changed.schedule.timezone, settings.schedule.timezone);
    assert_eq!(changed.exceptions, settings.exceptions);

    store.switch_test_account("did:web:bob.example");
    assert!(
        save_dnd_edits(&mut store, &authority, Some(true), Some(true))
            .unwrap()
            .is_none()
    );
    assert!(store.notification_dnd_settings().is_none());
}

#[test]
fn signed_out_identity_labels_do_not_show_a_principal_or_device_id() {
    let labels = session_identity_labels(
        false,
        "ak:did_core:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
        &[],
        "unknown",
    );
    assert_eq!(labels.principal, "Not signed in");
    assert_eq!(labels.device, "No authenticated device session");
    assert!(!labels.principal.contains("alice.example"));
    assert!(!labels.device.contains("ak:device:"));
}

#[test]
fn handle_label_and_title_agree_when_there_are_no_handles() {
    let labels = session_identity_labels(
        true,
        "ak:did_core:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
        &[],
        "no handles yet",
    );
    assert_eq!(labels.handles_label, "no handles yet");
    assert_eq!(labels.handles_title, labels.handles_label);
}

#[test]
fn handle_label_and_title_preserve_canonical_handles() {
    let handles = ["alice:example.com".to_owned(), "a:example.com".to_owned()];
    let labels = session_identity_labels(
        true,
        "ak:did_core:web:alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
        &handles,
        "unused",
    );
    assert_eq!(labels.handles_label, "alice:example.com, a:example.com");
    assert_eq!(labels.handles_title, labels.handles_label);
}
