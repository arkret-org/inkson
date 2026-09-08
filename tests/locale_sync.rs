//! The client half of "both apps change together".
//!
//! Two tiers carry a language choice off this device:
//!
//! * the `language` field of the `ak.client.ui_state` account-data cell (spec
//!   `discovery/client-preferences.md` §3.4) — the user's other inkson devices, via the principal
//!   server. Actor-private, so it is not on `ActorProfile`.
//! * the OIDC `ui_locales` parameter — coauth, on the next sign-in, built from the same device
//!   preference this module resolves.
//!
//! An integration test rather than a unit test because it exercises the two
//! tiers across their public surface (`inkson::account_data` and
//! `inkson::i18n`) the way coauth and the settings view reach them.

use inkson::account_data::{merge_client_ui_language, set_client_ui_language};
use inkson::i18n::{UiLocale, resolve_locale};
use serde_json::json;

fn published_ui_state_with_language(locale: UiLocale) -> serde_json::Value {
    let mut body = json!({"theme": "night"});
    set_client_ui_language(&mut body, locale);
    body
}

#[test]
fn a_choice_made_on_another_device_switches_this_one() {
    let published = published_ui_state_with_language(UiLocale::Zh);
    assert_eq!(
        merge_client_ui_language(UiLocale::En, &published),
        Some(UiLocale::Zh)
    );
}

#[test]
fn setting_the_language_preserves_the_other_ui_state_fields() {
    // The write path is read-merge-write on the shared cell: theme and any
    // sibling field must survive a language update.
    let published = published_ui_state_with_language(UiLocale::Zh);
    assert_eq!(published.get("theme"), Some(&json!("night")));
    assert_eq!(published.get("language"), Some(&json!("zh")));
}

#[test]
fn a_region_variant_from_another_client_folds_onto_the_base() {
    // The spec example carries `zh-CN`; the canonical base tag is what this
    // build can render.
    assert_eq!(
        merge_client_ui_language(UiLocale::En, &json!({ "language": "zh-CN" })),
        Some(UiLocale::Zh)
    );
}

#[test]
fn a_device_already_in_the_synced_language_does_not_churn() {
    let published = published_ui_state_with_language(UiLocale::Zh);
    assert_eq!(merge_client_ui_language(UiLocale::Zh, &published), None);
}

#[test]
fn an_entry_from_a_build_that_shipped_more_locales_is_ignored() {
    // Older builds carried `ar` / `es` / `ja` / `fr` with partial catalogues.
    // Selecting one now would render raw keys, so the local value must win.
    for tag in ["ar", "es", "ja", "fr"] {
        assert_eq!(
            merge_client_ui_language(UiLocale::En, &json!({ "language": tag })),
            None,
            "{tag}"
        );
    }
}

#[test]
fn a_cell_without_a_language_field_keeps_the_local_locale() {
    // Cells written before this field existed carry only theme etc.
    let published = json!({"theme": "night"});
    assert_eq!(merge_client_ui_language(UiLocale::Zh, &published), None);
}

#[test]
fn the_account_tier_outranks_this_devices_cache() {
    // Signing in on a device left in English must adopt the account language.
    assert_eq!(resolve_locale(Some("zh"), Some("en")), UiLocale::Zh);
    assert_eq!(resolve_locale(Some("en"), Some("zh")), UiLocale::En);
}

#[test]
fn the_device_cache_still_governs_before_sign_in() {
    // Boot runs before the session is restored, so this is the tier that keeps
    // the first paint in the right language.
    assert_eq!(resolve_locale(None, Some("zh")), UiLocale::Zh);
    assert_eq!(resolve_locale(None, Some("zh-Hans")), UiLocale::Zh);
}

#[test]
fn an_unrenderable_stored_preference_falls_through_instead_of_pinning() {
    for stale in ["ja", "", "   ", "not-a-tag"] {
        assert_eq!(resolve_locale(None, Some(stale)), UiLocale::En, "{stale}");
    }
}

#[test]
fn the_code_sent_as_ui_locales_is_one_coauth_accepts() {
    // `ui_locales` is built from `UiLocale::code()`. coauth resolves it with the
    // same crate, so anything this produces must parse back identically —
    // otherwise the hand-off silently degrades to the browser's language.
    for locale in arkret_locale::SUPPORTED {
        assert_eq!(
            arkret_locale::UiLocale::from_tag(locale.code()),
            Some(locale)
        );
        assert_eq!(
            arkret_locale::UiLocale::from_tag_list(locale.code()),
            Some(locale)
        );
    }
}
