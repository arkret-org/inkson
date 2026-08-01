//! The client half of "both apps change together".
//!
//! Two tiers carry a language choice off this device:
//!
//! * `client.language` account data — the user's other inkson devices, via
//!   the principal server. Actor-private, so it is not on `ActorProfile`.
//! * the OIDC `ui_locales` parameter — coauth, on the next sign-in, built
//!   from the same device preference this module resolves.
//!
//! An integration test rather than a unit test: the lib test target does not
//! currently compile (pre-existing SDK drift in `did_binding` / `did_resolver`
//! / `webrtc` / `read_receipts`, none of it locale-related), and an
//! integration test only needs the lib to build.

use inkson::account_data::{
    AccountDataKey, CLIENT_LANGUAGE_WIRE_KEY, build_client_language_body, merge_client_language,
};
use inkson::i18n::{Locale, resolve_locale};
use serde_json::json;

#[test]
fn the_declared_account_data_key_round_trips() {
    // The key was declared and never used, so nothing ever proved the wire
    // string and the enum agreed.
    assert_eq!(
        AccountDataKey::ClientLanguage.as_wire(),
        CLIENT_LANGUAGE_WIRE_KEY
    );
    assert_eq!(
        AccountDataKey::from_wire(CLIENT_LANGUAGE_WIRE_KEY),
        AccountDataKey::ClientLanguage
    );
    assert_eq!(
        AccountDataKey::ClientLanguage.as_wire_static(),
        Some(CLIENT_LANGUAGE_WIRE_KEY)
    );
    assert_eq!(
        AccountDataKey::Custom("x.y".to_owned()).as_wire_static(),
        None,
        "a custom key owns its string and has no 'static form"
    );
}

#[test]
fn a_choice_made_on_another_device_switches_this_one() {
    let published = build_client_language_body(Locale::Zh);
    assert_eq!(merge_client_language(Locale::En, &published), Some(Locale::Zh));
}

#[test]
fn a_device_already_in_the_synced_language_does_not_churn() {
    let published = build_client_language_body(Locale::Zh);
    assert_eq!(merge_client_language(Locale::Zh, &published), None);
}

#[test]
fn an_entry_from_a_build_that_shipped_more_locales_is_ignored() {
    // Older builds carried `ar` / `es` / `ja` / `fr` with partial catalogues.
    // Selecting one now would render raw keys, so the local value must win.
    for tag in ["ar", "es", "ja", "fr"] {
        assert_eq!(
            merge_client_language(Locale::En, &json!({ "locale": tag })),
            None,
            "{tag}"
        );
    }
}

#[test]
fn the_account_tier_outranks_this_devices_cache() {
    // Signing in on a device left in English must adopt the account language.
    assert_eq!(resolve_locale(Some("zh"), Some("en")), Locale::Zh);
    assert_eq!(resolve_locale(Some("en"), Some("zh")), Locale::En);
}

#[test]
fn the_device_cache_still_governs_before_sign_in() {
    // Boot runs before the session is restored, so this is the tier that keeps
    // the first paint in the right language.
    assert_eq!(resolve_locale(None, Some("zh")), Locale::Zh);
    assert_eq!(resolve_locale(None, Some("zh-Hans")), Locale::Zh);
}

#[test]
fn an_unrenderable_stored_preference_falls_through_instead_of_pinning() {
    for stale in ["ja", "", "   ", "not-a-tag"] {
        assert_eq!(resolve_locale(None, Some(stale)), Locale::En, "{stale}");
    }
}

#[test]
fn the_code_sent_as_ui_locales_is_one_coauth_accepts() {
    // `ui_locales` is built from `Locale::code()`. coauth resolves it with the
    // same crate, so anything this produces must parse back identically —
    // otherwise the hand-off silently degrades to the browser's language.
    for locale in arkret_locale::SUPPORTED {
        assert_eq!(arkret_locale::UiLocale::from_tag(locale.code()), Some(locale));
        assert_eq!(
            arkret_locale::UiLocale::from_tag_list(locale.code()),
            Some(locale)
        );
    }
}
