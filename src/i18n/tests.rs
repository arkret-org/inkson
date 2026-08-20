//! Unit tests for the i18n module. `use super::*` brings the locale builders
//! and helpers re-exported by `mod.rs` into scope.
//!
//! Tag parsing and the resolution order are `arkret-locale`'s contract and are
//! tested there. What is asserted here is inkson's side of the seam: that the
//! dictionaries cover the shipped locales, that the lookup chain falls back the
//! way the UI depends on, and that the formatters agree with the enum.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::*;

#[test]
fn every_shipped_locale_has_a_dictionary() {
    // A locale the shared crate advertises but this client cannot render would
    // show raw keys, so the two sets must not drift apart.
    let signal_dicts = {
        let mut dicts = HashMap::new();
        dicts.insert(Locale::En.code().to_owned(), english_translations());
        dicts.insert(Locale::Zh.code().to_owned(), chinese_translations());
        dicts
    };
    for locale in arkret_locale::SUPPORTED {
        assert!(
            signal_dicts.contains_key(locale.code()),
            "no dictionary for {}",
            locale.code()
        );
    }
    assert_eq!(signal_dicts.len(), arkret_locale::SUPPORTED.len());
}

#[test]
fn translate_chain_walks_region_then_base_then_english() {
    // Region-tagged dictionaries are not shipped, but the chain still has to
    // handle a raw BCP 47 tag: `set_locale` stores a `Locale`, while a caller
    // holding a tag from the wire can reach `translate_chain` directly.
    let mut dicts = HashMap::new();
    let mut zh_cn = TranslationDict::new(Locale::Zh);
    zh_cn.set("region.specific", "zh-CN value");
    let mut zh = TranslationDict::new(Locale::Zh);
    zh.set("base.value", "zh value");
    let mut en = TranslationDict::new(Locale::En);
    en.set("english.only", "en value");
    dicts.insert("zh-CN".to_owned(), zh_cn);
    dicts.insert("zh".to_owned(), zh);
    dicts.insert("en".to_owned(), en);

    assert_eq!(
        translate_chain("zh-CN", &dicts, "region.specific"),
        "zh-CN value"
    );
    assert_eq!(translate_chain("zh-CN", &dicts, "base.value"), "zh value");
    assert_eq!(translate_chain("zh-CN", &dicts, "english.only"), "en value");

    // Missing everywhere → returns the key itself and records the miss.
    assert_eq!(
        translate_chain("zh-CN", &dicts, "nothing.here"),
        "nothing.here"
    );
    assert!(
        missing_translation_snapshot()
            .iter()
            .any(|(tag, key)| tag == "zh-CN" && key == "nothing.here"),
        "the miss should be reported so QA can grow the dictionaries"
    );
}

#[test]
fn locale_direction_matches_layout_expectations() {
    // Both shipped locales are left-to-right. `TextDirection` is kept so the
    // shell's mirrored-layout branch stays wired up for a future RTL locale.
    assert_eq!(Locale::En.direction(), TextDirection::Ltr);
    assert_eq!(Locale::Zh.direction(), TextDirection::Ltr);
    assert_eq!(TextDirection::Ltr.as_str(), "ltr");
    assert_eq!(TextDirection::Rtl.as_str(), "rtl");
}

#[test]
fn a_stored_device_preference_survives_a_restart() {
    // The device cache is the only tier available before sign-in, so a user
    // who picked Chinese must still get Chinese on the next launch.
    assert_eq!(resolve_locale(None, Some("zh")), Locale::Zh);
    assert_eq!(resolve_locale(None, Some("en")), Locale::En);
}

#[test]
fn the_account_preference_overrides_a_stale_device_cache() {
    // This is the whole point of the account tier: signing in on a device that
    // was left in English must switch to the account's language.
    assert_eq!(resolve_locale(Some("zh"), Some("en")), Locale::Zh);
    assert_eq!(resolve_locale(Some("en"), Some("zh")), Locale::En);
}

#[test]
fn an_unrenderable_stored_value_does_not_pin_the_ui() {
    // A device cache written by an older build (which persisted `ar` / `ja`)
    // must fall through instead of selecting a dictionary that no longer
    // exists.
    for stale in ["ar", "ja-JP", "fr", "", "garbage"] {
        assert_eq!(resolve_locale(None, Some(stale)), Locale::En, "{stale}");
    }
}

#[test]
fn translation_lookup_fallback() {
    let mut dicts = HashMap::new();
    dicts.insert("en".to_owned(), english_translations());
    dicts.insert("zh".to_owned(), chinese_translations());

    assert_eq!(translate(Locale::Zh, &dicts, "login.server"), "服务器");

    // Fallback to English for a key the Chinese dictionary is missing.
    let partial_dicts = {
        let mut partial = HashMap::new();
        let mut zh_partial = TranslationDict::new(Locale::Zh);
        zh_partial.set("login.server", "服务器");
        partial.insert("en".to_owned(), english_translations());
        partial.insert("zh".to_owned(), zh_partial);
        partial
    };
    assert_eq!(
        translate(Locale::Zh, &partial_dicts, "login.passkey"),
        "Passkey Login"
    );

    // Fallback to the key itself when it is nowhere.
    assert_eq!(
        translate(Locale::En, &HashMap::new(), "nonexistent.key"),
        "nonexistent.key"
    );
}

#[test]
fn locale_formatters_are_stable() {
    let timestamp = DateTime::parse_from_rfc3339("2026-04-29T07:08:09.000Z")
        .unwrap()
        .with_timezone(&Utc);

    assert_eq!(
        format_datetime(Locale::En, timestamp),
        "Apr 29, 2026 07:08 UTC"
    );
    assert_eq!(
        format_datetime(Locale::Zh, timestamp),
        "2026年04月29日 07:08 UTC"
    );
    assert_eq!(format_number(Locale::En, 1234567), "1,234,567");
    assert_eq!(format_number(Locale::Zh, 1234567), "1 234 567");
}

#[test]
fn chinese_translation_is_complete() {
    let en = english_translations();
    let zh = chinese_translations();
    let report = translation_completeness(&en, &zh);
    assert_eq!(report.locale, Locale::Zh);
    assert_eq!(report.total_keys, en.strings.len());
    assert!(
        report.is_complete(),
        "missing keys: {:?}",
        report.missing_keys
    );

    // Both directions: a zh-only key renders as a raw key for English users,
    // so the dictionaries must not drift apart in either direction.
    let reverse = translation_completeness(&zh, &en);
    assert!(
        reverse.is_complete(),
        "zh-only keys: {:?}",
        reverse.missing_keys
    );

    let complete = translation_completeness(&en, &en);
    assert!(complete.is_complete());
}
