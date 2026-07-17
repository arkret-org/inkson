//! Unit tests for the i18n module. Moved verbatim out of the former
//! inline `mod tests` block; `use super::*` brings the locale builders
//! and helpers re-exported by `mod.rs` into scope.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::*;

#[test]
fn locale_from_code() {
    assert_eq!(Locale::from_code("en"), Locale::En);
    assert_eq!(Locale::from_code("zh"), Locale::Zh);
    assert_eq!(Locale::from_code("zh-CN"), Locale::Zh);
    assert_eq!(Locale::from_code("ar"), Locale::Ar);
    // Phase D.2 #8: `fr`, `es`, `ja` are first-class now.
    assert_eq!(Locale::from_code("fr"), Locale::Fr);
    assert_eq!(Locale::from_code("fr-CA"), Locale::Fr);
    assert_eq!(Locale::from_code("es"), Locale::Es);
    assert_eq!(Locale::from_code("es-MX"), Locale::Es);
    assert_eq!(Locale::from_code("ja"), Locale::Ja);
    assert_eq!(Locale::from_code("ja-JP"), Locale::Ja);
    // ar-SA collapses to ar (entry point of the
    // `ar-SA → ar → en` chain in `translate_chain`).
    assert_eq!(Locale::from_code("ar-SA"), Locale::Ar);
    // Unknown locale still falls back to English.
    assert_eq!(Locale::from_code("xx"), Locale::En);
}

#[test]
fn translate_chain_walks_region_then_base_then_english() {
    // Phase D.2 #8: `ar-SA → ar → en` lookup chain.
    let mut dicts = HashMap::new();
    let mut ar_sa = TranslationDict::new(Locale::Ar);
    ar_sa.set("region.specific", "ar-SA value");
    let mut ar = TranslationDict::new(Locale::Ar);
    ar.set("base.value", "ar value");
    let mut en = TranslationDict::new(Locale::En);
    en.set("english.only", "en value");
    dicts.insert("ar-SA".to_owned(), ar_sa);
    dicts.insert("ar".to_owned(), ar);
    dicts.insert("en".to_owned(), en);
    // Region-specific value wins.
    assert_eq!(
        translate_chain("ar-SA", &dicts, "region.specific"),
        "ar-SA value"
    );
    // Base value picked up via `ar-SA → ar`.
    assert_eq!(translate_chain("ar-SA", &dicts, "base.value"), "ar value");
    // English fallback via `ar-SA → ar → en`.
    assert_eq!(translate_chain("ar-SA", &dicts, "english.only"), "en value");
    // Missing everywhere → returns the key itself + records the miss.
    let _ = missing_translation_snapshot(); // ensure helper compiles
    assert_eq!(
        translate_chain("ar-SA", &dicts, "nothing.here"),
        "nothing.here"
    );
}

#[test]
fn locale_direction_matches_layout_expectations() {
    assert_eq!(Locale::En.direction(), TextDirection::Ltr);
    assert_eq!(Locale::Zh.direction(), TextDirection::Ltr);
    assert_eq!(Locale::Ar.direction(), TextDirection::Rtl);
    assert_eq!(Locale::Ar.direction().as_str(), "rtl");
}

#[test]
fn product_ui_locale_is_limited_to_english_and_chinese() {
    assert_eq!(Locale::En.product_ui(), Locale::En);
    assert_eq!(Locale::Zh.product_ui(), Locale::Zh);
    for locale in [Locale::Ar, Locale::Es, Locale::Ja, Locale::Fr] {
        assert_eq!(locale.product_ui(), Locale::En);
    }
}

#[test]
fn translation_lookup_fallback() {
    let mut dicts = HashMap::new();
    let en = english_translations();
    let zh = chinese_translations();
    dicts.insert("en".to_owned(), en);
    dicts.insert("zh".to_owned(), zh);

    // Chinese translation exists
    assert_eq!(translate(Locale::Zh, &dicts, "login.server"), "服务器");

    // Fallback to English for missing Chinese key
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

    // Fallback to key itself when not found anywhere
    assert_eq!(
        translate(Locale::En, &HashMap::new(), "nonexistent.key"),
        "nonexistent.key"
    );
}

#[test]
fn locale_formatters_are_stable() {
    let timestamp = DateTime::parse_from_rfc3339("2026-04-29T07:08:09Z")
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
    assert_eq!(
        format_datetime(Locale::Ar, timestamp),
        "2026/04/29 07:08 UTC"
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

    let complete = translation_completeness(&en, &en);
    assert!(complete.is_complete());
}
