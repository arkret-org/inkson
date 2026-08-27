//! Dictionary parity for the locales the product UI actually exposes.
//!
//! `translate_chain` falls back `zh → en → key`, so a missing Chinese key
//! degrades to English rather than crashing — which is exactly why gaps go
//! unnoticed and a page ends up half-translated. These tests make any gap a
//! build failure: en and zh must carry exactly the same key set.

use std::collections::BTreeSet;

use inkson::i18n::{UiLocale, chinese_translations, english_translations, translate};

fn key_set(dict: &inkson::i18n::TranslationDict) -> BTreeSet<String> {
    dict.strings.keys().cloned().collect()
}

#[test]
fn chinese_covers_every_english_key() {
    let en = english_translations();
    let zh = chinese_translations();
    let missing: Vec<String> = key_set(&en)
        .into_iter()
        .filter(|key| zh.get(key).is_none())
        .collect();

    assert!(
        missing.is_empty(),
        "these keys exist in en but not zh, so the Chinese UI would silently \
         fall back to English:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn no_orphan_chinese_keys() {
    let en = english_translations();
    let zh = chinese_translations();
    let orphans: Vec<String> = key_set(&zh)
        .into_iter()
        .filter(|key| en.get(key).is_none())
        .collect();

    assert!(
        orphans.is_empty(),
        "these keys exist in zh but not en — English is the reference locale, \
         so an en-only miss means the key is dead or misspelled:\n  {}",
        orphans.join("\n  ")
    );
}

#[test]
fn keys_resolve_to_real_text_in_both_locales() {
    let en = english_translations();
    let zh = chinese_translations();
    let dicts =
        std::collections::HashMap::from([("en".to_owned(), en.clone()), ("zh".to_owned(), zh)]);

    // `setup.opt.space_kind.space.hint` is intentionally blank: the generic
    // Space kind needs no explanatory line, and the call site filters empties.
    let allowed_blank = ["setup.opt.space_kind.space.hint"];
    let mut unresolved = Vec::new();

    for key in key_set(&en) {
        for locale in [UiLocale::En, UiLocale::Zh] {
            let text = translate(locale, &dicts, &key);
            if text == key {
                unresolved.push(format!("{key} ({})", locale.code()));
            } else if text.is_empty() && !allowed_blank.contains(&key.as_str()) {
                unresolved.push(format!("{key} ({}) is empty", locale.code()));
            }
        }
    }

    assert!(
        unresolved.is_empty(),
        "these keys did not resolve to display text:\n  {}",
        unresolved.join("\n  ")
    );
}

/// The Realm wizard's option tables are `(wire_value, label_key, hint_key)`.
/// A typo in a key would render the raw key in the form, so pin the exact
/// shape the dictionaries must carry for every wire value in the spec enums.
#[test]
fn option_table_keys_exist_for_every_wire_value() {
    let en = english_translations();
    let axes: &[(&str, &[&str])] = &[
        (
            "discoverability",
            &[
                "public",
                "listed",
                "restricted",
                "unlisted",
                "invite_only",
                "secret",
            ],
        ),
        ("join_rule", &["public", "invite", "knock", "restricted"]),
        (
            "history_access",
            &["since_join", "all_history_for_current_members"],
        ),
        ("encryption_profile", &["mls_rfc9420", "none"]),
        ("content_scheme", &["mls_exporter_aead_v1", "mls_rfc9420"]),
        ("security_class", &["standard", "high_assurance"]),
        (
            "federation_policy",
            &["open", "restricted", "closed", "quarantine"],
        ),
        ("hash_profile", &["sha256", "sha512", "sha3_256", "blake3"]),
        (
            "space_kind",
            &["space", "project", "folder", "board", "list"],
        ),
    ];

    let mut missing = Vec::new();
    for (axis, values) in axes {
        for value in *values {
            for suffix in ["", ".hint"] {
                let key = format!("setup.opt.{axis}.{value}{suffix}");
                if en.get(&key).is_none() {
                    missing.push(key);
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "option table keys missing from the English dictionary:\n  {}",
        missing.join("\n  ")
    );
}
