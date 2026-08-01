//! Dictionary parity for the locales the product UI actually exposes.
//!
//! `translate_chain` falls back `zh → en → key`, so a missing Chinese key
//! degrades to English rather than crashing — which is exactly why gaps go
//! unnoticed and a page ends up half-translated. These tests make the gap a
//! build failure for the namespaces that have been migrated.
//!
//! Secondary locales (ar / es / ja / fr) are intentionally partial; they are
//! not checked here.

use std::collections::BTreeSet;

use inkson::i18n::{Locale, chinese_translations, english_translations, translate};

/// Namespaces whose Chinese coverage must be complete. Grow this list as
/// modules are migrated; it mirrors `tests/ui_text_gate.rs::MIGRATED_ROOTS`.
const ENFORCED_PREFIXES: &[&str] = &["setup.", "route."];

fn keys_with_prefix(dict: &inkson::i18n::TranslationDict, prefix: &str) -> BTreeSet<String> {
    dict.strings
        .keys()
        .filter(|key| key.starts_with(prefix))
        .cloned()
        .collect()
}

#[test]
fn chinese_covers_every_migrated_english_key() {
    let en = english_translations();
    let zh = chinese_translations();
    let mut missing = Vec::new();

    for prefix in ENFORCED_PREFIXES {
        for key in keys_with_prefix(&en, prefix) {
            if zh.get(&key).is_none() {
                missing.push(key);
            }
        }
    }

    assert!(
        missing.is_empty(),
        "these keys exist in en but not zh, so the Chinese UI would silently \
         fall back to English:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn no_orphan_chinese_keys_in_migrated_namespaces() {
    let en = english_translations();
    let zh = chinese_translations();
    let mut orphans = Vec::new();

    for prefix in ENFORCED_PREFIXES {
        for key in keys_with_prefix(&zh, prefix) {
            if en.get(&key).is_none() {
                orphans.push(key);
            }
        }
    }

    assert!(
        orphans.is_empty(),
        "these keys exist in zh but not en — English is the reference locale, \
         so an en-only miss means the key is dead or misspelled:\n  {}",
        orphans.join("\n  ")
    );
}

#[test]
fn migrated_keys_resolve_to_real_text_in_both_locales() {
    let en = english_translations();
    let zh = chinese_translations();
    let dicts = std::collections::HashMap::from([
        ("en".to_owned(), en.clone()),
        ("zh".to_owned(), zh),
    ]);

    // `setup.opt.space_kind.space.hint` is intentionally blank: the generic
    // Space kind needs no explanatory line, and the call site filters empties.
    let allowed_blank = ["setup.opt.space_kind.space.hint"];
    let mut unresolved = Vec::new();

    for prefix in ENFORCED_PREFIXES {
        for key in keys_with_prefix(&en, prefix) {
            for locale in [Locale::En, Locale::Zh] {
                let text = translate(locale, &dicts, &key);
                if text == key {
                    unresolved.push(format!("{key} ({})", locale.code()));
                } else if text.is_empty() && !allowed_blank.contains(&key.as_str()) {
                    unresolved.push(format!("{key} ({}) is empty", locale.code()));
                }
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
            "history_visibility",
            &[
                "world_readable",
                "shared",
                "invited",
                "joined",
                "restricted",
            ],
        ),
        ("encryption_profile", &["mls_rfc9420", "none"]),
        (
            "content_scheme",
            &["mls_exporter_aead_v1", "mls_rfc9420"],
        ),
        ("security_class", &["standard", "high_assurance"]),
        (
            "federation_policy",
            &["open", "restricted", "closed", "quarantine"],
        ),
        (
            "anchor_profile",
            &["single_did", "threshold", "open_set", "mixed"],
        ),
        (
            "hash_profile",
            &["sha256", "sha512", "sha3_256", "blake3"],
        ),
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
