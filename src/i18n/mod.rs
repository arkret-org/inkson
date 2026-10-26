//! UI copy style rules for every string in these dictionaries:
//!
//! * Plain language first — lead with what happened or what the user can do, then one concrete next
//!   action. No protocol identifiers in user-facing copy: no `ak.*` event names, no `did:webvh:`
//!   examples, no MLS epoch / key package talk, no PCR / RHRK / SAS acronyms. Jargon belongs inside
//!   "technical details" affordances and Developer surfaces only.
//! * Error copy formula: what happened + what it means + what to do next.
//! * English: short sentences, sentence case. Chinese: concise and conversational, with the fixed
//!   vocabulary "Realm / 空间 / 设备 / 恢复密钥"; never mix English and Chinese inside one UI name.

use std::collections::HashMap;

/// The locale the client renders in.
///
/// This is [`arkret_locale::UiLocale`] — the same closed set coauth's server
/// and its SPA use — re-exported under the name this client already uses.
/// Sharing the type is what makes "the two apps must change together" a
/// compile-time property rather than a convention: neither side can invent a
/// locale the other cannot render.
///
/// The enum used to carry `Ar`/`Es`/`Ja`/`Fr` alongside deliberately partial
/// dictionaries, but `product_ui()` clamped every one of them back to `En`
/// before the shell ever saw it, so they were unreachable. They are gone,
/// along with the clamp. [`TextDirection`] survives so that adding a
/// right-to-left locale stays a change in one crate rather than an audit of
/// every layout.
pub use arkret_locale::{TextDirection, UiLocale};
#[cfg(test)]
use chrono::{DateTime, Utc};
use glory::Cage;
use serde::{Deserialize, Serialize};

/// Where this device's UI locale came from, resolved once at boot.
///
/// The shell owns the account and device-cache tiers, so it passes them in;
/// this helper only contributes the platform observation, which is the one
/// piece that needs `web_sys`.
///
/// * `account` — the signed-in account's `preferred_locale`, the cross-device source of truth.
///   `None` before sign-in.
/// * `device_cache` — this device's remembered choice. A cache: it seeds the pre-login experience
///   and never outranks the account.
#[must_use]
pub fn resolve_locale(account: Option<&str>, device_cache: Option<&str>) -> UiLocale {
    let platform = platform_language();
    arkret_locale::resolve(&arkret_locale::LocaleSources {
        account,
        // Inkson is the client that *sends* `ui_locales`; nothing hands one
        // back to it, so this tier is always empty here.
        requested: None,
        device_cache,
        platform: platform.as_deref(),
    })
}

/// The operating system / browser language preference, if observable.
fn platform_language() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window().and_then(|window| window.navigator().language())
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

/// Translation dictionary for a single locale.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TranslationDict {
    pub locale: UiLocale,
    pub strings: HashMap<String, String>,
}

impl TranslationDict {
    pub fn new(locale: UiLocale) -> Self {
        Self {
            locale,
            strings: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.strings.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.strings.get(key).map(|s| s.as_str())
    }
}

thread_local! {
    static APPLICATION_LOCALE: std::cell::Cell<Option<Cage<UiLocale>>> = const { std::cell::Cell::new(None) };
    static SCOPED_LOCALE: std::cell::Cell<Option<UiLocale>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn bind_application_locale(locale: Cage<UiLocale>) {
    APPLICATION_LOCALE.with(|active| active.set(Some(locale)));
}

/// Pure view models may choose a locale without requiring a mounted renderer.
pub fn tr_for_locale(locale: UiLocale, key: &str) -> String {
    static DICTIONARIES: std::sync::OnceLock<HashMap<String, TranslationDict>> =
        std::sync::OnceLock::new();
    let dictionaries = DICTIONARIES.get_or_init(|| {
        HashMap::from([
            (UiLocale::En.code().to_owned(), english_translations()),
            (UiLocale::Zh.code().to_owned(), chinese_translations()),
        ])
    });
    translate(locale, dictionaries, key)
}

pub fn with_locale<T>(locale: UiLocale, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<UiLocale>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SCOPED_LOCALE.with(|active| active.set(self.0));
        }
    }
    let previous = SCOPED_LOCALE.with(|active| active.replace(Some(locale)));
    let _restore = Restore(previous);
    run()
}

#[cfg(test)]
pub fn with_test_locale<T>(locale: UiLocale, run: impl FnOnce() -> T) -> T {
    with_locale(locale, run)
}

/// Lookup a translated string without requiring a Dioxus runtime.
///
/// Phase D.2 #8: extends the fallback chain so a region variant like
/// `ar-SA` walks `ar-SA → ar → en → key` even though the
/// [`UiLocale`] enum collapses region tags at parse time. Callers that
/// keep a raw BCP 47 tag around can call [`translate_chain`] instead;
/// this helper is the simple "I already have a `UiLocale`" entrypoint.
pub fn translate(locale: UiLocale, dicts: &HashMap<String, TranslationDict>, key: &str) -> String {
    translate_chain(locale.code(), dicts, key)
}

/// Phase D.2 #8: translate against an explicit BCP 47 chain. The
/// `requested_tag` may carry a region suffix (e.g. `"ar-SA"`). The
/// lookup tries the full tag, then strips each `-region` segment, then
/// falls back to English. Missing keys are reported via
/// [`record_missing_translation`] before returning the key itself.
pub fn translate_chain(
    requested_tag: &str,
    dicts: &HashMap<String, TranslationDict>,
    key: &str,
) -> String {
    // Build the lookup chain: `ar-SA → ar → en`.
    let mut chain: Vec<String> = Vec::new();
    let mut current = requested_tag.to_owned();
    chain.push(current.clone());
    while let Some(idx) = current.rfind('-') {
        current.truncate(idx);
        if !current.is_empty() {
            chain.push(current.clone());
        }
    }
    if !chain.iter().any(|tag| tag == "en") {
        chain.push("en".to_owned());
    }
    for tag in &chain {
        if let Some(dict) = dicts.get(tag.as_str())
            && let Some(val) = dict.get(key)
        {
            return val.to_owned();
        }
    }
    // Phase D.2 #8: surface the miss so QA can grow the dictionaries.
    record_missing_translation(requested_tag, key);
    key.to_owned()
}

/// Phase D.2 #8: shared sink for missing `(locale_tag, key)` pairs.
fn missing_translation_sink()
-> &'static std::sync::Mutex<std::collections::HashSet<(String, String)>> {
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<std::collections::HashSet<(String, String)>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Phase D.2 #8: missing-key sink. Each unique `(locale, key)` pair
/// is logged once via `tracing::warn!` so a long-running session
/// doesn't spam the journal for the same untranslated label. The
/// in-memory set is also queryable via
/// [`missing_translation_snapshot`] for test / diagnostic UI.
fn record_missing_translation(locale_tag: &str, key: &str) {
    let Ok(mut guard) = missing_translation_sink().lock() else {
        return;
    };
    let entry = (locale_tag.to_owned(), key.to_owned());
    if guard.insert(entry) {
        tracing::warn!(locale = %locale_tag, key = %key, "i18n missing translation");
    }
}

/// Phase D.2 #8: snapshot of every `(locale_tag, key)` pair that has
/// been reported missing by [`translate_chain`] during this process.
/// Used by the developer-tools diagnostic surface and the i18n unit
/// tests; production code should not iterate this.
pub fn missing_translation_snapshot() -> Vec<(String, String)> {
    let Ok(guard) = missing_translation_sink().lock() else {
        return Vec::new();
    };
    let mut out: Vec<_> = guard.iter().cloned().collect();
    out.sort();
    out
}

#[cfg(test)]
/// Format a UTC timestamp with locale-specific ordering.
pub fn format_datetime(locale: UiLocale, timestamp: DateTime<Utc>) -> String {
    match locale {
        UiLocale::En => timestamp.format("%b %d, %Y %H:%M UTC").to_string(),
        UiLocale::Zh => timestamp.format("%Y年%m月%d日 %H:%M UTC").to_string(),
    }
}

/// Format a non-negative integer with locale-appropriate grouping.
pub fn format_number(locale: UiLocale, value: u64) -> String {
    let grouped = group_decimal(value);
    match locale {
        // Comma-grouped thousands.
        UiLocale::En => grouped,
        // Eastern convention uses a space as a soft separator, since
        // thousands grouping is not native to the language.
        UiLocale::Zh => grouped.replace(',', " "),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationCompleteness {
    pub locale: UiLocale,
    pub total_keys: usize,
    pub missing_keys: Vec<String>,
}

impl TranslationCompleteness {
    #[cfg(test)]
    pub fn is_complete(&self) -> bool {
        self.missing_keys.is_empty()
    }
}

#[cfg(test)]
/// Compare a locale dictionary against a reference dictionary.
pub fn translation_completeness(
    reference: &TranslationDict,
    candidate: &TranslationDict,
) -> TranslationCompleteness {
    let mut missing_keys: Vec<String> = reference
        .strings
        .keys()
        .filter(|key| !candidate.strings.contains_key(*key))
        .cloned()
        .collect();
    missing_keys.sort();
    TranslationCompleteness {
        locale: candidate.locale,
        total_keys: reference.strings.len(),
        missing_keys,
    }
}

fn group_decimal(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (idx, ch) in digits.chars().rev().enumerate() {
        if idx > 0 && idx % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

mod en;
mod zh;

#[cfg(test)]
mod tests;

// Re-export the per-locale dictionary builders so existing
// `crate::i18n::<locale>_translations` paths keep resolving unchanged.
pub use en::english_translations;
pub use zh::chinese_translations;

/// Convenience for existing pure view models. Reading the live Cage records
/// the same locale dependency as an explicit translated binding.
pub fn tr(key: &str) -> String {
    let locale = SCOPED_LOCALE
        .with(std::cell::Cell::get)
        .or_else(|| {
            APPLICATION_LOCALE.with(|active| active.get().and_then(|locale| locale.try_get().ok()))
        })
        .unwrap_or(UiLocale::En);
    tr_for_locale(locale, key)
}

/// Substitute `{placeholder}` args into an already-localized string.
///
/// This is the single implementation of the placeholder convention used by
/// every localized string in the client (toasts, form errors, inline UI).
/// Callers that already resolved the message themselves — because they need
/// a dictionary-miss fallback, like the toast host — substitute through here
/// rather than re-implementing the `replace` loop.
pub fn substitute_args(mut message: String, args: &[(&'static str, String)]) -> String {
    for (placeholder, value) in args {
        message = message.replace(&format!("{{{placeholder}}}"), value);
    }
    message
}

/// [`tr`] plus `{placeholder}` substitution. Use for any UI string that
/// carries a runtime value (counts, ids, names).
pub fn tr_args(key: &str, args: &[(&'static str, String)]) -> String {
    substitute_args(tr(key), args)
}
