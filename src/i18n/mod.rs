use std::collections::HashMap;

use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Supported locales.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Locale {
    #[default]
    En,
    Zh,
    Ar,
    /// Phase D.2 #8: Spanish.
    Es,
    /// Phase D.2 #8: Japanese.
    Ja,
    /// Phase D.2 #8: French.
    Fr,
}

impl Locale {
    pub fn code(&self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Zh => "zh",
            Locale::Ar => "ar",
            Locale::Es => "es",
            Locale::Ja => "ja",
            Locale::Fr => "fr",
        }
    }

    /// Parse a BCP 47 locale string. The match recognises both the base
    /// tag (e.g. `"ar"`) and common region variants (`"ar-SA"`, `"ar-EG"`,
    /// `"zh-CN"`, `"zh-TW"`, `"es-MX"`, `"fr-CA"`, `"ja-JP"`). Region
    /// variants always fall through to the base locale dictionary.
    pub fn from_code(code: &str) -> Self {
        // Normalise on the base subtag so `ar-SA` and `ar-EG` both pick
        // the Arabic dictionary, which is the entry-point of the
        // ar-SA → ar → en fallback chain defined in [`translate`].
        let base = code
            .split(['-', '_'])
            .next()
            .unwrap_or(code)
            .to_ascii_lowercase();
        match base.as_str() {
            "zh" => Locale::Zh,
            "ar" => Locale::Ar,
            "es" => Locale::Es,
            "ja" => Locale::Ja,
            "fr" => Locale::Fr,
            _ => Locale::En,
        }
    }

    /// Resolve the platform UI locale for first launch. A persisted Inkson
    /// preference takes precedence at the app-shell layer; this is only the
    /// fallback used when the user has not selected a language yet.
    pub fn platform_preferred() -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            return web_sys::window()
                .and_then(|window| window.navigator().language())
                .map(|language| Self::from_code(&language))
                .unwrap_or_default();
        }

        #[cfg(not(target_arch = "wasm32"))]
        Self::default()
    }

    pub fn direction(&self) -> TextDirection {
        match self {
            Locale::Ar => TextDirection::Rtl,
            Locale::En | Locale::Zh | Locale::Es | Locale::Ja | Locale::Fr => TextDirection::Ltr,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextDirection {
    Ltr,
    Rtl,
}

impl TextDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ltr => "ltr",
            Self::Rtl => "rtl",
        }
    }
}

/// Translation dictionary for a single locale.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TranslationDict {
    pub locale: Locale,
    pub strings: HashMap<String, String>,
}

impl TranslationDict {
    pub fn new(locale: Locale) -> Self {
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

/// Global i18n state managed as a Dioxus signal.
pub type I18nSignal = Signal<(Locale, HashMap<String, TranslationDict>)>;

/// Get a translated string by key. Falls back to English, then to the key itself.
pub fn t(signal: &I18nSignal, key: &str) -> String {
    // Borrow on read and clone only the matched translation; avoids deep-copying
    // the whole (Locale, HashMap<String, TranslationDict>) dictionary on every
    // call (t() is invoked heavily per frame).
    let guard = signal.read();
    let (locale, dicts) = &*guard;
    translate(*locale, dicts, key)
}

/// Lookup a translated string without requiring a Dioxus runtime.
///
/// Phase D.2 #8: extends the fallback chain so a region variant like
/// `ar-SA` walks `ar-SA → ar → en → key` even though the
/// [`Locale`] enum collapses region tags at parse time. Callers that
/// keep a raw BCP 47 tag around can call [`translate_chain`] instead;
/// this helper is the simple "I already have a `Locale`" entrypoint.
pub fn translate(locale: Locale, dicts: &HashMap<String, TranslationDict>, key: &str) -> String {
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

/// Format a UTC timestamp with locale-specific ordering.
pub fn format_datetime(locale: Locale, timestamp: DateTime<Utc>) -> String {
    match locale {
        Locale::En => timestamp.format("%b %d, %Y %H:%M UTC").to_string(),
        Locale::Zh => timestamp.format("%Y年%m月%d日 %H:%M UTC").to_string(),
        Locale::Ar => timestamp.format("%Y/%m/%d %H:%M UTC").to_string(),
        // Phase D.2 #8 locale extensions:
        //   * Spanish uses day-first DD/MM/YYYY (DM ordering matches ES/MX/AR conventions).
        //   * Japanese uses year/month/day separators like Chinese.
        //   * French uses DD/MM/YYYY (matches FR/CA conventions).
        Locale::Es => timestamp.format("%d/%m/%Y %H:%M UTC").to_string(),
        Locale::Ja => timestamp.format("%Y年%m月%d日 %H:%M UTC").to_string(),
        Locale::Fr => timestamp.format("%d/%m/%Y %H:%M UTC").to_string(),
    }
}

/// Format a non-negative integer with locale-appropriate grouping.
pub fn format_number(locale: Locale, value: u64) -> String {
    let grouped = group_decimal(value);
    match locale {
        // English / Arabic / Japanese: comma-grouped thousands.
        Locale::En | Locale::Ar | Locale::Ja => grouped,
        // Chinese: Eastern convention uses non-breaking space as a soft
        // separator since the thousands grouping is not native to the
        // language; we keep this for parity with the pre-D.2 behaviour.
        Locale::Zh => grouped.replace(',', " "),
        // Spanish / French: dot grouping (es-ES / fr-FR style). Newer
        // ISO 31 recommends thin-space grouping but the existing
        // tooling consumes ASCII, so the dot is the pragmatic choice.
        Locale::Es | Locale::Fr => grouped.replace(',', "."),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationCompleteness {
    pub locale: Locale,
    pub total_keys: usize,
    pub missing_keys: Vec<String>,
}

impl TranslationCompleteness {
    pub fn is_complete(&self) -> bool {
        self.missing_keys.is_empty()
    }

    pub fn missing_count(&self) -> usize {
        self.missing_keys.len()
    }
}

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
mod other_locales;
mod zh;

#[cfg(test)]
mod tests;

// Re-export the per-locale dictionary builders so existing
// `crate::i18n::<locale>_translations` paths keep resolving unchanged.
pub use en::english_translations;
pub use other_locales::{
    arabic_translations, french_translations, japanese_translations, spanish_translations,
};
pub use zh::chinese_translations;

/// Initialize the i18n system with default translations.
pub fn init_i18n() -> I18nSignal {
    init_i18n_with_locale(Locale::En)
}

/// Initialize i18n preloaded with a specific locale.
pub fn init_i18n_with_locale(locale: Locale) -> I18nSignal {
    let mut dicts = HashMap::new();
    dicts.insert("en".to_owned(), english_translations());
    dicts.insert("zh".to_owned(), chinese_translations());
    dicts.insert("ar".to_owned(), arabic_translations());
    // Phase D.2 #8: new locale slots — coverage is intentionally a
    // subset (nav / common / login) so missing keys fall through the
    // `xx → en` chain and surface in `missing_translation_snapshot()`
    // for QA to grow as needed.
    dicts.insert("es".to_owned(), spanish_translations());
    dicts.insert("ja".to_owned(), japanese_translations());
    dicts.insert("fr".to_owned(), french_translations());
    Signal::new((locale, dicts))
}

/// Switch the active locale on an existing signal without rebuilding the
/// translation tables. Call this from the Settings language picker.
pub fn set_locale(signal: &mut I18nSignal, locale: Locale) {
    if signal.read().0 == locale {
        return;
    }
    let dicts = signal.read().1.clone();
    signal.set((locale, dicts));
}

/// Convenience: pull the current i18n signal from Dioxus context and
/// translate `key`. Views call this once they have been wrapped in a
/// `provide_context(init_i18n_with_locale(...))` ancestor — currently
/// `WorkspaceView`. Falls back to the key itself when no context is
/// installed (e.g. unit tests outside Dioxus runtime).
pub fn tr(key: &str) -> String {
    match try_consume_context::<I18nSignal>() {
        Some(signal) => t(&signal, key),
        None => key.to_owned(),
    }
}
