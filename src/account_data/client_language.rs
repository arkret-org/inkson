//! `client.language` account-data payload helpers.
//!
//! Spec: `discovery/client-preferences.md` §2 declares `client.language` as the
//! actor-private carrier for a user's locale preference. The key was declared
//! in [`super::AccountDataKey`] but never read or written by anything, so a
//! user who chose a language on one device found the next one still guessing
//! from `navigator.language`.
//!
//! This is deliberately *not* the public [`ActorProfile`]: which language
//! someone reads in is nobody else's business, and `ActorProfile` is visible
//! to every member of a Realm. Account data is actor-private and encrypted at
//! rest like the rest of the client-preference keys.
//!
//! [`ActorProfile`]: arkret_models_identity::ActorProfile

use serde_json::Value;

use crate::i18n::Locale;

/// Build the canonical `content` body for the `client.language` entry.
///
/// The stored tag is [`Locale::code`] — the canonical base language, never a
/// region variant. A device that writes `zh` and a device that reads it agree
/// without either needing a fallback chain.
#[must_use]
pub fn build_client_language_body(locale: Locale) -> Value {
    serde_json::json!({
        "locale": locale.code(),
        "direction": locale.direction().as_str(),
    })
}

/// Read the locale out of a remote `client.language` payload.
///
/// Returns `None` when the entry is absent, malformed, or names a language
/// this build cannot render — an older client may have written `ja` back when
/// the enum still carried it, and selecting a dictionary that no longer exists
/// would render raw keys. Falling through leaves the local value in charge.
#[must_use]
pub fn locale_from_client_language(value: &Value) -> Option<Locale> {
    value
        .get("locale")
        .and_then(Value::as_str)
        .and_then(Locale::from_tag)
}

/// Merge a remote `client.language` payload into the locally-active locale.
///
/// Returns `Some(remote)` when the device should switch, `None` when it is
/// already correct or the remote payload carries nothing usable. Mirrors
/// [`super::merge_client_ui_theme`], which solves the same problem for the
/// theme.
#[must_use]
pub fn merge_client_language(local: Locale, remote_value: &Value) -> Option<Locale> {
    let remote = locale_from_client_language(remote_value)?;
    (remote != local).then_some(remote)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_stores_the_canonical_base_tag() {
        assert_eq!(
            build_client_language_body(Locale::Zh),
            serde_json::json!({"locale": "zh", "direction": "ltr"})
        );
    }

    #[test]
    fn a_written_body_reads_back_as_the_same_locale() {
        for locale in arkret_locale::SUPPORTED {
            let body = build_client_language_body(locale);
            assert_eq!(locale_from_client_language(&body), Some(locale));
        }
    }

    #[test]
    fn a_region_variant_from_another_client_folds_onto_the_base() {
        let body = serde_json::json!({"locale": "zh-Hans"});
        assert_eq!(locale_from_client_language(&body), Some(Locale::Zh));
    }

    #[test]
    fn an_unrenderable_remote_value_leaves_the_local_locale_alone() {
        // An older build persisted `ja` / `ar`; those dictionaries are gone.
        for tag in ["ja", "ar", "fr", ""] {
            let body = serde_json::json!({ "locale": tag });
            assert_eq!(merge_client_language(Locale::En, &body), None, "{tag}");
        }
        assert_eq!(merge_client_language(Locale::En, &serde_json::json!({})), None);
    }

    #[test]
    fn a_matching_remote_value_is_not_a_change() {
        let body = build_client_language_body(Locale::Zh);
        assert_eq!(merge_client_language(Locale::Zh, &body), None);
        assert_eq!(merge_client_language(Locale::En, &body), Some(Locale::Zh));
    }
}
