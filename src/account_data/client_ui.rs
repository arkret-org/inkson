//! `ak.client.ui_state` account-data payload helpers (theme, sidebar collapsed,
//! per-Realm view, avatar blob ref cache, language).
//!
//! Spec: `discovery/client-preferences.md` §2 — the `ak.client.ui_state`
//! account-data key carries cross-device UI preferences, and §3.4 assigns the
//! `language` field to this cell. Inkson persists theme + sidebar state
//! locally and best-effort syncs them across
//! devices via `ak.account_data.set`.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::i18n::UiLocale;

// ─────────────────────────────────────────────────────────────────────────
// A4a — `ak.client.ui_state` payload (theme, sidebar collapsed, per-Realm view).
// Spec: `discovery/client-preferences.md` §2 — the `ak.client.ui_state`
// account-data key carries cross-device UI preferences. Inkson persists
// theme + sidebar state locally and best-effort syncs them across
// devices via `ak.account_data.set`.
// ─────────────────────────────────────────────────────────────────────────

/// Build the canonical `content` body for the `ak.client.ui_state` account-data
/// entry. Mirrors the shape clients on other platforms agree on so a
/// device that joins later sees the same field names.
///
/// Empty / `None` fields are skipped so we don't ship stale defaults.
/// `theme` MUST be one of `"light" | "night" | "system"`.
///
/// `avatar_blob_ref` (A4b) carries the actor-private cross-device cache
/// of the most-recently uploaded avatar reference. The blob_ref itself
/// (`ak:blob:sha256:<hex>`) is public — the avatar is also published via
/// `ak.self.account.command.update_profile.v1` so other actors see it through the
/// directory. We mirror it here so a second device that signs in picks
/// up the same blob without needing to re-fetch the account viewer.
pub fn build_client_ui_body(
    theme: Option<&str>,
    sidebar_collapsed: Option<bool>,
    per_realm_view: &BTreeMap<String, String>,
    avatar_blob_ref: Option<&str>,
) -> Value {
    let mut map = serde_json::Map::new();
    if let Some(value) = theme
        && !value.is_empty()
    {
        map.insert("theme".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = sidebar_collapsed {
        map.insert("sidebar_collapsed".to_owned(), Value::Bool(value));
    }
    if !per_realm_view.is_empty() {
        let mut obj = serde_json::Map::new();
        for (k, v) in per_realm_view {
            obj.insert(k.clone(), Value::String(v.clone()));
        }
        map.insert("per_realm_view".to_owned(), Value::Object(obj));
    }
    if let Some(value) = avatar_blob_ref {
        let trimmed = value.trim();
        map.insert(
            "avatar_blob_ref".to_owned(),
            Value::String(trimmed.to_owned()),
        );
    }
    Value::Object(map)
}

/// Extract `avatar_blob_ref` from a `ak.client.ui_state` payload. Returns `None`
/// when the field is missing, empty, or not a string (older clients
/// wrote `ak.client.ui_state` without this field; treat that as "no override").
pub fn avatar_blob_ref_from_client_ui(value: &Value) -> Option<String> {
    value
        .get("avatar_blob_ref")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|value| arkret_sdk::BlobRef::new(value.to_owned()).ok())
        .map(|value| value.to_string())
}

/// True when a remote `ak.client.ui_state` payload explicitly tombstones the avatar
/// cache with `avatar_blob_ref: ""`. Missing/non-string fields mean "no
/// opinion" so older clients do not clear a newer local value by accident.
pub fn avatar_blob_ref_tombstoned_from_client_ui(value: &Value) -> bool {
    value
        .get("avatar_blob_ref")
        .and_then(Value::as_str)
        .map(str::trim)
        == Some("")
}

/// Theme preference recovered from a `ak.client.ui_state` account-data payload.
///
/// Returns one of `"light" | "night" | "system"` when the remote payload
/// carries a valid `theme` field, otherwise `None`. Invalid / unknown
/// theme strings are dropped (caller should keep the existing local
/// value).
pub fn theme_from_client_ui(value: &Value) -> Option<String> {
    value
        .get("theme")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| matches!(*s, "light" | "night" | "system"))
        .map(ToOwned::to_owned)
}

/// Set the `language` field (spec `discovery/client-preferences.md` §3.4) on a
/// decrypted `ak.client.ui_state` body, preserving every other field already
/// present (theme, recent_realms, avatar_blob_ref, ...).
///
/// The stored tag is [`UiLocale::code`] — the canonical base language, never a
/// region variant. A device that writes `zh` and a device that reads it agree
/// without either needing a fallback chain.
pub fn set_client_ui_language(body: &mut Value, locale: UiLocale) {
    if let Value::Object(map) = body {
        map.insert(
            "language".to_owned(),
            Value::String(locale.code().to_owned()),
        );
    }
}

/// Locale recovered from the `language` field of a `ak.client.ui_state`
/// payload.
///
/// Returns `None` when the field is absent, malformed, or names a language
/// this build cannot render — an older client may have written `ja` back when
/// the enum still carried it, and selecting a dictionary that no longer exists
/// would render raw keys. Falling through leaves the local value in charge.
pub fn language_from_client_ui(value: &Value) -> Option<UiLocale> {
    value
        .get("language")
        .and_then(Value::as_str)
        .and_then(UiLocale::from_tag)
}

/// Merge the `language` field of a remote `ak.client.ui_state` payload into
/// the locally-active locale.
///
/// Returns `Some(remote)` when the device should switch, `None` when it is
/// already correct or the remote payload carries nothing usable. Mirrors
/// [`merge_client_ui_theme`], which solves the same problem for the theme.
pub fn merge_client_ui_language(local: UiLocale, remote_value: &Value) -> Option<UiLocale> {
    let remote = language_from_client_ui(remote_value)?;
    (remote != local).then_some(remote)
}

/// Merge a remote `ak.client.ui_state` theme into the local cached theme. Local
/// state stays authoritative when the remote payload doesn't carry a
/// valid `theme` field — that means the entry was written by an older
/// client that only synced `sidebar_collapsed`.
///
/// Returns `Some(new_theme)` when the merged value differs from the
/// local one (caller should update the UI Signal + persist locally), or
/// `None` when no change is required.
pub fn merge_client_ui_theme(local_theme: &str, remote_value: &Value) -> Option<String> {
    let remote = theme_from_client_ui(remote_value)?;
    if remote == local_theme {
        None
    } else {
        Some(remote)
    }
}
