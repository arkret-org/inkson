//! `client.ui` account-data payload helpers (theme, sidebar collapsed,
//! per-Realm view, avatar blob ref cache).
//!
//! Spec: `discovery/client-preferences.md` §2 — the `client.ui`
//! account-data key carries cross-device UI preferences. Inkson persists
//! theme + sidebar state locally and best-effort syncs them across
//! devices via `ck.account_data.set`.

use std::collections::BTreeMap;

use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────
// A4a — `client.ui` payload (theme, sidebar collapsed, per-Realm view).
// Spec: `discovery/client-preferences.md` §2 — the `client.ui`
// account-data key carries cross-device UI preferences. Inkson persists
// theme + sidebar state locally and best-effort syncs them across
// devices via `ck.account_data.set`.
// ─────────────────────────────────────────────────────────────────────────

/// Build the canonical `content` body for the `client.ui` account-data
/// entry. Mirrors the shape clients on other platforms agree on so a
/// device that joins later sees the same field names.
///
/// Empty / `None` fields are skipped so we don't ship stale defaults.
/// `theme` MUST be one of `"light" | "night" | "system"`.
///
/// `avatar_blob_ref` (A4b) carries the actor-private cross-device cache
/// of the most-recently uploaded avatar reference. The blob_ref itself
/// (`ck:blob:sha256:<hex>`) is public — the avatar is also published via
/// `ck.self.account.command.update_profile` so other actors see it through the
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

/// Extract `avatar_blob_ref` from a `client.ui` payload. Returns `None`
/// when the field is missing, empty, or not a string (older clients
/// wrote `client.ui` without this field; treat that as "no override").
pub fn avatar_blob_ref_from_client_ui(value: &Value) -> Option<String> {
    value
        .get("avatar_blob_ref")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// True when a remote `client.ui` payload explicitly tombstones the avatar
/// cache with `avatar_blob_ref: ""`. Missing/non-string fields mean "no
/// opinion" so older clients do not clear a newer local value by accident.
pub fn avatar_blob_ref_tombstoned_from_client_ui(value: &Value) -> bool {
    value
        .get("avatar_blob_ref")
        .and_then(Value::as_str)
        .map(str::trim)
        == Some("")
}

/// Theme preference recovered from a `client.ui` account-data payload.
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

/// Merge a remote `client.ui` theme into the local cached theme. Local
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
