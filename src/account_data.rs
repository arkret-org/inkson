//! Client-side account_data layer per `discovery/client-preferences.md`.
//!
//! Spec: actor-private preferences (UI state, read-receipt overrides, presence
//! gating, blocklist, language) are stored as `cx.account_data.set` events with
//! actor-private wire scope. Yougen previously kept these as ad-hoc fields on
//! `LocalState`; this module centralizes the storage shape so the future
//! `cx.account_data.set` write path has a single canonical entry point.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::canonical_sha256;
use crate::operation::OperationBuilder;

/// Canonical account_data namespace keys.
///
/// Keys mirror the spec example list in `discovery/client-preferences.md` §2.
/// Custom apps may extend with `Custom(String)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountDataKey {
    /// `client.ui` — sidebar collapsed, theme, default view per Space.
    ClientUi,
    /// `client.read_receipts` — global + per-space + per-flow send override.
    ClientReadReceipts,
    /// `client.presence` — per-space typing / online / last-seen toggles.
    ClientPresence,
    /// `client.blocklist` — actor-private personal blocklist entries.
    ClientBlocklist,
    /// `client.notifications` — per-space mute, sound, push routing.
    ClientNotifications,
    /// `client.language` — locale / RTL preferences.
    ClientLanguage,
    /// Application-specific extension key.
    Custom(String),
}

impl AccountDataKey {
    pub fn as_wire(&self) -> &str {
        match self {
            Self::ClientUi => "client.ui",
            Self::ClientReadReceipts => "client.read_receipts",
            Self::ClientPresence => "client.presence",
            Self::ClientBlocklist => "client.blocklist",
            Self::ClientNotifications => "client.notifications",
            Self::ClientLanguage => "client.language",
            Self::Custom(s) => s,
        }
    }

    pub fn from_wire(s: &str) -> Self {
        match s {
            "client.ui" => Self::ClientUi,
            "client.read_receipts" => Self::ClientReadReceipts,
            "client.presence" => Self::ClientPresence,
            "client.blocklist" => Self::ClientBlocklist,
            "client.notifications" => Self::ClientNotifications,
            "client.language" => Self::ClientLanguage,
            other => Self::Custom(other.to_owned()),
        }
    }
}

/// A single account_data record. Tracks the canonical hash so cas-register
/// merges can be applied client-side without re-serializing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDataRecord {
    pub key: String,
    pub value: Value,
    /// `sha256:<hex>` digest over canonical `value`. Used as the cas-register
    /// witness when applying remote updates.
    pub digest: String,
    /// Last-touched HLC string. Empty before the first write.
    #[serde(default)]
    pub hlc: String,
}

/// In-memory actor-private account_data store. Persistence is the caller's
/// responsibility (e.g. `local_state` hydrate / save).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDataStore {
    entries: BTreeMap<String, AccountDataRecord>,
}

impl AccountDataStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &AccountDataKey) -> Option<&AccountDataRecord> {
        self.entries.get(key.as_wire())
    }

    /// Insert or replace `key` with `value`. Recomputes the canonical digest.
    /// Returns the new record's digest.
    pub fn set(
        &mut self,
        key: AccountDataKey,
        value: Value,
        hlc: String,
    ) -> anyhow::Result<String> {
        let digest = canonical_sha256(&value)?;
        let wire = key.as_wire().to_owned();
        let record = AccountDataRecord {
            key: wire.clone(),
            value,
            digest: digest.clone(),
            hlc,
        };
        self.entries.insert(wire, record);
        Ok(digest)
    }

    pub fn remove(&mut self, key: &AccountDataKey) -> Option<AccountDataRecord> {
        self.entries.remove(key.as_wire())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &AccountDataRecord)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Wire-key for an actor-private Space remark per
/// `discovery/client-preferences.md` §3.7: `cx.contacts.space.<space_id>`.
///
/// The same string is the path segment passed to soland's
/// `PUT /api/v1/account_data/{type}` endpoint. Callers should already have
/// validated `space_id` shape (`cx:space:<uuid>`).
pub fn space_remark_account_data_key(space_id: &str) -> String {
    format!("cx.contacts.space.{space_id}")
}

/// Inverse of [`space_remark_account_data_key`]. Returns the `space_id`
/// segment when `key` is a Space-remark wire key; returns `None` for any
/// other namespace. Used when hydrating `account_data` entries from `/sync`.
pub fn space_id_from_space_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("cx.contacts.space.")
}

/// User-private Space remark per `discovery/client-preferences.md` §3.7.
///
/// Persisted as the `content` payload under
/// `cx.contacts.space.<space_id>` (the wire key built by
/// [`space_remark_account_data_key`]). The protocol treats the payload as
/// opaque on the server; this struct is the canonical local shape so the
/// settings UI and the sidebar agree.
///
/// All fields are spec-aligned; the struct intentionally mirrors the §3.6
/// `cx.contacts.actor.<did>` shape so future cross-actor / cross-Space
/// editing UIs can be unified.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceRemark {
    /// Schema version — currently fixed to `1`.
    #[serde(default = "default_space_remark_version")]
    pub version: u32,
    /// Spec §3.7 `subject.id` — the Space id this remark applies to.
    pub space_id: String,
    /// Spec §3.7 `local_name` — actor-private alias shown in place of the
    /// public `Space.title` when set. Max 128 chars; empty / whitespace-only
    /// means "no remark". Never serialised when empty so the wire payload
    /// can be tombstoned by setting `local_name=""`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_name: String,
    /// Spec §3.7 `note` — free-text up to 4096 chars.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Spec §3.7 `tags` — private grouping labels; namespace shared with
    /// `cx.tags.space.<space_id>` so the same label can drive both UIs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Spec §3.7 `pinned` — whether the Space sticks to the top of the
    /// sidebar regardless of activity.
    #[serde(default, skip_serializing_if = "is_false")]
    pub pinned: bool,
    /// Spec §3.7 `verified_title_at_save` — Space `title` snapshot at the
    /// time the remark was written, used to detect title drift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_title_at_save: Option<String>,
    /// Spec §3.7 `verified_owning_organizations_at_save` — `owning_organizations`
    /// snapshot at write time; UI can warn on takeover / org drift.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_owning_organizations_at_save: Vec<String>,
    /// Spec §3.7 `saved_at` / `updated_at` — RFC 3339 timestamps. Optional
    /// here because v1 clients populate them via `chrono::Utc::now()` at the
    /// edit site rather than relying on the server clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

fn default_space_remark_version() -> u32 {
    1
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl SpaceRemark {
    /// New remark seeded with `local_name`. Caller fills the rest as needed.
    pub fn new(space_id: impl Into<String>, local_name: impl Into<String>) -> Self {
        Self {
            version: 1,
            space_id: space_id.into(),
            local_name: local_name.into(),
            ..Self::default()
        }
    }

    /// True when the remark carries no user content — the canonical
    /// "tombstoned" form. Callers SHOULD delete the underlying account_data
    /// entry rather than ship an empty payload.
    pub fn is_empty(&self) -> bool {
        self.local_name.trim().is_empty()
            && self.note.trim().is_empty()
            && self.tags.is_empty()
            && !self.pinned
    }

    /// Best-effort name to render for a Space: trimmed `local_name` when set,
    /// otherwise `fallback` (the public `Space.title`). Mirrors the priority
    /// in `discovery/client-preferences.md` §3.7 UI rules.
    pub fn display_name<'a>(&'a self, fallback: &'a str) -> &'a str {
        let trimmed = self.local_name.trim();
        if trimmed.is_empty() {
            fallback
        } else {
            trimmed
        }
    }
}

/// Build a `cx.account_data.set` operation envelope for `key` -> `value`.
///
/// `cx.account_data.set` is classified `actor_private_event` in
/// `conformance.rs:393`; reducers MUST NOT include it in shared Space state.
pub fn build_account_data_set(
    space_id: &str,
    actor: &str,
    key: &AccountDataKey,
    value: Value,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.account_data.set").body(serde_json::json!({
        "key": key.as_wire(),
        "value": value,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_round_trip() {
        for s in [
            "client.ui",
            "client.read_receipts",
            "client.presence",
            "client.blocklist",
            "client.notifications",
            "client.language",
        ] {
            assert_eq!(AccountDataKey::from_wire(s).as_wire(), s);
        }
        assert_eq!(AccountDataKey::from_wire("custom.x").as_wire(), "custom.x");
    }

    #[test]
    fn set_recomputes_digest() {
        let mut store = AccountDataStore::new();
        let digest_a = store
            .set(
                AccountDataKey::ClientUi,
                json!({"sidebar_collapsed": true}),
                "0-0-0".into(),
            )
            .unwrap();
        let digest_b = store
            .set(
                AccountDataKey::ClientUi,
                json!({"sidebar_collapsed": false}),
                "0-0-1".into(),
            )
            .unwrap();
        assert_ne!(digest_a, digest_b);
        assert_eq!(
            store.get(&AccountDataKey::ClientUi).unwrap().digest,
            digest_b
        );
    }

    #[test]
    fn space_remark_key_round_trip() {
        let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";
        let key = space_remark_account_data_key(space_id);
        assert_eq!(key, format!("cx.contacts.space.{space_id}"));
        assert_eq!(space_id_from_space_remark_key(&key), Some(space_id));
        assert_eq!(
            space_id_from_space_remark_key("cx.read_receipt.preferences"),
            None
        );
    }

    #[test]
    fn space_remark_serialises_minimal_payload() {
        // Empty fields MUST NOT appear on the wire — keeps the payload
        // tombstone-friendly and avoids leaking placeholder data.
        let remark = SpaceRemark::new(
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "Acme · Eng",
        );
        let wire = serde_json::to_value(&remark).unwrap();
        assert_eq!(
            wire["space_id"],
            "cx:space:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(wire["local_name"], "Acme · Eng");
        assert_eq!(wire["version"], 1);
        assert!(wire.get("note").is_none());
        assert!(wire.get("pinned").is_none());
        assert!(wire.get("tags").is_none());
    }

    #[test]
    fn space_remark_display_name_prefers_local_name() {
        let r = SpaceRemark::new("cx:space:abc", "Acme · Eng");
        assert_eq!(r.display_name("Engineering"), "Acme · Eng");
        let empty = SpaceRemark {
            local_name: "   ".into(),
            ..SpaceRemark::default()
        };
        assert_eq!(empty.display_name("Engineering"), "Engineering");
    }

    #[test]
    fn space_remark_is_empty_treats_whitespace_as_tombstone() {
        let r = SpaceRemark {
            local_name: "   ".into(),
            note: String::new(),
            ..SpaceRemark::default()
        };
        assert!(r.is_empty());
        let r2 = SpaceRemark {
            local_name: "x".into(),
            ..SpaceRemark::default()
        };
        assert!(!r2.is_empty());
    }

    #[test]
    fn build_account_data_set_emits_canonical_kind() {
        let op = build_account_data_set(
            "cx:space:s1",
            "did:web:alice",
            &AccountDataKey::ClientReadReceipts,
            json!({"send": false}),
        )
        .build("node");
        assert_eq!(op.op_type, "cx.account_data.set");
        assert_eq!(op.body["key"], "client.read_receipts");
        assert_eq!(op.body["value"]["send"], false);
    }
}
