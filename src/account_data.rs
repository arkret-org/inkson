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
    pub fn set(&mut self, key: AccountDataKey, value: Value, hlc: String) -> anyhow::Result<String> {
        let digest = canonical_sha256(&value)?;
        let wire = key.as_wire().to_owned();
        let record = AccountDataRecord { key: wire.clone(), value, digest: digest.clone(), hlc };
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
