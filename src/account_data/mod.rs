//! Client-side account_data layer per `discovery/client-preferences.md`.
//!
//! Spec: actor-private preferences (UI state, read-receipt overrides, presence
//! gating, blocklist, language) are stored as `ak.account_data.set` events with
//! actor-private wire scope. Inkson previously kept these as ad-hoc fields on
//! `LocalState`; this module centralizes the storage shape so
//! `ak.account_data.set` writes have a single canonical entry point.

use std::collections::BTreeMap;

use arkret_wire::AccountDataKey as WireAccountDataKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod blocklist;
mod client_ui;
mod crypto;
mod keys;
mod productivity;
mod remark;

pub use blocklist::*;
pub use client_ui::*;
pub use crypto::*;
pub use keys::*;
pub use productivity::*;
pub use remark::*;

/// Canonical account_data namespace keys.
///
/// Keys mirror the spec example list in `discovery/client-preferences.md` §2.
/// Custom apps may extend with `Custom(String)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountDataKey {
    /// `ak.client.ui_state` — sidebar collapsed, theme, default view per Realm.
    ClientUi,
    /// `ak.read_receipt.preferences` — global + per-Realm + per-strand send override.
    ClientReadReceipts,
    /// `ak.presence.visibility` — principal-private presence fanout policy.
    ClientPresence,
    /// `ak.presence.preference` — principal-private manual presence
    /// preference (pinned state / status message / expiry), enforced on
    /// the send side (profiles-presence.md §3.6).
    ClientPresencePreference,
    /// `ak.account.blocklist` — actor-private personal blocklist entries.
    ClientBlocklist,
    /// `ak.push_rules` — per-Realm mute, sound, push routing.
    ClientNotifications,
    /// `ak.dnd_schedule` — actor-private quiet-hour schedule and exceptions.
    ClientDndSchedule,
    /// `client.language` — locale / RTL preferences.
    ClientLanguage,
    /// Application-specific extension key.
    Custom(String),
}

impl AccountDataKey {
    pub fn as_wire(&self) -> &str {
        match self {
            Self::ClientUi => WireAccountDataKey::CLIENT_UI_STATE,
            Self::ClientReadReceipts => WireAccountDataKey::READ_RECEIPT_PREFERENCES,
            Self::ClientPresence => WireAccountDataKey::PRESENCE_VISIBILITY,
            Self::ClientPresencePreference => WireAccountDataKey::PRESENCE_PREFERENCE,
            Self::ClientBlocklist => WireAccountDataKey::ACCOUNT_BLOCKLIST,
            Self::ClientNotifications => WireAccountDataKey::PUSH_RULES,
            Self::ClientDndSchedule => WireAccountDataKey::DND_SCHEDULE,
            Self::ClientLanguage => "client.language",
            Self::Custom(s) => s,
        }
    }

    pub fn from_wire(s: &str) -> Self {
        match s {
            WireAccountDataKey::CLIENT_UI_STATE => Self::ClientUi,
            WireAccountDataKey::READ_RECEIPT_PREFERENCES => Self::ClientReadReceipts,
            WireAccountDataKey::PRESENCE_VISIBILITY => Self::ClientPresence,
            WireAccountDataKey::PRESENCE_PREFERENCE => Self::ClientPresencePreference,
            WireAccountDataKey::ACCOUNT_BLOCKLIST => Self::ClientBlocklist,
            WireAccountDataKey::PUSH_RULES => Self::ClientNotifications,
            WireAccountDataKey::DND_SCHEDULE => Self::ClientDndSchedule,
            "client.language" => Self::ClientLanguage,
            other => Self::Custom(other.to_owned()),
        }
    }
}

/// A single account_data record with the server-authoritative CAS revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDataRecord {
    pub key: String,
    pub value: Value,
    pub revision: u64,
    /// Last-touched HLC string. Empty before the first write.
    #[serde(default)]
    pub hlc: String,
}

/// In-memory actor-private account_data store. Persistence is the caller's
/// responsibility (e.g. `local_state` hydrate / save).
///
/// F-ACCT-SNAP-1: tracks the server-declared snapshot head this store was
/// last reconciled to (per `sync/account-data-sync.md`). A new device can
/// hydrate from `snapshot_head` instead of replaying every historic
/// `ak.account_data.set` event; once the snapshot endpoint surfaces a
/// fingerprint matching this value, the client knows it's caught up and
/// can resume incremental sync from the live event stream.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDataStore {
    entries: BTreeMap<String, AccountDataRecord>,
    /// Latest snapshot head this store was reconciled to (e.g.
    /// `sha256:<hex>` per the spec's account-data snapshot fingerprint).
    /// `None` until the first snapshot catch-up completes; subsequent
    /// snapshot fetches refresh the value. Persisted alongside `entries`
    /// so a restart can resume incremental sync from this point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_head: Option<String>,
}

impl AccountDataStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &AccountDataKey) -> Option<&AccountDataRecord> {
        self.entries.get(key.as_wire())
    }

    /// Insert or replace `key` with a server-observed revision.
    pub fn set(
        &mut self,
        key: AccountDataKey,
        value: Value,
        revision: u64,
        hlc: String,
    ) -> anyhow::Result<u64> {
        if revision == 0 {
            anyhow::bail!("live account_data revision must be greater than zero");
        }
        let wire = key.as_wire().to_owned();
        if let Some(current) = self.entries.get(&wire) {
            if current.revision > revision {
                anyhow::bail!(
                    "stale account_data revision {} is older than current revision {}",
                    revision,
                    current.revision,
                );
            }
            if current.revision == revision && (current.value != value || current.hlc != hlc) {
                anyhow::bail!("account_data revision collision carries different content");
            }
        }
        let record = AccountDataRecord {
            key: wire.clone(),
            value,
            revision,
            hlc,
        };
        self.entries.insert(wire, record);
        Ok(revision)
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

    /// F-ACCT-SNAP-1: most recent snapshot head this store has caught
    /// up to, or `None` before the first snapshot reconcile.
    pub fn snapshot_head(&self) -> Option<&str> {
        self.snapshot_head.as_deref()
    }

    /// F-ACCT-SNAP-1: record the snapshot head the store was just
    /// reconciled to (called after applying a snapshot batch from the
    /// server). Subsequent live events apply on top of this point.
    pub fn set_snapshot_head(&mut self, head: impl Into<String>) {
        self.snapshot_head = Some(head.into());
    }

    /// F-ACCT-SNAP-1: drop the snapshot head (e.g. on logout or when a
    /// trust-bundle change invalidates prior reconciliation).
    pub fn clear_snapshot_head(&mut self) {
        self.snapshot_head = None;
    }
}

#[cfg(test)]
mod tests;
