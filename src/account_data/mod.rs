//! Client-side account_data layer per `discovery/client-preferences.md`.
//!
//! Spec: actor-private preferences (UI state, read-receipt overrides, presence
//! gating, blocklist) are stored as `ak.account_data.set` events with
//! actor-private wire scope. Inkson previously kept these as ad-hoc fields on
//! `LocalState`; this module centralizes the storage shape so
//! `ak.account_data.set` writes have a single canonical entry point.
//!
//! The key vocabulary itself is **not** redefined here. Registered namespace
//! literals come from the generated `arkret_wire::AccountDataKey` (whose rows
//! are `account-data-key-registry.json`), and keys travel through this module
//! as the `&str` the wire actually carries — the same shape the private
//! account-data builders already use. Derived keys are built by the
//! `arkret_sdk` helpers wrapped in [`keys`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod blocklist;
mod client_ui;
mod crypto;
mod keys;
mod notification_inbox;
mod productivity;
mod remark;

pub use blocklist::*;
pub use client_ui::*;
pub use crypto::*;
pub use keys::*;
pub use notification_inbox::*;
pub use productivity::*;
pub use remark::*;

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
/// last reconciled to (the account-data delta itself arrives on the
/// `sync/client-sync.md` account-subscribe frame). A new device can
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

    pub fn get(&self, key: &str) -> Option<&AccountDataRecord> {
        self.entries.get(key)
    }

    /// Insert or replace `key` with a server-observed revision.
    pub fn set(
        &mut self,
        key: &str,
        value: Value,
        revision: u64,
        hlc: String,
    ) -> anyhow::Result<u64> {
        if revision == 0 {
            anyhow::bail!("live account_data revision must be greater than zero");
        }
        let wire = key.to_owned();
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

    pub fn remove(&mut self, key: &str) -> Option<AccountDataRecord> {
        self.entries.remove(key)
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
