//! Client-side account_data layer per `discovery/client-preferences.md`.
//!
//! Spec: actor-private preferences (UI state, read-receipt overrides, presence
//! gating, blocklist, language) are stored as `ck.account_data.set` events with
//! actor-private wire scope. Yougen previously kept these as ad-hoc fields on
//! `LocalState`; this module centralizes the storage shape so
//! `ck.account_data.set` writes have a single canonical entry point.

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
    /// `ck.read_receipt.preferences` — global + per-space + per-flow send override.
    ClientReadReceipts,
    /// `client.presence` — per-space typing / online / last-seen toggles.
    ClientPresence,
    /// `ck.account.blocklist` — actor-private personal blocklist entries.
    ClientBlocklist,
    /// `cx.push_rules` — per-space mute, sound, push routing.
    ClientNotifications,
    /// `cx.dnd_schedule` — actor-private quiet-hour schedule and exceptions.
    ClientDndSchedule,
    /// `client.language` — locale / RTL preferences.
    ClientLanguage,
    /// Application-specific extension key.
    Custom(String),
}

impl AccountDataKey {
    pub fn as_wire(&self) -> &str {
        match self {
            Self::ClientUi => "client.ui",
            Self::ClientReadReceipts => "ck.read_receipt.preferences",
            Self::ClientPresence => "client.presence",
            Self::ClientBlocklist => "ck.account.blocklist",
            Self::ClientNotifications => "cx.push_rules",
            Self::ClientDndSchedule => "cx.dnd_schedule",
            Self::ClientLanguage => "client.language",
            Self::Custom(s) => s,
        }
    }

    pub fn from_wire(s: &str) -> Self {
        match s {
            "client.ui" => Self::ClientUi,
            "ck.read_receipt.preferences" => Self::ClientReadReceipts,
            "client.presence" => Self::ClientPresence,
            "ck.account.blocklist" => Self::ClientBlocklist,
            "cx.push_rules" => Self::ClientNotifications,
            "cx.dnd_schedule" => Self::ClientDndSchedule,
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
///
/// F-ACCT-SNAP-1: tracks the server-declared snapshot head this store was
/// last reconciled to (per `sync/account-data-sync.md`). A new device can
/// hydrate from `snapshot_head` instead of replaying every historic
/// `ck.account_data.set` event; once the snapshot endpoint surfaces a
/// fingerprint matching this value, the client knows it's caught up and
/// can resume incremental sync from the live event stream.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDataStore {
    entries: BTreeMap<String, AccountDataRecord>,
    /// Latest snapshot head this store was reconciled to (e.g.
    /// `sha256:<hex>` per the spec's account-data snapshot fingerprint).
    /// `None` until the first snapshot catch-up completes; subsequent
    /// snapshot fetches refresh the value. Persisted alongside `entries`
    /// so a restart can resume incremental sync from this point. Kept
    /// `#[serde(default)]` for backward compatibility with pre-snapshot
    /// on-disk state.
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

// ─────────────────────────────────────────────────────────────────────────
// A4a — `client.ui` payload (theme, sidebar collapsed, per-space view).
// Spec: `discovery/client-preferences.md` §2 — the `client.ui`
// account-data key carries cross-device UI preferences. Yougen persists
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
/// `cx.account.update_profile` so other actors see it through the
/// directory. We mirror it here so a second device that signs in picks
/// up the same blob without needing to re-fetch `/account/me`.
pub fn build_client_ui_body(
    theme: Option<&str>,
    sidebar_collapsed: Option<bool>,
    per_space_view: &BTreeMap<String, String>,
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
    if !per_space_view.is_empty() {
        let mut obj = serde_json::Map::new();
        for (k, v) in per_space_view {
            obj.insert(k.clone(), Value::String(v.clone()));
        }
        map.insert("per_space_view".to_owned(), Value::Object(obj));
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

/// Wire-key for an actor-private Space remark per
/// `discovery/client-preferences.md` §3.7: `cx.contacts.space.<space_id>`.
///
/// The same string is the path segment passed to soland's
/// `PUT /_cokret/self/account_data/{type}` endpoint. Callers should already have
/// validated `space_id` shape (`ck:space:<uuid>`).
pub fn space_remark_account_data_key(space_id: &str) -> String {
    format!("cx.contacts.space.{space_id}")
}

/// Inverse of [`space_remark_account_data_key`]. Returns the `space_id`
/// segment when `key` is a Space-remark wire key; returns `None` for any
/// other namespace. Used when hydrating `account_data` entries from `/sync`.
pub fn space_id_from_space_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("cx.contacts.space.")
}

/// Wire-key for an actor-private contact remark per
/// `discovery/client-preferences.md` §3.6: `ck.contacts.actor.<did>`.
pub fn contact_remark_account_data_key(actor_did: &str) -> String {
    format!("ck.contacts.actor.{actor_did}")
}

/// Inverse of [`contact_remark_account_data_key`]. Returns the DID segment
/// when `key` is an actor contact remark.
pub fn actor_did_from_contact_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("ck.contacts.actor.")
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
/// `ck.contacts.actor.<did>` shape so future cross-actor / cross-Space
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

/// User-private actor/contact remark per
/// `discovery/client-preferences.md` §3.6.
///
/// Stored under `ck.contacts.actor.<did>` and intentionally never embedded in
/// public profile, mention, message, search, or push payloads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRemark {
    #[serde(default = "default_space_remark_version")]
    pub version: u32,
    pub actor_did: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_handle_at_save: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl ContactRemark {
    pub fn new(actor_did: impl Into<String>, local_name: impl Into<String>) -> Self {
        Self {
            version: 1,
            actor_did: actor_did.into(),
            local_name: local_name.into(),
            ..Self::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.local_name.trim().is_empty()
            && self.note.trim().is_empty()
            && self.tags.is_empty()
            && !self.pinned
    }

    pub fn display_name<'a>(&'a self, fallback: &'a str) -> &'a str {
        let trimmed = self.local_name.trim();
        if trimmed.is_empty() {
            fallback
        } else {
            trimmed
        }
    }
}

/// A single local actor-DID entry in the actor-private personal blocklist
/// (`ck.account.blocklist` per `discovery/client-preferences.md` §3.5).
///
/// The local UI model stays compact (`did`, optional reason, timestamp).
/// [`build_blocklist_account_data_body`] expands it to the canonical account
/// data wire shape: `{ target: { kind: "actor", did }, mode, applies_to,
/// created_at }`. [`blocklist_entries_from_account_data`] accepts that
/// canonical shape and the pre-canonical `{ did, reason, blocked_at }` shape
/// so existing local state and older soland rows continue to hydrate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// Target DID. Lower-cased + trimmed by [`block_user_in`] before
    /// insertion.
    pub did: String,
    /// Optional user-supplied reason. Empty strings tombstone to `None`
    /// on the wire to keep payloads tight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// RFC 3339 timestamp at which the block was first written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_at: Option<String>,
}

impl BlocklistEntry {
    /// Construct a new entry. Normalises `did` (trim) and treats an
    /// empty `reason` as `None`.
    pub fn new(did: impl Into<String>, reason: Option<String>) -> Self {
        let did = did.into().trim().to_owned();
        let reason = reason.and_then(|r| {
            let trimmed = r.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        Self {
            did,
            reason,
            blocked_at: Some(chrono::Utc::now().to_rfc3339()),
        }
    }
}

/// True when `did` appears in `list`. Empty + whitespace `did` is
/// always `false`. Matching is exact on the (already trimmed) DID
/// string — callers are expected to feed canonical DIDs.
pub fn is_blocked(list: &[BlocklistEntry], did: &str) -> bool {
    let needle = did.trim();
    if needle.is_empty() {
        return false;
    }
    list.iter().any(|e| e.did == needle)
}

/// Append `did` to `list` (idempotent — duplicate DIDs are not
/// inserted). Returns `true` when the list changed. `blocked_at` is
/// stamped with the supplied timestamp; pass `chrono::Utc::now()` at
/// the call site so this module stays time-source agnostic.
pub fn block_user_in(
    list: &mut Vec<BlocklistEntry>,
    did: &str,
    reason: Option<String>,
    blocked_at: Option<String>,
) -> bool {
    let mut entry = BlocklistEntry::new(did, reason);
    if entry.did.is_empty() {
        return false;
    }
    if list.iter().any(|e| e.did == entry.did) {
        return false;
    }
    if let Some(blocked_at) = blocked_at {
        entry.blocked_at = Some(blocked_at);
    }
    list.push(entry);
    true
}

/// Remove every entry matching `did` from `list`. Returns `true` when
/// at least one entry was removed.
pub fn unblock_user_in(list: &mut Vec<BlocklistEntry>, did: &str) -> bool {
    let needle = did.trim();
    if needle.is_empty() {
        return false;
    }
    let before = list.len();
    list.retain(|e| e.did != needle);
    list.len() != before
}

const BLOCKLIST_ACCOUNT_DATA_VERSION: u32 = 1;
const DEFAULT_BLOCKLIST_APPLIES_TO: &[&str] = &[
    "messages",
    "mentions",
    "dm",
    "calls",
    "presence",
    "notifications",
    "directory",
];

/// Canonical wire body for the `ck.account.blocklist` account-data entry.
/// The settings UI calls this just before PUTting via
/// [`crate::api::CokretApi::set_account_data`]; keep the shape aligned with
/// `discovery/client-preferences.md` §3.5 so other clients agree on layout.
pub fn build_blocklist_account_data_body(entries: &[BlocklistEntry]) -> Value {
    let entries = entries
        .iter()
        .filter(|entry| !entry.did.trim().is_empty())
        .map(|entry| {
            let mut object = serde_json::json!({
                "target": {
                    "kind": "actor",
                    "did": entry.did.trim(),
                },
                "mode": "block",
                "applies_to": DEFAULT_BLOCKLIST_APPLIES_TO,
                "created_at": entry
                    .blocked_at
                    .clone()
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
            });
            if let Some(reason) = entry
                .reason
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                && let Some(map) = object.as_object_mut()
            {
                map.insert("reason_code".to_owned(), Value::String(reason.to_owned()));
            }
            object
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "version": BLOCKLIST_ACCOUNT_DATA_VERSION,
        "entries": entries,
    })
}

/// Parse the `ck.account.blocklist` account-data content body. Malformed
/// actor entries are skipped instead of partially corrupting the local UI.
/// This parser intentionally accepts legacy rows written by earlier yougen
/// and cotest fixtures: `{ did, reason, blocked_at }`,
/// `{ target: "did:...", kind: "block" }`, and the canonical
/// `{ target: { kind: "actor", did }, mode: "block", created_at }`.
pub fn blocklist_entries_from_account_data(value: &Value) -> Result<Vec<BlocklistEntry>, String> {
    let entries = value
        .get("entries")
        .ok_or_else(|| "cx.account.blocklist.entries missing".to_owned())?;
    let entries = entries
        .as_array()
        .ok_or_else(|| "cx.account.blocklist.entries must be an array".to_owned())?;
    Ok(entries
        .iter()
        .filter_map(blocklist_entry_from_account_data_value)
        .collect())
}

fn blocklist_entry_from_account_data_value(value: &Value) -> Option<BlocklistEntry> {
    match value {
        Value::String(did) => blocklist_entry_from_parts(did, None, None),
        Value::Object(object) => {
            let mode = object
                .get("mode")
                .or_else(|| object.get("kind"))
                .or_else(|| object.get("action"))
                .or_else(|| object.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("block");
            if matches!(mode, "allow" | "unblock" | "removed" | "deleted") {
                return None;
            }
            if !matches!(mode, "block" | "mute" | "hide") {
                return None;
            }
            let did = object
                .get("target")
                .and_then(blocklist_target_did)
                .or_else(|| object.get("did").and_then(Value::as_str))
                .or_else(|| object.get("actor").and_then(Value::as_str))?;
            let reason = object
                .get("reason_code")
                .or_else(|| object.get("reason"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let blocked_at = object
                .get("created_at")
                .or_else(|| object.get("blocked_at"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            blocklist_entry_from_parts(did, reason, blocked_at)
        }
        _ => None,
    }
}

fn blocklist_target_did(value: &Value) -> Option<&str> {
    match value {
        Value::String(did) => Some(did.as_str()),
        Value::Object(object) => {
            let target_kind = object.get("kind").and_then(Value::as_str);
            if target_kind.is_some_and(|kind| kind != "actor") {
                return None;
            }
            object
                .get("did")
                .or_else(|| object.get("actor"))
                .or_else(|| object.get("id"))
                .and_then(Value::as_str)
        }
        _ => None,
    }
}

fn blocklist_entry_from_parts(
    did: &str,
    reason: Option<String>,
    blocked_at: Option<String>,
) -> Option<BlocklistEntry> {
    let mut entry = BlocklistEntry::new(did, reason);
    if entry.did.trim().is_empty() {
        return None;
    }
    if let Some(blocked_at) = blocked_at {
        let blocked_at = blocked_at.trim();
        if !blocked_at.is_empty() {
            entry.blocked_at = Some(blocked_at.to_owned());
        }
    }
    Some(entry)
}

/// Build a `ck.account_data.set` operation envelope for `key` -> `value`.
///
/// `ck.account_data.set` is classified `actor_private_event` in
/// `conformance.rs:393`; reducers MUST NOT include it in shared Space state.
pub fn build_account_data_set(
    space_id: &str,
    actor: &str,
    key: &AccountDataKey,
    value: Value,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "ck.account_data.set").body(serde_json::json!({
        "key": key.as_wire(),
        "value": value,
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // ── F-ACCT-SNAP-1 ────────────────────────────────────────────────

    #[test]
    fn snapshot_head_default_is_none_and_round_trips() {
        let mut store = AccountDataStore::new();
        assert_eq!(store.snapshot_head(), None);

        store.set_snapshot_head("sha256:abc123");
        assert_eq!(store.snapshot_head(), Some("sha256:abc123"));

        // Subsequent reconcile overwrites without affecting entries.
        store
            .set(
                AccountDataKey::ClientUi,
                json!({"theme": "night"}),
                "01970e589d21-0001-a13f9c2e".to_owned(),
            )
            .unwrap();
        store.set_snapshot_head("sha256:def456");
        assert_eq!(store.snapshot_head(), Some("sha256:def456"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn snapshot_head_clears_independently_of_entries() {
        let mut store = AccountDataStore::new();
        store
            .set(
                AccountDataKey::ClientUi,
                json!({"theme": "light"}),
                "01970e589d21-0001-a13f9c2e".to_owned(),
            )
            .unwrap();
        store.set_snapshot_head("sha256:abc123");
        store.clear_snapshot_head();
        assert_eq!(store.snapshot_head(), None);
        // Entries survive the snapshot reset — a trust-bundle change
        // forces re-reconciliation but doesn't wipe live data.
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn snapshot_head_persists_through_serde_round_trip() {
        let mut store = AccountDataStore::new();
        store
            .set(
                AccountDataKey::ClientUi,
                json!({"theme": "night"}),
                "01970e589d21-0001-a13f9c2e".to_owned(),
            )
            .unwrap();
        store.set_snapshot_head("sha256:abc123");

        let bytes = serde_json::to_string(&store).unwrap();
        let restored: AccountDataStore = serde_json::from_str(&bytes).unwrap();
        assert_eq!(restored.snapshot_head(), Some("sha256:abc123"));
        assert_eq!(restored.len(), 1);
    }

    /// Pre-snapshot persisted state has no `snapshot_head` field; loading
    /// it should default to `None` rather than fail to deserialize.
    #[test]
    fn snapshot_head_absent_from_legacy_state_defaults_to_none() {
        let legacy = json!({
            "entries": {
                "client.ui": {
                    "key": "client.ui",
                    "value": {"theme": "light"},
                    "digest": "sha256:00",
                    "hlc": ""
                }
            }
        });
        let store: AccountDataStore = serde_json::from_value(legacy).unwrap();
        assert_eq!(store.snapshot_head(), None);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn key_round_trip() {
        for s in [
            "client.ui",
            "ck.read_receipt.preferences",
            "client.presence",
            "ck.account.blocklist",
            "cx.push_rules",
            "cx.dnd_schedule",
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
        let space_id = "ck:space:0196419b-0000-7000-8000-000000000000";
        let key = space_remark_account_data_key(space_id);
        assert_eq!(key, format!("cx.contacts.space.{space_id}"));
        assert_eq!(space_id_from_space_remark_key(&key), Some(space_id));
        assert_eq!(
            space_id_from_space_remark_key("ck.read_receipt.preferences"),
            None
        );
    }

    #[test]
    fn contact_remark_key_round_trip() {
        let did = "did:web:alice.example";
        let key = contact_remark_account_data_key(did);
        assert_eq!(key, format!("ck.contacts.actor.{did}"));
        assert_eq!(actor_did_from_contact_remark_key(&key), Some(did));
        assert_eq!(
            actor_did_from_contact_remark_key("cx.contacts.space.x"),
            None
        );
    }

    #[test]
    fn space_remark_serialises_minimal_payload() {
        // Empty fields MUST NOT appear on the wire — keeps the payload
        // tombstone-friendly and avoids leaking placeholder data.
        let remark = SpaceRemark::new(
            "ck:space:0196419b-0000-7000-8000-000000000000",
            "Acme · Eng",
        );
        let wire = serde_json::to_value(&remark).unwrap();
        assert_eq!(
            wire["space_id"],
            "ck:space:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(wire["local_name"], "Acme · Eng");
        assert_eq!(wire["version"], 1);
        assert!(wire.get("note").is_none());
        assert!(wire.get("pinned").is_none());
        assert!(wire.get("tags").is_none());
    }

    #[test]
    fn space_remark_display_name_prefers_local_name() {
        let r = SpaceRemark::new("ck:space:abc", "Acme · Eng");
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
    fn contact_remark_serialises_minimal_private_payload() {
        let remark = ContactRemark::new("did:web:alice.example", "Alice from Ops");
        let wire = serde_json::to_value(&remark).unwrap();
        assert_eq!(wire["version"], 1);
        assert_eq!(wire["actor_did"], "did:web:alice.example");
        assert_eq!(wire["local_name"], "Alice from Ops");
        assert!(wire.get("note").is_none());
        assert_eq!(remark.display_name("Alice"), "Alice from Ops");

        let empty = ContactRemark {
            actor_did: "did:web:alice.example".to_owned(),
            local_name: " ".to_owned(),
            ..ContactRemark::default()
        };
        assert!(empty.is_empty());
    }

    #[test]
    fn is_blocked_returns_true_for_blocked_did() {
        let list = vec![
            BlocklistEntry::new("did:web:alice.example", None),
            BlocklistEntry::new("did:web:bob.example", Some("spam".into())),
        ];
        assert!(is_blocked(&list, "did:web:alice.example"));
        assert!(is_blocked(&list, "did:web:bob.example"));
        assert!(!is_blocked(&list, "did:web:carol.example"));
        // Whitespace-only / empty needle short-circuits to false.
        assert!(!is_blocked(&list, ""));
        assert!(!is_blocked(&list, "   "));
    }

    #[test]
    fn block_user_appends_to_list_without_duplicates() {
        let mut list: Vec<BlocklistEntry> = Vec::new();
        assert!(block_user_in(
            &mut list,
            "did:web:alice.example",
            Some("spam".into()),
            Some("2026-05-18T00:00:00Z".into()),
        ));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].did, "did:web:alice.example");
        assert_eq!(list[0].reason.as_deref(), Some("spam"));
        assert_eq!(list[0].blocked_at.as_deref(), Some("2026-05-18T00:00:00Z"));
        // Second call with the same DID is a no-op.
        assert!(!block_user_in(
            &mut list,
            "did:web:alice.example",
            Some("different".into()),
            None,
        ));
        assert_eq!(list.len(), 1);
        // Empty DID is rejected.
        assert!(!block_user_in(&mut list, "   ", None, None));
        assert_eq!(list.len(), 1);
        // Empty reason tombstones to None on the wire.
        assert!(block_user_in(
            &mut list,
            "did:web:bob.example",
            Some("   ".into()),
            None,
        ));
        assert_eq!(list[1].reason, None);
    }

    #[test]
    fn unblock_user_removes_matching_did() {
        let mut list = vec![
            BlocklistEntry::new("did:web:alice.example", None),
            BlocklistEntry::new("did:web:bob.example", Some("spam".into())),
        ];
        assert!(unblock_user_in(&mut list, "did:web:alice.example"));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].did, "did:web:bob.example");
        // Idempotent: removing a missing DID returns false.
        assert!(!unblock_user_in(&mut list, "did:web:alice.example"));
        assert_eq!(list.len(), 1);
        // Empty needle is rejected.
        assert!(!unblock_user_in(&mut list, ""));
    }

    #[test]
    fn build_blocklist_account_data_body_emits_entries_array() {
        let entries = vec![BlocklistEntry::new(
            "did:web:alice.example",
            Some("spam".into()),
        )];
        let body = build_blocklist_account_data_body(&entries);
        assert_eq!(body["version"], 1);
        assert_eq!(body["entries"][0]["target"]["kind"], "actor");
        assert_eq!(body["entries"][0]["target"]["did"], "did:web:alice.example");
        assert_eq!(body["entries"][0]["mode"], "block");
        assert_eq!(body["entries"][0]["reason_code"], "spam");
        assert!(body["entries"][0]["created_at"].is_string());
        assert!(
            body["entries"][0]["applies_to"]
                .as_array()
                .unwrap()
                .contains(&json!("messages"))
        );
    }

    #[test]
    fn blocklist_entries_parse_legacy_account_data_body() {
        let body = json!({
            "entries": [
                {"did": "did:web:mallory.example", "reason": "spam"},
                {"did": "   "}
            ]
        });
        let entries = blocklist_entries_from_account_data(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].did, "did:web:mallory.example");
    }

    #[test]
    fn blocklist_entries_parse_canonical_account_data_body() {
        let body = json!({
            "version": 1,
            "entries": [
                {
                    "target": {"kind": "actor", "did": "did:web:mallory.example"},
                    "mode": "block",
                    "reason_code": "harassment",
                    "created_at": "2026-05-29T00:00:00Z"
                },
                {
                    "target": {"kind": "actor", "did": "did:web:carol.example"},
                    "mode": "unblock",
                    "created_at": "2026-05-29T00:00:00Z"
                },
                {
                    "target": {"kind": "domain", "value": "example.com"},
                    "mode": "block",
                    "created_at": "2026-05-29T00:00:00Z"
                }
            ]
        });
        let entries = blocklist_entries_from_account_data(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].did, "did:web:mallory.example");
        assert_eq!(entries[0].reason.as_deref(), Some("harassment"));
        assert_eq!(
            entries[0].blocked_at.as_deref(),
            Some("2026-05-29T00:00:00Z")
        );
    }

    // ── A4a — client.ui shape + merge logic ────────────────────────────
    #[test]
    fn build_client_ui_body_only_emits_present_fields() {
        let body = build_client_ui_body(Some("light"), None, &BTreeMap::new(), None);
        assert_eq!(body["theme"], "light");
        assert!(body.get("sidebar_collapsed").is_none());
        assert!(body.get("per_space_view").is_none());
        assert!(body.get("avatar_blob_ref").is_none());

        let mut per_space = BTreeMap::new();
        per_space.insert("ck:space:abc".to_owned(), "kanban".to_owned());
        let body = build_client_ui_body(Some("night"), Some(true), &per_space, None);
        assert_eq!(body["theme"], "night");
        assert_eq!(body["sidebar_collapsed"], true);
        assert_eq!(body["per_space_view"]["ck:space:abc"], "kanban");

        // Empty theme string is dropped (treated as unset).
        let body = build_client_ui_body(Some(""), Some(false), &BTreeMap::new(), None);
        assert!(body.get("theme").is_none());
        assert_eq!(body["sidebar_collapsed"], false);
    }

    // ── A4b — avatar_blob_ref round-trip through client.ui ─────────────
    #[test]
    fn avatar_blob_ref_round_trips_through_client_ui() {
        let blob_ref = "ck:blob:sha256:0123456789abcdef";
        let body = build_client_ui_body(Some("light"), None, &BTreeMap::new(), Some(blob_ref));
        assert_eq!(body["avatar_blob_ref"], blob_ref);
        assert_eq!(
            avatar_blob_ref_from_client_ui(&body),
            Some(blob_ref.to_owned())
        );

        // Empty / whitespace-only references are preserved as an explicit
        // tombstone so another device can clear its local avatar cache.
        let tombstoned = build_client_ui_body(None, None, &BTreeMap::new(), Some("   "));
        assert_eq!(tombstoned["avatar_blob_ref"], "");
        assert_eq!(avatar_blob_ref_from_client_ui(&tombstoned), None);
        assert!(avatar_blob_ref_tombstoned_from_client_ui(&tombstoned));

        let without_avatar = json!({"theme": "light"});
        assert_eq!(avatar_blob_ref_from_client_ui(&without_avatar), None);

        // Non-string values are rejected.
        let weird = json!({"avatar_blob_ref": 42});
        assert_eq!(avatar_blob_ref_from_client_ui(&weird), None);
    }

    #[test]
    fn theme_from_client_ui_only_accepts_known_themes() {
        assert_eq!(
            theme_from_client_ui(&json!({"theme": "light"})),
            Some("light".to_owned())
        );
        assert_eq!(
            theme_from_client_ui(&json!({"theme": "night"})),
            Some("night".to_owned())
        );
        assert_eq!(
            theme_from_client_ui(&json!({"theme": "system"})),
            Some("system".to_owned())
        );
        assert_eq!(theme_from_client_ui(&json!({"theme": "neon"})), None);
        assert_eq!(theme_from_client_ui(&json!({"theme": ""})), None);
        assert_eq!(theme_from_client_ui(&json!({})), None);
    }

    #[test]
    fn merge_client_ui_theme_prefers_remote_when_different() {
        // remote has a different valid theme → return it
        assert_eq!(
            merge_client_ui_theme("light", &json!({"theme": "night"})),
            Some("night".to_owned())
        );
        // remote matches local → no change
        assert_eq!(
            merge_client_ui_theme("light", &json!({"theme": "light"})),
            None
        );
        // remote has no theme field → no change (older client wrote only
        // sidebar_collapsed); local stays authoritative
        assert_eq!(
            merge_client_ui_theme("light", &json!({"sidebar_collapsed": true})),
            None
        );
        // remote has an invalid theme → no change
        assert_eq!(
            merge_client_ui_theme("system", &json!({"theme": "neon"})),
            None
        );
    }

    #[test]
    fn build_account_data_set_emits_canonical_kind() {
        let op = build_account_data_set(
            "ck:space:s1",
            "did:web:alice",
            &AccountDataKey::ClientReadReceipts,
            json!({"send": false}),
        )
        .build("node");
        assert_eq!(op.kind, "ck.account_data.set");
        assert_eq!(op.payload["key"], "ck.read_receipt.preferences");
        assert_eq!(op.payload["value"]["send"], false);
    }
}
