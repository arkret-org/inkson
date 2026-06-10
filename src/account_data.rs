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
    /// `client.ui` — sidebar collapsed, theme, default view per Realm.
    ClientUi,
    /// `ck.read_receipt.preferences` — global + per-Realm + per-flow send override.
    ClientReadReceipts,
    /// `client.presence` — per-Realm typing / online / last-seen toggles.
    ClientPresence,
    /// `ck.account.blocklist` — actor-private personal blocklist entries.
    ClientBlocklist,
    /// `ck.push_rules` — per-Realm mute, sound, push routing.
    ClientNotifications,
    /// `ck.dnd_schedule` — actor-private quiet-hour schedule and exceptions.
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
            Self::ClientNotifications => "ck.push_rules",
            Self::ClientDndSchedule => "ck.dnd_schedule",
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
            "ck.push_rules" => Self::ClientNotifications,
            "ck.dnd_schedule" => Self::ClientDndSchedule,
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
// A4a — `client.ui` payload (theme, sidebar collapsed, per-Realm view).
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
/// `ck.self.account.update_profile` so other actors see it through the
/// directory. We mirror it here so a second device that signs in picks
/// up the same blob without needing to re-fetch `/account/me`.
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

/// Wire-key for an actor-private Realm remark per
/// `discovery/client-preferences.md` §3.7: `ck.contacts.realm.<realm_id>`.
///
/// The same string is the `key` used in `ck.account_data.set`. Callers should
/// already have validated `realm_id` shape (`ck:realm:<uuid>`).
pub fn realm_remark_account_data_key(realm_id: &str) -> String {
    format!("ck.contacts.realm.{realm_id}")
}

/// Inverse of [`realm_remark_account_data_key`]. Returns the `realm_id`
/// segment when `key` is a Realm-remark wire key; returns `None` for any
/// other namespace. Used when hydrating `account_data` entries from `/sync`.
pub fn realm_id_from_realm_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("ck.contacts.realm.")
}

/// Wire-key for an actor-private contact remark per
/// `discovery/client-preferences.md` §3.6: `ck.contacts.actor.<did>`.
pub fn contact_remark_account_data_key(actor_id: &str) -> String {
    format!("ck.contacts.actor.{actor_id}")
}

/// Inverse of [`contact_remark_account_data_key`]. Returns the DID segment
/// when `key` is an actor contact remark.
pub fn actor_id_from_contact_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("ck.contacts.actor.")
}

/// User-private Realm remark per `discovery/client-preferences.md` §3.7.
///
/// Persisted as the `content` payload under
/// `ck.contacts.realm.<realm_id>` (the wire key built by
/// [`realm_remark_account_data_key`]). The protocol treats the payload as
/// opaque on the server; this struct is the canonical local shape so the
/// settings UI and the sidebar agree.
///
/// All fields are spec-aligned; the struct intentionally mirrors the §3.6
/// `ck.contacts.actor.<did>` shape so future cross-actor / cross-Realm
/// editing UIs can be unified.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmRemark {
    /// Schema version — currently fixed to `1`.
    #[serde(default = "default_remark_version")]
    pub version: u32,
    /// Spec §3.7 `subject` — the Realm this remark applies to.
    pub subject: RemarkSubject,
    /// Spec §3.7 `local_name` — actor-private alias shown in place of the
    /// public Realm title when set. Max 128 chars; empty / whitespace-only
    /// means "no remark". Never serialised when empty so the wire payload
    /// can be tombstoned by setting `local_name=""`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_name: String,
    /// Spec §3.7 `note` — free-text up to 4096 chars.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Spec §3.7 `tags` — private grouping labels; namespace shared with
    /// `ck.tags.realm.<realm_id>` so the same label can drive both UIs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Spec §3.7 `pinned` — whether the Realm sticks to the top of the
    /// sidebar regardless of activity.
    #[serde(default, skip_serializing_if = "is_false")]
    pub pinned: bool,
    /// Spec §3.7 `verified_title_at_save` — Realm `title` snapshot at the
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemarkSubject {
    pub kind: String,
    pub id: String,
}

impl Default for RemarkSubject {
    fn default() -> Self {
        Self {
            kind: "realm".to_owned(),
            id: String::new(),
        }
    }
}

fn default_remark_version() -> u32 {
    1
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl RealmRemark {
    /// New remark seeded with `local_name`. Caller fills the rest as needed.
    pub fn new(realm_id: impl Into<String>, local_name: impl Into<String>) -> Self {
        Self {
            version: 1,
            subject: RemarkSubject {
                kind: "realm".to_owned(),
                id: realm_id.into(),
            },
            local_name: local_name.into(),
            ..Self::default()
        }
    }

    /// Build the next private Realm remark after toggling only `pinned`.
    ///
    /// This intentionally starts from the existing remark when one is present
    /// so local_name / note / tags and verified snapshots survive pin/unpin.
    /// The account-data key supplies the canonical Realm id, so the subject is
    /// re-normalized to match that key before writing.
    pub fn with_pinned_preserving_fields(
        realm_id: impl Into<String>,
        existing: Option<&Self>,
        pinned: bool,
        updated_at: Option<String>,
    ) -> Self {
        let realm_id = realm_id.into();
        let mut next = existing
            .cloned()
            .unwrap_or_else(|| Self::new(realm_id.clone(), ""));
        if next.version == 0 {
            next.version = 1;
        }
        next.subject = RemarkSubject {
            kind: "realm".to_owned(),
            id: realm_id,
        };
        next.pinned = pinned;

        if let Some(updated_at) = updated_at {
            if next.saved_at.is_none() && !next.is_empty() {
                next.saved_at = Some(updated_at.clone());
            }
            next.updated_at = Some(updated_at);
        }

        next
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

    /// Best-effort name to render for a Realm: trimmed `local_name` when set,
    /// otherwise `fallback` (the public Realm title). Mirrors the priority
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
    #[serde(default = "default_remark_version")]
    pub version: u32,
    /// Subject actor DID. Wire field `actor_id` per the v1 protocol naming
    /// rule: a single protocol responsibility subject uses the `_id` suffix
    /// even when the value is a DID (see `forbidden-wire-fields.json`).
    pub actor_id: String,
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
    pub fn new(actor_id: impl Into<String>, local_name: impl Into<String>) -> Self {
        Self {
            version: 1,
            actor_id: actor_id.into(),
            local_name: local_name.into(),
            ..Self::default()
        }
    }

    pub fn with_pinned_preserving_fields(
        actor_id: impl Into<String>,
        existing: Option<&Self>,
        pinned: bool,
        updated_at: Option<String>,
    ) -> Self {
        let actor_id = actor_id.into();
        let mut next = existing
            .cloned()
            .unwrap_or_else(|| Self::new(actor_id.clone(), ""));
        if next.version == 0 {
            next.version = 1;
        }
        next.actor_id = actor_id;
        next.pinned = pinned;

        if let Some(updated_at) = updated_at {
            if next.saved_at.is_none() && !next.is_empty() {
                next.saved_at = Some(updated_at.clone());
            }
            next.updated_at = Some(updated_at);
        }

        next
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
/// [`build_blocklist_account_data_body`] expands it to the canonical account
/// data wire shape: `{ target: { kind, did|domain }, mode, applies_to,
/// reason_code, created_at, expires_at, entry_id }`.
/// [`blocklist_entries_from_account_data`] accepts that canonical shape and
/// the pre-canonical `{ did, reason, blocked_at }` shape so existing local
/// state and older soland rows continue to hydrate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// Target identifier value. For `kind = "actor" | "service" |
    /// "organization" | "device"` this is a DID; for `kind = "domain"` it is
    /// a normalized DNS domain. Trimmed before insertion (DID values are not
    /// lower-cased because base58 SCIDs are case-sensitive; domain values are
    /// lower-cased by [`normalize_blocklist_value`]). The field name stays
    /// `did` for wire/UI backward-compat — non-DID kinds reuse the same slot.
    pub did: String,
    /// `target.kind` per `discovery/client-preferences.md` §3.5. Defaults to
    /// `actor` so legacy disk rows and older wire shapes (which only ever
    /// carried actor DIDs) hydrate unchanged.
    #[serde(default = "default_blocklist_target_kind")]
    pub kind: String,
    /// Optional user-supplied reason (serialised as `reason_code`). Empty
    /// strings tombstone to `None` on the wire to keep payloads tight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// RFC 3339 timestamp at which the block was first written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_at: Option<String>,
    /// Surfaces the block applies to (`messages`, `dm`, `calls`, …). Empty
    /// means "all default surfaces" and expands to
    /// [`DEFAULT_BLOCKLIST_APPLIES_TO`] on the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to: Vec<String>,
    /// Optional RFC 3339 expiry. `None` is a permanent block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Stable per-entry id (`ck:block:<hash>`), preserved across sync so other
    /// clients / appeal flows can reference a specific block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
}

/// Default `target.kind` for personal blocklist entries.
pub const DEFAULT_BLOCKLIST_TARGET_KIND: &str = "actor";

/// `target.kind` values the personal blocklist settings UI can create. The
/// spec (`client-preferences.md` §3.5) also defines `device` / `handle` /
/// `applet` / `keyword`; those are accepted on parse but not yet offered as
/// create options in the UI.
pub const BLOCKLIST_TARGET_KINDS: &[&str] = &["actor", "service", "domain", "organization"];

fn default_blocklist_target_kind() -> String {
    DEFAULT_BLOCKLIST_TARGET_KIND.to_owned()
}

/// True when `kind` identifies its target by DID (vs. a bare domain string).
pub fn blocklist_kind_is_did(kind: &str) -> bool {
    matches!(kind, "actor" | "service" | "organization" | "device")
}

/// Normalise a block target value. DID kinds are only trimmed (SCIDs are
/// case-sensitive); domain kinds are trimmed, lower-cased and stripped of an
/// accidental URL scheme / path / leading `@` so the stored value is a bare
/// DNS domain per `client-preferences.md` §3.5.
pub fn normalize_blocklist_value(kind: &str, value: &str) -> String {
    let trimmed = value.trim();
    if blocklist_kind_is_did(kind) {
        return trimmed.to_owned();
    }
    let mut v = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches('@');
    v = v.split('/').next().unwrap_or(v);
    v.trim_end_matches('.').to_ascii_lowercase()
}

/// Drop unknown / duplicate surfaces and lower-case the rest, preserving the
/// caller's order. An empty result is left empty so the wire builder can
/// expand it to [`DEFAULT_BLOCKLIST_APPLIES_TO`].
fn normalize_blocklist_applies_to(values: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in values {
        let v = v.trim().to_ascii_lowercase();
        if DEFAULT_BLOCKLIST_APPLIES_TO.contains(&v.as_str()) && !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

/// Derive a stable, dependency-free entry id from the block's identity. Run
/// once at block time and persisted, so cross-process hash stability is not
/// required.
fn derive_blocklist_entry_id(kind: &str, value: &str, blocked_at: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    kind.hash(&mut hasher);
    value.hash(&mut hasher);
    blocked_at.hash(&mut hasher);
    format!("ck:block:{:016x}", hasher.finish())
}

impl BlocklistEntry {
    /// Construct an actor-kind entry. Normalises `did` (trim) and treats an
    /// empty `reason` as `None`. `blocked_at` is stamped to now.
    pub fn new(did: impl Into<String>, reason: Option<String>) -> Self {
        Self::new_target(DEFAULT_BLOCKLIST_TARGET_KIND, did, reason, Vec::new(), None)
    }

    /// Construct an entry for an arbitrary `target.kind`. Normalises kind,
    /// value, reason, `applies_to` and `expires_at`. `entry_id` is left
    /// `None`; [`block_target_in`] stamps it once the entry is accepted.
    pub fn new_target(
        kind: impl Into<String>,
        value: impl Into<String>,
        reason: Option<String>,
        applies_to: Vec<String>,
        expires_at: Option<String>,
    ) -> Self {
        let kind = {
            let k = kind.into().trim().to_ascii_lowercase();
            if k.is_empty() {
                DEFAULT_BLOCKLIST_TARGET_KIND.to_owned()
            } else {
                k
            }
        };
        let did = normalize_blocklist_value(&kind, &value.into());
        let reason = reason.and_then(|r| {
            let trimmed = r.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        let expires_at = expires_at.and_then(|e| {
            let trimmed = e.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        Self {
            did,
            kind,
            reason,
            blocked_at: Some(chrono::Utc::now().to_rfc3339()),
            applies_to: normalize_blocklist_applies_to(applies_to),
            expires_at,
            entry_id: None,
        }
    }
}

/// True when actor `did` appears in `list`. Empty + whitespace `did` is
/// always `false`. Matching is exact on the (already trimmed) DID string and
/// scoped to `kind == "actor"` entries — this is the timeline / chat sender
/// filter, so domain / service / organization blocks (which gate other
/// surfaces) must not accidentally match a sender DID string.
pub fn is_blocked(list: &[BlocklistEntry], did: &str) -> bool {
    let needle = did.trim();
    if needle.is_empty() {
        return false;
    }
    list.iter().any(|e| e.kind == "actor" && e.did == needle)
}

/// Append an actor block for `did` (idempotent). Thin wrapper over
/// [`block_target_in`] kept for existing call sites that only block actors.
pub fn block_user_in(
    list: &mut Vec<BlocklistEntry>,
    did: &str,
    reason: Option<String>,
    blocked_at: Option<String>,
) -> bool {
    block_target_in(
        list,
        DEFAULT_BLOCKLIST_TARGET_KIND,
        did,
        reason,
        Vec::new(),
        None,
        blocked_at,
    )
}

/// Append a `(kind, value)` block to `list` (idempotent — a duplicate
/// `(kind, value)` pair is not inserted). Returns `true` when the list
/// changed. `blocked_at` is stamped with the supplied timestamp; pass
/// `chrono::Utc::now()` at the call site so this module stays time-source
/// agnostic. The accepted entry is stamped with a derived `entry_id`.
#[allow(clippy::too_many_arguments)]
pub fn block_target_in(
    list: &mut Vec<BlocklistEntry>,
    kind: &str,
    value: &str,
    reason: Option<String>,
    applies_to: Vec<String>,
    expires_at: Option<String>,
    blocked_at: Option<String>,
) -> bool {
    let mut entry = BlocklistEntry::new_target(kind, value, reason, applies_to, expires_at);
    if entry.did.is_empty() {
        return false;
    }
    if let Some(blocked_at) = blocked_at {
        let blocked_at = blocked_at.trim();
        if !blocked_at.is_empty() {
            entry.blocked_at = Some(blocked_at.to_owned());
        }
    }
    if list
        .iter()
        .any(|e| e.kind == entry.kind && e.did == entry.did)
    {
        return false;
    }
    let stamp = entry.blocked_at.clone().unwrap_or_default();
    entry.entry_id = Some(derive_blocklist_entry_id(&entry.kind, &entry.did, &stamp));
    list.push(entry);
    true
}

/// Remove every entry whose target value matches `did`, regardless of kind.
/// Returns `true` when at least one entry was removed. Used by the actor-only
/// blocklist surfaces that key on the DID value alone.
pub fn unblock_user_in(list: &mut Vec<BlocklistEntry>, did: &str) -> bool {
    let needle = did.trim();
    if needle.is_empty() {
        return false;
    }
    let before = list.len();
    list.retain(|e| e.did != needle);
    list.len() != before
}

/// Remove the entry matching `(kind, value)` from `list`. Returns `true` when
/// at least one entry was removed. Prefer this over [`unblock_user_in`] when
/// the surface tracks the target kind (so a domain block and a same-string
/// actor block can be unblocked independently).
pub fn unblock_target_in(list: &mut Vec<BlocklistEntry>, kind: &str, value: &str) -> bool {
    let kind = {
        let k = kind.trim().to_ascii_lowercase();
        if k.is_empty() {
            DEFAULT_BLOCKLIST_TARGET_KIND.to_owned()
        } else {
            k
        }
    };
    let value = normalize_blocklist_value(&kind, value);
    if value.is_empty() {
        return false;
    }
    let before = list.len();
    list.retain(|e| !(e.kind == kind && e.did == value));
    list.len() != before
}

const BLOCKLIST_ACCOUNT_DATA_VERSION: u32 = 1;

/// Surfaces a personal block can apply to (`client-preferences.md` §3.5
/// `applies_to`). An entry with an empty `applies_to` expands to this full
/// set on the wire (block everything).
pub const DEFAULT_BLOCKLIST_APPLIES_TO: &[&str] = &[
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
///
/// Per-entry shape: `{ entry_id?, target: { kind, did|domain }, mode: "block",
/// applies_to[], reason_code?, created_at, expires_at }`. The target value is
/// emitted under `did` for DID-shaped kinds and `domain` for `kind="domain"`.
pub fn build_blocklist_account_data_body(entries: &[BlocklistEntry]) -> Value {
    let entries = entries
        .iter()
        .filter(|entry| !entry.did.trim().is_empty())
        .map(|entry| {
            let kind = if entry.kind.trim().is_empty() {
                DEFAULT_BLOCKLIST_TARGET_KIND
            } else {
                entry.kind.as_str()
            };
            let id_field = if blocklist_kind_is_did(kind) {
                "did"
            } else {
                "domain"
            };
            let mut target = serde_json::Map::new();
            target.insert("kind".to_owned(), Value::String(kind.to_owned()));
            target.insert(
                id_field.to_owned(),
                Value::String(entry.did.trim().to_owned()),
            );
            let applies_to: Vec<&str> = if entry.applies_to.is_empty() {
                DEFAULT_BLOCKLIST_APPLIES_TO.to_vec()
            } else {
                entry.applies_to.iter().map(String::as_str).collect()
            };
            let mut object = serde_json::json!({
                "target": Value::Object(target),
                "mode": "block",
                "applies_to": applies_to,
                "created_at": entry
                    .blocked_at
                    .clone()
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
            });
            if let Some(map) = object.as_object_mut() {
                if let Some(entry_id) = entry
                    .entry_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    map.insert("entry_id".to_owned(), Value::String(entry_id.to_owned()));
                }
                if let Some(reason) = entry
                    .reason
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    map.insert("reason_code".to_owned(), Value::String(reason.to_owned()));
                }
                // `expires_at` is always present so peers can distinguish a
                // permanent block (explicit null) from an absent field.
                match entry
                    .expires_at
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    Some(expires) => {
                        map.insert("expires_at".to_owned(), Value::String(expires.to_owned()));
                    }
                    None => {
                        map.insert("expires_at".to_owned(), Value::Null);
                    }
                }
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
        .ok_or_else(|| "ck.account.blocklist.entries missing".to_owned())?;
    let entries = entries
        .as_array()
        .ok_or_else(|| "ck.account.blocklist.entries must be an array".to_owned())?;
    Ok(entries
        .iter()
        .filter_map(blocklist_entry_from_account_data_value)
        .collect())
}

fn blocklist_entry_from_account_data_value(value: &Value) -> Option<BlocklistEntry> {
    match value {
        Value::String(did) => blocklist_entry_from_parts(
            DEFAULT_BLOCKLIST_TARGET_KIND,
            did,
            None,
            None,
            Vec::new(),
            None,
            None,
        ),
        Value::Object(object) => {
            // Top-level `kind` is the legacy *action* alias (block/unblock),
            // distinct from `target.kind` (the target type). Keep accepting it.
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
            let (target_kind, target_value) = object
                .get("target")
                .and_then(blocklist_target_kind_value)
                .or_else(|| {
                    object
                        .get("did")
                        .or_else(|| object.get("actor"))
                        .and_then(Value::as_str)
                        .map(|v| (DEFAULT_BLOCKLIST_TARGET_KIND.to_owned(), v.to_owned()))
                })?;
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
            let applies_to = object
                .get("applies_to")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let expires_at = object
                .get("expires_at")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let entry_id = object
                .get("entry_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            blocklist_entry_from_parts(
                &target_kind,
                &target_value,
                reason,
                blocked_at,
                applies_to,
                expires_at,
                entry_id,
            )
        }
        _ => None,
    }
}

/// Extract `(target.kind, value)` from a wire `target`. Accepts a bare string
/// (legacy actor DID), and objects keyed by `did` / `actor` / `domain` /
/// `value` / `id`. When `kind` is absent it is inferred: a `domain` field
/// implies `domain`, otherwise `actor`.
fn blocklist_target_kind_value(value: &Value) -> Option<(String, String)> {
    match value {
        Value::String(did) => Some((DEFAULT_BLOCKLIST_TARGET_KIND.to_owned(), did.clone())),
        Value::Object(object) => {
            let kind = object
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k.trim().to_ascii_lowercase());
            let value = object
                .get("did")
                .or_else(|| object.get("actor"))
                .or_else(|| object.get("domain"))
                .or_else(|| object.get("value"))
                .or_else(|| object.get("id"))
                .and_then(Value::as_str)?;
            let kind = kind.unwrap_or_else(|| {
                if object.get("domain").is_some() {
                    "domain".to_owned()
                } else {
                    DEFAULT_BLOCKLIST_TARGET_KIND.to_owned()
                }
            });
            Some((kind, value.to_owned()))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn blocklist_entry_from_parts(
    kind: &str,
    value: &str,
    reason: Option<String>,
    blocked_at: Option<String>,
    applies_to: Vec<String>,
    expires_at: Option<String>,
    entry_id: Option<String>,
) -> Option<BlocklistEntry> {
    let mut entry = BlocklistEntry::new_target(kind, value, reason, applies_to, expires_at);
    if entry.did.trim().is_empty() {
        return None;
    }
    if let Some(blocked_at) = blocked_at {
        let blocked_at = blocked_at.trim();
        if !blocked_at.is_empty() {
            entry.blocked_at = Some(blocked_at.to_owned());
        }
    }
    entry.entry_id = entry_id.and_then(|e| {
        let trimmed = e.trim().to_owned();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    Some(entry)
}

/// Build a `ck.account_data.set` operation envelope for `key` -> `value`.
///
/// `ck.account_data.set` is classified `actor_private_event` in
/// `conformance.rs:393`; reducers MUST NOT include it in shared Realm state.
pub fn build_account_data_set(
    realm_id: &str,
    actor: &str,
    key: &AccountDataKey,
    value: Value,
) -> OperationBuilder {
    let value_field = if private_account_data_key_prefix(key.as_wire()).is_some() {
        "encrypted_payload"
    } else {
        "body"
    };
    let mut payload = serde_json::json!({
        "key": key.as_wire(),
        "owner": actor,
        "updated_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    payload[value_field] = value;
    OperationBuilder::new(realm_id, actor, "ck.account_data.set").body(payload)
}

pub fn build_account_data_tombstone(
    realm_id: &str,
    actor: &str,
    key: &AccountDataKey,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.account_data.set").body(serde_json::json!({
        "key": key.as_wire(),
        "owner": actor,
        "tombstone": true,
        "updated_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }))
}

pub fn private_account_data_key_prefix(key: &str) -> Option<&'static str> {
    if let Some(prefix) = [
        cokret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_ACTOR,
        cokret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_REALM,
    ]
    .into_iter()
    .find(|prefix| {
        key.strip_prefix(*prefix)
            .is_some_and(|rest| rest.starts_with('.'))
    }) {
        return Some(prefix);
    }

    [
        cokret_sdk::ACCOUNT_DATA_TYPE_REMINDER,
        cokret_sdk::ACCOUNT_DATA_TYPE_SCHEDULED_SEND,
        cokret_sdk::ACCOUNT_DATA_TYPE_SNOOZE,
        cokret_sdk::ACCOUNT_DATA_TYPE_SAVED,
        cokret_sdk::ACCOUNT_DATA_TYPE_DRAFT,
        cokret_sdk::ACCOUNT_DATA_TYPE_FILE_TRANSFER,
        cokret_sdk::ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST,
    ]
    .into_iter()
    .find(|prefix| {
        key.strip_prefix(*prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
    })
}

pub fn validate_private_account_data_key(key: &str) -> anyhow::Result<()> {
    cokret_sdk::validate_private_account_data_key(key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn reminder_account_data_key(id: &str) -> anyhow::Result<String> {
    cokret_sdk::reminder_account_data_key(id).map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn scheduled_send_account_data_key(planned_message_id: &str) -> anyhow::Result<String> {
    let planned_message_id = cokret_sdk::MessageId::new(planned_message_id.to_owned())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(cokret_sdk::scheduled_send_account_data_key(
        &planned_message_id,
    ))
}

pub fn snooze_account_data_key(namespace_key: &[u8], target_ref: &str) -> anyhow::Result<String> {
    cokret_sdk::snooze_account_data_key(namespace_key, target_ref)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn saved_account_data_key(
    namespace_key: &[u8],
    collection_title: &str,
    target_ref: &str,
) -> anyhow::Result<String> {
    cokret_sdk::saved_account_data_key(namespace_key, collection_title, target_ref)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn draft_account_data_key(
    namespace_key: &[u8],
    kind: cokret_sdk::DraftKind,
    target_ref: &str,
    draft_slot: &str,
) -> anyhow::Result<String> {
    cokret_sdk::draft_account_data_key(namespace_key, kind, target_ref, draft_slot)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn search_index_manifest_account_data_key(
    namespace_key: &[u8],
    realm_id: &str,
) -> anyhow::Result<String> {
    let realm_id = cokret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    cokret_sdk::search_index_manifest_account_data_key(namespace_key, &realm_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn file_transfer_account_data_key(
    namespace_key: &[u8],
    transfer_id: &str,
) -> anyhow::Result<String> {
    cokret_sdk::file_transfer_account_data_key(namespace_key, transfer_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn build_private_account_data_set(
    realm_id: &str,
    actor: &str,
    key: &str,
    encrypted_payload: Value,
) -> anyhow::Result<OperationBuilder> {
    validate_private_account_data_key(key)?;
    Ok(
        OperationBuilder::new(realm_id, actor, "ck.account_data.set").body(serde_json::json!({
            "key": key,
            "owner": actor,
            "encrypted_payload": encrypted_payload,
            "updated_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })),
    )
}

pub fn build_private_account_data_tombstone(
    realm_id: &str,
    actor: &str,
    key: &str,
) -> anyhow::Result<OperationBuilder> {
    validate_private_account_data_key(key)?;
    Ok(
        OperationBuilder::new(realm_id, actor, "ck.account_data.set").body(serde_json::json!({
            "key": key,
            "owner": actor,
            "tombstone": true,
            "updated_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })),
    )
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
            "ck.push_rules",
            "ck.dnd_schedule",
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
    fn realm_remark_key_round_trip() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        let key = realm_remark_account_data_key(realm_id);
        assert_eq!(key, format!("ck.contacts.realm.{realm_id}"));
        assert_eq!(realm_id_from_realm_remark_key(&key), Some(realm_id));
        assert_eq!(
            realm_id_from_realm_remark_key("ck.read_receipt.preferences"),
            None
        );
    }

    #[test]
    fn contact_remark_key_round_trip() {
        let did = "did:web:alice.example";
        let key = contact_remark_account_data_key(did);
        assert_eq!(key, format!("ck.contacts.actor.{did}"));
        assert_eq!(actor_id_from_contact_remark_key(&key), Some(did));
        assert_eq!(
            actor_id_from_contact_remark_key("ck.contacts.realm.x"),
            None
        );
    }

    #[test]
    fn realm_remark_serialises_minimal_payload() {
        // Empty fields MUST NOT appear on the wire — keeps the payload
        // tombstone-friendly and avoids leaking placeholder data.
        let remark = RealmRemark::new(
            "ck:realm:0196419b-0000-7000-8000-000000000000",
            "Acme · Eng",
        );
        let wire = serde_json::to_value(&remark).unwrap();
        assert_eq!(
            wire["subject"],
            serde_json::json!({
                "kind": "realm",
                "id": "ck:realm:0196419b-0000-7000-8000-000000000000"
            })
        );
        assert_eq!(wire["local_name"], "Acme · Eng");
        assert_eq!(wire["version"], 1);
        assert!(wire.get("note").is_none());
        assert!(wire.get("pinned").is_none());
        assert!(wire.get("tags").is_none());
    }

    #[test]
    fn realm_remark_display_name_prefers_local_name() {
        let r = RealmRemark::new("ck:realm:abc", "Acme · Eng");
        assert_eq!(r.display_name("Engineering"), "Acme · Eng");
        let empty = RealmRemark {
            local_name: "   ".into(),
            ..RealmRemark::default()
        };
        assert_eq!(empty.display_name("Engineering"), "Engineering");
    }

    #[test]
    fn realm_remark_is_empty_treats_whitespace_as_tombstone() {
        let r = RealmRemark {
            local_name: "   ".into(),
            note: String::new(),
            ..RealmRemark::default()
        };
        assert!(r.is_empty());
        let r2 = RealmRemark {
            local_name: "x".into(),
            ..RealmRemark::default()
        };
        assert!(!r2.is_empty());
    }

    #[test]
    fn realm_remark_pinned_builder_preserves_private_fields() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        let existing = RealmRemark {
            version: 1,
            subject: RemarkSubject {
                kind: "realm".to_owned(),
                id: realm_id.to_owned(),
            },
            local_name: "Acme Eng".to_owned(),
            note: "Private note".to_owned(),
            tags: vec!["work".to_owned()],
            pinned: false,
            verified_title_at_save: Some("Engineering".to_owned()),
            verified_owning_organizations_at_save: vec!["did:web:acme.example".to_owned()],
            saved_at: Some("2026-06-01T00:00:00Z".to_owned()),
            updated_at: Some("2026-06-01T00:00:00Z".to_owned()),
        };

        let next = RealmRemark::with_pinned_preserving_fields(
            realm_id,
            Some(&existing),
            true,
            Some("2026-06-06T00:00:00Z".to_owned()),
        );

        assert!(next.pinned);
        assert_eq!(next.local_name, existing.local_name);
        assert_eq!(next.note, existing.note);
        assert_eq!(next.tags, existing.tags);
        assert_eq!(next.verified_title_at_save, existing.verified_title_at_save);
        assert_eq!(
            next.verified_owning_organizations_at_save,
            existing.verified_owning_organizations_at_save
        );
        assert_eq!(next.saved_at, existing.saved_at);
        assert_eq!(next.updated_at.as_deref(), Some("2026-06-06T00:00:00Z"));
    }

    #[test]
    fn realm_remark_unpin_builder_can_tombstone_empty_remark() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
        let existing = RealmRemark::with_pinned_preserving_fields(
            realm_id,
            None,
            true,
            Some("2026-06-06T00:00:00Z".to_owned()),
        );
        assert!(!existing.is_empty());

        let next = RealmRemark::with_pinned_preserving_fields(
            realm_id,
            Some(&existing),
            false,
            Some("2026-06-06T00:01:00Z".to_owned()),
        );

        assert!(!next.pinned);
        assert_eq!(next.subject.id, realm_id);
        assert!(next.is_empty());
    }

    #[test]
    fn contact_remark_serialises_minimal_private_payload() {
        let remark = ContactRemark::new("did:web:alice.example", "Alice from Ops");
        let wire = serde_json::to_value(&remark).unwrap();
        assert_eq!(wire["version"], 1);
        assert_eq!(wire["actor_id"], "did:web:alice.example");
        assert_eq!(wire["local_name"], "Alice from Ops");
        assert!(wire.get("note").is_none());
        assert_eq!(remark.display_name("Alice"), "Alice from Ops");

        let empty = ContactRemark {
            actor_id: "did:web:alice.example".to_owned(),
            local_name: " ".to_owned(),
            ..ContactRemark::default()
        };
        assert!(empty.is_empty());
    }

    #[test]
    fn contact_remark_pinned_builder_preserves_private_fields() {
        let actor_id = "did:web:alice.example";
        let existing = ContactRemark {
            version: 1,
            actor_id: actor_id.to_owned(),
            local_name: "Alice from Ops".to_owned(),
            note: "met at launch".to_owned(),
            tags: vec!["ops".to_owned()],
            pinned: false,
            verified_handle_at_save: Some("alice:example.com".to_owned()),
            saved_at: Some("2026-06-05T00:00:00Z".to_owned()),
            updated_at: Some("2026-06-05T00:00:00Z".to_owned()),
        };

        let next = ContactRemark::with_pinned_preserving_fields(
            actor_id,
            Some(&existing),
            true,
            Some("2026-06-06T00:00:00Z".to_owned()),
        );

        assert!(next.pinned);
        assert_eq!(next.local_name, existing.local_name);
        assert_eq!(next.note, existing.note);
        assert_eq!(next.tags, existing.tags);
        assert_eq!(
            next.verified_handle_at_save,
            existing.verified_handle_at_save
        );
        assert_eq!(next.saved_at, existing.saved_at);
        assert_eq!(next.updated_at.as_deref(), Some("2026-06-06T00:00:00Z"));
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
    fn block_target_in_dedupes_per_kind_and_value_and_stamps_entry_id() {
        let mut list: Vec<BlocklistEntry> = Vec::new();
        // Domain block: value is normalized (scheme stripped, lower-cased).
        assert!(block_target_in(
            &mut list,
            "domain",
            "https://Spam.Example/path",
            None,
            vec!["dm".into(), "calls".into()],
            Some("2026-08-01T00:00:00Z".into()),
            Some("2026-05-18T00:00:00Z".into()),
        ));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].kind, "domain");
        assert_eq!(list[0].did, "spam.example");
        assert_eq!(list[0].applies_to, vec!["dm", "calls"]);
        assert_eq!(list[0].expires_at.as_deref(), Some("2026-08-01T00:00:00Z"));
        assert!(
            list[0]
                .entry_id
                .as_deref()
                .is_some_and(|id| id.starts_with("ck:block:"))
        );
        // Same (kind, value) is a no-op even with different metadata.
        assert!(!block_target_in(
            &mut list,
            "domain",
            "spam.example",
            None,
            Vec::new(),
            None,
            None,
        ));
        assert_eq!(list.len(), 1);
        // Same value, different kind (service) is a distinct entry.
        assert!(block_target_in(
            &mut list,
            "service",
            "did:web:spam.example",
            None,
            Vec::new(),
            None,
            None,
        ));
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].kind, "service");
    }

    #[test]
    fn is_blocked_is_scoped_to_actor_kind() {
        let mut list: Vec<BlocklistEntry> = Vec::new();
        block_target_in(
            &mut list,
            "service",
            "did:web:server.example",
            None,
            Vec::new(),
            None,
            None,
        );
        // A service block must not satisfy the actor-sender filter.
        assert!(!is_blocked(&list, "did:web:server.example"));
        block_user_in(&mut list, "did:web:alice.example", None, None);
        assert!(is_blocked(&list, "did:web:alice.example"));
    }

    #[test]
    fn unblock_target_in_removes_only_matching_kind() {
        let mut list: Vec<BlocklistEntry> = Vec::new();
        block_user_in(&mut list, "did:web:dup.example", None, None);
        block_target_in(
            &mut list,
            "service",
            "did:web:dup.example",
            None,
            Vec::new(),
            None,
            None,
        );
        assert_eq!(list.len(), 2);
        // Removing the service block leaves the actor block intact.
        assert!(unblock_target_in(
            &mut list,
            "service",
            "did:web:dup.example"
        ));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].kind, "actor");
        assert!(!unblock_target_in(
            &mut list,
            "service",
            "did:web:dup.example"
        ));
    }

    #[test]
    fn build_blocklist_account_data_body_emits_domain_and_expiry_fields() {
        let mut list: Vec<BlocklistEntry> = Vec::new();
        block_target_in(
            &mut list,
            "domain",
            "spam.example",
            None,
            vec!["dm".into()],
            Some("2026-08-01T00:00:00Z".into()),
            None,
        );
        let body = build_blocklist_account_data_body(&list);
        let entry = &body["entries"][0];
        assert_eq!(entry["target"]["kind"], "domain");
        // Domain kinds emit the value under `domain`, not `did`.
        assert_eq!(entry["target"]["domain"], "spam.example");
        assert!(entry["target"].get("did").is_none());
        assert_eq!(entry["mode"], "block");
        assert_eq!(entry["applies_to"], json!(["dm"]));
        assert_eq!(entry["expires_at"], "2026-08-01T00:00:00Z");
        assert!(entry["entry_id"].as_str().unwrap().starts_with("ck:block:"));
    }

    #[test]
    fn build_blocklist_account_data_body_emits_null_expiry_for_permanent_block() {
        let mut list: Vec<BlocklistEntry> = Vec::new();
        block_user_in(&mut list, "did:web:alice.example", None, None);
        let body = build_blocklist_account_data_body(&list);
        // Permanent blocks emit an explicit null so peers can tell "no expiry"
        // apart from "field absent".
        assert!(body["entries"][0]["expires_at"].is_null());
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
                    "target": {"kind": "domain", "domain": "Example.com"},
                    "mode": "block",
                    "applies_to": ["dm", "calls"],
                    "expires_at": "2026-07-01T00:00:00Z",
                    "created_at": "2026-05-29T00:00:00Z"
                }
            ]
        });
        let entries = blocklist_entries_from_account_data(&body).unwrap();
        // The `unblock` mode entry is dropped; the actor + domain blocks parse.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].did, "did:web:mallory.example");
        assert_eq!(entries[0].kind, "actor");
        assert_eq!(entries[0].reason.as_deref(), Some("harassment"));
        assert_eq!(
            entries[0].blocked_at.as_deref(),
            Some("2026-05-29T00:00:00Z")
        );
        // Domain target: kind preserved, value normalized (lower-cased),
        // applies_to + expires_at round-tripped.
        assert_eq!(entries[1].kind, "domain");
        assert_eq!(entries[1].did, "example.com");
        assert_eq!(entries[1].applies_to, vec!["dm", "calls"]);
        assert_eq!(
            entries[1].expires_at.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
    }

    // ── A4a — client.ui shape + merge logic ────────────────────────────
    #[test]
    fn build_client_ui_body_only_emits_present_fields() {
        let body = build_client_ui_body(Some("light"), None, &BTreeMap::new(), None);
        assert_eq!(body["theme"], "light");
        assert!(body.get("sidebar_collapsed").is_none());
        assert!(body.get("per_realm_view").is_none());
        assert!(body.get("avatar_blob_ref").is_none());

        let mut per_realm = BTreeMap::new();
        per_realm.insert("ck:realm:abc".to_owned(), "kanban".to_owned());
        let body = build_client_ui_body(Some("night"), Some(true), &per_realm, None);
        assert_eq!(body["theme"], "night");
        assert_eq!(body["sidebar_collapsed"], true);
        assert_eq!(body["per_realm_view"]["ck:realm:abc"], "kanban");

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
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            &AccountDataKey::ClientReadReceipts,
            json!({"send": false}),
        )
        .build("node");
        assert_eq!(op.kind, "ck.account_data.set");
        assert_eq!(op.payload["key"], "ck.read_receipt.preferences");
        assert_eq!(op.payload["owner"], "did:web:alice");
        assert_eq!(op.payload["body"]["send"], false);
        assert!(op.payload["updated_at"].is_string());
    }

    #[test]
    fn productivity_account_data_keys_use_sdk_private_derivation() {
        let ns = b"yougen-account-data-test-key";
        let target_ref = "ck:flow:01904100-0000-7000-8000-000000000001";
        let snooze = snooze_account_data_key(ns, target_ref).unwrap();
        let saved = saved_account_data_key(ns, "Focus", target_ref).unwrap();
        let draft =
            draft_account_data_key(ns, cokret_sdk::DraftKind::Message, target_ref, "main").unwrap();
        let manifest = search_index_manifest_account_data_key(
            ns,
            "ck:realm:01904100-0000-7000-8000-000000000001",
        )
        .unwrap();
        let transfer = file_transfer_account_data_key(ns, "0123456789abcdefghijkl").unwrap();

        for key in [&snooze, &saved, &draft, &manifest, &transfer] {
            assert!(validate_private_account_data_key(key).is_ok());
            assert!(!key.contains("ck:flow:"));
            assert!(!key.contains("Focus"));
        }
    }

    #[test]
    fn scheduled_send_key_requires_message_typed_id() {
        assert!(
            scheduled_send_account_data_key("ck:message:01904100-0000-7000-8000-000000000001")
                .is_ok()
        );
        assert!(scheduled_send_account_data_key("not-a-message-id").is_err());
    }

    #[test]
    fn contact_and_realm_remarks_are_encrypted_account_data() {
        let realm_id = "ck:realm:01904100-0000-7000-8000-000000000001";
        let realm_key = realm_remark_account_data_key(realm_id);
        let actor_key = contact_remark_account_data_key("did:web:alice.example");

        assert_eq!(
            private_account_data_key_prefix(&realm_key),
            Some(cokret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_REALM)
        );
        assert_eq!(
            private_account_data_key_prefix(&actor_key),
            Some(cokret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_ACTOR)
        );
        assert!(validate_private_account_data_key(&realm_key).is_ok());
        assert!(validate_private_account_data_key(&actor_key).is_ok());

        let op = build_account_data_set(
            realm_id,
            "did:web:alice.example",
            &AccountDataKey::Custom(realm_key),
            json!({"pinned": true}),
        )
        .build("node");
        assert!(op.payload.get("encrypted_payload").is_some());
        assert!(op.payload.get("body").is_none());
    }

    #[test]
    fn private_account_data_builders_emit_encrypted_payload() {
        let key = "ck.scheduled_send.v1:ck:message:01904100-0000-7000-8000-000000000001";
        let op = build_private_account_data_set(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            key,
            json!({"ciphertext": "opaque"}),
        )
        .unwrap()
        .build("node");
        assert_eq!(op.kind, "ck.account_data.set");
        assert_eq!(op.payload["key"], key);
        assert!(op.payload.get("body").is_none());
        assert_eq!(op.payload["encrypted_payload"]["ciphertext"], "opaque");

        let tombstone = build_private_account_data_tombstone(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            key,
        )
        .unwrap()
        .build("node");
        assert_eq!(tombstone.payload["tombstone"], true);
    }

    #[test]
    fn generic_builder_does_not_put_private_values_under_body() {
        let key = AccountDataKey::Custom(
            "ck.scheduled_send.v1:ck:message:01904100-0000-7000-8000-000000000001".to_owned(),
        );
        let op = build_account_data_set(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            &key,
            json!({"ciphertext": "opaque"}),
        )
        .build("node");
        assert!(op.payload.get("body").is_none());
        assert_eq!(op.payload["encrypted_payload"]["ciphertext"], "opaque");
    }

    #[test]
    fn build_account_data_tombstone_emits_canonical_payload() {
        let op = build_account_data_tombstone(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            &AccountDataKey::ClientReadReceipts,
        )
        .build("node");
        assert_eq!(op.kind, "ck.account_data.set");
        assert_eq!(op.payload["key"], "ck.read_receipt.preferences");
        assert_eq!(op.payload["owner"], "did:web:alice");
        assert_eq!(op.payload["tombstone"], true);
        assert!(op.payload["updated_at"].is_string());
    }
}
