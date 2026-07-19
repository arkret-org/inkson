//! Actor-private personal blocklist (`ak.account.blocklist`) entry type,
//! mutators, and account-data wire (de)serialization.
//!
//! Spec: `discovery/client-preferences.md` §3.5.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single local actor-DID entry in the actor-private personal blocklist
/// (`ak.account.blocklist` per `discovery/client-preferences.md` §3.5).
///
/// [`build_blocklist_account_data_body`] expands it to the canonical account
/// data wire shape: `{ target: { kind, did|domain }, mode, applies_to,
/// reason_code, created_at, expires_at, entry_id }`.
/// [`blocklist_entries_from_account_data`] accepts only that canonical shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// Target identifier value. For `kind = "actor" | "service" |
    /// "organization" | "device"` this is a DID; for `kind = "domain"` it is
    /// a normalized DNS domain. Trimmed before insertion (DID values are not
    /// lower-cased because base58 SCIDs are case-sensitive; domain values are
    /// lower-cased by [`normalize_blocklist_value`]). The field name stays
    /// `did` for wire/UI backward-compat — non-DID kinds reuse the same slot.
    pub did: String,
    /// `target.kind` per `discovery/client-preferences.md` §3.5.
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
    /// Stable per-entry id (`ak:block:<hash>`), preserved across sync so other
    /// clients / appeal strands can reference a specific block.
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
    format!("ak:block:{:016x}", hasher.finish())
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
/// scoped to `kind == "actor"` entries — this is the message sender
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

const BLOCKLIST_ACCOUNT_DATA_VERSION: u64 = 1;

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

/// Canonical wire body for the `ak.account.blocklist` account-data entry.
/// The settings UI calls this just before PUTting via
/// [`crate::transport::TransportClient::set_account_data`]; keep the shape aligned with
/// `discovery/client-preferences.md` §3.5 so other clients agree on layout.
///
/// Per-entry shape: `{ entry_id?, target: { kind, did|domain }, mode: "block",
/// applies_to[], reason_code?, created_at, expires_at }`. The target value is
/// emitted under `did` for DID-shaped kinds and `domain` for `kind="domain"`.
pub fn build_blocklist_account_data_body(entries: &[BlocklistEntry]) -> Value {
    let entries = entries
        .iter()
        .filter(|entry| !entry.did.trim().is_empty())
        .filter_map(|entry| {
            let kind = if entry.kind.trim().is_empty() {
                DEFAULT_BLOCKLIST_TARGET_KIND
            } else {
                entry.kind.as_str()
            };
            let target = if blocklist_kind_is_did(kind) {
                arkret_sdk::AccountBlocklistTarget {
                    kind: kind.to_owned(),
                    did: arkret_sdk::Did::new(entry.did.trim().to_owned()).ok(),
                    object_ref: None,
                    value: None,
                }
            } else {
                arkret_sdk::AccountBlocklistTarget {
                    kind: kind.to_owned(),
                    did: None,
                    object_ref: None,
                    value: arkret_sdk::NonEmptyString::new(entry.did.trim().to_owned()).ok(),
                }
            };
            if target.did.is_none() && target.value.is_none() {
                return None;
            }
            let applies_to = if entry.applies_to.is_empty() {
                DEFAULT_BLOCKLIST_APPLIES_TO
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect()
            } else {
                entry.applies_to.clone()
            };
            Some(arkret_sdk::AccountBlocklistPayloadEntry {
                entry_id: entry.entry_id.as_ref().and_then(|value| {
                    arkret_sdk::NonEmptyString::new(value.trim().to_owned()).ok()
                }),
                target,
                mode: "block".to_owned(),
                applies_to,
                reason_code: entry.reason.as_ref().and_then(|value| {
                    arkret_sdk::NonEmptyString::new(value.trim().to_owned()).ok()
                }),
                created_at: entry
                    .blocked_at
                    .as_deref()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(chrono::Utc::now),
                expires_at: entry
                    .expires_at
                    .as_deref()
                    .and_then(|value| value.parse().ok()),
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_value(arkret_sdk::AccountBlocklistPayload {
        version: BLOCKLIST_ACCOUNT_DATA_VERSION,
        entries,
    })
    .expect("canonical blocklist payload serializes")
}

/// Parse the `ak.account.blocklist` account-data content body. Malformed
/// actor entries are skipped instead of partially corrupting the local UI.
pub fn blocklist_entries_from_account_data(value: &Value) -> Result<Vec<BlocklistEntry>, String> {
    let payload: arkret_sdk::AccountBlocklistPayload =
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
    Ok(payload
        .entries
        .into_iter()
        .filter(|entry| matches!(entry.mode.as_str(), "block" | "mute" | "hide"))
        .filter_map(|entry| {
            let value = entry
                .target
                .did
                .map(|did| did.to_string())
                .or_else(|| entry.target.value.map(|value| value.to_string()))
                .or(entry.target.object_ref)?;
            blocklist_entry_from_parts(
                &entry.target.kind,
                &value,
                entry.reason_code.map(|value| value.to_string()),
                Some(entry.created_at.to_rfc3339()),
                entry.applies_to,
                entry.expires_at.map(|value| value.to_rfc3339()),
                entry.entry_id.map(|value| value.to_string()),
            )
        })
        .collect())
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
