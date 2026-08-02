//! Actor-private personal blocklist (`ak.account.blocklist`) entry type,
//! mutators, and account-data wire (de)serialization.
//!
//! Spec: `discovery/client-preferences.md` §3.5.

use arkret_models_collaboration::objects::productivity::{
    AccountBlocklistAppletTarget, AccountBlocklistAppletTargetKind, AccountBlocklistDeviceIdTarget,
    AccountBlocklistDeviceTargetKind, AccountBlocklistDeviceVerificationMethodTarget,
    AccountBlocklistDidTarget, AccountBlocklistDidTargetKind, AccountBlocklistMode,
    AccountBlocklistPayload, AccountBlocklistPayloadEntry, AccountBlocklistSurface,
    AccountBlocklistTarget, AccountBlocklistValueTarget, AccountBlocklistValueTargetKind,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single local entry in the actor-private personal blocklist
/// (`ak.account.blocklist` per `discovery/client-preferences.md` §3.5).
///
/// [`build_blocklist_account_data_body`] expands it to the canonical account
/// data wire shape: `{ target: { kind, did|object_ref|value }, mode, applies_to,
/// reason_code, created_at, expires_at, entry_id }`.
/// [`blocklist_entries_from_account_data`] accepts only that canonical shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// Target identifier value. DID-backed kinds carry a DID, `device` and
    /// `applet` carry their typed object reference (or a verification-method
    /// DID URL for a device), and value-backed kinds carry normalized text.
    /// The local field name remains `did` for the existing UI/storage model;
    /// the wire builder maps it into the SDK's closed target union.
    pub did: String,
    /// `target.kind` per `discovery/client-preferences.md` §3.5.
    #[serde(default = "default_blocklist_target_kind")]
    pub kind: String,
    /// Holder-facing behavior for the covered surfaces.
    #[serde(default = "default_blocklist_mode")]
    pub mode: AccountBlocklistMode,
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

fn default_blocklist_mode() -> AccountBlocklistMode {
    AccountBlocklistMode::Block
}

/// True when `kind` identifies its target by DID (vs. a bare domain string).
pub fn blocklist_kind_is_did(kind: &str) -> bool {
    matches!(kind, "actor" | "service" | "organization")
}

/// Normalise a block target value. DID kinds are only trimmed (SCIDs are
/// case-sensitive); domain kinds are trimmed, lower-cased and stripped of an
/// accidental URL scheme / path / leading `@` so the stored value is a bare
/// DNS domain per `client-preferences.md` §3.5.
pub fn normalize_blocklist_value(kind: &str, value: &str) -> String {
    let trimmed = value.trim();
    if blocklist_kind_is_did(kind) || matches!(kind, "device" | "applet") {
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
            mode: default_blocklist_mode(),
            reason,
            blocked_at: Some(arkret_sdk::canonical::format_timestamp_canonical(
                chrono::Utc::now(),
            )),
            applies_to: normalize_blocklist_applies_to(applies_to),
            expires_at,
            entry_id: None,
        }
    }
}

/// True when an active actor entry hides `did` on the message surface.
/// Empty input, expired entries, `mute`, and entries that do not cover
/// `messages` return `false`. Domain, service, and organization targets gate
/// other surfaces and must not accidentally match a sender DID string.
pub fn is_blocked(list: &[BlocklistEntry], did: &str) -> bool {
    actor_entries_filter_surface(list, did, "messages", false)
}

/// True when an actor entry suppresses notification attention on any related
/// surface. Unlike message rendering, `mute` also suppresses attention.
pub fn suppresses_notifications(
    list: &[BlocklistEntry],
    did: &str,
    related_surfaces: &[&str],
) -> bool {
    related_surfaces
        .iter()
        .any(|surface| actor_entries_filter_surface(list, did, surface, true))
}

/// True when this entry hides an actor's message body in the default view.
pub fn hides_actor_messages(entry: &BlocklistEntry) -> bool {
    entry_filters_surface(entry, "messages", false, chrono::Utc::now())
}

fn actor_entries_filter_surface(
    list: &[BlocklistEntry],
    did: &str,
    surface: &str,
    include_mute: bool,
) -> bool {
    let needle = did.trim();
    if needle.is_empty() {
        return false;
    }
    let now = chrono::Utc::now();
    list.iter().any(|entry| {
        entry.kind == "actor"
            && entry.did == needle
            && entry_filters_surface(entry, surface, include_mute, now)
    })
}

fn entry_filters_surface(
    entry: &BlocklistEntry,
    surface: &str,
    include_mute: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if entry.kind != "actor"
        || (!entry.applies_to.is_empty() && !entry.applies_to.iter().any(|value| value == surface))
        || entry.expires_at.as_deref().is_some_and(|value| {
            chrono::DateTime::parse_from_rfc3339(value).is_ok_and(|expires_at| expires_at <= now)
        })
    {
        return false;
    }
    matches!(
        entry.mode,
        AccountBlocklistMode::Block | AccountBlocklistMode::Hide
    ) || include_mute && entry.mode == AccountBlocklistMode::Mute
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

/// Surfaces a personal block can apply to (`client-preferences.md` §3.5
/// `applies_to`). An entry with an empty `applies_to` expands to this full
/// set on the wire (block everything).
pub const DEFAULT_BLOCKLIST_APPLIES_TO: &[&str] = &[
    "messages",
    "mentions",
    "dm",
    "calls",
    "contacts",
    "applets",
    "presence",
    "notifications",
    "directory",
];

/// Canonical wire body for the `ak.account.blocklist` account-data entry.
/// The settings UI calls this inside the account-data CAS merge closure; keep
/// the shape aligned with `discovery/client-preferences.md` §3.5 so owner and
/// payload version remain bound to the accepted account-data revision.
///
/// Per-entry shape: `{ entry_id?, target: { kind, did|object_ref|value }, mode,
/// applies_to[], reason_code?, created_at, expires_at }`.
pub fn build_blocklist_account_data_body(
    owner: &str,
    version: u64,
    entries: &[BlocklistEntry],
) -> Result<Value, String> {
    let owner = arkret_sdk::Did::new(owner.trim().to_owned()).map_err(|error| error.to_string())?;
    if version == 0 {
        return Err("account blocklist version must be at least 1".to_owned());
    }
    let entries = entries
        .iter()
        .filter(|entry| !entry.did.trim().is_empty())
        .map(|entry| {
            let kind = if entry.kind.trim().is_empty() {
                DEFAULT_BLOCKLIST_TARGET_KIND
            } else {
                entry.kind.as_str()
            };
            let target = blocklist_target_to_wire(kind, entry.did.trim())?;
            let applies_to = if entry.applies_to.is_empty() {
                DEFAULT_BLOCKLIST_APPLIES_TO
                    .iter()
                    .map(|value| blocklist_surface_to_wire(value))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                entry
                    .applies_to
                    .iter()
                    .map(|value| blocklist_surface_to_wire(value))
                    .collect::<Result<Vec<_>, _>>()?
            };
            Ok(AccountBlocklistPayloadEntry {
                entry_id: entry.entry_id.as_ref().and_then(|value| {
                    arkret_sdk::NonEmptyString::new(value.trim().to_owned()).ok()
                }),
                target,
                mode: entry.mode,
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
        .collect::<Result<Vec<_>, String>>()?;
    let payload = AccountBlocklistPayload {
        owner,
        version,
        entries,
        updated_at: Some(chrono::Utc::now()),
    };
    payload.validate().map_err(|error| error.to_string())?;
    serde_json::to_value(payload).map_err(|error| error.to_string())
}

/// Parse and validate the canonical `ak.account.blocklist` account-data body,
/// including its holder binding.
pub fn blocklist_entries_from_account_data(
    value: &Value,
    expected_owner: &str,
    expected_revision: u64,
) -> Result<Vec<BlocklistEntry>, String> {
    let payload: AccountBlocklistPayload =
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
    payload.validate().map_err(|error| error.to_string())?;
    if payload.owner.as_str() != expected_owner.trim() {
        return Err("account blocklist owner does not match the active account".to_owned());
    }
    if payload.version != expected_revision {
        return Err("account blocklist version does not match account-data revision".to_owned());
    }
    Ok(payload
        .entries
        .into_iter()
        .filter_map(|entry| {
            let (kind, value) = blocklist_target_from_wire(entry.target);
            blocklist_entry_from_parts(
                &kind,
                &value,
                entry.mode,
                entry.reason_code.map(|value| value.to_string()),
                Some(arkret_sdk::canonical::format_timestamp_canonical(
                    entry.created_at,
                )),
                entry
                    .applies_to
                    .into_iter()
                    .map(blocklist_surface_from_wire)
                    .map(ToOwned::to_owned)
                    .collect(),
                entry
                    .expires_at
                    .map(arkret_sdk::canonical::format_timestamp_canonical),
                entry.entry_id.map(|value| value.to_string()),
            )
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn blocklist_entry_from_parts(
    kind: &str,
    value: &str,
    mode: AccountBlocklistMode,
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
    entry.mode = mode;
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

fn blocklist_surface_to_wire(value: &str) -> Result<AccountBlocklistSurface, String> {
    match value.trim() {
        "messages" => Ok(AccountBlocklistSurface::Messages),
        "mentions" => Ok(AccountBlocklistSurface::Mentions),
        "dm" => Ok(AccountBlocklistSurface::Dm),
        "calls" => Ok(AccountBlocklistSurface::Calls),
        "contacts" => Ok(AccountBlocklistSurface::Contacts),
        "applets" => Ok(AccountBlocklistSurface::Applets),
        "presence" => Ok(AccountBlocklistSurface::Presence),
        "notifications" => Ok(AccountBlocklistSurface::Notifications),
        "directory" => Ok(AccountBlocklistSurface::Directory),
        other => Err(format!("unsupported account blocklist surface `{other}`")),
    }
}

fn blocklist_surface_from_wire(value: AccountBlocklistSurface) -> &'static str {
    match value {
        AccountBlocklistSurface::Messages => "messages",
        AccountBlocklistSurface::Mentions => "mentions",
        AccountBlocklistSurface::Dm => "dm",
        AccountBlocklistSurface::Calls => "calls",
        AccountBlocklistSurface::Contacts => "contacts",
        AccountBlocklistSurface::Applets => "applets",
        AccountBlocklistSurface::Presence => "presence",
        AccountBlocklistSurface::Notifications => "notifications",
        AccountBlocklistSurface::Directory => "directory",
    }
}

fn blocklist_target_to_wire(kind: &str, value: &str) -> Result<AccountBlocklistTarget, String> {
    match kind {
        "actor" | "service" | "organization" => {
            let kind = match kind {
                "actor" => AccountBlocklistDidTargetKind::Actor,
                "service" => AccountBlocklistDidTargetKind::Service,
                "organization" => AccountBlocklistDidTargetKind::Organization,
                _ => unreachable!(),
            };
            Ok(AccountBlocklistTarget::Did(AccountBlocklistDidTarget {
                kind,
                did: arkret_sdk::Did::new(value.to_owned()).map_err(|error| error.to_string())?,
            }))
        }
        "device" => {
            if let Ok(object_ref) = arkret_sdk::DeviceId::new(value.to_owned()) {
                return Ok(AccountBlocklistTarget::DeviceId(
                    AccountBlocklistDeviceIdTarget {
                        kind: AccountBlocklistDeviceTargetKind::Device,
                        object_ref,
                    },
                ));
            }
            Ok(AccountBlocklistTarget::DeviceVerificationMethod(
                AccountBlocklistDeviceVerificationMethodTarget {
                    kind: AccountBlocklistDeviceTargetKind::Device,
                    value: arkret_sdk::DidUrl::new(value.to_owned())
                        .map_err(|error| error.to_string())?,
                },
            ))
        }
        "applet" => Ok(AccountBlocklistTarget::Applet(
            AccountBlocklistAppletTarget {
                kind: AccountBlocklistAppletTargetKind::Applet,
                object_ref: arkret_sdk::AppletId::new(value.to_owned())
                    .map_err(|error| error.to_string())?,
            },
        )),
        "handle" | "domain" | "keyword" => {
            let kind = match kind {
                "handle" => AccountBlocklistValueTargetKind::Handle,
                "domain" => AccountBlocklistValueTargetKind::Domain,
                "keyword" => AccountBlocklistValueTargetKind::Keyword,
                _ => unreachable!(),
            };
            Ok(AccountBlocklistTarget::Value(AccountBlocklistValueTarget {
                kind,
                value: arkret_sdk::NonEmptyString::new(value.to_owned())
                    .map_err(|error| error.to_string())?,
            }))
        }
        other => Err(format!(
            "unsupported account blocklist target kind `{other}`"
        )),
    }
}

fn blocklist_target_from_wire(target: AccountBlocklistTarget) -> (String, String) {
    match target {
        AccountBlocklistTarget::Did(target) => {
            let kind = match target.kind {
                AccountBlocklistDidTargetKind::Actor => "actor",
                AccountBlocklistDidTargetKind::Service => "service",
                AccountBlocklistDidTargetKind::Organization => "organization",
            };
            (kind.to_owned(), target.did.to_string())
        }
        AccountBlocklistTarget::DeviceId(target) => {
            ("device".to_owned(), target.object_ref.to_string())
        }
        AccountBlocklistTarget::DeviceVerificationMethod(target) => {
            ("device".to_owned(), target.value.to_string())
        }
        AccountBlocklistTarget::Applet(target) => {
            ("applet".to_owned(), target.object_ref.to_string())
        }
        AccountBlocklistTarget::Value(target) => {
            let kind = match target.kind {
                AccountBlocklistValueTargetKind::Handle => "handle",
                AccountBlocklistValueTargetKind::Domain => "domain",
                AccountBlocklistValueTargetKind::Keyword => "keyword",
            };
            (kind.to_owned(), target.value.to_string())
        }
    }
}
