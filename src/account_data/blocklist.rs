//! Actor-private personal blocklist (`ak.account.blocklist`) helpers.
//!
//! The persisted and in-memory entries are the SDK contract types themselves.
//! UI-only target choices are represented by [`BlocklistUiTargetKind`], which
//! is deliberately not serializable and therefore cannot become a parallel
//! wire model.

use arkret_models_collaboration::objects::productivity::{
    AccountBlocklistDidTarget, AccountBlocklistDidTargetKind, AccountBlocklistMode,
    AccountBlocklistPayload, AccountBlocklistPayloadEntry, AccountBlocklistSurface,
    AccountBlocklistTarget, AccountBlocklistValueTarget, AccountBlocklistValueTargetKind,
};
use serde_json::Value;

/// UI projection for selecting a target variant. This enum is never
/// serialized; the SDK's closed [`AccountBlocklistTarget`] is the only stored
/// and wire representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlocklistUiTargetKind {
    Actor,
    Service,
    Organization,
    Domain,
}

impl BlocklistUiTargetKind {
    pub const ALL: [Self; 4] = [Self::Actor, Self::Service, Self::Domain, Self::Organization];

    pub const fn ui_value(self) -> &'static str {
        match self {
            Self::Actor => "actor",
            Self::Service => "service",
            Self::Organization => "organization",
            Self::Domain => "domain",
        }
    }

    pub fn from_ui_value(value: &str) -> Option<Self> {
        match value {
            "actor" => Some(Self::Actor),
            "service" => Some(Self::Service),
            "organization" => Some(Self::Organization),
            "domain" => Some(Self::Domain),
            _ => None,
        }
    }

    pub const fn is_did(self) -> bool {
        !matches!(self, Self::Domain)
    }
}

pub const DEFAULT_BLOCKLIST_APPLIES_TO: [AccountBlocklistSurface; 9] = [
    AccountBlocklistSurface::Messages,
    AccountBlocklistSurface::Mentions,
    AccountBlocklistSurface::Dm,
    AccountBlocklistSurface::Calls,
    AccountBlocklistSurface::Contacts,
    AccountBlocklistSurface::Applets,
    AccountBlocklistSurface::Presence,
    AccountBlocklistSurface::Notifications,
    AccountBlocklistSurface::Directory,
];

pub const fn blocklist_surface_label(surface: AccountBlocklistSurface) -> &'static str {
    match surface {
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

pub fn normalize_blocklist_value(kind: BlocklistUiTargetKind, value: &str) -> String {
    let trimmed = value.trim();
    if kind.is_did() {
        return trimmed.to_owned();
    }
    let mut value = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches('@');
    value = value.split('/').next().unwrap_or(value);
    value.trim_end_matches('.').to_ascii_lowercase()
}

fn target_from_ui(
    kind: BlocklistUiTargetKind,
    value: &str,
) -> Result<AccountBlocklistTarget, String> {
    let value = normalize_blocklist_value(kind, value);
    match kind {
        BlocklistUiTargetKind::Actor
        | BlocklistUiTargetKind::Service
        | BlocklistUiTargetKind::Organization => {
            let kind = match kind {
                BlocklistUiTargetKind::Actor => AccountBlocklistDidTargetKind::Actor,
                BlocklistUiTargetKind::Service => AccountBlocklistDidTargetKind::Service,
                BlocklistUiTargetKind::Organization => AccountBlocklistDidTargetKind::Organization,
                BlocklistUiTargetKind::Domain => unreachable!(),
            };
            Ok(AccountBlocklistTarget::Did(AccountBlocklistDidTarget {
                kind,
                did: arkret_sdk::Did::new(value).map_err(|error| error.to_string())?,
            }))
        }
        BlocklistUiTargetKind::Domain => {
            Ok(AccountBlocklistTarget::Value(AccountBlocklistValueTarget {
                kind: AccountBlocklistValueTargetKind::Domain,
                value: arkret_sdk::NonEmptyString::new(value).map_err(|error| error.to_string())?,
            }))
        }
    }
}

pub fn blocklist_target_kind_label(target: &AccountBlocklistTarget) -> &'static str {
    match target {
        AccountBlocklistTarget::Did(target) => match target.kind {
            AccountBlocklistDidTargetKind::Actor => "actor",
            AccountBlocklistDidTargetKind::Service => "service",
            AccountBlocklistDidTargetKind::Organization => "organization",
        },
        AccountBlocklistTarget::DeviceId(_)
        | AccountBlocklistTarget::DeviceVerificationMethod(_) => "device",
        AccountBlocklistTarget::Applet(_) => "applet",
        AccountBlocklistTarget::Value(target) => match target.kind {
            AccountBlocklistValueTargetKind::Handle => "handle",
            AccountBlocklistValueTargetKind::Domain => "domain",
            AccountBlocklistValueTargetKind::Keyword => "keyword",
        },
    }
}

pub fn blocklist_target_value(target: &AccountBlocklistTarget) -> &str {
    match target {
        AccountBlocklistTarget::Did(target) => target.did.as_str(),
        AccountBlocklistTarget::DeviceId(target) => target.object_ref.as_str(),
        AccountBlocklistTarget::DeviceVerificationMethod(target) => target.value.as_str(),
        AccountBlocklistTarget::Applet(target) => target.object_ref.as_str(),
        AccountBlocklistTarget::Value(target) => target.value.as_str(),
    }
}

pub fn target_is_actor(target: &AccountBlocklistTarget) -> bool {
    matches!(
        target,
        AccountBlocklistTarget::Did(AccountBlocklistDidTarget {
            kind: AccountBlocklistDidTargetKind::Actor,
            ..
        })
    )
}

fn derive_entry_id(
    target: &AccountBlocklistTarget,
    created_at: chrono::DateTime<chrono::Utc>,
) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    serde_json::to_vec(target)
        .unwrap_or_default()
        .hash(&mut hasher);
    created_at
        .timestamp_nanos_opt()
        .unwrap_or_default()
        .hash(&mut hasher);
    format!("ak:block:{:016x}", hasher.finish())
}

pub fn new_blocklist_entry(
    kind: BlocklistUiTargetKind,
    value: &str,
    reason_code: Option<String>,
    applies_to: Vec<AccountBlocklistSurface>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<AccountBlocklistPayloadEntry, String> {
    let target = target_from_ui(kind, value)?;
    let reason_code = reason_code
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(arkret_sdk::NonEmptyString::new)
        .transpose()
        .map_err(|error| error.to_string())?;
    let applies_to = if applies_to.is_empty() {
        DEFAULT_BLOCKLIST_APPLIES_TO.to_vec()
    } else {
        applies_to
    };
    let entry_id = arkret_sdk::NonEmptyString::new(derive_entry_id(&target, created_at))
        .map_err(|error| error.to_string())?;
    let entry = AccountBlocklistPayloadEntry {
        entry_id: Some(entry_id),
        target,
        mode: AccountBlocklistMode::Block,
        applies_to,
        reason_code,
        expires_at,
        created_at,
    };
    entry.validate().map_err(|error| error.to_string())?;
    Ok(entry)
}

pub fn is_blocked(list: &[AccountBlocklistPayloadEntry], did: &str) -> bool {
    actor_entries_filter_surface(list, did, AccountBlocklistSurface::Messages, false)
}

pub fn suppresses_notifications(
    list: &[AccountBlocklistPayloadEntry],
    did: &str,
    related_surfaces: &[AccountBlocklistSurface],
) -> bool {
    related_surfaces
        .iter()
        .any(|surface| actor_entries_filter_surface(list, did, *surface, true))
}

pub fn hides_actor_messages(entry: &AccountBlocklistPayloadEntry) -> bool {
    entry_filters_surface(
        entry,
        AccountBlocklistSurface::Messages,
        false,
        chrono::Utc::now(),
    )
}

fn actor_entries_filter_surface(
    list: &[AccountBlocklistPayloadEntry],
    did: &str,
    surface: AccountBlocklistSurface,
    include_mute: bool,
) -> bool {
    let needle = did.trim();
    if needle.is_empty() {
        return false;
    }
    let now = chrono::Utc::now();
    list.iter().any(|entry| {
        target_is_actor(&entry.target)
            && blocklist_target_value(&entry.target) == needle
            && entry_filters_surface(entry, surface, include_mute, now)
    })
}

fn entry_filters_surface(
    entry: &AccountBlocklistPayloadEntry,
    surface: AccountBlocklistSurface,
    include_mute: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if !target_is_actor(&entry.target)
        || !entry.applies_to.contains(&surface)
        || entry.expires_at.is_some_and(|expires_at| expires_at <= now)
    {
        return false;
    }
    matches!(
        entry.mode,
        AccountBlocklistMode::Block | AccountBlocklistMode::Hide
    ) || include_mute && entry.mode == AccountBlocklistMode::Mute
}

pub fn block_user_in(
    list: &mut Vec<AccountBlocklistPayloadEntry>,
    did: &str,
    reason_code: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    block_target_in(
        list,
        BlocklistUiTargetKind::Actor,
        did,
        reason_code,
        DEFAULT_BLOCKLIST_APPLIES_TO.to_vec(),
        None,
        created_at,
    )
}

pub fn block_target_in(
    list: &mut Vec<AccountBlocklistPayloadEntry>,
    kind: BlocklistUiTargetKind,
    value: &str,
    reason_code: Option<String>,
    applies_to: Vec<AccountBlocklistSurface>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Ok(entry) =
        new_blocklist_entry(kind, value, reason_code, applies_to, expires_at, created_at)
    else {
        return false;
    };
    if list
        .iter()
        .any(|candidate| candidate.target == entry.target)
    {
        return false;
    }
    list.push(entry);
    true
}

pub fn unblock_user_in(list: &mut Vec<AccountBlocklistPayloadEntry>, did: &str) -> bool {
    let needle = did.trim();
    if needle.is_empty() {
        return false;
    }
    let before = list.len();
    list.retain(|entry| {
        !(target_is_actor(&entry.target) && blocklist_target_value(&entry.target) == needle)
    });
    list.len() != before
}

pub fn unblock_target_in(
    list: &mut Vec<AccountBlocklistPayloadEntry>,
    target: &AccountBlocklistTarget,
) -> bool {
    let before = list.len();
    list.retain(|entry| entry.target != *target);
    list.len() != before
}

/// Build the canonical blocklist payload. `version` is the payload schema
/// version and is always 1; concurrency is exclusively the outer Account Data
/// CAS revision.
pub fn build_blocklist_account_data_body(
    owner: &str,
    entries: &[AccountBlocklistPayloadEntry],
) -> Result<Value, String> {
    let payload = AccountBlocklistPayload {
        owner: arkret_sdk::Did::new(owner.trim().to_owned()).map_err(|error| error.to_string())?,
        version: 1,
        entries: entries.to_vec(),
        updated_at: Some(chrono::Utc::now()),
    };
    payload.validate().map_err(|error| error.to_string())?;
    serde_json::to_value(payload).map_err(|error| error.to_string())
}

/// Decode the SDK payload and enforce holder binding. The outer Account Data
/// row owns the CAS revision and is intentionally not compared to payload
/// `version`.
pub fn blocklist_entries_from_account_data(
    value: &Value,
    expected_owner: &str,
) -> Result<Vec<AccountBlocklistPayloadEntry>, String> {
    let payload: AccountBlocklistPayload =
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
    payload.validate().map_err(|error| error.to_string())?;
    if payload.version != 1 {
        return Err("account blocklist payload schema version must be 1".to_owned());
    }
    if payload.owner.as_str() != expected_owner.trim() {
        return Err("account blocklist owner does not match the active account".to_owned());
    }
    Ok(payload.entries)
}
