//! Actor-private Realm / contact remark account-data types and wire-key
//! helpers.
//!
//! Spec: `discovery/client-preferences.md` §3.6 (contact remarks) and §3.7
//! (Realm remarks). Stored under `ak.contacts.actor.<did>` and
//! `ak.contacts.realm.<realm_id>` respectively.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Wire-key for an actor-private Realm remark per
/// `discovery/client-preferences.md` §3.7: `ak.contacts.realm.<realm_id>`.
///
/// The same string is the `key` used in `ak.account_data.set`. Callers should
/// already have validated `realm_id` shape (`ak:realm:<uuid>`).
pub fn realm_remark_account_data_key(realm_id: &str) -> String {
    format!("ak.contacts.realm.{realm_id}")
}

/// Inverse of [`realm_remark_account_data_key`]. Returns the `realm_id`
/// segment when `key` is a Realm-remark wire key; returns `None` for any
/// other namespace. Used when hydrating `account_data` entries from `/sync`.
pub fn realm_id_from_realm_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("ak.contacts.realm.")
}

/// Wire-key for an actor-private contact remark per
/// `discovery/client-preferences.md` §3.6: `ak.contacts.actor.<did>`.
pub fn contact_remark_account_data_key(actor_id: &str) -> String {
    format!("ak.contacts.actor.{actor_id}")
}

/// Inverse of [`contact_remark_account_data_key`]. Returns the DID segment
/// when `key` is an actor contact remark.
pub fn actor_id_from_contact_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("ak.contacts.actor.")
}

/// User-private Realm remark per `discovery/client-preferences.md` §3.7.
///
/// Persisted as the `content` payload under
/// `ak.contacts.realm.<realm_id>` (the wire key built by
/// [`realm_remark_account_data_key`]). The protocol treats the payload as
/// opaque on the server; this struct is the canonical local shape so the
/// settings UI and the sidebar agree.
///
/// All fields are spec-aligned; the struct intentionally mirrors the §3.6
/// `ak.contacts.actor.<did>` shape so future cross-actor / cross-Realm
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
    /// `ak.tags.realm.<realm_id>` so the same label can drive both UIs.
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
    /// Spec §3.7 `saved_at` / `updated_at` — RFC 3339 timestamps.
    /// `saved_at` is mandatory on the wire; the serde default only migrates
    /// older local state written before that requirement was enforced here.
    #[serde(default = "default_saved_at")]
    pub saved_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
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

fn default_saved_at() -> DateTime<Utc> {
    Utc::now()
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
            saved_at: Utc::now(),
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
        updated_at: Option<DateTime<Utc>>,
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
/// Stored under `ak.contacts.actor.<did>` and intentionally never embedded in
/// public profile, mention, message, search, or push payloads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRemark {
    #[serde(default = "default_remark_version")]
    pub version: u32,
    /// Subject actor DID. Wire field `actor_id` per the v1 protocol naming
    /// rule: a single protocol responsibility subject uses the `_id` suffix
    /// even when the value is a DID.
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
