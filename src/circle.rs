//! Circle UX scaffolding (CKP-0007, P3B.2).
//!
//! A `Circle` is an intra-Realm cryptographic sub-boundary that hosts its
//! own MLS group and a strict-subset of the parent Realm's membership. The
//! spec is in `cokret-rust-sdk/crates/core/src/model/circle.rs`; this
//! module is the *client* surface that the rest of yougen consumes:
//!
//! - [`CircleScope`] is the active scope a composer / new-Flow form is writing into. `Realm` is the
//!   default; `Circle { … }` flags a Circle-scoped write that must end up with `scope_circle_id`
//!   set on the canonical envelope.
//! - [`CircleSummary`] is the lightweight projection rendered by the Space-sidebar Circle list, the
//!   scope picker, and the Realm-detail modal.
//! - [`CircleErrorKind`] is the typed mapping from the CKP-0007 reason codes that surface in
//!   soland's error envelopes. The UI Toast layer (see [`crate::components::circle_error_toast`])
//!   consumes this to produce localized user-facing strings.
//!
//! ## Status
//!
//! P3B.2 ships the typed scaffolding — types, scope picker component,
//! detail view, error-code mapping, the composer banner, and the
//! timeline accent rail wiring inside `views/chat.rs`. The local
//! `DecryptedScope` enum has been replaced with a re-export of the
//! SDK's [`cokret_sdk::model::events::EffectiveScope`]; pattern
//! matching against `effective_scope` now happens against the same
//! enum the reducer produces.

use cokret_sdk::ERROR_CODE_DELIVERY_BINDING_HANDED_OVER;
use serde::{Deserialize, Serialize};

/// The scope a composer / Flow-create form is actively writing into.
///
/// Realm scope is the legacy default; Circle scope flags a CKP-0007
/// write that MUST end up with `scope_circle_id` populated on the
/// envelope object.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircleScope {
    /// Default — visible to every active Realm member.
    #[default]
    Realm,
    /// Circle-scoped — visible to a strict subset of Realm members.
    Circle {
        /// `ck:circle:…` id stamped onto the envelope as
        /// `scope_circle_id`.
        circle_id: String,
        /// Cached title for banner rendering. Reducer-authoritative
        /// version is fetched lazily via the Circle directory.
        title: String,
        /// Cached member count for the banner subline. `0` means the
        /// projection has not been hydrated yet — render "members" with
        /// no count rather than `0 members`.
        member_count: u32,
    },
}

impl CircleScope {
    /// Returns the `ck:circle:…` id if this scope is Circle, otherwise
    /// `None` (Realm scope).
    pub fn circle_id(&self) -> Option<&str> {
        match self {
            CircleScope::Realm => None,
            CircleScope::Circle { circle_id, .. } => Some(circle_id.as_str()),
        }
    }

    /// Human-readable label used by the composer banner. `"Realm"` for
    /// Realm scope, the Circle title otherwise.
    pub fn label(&self) -> &str {
        match self {
            CircleScope::Realm => "Realm",
            CircleScope::Circle { title, .. } => title.as_str(),
        }
    }

    /// Whether the composer should render the colored Circle banner.
    pub fn is_circle(&self) -> bool {
        matches!(self, CircleScope::Circle { .. })
    }
}

/// Lightweight projection of a Circle for sidebar / picker / modal
/// rendering. The full canonical struct is
/// [`cokret_sdk::cokret_core::model::circle::Circle`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircleSummary {
    /// `ck:circle:…`
    pub id: String,
    /// `ck:realm:…` of the parent Realm.
    pub realm_id: String,
    pub title: String,
    pub short_name: String,
    pub color_token: String,
    pub symbol: String,
    pub member_count: u32,
    /// `true` if the active account is a member of this Circle (used to
    /// hide non-member Circles from the sidebar projection).
    pub viewer_is_member: bool,
}

impl CircleSummary {
    /// Build a [`CircleScope::Circle`] from this summary, consuming the
    /// title + member count.
    pub fn into_scope(self) -> CircleScope {
        CircleScope::Circle {
            circle_id: self.id,
            title: self.title,
            member_count: self.member_count,
        }
    }
}

/// CKP-0007 reason / error codes surfaced to the user via the Toast
/// layer. Maps from the wire `reason_code` (a `failed_precondition` /
/// `schema_violation` sub-code) to a typed enum the UI can translate.
///
/// One Circle-adjacent code is the top-level
/// [`cokret_sdk::error_codes::ERROR_CODE_DELIVERY_BINDING_HANDED_OVER`]
/// already registered in CKP-0006; we surface it through the same
/// pipeline so a single Toast component handles all Circle-adjacent
/// failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircleErrorKind {
    /// `circle_realm_mismatch` — object's `scope_circle_id` references
    /// a Circle whose `realm_id` does not match the object's `realm_id`.
    RealmMismatch,
    /// `circle_not_active` — `scope_circle_id` points at an archived
    /// or tombstoned Circle.
    NotActive,
    /// `circle_member_must_be_realm_member` — attempted to add a
    /// non-Realm member to the Circle (strict-subset invariant).
    MemberNotInRealm,
    /// `scope_rebind_forbidden` — attempted to change the
    /// `scope_circle_id` on an object without an audited-high-risk
    /// path.
    ScopeRebindForbidden,
    /// `metadata_encryption_floor_violation` — a write would expose
    /// metadata below the effective floor.
    MetadataFloorViolated,
    /// `circle_encryption_below_realm_floor` — attempted to create a
    /// plaintext Circle where the parent Realm requires E2EE.
    EncryptionBelowRealmFloor,
    /// `circle_encryption_profile_create_locked` — attempted to mutate
    /// a Circle's create-locked encryption profile.
    EncryptionProfileCreateLocked,
    /// `delivery_binding_handed_over` — the Circle's delivery binding
    /// moved to another epoch / device set; the caller must re-fetch.
    DeliveryBindingHandedOver,
}

impl CircleErrorKind {
    /// Match a wire `reason_code` string against the typed enum.
    /// Returns `None` if the reason isn't one of the Circle codes.
    pub fn from_reason_code(reason: &str) -> Option<Self> {
        match reason {
            "circle_realm_mismatch" => Some(Self::RealmMismatch),
            "circle_not_active" => Some(Self::NotActive),
            "circle_member_must_be_realm_member" => Some(Self::MemberNotInRealm),
            "scope_rebind_forbidden" => Some(Self::ScopeRebindForbidden),
            "metadata_encryption_floor_violation" => Some(Self::MetadataFloorViolated),
            "circle_encryption_below_realm_floor" => Some(Self::EncryptionBelowRealmFloor),
            "circle_encryption_profile_create_locked" => Some(Self::EncryptionProfileCreateLocked),
            _ => None,
        }
    }

    /// Match an `ErrorEnvelope.code` against Circle-adjacent wire codes
    /// that may be emitted directly as the envelope code.
    pub fn from_error_code(code: &str) -> Option<Self> {
        match code {
            ERROR_CODE_DELIVERY_BINDING_HANDED_OVER => Some(Self::DeliveryBindingHandedOver),
            "circle_encryption_below_realm_floor" => Some(Self::EncryptionBelowRealmFloor),
            "circle_encryption_profile_create_locked" => Some(Self::EncryptionProfileCreateLocked),
            _ => None,
        }
    }

    /// English-key for the i18n dictionary
    /// (`error.circle.<kind>` family). Localized strings live in
    /// [`crate::i18n::english_translations`].
    pub fn i18n_key(self) -> &'static str {
        match self {
            Self::RealmMismatch => "error.circle.realm_mismatch",
            Self::NotActive => "error.circle.not_active",
            Self::MemberNotInRealm => "error.circle.member_not_in_realm",
            Self::ScopeRebindForbidden => "error.circle.scope_rebind_forbidden",
            Self::MetadataFloorViolated => "error.circle.metadata_floor",
            Self::EncryptionBelowRealmFloor => "error.circle.encryption_below_realm_floor",
            Self::EncryptionProfileCreateLocked => "error.circle.encryption_profile_locked",
            Self::DeliveryBindingHandedOver => "error.circle.delivery_binding_handed_over",
        }
    }

    /// Fallback English string when the i18n dictionary doesn't carry
    /// the key (e.g. during early boot before [`crate::i18n::init_i18n`]
    /// has populated translations).
    pub fn english_fallback(self) -> &'static str {
        match self {
            Self::RealmMismatch => {
                "This Circle belongs to a different Realm than the message you tried to send."
            }
            Self::NotActive => {
                "The Circle is archived or tombstoned and can no longer receive messages."
            }
            Self::MemberNotInRealm => {
                "Cannot add this user to the Circle — they are not an active member of the parent Realm."
            }
            Self::ScopeRebindForbidden => {
                "Changing an existing object's Circle scope requires an audited admin action."
            }
            Self::MetadataFloorViolated => {
                "This write would expose metadata below the Realm or Circle encryption floor."
            }
            Self::EncryptionBelowRealmFloor => {
                "This Realm requires E2EE, so the Circle must stay MLS-backed."
            }
            Self::EncryptionProfileCreateLocked => {
                "Circle encryption_profile is locked at creation. Create a new Circle to change its E2EE mode."
            }
            Self::DeliveryBindingHandedOver => {
                "The Circle's delivery binding moved to a newer set of devices — please retry."
            }
        }
    }
}

/// Re-export the SDK's canonical `EffectiveScope` so client code can
/// pattern-match on the same enum the reducer produces. Earlier
/// rounds shipped a local `DecryptedScope` mirror — that mirror has
/// been deleted now that the SDK enum is available.
pub use cokret_sdk::model::EffectiveScope;

/// Classify the relationship between an envelope's
/// [`EffectiveScope`] and the payload-level `scope_circle_id`.
///
/// When the two disagree the message body is held in
/// [`MessageCryptoState::NeedsVerification`] and the UI raises a
/// warning badge (see [`crate::components::sync_badge`]). When they
/// agree the body decrypts against the matching MLS group (Realm vs
/// Circle).
pub fn classify_scope_match(
    effective: &EffectiveScope,
    payload_scope_circle_id: Option<&str>,
) -> ScopeMatch {
    match (effective.circle_id(), payload_scope_circle_id) {
        (None, None) => ScopeMatch::Realm,
        (Some(envelope_circle), Some(payload_circle))
            if envelope_circle.as_str() == payload_circle =>
        {
            ScopeMatch::Circle
        }
        _ => ScopeMatch::Mismatch,
    }
}

/// Outcome of [`classify_scope_match`]. Mirrors the three states the
/// chat renderer cares about: Realm-scoped, Circle-scoped, or a
/// mismatch that demands manual verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeMatch {
    /// Realm-scoped — decrypted against the parent Realm MLS group.
    Realm,
    /// Circle-scoped — decrypted against the Circle's independent MLS
    /// group.
    Circle,
    /// `effective_scope` and payload `scope_circle_id` disagreed —
    /// surface as `NeedsVerification` in the message card.
    Mismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_scope_default_label_is_realm() {
        let scope = CircleScope::default();
        assert_eq!(scope.label(), "Realm");
        assert_eq!(scope.circle_id(), None);
        assert!(!scope.is_circle());
    }

    #[test]
    fn circle_scope_carries_id_and_title() {
        let scope = CircleScope::Circle {
            circle_id: "ck:circle:abc".to_owned(),
            title: "Ops".to_owned(),
            member_count: 4,
        };
        assert_eq!(scope.circle_id(), Some("ck:circle:abc"));
        assert_eq!(scope.label(), "Ops");
        assert!(scope.is_circle());
    }

    #[test]
    fn reason_code_maps_circle_reasons() {
        assert_eq!(
            CircleErrorKind::from_reason_code("circle_realm_mismatch"),
            Some(CircleErrorKind::RealmMismatch)
        );
        assert_eq!(
            CircleErrorKind::from_reason_code("circle_not_active"),
            Some(CircleErrorKind::NotActive)
        );
        assert_eq!(
            CircleErrorKind::from_reason_code("circle_member_must_be_realm_member"),
            Some(CircleErrorKind::MemberNotInRealm)
        );
        assert_eq!(
            CircleErrorKind::from_reason_code("scope_rebind_forbidden"),
            Some(CircleErrorKind::ScopeRebindForbidden)
        );
        assert_eq!(
            CircleErrorKind::from_reason_code("metadata_encryption_floor_violation"),
            Some(CircleErrorKind::MetadataFloorViolated)
        );
        assert_eq!(
            CircleErrorKind::from_reason_code("circle_encryption_below_realm_floor"),
            Some(CircleErrorKind::EncryptionBelowRealmFloor)
        );
        assert_eq!(
            CircleErrorKind::from_reason_code("circle_encryption_profile_create_locked"),
            Some(CircleErrorKind::EncryptionProfileCreateLocked)
        );
        assert_eq!(CircleErrorKind::from_reason_code("unrelated"), None);
    }

    #[test]
    fn direct_circle_errors_use_error_code() {
        assert_eq!(
            CircleErrorKind::from_error_code(ERROR_CODE_DELIVERY_BINDING_HANDED_OVER),
            Some(CircleErrorKind::DeliveryBindingHandedOver)
        );
        assert_eq!(
            CircleErrorKind::from_error_code("circle_encryption_below_realm_floor"),
            Some(CircleErrorKind::EncryptionBelowRealmFloor)
        );
        assert_eq!(
            CircleErrorKind::from_error_code("circle_encryption_profile_create_locked"),
            Some(CircleErrorKind::EncryptionProfileCreateLocked)
        );
        assert_eq!(CircleErrorKind::from_error_code("invalid_param"), None);
    }

    #[test]
    fn summary_into_scope_round_trips() {
        let summary = CircleSummary {
            id: "ck:circle:opsroom".to_owned(),
            realm_id: "ck:realm:home".to_owned(),
            title: "Ops Room".to_owned(),
            short_name: "Ops".to_owned(),
            color_token: "indigo".to_owned(),
            symbol: "shield".to_owned(),
            member_count: 7,
            viewer_is_member: true,
        };
        let scope = summary.into_scope();
        assert_eq!(scope.circle_id(), Some("ck:circle:opsroom"));
        assert_eq!(scope.label(), "Ops Room");
    }

    #[test]
    fn all_kinds_have_distinct_i18n_keys() {
        let keys = [
            CircleErrorKind::RealmMismatch.i18n_key(),
            CircleErrorKind::NotActive.i18n_key(),
            CircleErrorKind::MemberNotInRealm.i18n_key(),
            CircleErrorKind::ScopeRebindForbidden.i18n_key(),
            CircleErrorKind::MetadataFloorViolated.i18n_key(),
            CircleErrorKind::EncryptionBelowRealmFloor.i18n_key(),
            CircleErrorKind::EncryptionProfileCreateLocked.i18n_key(),
            CircleErrorKind::DeliveryBindingHandedOver.i18n_key(),
        ];
        let unique: std::collections::HashSet<_> = keys.iter().copied().collect();
        assert_eq!(unique.len(), keys.len(), "i18n keys must be distinct");
        for key in keys {
            assert!(key.starts_with("error.circle."));
        }
    }
}
