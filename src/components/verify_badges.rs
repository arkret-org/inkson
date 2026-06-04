//! Visual indicators for crypto state and Realm class (P3B.6).
//!
//! Two small surfaces:
//!
//! - [`NeedsVerificationBadge`] — rendered next to a message when its crypto state is
//!   `NeedsVerification`. Red dot + tooltip warning the reader the sender's device hasn't been
//!   cross-signed yet.
//! - [`RealmClassBadge`] — rendered next to a Realm name in the switcher / sidebar / breadcrumb so
//!   the user can instantly tell a Principal Realm (federation identity) apart from a Collaboration
//!   Realm (shared workspace inside someone else's Principal Realm).
//!
//! The badges are intentionally pure — they take a single typed prop
//! and render an `<span>` with a stable `data-testid` for the e2e
//! harness.

use dioxus::prelude::*;

// TRUST-CACHE: `NeedsVerificationBadge` and `RealmClassBadge` are
// cache-allowed surfaces per CKP B-E §1 / identity-handles §6. They
// render the locally-cached binding state but MUST downgrade to the
// "needs verification" tint on a cache miss or any §6.1.2 trigger.
// Authority surfaces (wallet disclosure / accept invite / audit-trail
// review) MUST go through `crate::did_resolver::build_default_resolver`
// and verify the DID Document inline before granting trust — they
// MUST NOT consult these cached badges as a source of truth.

/// Renders a small "Needs verification" badge. Hidden when `active` is
/// `false` so call sites can unconditionally include the badge in
/// message-card rsx without an `if` branch.
#[component]
pub fn NeedsVerificationBadge(active: bool) -> Element {
    if !active {
        return rsx! {};
    }
    rsx! {
        span {
            class: "badge needs-verification-badge red",
            "data-testid": "needs-verification-badge",
            title: "Sender device hasn't been verified. Cross-sign or scan a QR before trusting this message.",
            "⚠ Needs verification"
        }
    }
}

/// Realm classification used by [`RealmClassBadge`]. Sourced from the
/// Realm's `security_class` field (`principal` | `collaboration`)
/// surfaced by `ck.realm.create`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealmClass {
    /// The user's home Realm — carries the federation identity, the
    /// device set, the recovery vault. Loss of this Realm is a hard
    /// account-recovery event.
    Principal,
    /// A workspace inside someone else's Principal Realm. The user has
    /// no federation identity here — they're a guest member.
    Collaboration,
    /// Unknown / not yet hydrated. Renders nothing (so the badge
    /// doesn't flash on initial load).
    Unknown,
}

impl RealmClass {
    pub fn from_wire(value: &str) -> Self {
        match value {
            "principal" => Self::Principal,
            "collaboration" => Self::Collaboration,
            _ => Self::Unknown,
        }
    }
}

#[component]
pub fn RealmClassBadge(class: RealmClass) -> Element {
    match class {
        RealmClass::Principal => rsx! {
            span {
                class: "badge realm-class-badge principal",
                "data-testid": "realm-class-badge",
                "data-class": "principal",
                title: "Principal Realm — your home federation identity lives here.",
                "★ Principal"
            }
        },
        RealmClass::Collaboration => rsx! {
            span {
                class: "badge realm-class-badge collaboration",
                "data-testid": "realm-class-badge",
                "data-class": "collaboration",
                title: "Collaboration Realm — guest workspace inside another Principal Realm.",
                "↔ Collaboration"
            }
        },
        RealmClass::Unknown => rsx! {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_class_from_wire_maps_known_values() {
        assert_eq!(RealmClass::from_wire("principal"), RealmClass::Principal);
        assert_eq!(
            RealmClass::from_wire("collaboration"),
            RealmClass::Collaboration
        );
        assert_eq!(RealmClass::from_wire("hybrid"), RealmClass::Unknown);
        assert_eq!(RealmClass::from_wire(""), RealmClass::Unknown);
    }
}
