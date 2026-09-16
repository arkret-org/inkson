//! Realm creation defaults shared by UI and event builders.
//!
//! These are holder-local presentation tokens, not wire values. A Realm scope
//! is plaintext until its own accepted `ak.mls.genesis`, after which it is
//! irreversibly standard RFC 9420; there is no create-locked encryption profile
//! or encryption floor on the wire any more.

/// The default the create wizard preselects: activate MLS for the new Realm by
/// authoring its `ak.mls.genesis` as part of the bootstrap unit.
pub const RECOMMENDED_REALM_ENCRYPTION_PROFILE: &str = "mls_rfc9420";

/// The holder-facing label for "every shared write in this Realm is end-to-end
/// encrypted", i.e. the Realm scope has an accepted `ak.mls.genesis`.
pub const RECOMMENDED_REALM_ENCRYPTION_FLOOR: &str = "e2ee_required";
