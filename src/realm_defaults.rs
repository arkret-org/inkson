//! Realm creation defaults shared by UI and event builders.

pub const RECOMMENDED_REALM_ENCRYPTION_PROFILE: &str = "mls_rfc9420";
pub const RECOMMENDED_REALM_ENCRYPTION_FLOOR: &str = "e2ee_required";

/// Same value as [`RECOMMENDED_REALM_ENCRYPTION_FLOOR`], as the SDK enum the
/// typed payloads take. The string form stays because several UI comparisons
/// read the floor back out of untyped projections.
pub const RECOMMENDED_REALM_ENCRYPTION_FLOOR_TYPED: arkret_sdk::EncryptionFloor =
    arkret_sdk::EncryptionFloor::E2eeRequired;
