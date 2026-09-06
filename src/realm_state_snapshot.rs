#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmStateSnapshotTrustState {
    LowerTrust,
    Verified,
    Degraded,
}
