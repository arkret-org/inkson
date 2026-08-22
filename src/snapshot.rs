#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SnapshotTrustState {
    LowerTrust,
    Verified,
    Degraded,
}
