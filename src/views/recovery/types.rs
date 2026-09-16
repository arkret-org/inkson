//! Serialized recovery state and backup-summary data types.

use serde::{Deserialize, Serialize};

/// One row in the backup history summary. The server returns the full
/// `ak.schema.key_backup.v1` envelope; the user-facing panel keeps only the
/// fields needed for aggregate status and timestamp display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BackupSummaryRow {
    pub(crate) backup_id: String,
    pub(crate) backup_kind: String,
    pub(crate) created_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecoveryState {
    /// SHA-256 fingerprint of the current Recovery Key (never the plaintext).
    #[serde(default)]
    pub(crate) recovery_key_fingerprint: String,
    /// Canonical X25519 multikey derived from the current Recovery Key.
    /// This is not secret; it lets the device seal future backups without
    /// asking the user to re-enter the 24 words.
    #[serde(default)]
    pub(crate) backup_hpke_public_key_multibase: String,
    /// RFC-3339 UTC timestamp of the last Recovery Key rotation.
    #[serde(default)]
    pub(crate) recovery_key_rotated_at: String,
}
