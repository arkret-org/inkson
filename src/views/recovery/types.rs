//! Serialized recovery state and backup-summary data types.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Guardian {
    pub(crate) label: String,
    pub(crate) did: String,
    pub(crate) note: String,
    #[serde(default)]
    pub(crate) confirmed: bool,
}

/// One row in the backup history summary. The server returns the full
/// `ak.schema.key_backup.v1` envelope; the user-facing panel keeps only the
/// fields needed for aggregate status and timestamp display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BackupSummaryRow {
    pub(crate) backup_id: String,
    pub(crate) backup_class: String,
    pub(crate) created_at: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BackupClassCounts {
    pub(crate) did_recovery: usize,
    pub(crate) secret_storage: usize,
    pub(crate) mls_history: usize,
    pub(crate) other: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// 3 of 5, 2 of 3, etc. — encoded as `threshold / total`.
    #[serde(default = "default_threshold")]
    pub(crate) sss_threshold: u32,
    #[serde(default = "default_total")]
    pub(crate) sss_total: u32,
    #[serde(default)]
    pub(crate) guardians: Vec<Guardian>,
    /// RFC-3339 UTC of the last "Rehearse social recovery" click.
    #[serde(default)]
    pub(crate) last_rehearsed_at: String,
}

pub(crate) fn default_threshold() -> u32 {
    3
}
pub(crate) fn default_total() -> u32 {
    5
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self {
            recovery_key_fingerprint: String::new(),
            backup_hpke_public_key_multibase: String::new(),
            recovery_key_rotated_at: String::new(),
            sss_threshold: default_threshold(),
            sss_total: default_total(),
            guardians: Vec::new(),
            last_rehearsed_at: String::new(),
        }
    }
}
