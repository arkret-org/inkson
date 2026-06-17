//! Typed MLS-runtime readiness status and error surface.

use crate::secure_key_store::SecureKeyStoreError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsRuntimeStatus {
    Ready,
    MissingWelcome,
    MissingDeviceSecret(String),
    SnapshotDecryptFailed(String),
    UnsupportedTarget,
}

impl MlsRuntimeStatus {
    pub fn user_message(&self) -> String {
        match self {
            Self::Ready => "MLS state ready".to_owned(),
            Self::MissingWelcome => {
                "MLS state is not ready on this device yet; wait for an MLS Welcome or restore this device's encrypted MLS history backup.".to_owned()
            }
            Self::MissingDeviceSecret(reason) => {
                format!("device MLS snapshot secret unavailable: {reason}")
            }
            Self::SnapshotDecryptFailed(reason) => {
                format!("stored MLS history could not be decrypted ({reason}); restore your encrypted MLS history with your 24-word Recovery Key.")
            }
            Self::UnsupportedTarget => {
                "MLS runtime unavailable (internal error)".to_owned()
            }
        }
    }
}

#[derive(Debug)]
pub enum MlsRuntimeError {
    EmptyPlaintext,
    MissingWelcome,
    DeviceSecret(SecureKeyStoreError),
    Identity(String),
    Genesis(String),
    Welcome(String),
    SnapshotRestore(String),
    Commit(String),
    Encrypt(String),
    Backup(String),
    BackupDecode(String),
    Serialize(String),
    Export(String),
    Salt(String),
    /// SEC-08 — a `minimal_metadata_realm` send tried to use a non-hidden
    /// `aad_visibility`, which `enforce_minimal_metadata_aad` rejects
    /// (`encryption-and-audit.md` §2.9). Fail-closed: the message/reaction is
    /// never emitted with a wider visibility than the profile permits.
    AadPolicy(String),
}

impl MlsRuntimeError {
    pub fn status(&self) -> MlsRuntimeStatus {
        match self {
            Self::EmptyPlaintext => MlsRuntimeStatus::Ready,
            Self::MissingWelcome => MlsRuntimeStatus::MissingWelcome,
            Self::DeviceSecret(err) => MlsRuntimeStatus::MissingDeviceSecret(err.to_string()),
            Self::Identity(reason) | Self::Welcome(reason) => {
                MlsRuntimeStatus::SnapshotDecryptFailed(reason.clone())
            }
            Self::SnapshotRestore(reason) => {
                MlsRuntimeStatus::SnapshotDecryptFailed(reason.clone())
            }
            Self::Genesis(_)
            | Self::Commit(_)
            | Self::Encrypt(_)
            | Self::Backup(_)
            | Self::BackupDecode(_)
            | Self::Serialize(_)
            | Self::Export(_)
            | Self::Salt(_)
            | Self::AadPolicy(_) => MlsRuntimeStatus::Ready,
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            Self::EmptyPlaintext => "internal: no MLS plaintext values to encrypt".to_owned(),
            Self::MissingWelcome | Self::DeviceSecret(_) | Self::SnapshotRestore(_) => {
                self.status().user_message()
            }
            Self::Identity(reason) => format!("MLS identity unavailable: {reason}"),
            Self::Genesis(reason) => format!("MLS initial group setup failed: {reason}"),
            Self::Welcome(reason) => format!("MLS Welcome could not be applied: {reason}"),
            Self::Commit(reason) => format!("MLS commit failed: {reason}"),
            Self::Encrypt(reason) => format!("MLS payload encryption failed: {reason}"),
            Self::Backup(reason) => format!("MLS history backup failed: {reason}"),
            Self::BackupDecode(reason) => format!("MLS history backup is invalid: {reason}"),
            Self::Serialize(reason) => {
                format!("MLS encrypted payload serialization failed: {reason}")
            }
            Self::Export(reason) => format!("MLS state export failed: {reason}"),
            Self::Salt(reason) => format!("MLS snapshot salt generation failed: {reason}"),
            Self::AadPolicy(reason) => {
                format!("MLS minimal-metadata AAD policy violation: {reason}")
            }
        }
    }
}
