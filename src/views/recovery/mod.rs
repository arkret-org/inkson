//! Recovery surface — Recovery Key (24 words) + restore-from-backup.
//!
//! - **Recovery Key (24 words)**: 256 bits of entropy, formatted as a 24-word BIP-39 mnemonic. This
//!   is the ONLY user-visible recovery credential — `normalize_recovery_key_input` (and therefore
//!   the `MlsUnlockPrompt` restore path) only accepts this 24-word format. Enrollment is
//!   custody-first: the client generates and displays the words in memory, requires an exact
//!   re-entry, and only then publishes the recovery policy and `did_recovery` backup. Public local
//!   metadata (SHA-256 fingerprint, backup-HPKE multikey, and rotation timestamp) is committed
//!   after server acceptance. The recovery secret is never uploaded or persisted as ordinary device
//!   state.
//! - **Backup history**: summarizes the server-side `ak.schema.key_backup.v1` ciphertext envelopes
//!   by creation time, emphasizing the latest encrypted backup without exposing per-backup
//!   controls.
//! The Recovery view never persists the Recovery Key itself in plaintext,
//! encrypted form, or via the private-data path.
//!
//! Split by responsibility into:
//!   - [`types`]: serialized state + backup-summary data types;
//!   - [`backup_summary`]: backup-list parsing, sorting, and status formatting;
//!   - [`state`]: private-data load/save and recovery-material predicates;
//!   - [`helpers`]: clipboard helper;
//!   - [`upload`]: the RK-as-authority server backup flow;
//!   - [`panel`]: the `RecoveryPanel` Dioxus component.

const RECOVERY_STATE_KEY: &str = "recovery.state.v1";

mod backup_summary;
mod helpers;
mod panel;
mod state;
mod types;
mod upload;

#[cfg(test)]
mod tests;

pub use panel::RecoveryPanel;
pub(crate) use state::{
    local_recovery_key_fingerprint, local_recovery_public_key, local_recovery_public_key_result,
    recovery_options_configured, save_generated_recovery_key_metadata,
};
pub(crate) use upload::{RecoveryKeyBackupOutcome, upload_recovery_key_account_backup};
