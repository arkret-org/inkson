//! Recovery surface — Recovery Key (24 words) + restore-from-backup, with
//! Social Recovery tucked behind an "Advanced" fold.
//!
//! - **Recovery Key (24 words)**: 256 bits of entropy, formatted as a 24-word BIP-39 mnemonic. This
//!   is the ONLY user-visible recovery credential — `normalize_recovery_key_input` (and therefore
//!   the `MlsUnlockPrompt` restore path) only accepts this 24-word format, so generating the key
//!   publishes the recovery policy and a `did_recovery` backup immediately, then wraps the account
//!   MLS secret behind it when one exists (see `upload_recovery_key_account_backup`). The mnemonic
//!   plaintext only lives in memory between Generate and the user's Copy interaction; only a
//!   SHA-256 fingerprint plus rotation timestamp are persisted via
//!   `LocalStateStore::save_private_data` — the words themselves are never uploaded.
//! - **Backup history**: summarizes the server-side `ck.schema.key_backup.v1` ciphertext envelopes
//!   by creation time, emphasizing the latest encrypted backup without exposing per-backup
//!   controls.
//! - **Social Recovery** (advanced, local bookkeeping only): guardian list + Shamir threshold +
//!   last-rehearsal timestamp persisted as JSON under the same private_data store.
//!
//! Everything writeable goes through `private_data`, which is itself
//! encrypted at rest under the account DID via `xor_encrypt` (and on
//! wasm32 mirrored to localStorage). The Recovery view never persists
//! the Recovery Key in plaintext.
//!
//! Split by responsibility into:
//!   - [`types`]: serialized state + backup-summary data types;
//!   - [`backup_summary`]: backup-list parsing, sorting, and status formatting;
//!   - [`state`]: private-data load/save and recovery-material predicates;
//!   - [`helpers`]: passkey-wrap AAD and clipboard helpers;
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
    local_recovery_key_fingerprint, recovery_options_configured,
    save_generated_recovery_key_metadata,
};
pub(crate) use upload::{RecoveryKeyBackupOutcome, upload_recovery_key_account_backup};
