//! Recovery surface — Recovery Key (24 words) + restore-from-backup, with
//! Social Recovery tucked behind an "Advanced" fold.
//!
//! - **Recovery Key (24 words)**: 256 bits of entropy, formatted as a 24-word BIP-39 mnemonic. This
//!   is the ONLY user-visible recovery credential — `normalize_recovery_key_input` (and therefore
//!   the `MlsUnlockPrompt` restore path) only accepts this 24-word format. Enrollment is
//!   server-first (design: `docs/design/recovery-key-server-first.md`): generating the key
//!   publishes the recovery policy and a `did_recovery` backup, wraps the account MLS secret behind
//!   it when one exists (see `upload_recovery_key_account_backup`), and the words are shown ONLY
//!   after the server accepts — so a rejected registration never invalidates a copy the user
//!   already wrote down. Local metadata (SHA-256 fingerprint + rotation timestamp, via
//!   `LocalStateStore::save_private_data`) stays pending until the user passes the transcription
//!   check; until then, the words are staged only in the hardened secure store so an accidental
//!   refresh can resume the same confirmation. The words are never uploaded.
//! - **Backup history**: summarizes the server-side `ak.schema.key_backup.v1` ciphertext envelopes
//!   by creation time, emphasizing the latest encrypted backup without exposing per-backup
//!   controls.
//! - **Social Recovery** (advanced, local bookkeeping only): guardian list + Shamir threshold +
//!   last-rehearsal timestamp persisted as JSON under the same private_data store.
//!
//! Everything writeable goes through `private_data`, which is XOR-obfuscated
//! (NOT encrypted) at rest under the public account DID via
//! `obfuscate_nonsensitive` (and on wasm32 mirrored to localStorage) — it holds
//! only non-sensitive markers such as a last-rehearsal timestamp. The Recovery
//! view never persists the Recovery Key itself in plaintext or via this path; pending words use
//! the platform SecureKeyStore and are deleted after confirmation.
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
    local_recovery_key_fingerprint, local_recovery_public_key, recovery_options_configured,
    save_generated_recovery_key_metadata,
};
pub(crate) use upload::{
    RecoveryKeyBackupOutcome, clear_pending_recovery_key, load_pending_recovery_key,
    upload_recovery_key_account_backup,
};
