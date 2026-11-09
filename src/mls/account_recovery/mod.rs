//! Account checkpoint-key import and native content-root backup publication.
//!
//! The account secret protects local checkpoints. It is not a remote content
//! archive key: former endpoints may retain it. Historical content uses original
//! ciphertext and policy-bound fresh HPKE root blocks, independently of this
//! checkpoint-key import.

mod backup_body;
mod content_roots;
mod current_basis;
pub(crate) use content_roots::ensure_content_root_backup;
mod recovery_transaction;
mod restore;
mod rotation_transaction;
mod upload;

// Which stored envelope a restoring client may open is host runtime logic on
// top of the shared active-series rule in `garth::mls::backup_selection`.
// The series chain itself is a wire-shape decision, owned by garth.
pub(crate) use garth::mls::backup_series::series_supersedes_digest;

pub(crate) use crate::mls::runtime::{
    select_mls_account_secret_backup, select_preferred_mls_account_secret_backup,
};

#[cfg(test)]
mod tests;

pub use backup_body::{
    MLS_ACCOUNT_SECRET_ITEM_KIND, MLS_ACCOUNT_SECRET_SECRET_ID,
    build_mls_account_secret_backup_body_with_kek,
    build_mls_account_secret_backup_body_with_kek_and_version, decrypt_mls_account_secret_backup,
    open_mls_account_secret_recovery_public_key_backup,
};
pub(crate) use recovery_transaction::{
    CompletedFreshDeviceRecovery, execute_pcr_policy_recovery,
    load_completed_pending_pcr_policy_recovery, resume_pending_pcr_policy_recovery,
};
pub(crate) use restore::mls_restore_prompt_required_after_material;
pub use restore::{
    AccountSecretRestoreReport, auto_restore_mls_account_secret_with_passphrase,
    fetch_mls_restore_payload, fetch_mls_restore_payload_after_encrypted_projection,
    fetch_mls_restore_payload_after_projection,
    fetch_mls_restore_payload_with_recovery_session_unlock_proof,
    fetch_mls_restore_payload_with_unlock_proof, mls_backup_prompt_required,
    mls_restore_prompt_required, restore_mls_account_secret_with_passphrase_from_payload,
    restore_mls_account_secret_with_recovery_key_from_payload,
};
pub(crate) use rotation_transaction::execute_device_revoke_security_rotation;
pub use upload::{
    upload_mls_account_secret_backup_with_passphrase,
    upload_mls_account_secret_backup_with_recovery_key,
    upload_mls_account_secret_backup_with_recovery_public_key,
};
