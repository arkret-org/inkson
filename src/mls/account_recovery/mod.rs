//! Account-recoverable MLS snapshot secret.
//!
//! The MLS snapshot secret is account-scoped (see [`crate::mls::runtime`]) so
//! every device of an account shares one secret and can therefore decrypt the
//! `mls_history` key-backups uploaded by sibling devices. To make that secret
//! survive a brand-new browser, it is wrapped behind the user's Recovery Key
//! (24 words) and uploaded to soland's `secret_storage` endpoint using the
//! `passphrase_kdf` envelope shape from
//! [`crate::key_backup::build_passphrase_kdf_backup_body`].
//!
//! The account secret plaintext is encrypted with XChaCha20-Poly1305 under an
//! Argon2id-derived KEK (see [`crate::recovery_crypto`]); it is never
//! transmitted in clear.
//!
//! This module is split by responsibility:
//! - [`backup_body`] — build / decrypt / classify the on-wire backup envelopes.
//! - [`selection`] — pure selection helpers over a `list_key_backups` payload.
//! - [`series`] — `supersedes` chain construction and verification.
//! - [`restore`] — fetch + restore flow (account secret, history, sidecar).
//! - [`upload`] — backup / rotation upload flow and superseded cleanup.

mod backup_body;
mod recovery_transaction;
mod restore;
mod rotation_transaction;
mod selection;
mod series;
mod upload;

pub(crate) use series::apply_next_series;

#[cfg(test)]
mod tests;

pub use backup_body::{
    MLS_ACCOUNT_SECRET_ITEM_KIND, MLS_ACCOUNT_SECRET_SECRET_ID, MLS_PRIVATE_PLAINTEXT_ITEM_KIND,
    MLS_PRIVATE_PLAINTEXT_SECRET_ID, build_mls_account_secret_backup_body_with_kek,
    build_mls_account_secret_backup_body_with_kek_and_version,
    build_mls_account_secret_recovery_public_key_backup,
    build_mls_private_plaintext_backup_body_with_kek, decrypt_mls_account_secret_backup,
    decrypt_mls_private_plaintext_backup, is_mls_account_secret_backup,
    is_mls_private_plaintext_backup, is_passphrase_account_secret_backup,
    is_recovery_public_key_account_secret_backup,
    open_mls_account_secret_recovery_public_key_backup,
};
#[cfg(debug_assertions)]
pub use recovery_transaction::unlock_joint_recovery_backups;
#[cfg(debug_assertions)]
pub(crate) use recovery_transaction::{
    authorize_recovery_device_request, prepare_enrollment_authority_recovery,
};
pub(crate) use recovery_transaction::{
    execute_cross_signing_recovery, execute_enrollment_authority_recovery,
    resume_pending_fresh_device_recovery,
};
pub use restore::{
    RestoreReport, auto_restore_mls_history_with_passphrase, fetch_mls_account_secret_backup,
    fetch_mls_history_restore_payload_with_unlock_proof, fetch_mls_restore_payload,
    fetch_mls_restore_payload_after_projection,
    fetch_mls_restore_payload_with_recovery_session_unlock_proof,
    fetch_mls_restore_payload_with_unlock_proof, mls_backup_prompt_required,
    mls_restore_prompt_required, restore_mls_history_with_local_secret_from_payload,
    restore_mls_history_with_passphrase_from_payload,
    restore_mls_history_with_recovery_key_from_payload,
};
pub(crate) use rotation_transaction::execute_device_revoke_security_rotation;
pub use selection::{
    mls_account_secret_backup_version, mls_history_series_tail_ids,
    select_mls_account_secret_backup, select_mls_account_secret_recovery_public_key_backup,
    select_mls_history_backups, select_mls_history_tail_for_realm,
    select_mls_private_plaintext_backup, select_preferred_mls_account_secret_backup,
};
pub use upload::{
    fetch_mls_history_tail_for_realm, fetch_mls_private_plaintext_backup_body,
    upload_mls_account_secret_backup_with_passphrase,
    upload_mls_account_secret_backup_with_recovery_key,
    upload_mls_account_secret_backup_with_recovery_public_key,
    upload_mls_history_backup_with_previous, upload_mls_private_plaintext_backup,
    upload_mls_private_plaintext_backup_with_previous,
};
