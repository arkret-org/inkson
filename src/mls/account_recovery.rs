//! Account-recoverable MLS snapshot secret.
//!
//! The MLS snapshot secret is account-scoped (see [`crate::mls::runtime`]) so
//! every device of an account shares one secret and can therefore decrypt the
//! `mls_history` key-backups uploaded by sibling devices. To make that secret
//! survive a brand-new browser, it is wrapped behind the user's recovery
//! passphrase and uploaded to soland's `secret_storage` endpoint using the same
//! envelope shape as [`crate::key_backup::build_recovery_vault_backup_body`].
//!
//! The account secret plaintext is encrypted with XChaCha20-Poly1305 under an
//! Argon2id-derived KEK (see [`crate::recovery_crypto`]); it is never
//! transmitted in clear.

use anyhow::{Result, anyhow};
use serde_json::Value;

use crate::key_backup::build_recovery_vault_backup_body;
use crate::recovery_crypto::{
    VAULT_ARGON2_M_KIB, VAULT_ARGON2_P, VAULT_ARGON2_T, VaultKek, decrypt_vault, derive_vault_kek,
    encrypt_vault,
};

/// `item_type` carried by the account MLS snapshot secret backup.
///
/// Both soland's validator
/// (`soland/src/routing/identity/key_backup.rs::KEY_BACKUP_CONTENT_TYPES`)
/// and the yougen client validator
/// (`key_backup::item_type_allowed_for_class`) allowlist this dedicated
/// content type under the `secret_storage` class, so it is the primary
/// discriminator for the recovery import path. `secret_id` is still carried
/// for human-readable disambiguation.
pub const MLS_ACCOUNT_SECRET_ITEM_TYPE: &str = "mls_account_secret";
/// `secret_id` carried by the account MLS snapshot secret backup. This is the
/// stable discriminator the recovery import path matches against.
pub const MLS_ACCOUNT_SECRET_SECRET_ID: &str = "yougen_mls_account_secret";

/// X5.3 — `item_type` carried by the encrypted local-plaintext sidecar backup.
///
/// The sidecar (`LocalStateStore::mls_private_plaintext`, the author's own
/// plaintext for their encrypted private flow fields) MUST cross devices: a new
/// browser can never decrypt the author's own MLS ciphertext (OpenMLS
/// `validation.rs` rejects own-leaf messages before any key lookup), so without
/// this backup the author loses sight of everything they wrote after switching
/// browsers. The sidecar JSON is encrypted under a KEK derived from the ACCOUNT
/// SECRET (not the passphrase directly) so the restore flow — which imports the
/// account secret first — can decrypt it with NO second passphrase prompt. Both
/// soland's validator and the yougen client validator allowlist this content
/// type under the `secret_storage` class.
pub const MLS_PRIVATE_PLAINTEXT_ITEM_TYPE: &str = "mls_private_plaintext";
/// `secret_id` carried by the encrypted local-plaintext sidecar backup.
pub const MLS_PRIVATE_PLAINTEXT_SECRET_ID: &str = "yougen_mls_private_plaintext";

/// Build a `secret_storage` PUT body that wraps the account MLS snapshot secret
/// behind an already-derived recovery KEK.
///
/// The envelope shape reuses [`build_recovery_vault_backup_body`] (same
/// `secret_storage` / `passphrase_kdf` / argon2id+xchacha20poly1305 shape that
/// soland already validates). The plaintext account secret is encrypted with the
/// supplied KEK; only the ciphertext, salt and nonce travel on the wire. The
/// `item_type` / `secret_id` are overwritten to the MLS-secret identifiers.
///
/// NOTE: the KEK MUST be derived from the user's recovery *passphrase* (the same
/// source `decrypt_mls_account_secret_backup` stretches on restore), never from
/// the account secret itself — wrapping the account secret under a KEK derived
/// from that same account secret would make the backup self-referential and
/// undecryptable by the recovery flow. (A former `build_mls_account_secret_backup_body`
/// helper that derived the KEK from the account secret was removed for this
/// reason; it was dead code and a latent footgun.)
pub fn build_mls_account_secret_backup_body_with_kek(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    kek: &VaultKek,
    account_secret: &str,
) -> Result<Value> {
    build_mls_account_secret_backup_body_with_kek_and_version(
        backup_id,
        actor_did,
        device_id,
        kek,
        account_secret,
        crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION,
    )
}

/// Variant of [`build_mls_account_secret_backup_body_with_kek`] that records
/// the local account-secret version in the backup content metadata.
pub fn build_mls_account_secret_backup_body_with_kek_and_version(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    kek: &VaultKek,
    account_secret: &str,
    account_secret_version: u32,
) -> Result<Value> {
    let ct = encrypt_vault(kek, account_secret.as_bytes())
        .map_err(|err| anyhow!("encrypt account secret: {err}"))?;
    // `encrypt_vault` emits base64url (`-`/`_`) natively, which is exactly the
    // charset the key-backup validator requires, so the wire fields go straight
    // into the uploaded body.
    let mut body = build_recovery_vault_backup_body(
        backup_id,
        actor_did,
        device_id,
        &ct.ciphertext_b64,
        &ct.digest_sha256,
        &ct.salt_b64,
        &ct.nonce_b64,
        VAULT_ARGON2_M_KIB,
        VAULT_ARGON2_T,
        VAULT_ARGON2_P,
    );
    // Re-label the single content item from the recovery-vault default
    // (`recovery_secret` / `yougen_recovery_vault_payload`) to the MLS account
    // secret identifiers, then re-attach domain separation so the AAD's
    // `item_types` matches the rewritten contents.
    if let Some(item) = body
        .get_mut("contents")
        .and_then(Value::as_array_mut)
        .and_then(|c| c.first_mut())
        .and_then(Value::as_object_mut)
    {
        item.insert(
            "item_type".to_owned(),
            Value::String(MLS_ACCOUNT_SECRET_ITEM_TYPE.to_owned()),
        );
        item.insert(
            "secret_id".to_owned(),
            Value::String(MLS_ACCOUNT_SECRET_SECRET_ID.to_owned()),
        );
        item.insert(
            "secret_version".to_owned(),
            Value::Number(serde_json::Number::from(account_secret_version)),
        );
    }
    crate::key_backup::attach_key_backup_domain_separation(
        &mut body,
        crate::key_backup::KeyBackupClass::SecretStorage,
        "recovery_vault",
    );
    Ok(body)
}

/// Decrypt a downloaded `mls_account_secret` backup body with the user's
/// recovery passphrase and return the account snapshot secret bytes.
///
/// Mirrors [`decrypt_vault`]: the salt/nonce/ciphertext are read from the
/// envelope and the passphrase is stretched with the same Argon2id parameters.
pub fn decrypt_mls_account_secret_backup(passphrase: &[u8], body: &Value) -> Result<Vec<u8>> {
    let encryption = body
        .get("encryption")
        .ok_or_else(|| anyhow!("backup body missing encryption"))?;
    let salt_b64 = encryption
        .get("kdf")
        .and_then(|kdf| kdf.get("salt"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup body missing encryption.kdf.salt"))?;
    let nonce_b64 = encryption
        .get("aead")
        .and_then(|aead| aead.get("nonce"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup body missing encryption.aead.nonce"))?;
    let ciphertext_b64 = body
        .get("ciphertext")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup body missing ciphertext"))?;
    // The wire fields are base64url, which is exactly what `decrypt_vault`
    // decodes, so they are fed straight in.
    decrypt_vault(passphrase, salt_b64, nonce_b64, ciphertext_b64)
}

/// True when `body` is an MLS account-secret backup. Matched on the dedicated
/// `mls_account_secret` item type (now allowlisted by both validators);
/// `secret_id` remains as a secondary, human-readable label.
pub fn is_mls_account_secret_backup(body: &Value) -> bool {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|item| item.get("item_type"))
        .and_then(Value::as_str)
        == Some(MLS_ACCOUNT_SECRET_ITEM_TYPE)
}

/// X5.3 — build a `secret_storage` PUT body that wraps the entire encrypted
/// local-plaintext sidecar map behind a KEK derived from the ACCOUNT SECRET.
///
/// Mirrors [`build_mls_account_secret_backup_body_with_kek_and_version`] but
/// with the sidecar identifiers and the sidecar JSON bytes as the encrypted
/// payload. `sidecar_json` is the serialized `mls_private_plaintext` map
/// (`serde_json::to_vec` of `space -> flow -> field -> plaintext`); only its
/// ciphertext, salt and nonce travel on the wire. The caller derives `kek` from
/// the account secret (`derive_vault_kek(account_secret.as_bytes())`), so the
/// restore path — which imports the account secret first — can decrypt with no
/// second passphrase prompt. base64url-clean; domain separation re-attached so
/// the AAD's `item_types` matches the rewritten contents.
pub fn build_mls_private_plaintext_backup_body_with_kek(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    kek: &VaultKek,
    sidecar_json: &[u8],
) -> Result<Value> {
    let ct = encrypt_vault(kek, sidecar_json)
        .map_err(|err| anyhow!("encrypt private plaintext sidecar: {err}"))?;
    // `encrypt_vault` emits base64url natively (the charset the validator
    // requires), so the wire fields go straight into the uploaded body.
    let mut body = build_recovery_vault_backup_body(
        backup_id,
        actor_did,
        device_id,
        &ct.ciphertext_b64,
        &ct.digest_sha256,
        &ct.salt_b64,
        &ct.nonce_b64,
        VAULT_ARGON2_M_KIB,
        VAULT_ARGON2_T,
        VAULT_ARGON2_P,
    );
    if let Some(item) = body
        .get_mut("contents")
        .and_then(Value::as_array_mut)
        .and_then(|c| c.first_mut())
        .and_then(Value::as_object_mut)
    {
        item.insert(
            "item_type".to_owned(),
            Value::String(MLS_PRIVATE_PLAINTEXT_ITEM_TYPE.to_owned()),
        );
        item.insert(
            "secret_id".to_owned(),
            Value::String(MLS_PRIVATE_PLAINTEXT_SECRET_ID.to_owned()),
        );
    }
    crate::key_backup::attach_key_backup_domain_separation(
        &mut body,
        crate::key_backup::KeyBackupClass::SecretStorage,
        "recovery_vault",
    );
    Ok(body)
}

/// X5.3 — decrypt a downloaded `mls_private_plaintext` backup body and return
/// the serialized sidecar JSON bytes.
///
/// The KEK source is the ACCOUNT SECRET bytes (NOT the recovery passphrase):
/// the restore flow imports the account secret first, then feeds its bytes here
/// so the sidecar is recovered with no second passphrase prompt. `decrypt_vault`
/// internally derives the KEK from these bytes + the stored salt, exactly as the
/// account-secret path does.
pub fn decrypt_mls_private_plaintext_backup(
    account_secret: &[u8],
    body: &Value,
) -> Result<Vec<u8>> {
    let encryption = body
        .get("encryption")
        .ok_or_else(|| anyhow!("backup body missing encryption"))?;
    let salt_b64 = encryption
        .get("kdf")
        .and_then(|kdf| kdf.get("salt"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup body missing encryption.kdf.salt"))?;
    let nonce_b64 = encryption
        .get("aead")
        .and_then(|aead| aead.get("nonce"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup body missing encryption.aead.nonce"))?;
    let ciphertext_b64 = body
        .get("ciphertext")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup body missing ciphertext"))?;
    decrypt_vault(account_secret, salt_b64, nonce_b64, ciphertext_b64)
}

/// True when `body` is an MLS private-plaintext sidecar backup. Matched on the
/// dedicated `mls_private_plaintext` item type.
pub fn is_mls_private_plaintext_backup(body: &Value) -> bool {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|item| item.get("item_type"))
        .and_then(Value::as_str)
        == Some(MLS_PRIVATE_PLAINTEXT_ITEM_TYPE)
}

/// Pure body-selection: pick the latest `mls_private_plaintext` backup from a
/// `list_key_backups`-shaped payload, if present. Newer `series_seq` wins,
/// followed by the creation timestamp.
pub fn select_mls_private_plaintext_backup(list_payload: &Value) -> Option<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| is_mls_private_plaintext_backup(body))
        .max_by(|a, b| {
            (backup_series_seq(a), backup_created_at(a))
                .cmp(&(backup_series_seq(b), backup_created_at(b)))
        })
        .cloned()
}

/// Iterate the `{"backups": [...]}` payload returned by
/// [`crate::api::ContrixApi::list_key_backups`].
///
/// The selection helpers below are consumed by the async auto-restore helpers
/// (now available on all targets) and their tests.
fn iter_backup_bodies(list_payload: &Value) -> impl Iterator<Item = &Value> {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .map(|arr| arr.iter())
        .into_iter()
        .flatten()
}

fn backup_series_seq(body: &Value) -> u64 {
    body.get("series_seq").and_then(Value::as_u64).unwrap_or(0)
}

fn backup_created_at(body: &Value) -> &str {
    body.get("created_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn backup_secret_version(body: &Value) -> u64 {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|item| item.get("secret_version"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// Version recorded in an `mls_account_secret` backup. Legacy backups did not
/// carry this field, so they import at the current default version.
pub fn mls_account_secret_backup_version(body: &Value) -> u32 {
    backup_secret_version(body)
        .try_into()
        .ok()
        .filter(|version| *version > 0)
        .unwrap_or(crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION)
}

/// Pure body-selection: pick the latest `mls_account_secret` backup from a
/// `list_key_backups`-shaped payload, if present. Newer `series_seq` wins,
/// followed by the local secret version and creation timestamp.
pub fn select_mls_account_secret_backup(list_payload: &Value) -> Option<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| is_mls_account_secret_backup(body))
        .max_by(|a, b| {
            (
                backup_series_seq(a),
                backup_secret_version(a),
                backup_created_at(a),
            )
                .cmp(&(
                    backup_series_seq(b),
                    backup_secret_version(b),
                    backup_created_at(b),
                ))
        })
        .cloned()
}

/// Pure body-selection: collect every `mls_history` backup body from a
/// `list_key_backups`-shaped payload.
pub fn select_mls_history_backups(list_payload: &Value) -> Vec<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| {
            body.get("backup_class").and_then(Value::as_str)
                == Some(crate::key_backup::KeyBackupClass::MlsHistory.as_str())
        })
        .cloned()
        .collect()
}

fn mls_history_backup_needs_restore(
    body: &Value,
    state_store: &crate::local_state::LocalStateStore,
    local_secret: &str,
) -> bool {
    let Ok(envelope) = crate::mls::runtime::decode_mls_history_backup_envelope(body) else {
        return false;
    };
    // P0 fork guard: verify the local secret can actually open the SERVER's
    // history ciphertext. A new device's Welcome bootstrap mints a fresh random
    // account/device-snapshot secret when none exists yet, then saves a local
    // snapshot encrypted under that random secret. That local snapshot will
    // always self-decrypt, so testing only the local snapshot (as we did below)
    // cannot tell a genuinely-recovered secret apart from a forked random one.
    // If the local secret fails to decrypt this server backup, the device has
    // forked from the account-secret recovery chain and MUST be prompted to
    // unlock/import before it pollutes the chain with its own history backups.
    // (Backups this same device uploaded under the random secret still decrypt,
    // so we rely on `.any()` across the full server set to catch a sibling
    // device's backup made under the real account secret.)
    if crate::mls::persistence::decrypt_envelope(&envelope, local_secret).is_err() {
        return true;
    }
    let Some(local_snapshot) = state_store.mls_snapshot_for(&envelope.space_id) else {
        return true;
    };
    if local_snapshot.group_id != envelope.group_id || local_snapshot.epoch < envelope.epoch {
        return true;
    }
    crate::mls::persistence::decrypt_envelope(&local_snapshot, local_secret).is_err()
}

/// Decide whether the app should ask the user for their recovery passphrase to
/// unlock MLS history.
///
/// A local account secret alone is not enough readiness proof: an earlier
/// incomplete bootstrap can leave a stale/random local secret without any
/// usable per-Space MLS snapshot. In that state encrypted writes still fail
/// with `MissingWelcome`, so the prompt must stay available whenever the
/// server has account-secret recovery material and local history is missing,
/// stale, or undecryptable.
pub fn mls_restore_prompt_required(
    list_payload: &Value,
    state_store: &crate::local_state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
) -> bool {
    if select_mls_account_secret_backup(list_payload).is_none() {
        return false;
    }
    let local_secret =
        crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_did, device_id).ok();
    let Some(local_secret) = local_secret.filter(|secret| !secret.trim().is_empty()) else {
        return true;
    };
    select_mls_history_backups(list_payload)
        .iter()
        .any(|body| mls_history_backup_needs_restore(body, state_store, &local_secret))
}

/// Counts returned by [`auto_restore_mls_history_with_passphrase`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Whether the account MLS secret was imported or refreshed from the
    /// server backup on this call.
    pub account_secret_imported: bool,
    /// Number of `mls_history` backups successfully restored into the state store.
    pub restored: usize,
    /// Number of `mls_history` backups that failed to restore.
    pub failed: usize,
    /// X5.3 — whether the encrypted local-plaintext sidecar backup was
    /// successfully decrypted and merged into the local state store on this
    /// call. Stays `false` when no sidecar backup exists or restore of it
    /// failed (a non-fatal condition; see `first_error`).
    pub private_plaintext_restored: bool,
    /// First restore failure reason, for diagnostics.
    pub first_error: Option<String>,
}

/// Pure-fetch helper: list the server's key backups and return the
/// `mls_account_secret` body if one is present (None if absent). No passphrase
/// is required — this is the SAFE half that can run at silent boot to *detect*
/// whether account-secret recovery is available.
pub async fn fetch_mls_account_secret_backup(
    api: &crate::api::ContrixApi,
) -> Result<Option<Value>> {
    let payload = api
        .list_key_backups()
        .await
        .map_err(|err| anyhow!("list key backups: {err}"))?;
    Ok(select_mls_account_secret_backup(&payload))
}

/// Fetch the full key-backup list once for MLS account-secret import +
/// history restore.
///
/// UI callers that hold a Dioxus `Signal<LocalStateStore>` should call this
/// before acquiring `state_store.write()`, then pass the returned payload into
/// [`restore_mls_history_with_passphrase_from_payload`]. That keeps the local
/// state write guard out of the network await.
pub async fn fetch_mls_restore_payload(api: &crate::api::ContrixApi) -> Result<Value> {
    api.list_key_backups()
        .await
        .map_err(|err| anyhow!("list key backups: {err}"))
}

/// Restore MLS account secret + history from an already-fetched
/// `list_key_backups` payload.
///
/// This function is deliberately synchronous: it can run inside a short
/// `state_store.write()` critical section after all network awaits have
/// completed.
pub fn restore_mls_history_with_passphrase_from_payload(
    list_payload: &Value,
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    let mut report = RestoreReport::default();

    // Step 1: refresh the local account secret from the server backup when it
    // exists. This deliberately runs even if a local secret is present: a
    // previous incomplete bootstrap may have generated a stale/random secret,
    // which would make every history restore fail with a secret mismatch.
    let has_local_secret =
        crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_did, device_id)
            .is_ok();
    if let Some(secret_body) = select_mls_account_secret_backup(list_payload) {
        // Fail closed against series rollback / withholding: the selected tail
        // must sit at the end of a complete, digest-linked chain back to genesis
        // before we trust it as the account secret to import.
        verify_series_chain(&secret_body, &all_mls_account_secret_backups(list_payload))?;
        let secret_bytes = decrypt_mls_account_secret_backup(passphrase, &secret_body)?;
        let secret = String::from_utf8(secret_bytes)
            .map_err(|err| anyhow!("account secret is not valid UTF-8: {err}"))?;
        let version = mls_account_secret_backup_version(&secret_body);
        crate::mls::runtime::replace_account_mls_secret_version(
            secure_store,
            actor_did,
            version,
            &secret,
        )
        .map_err(|err| anyhow!("replace account MLS secret: {err}"))?;
        report.account_secret_imported = true;
    } else if !has_local_secret {
        return Err(anyhow!(
            "no mls_account_secret backup on server; cannot recover MLS history"
        ));
    }

    // Step 2: restore every mls_history backup. A failure on one backup is
    // counted but does not abort the others.
    for body in select_mls_history_backups(list_payload) {
        match crate::mls::runtime::restore_mls_history_backup_with_device_snapshot(
            state_store,
            secure_store,
            actor_did,
            device_id,
            &body,
        ) {
            Ok(_) => report.restored += 1,
            Err(err) => {
                report.failed += 1;
                if report.first_error.is_none() {
                    report.first_error = Some(err.user_message());
                }
            }
        }
    }

    // Step 3 (X5.3): restore the author's encrypted local-plaintext sidecar.
    // The KEK source is the account secret imported in Step 1 — load it back
    // (now local) and decrypt with no second passphrase prompt, then merge the
    // sidecar map into the state store. Failure here is NON-FATAL: the author
    // simply won't see their own old content until the next encrypted write
    // rebuilds the sidecar; the rest of the restore stands.
    if let Some(sidecar_body) = select_mls_private_plaintext_backup(list_payload) {
        match restore_private_plaintext_sidecar(&sidecar_body, state_store, secure_store, actor_did)
        {
            Ok(()) => report.private_plaintext_restored = true,
            Err(err) => {
                if report.first_error.is_none() {
                    report.first_error = Some(format!("private plaintext restore: {err}"));
                }
            }
        }
    }

    Ok(report)
}

/// X5.3 — decrypt the `mls_private_plaintext` sidecar backup with the local
/// account secret and merge it into `state_store`. Factored out so the restore
/// step stays readable and so the `?` short-circuit doesn't abort the whole
/// restore.
fn restore_private_plaintext_sidecar(
    sidecar_body: &Value,
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
) -> Result<()> {
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_did)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no account secret available to decrypt sidecar"))?;
    let sidecar_json =
        decrypt_mls_private_plaintext_backup(stored.secret.as_bytes(), sidecar_body)?;
    let map: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    > = serde_json::from_slice(&sidecar_json)
        .map_err(|err| anyhow!("parse sidecar JSON: {err}"))?;
    state_store.merge_private_plaintext_map(map);
    Ok(())
}

/// Auto-restore MLS history for a fresh device using the recovery passphrase.
///
/// Flow:
///   1. Fetch the server's `mls_account_secret` backup when present, decrypt it with `passphrase`,
///      and replace the local account key with it. This also repairs stale local secrets left by
///      incomplete bootstraps.
///   2. List every `mls_history` backup and restore each one via
///      [`crate::mls::runtime::restore_mls_history_backup_with_device_snapshot`].
///
/// This is the function the recovery UI / a future "unlock MLS" prompt calls
/// once the user has supplied the passphrase. Returns per-backup counts.
pub async fn auto_restore_mls_history_with_passphrase(
    api: &crate::api::ContrixApi,
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    // List once and reuse for both the account-secret and history selection.
    let payload = fetch_mls_restore_payload(api).await?;
    restore_mls_history_with_passphrase_from_payload(
        &payload,
        state_store,
        secure_store,
        actor_did,
        device_id,
        passphrase,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsAccountSecretRotationUpload {
    pub rotation: crate::mls::runtime::AccountMlsSecretRotation,
    pub account_secret_backup_id: String,
    pub account_secret_series_seq: u64,
    pub history_backup_ids: Vec<String>,
}

/// Chain a successor backup envelope onto the previous series tail.
///
/// A genesis envelope (no predecessor) keeps its own freshly-generated
/// `series_id` / `series_seq=0` and carries no `supersedes`. A successor
/// inherits the predecessor's `series_id`, bumps `series_seq`, and binds the
/// chain with `supersedes` (the predecessor's `backup_id`) plus
/// `supersedes_digest` (the canonical SHA-256 of the predecessor envelope).
///
/// soland's `enforce_key_backup_series_chain` rejects any `series_seq > 0`
/// envelope that omits `supersedes` / `supersedes_digest` with a
/// `series_chain_broken` 409, so the second and later uploads in a series must
/// carry these fields. The caller MUST give the successor envelope a *fresh*
/// `backup_id` (not the predecessor's) so the predecessor stays persisted as a
/// distinct chain link and `series_predecessor_not_found` is not triggered.
fn apply_next_series(previous: Option<&Value>, body: &mut Value) -> u64 {
    let Some(prev) = previous else {
        return body.get("series_seq").and_then(Value::as_u64).unwrap_or(0);
    };
    let next_seq = prev.get("series_seq").and_then(Value::as_u64).unwrap_or(0) + 1;
    if let Some(series_id) = prev.get("series_id").and_then(Value::as_str) {
        body["series_id"] = Value::String(series_id.to_owned());
    }
    body["series_seq"] = Value::Number(serde_json::Number::from(next_seq));
    if let Some(prev_backup_id) = prev.get("backup_id").and_then(Value::as_str) {
        body["supersedes"] = Value::String(prev_backup_id.to_owned());
    }
    body["supersedes_digest"] = Value::String(series_supersedes_digest(prev));
    next_seq
}

/// `sha256:<hex>` over the canonical bytes of the predecessor backup envelope,
/// used to bind a series successor's `supersedes_digest`. Any
/// `auth_data.signature` is stripped first so the digest stays stable across
/// (re)signing (yougen bodies currently carry no `auth_data`, so this is a
/// no-op today, but keeps the digest definition spec-aligned).
fn series_supersedes_digest(previous: &Value) -> String {
    let mut canonical = previous.clone();
    if let Some(auth_data) = canonical
        .get_mut("auth_data")
        .and_then(Value::as_object_mut)
    {
        auth_data.remove("signature");
    }
    crate::canonical::canonical_sha256(&canonical)
        .unwrap_or_else(|_| format!("sha256:{}", "0".repeat(64)))
}

/// Generate a fresh protocol `backup_id` for a new envelope in a series.
fn fresh_backup_id() -> String {
    format!("cx:backup:{}", crate::operation::uuid_v7())
}

/// Verify the `supersedes` chain of a key-backup series back to genesis.
///
/// `tail` is the highest-`series_seq` body selected for the series; `all` is the
/// full set of candidate bodies (same backup class) returned by the server
/// list. The chain is valid only when every `series_seq` from `0..=tail` is
/// present exactly once, each successor's `supersedes` points at the immediate
/// predecessor's `backup_id`, and each `supersedes_digest` matches the canonical
/// digest of that predecessor envelope.
///
/// Returns `Err("series_chain_broken: ...")` on any gap, duplicate, mislinked
/// predecessor, or digest mismatch, so the restore path can fail closed against
/// a server that rolled the series back, forged a high `series_seq`, or withheld
/// an intermediate envelope (per key-management.md series-tail requirements).
fn verify_series_chain(tail: &Value, all: &[Value]) -> Result<()> {
    let series_id = tail
        .get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if series_id.is_empty() {
        return Err(anyhow!(
            "series_chain_broken: selected backup has no series_id"
        ));
    }
    let tail_seq = backup_series_seq(tail);
    let mut by_seq: std::collections::BTreeMap<u64, &Value> = std::collections::BTreeMap::new();
    for body in all {
        if body.get("series_id").and_then(Value::as_str) != Some(series_id) {
            continue;
        }
        let seq = backup_series_seq(body);
        if by_seq.insert(seq, body).is_some() {
            return Err(anyhow!(
                "series_chain_broken: duplicate series_seq {seq} in series {series_id}"
            ));
        }
    }
    for seq in 0..=tail_seq {
        let Some(body) = by_seq.get(&seq) else {
            return Err(anyhow!(
                "series_chain_broken: missing series_seq {seq} in series {series_id}"
            ));
        };
        if seq == 0 {
            continue;
        }
        let prev = by_seq
            .get(&(seq - 1))
            .expect("predecessor presence checked by the 0..=tail_seq loop");
        let prev_backup_id = prev
            .get("backup_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if body.get("supersedes").and_then(Value::as_str) != Some(prev_backup_id) {
            return Err(anyhow!(
                "series_chain_broken: series_seq {seq} `supersedes` does not point at its predecessor"
            ));
        }
        let expected_digest = series_supersedes_digest(prev);
        if body.get("supersedes_digest").and_then(Value::as_str) != Some(expected_digest.as_str()) {
            return Err(anyhow!(
                "series_chain_broken: series_seq {seq} `supersedes_digest` mismatch"
            ));
        }
    }
    Ok(())
}

/// Collect every `mls_account_secret` backup body from a `list_key_backups`
/// payload (used to verify the series chain before trusting a selected tail).
fn all_mls_account_secret_backups(list_payload: &Value) -> Vec<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| is_mls_account_secret_backup(body))
        .cloned()
        .collect()
}

fn passphrase_is_blank(passphrase: &[u8]) -> bool {
    passphrase.is_empty()
        || std::str::from_utf8(passphrase)
            .map(|text| text.trim().is_empty())
            .unwrap_or(false)
}

/// Device-revoke follow-up: rotate the account MLS snapshot secret, upload the
/// new account-secret backup, and upload freshly rewrapped MLS-history backups.
///
/// This deliberately does not mutate local state. Callers should commit
/// `upload.rotation` via
/// [`crate::mls::runtime::commit_account_mls_secret_rotation`] only after this
/// function returns `Ok`, so local snapshots and the local secret advance
/// together.
pub async fn upload_mls_account_secret_rotation_after_device_revoke(
    api: &crate::api::ContrixApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    passphrase: &[u8],
    snapshots: &std::collections::BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<MlsAccountSecretRotationUpload> {
    if passphrase_is_blank(passphrase) {
        return Err(anyhow!(
            "recovery passphrase is required to rotate the account MLS secret"
        ));
    }

    let list_payload = fetch_mls_restore_payload(api).await?;
    let previous_account_backup = select_mls_account_secret_backup(&list_payload);
    // Each successor in a series MUST carry a fresh backup_id so the predecessor
    // stays persisted as a distinct chain link (see `apply_next_series`).
    let account_backup_id = fresh_backup_id();

    let rotation = crate::mls::runtime::prepare_account_mls_secret_rotation(
        secure_store,
        actor_did,
        device_id,
        snapshots,
    )
    .map_err(|err| anyhow!(err.user_message()))?;

    let kek = derive_vault_kek(passphrase).map_err(|err| anyhow!("derive KEK: {err}"))?;
    let mut account_body = build_mls_account_secret_backup_body_with_kek_and_version(
        &account_backup_id,
        actor_did,
        device_id,
        &kek,
        &rotation.new_secret,
        rotation.new_version,
    )?;
    let account_secret_series_seq =
        apply_next_series(previous_account_backup.as_ref(), &mut account_body);
    api.put_key_backup(&account_backup_id, account_body)
        .await
        .map_err(|err| anyhow!("upload rotated account MLS secret backup: {err}"))?;

    let mut history_backup_ids = Vec::with_capacity(rotation.rewrapped_snapshots.len());
    for snapshot in rotation.rewrapped_snapshots.values() {
        let backup_id =
            crate::mls::runtime::upload_mls_snapshot_backup(api, snapshot, actor_did, device_id)
                .await
                .map_err(|err| {
                    anyhow!(
                        "upload rewrapped MLS history backup: {}",
                        err.user_message()
                    )
                })?;
        history_backup_ids.push(backup_id);
    }

    Ok(MlsAccountSecretRotationUpload {
        rotation,
        account_secret_backup_id: account_backup_id,
        account_secret_series_seq,
        history_backup_ids,
    })
}

/// Decide whether the app should prompt the user to set a recovery passphrase
/// and back up their account MLS secret.
///
/// This is the mirror of [`mls_restore_prompt_required`]: it fires when the
/// user HAS used encryption (a local account MLS secret exists) but the server
/// holds NO `mls_account_secret` backup yet, so switching browsers would lose
/// their history. Normal users never reach the explicit recovery-setup screen,
/// so without this nudge their account secret stays purely local.
///
/// Returns `false` when a server backup already exists (nothing to do), and
/// `false` when there is no local account secret (the user never used
/// encryption — don't nag).
pub fn mls_backup_prompt_required(
    list_payload: &Value,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
) -> bool {
    let _ = device_id;
    if select_mls_account_secret_backup(list_payload).is_some() {
        return false;
    }
    matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store, actor_did),
        Ok(Some(_))
    )
}

/// Wrap the local account MLS secret behind a freshly-derived recovery KEK and
/// upload it to soland's `secret_storage` endpoint.
///
/// This is the upload half of the backup-prompt flow (the inverse of
/// [`auto_restore_mls_history_with_passphrase`]). It re-uses any prior
/// account-secret backup's `backup_id`/series so the upload stays in the same
/// rotation series. Returns the `backup_id` it wrote.
pub async fn upload_mls_account_secret_backup_with_passphrase(
    api: &crate::api::ContrixApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<String> {
    if passphrase_is_blank(passphrase) {
        return Err(anyhow!(
            "recovery passphrase is required to back up the account MLS secret"
        ));
    }

    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_did)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no local account MLS secret to back up"))?;

    let list_payload = fetch_mls_restore_payload(api).await?;
    let previous_account_backup = select_mls_account_secret_backup(&list_payload);
    // Fresh backup_id per series link (see `apply_next_series`).
    let account_backup_id = fresh_backup_id();

    let kek = derive_vault_kek(passphrase).map_err(|err| anyhow!("derive KEK: {err}"))?;
    let mut account_body = build_mls_account_secret_backup_body_with_kek_and_version(
        &account_backup_id,
        actor_did,
        device_id,
        &kek,
        &stored.secret,
        stored.version,
    )?;
    apply_next_series(previous_account_backup.as_ref(), &mut account_body);
    api.put_key_backup(&account_backup_id, account_body)
        .await
        .map_err(|err| anyhow!("upload account MLS secret backup: {err}"))?;

    Ok(account_backup_id)
}

/// X5.3 — wrap the entire local-plaintext sidecar map behind a KEK derived from
/// the ACCOUNT SECRET and upload it to soland's `secret_storage` endpoint.
///
/// The KEK source is the account secret (already recoverable via the passphrase
/// through the X3 `mls_account_secret` backup), so the restore flow decrypts the
/// sidecar with no second passphrase prompt. Reuses any prior sidecar backup's
/// `backup_id`/series so the upload stays in the same rotation series
/// (`series_seq++` whenever the sidecar changes). Returns the `backup_id` it
/// wrote. Errors if no local account secret exists (the user hasn't used
/// encryption, so there is nothing to wrap the sidecar with).
pub async fn upload_mls_private_plaintext_backup(
    api: &crate::api::ContrixApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    sidecar_json: &[u8],
) -> Result<String> {
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_did)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no account secret; cannot back up private plaintext"))?;

    let kek =
        derive_vault_kek(stored.secret.as_bytes()).map_err(|err| anyhow!("derive KEK: {err}"))?;

    let list_payload = fetch_mls_restore_payload(api).await?;
    let previous_backup = select_mls_private_plaintext_backup(&list_payload);
    // Fresh backup_id per series link (see `apply_next_series`).
    let backup_id = fresh_backup_id();

    let mut body = build_mls_private_plaintext_backup_body_with_kek(
        &backup_id,
        actor_did,
        device_id,
        &kek,
        sidecar_json,
    )?;
    apply_next_series(previous_backup.as_ref(), &mut body);
    api.put_key_backup(&backup_id, body)
        .await
        .map_err(|err| anyhow!("upload private plaintext backup: {err}"))?;

    Ok(backup_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_backup::{KeyBackupClass, validate_key_backup_envelope};
    use crate::secure_key_store::MemorySecureKeyStore;

    const BACKUP_ID: &str = "cx:backup:01964137-0000-7000-8000-00000000beef";
    const ACTOR: &str = "did:web:alice.example";
    const DEVICE: &str = "cx:device:01964137-0000-7000-8000-000000000001";
    const PASSPHRASE: &[u8] = b"correct horse battery staple";
    const ACCOUNT_SECRET: &str = "qr6h9rJ8nU0H2pP5w3sLx1A4bC7dE9fG2hI5jK8lM0N";

    fn wrap() -> Value {
        let kek = derive_vault_kek(PASSPHRASE).unwrap();
        build_mls_account_secret_backup_body_with_kek(
            BACKUP_ID,
            ACTOR,
            DEVICE,
            &kek,
            ACCOUNT_SECRET,
        )
        .unwrap()
    }

    fn temp_state_store(name: &str) -> crate::local_state::LocalStateStore {
        let path = std::env::temp_dir().join(format!(
            "yougen-mls-account-recovery-{name}-{}.json",
            crate::operation::uuid_v7()
        ));
        crate::local_state::LocalStateStore::with_path(path)
    }

    fn history_envelope(
        space_id: &str,
        group_id: &str,
        epoch: u64,
        secret: &str,
    ) -> crate::mls::persistence::MlsSnapshotEnvelope {
        crate::mls::persistence::encrypt_state(
            space_id,
            group_id,
            epoch,
            b"opaque sdk state bytes",
            secret,
            b"deterministic-salt",
        )
    }

    fn history_body(envelope: &crate::mls::persistence::MlsSnapshotEnvelope) -> Value {
        envelope.to_key_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000feed",
            ACTOR,
            DEVICE,
        )
    }

    #[test]
    fn wrap_then_unwrap_round_trips_the_secret() {
        let body = wrap();
        let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
        assert_eq!(recovered, ACCOUNT_SECRET.as_bytes());
    }

    #[test]
    fn wrong_passphrase_fails_to_unwrap() {
        let body = wrap();
        let result = decrypt_mls_account_secret_backup(b"incorrect horse", &body);
        assert!(result.is_err());
    }

    #[test]
    fn put_body_has_expected_item_identifiers() {
        let body = wrap();
        assert!(is_mls_account_secret_backup(&body));
        assert_eq!(
            body["contents"][0]["item_type"].as_str(),
            Some(MLS_ACCOUNT_SECRET_ITEM_TYPE)
        );
        assert_eq!(
            body["contents"][0]["secret_id"].as_str(),
            Some(MLS_ACCOUNT_SECRET_SECRET_ID)
        );
        assert_eq!(body["backup_class"], "secret_storage");
        // item_type must be one both validators' allowlists accept.
        assert_eq!(MLS_ACCOUNT_SECRET_ITEM_TYPE, "mls_account_secret");
        assert_eq!(
            mls_account_secret_backup_version(&body),
            crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION
        );
    }

    #[test]
    fn put_body_contains_no_plaintext_secret() {
        let body = wrap();
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains(ACCOUNT_SECRET));
    }

    #[test]
    fn real_encrypt_build_validate_decrypt_round_trips_end_to_end() {
        // No hand-crafted fixtures: this exercises the REAL pipeline —
        // encrypt_vault (which emits base64url) → build the upload body → the
        // SAME key-backup validator the mls_history backup uses → decrypt back
        // to the plaintext secret. encrypt_vault now emits base64url natively,
        // so the validator's base64url charset check on ciphertext/nonce/salt
        // passes for every random ciphertext (no `+`/`/` ever appear).
        let body = wrap();

        // 1. The three wire fields are base64url (only `[A-Za-z0-9-_]`), never STANDARD-base64
        //    `+`/`/`.
        for (label, field) in [
            ("ciphertext", body["ciphertext"].as_str().unwrap()),
            ("salt", body["encryption"]["kdf"]["salt"].as_str().unwrap()),
            (
                "nonce",
                body["encryption"]["aead"]["nonce"].as_str().unwrap(),
            ),
        ] {
            assert!(!field.is_empty(), "{label} must not be empty");
            assert!(
                field
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "{label} must be base64url (no `+`/`/`/`=`), got: {field}"
            );
        }

        // 2. The body validates under the exact validator soland-mirroring clients run (the same
        //    one `mls_history` backups must pass).
        validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage)).expect(
            "mls_account_secret backup must validate as a secret_storage envelope (base64url-clean)",
        );

        // 3. The full decrypt path recovers the original secret bytes.
        let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
        assert_eq!(recovered, ACCOUNT_SECRET.as_bytes());
    }

    #[test]
    fn round_trips_even_when_random_bytes_would_need_url_safe_alphabet() {
        // Hammer the encode/decode boundary: across many random salts/nonces
        // and ciphertexts, the produced ciphertext WILL contain bytes that
        // STANDARD base64 renders as `+`/`/`. Every one of these must still
        // validate (base64url-clean) and decrypt back to the input.
        for i in 0..32u32 {
            let secret = format!("account-secret-payload-with-entropy-{i:08x}-padding++//");
            let kek = derive_vault_kek(PASSPHRASE).unwrap();
            let body = build_mls_account_secret_backup_body_with_kek(
                BACKUP_ID, ACTOR, DEVICE, &kek, &secret,
            )
            .unwrap();

            for field in [
                body["ciphertext"].as_str().unwrap(),
                body["encryption"]["kdf"]["salt"].as_str().unwrap(),
                body["encryption"]["aead"]["nonce"].as_str().unwrap(),
            ] {
                assert!(
                    field
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                    "iteration {i}: field is not base64url-clean: {field}"
                );
            }

            validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
                .unwrap_or_else(|err| panic!("iteration {i}: envelope must validate: {err}"));

            let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
            assert_eq!(recovered, secret.as_bytes(), "iteration {i}: round-trip");
        }
    }

    #[test]
    fn select_account_secret_finds_it_in_a_list_payload() {
        let account_secret_body = wrap();
        // A `list_key_backups`-shaped payload mixing a history backup, an
        // unrelated recovery vault, and the account-secret backup.
        let payload = serde_json::json!({
            "backups": [
                { "backup_id": "cx:backup:a", "backup_class": "mls_history" },
                { "backup_id": "cx:backup:b", "backup_class": "recovery",
                  "contents": [ { "secret_id": "yougen_recovery_vault_payload" } ] },
                account_secret_body.clone(),
            ]
        });
        let found = select_mls_account_secret_backup(&payload).expect("account secret present");
        assert!(is_mls_account_secret_backup(&found));
        // No-account-secret payload returns None.
        let none_payload = serde_json::json!({
            "backups": [ { "backup_id": "cx:backup:a", "backup_class": "mls_history" } ]
        });
        assert!(select_mls_account_secret_backup(&none_payload).is_none());
        // Absent/empty payloads are tolerated.
        assert!(select_mls_account_secret_backup(&serde_json::json!({})).is_none());
    }

    #[test]
    fn select_account_secret_prefers_highest_series_seq() {
        let mut older = wrap();
        older["backup_id"] = serde_json::json!("cx:backup:01964137-0000-7000-8000-00000000bee1");
        older["series_seq"] = serde_json::json!(1);
        let mut newer = wrap();
        newer["backup_id"] = serde_json::json!("cx:backup:01964137-0000-7000-8000-00000000bee2");
        newer["series_seq"] = serde_json::json!(2);
        let payload = serde_json::json!({
            "backups": [newer.clone(), older]
        });

        let found = select_mls_account_secret_backup(&payload).expect("account secret present");

        assert_eq!(found["backup_id"], newer["backup_id"]);
    }

    #[test]
    fn prompt_required_when_local_secret_exists_but_history_is_missing() {
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret(&store, ACTOR, "stale-local-secret").unwrap();
        let state = temp_state_store("prompt-missing-history");
        let envelope = history_envelope("cx:space:prompt", "group-a", 7, ACCOUNT_SECRET);
        let payload = serde_json::json!({
            "backups": [wrap(), history_body(&envelope)]
        });

        assert!(mls_restore_prompt_required(
            &payload, &state, &store, ACTOR, DEVICE
        ));
    }

    #[test]
    fn prompt_not_required_when_local_history_is_current_and_decryptable() {
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret(&store, ACTOR, ACCOUNT_SECRET).unwrap();
        let mut state = temp_state_store("prompt-current-history");
        let envelope = history_envelope("cx:space:prompt", "group-a", 7, ACCOUNT_SECRET);
        state.save_mls_snapshot(envelope.space_id.clone(), envelope.clone());
        let payload = serde_json::json!({
            "backups": [wrap(), history_body(&envelope)]
        });

        assert!(!mls_restore_prompt_required(
            &payload, &state, &store, ACTOR, DEVICE
        ));
    }

    #[test]
    fn verify_series_chain_accepts_single_genesis() {
        let genesis = wrap();
        assert_eq!(backup_series_seq(&genesis), 0);
        verify_series_chain(&genesis, std::slice::from_ref(&genesis))
            .expect("a lone genesis envelope is a valid one-link chain");
    }

    #[test]
    fn verify_series_chain_rejects_missing_intermediate() {
        // Genesis + a forged seq=2 tail with no seq=1 link present: a withholding
        // server signature that must be rejected.
        let mut genesis = wrap();
        genesis["series_id"] =
            serde_json::json!("cx:backup_series:01964137-0000-7000-8000-0000000000c1");
        genesis["series_seq"] = serde_json::json!(0);
        let mut forged_tail = genesis.clone();
        forged_tail["backup_id"] =
            serde_json::json!("cx:backup:01964137-0000-7000-8000-0000000000c2");
        forged_tail["series_seq"] = serde_json::json!(2);
        forged_tail["supersedes"] = serde_json::json!("cx:backup:does-not-exist");
        forged_tail["supersedes_digest"] = serde_json::json!("sha256:deadbeef");

        let err = verify_series_chain(&forged_tail, &[genesis, forged_tail.clone()])
            .expect_err("a chain missing series_seq 1 must be rejected");
        assert!(err.to_string().contains("series_chain_broken"));
    }

    #[test]
    fn verify_series_chain_accepts_well_formed_successor() {
        // Mirror what the upload path now produces: genesis then a successor
        // linked by apply_next_series.
        let mut genesis = wrap();
        genesis["backup_id"] = serde_json::json!("cx:backup:01964137-0000-7000-8000-0000000000d0");
        genesis["series_id"] =
            serde_json::json!("cx:backup_series:01964137-0000-7000-8000-0000000000d1");
        genesis["series_seq"] = serde_json::json!(0);

        let mut successor = wrap();
        successor["backup_id"] =
            serde_json::json!("cx:backup:01964137-0000-7000-8000-0000000000d2");
        apply_next_series(Some(&genesis), &mut successor);

        verify_series_chain(&successor, &[genesis, successor.clone()])
            .expect("an apply_next_series-linked successor must verify");
    }

    #[test]
    fn prompt_required_when_local_snapshot_uses_forked_random_secret() {
        // P0 regression: a new device's Welcome bootstrap minted a random
        // account secret and saved a self-consistent local snapshot under it,
        // while the server holds history encrypted under the REAL account
        // secret. The old detection only checked the (self-decryptable) local
        // snapshot and silently skipped the restore prompt, forking the chain.
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret(&store, ACTOR, "forked-random-secret")
            .unwrap();
        let mut state = temp_state_store("prompt-forked-secret");
        // Server backup is encrypted under the real account secret...
        let server_envelope = history_envelope("cx:space:prompt", "group-a", 7, ACCOUNT_SECRET);
        // ...but the local snapshot was saved under the forked random secret at
        // the same (or higher) epoch, so it self-decrypts and passes the old
        // epoch/group gates.
        let local_envelope =
            history_envelope("cx:space:prompt", "group-a", 7, "forked-random-secret");
        state.save_mls_snapshot(local_envelope.space_id.clone(), local_envelope);
        let payload = serde_json::json!({
            "backups": [wrap(), history_body(&server_envelope)]
        });

        assert!(
            mls_restore_prompt_required(&payload, &state, &store, ACTOR, DEVICE),
            "forked random local secret must still trigger the restore prompt"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn restore_replaces_stale_local_secret_before_history_replay() {
        use contrix_sdk::{ContrixMlsIdentity, DeviceId, Did};

        let device_a = "cx:device:01964137-0000-7000-8000-00000000000a";
        let space = "cx:space:01964137-0000-7000-8000-0000000000ab";
        let identity = ContrixMlsIdentity::new_basic(
            Did::new(ACTOR.to_owned()).unwrap(),
            DeviceId::new(device_a.to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(space.as_bytes()).unwrap();
        let record = group.export_state_record().unwrap();
        let envelope = crate::mls::persistence::encrypt_state(
            space,
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            ACCOUNT_SECRET,
            b"deterministic-salt",
        );
        let payload = serde_json::json!({
            "backups": [wrap(), history_body(&envelope)]
        });
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret_version(
            &store,
            ACTOR,
            crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION + 1,
            "stale-local-secret",
        )
        .unwrap();
        let mut state = temp_state_store("restore-stale-secret");

        let report = restore_mls_history_with_passphrase_from_payload(
            &payload, &mut state, &store, ACTOR, DEVICE, PASSPHRASE,
        )
        .unwrap();

        assert!(report.account_secret_imported);
        assert_eq!(report.restored, 1);
        assert_eq!(report.failed, 0);
        let loaded = crate::mls::runtime::load_account_mls_secret(&store, ACTOR)
            .unwrap()
            .expect("secret present");
        assert_eq!(
            loaded.version,
            crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION
        );
        assert_eq!(loaded.secret, ACCOUNT_SECRET);
        assert!(state.mls_snapshot_for(space).is_some());
    }

    #[test]
    fn backup_prompt_not_required_when_no_local_secret() {
        // User never used encryption: no local account secret, server has no
        // backup either. Don't nag.
        let store = MemorySecureKeyStore::new();
        let payload = serde_json::json!({ "backups": [] });
        assert!(!mls_backup_prompt_required(&payload, &store, ACTOR, DEVICE));
    }

    #[test]
    fn backup_prompt_required_when_local_secret_and_no_server_backup() {
        // User has used encryption (local secret present) but never backed it
        // up to the server -> prompt them to set a recovery passphrase.
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret(&store, ACTOR, ACCOUNT_SECRET).unwrap();
        let payload = serde_json::json!({
            "backups": [ { "backup_id": "cx:backup:a", "backup_class": "mls_history" } ]
        });
        assert!(mls_backup_prompt_required(&payload, &store, ACTOR, DEVICE));
    }

    #[test]
    fn backup_prompt_not_required_when_server_backup_present() {
        // Server already holds the account-secret backup: nothing to upload.
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret(&store, ACTOR, ACCOUNT_SECRET).unwrap();
        let payload = serde_json::json!({ "backups": [wrap()] });
        assert!(!mls_backup_prompt_required(&payload, &store, ACTOR, DEVICE));
    }

    #[test]
    fn select_history_backups_filters_by_class() {
        let payload = serde_json::json!({
            "backups": [
                { "backup_id": "cx:backup:a", "backup_class": "mls_history" },
                { "backup_id": "cx:backup:b", "backup_class": "secret_storage" },
                { "backup_id": "cx:backup:c", "backup_class": "mls_history" },
                { "backup_id": "cx:backup:d" },
            ]
        });
        let histories = select_mls_history_backups(&payload);
        assert_eq!(histories.len(), 2);
        assert!(
            histories
                .iter()
                .all(|b| { b.get("backup_class").and_then(Value::as_str) == Some("mls_history") })
        );
        assert!(select_mls_history_backups(&serde_json::json!({})).is_empty());
    }

    // ---- X5.3: encrypted private-plaintext sidecar backup ----

    fn sample_sidecar() -> std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    > {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("body".to_owned(), "\"author body\"".to_owned());
        fields.insert("synthesis".to_owned(), "\"author synthesis\"".to_owned());
        let mut flows = std::collections::BTreeMap::new();
        flows.insert("cx:flow:alpha".to_owned(), fields);
        let mut spaces = std::collections::BTreeMap::new();
        spaces.insert("cx:space:demo".to_owned(), flows);
        spaces
    }

    fn wrap_sidecar() -> (Vec<u8>, Value) {
        let sidecar = sample_sidecar();
        let json = serde_json::to_vec(&sidecar).unwrap();
        let kek = derive_vault_kek(ACCOUNT_SECRET.as_bytes()).unwrap();
        let body =
            build_mls_private_plaintext_backup_body_with_kek(BACKUP_ID, ACTOR, DEVICE, &kek, &json)
                .unwrap();
        (json, body)
    }

    #[test]
    fn sidecar_backup_round_trips_under_account_secret() {
        let (json, body) = wrap_sidecar();
        let recovered =
            decrypt_mls_private_plaintext_backup(ACCOUNT_SECRET.as_bytes(), &body).unwrap();
        assert_eq!(recovered, json);
        // The decoded map equals the original sidecar.
        let map: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
        > = serde_json::from_slice(&recovered).unwrap();
        assert_eq!(map, sample_sidecar());
    }

    #[test]
    fn sidecar_backup_wrong_account_secret_fails() {
        let (_json, body) = wrap_sidecar();
        let result = decrypt_mls_private_plaintext_backup(b"a-different-account-secret", &body);
        assert!(result.is_err());
    }

    #[test]
    fn sidecar_backup_has_expected_identifiers_and_no_plaintext_leak() {
        let (_json, body) = wrap_sidecar();
        assert!(is_mls_private_plaintext_backup(&body));
        assert_eq!(
            body["contents"][0]["item_type"].as_str(),
            Some(MLS_PRIVATE_PLAINTEXT_ITEM_TYPE)
        );
        assert_eq!(
            body["contents"][0]["secret_id"].as_str(),
            Some(MLS_PRIVATE_PLAINTEXT_SECRET_ID)
        );
        assert_eq!(body["backup_class"], "secret_storage");
        assert_eq!(MLS_PRIVATE_PLAINTEXT_ITEM_TYPE, "mls_private_plaintext");
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("author body"));
        assert!(!serialized.contains("author synthesis"));
    }

    #[test]
    fn sidecar_backup_validates_as_secret_storage_envelope() {
        let (_json, body) = wrap_sidecar();
        validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage)).expect(
            "mls_private_plaintext backup must validate as a secret_storage envelope (base64url-clean)",
        );
    }

    #[test]
    fn select_sidecar_finds_and_prefers_highest_series_seq() {
        let (_json, base_body) = wrap_sidecar();
        let mut older = base_body.clone();
        older["backup_id"] = serde_json::json!("cx:backup:01964137-0000-7000-8000-0000000000a1");
        older["series_seq"] = serde_json::json!(1);
        let mut newer = base_body.clone();
        newer["backup_id"] = serde_json::json!("cx:backup:01964137-0000-7000-8000-0000000000a2");
        newer["series_seq"] = serde_json::json!(2);
        let payload = serde_json::json!({
            "backups": [
                { "backup_id": "cx:backup:h", "backup_class": "mls_history" },
                older,
                newer.clone(),
            ]
        });
        let found = select_mls_private_plaintext_backup(&payload).expect("sidecar present");
        assert!(is_mls_private_plaintext_backup(&found));
        assert_eq!(found["backup_id"], newer["backup_id"]);
        // Absent payload -> None.
        assert!(
            select_mls_private_plaintext_backup(&serde_json::json!({ "backups": [] })).is_none()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn restore_brings_back_the_sidecar_into_the_store() {
        use contrix_sdk::{ContrixMlsIdentity, DeviceId, Did};

        // Build a real, decryptable account-secret + history backup so Step 1/2
        // succeed and the account secret is local for the sidecar KEK source.
        let device_a = "cx:device:01964137-0000-7000-8000-00000000000a";
        let space = "cx:space:01964137-0000-7000-8000-0000000000ab";
        let identity = ContrixMlsIdentity::new_basic(
            Did::new(ACTOR.to_owned()).unwrap(),
            DeviceId::new(device_a.to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(space.as_bytes()).unwrap();
        let record = group.export_state_record().unwrap();
        let history = crate::mls::persistence::encrypt_state(
            space,
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            ACCOUNT_SECRET,
            b"deterministic-salt",
        );

        // The sidecar is encrypted under the ACCOUNT SECRET (not the passphrase).
        let (_json, sidecar_body) = wrap_sidecar();

        let payload = serde_json::json!({
            "backups": [wrap(), history_body(&history), sidecar_body]
        });
        let store = MemorySecureKeyStore::new();
        let mut state = temp_state_store("restore-sidecar");

        let report = restore_mls_history_with_passphrase_from_payload(
            &payload, &mut state, &store, ACTOR, DEVICE, PASSPHRASE,
        )
        .unwrap();

        assert!(report.account_secret_imported);
        assert_eq!(report.restored, 1);
        assert!(
            report.private_plaintext_restored,
            "sidecar must be restored"
        );
        assert_eq!(
            state.private_plaintext_for("cx:space:demo", "cx:flow:alpha", "body"),
            Some("\"author body\"".to_owned())
        );
        assert_eq!(
            state.private_plaintext_for("cx:space:demo", "cx:flow:alpha", "synthesis"),
            Some("\"author synthesis\"".to_owned())
        );
    }
}
