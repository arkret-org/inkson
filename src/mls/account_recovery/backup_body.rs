//! Build, decrypt, and classify the on-wire account-recovery backup envelopes.

use anyhow::{Result, anyhow};
use arkret_models_crypto::{KeyBackup, SecretStorageContentIndex, SecretStorageItemKind};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::Value;

use super::selection::mls_account_secret_backup_version;
use crate::key_backup::{
    BackupKind, build_passphrase_kdf_backup_body, open_passphrase_kdf_backup_body,
};
use crate::recovery_crypto::VaultKek;

/// `item_kind` carried by the account MLS snapshot secret backup.
///
/// Both soland's validator
/// (`soland/src/routing/identity/key_backup.rs::KEY_BACKUP_CONTENT_TYPES`)
/// and the inkson client validator
/// (`key_backup::item_kind_allowed_for_class`) allowlist this dedicated
/// content type under the `secret_storage` class, so it is the primary
/// discriminator for the recovery import path. `secret_id` is still carried
/// for human-readable disambiguation.
pub const MLS_ACCOUNT_SECRET_ITEM_KIND: SecretStorageItemKind =
    SecretStorageItemKind::MlsAccountSecret;
/// `secret_id` carried by the account MLS snapshot secret backup. This is the
/// stable discriminator the recovery import path matches against.
pub const MLS_ACCOUNT_SECRET_SECRET_ID: &str = "inkson_mls_account_secret";

/// X5.3 — `item_kind` carried by the encrypted local-plaintext sidecar backup.
///
/// The sidecar (`LocalStateStore::mls_private_plaintext`, the author's own
/// plaintext for their encrypted private strand fields) MUST cross devices: a new
/// browser can never decrypt the author's own MLS ciphertext (OpenMLS
/// `validation.rs` rejects own-leaf messages before any key lookup), so without
/// this backup the author loses sight of everything they wrote after switching
/// browsers. The sidecar JSON is encrypted under a KEK derived from the ACCOUNT
/// SECRET (not the passphrase directly) so the restore strand — which imports the
/// account secret first — can decrypt it with NO second passphrase prompt. Both
/// soland's validator and the inkson client validator allowlist this content
/// type under the `secret_storage` class.
pub const MLS_PRIVATE_PLAINTEXT_ITEM_KIND: SecretStorageItemKind =
    SecretStorageItemKind::MlsPrivatePlaintext;
/// `secret_id` carried by the encrypted local-plaintext sidecar backup.
pub const MLS_PRIVATE_PLAINTEXT_SECRET_ID: &str = "inkson_mls_private_plaintext";

/// Build a `secret_storage` PUT body that wraps the account MLS snapshot secret
/// behind an already-derived recovery KEK.
///
/// The envelope shape comes from [`crate::key_backup::build_passphrase_kdf_backup_body`]
/// (the `secret_storage` / `passphrase_kdf` / argon2id+xchacha20poly1305 shape
/// that soland already validates). The plaintext account secret is encrypted
/// with the supplied KEK; only the ciphertext, salt and nonce travel on the
/// wire. The `item_kind` / `secret_id` are the MLS-secret identifiers.
///
/// NOTE: the KEK MUST be derived from the user's Recovery Key (the same
/// source `decrypt_mls_account_secret_backup` stretches on restore), never from
/// the account secret itself — wrapping the account secret under a KEK derived
/// from that same account secret would make the backup self-referential and
/// undecryptable by the recovery strand. (A former `build_mls_account_secret_backup_body`
/// helper that derived the KEK from the account secret was removed for this
/// reason; it was dead code and a latent footgun.)
pub fn build_mls_account_secret_backup_body_with_kek(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    kek: &VaultKek,
    account_secret: &str,
) -> Result<KeyBackup> {
    build_mls_account_secret_backup_body_with_kek_and_version(
        backup_id,
        actor_id,
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
    actor_id: &str,
    device_id: &str,
    kek: &VaultKek,
    account_secret: &str,
    account_secret_version: u32,
) -> Result<KeyBackup> {
    // Spec §7.5: item identifiers are set before sealing so the SDK-derived
    // AAD binds the real `mls_account_secret` item. Post-seal relabeling would
    // desynchronize the derived AAD from the ciphertext.
    build_passphrase_kdf_backup_body(
        backup_id,
        actor_id,
        device_id,
        kek,
        account_secret.as_bytes(),
        BackupKind::SecretStorage,
        "recovery_vault",
        &SecretStorageContentIndex {
            item_kind: MLS_ACCOUNT_SECRET_ITEM_KIND,
            realm_id: None,
            from_epoch: None,
            to_epoch: None,
            secret_id: Some(MLS_ACCOUNT_SECRET_SECRET_ID.to_owned()),
            secret_version: Some(account_secret_version),
            extra: Default::default(),
        },
    )
}

/// Build the next passphrase-recoverable account-secret envelope after the
/// predecessor series and current PCR frontier have been resolved.
#[allow(clippy::too_many_arguments)]
pub fn build_mls_account_secret_backup_successor_body_with_kek_and_version(
    backup_id: &str,
    predecessor: &KeyBackup,
    kek: &VaultKek,
    account_secret: &str,
    account_secret_version: u32,
    frontier_digest: &arkret_sdk::Hash,
    device_generation_ref: u64,
) -> Result<KeyBackup> {
    crate::key_backup::build_passphrase_kdf_backup_successor_body(
        backup_id,
        predecessor,
        kek,
        account_secret.as_bytes(),
        &SecretStorageContentIndex {
            item_kind: MLS_ACCOUNT_SECRET_ITEM_KIND,
            realm_id: None,
            from_epoch: None,
            to_epoch: None,
            secret_id: Some(MLS_ACCOUNT_SECRET_SECRET_ID.to_owned()),
            secret_version: Some(account_secret_version),
            extra: Default::default(),
        },
        frontier_digest,
        device_generation_ref,
    )
}

/// Decrypt a downloaded `mls_account_secret` backup body with the user's
/// recovery passphrase and return the account snapshot secret bytes.
///
/// Delegates to [`crate::key_backup::open_passphrase_kdf_backup_body`]: verifies
/// `key_commitment`, recomputes the spec §7.5 deterministic nonce, binds the
/// AEAD AAD, then decrypts.
pub fn decrypt_mls_account_secret_backup(passphrase: &[u8], body: &Value) -> Result<Vec<u8>> {
    opened_single_secret(passphrase, body)
}

/// True when `body` is an MLS account-secret backup (ANY recipient method).
/// Matched on the dedicated `mls_account_secret` item type.
pub fn is_mls_account_secret_backup(body: &Value) -> bool {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|item| item.get("item_kind"))
        .and_then(Value::as_str)
        == Some(MLS_ACCOUNT_SECRET_ITEM_KIND.as_str())
}

/// The `encryption.recipient_method` of a backup envelope.
fn backup_recipient_method(body: &Value) -> Option<&str> {
    body.pointer("/encryption/recipient_method")
        .and_then(Value::as_str)
}

/// True when `body` is the **passphrase-recoverable** account-secret backup
/// (`recipient_method=passphrase_kdf`). The account secret now has TWO backups —
/// this passphrase one and an HPKE `recovery_public_key` one — sharing the same
/// `item_kind`, so the passphrase restore path MUST only pick this variant
/// (else it would try to passphrase-decrypt an HPKE envelope).
pub fn is_passphrase_account_secret_backup(body: &Value) -> bool {
    is_mls_account_secret_backup(body) && backup_recipient_method(body) == Some("passphrase_kdf")
}

/// True when `body` is the HPKE `recovery_public_key` account-secret backup —
/// the passphrase-free fresh-device recovery path (open with the recovery
/// private key, no passphrase prompt).
pub fn is_recovery_public_key_account_secret_backup(body: &Value) -> bool {
    is_mls_account_secret_backup(body)
        && backup_recipient_method(body) == Some("recovery_public_key")
}

/// X5.3 — build a `secret_storage` PUT body that wraps the entire encrypted
/// local-plaintext sidecar map behind a KEK derived from the ACCOUNT SECRET.
///
/// Mirrors [`build_mls_account_secret_backup_body_with_kek_and_version`] but
/// with the sidecar identifiers and the sidecar JSON bytes as the encrypted
/// payload. `sidecar_json` is the serialized `mls_private_plaintext` map
/// (`serde_json::to_vec` of `realm -> strand -> field -> plaintext`); only its
/// ciphertext, salt and nonce travel on the wire. The caller derives `kek` from
/// the account secret (`derive_vault_kek(account_secret.as_bytes())`), so the
/// restore path — which imports the account secret first — can decrypt with no
/// second passphrase prompt. base64url-clean; domain separation re-attached so
/// the AAD's `item_kinds` matches the rewritten contents.
pub fn build_mls_private_plaintext_backup_body_with_kek(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    kek: &VaultKek,
    sidecar_json: &[u8],
) -> Result<KeyBackup> {
    build_passphrase_kdf_backup_body(
        backup_id,
        actor_id,
        device_id,
        kek,
        sidecar_json,
        BackupKind::SecretStorage,
        "recovery_vault",
        &SecretStorageContentIndex {
            item_kind: MLS_PRIVATE_PLAINTEXT_ITEM_KIND,
            realm_id: None,
            from_epoch: None,
            to_epoch: None,
            secret_id: Some(MLS_PRIVATE_PLAINTEXT_SECRET_ID.to_owned()),
            secret_version: None,
            extra: Default::default(),
        },
    )
}

/// Build the next private-plaintext sidecar envelope with its series and PCR
/// frontier identity fixed before the SDK seals the plaintext keybag.
pub fn build_mls_private_plaintext_backup_successor_body_with_kek(
    backup_id: &str,
    predecessor: &KeyBackup,
    kek: &VaultKek,
    sidecar_json: &[u8],
    frontier_digest: &arkret_sdk::Hash,
    device_generation_ref: u64,
) -> Result<KeyBackup> {
    crate::key_backup::build_passphrase_kdf_backup_successor_body(
        backup_id,
        predecessor,
        kek,
        sidecar_json,
        &SecretStorageContentIndex {
            item_kind: MLS_PRIVATE_PLAINTEXT_ITEM_KIND,
            realm_id: None,
            from_epoch: None,
            to_epoch: None,
            secret_id: Some(MLS_PRIVATE_PLAINTEXT_SECRET_ID.to_owned()),
            secret_version: None,
            extra: Default::default(),
        },
        frontier_digest,
        device_generation_ref,
    )
}

/// X5.3 — decrypt a downloaded `mls_private_plaintext` backup body and return
/// the serialized sidecar JSON bytes.
///
/// The KEK source is the ACCOUNT SECRET bytes (NOT the recovery passphrase):
/// the restore strand imports the account secret first, then feeds its bytes here
/// so the sidecar is recovered with no second passphrase prompt.
/// `open_passphrase_kdf_backup_body` derives the Argon2id root from these bytes +
/// the stored salt, exactly as the account-secret path does.
pub fn decrypt_mls_private_plaintext_backup(
    account_secret: &[u8],
    body: &Value,
) -> Result<Vec<u8>> {
    opened_single_secret(account_secret, body)
}

fn opened_single_secret(unlock_key: &[u8], body: &Value) -> Result<Vec<u8>> {
    let plaintext = open_passphrase_kdf_backup_body(unlock_key, body)?;
    let arkret_models_crypto::KeyBackupKeybag::SecretStorage { items } = &plaintext.keybag else {
        return Err(anyhow!(
            "single-secret key backup must decrypt to a secret_storage keybag"
        ));
    };
    let [item] = items.as_slice() else {
        return Err(anyhow!(
            "single-secret key backup must decrypt to exactly one plaintext item"
        ));
    };
    B64.decode(item.secret_b64u.as_bytes())
        .map_err(|error| anyhow!("key backup plaintext secret is not base64url: {error}"))
}

/// True when `body` is an MLS private-plaintext sidecar backup. Matched on the
/// dedicated `mls_private_plaintext` item type.
pub fn is_mls_private_plaintext_backup(body: &Value) -> bool {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|item| item.get("item_kind"))
        .and_then(Value::as_str)
        == Some(MLS_PRIVATE_PLAINTEXT_ITEM_KIND.as_str())
}

/// Build the HPKE `recovery_public_key` account-secret backup: the account
/// secret HPKE-sealed to the actor's recovery public key. ANY device (holding
/// only the public key) can build/upload this; a fresh device opens it with the
/// recovery PRIVATE key — no passphrase prompt (key-management.md §7.5.2).
#[allow(clippy::too_many_arguments)]
pub fn build_mls_account_secret_recovery_public_key_backup(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    account_secret: &str,
    account_secret_version: u32,
    // The actor's currently-accepted recovery policy `(policy_id,
    // policy_version)`. It is written into the envelope's
    // `recovery_policy_ref`; the fresh-device restore path cross-checks it
    // against the live accepted policy before importing the secret, so a
    // compromised server can't replay an old-policy / non-frontier account-secret
    // backup sealed to the same recovery public key.
    recovery_policy_ref: (&str, u64),
) -> Result<KeyBackup> {
    build_mls_account_secret_recovery_public_key_backup_in_series(
        backup_id,
        actor_id,
        device_id,
        recovery_public_key,
        recovery_key_ref,
        account_secret,
        account_secret_version,
        recovery_policy_ref,
        None,
        None,
    )
}

/// Build an HPKE account-secret backup that extends `previous_series_tail`.
///
/// Series metadata is part of the HPKE `info`, so the successor link must be
/// attached before sealing. Mutating `series_id`, `series_seq`, or
/// `supersedes_id` afterwards makes the final envelope undecryptable.
#[allow(clippy::too_many_arguments)]
pub fn build_mls_account_secret_recovery_public_key_backup_in_series(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    account_secret: &str,
    account_secret_version: u32,
    recovery_policy_ref: (&str, u64),
    previous_series_tail: Option<&Value>,
    frontier_ref: Option<arkret_sdk::KeyBackupFrontierRef>,
) -> Result<KeyBackup> {
    crate::key_backup::build_recovery_public_key_backup_body_in_series(
        backup_id,
        actor_id,
        device_id,
        recovery_public_key,
        recovery_key_ref,
        crate::key_backup::BackupKind::SecretStorage,
        "recovery_vault",
        &SecretStorageContentIndex {
            item_kind: MLS_ACCOUNT_SECRET_ITEM_KIND,
            realm_id: None,
            from_epoch: None,
            to_epoch: None,
            secret_id: Some(MLS_ACCOUNT_SECRET_SECRET_ID.to_owned()),
            secret_version: Some(account_secret_version),
            extra: Default::default(),
        },
        account_secret.as_bytes(),
        Some(recovery_policy_ref),
        None,
        previous_series_tail,
        frontier_ref,
    )
}

/// SEC-05: verify a `recovery_public_key` account-secret backup envelope's
/// `recovery_policy_ref` against the actor's currently-accepted policy before it
/// is opened. The envelope's ref must be present and match so a compromised
/// server cannot replay a backup minted under an old policy or frontier.
pub fn ensure_recovery_public_key_backup_policy_matches(
    body: &Value,
    expected_recovery_policy_ref: (&str, u64),
) -> Result<()> {
    let (expected_id, expected_version) = expected_recovery_policy_ref;
    let policy_ref = body.get("recovery_policy_ref").ok_or_else(|| {
        anyhow!(
            "recovery_public_key account-secret backup carries no recovery_policy_ref; \
             refusing to import against accepted policy {expected_id} v{expected_version}"
        )
    })?;
    let actual_id = policy_ref
        .get("policy_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let actual_version = policy_ref
        .get("policy_version")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if actual_id != expected_id || actual_version != expected_version {
        return Err(anyhow!(
            "recovery_public_key account-secret backup recovery_policy_ref ({actual_id} v{actual_version}) \
             does not match accepted policy ({expected_id} v{expected_version})"
        ));
    }
    Ok(())
}

/// Open the HPKE `recovery_public_key` account-secret backup with the recovery
/// private key, returning `(secret, version)`.
///
/// The envelope's `recovery_policy_ref` must match the accepted policy before
/// the HPKE open.
pub fn open_mls_account_secret_recovery_public_key_backup(
    recovery_private_key: &[u8],
    body: &Value,
    expected_recovery_policy_ref: (&str, u64),
) -> Result<(String, u32)> {
    ensure_recovery_public_key_backup_policy_matches(body, expected_recovery_policy_ref)?;
    let plaintext =
        crate::key_backup::open_recovery_public_key_backup_body(recovery_private_key, body)?;
    let arkret_models_crypto::KeyBackupKeybag::SecretStorage { items } = &plaintext.keybag else {
        return Err(anyhow!(
            "account-secret backup must decrypt to a secret_storage keybag"
        ));
    };
    let [item] = items.as_slice() else {
        return Err(anyhow!(
            "account-secret backup must decrypt to exactly one plaintext item"
        ));
    };
    let secret = String::from_utf8(
        B64.decode(item.secret_b64u.as_bytes())
            .map_err(|error| anyhow!("account secret is not base64url: {error}"))?,
    )
    .map_err(|err| anyhow!("account secret is not valid UTF-8: {err}"))?;
    Ok((secret, mls_account_secret_backup_version(body)))
}
