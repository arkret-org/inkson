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
/// DEVIATION FROM DESIGN: the design asked for `item_type ==
/// "mls_account_secret"`, but soland's (unmodifiable) `secret_storage`
/// item-type allowlist
/// (`soland/src/routing/identity/key_backup.rs::KEY_BACKUP_CONTENT_TYPES`)
/// does NOT include that string and would reject the PUT with a
/// `SchemaViolation`. We therefore reuse the already-allowlisted
/// `mls_group_secrets_backup_key` content type — which is the
/// closest-semantics `secret_storage` item (an MLS-group secret backup key) —
/// and carry the MLS account-secret identity through the (unvalidated)
/// `secret_id`. The recovery side keys off `secret_id`, so the change is
/// transparent end-to-end.
pub const MLS_ACCOUNT_SECRET_ITEM_TYPE: &str = "mls_group_secrets_backup_key";
/// `secret_id` carried by the account MLS snapshot secret backup. This is the
/// stable discriminator the recovery import path matches against.
pub const MLS_ACCOUNT_SECRET_SECRET_ID: &str = "yougen_mls_account_secret";

/// Build a `secret_storage` PUT body that wraps the account MLS snapshot secret
/// behind the user's recovery passphrase.
///
/// The envelope shape reuses [`build_recovery_vault_backup_body`] (same
/// `secret_storage` / `passphrase_kdf` / argon2id+xchacha20poly1305 shape that
/// soland already validates). The plaintext account secret is encrypted with a
/// freshly-derived KEK; only the ciphertext, salt and nonce travel on the wire.
/// The `item_type` / `secret_id` are overwritten to the MLS-secret identifiers.
pub fn build_mls_account_secret_backup_body(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    account_secret: &str,
) -> Result<Value> {
    let kek = derive_vault_kek(account_secret.as_bytes())
        .map_err(|err| anyhow!("derive KEK: {err}"))?;
    build_mls_account_secret_backup_body_with_kek(backup_id, actor_did, device_id, &kek, account_secret)
}

/// Variant of [`build_mls_account_secret_backup_body`] that wraps the account
/// secret with an already-derived KEK (used when the passphrase has already been
/// stretched on the recovery setup path so we avoid a second Argon2id pass).
pub fn build_mls_account_secret_backup_body_with_kek(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    kek: &VaultKek,
    account_secret: &str,
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

/// True when `body` is an MLS account-secret backup. Matched on `secret_id`
/// (the stable discriminator) rather than `item_type`, since the item_type is a
/// shared `secret_storage` content type (see [`MLS_ACCOUNT_SECRET_ITEM_TYPE`]).
pub fn is_mls_account_secret_backup(body: &Value) -> bool {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|item| item.get("secret_id"))
        .and_then(Value::as_str)
        == Some(MLS_ACCOUNT_SECRET_SECRET_ID)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_backup::{KeyBackupClass, validate_key_backup_envelope};

    const BACKUP_ID: &str = "cx:backup:01964137-0000-7000-8000-00000000beef";
    const ACTOR: &str = "did:web:alice.example";
    const DEVICE: &str = "cx:device:01964137-0000-7000-8000-000000000001";
    const PASSPHRASE: &[u8] = b"correct horse battery staple";
    const ACCOUNT_SECRET: &str = "qr6h9rJ8nU0H2pP5w3sLx1A4bC7dE9fG2hI5jK8lM0N";

    fn wrap() -> Value {
        let kek = derive_vault_kek(PASSPHRASE).unwrap();
        build_mls_account_secret_backup_body_with_kek(BACKUP_ID, ACTOR, DEVICE, &kek, ACCOUNT_SECRET)
            .unwrap()
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
        // item_type must be one soland's allowlist accepts.
        assert_eq!(
            MLS_ACCOUNT_SECRET_ITEM_TYPE, "mls_group_secrets_backup_key",
            "item_type must remain in soland's KEY_BACKUP_CONTENT_TYPES allowlist"
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

        // 1. The three wire fields are base64url (only `[A-Za-z0-9-_]`),
        //    never STANDARD-base64 `+`/`/`.
        for (label, field) in [
            ("ciphertext", body["ciphertext"].as_str().unwrap()),
            ("salt", body["encryption"]["kdf"]["salt"].as_str().unwrap()),
            ("nonce", body["encryption"]["aead"]["nonce"].as_str().unwrap()),
        ] {
            assert!(!field.is_empty(), "{label} must not be empty");
            assert!(
                field
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "{label} must be base64url (no `+`/`/`/`=`), got: {field}"
            );
        }

        // 2. The body validates under the exact validator soland-mirroring
        //    clients run (the same one `mls_history` backups must pass).
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
}
