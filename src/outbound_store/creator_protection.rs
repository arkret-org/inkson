//! Device-secret protection of creator recovery material. No key is minted here.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(not(target_arch = "wasm32"))]
use chacha20poly1305::aead::{Aead, Payload};
#[cfg(not(target_arch = "wasm32"))]
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::secure_key_store::SecureKeyStore;

fn device_key(
    store: &dyn SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    purpose: &str,
) -> anyhow::Result<[u8; 32]> {
    let material = crate::secure_key_store::load_signing_seed_for(store, authority, device)?
        .ok_or_else(|| anyhow::anyhow!("creator recovery requires the original device secret"))?;
    let context = crate::canonical::canonical_json_bytes(&(
        "inkson.mls.creator_bootstrap.v1",
        authority,
        device,
        purpose,
    ))?;
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &material.seed)
        .expand(&context, &mut key)
        .map_err(|_| anyhow::anyhow!("derive creator device protection key"))?;
    Ok(key)
}

pub(crate) fn checkpoint_secret(
    store: &dyn SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> anyhow::Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(device_key(store, authority, device, "epoch_zero")?))
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedCreatorRecord {
    creator_device_id: arkret_sdk::DeviceId,
    nonce: String,
    ciphertext: String,
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn protect_records(
    raw: &str,
    authority: &arkret_sdk::AccountId,
    store: &dyn SecureKeyStore,
) -> anyhow::Result<String> {
    let mut value: serde_json::Value = serde_json::from_str(raw)?;
    if let Some(records) = value
        .get_mut("creator_bootstrap_records")
        .and_then(serde_json::Value::as_array_mut)
    {
        for record in records {
            let typed: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord = serde_json::from_value(record.clone())?;
            let device = typed.intent().creator_device_id();
            anyhow::ensure!(
                typed.intent().owner_actor_id().as_account_id() == Some(authority),
                "creator record belongs to another account vault"
            );
            let key = device_key(store, authority, device, "record")?;
            let aad = crate::canonical::canonical_json_bytes(&(authority, device))?;
            let mut nonce = [0u8; 12];
            getrandom::fill(&mut nonce)?;
            let plaintext = crate::canonical::canonical_json_bytes(&typed)?;
            let ciphertext = ChaCha20Poly1305::new((&key).into())
                .encrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("encrypt creator record"))?;
            *record = serde_json::to_value(ProtectedCreatorRecord {
                creator_device_id: device.clone(),
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            })?;
        }
    }
    Ok(serde_json::to_string(&value)?)
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn open_records(
    raw: &str,
    authority: &arkret_sdk::AccountId,
    store: &dyn SecureKeyStore,
) -> anyhow::Result<String> {
    let mut value: serde_json::Value = serde_json::from_str(raw)?;
    if let Some(records) = value
        .get_mut("creator_bootstrap_records")
        .and_then(serde_json::Value::as_array_mut)
    {
        for record in records {
            let protected: ProtectedCreatorRecord = serde_json::from_value(record.clone())?;
            let key = device_key(store, authority, &protected.creator_device_id, "record")?;
            let aad =
                crate::canonical::canonical_json_bytes(&(authority, &protected.creator_device_id))?;
            let nonce: [u8; 12] = URL_SAFE_NO_PAD
                .decode(protected.nonce)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid creator record nonce"))?;
            let ciphertext = URL_SAFE_NO_PAD.decode(protected.ciphertext)?;
            let plaintext = ChaCha20Poly1305::new((&key).into())
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("creator record device secret mismatch or tamper"))?;
            let original: serde_json::Value = serde_json::from_slice(&plaintext)?;
            let intent: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent = serde_json::from_value(original.get("intent").cloned().ok_or_else(|| anyhow::anyhow!("protected creator lost its authenticated coordinates"))?)?;
            intent.validate()?;
            anyhow::ensure!(
                intent.owner_actor_id().as_account_id() == Some(authority)
                    && intent.creator_device_id() == &protected.creator_device_id,
                "protected creator record coordinate mismatch"
            );
            *record = original;
        }
    }
    Ok(serde_json::to_string(&value)?)
}
