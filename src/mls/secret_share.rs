//! D2D root-secret direct share (`ak.secret.*` to-device).
//!
//! Implements the device-to-device branch of the passwordless recovery path
//! described in `arkret-spec/.../crypto-media/device-lifecycle.md` §10.7: a
//! newly authorized device that has completed SAS verification (§10.3) with an
//! existing authorized device can pull the account-scoped MLS secret
//! (`inkson_mls_account_secret`, see [`crate::mls::account_recovery`] /
//! [`crate::mls::runtime`]) directly from that sibling device over HPKE,
//! without the user re-entering the 24-word Recovery Key.
//!
//! Two to-device kinds carry the strand:
//!   * `ak.secret.request` — new device → existing device, advertising the HPKE public key to seal
//!     to. Carries no secret material.
//!   * `ak.secret.send` — existing device → new device, the secret HPKE-sealed (RFC 9180, via
//!     [`crate::hpke_backup`]) to that public key.
//!
//! The sealed plaintext (`{account_secret, secret_version, request_id,
//! secret_id}`) is never visible to soland's device-message queue. The HPKE AAD
//! binds the envelope identity + expiry fields both sides can reconstruct
//! verbatim (§10.7); freshness is bound by the one-time `request_id`.
//!
//! The opened secret feeds [`crate::mls::runtime::replace_account_mls_secret_version`]
//! — the same landing point the 24-word path uses — so the rest of the MLS
//! history restore (server-held `mls_history` backups) is shared with the
//! recovery strand.

use anyhow::{Result, anyhow, bail};
use arkret_wire::{HPKE_SUITE_X25519_CHACHA20POLY1305_V1, SECRET_SEND_KIND};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::hpke_backup;
use crate::mls::runtime::{self, StoredAccountMlsSecret};
use crate::secure_key_store::SecureKeyStore;

/// Wire `kind` for the secret request.
/// Wire `kind` for the sealed secret response.
/// HPKE scheme label on `ak.secret.send.content.scheme`. Matches the canonical
/// device HPKE label in `device-lifecycle.md` §4. The crypto suite is the
/// RFC 9180 base mode of [`crate::hpke_backup`] (DHKEM-X25519 / HKDF-SHA256 /
/// ChaCha20Poly1305).
/// `secret_id` for the account MLS snapshot secret — the only secret class the
/// D2D direct-share path ships in v1. Equal to
/// [`crate::mls::account_recovery::MLS_ACCOUNT_SECRET_SECRET_ID`].
pub const SECRET_SHARE_SECRET_ID: &str = "inkson_mls_account_secret";

/// Per-strand state held by the requesting (new) device between sending
/// `ak.secret.request` and opening the matching `ak.secret.send`. The private
/// key never leaves the device.
pub struct SecretShareRequester {
    /// One-time random correlation id; bound into the sealed plaintext.
    pub request_id: String,
    /// X25519 HPKE private key the sibling device's response is sealed to.
    recipient_private_key: Vec<u8>,
    /// base64url public half advertised in `ak.secret.request`.
    pub recipient_public_b64: String,
}

impl std::fmt::Debug for SecretShareRequester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the private key.
        f.debug_struct("SecretShareRequester")
            .field("request_id", &self.request_id)
            .field("recipient_public_b64", &self.recipient_public_b64)
            .field("recipient_private_key", &"<redacted>")
            .finish()
    }
}

/// Plaintext recovered by the requesting device after a successful open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedSecret {
    pub account_secret: String,
    pub secret_version: u32,
}

/// Mint a fresh request: a one-time id + an ephemeral X25519 HPKE keypair the
/// sibling device seals its response to.
pub fn new_secret_request() -> Result<SecretShareRequester> {
    let mut id_bytes = [0u8; 16];
    getrandom::fill(&mut id_bytes).map_err(|err| anyhow!("secret-share request id rng: {err}"))?;
    let (sk, pk) = hpke_backup::generate_recovery_keypair()?;
    Ok(SecretShareRequester {
        request_id: URL_SAFE_NO_PAD.encode(id_bytes),
        recipient_private_key: sk,
        recipient_public_b64: URL_SAFE_NO_PAD.encode(pk),
    })
}

/// Build `ak.secret.request.content` for the requesting device.
pub fn build_request_content(
    req: &SecretShareRequester,
    requesting_device_id: &str,
) -> Result<arkret_crypto::secret_share::SecretShareRequestContent> {
    let content = arkret_crypto::secret_share::SecretShareRequestContent {
        request_id: req.request_id.clone(),
        secret_id: SECRET_SHARE_SECRET_ID.to_owned(),
        from_device: arkret_sdk::DeviceId::new(requesting_device_id.to_owned())
            .map_err(|err| anyhow!("invalid secret-share requesting device id: {err}"))?,
        recipient_hpke_public_key: req.recipient_public_b64.clone(),
    };
    Ok(content)
}

/// Parse and validate an inbound `ak.secret.request.content`.
pub fn parse_request_content(
    content: &Value,
) -> Result<arkret_crypto::secret_share::SecretShareRequestContent> {
    let content: arkret_crypto::secret_share::SecretShareRequestContent =
        serde_json::from_value(content.clone())
            .map_err(|err| anyhow!("decode ak.secret.request.content: {err}"))?;
    content
        .validate()
        .map_err(|err| anyhow!("invalid ak.secret.request.content: {err}"))?;
    if content.secret_id != SECRET_SHARE_SECRET_ID {
        bail!(
            "ak.secret.request.secret_id {:?} is not supported",
            content.secret_id
        );
    }
    Ok(content)
}

/// Build `ak.secret.send.content` on the responding (existing) device: seal the
/// account secret to the requester's HPKE public key.
///
/// `account_did` is the shared principal DID of both devices (same-account
/// D2D). `self_device_id` is the responding device (the envelope's
/// `sender_device_id`). `expires_at` is the RFC3339 value used for the
/// `DeviceMessageTarget.expires_at`; it is part of the HPKE AAD and so MUST be
/// the exact string later put on the wire.
pub fn build_send_content(
    request: &arkret_crypto::secret_share::SecretShareRequestContent,
    account_secret: &StoredAccountMlsSecret,
    account_did: &str,
    self_device_id: &str,
    expires_at: &str,
) -> Result<arkret_crypto::secret_share::SecretShareSendContent> {
    let recipient_pk = URL_SAFE_NO_PAD
        .decode(request.recipient_hpke_public_key.as_bytes())
        .map_err(|err| anyhow!("decode requester hpke public key: {err}"))?;
    let plaintext = secret_plaintext(
        &account_secret.secret,
        account_secret.version,
        &request.request_id,
    )?;
    let aad = send_aad(
        account_did,
        self_device_id,
        account_did,
        request.from_device.as_str(),
        expires_at,
    )?;
    let sealed = hpke_backup::hpke_seal(
        &recipient_pk,
        arkret_wire::SECRET_SHARE_HPKE_INFO,
        &aad,
        &plaintext,
    )?;
    let content = arkret_crypto::secret_share::SecretShareSendContent {
        request_id: request.request_id.clone(),
        secret_id: SECRET_SHARE_SECRET_ID.to_owned(),
        from_device: arkret_sdk::DeviceId::new(self_device_id.to_owned())
            .map_err(|err| anyhow!("invalid secret-share sending device id: {err}"))?,
        scheme: HPKE_SUITE_X25519_CHACHA20POLY1305_V1.to_owned(),
        enc: URL_SAFE_NO_PAD.encode(sealed.enc),
        ciphertext: URL_SAFE_NO_PAD.encode(sealed.ciphertext),
    };
    Ok(content)
}

/// Open an inbound `ak.secret.send.content` on the requesting (new) device.
///
/// Rejects unsolicited sends (no matching pending `request_id`), wrong scheme,
/// AAD/identity tampering (HPKE open fails), and inner/outer field mismatch.
/// `sender_device_id` is the responding device from the received envelope;
/// `our_device_id` is this device; `expires_at` is the received envelope
/// `expires_at`. All three feed the AAD that MUST match the sender's.
pub fn open_send_content(
    requester: &SecretShareRequester,
    send_content: &Value,
    account_did: &str,
    sender_device_id: &str,
    our_device_id: &str,
    expires_at: &str,
) -> Result<OpenedSecret> {
    let send_content: arkret_crypto::secret_share::SecretShareSendContent =
        serde_json::from_value(send_content.clone())
            .map_err(|err| anyhow!("decode ak.secret.send.content: {err}"))?;
    let outer_request_id = send_content.request_id;
    if outer_request_id != requester.request_id {
        bail!("ak.secret.send.request_id does not match a pending request (unsolicited)");
    }
    let secret_id = send_content.secret_id;
    if secret_id != SECRET_SHARE_SECRET_ID {
        bail!("ak.secret.send.secret_id {secret_id:?} is not supported");
    }
    if send_content.from_device.as_str() != sender_device_id {
        bail!("ak.secret.send.from_device does not match envelope sender_device_id");
    }
    let scheme = send_content.scheme;
    if scheme != HPKE_SUITE_X25519_CHACHA20POLY1305_V1 {
        bail!("ak.secret.send.scheme {scheme:?} is not {HPKE_SUITE_X25519_CHACHA20POLY1305_V1}");
    }
    let enc = URL_SAFE_NO_PAD
        .decode(send_content.enc.as_bytes())
        .map_err(|err| anyhow!("decode ak.secret.send.enc: {err}"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(send_content.ciphertext.as_bytes())
        .map_err(|err| anyhow!("decode ak.secret.send.ciphertext: {err}"))?;

    let aad = send_aad(
        account_did,
        sender_device_id,
        account_did,
        our_device_id,
        expires_at,
    )?;
    let plaintext = hpke_backup::hpke_open(
        &requester.recipient_private_key,
        &enc,
        arkret_wire::SECRET_SHARE_HPKE_INFO,
        &aad,
        &ciphertext,
    )?;

    let parsed: Value = serde_json::from_slice(&plaintext)
        .map_err(|err| anyhow!("parse secret-share plaintext: {err}"))?;
    let inner_request_id = string_field(&parsed, "request_id")?;
    if inner_request_id != requester.request_id {
        bail!("secret-share plaintext request_id does not match the pending request");
    }
    let inner_secret_id = string_field(&parsed, "secret_id")?;
    if inner_secret_id != SECRET_SHARE_SECRET_ID {
        bail!("secret-share plaintext secret_id {inner_secret_id:?} is not supported");
    }
    let account_secret = string_field(&parsed, "account_secret")?;
    let secret_version = parsed
        .get("secret_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("secret-share plaintext missing secret_version"))?
        as u32;
    Ok(OpenedSecret {
        account_secret,
        secret_version,
    })
}

/// Land an opened secret into the account-scoped secure key store, replacing any
/// stale local version — the shared landing point with the 24-word path.
pub fn land_opened_secret(
    store: &dyn SecureKeyStore,
    actor_id: &str,
    opened: &OpenedSecret,
) -> Result<()> {
    runtime::replace_account_mls_secret_version(
        store,
        actor_id,
        opened.secret_version,
        &opened.account_secret,
    )
    .map_err(|err| anyhow!("replace account mls secret from D2D share: {err}"))
}

/// Send `ak.secret.request` from the requesting (new) device to a sibling
/// (existing) device. TTL 30m (well under the §7 24h cap).
pub async fn send_request(
    api: &crate::transport::TransportClient,
    requester: &SecretShareRequester,
    account_did: &str,
    target_existing_device_id: &str,
    requesting_device_id: &str,
) -> Result<()> {
    let content = build_request_content(requester, requesting_device_id)?;
    crate::transport::keys::send_device_message::<arkret_sdk::device_message_spec::SecretRequest>(
        &api.sdk_http_client()?,
        &format!("ak.secret.request:{}", requester.request_id),
        account_did,
        target_existing_device_id,
        &crate::clock::timestamp_in(30),
        content,
    )
    .await
    .map_err(|err| anyhow!("send ak.secret.request: {err}"))?;
    Ok(())
}

/// Respond to an inbound `ak.secret.request` from the responding (existing)
/// device: seal the account secret and ship `ak.secret.send`. The `expires_at`
/// is computed once here and used for BOTH the HPKE AAD and the wire envelope,
/// so the two can never drift. TTL 30m.
///
/// Callers MUST gate this behind explicit user authorization and confirm
/// `request.from_device` is a non-revoked device of `account_did` bound to the
/// completed SAS transcript (device-lifecycle.md §10.7 anti-abuse) before
/// invoking it.
pub async fn respond_to_request(
    api: &crate::transport::TransportClient,
    request: &arkret_crypto::secret_share::SecretShareRequestContent,
    account_secret: &StoredAccountMlsSecret,
    account_did: &str,
    self_device_id: &str,
) -> Result<()> {
    let expires_at = crate::clock::timestamp_in(30);
    let content = build_send_content(
        request,
        account_secret,
        account_did,
        self_device_id,
        &expires_at,
    )?;
    crate::transport::keys::send_device_message::<arkret_sdk::device_message_spec::SecretSend>(
        &api.sdk_http_client()?,
        &format!("ak.secret.send:{}", request.request_id),
        account_did,
        request.from_device.as_str(),
        &expires_at,
        content,
    )
    .await
    .map_err(|err| anyhow!("send ak.secret.send: {err}"))?;
    Ok(())
}

/// Try to open a single received `DeviceMessageEnvelope` as a `ak.secret.send`
/// response. Returns `Ok(None)` for any other kind so a poll loop can pass the
/// whole inbox through. The envelope `sender_device_id` and `expires_at` feed
/// the AAD, so they are read from the received envelope rather than guessed.
pub fn try_open_envelope(
    requester: &SecretShareRequester,
    envelope: &Value,
    account_did: &str,
    our_device_id: &str,
) -> Result<Option<OpenedSecret>> {
    if envelope.get("kind").and_then(Value::as_str) != Some(SECRET_SEND_KIND) {
        return Ok(None);
    }
    let sender_device_id = string_field(envelope, "sender_device_id")?;
    let expires_at = string_field(envelope, "expires_at")?;
    let content = envelope
        .get("content")
        .ok_or_else(|| anyhow!("ak.secret.send envelope missing content"))?;
    let opened = open_send_content(
        requester,
        content,
        account_did,
        &sender_device_id,
        our_device_id,
        &expires_at,
    )?;
    Ok(Some(opened))
}

/// Canonical HPKE AAD for `ak.secret.send` (device-lifecycle.md §10.7): the
/// RFC 8785 JCS bytes of the six envelope binding fields both sides
/// reconstruct. `expires_at` is the already-validated canonical Arkret
/// timestamp string; non-canonical spellings are rejected before AAD creation.
fn send_aad(
    sender_principal_id: &str,
    sender_device_id: &str,
    recipient_principal_id: &str,
    recipient_device_id: &str,
    expires_at: &str,
) -> Result<Vec<u8>> {
    arkret_sdk::canonical::validate_timestamp_canonical(expires_at)
        .map_err(|err| anyhow!("invalid secret-share expires_at {expires_at:?}: {err}"))?;
    let aad = json!({
        "kind": SECRET_SEND_KIND,
        "sender_principal_id": sender_principal_id,
        "sender_device_id": sender_device_id,
        "recipient_principal_id": recipient_principal_id,
        "recipient_device_id": recipient_device_id,
        "expires_at": expires_at,
    });
    arkret_sdk::canonical::canonical_json_bytes(&aad)
        .map_err(|err| anyhow!("canonicalize secret-share AAD: {err}"))
}

fn secret_plaintext(secret: &str, secret_version: u32, request_id: &str) -> Result<Vec<u8>> {
    let plaintext = json!({
        "account_secret": secret,
        "secret_version": secret_version,
        "request_id": request_id,
        "secret_id": SECRET_SHARE_SECRET_ID,
    });
    arkret_sdk::canonical::canonical_json_bytes(&plaintext)
        .map_err(|err| anyhow!("canonicalize secret-share plaintext: {err}"))
}

/// YOU-05-008: required-field wrapper over the shared
/// `crate::realm_tree::string_field` helper (trims and rejects empty
/// values), erroring instead of returning `None`.
fn string_field(value: &Value, field: &str) -> Result<String> {
    crate::realm_tree::string_field(value, &[field])
        .ok_or_else(|| anyhow!("missing or empty field {field:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;

    const ACCOUNT_DID: &str = "did:web:alice.example";
    const OLD_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000a";
    const NEW_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000b";
    const EXPIRES: &str = "2026-06-10T00:30:00.000Z";

    fn stored_secret() -> StoredAccountMlsSecret {
        StoredAccountMlsSecret {
            version: 1,
            secret: "account-secret-bytes-base64url".to_owned(),
        }
    }

    fn drive_happy_path() -> (SecretShareRequester, Value) {
        let requester = new_secret_request().unwrap();
        let request_content = build_request_content(&requester, NEW_DEVICE).unwrap();
        let parsed =
            parse_request_content(&serde_json::to_value(request_content).unwrap()).unwrap();
        assert_eq!(parsed.from_device.as_str(), NEW_DEVICE);
        let send = build_send_content(&parsed, &stored_secret(), ACCOUNT_DID, OLD_DEVICE, EXPIRES)
            .unwrap();
        (requester, serde_json::to_value(send).unwrap())
    }

    #[test]
    fn round_trip_opens_and_lands() {
        let (requester, send) = drive_happy_path();
        let opened = open_send_content(
            &requester,
            &send,
            ACCOUNT_DID,
            OLD_DEVICE,
            NEW_DEVICE,
            EXPIRES,
        )
        .unwrap();
        assert_eq!(
            opened,
            OpenedSecret {
                account_secret: stored_secret().secret,
                secret_version: 1
            }
        );

        let store = MemorySecureKeyStore::default();
        land_opened_secret(&store, ACCOUNT_DID, &opened).unwrap();
        let loaded = runtime::load_account_mls_secret(&store, ACCOUNT_DID)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.secret, stored_secret().secret);
    }

    #[test]
    fn rejects_unsolicited_request_id() {
        let (_requester, send) = drive_happy_path();
        let other = new_secret_request().unwrap();
        let err = open_send_content(&other, &send, ACCOUNT_DID, OLD_DEVICE, NEW_DEVICE, EXPIRES)
            .unwrap_err();
        assert!(format!("{err}").contains("unsolicited"));
    }

    #[test]
    fn rejects_tampered_sender_device_aad() {
        let (requester, send) = drive_happy_path();
        // A relay that swaps the sender device (verify-A-send-from-B) is caught
        // by the explicit sender-device binding check before HPKE open.
        let err = open_send_content(
            &requester,
            &send,
            ACCOUNT_DID,
            "ak:device:01904100-0000-7000-8000-00000000000c",
            NEW_DEVICE,
            EXPIRES,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("from_device does not match"));
    }

    #[test]
    fn rejects_wrong_recipient_keypair() {
        let (_requester, send) = drive_happy_path();
        // Sealed to the original requester's public key; a different device's
        // private key cannot open it.
        let attacker = new_secret_request().unwrap();
        let err = open_send_content(
            &attacker,
            &send,
            ACCOUNT_DID,
            OLD_DEVICE,
            NEW_DEVICE,
            EXPIRES,
        )
        .unwrap_err();
        // Fails the pending-id check before crypto (defence in depth); flip the
        // id to exercise the crypto path too.
        assert!(format!("{err}").contains("unsolicited"));

        let mut spoofed = attacker;
        spoofed.request_id = send
            .get("request_id")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        let err = open_send_content(
            &spoofed,
            &send,
            ACCOUNT_DID,
            OLD_DEVICE,
            NEW_DEVICE,
            EXPIRES,
        )
        .unwrap_err();
        // RFC 9180 HPKE (hpke_backup::hpke_open) surfaces the AEAD open failure as
        // "hpke open: <backend error>"; a wrong recipient key still fails closed.
        assert!(format!("{err}").contains("hpke open"));
    }

    #[test]
    fn aad_rejects_noncanonical_expires_at_before_hpke_open() {
        let (requester, send) = drive_happy_path();
        let error = open_send_content(
            &requester,
            &send,
            ACCOUNT_DID,
            OLD_DEVICE,
            NEW_DEVICE,
            "2026-06-10T00:30:00+00:00",
        )
        .unwrap_err();
        assert!(format!("{error}").contains("invalid secret-share expires_at"));
    }

    #[test]
    fn try_open_envelope_filters_kind_and_opens_send() {
        let (requester, send) = drive_happy_path();
        // A non-secret-share envelope is ignored.
        let other = json!({"kind": "ak.key.verification.done", "content": {}});
        assert_eq!(
            try_open_envelope(&requester, &other, ACCOUNT_DID, NEW_DEVICE).unwrap(),
            None
        );

        // A materialized ak.secret.send envelope (as soland would hand it back).
        let envelope = json!({
            "kind": SECRET_SEND_KIND,
            "sender_principal_id": ACCOUNT_DID,
            "sender_device_id": OLD_DEVICE,
            "recipient_principal_id": ACCOUNT_DID,
            "recipient_device_id": NEW_DEVICE,
            "sent_at": "2026-06-10T00:00:00.000Z",
            "expires_at": EXPIRES,
            "content": send,
        });
        let opened = try_open_envelope(&requester, &envelope, ACCOUNT_DID, NEW_DEVICE).unwrap();
        assert_eq!(opened.unwrap().account_secret, stored_secret().secret);
    }

    #[test]
    fn parse_request_rejects_foreign_secret_id() {
        let content = json!({
            "request_id": "r1",
            "secret_id": "some_other_secret",
            "from_device": NEW_DEVICE,
            "recipient_hpke_public_key": "cHVi..",
        });
        assert!(parse_request_content(&content).is_err());
    }
}
