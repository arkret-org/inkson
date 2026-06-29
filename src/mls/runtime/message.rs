//! Welcome application, application-payload encrypt / decrypt, and the SEC-08
//! minimal-metadata AAD policy enforcement.

use super::{
    MlsRuntimeError, delete_mls_key_package_identity_state, load_device_snapshot_secret,
    load_mls_key_package_identity_state, load_or_create_device_snapshot_secret,
    should_force_epoch_advance,
};
use crate::secure_key_store::SecureKeyStore;

/// Outcome of [`apply_welcome_messages_with_device_snapshot`].
///
/// Lets callers distinguish "no welcomes present" (`applied == 0 && failed ==
/// 0`) from "welcomes present but some/all failed" (`failed > 0`). A failure of
/// one welcome never aborts the others; `first_error` carries the first failure
/// reason for diagnostics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WelcomeApplyOutcome {
    pub applied: usize,
    pub failed: usize,
    /// YOU-02-005: welcomes skipped because a snapshot at an equal-or-higher
    /// epoch for the same group already exists (a replayed / stale Welcome that
    /// would otherwise roll the local MLS snapshot back to the join epoch).
    pub skipped_stale: usize,
    pub first_error: Option<String>,
}

impl WelcomeApplyOutcome {
    fn record_failure(&mut self, reason: String) {
        self.failed += 1;
        if self.first_error.is_none() {
            self.first_error = Some(reason);
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct WelcomeMessageEntry {
    content: serde_json::Value,
    key_package_id: Option<String>,
}

/// Canonical exporter-aead `aad_bytes` for `(realm_id, epoch)`, bound into the
/// `mls-exporter-aead-v1` content AEAD AAD on both the provider encrypt and the
/// receiver tier-3 decrypt paths (`encryption-and-audit.md` history sharing,
/// constraint ①: the epoch MUST be encoded so a key from epoch N can only open
/// content authored at epoch N). MUST be reconstructed byte-identically on both
/// ends — the SDK binds it verbatim into the AEAD AAD.
pub fn history_content_aad_bytes(realm_id: &str, epoch: u64) -> Vec<u8> {
    let aad = serde_json::json!({
        "purpose": "ck.realm_key.history_content.v1",
        "realm_id": realm_id.trim(),
        "epoch": epoch,
    });
    cokret_sdk::canonical::canonical_json_bytes(&aad)
        .unwrap_or_else(|_| format!("{}|{epoch}", realm_id.trim()).into_bytes())
}

pub fn decrypt_application_payload(
    state_store: &crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload: &cokret_sdk::EncryptedPayload,
) -> Option<Vec<u8>> {
    let digest = payload.payload_digest.as_str();
    if let Some(plaintext) = state_store.mls_decrypted_plaintext_for(realm_id, digest) {
        return Some(plaintext);
    }
    // Serialize the whole decrypt→write-back sequence per store so two views
    // can't advance the same group from the same base snapshot concurrently.
    let _serial = state_store.mls_decrypt_serial_guard();
    // Double-check under the guard: a racing call may have already decrypted
    // and persisted this exact payload.
    if let Some(plaintext) = state_store.mls_decrypted_plaintext_for(realm_id, digest) {
        return Some(plaintext);
    }
    // A local snapshot lets us instantiate a `CokretMlsGroup` and try the live
    // receive ratchet first. But the exporter-aead history-decrypt path does NOT
    // need a group at all — the content key derives purely from the granted
    // `history_secret` — so a never-Welcomed joiner (no snapshot) can still read
    // granted history via the group-free standalone path below. When no snapshot
    // is present we skip straight to tier-3 history decrypt.
    let Some(snapshot) = state_store.mls_snapshot_for(realm_id) else {
        return try_history_decrypt_standalone(state_store, realm_id, payload);
    };
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id).ok()?;
    // COR-04: read/decrypt path — floor 0 is intentional. The live receive ratchet
    // and the tier-3 history fallback legitimately read PRE-join / older epochs, so
    // an epoch-floor reject here would break decryption of granted history. No
    // ratchet advance / persist happens on this path.
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    let plaintext = match group.decrypt_payload(payload) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            // Tier-3 history decrypt: the live receive ratchet cannot open this
            // (pre-join epoch, or another device's content this group can't
            // ratchet to). Fall back to any granted `history_secret` for the
            // payload's epoch and decrypt it as `mls-exporter-aead-v1` content.
            // This is group-free, so it works whether or not the snapshot could
            // ratchet to the payload's epoch.
            return try_history_decrypt_standalone(state_store, realm_id, payload);
        }
    };
    // §5.6 MUST: persist the advanced receive chain. A failure to export /
    // serialize the post-decrypt state is NOT a soft failure we may swallow
    // silently — without the write-back the consumed message key would make
    // this very plaintext unrecoverable after restart — so fall back to
    // returning the plaintext only after latching a loud error.
    let advanced = export_receive_chain_envelope(&group, realm_id, &secret, &snapshot);
    match advanced {
        Ok(envelope) => {
            state_store.advance_mls_receive_chain(realm_id, envelope, digest, &plaintext);
        }
        Err(err) => {
            tracing::error!(
                %realm_id,
                error = %err.user_message(),
                "MLS receive-chain write-back failed after successful decrypt \
                 (spec §5.6 violation risk: message may be unreadable after restart)",
            );
        }
    }
    Some(plaintext)
}

/// Tier-3 history decrypt: try every granted `history_secret` for this Realm
/// against `payload`, decrypting the ciphertext as `mls-exporter-aead-v1`
/// content (`encryption-and-audit.md` history sharing). The provider that
/// authored the content bound `history_content_aad_bytes(realm_id, epoch)` into
/// the AEAD AAD, so the receiver reconstructs the same value here. Returns the
/// first secret that opens the payload, else `None` (a device that was not
/// granted the epoch's key, or a non-exporter-aead payload). Does NOT touch
/// the receive ratchet.
///
/// Group-free: uses the SDK's
/// [`cokret_sdk::mls::decrypt_content_exporter_aead_standalone`] so a device
/// that holds the granted `history_secret` but has **no** local MLS snapshot
/// for the Realm (e.g. a member granted history before processing its own
/// Welcome) can still read pre-join content.
fn try_history_decrypt_standalone(
    state_store: &crate::local_state::LocalStateStore,
    realm_id: &str,
    payload: &cokret_sdk::EncryptedPayload,
) -> Option<Vec<u8>> {
    let nonce_and_ct = cokret_sdk::base64url_decode(payload.ciphertext.as_bytes()).ok()?;
    // The payload's own epoch is the only key that can open it; prefer the exact
    // match, but fall back to scanning all granted secrets so a payload whose
    // epoch field drifted from the keyed epoch still resolves.
    let exact = state_store.history_secret_for(realm_id, payload.epoch);
    let scan = state_store.history_secrets_for(realm_id);
    let candidates = exact
        .into_iter()
        .map(|secret| (payload.epoch, secret))
        .chain(
            scan.into_iter()
                .filter(|(epoch, _)| *epoch != payload.epoch),
        );
    for (epoch, secret) in candidates {
        let aad_bytes = history_content_aad_bytes(realm_id, epoch);
        if let Ok(plaintext) = cokret_sdk::mls::decrypt_content_exporter_aead_standalone(
            &secret,
            realm_id,
            &nonce_and_ct,
            &aad_bytes,
        ) {
            return Some(plaintext);
        }
    }
    None
}

/// Provider-side: derive + retain the **current** epoch `history_secret` for a
/// Realm and persist it locally, so this device can later seal it into a
/// `ck.realm_key.share` for a late joiner (`encryption-and-audit.md` history
/// sharing). MUST be called while the group is at the epoch whose key is being
/// retained (OpenMLS only exports the current epoch). Returns
/// `(epoch, history_secret)` on success.
///
/// Persisting into the provider's own `history_secrets` lets a past epoch's key
/// survive an app restart (OpenMLS could not re-derive it once the group has
/// advanced past that epoch).
pub fn derive_and_retain_realm_history_secret(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Option<(u64, Vec<u8>)> {
    let snapshot = state_store.mls_snapshot_for(realm_id)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id).ok()?;
    // COR-04: read-only export of the CURRENT epoch's history secret — floor 0 is
    // intentional (no ratchet advance / persist; OpenMLS only exports the epoch the
    // snapshot already holds, so a Seal-view floor would add no safety here).
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    let epoch = snapshot.epoch;
    let history_secret = group.derive_and_retain_history_secret(realm_id).ok()?;
    if history_secret.is_empty() {
        return None;
    }
    state_store.save_history_secret(realm_id.to_owned(), epoch, history_secret.clone());
    Some((epoch, history_secret))
}

/// Filter a to-device inbox / device-messages batch down to the
/// `ck.realm_key.share` envelopes addressed at this Realm. The discriminator is
/// the envelope `kind`; the Realm binding is the share payload's
/// `key_scope.effective_scope.realm_id` (set by
/// [`crate::mls::admission::build_realm_key_share_event`]).
pub fn collect_realm_key_share_messages_for_realm(
    messages: &[serde_json::Value],
    realm_id: &str,
) -> Vec<serde_json::Value> {
    let realm_id = realm_id.trim();
    messages
        .iter()
        .filter(|message| {
            message
                .get("kind")
                .or_else(|| message.get("type"))
                .and_then(|t| t.as_str())
                == Some(cokret_sdk::events::kinds::REALM_KEY_SHARE)
        })
        .filter(|message| {
            // Accept shares whose scope names this realm, OR carry no scope hint
            // (a directed to-device share already addressed to this device).
            let scope_realm = message
                .get("content")
                .and_then(|content| content.get("key_scope"))
                .and_then(|scope| scope.get("effective_scope"))
                .and_then(|scope| scope.get("realm_id"))
                .and_then(serde_json::Value::as_str);
            scope_realm.is_none_or(|value| value.trim() == realm_id)
        })
        .cloned()
        .collect()
}

/// Open one inbound `ck.realm_key.share` with this device's HPKE private key and
/// install every recovered `(epoch, history_secret)` into local state, so the
/// tier-3 decrypt path can read pre-join content. Returns the number of secrets
/// installed (0 when the share is not for this device / does not open / carries
/// no ciphertext). The share `ciphertext` is the
/// `base64url(eph_pub || ct)` blob produced by
/// [`crate::mls::secret_share::seal_history_secret_to_device_pubkey`].
pub fn ingest_realm_key_share(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    share_envelope: &serde_json::Value,
) -> usize {
    let content = share_envelope.get("content").unwrap_or(share_envelope);
    let payload: cokret_sdk::RealmKeySharePayload = match serde_json::from_value(content.clone()) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::debug!(%realm_id, error = %err, "skip malformed ck.realm_key.share");
            return 0;
        }
    };
    // Only consume member_device shares addressed to THIS device (the seal opens
    // only with this device's HPKE private key anyway, but check the routing
    // first). RRK shares (share_class=realm_recovery_key) carry no
    // recipient_device_id and are not consumed here.
    if payload.recipient_device_id.as_deref().map(str::trim) != Some(device_id.trim()) {
        return 0;
    }
    // SEC-02 / device-lifecycle.md §13: sender-device authentication. When the
    // share carries a populated `sender_device_signature`, verify it over
    // `sender_signing_input()`. The verifying key is bound to the sender's
    // device-directory record (`(sender_principal_id, sender_device_id)`) when
    // that record is cached: the self-asserted `signer_public_key_multibase` MUST
    // byte-equal the directory key, and a revoked / absent device (NegativeHit)
    // is rejected outright. When no directory record is cached (Miss — keys not
    // prefetched) we fall back to the self-asserted key, since the per-secret
    // HPKE seal still gates confidentiality/integrity. An empty / absent
    // signature is tolerated (legacy provider) only on the Miss path.
    let sender_principal_id = realm_key_share_sender_principal_id(share_envelope);
    if !verify_realm_key_share_sender_signature(&payload, sender_principal_id.as_deref()) {
        tracing::debug!(
            %realm_id,
            "reject ck.realm_key.share: sender_device_signature failed device-bound verification"
        );
        return 0;
    }
    let Some(sealed) = payload
        .ciphertext
        .as_deref()
        .filter(|c| !c.trim().is_empty())
    else {
        return 0;
    };
    let privkey = match super::load_device_hpke_private_key(secure_store, actor_id, device_id) {
        Ok(Some(privkey)) => privkey,
        Ok(None) => {
            tracing::debug!(%realm_id, "no device HPKE key to open ck.realm_key.share");
            return 0;
        }
        Err(err) => {
            tracing::debug!(%realm_id, error = %err, "load device HPKE key failed");
            return 0;
        }
    };
    let secrets =
        match cokret_sdk::secret_share::open_history_secret_with_device_privkey(&privkey, sealed) {
            Ok(secrets) => secrets,
            Err(err) => {
                tracing::debug!(%realm_id, error = %err, "open ck.realm_key.share failed");
                return 0;
            }
        };
    let mut installed = 0_usize;
    for (epoch, secret) in secrets {
        if secret.is_empty() {
            continue;
        }
        state_store.save_history_secret(realm_id.to_owned(), epoch, secret);
        installed += 1;
    }
    installed
}

/// Extract the sender's principal DID from a `ck.realm_key.share` to-device
/// envelope so [`verify_realm_key_share_sender_signature`] can bind the signing
/// key to the sender's device-directory record. To-device / event envelopes
/// expose the sender under one of these top-level keys.
fn realm_key_share_sender_principal_id(envelope: &serde_json::Value) -> Option<String> {
    [
        "sender_principal_id",
        "sender",
        "actor_id",
        "sender_actor_id",
    ]
    .iter()
    .find_map(|key| {
        envelope
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

/// SEC-02: derive the `(sender_principal_id, sender_device_id)` directory pair
/// for a `ck.realm_key.share` to-device envelope. Callers prime the
/// device-directory cache with this pair (a `keys/query`) before
/// [`ingest_realm_key_share`] runs, so the synchronous
/// [`verify_realm_key_share_sender_signature`] can fail-closed on a directory
/// Miss instead of tolerating an unauthenticated empty signature. Returns
/// `None` when the envelope exposes no sender principal or no sender device id.
pub fn realm_key_share_sender_device_pair(
    envelope: &serde_json::Value,
) -> Option<(String, String)> {
    let principal = realm_key_share_sender_principal_id(envelope)?;
    let content = envelope.get("content").unwrap_or(envelope);
    let device_id = content
        .get("sender_device_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_owned();
    Some((principal, device_id))
}

/// Verify a `ck.realm_key.share` payload's `sender_device_signature`
/// (device-lifecycle.md §13), binding the verifying key to the sender's device
/// directory record when available (SEC-02).
///
/// Trust resolution for `(sender_principal_id, payload.sender_device_id)`:
/// - **Directory Hit**: the self-asserted `signer_public_key_multibase` MUST byte-equal the
///   directory's authoritative key (which itself required a full cross-signing / service-attested
///   trust chain to be cached). A populated signature is REQUIRED and MUST verify; an empty
///   signature is rejected.
/// - **Directory NegativeHit** (revoked / absent / no signing key): rejected.
/// - **Directory Miss** (resolution failed for a claimed sender, even after the caller's prefetch):
///   a populated signature must verify under its own embedded key; an empty signature is **rejected**
///   (SEC-02 fail-closed — the prior fail-open window that tolerated an unauthenticated empty
///   signature on Miss is closed). The per-secret HPKE seal remains the confidentiality/integrity gate.
/// - **No sender principal at all**: the share cannot impersonate any actor, so an empty signature is
///   tolerated and a populated one is verified under its embedded key (HPKE seal gates the payload).
pub(crate) fn verify_realm_key_share_sender_signature(
    payload: &cokret_sdk::RealmKeySharePayload,
    sender_principal_id: Option<&str>,
) -> bool {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let sig_obj = &payload.sender_device_signature;
    let is_empty = sig_obj.is_null()
        || sig_obj
            .as_object()
            .is_some_and(|map| map.is_empty() || !map.contains_key("signature"));

    // Resolve the sender device's authoritative directory key (sync, cache-only).
    // The caller (`app::history-share` install loop) primes this cache with a
    // `keys/query` for the sender device BEFORE this verifier runs, so a Miss
    // here means directory resolution genuinely failed for a claimed sender.
    let directory_key = sender_principal_id.map(|principal| {
        match crate::device_directory::cached_device_signing_key(
            principal,
            payload.sender_device_id.trim(),
        ) {
            crate::device_directory::CacheLookup::Hit(material) => DirectoryVerdict::Key(material),
            crate::device_directory::CacheLookup::NegativeHit => DirectoryVerdict::Revoked,
            crate::device_directory::CacheLookup::Miss => DirectoryVerdict::Unresolved,
        }
    });

    // Fail closed on a revoked / absent sender device.
    if matches!(directory_key, Some(DirectoryVerdict::Revoked)) {
        return false;
    }

    if is_empty {
        // SEC-02 fail-closed: an empty `sender_device_signature` is acceptable
        // ONLY when the envelope carries no claimed sender principal at all (an
        // unbindable share that cannot impersonate any actor; the per-secret
        // HPKE seal remains the confidentiality/integrity gate). Whenever a
        // sender principal IS claimed — Hit, revoked, or unresolved (Miss after
        // a prefetch attempt) — the sender MUST sign the share. This closes the
        // prior fail-open window where a Miss tolerated an empty signature.
        return directory_key.is_none();
    }

    let Some(sig_b64) = sig_obj.get("signature").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let Some(pubkey_multibase) = sig_obj
        .get("signer_public_key_multibase")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    let Ok(pubkey_bytes) = cokret_sdk::decode_ed25519_multibase(pubkey_multibase) else {
        return false;
    };
    // SEC-02: when a directory key is cached, the self-asserted signer key MUST
    // match it byte-for-byte — otherwise an attacker could self-sign with any key.
    if let Some(DirectoryVerdict::Key(material)) = &directory_key {
        let Ok(directory_bytes) = material.ed25519_bytes() else {
            return false;
        };
        if directory_bytes.as_slice() != pubkey_bytes.as_slice() {
            return false;
        }
    }
    let Ok(sig_bytes) = cokret_sdk::base64url_decode(sig_b64.as_bytes()) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_bytes) else {
        return false;
    };
    let signing_input = payload.sender_signing_input();
    verifying_key.verify(&signing_input, &signature).is_ok()
}

/// Outcome of a synchronous device-directory lookup for the realm-key-share
/// sender device.
enum DirectoryVerdict {
    /// A trusted authoritative verify key is cached.
    Key(cokret_sdk::signatures::PublicKeyMaterial),
    /// The sender device is revoked / absent / has no signing key.
    Revoked,
    /// A sender principal was claimed but the directory key could not be
    /// resolved (cache Miss after a prefetch attempt). A populated signature is
    /// still verified under its embedded key (best effort, HPKE seal gates
    /// confidentiality); an empty signature is rejected (SEC-02 fail-closed).
    Unresolved,
}

/// Read-only: list the principal DIDs currently in this Realm's local MLS
/// group, or `None` when this device holds no MLS state for the Realm (it can
/// neither introspect the roster nor produce Welcomes). Used by the admin-side
/// admission reconciler to find joined members not yet represented in the
/// group. Does NOT advance or persist any chain.
pub fn mls_group_member_principal_ids_for_realm(
    state_store: &crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Option<Vec<String>> {
    let snapshot = state_store.mls_snapshot_for(realm_id)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id).ok()?;
    // COR-04: read-only roster introspection — floor 0 is intentional (does NOT
    // advance or persist any chain; just reads the local snapshot's member list).
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    Some(
        group
            .member_principal_ids()
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect(),
    )
}

/// Export + re-encrypt the post-decrypt group state as a snapshot envelope,
/// carrying the epoch clock and bumping the §5.6 observed-message counter.
fn export_receive_chain_envelope(
    group: &cokret_sdk::CokretMlsGroup,
    realm_id: &str,
    secret: &str,
    previous: &crate::mls::persistence::MlsSnapshotEnvelope,
) -> Result<crate::mls::persistence::MlsSnapshotEnvelope, MlsRuntimeError> {
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let observed = if post_state.epoch == previous.epoch {
        previous.app_messages_observed.saturating_add(1)
    } else {
        1
    };
    Ok(crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        secret,
        &salt,
    )
    .carry_epoch_started_at(previous)
    .with_app_messages_observed(observed))
}

fn welcome_entry_key_package_id(entry: &serde_json::Value) -> Option<String> {
    entry
        .get("unsigned")
        .and_then(|unsigned| unsigned.get("key_package_id"))
        .or_else(|| {
            entry
                .get("content")
                .and_then(|content| content.get("key_package_id"))
        })
        .or_else(|| {
            entry
                .get("content")
                .and_then(|content| content.get("keypackage_id"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn collect_welcome_message_entries(value: &serde_json::Value) -> Vec<WelcomeMessageEntry> {
    let mut welcomes = Vec::new();
    let Some(messages) = value
        .get("messages")
        .or_else(|| value.get("events"))
        .and_then(|v| v.as_array())
    else {
        return welcomes;
    };
    for entry in messages {
        if entry
            .get("kind")
            .or_else(|| entry.get("type"))
            .and_then(|t| t.as_str())
            == Some("ck.mls.welcome")
            && let Some(content) = entry.get("content")
        {
            welcomes.push(WelcomeMessageEntry {
                content: content.clone(),
                key_package_id: welcome_entry_key_package_id(entry),
            });
        }
    }
    welcomes
}

pub fn collect_welcome_entries(value: &serde_json::Value) -> Vec<serde_json::Value> {
    // Spec form is `{ messages: [ { kind, content, unsigned, ... } ] }`
    // (`DeviceMessagesGetOutcome` / `DeviceMessageEnvelope`); the discriminator
    // is `kind` and the payload lives under `content`.
    collect_welcome_message_entries(value)
        .into_iter()
        .map(|entry| entry.content)
        .collect()
}

pub fn mls_group_id_for_realm(realm_id: &str) -> String {
    cokret_sdk::base64url_encode(realm_id.trim().as_bytes())
}

pub fn mls_welcome_message_matches_realm(message: &serde_json::Value, realm_id: &str) -> bool {
    if message
        .get("kind")
        .or_else(|| message.get("type"))
        .and_then(|t| t.as_str())
        != Some("ck.mls.welcome")
    {
        return false;
    }
    let expected_group_id = mls_group_id_for_realm(realm_id);
    message
        .get("content")
        .and_then(|content| content.get("group_id"))
        .and_then(serde_json::Value::as_str)
        == Some(expected_group_id.as_str())
}

pub fn collect_mls_welcome_messages_for_realm(
    messages: &[serde_json::Value],
    realm_id: &str,
) -> Vec<serde_json::Value> {
    messages
        .iter()
        .filter(|message| mls_welcome_message_matches_realm(message, realm_id))
        .cloned()
        .collect()
}

pub fn local_mls_welcome_hint_for_realm(messages: &[serde_json::Value], realm_id: &str) -> String {
    let mut hints = messages
        .iter()
        .filter(|message| mls_welcome_message_matches_realm(message, realm_id))
        .map(|message| {
            message
                .get("unsigned")
                .and_then(|unsigned| unsigned.get("mls_welcome_id"))
                .or_else(|| {
                    message
                        .get("content")
                        .and_then(|content| content.get("welcome_hash"))
                })
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned()
        })
        .collect::<Vec<_>>();
    hints.sort();
    hints.dedup();
    format!("{}:{}", hints.len(), hints.join(","))
}

fn durable_welcome_payload_reject_reason(value: &serde_json::Value) -> Option<&'static str> {
    let looks_like_durable_payload = value.get("claim_ref").is_some()
        || value.get("claim_id").is_some()
        || value.get("keypackage_digest").is_some()
        || value.get("keypackage_ref").is_some();
    if !looks_like_durable_payload {
        return None;
    }
    let _ = serde_json::from_value::<cokret_sdk::MlsWelcomePayload>(value.clone());
    Some(cokret_sdk::error::REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)
}

/// YGN-SEC-01 闸门 (1): 接受一个入站 Welcome 之前,独立验证其 `claim_envelope`
/// 的发送者签名(`encryption-and-audit.md` §发送 admin gate;`admission.rs`
/// `sign_welcome_claim_envelope` 是发送端)。
///
/// fail-closed 语义:
/// - 当 `welcome_value` 携带 `claim_envelope` 时,签名 **必须** 验证通过;形态非法、 验签 key
///   解析不到、或签名不匹配,一律 `Err(reason)` → 调用方 `record_failure` 并拒绝该
///   Welcome(绝不放行未验签者把本设备拉入群)。
/// - 验签 key **经 `device_directory` 解析**(同步缓存,bootstrap 已经 `prefetch_device_keys`
///   预热),绝不取自 envelope 自述的 `kid`/`requester_did`。
/// - `ssk_generation` 分支(发送端用 cross-signing self-signing key 签名)在客户端 当前
///   **无法可靠解析远端 actor 的 SSK 公钥**(`device_directory` 只解析设备 signing key,SSK 公钥需要
///   actor 的 cross-signing publish + DID 锚定,本同步 接收路径无该输入),按纪律对该分支同样
///   fail-closed(宁可拒绝)。
///
/// 返回 `Ok(())` 仅当:(a) `welcome_value` 不含 `claim_envelope`(降维后的纯
/// routing+ciphertext Welcome,无可验之物——governance_binding 闸门与服务端
/// admin gate 兜底),或 (b) 携带且经目录解析的设备签名验证通过。
fn verify_welcome_claim_envelope_signer(welcome_value: &serde_json::Value) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let Some(claim_value) = welcome_value.get("claim_envelope") else {
        // 没有可验签的 claim_envelope(soland 降维后的纯 Welcome)。此处不是放行
        // 授权,而是"无此材料":真正的 epoch/Seal 绑定由 governance_binding 闸门
        // (2) 强制;服务端 admission admin gate 是额外一层。
        return Ok(());
    };
    let envelope: cokret_sdk::MlsWelcomeClaimEnvelope = serde_json::from_value(claim_value.clone())
        .map_err(|err| format!("claim_envelope decode: {err}"))?;
    // 形态校验:kid/sig 非空、alg ∈ {EdDSA, Ed25519}。
    envelope
        .validate_signature_shape()
        .map_err(|reason| format!("claim_envelope signature shape: {reason}"))?;

    // ssk_generation 分支:无法在本同步接收路径可靠解析 SSK 公钥 → fail-closed。
    if envelope.ssk_generation.is_some() {
        return Err(
            "claim_envelope is self-signing-key signed (ssk_generation present); the \
             cross-signing SSK public key cannot be resolved on the synchronous receive \
             path, so this Welcome is rejected fail-closed (YGN-SEC-01)"
                .to_owned(),
        );
    }

    // device 分支:经 device_directory 同步缓存解析 (actor, device) 的设备签名 key。
    let Some(requester_device_id) = envelope
        .requester_device_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(
            "claim_envelope carries neither ssk_generation nor requester_device_id; \
             no resolvable signer (YGN-SEC-01)"
                .to_owned(),
        );
    };
    let requester_did = envelope.requester_did.as_str();
    let verifying_key = match crate::device_directory::cached_device_signing_key(
        requester_did,
        requester_device_id,
    ) {
        crate::device_directory::CacheLookup::Hit(material) => {
            let bytes = material.ed25519_bytes().map_err(|err| {
                format!("claim_envelope signer key decode ({requester_did}/{requester_device_id}): {err}")
            })?;
            VerifyingKey::from_bytes(&bytes).map_err(|err| {
                format!("claim_envelope signer key invalid ({requester_did}/{requester_device_id}): {err}")
            })?
        }
        crate::device_directory::CacheLookup::NegativeHit => {
            return Err(format!(
                "claim_envelope signer {requester_did}/{requester_device_id} is revoked / \
                 absent in directory (negative verdict); Welcome rejected (YGN-SEC-01)"
            ));
        }
        crate::device_directory::CacheLookup::Miss => {
            return Err(format!(
                "claim_envelope signer key for {requester_did}/{requester_device_id} not in \
                 device-directory cache; fail-closed (YGN-SEC-01)"
            ));
        }
    };

    let signing_bytes = envelope
        .canonical_signing_bytes()
        .map_err(|err| format!("claim_envelope canonical bytes: {err}"))?;
    let sig_bytes = cokret_sdk::base64url_decode(envelope.signature.sig.as_bytes())
        .map_err(|err| format!("claim_envelope signature decode: {err}"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|err| format!("claim_envelope signature malformed: {err}"))?;
    verifying_key
        .verify(&signing_bytes, &signature)
        .map_err(|err| format!("claim_envelope signature verification failed: {err}"))?;
    Ok(())
}

/// YGN-SEC-01 闸门 (2): 在持久化快照之前,独立验证 Welcome 内嵌的
/// `governance_binding`(`encryption-and-audit.md` :438 — 客户端在接受 MLS epoch
/// 前 MUST 独立验证 `governance_binding` 指向的 Seal view 与 state_root)。
///
/// 这里把"仅记录 policy_root"升级为"独立验证 MLS 群 **真实内嵌** 的
/// governance_binding extension 与服务端转发的 durable payload 声明逐字段一致":
/// 用 welcome 声明的 `mls_group_id`/`previous_epoch`/`next_epoch`/`policy_root`/
/// `binding_profile`/`reducer_profile` 构造 expected context,交给 SDK
/// `CokretMlsGroup::verify_current_governance_binding` 比对 MLS GroupContext 内嵌
/// 的 CBOR binding。任一字段不一致或 MLS 群没有 binding extension → `Err` → 拒绝。
///
/// 当 `welcome_value` 不含 `governance_binding`(降维后的纯 Welcome)时返回
/// `Ok(None)`:无声明可比对(此路径下 Seal inclusion 由服务端 admission +
/// claim_envelope 闸门兜底)。携带时返回 `Ok(Some(policy_root))` 供调用方记录
/// genesis policy_root。
///
/// 边界(spec :438 完整要求):本同步接收路径未注入 Cokret Seal view,无法回补
/// Control Move inclusion proof 把 `policy_root`/`state_root` 锚到一个已接受的
/// Seal。此处保证的是"MLS 群内嵌 binding == 服务端声明",尚未完成"声明的 Seal
/// 在本设备已接受的 Seal 视图中可被 inclusion-proof 验证"。完整闭合见下方 TODO。
fn verify_welcome_governance_binding(
    group: &cokret_sdk::CokretMlsGroup,
    welcome_value: &serde_json::Value,
) -> Result<Option<String>, String> {
    let Some(binding) = welcome_value.get("governance_binding") else {
        return Ok(None);
    };

    let mls_group_id = binding
        .get("mls_group_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "governance_binding.mls_group_id missing".to_owned())?;
    let previous_epoch = binding
        .get("previous_epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "governance_binding.previous_epoch missing".to_owned())?;
    let next_epoch = binding
        .get("next_epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "governance_binding.next_epoch missing".to_owned())?;
    let policy_root_str = binding
        .get("policy_root")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "governance_binding.policy_root missing".to_owned())?
        .to_owned();
    // binding_profile / reducer_profile 默认走 spec 常量(welcome 声明可覆盖)。
    let binding_profile = binding
        .get("binding_profile")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(cokret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE)
        .to_owned();
    let reducer_profile = binding
        .get("reducer_profile")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(cokret_sdk::CORE_REDUCER_PROFILE)
        .to_owned();

    let policy_root_hash = cokret_sdk::Hash::new(policy_root_str.clone())
        .map_err(|err| format!("governance_binding.policy_root invalid hash: {err:?}"))?;

    let mut expected = cokret_sdk::MlsGovernanceBindingValidationContext::for_commit(
        mls_group_id,
        previous_epoch,
        next_epoch,
        &binding_profile,
        &reducer_profile,
    );
    expected.policy_root = Some(&policy_root_hash);

    // 比对 MLS 群真实内嵌的 governance_binding extension 与上面声明的 expected。
    // 群内无 binding extension、profile/epoch/policy_root 任一不符 → Err。
    group
        .verify_current_governance_binding(&expected)
        .map_err(|err| format!("governance_binding independent verification failed: {err}"))?;

    // TODO(YGN-SEC-01, encryption-and-audit.md:438): 完整闭合还需把声明的
    // policy_root / state_root 对一个本设备已接受的 Cokret Seal view 做 Control
    // Move inclusion-proof 校验,失败时标记 epoch 为 decryption_pending /
    // state_mismatch。本同步接收路径当前未注入 Seal view,故此层依赖 claim_envelope
    // 闸门 (1) + 服务端 admission admin gate 兜底,留待 Seal view 注入后补齐。

    Ok(Some(policy_root_str))
}

pub fn apply_welcome_messages_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    messages_value: &serde_json::Value,
) -> Result<WelcomeApplyOutcome, MlsRuntimeError> {
    let welcome_entries = collect_welcome_message_entries(messages_value);
    // A totally-empty welcome set is a success with nothing to do.
    if welcome_entries.is_empty() {
        return Ok(WelcomeApplyOutcome::default());
    }
    // The snapshot secret / identity are prerequisites for ALL welcomes: if they
    // are unavailable no welcome could possibly apply, so surface them as a hard
    // error (the readiness status machinery keys off these).
    let secret = load_or_create_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let principal_did = cokret_sdk::Did::new(actor_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let device_id_typed = cokret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    // Per-welcome failures no longer abort the loop or get swallowed: each is
    // counted and the first reason retained so callers can report partial
    // success without failing the whole boot.
    let mut outcome = WelcomeApplyOutcome::default();
    for welcome_entry in welcome_entries {
        let welcome_value = welcome_entry.content;
        if let Some(reason) = durable_welcome_payload_reject_reason(&welcome_value) {
            outcome.record_failure(format!("welcome claim envelope: {reason}"));
            continue;
        }
        // YGN-SEC-01 闸门 (1): 接受 Welcome 之前,先独立验证 claim_envelope 发送者
        // 签名(经 device_directory 解析 key,fail-closed)。在 join 之前做,因为
        // 签名校验不依赖 MLS 协议层解密,提前拒绝攻击者构造的 Welcome。
        if let Err(reason) = verify_welcome_claim_envelope_signer(&welcome_value) {
            outcome.record_failure(format!("welcome claim envelope authz: {reason}"));
            continue;
        }
        // The admission's Welcome carries the same `governance_binding` as its
        // `ck.mls.commit`, so the joining member records the genesis-locked
        // `policy_root` here. Without it, a later self-update commit by this
        // member would recompute `policy_root` from its own moving Seal
        // `state_root` and be rejected `governance_binding_mismatch`.
        //
        // YGN-SEC-01 闸门 (2) 在 join 之后(需要 MLS 群对象)再独立验证此
        // governance_binding 与 MLS GroupContext 内嵌值一致,见下方
        // `verify_welcome_governance_binding`;此处保留原始 JSON 供该校验使用。
        let welcome_value_for_governance = welcome_value.clone();
        let welcome = match serde_json::from_value::<cokret_sdk::MlsWelcomeEnvelope>(welcome_value)
        {
            Ok(welcome) => welcome,
            Err(err) => {
                outcome.record_failure(format!("welcome envelope parse: {err}"));
                continue;
            }
        };
        let identity = match welcome_entry.key_package_id.as_deref() {
            Some(key_package_id) => match load_mls_key_package_identity_state(
                secure_store,
                actor_id,
                device_id,
                key_package_id,
            ) {
                Ok(Some(serialized_state)) => {
                    match cokret_sdk::CokretMlsIdentity::restore_from_private_state(
                        principal_did.clone(),
                        device_id_typed.clone(),
                        &serialized_state,
                    ) {
                        Ok(identity) => identity,
                        Err(err) => {
                            outcome.record_failure(format!(
                                "restore KeyPackage identity state: {err}"
                            ));
                            continue;
                        }
                    }
                }
                Ok(None) => {
                    // The Welcome names a KeyPackage we have no stored private
                    // identity state for. A fresh `new_basic` identity can NEVER
                    // hold that KeyPackage's init key, so `join_from_welcome`
                    // would fail with `NoMatchingKeyPackage`. Fail closed with a
                    // diagnosable message instead of silently retrying with an
                    // identity that cannot work. (mls-welcome-debug)
                    tracing::warn!(
                        target: "mls_admission",
                        realm = %crate::views::helpers::short_protocol_id(realm_id),
                        actor = %crate::views::helpers::short_protocol_id(actor_id),
                        device = %crate::views::helpers::short_protocol_id(device_id),
                        key_package_id = %crate::views::helpers::short_protocol_id(key_package_id),
                        "welcome apply: no local KeyPackage identity state for the Welcome's key_package_id — the published KeyPackage's private init key is missing from this device's secure store (cannot decrypt Welcome)"
                    );
                    outcome.record_failure(format!(
                        "no local KeyPackage identity state for welcome key_package_id={key_package_id}"
                    ));
                    continue;
                }
                Err(err) => {
                    outcome.record_failure(format!("load KeyPackage identity state: {err}"));
                    continue;
                }
            },
            None => {
                tracing::warn!(
                    target: "mls_admission",
                    realm = %crate::views::helpers::short_protocol_id(realm_id),
                    "welcome apply: Welcome carries no key_package_id — cannot select the KeyPackage private state to decrypt it"
                );
                outcome.record_failure("welcome carries no key_package_id".to_owned());
                continue;
            }
        };
        let group = match cokret_sdk::CokretMlsGroup::join_from_welcome(identity, &welcome) {
            Ok(group) => group,
            Err(err) => {
                outcome.record_failure(format!("join welcome: {err}"));
                continue;
            }
        };
        // YGN-SEC-01 闸门 (2): 独立验证 MLS 群内嵌的 governance_binding 与服务端
        // 转发的 durable payload 声明一致(`encryption-and-audit.md` :438)。失败
        // (群内无 binding / profile / epoch / policy_root 不符)→ 拒绝该 Welcome,
        // 不持久化快照。返回声明的 policy_root 供下方 genesis 记录。
        let welcome_policy_root =
            match verify_welcome_governance_binding(&group, &welcome_value_for_governance) {
                Ok(policy_root) => policy_root,
                Err(reason) => {
                    outcome.record_failure(format!("welcome governance_binding authz: {reason}"));
                    continue;
                }
            };
        let post_state = match group.export_state_record() {
            Ok(post_state) => post_state,
            Err(err) => {
                outcome.record_failure(format!("export state: {err}"));
                continue;
            }
        };
        let serialized_state = match serde_json::to_vec(&post_state) {
            Ok(serialized_state) => serialized_state,
            Err(err) => {
                outcome.record_failure(format!("serialize state: {err}"));
                continue;
            }
        };
        // YOU-02-005: epoch guard against rolling the realm snapshot backwards.
        // A replayed / re-delivered Welcome (device_messages GET is read-only
        // until the client consumes an explicit ack token) must not
        // overwrite a snapshot that has already advanced past the join epoch.
        // Doing so would discard the sender ratchet position (risking AEAD
        // generation/nonce reuse on the next send) and desync `expected_prev_epoch`
        // from the server. Skip when we already hold an equal-or-higher epoch for
        // the same group.
        if let Some(existing) = state_store.mls_snapshot_for(realm_id)
            && existing.group_id == post_state.group_id
            && existing.epoch >= post_state.epoch
        {
            outcome.skipped_stale += 1;
            continue;
        }
        let mut salt = [0u8; 16];
        if let Err(err) = getrandom::fill(&mut salt) {
            outcome.record_failure(format!("salt: {err}"));
            continue;
        }
        let snapshot = crate::mls::persistence::encrypt_state(
            realm_id,
            &post_state.group_id,
            post_state.epoch,
            &serialized_state,
            &secret,
            &salt,
        );
        state_store.save_mls_snapshot(realm_id.to_owned(), snapshot);
        if let Some(policy_root) = welcome_policy_root.as_deref() {
            state_store.record_genesis_policy_root_for_effective_scope(realm_id, None, policy_root);
        }
        if let Some(key_package_id) = welcome_entry.key_package_id.as_deref()
            && let Err(err) = delete_mls_key_package_identity_state(
                secure_store,
                actor_id,
                device_id,
                key_package_id,
            )
        {
            tracing::warn!(
                %realm_id,
                %key_package_id,
                error = %err,
                "failed to delete consumed MLS KeyPackage identity state",
            );
        }
        outcome.applied += 1;
    }
    Ok(outcome)
}

#[allow(clippy::type_complexity)]
pub fn encrypt_values_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    content_type: &str,
    plaintext_values: &[Vec<u8>],
) -> Result<
    (
        cokret_sdk::Hash,
        Vec<cokret_sdk::Did>,
        Vec<serde_json::Value>,
        Option<cokret_sdk::MlsCommitEnvelope>,
        Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    ),
    MlsRuntimeError,
> {
    if plaintext_values.is_empty() {
        return Err(MlsRuntimeError::EmptyPlaintext);
    }
    let snapshot = state_store
        .mls_snapshot_for(realm_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: send/encrypt under the Seal-view epoch floor so encrypting from a
    // stale local snapshot (below the Seal lattice) is rejected as OutdatedSnapshot
    // rather than producing ciphertext on a forked ratchet.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    let should_commit = should_force_epoch_advance(
        state_store.realm_projection_is_minimal_metadata(realm_id),
        snapshot.epoch_started_at,
        crate::clock::now_utc(),
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    );
    let commit_envelope = if should_commit {
        Some(
            group
                .self_update_commit()
                .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?,
        )
    } else {
        None
    };
    let mut encrypted_values = Vec::with_capacity(plaintext_values.len());
    for plaintext in plaintext_values {
        let encrypted = group
            .encrypt_payload(content_type, plaintext)
            .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))?;
        encrypted_values.push(
            serde_json::to_value(&encrypted)
                .map_err(|err| MlsRuntimeError::Serialize(err.to_string()))?,
        );
    }
    let schedule_hash = group.schedule_hash();
    let member_dids = group.member_principal_ids();
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let sent = plaintext_values.len() as u64;
    let mut new_envelope = crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    if commit_envelope.is_some() {
        // Persist-on-accept: forced epoch advances must only be saved after the
        // server accepts the matching `ck.mls.commit`. The messages encrypted
        // above already ride the NEW epoch, so the §5.6 observed-message
        // counter restarts at their count.
        return Ok((
            schedule_hash,
            member_dids,
            encrypted_values,
            commit_envelope,
            Some(new_envelope.with_app_messages_observed(sent)),
        ));
    }
    new_envelope = new_envelope
        .carry_epoch_started_at(&snapshot)
        .with_app_messages_observed(snapshot.app_messages_observed.saturating_add(sent));
    state_store.save_mls_snapshot(realm_id.to_owned(), new_envelope);
    Ok((schedule_hash, member_dids, encrypted_values, None, None))
}

/// Encrypt a single message plaintext under the Realm MLS group, binding
/// `aad` into the payload digest, and return the structured
/// [`cokret_sdk::EncryptedPayload`] (not yet wrapped as a wire envelope).
///
/// The caller assembles the spec-canonical `ck.schema.encrypted_envelope.v1`
/// wire shape via [`cokret_sdk::EncryptedEnvelopeV1::from_payload`] once it
/// knows the accepted group-state reference for this epoch (genesis, latest
/// winning commit, or a forced commit returned by this helper). `aad` MUST be
/// the canonical `EncryptedEnvelopeAadV1` value, so the digest verification
/// round-trips.
type DeviceSnapshotEncryption = (
    cokret_sdk::Hash,
    Vec<cokret_sdk::Did>,
    cokret_sdk::EncryptedPayload,
    Option<cokret_sdk::MlsCommitEnvelope>,
    Option<crate::mls::persistence::MlsSnapshotEnvelope>,
);

pub fn encrypt_message_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    content_type: &str,
    aad: serde_json::Value,
    plaintext: &[u8],
) -> Result<DeviceSnapshotEncryption, MlsRuntimeError> {
    let snapshot = state_store
        .mls_snapshot_for(realm_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    // SEC-08 (§2.9) — fail-closed: a `minimal_metadata_realm` message MUST use
    // `aad_visibility=hidden`. Enforce before any optional commit/encrypt so a
    // non-hidden AAD never advances the epoch nor produces ciphertext.
    let is_minimal_metadata = state_store.realm_projection_is_minimal_metadata(realm_id);
    assert_minimal_metadata_aad(&aad_visibility_of(&aad), is_minimal_metadata)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: send/encrypt under the Seal-view epoch floor so encrypting from a
    // stale local snapshot (below the Seal lattice) is rejected as OutdatedSnapshot
    // rather than producing ciphertext on a forked ratchet.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    let should_commit = should_force_epoch_advance(
        is_minimal_metadata,
        snapshot.epoch_started_at,
        crate::clock::now_utc(),
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    );
    let commit_envelope = if should_commit {
        Some(
            group
                .self_update_commit()
                .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?,
        )
    } else {
        None
    };
    let encrypted = group
        .encrypt_payload_with_aad(content_type, Some(aad), plaintext)
        .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))?;
    let schedule_hash = group.schedule_hash();
    let member_dids = group.member_principal_ids();
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let mut new_envelope = crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    if commit_envelope.is_some() {
        // Persist-on-accept: forced epoch advances must only be saved after the
        // server accepts the matching `ck.mls.commit`. The single message
        // encrypted above rides the NEW epoch (§5.6 counter restarts at 1).
        return Ok((
            schedule_hash,
            member_dids,
            encrypted,
            commit_envelope,
            Some(new_envelope.with_app_messages_observed(1)),
        ));
    }
    new_envelope = new_envelope
        .carry_epoch_started_at(&snapshot)
        .with_app_messages_observed(snapshot.app_messages_observed.saturating_add(1));
    state_store.save_mls_snapshot(realm_id.to_owned(), new_envelope);
    Ok((schedule_hash, member_dids, encrypted, None, None))
}

/// SEC-08 — fail-closed committer-side assertion that a `minimal_metadata_realm`
/// send uses `aad_visibility=hidden` (`encryption-and-audit.md` §2.9).
///
/// Thin wrapper over the SDK's [`cokret_sdk::enforce_minimal_metadata_aad`]
/// that maps the SDK protocol error into [`MlsRuntimeError::AadPolicy`] so the
/// runtime's typed error surface stays uniform. This mirrors soland's
/// server-side reject, giving client + server defence in depth: a minimal Realm
/// can never emit a non-hidden AAD, and the server would reject it if it
/// somehow did.
pub fn assert_minimal_metadata_aad(
    visibility: &cokret_sdk::AadVisibility,
    is_minimal_metadata: bool,
) -> Result<(), MlsRuntimeError> {
    cokret_sdk::enforce_minimal_metadata_aad(visibility, is_minimal_metadata)
        .map_err(|err| MlsRuntimeError::AadPolicy(err.to_string()))
}

/// SEC-08 — infer the [`cokret_sdk::AadVisibility`] discriminator from a
/// canonical `ck.schema.encrypted_envelope.v1` AAD value.
///
/// The schema discriminator is structural (`encryption-and-audit.md` §2.9): a
/// `hidden` envelope omits both `event_id` and `event_ref_digest`; an
/// `opaque_id` envelope carries `event_id`; a `routing_digest` envelope carries
/// `event_ref_digest`. Used by [`assert_minimal_metadata_aad`] on the message
/// path so a minimal Realm cannot ship a non-hidden AAD even if a caller
/// constructed one. `event_id` is checked first so a malformed value carrying
/// both fields resolves to the *less* private (and therefore rejected) form.
pub(crate) fn aad_visibility_of(aad: &serde_json::Value) -> cokret_sdk::AadVisibility {
    let has = |key: &str| aad.get(key).is_some_and(|v| !v.is_null());
    if has("event_id") {
        cokret_sdk::AadVisibility::OpaqueId
    } else if has("event_ref_digest") {
        cokret_sdk::AadVisibility::RoutingDigest
    } else {
        cokret_sdk::AadVisibility::Hidden
    }
}
