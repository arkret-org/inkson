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
        .chain(scan.into_iter().filter(|(epoch, _)| *epoch != payload.epoch));
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
    let content = share_envelope
        .get("content")
        .unwrap_or(share_envelope);
    let payload: cokret_sdk::RealmKeySharePayload =
        match serde_json::from_value(content.clone()) {
            Ok(payload) => payload,
            Err(err) => {
                tracing::debug!(%realm_id, error = %err, "skip malformed ck.realm_key.share");
                return 0;
            }
        };
    // Only consume shares addressed to THIS device (the seal opens only with
    // this device's HPKE private key anyway, but check the routing first).
    if payload.recipient_device_id.trim() != device_id.trim() {
        return 0;
    }
    // Best-effort sender-device authentication (device-lifecycle.md §13): when
    // the share carries a populated `sender_device_signature`, verify it over
    // `sender_signing_input()` and reject on mismatch. An empty / absent
    // signature object is tolerated (legacy provider, or no signer installed at
    // share time) — the per-secret HPKE seal still gates confidentiality and
    // integrity, so we do not fail closed on a missing signature.
    if !verify_realm_key_share_sender_signature(&payload) {
        tracing::debug!(
            %realm_id,
            "reject ck.realm_key.share: sender_device_signature present but invalid"
        );
        return 0;
    }
    let Some(sealed) = payload.ciphertext.as_deref().filter(|c| !c.trim().is_empty()) else {
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

/// Best-effort verification of a `ck.realm_key.share` payload's
/// `sender_device_signature` (device-lifecycle.md §13).
///
/// Returns `true` when the signature is absent / an empty object (legacy
/// provider, or no signer installed at share time — tolerated because the
/// per-secret HPKE seal already gates integrity), OR when a populated
/// signature object verifies over [`cokret_sdk::RealmKeySharePayload::sender_signing_input`].
/// Returns `false` only when a populated signature object is present but fails
/// to verify (malformed, wrong key, or tampered body).
///
/// The verifying key is taken from the signature object's
/// `signer_public_key_multibase` (self-asserted by the provider). This binds
/// the share body to *some* Ed25519 key the provider controls; a stronger
/// binding of that key to `sender_device_id` requires DID resolution and is a
/// follow-up — for now the HPKE seal remains the confidentiality/integrity
/// gate and this signature is an additional best-effort authenticity check.
pub(crate) fn verify_realm_key_share_sender_signature(
    payload: &cokret_sdk::RealmKeySharePayload,
) -> bool {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let sig_obj = &payload.sender_device_signature;
    // Empty / absent signature object → tolerated (best-effort).
    let is_empty = sig_obj.is_null()
        || sig_obj
            .as_object()
            .is_some_and(|map| map.is_empty() || !map.contains_key("signature"));
    if is_empty {
        return true;
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
    let Ok(sig_bytes) = cokret_sdk::base64url_decode(sig_b64.as_bytes()) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let Ok(pubkey_bytes) = cokret_sdk::decode_ed25519_multibase(pubkey_multibase) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_bytes) else {
        return false;
    };
    let signing_input = payload.sender_signing_input();
    verifying_key.verify(&signing_input, &signature).is_ok()
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
                Ok(None) => match cokret_sdk::CokretMlsIdentity::new_basic(
                    principal_did.clone(),
                    device_id_typed.clone(),
                ) {
                    Ok(identity) => identity,
                    Err(err) => {
                        outcome.record_failure(format!("identity: {err:?}"));
                        continue;
                    }
                },
                Err(err) => {
                    outcome.record_failure(format!("load KeyPackage identity state: {err}"));
                    continue;
                }
            },
            None => match cokret_sdk::CokretMlsIdentity::new_basic(
                principal_did.clone(),
                device_id_typed.clone(),
            ) {
                Ok(identity) => identity,
                Err(err) => {
                    outcome.record_failure(format!("identity: {err:?}"));
                    continue;
                }
            },
        };
        let group = match cokret_sdk::CokretMlsGroup::join_from_welcome(identity, &welcome) {
            Ok(group) => group,
            Err(err) => {
                outcome.record_failure(format!("join welcome: {err}"));
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
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
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
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
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
