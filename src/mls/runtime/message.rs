//! Welcome application, application-payload encrypt / decrypt, and the SEC-08
//! minimal-metadata AAD policy enforcement.

use super::{
    MlsRuntimeError, load_device_snapshot_secret, load_or_create_device_snapshot_secret,
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
    let snapshot = state_store.mls_snapshot_for(realm_id)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id).ok()?;
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    let plaintext = group.decrypt_payload(payload).ok()?;
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

pub fn collect_welcome_entries(value: &serde_json::Value) -> Vec<serde_json::Value> {
    // Spec form is `{ messages: [ { kind, content, … } ] }`
    // (`DeviceMessagesGetOutcome` / `DeviceMessageEnvelope`); the discriminator
    // is `kind` and the payload lives under `content`.
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
            welcomes.push(content.clone());
        }
    }
    welcomes
}

pub fn apply_welcome_messages_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    messages_value: &serde_json::Value,
) -> Result<WelcomeApplyOutcome, MlsRuntimeError> {
    let welcome_entries = collect_welcome_entries(messages_value);
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
    for welcome_value in welcome_entries {
        let welcome = match serde_json::from_value::<cokret_sdk::MlsWelcomeEnvelope>(welcome_value)
        {
            Ok(welcome) => welcome,
            Err(err) => {
                outcome.record_failure(format!("welcome envelope parse: {err}"));
                continue;
            }
        };
        let identity = match cokret_sdk::CokretMlsIdentity::new_basic(
            principal_did.clone(),
            device_id_typed.clone(),
        ) {
            Ok(identity) => identity,
            Err(err) => {
                outcome.record_failure(format!("identity: {err:?}"));
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
        if let Some(existing) = state_store.mls_snapshot_for(realm_id) {
            if existing.group_id == post_state.group_id && existing.epoch >= post_state.epoch {
                outcome.skipped_stale += 1;
                continue;
            }
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
pub fn encrypt_message_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    content_type: &str,
    aad: serde_json::Value,
    plaintext: &[u8],
) -> Result<
    (
        cokret_sdk::Hash,
        Vec<cokret_sdk::Did>,
        cokret_sdk::EncryptedPayload,
        Option<cokret_sdk::MlsCommitEnvelope>,
        Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    ),
    MlsRuntimeError,
> {
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
