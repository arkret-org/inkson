//! Welcome application, application-payload encrypt / decrypt, and the SEC-08
//! minimal-metadata AAD policy enforcement.

use super::{
    MlsRuntimeError, load_device_snapshot_secret, load_mls_key_package_identity_state,
    load_or_create_device_snapshot_secret, should_force_epoch_advance,
};
use crate::secure_key_store::SecureKeyStore;

#[derive(Clone, Debug)]
pub struct PreparedMlsCommit {
    pub envelope: arkret_sdk::MlsCommitEnvelope,
    pub previous_governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
}

impl std::ops::Deref for PreparedMlsCommit {
    type Target = arkret_sdk::MlsCommitEnvelope;

    fn deref(&self) -> &Self::Target {
        &self.envelope
    }
}

fn warn_mls_decrypt_once(
    realm_id: &str,
    digest: &str,
    payload_epoch: u64,
    snapshot_epoch: Option<u64>,
    reason: &str,
) {
    use std::collections::BTreeSet;
    use std::sync::{Mutex, OnceLock, PoisonError};

    static WARNED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let key = format!("{realm_id}\u{1f}{digest}\u{1f}{reason}");
    if WARNED
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key)
    {
        tracing::warn!(
            %realm_id,
            %digest,
            payload_epoch,
            snapshot_epoch,
            %reason,
            "MLS application payload remains decryption-pending"
        );
    }
}

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
    pub(crate) consumable_claims: Vec<WelcomeConsumeCandidate>,
}

impl WelcomeApplyOutcome {
    fn record_failure(&mut self, reason: String) {
        self.failed += 1;
        if self.first_error.is_none() {
            self.first_error = Some(reason);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WelcomeConsumeCandidate {
    pub(crate) key_package_id: String,
    pub(crate) claim_id: String,
    pub(crate) welcome_event_id: String,
    pub(crate) realm_id: String,
    pub(crate) strand_id: Option<String>,
    pub(crate) mls_group_id: String,
    pub(crate) epoch: u64,
    pub(crate) welcome_digest: arkret_sdk::Hash,
    /// Present only for a peer claim whose purpose is the replacement-repair
    /// profile and whose exact target ref matches the Welcome payload.
    pub(crate) repair_target_keypackage_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct WelcomeMessageEntry {
    content: serde_json::Value,
    key_package_id: Option<String>,
    welcome_event_id: Option<String>,
}

/// True when `realm_id` declares the §2.10 `mls_exporter_aead_v1` content scheme
/// (capability axis), so authored content uses the history-shareable exporter
/// AEAD path instead of forward-secret `mls_rfc9420`. Normalizes case and
/// hyphen aliases to the canonical underscore spelling. See
/// [[content-scheme-capability-vs-toggle]].
pub(crate) fn realm_content_scheme_is_exporter_aead(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
) -> bool {
    state_store
        .realm_content_scheme(realm_id)
        .map(|scheme| scheme.trim().to_ascii_lowercase().replace('-', "_"))
        .is_some_and(|scheme| scheme == "mls_exporter_aead_v1")
}

fn realm_content_scheme_is_exporter_aead_for_send(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    circle: Option<&str>,
) -> Result<bool, MlsRuntimeError> {
    if circle.is_some() {
        return Ok(false);
    }
    let scheme = state_store
        .realm_content_scheme(realm_id)
        .ok_or(MlsRuntimeError::EncryptionPolicyPending)?
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_");
    match scheme.as_str() {
        "mls_exporter_aead_v1" => Ok(true),
        "mls_rfc9420" => Ok(false),
        unsupported => Err(MlsRuntimeError::Encrypt(format!(
            "unsupported Realm content scheme: {unsupported}"
        ))),
    }
}

pub fn decrypt_application_payload(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload: &arkret_sdk::EncryptedPayload,
) -> Option<Vec<u8>> {
    decrypt_application_payload_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
        payload,
        None,
    )
}

pub fn decrypt_application_payload_for_effective_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload: &arkret_sdk::EncryptedPayload,
    circle_id: Option<&str>,
) -> Option<Vec<u8>> {
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?;
    let effective_scope = match circle_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(circle_id) => arkret_sdk::ScopeRef::Circle {
            realm_id: realm,
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).ok()?,
        },
        None => arkret_sdk::ScopeRef::Realm { realm_id: realm },
    };
    decrypt_application_payload_for_scope(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
        payload,
        &effective_scope,
    )
}

pub fn decrypt_application_payload_for_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload: &arkret_sdk::EncryptedPayload,
    effective_scope: &arkret_sdk::ScopeRef,
) -> Option<Vec<u8>> {
    if effective_scope.realm_id_opt()?.as_str() != realm_id {
        return None;
    }
    let circle = match effective_scope {
        arkret_sdk::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str()),
        arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Sidecar { .. } => None,
        _ => return None,
    };
    let sidecar_scoped = matches!(effective_scope, arkret_sdk::ScopeRef::Sidecar { .. });
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
    // A local snapshot lets us instantiate a `ArkretMlsGroup` and try the live
    // receive ratchet first. But the exporter-aead history-decrypt path does NOT
    // need a group at all — the content key derives purely from the granted
    // `history_secret` — so a never-Welcomed joiner (no snapshot) can still read
    // granted history via the group-free standalone path below. When no snapshot
    // is present we skip straight to tier-3 history decrypt.
    let Some(snapshot) = state_store.mls_snapshot_for_scope(effective_scope) else {
        let plaintext = (!sidecar_scoped && circle.is_none())
            .then(|| try_history_decrypt_standalone(state_store, realm_id, payload))
            .flatten();
        if plaintext.is_none() && circle.is_none() && !sidecar_scoped {
            warn_mls_decrypt_once(
                realm_id,
                digest,
                payload.epoch,
                None,
                "no local MLS snapshot or granted history secret",
            );
        }
        return plaintext;
    };
    let secret = match load_device_snapshot_secret(secure_store, actor_id, device_id) {
        Ok(secret) => secret,
        Err(error) => {
            if circle.is_none() && !sidecar_scoped {
                warn_mls_decrypt_once(
                    realm_id,
                    digest,
                    payload.epoch,
                    Some(snapshot.epoch),
                    &format!("device snapshot secret unavailable: {error}"),
                );
            }
            return None;
        }
    };
    // COR-04: read/decrypt path — floor 0 is intentional. The live receive ratchet
    // and the tier-3 history fallback legitimately read PRE-join / older epochs, so
    // an epoch-floor reject here would break decryption of granted history. No
    // ratchet advance / persist happens on this path.
    let mut group = match crate::mls::persistence::restore_envelope(&snapshot, &secret, 0) {
        Ok(group) => group,
        Err(error) => {
            if circle.is_none() && !sidecar_scoped {
                warn_mls_decrypt_once(
                    realm_id,
                    digest,
                    payload.epoch,
                    Some(snapshot.epoch),
                    &format!("restore local MLS snapshot: {error}"),
                );
            }
            return None;
        }
    };
    let plaintext = match group.decrypt_payload(payload) {
        Ok(plaintext) => plaintext,
        Err(live_error) => {
            // §2.10 exporter-aead content at our CURRENT epoch: the live ratchet
            // cannot open it (it is not an MLS PrivateMessage), but every member
            // at epoch N can derive `history_secret[N]` directly from the group.
            // Do so and open it — this keeps post-join content readable once a
            // Realm uses the exporter-aead content scheme, without depending on a
            // prior retain or a `ak.realm_key.share`. Past-epoch / pre-join
            // content (epoch != current) still needs a retained or granted
            // secret, handled by the group-free standalone path below.
            if payload.scheme == arkret_sdk::EncryptedPayloadScheme::MlsExporterAeadV1
                && snapshot.epoch == payload.epoch
                && let Ok(secret) = group.derive_and_retain_history_secret(realm_id)
                && let Some(key_ref) = payload.key_ref.as_ref()
                && let Some(payload_aad) = payload.aad.as_ref()
                && payload.purpose.as_deref()
                    == Some(arkret_sdk::mls::MLS_EXPORTER_AEAD_CONTENT_PURPOSE)
                && payload_aad.realm_id.as_str() == realm_id
                && key_ref
                    == &arkret_sdk::KeyRefObject::mls_exporter_aead(
                        payload.group_id.clone(),
                        payload.epoch,
                    )
                && let Ok(nonce_and_ct) =
                    arkret_sdk::base64url_decode(payload.ciphertext.as_bytes())
                && payload.verify_mls_payload_digest(&nonce_and_ct).is_ok()
                && let Ok(plaintext) = group.decrypt_content_exporter_aead(
                    &secret,
                    key_ref,
                    payload.epoch,
                    &nonce_and_ct,
                    payload_aad,
                )
            {
                return Some(plaintext);
            }
            // Tier-3 history decrypt: the live receive ratchet cannot open this
            // (pre-join epoch, or another device's content this group can't
            // ratchet to). Fall back to any granted `history_secret` for the
            // payload's epoch and decrypt it as `mls_exporter_aead_v1` content.
            // This is group-free, so it works whether or not the snapshot could
            // ratchet to the payload's epoch.
            let plaintext = (!sidecar_scoped && circle.is_none())
                .then(|| try_history_decrypt_standalone(state_store, realm_id, payload))
                .flatten();
            if plaintext.is_none() && circle.is_none() && !sidecar_scoped {
                warn_mls_decrypt_once(
                    realm_id,
                    digest,
                    payload.epoch,
                    Some(snapshot.epoch),
                    &format!(
                        "live MLS decrypt failed ({live_error}); no granted history secret opened the payload"
                    ),
                );
            }
            return plaintext;
        }
    };
    // §5.6 MUST: persist the advanced receive chain. A failure to export /
    // serialize the post-decrypt state is NOT a soft failure we may swallow
    // silently — without the write-back the consumed message key would make
    // this very plaintext unrecoverable after restart. Latch a loud error and
    // fail closed without exposing or caching the plaintext.
    let advanced = export_receive_chain_envelope(&group, realm_id, &secret, &snapshot);
    match advanced {
        Ok(envelope) => {
            state_store.advance_mls_receive_chain_for_scope(
                effective_scope,
                envelope,
                digest,
                &plaintext,
            );
        }
        Err(err) => {
            if circle.is_none() {
                tracing::error!(
                    %realm_id,
                    error = %err.user_message(),
                    "MLS receive-chain write-back failed after successful decrypt \
                     (spec §5.6 violation risk: message may be unreadable after restart)",
                );
            } else {
                tracing::error!(
                    "Circle-scoped MLS receive-chain write-back failed after successful decrypt"
                );
            }
            return None;
        }
    }
    Some(plaintext)
}

/// SPI-INK-001 — resolve the locally verified MLS group state into the
/// §2.10.3 minimal-metadata author view for `(group_id, epoch,
/// group_state_ref)`. The ONLY trust anchor is the local snapshot the device
/// verified through its own genesis / commit chain — no directory, no
/// `keys/query`, no current-epoch fallback. The cited `group_state_ref` must
/// equal the exact accepted genesis / winning commit Event recorded locally
/// for this group and epoch.
#[allow(clippy::too_many_arguments)]
pub fn minimal_metadata_author_view(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    group_id: &str,
    epoch: u64,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::AuthorGroupStateView> {
    let snapshot = state_store
        .mls_snapshot_for(realm_id)
        .filter(|snapshot| snapshot.epoch == epoch && snapshot.group_id == group_id)
        .or_else(|| {
            state_store.historical_mls_snapshot_for_effective_scope(realm_id, None, group_id, epoch)
        })?;
    let accepted_ref = state_store
        .mls_group_state_ref_for_effective_scope(realm_id, None, group_id, epoch)
        .ok()?;
    if accepted_ref.as_str() != group_state_ref {
        return None;
    }
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id).ok()?;
    // COR-04: read-only restore — no ratchet advance / persist on this path.
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    if group.group_id() != group_id || group.epoch() != epoch {
        return None;
    }
    Some(group.author_group_state_view(group_state_ref))
}

#[allow(clippy::too_many_arguments)]
pub fn ordinary_agent_mls_author_view(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    group_id: &str,
    epoch: u64,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::AgentMlsSignerView> {
    let group_state = minimal_metadata_author_view(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
        group_id,
        epoch,
        group_state_ref,
    )?;
    let mut leaf_authorization_refs = Vec::new();
    for leaf in &group_state.active_leaves {
        let arkret_sdk::mls::AuthorLeafCredential::Basic { identity } = &leaf.credential else {
            continue;
        };
        let Ok(identity) = std::str::from_utf8(identity) else {
            continue;
        };
        let Ok(signer_id) = arkret_sdk::Did::new(identity.to_owned()) else {
            continue;
        };
        let Ok(signer_core) = arkret_sdk::project_full_id_to_core_id(&signer_id) else {
            continue;
        };
        let signer_actor = arkret_sdk::ActorId::from(signer_core);
        for entry in state_store.cached_agent_signer_evidence_for_agent(&signer_actor) {
            let binding = match &entry.evidence {
                arkret_sdk::AgentSignerEvidence::CurrentAdmission {
                    admission_evidence, ..
                }
                | arkret_sdk::AgentSignerEvidence::HistoricalEvent {
                    admission_evidence, ..
                } => {
                    &admission_evidence
                        .agent_authority_snapshot
                        .core
                        .signing_key_binding
                }
            };
            let Ok(key) = arkret_sdk::base64url_decode(binding.public_key.key.as_str().as_bytes())
            else {
                continue;
            };
            if key == leaf.signature_key {
                leaf_authorization_refs.push((
                    leaf.leaf_index,
                    binding.agent_key_authorize_event_id.clone(),
                ));
            }
        }
    }
    leaf_authorization_refs.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.as_str().cmp(right.1.as_str()))
    });
    leaf_authorization_refs.dedup();
    Some(arkret_sdk::mls::AgentMlsSignerView {
        group_state,
        leaf_authorization_refs,
    })
}

/// Tier-3 history decrypt: use the exact granted `history_secret` named by an
/// `mls_exporter_aead_v1` payload. The provider binds the payload's typed AAD,
/// key reference and epoch into the immutable AEAD header. A malformed payload
/// or missing exact-epoch secret returns `None`; this path never scans other
/// epoch keys. Does NOT touch the receive ratchet.
///
/// Group-free: uses the SDK's
/// [`arkret_sdk::mls::decrypt_content_exporter_aead_standalone`] so a device
/// that holds the granted `history_secret` but has **no** local MLS snapshot
/// for the Realm (e.g. a member granted history before processing its own
/// Welcome) can still read pre-join content.
fn try_history_decrypt_standalone(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    payload: &arkret_sdk::EncryptedPayload,
) -> Option<Vec<u8>> {
    if payload.scheme != arkret_sdk::EncryptedPayloadScheme::MlsExporterAeadV1
        || payload.group_id.trim().is_empty()
        || payload.purpose.as_deref() != Some(arkret_sdk::mls::MLS_EXPORTER_AEAD_CONTENT_PURPOSE)
    {
        return None;
    }
    let nonce_and_ct = arkret_sdk::base64url_decode(payload.ciphertext.as_bytes()).ok()?;
    payload.verify_mls_payload_digest(&nonce_and_ct).ok()?;
    let key_ref = payload.key_ref.as_ref()?;
    if key_ref
        != &arkret_sdk::KeyRefObject::mls_exporter_aead(payload.group_id.clone(), payload.epoch)
    {
        return None;
    }
    let aad = payload.aad.as_ref()?;
    if aad.realm_id.as_str() != realm_id {
        return None;
    }
    // There is no local group snapshot on this path, so the suite has to come
    // from the envelope. `encryption-and-audit.md` §2.10.2 requires the producer
    // to carry it; a payload without it is not decryptable here rather than
    // decryptable under a guessed suite.
    let aead_profile = payload.aead_profile.as_deref()?;
    let secret = state_store.history_secret_for(realm_id, payload.epoch)?;
    arkret_sdk::mls::decrypt_content_exporter_aead_standalone(
        &secret,
        key_ref,
        payload.epoch,
        aead_profile,
        &nonce_and_ct,
        aad,
    )
    .ok()
}

/// Provider-side: derive + retain the **current** epoch `history_secret` for a
/// Realm and persist it locally, so this device can later seal it into a
/// `ak.realm_key.share` for a late joiner (`encryption-and-audit.md` history
/// sharing). MUST be called while the group is at the epoch whose key is being
/// retained (OpenMLS only exports the current epoch). Returns
/// `(epoch, history_secret)` on success.
///
/// Persisting into the provider's own `history_secrets` lets a past epoch's key
/// survive an app restart (OpenMLS could not re-derive it once the group has
/// advanced past that epoch).
type RetainedRealmHistorySecret = (
    u64,
    zeroize::Zeroizing<Vec<u8>>,
    crate::state::PendingHistorySecrets,
);

pub(crate) fn derive_and_retain_realm_history_secret(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<RetainedRealmHistorySecret>, MlsRuntimeError> {
    let Some(snapshot) = state_store.mls_snapshot_for(realm_id) else {
        return Ok(None);
    };
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: read-only export of the CURRENT epoch's history secret — floor 0 is
    // intentional (no ratchet advance / persist; OpenMLS only exports the epoch the
    // snapshot already holds, so a Seal-view floor would add no safety here).
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|error| MlsRuntimeError::SnapshotRestore(error.to_string()))?;
    let epoch = snapshot.epoch;
    let history_secret = group
        .derive_and_retain_history_secret(realm_id)
        .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
    if history_secret.is_empty() {
        return Ok(None);
    }
    let Some(pending) = state_store
        .prepare_history_secrets(
            secure_store,
            realm_id.to_owned(),
            [(epoch, history_secret.to_vec())],
        )
        .map_err(MlsRuntimeError::DeviceSecret)?
    else {
        return Ok(None);
    };
    Ok(Some((epoch, history_secret, pending)))
}

fn realm_key_share_payload_candidate(value: &serde_json::Value) -> Option<&serde_json::Value> {
    value
        .get("key_scope")
        .is_some()
        .then_some(value)
        .filter(|candidate| {
            candidate.get("recipient_principal_id").is_some()
                || candidate.get("ciphertext").is_some()
                || candidate.get("share_kind").is_some()
        })
}

fn realm_key_share_payload_value(envelope: &serde_json::Value) -> Option<&serde_json::Value> {
    envelope
        .get("payload")
        .and_then(realm_key_share_payload_candidate)
        .or_else(|| {
            envelope
                .get("payload")
                .and_then(|payload| payload.get("content"))
                .and_then(realm_key_share_payload_candidate)
        })
        // soland's durable to-device projection (sync `to_device[]` and
        // device-messages) nests the spec payload under `content.payload`,
        // mirroring the request direction handled in
        // `parse_realm_key_request_envelope`.
        .or_else(|| {
            envelope
                .get("content")
                .and_then(|content| content.get("payload"))
                .and_then(realm_key_share_payload_candidate)
        })
        .or_else(|| {
            envelope
                .get("content")
                .and_then(realm_key_share_payload_candidate)
        })
        .or_else(|| realm_key_share_payload_candidate(envelope))
}

/// Extract the Realm named by a `ak.realm_key.share` to-device/event envelope.
/// The spec payload binds it under `key_scope.effective_scope.realm_id`; soland's
/// to-device projection also repeats it at top-level for routing. If both are
/// present they must agree, otherwise the envelope is ignored fail-closed.
pub fn realm_key_share_message_realm_id(envelope: &serde_json::Value) -> Option<String> {
    let payload_realm = realm_key_share_payload_value(envelope)
        .and_then(|payload| payload.get("key_scope"))
        .and_then(|scope| scope.get("effective_scope"))
        .and_then(|scope| scope.get("realm_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let top_realm = envelope
        .get("realm_id")
        .or_else(|| {
            envelope
                .get("content")
                .and_then(|content| content.get("realm_id"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match (payload_realm, top_realm) {
        (Some(scope), Some(top)) if scope != top => None,
        (Some(scope), _) => Some(scope.to_owned()),
        (None, Some(top)) => Some(top.to_owned()),
        (None, None) => None,
    }
}

/// Stable source Event identifier for a projected `ak.realm_key.share`, when
/// present. Used only for local inbox dismissal after successful install.
pub fn realm_key_share_message_operation_id(envelope: &serde_json::Value) -> Option<String> {
    envelope
        .get("operation_id")
        .or_else(|| envelope.get("event_id"))
        .or_else(|| {
            envelope
                .get("payload")
                .and_then(|payload| payload.get("operation_id"))
        })
        .or_else(|| {
            envelope
                .get("payload")
                .and_then(|payload| payload.get("event_id"))
        })
        .or_else(|| {
            envelope
                .get("content")
                .and_then(|content| content.get("operation_id"))
        })
        .or_else(|| {
            envelope
                .get("content")
                .and_then(|content| content.get("event_id"))
        })
        .or_else(|| {
            envelope
                .get("unsigned")
                .and_then(|unsigned| unsigned.get("source_event_id"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// Filter a to-device inbox / device-messages batch down to the
/// `ak.realm_key.share` envelopes addressed at this Realm. The discriminator is
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
                == Some(arkret_sdk::EventKind::RealmKeyShare.as_str())
        })
        .filter(|message| realm_key_share_message_realm_id(message).as_deref() == Some(realm_id))
        .cloned()
        .collect()
}

/// Open one inbound `ak.realm_key.share` with this device's HPKE private key and
/// install every recovered `(epoch, history_secret)` into local state, so the
/// tier-3 decrypt path can read pre-join content. Returns the number of secrets
/// installed (0 when the share is not for this device / does not open / carries
/// no ciphertext). The share `ciphertext` is the
/// `base64url(eph_pub || ct)` blob produced by
/// [`crate::mls::secret_share::seal_history_secret_to_device_pubkey`].
pub(crate) fn ingest_realm_key_share(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    share_envelope: &serde_json::Value,
) -> Result<Vec<crate::state::PendingHistorySecrets>, MlsRuntimeError> {
    let content = realm_key_share_payload_value(share_envelope)
        .or_else(|| share_envelope.get("payload"))
        .unwrap_or(share_envelope);
    let payload: arkret_sdk::RealmKeySharePayload = match serde_json::from_value(content.clone()) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::debug!(%realm_id, error = %err, "skip malformed ak.realm_key.share");
            return Ok(Vec::new());
        }
    };
    let Some(expected_authorization_ref) =
        crate::views::realm_admin::realm_history_share_source_authorization_ref(
            state_store,
            realm_id,
        )
    else {
        tracing::debug!(%realm_id, "defer ak.realm_key.share: history policy unavailable");
        return Ok(Vec::new());
    };
    if payload.source_authorization_ref.as_str() != expected_authorization_ref {
        tracing::debug!(%realm_id, "reject ak.realm_key.share: source authorization mismatch");
        return Ok(Vec::new());
    }
    // Only consume member_device shares addressed to THIS device (the seal opens
    // only with this device's HPKE private key anyway, but check the routing
    // first). RRK shares (share_kind=realm_recovery_key) carry no
    // recipient_device_id and are not consumed here.
    let arkret_sdk::RealmKeyShareTarget::MemberDevice {
        ref recipient_device_id,
    } = payload.target
    else {
        return Ok(Vec::new());
    };
    if recipient_device_id.as_str().trim() != device_id.trim() {
        return Ok(Vec::new());
    }
    // SEC-02 / device-lifecycle.md §13: sender-device authentication. When the
    // share carries a sender principal, the sender device must sign the share;
    // a revoked/absent device is rejected, and a cache miss after prefetch still
    // fails closed for empty signatures.
    let sender_principal_id = realm_key_share_sender_principal_id(share_envelope);
    if !verify_realm_key_share_sender_signature(&payload, sender_principal_id.as_deref()) {
        tracing::debug!(%realm_id, "reject ak.realm_key.share: sender_device_signature failed");
        return Ok(Vec::new());
    }
    let arkret_sdk::RealmKeyShareMaterial::Ciphertext { ref ciphertext } = payload.material else {
        return Ok(Vec::new());
    };
    let sealed = ciphertext.as_str();
    if sealed.trim().is_empty() {
        return Ok(Vec::new());
    }
    let privkey = match super::load_device_hpke_private_key(secure_store, actor_id, device_id) {
        Ok(Some(privkey)) => privkey,
        Ok(None) => {
            tracing::debug!(%realm_id, "no device HPKE key to open ak.realm_key.share");
            return Ok(Vec::new());
        }
        Err(err) => {
            tracing::debug!(%realm_id, error = %err, "load device HPKE key failed");
            return Ok(Vec::new());
        }
    };
    let secrets = match arkret_crypto::secret_share::open_history_secret_with_device_privkey(
        &privkey, sealed,
    ) {
        Ok(secrets) => secrets,
        Err(err) => {
            tracing::debug!(%realm_id, error = %err, "open ak.realm_key.share failed");
            return Ok(Vec::new());
        }
    };
    let pending = state_store
        .prepare_history_secrets(secure_store, realm_id.to_owned(), secrets)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    Ok(pending.into_iter().collect())
}

/// Extract the sender's principal DID from a `ak.realm_key.share` to-device
/// envelope so [`verify_realm_key_share_sender_signature`] can bind the signing
/// key to the sender's device-directory record.
fn realm_key_share_sender_principal_id(envelope: &serde_json::Value) -> Option<String> {
    envelope
        .get("sender_principal_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// SEC-02: derive the `(sender_principal_id, sender_device_id)` directory pair
/// for a `ak.realm_key.share` to-device envelope. Callers prime the
/// device-directory cache with this pair (a `keys/query`) before
/// [`ingest_realm_key_share`] runs, so the synchronous
/// [`verify_realm_key_share_sender_signature`] can fail-closed on a directory
/// Miss instead of tolerating an unauthenticated empty signature. Returns
/// `None` when the envelope exposes no sender principal or no sender device id.
pub fn realm_key_share_sender_device_pair(
    envelope: &serde_json::Value,
) -> Option<(String, String)> {
    let principal = realm_key_share_sender_principal_id(envelope)?;
    let payload = realm_key_share_payload_value(envelope);
    let device_id = envelope
        .get("sender_device_id")
        .or_else(|| {
            envelope
                .get("payload")
                .and_then(|payload| payload.get("sender_device_id"))
        })
        .or_else(|| payload.and_then(|payload| payload.get("sender_device_id")))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_owned();
    Some((principal, device_id))
}

/// Verify a `ak.realm_key.share` payload's `sender_device_signature`
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
///   a populated signature must verify under its own embedded key; an empty signature is
///   **rejected** (SEC-02 fail-closed — the prior fail-open window that tolerated an
///   unauthenticated empty signature on Miss is closed). The per-secret HPKE seal remains the
///   confidentiality/integrity gate.
/// - **No sender principal at all**: the share cannot impersonate any actor, so an empty signature
///   is tolerated and a populated one is verified under its embedded key (HPKE seal gates the
///   payload).
pub(crate) fn verify_realm_key_share_sender_signature(
    payload: &arkret_sdk::RealmKeySharePayload,
    sender_principal_id: Option<&str>,
) -> bool {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let sig_obj = match &payload.sender_device_signature {
        arkret_sdk::SignatureMaterial::Variant1(fields) => fields,
        arkret_sdk::SignatureMaterial::NonEmptyString(_) => return false,
    };
    let is_empty = sig_obj.is_empty() || !sig_obj.contains_key("signature");

    // Resolve the sender device's authoritative directory key (sync, cache-only).
    // The caller (`app::history-share` install loop) primes this cache with a
    // `keys/query` for the sender device BEFORE this verifier runs, so a Miss
    // here means directory resolution genuinely failed for a claimed sender.
    let directory_key = sender_principal_id.map(|principal| {
        match crate::identity::device_directory::cached_device_signing_key(
            principal,
            payload.sender_device_id.as_str(),
        ) {
            crate::identity::device_directory::CacheLookup::Hit(material) => {
                DirectoryVerdict::Key(material)
            }
            crate::identity::device_directory::CacheLookup::NegativeHit => {
                DirectoryVerdict::Revoked
            }
            crate::identity::device_directory::CacheLookup::Miss => DirectoryVerdict::Unresolved,
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
    let Ok(pubkey_bytes) = arkret_sdk::decode_ed25519_multibase(pubkey_multibase) else {
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
    let Ok(sig_bytes) = arkret_sdk::base64url_decode(sig_b64.as_bytes()) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_bytes) else {
        return false;
    };
    // Fail closed when the transcript cannot be rebuilt: verifying against
    // empty bytes would accept a signature over nothing.
    let Ok(signing_input) = payload.sender_signing_input() else {
        return false;
    };
    verifying_key.verify(&signing_input, &signature).is_ok()
}

/// Outcome of a synchronous device-directory lookup for the realm-key-share
/// sender device.
enum DirectoryVerdict {
    /// A trusted authoritative verify key is cached.
    Key(arkret_sdk::signatures::PublicKeyMaterial),
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
    state_store: &crate::state::LocalStateStore,
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
    group: &arkret_sdk::ArkretMlsGroup,
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

fn welcome_entry_event_id(entry: &serde_json::Value) -> Option<String> {
    entry
        .get("unsigned")
        .and_then(|unsigned| unsigned.get("source_event_id"))
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
            == Some("ak.mls.welcome")
            && let Some(content) = entry.get("content")
        {
            welcomes.push(WelcomeMessageEntry {
                content: content.clone(),
                key_package_id: welcome_entry_key_package_id(entry),
                welcome_event_id: welcome_entry_event_id(entry),
            });
        }
    }
    welcomes
}

fn welcome_consume_candidate(
    entry: &WelcomeMessageEntry,
    realm_id: &str,
) -> Option<WelcomeConsumeCandidate> {
    let payload =
        serde_json::from_value::<arkret_sdk::MlsWelcomePayload>(entry.content.clone()).ok()?;
    let (strand_id, repair_target_keypackage_ref) = match &payload.claim_receipt {
        arkret_sdk::MlsWelcomeClaimReceipt::SelfClaim(receipt) => (
            receipt.request.strand_id.as_ref().map(ToString::to_string),
            None,
        ),
        arkret_sdk::MlsWelcomeClaimReceipt::PeerClaim(receipt) => {
            let repair_target = if receipt.request.claim_purpose
                == arkret_sdk::PeerKeyPackageClaimPurpose::DirectConversationRepair
            {
                let target = receipt.request.target_keypackage_ref.as_ref()?;
                if target.as_str() != payload.keypackage_ref.as_str() {
                    return None;
                }
                Some(target.as_str().to_owned())
            } else {
                None
            };
            (
                receipt.request.strand_id.as_ref().map(ToString::to_string),
                repair_target,
            )
        }
    };
    Some(WelcomeConsumeCandidate {
        key_package_id: entry.key_package_id.clone()?,
        claim_id: payload.claim_id.as_str().to_owned(),
        welcome_event_id: entry.welcome_event_id.clone()?,
        realm_id: realm_id.to_owned(),
        strand_id,
        mls_group_id: payload.mls_group_id.as_str().to_owned(),
        epoch: payload.epoch,
        welcome_digest: payload.claim_envelope.welcome_digest,
        repair_target_keypackage_ref,
    })
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
    arkret_sdk::base64url_encode(realm_id.trim().as_bytes())
}

pub fn mls_welcome_message_matches_realm(message: &serde_json::Value, realm_id: &str) -> bool {
    if message
        .get("kind")
        .or_else(|| message.get("type"))
        .and_then(|t| t.as_str())
        != Some("ak.mls.welcome")
    {
        return false;
    }
    let expected_group_id = mls_group_id_for_realm(realm_id);
    message
        .get("content")
        .and_then(|content| {
            content
                .get("group_id")
                .or_else(|| content.get("mls_group_id"))
        })
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

pub(super) fn durable_welcome_payload_reject_reason(value: &serde_json::Value) -> Option<String> {
    let looks_like_durable_payload = value.get("claim_ref").is_some()
        || value.get("claim_id").is_some()
        || value.get("keypackage_digest").is_some()
        || value.get("keypackage_ref").is_some();
    if !looks_like_durable_payload {
        return None;
    }
    serde_json::from_value::<arkret_sdk::MlsWelcomePayload>(value.clone())
        .err()
        .map(|error| {
            format!(
                "{}: {error}",
                arkret_sdk::error::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH
            )
        })
}

pub(super) fn durable_welcome_wire_payload(value: &serde_json::Value) -> serde_json::Value {
    let mut wire_payload = value.clone();
    if let Some(object) = wire_payload.as_object_mut() {
        for field in [
            "event_id",
            "sender",
            "hlc",
            "executed_by",
            "authorization_ref",
            "seal_ref",
            "seal_basis",
            "preconditions",
            "effects",
            "accepted_event_id",
        ] {
            object.remove(field);
        }
    }
    wire_payload
}

fn decode_welcome_envelope(
    value: &serde_json::Value,
) -> Result<arkret_sdk::MlsWelcomeEnvelope, String> {
    if value.get("mls_group_id").is_none() {
        return serde_json::from_value(value.clone())
            .map_err(|error| format!("welcome envelope parse: {error}"));
    }
    let durable: arkret_sdk::MlsWelcomePayload = serde_json::from_value(value.clone())
        .map_err(|error| format!("durable Welcome payload parse: {error}"))?;
    let ciphertext = durable
        .carrier
        .ciphertext()
        .ok_or_else(|| "durable Welcome payload has no inline ciphertext".to_owned())?
        .to_owned();
    let welcome_bytes = arkret_sdk::base64url_decode(ciphertext.as_bytes())
        .map_err(|error| format!("durable Welcome ciphertext decode: {error}"))?;
    let welcome_hash = arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&welcome_bytes))
        .map_err(|error| format!("durable Welcome digest: {error}"))?;
    if welcome_hash != durable.claim_envelope.welcome_digest {
        return Err(
            "durable Welcome ciphertext differs from claim_envelope.welcome_digest".to_owned(),
        );
    }
    let recipient_device_id = match durable.recipient {
        arkret_sdk::MlsWelcomeRecipient::Device {
            recipient_device_id,
        } => recipient_device_id,
        arkret_sdk::MlsWelcomeRecipient::NativeAgent { .. } => {
            return Err(
                "Native Agent Welcome cannot be mapped to an ak:device recipient; the Agent runtime endpoint must consume it through the Native Agent branch"
                    .to_owned(),
            );
        }
    };
    let recipient_full_id = arkret_sdk::FullId::new(
        crate::event_signer::active_signer()
            .ok_or_else(|| "active recipient signer is unavailable".to_owned())?
            .signer_did()
            .to_owned(),
    )
    .map_err(|error| format!("active recipient full_id is invalid: {error}"))?;
    if arkret_sdk::project_full_id_to_core_id(&recipient_full_id)
        .map_err(|error| format!("project active recipient full_id: {error}"))?
        != durable.recipient_principal_id
    {
        return Err("active recipient full_id does not match durable Welcome recipient".to_owned());
    }
    Ok(arkret_sdk::MlsWelcomeEnvelope {
        group_id: durable.mls_group_id.as_str().to_owned(),
        epoch: durable.epoch,
        recipient_principal_id: recipient_full_id,
        recipient_device_id,
        welcome: ciphertext,
        welcome_hash,
        ratchet_tree: None,
    })
}

/// YGN-SEC-01 gate (1): before accepting an inbound Welcome, independently
/// verify the sender signature on its `claim_envelope` (`encryption-and-audit.md`
/// admin send gate; `admission.rs` signs it with `sign_welcome_claim_envelope`).
///
/// Fail-closed semantics:
/// - If `welcome_value` carries `claim_envelope`, the signature must verify. Malformed shape,
///   unresolved verification key, or a mismatched signature returns `Err(reason)`, the caller
///   records the failure, and the Welcome is rejected before it can add this device to the group.
/// - The verification key is resolved through `device_directory` (the sync cache warmed by
///   `prefetch_device_keys` during bootstrap), never from the envelope's self-declared `kid` or
///   `requester_did`.
///
/// Returns `Ok(())` only when either the Welcome contains no `claim_envelope`
/// (a reduced routing+ciphertext Welcome with no material to verify, covered by
/// the governance-binding gate and the server admin gate) or it carries a
/// directory-resolved device signature that verifies.
fn verify_welcome_claim_envelope_signer(welcome_value: &serde_json::Value) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let Some(claim_value) = welcome_value.get("claim_envelope") else {
        // No verifiable claim_envelope is present on this reduced Welcome. This
        // does not grant authorization; the epoch/Seal binding is enforced by
        // governance-binding gate (2), with the server admission admin gate as
        // an additional layer.
        return Ok(());
    };
    let envelope: arkret_sdk::MlsWelcomeClaimEnvelope = serde_json::from_value(claim_value.clone())
        .map_err(|err| format!("claim_envelope decode: {err}"))?;
    // Shape validation: non-empty kid/sig and alg in {Ed25519, Ed25519}.
    envelope
        .validate_signature_shape()
        .map_err(|reason| format!("claim_envelope signature shape: {reason}"))?;

    let (requester_full_id, requester_device_id, requester_authorize_event_id) = match &envelope
        .trust_binding
    {
        arkret_sdk::MlsRequesterTrustBinding::RequesterDevice {
            requester_device_id,
            requester_device_authorize_event_id,
        } => {
            let controller = envelope
                .signature
                .kid
                .as_str()
                .split_once('#')
                .map(|(controller, _)| controller)
                .ok_or_else(|| {
                    "claim_envelope device signature kid has no DID URL fragment".to_owned()
                })?;
            let full_id = arkret_sdk::FullId::new(controller.to_owned())
                .map_err(|error| format!("claim_envelope requester FullId: {error}"))?;
            let projected = arkret_sdk::project_full_id_to_core_id(&full_id)
                .map_err(|error| format!("claim_envelope requester CoreId projection: {error}"))?;
            if projected != envelope.requester_did {
                return Err(
                    "claim_envelope signature controller does not project to requester core id"
                        .to_owned(),
                );
            }
            (
                full_id,
                requester_device_id,
                requester_device_authorize_event_id,
            )
        }
        arkret_sdk::MlsRequesterTrustBinding::RequesterNativeAgent { .. } => {
            return Err(
                    "Native Agent claim_envelope verification is unavailable until current AgentSignerEvidence observation is normatively bound to this Welcome"
                        .to_owned(),
                );
        }
    };
    let requester_full_id = requester_full_id.as_str();
    let requester_device_id = requester_device_id.as_str();
    if crate::identity::device_directory::cached_device_authorize_event_id(
        requester_full_id,
        requester_device_id,
    )
    .as_ref()
        != Some(requester_authorize_event_id)
    {
        return Err(format!(
            "claim_envelope device authorization is not the current accepted Event for {requester_full_id}/{requester_device_id}"
        ));
    }
    let verifying_key = match crate::identity::device_directory::cached_device_signing_key(
        requester_full_id,
        requester_device_id,
    ) {
        crate::identity::device_directory::CacheLookup::Hit(material) => {
            let bytes = material.ed25519_bytes().map_err(|err| {
                format!("claim_envelope signer key decode ({requester_full_id}/{requester_device_id}): {err}")
            })?;
            VerifyingKey::from_bytes(&bytes).map_err(|err| {
                format!("claim_envelope signer key invalid ({requester_full_id}/{requester_device_id}): {err}")
            })?
        }
        crate::identity::device_directory::CacheLookup::NegativeHit => {
            return Err(format!(
                "claim_envelope signer {requester_full_id}/{requester_device_id} is revoked / \
                 absent in directory (negative verdict); Welcome rejected (YGN-SEC-01)"
            ));
        }
        crate::identity::device_directory::CacheLookup::Miss => {
            return Err(format!(
                "claim_envelope signer key for {requester_full_id}/{requester_device_id} not in \
                 device-directory cache; fail-closed (YGN-SEC-01)"
            ));
        }
    };

    let signing_bytes = envelope
        .canonical_signing_bytes()
        .map_err(|err| format!("claim_envelope canonical bytes: {err}"))?;
    let sig_bytes = arkret_sdk::base64url_decode(envelope.signature.sig.as_bytes())
        .map_err(|err| format!("claim_envelope signature decode: {err}"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|err| format!("claim_envelope signature malformed: {err}"))?;
    verifying_key
        .verify(&signing_bytes, &signature)
        .map_err(|err| format!("claim_envelope signature verification failed: {err}"))?;
    Ok(())
}

/// YGN-SEC-01 gate (2): before persisting the snapshot, independently verify
/// the Welcome's embedded `governance_binding` (`encryption-and-audit.md`:438:
/// clients MUST independently verify the referenced Seal view and state_root
/// before accepting an MLS epoch).
///
/// The MLS group's embedded governance-binding extension must exactly match the
/// durable payload forwarded by the server. The Welcome-declared group, epochs,
/// binding/reducer profiles, Security Frontier digest, and active leaf set build
/// the expected context passed to
/// `ArkretMlsGroup::verify_current_governance_binding`. Any field mismatch or
/// missing MLS binding extension returns `Err` and rejects the Welcome.
///
/// A missing binding, missing full-profile roots, or absence of a locally
/// verifiable accepted-Seal proof bundle is a hard `state_mismatch`. The caller
/// records the Welcome as failed/decryption-pending and MUST NOT persist the
/// joined snapshot. Server admission and claim signatures are defense in depth,
/// not substitutes for the independent proof required by §2.5.1.
fn verify_welcome_governance_binding(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    group: &arkret_sdk::ArkretMlsGroup,
    welcome_value: &serde_json::Value,
) -> Result<(), String> {
    let binding_value = welcome_value.get("governance_binding").ok_or_else(|| {
        "governance_binding missing; epoch remains decryption_pending (state_mismatch)".to_owned()
    })?;
    let binding: arkret_sdk::MlsGovernanceBindingPayload =
        serde_json::from_value(binding_value.clone())
            .map_err(|error| format!("governance_binding decode: {error}"))?;
    binding
        .validate()
        .map_err(|error| format!("governance_binding validation: {error}"))?;
    if binding.realm_id().as_str() != realm_id {
        return Err("governance_binding Realm differs from the receiving Realm".to_owned());
    }
    let current = group
        .current_governance_binding()
        .map_err(|error| format!("read MLS GroupContext governance_binding: {error}"))?;
    if current.as_ref() != Some(&binding) {
        return Err(
            "MLS GroupContext governance_binding differs from the durable Welcome payload"
                .to_owned(),
        );
    }
    let request = crate::mls::governance_proof::proof_request_for_scope(
        state_store,
        binding.effective_scope().clone(),
        binding.mls_group_id(),
        binding.previous_epoch(),
        binding.next_epoch(),
    )?;
    let verified = crate::mls::governance_proof::cached_verified_binding(state_store, &request)?;
    if verified != binding {
        return Err(
            "durable Welcome governance binding differs from the locally verified Seal proof"
                .to_owned(),
        );
    }
    Ok(())
}

pub(crate) struct WelcomeSecurityFrontierPreview {
    pub binding: arkret_sdk::MlsGovernanceBindingPayload,
    pub leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
}

/// Join each durable Welcome in an isolated in-memory provider so the proof
/// verifier can use the transcript-authenticated post-Commit leaf set before
/// any snapshot is persisted.
pub(crate) fn preview_welcome_security_frontiers(
    secure_store: &dyn SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    messages_value: &serde_json::Value,
) -> Result<Vec<WelcomeSecurityFrontierPreview>, String> {
    let principal_did = arkret_sdk::Did::new(actor_id.to_owned())
        .map_err(|error| format!("preview Welcome principal: {error}"))?;
    let device_id_typed = arkret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|error| format!("preview Welcome device: {error}"))?;
    let mut previews = Vec::new();
    for entry in collect_welcome_message_entries(messages_value) {
        let payload = durable_welcome_wire_payload(&entry.content);
        let binding_value = payload
            .get("governance_binding")
            .ok_or_else(|| "durable MLS Welcome omits governance_binding".to_owned())?;
        let binding: arkret_sdk::MlsGovernanceBindingPayload =
            serde_json::from_value(binding_value.clone())
                .map_err(|error| format!("decode Welcome governance_binding: {error}"))?;
        let welcome = decode_welcome_envelope(&payload)?;
        let key_package_id = entry
            .key_package_id
            .as_deref()
            .ok_or_else(|| "Welcome carries no key_package_id".to_owned())?;
        let serialized_state = load_mls_key_package_identity_state(
            secure_store,
            actor_id,
            device_id,
            key_package_id,
        )
        .map_err(|error| format!("load Welcome KeyPackage state: {error}"))?
        .ok_or_else(|| {
            format!(
                "no local KeyPackage identity state for welcome key_package_id={key_package_id}"
            )
        })?;
        let identity = arkret_sdk::ArkretMlsIdentity::restore_from_private_state(
            principal_did.clone(),
            device_id_typed.clone(),
            &serialized_state,
        )
        .map_err(|error| format!("restore Welcome KeyPackage identity: {error}"))?;
        let group = arkret_sdk::ArkretMlsGroup::join_from_welcome(identity, &welcome)
            .map_err(|error| format!("preview Welcome group: {error}"))?;
        let embedded = group
            .current_governance_binding()
            .map_err(|error| format!("read preview governance binding: {error}"))?;
        if embedded.as_ref() != Some(&binding) {
            return Err(
                "MLS GroupContext governance_binding differs from durable Welcome payload"
                    .to_owned(),
            );
        }
        previews.push(WelcomeSecurityFrontierPreview {
            binding,
            leaves: group
                .security_frontier_leaves()
                .map_err(|error| format!("derive Welcome MLS leaf set: {error}"))?,
        });
    }
    Ok(previews)
}

pub fn apply_welcome_messages_with_device_snapshot(
    state_store: &mut crate::state::LocalStateStore,
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
    let principal_did = arkret_sdk::Did::new(actor_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let device_id_typed = arkret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    // Per-welcome failures no longer abort the loop or get swallowed: each is
    // counted and the first reason retained so callers can report partial
    // success without failing the whole boot.
    let mut outcome = WelcomeApplyOutcome::default();
    for welcome_entry in welcome_entries {
        let welcome_value = durable_welcome_wire_payload(&welcome_entry.content);
        if let Some(reason) = durable_welcome_payload_reject_reason(&welcome_value) {
            outcome.record_failure(format!("welcome claim envelope: {reason}"));
            continue;
        }
        // YGN-SEC-01 gate (1): before accepting the Welcome, independently
        // verify the claim_envelope sender signature with a device_directory key
        // and fail closed. This runs before join because signature verification
        // does not depend on MLS-layer decryption.
        if let Err(reason) = verify_welcome_claim_envelope_signer(&welcome_value) {
            outcome.record_failure(format!("welcome claim envelope authz: {reason}"));
            continue;
        }
        // YGN-SEC-01 gate (2) runs after join because it needs the MLS group
        // object. It independently verifies this governance_binding against the
        // MLS GroupContext; keep the raw JSON for that check.
        let welcome_value_for_governance = welcome_value.clone();
        let welcome = match decode_welcome_envelope(&welcome_value) {
            Ok(welcome) => welcome,
            Err(err) => {
                outcome.record_failure(err);
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
                    match arkret_sdk::ArkretMlsIdentity::restore_from_private_state(
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
                        realm = %yoface::utils::text::short_protocol_id(realm_id),
                        actor = %yoface::utils::text::short_protocol_id(actor_id),
                        device = %yoface::utils::text::short_protocol_id(device_id),
                        key_package_id = %yoface::utils::text::short_protocol_id(key_package_id),
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
                    realm = %yoface::utils::text::short_protocol_id(realm_id),
                    "welcome apply: Welcome carries no key_package_id — cannot select the KeyPackage private state to decrypt it"
                );
                outcome.record_failure("welcome carries no key_package_id".to_owned());
                continue;
            }
        };
        let group = match arkret_sdk::ArkretMlsGroup::join_from_welcome(identity, &welcome) {
            Ok(group) => group,
            Err(err) => {
                outcome.record_failure(format!("join welcome: {err}"));
                continue;
            }
        };
        // YGN-SEC-01 gate (2): independently verify that the MLS group's
        // embedded governance_binding matches the durable payload forwarded by
        // the server (`encryption-and-audit.md`:438). Missing binding or
        // profile, epoch, Security Frontier, or leaf-set mismatch rejects the
        // Welcome before snapshot persistence.
        if let Err(reason) = verify_welcome_governance_binding(
            state_store,
            realm_id,
            &group,
            &welcome_value_for_governance,
        ) {
            outcome.record_failure(format!("welcome governance_binding authz: {reason}"));
            continue;
        }
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
        let welcome_binding = welcome_value_for_governance
            .get("governance_binding")
            .cloned()
            .and_then(|value| {
                serde_json::from_value::<arkret_sdk::MlsGovernanceBindingPayload>(value).ok()
            });
        let Some(effective_scope) = welcome_binding
            .as_ref()
            .map(|binding| binding.effective_scope().clone())
        else {
            outcome.record_failure(
                "Welcome governance binding disappeared before persistence".to_owned(),
            );
            continue;
        };
        if let Some(existing) =
            state_store.mls_snapshot_for_scope_and_group(&effective_scope, &post_state.group_id)
            && existing.group_id == post_state.group_id
            && existing.epoch >= post_state.epoch
        {
            outcome.skipped_stale += 1;
            if let Some(candidate) = welcome_consume_candidate(&welcome_entry, realm_id) {
                outcome.consumable_claims.push(candidate);
            }
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
        if let Some(commit_ref) = welcome_value
            .get("commit_ref")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let commit_ref = match arkret_sdk::EventId::new(commit_ref.to_owned()) {
                Ok(commit_ref) => commit_ref,
                Err(error) => {
                    outcome.record_failure(format!(
                        "welcome commit_ref is not a valid Event id: {error}"
                    ));
                    continue;
                }
            };
            if let Err(error) = state_store.record_mls_group_state_ref_for_scope(
                &effective_scope,
                &post_state.group_id,
                post_state.epoch,
                commit_ref,
            ) {
                outcome.record_failure(format!("persist Welcome group-state reference: {error}"));
                continue;
            }
        }
        state_store.save_mls_snapshot_for_scope(&effective_scope, snapshot);
        // Retain the claimed KeyPackage private state until redelivery has
        // quiesced. The server-side package is single-use, but the durable
        // to-device queue may replay the same Welcome before its ACK lands; the
        // equal-or-higher snapshot guard above makes that replay idempotent.
        outcome.applied += 1;
        if let Some(candidate) = welcome_consume_candidate(&welcome_entry, realm_id) {
            outcome.consumable_claims.push(candidate);
        }
    }
    Ok(outcome)
}

#[allow(clippy::type_complexity)]
#[cfg(test)]
pub(crate) fn encrypt_values_with_device_snapshot(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    content_type: &str,
    plaintext_values: &[Vec<u8>],
) -> Result<
    (
        arkret_sdk::Hash,
        Vec<arkret_sdk::Did>,
        Vec<serde_json::Value>,
        Option<PreparedMlsCommit>,
        Option<crate::mls::persistence::MlsSnapshotEnvelope>,
        Option<crate::state::PendingHistorySecrets>,
    ),
    MlsRuntimeError,
> {
    let aad_realm_id = arkret_sdk::RealmId::new(realm_id.to_owned()).map_err(|error| {
        MlsRuntimeError::Serialize(format!("invalid Realm id for encrypted AAD: {error:?}"))
    })?;
    let aad_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: aad_realm_id,
    };
    let aad = arkret_sdk::EncryptedEnvelopeAad::hidden(&aad_scope, "ak.strand.update").map_err(
        |error| MlsRuntimeError::Serialize(format!("invalid scope for encrypted AAD: {error:?}")),
    )?;
    encrypt_values_with_device_snapshot_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
        content_type,
        plaintext_values,
        aad,
        None,
        None,
    )
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(crate) fn encrypt_values_with_device_snapshot_for_effective_scope(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    content_type: &str,
    plaintext_values: &[Vec<u8>],
    aad: arkret_sdk::EncryptedEnvelopeAad,
    circle_id: Option<&str>,
    sidecar_binding: Option<&arkret_sdk::SidecarMlsBinding>,
) -> Result<
    (
        arkret_sdk::Hash,
        Vec<arkret_sdk::Did>,
        Vec<serde_json::Value>,
        Option<PreparedMlsCommit>,
        Option<crate::mls::persistence::MlsSnapshotEnvelope>,
        Option<crate::state::PendingHistorySecrets>,
    ),
    MlsRuntimeError,
> {
    if plaintext_values.is_empty() {
        return Err(MlsRuntimeError::EmptyPlaintext);
    }
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let effective_scope = runtime_effective_scope(realm_id, circle, sidecar_binding)?;
    let snapshot = state_store
        .mls_snapshot_for_scope(&effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: send/encrypt under the Seal-view epoch floor so encrypting from a
    // stale local snapshot (below the Seal lattice) is rejected as OutdatedSnapshot
    // rather than producing ciphertext on a forked ratchet.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    if sidecar_binding.is_none() {
        ensure_realm_membership_is_covered_for_send(state_store, realm_id, circle, &group)?;
    }
    let use_exporter_aead = sidecar_binding.is_none()
        && realm_content_scheme_is_exporter_aead_for_send(state_store, realm_id, circle)?;
    let should_commit = should_force_epoch_advance(
        state_store.realm_projection_is_minimal_metadata(realm_id),
        snapshot.epoch_started_at,
        crate::clock::now_utc(),
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    );
    let commit_envelope = if should_commit {
        Some(self_update_with_verified_governance_binding(
            state_store,
            realm_id,
            circle,
            sidecar_binding,
            &mut group,
        )?)
    } else {
        None
    };
    // §2.10 content scheme dispatch (capability axis): when this Realm declares
    // `content_scheme=mls_exporter_aead_v1`, author content under the
    // history-shareable exporter-aead scheme so a late joiner granted the
    // epoch's `history_secret` can decrypt it. Otherwise keep the default
    // forward-secret `mls_rfc9420` PrivateMessage path. The epoch is read AFTER
    // any forced commit above and is bound with key_ref + typed routing AAD in
    // the SDK's closed immutable header.
    let mut encrypted_values = Vec::with_capacity(plaintext_values.len());
    let exporter_key_ref = use_exporter_aead
        .then(|| arkret_sdk::KeyRefObject::mls_exporter_aead(group.group_id(), group.epoch()));
    for plaintext in plaintext_values {
        let encrypted = if let Some(key_ref) = exporter_key_ref.as_ref() {
            group.encrypt_payload_exporter_aead(
                content_type,
                realm_id,
                key_ref.clone(),
                aad.clone(),
                plaintext,
            )
        } else {
            group.encrypt_payload_with_aad(content_type, Some(aad.clone()), plaintext)
        }
        .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))?;
        encrypted_values.push(
            serde_json::to_value(&encrypted)
                .map_err(|err| MlsRuntimeError::Serialize(err.to_string()))?,
        );
    }
    // §2.10 history sharing: retain THIS epoch's `history_secret` at author time.
    // The author never decrypts its own ciphertext (OpenMLS refuses), so the
    // lazy decrypt-path retain (see `decrypt_application_payload`) never fires
    // for content this device wrote. Without an explicit retain here the secret
    // is lost the moment the epoch advances (forward secrecy), so a later
    // `ak.realm_key.request` finds nothing in `history_secrets_for` and
    // `share_history_to_requester` returns `Ok(false)` — leaving every late
    // joiner's pre-join cards permanently locked. `group.epoch()` is read after
    // any forced commit above, so it matches the epoch the content rides.
    let pending_history_secrets = if use_exporter_aead {
        let history_secret = group
            .derive_and_retain_history_secret(realm_id)
            .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
        if history_secret.is_empty() {
            return Err(MlsRuntimeError::Encrypt(
                "MLS history-secret derivation returned an empty secret".to_owned(),
            ));
        }
        state_store
            .prepare_history_secrets(
                secure_store,
                realm_id.to_owned(),
                [(group.epoch(), history_secret.to_vec())],
            )
            .map_err(MlsRuntimeError::DeviceSecret)?
    } else {
        None
    };
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
        // server accepts the matching `ak.mls.commit`. The messages encrypted
        // above already ride the NEW epoch, so the §5.6 observed-message
        // counter restarts at their count.
        return Ok((
            schedule_hash,
            member_dids,
            encrypted_values,
            commit_envelope,
            Some(new_envelope.with_app_messages_observed(sent)),
            pending_history_secrets,
        ));
    }
    new_envelope = new_envelope
        .carry_epoch_started_at(&snapshot)
        .with_app_messages_observed(snapshot.app_messages_observed.saturating_add(sent));
    state_store.save_mls_snapshot_for_scope(&effective_scope, new_envelope);
    Ok((
        schedule_hash,
        member_dids,
        encrypted_values,
        None,
        None,
        pending_history_secrets,
    ))
}

/// Encrypt a single message plaintext under the Realm MLS group, binding
/// `aad` into the payload digest, and return the structured
/// [`arkret_sdk::EncryptedPayload`] (not yet wrapped as a wire envelope).
///
/// The caller assembles the spec-canonical `ak.schema.encrypted_envelope.v1`
/// wire shape via [`arkret_sdk::encrypted_envelope_from_payload`] once it
/// knows the accepted group-state reference for this epoch (genesis, latest
/// winning commit, or a forced commit returned by this helper). `aad` MUST be
/// the canonical `EncryptedEnvelopeAad` value, so the digest verification
/// round-trips.
type DeviceSnapshotEncryption = (
    arkret_sdk::Hash,
    Vec<arkret_sdk::Did>,
    arkret_sdk::EncryptedPayload,
    Option<arkret_sdk::EncryptedPayload>,
    Option<PreparedMlsCommit>,
    Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    Option<crate::state::PendingHistorySecrets>,
    Option<Vec<u8>>,
);

/// Encrypt one message content plaintext — and optionally a second
/// `encrypted_metadata` plaintext — under the SAME restored group session, so
/// both ciphertexts ride the same epoch (and the same forced commit, when
/// one is produced). Callers MUST NOT encrypt the metadata with a separate
/// call: a second restore from the pre-commit snapshot would fork the ratchet.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_message_with_device_snapshot(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    content_type: &str,
    aad: arkret_sdk::EncryptedEnvelopeAad,
    plaintext: &[u8],
    metadata_content_type: Option<&str>,
    metadata_plaintext: Option<&[u8]>,
    circle_id: Option<&str>,
    sidecar_binding: Option<&arkret_sdk::SidecarMlsBinding>,
) -> Result<DeviceSnapshotEncryption, MlsRuntimeError> {
    if metadata_content_type.is_some() != metadata_plaintext.is_some() {
        return Err(MlsRuntimeError::Serialize(
            "metadata content type and plaintext must be supplied together".to_owned(),
        ));
    }
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let effective_scope = runtime_effective_scope(realm_id, circle, sidecar_binding)?;
    let snapshot = state_store
        .mls_snapshot_for_scope(&effective_scope)
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
    if sidecar_binding.is_none() {
        ensure_realm_membership_is_covered_for_send(state_store, realm_id, circle, &group)?;
    }
    let use_exporter_aead = sidecar_binding.is_none()
        && realm_content_scheme_is_exporter_aead_for_send(state_store, realm_id, circle)?;
    let should_commit = should_force_epoch_advance(
        is_minimal_metadata,
        snapshot.epoch_started_at,
        crate::clock::now_utc(),
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    );
    let commit_envelope = if should_commit {
        Some(self_update_with_verified_governance_binding(
            state_store,
            realm_id,
            circle,
            sidecar_binding,
            &mut group,
        )?)
    } else {
        None
    };
    // §2.10 content scheme dispatch — see `encrypt_values_with_device_snapshot`.
    // The routing `aad`, exact key reference, epoch, purpose and suite are all
    // bound by the exporter-AEAD immutable header.
    let exporter_key_ref = use_exporter_aead
        .then(|| arkret_sdk::KeyRefObject::mls_exporter_aead(group.group_id(), group.epoch()));
    let encrypt_one =
        |group: &mut arkret_sdk::ArkretMlsGroup, payload_content_type: &str, bytes: &[u8]| {
            if let Some(key_ref) = exporter_key_ref.as_ref() {
                group.encrypt_payload_exporter_aead(
                    payload_content_type,
                    realm_id,
                    key_ref.clone(),
                    aad.clone(),
                    bytes,
                )
            } else {
                group.encrypt_payload_with_aad(payload_content_type, Some(aad.clone()), bytes)
            }
            .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))
        };
    let encrypted = encrypt_one(&mut group, content_type, plaintext)?;
    // The optional `encrypted_metadata` plaintext (e.g. the Sidecar exchange
    // binding) is a second application message on the same ratchet, bound to
    // the same canonical AAD/visibility as the content envelope.
    let encrypted_metadata = metadata_plaintext
        .zip(metadata_content_type)
        .map(|(metadata, metadata_content_type)| {
            encrypt_one(&mut group, metadata_content_type, metadata)
        })
        .transpose()?;
    // §2.10 history sharing: retain this epoch's `history_secret` at author time
    // so a late joiner can decrypt it — see the fuller rationale in
    // `encrypt_values_with_device_snapshot`. Without this the author's own
    // messages become permanently unreadable to every late joiner.
    let pending_history_secrets = if use_exporter_aead {
        let history_secret = group
            .derive_and_retain_history_secret(realm_id)
            .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
        if history_secret.is_empty() {
            return Err(MlsRuntimeError::Encrypt(
                "MLS history-secret derivation returned an empty secret".to_owned(),
            ));
        }
        state_store
            .prepare_history_secrets(
                secure_store,
                realm_id.to_owned(),
                [(group.epoch(), history_secret.to_vec())],
            )
            .map_err(MlsRuntimeError::DeviceSecret)?
    } else {
        None
    };
    // `push-notifications.md` §4.5 — the mention routing key MUST come from the
    // same epoch the ciphertext above was produced under, so it is read here
    // (after any forced commit) rather than from the caller's stale snapshot.
    let mention_routing_key = super::mention_routing_key_from_group(state_store, realm_id, &group)?;
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
    let sent = 1 + u64::from(encrypted_metadata.is_some());
    if commit_envelope.is_some() {
        // Persist-on-accept: forced epoch advances must only be saved after the
        // server accepts the matching `ak.mls.commit`. The messages encrypted
        // above ride the NEW epoch (§5.6 counter restarts at `sent`).
        return Ok((
            schedule_hash,
            member_dids,
            encrypted,
            encrypted_metadata,
            commit_envelope,
            Some(new_envelope.with_app_messages_observed(sent)),
            pending_history_secrets,
            mention_routing_key,
        ));
    }
    new_envelope = new_envelope
        .carry_epoch_started_at(&snapshot)
        .with_app_messages_observed(snapshot.app_messages_observed.saturating_add(sent));
    state_store.save_mls_snapshot_for_scope(&effective_scope, new_envelope);
    Ok((
        schedule_hash,
        member_dids,
        encrypted,
        encrypted_metadata,
        None,
        None,
        pending_history_secrets,
        mention_routing_key,
    ))
}

fn ensure_realm_membership_is_covered_for_send(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    group: &arkret_sdk::ArkretMlsGroup,
) -> Result<(), MlsRuntimeError> {
    // Circle membership has its own projection/frontier and must not be
    // compared to the Realm-default roster.
    if circle_id.is_some() {
        return Ok(());
    }
    let Some(joined) = state_store.complete_joined_member_hint_for_realm(realm_id) else {
        return Ok(());
    };
    let group_members = group
        .member_principal_ids()
        .into_iter()
        .map(|did| did.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    if group_members != joined {
        return Err(MlsRuntimeError::EncryptionTransitionPending);
    }
    Ok(())
}

/// UI/readiness form of the conservative roster-hint check. `None` means
/// account sync has not supplied a complete hint (or local MLS state is not
/// restorable); `Some(false)` pauses encryption. `Some(true)` is not itself
/// authorization and cannot replace the verified governance-binding gates.
pub(crate) fn realm_mls_roster_matches_complete_membership_hint(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Option<bool> {
    let joined = state_store.complete_joined_member_hint_for_realm(realm_id)?;
    let members = mls_group_member_principal_ids_for_realm(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
    )?
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    Some(members == joined)
}

fn self_update_with_verified_governance_binding(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    sidecar_binding: Option<&arkret_sdk::SidecarMlsBinding>,
    group: &mut arkret_sdk::ArkretMlsGroup,
) -> Result<PreparedMlsCommit, MlsRuntimeError> {
    let previous_governance_binding = group
        .current_governance_binding()
        .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?
        .ok_or_else(|| {
            MlsRuntimeError::Commit(
                "MLS commit requires the current governance binding predecessor".to_owned(),
            )
        })?;
    let effective_scope = runtime_effective_scope(realm_id, circle_id, sidecar_binding)?;
    let request = crate::mls::governance_proof::proof_request_for_scope(
        state_store,
        effective_scope,
        group.group_id(),
        group.epoch(),
        group.epoch().saturating_add(1),
    )
    .map_err(MlsRuntimeError::Commit)?;
    let mut binding = crate::mls::governance_proof::cached_verified_binding(state_store, &request)
        .map_err(MlsRuntimeError::Commit)?;
    if let Some(sidecar_binding) = sidecar_binding {
        binding =
            crate::mls::governance_proof::bind_sidecar_scope(&binding, sidecar_binding.clone())
                .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?;
    }
    let envelope = group
        .update_governance_binding(&binding)
        .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?;
    Ok(PreparedMlsCommit {
        envelope,
        previous_governance_binding,
    })
}

fn runtime_effective_scope(
    realm_id: &str,
    circle_id: Option<&str>,
    sidecar_binding: Option<&arkret_sdk::SidecarMlsBinding>,
) -> Result<arkret_sdk::ScopeRef, MlsRuntimeError> {
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| MlsRuntimeError::Serialize(format!("invalid MLS Realm id: {error}")))?;
    if let Some(binding) = sidecar_binding {
        return Ok(arkret_sdk::ScopeRef::Sidecar {
            realm_id,
            sidecar_id: binding.sidecar_id.clone(),
        });
    }
    match circle_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(circle_id) => Ok(arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).map_err(|error| {
                MlsRuntimeError::Serialize(format!("invalid MLS Circle id: {error}"))
            })?,
        }),
        None => Ok(arkret_sdk::ScopeRef::Realm { realm_id }),
    }
}

/// SEC-08 — fail-closed committer-side assertion that a `minimal_metadata_realm`
/// send uses `aad_visibility=hidden` (`encryption-and-audit.md` §2.9).
///
/// Thin wrapper over the SDK's [`arkret_sdk::enforce_minimal_metadata_aad`]
/// that maps the SDK protocol error into [`MlsRuntimeError::AadPolicy`] so the
/// runtime's typed error surface stays uniform. This mirrors soland's
/// server-side reject, giving client + server defence in depth: a minimal Realm
/// can never emit a non-hidden AAD, and the server would reject it if it
/// somehow did.
pub fn assert_minimal_metadata_aad(
    visibility: &arkret_sdk::EncryptedEnvelopeAadVisibility,
    is_minimal_metadata: bool,
) -> Result<(), MlsRuntimeError> {
    arkret_sdk::enforce_minimal_metadata_aad(visibility, is_minimal_metadata)
        .map_err(|err| MlsRuntimeError::AadPolicy(err.to_string()))
}

/// SEC-08 — infer the [`arkret_sdk::EncryptedEnvelopeAadVisibility`] discriminator from a
/// canonical `ak.schema.encrypted_envelope.v1` AAD value.
///
/// The schema discriminator is structural (`encryption-and-audit.md` §2.9): a
/// `hidden` envelope omits both `event_id` and `event_ref_digest`; an
/// `opaque_id` envelope carries `event_id`; a `routing_digest` envelope carries
/// `event_ref_digest`. Used by [`assert_minimal_metadata_aad`] on the message
/// path so a minimal Realm cannot ship a non-hidden AAD even if a caller
/// constructed one. `event_id` is checked first so a malformed value carrying
/// both fields resolves to the *less* private (and therefore rejected) form.
pub(crate) fn aad_visibility_of(
    aad: &arkret_sdk::EncryptedEnvelopeAad,
) -> arkret_sdk::EncryptedEnvelopeAadVisibility {
    if aad.event_id.is_some() {
        arkret_sdk::EncryptedEnvelopeAadVisibility::OpaqueId
    } else if aad.event_ref_digest.is_some() {
        arkret_sdk::EncryptedEnvelopeAadVisibility::RoutingDigest
    } else {
        arkret_sdk::EncryptedEnvelopeAadVisibility::Hidden
    }
}
