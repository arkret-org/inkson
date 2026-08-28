//! Welcome application, application-payload encrypt / decrypt, and the SEC-08
//! minimal-metadata AAD policy enforcement.

use arkret_sdk::{DeviceId, PrincipalAuthorityKey};
use arkret_wire::event_kind_str;

use super::{
    MlsRuntimeError, load_device_snapshot_secret, load_mls_key_package_identity_state,
    should_force_epoch_advance,
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

/// Accepted-Welcome convergence and KeyPackage-ack outcome.
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

#[cfg(test)]
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
    pub(crate) claim_request_id: arkret_sdk::Base64UrlString,
    pub(crate) recipient_principal_id: arkret_sdk::DidCoreId,
    pub(crate) recipient: arkret_sdk::MlsWelcomeRecipient,
    pub(crate) recipient_id: arkret_sdk::DidCoreId,
    pub(crate) welcome_event_id: String,
    pub(crate) realm_id: String,
    pub(crate) strand_id: Option<String>,
    pub(crate) mls_group_id: String,
    pub(crate) epoch: u64,
    pub(crate) welcome_digest: arkret_sdk::Hash,
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

pub(super) fn realm_content_scheme_is_exporter_aead_for_send(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    circle: Option<&str>,
) -> Result<bool, MlsRuntimeError> {
    let scheme = circle
        .map(|circle_id| state_store.circle_content_scheme(realm_id, circle_id))
        .unwrap_or_else(|| state_store.realm_content_scheme(realm_id))
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

pub(crate) fn verify_exporter_sender_domain_for_send(
    device_id: &str,
    is_minimal_metadata: bool,
    use_exporter_aead: bool,
) -> Result<(), MlsRuntimeError> {
    if !use_exporter_aead {
        return Ok(());
    }
    if is_minimal_metadata {
        return Ok(());
    }
    arkret_sdk::DeviceId::new(device_id.trim().to_owned())
        .map(|_| ())
        .map_err(|error| {
            MlsRuntimeError::Identity(format!(
                "ordinary exporter-AEAD requires a canonical local device id: {error}"
            ))
        })
}

/// Test-only entry point: production decryption always carries a verified
/// sender domain and enters via
/// [`decrypt_application_payload_for_scope_from_verified_sender`]; these
/// realm/circle-string adapters exist for the receive-chain test matrix.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn decrypt_application_payload_for_effective_scope_internal(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    payload: &arkret_sdk::EncryptedPayload,
    circle_id: Option<&str>,
    verified_sender_domain: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?;
    let effective_scope = match circle_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(circle_id) => arkret_sdk::ScopeRef::Circle {
            realm_id: realm,
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).ok()?,
        },
        None => arkret_sdk::ScopeRef::Realm { realm_id: realm },
    };
    decrypt_application_payload_for_scope_internal(
        state_store,
        secure_store,
        realm_id,
        authority,
        device_id,
        payload,
        &effective_scope,
        verified_sender_domain,
    )
}

/// Reconstruct the authenticated pre-encryption header from a minimal wire
/// envelope plus context already verified from the signed outer Event and the
/// exact winning MLS group state. Any missing or stale coordinate fails closed.
pub(crate) fn encrypted_payload_from_verified_event_context(
    state_store: &crate::state::LocalStateStore,
    envelope: &arkret_sdk::EncryptedEnvelope,
    effective_scope: &arkret_sdk::ScopeRef,
    event_kind: &str,
    verified_sender_domain: &[u8],
    reaction_routing_window: Option<u64>,
) -> Option<arkret_sdk::EncryptedPayload> {
    let scheme = match effective_scope {
        arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => state_store.circle_content_scheme(realm_id.as_str(), circle_id.as_str()),
        arkret_sdk::ScopeRef::Sidecar { .. } => Some("mls_rfc9420".to_owned()),
        _ => state_store.realm_content_scheme(effective_scope.realm_id_opt()?.as_str()),
    }?;
    let scheme = match scheme.trim() {
        "mls_rfc9420" => arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
        "mls_exporter_aead_v1" => arkret_sdk::EncryptedPayloadScheme::MlsExporterAeadV1,
        _ => return None,
    };
    let group_id = effective_scope.canonical_mls_group_id().ok()?;
    let accepted_ref = state_store
        .mls_group_state_ref_for_scope(
            effective_scope,
            &group_id,
            envelope.encryption_context.epoch(),
        )
        .ok()?;
    if accepted_ref != *envelope.encryption_context.group_state_ref() {
        return None;
    }
    let sender_domain = std::str::from_utf8(verified_sender_domain).ok()?;
    let header = envelope
        .reconstruct_pre_encryption_header(
            scheme,
            effective_scope.clone(),
            event_kind,
            sender_domain,
            reaction_routing_window,
        )
        .ok()?;
    arkret_sdk::mls::encrypted_envelope_to_payload_with_verified_header(envelope, header).ok()
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_application_payload_for_scope_from_verified_sender(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    payload: &arkret_sdk::EncryptedPayload,
    effective_scope: &arkret_sdk::ScopeRef,
    verified_sender_domain: &[u8],
) -> Option<Vec<u8>> {
    let plaintext = decrypt_application_payload_for_scope_internal(
        state_store,
        secure_store,
        realm_id,
        authority,
        device_id,
        payload,
        effective_scope,
        Some(verified_sender_domain),
    )?;
    authenticate_received_identity_link(
        state_store,
        secure_store,
        authority,
        device_id,
        effective_scope,
        payload,
        verified_sender_domain,
        &plaintext,
    )?;
    Some(plaintext)
}

#[allow(clippy::too_many_arguments)]
fn authenticate_received_identity_link(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    effective_scope: &arkret_sdk::ScopeRef,
    payload: &arkret_sdk::EncryptedPayload,
    verified_sender_domain: &[u8],
    plaintext: &[u8],
) -> Option<()> {
    if payload.content_type != arkret_sdk::IDENTITY_LINK_MLS_CONTENT_TYPE {
        return Some(());
    }
    let identity_link: arkret_sdk::IdentityLink = serde_json::from_slice(plaintext).ok()?;
    identity_link.validate_minimal().ok()?;
    let canonical = arkret_sdk::canonical::canonical_json_bytes(&identity_link).ok()?;
    let trusted_domain = state_store.load().server_trust_domain?;
    if canonical != plaintext
        || identity_link.status != arkret_sdk::IdentityLinkStatus::Active
        || identity_link.pairwise_actor_id.as_str().as_bytes() != verified_sender_domain
        || identity_link.trust_domain.as_str() != trusted_domain
        || effective_scope.realm_id_opt()? != &identity_link.realm_id
        || identity_link.mls_group_id.as_deref() != Some(payload.group_id.as_str())
        || identity_link.mls_epoch != payload.epoch
        || identity_link
            .expires_at
            .is_some_and(|expires_at| expires_at <= chrono::Utc::now())
    {
        return None;
    }
    let accepted_ref = state_store
        .mls_group_state_ref_for_effective_scope(
            identity_link.realm_id.as_str(),
            match effective_scope {
                arkret_sdk::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str()),
                _ => None,
            },
            &payload.group_id,
            payload.epoch,
        )
        .ok()?;
    let view = minimal_metadata_author_view_for_scope(
        state_store,
        secure_store,
        authority,
        device_id,
        effective_scope,
        &payload.group_id,
        payload.epoch,
        accepted_ref.as_str(),
    )?;
    let leaf_index = u32::try_from(identity_link.mls_leaf_index).ok()?;
    let mut matching = view.active_leaves.iter().filter(|leaf| {
        leaf.leaf_index == leaf_index
            && matches!(
                &leaf.credential,
                arkret_sdk::mls::AuthorLeafCredential::Basic { identity }
                    if identity.as_slice() == identity_link.pairwise_actor_id.as_str().as_bytes()
            )
    });
    let leaf = matching.next()?;
    if matching.next().is_some() || leaf.leaf_node_canonical_bytes.is_empty() {
        return None;
    }
    let entry = crate::state::LocallyAuthenticatedIdentityLink {
        identity_link,
        identity_link_canonical_bytes_b64u: arkret_sdk::Base64UrlString::new(
            arkret_sdk::base64url_encode(&canonical),
        )
        .ok()?,
        identity_link_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
            &canonical,
        ))
        .ok()?,
        leaf_node_canonical_bytes_b64u: arkret_sdk::Base64UrlString::new(
            arkret_sdk::base64url_encode(&leaf.leaf_node_canonical_bytes),
        )
        .ok()?,
        leaf_node_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
            &leaf.leaf_node_canonical_bytes,
        ))
        .ok()?,
        winning_group_state_ref: accepted_ref,
    };
    state_store
        .cache_locally_authenticated_identity_link(entry)
        .ok()?;
    Some(())
}

#[allow(clippy::too_many_arguments)]
fn decrypt_application_payload_for_scope_internal(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    payload: &arkret_sdk::EncryptedPayload,
    effective_scope: &arkret_sdk::ScopeRef,
    verified_sender_domain: Option<&[u8]>,
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
        let plaintext = (!sidecar_scoped)
            .then(|| {
                try_history_decrypt_standalone(
                    state_store,
                    realm_id,
                    payload,
                    effective_scope,
                    verified_sender_domain,
                )
            })
            .flatten();
        if plaintext.is_none() && !sidecar_scoped {
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
    let secret = match load_device_snapshot_secret(secure_store, authority, device_id) {
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
            // prior local retain. Past-epoch or pre-join content still needs a
            // retained local-authoritative secret or an event-local external
            // candidate, handled by the group-free path below.
            if payload.scheme == arkret_sdk::EncryptedPayloadScheme::MlsExporterAeadV1
                && snapshot.epoch == payload.epoch
                && let Ok(secret) = group.derive_and_retain_history_secret(realm_id)
                && let Ok(ciphertext) = arkret_sdk::base64url_decode(payload.ciphertext.as_bytes())
                && payload.verify_payload_digest().is_ok()
                && let Ok(plaintext) = group.decrypt_content_exporter_aead(
                    &secret,
                    verified_sender_domain?,
                    &payload.pre_encryption_header,
                    &ciphertext,
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
            let plaintext = (!sidecar_scoped)
                .then(|| {
                    try_history_decrypt_standalone(
                        state_store,
                        realm_id,
                        payload,
                        effective_scope,
                        verified_sender_domain,
                    )
                })
                .flatten();
            if plaintext.is_none() && !sidecar_scoped {
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
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    group_id: &str,
    epoch: u64,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::AuthorGroupStateView> {
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?,
    };
    minimal_metadata_author_view_for_scope(
        state_store,
        secure_store,
        authority,
        device_id,
        &effective_scope,
        group_id,
        epoch,
        group_state_ref,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn minimal_metadata_author_view_for_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    effective_scope: &arkret_sdk::ScopeRef,
    group_id: &str,
    epoch: u64,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::AuthorGroupStateView> {
    let realm_id = effective_scope.realm_id_opt()?.as_str();
    let circle_id = match effective_scope {
        arkret_sdk::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str()),
        _ => None,
    };
    let snapshot = state_store
        .mls_snapshot_for_scope(effective_scope)
        .filter(|snapshot| snapshot.epoch == epoch && snapshot.group_id == group_id)
        .or_else(|| {
            state_store
                .historical_mls_snapshot_for_effective_scope(realm_id, circle_id, group_id, epoch)
        })?;
    let accepted_ref = state_store
        .mls_group_state_ref_for_effective_scope(realm_id, circle_id, group_id, epoch)
        .ok()?;
    if accepted_ref.as_str() != group_state_ref {
        return None;
    }
    let secret = load_device_snapshot_secret(secure_store, authority, device_id).ok()?;
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
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    group_id: &str,
    epoch: u64,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::AgentMlsSignerView> {
    let group_state = minimal_metadata_author_view(
        state_store,
        secure_store,
        realm_id,
        authority,
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
        let Ok(signer_core) = arkret_sdk::project_did_to_core_id(&signer_id) else {
            continue;
        };
        let signer_actor = signer_core;
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
/// `mls_exporter_aead_v1` payload. The provider binds the payload's exact
/// pre-encryption header and epoch into the AEAD transcript. A malformed payload
/// or missing exact-epoch secret returns `None`; this path never scans other
/// epoch keys. Does NOT touch the receive ratchet.
///
/// Group-free decryption also needs the exact verified historical ciphersuite;
/// the minimal wire envelope intentionally carries no algorithm selector.
fn try_history_decrypt_standalone(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    payload: &arkret_sdk::EncryptedPayload,
    effective_scope: &arkret_sdk::ScopeRef,
    verified_sender_domain: Option<&[u8]>,
) -> Option<Vec<u8>> {
    if payload.scheme != arkret_sdk::EncryptedPayloadScheme::MlsExporterAeadV1
        || payload.group_id.trim().is_empty()
        || payload.pre_encryption_header.effective_scope != *effective_scope
    {
        return None;
    }
    if payload
        .pre_encryption_header
        .effective_scope
        .realm_id_opt()?
        .as_str()
        != realm_id
    {
        return None;
    }
    let secret =
        state_store.history_secret_for(effective_scope, &payload.group_id, payload.epoch)?;
    let sender_domain = verified_sender_domain?;
    let cipher_suite = state_store.history_epoch_cipher_suite(
        effective_scope,
        &payload.group_id,
        payload.epoch,
    )?;
    let ciphertext = arkret_sdk::base64url_decode(payload.ciphertext.as_bytes()).ok()?;
    arkret_sdk::mls::decrypt_content_exporter_aead_standalone(
        &secret,
        sender_domain,
        &payload.pre_encryption_header,
        &cipher_suite,
        &ciphertext,
    )
    .ok()
}

/// Try bounded external history-secret candidates against one exact accepted
/// Event and durably bind every outcome before exposing plaintext.
///
/// This never promotes candidate material into the local-authoritative epoch
/// ledger. A successful binding is scoped to the exact Event identity, digest,
/// verified sender domain, effective scope, group, and epoch.
pub(crate) fn decrypt_external_history_candidates_for_event(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    payload: &arkret_sdk::EncryptedPayload,
    effective_scope: &arkret_sdk::ScopeRef,
    event_binding_key: arkret_sdk::EventCandidateBindingKey,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Vec<u8>>, MlsRuntimeError> {
    if payload.scheme != arkret_sdk::EncryptedPayloadScheme::MlsExporterAeadV1
        || payload.pre_encryption_header.effective_scope != *effective_scope
        || effective_scope.realm_id_opt().map(|realm| realm.as_str()) != Some(realm_id)
    {
        return Ok(None);
    }
    let expected_scope = match effective_scope {
        arkret_sdk::ScopeRef::Realm { realm_id } => arkret_sdk::HistoryEffectiveScope::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => arkret_sdk::HistoryEffectiveScope::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        _ => return Ok(None),
    };
    if event_binding_key.effective_scope != expected_scope
        || event_binding_key.mls_group_id != payload.group_id
        || event_binding_key.epoch != payload.epoch
        || event_binding_key.event_id.identity_key().event_digest()
            != event_binding_key.event_digest()
        || event_binding_key.verified_sender_domain.is_empty()
    {
        return Err(MlsRuntimeError::Decrypt(
            "external history candidate Event binding is inconsistent".to_owned(),
        ));
    }
    let cipher_suite = state_store
        .history_epoch_cipher_suite(effective_scope, &payload.group_id, payload.epoch)
        .ok_or_else(|| {
            MlsRuntimeError::Decrypt("verified history epoch ciphersuite is unavailable".to_owned())
        })?;
    let ciphertext = arkret_sdk::base64url_decode(payload.ciphertext.as_bytes())
        .map_err(|error| MlsRuntimeError::Decrypt(error.to_string()))?;
    let candidates = state_store
        .history_candidates_for(
            secure_store,
            &expected_scope,
            &payload.group_id,
            payload.epoch,
        )
        .map_err(|error| MlsRuntimeError::Decrypt(error.to_string()))?;
    for candidate in candidates {
        // The AEAD attempt and the Event->candidate binding it establishes are
        // one SDK operation; this client only decides what to persist.
        let attempt = arkret_sdk::mls::bind_event_candidate(
            &candidate,
            &event_binding_key,
            &payload.pre_encryption_header,
            &cipher_suite,
            &ciphertext,
            now,
        )
        .map_err(|error| MlsRuntimeError::Decrypt(error.to_string()))?;
        state_store
            .record_history_candidate_binding(attempt.binding, now)
            .map_err(|error| MlsRuntimeError::Decrypt(error.to_string()))?;
        if attempt.plaintext.is_some() {
            return Ok(attempt.plaintext);
        }
    }
    Ok(None)
}

/// Derive and retain the **current** epoch `history_secret` as local-authoritative
/// material. It can later be included in a portable backup or used as a source
/// for the receipt-bound history-key recovery protocol. This MUST be called
/// while the group is at the epoch whose key is being retained because OpenMLS
/// only exports the current epoch. Returns
/// `(epoch, history_secret)` on success.
///
/// Persisting into the device's own `history_secrets` lets a past epoch's key
/// survive an app restart (OpenMLS could not re-derive it once the group has
/// advanced past that epoch).
type RetainedRealmHistorySecret = (
    u64,
    zeroize::Zeroizing<Vec<u8>>,
    crate::state::PendingHistorySecrets,
);

fn prepare_local_authoritative_history_secret(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    effective_scope: &arkret_sdk::ScopeRef,
    group: &arkret_sdk::ArkretMlsGroup,
    epoch: u64,
) -> Result<Option<crate::state::PendingHistorySecrets>, MlsRuntimeError> {
    let evidence = state_store
        .accepted_mls_transition_evidence(effective_scope, &group.group_id(), epoch)
        .map_err(MlsRuntimeError::Encrypt)?;
    let record = group
        .export_local_authoritative_history_secret(
            &evidence.effective_scope,
            epoch,
            &evidence.local_state_ref,
            &evidence.transition_ref,
            &evidence.transition_event_digest,
            &evidence.mls_transition_digest,
        )
        .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
    state_store
        .prepare_history_secrets(secure_store, effective_scope, &group.group_id(), [record])
        .map_err(|error| MlsRuntimeError::Encrypt(format!("retain MLS history secret: {error}")))
}

pub(crate) fn derive_and_retain_realm_history_secret(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
) -> Result<Option<RetainedRealmHistorySecret>, MlsRuntimeError> {
    let Some(snapshot) = state_store.mls_snapshot_for(realm_id) else {
        return Ok(None);
    };
    let secret = load_device_snapshot_secret(secure_store, authority, device_id)
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
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| MlsRuntimeError::Serialize(format!("invalid Realm id: {error:?}")))?,
    };
    let Some(pending) = prepare_local_authoritative_history_secret(
        state_store,
        secure_store,
        &effective_scope,
        &group,
        epoch,
    )?
    else {
        return Ok(None);
    };
    Ok(Some((epoch, history_secret, pending)))
}

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
            == Some(event_kind_str::MLS_WELCOME)
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
    let receipt = &payload.claim_receipt;
    let strand_id = receipt.request.strand_id.as_ref().map(ToString::to_string);
    Some(WelcomeConsumeCandidate {
        key_package_id: entry.key_package_id.clone()?,
        claim_id: payload.claim_id.as_str().to_owned(),
        claim_request_id: receipt.claim_request_id.clone(),
        recipient_principal_id: payload.recipient_principal_id.clone().or_else(
            || match &payload.recipient {
                arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise {
                    recipient_pairwise_actor_id,
                    ..
                } => Some(recipient_pairwise_actor_id.clone()),
                _ => None,
            },
        )?,
        recipient: payload.recipient,
        recipient_id: receipt.destination_id.clone(),
        welcome_event_id: entry.welcome_event_id.clone()?,
        realm_id: realm_id.to_owned(),
        strand_id,
        mls_group_id: payload.mls_group_id.as_str().to_owned(),
        epoch: payload.epoch,
        welcome_digest: payload.claim_envelope.welcome_digest,
    })
}

/// Build both recipient proofs only after the joined MLS snapshot has crossed
/// the durable barrier. The KeyPackage identity state supplies the exact Leaf
/// signing key; transport session identity is deliberately not used as the
/// pairwise actor authority.
pub(crate) fn sign_welcome_consume_request(
    secure_store: &dyn SecureKeyStore,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    candidate: &WelcomeConsumeCandidate,
) -> Result<arkret_sdk::KeyPackagesConsumeRequestBody, String> {
    let serialized_state = load_mls_key_package_identity_state(
        secure_store,
        authority,
        device_id,
        &candidate.key_package_id,
    )
    .map_err(|error| format!("load consumed KeyPackage identity state: {error}"))?
    .ok_or_else(|| {
        format!(
            "no local KeyPackage identity state for consume key_package_id={}",
            candidate.key_package_id
        )
    })?;
    let expected_endpoint = welcome_recipient_endpoint(
        &Some(candidate.recipient_principal_id.clone()),
        candidate.recipient.clone(),
    )?;
    let identity = arkret_sdk::ArkretMlsIdentity::restore_from_private_state(
        expected_endpoint,
        &serialized_state,
    )
    .map_err(|error| format!("restore consumed KeyPackage identity state: {error}"))?;
    let recipient = match &candidate.recipient {
        arkret_sdk::MlsWelcomeRecipient::Device {
            recipient_device_id,
        } => {
            let signer = crate::event_signer::active_signer().ok_or_else(|| {
                "recipient device durable receipt requires the active accepted device signer"
                    .to_owned()
            })?;
            let method = arkret_sdk::DidUrl::new(signer.verification_method().to_owned()).map_err(
                |error| format!("invalid recipient device verification method: {error}"),
            )?;
            if method
                .as_str()
                .rsplit_once('#')
                .map(|(_, fragment)| fragment)
                != Some(recipient_device_id.as_str())
            {
                return Err(
                    "recipient device verification method does not name the Welcome device"
                        .to_owned(),
                );
            }
            arkret_sdk::RecipientMlsDurableSigner::Device {
                recipient_device_id: recipient_device_id.clone(),
                device_verification_method: method,
            }
        }
        arkret_sdk::MlsWelcomeRecipient::NativeAgent { .. } => {
            return Err(
                "Inkson cannot sign a Native Agent durable receipt with a human client key"
                    .to_owned(),
            );
        }
        arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise {
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
        } => {
            if recipient_pairwise_actor_id != &candidate.recipient_principal_id {
                return Err("pairwise Welcome recipient actor drifted before consume".to_owned());
            }
            arkret_sdk::RecipientMlsDurableSigner::MinimalMetadataPairwise {
                recipient_pairwise_verification_method: recipient_pairwise_verification_method
                    .clone(),
            }
        }
    };
    let kid = match &recipient {
        arkret_sdk::RecipientMlsDurableSigner::Device {
            device_verification_method,
            ..
        } => device_verification_method.as_str(),
        arkret_sdk::RecipientMlsDurableSigner::NativeAgent { .. } => unreachable!(),
        arkret_sdk::RecipientMlsDurableSigner::MinimalMetadataPairwise {
            recipient_pairwise_verification_method,
        } => recipient_pairwise_verification_method.as_str(),
    };
    let placeholder_signature = arkret_sdk::KeyOperationSignature {
        kid: arkret_sdk::NonEmptyString::new(kid).map_err(|error| error.to_string())?,
        signature_algorithm: Some(
            arkret_sdk::NonEmptyString::new("Ed25519").map_err(|error| error.to_string())?,
        ),
        sig: arkret_sdk::Base64UrlString::new("AA").map_err(|error| error.to_string())?,
    };
    let receipt = arkret_sdk::RecipientMlsDurableReceipt {
        domain: arkret_sdk::NonEmptyString::new(
            arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1,
        )
        .map_err(|error| error.to_string())?,
        claim_request_id: candidate.claim_request_id.clone(),
        key_package_ref: arkret_sdk::NonEmptyString::new(&candidate.key_package_id)
            .map_err(|error| error.to_string())?,
        recipient_principal_id: candidate.recipient_principal_id.clone(),
        recipient,
        recipient_id: candidate.recipient_id.clone(),
        realm_id: arkret_sdk::RealmId::new(candidate.realm_id.clone())
            .map_err(|error| error.to_string())?,
        mls_group_id: arkret_sdk::NonEmptyString::new(&candidate.mls_group_id)
            .map_err(|error| error.to_string())?,
        mls_epoch: candidate.epoch,
        welcome_ref: arkret_sdk::EventId::new(&candidate.welcome_event_id)
            .map_err(|error| error.to_string())?,
        welcome_digest: candidate.welcome_digest.clone(),
        durable_at: crate::clock::now_utc(),
        signature: placeholder_signature,
    };
    let receipt = identity
        .sign_recipient_mls_durable_receipt(receipt)
        .map_err(|error| format!("sign recipient durable receipt: {error}"))?;
    identity
        .signed_key_packages_consume_request(
            arkret_sdk::NonEmptyString::new(&candidate.claim_id)
                .map_err(|error| error.to_string())?,
            receipt,
        )
        .map_err(|error| format!("sign KeyPackage consume request: {error}"))
}

pub(crate) fn accepted_welcome_consume_candidates(
    messages_value: &serde_json::Value,
    realm_id: &str,
    accepted_welcome_event_ids: &std::collections::BTreeSet<String>,
) -> Vec<WelcomeConsumeCandidate> {
    collect_welcome_message_entries(messages_value)
        .iter()
        .filter_map(|entry| welcome_consume_candidate(entry, realm_id))
        .filter(|candidate| accepted_welcome_event_ids.contains(&candidate.welcome_event_id))
        .collect()
}

pub fn mls_group_id_for_realm(realm_id: &str) -> Result<String, String> {
    let realm_id = arkret_sdk::RealmId::new(realm_id.trim().to_owned())
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    arkret_sdk::ScopeRef::Realm { realm_id }
        .canonical_mls_group_id()
        .map_err(|error| error.to_string())
}

pub fn mls_welcome_message_matches_realm(message: &serde_json::Value, realm_id: &str) -> bool {
    if message
        .get("kind")
        .or_else(|| message.get("type"))
        .and_then(|t| t.as_str())
        != Some(event_kind_str::MLS_WELCOME)
    {
        return false;
    }
    let Some(content) = message.get("content") else {
        return false;
    };
    if content
        .get("governance_binding")
        .and_then(|binding| binding.get("effective_scope"))
        .and_then(|scope| scope.get("realm_id"))
        .and_then(serde_json::Value::as_str)
        == Some(realm_id)
    {
        return true;
    }
    let Ok(expected_group_id) = mls_group_id_for_realm(realm_id) else {
        return false;
    };
    content
        .get("mls_group_id")
        .and_then(serde_json::Value::as_str)
        == Some(expected_group_id.as_str())
}

/// Reads the local MLS roster without advancing or persisting any chain.
pub fn mls_group_member_principal_ids_for_realm(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
) -> Option<Vec<String>> {
    mls_group_member_principal_ids_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
        authority,
        device_id,
    )
}

/// Local RFC 9420 member roster of one effective MLS scope.
pub fn mls_group_member_principal_ids_for_effective_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
) -> Option<Vec<String>> {
    let snapshot = state_store.mls_snapshot_for_effective_scope(realm_id, circle_id)?;
    let secret = load_device_snapshot_secret(secure_store, authority, device_id).ok()?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    Some(
        group
            .member_principal_ids()
            .ok()?
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect(),
    )
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
                        .and_then(|content| content.get("claim_envelope"))
                        .and_then(|envelope| envelope.get("welcome_digest"))
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

#[cfg(test)]
pub(super) fn durable_welcome_payload_reject_reason(value: &serde_json::Value) -> Option<String> {
    serde_json::from_value::<arkret_sdk::MlsWelcomePayload>(value.clone())
        .err()
        .map(|error| {
            format!(
                "{}: {error}",
                arkret_sdk::error_codes::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH
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

pub(super) fn decode_welcome_envelope(
    value: &serde_json::Value,
) -> Result<arkret_sdk::MlsWelcomeEnvelope, String> {
    let durable: arkret_sdk::MlsWelcomePayload = serde_json::from_value(value.clone())
        .map_err(|error| format!("durable Welcome payload parse: {error}"))?;
    let ciphertext = durable.carrier.ciphertext();
    let welcome_hash = arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
        durable.carrier.welcome_bytes(),
    ))
    .map_err(|error| format!("durable Welcome digest: {error}"))?;
    if welcome_hash != durable.claim_envelope.welcome_digest {
        return Err(
            "durable Welcome ciphertext differs from claim_envelope.welcome_digest".to_owned(),
        );
    }
    let recipient =
        welcome_recipient_endpoint(&durable.recipient_principal_id, durable.recipient.clone())?;
    Ok(arkret_sdk::MlsWelcomeEnvelope {
        group_id: durable.mls_group_id.as_str().to_owned(),
        epoch: durable.epoch,
        recipient,
        welcome: ciphertext,
        welcome_hash,
        ratchet_tree: None,
    })
}

pub(super) fn validate_welcome_claim_receipt_context(
    welcome: &arkret_sdk::MlsWelcomePayload,
) -> Result<(), String> {
    let receipt = &welcome.claim_receipt;
    let request = &receipt.request;
    let target_principal_id =
        match &welcome.recipient {
            arkret_sdk::MlsWelcomeRecipient::Device { .. } => welcome
                .recipient_principal_id
                .as_ref()
                .ok_or_else(|| "device Welcome omits recipient_principal_id".to_owned())?,
            arkret_sdk::MlsWelcomeRecipient::NativeAgent {
                recipient_agent_id, ..
            } => recipient_agent_id,
            arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise {
                recipient_pairwise_actor_id,
                ..
            } => recipient_pairwise_actor_id,
        };
    if receipt.claim_request_id != request.claim_request_id
        || request.requester != welcome.claim_envelope.requester_actor_id
        || request.intended_realm_id != welcome.claim_envelope.intended_realm_id
        || request.intended_realm_id.as_str() != welcome.governance_binding.realm_id().as_str()
        || request.mls_group_id.as_str() != welcome.mls_group_id.as_str()
        || &request.target_principal_id != target_principal_id
    {
        return Err(
            "claim_receipt does not match the exact Welcome requester, Realm, MLS group, target, and claim request id"
                .to_owned(),
        );
    }
    Ok(())
}

pub(super) fn welcome_recipient_endpoint(
    recipient_principal_id: &Option<arkret_sdk::DidCoreId>,
    recipient: arkret_sdk::MlsWelcomeRecipient,
) -> Result<arkret_sdk::MlsEndpointIdentity, String> {
    match recipient {
        arkret_sdk::MlsWelcomeRecipient::Device {
            recipient_device_id,
        } => {
            let recipient_did = arkret_sdk::Did::new(
                crate::event_signer::active_signer()
                    .ok_or_else(|| "active recipient signer is unavailable".to_owned())?
                    .signer_did()
                    .to_owned(),
            )
            .map_err(|error| format!("active recipient did is invalid: {error}"))?;
            let recipient_principal_id = recipient_principal_id
                .as_ref()
                .ok_or_else(|| "device Welcome recipient_principal_id is required".to_owned())?;
            if arkret_sdk::project_did_to_core_id(&recipient_did)
                .map_err(|error| format!("project active recipient did: {error}"))?
                != *recipient_principal_id
            {
                return Err(
                    "active recipient did does not match durable Welcome recipient".to_owned(),
                );
            }
            Ok(arkret_sdk::MlsEndpointIdentity::human_device(
                recipient_principal_id.clone(),
                recipient_device_id,
            ))
        }
        arkret_sdk::MlsWelcomeRecipient::NativeAgent {
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        } => {
            if recipient_principal_id.as_ref() != Some(&recipient_agent_id) {
                return Err(
                    "Native Agent Welcome recipient differs from recipient_principal_id".to_owned(),
                );
            }
            Ok(arkret_sdk::MlsEndpointIdentity::native_agent_runtime(
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            )
            .map_err(|error| format!("Native Agent Welcome endpoint is invalid: {error}"))?)
        }
        arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise {
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
        } => {
            if recipient_principal_id.is_some() {
                return Err("pairwise Welcome must not carry recipient_principal_id".to_owned());
            }
            arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
                recipient_pairwise_actor_id,
                recipient_pairwise_verification_method,
            )
            .map_err(|error| format!("pairwise Welcome endpoint is invalid: {error}"))
        }
    }
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
/// Returns `Ok(())` only when the required claim envelope is present and its
/// directory-resolved device signature verifies.
pub(super) fn verify_welcome_claim_envelope_signer(
    welcome: &arkret_sdk::MlsWelcomePayload,
) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let envelope = &welcome.claim_envelope;
    let claim_receipt = &welcome.claim_receipt;
    validate_welcome_claim_receipt_context(welcome)?;
    // Shape validation: non-empty kid/sig and alg in {Ed25519, Ed25519}.
    envelope
        .validate_signature_shape()
        .map_err(|reason| format!("claim_envelope signature shape: {reason}"))?;

    if let arkret_sdk::MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
        requester_pairwise_verification_method,
    } = &envelope.trust_binding
    {
        let endpoint = arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
            envelope.requester_actor_id.clone(),
            requester_pairwise_verification_method.clone(),
        )
        .map_err(|error| format!("claim_envelope pairwise requester is invalid: {error}"))?;
        if envelope.signature.kid.as_str() != requester_pairwise_verification_method.as_str()
            || endpoint.actor_id() != &envelope.requester_actor_id
        {
            return Err(
                "claim_envelope pairwise signature key differs from the exact requester endpoint"
                    .to_owned(),
            );
        }
        let multibase = requester_pairwise_verification_method
            .as_str()
            .split_once('#')
            .and_then(|(controller, fragment)| {
                controller
                    .strip_prefix("did:key:")
                    .filter(|key| *key == fragment)
            })
            .ok_or_else(|| {
                "claim_envelope pairwise verification method is not canonical did:key".to_owned()
            })?;
        let key_bytes = arkret_sdk::decode_ed25519_multibase(multibase)
            .map_err(|error| format!("claim_envelope pairwise key decode: {error}"))?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|error| format!("claim_envelope pairwise key is invalid: {error}"))?;
        let signing_bytes = envelope
            .canonical_signing_bytes(claim_receipt)
            .map_err(|error| format!("claim_envelope canonical bytes: {error}"))?;
        let signature_bytes = arkret_sdk::base64url_decode(envelope.signature.sig.as_bytes())
            .map_err(|error| format!("claim_envelope signature decode: {error}"))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|error| format!("claim_envelope signature malformed: {error}"))?;
        return verifying_key
            .verify(&signing_bytes, &signature)
            .map_err(|error| format!("claim_envelope signature verification failed: {error}"));
    }

    let (requester_did, requester_device_id, requester_authorize_event_id) = match &envelope
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
            let did = arkret_sdk::Did::new(controller.to_owned())
                .map_err(|error| format!("claim_envelope requester Did: {error}"))?;
            let projected = arkret_sdk::project_did_to_core_id(&did).map_err(|error| {
                format!("claim_envelope requester DidCoreId projection: {error}")
            })?;
            if projected != envelope.requester_actor_id {
                return Err(
                    "claim_envelope signature controller does not project to requester core id"
                        .to_owned(),
                );
            }
            (
                did,
                requester_device_id,
                requester_device_authorize_event_id,
            )
        }
        arkret_sdk::MlsRequesterTrustBinding::RequesterNativeAgent { .. } => {
            return Err(
                    "Native Agent claim_envelope verification is unavailable until its authorization Event is normatively bound to this Welcome"
                        .to_owned(),
                );
        }
        arkret_sdk::MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise { .. } => {
            unreachable!("pairwise claim envelopes are verified above")
        }
    };
    let requester_did = requester_did.as_str();
    let requester_device_id = requester_device_id.as_str();
    if crate::identity::device_directory::cached_device_authorize_event_id(
        requester_did,
        requester_device_id,
    )
    .as_ref()
        != Some(requester_authorize_event_id)
    {
        return Err(format!(
            "claim_envelope device authorization is not the current accepted Event for {requester_did}/{requester_device_id}"
        ));
    }
    let verifying_key = match crate::identity::device_directory::cached_device_signing_key(
        requester_did,
        requester_device_id,
    ) {
        crate::identity::device_directory::CacheLookup::Hit(material) => {
            let bytes = material.ed25519_bytes().map_err(|err| {
                format!("claim_envelope signer key decode ({requester_did}/{requester_device_id}): {err}")
            })?;
            VerifyingKey::from_bytes(&bytes).map_err(|err| {
                format!("claim_envelope signer key invalid ({requester_did}/{requester_device_id}): {err}")
            })?
        }
        crate::identity::device_directory::CacheLookup::NegativeHit => {
            return Err(format!(
                "claim_envelope signer {requester_did}/{requester_device_id} is revoked / \
                 absent in directory (negative verdict); Welcome rejected (YGN-SEC-01)"
            ));
        }
        crate::identity::device_directory::CacheLookup::Miss => {
            return Err(format!(
                "claim_envelope signer key for {requester_did}/{requester_device_id} not in \
                 device-directory cache; fail-closed (YGN-SEC-01)"
            ));
        }
    };

    let signing_bytes = envelope
        .canonical_signing_bytes(claim_receipt)
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
pub(super) fn verify_welcome_governance_binding(
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
    let verified = crate::mls::governance_proof::cached_verified_binding_for_transition(
        state_store,
        binding.effective_scope(),
        binding.mls_group_id(),
        binding.previous_epoch(),
        binding.next_epoch(),
    )?;
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
    checkpoint: &arkret_sdk::MlsGovernanceVerificationCheckpoint,
    secure_store: &dyn SecureKeyStore,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    messages_value: &serde_json::Value,
) -> Result<Vec<WelcomeSecurityFrontierPreview>, String> {
    let principal_id = authority.principal_id.clone();
    let device_id_typed = device_id.clone();
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
            authority,
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
            arkret_sdk::MlsEndpointIdentity::human_device(
                principal_id.clone(),
                device_id_typed.clone(),
            ),
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
        let leaves = crate::mls::governance_proof::reconstruct_transition_security_frontier(
            checkpoint, &group, &binding,
        )?;
        previews.push(WelcomeSecurityFrontierPreview { binding, leaves });
    }
    Ok(previews)
}

#[cfg(test)]
pub(crate) fn apply_welcome_messages_with_device_snapshot(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &DeviceId,
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
    let secret = load_device_snapshot_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let principal_id = authority.principal_id.clone();
    let device_id_typed = device_id.clone();
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
        let typed_welcome =
            match serde_json::from_value::<arkret_sdk::MlsWelcomePayload>(welcome_value.clone()) {
                Ok(welcome) => welcome,
                Err(error) => {
                    outcome.record_failure(format!("welcome claim envelope: {error}"));
                    continue;
                }
            };
        if let Err(reason) = verify_welcome_claim_envelope_signer(&typed_welcome) {
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
                authority,
                device_id,
                key_package_id,
            ) {
                Ok(Some(serialized_state)) => {
                    match arkret_sdk::ArkretMlsIdentity::restore_from_private_state(
                        arkret_sdk::MlsEndpointIdentity::human_device(
                            principal_id.clone(),
                            device_id_typed.clone(),
                        ),
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
                    // identity state for. A freshly generated identity can NEVER
                    // hold that KeyPackage's init key, so `join_from_welcome`
                    // would fail with `NoMatchingKeyPackage`. Fail closed with a
                    // diagnosable message instead of silently retrying with an
                    // identity that cannot work. (mls-welcome-debug)
                    tracing::warn!(
                        target: "mls_admission",
                        realm = %yoface::utils::text::short_protocol_id(realm_id),
                        actor = %yoface::utils::text::short_protocol_id(actor_id),
                        device = %yoface::utils::text::short_protocol_id(device_id.as_str()),
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
        let mut group = match arkret_sdk::ArkretMlsGroup::join_from_welcome(identity, &welcome) {
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
        let Some(welcome_binding) = welcome_value_for_governance
            .get("governance_binding")
            .cloned()
            .and_then(|value| {
                serde_json::from_value::<arkret_sdk::MlsGovernanceBindingPayload>(value).ok()
            })
        else {
            outcome.record_failure(
                "Welcome governance binding disappeared before persistence".to_owned(),
            );
            continue;
        };
        let authority_hints =
            match crate::mls::governance_proof::leaf_authority_hints_from_welcome(&typed_welcome) {
                Ok(authority_hints) => authority_hints,
                Err(reason) => {
                    outcome.record_failure(format!("derive Welcome leaf authorities: {reason}"));
                    continue;
                }
            };
        if let Err(reason) =
            crate::mls::governance_proof::install_cached_transition_leaf_bindings_with_hints(
                state_store,
                &mut group,
                &welcome_binding,
                &authority_hints,
            )
        {
            outcome.record_failure(format!("install Welcome T3 leaf bindings: {reason}"));
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
        let effective_scope = welcome_binding.effective_scope().clone();
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
        if let Err(error) = state_store.save_mls_snapshot_for_scope(&effective_scope, snapshot) {
            outcome.record_failure(format!("persist Welcome MLS snapshot: {error}"));
            continue;
        }
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
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    content_type: &str,
    plaintext_values: &[Vec<u8>],
) -> Result<
    (
        arkret_sdk::Hash,
        Vec<arkret_sdk::DidCoreId>,
        Vec<serde_json::Value>,
        Option<PreparedMlsCommit>,
        Option<crate::mls::persistence::MlsSnapshotEnvelope>,
        Option<crate::state::PendingHistorySecrets>,
    ),
    MlsRuntimeError,
> {
    let effective_scope = runtime_effective_scope(realm_id, None, None)?;
    let snapshot = state_store
        .mls_snapshot_for_scope(&effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let group_state_ref = state_store
        .mls_group_state_ref_for_scope(&effective_scope, &snapshot.group_id, snapshot.epoch)
        .map_err(|_| MlsRuntimeError::EncryptionTransitionPending)?;
    encrypt_values_with_device_snapshot_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        authority,
        device_id,
        content_type,
        plaintext_values,
        event_kind_str::STRAND_UPDATE,
        group_state_ref,
        None,
        None,
    )
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(crate) fn encrypt_values_with_device_snapshot_for_effective_scope(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    content_type: &str,
    plaintext_values: &[Vec<u8>],
    event_kind: &str,
    group_state_ref: arkret_sdk::EventId,
    circle_id: Option<&str>,
    sidecar_binding: Option<&arkret_sdk::SidecarMlsBinding>,
) -> Result<
    (
        arkret_sdk::Hash,
        Vec<arkret_sdk::DidCoreId>,
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
    let secret = load_device_snapshot_secret(secure_store, authority, device_id)
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
    verify_exporter_sender_domain_for_send(
        device_id.as_str(),
        state_store.realm_projection_is_minimal_metadata(realm_id),
        use_exporter_aead,
    )?;
    let should_commit = should_force_epoch_advance(
        state_store.realm_projection_is_minimal_metadata(realm_id),
        snapshot.epoch_started_at,
        crate::clock::now_utc(),
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    );
    if should_commit {
        return Err(MlsRuntimeError::EncryptionTransitionPending);
    }
    let commit_envelope = None;
    // §2.10 content scheme dispatch (capability axis): when this Realm declares
    // `content_scheme=mls_exporter_aead_v1`, author content under the
    // history-shareable exporter-aead scheme so a late joiner granted the
    // epoch's `history_secret` can decrypt it. Otherwise keep the default
    // forward-secret `mls_rfc9420` PrivateMessage path. The epoch is read after
    // the rotation gate and the SDK reconstructs the authenticated header from
    // the signed outer Event plus this minimal encrypted envelope.
    let mut encrypted_values = Vec::with_capacity(plaintext_values.len());
    for plaintext in plaintext_values {
        let scheme = if use_exporter_aead {
            arkret_sdk::EncryptedPayloadScheme::MlsExporterAeadV1
        } else {
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420
        };
        let sender_domain = group
            .local_content_sender_domain()
            .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            content_type,
            scheme,
            effective_scope.clone(),
            event_kind,
            group.epoch(),
            group_state_ref.clone(),
            sender_domain,
            use_exporter_aead.then(|| group.next_content_counter()),
            arkret_sdk::EventContentRoutingContext::None,
        )
        .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
        let encrypted = if use_exporter_aead {
            group.encrypt_payload_exporter_aead(realm_id, header, plaintext)
        } else {
            group.encrypt_payload(header, plaintext)
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
    // is lost the moment the epoch advances (forward secrecy). `group.epoch()`
    // is read after any forced commit above, so it matches the epoch the
    // content rides and remains available to a future verified share path.
    let pending_history_secrets = if use_exporter_aead {
        let history_secret = group
            .derive_and_retain_history_secret(realm_id)
            .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
        if history_secret.is_empty() {
            return Err(MlsRuntimeError::Encrypt(
                "MLS history-secret derivation returned an empty secret".to_owned(),
            ));
        }
        prepare_local_authoritative_history_secret(
            state_store,
            secure_store,
            &effective_scope,
            &group,
            group.epoch(),
        )?
    } else {
        None
    };
    let schedule_hash = group.schedule_hash();
    let member_ids = group
        .member_principal_ids()
        .map_err(|error| MlsRuntimeError::Identity(error.to_string()))?;
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
            member_ids,
            encrypted_values,
            commit_envelope,
            Some(new_envelope.with_app_messages_observed(sent)),
            pending_history_secrets,
        ));
    }
    new_envelope = new_envelope
        .carry_epoch_started_at(&snapshot)
        .with_app_messages_observed(snapshot.app_messages_observed.saturating_add(sent));
    state_store
        .save_mls_snapshot_for_scope(&effective_scope, new_envelope)
        .map_err(MlsRuntimeError::Commit)?;
    Ok((
        schedule_hash,
        member_ids,
        encrypted_values,
        None,
        None,
        pending_history_secrets,
    ))
}

/// Encrypt a single message plaintext under the Realm MLS group, binding the
/// closed pre-encryption header, and return the structured
/// [`arkret_sdk::EncryptedPayload`] (not yet wrapped as a wire envelope).
///
/// The caller assembles the spec-canonical `ak.schema.encrypted_envelope.v1`
/// wire shape via [`arkret_sdk::encrypted_envelope_from_payload`] once it
/// knows the accepted group-state reference for this epoch (genesis or latest
/// winning commit). The exact header is retained only in the local payload and
/// reduced to the minimal wire shape at Event assembly time.
type DeviceSnapshotEncryption = (
    arkret_sdk::Hash,
    Vec<arkret_sdk::DidCoreId>,
    arkret_sdk::EncryptedPayload,
    Option<arkret_sdk::EncryptedPayload>,
    Option<PreparedMlsCommit>,
    Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    Option<crate::state::PendingHistorySecrets>,
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
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    content_type: &str,
    event_kind: &str,
    group_state_ref: arkret_sdk::EventId,
    plaintext: &[u8],
    metadata_content_type: Option<&str>,
    metadata_plaintext: Option<&[u8]>,
    expected_sender_domain: Option<&str>,
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
    let is_minimal_metadata = state_store.realm_projection_is_minimal_metadata(realm_id);
    let secret = load_device_snapshot_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: send/encrypt under the Seal-view epoch floor so encrypting from a
    // stale local snapshot (below the Seal lattice) is rejected as OutdatedSnapshot
    // rather than producing ciphertext on a forked ratchet.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    if let Some(expected_sender_domain) = expected_sender_domain {
        let active_sender_domain = group
            .local_content_sender_domain()
            .map_err(|error| MlsRuntimeError::Identity(error.to_string()))?;
        if active_sender_domain != expected_sender_domain {
            return Err(MlsRuntimeError::EncryptionTransitionPending);
        }
    }
    if sidecar_binding.is_none() {
        ensure_realm_membership_is_covered_for_send(state_store, realm_id, circle, &group)?;
    }
    let use_exporter_aead = sidecar_binding.is_none()
        && realm_content_scheme_is_exporter_aead_for_send(state_store, realm_id, circle)?;
    verify_exporter_sender_domain_for_send(
        device_id.as_str(),
        is_minimal_metadata,
        use_exporter_aead,
    )?;
    let should_commit = should_force_epoch_advance(
        is_minimal_metadata,
        snapshot.epoch_started_at,
        crate::clock::now_utc(),
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    );
    if should_commit {
        return Err(MlsRuntimeError::EncryptionTransitionPending);
    }
    let commit_envelope = None;
    // §2.10 content scheme dispatch — see `encrypt_values_with_device_snapshot`.
    let encrypt_one =
        |group: &mut arkret_sdk::ArkretMlsGroup, payload_content_type: &str, bytes: &[u8]| {
            let scheme = if use_exporter_aead {
                arkret_sdk::EncryptedPayloadScheme::MlsExporterAeadV1
            } else {
                arkret_sdk::EncryptedPayloadScheme::MlsRfc9420
            };
            let sender_domain = group
                .local_content_sender_domain()
                .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
            let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
                "1.0",
                payload_content_type,
                scheme,
                effective_scope.clone(),
                event_kind,
                group.epoch(),
                group_state_ref.clone(),
                sender_domain,
                use_exporter_aead.then(|| group.next_content_counter()),
                arkret_sdk::EventContentRoutingContext::None,
            )
            .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
            if use_exporter_aead {
                group.encrypt_payload_exporter_aead(realm_id, header, bytes)
            } else {
                group.encrypt_payload(header, bytes)
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
        prepare_local_authoritative_history_secret(
            state_store,
            secure_store,
            &effective_scope,
            &group,
            group.epoch(),
        )?
    } else {
        None
    };
    let schedule_hash = group.schedule_hash();
    let member_ids = group
        .member_principal_ids()
        .map_err(|error| MlsRuntimeError::Identity(error.to_string()))?;
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
            member_ids,
            encrypted,
            encrypted_metadata,
            commit_envelope,
            Some(new_envelope.with_app_messages_observed(sent)),
            pending_history_secrets,
        ));
    }
    new_envelope = new_envelope
        .carry_epoch_started_at(&snapshot)
        .with_app_messages_observed(snapshot.app_messages_observed.saturating_add(sent));
    state_store
        .save_mls_snapshot_for_scope(&effective_scope, new_envelope)
        .map_err(MlsRuntimeError::Commit)?;
    Ok((
        schedule_hash,
        member_ids,
        encrypted,
        encrypted_metadata,
        None,
        None,
        pending_history_secrets,
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
        .map_err(|error| MlsRuntimeError::Identity(error.to_string()))?
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
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
) -> Option<bool> {
    let joined = state_store.complete_joined_member_hint_for_realm(realm_id)?;
    let members = mls_group_member_principal_ids_for_realm(
        state_store,
        secure_store,
        realm_id,
        authority,
        device_id,
    )?
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    Some(members == joined)
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

#[cfg(test)]
mod endpoint_tests {
    use super::welcome_recipient_endpoint;

    #[test]
    fn native_agent_welcome_recipient_keeps_the_runtime_authority_tuple() {
        let agent_id = crate::mls_api_helpers::principal_core_id("did:web:agent.example").unwrap();
        let method =
            arkret_sdk::DidUrl::new("did:web:agent.example#runtime-key".to_owned()).unwrap();
        let authorization_ref =
            arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                .unwrap();
        let endpoint = welcome_recipient_endpoint(
            &Some(agent_id.clone()),
            arkret_sdk::MlsWelcomeRecipient::NativeAgent {
                recipient_agent_id: agent_id.clone(),
                recipient_agent_verification_method: method.clone(),
                agent_key_authorize_event_id: authorization_ref.clone(),
            },
        )
        .unwrap();

        assert_eq!(
            endpoint,
            arkret_sdk::MlsEndpointIdentity::NativeAgentRuntime {
                agent_id,
                verification_method: method,
                agent_key_authorize_event_id: authorization_ref,
            }
        );
    }

    #[test]
    fn pairwise_welcome_recipient_has_no_account_principal_mirror() {
        let actor = arkret_sdk::DidCoreId::new(
            "ak:did_core:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x".to_owned(),
        )
        .unwrap();
        let method = arkret_sdk::DidUrl::new(
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x".to_owned(),
        )
        .unwrap();
        let endpoint = welcome_recipient_endpoint(
            &None,
            arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise {
                recipient_pairwise_actor_id: actor.clone(),
                recipient_pairwise_verification_method: method.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            endpoint,
            arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise {
                pairwise_actor_id: actor,
                verification_method: method,
            }
        );
    }
}
