//! Welcome application, application-payload encrypt / decrypt, and the SEC-08
//! minimal-metadata AAD policy enforcement.

use arkret_sdk::{AccountId, DeviceId};
use arkret_wire::event_kind_str;

use super::{
    MlsRuntimeError, load_device_checkpoint_secret, load_mls_key_package_identity_state,
    should_force_epoch_advance,
};
use crate::secure_key_store::SecureKeyStore;

pub(crate) fn warn_mls_decrypt_once(
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
    /// Welcomes skipped because a snapshot at an equal-or-higher
    /// epoch for the same group already exists (a replayed / stale Welcome that
    /// would otherwise roll the local MLS snapshot back to the join epoch).
    pub skipped_stale: usize,
    pub first_error: Option<String>,
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
    authority: &AccountId,
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
    let group_id = effective_scope.canonical_mls_group_id().ok()?;
    let warn_pending = |reason: &str| {
        warn_mls_decrypt_once(
            effective_scope
                .realm_id_opt()
                .map(|id| id.as_str())
                .unwrap_or_default(),
            envelope
                .payload_digest()
                .map(|digest| digest.to_string())
                .unwrap_or_default()
                .as_str(),
            envelope.encryption_context.epoch(),
            state_store
                .mls_checkpoint_for_scope(effective_scope)
                .map(|snapshot| snapshot.epoch),
            reason,
        );
    };
    let scheme = arkret_sdk::EncryptedPayloadScheme::MlsRfc9420;
    if !matches!(effective_scope, arkret_sdk::ScopeRef::Sidecar { .. })
        && matches!(
            state_store.installed_scope_mls_current(effective_scope),
            crate::current_projection::ScopeMlsCurrent::NotActivated
        )
    {
        warn_pending("the scope has no accepted MLS Genesis, so it carries no ciphertext");
        return None;
    }
    let accepted_ref = state_store
        .mls_group_state_ref_for_scope(
            effective_scope,
            &group_id,
            envelope.encryption_context.epoch(),
        )
        .map_err(|error| warn_pending(&error))
        .ok()?;
    if accepted_ref != *envelope.encryption_context.group_state_ref() {
        warn_pending("encrypted Event cites a different accepted MLS group-state reference");
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
        .map_err(|error| warn_pending(&format!("reconstruct encrypted Event header: {error}")))
        .ok()?;
    arkret_sdk::mls::encrypted_envelope_to_payload_with_verified_header(envelope, header)
        .map_err(|error| warn_pending(&format!("reconstruct encrypted Event payload: {error}")))
        .ok()
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_application_payload_for_scope_from_verified_sender(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
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
    authority: &AccountId,
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
    let pairwise_actor = arkret_sdk::ActorId::service(identity_link.pairwise_actor_id.clone());
    let pairwise_credential = arkret_sdk::mls_basic_credential_identity(&pairwise_actor).ok()?;
    let trusted_domain = state_store.load().server_trust_domain?;
    if canonical != plaintext
        || identity_link.status != arkret_sdk::IdentityLinkStatus::Active
        || pairwise_credential.as_slice() != verified_sender_domain
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
    let view = verified_author_group_view_for_scope(
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
                    if identity.as_slice() == pairwise_credential.as_slice()
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
    authority: &AccountId,
    device_id: &DeviceId,
    payload: &arkret_sdk::EncryptedPayload,
    effective_scope: &arkret_sdk::ScopeRef,
    verified_sender_domain: Option<&[u8]>,
) -> Option<Vec<u8>> {
    if state_store.realm_projection_has_retired_minimal_metadata_marker(realm_id) {
        return None;
    }
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
    // Decryption needs this device's own installed group state: MLS content is
    // readable only by an endpoint that holds a leaf in the group. A device
    // that has not been welcomed into the scope has nothing to try.
    let Some(snapshot) = state_store.mls_checkpoint_for_scope(effective_scope) else {
        if !sidecar_scoped {
            warn_mls_decrypt_once(
                realm_id,
                digest,
                payload.epoch,
                None,
                "no local MLS group state for this scope",
            );
        }
        return None;
    };
    let secret = match load_device_checkpoint_secret(secure_store, authority, device_id) {
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
    // Read/decrypt path: floor 0 is intentional. The receive ratchet legitimately
    // reads epochs at or below the installed one, so an epoch-floor reject here
    // would refuse readable content. No ratchet advance happens before the
    // write-back below.
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
            if !sidecar_scoped {
                warn_mls_decrypt_once(
                    realm_id,
                    digest,
                    payload.epoch,
                    Some(snapshot.epoch),
                    &format!("MLS decrypt failed ({live_error})"),
                );
            }
            return None;
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

/// Resolve a locally verified MLS group state for an exact accepted epoch and
/// group-state Event. Identity-link admission uses this generic leaf view;
/// it must not fall back to the current epoch or a different commit.
#[allow(clippy::too_many_arguments)]
pub fn verified_author_group_view(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    device_id: &DeviceId,
    group_id: &str,
    epoch: u64,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::AuthorGroupStateView> {
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?,
    };
    verified_author_group_view_for_scope(
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
pub fn verified_author_group_view_for_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    effective_scope: &arkret_sdk::ScopeRef,
    group_id: &str,
    epoch: u64,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::AuthorGroupStateView> {
    let group = restore_author_group_for_scope(
        state_store,
        secure_store,
        authority,
        device_id,
        effective_scope,
        group_id,
        epoch,
        group_state_ref,
    )?;
    Some(group.author_group_state_view(group_state_ref))
}

#[cfg(test)]
mod agent_authorization_tests {
    use super::*;

    #[test]
    fn same_key_reauthorization_cannot_replace_the_accepted_leaf_authorization() {
        let actor = crate::test_support::account_actor("did:web:agent.example");
        let authorization =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [51; 32]);
        let replacement =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [52; 32]);
        let method = arkret_sdk::DidUrl::new("did:web:agent.example#runtime").unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let key = signing.verifying_key().to_bytes();
        let identity = arkret_sdk::ArkretMlsIdentity::new_agent(
            actor.clone(),
            method,
            authorization.clone(),
            arkret_sdk::ArkretMlsSigner::from_ed25519_signing_key(signing),
        )
        .unwrap();
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
        };
        let mut group = identity.create_group(&scope).unwrap();
        group
            .install_local_creator_binding(actor.clone(), None)
            .unwrap();
        let state_ref = authorization.as_str();
        let view = agent_author_view_from_verified_group(&group, state_ref).unwrap();
        let group_id = group.group_id();
        let mut claim = arkret_sdk::mls::AgentMlsSignerClaim {
            group_id: group_id.as_str(),
            epoch: group.epoch(),
            group_state_ref: state_ref,
            signer_actor_id: &actor,
            signing_key: &key,
            agent_key_authorize_event_id: &authorization,
        };
        assert_eq!(
            arkret_sdk::mls::verify_ordinary_agent_mls_binding(&view, &claim).unwrap(),
            0
        );
        claim.agent_key_authorize_event_id = &replacement;
        assert!(arkret_sdk::mls::verify_ordinary_agent_mls_binding(&view, &claim).is_err());
    }
}

#[allow(clippy::too_many_arguments)]
fn restore_author_group_for_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    effective_scope: &arkret_sdk::ScopeRef,
    group_id: &str,
    epoch: u64,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::ArkretMlsGroup> {
    let realm_id = effective_scope.realm_id_opt()?.as_str();
    let circle_id = match effective_scope {
        arkret_sdk::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str()),
        _ => None,
    };
    let snapshot = state_store
        .mls_checkpoint_for_scope(effective_scope)
        .filter(|snapshot| snapshot.epoch == epoch && snapshot.group_id == group_id)
        .or_else(|| {
            state_store
                .historical_mls_checkpoint_for_effective_scope(realm_id, circle_id, group_id, epoch)
        })?;
    let accepted_ref = state_store
        .mls_group_state_ref_for_effective_scope(realm_id, circle_id, group_id, epoch)
        .ok()?;
    if accepted_ref.as_str() != group_state_ref {
        return None;
    }
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id).ok()?;
    // COR-04: read-only restore — no ratchet advance / persist on this path.
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    if group.group_id().as_str() != group_id || group.epoch() != epoch {
        return None;
    }
    Some(group)
}

#[allow(clippy::too_many_arguments)]
pub fn ordinary_agent_mls_author_view(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    device_id: &DeviceId,
    group_id: &str,
    epoch: u64,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::AgentMlsSignerView> {
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?,
    };
    let group = restore_author_group_for_scope(
        state_store,
        secure_store,
        authority,
        device_id,
        &scope,
        group_id,
        epoch,
        group_state_ref,
    )?;
    agent_author_view_from_verified_group(&group, group_state_ref)
}

fn agent_author_view_from_verified_group(
    group: &arkret_sdk::ArkretMlsGroup,
    group_state_ref: &str,
) -> Option<arkret_sdk::mls::AgentMlsSignerView> {
    let group_state = group.author_group_state_view(group_state_ref);
    let leaves = group.verified_leaf_bindings().ok()?;
    let mut leaf_authorization_refs = Vec::new();
    for leaf in &group_state.active_leaves {
        let arkret_sdk::mls::AuthorLeafCredential::Basic { identity } = &leaf.credential else {
            continue;
        };
        let Ok(signer_actor) = arkret_sdk::decode_mls_basic_credential_identity(identity) else {
            continue;
        };
        let Some(identity) = leaves.iter().find(|binding| {
            binding.leaf_index == leaf.leaf_index && binding.actor_id == signer_actor
        }) else {
            continue;
        };
        // The verified roster binds the exact accepted authorization instance.
        // Key equality cannot substitute for it when a runtime is reauthorized.
        if let arkret_sdk::MlsEndpointIdentity::AgentRuntime {
            agent_key_authorize_event_id,
            ..
        } = &identity.endpoint
        {
            leaf_authorization_refs.push((leaf.leaf_index, agent_key_authorize_event_id.clone()));
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

/// The complete member identities occupying this scope's MLS group.
pub(crate) fn mls_group_member_actor_ids_for_effective_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Option<Vec<arkret_sdk::ActorId>> {
    let snapshot = state_store.mls_checkpoint_for_effective_scope(realm_id, circle_id)?;
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(|error| {
            tracing::warn!("MLS reconciliation checkpoint key is unavailable");
            error
        })
        .ok()?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|error| {
            tracing::warn!("MLS reconciliation checkpoint restore failed");
            error
        })
        .ok()?;
    group
        .member_actor_ids()
        .map_err(|error| {
            tracing::warn!("MLS reconciliation verified leaf bindings are unavailable");
            error
        })
        .ok()
}

/// Active human-device leaves for one effective MLS scope. Realm membership is
/// actor-scoped, but each authorized endpoint needs its own leaf and its own
/// Welcome delivery, so this projection stays separate from
/// `member_actor_ids`, which deduplicates devices of the same account actor.
pub(crate) fn mls_group_member_device_ids_for_effective_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Option<Vec<DeviceId>> {
    let snapshot = state_store.mls_checkpoint_for_effective_scope(realm_id, circle_id)?;
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id).ok()?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    Some(
        group
            .verified_leaf_bindings()
            .ok()?
            .into_iter()
            .filter_map(|binding| match binding.endpoint {
                arkret_sdk::MlsEndpointIdentity::HumanDevice { device_id, .. } => Some(device_id),
                arkret_sdk::MlsEndpointIdentity::AgentRuntime { .. }
                | arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => None,
            })
            .collect(),
    )
}

fn export_receive_chain_envelope(
    group: &arkret_sdk::ArkretMlsGroup,
    realm_id: &str,
    secret: &str,
    previous: &crate::mls::persistence::MlsLocalCheckpointEnvelope,
) -> Result<crate::mls::persistence::MlsLocalCheckpointEnvelope, MlsRuntimeError> {
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|err| MlsRuntimeError::Encrypt(format!("MLS checkpoint salt: {err}")))?;
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

#[cfg(test)]
pub(crate) fn encrypt_values_with_device_snapshot(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    device_id: &DeviceId,
    content_type: &str,
    plaintext_values: &[Vec<u8>],
) -> Result<(Vec<arkret_sdk::DidCoreId>, Vec<serde_json::Value>), MlsRuntimeError> {
    super::reject_retired_minimal_metadata_realm(state_store, realm_id)?;
    let effective_scope = runtime_effective_scope(realm_id, None, None)?;
    let snapshot = state_store
        .mls_checkpoint_for_scope(&effective_scope)
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_values_with_device_snapshot_for_effective_scope(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    device_id: &DeviceId,
    content_type: &str,
    plaintext_values: &[Vec<u8>],
    event_kind: &str,
    group_state_ref: arkret_sdk::EventId,
    circle_id: Option<&str>,
    sidecar_id: Option<&arkret_sdk::SidecarId>,
) -> Result<(Vec<arkret_sdk::DidCoreId>, Vec<serde_json::Value>), MlsRuntimeError> {
    super::reject_retired_minimal_metadata_realm(state_store, realm_id)?;
    if plaintext_values.is_empty() {
        return Err(MlsRuntimeError::EmptyPlaintext);
    }
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let effective_scope = runtime_effective_scope(realm_id, circle, sidecar_id)?;
    let snapshot = state_store
        .mls_checkpoint_for_scope(&effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // Encrypt under the accepted epoch floor so authoring from a stale local
    // checkpoint is rejected as an outdated checkpoint rather than producing
    // ciphertext on a forked ratchet.
    let epoch_floor = super::accepted_mls_epoch_floor_for_scope(state_store, &effective_scope);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::CheckpointRestore(err.to_string()))?;
    if sidecar_id.is_none() {
        ensure_realm_membership_is_covered_for_send(state_store, realm_id, circle, &group)?;
    }
    // A due epoch advance pauses the send: the commit has to be authored,
    // accepted and installed before content may ride a new epoch.
    if should_force_epoch_advance(
        snapshot.epoch_started_at,
        crate::clock::now_utc(),
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    ) {
        return Err(MlsRuntimeError::EncryptionTransitionPending);
    }
    let mut encrypted_values = Vec::with_capacity(plaintext_values.len());
    let mut authored_digests = Vec::with_capacity(plaintext_values.len());
    for plaintext in plaintext_values {
        let sender_domain = group
            .local_content_sender_domain()
            .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            content_type,
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            effective_scope.clone(),
            event_kind,
            group.epoch(),
            group_state_ref.clone(),
            sender_domain,
            arkret_sdk::EventContentRoutingContext::None,
        )
        .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
        let encrypted = group
            .encrypt_payload(header, plaintext)
            .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))?;
        authored_digests.push(encrypted.payload_digest.clone());
        encrypted_values.push(
            serde_json::to_value(&encrypted)
                .map_err(|err| MlsRuntimeError::Serialize(err.to_string()))?,
        );
    }
    let member_ids = group
        .member_principal_ids()
        .map_err(|error| MlsRuntimeError::Identity(error.to_string()))?;
    let sent = plaintext_values.len() as u64;
    let new_envelope = persist_send_ratchet(
        state_store,
        &effective_scope,
        &group,
        realm_id,
        &secret,
        &snapshot,
        sent,
    )?;
    let _ = new_envelope;
    for (digest, plaintext) in authored_digests.iter().zip(plaintext_values) {
        state_store
            .retain_authored_mls_plaintext(realm_id, digest, plaintext)
            .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?;
    }
    Ok((member_ids, encrypted_values))
}

/// Persist the post-send ratchet state. The send advanced the sender ratchet,
/// so failing to persist it would make the next send reuse a consumed key.
fn persist_send_ratchet(
    state_store: &mut crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    group: &arkret_sdk::ArkretMlsGroup,
    realm_id: &str,
    secret: &str,
    previous: &crate::mls::persistence::MlsLocalCheckpointEnvelope,
    sent: u64,
) -> Result<crate::mls::persistence::MlsLocalCheckpointEnvelope, MlsRuntimeError> {
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|err| MlsRuntimeError::Encrypt(format!("MLS checkpoint salt: {err}")))?;
    let new_envelope = crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        secret,
        &salt,
    )
    .carry_epoch_started_at(previous)
    .with_app_messages_observed(previous.app_messages_observed.saturating_add(sent));
    state_store
        .save_mls_checkpoint_for_scope(effective_scope, new_envelope.clone())
        .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?;
    Ok(new_envelope)
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
/// One message content ciphertext and its optional `encrypted_metadata`
/// companion, both authored on the same restored group session.
pub(crate) struct DeviceSnapshotEncryption {
    pub(crate) member_ids: Vec<arkret_sdk::DidCoreId>,
    pub(crate) content: arkret_sdk::EncryptedPayload,
    pub(crate) metadata: Option<arkret_sdk::EncryptedPayload>,
}

/// Encrypt one message content plaintext — and optionally a second
/// `encrypted_metadata` plaintext — under the SAME restored group session, so
/// both ciphertexts ride the same epoch. Callers MUST NOT encrypt the metadata
/// with a separate call: a second restore from the same checkpoint would fork
/// the ratchet.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_message_with_device_snapshot(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    device_id: &DeviceId,
    content_type: &str,
    event_kind: &str,
    group_state_ref: arkret_sdk::EventId,
    plaintext: &[u8],
    metadata_content_type: Option<&str>,
    metadata_plaintext: Option<&[u8]>,
    expected_sender_domain: Option<&str>,
    circle_id: Option<&str>,
    sidecar_id: Option<&arkret_sdk::SidecarId>,
) -> Result<DeviceSnapshotEncryption, MlsRuntimeError> {
    super::reject_retired_minimal_metadata_realm(state_store, realm_id)?;
    if metadata_content_type.is_some() != metadata_plaintext.is_some() {
        return Err(MlsRuntimeError::Serialize(
            "metadata content type and plaintext must be supplied together".to_owned(),
        ));
    }
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let effective_scope = runtime_effective_scope(realm_id, circle, sidecar_id)?;
    let snapshot = state_store
        .mls_checkpoint_for_scope(&effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    if circle.is_none()
        && sidecar_id.is_none()
        && state_store.realm_collaboration_role(realm_id)
            == Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
    {
        let context = state_store
            .direct_message_context(realm_id, &arkret_sdk::ActorId::account(authority.clone()))
            .ok_or(MlsRuntimeError::EncryptionTransitionPending)?;
        let local_ref = state_store
            .mls_group_state_ref_for_scope(&effective_scope, &snapshot.group_id, snapshot.epoch)
            .map_err(|_| MlsRuntimeError::EncryptionTransitionPending)?;
        if local_ref != context.group_state_ref {
            return Err(MlsRuntimeError::EncryptionTransitionPending);
        }
    }
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // Encrypt under the accepted epoch floor so authoring from a stale local
    // checkpoint is rejected as an outdated checkpoint rather than producing
    // ciphertext on a forked ratchet.
    let epoch_floor = super::accepted_mls_epoch_floor_for_scope(state_store, &effective_scope);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::CheckpointRestore(err.to_string()))?;
    if let Some(expected_sender_domain) = expected_sender_domain {
        let active_sender_domain = group
            .local_content_sender_domain()
            .map_err(|error| MlsRuntimeError::Identity(error.to_string()))?;
        if active_sender_domain != expected_sender_domain {
            return Err(MlsRuntimeError::EncryptionTransitionPending);
        }
    }
    if sidecar_id.is_none() {
        ensure_realm_membership_is_covered_for_send(state_store, realm_id, circle, &group)?;
    }
    if should_force_epoch_advance(
        snapshot.epoch_started_at,
        crate::clock::now_utc(),
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    ) {
        return Err(MlsRuntimeError::EncryptionTransitionPending);
    }
    let mut encrypt_one =
        |group: &mut arkret_sdk::ArkretMlsGroup, payload_content_type: &str, bytes: &[u8]| {
            let sender_domain = group
                .local_content_sender_domain()
                .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
            let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
                "1.0",
                payload_content_type,
                arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
                effective_scope.clone(),
                event_kind,
                group.epoch(),
                group_state_ref.clone(),
                sender_domain,
                arkret_sdk::EventContentRoutingContext::None,
            )
            .map_err(|error| MlsRuntimeError::Encrypt(error.to_string()))?;
            group
                .encrypt_payload(header, bytes)
                .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))
        };
    let content = encrypt_one(&mut group, content_type, plaintext)?;
    // The optional `encrypted_metadata` plaintext is a second application
    // message on the same ratchet, bound to the same canonical AAD as the
    // content envelope.
    let metadata = metadata_plaintext
        .zip(metadata_content_type)
        .map(|(metadata, metadata_content_type)| {
            encrypt_one(&mut group, metadata_content_type, metadata)
        })
        .transpose()?;
    let member_ids = group
        .member_principal_ids()
        .map_err(|error| MlsRuntimeError::Identity(error.to_string()))?;
    let sent = 1 + u64::from(metadata.is_some());
    persist_send_ratchet(
        state_store,
        &effective_scope,
        &group,
        realm_id,
        &secret,
        &snapshot,
        sent,
    )?;
    state_store
        .retain_authored_mls_plaintext(realm_id, &content.payload_digest, plaintext)
        .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?;
    if let (Some(metadata), Some(plaintext)) = (&metadata, metadata_plaintext) {
        state_store
            .retain_authored_mls_plaintext(realm_id, &metadata.payload_digest, plaintext)
            .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?;
    }
    Ok(DeviceSnapshotEncryption {
        member_ids,
        content,
        metadata,
    })
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
    let Some(joined) = state_store
        .complete_joined_member_hint_for_realm(realm_id)
        .map_err(|error| MlsRuntimeError::Identity(error.to_string()))?
    else {
        return Ok(());
    };
    let group_members = group
        .member_actor_ids()
        .map_err(|error| MlsRuntimeError::Identity(error.to_string()))?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if !realm_membership_matches_sending_group(
        state_store,
        realm_id,
        group,
        &joined,
        &group_members,
    ) {
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
    authority: &AccountId,
    device_id: &DeviceId,
) -> Option<bool> {
    let joined = match state_store.complete_joined_member_hint_for_realm(realm_id) {
        Ok(joined) => joined?,
        Err(_) => return Some(false),
    };
    let snapshot = state_store.mls_checkpoint_for_effective_scope(realm_id, None)?;
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id).ok()?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).ok()?;
    let members = group
        .member_actor_ids()
        .ok()?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    Some(realm_membership_matches_sending_group(
        state_store,
        realm_id,
        &group,
        &joined,
        &members,
    ))
}

/// Before the peer Add, the registered Direct bootstrap source authorizes
/// the verified founder's epoch-zero leaf. Realm membership already includes
/// both participants, but no peer history key exists before its Add/Welcome.
fn realm_membership_matches_sending_group(
    state: &crate::state::LocalStateStore,
    realm_id: &str,
    group: &arkret_sdk::ArkretMlsGroup,
    joined: &std::collections::BTreeSet<arkret_sdk::ActorId>,
    members: &std::collections::BTreeSet<arkret_sdk::ActorId>,
) -> bool {
    if members == joined {
        return true;
    }
    let actor = group.local_actor_id();
    if state.realm_collaboration_role(realm_id)
        != Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
        || group.epoch() != 0
        || joined.len() != 2
        || !joined.contains(actor)
        || members.len() != 1
        || !members.contains(actor)
    {
        return false;
    }
    let Some(context) = state.direct_message_context(realm_id, actor) else {
        return false;
    };
    let Some(peer) = state.direct_conversation_peer(realm_id) else {
        return false;
    };
    let peer = peer.contact_actor_id();
    if peer == *actor || !joined.contains(&peer) {
        return false;
    }
    if context.authority_source
        != arkret_wire::AuthoritySourceId::DirectConversationBootstrapParticipantV1
    {
        return false;
    }
    let Ok(realm) = arkret_sdk::RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    if arkret_sdk::RealmId::from_event_id(&context.authority_event_ref) != realm {
        return false;
    }
    let scope = arkret_sdk::ScopeRef::Realm { realm_id: realm };
    let Some(current) = state.current_mls_group_for_scope(&scope) else {
        return false;
    };
    current.epoch == 0
        && current.current_key_access_revision == current.covered_key_access_revision
        && current.genesis_event_ref == context.group_state_ref
        && current.current_mls_commit_event_ref == context.group_state_ref
        && state
            .mls_group_state_ref_for_scope(&scope, group.group_id().as_str(), 0)
            .is_ok_and(|reference| reference == context.group_state_ref)
}

fn runtime_effective_scope(
    realm_id: &str,
    circle_id: Option<&str>,
    sidecar_id: Option<&arkret_sdk::SidecarId>,
) -> Result<arkret_sdk::ScopeRef, MlsRuntimeError> {
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| MlsRuntimeError::Serialize(format!("invalid MLS Realm id: {error}")))?;
    if let Some(sidecar_id) = sidecar_id {
        return Ok(arkret_sdk::ScopeRef::Sidecar {
            realm_id,
            sidecar_id: sidecar_id.clone(),
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
