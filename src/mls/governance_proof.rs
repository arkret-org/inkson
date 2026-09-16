//! Host-side construction of the `governance_binding` an `ak.mls.genesis` /
//! `ak.mls.commit` Event carries, plus the verified leaf attribution that a
//! group needs after every transition.
//!
//! There is no governance proof round-trip any more: the accepted `RealmCommit`
//! on the scope's own stream is the ordering and governance authority, so the
//! coordinates a producer must bind come straight from the scope's current MLS
//! group state (`CurrentSelector::MlsGroup`) in the authority-signed Realm
//! snapshot, and from the exact accepted base transition this client already
//! installed.
//!
//! Member attribution is the other half. `ArkretMlsGroup` clears its leaf
//! bindings whenever it merges an accepted Commit, and the SDK refuses every
//! roster read until the caller installs the complete post-transition map. The
//! host is the only party that can build that map, because it holds both the
//! pre-transition bindings and the checked KeyPackage claim evidence for every
//! newly added leaf.

use std::collections::BTreeMap;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait GovernanceProofStateStorePlatform: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> GovernanceProofStateStorePlatform for T {}
#[cfg(target_arch = "wasm32")]
pub(crate) trait GovernanceProofStateStorePlatform {}
#[cfg(target_arch = "wasm32")]
impl<T> GovernanceProofStateStorePlatform for T {}

pub(crate) trait GovernanceProofStateStore:
    Clone + GovernanceProofStateStorePlatform + 'static
{
    fn with_read<R>(&self, read: impl FnOnce(&crate::state::LocalStateStore) -> R) -> R;
    fn with_write<R>(&self, write: impl FnOnce(&mut crate::state::LocalStateStore) -> R) -> R;
}

impl GovernanceProofStateStore for crate::runtime::input::StateStoreHandle {
    fn with_read<R>(&self, read: impl FnOnce(&crate::state::LocalStateStore) -> R) -> R {
        self.read(read)
    }

    fn with_write<R>(&self, write: impl FnOnce(&mut crate::state::LocalStateStore) -> R) -> R {
        self.write(write)
    }
}

/// The MLS governance binding for an epoch-zero `ak.mls.genesis`.
///
/// Genesis is the only transition with no base group state, and it always
/// declares key-access revision zero: the scope has no accepted membership
/// revision to cover before its own group exists.
pub(crate) fn genesis_binding(
    effective_scope: &arkret_sdk::ScopeRef,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    arkret_sdk::MlsGovernanceBindingPayload::new(effective_scope.clone(), None, 0, 0, 0)
        .map_err(|error| format!("invalid MLS Genesis governance binding: {error}"))
}

/// The MLS governance binding for a `previous_epoch -> next_epoch` transition.
///
/// `base_group_state_ref` is the accepted `ak.mls.genesis` / `ak.mls.commit`
/// Event that materialized `previous_epoch` for this exact scope and group; the
/// client refuses to author a transition it cannot name that base for.
/// `key_access_revision` is the scope's current key-access revision as the
/// Station published it, so an accepted Commit records exactly which membership
/// revision its new epoch covers.
pub(crate) fn binding_for_transition(
    state_store: &crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    mls_group_id: &str,
    previous_epoch: u64,
    next_epoch: u64,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    if previous_epoch == 0 && next_epoch == 0 {
        return genesis_binding(effective_scope);
    }
    let base_group_state_ref =
        state_store.mls_group_state_ref_for_scope(effective_scope, mls_group_id, previous_epoch)?;
    let key_access_revision = current_key_access_revision(state_store, effective_scope)?;
    arkret_sdk::MlsGovernanceBindingPayload::new(
        effective_scope.clone(),
        Some(base_group_state_ref),
        previous_epoch,
        next_epoch,
        key_access_revision,
    )
    .map_err(|error| format!("invalid MLS transition governance binding: {error}"))
}

/// The key-access revision the scope's current MLS group state declares.
///
/// A scope whose snapshot has not delivered `CurrentSelector::MlsGroup` yet has
/// no authoritative revision. That is not a licence to guess: authoring a
/// transition that under-declares its coverage would silently leave a
/// membership change uncovered, so the read fails closed.
pub(crate) fn current_key_access_revision(
    state_store: &crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
) -> Result<u64, String> {
    state_store
        .current_mls_group_for_scope(effective_scope)
        .map(|current| current.current_key_access_revision)
        .ok_or_else(|| {
            "MLS authoring requires the scope's current key-access revision".to_owned()
        })
}

/// The verified authority a newly occupied MLS leaf binds to.
///
/// A human device leaf binds to its accepted `ak.device.authorize` Event; an
/// Agent runtime leaf binds to its endpoint identity, which already carries the
/// accepted `ak.agent.key.authorize` reference.
#[derive(Clone, Debug)]
pub(crate) struct MlsLeafAuthorityHint {
    pub(crate) endpoint: arkret_sdk::MlsEndpointIdentity,
    pub(crate) device_authorize_event_id: Option<arkret_sdk::EventId>,
}

pub(crate) fn leaf_authority_hint_from_claim(
    claim: &arkret_sdk::KeyPackageClaimRecord,
) -> Result<MlsLeafAuthorityHint, String> {
    claim
        .validate_shape()
        .map_err(|error| format!("invalid claimed MLS leaf authority: {error}"))?;
    let endpoint = crate::mls_api_helpers::keypackage_claim_record_to_mls_record(claim)
        .map_err(|error| format!("invalid claimed MLS endpoint: {error}"))?
        .endpoint;
    Ok(MlsLeafAuthorityHint {
        endpoint,
        device_authorize_event_id: claim.device_authorize_event_id.clone(),
    })
}

/// Recover the complete target only from the checked peer claim receipt,
/// never from the inviting client's selected Station.
pub(crate) fn claimed_actor_id(
    claim: &arkret_sdk::KeyPackageClaimRecord,
    receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<arkret_sdk::ActorId, String> {
    arkret_sdk::validate_target_claim_evidence(claim, receipt)
        .map_err(|error| format!("invalid target claim evidence: {error}"))?;
    if claim.pairwise_verification_method.is_some() {
        return Ok(arkret_sdk::ActorId::service(claim.principal_id.clone()));
    }
    // Agent and human-device claims produce the same account ActorId. An Agent
    // is a Station-carried account, and `validate_target_claim_evidence` above
    // has already refused any Agent claim whose `agent_id` is not literally
    // `principal_id`, so there is no second principal to project here.
    Ok(arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        claim.principal_id.clone(),
        receipt.destination_id.clone(),
    )))
}

/// Install the complete verified leaf-binding map for the group's current
/// epoch.
///
/// `previous` is the exact binding map the group held before the transition
/// (read with `verified_leaf_bindings()` before merging the accepted Commit, or
/// carried across from the restored snapshot). A leaf that is still occupied by
/// the identical RFC 9420 credential and signature key keeps its verified
/// binding; every newly occupied leaf must be covered by `authority_hints`,
/// which come from checked KeyPackage claim evidence. A leaf that neither
/// matches a retained binding nor has verified Add authority fails closed
/// rather than being attributed from BasicCredential bytes alone.
pub(crate) fn install_post_transition_leaf_bindings(
    group: &mut arkret_sdk::ArkretMlsGroup,
    previous: &[arkret_sdk::MlsVerifiedLeafBinding],
    authority_hints: &[MlsLeafAuthorityHint],
) -> Result<(), String> {
    let retained = previous
        .iter()
        .map(|binding| (binding.leaf_index, binding))
        .collect::<BTreeMap<_, _>>();
    let mut installed = Vec::new();
    for leaf in group.active_author_leaves() {
        let arkret_sdk::mls::AuthorLeafCredential::Basic { identity } = &leaf.credential else {
            return Err("accepted Arkret MLS leaf does not use BasicCredential".to_owned());
        };
        let credential = std::str::from_utf8(identity)
            .map_err(|_| "MLS leaf credential is not UTF-8".to_owned())?
            .to_owned();
        let signature_key: [u8; 32] = leaf
            .signature_key
            .as_slice()
            .try_into()
            .map_err(|_| "accepted MLS leaf signature key is not Ed25519".to_owned())?;
        let multibase = arkret_sdk::ed25519_pubkey_to_did_key_multibase(&signature_key);
        let signature_key_b64 =
            arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(signature_key))
                .map_err(|error| format!("invalid accepted MLS leaf key: {error}"))?;

        if let Some(binding) = retained.get(&leaf.leaf_index)
            && binding.credential_ref.as_str() == credential
            && binding.signature_key == signature_key_b64
        {
            installed.push((*binding).clone());
            continue;
        }

        let (actor_id, endpoint, device_authorize_event_id) =
            if arkret_sdk::DeviceId::new(credential.clone()).is_ok() {
                let mut matches = authority_hints.iter().filter(|hint| {
                    matches!(
                        &hint.endpoint,
                        arkret_sdk::MlsEndpointIdentity::HumanDevice { device_id, .. }
                            if device_id.as_str() == credential
                    )
                });
                let hint = matches
                    .next()
                    .ok_or_else(|| "new ordinary MLS leaf has no verified Add authority".to_owned())?;
                if matches.next().is_some() {
                    return Err("ordinary MLS leaf has duplicate authority hints".to_owned());
                }
                let authority = hint.device_authorize_event_id.clone().ok_or_else(|| {
                    "ordinary MLS leaf authority hint omits device authorization Event".to_owned()
                })?;
                let actor = hint_actor_id(hint)?;
                (actor, hint.endpoint.clone(), Some(authority))
            } else if credential.starts_with("ak:did_core:key:") {
                // A minimal-metadata pairwise leaf names its own leaf key as its
                // principal, so it carries its verification inline and needs no
                // separate Add-authority Event.
                if credential != format!("ak:did_core:key:{multibase}") {
                    return Err(
                        "minimal-metadata MLS credential does not name its exact leaf key"
                            .to_owned(),
                    );
                }
                let pairwise = arkret_sdk::DidCoreId::new(credential.clone())
                    .map_err(|error| format!("invalid pairwise MLS principal: {error}"))?;
                let method = arkret_sdk::DidUrl::new(format!("did:key:{multibase}#{multibase}"))
                    .map_err(|error| format!("invalid pairwise MLS method: {error}"))?;
                let endpoint = arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
                    pairwise.clone(),
                    method,
                )
                .map_err(|error| format!("invalid pairwise MLS endpoint: {error}"))?;
                (arkret_sdk::ActorId::service(pairwise), endpoint, None)
            } else {
                let mut matches = authority_hints.iter().filter(|hint| {
                    matches!(
                        &hint.endpoint,
                        arkret_sdk::MlsEndpointIdentity::AgentRuntime { agent_id, .. }
                            if agent_id.as_str() == credential
                    )
                });
                let hint = matches
                    .next()
                    .ok_or_else(|| "Agent MLS leaf has no verified authority hint".to_owned())?;
                if matches.next().is_some() {
                    return Err("Agent MLS leaf has duplicate authority hints".to_owned());
                }
                (hint_actor_id(hint)?, hint.endpoint.clone(), None)
            };

        installed.push(arkret_sdk::MlsVerifiedLeafBinding {
            leaf_index: leaf.leaf_index,
            actor_id,
            endpoint,
            credential_ref: arkret_sdk::NonEmptyString::new(credential)
                .map_err(|error| format!("invalid MLS leaf credential ref: {error}"))?,
            signature_key: signature_key_b64,
            device_authorize_event_id,
        });
    }
    group
        .install_verified_leaf_bindings(installed)
        .map_err(|error| format!("install accepted MLS leaf bindings: {error}"))
}

/// The complete member identity an authority hint stands for.
///
/// Every hint endpoint carries its signing principal; an account actor needs the
/// Station half too, which the claim receipt already pinned when the hint was
/// built, so this keeps the endpoint's own principal projection and lets the
/// caller override it with [`claimed_actor_id`] where the full account is known.
fn hint_actor_id(hint: &MlsLeafAuthorityHint) -> Result<arkret_sdk::ActorId, String> {
    Ok(arkret_sdk::ActorId::service(
        hint.endpoint.actor_id().clone(),
    ))
}

/// Install the post-transition bindings using the exact accepted member
/// identities the caller resolved, overriding the endpoint-only projection for
/// every leaf whose complete `ActorId` is known.
pub(crate) fn install_post_transition_leaf_bindings_with_actors(
    group: &mut arkret_sdk::ArkretMlsGroup,
    previous: &[arkret_sdk::MlsVerifiedLeafBinding],
    authority_hints: &[MlsLeafAuthorityHint],
    actors: &[(arkret_sdk::MlsEndpointIdentity, arkret_sdk::ActorId)],
) -> Result<(), String> {
    install_post_transition_leaf_bindings(group, previous, authority_hints)?;
    if actors.is_empty() {
        return Ok(());
    }
    let mut bindings = group
        .verified_leaf_bindings()
        .map_err(|error| format!("read installed MLS leaf bindings: {error}"))?;
    for binding in &mut bindings {
        if let Some((_, actor)) = actors
            .iter()
            .find(|(endpoint, _)| endpoint == &binding.endpoint)
        {
            binding.actor_id = actor.clone();
        }
    }
    group
        .install_verified_leaf_bindings(bindings)
        .map_err(|error| format!("install accepted MLS member identities: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> arkret_sdk::ScopeRef {
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn a_genesis_binding_is_epoch_zero_without_a_base_state() {
        let binding = genesis_binding(&scope()).unwrap();
        assert_eq!(binding.previous_epoch(), 0);
        assert_eq!(binding.next_epoch(), 0);
        assert_eq!(binding.key_access_revision(), 0);
        assert!(binding.base_group_state_ref().is_none());
        assert_eq!(binding.effective_scope(), &scope());
    }
}
