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
        .ok_or_else(|| "MLS authoring requires the scope's current key-access revision".to_owned())
}

/// The verified authority a newly occupied MLS leaf binds to.
///
/// A human device leaf binds to its accepted `ak.device.authorize` Event; an
/// Agent runtime leaf binds to its endpoint identity, which already carries the
/// accepted `ak.agent.key.authorize` reference.
#[derive(Clone, Debug)]
pub(crate) struct MlsLeafAuthorityHint {
    pub(crate) actor_id: arkret_sdk::ActorId,
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
        actor_id: claim.actor_id.clone(),
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
    let account = claim
        .actor_id
        .as_account_id()
        .ok_or_else(|| "claimed KeyPackage actor_id is not an account".to_owned())?;
    if account.station_id != receipt.destination_id {
        return Err("claimed KeyPackage actor_id differs from receipt destination".to_owned());
    }
    Ok(claim.actor_id.clone())
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
        let credential_actor = arkret_sdk::decode_mls_basic_credential_identity(identity)
            .map_err(|error| format!("invalid MLS leaf ActorId credential: {error}"))?;
        let signature_key: [u8; 32] = leaf
            .signature_key
            .as_slice()
            .try_into()
            .map_err(|_| "accepted MLS leaf signature key is not Ed25519".to_owned())?;
        let signature_key_b64 =
            arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(signature_key))
                .map_err(|error| format!("invalid accepted MLS leaf key: {error}"))?;

        if let Some(binding) = retained.get(&leaf.leaf_index)
            && binding.actor_id == credential_actor
            && binding.signature_key == signature_key_b64
        {
            installed.push((*binding).clone());
            continue;
        }

        let mut matches = authority_hints
            .iter()
            .filter(|hint| hint.actor_id == credential_actor);
        let hint = matches
            .next()
            .ok_or_else(|| "new MLS leaf has no verified Add authority".to_owned())?;
        if matches.next().is_some() {
            return Err("new MLS leaf has duplicate authority hints".to_owned());
        }
        let device_authorize_event_id = match &hint.endpoint {
            arkret_sdk::MlsEndpointIdentity::HumanDevice { .. } => {
                Some(hint.device_authorize_event_id.clone().ok_or_else(|| {
                    "ordinary MLS leaf authority hint omits device authorization Event".to_owned()
                })?)
            }
            _ => None,
        };

        installed.push(arkret_sdk::MlsVerifiedLeafBinding {
            leaf_index: leaf.leaf_index,
            actor_id: credential_actor,
            endpoint: hint.endpoint.clone(),
            signature_key: signature_key_b64,
            device_authorize_event_id,
        });
    }
    group
        .install_verified_leaf_bindings(installed)
        .map_err(|error| format!("install accepted MLS leaf bindings: {error}"))
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
