//! Complete historical authority check before a joined MLS group may acquire
//! leaf bindings. The service roster is data until every signature, public
//! Genesis byte and occupied leaf has been checked against the accepted cut.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use arkret_sdk::{
    ActorId, AuthenticatedServiceResolution, DidCoreId, EventId, MlsEndpointIdentity,
    MlsGroupStateMaterialOutcome, MlsMemberGroupStateMaterialReadRequestBody,
    MlsRosterAuthorityReadOutcome, MlsRosterAuthorityReadRequestBody, MlsRosterRecord,
    MlsVerifiedLeafBinding, MlsWelcomeRecipientEndpoint,
};

/// Verify a complete signed roster and the exact Genesis public material,
/// then install an every-and-only binding map for the already verified joined
/// RFC group. The caller must obtain `request` and `expected_head` from the
/// accepted target/current cut, not from a Welcome or an untrusted page.
pub(crate) fn install_signed_roster_bindings(
    group: &mut arkret_sdk::ArkretMlsGroup,
    pages: &[MlsRosterAuthorityReadOutcome],
    request: &MlsRosterAuthorityReadRequestBody,
    expected_governance: &DidCoreId,
    expected_head: &EventId,
    governance_resolution: &AuthenticatedServiceResolution,
    attestor_resolutions: &HashMap<DidCoreId, AuthenticatedServiceResolution>,
    material: &MlsGroupStateMaterialOutcome,
) -> Result<(), String> {
    arkret_sdk::verify_mls_roster_authority_pages(
        pages,
        request,
        expected_governance,
        expected_head,
        governance_resolution,
        attestor_resolutions,
    )
    .map_err(|error| format!("verify signed MLS roster: {error}"))?;
    if group.scope() != &request.effective_scope
        || group.group_id() != request.mls_group_id
        || group.epoch() != request.target_epoch
    {
        return Err("joined MLS group differs from the accepted roster cut".to_owned());
    }
    let manifest = &pages[0].manifest;
    let material_request = MlsMemberGroupStateMaterialReadRequestBody {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        epoch: Default::default(),
        group_state_event_id: request.genesis_event_ref.clone(),
        caller_actor_id: request.caller_actor_id.clone(),
        target_commit_event_ref: request.target_commit_event_ref.clone(),
        target_epoch: request.target_epoch,
        group_info_ref: manifest.group_info_ref.clone(),
        ratchet_tree_ref: manifest.ratchet_tree_ref.clone(),
        max_response_bytes: None,
    };
    let bytes = material
        .validate_for_request(&material_request.as_peer_request())
        .map_err(|error| format!("verify MLS Genesis material digest and selectors: {error}"))?;
    let genesis_leaves = arkret_sdk::mls::validate_public_group_state(
        &bytes.group_info_bytes,
        &bytes.ratchet_tree_bytes,
        request.mls_group_id.as_str(),
        0,
    )
    .map_err(|error| format!("verify RFC Genesis public tree: {error}"))?;
    let records = pages
        .iter()
        .flat_map(|page| page.records.iter())
        .collect::<Vec<_>>();
    let MlsRosterRecord::Genesis {
        actor_id,
        leaf_signature_key_b64u,
        endpoint,
        authorization_event_ref,
        ..
    } = records[0]
    else {
        return Err("signed MLS roster has no Genesis record".to_owned());
    };
    if genesis_leaves.len() != 1
        || genesis_leaves[0].actor_id != *actor_id
        || genesis_leaves[0].signature_key != *leaf_signature_key_b64u
    {
        return Err("signed MLS Genesis leaf differs from RFC public tree".to_owned());
    }
    let mut authorities = vec![authority_from_record(
        actor_id,
        leaf_signature_key_b64u,
        endpoint,
        authorization_event_ref,
    )?];
    for record in records.into_iter().skip(1) {
        let MlsRosterRecord::Add {
            proposal_wire_b64u,
            attestation,
            ..
        } = record
        else {
            return Err("signed MLS roster repeats Genesis".to_owned());
        };
        let proposal_bytes = arkret_sdk::base64url_decode(proposal_wire_b64u.as_str())
            .map_err(|error| format!("decode signed MLS Add Proposal: {error}"))?;
        let proposal = arkret_sdk::mls::verify_add_proposal_leaf(&proposal_bytes)
            .map_err(|error| format!("verify signed MLS Add Proposal: {error}"))?;
        if proposal.actor_id != attestation.actor_id
            || proposal.leaf_signature_key != attestation.leaf_signature_key_b64u
        {
            return Err("signed MLS Add differs from its RFC KeyPackage leaf".to_owned());
        }
        authorities.push(authority_from_record(
            &attestation.actor_id,
            &attestation.leaf_signature_key_b64u,
            &attestation.endpoint,
            &attestation.authorization_event_ref,
        )?);
    }
    let occupied = group
        .active_author_leaves()
        .into_iter()
        .map(|leaf| {
            let arkret_sdk::mls::AuthorLeafCredential::Basic { identity } = leaf.credential else {
                return Err("occupied MLS leaf has no BasicCredential".to_owned());
            };
            let actor_id = arkret_sdk::decode_mls_basic_credential_identity(&identity)
                .map_err(|error| format!("decode occupied MLS ActorId: {error}"))?;
            let signature_key =
                arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(&leaf.signature_key))
                    .map_err(|error| error.to_owned())?;
            Ok(arkret_sdk::mls::MlsPublicEndpointLeaf {
                leaf_index: leaf.leaf_index,
                actor_id,
                signature_key,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let bindings = match_occupied_leaf_authorities(&occupied, &authorities)?;
    group
        .install_verified_leaf_bindings(bindings)
        .map_err(|error| format!("install verified MLS roster bindings: {error}"))
}

fn authority_from_record(
    actor_id: &ActorId,
    signature_key: &arkret_sdk::Base64UrlString,
    endpoint: &MlsWelcomeRecipientEndpoint,
    authorization_event_ref: &EventId,
) -> Result<MlsVerifiedLeafBinding, String> {
    let (endpoint, device_authorize_event_id) = match endpoint {
        MlsWelcomeRecipientEndpoint::Device { device_id } => (
            MlsEndpointIdentity::human_device(
                actor_id.signing_principal_id().clone(),
                device_id.clone(),
            ),
            Some(authorization_event_ref.clone()),
        ),
        MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method,
        } => (
            MlsEndpointIdentity::agent_runtime(
                actor_id.signing_principal_id().clone(),
                verification_method.clone(),
                authorization_event_ref.clone(),
            )
            .map_err(|error| format!("verify roster Agent endpoint: {error}"))?,
            None,
        ),
    };
    actor_id
        .validate()
        .map_err(|error| format!("verify MLS roster ActorId: {error}"))?;
    if matches!(&endpoint, MlsEndpointIdentity::HumanDevice { .. })
        && !matches!(actor_id, ActorId::Account { .. })
    {
        return Err("MLS roster device endpoint is not an account Actor".to_owned());
    }
    Ok(MlsVerifiedLeafBinding {
        leaf_index: 0, // Replaced solely by the verified occupied RFC tree.
        actor_id: actor_id.clone(),
        endpoint,
        signature_key: signature_key.clone(),
        device_authorize_event_id,
    })
}

fn match_occupied_leaf_authorities(
    occupied: &[arkret_sdk::mls::MlsPublicEndpointLeaf],
    authorities: &[MlsVerifiedLeafBinding],
) -> Result<Vec<MlsVerifiedLeafBinding>, String> {
    let mut exact = BTreeMap::new();
    // Every record was independently verified in signed Commit order. A
    // Remove+Add may reuse even the same Actor/key/index tuple; its later Add
    // is a new provenance event and supplies the current endpoint authority.
    for authority in authorities {
        let key = (authority.actor_id.clone(), authority.signature_key.clone());
        exact.insert(key, authority);
    }
    let mut bindings = Vec::with_capacity(occupied.len());
    let mut occupied_indices = BTreeSet::new();
    let mut occupied_keys = BTreeSet::new();
    for leaf in occupied {
        let key = (leaf.actor_id.clone(), leaf.signature_key.clone());
        if !occupied_indices.insert(leaf.leaf_index) || !occupied_keys.insert(key.clone()) {
            return Err("RFC MLS tree repeats an occupied leaf or leaf key".to_owned());
        }
        let authority = exact
            .get(&key)
            .ok_or_else(|| "occupied MLS leaf has no signed historical authority".to_owned())?;
        let mut binding = (*authority).clone();
        binding.leaf_index = leaf.leaf_index;
        bindings.push(binding);
    }
    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> ActorId {
        ActorId::account(arkret_sdk::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn authority(key: &str, device_id: &str) -> MlsVerifiedLeafBinding {
        MlsVerifiedLeafBinding {
            leaf_index: 0,
            actor_id: actor(),
            endpoint: MlsEndpointIdentity::human_device(
                actor().signing_principal_id().clone(),
                arkret_sdk::DeviceId::new(device_id).unwrap(),
            ),
            signature_key: arkret_sdk::Base64UrlString::new(key).unwrap(),
            device_authorize_event_id: Some(
                EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap(),
            ),
        }
    }

    fn leaf(index: u32, key: &str) -> arkret_sdk::mls::MlsPublicEndpointLeaf {
        arkret_sdk::mls::MlsPublicEndpointLeaf {
            leaf_index: index,
            actor_id: actor(),
            signature_key: arkret_sdk::Base64UrlString::new(key).unwrap(),
        }
    }

    #[test]
    fn same_actor_two_keys_take_distinct_rfc_leaf_indices() {
        let device_one = "ak:device:0196419b-0000-7000-8000-000000000001";
        let device_two = "ak:device:0196419b-0000-7000-8000-000000000002";
        let bindings = match_occupied_leaf_authorities(
            &[leaf(4, "AQ"), leaf(1, "Ag")],
            &[authority("Ag", device_two), authority("AQ", device_one)],
        )
        .unwrap();
        assert_eq!(bindings[0].leaf_index, 4);
        assert_eq!(bindings[0].signature_key.as_str(), "AQ");
        assert_eq!(bindings[1].leaf_index, 1);
        assert_eq!(bindings[1].signature_key.as_str(), "Ag");
        assert!(matches!(
            &bindings[1].endpoint,
            MlsEndpointIdentity::HumanDevice { device_id, .. } if device_id.as_str() == device_two
        ));
    }

    #[test]
    fn remove_then_add_can_reuse_index_only_for_the_new_leaf_key() {
        let device_one = "ak:device:0196419b-0000-7000-8000-000000000001";
        let device_two = "ak:device:0196419b-0000-7000-8000-000000000002";
        let bindings = match_occupied_leaf_authorities(
            &[leaf(2, "Ag")],
            &[authority("AQ", device_one), authority("Ag", device_two)],
        )
        .unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].leaf_index, 2);
        assert_eq!(bindings[0].signature_key.as_str(), "Ag");
    }

    #[test]
    fn missing_or_wrong_historical_leaf_authority_fails_closed() {
        assert!(match_occupied_leaf_authorities(&[leaf(4, "AQ")], &[]).is_err());
        assert!(
            match_occupied_leaf_authorities(
                &[leaf(4, "AQ")],
                &[authority(
                    "Ag",
                    "ak:device:0196419b-0000-7000-8000-000000000001"
                )],
            )
            .is_err()
        );
        assert!(
            match_occupied_leaf_authorities(
                &[leaf(4, "AQ"), leaf(4, "Ag")],
                &[
                    authority("AQ", "ak:device:0196419b-0000-7000-8000-000000000001"),
                    authority("Ag", "ak:device:0196419b-0000-7000-8000-000000000002")
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn identical_leaf_tuple_readd_uses_later_signed_history() {
        let first = authority("AQ", "ak:device:0196419b-0000-7000-8000-000000000001");
        let mut readded = first.clone();
        readded.device_authorize_event_id =
            Some(EventId::new("ak:event:ARELvWOpF6BRhrks3DlbQy-9XIE6aAQQumDQp7fA4Ape").unwrap());
        let bindings =
            match_occupied_leaf_authorities(&[leaf(2, "AQ")], &[first, readded.clone()]).unwrap();
        assert_eq!(
            bindings[0].device_authorize_event_id,
            readded.device_authorize_event_id
        );
    }
}
