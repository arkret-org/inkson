//! Complete historical authority check before a joined MLS group may acquire
//! leaf bindings. The service roster is data until every signature, public
//! Genesis byte and occupied leaf has been checked against the accepted cut.

use arkret_sdk::{
    ActorId, AuthenticatedServiceResolution, DidCoreId, EventId, MlsGroupStateMaterialOutcome,
    MlsMemberGroupStateMaterialReadRequestBody, MlsRosterAuthorityReadOutcome,
    MlsRosterAuthorityReadRequestBody,
};

/// Obtain the signed historical authority for an accepted Welcome at the
/// target Commit cut. Each signed Add record carries the original recipient
/// Station's frozen method history for independent receipt and attestation
/// verification; the current governance route only verifies the manifest.
pub(crate) async fn install_welcome_roster_from_service(
    api: &crate::transport::TransportClient,
    group: &mut arkret_sdk::ArkretMlsGroup,
    accepted_commit: &arkret_wire::CommittedEventFullView,
    authority: &arkret_sdk::AccountId,
) -> Result<(), String> {
    let transition = crate::mls::accepted_artifact::accepted_mls_transition(accepted_commit)?;
    let scope = &transition.effective_scope;
    let realm_id = scope
        .realm_id_opt()
        .ok_or_else(|| "MLS roster requires a Realm or Circle scope".to_owned())?;
    let http = api.http();
    let authority_client = garth::AuthorityClient::new(http.clone());
    let (bundle, freshness, mut replica) =
        crate::realm_events_engine::fresh_verified_realm(&authority_client, http, realm_id)
            .await
            .map_err(|error| format!("verify current MLS governance Station: {error}"))?;
    let snapshot = http
        .realm_state_snapshot_head(realm_id)
        .await
        .map_err(|error| format!("read MLS roster current Snapshot: {error}"))?;
    let keys = garth::fetch_historical_station_key_directory(http, &bundle, None, Some(&snapshot))
        .await
        .map_err(|error| format!("read MLS roster Station history: {error}"))?;
    let freshness =
        arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), freshness.expected_nonce);
    replica
        .install_verified_current_snapshot_heads(&snapshot, &freshness, &keys)
        .map_err(|error| format!("verify MLS roster current Snapshot: {error}"))?;
    let groups = snapshot
        .current_state_entries
        .iter()
        .filter_map(|row| match row {
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                value,
                ..
            } if scope_ref == scope => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [value] = groups.as_slice() else {
        return Err("MLS roster has no unique signed scope current".to_owned());
    };
    let current: arkret_wire::MlsGroupCurrent = serde_json::from_value((*value).clone())
        .map_err(|error| format!("decode signed MLS scope current: {error}"))?;
    if accepted_commit.event.kind != arkret_sdk::EventKind::MlsCommit
        || &current.effective_scope != scope
        || current.epoch < transition.next_epoch
        || group.epoch() != transition.next_epoch
        || group.group_id() != transition.mls_group_id
    {
        return Err("MLS roster target differs from the accepted Welcome cut".to_owned());
    }
    let governance_resolution: AuthenticatedServiceResolution =
        serde_json::from_value(bundle.current_route_record)
            .map_err(|error| format!("MLS governance route is not a closed resolution: {error}"))?;
    if governance_resolution.service_id != bundle.current_service_id {
        return Err("MLS governance resolution belongs to another Station".to_owned());
    }
    let request = MlsRosterAuthorityReadRequestBody {
        realm_id: realm_id.clone(),
        effective_scope: scope.clone(),
        mls_group_id: transition.mls_group_id,
        genesis_event_ref: current.genesis_event_ref,
        target_commit_event_ref: accepted_commit.event.event_id.clone(),
        target_epoch: transition.next_epoch,
        caller_actor_id: ActorId::account(authority.clone()),
        cursor: None,
    };
    let pages = crate::transport::EndpointClients::new(api.clone())
        .mls()
        .unverified_member_roster_authority_pages(&request)
        .await
        .map_err(|error| format!("read complete MLS roster: {error}"))?;
    let manifest = &pages
        .first()
        .ok_or_else(|| "MLS roster has no signed page".to_owned())?
        .manifest;
    arkret_sdk::verify_mls_roster_authority_manifest_signature(
        manifest,
        &request,
        &bundle.current_service_id,
        &current.current_mls_commit_event_ref,
        &governance_resolution,
    )
    .map_err(|error| format!("verify MLS roster manifest: {error}"))?;
    arkret_sdk::verify_mls_roster_authority_pages(
        &pages,
        &request,
        &bundle.current_service_id,
        &current.current_mls_commit_event_ref,
        &governance_resolution,
    )
    .map_err(|error| format!("verify complete historical MLS roster: {error}"))?;
    let material_request = genesis_material_request(&request, manifest);
    let material = http
        .self_mls_group_state_material(&material_request)
        .await
        .map_err(|error| format!("read accepted MLS Genesis material: {error}"))?;
    install_signed_roster_bindings(
        group,
        &pages,
        &request,
        &bundle.current_service_id,
        &current.current_mls_commit_event_ref,
        &governance_resolution,
        &material,
    )
}

fn genesis_material_request(
    request: &MlsRosterAuthorityReadRequestBody,
    manifest: &arkret_sdk::MlsRosterAuthorityManifest,
) -> MlsMemberGroupStateMaterialReadRequestBody {
    MlsMemberGroupStateMaterialReadRequestBody {
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
    }
}

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
    material: &MlsGroupStateMaterialOutcome,
) -> Result<(), String> {
    arkret_sdk::install_verified_mls_roster_bindings(
        group,
        pages,
        request,
        expected_governance,
        expected_head,
        governance_resolution,
        material,
    )
}
