//! Own-Station roster keys plus independent original signatures and RFC MLS.

pub(crate) async fn install_welcome_roster_from_service(
    api: &crate::transport::TransportClient,
    state: &crate::runtime::input::StateStoreHandle,
    group: &mut arkret_sdk::ArkretMlsGroup,
    accepted_commit: &arkret_wire::CommittedEventFullView,
    authority: &arkret_sdk::AccountId,
) -> Result<(), String> {
    let transition = crate::mls::accepted_artifact::accepted_mls_transition(accepted_commit)?;
    let scope = &transition.effective_scope;
    let realm = scope
        .realm_id_opt()
        .ok_or("MLS roster scope has no Realm")?;
    let session = crate::transport::auth::AuthoringSessionFence::capture()
        .map_err(|error| error.to_string())?;
    state.read(|store| {
        if store.active_authority().as_ref() != Some(authority) || store.current_reset_required() {
            return Err("MLS roster account current is unavailable".to_owned());
        }
        Ok(())
    })?;
    if accepted_commit.event.kind != arkret_sdk::EventKind::MlsCommit
        || accepted_commit.commit.realm_id != *realm
        || group.epoch() != transition.next_epoch
        || group.group_id() != transition.mls_group_id
    {
        return Err("MLS roster target differs from accepted Commit/Welcome".into());
    }
    let request = arkret_sdk::MlsMemberRosterAuthorityReadRequestBody {
        realm_id: realm.clone(),
        effective_scope: scope.clone(),
        mls_group_id: transition.mls_group_id,
        target_commit_event_ref: accepted_commit.event.event_id.clone(),
        target_epoch: transition.next_epoch,
        caller_actor_id: arkret_sdk::ActorId::account(authority.clone()),
        cursor: None,
    };
    let pages = crate::transport::EndpointClients::new(api.clone())
        .mls()
        .unverified_member_roster_authority_pages(&request)
        .await
        .map_err(|error| error.to_string())?;
    let peer = arkret_sdk::verify_mls_member_roster_authority_pages(&pages, &request)
        .map_err(|error| error.to_string())?;
    session
        .check_session_identity()
        .map_err(|error| error.to_string())?;
    let material_request =
        arkret_sdk::mls_roster_genesis_material_request(&peer, &pages[0].roster.manifest);
    let material = api
        .http()
        .self_mls_group_state_material(&material_request)
        .await
        .map_err(|error| error.to_string())?;
    session
        .check_session_identity()
        .map_err(|error| error.to_string())?;
    if !state.read(|store| {
        store.active_authority().as_ref() == Some(authority) && !store.current_reset_required()
    }) {
        return Err("MLS roster account changed during material read".into());
    }
    arkret_sdk::install_verified_mls_self_roster_bindings(group, &pages, &request, &material)
}
