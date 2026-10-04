//! The independent Sidecar handshake. Realm/Circle creator transactions must
//! never be opened for a Sidecar; its accepted participant cut binds both the
//! private RFC 9420 state and the producer-signed Genesis.

use anyhow::Context as _;
use garth::OutboundQueueStore;

use crate::runtime::input::StateStoreHandle;

pub(crate) async fn creator_device_authorization(
    submitter: &crate::event_submit::EventSubmitter,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> anyhow::Result<arkret_sdk::EventId> {
    submitter
        .event_proof_context(arkret_sdk::DigestSuite::Sha256)
        .await?;
    anyhow::ensure!(
        crate::secure_key_store::active_device_seed_scope()
            .is_some_and(|scope| { &scope.authority == authority && &scope.device_id == device }),
        "Sidecar creator device differs from the active authoring scope"
    );
    crate::identity::device_directory::cached_device_authorize_event_id(
        &authority.to_string(),
        device.as_str(),
    )
    .ok_or_else(|| anyhow::anyhow!("verified Sidecar creator device authorization is unavailable"))
}

fn genesis_binding(
    view: &arkret_sdk::AgentSidecarView,
    authority: &arkret_sdk::AccountId,
) -> anyhow::Result<arkret_sdk::MlsGovernanceBindingPayload> {
    view.validate()?;
    crate::sidecar::validate_agent_sidecar_view(view)?;
    anyhow::ensure!(
        view.sidecar.controller_account_id == *authority
            && view.sidecar.state == arkret_sdk::AgentSidecarState::Active,
        "Sidecar MLS requires its active exact controller Account"
    );
    let digest = arkret_sdk::sidecar_participant_authority_digest(
        &view.sidecar.id,
        &view.sidecar.realm_id,
        authority,
        &view.desired_agent_ids,
    )?;
    anyhow::ensure!(
        digest == view.mls_context.participant_authority_digest,
        "Sidecar current participant transcript differs from its authority digest"
    );
    arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        view.sidecar.realm_id.clone(),
        view.sidecar.id.clone(),
        None,
        0,
        0,
        0,
        digest,
        view.mls_context.authority_stream_head.clone(),
    )
    .map_err(Into::into)
}

/// Persist the accepted reference only after the original submission engine
/// has verified the exact committed Genesis. The checkpoint is not ready at
/// the earlier in-memory mutation or outbound acceptance boundary.
async fn publish_genesis(
    state: &StateStoreHandle,
    scope: &arkret_sdk::ScopeRef,
    event_id: &arkret_sdk::EventId,
) -> anyhow::Result<()> {
    let barrier = state
        .write(|store| store.mark_mls_genesis_emitted_for_scope_with_event(scope, event_id))
        .map_err(anyhow::Error::msg)?;
    barrier.wait().await?;
    let durable = state.read(|store| store.durable_mls_checkpoint_for_scope(scope))?;
    anyhow::ensure!(
        durable.is_some_and(|checkpoint| {
            checkpoint.epoch == 0 && checkpoint.group_state_event_id.as_ref() == Some(event_id)
        }),
        "Sidecar Genesis reference has not become durable"
    );
    Ok(())
}

pub(crate) async fn ensure_sidecar_mls_genesis(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    expected: &arkret_sdk::AgentSidecarView,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: expected.sidecar.realm_id.clone(),
        sidecar_id: expected.sidecar.id.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let lock_key = format!("{authority}|{device}|{group_id}");
    let lock = crate::mls::admission::mls_admission_authoring_lock(&lock_key);
    let _guard = lock.lock().await;
    let submitter = api
        .event_submitter()?
        .with_authority(authority.clone())
        .with_state_store(state.clone());
    // A lost response must replay its original signed unit before any new
    // material is generated. No Sidecar creator-FSM record is opened here.
    submitter.drain_outbound().await?;
    let http = api.sdk_http_client()?;
    let view = http.agent_sidecar_get(&expected.sidecar.id).await?;
    anyhow::ensure!(
        view.sidecar.id == expected.sidecar.id
            && view.sidecar.realm_id == expected.sidecar.realm_id,
        "Sidecar current changed the exact handshake scope"
    );
    let binding = genesis_binding(&view, authority)?;
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let secret =
        crate::mls::runtime::ensure_existing_account_mls_secret_durable(secure.as_ref(), authority)
            .await?;

    if let Some(accepted) = view.mls_context.genesis_event_ref.as_ref() {
        anyhow::ensure!(
            view.mls_context.mls_group_id.as_deref() == Some(group_id.as_str()),
            "accepted Sidecar Genesis names another scope-derived MLS group"
        );
        let accepted = arkret_sdk::EventId::new(accepted.clone())?;
        let checkpoint = state
            .read(|store| store.mls_checkpoint_for_scope_and_group(&scope, group_id.as_str()))
            .ok_or_else(|| {
                anyhow::anyhow!("Sidecar requires this device's verified Welcome or recovery")
            })?;
        if checkpoint.group_state_event_id.is_some() {
            anyhow::ensure!(
                checkpoint.epoch != 0
                    || checkpoint.group_state_event_id.as_ref() == Some(&accepted),
                "local Sidecar Genesis differs from the accepted winner"
            );
            return Ok(view);
        }
        // Acceptance may have landed just before a crash interrupted local
        // publication. Recover only this vault's exact committed producer
        // unit, never bind arbitrary epoch-zero keys to a server reference.
        let vault = crate::outbound_store::InksonOutboundStore::open(
            authority,
            crate::outbound_store::OutboundLane::Standard,
        )?;
        let queued = vault
            .mutate_outbound(|queue| Ok(queue.snapshot().items))
            .await?;
        let original = queued
            .iter()
            .find(|item| item.event_id() == &accepted)
            .ok_or_else(|| {
                anyhow::anyhow!("accepted Sidecar Genesis has no original local submission")
            })?;
        let event = original.submission.primary_event();
        let commit = original
            .commit()
            .ok_or_else(|| anyhow::anyhow!("Sidecar Genesis submission is not committed yet"))?;
        let transition =
            crate::mls::accepted_artifact::accepted_from_submission(event.clone(), commit.clone())
                .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            transition.effective_scope == scope
                && event.actor_id == arkret_sdk::ActorId::account(authority.clone()),
            "accepted Sidecar Genesis belongs to another scope or Account"
        );
        let payload: arkret_sdk::MlsGenesisPayload =
            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
        let restored = state
            .read(|store| {
                crate::mls::runtime::initial_mls_checkpoint_summary_with_pinned_binding(
                    store,
                    secure.as_ref(),
                    scope.realm_id().as_str(),
                    None,
                    authority,
                    device,
                    Some(view.sidecar.id.clone()),
                    Some(&payload.governance_binding),
                )
            })
            .map_err(|error| anyhow::anyhow!(error.user_message()))?
            .ok_or_else(|| {
                anyhow::anyhow!("original Sidecar epoch-zero material is unavailable")
            })?;
        anyhow::ensure!(
            payload.group_info_ref.as_str()
                == format!(
                    "ak:blob:{}",
                    crate::canonical::sha256_digest(&restored.group_info_bytes)
                )
                && payload.ratchet_tree_ref.as_str()
                    == format!(
                        "ak:blob:{}",
                        crate::canonical::sha256_digest(&restored.ratchet_tree_bytes)
                    )
                && payload.creator_leaf_authority == restored.creator_leaf_authority,
            "accepted Sidecar Genesis does not bind the original private checkpoint"
        );
        publish_genesis(state, &scope, &accepted).await?;
        return Ok(view);
    }

    let summary = match state
        .read(|store| {
            crate::mls::runtime::initial_mls_checkpoint_summary_with_pinned_binding(
                store,
                secure.as_ref(),
                scope.realm_id().as_str(),
                None,
                authority,
                device,
                Some(view.sidecar.id.clone()),
                Some(&binding),
            )
        })
        .map_err(|error| anyhow::anyhow!(error.user_message()))?
    {
        Some(summary) => summary,
        None => {
            anyhow::ensure!(
                state
                    .read(|store| store.mls_checkpoint_for_scope(&scope))
                    .is_none(),
                "Sidecar without accepted Genesis holds incompatible later private state"
            );
            // Directory notifications may fence the cached device root during
            // the earlier current/secret awaits. Resolve it before the pure
            // generation step and pin its exact accepted authorization.
            let device_authorization =
                creator_device_authorization(&submitter, authority, device).await?;
            let (checkpoint, summary) = crate::mls::runtime::generate_creator_epoch_zero(
                &scope,
                authority,
                device,
                &binding,
                &secret,
                Some(&device_authorization),
            )
            .map_err(|error| anyhow::anyhow!(error.user_message()))?;
            let barrier = state.write(|store| {
                store
                    .save_mls_checkpoint_for_scope(&scope, checkpoint)
                    .map_err(anyhow::Error::msg)?;
                store.begin_durable_flush()
            })?;
            barrier.wait().await?;
            summary
        }
    };
    let operation = state
        .write(|store| {
            crate::mls::group_events::build_creator_mls_genesis_event_for_sidecar_scope(
                store,
                scope.realm_id().as_str(),
                &view.sidecar.id,
                authority.principal_id.as_str(),
                Some(&summary),
                &binding,
            )
        })
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("Sidecar Genesis authoring returned no original unit"))?;
    crate::mls::runtime::upload_mls_genesis_public_material(api, &summary)
        .await
        .map_err(|error| anyhow::anyhow!(error.user_message()))?;
    let result = submitter.submit_sdk_event(&operation).await?;
    let accepted = arkret_sdk::EventId::new(result.event_id)?;
    publish_genesis(state, &scope, &accepted).await?;
    let current = http.agent_sidecar_get(&view.sidecar.id).await?;
    genesis_binding(&current, authority)?;
    anyhow::ensure!(
        current.sidecar.id == view.sidecar.id
            && current.sidecar.realm_id == view.sidecar.realm_id
            && current.mls_context.genesis_event_ref.as_deref() == Some(accepted.as_str()),
        "Sidecar current has not converged to its accepted Genesis"
    );
    Ok(current)
}

/// Add missing authorized controller devices and current Agent endpoints through the existing
/// durable atomic Commit/Welcome lane. Effective access stays pending until
/// the recipients have actually consumed their exact Welcome deliveries.
pub(crate) async fn reconcile_sidecar_mls(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    expected: &arkret_sdk::AgentSidecarView,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    let mut view = ensure_sidecar_mls_genesis(api, state, authority, device, expected)
        .await
        .context("Sidecar Genesis preparation failed")?;
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: view.sidecar.realm_id.clone(),
        sidecar_id: view.sidecar.id.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let lock = crate::mls::admission::mls_admission_authoring_lock(&format!(
        "{authority}|{device}|{group_id}"
    ));
    let _guard = lock.lock().await;
    let http = api.sdk_http_client()?;
    let submitter = api
        .event_submitter()?
        .with_authority(authority.clone())
        .with_state_store(state.clone());
    submitter.drain_mls_outbound().await?;
    anyhow::ensure!(
        !submitter
            .has_pending_mls_admission_for_realm(scope.realm_id().as_str())
            .await?,
        "an original durable MLS transition is still converging"
    );
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let secret =
        crate::mls::runtime::load_device_checkpoint_secret(secure.as_ref(), authority, device)
            .context("Sidecar checkpoint key is unavailable")?;
    let devices = crate::transport::keys::list_devices(&http).await?;
    let mut targets = devices
        .devices
        .iter()
        .filter(|target| {
            target.device_id != *device
                && target.status == arkret_sdk::DeviceSummaryStatus::Active
                && target.verification_state == arkret_sdk::DeviceSummaryVerificationState::Verified
                && target.authorized_event_ref.is_some()
                && target.validate().is_ok()
        })
        .map(|target| {
            (
                authority.principal_id.clone(),
                Some(target.device_id.clone()),
            )
        })
        .collect::<Vec<_>>();
    targets.extend(
        view.desired_agent_ids
            .iter()
            .cloned()
            .map(|agent| (agent, None)),
    );
    for (agent, target_device) in targets {
        // Revalidate the exact scope and controller on each cut. A removed
        // Agent is never claimed from an earlier displayed desired set.
        view = http.agent_sidecar_get(&expected.sidecar.id).await?;
        genesis_binding(&view, authority)?;
        anyhow::ensure!(
            view.sidecar.realm_id == *scope.realm_id(),
            "Sidecar read changed its parent Realm"
        );
        let endpoint = if let Some(target_device) = &target_device {
            // Re-check device lifecycle at this cut. A stale account inventory
            // cannot authorize a new leaf after revoke or generation fencing.
            let devices = crate::transport::keys::list_devices(&http).await?;
            if !devices.devices.iter().any(|target| {
                target.device_id == *target_device
                    && target.status == arkret_sdk::DeviceSummaryStatus::Active
                    && target.verification_state
                        == arkret_sdk::DeviceSummaryVerificationState::Verified
                    && target.authorized_event_ref.is_some()
                    && target.validate().is_ok()
            }) {
                continue;
            }
            arkret_sdk::MlsEndpointIdentity::human_device(
                authority.principal_id.clone(),
                target_device.clone(),
            )
        } else {
            if !view.desired_agent_ids.contains(&agent) {
                continue;
            }
            let agent_view = http.agent_get(agent.as_str()).await?;
            anyhow::ensure!(
                agent_view.agent.lifecycle == arkret_sdk::AgentLifecycleState::Active,
                "Sidecar desired Agent is no longer active"
            );
            let keys = agent_view
                .key_state
                .ok_or_else(|| anyhow::anyhow!("Sidecar Agent runtime key is unavailable"))?;
            anyhow::ensure!(
                keys.controller_account_id == *authority && keys.agent_id == agent,
                "Sidecar Agent runtime belongs to another controller or principal"
            );
            let key = keys
                .active_authorizations
                .iter()
                .find(|key| {
                    Some(&key.authorized_event_ref) == keys.authorized_event_ref.as_ref()
                        && key
                            .expires_at
                            .is_none_or(|expiry| expiry > crate::clock::now_utc())
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("Sidecar Agent has no current authorized runtime key")
                })?;
            arkret_sdk::MlsEndpointIdentity::agent_runtime(
                agent.clone(),
                key.verification_method.clone(),
                key.authorized_event_ref.clone(),
            )?
        };
        let checkpoint = state
            .read(|store| store.mls_checkpoint_for_scope_and_group(&scope, group_id.as_str()))
            .ok_or_else(|| anyhow::anyhow!("Sidecar has no local MLS checkpoint"))?;
        let group =
            crate::mls::persistence::restore_envelope(&checkpoint, &secret, checkpoint.epoch)
                .map_err(|error| anyhow::anyhow!(error.to_string()))
                .context("Sidecar private checkpoint could not be restored")?;
        let target_actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId {
            station_id: authority.station_id.clone(),
            principal_id: agent.clone(),
        });
        if group
            .verified_leaf_bindings()
            .context("Sidecar local leaf bindings could not be verified")?
            .iter()
            .any(|leaf| leaf.actor_id == target_actor && leaf.endpoint == endpoint)
        {
            continue;
        }
        let current = crate::realm_events_engine::verified_sidecar_mls_current(api, &scope)
            .await
            .context("Sidecar signed MLS current could not be verified")?;
        let after = http.agent_sidecar_get(&expected.sidecar.id).await?;
        genesis_binding(&after, authority)?;
        anyhow::ensure!(
            after.sidecar.realm_id == *scope.realm_id()
                && after.mls_context.participant_authority_digest
                    == view.mls_context.participant_authority_digest
                && after.mls_context.authority_stream_head
                    == view.mls_context.authority_stream_head
                && after.desired_agent_ids == view.desired_agent_ids
                && after.mls_context.epoch == Some(current.epoch)
                && current.genesis_event_ref.as_str()
                    == after.mls_context.genesis_event_ref.as_deref().unwrap_or("")
                && checkpoint.epoch == current.epoch
                && checkpoint.group_state_event_id.as_ref()
                    == Some(&current.current_mls_commit_event_ref),
            "Sidecar participant cut or exact private base changed during MLS reconciliation"
        );
        let next_epoch = current
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Sidecar MLS epoch overflow"))?;
        let binding = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
            scope.realm_id().clone(),
            view.sidecar.id.clone(),
            Some(current.current_mls_commit_event_ref),
            current.epoch,
            next_epoch,
            current.current_key_access_revision,
            view.mls_context.participant_authority_digest.clone(),
            view.mls_context.authority_stream_head.clone(),
        )?;
        let claim_id = crate::mls_api_helpers::generate_mls_claim_request_id()?;
        let clients = crate::transport::EndpointClients::from_http(http.clone());
        let outcome = clients
            .mls()
            .claim_key_package(
                agent.as_str(),
                scope.realm_id().as_str(),
                authority.principal_id.as_str(),
                device.as_str(),
                Some(authority.station_id.as_str()),
                &claim_id,
                target_device.as_ref().map(|device| device.as_str()),
                group_id.as_str(),
                target_device.is_none().then_some(&endpoint),
            )
            .await?;
        anyhow::ensure!(
            outcome.claims.len() == 1,
            "Sidecar claim must return the exact requested endpoint"
        );
        let claim = &outcome.claims[0];
        anyhow::ensure!(
            crate::mls::governance_proof::claimed_actor_id(claim, &outcome.claim_receipt)
                .map_err(anyhow::Error::msg)?
                == target_actor,
            "Sidecar claim changed the complete Agent ActorId"
        );
        let draft = state
            .read(|store| {
                crate::mls::admission::build_admission_events_with_binding(
                    store,
                    secure.as_ref(),
                    &scope,
                    authority,
                    authority.principal_id.as_str(),
                    device,
                    claim,
                    &claim_id,
                    &outcome.claim_receipt,
                    Some(&binding),
                )
            })
            .map_err(anyhow::Error::msg)?;
        let authored = submitter
            .author_for_direct_submission(&draft.commit)
            .await?;
        let welcomes = (draft.welcomes)(authored.event()).map_err(anyhow::Error::msg)?;
        submitter
            .submit_mls_commit(
                authored,
                welcomes,
                device.clone(),
                draft.authority_hints,
                state,
                draft.staged_checkpoint,
            )
            .await?;
    }
    // A controller current read reports actual recipient consume/readiness;
    // local staging or a successful Commit never substitutes for that gate.
    http.agent_sidecar_get(&expected.sidecar.id)
        .await
        .map_err(Into::into)
}
