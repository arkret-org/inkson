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

async fn ensure_sidecar_mls_genesis(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    expected: &arkret_sdk::AgentSidecarView,
    guard: &ReconciliationGuard,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    guard()?;
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: expected.sidecar.realm_id.clone(),
        sidecar_id: expected.sidecar.id.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let lock_key = format!("{authority}|{device}|{group_id}");
    let lock = crate::mls::admission::mls_admission_authoring_lock(&lock_key);
    let _guard = lock.lock().await;
    guard()?;
    let submitter = api
        .event_submitter()?
        .with_authority(authority.clone())
        .with_state_store(state.clone());
    // A lost response must replay its original signed unit before any new
    // material is generated. No Sidecar creator-FSM record is opened here.
    submitter.drain_outbound().await?;
    guard()?;
    let http = api.sdk_http_client()?;
    let view = http.agent_sidecar_get(&expected.sidecar.id).await?;
    guard()?;
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
    guard()?;

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
        guard()?;
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
        guard()?;
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
            guard()?;
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
            guard()?;
            summary
        }
    };
    guard()?;
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
    guard()?;
    crate::mls::runtime::upload_mls_genesis_public_material(api, &summary)
        .await
        .map_err(|error| anyhow::anyhow!(error.user_message()))?;
    guard()?;
    let result = submitter.submit_sdk_event(&operation).await?;
    guard()?;
    let accepted = arkret_sdk::EventId::new(result.event_id)?;
    publish_genesis(state, &scope, &accepted).await?;
    guard()?;
    let current = http.agent_sidecar_get(&view.sidecar.id).await?;
    guard()?;
    genesis_binding(&current, authority)?;
    anyhow::ensure!(
        current.sidecar.id == view.sidecar.id
            && current.sidecar.realm_id == view.sidecar.realm_id
            && current.mls_context.genesis_event_ref.as_deref() == Some(accepted.as_str()),
        "Sidecar current has not converged to its accepted Genesis"
    );
    Ok(current)
}

type ReconciliationGuard = std::rc::Rc<dyn Fn() -> anyhow::Result<()>>;
type EndpointCut = Vec<(
    arkret_sdk::ActorId,
    arkret_sdk::MlsEndpointIdentity,
    Option<arkret_sdk::EventId>,
)>;

#[derive(Debug, PartialEq)]
enum SidecarRepairPlan {
    Noop,
    Remove(Vec<u32>),
    Refresh,
}

fn sidecar_repair_plan(
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    leaves: &[arkret_sdk::MlsVerifiedLeafBinding],
    expected: &EndpointCut,
    accepted: &arkret_sdk::MlsGovernanceBindingPayload,
    next: &arkret_sdk::MlsGovernanceBindingPayload,
) -> anyhow::Result<SidecarRepairPlan> {
    anyhow::ensure!(
        accepted.effective_scope() == next.effective_scope()
            && matches!(next.effective_scope(), arkret_sdk::ScopeRef::Sidecar { .. }),
        "Sidecar repair crossed its signed native scope"
    );
    let matches = |leaf: &arkret_sdk::MlsVerifiedLeafBinding| {
        expected.iter().any(|(actor, endpoint, authorization)| {
            leaf.actor_id == *actor
                && leaf.endpoint == *endpoint
                && leaf.device_authorize_event_id == *authorization
        })
    };
    for leaf in leaves {
        if let arkret_sdk::MlsEndpointIdentity::AgentRuntime { agent_id, .. } = &leaf.endpoint {
            anyhow::ensure!(
                leaf.actor_id.as_account_id().is_some_and(|account| {
                    account.station_id == authority.station_id && account.principal_id == *agent_id
                }),
                "Sidecar Agent leaf differs from its complete controller-Station identity"
            );
        }
    }
    let author = arkret_sdk::ActorId::account(authority.clone());
    let author_endpoint = arkret_sdk::MlsEndpointIdentity::human_device(
        authority.principal_id.clone(),
        device.clone(),
    );
    anyhow::ensure!(
        leaves.iter().any(|leaf| leaf.actor_id == author
            && leaf.endpoint == author_endpoint
            && matches(leaf)),
        "Sidecar repair requires its exact currently authorized author leaf"
    );
    let mut removed = leaves
        .iter()
        .filter(|leaf| !matches(leaf))
        .map(|leaf| leaf.leaf_index)
        .collect::<Vec<_>>();
    removed.sort_unstable();
    removed.dedup();
    if !removed.is_empty() {
        return Ok(SidecarRepairPlan::Remove(removed));
    }
    // Missing leaves belong to the existing Add lane. A SelfUpdate must never
    // turn an incomplete roster into apparent current authority.
    if expected.iter().any(|(actor, endpoint, authorization)| {
        !leaves.iter().any(|leaf| {
            leaf.actor_id == *actor
                && leaf.endpoint == *endpoint
                && leaf.device_authorize_event_id == *authorization
        })
    }) {
        return Ok(SidecarRepairPlan::Noop);
    }
    let old = accepted
        .sidecar_binding()
        .ok_or_else(|| anyhow::anyhow!("accepted Sidecar MLS binding is missing"))?;
    let new = next
        .sidecar_binding()
        .ok_or_else(|| anyhow::anyhow!("fresh Sidecar MLS binding is missing"))?;
    Ok(
        if old == new && accepted.key_access_revision() == next.key_access_revision() {
            SidecarRepairPlan::Noop
        } else {
            SidecarRepairPlan::Refresh
        },
    )
}

fn stage_sidecar_repair(
    store: &crate::state::LocalStateStore,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
    scope: &arkret_sdk::ScopeRef,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    expected: &EndpointCut,
    accepted: &arkret_sdk::MlsGovernanceBindingPayload,
    binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> anyhow::Result<Option<crate::mls::runtime::StagedMlsCommit>> {
    let checkpoint = store
        .mls_checkpoint_for_scope(scope)
        .ok_or_else(|| anyhow::anyhow!("Sidecar repair has no private checkpoint"))?;
    let secret = crate::mls::runtime::load_device_checkpoint_secret(secure, authority, device)?;
    let group = crate::mls::persistence::restore_envelope(&checkpoint, &secret, checkpoint.epoch)?;
    let plan = sidecar_repair_plan(
        authority,
        device,
        &group.verified_leaf_bindings()?,
        expected,
        accepted,
        binding,
    )?;
    let removed = match plan {
        SidecarRepairPlan::Noop => return Ok(None),
        SidecarRepairPlan::Remove(indices) => indices,
        SidecarRepairPlan::Refresh => Vec::new(),
    };
    Ok(Some(
        crate::mls::runtime::build_sidecar_reconciliation_commit_with_binding(
            store, secure, scope, authority, device, &removed, binding,
        )
        .map_err(|error| anyhow::anyhow!(error.user_message()))?,
    ))
}

async fn reconcile_existing_sidecar_leaves(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    sidecar_id: &arkret_sdk::SidecarId,
    guard: &ReconciliationGuard,
) -> anyhow::Result<()> {
    guard()?;
    let request_epoch = crate::identity::device_directory::session_cache_epoch();
    let http = api.sdk_http_client()?;
    let view = http.agent_sidecar_get(sidecar_id).await?;
    guard()?;
    genesis_binding(&view, authority)?;
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: view.sidecar.realm_id.clone(),
        sidecar_id: sidecar_id.clone(),
    };
    let devices = crate::transport::keys::list_devices(&http).await?;
    guard()?;
    let controller_actor = arkret_sdk::ActorId::account(authority.clone());
    let mut expected: EndpointCut = devices
        .devices
        .iter()
        .filter(|d| {
            d.status == arkret_sdk::DeviceSummaryStatus::Active
                && d.verification_state == arkret_sdk::DeviceSummaryVerificationState::Verified
                && d.authorized_event_ref.is_some()
                && d.validate().is_ok()
        })
        .map(|d| {
            (
                controller_actor.clone(),
                arkret_sdk::MlsEndpointIdentity::human_device(
                    authority.principal_id.clone(),
                    d.device_id.clone(),
                ),
                d.authorized_event_ref.clone(),
            )
        })
        .collect();
    for agent in &view.desired_agent_ids {
        let detail = http.agent_get(agent.as_str()).await?;
        guard()?;
        anyhow::ensure!(
            detail.agent.lifecycle == arkret_sdk::AgentLifecycleState::Active,
            "Sidecar desired Agent is not active"
        );
        let keys = detail
            .key_state
            .ok_or_else(|| anyhow::anyhow!("Sidecar desired Agent has no runtime authorization"))?;
        anyhow::ensure!(
            keys.controller_account_id == *authority && keys.agent_id == *agent,
            "Sidecar runtime authorization changed its complete controller"
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
            .ok_or_else(|| anyhow::anyhow!("Sidecar runtime key is not current"))?;
        expected.push((
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                agent.clone(),
                authority.station_id.clone(),
            )),
            arkret_sdk::MlsEndpointIdentity::agent_runtime(
                agent.clone(),
                key.verification_method.clone(),
                key.authorized_event_ref.clone(),
            )?,
            None,
        ));
    }
    let (current, current_source) = sidecar_snapshot_read(
        crate::realm_events_engine::verified_sidecar_mls_current(api, &scope)
            .await
            .map_err(anyhow::Error::from),
    )?;
    let original_guard = &guard;
    let guard = || -> anyhow::Result<()> {
        original_guard()?;
        current_source.check_session()?;
        Ok(())
    };
    guard()?;
    // Authoring completion persists a private checkpoint before the hint
    // follower necessarily downloads its original Genesis/Commit. Repair
    // must acquire that verified native history before inspecting its binding.
    crate::realm_events_engine::refresh_sidecar_history(
        &http,
        authority,
        request_epoch,
        scope.realm_id(),
        state.clone(),
        || guard().is_ok(),
    )
    .await?;
    guard()?;
    let after = http.agent_sidecar_get(sidecar_id).await?;
    guard()?;
    genesis_binding(&after, authority)?;
    anyhow::ensure!(
        after.sidecar.realm_id == view.sidecar.realm_id
            && after.desired_agent_ids == view.desired_agent_ids
            && after.mls_context.participant_authority_digest
                == view.mls_context.participant_authority_digest
            && after.mls_context.authority_stream_head == view.mls_context.authority_stream_head
            && after.mls_context.epoch == Some(current.epoch),
        "Sidecar authority cut changed during roster repair"
    );
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let secret =
        crate::mls::runtime::load_device_checkpoint_secret(secure.as_ref(), authority, device)?;
    let binding = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        scope.realm_id().clone(),
        sidecar_id.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("MLS epoch overflow"))?,
        current.current_key_access_revision,
        view.mls_context.participant_authority_digest.clone(),
        view.mls_context.authority_stream_head.clone(),
    )?;
    let staged = state.read(
        |store| -> anyhow::Result<Option<crate::mls::runtime::StagedMlsCommit>> {
            let checkpoint = store
                .mls_checkpoint_for_scope(&scope)
                .ok_or_else(|| anyhow::anyhow!("Sidecar repair has no private checkpoint"))?;
            anyhow::ensure!(
                checkpoint.epoch == current.epoch
                    && checkpoint.group_state_event_id.as_ref()
                        == Some(&current.current_mls_commit_event_ref),
                "Sidecar repair private base differs from signed current"
            );
            crate::mls::persistence::restore_envelope(&checkpoint, &secret, current.epoch)?;
            let (_, history) = store.verified_sidecar_inputs(scope.realm_id().as_str())?;
            let full = history
                .get(sidecar_id.as_str())
                .and_then(|rows| {
                    rows.iter().find(|row| {
                        row.event.event_id == current.current_mls_commit_event_ref
                            && row.event.scope_ref == scope
                    })
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("Sidecar repair lacks the exact verified accepted MLS Event")
                })?;
            let accepted = match full.event.kind {
                arkret_sdk::EventKind::MlsGenesis => {
                    serde_json::from_value::<arkret_sdk::MlsGenesisPayload>(serde_json::to_value(
                        &full.event.payload,
                    )?)?
                    .governance_binding
                }
                arkret_sdk::EventKind::MlsCommit => {
                    serde_json::from_value::<arkret_sdk::MlsCommitPayload>(serde_json::to_value(
                        &full.event.payload,
                    )?)?
                    .governance_binding()
                    .clone()
                }
                _ => anyhow::bail!("Sidecar current MLS Event has another kind"),
            };
            stage_sidecar_repair(
                store,
                secure.as_ref(),
                &scope,
                authority,
                device,
                &expected,
                &accepted,
                &binding,
            )
        },
    )?;
    let Some(staged) = staged else { return Ok(()) };
    guard()?;
    let operation = state
        .read(|store| {
            crate::mls::group_events::mls_commit_event_with_binding(
                store,
                authority.principal_id.as_str(),
                &staged.envelope,
                &binding,
            )
        })
        .map_err(anyhow::Error::msg)?;
    let submitter = api
        .event_submitter()?
        .with_authority(authority.clone())
        .with_state_store(state.clone());
    let authored = submitter.author_for_direct_submission(&operation).await?;
    guard()?;
    submitter
        .submit_mls_commit(
            authored,
            Vec::new(),
            device.clone(),
            Vec::new(),
            state,
            staged.staged_checkpoint,
        )
        .await?;
    guard()?;
    Ok(())
}

/// Withdraw obsolete endpoints, rotate the access cut, and add missing endpoints through the
/// existing durable atomic Commit/Welcome lane. Effective access stays pending until
/// the recipients have actually consumed their exact Welcome deliveries.
pub(crate) async fn reconcile_sidecar_mls(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    expected: &arkret_sdk::AgentSidecarView,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    reconcile_sidecar_mls_with_guard(
        api,
        state,
        authority,
        device,
        expected,
        std::rc::Rc::new(move || fence.check()),
    )
    .await
}

pub(crate) async fn reconcile_sidecar_mls_with_guard(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    expected: &arkret_sdk::AgentSidecarView,
    guard: ReconciliationGuard,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    retry_sidecar_preparation(
        &guard,
        || reconcile_sidecar_mls_attempt(api, state, authority, device, expected, guard.clone()),
        || crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(2)),
    )
    .await
}

// A signed-current read can be temporarily unavailable while its governing
// cut moves. Retry only that typed response, never a rejected/unknown write.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct SidecarSnapshotReadUnavailable(anyhow::Error);

pub(crate) fn sidecar_snapshot_read<T>(result: anyhow::Result<T>) -> anyhow::Result<T> {
    result.map_err(|error| {
        let temporary = crate::api_error::api_error_status_and_envelope(&error).is_some_and(|(status, problem)|
            status.as_u16() == 503 && problem.code() == arkret_sdk::error_codes::ErrorCode::REALM_STATE_SNAPSHOT_UNAVAILABLE)
            || error.chain().any(|cause| matches!(cause.downcast_ref::<garth::Error>(),
                Some(garth::Error::Api { status: 503, error }) if error.code() == arkret_sdk::error_codes::ErrorCode::REALM_STATE_SNAPSHOT_UNAVAILABLE));
        if temporary { anyhow::Error::new(SidecarSnapshotReadUnavailable(error)) } else { error }
    })
}

pub(crate) async fn retry_sidecar_preparation<T, F, Fut, W, Wait>(
    guard: &ReconciliationGuard,
    mut attempt: F,
    mut wait: W,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
    W: FnMut() -> Wait,
    Wait: std::future::Future<Output = ()>,
{
    for cycle in 0..8 {
        guard()?;
        let result = attempt().await;
        guard()?;
        match result {
            Ok(value) => return Ok(value),
            Err(error) => {
                let temporary = error.chain().any(|cause| {
                    cause
                        .downcast_ref::<SidecarSnapshotReadUnavailable>()
                        .is_some()
                });
                if !temporary || cycle == 7 {
                    return Err(error);
                }
                wait().await;
                guard()?;
            }
        }
    }
    unreachable!("bounded preparation loop returns on its last attempt")
}

async fn reconcile_sidecar_mls_attempt(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    expected: &arkret_sdk::AgentSidecarView,
    guard: ReconciliationGuard,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    guard()?;
    let mut view = ensure_sidecar_mls_genesis(api, state, authority, device, expected, &guard)
        .await
        .context("Sidecar Genesis preparation failed")?;
    guard()?;
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: view.sidecar.realm_id.clone(),
        sidecar_id: view.sidecar.id.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let lock = crate::mls::admission::mls_admission_authoring_lock(&format!(
        "{authority}|{device}|{group_id}"
    ));
    let _guard = lock.lock().await;
    guard()?;
    let http = api.sdk_http_client()?;
    let submitter = api
        .event_submitter()?
        .with_authority(authority.clone())
        .with_state_store(state.clone());
    submitter.drain_mls_outbound().await?;
    guard()?;
    anyhow::ensure!(
        !submitter
            .has_pending_mls_admission_for_realm(scope.realm_id().as_str())
            .await?,
        "an original durable MLS transition is still converging"
    );
    guard()?;
    reconcile_existing_sidecar_leaves(api, state, authority, device, &view.sidecar.id, &guard)
        .await?;
    guard()?;
    view = http.agent_sidecar_get(&expected.sidecar.id).await?;
    guard()?;
    genesis_binding(&view, authority)?;
    anyhow::ensure!(
        view.sidecar.realm_id == *scope.realm_id(),
        "Sidecar target cut changed its native scope"
    );
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let secret =
        crate::mls::runtime::load_device_checkpoint_secret(secure.as_ref(), authority, device)
            .context("Sidecar checkpoint key is unavailable")?;
    let devices = crate::transport::keys::list_devices(&http).await?;
    guard()?;
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
        guard()?;
        genesis_binding(&view, authority)?;
        anyhow::ensure!(
            view.sidecar.realm_id == *scope.realm_id(),
            "Sidecar read changed its parent Realm"
        );
        let endpoint = if let Some(target_device) = &target_device {
            // Re-check device lifecycle at this cut. A stale account inventory
            // cannot authorize a new leaf after revoke or generation fencing.
            let devices = crate::transport::keys::list_devices(&http).await?;
            guard()?;
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
            guard()?;
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
        let (current, current_source) = sidecar_snapshot_read(
            crate::realm_events_engine::verified_sidecar_mls_current(api, &scope)
                .await
                .map_err(anyhow::Error::from),
        )
        .context("Sidecar signed MLS current could not be verified")?;
        let original_guard = &guard;
        let guard = || -> anyhow::Result<()> {
            original_guard()?;
            current_source.check_session()?;
            Ok(())
        };
        guard()?;
        let after = http.agent_sidecar_get(&expected.sidecar.id).await?;
        guard()?;
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
        guard()?;
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
        guard()?;
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
        guard()?;
        let welcomes = (draft.welcomes)(authored.event()).map_err(anyhow::Error::msg)?;
        guard()?;
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
        guard()?;
    }
    reconcile_existing_sidecar_leaves(api, state, authority, device, &view.sidecar.id, &guard)
        .await?;
    guard()?;
    // A controller current read reports actual recipient consume/readiness;
    // local staging or a successful Commit never substitutes for that gate.
    http.agent_sidecar_get(&expected.sidecar.id)
        .await
        .map_err(Into::into)
}

/// Restore can repair obsolete leaves without a new ensure ceremony or a
/// KeyPackage claim. Missing desired endpoints stay in the explicit Add lane.
pub(crate) async fn reconcile_restored_sidecar_membership(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    view: &arkret_sdk::AgentSidecarView,
    guard: ReconciliationGuard,
) -> anyhow::Result<arkret_sdk::AgentSidecarView> {
    guard()?;
    genesis_binding(view, authority)?;
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: view.sidecar.realm_id.clone(),
        sidecar_id: view.sidecar.id.clone(),
    };
    let lock = crate::mls::admission::mls_admission_authoring_lock(&format!(
        "{authority}|{device}|{}",
        scope.canonical_mls_group_id()?
    ));
    let _lock = lock.lock().await;
    guard()?;
    let submitter = api
        .event_submitter()?
        .with_authority(authority.clone())
        .with_state_store(state.clone());
    submitter.drain_mls_outbound().await?;
    guard()?;
    anyhow::ensure!(
        !submitter
            .has_pending_mls_admission_for_realm(scope.realm_id().as_str())
            .await?,
        "an original durable MLS transition is still converging"
    );
    guard()?;
    reconcile_existing_sidecar_leaves(api, state, authority, device, &view.sidecar.id, &guard)
        .await?;
    guard()?;
    api.sdk_http_client()?
        .agent_sidecar_get(&view.sidecar.id)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
pub(crate) mod tests {
    use arkret_sdk::{
        AccountId, ActorId, ArkretMlsGroup, ArkretMlsIdentity, DeviceId, DidCoreId, EventId,
        ScopeRef,
    };

    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;
    use crate::test_support as fixture;

    fn event(seed: u8) -> EventId {
        EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [seed; 32])
    }
    fn account(name: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }
    fn agent(name: &str, seed: u8) -> ArkretMlsIdentity {
        ArkretMlsIdentity::new_agent(
            ActorId::account(account(name)),
            arkret_sdk::DidUrl::new(format!("did:web:{name}.example#runtime-{seed}")).unwrap(),
            event(seed),
            arkret_sdk::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            ),
        )
        .unwrap()
    }
    struct RepairFixture {
        state: crate::state::LocalStateStore,
        secure: MemorySecureKeyStore,
        authority: AccountId,
        device: DeviceId,
        scope: ScopeRef,
        owner: ArkretMlsGroup,
        paused: ArkretMlsGroup,
        remaining: ArkretMlsGroup,
        revoked_device: Option<ArkretMlsGroup>,
        accepted: arkret_sdk::MlsGovernanceBindingPayload,
        base: EventId,
        genesis: EventId,
        expected: EndpointCut,
    }
    fn binding(
        scope: &ScopeRef,
        authority: &AccountId,
        desired: &[DidCoreId],
        base: Option<EventId>,
        previous: u64,
        next: u64,
        head: u8,
    ) -> arkret_sdk::MlsGovernanceBindingPayload {
        let ScopeRef::Sidecar {
            realm_id,
            sidecar_id,
        } = scope
        else {
            unreachable!()
        };
        arkret_sdk::MlsGovernanceBindingPayload::sidecar(
            realm_id.clone(),
            sidecar_id.clone(),
            base,
            previous,
            next,
            0,
            arkret_sdk::sidecar_participant_authority_digest(
                sidecar_id, realm_id, authority, desired,
            )
            .unwrap(),
            vec![event(head)],
        )
        .unwrap()
    }
    fn checkpoint(
        group: &ArkretMlsGroup,
        scope: &ScopeRef,
        secret: &str,
    ) -> crate::mls::persistence::MlsLocalCheckpointEnvelope {
        let record = group.export_state_record().unwrap();
        crate::mls::persistence::encrypt_state(
            scope.realm_id().as_str(),
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            secret,
            &[0x77; 16],
        )
    }
    fn fixture() -> RepairFixture {
        fixture_with_revoked_device(false)
    }
    fn fixture_with_revoked_device(add_revoked: bool) -> RepairFixture {
        let authority = account("controller");
        let device = DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1").unwrap();
        let scope = ScopeRef::Sidecar {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN",
            )
            .unwrap(),
            sidecar_id: arkret_sdk::SidecarId::from_event_id(&event(60)),
        };
        let owner_identity = ArkretMlsIdentity::new_test_human_device(
            ActorId::account(authority.clone()),
            device.clone(),
        )
        .unwrap();
        let paused_identity = agent("paused", 31);
        let remaining_identity = agent("remaining", 32);
        let mut endpoints = vec![
            owner_identity.endpoint_identity(),
            paused_identity.endpoint_identity(),
            remaining_identity.endpoint_identity(),
        ];
        let desired = vec![
            account("paused").principal_id,
            account("remaining").principal_id,
        ];
        let genesis = event(61);
        let mut owner = owner_identity
            .create_group_with_governance_binding(
                &scope,
                &binding(&scope, &authority, &desired, None, 0, 0, 62),
            )
            .unwrap();
        owner
            .install_test_leaf_bindings(vec![endpoints[0].clone()])
            .unwrap();
        let first_binding = binding(
            &scope,
            &authority,
            &desired,
            Some(genesis.clone()),
            0,
            1,
            62,
        );
        let first = owner
            .add_member_with_governance_binding(
                &fixture::claimed_mls_key_package(
                    paused_identity.key_package_record().unwrap(),
                    1_760_000_000_001,
                ),
                &first_binding,
            )
            .unwrap();
        let first_accepted = fixture::accepted_mls_commit_with_binding(
            ActorId::account(authority.clone()),
            &first.commit,
            first_binding,
            63,
        );
        owner
            .install_recovered_own_commit(&first_accepted, &genesis)
            .unwrap();
        owner
            .install_test_leaf_bindings(endpoints[..2].to_vec())
            .unwrap();
        let welcome = fixture::accepted_mls_welcome(
            &first.welcome,
            ActorId::account(account("paused")),
            &first_accepted,
            1_760_000_000_002,
        );
        let mut paused = ArkretMlsGroup::join_from_verified_welcome_delivery(
            paused_identity,
            &welcome,
            &first_accepted,
        )
        .unwrap();
        paused
            .install_test_leaf_bindings(endpoints[..2].to_vec())
            .unwrap();
        let second_binding = binding(
            &scope,
            &authority,
            &desired,
            Some(first_accepted.event.event_id.clone()),
            1,
            2,
            62,
        );
        let second = owner
            .add_member_with_governance_binding(
                &fixture::claimed_mls_key_package(
                    remaining_identity.key_package_record().unwrap(),
                    1_760_000_000_003,
                ),
                &second_binding,
            )
            .unwrap();
        let second_accepted = fixture::accepted_mls_commit_with_binding(
            ActorId::account(authority.clone()),
            &second.commit,
            second_binding.clone(),
            64,
        );
        let current1 = current(&scope, &genesis, &first_accepted.event.event_id, 1);
        owner
            .install_accepted_commit(&second_accepted, &current1)
            .unwrap();
        paused
            .install_accepted_commit(&second_accepted, &current1)
            .unwrap();
        paused
            .install_test_leaf_bindings(endpoints.clone())
            .unwrap();
        assert_eq!(paused.epoch(), owner.epoch());
        owner.install_test_leaf_bindings(endpoints.clone()).unwrap();
        let welcome2 = fixture::accepted_mls_welcome(
            &second.welcome,
            ActorId::account(account("remaining")),
            &second_accepted,
            1_760_000_000_004,
        );
        let mut remaining = ArkretMlsGroup::join_from_verified_welcome_delivery(
            remaining_identity,
            &welcome2,
            &second_accepted,
        )
        .unwrap();
        remaining
            .install_test_leaf_bindings(endpoints.clone())
            .unwrap();
        let mut base = second_accepted.event.event_id;
        let mut accepted_binding = second_binding;
        let mut revoked_device = None;
        if add_revoked {
            let identity = ArkretMlsIdentity::new_test_human_device(
                ActorId::account(authority.clone()),
                DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a9").unwrap(),
            )
            .unwrap();
            endpoints.push(identity.endpoint_identity());
            let next = binding(&scope, &authority, &desired, Some(base.clone()), 2, 3, 62);
            let add = owner
                .add_member_with_governance_binding(
                    &fixture::claimed_mls_key_package(
                        identity.key_package_record().unwrap(),
                        1_760_000_000_005,
                    ),
                    &next,
                )
                .unwrap();
            let accepted = fixture::accepted_mls_commit_with_binding(
                ActorId::account(authority.clone()),
                &add.commit,
                next.clone(),
                67,
            );
            let prior = current(&scope, &genesis, &base, 2);
            owner.install_accepted_commit(&accepted, &prior).unwrap();
            paused.install_accepted_commit(&accepted, &prior).unwrap();
            remaining
                .install_accepted_commit(&accepted, &prior)
                .unwrap();
            for group in [&mut owner, &mut paused, &mut remaining] {
                group.install_test_leaf_bindings(endpoints.clone()).unwrap();
            }
            let welcome = fixture::accepted_mls_welcome(
                &add.welcome,
                ActorId::account(authority.clone()),
                &accepted,
                1_760_000_000_006,
            );
            let mut revoked =
                ArkretMlsGroup::join_from_verified_welcome_delivery(identity, &welcome, &accepted)
                    .unwrap();
            revoked
                .install_test_leaf_bindings(endpoints.clone())
                .unwrap();
            revoked_device = Some(revoked);
            base = accepted.event.event_id;
            accepted_binding = next;
        }
        let secure = MemorySecureKeyStore::new();
        let secret =
            crate::mls::runtime::load_or_create_account_mls_secret(&secure, &authority).unwrap();
        let mut state = crate::state::isolated_store_for_tests("sidecar-roster-repair");
        state
            .install_accepted_mls_transition(&scope, checkpoint(&owner, &scope, &secret), &base)
            .unwrap();
        let expected = owner
            .verified_leaf_bindings()
            .unwrap()
            .into_iter()
            .filter(|leaf| leaf.actor_id != ActorId::account(account("paused")) &&
                !matches!(&leaf.endpoint, arkret_sdk::MlsEndpointIdentity::HumanDevice { device_id, .. }
                    if device_id.as_str().ends_with("0000000000a9")))
            .map(|leaf| (leaf.actor_id, leaf.endpoint, leaf.device_authorize_event_id))
            .collect();
        RepairFixture {
            state,
            secure,
            authority,
            device,
            scope,
            owner,
            paused,
            remaining,
            revoked_device,
            accepted: accepted_binding,
            base,
            genesis,
            expected,
        }
    }
    fn current(
        scope: &ScopeRef,
        genesis: &EventId,
        base: &EventId,
        epoch: u64,
    ) -> arkret_wire::MlsGroupCurrent {
        arkret_wire::MlsGroupCurrent {
            effective_scope: scope.clone(),
            genesis_event_ref: genesis.clone(),
            current_mls_commit_event_ref: base.clone(),
            epoch,
            cipher_suite: arkret_wire::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            )
            .unwrap(),
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: arkret_sdk::BlobRef::new(format!(
                "ak:blob:sha256:{}",
                "33".repeat(32)
            ))
            .unwrap(),
        }
    }

    #[test]
    pub(crate) fn sidecar_repair_actual_remove_rotates_and_excludes_paused_endpoint_after_restart()
    {
        let mut f = fixture();
        let next = binding(
            &f.scope,
            &f.authority,
            &[account("remaining").principal_id],
            Some(f.base.clone()),
            2,
            3,
            65,
        );
        let staged = stage_sidecar_repair(
            &f.state,
            &f.secure,
            &f.scope,
            &f.authority,
            &f.device,
            &f.expected,
            &f.accepted,
            &next,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            f.state.mls_checkpoint_for_scope(&f.scope).unwrap().epoch,
            2,
            "staging is not acceptance"
        );
        let (info, tree) = f.owner.public_group_state_bytes().unwrap();
        let mut tracker = arkret_sdk::MlsPublicGroupTracker::from_external(
            &info,
            &tree,
            f.owner.group_id().as_str(),
            2,
        )
        .unwrap();
        tracker
            .process_public_handshake(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    staged.envelope.commit.as_str(),
                )
                .unwrap(),
            )
            .unwrap();
        let secret =
            crate::mls::runtime::load_device_checkpoint_secret(&f.secure, &f.authority, &f.device)
                .unwrap();
        let mut recovered =
            crate::mls::persistence::restore_envelope(&staged.staged_checkpoint, &secret, 2)
                .unwrap();
        assert_eq!(recovered.epoch(), 2);
        assert!(recovered.has_pending_commit());
        let accepted = fixture::accepted_mls_commit_with_binding(
            ActorId::account(f.authority.clone()),
            &staged.envelope,
            next,
            66,
        );
        recovered
            .install_recovered_own_commit(&accepted, &f.base)
            .unwrap();
        let base = current(&f.scope, &f.genesis, &f.base, 2);
        f.remaining
            .install_accepted_commit(&accepted, &base)
            .unwrap();
        let endpoints = f
            .expected
            .iter()
            .map(|(_, endpoint, _)| endpoint.clone())
            .collect::<Vec<_>>();
        recovered
            .install_test_leaf_bindings(endpoints.clone())
            .unwrap();
        f.remaining.install_test_leaf_bindings(endpoints).unwrap();
        f.remaining =
            ArkretMlsGroup::restore_from_state_record(&f.remaining.export_state_record().unwrap())
                .unwrap();
        assert_eq!(f.paused.epoch(), 2);
        let leaves = recovered.verified_leaf_bindings().unwrap();
        assert_eq!(leaves.len(), 2);
        assert!(
            leaves
                .iter()
                .all(|leaf| leaf.actor_id != ActorId::account(account("paused")))
        );
        assert!(
            tracker
                .leaves()
                .unwrap()
                .iter()
                .all(|leaf| leaf.actor_id != ActorId::account(account("paused")))
        );
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/json",
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            f.scope.clone(),
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            3,
            accepted.event.event_id.clone(),
            recovered.local_content_sender_domain().unwrap(),
            arkret_sdk::EventContentRoutingContext::None,
        )
        .unwrap();
        let encrypted = recovered
            .encrypt_payload(header, b"after paused leaf removal")
            .unwrap();
        assert_eq!(
            f.remaining.decrypt_payload(&encrypted).unwrap(),
            b"after paused leaf removal"
        );
        f.paused.install_accepted_commit(&accepted, &base).unwrap();
        assert!(f.paused.decrypt_payload(&encrypted).is_err());
    }

    #[test]
    fn sidecar_repair_keeps_same_actor_active_endpoint_and_rejects_wrong_base_scope_or_author() {
        let mut f = fixture_with_revoked_device(true);
        let leaves = f.owner.verified_leaf_bindings().unwrap();
        let next = binding(
            &f.scope,
            &f.authority,
            &[account("remaining").principal_id],
            Some(f.base.clone()),
            3,
            4,
            65,
        );
        assert_eq!(
            sidecar_repair_plan(
                &f.authority,
                &f.device,
                &leaves,
                &f.expected,
                &f.accepted,
                &next
            )
            .unwrap(),
            SidecarRepairPlan::Remove(vec![1, 3])
        );
        let staged = stage_sidecar_repair(
            &f.state,
            &f.secure,
            &f.scope,
            &f.authority,
            &f.device,
            &f.expected,
            &f.accepted,
            &next,
        )
        .unwrap()
        .unwrap();
        let (info, tree) = f.owner.public_group_state_bytes().unwrap();
        let mut tracker = arkret_sdk::MlsPublicGroupTracker::from_external(
            &info,
            &tree,
            f.owner.group_id().as_str(),
            3,
        )
        .unwrap();
        tracker
            .process_public_handshake(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    staged.envelope.commit.as_str(),
                )
                .unwrap(),
            )
            .unwrap();
        let accepted = fixture::accepted_mls_commit_with_binding(
            ActorId::account(f.authority.clone()),
            &staged.envelope,
            next.clone(),
            68,
        );
        let secret =
            crate::mls::runtime::load_device_checkpoint_secret(&f.secure, &f.authority, &f.device)
                .unwrap();
        let mut repaired =
            crate::mls::persistence::restore_envelope(&staged.staged_checkpoint, &secret, 3)
                .unwrap();
        repaired
            .install_recovered_own_commit(&accepted, &f.base)
            .unwrap();
        let endpoints = f
            .expected
            .iter()
            .map(|(_, endpoint, _)| endpoint.clone())
            .collect::<Vec<_>>();
        repaired
            .install_test_leaf_bindings(endpoints.clone())
            .unwrap();
        let base = current(&f.scope, &f.genesis, &f.base, 3);
        f.remaining
            .install_accepted_commit(&accepted, &base)
            .unwrap();
        f.remaining.install_test_leaf_bindings(endpoints).unwrap();
        let retained = repaired.verified_leaf_bindings().unwrap();
        assert_eq!(retained.len(), 2);
        assert!(retained.iter().any(
            |leaf| leaf.actor_id == ActorId::account(f.authority.clone())
                && leaf.endpoint
                    == arkret_sdk::MlsEndpointIdentity::human_device(
                        f.authority.principal_id.clone(),
                        f.device.clone()
                    )
        ));
        assert_eq!(
            tracker
                .leaves()
                .unwrap()
                .iter()
                .filter(|leaf| leaf.actor_id == ActorId::account(f.authority.clone()))
                .count(),
            1
        );
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/json",
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            f.scope.clone(),
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            4,
            accepted.event.event_id.clone(),
            repaired.local_content_sender_domain().unwrap(),
            arkret_sdk::EventContentRoutingContext::None,
        )
        .unwrap();
        let encrypted = repaired
            .encrypt_payload(header, b"exact active controller endpoint retained")
            .unwrap();
        assert_eq!(
            f.remaining.decrypt_payload(&encrypted).unwrap(),
            b"exact active controller endpoint retained"
        );
        let mut revoked = f.revoked_device.take().unwrap();
        revoked.install_accepted_commit(&accepted, &base).unwrap();
        assert!(revoked.decrypt_payload(&encrypted).is_err());
        let wrong = binding(
            &f.scope,
            &f.authority,
            &[account("remaining").principal_id],
            Some(event(90)),
            3,
            4,
            65,
        );
        assert!(
            stage_sidecar_repair(
                &f.state,
                &f.secure,
                &f.scope,
                &f.authority,
                &f.device,
                &f.expected,
                &f.accepted,
                &wrong
            )
            .is_err()
        );
        let scope = ScopeRef::Sidecar {
            realm_id: f.scope.realm_id().clone(),
            sidecar_id: arkret_sdk::SidecarId::from_event_id(&event(99)),
        };
        let wrong_scope = binding(
            &scope,
            &f.authority,
            &[account("remaining").principal_id],
            Some(f.base.clone()),
            3,
            4,
            65,
        );
        assert!(
            stage_sidecar_repair(
                &f.state,
                &f.secure,
                &f.scope,
                &f.authority,
                &f.device,
                &f.expected,
                &f.accepted,
                &wrong_scope
            )
            .is_err()
        );
        assert!(
            sidecar_repair_plan(
                &account("other"),
                &f.device,
                &leaves,
                &f.expected,
                &f.accepted,
                &next
            )
            .is_err()
        );
    }

    #[test]
    fn sidecar_repair_same_roster_changed_cut_authors_real_self_update() {
        let mut f = fixture();
        let expected = f
            .owner
            .verified_leaf_bindings()
            .unwrap()
            .into_iter()
            .map(|leaf| (leaf.actor_id, leaf.endpoint, leaf.device_authorize_event_id))
            .collect::<EndpointCut>();
        let old_secret = f
            .owner
            .export_secret("sidecar-repair-test", b"rotation", 32)
            .unwrap();
        let mut old_peer =
            ArkretMlsGroup::restore_from_state_record(&f.paused.export_state_record().unwrap())
                .unwrap();
        let next = binding(
            &f.scope,
            &f.authority,
            &[
                account("paused").principal_id,
                account("remaining").principal_id,
            ],
            Some(f.base.clone()),
            2,
            3,
            65,
        );
        let staged = stage_sidecar_repair(
            &f.state,
            &f.secure,
            &f.scope,
            &f.authority,
            &f.device,
            &expected,
            &f.accepted,
            &next,
        )
        .unwrap()
        .unwrap();
        let (info, tree) = f.owner.public_group_state_bytes().unwrap();
        let mut tracker = arkret_sdk::MlsPublicGroupTracker::from_external(
            &info,
            &tree,
            f.owner.group_id().as_str(),
            2,
        )
        .unwrap();
        let old_leaves = tracker.leaves().unwrap();
        tracker
            .process_public_handshake(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    staged.envelope.commit.as_str(),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(tracker.leaves().unwrap(), old_leaves);
        let accepted = fixture::accepted_mls_commit_with_binding(
            ActorId::account(f.authority.clone()),
            &staged.envelope,
            next,
            69,
        );
        let secret =
            crate::mls::runtime::load_device_checkpoint_secret(&f.secure, &f.authority, &f.device)
                .unwrap();
        let mut repaired =
            crate::mls::persistence::restore_envelope(&staged.staged_checkpoint, &secret, 2)
                .unwrap();
        repaired
            .install_recovered_own_commit(&accepted, &f.base)
            .unwrap();
        let base = current(&f.scope, &f.genesis, &f.base, 2);
        let endpoints = expected
            .iter()
            .map(|(_, endpoint, _)| endpoint.clone())
            .collect::<Vec<_>>();
        for group in [&mut repaired, &mut f.paused, &mut f.remaining] {
            if group.epoch() == 2 {
                group.install_accepted_commit(&accepted, &base).unwrap();
            }
            group.install_test_leaf_bindings(endpoints.clone()).unwrap();
            assert_eq!(group.epoch(), 3);
            assert_eq!(group.verified_leaf_bindings().unwrap().len(), 3);
        }
        let next_secret = repaired
            .export_secret("sidecar-repair-test", b"rotation", 32)
            .unwrap();
        assert!(old_secret.as_slice() != next_secret.as_slice());
        assert!(
            next_secret.as_slice()
                == f.remaining
                    .export_secret("sidecar-repair-test", b"rotation", 32)
                    .unwrap()
                    .as_slice()
        );
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/json",
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            f.scope.clone(),
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            3,
            accepted.event.event_id,
            repaired.local_content_sender_domain().unwrap(),
            arkret_sdk::EventContentRoutingContext::None,
        )
        .unwrap();
        let encrypted = repaired
            .encrypt_payload(header, b"same roster fresh authority cut")
            .unwrap();
        assert!(old_peer.decrypt_payload(&encrypted).is_err());
        assert_eq!(
            f.paused.decrypt_payload(&encrypted).unwrap(),
            b"same roster fresh authority cut"
        );
        assert_eq!(
            f.remaining.decrypt_payload(&encrypted).unwrap(),
            b"same roster fresh authority cut"
        );
    }

    #[test]
    fn sidecar_repair_matching_cut_is_noop_and_missing_endpoint_does_not_self_update() {
        let f = fixture();
        let leaves = f.owner.verified_leaf_bindings().unwrap();
        let mut expected = leaves
            .iter()
            .map(|leaf| {
                (
                    leaf.actor_id.clone(),
                    leaf.endpoint.clone(),
                    leaf.device_authorize_event_id.clone(),
                )
            })
            .collect::<EndpointCut>();
        assert!(
            stage_sidecar_repair(
                &f.state,
                &f.secure,
                &f.scope,
                &f.authority,
                &f.device,
                &expected,
                &f.accepted,
                &f.accepted
            )
            .unwrap()
            .is_none()
        );
        expected.push((
            ActorId::account(account("new-agent")),
            agent("new-agent", 35).endpoint_identity(),
            None,
        ));
        let next = binding(
            &f.scope,
            &f.authority,
            &[
                account("paused").principal_id,
                account("remaining").principal_id,
                account("new-agent").principal_id,
            ],
            Some(f.base.clone()),
            2,
            3,
            65,
        );
        assert!(
            stage_sidecar_repair(
                &f.state,
                &f.secure,
                &f.scope,
                &f.authority,
                &f.device,
                &expected,
                &f.accepted,
                &next
            )
            .unwrap()
            .is_none()
        );
    }
    fn snapshot_unavailable() -> anyhow::Error {
        sidecar_snapshot_read::<()>(Err(anyhow::Error::new(garth::Error::Api {
            status: 503,
            error: Box::new(arkret_sdk::Problem::from_code(
                arkret_sdk::error_codes::ErrorCode::REALM_STATE_SNAPSHOT_UNAVAILABLE,
                "temporary cut read",
            )),
        })))
        .unwrap_err()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sidecar_prepare_typed_snapshot_retry_executes_real_add_against_fresh_cut() {
        let f = fixture();
        let mut owner = f.owner;
        let new_agent = agent("new-desired", 73);
        let key_package = fixture::claimed_mls_key_package(
            new_agent.key_package_record().unwrap(),
            1_760_000_000_007,
        );
        let next = binding(
            &f.scope,
            &f.authority,
            &[
                account("paused").principal_id,
                account("remaining").principal_id,
                account("new-desired").principal_id,
            ],
            Some(f.base.clone()),
            2,
            3,
            74,
        );
        let mut attempts = 0;
        let mut claims = 0;
        let mut waits = 0;
        let guard: ReconciliationGuard = std::rc::Rc::new(|| Ok(()));
        let envelope = retry_sidecar_preparation(
            &guard,
            || {
                attempts += 1;
                std::future::ready(if attempts == 1 {
                    Err(snapshot_unavailable())
                } else {
                    claims += 1;
                    owner
                        .add_member_with_governance_binding(&key_package, &next)
                        .map(|result| result.commit)
                        .map_err(anyhow::Error::from)
                })
            },
            || {
                waits += 1;
                std::future::ready(())
            },
        )
        .await
        .unwrap();
        assert_eq!((attempts, claims, waits), (2, 1, 1));
        assert!(owner.has_pending_commit());
        assert_eq!(owner.epoch(), 2, "retry authoring is not acceptance");
        let (info, tree) = f.remaining.public_group_state_bytes().unwrap();
        let mut tracker = arkret_sdk::MlsPublicGroupTracker::from_external(
            &info,
            &tree,
            owner.group_id().as_str(),
            2,
        )
        .unwrap();
        tracker
            .process_public_handshake(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    envelope.commit.as_str(),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(
            tracker
                .leaves()
                .unwrap()
                .iter()
                .any(|leaf| leaf.actor_id == ActorId::account(account("new-desired")))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sidecar_prepare_retry_is_bounded_and_never_retries_unknown_write_outcomes() {
        let guard: ReconciliationGuard = std::rc::Rc::new(|| Ok(()));
        let mut attempts = 0;
        let mut waits = 0;
        assert!(
            retry_sidecar_preparation(
                &guard,
                || {
                    attempts += 1;
                    std::future::ready(Err::<(), _>(snapshot_unavailable()))
                },
                || {
                    waits += 1;
                    std::future::ready(())
                }
            )
            .await
            .is_err()
        );
        assert_eq!((attempts, waits), (8, 7));
        for (status, code) in [
            (
                403,
                arkret_sdk::error_codes::ErrorCode::REALM_STATE_SNAPSHOT_UNAVAILABLE,
            ),
            (
                503,
                arkret_sdk::error_codes::ErrorCode::TEMPORARILY_UNAVAILABLE,
            ),
        ] {
            let mut attempts = 0;
            assert!(
                retry_sidecar_preparation(
                    &guard,
                    || {
                        attempts += 1;
                        std::future::ready(sidecar_snapshot_read::<()>(Err(anyhow::Error::new(
                            garth::Error::Api {
                                status,
                                error: Box::new(arkret_sdk::Problem::from_code(
                                    code,
                                    "not a retryable snapshot read",
                                )),
                            },
                        ))))
                    },
                    || async {
                        panic!("must not retry non-snapshot refusal");
                    }
                )
                .await
                .is_err()
            );
            assert_eq!(attempts, 1);
        }
        let mut f = fixture();
        let pending = f
            .owner
            .self_update_commit_with_governance_binding(&binding(
                &f.scope,
                &f.authority,
                &[
                    account("paused").principal_id,
                    account("remaining").principal_id,
                ],
                Some(f.base),
                2,
                3,
                75,
            ))
            .unwrap();
        let before = f.owner.export_state_record().unwrap();
        let mut attempts = 0;
        assert!(
            retry_sidecar_preparation(
                &guard,
                || {
                    attempts += 1;
                    std::future::ready(Err::<(), _>(anyhow::anyhow!(
                        "response lost after potential authority acceptance"
                    )))
                },
                || async {
                    panic!("unknown write must replay original unit, not retry authoring");
                }
            )
            .await
            .is_err()
        );
        assert_eq!(attempts, 1);
        assert!(f.owner.has_pending_commit());
        let mut after = f.owner.export_state_record().unwrap();
        // Export refreshes only its observation timestamp. Compare every
        // identity and exact private-snapshot byte, including pending digest,
        // ratchets and Signal nonce, without treating wall time as MLS state.
        after.updated_at = before.updated_at;
        assert!(after == before);
        assert_eq!(pending.epoch, 3);
        let mut attempts = 0;
        assert!(
            retry_sidecar_preparation(
                &guard,
                || {
                    attempts += 1;
                    std::future::ready(Err::<(), _>(anyhow::Error::new(garth::Error::Api {
                        status: 503,
                        error: Box::new(arkret_sdk::Problem::from_code(
                            arkret_sdk::error_codes::ErrorCode::REALM_STATE_SNAPSHOT_UNAVAILABLE,
                            "unclassified submit outcome",
                        )),
                    })))
                },
                || async {
                    panic!("write-side 503 must not masquerade as read retry");
                }
            )
            .await
            .is_err()
        );
        assert_eq!(attempts, 1);
    }
}
