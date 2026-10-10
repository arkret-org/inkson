//! Rebuildable private exchange projection from verified, authenticated facts.

use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::{
    AccountId, AgentSidecar, AgentSidecarEventExchangeBinding, AgentSidecarExchangeAction,
    AgentSidecarExchangeControl, AgentSidecarExchangeControlPayload,
    AgentSidecarExchangeControlsCurrentValue, AgentSidecarExchangeProjection,
    AgentSidecarExchangeRole, AgentSidecarExchangeStatus, AgentSidecarFoldedCheckpoint,
    CurrentSelector, EncryptedEnvelope, Event, EventId, EventKind, Hash, MessageMetadata, ScopeRef,
    SidecarContextRef, TypedCurrentRow,
};

use crate::state::LocalStateStore;

struct Exchange {
    projection: AgentSidecarExchangeProjection,
    parents: BTreeMap<EventId, BTreeSet<EventId>>,
    completion_requested: bool,
}

impl Exchange {
    fn closure(&self, heads: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        let mut closure = BTreeSet::new();
        let mut pending = heads.iter().cloned().collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if closure.insert(id.clone())
                && let Some(parents) = self.parents.get(&id)
            {
                pending.extend(parents.iter().cloned());
            }
        }
        closure
    }

    fn heads(&self) -> Vec<EventId> {
        let mut heads = self.parents.keys().cloned().collect::<BTreeSet<_>>();
        for parents in self.parents.values() {
            for parent in parents {
                heads.remove(parent);
            }
        }
        heads.into_iter().collect()
    }

    fn contribute(&mut self, event: &Event, parents: BTreeSet<EventId>) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.parents.contains_key(&event.event_id),
            "Sidecar fact is duplicated"
        );
        self.parents.insert(event.event_id.clone(), parents);
        self.projection.folded_checkpoint.event_ids = self.heads();
        self.projection.folded_checkpoint.event_set_digest = Hash::new(
            arkret_sdk::canonical::canonical_sha256(&self.parents.keys().collect::<Vec<_>>())?,
        )?;
        Ok(())
    }
}

fn sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn after_parents(event: &Event, exchange: &Exchange) -> BTreeSet<EventId> {
    event
        .semantic_refs
        .iter()
        .filter(|reference| reference.role == "after" && reference.critical)
        .filter_map(|reference| EventId::new(reference.id.clone()).ok())
        .filter(|id| exchange.parents.contains_key(id))
        .collect()
}

type GroupViewKey = (String, String, u64, String);

/// Disposable within one verified fold. Restore each historical MLS tree once,
/// while still checking every Event's proof, signer and encrypted payload.
struct FoldValidationCache {
    device: Option<crate::state::PersistedDeviceAuthoringAuthority>,
    agents: BTreeMap<GroupViewKey, arkret_sdk::mls::AgentMlsSignerView>,
    authors: BTreeMap<GroupViewKey, arkret_sdk::mls::AuthorGroupStateView>,
}

impl FoldValidationCache {
    fn new(store: &LocalStateStore) -> Self {
        Self {
            device: store.load().device_authoring_authority,
            agents: BTreeMap::new(),
            authors: BTreeMap::new(),
        }
    }

    fn key(event: &Event, envelope: &EncryptedEnvelope) -> anyhow::Result<GroupViewKey> {
        Ok((
            arkret_sdk::canonical::canonical_json_string(&event.scope_ref)?,
            event.scope_ref.canonical_mls_group_id()?.to_string(),
            envelope.encryption_context.epoch(),
            envelope.encryption_context.group_state_ref().to_string(),
        ))
    }
}

fn decrypt(
    store: &LocalStateStore,
    controller: &AccountId,
    event: &Event,
    envelope: &EncryptedEnvelope,
    validation: &mut FoldValidationCache,
) -> anyhow::Result<Vec<u8>> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    decrypt_with_secure_store(
        store,
        controller,
        event,
        envelope,
        validation,
        secure_store.as_ref(),
    )
}

fn decrypt_with_secure_store(
    store: &LocalStateStore,
    controller: &AccountId,
    event: &Event,
    envelope: &EncryptedEnvelope,
    validation: &mut FoldValidationCache,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<Vec<u8>> {
    envelope.validate()?;
    event.validate_proof_bindings_with_digest_suite(
        event.realm_id.digest_suite_code().digest_suite(),
    )?;
    let local = validation
        .device
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Sidecar fold awaits its local authorized device"))?;
    anyhow::ensure!(
        &local.account_id == controller,
        "Sidecar fold belongs to another controller Account"
    );
    let sender = arkret_sdk::mls_basic_credential_identity(event.actual_signer())?;
    if event.human_device_producer()?.is_none() {
        let group_id = event.scope_ref.canonical_mls_group_id()?;
        let key = FoldValidationCache::key(event, envelope)?;
        let view = if let Some(view) = validation.agents.get(&key) {
            view.clone()
        } else {
            let view = crate::mls::runtime::ordinary_agent_mls_author_view_for_scope(
                store,
                secure_store,
                controller,
                &local.device_id,
                &event.scope_ref,
                group_id.as_str(),
                envelope.encryption_context.epoch(),
                envelope.encryption_context.group_state_ref().as_str(),
            )
            .ok_or_else(|| {
                anyhow::anyhow!("Sidecar fact awaits its exact historical Agent MLS leaf")
            })?;
            validation
                .authors
                .insert(key.clone(), view.group_state.clone());
            validation.agents.insert(key, view.clone());
            view
        };
        let binding = crate::identity::agent_signer_evidence::OrdinaryAgentMlsBinding {
            view: &view,
            group_id: group_id.as_str(),
            epoch: envelope.encryption_context.epoch(),
            group_state_ref: envelope.encryption_context.group_state_ref().as_str(),
        };
        anyhow::ensure!(
            crate::identity::agent_signer_evidence::verify_cached_event(
                &serde_json::to_value(event)?,
                store,
                Some(binding)
            ) == crate::identity::agent_signer_evidence::CachedAgentEventVerdict::Verified,
            "Sidecar fact awaits authenticated historical Agent signer and MLS binding evidence"
        );
    }
    let payload = crate::mls::runtime::encrypted_payload_from_verified_event_context(
        store,
        envelope,
        &event.scope_ref,
        event.kind.as_str(),
        &sender,
        None,
    )
    .ok_or_else(|| anyhow::anyhow!("Sidecar fact awaits its exact accepted MLS state"))?;
    crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
        store,
        secure_store,
        event.realm_id.as_str(),
        controller,
        &local.device_id,
        &payload,
        &event.scope_ref,
        &sender,
    )
    .ok_or_else(|| anyhow::anyhow!("Sidecar fact could not be authenticated and decrypted"))
}

fn eligible_agents(
    store: &LocalStateStore,
    controller: &AccountId,
    event: &Event,
    envelope: &EncryptedEnvelope,
    agents: &[arkret_sdk::DidCoreId],
    validation: &mut FoldValidationCache,
) -> anyhow::Result<bool> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    eligible_agents_with_secure_store(
        store,
        controller,
        event,
        envelope,
        agents,
        validation,
        secure_store.as_ref(),
    )
}

fn eligible_agents_with_secure_store(
    store: &LocalStateStore,
    controller: &AccountId,
    event: &Event,
    envelope: &EncryptedEnvelope,
    agents: &[arkret_sdk::DidCoreId],
    validation: &mut FoldValidationCache,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<bool> {
    let local = validation
        .device
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Sidecar fold awaits its local authorized device"))?;
    let group_id = event.scope_ref.canonical_mls_group_id()?;
    let key = FoldValidationCache::key(event, envelope)?;
    let view = if let Some(view) = validation.authors.get(&key) {
        view.clone()
    } else {
        let view = crate::mls::runtime::verified_author_group_view_for_scope(
            store,
            secure_store,
            controller,
            &local.device_id,
            &event.scope_ref,
            group_id.as_str(),
            envelope.encryption_context.epoch(),
            envelope.encryption_context.group_state_ref().as_str(),
        )
        .ok_or_else(|| {
            anyhow::anyhow!("Sidecar eligibility awaits its exact historical MLS leaf set")
        })?;
        validation.authors.insert(key, view.clone());
        view
    };
    Ok(agents.iter().all(|agent| {
        view.active_leaves.iter().any(|leaf| {
            let arkret_sdk::mls::AuthorLeafCredential::Basic { identity } = &leaf.credential else {
                return false;
            };
            arkret_sdk::decode_mls_basic_credential_identity(identity).is_ok_and(|actor| {
                actor.as_account_id().is_some_and(|account| {
                    account.principal_id == *agent && account.station_id == controller.station_id
                })
            })
        })
    }))
}

pub(crate) fn rebuild(
    store: &LocalStateStore,
    controller: &AccountId,
    realm: &str,
) -> anyhow::Result<Vec<AgentSidecarExchangeProjection>> {
    Ok(rebuild_with_closes(store, controller, realm)?.0)
}

type RebuiltExchanges = (
    Vec<AgentSidecarExchangeProjection>,
    Vec<(AgentSidecarExchangeProjection, AgentSidecarExchangeControl)>,
);

pub(crate) fn rebuild_with_closes(
    store: &LocalStateStore,
    controller: &AccountId,
    realm: &str,
) -> anyhow::Result<RebuiltExchanges> {
    let (snapshot, histories) = store.verified_sidecar_inputs(realm)?;
    let mut validation = FoldValidationCache::new(store);
    let mut result = Vec::new();
    let mut closes = Vec::new();
    for row in &snapshot.current_state_entries {
        let TypedCurrentRow::Value {
            selector: CurrentSelector::Sidecar { sidecar_id },
            value,
            ..
        } = row
        else {
            continue;
        };
        let sidecar: AgentSidecar = serde_json::from_value(value.clone())?;
        sidecar.validate_shape()?;
        anyhow::ensure!(
            &sidecar.id == sidecar_id && sidecar.realm_id == snapshot.realm_id,
            "Sidecar current selector differs from its value"
        );
        if &sidecar.controller_account_id != controller {
            continue;
        }
        let history = histories.get(sidecar_id.as_str()).ok_or_else(|| {
            anyhow::anyhow!("controller Sidecar has no complete verified history")
        })?;
        let scope = ScopeRef::Sidecar {
            realm_id: sidecar.realm_id.clone(),
            sidecar_id: sidecar_id.clone(),
        };
        let mut controls = BTreeMap::new();
        let mut attached = BTreeSet::new();
        for row in &snapshot.current_state_entries {
            let TypedCurrentRow::Value {
                selector,
                source_stream_ref,
                revision,
                value,
            } = row;
            match selector {
                CurrentSelector::SidecarContext {
                    sidecar_id: candidate,
                    source_context_ref,
                } if candidate == sidecar_id => {
                    attached.insert(arkret_sdk::canonical::canonical_json_string(
                        source_context_ref,
                    )?);
                }
                CurrentSelector::AgentSidecarExchangeControls {
                    sidecar_id: candidate,
                    source_context_ref,
                } if candidate == sidecar_id => {
                    let current: AgentSidecarExchangeControlsCurrentValue =
                        serde_json::from_value(value.clone())?;
                    current.validate_for_context(sidecar_id, source_context_ref)?;
                    anyhow::ensure!(
                        !current.assertions().is_empty()
                            && *source_stream_ref
                                == arkret_sdk::CommitStreamRef::from_scope(
                                    &scope,
                                    Some(sidecar.realm_id.clone())
                                )?,
                        "Sidecar controls current has an invalid source or empty set"
                    );
                    let latest = current
                        .assertions()
                        .iter()
                        .filter_map(|assertion| {
                            history
                                .iter()
                                .find(|full| full.event.event_id == *assertion.tag_id.event_id())
                        })
                        .max_by_key(|full| full.commit.stream_position)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Sidecar control current has no verified covering Event"
                            )
                        })?;
                    anyhow::ensure!(
                        latest.commit.commit_id == revision.commit_id
                            && latest.commit.stream_position == revision.stream_position,
                        "Sidecar control current differs from its verified covering Commit"
                    );
                    for assertion in current.assertions() {
                        anyhow::ensure!(
                            controls
                                .insert(
                                    assertion.tag_id.event_id().clone(),
                                    assertion.value.clone()
                                )
                                .is_none(),
                            "Sidecar controls current repeats an Event across contexts"
                        );
                    }
                }
                _ => {}
            }
        }
        let mut exchanges = BTreeMap::<String, Exchange>::new();
        let mut accepted_contexts = BTreeSet::new();
        for full in history {
            let event = &full.event;
            if event.kind == EventKind::SidecarCreate {
                continue;
            }
            anyhow::ensure!(
                event.scope_ref == scope,
                "Sidecar verified history crosses its native scope"
            );
            if event.kind == EventKind::SidecarContextAttach {
                let payload: arkret_sdk::SidecarContextAttachPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                payload.validate()?;
                anyhow::ensure!(
                    payload.sidecar_id == *sidecar_id
                        && event.actor_id.as_account_id() == Some(controller),
                    "Sidecar attached context differs from its controller and native identity"
                );
                accepted_contexts.insert(arkret_sdk::canonical::canonical_json_string(
                    &payload.source_context_ref,
                )?);
            }
            if event.kind == EventKind::MessageCreate {
                let Some(encrypted) = event.payload.get("encrypted_metadata") else {
                    continue;
                };
                let envelope: EncryptedEnvelope = serde_json::from_value(encrypted.clone())?;
                let metadata: MessageMetadata = serde_json::from_slice(&decrypt(
                    store,
                    controller,
                    event,
                    &envelope,
                    &mut validation,
                )?)?;
                let Some(binding) = crate::sidecar::sidecar_exchange_binding(&metadata) else {
                    continue;
                };
                if event.executed_by.is_some() || event.applet_id.is_some() {
                    continue;
                }
                match binding.role {
                    AgentSidecarExchangeRole::Request => {
                        if event.actor_id.as_account_id() != Some(controller) {
                            continue;
                        }
                        let context = binding
                            .request_context
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("Sidecar request has no context"))?;
                        let source = SidecarContextRef::Strand {
                            strand_id: context.source_track_ref.strand_id.clone(),
                        };
                        if context.source_track_ref.realm_id != sidecar.realm_id
                            || context.source_track_ref.track_name.is_empty()
                            || context.addressed_agent_ids.is_empty()
                            || !attached
                                .contains(&arkret_sdk::canonical::canonical_json_string(&source)?)
                            || !accepted_contexts
                                .contains(&arkret_sdk::canonical::canonical_json_string(&source)?)
                            || event
                                .payload
                                .get("strand_id")
                                .and_then(serde_json::Value::as_str)
                                != Some(context.source_track_ref.strand_id.as_str())
                        {
                            continue;
                        }
                        let Some(coordinator) = context
                            .coordinator_agent_id
                            .as_ref()
                            .or_else(|| {
                                (context.addressed_agent_ids.len() == 1)
                                    .then(|| &context.addressed_agent_ids[0])
                            })
                            .filter(|coordinator| {
                                context.addressed_agent_ids.contains(coordinator)
                            })
                        else {
                            continue;
                        };
                        if !eligible_agents(
                            store,
                            controller,
                            event,
                            &envelope,
                            &context.addressed_agent_ids,
                            &mut validation,
                        )? {
                            continue;
                        }
                        anyhow::ensure!(
                            !exchanges.contains_key(&binding.exchange_id),
                            "Sidecar exchange identity has conflicting accepted requests"
                        );
                        let projection = AgentSidecarExchangeProjection {
                            schema: arkret_sdk::SchemaId::AGENT_SIDECAR_EXCHANGE_PROJECTION_V1
                                .to_owned(),
                            controller_account_id: controller.clone(),
                            sidecar_id: sidecar_id.clone(),
                            exchange_id: binding.exchange_id.clone(),
                            source_track_ref: context.source_track_ref.clone(),
                            source_event_id: context.source_checkpoint_anchor_id.clone(),
                            source_hlc: context.source_hlc.clone(),
                            client_order_key: context.client_order_key.clone(),
                            addressed_agent_ids: context.addressed_agent_ids.clone(),
                            coordinator_agent_id: coordinator.clone(),
                            coordinator_assignment_event_id: event.event_id.clone(),
                            participating_agent_ids: Vec::new(),
                            private_request_event_id: event.event_id.clone(),
                            user_facing_response_event_ids: Vec::new(),
                            status: AgentSidecarExchangeStatus::Delivered,
                            failure_reason_code: None,
                            terminal_event_id: None,
                            folded_checkpoint: AgentSidecarFoldedCheckpoint {
                                event_ids: Vec::new(),
                                event_set_digest: Hash::new(
                                    arkret_sdk::canonical::canonical_sha256(&Vec::<EventId>::new())?,
                                )?,
                                max_hlc: context.source_hlc.clone(),
                            },
                        };
                        let mut exchange = Exchange {
                            projection,
                            parents: BTreeMap::new(),
                            completion_requested: false,
                        };
                        exchange.contribute(event, BTreeSet::new())?;
                        exchanges.insert(binding.exchange_id.clone(), exchange);
                    }
                    AgentSidecarExchangeRole::UserFacingResponse
                    | AgentSidecarExchangeRole::Internal => {
                        let Some(exchange) = exchanges.get_mut(&binding.exchange_id) else {
                            continue;
                        };
                        accept_response(exchange, event, &binding)?;
                    }
                }
            } else if event.kind == EventKind::AgentSidecarExchangeControl {
                let payload: AgentSidecarExchangeControlPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                anyhow::ensure!(
                    controls.remove(&event.event_id).as_ref() == Some(&payload)
                        && payload.sidecar_id == *sidecar_id
                        && event.actor_id.as_account_id() == Some(controller)
                        && event.executed_by.is_none()
                        && event.applet_id.is_none(),
                    "Sidecar control differs from its exact current assertion or controller"
                );
                let control: AgentSidecarExchangeControl = serde_json::from_slice(&decrypt(
                    store,
                    controller,
                    event,
                    &payload.encrypted_payload,
                    &mut validation,
                )?)?;
                control.validate_shape()?;
                if let Some(coordinator) = &control.coordinator_agent_id {
                    anyhow::ensure!(
                        eligible_agents(
                            store,
                            controller,
                            event,
                            &payload.encrypted_payload,
                            std::slice::from_ref(coordinator),
                            &mut validation,
                        )?,
                        "Sidecar reassignment names no eligible Agent at its accepted MLS cut"
                    );
                }
                let exchange = exchanges.get_mut(&control.exchange_id).ok_or_else(|| {
                    anyhow::anyhow!("Sidecar control names no authenticated request")
                })?;
                anyhow::ensure!(
                    payload.source_context_ref
                        == SidecarContextRef::Strand {
                            strand_id: exchange.projection.source_track_ref.strand_id.clone()
                        },
                    "Sidecar control source context differs from its request"
                );
                accept_control(exchange, event, &control)?;
            }
        }
        anyhow::ensure!(
            controls.is_empty(),
            "Sidecar current includes controls outside its complete verified history"
        );
        for exchange in exchanges.into_values() {
            exchange.projection.validate_shape()?;
            if exchange.completion_requested
                && exchange.projection.status == AgentSidecarExchangeStatus::Responding
            {
                closes.push((
                    exchange.projection.clone(),
                    AgentSidecarExchangeControl {
                        schema: arkret_sdk::SchemaId::AGENT_SIDECAR_EXCHANGE_CONTROL_V1.to_owned(),
                        exchange_id: exchange.projection.exchange_id.clone(),
                        request_event_id: exchange.projection.private_request_event_id.clone(),
                        basis_event_ids: exchange.heads(),
                        action: AgentSidecarExchangeAction::Close,
                        response_event_ids: Some(
                            exchange.projection.user_facing_response_event_ids.clone(),
                        ),
                        failure_reason_code: None,
                        expected_coordinator_agent_id: None,
                        coordinator_agent_id: None,
                    },
                ));
            }
            result.push(exchange.projection);
        }
    }
    result.sort_by(|left, right| {
        (&left.sidecar_id, &left.exchange_id).cmp(&(&right.sidecar_id, &right.exchange_id))
    });
    Ok((result, closes))
}

fn accept_response(
    exchange: &mut Exchange,
    event: &Event,
    binding: &AgentSidecarEventExchangeBinding,
) -> anyhow::Result<()> {
    binding.validate_shape()?;
    let projection = &exchange.projection;
    if projection.terminal_event_id.is_some()
        || binding.request_event_id.as_ref() != Some(&projection.private_request_event_id)
    {
        return Ok(());
    }
    let Some(actor) = event.actor_id.as_account_id() else {
        return Ok(());
    };
    if actor.station_id != projection.controller_account_id.station_id
        || !projection.addressed_agent_ids.contains(&actor.principal_id)
    {
        return Ok(());
    }
    let parents = after_parents(event, exchange);
    let closure = exchange.closure(&parents);
    if !closure.contains(&projection.private_request_event_id) {
        return Ok(());
    }
    if binding.completes_exchange == Some(true)
        && (actor.principal_id != projection.coordinator_agent_id
            || binding.coordinator_assignment_event_id.as_ref()
                != Some(&projection.coordinator_assignment_event_id)
            || !closure.contains(&projection.coordinator_assignment_event_id))
    {
        return Ok(());
    }
    if binding.role == AgentSidecarExchangeRole::UserFacingResponse {
        exchange.completion_requested |= binding.completes_exchange == Some(true);
        exchange
            .projection
            .user_facing_response_event_ids
            .push(event.event_id.clone());
        exchange.projection.user_facing_response_event_ids.sort();
        exchange.projection.status = AgentSidecarExchangeStatus::Responding;
    }
    if !exchange
        .projection
        .participating_agent_ids
        .contains(&actor.principal_id)
    {
        exchange
            .projection
            .participating_agent_ids
            .push(actor.principal_id.clone());
        exchange.projection.participating_agent_ids.sort();
    }
    exchange.contribute(event, parents)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "sidecar_fold/tests_mls.rs"]
mod mls_tests;

fn accept_control(
    exchange: &mut Exchange,
    event: &Event,
    control: &AgentSidecarExchangeControl,
) -> anyhow::Result<()> {
    control.validate_shape()?;
    anyhow::ensure!(
        control.exchange_id == exchange.projection.exchange_id
            && control.request_event_id == exchange.projection.private_request_event_id
            && !control.basis_event_ids.is_empty()
            && sorted_unique(&control.basis_event_ids)
            && exchange.projection.terminal_event_id.is_none(),
        "Sidecar control has an invalid request, basis or terminal transition"
    );
    let basis = control
        .basis_event_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        basis.iter().all(|id| exchange.parents.contains_key(id)
            && event
                .semantic_refs
                .iter()
                .any(|reference| reference.role == "after"
                    && reference.critical
                    && reference.id == id.as_str())),
        "Sidecar control basis is not covered by accepted causal refs"
    );
    let closure = exchange.closure(&basis);
    anyhow::ensure!(
        closure.contains(&exchange.projection.private_request_event_id)
            && closure.contains(&exchange.projection.coordinator_assignment_event_id)
            && basis.iter().all(
                |id| !basis
                    .iter()
                    .filter(|other| *other != id)
                    .any(|other| exchange
                        .closure(&BTreeSet::from([other.clone()]))
                        .contains(id))
            ),
        "Sidecar control basis does not cover its request and assignment as maximal heads"
    );
    match control.action {
        AgentSidecarExchangeAction::ReassignCoordinator => {
            let coordinator = control
                .coordinator_agent_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Sidecar reassignment has no coordinator"))?;
            anyhow::ensure!(
                control.expected_coordinator_agent_id.as_ref()
                    == Some(&exchange.projection.coordinator_agent_id)
                    && exchange
                        .projection
                        .addressed_agent_ids
                        .contains(coordinator),
                "Sidecar coordinator reassignment does not extend its exact assignment"
            );
            exchange.projection.coordinator_agent_id = coordinator.clone();
            exchange.projection.coordinator_assignment_event_id = event.event_id.clone();
            exchange.completion_requested = false;
        }
        AgentSidecarExchangeAction::Close
        | AgentSidecarExchangeAction::Cancel
        | AgentSidecarExchangeAction::Fail => {
            let responses = exchange
                .projection
                .user_facing_response_event_ids
                .iter()
                .filter(|id| closure.contains(*id))
                .cloned()
                .collect::<Vec<_>>();
            anyhow::ensure!(
                control.response_event_ids.as_ref() == Some(&responses),
                "Sidecar terminal control does not carry its exact causal response set"
            );
            anyhow::ensure!(
                control.action == AgentSidecarExchangeAction::Close || responses.is_empty(),
                "Sidecar fail/cancel cannot retain user-facing responses"
            );
            exchange.projection.user_facing_response_event_ids = responses;
            if exchange
                .projection
                .user_facing_response_event_ids
                .is_empty()
            {
                exchange.projection.status = AgentSidecarExchangeStatus::Failed;
                exchange.projection.failure_reason_code = Some(match control.action {
                    AgentSidecarExchangeAction::Close => {
                        arkret_sdk::SIDECAR_EXCHANGE_CLOSED_EMPTY_REASON.to_owned()
                    }
                    AgentSidecarExchangeAction::Cancel => {
                        arkret_sdk::SIDECAR_EXCHANGE_CANCELLED_REASON.to_owned()
                    }
                    AgentSidecarExchangeAction::Fail => control
                        .failure_reason_code
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("Sidecar failure has no reason"))?,
                    _ => unreachable!(),
                });
            } else {
                exchange.projection.status = AgentSidecarExchangeStatus::Complete;
            }
            exchange.projection.terminal_event_id = Some(event.event_id.clone());
        }
    }
    exchange.contribute(event, basis)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> EventId {
        EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [byte; 32])
    }

    // These fixtures isolate causal reduction. The production entry point
    // obtains its Events exclusively from VerifiedScanPage and authenticated MLS.
    fn event(byte: u8, actor: arkret_sdk::ActorId, parents: &[EventId]) -> Event {
        let realm = arkret_sdk::RealmId::from_event_id(&id(8));
        Event {
            event_id: id(byte),
            kind: EventKind::MessageCreate,
            realm_id: realm.clone(),
            scope_ref: ScopeRef::Sidecar {
                realm_id: realm,
                sidecar_id: arkret_sdk::SidecarId::from_event_id(&id(9)),
            },
            actor_id: actor,
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            semantic_refs: parents
                .iter()
                .map(|id| arkret_sdk::SemanticRef::new(id.to_string(), "after"))
                .collect(),
            payload: BTreeMap::new(),
            producer_proof: None,
        }
    }

    fn exchange() -> Exchange {
        let actor = crate::test_support::account_actor("did:web:controller.example");
        let controller = actor.as_account_id().unwrap();
        let mut exchange = Exchange {
            projection:serde_json::from_value(serde_json::json!({
                "schema":"ak.schema.agent_sidecar_exchange_projection.v1","controller_account_id":controller,
                "sidecar_id":arkret_sdk::SidecarId::from_event_id(&id(9)),"exchange_id":"fold-exchange-0000000001",
                "source_track_ref":{"realm_id":arkret_sdk::RealmId::from_event_id(&id(8)),"strand_id":arkret_sdk::StrandId::from_event_id(&id(10)),"track_name":"discussion"},
                "source_hlc":"0198ff000000-0001-0a0b0c0d","client_order_key":"order-1",
                "addressed_agent_ids":["ak:did_core:web:agent.example"],"coordinator_agent_id":"ak:did_core:web:agent.example",
                "coordinator_assignment_event_id":id(1),"participating_agent_ids":[],"private_request_event_id":id(1),
                "user_facing_response_event_ids":[],"status":"delivered",
                "folded_checkpoint":{"event_ids":[id(1)],"event_set_digest":format!("sha256:{}","0".repeat(64)),"max_hlc":"0198ff000000-0001-0a0b0c0d"}
            })).unwrap(), parents:BTreeMap::new(), completion_requested:false,
        };
        exchange
            .contribute(&event(1, actor, &[]), BTreeSet::new())
            .unwrap();
        exchange
    }

    fn binding(role: AgentSidecarExchangeRole) -> AgentSidecarEventExchangeBinding {
        AgentSidecarEventExchangeBinding {
            schema: arkret_sdk::SchemaId::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1.to_owned(),
            exchange_id: "fold-exchange-0000000001".to_owned(),
            role,
            request_event_id: Some(id(1)),
            completes_exchange: None,
            coordinator_assignment_event_id: None,
            request_context: None,
        }
    }

    fn close(exchange: &Exchange) -> AgentSidecarExchangeControl {
        AgentSidecarExchangeControl {
            schema: arkret_sdk::SchemaId::AGENT_SIDECAR_EXCHANGE_CONTROL_V1.to_owned(),
            exchange_id: exchange.projection.exchange_id.clone(),
            request_event_id: id(1),
            basis_event_ids: exchange.heads(),
            action: AgentSidecarExchangeAction::Close,
            response_event_ids: Some(exchange.projection.user_facing_response_event_ids.clone()),
            failure_reason_code: None,
            expected_coordinator_agent_id: None,
            coordinator_agent_id: None,
        }
    }

    #[test]
    fn response_completion_waits_for_a_durable_controller_close() {
        let mut exchange = exchange();
        let actor = crate::test_support::account_actor("did:web:agent.example");
        let mut response = binding(AgentSidecarExchangeRole::UserFacingResponse);
        response.completes_exchange = Some(true);
        response.coordinator_assignment_event_id = Some(id(1));
        accept_response(&mut exchange, &event(2, actor, &[id(1)]), &response).unwrap();
        assert_eq!(
            exchange.projection.status,
            AgentSidecarExchangeStatus::Responding
        );
        assert!(exchange.projection.terminal_event_id.is_none());
        assert!(exchange.completion_requested);
        let control = close(&exchange);
        let controller = crate::test_support::account_actor("did:web:controller.example");
        accept_control(
            &mut exchange,
            &event(3, controller, &control.basis_event_ids),
            &control,
        )
        .unwrap();
        assert_eq!(
            exchange.projection.status,
            AgentSidecarExchangeStatus::Complete
        );
        assert_eq!(exchange.projection.folded_checkpoint.event_ids, vec![id(3)]);
        let mut contributing = vec![id(1), id(2), id(3)];
        contributing.sort();
        assert_eq!(
            exchange
                .projection
                .folded_checkpoint
                .event_set_digest
                .as_str(),
            arkret_sdk::canonical::canonical_sha256(&contributing).unwrap()
        );
        exchange.projection.validate_shape().unwrap();
    }

    #[test]
    fn internal_and_uncovered_response_never_become_user_facing_echoes() {
        let mut exchange = exchange();
        let actor = crate::test_support::account_actor("did:web:agent.example");
        accept_response(
            &mut exchange,
            &event(2, actor.clone(), &[]),
            &binding(AgentSidecarExchangeRole::UserFacingResponse),
        )
        .unwrap();
        assert_eq!(exchange.parents.len(), 1);
        accept_response(
            &mut exchange,
            &event(3, actor, &[id(1)]),
            &binding(AgentSidecarExchangeRole::Internal),
        )
        .unwrap();
        assert!(
            exchange
                .projection
                .user_facing_response_event_ids
                .is_empty()
        );
        assert_eq!(
            exchange.projection.status,
            AgentSidecarExchangeStatus::Delivered
        );
        let control = close(&exchange);
        let controller = crate::test_support::account_actor("did:web:controller.example");
        accept_control(
            &mut exchange,
            &event(4, controller, &control.basis_event_ids),
            &control,
        )
        .unwrap();
        assert_eq!(
            exchange.projection.status,
            AgentSidecarExchangeStatus::Failed
        );
        assert_eq!(
            exchange.projection.failure_reason_code.as_deref(),
            Some(arkret_sdk::SIDECAR_EXCHANGE_CLOSED_EMPTY_REASON)
        );
    }

    #[test]
    fn invalid_basis_and_stale_assignment_have_no_projection_effect() {
        let mut exchange = exchange();
        let mut control = close(&exchange);
        control.basis_event_ids = vec![id(7)];
        let before = exchange.projection.clone();
        assert!(
            accept_control(
                &mut exchange,
                &event(
                    4,
                    crate::test_support::account_actor("did:web:controller.example"),
                    &control.basis_event_ids
                ),
                &control
            )
            .is_err()
        );
        assert_eq!(exchange.projection, before);
        let mut response = binding(AgentSidecarExchangeRole::UserFacingResponse);
        response.completes_exchange = Some(true);
        response.coordinator_assignment_event_id = Some(id(7));
        accept_response(
            &mut exchange,
            &event(
                2,
                crate::test_support::account_actor("did:web:agent.example"),
                &[id(1)],
            ),
            &response,
        )
        .unwrap();
        assert_eq!(exchange.projection, before);
    }
}
