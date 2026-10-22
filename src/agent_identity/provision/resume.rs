//! Resume the same durable units through the normal authenticated APIs.

use arkret_sdk::{AgentProvisionOutcome, AgentProvisionRequestBody};

use super::*;
use crate::transport::auth::{
    AuthoringSessionFence, with_authed_api, with_authed_sdk_client, with_event_submitter,
};

fn ceremony_gate(authority: &AccountId) -> anyhow::Result<std::sync::Arc<tokio::sync::Mutex<()>>> {
    type Gates = std::collections::BTreeMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>;
    static GATES: std::sync::OnceLock<std::sync::Mutex<Gates>> = std::sync::OnceLock::new();
    let key = crate::secure_key_store::account_id_storage_digest(authority)?;
    let mut gates = GATES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| anyhow::anyhow!("Agent ceremony gate lock poisoned"))?;
    gates.retain(|_, gate| gate.strong_count() > 0);
    if let Some(gate) = gates.get(&key).and_then(std::sync::Weak::upgrade) {
        return Ok(gate);
    }
    let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    gates.insert(key, std::sync::Arc::downgrade(&gate));
    Ok(gate)
}

fn check_holder(record: &ProvisionCeremony, fence: &AuthoringSessionFence) -> anyhow::Result<()> {
    fence.check()?;
    let scope = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("Agent recovery needs its original device authority"))?;
    anyhow::ensure!(
        scope.authority == record.authority && scope.device_id == record.device_id,
        "Agent recovery belongs to another complete Account or device"
    );
    record.validate()
}

async fn publish_binding(
    record: &ProvisionCeremony,
    credential: &str,
    fence: &AuthoringSessionFence,
) -> anyhow::Result<()> {
    check_holder(record, fence)?;
    let body = record
        .binding_operation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("original Agent DID binding is not frozen"))?
        .clone();
    let owned = record.clone();
    let check = fence.clone();
    let binding = with_authed_sdk_client(
        &record.principal_endpoint,
        credential.to_owned(),
        move |http| async move {
            check_holder(&owned, &check)?;
            crate::transport::account::submit_did_operation(&http, &body).await
        },
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))?;
    check_holder(record, fence)?;
    anyhow::ensure!(
        binding.did.as_str() == record.inception.did
            && binding.status != arkret_sdk::DidOperationSubmitStatus::Pending,
        "original Agent DID binding is not accepted yet"
    );
    Ok(())
}

async fn commit(
    record: &ProvisionCeremony,
    credential: &str,
    fence: &AuthoringSessionFence,
) -> anyhow::Result<AgentProvisionOutcome> {
    check_holder(record, fence)?;
    let body = AgentProvisionRequestBody::Commit(
        record
            .authored
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Agent ceremony has no frozen commit"))?
            .commit
            .clone(),
    );
    let owned = record.clone();
    let check = fence.clone();
    let outcome = with_authed_sdk_client(
        &record.principal_endpoint,
        credential.to_owned(),
        move |http| async move {
            check_holder(&owned, &check)?;
            let actor = arkret_sdk::ActorId::account(owned.authority.clone());
            let producer = check.signer.publication_context(&actor)?;
            let verified = arkret_sdk::VerifiedSubmission::verify(body, |_| Ok(producer.clone()))?;
            Ok(http.agent_provision(&verified).await?)
        },
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))?;
    check_holder(record, fence)?;
    let prepared = record
        .preparation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Agent ceremony has no frozen preparation"))?;
    let authored = record
        .authored
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Agent ceremony has no frozen commit"))?;
    let matches = match &outcome {
        AgentProvisionOutcome::AwaitingPcrGenesis(value) => {
            value.agent_id == prepared.agent_id
                && value.did == prepared.did
                && value.initial_resolution == prepared.initial_resolution
                && value.allocation_handle == prepared.allocation_handle
                && value.controller_authorization_ref == prepared.controller_authorization_ref
                && value.principal_control_realm_id == authored.commit.principal_control_realm_id
        }
        AgentProvisionOutcome::AwaitingDidBinding(value) => {
            value.agent_id == prepared.agent_id
                && value.did == prepared.did
                && value.initial_resolution == prepared.initial_resolution
                && value.allocation_handle == prepared.allocation_handle
                && value.controller_authorization_ref == prepared.controller_authorization_ref
                && value.principal_control_realm_id == authored.commit.principal_control_realm_id
        }
        AgentProvisionOutcome::Complete(value) => {
            value.agent_id == prepared.agent_id
                && value.did == prepared.did
                && value.initial_resolution == prepared.initial_resolution
                && value.controller_authorization_ref == prepared.controller_authorization_ref
                && value.principal_control_realm_id == authored.commit.principal_control_realm_id
        }
        AgentProvisionOutcome::AwaitingControllerEvent(_) => false,
    };
    anyhow::ensure!(
        matches,
        "Agent recovery outcome differs from its original frozen coordinates"
    );
    Ok(outcome)
}

pub(crate) async fn resume_ceremony(
    mut record: ProvisionCeremony,
    evidence: crate::state::RecoveryMaterialEvidence,
    credential: String,
) -> anyhow::Result<AgentProvisionComplete> {
    let gate = ceremony_gate(&record.authority)?;
    let _serial = gate.lock().await;
    let vault = crate::outbound_store::InksonOutboundStore::open(
        &record.authority,
        crate::outbound_store::OutboundLane::Standard,
    )?;
    record = vault
        .agent_provision_record(&record.authority, &record.operation_id)
        .await?;
    let fence = AuthoringSessionFence::capture()?;
    check_holder(&record, &fence)?;
    anyhow::ensure!(
        evidence.account_id == record.authority
            && evidence.device_id == record.device_id
            && evidence.principal_did == record.controller_did
            && evidence.controller_authority.as_ref() == Some(&record.authority),
        "Agent recovery lacks the original complete controller evidence"
    );
    let base = record.principal_endpoint.clone();
    if record.preparation.is_none() {
        let store = crate::secure_key_store::default_secure_key_store("inkson");
        super::super::store_keys_durable(store.as_ref(), &record.inception.did, &record.keys)
            .await?;
        check_holder(&record, &fence)?;
        let body = record.inception.submit_body.clone();
        let owned = record.clone();
        let check = fence.clone();
        let outcome = with_authed_sdk_client(&base, credential.clone(), move |http| async move {
            check_holder(&owned, &check)?;
            crate::transport::account::submit_did_operation(&http, &body).await
        })
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;
        check_holder(&record, &fence)?;
        anyhow::ensure!(
            outcome.did.as_str() == record.inception.did
                && outcome.status != arkret_sdk::DidOperationSubmitStatus::Pending,
            "original Agent inception is not accepted yet"
        );
        let prepare =
            AgentProvisionRequestBody::Prepare(arkret_sdk::AgentProvisionPrepareRequestBody {
                phase: arkret_sdk::AgentProvisionPreparePhase::Prepare,
                operation_id: record.operation_id.clone(),
                idempotency_key: record.idempotency_key.clone(),
                did: Did::new(record.inception.did.clone())?,
                slug: record.slug.clone(),
                requested_scope: record.requested_scope.clone(),
                pairing_ttl_ms: None,
                controller_station_id: record.authority.station_id.clone(),
            });
        let owned = record.clone();
        let check = fence.clone();
        let preparation =
            with_authed_sdk_client(&base, credential.clone(), move |http| async move {
                check_holder(&owned, &check)?;
                Ok(http
                    .agent_provision(&arkret_sdk::VerifiedSubmission::from_verified_events(
                        prepare,
                        &[],
                    )?)
                    .await?)
            })
            .await
            .map_err(|error| anyhow::anyhow!(error.display()))?;
        check_holder(&record, &fence)?;
        let AgentProvisionOutcome::AwaitingControllerEvent(preparation) = preparation else {
            anyhow::bail!("unfrozen provision returned an already committed allocation")
        };
        let mut next = record.clone();
        next.preparation = Some(preparation);
        record = vault.advance_agent_provision(&record, next).await?;
    }
    if record.authored.is_none() {
        let prepared = record
            .preparation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Agent ceremony has no frozen preparation"))?
            .clone();
        anyhow::ensure!(
            prepared.controller_realm_id == evidence.principal_control_realm_id,
            "Agent allocation changed the original controller PCR"
        );
        let verified = evidence.clone();
        let owned = record.clone();
        let check = fence.clone();
        with_authed_api(&base, credential.clone(), move |api| async move {
            check_holder(&owned, &check)?;
            crate::recovery_flow::verify_recovery_authority_evidence(&api, &verified).await
        })
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;
        check_holder(&record, &fence)?;
        let owned = record.clone();
        let allocation = prepared.clone();
        let check = fence.clone();
        let genesis =
            with_event_submitter(&base, credential.clone(), move |submitter| async move {
                check_holder(&owned, &check)?;
                let describe = submitter.service_describe().await?;
                check_holder(&owned, &check)?;
                let draft = crate::event_builders::build_agent_pcr_create_event(
                    allocation.agent_id.as_str(),
                    allocation.initial_resolution,
                    owned.authority.station_id.clone(),
                    owned.authority.principal_id.as_str(),
                    allocation.controller_authorization_ref.as_str(),
                    describe.trust_domain.as_str(),
                )?;
                let intent = draft.into_intent();
                submitter
                    .author_event_unit(vec![Box::new(move |_| Ok(vec![intent]))])
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("frozen Agent genesis is missing"))
            })
            .await
            .map_err(|error| anyhow::anyhow!(error.display()))?;
        check_holder(&record, &fence)?;
        let digest = arkret_signatures::agent::agent_requested_scope_digest(
            &prepared.agent_id,
            &record.authority.principal_id,
            &record.requested_scope,
        )?;
        let draft = arkret_bootstrap::build_agent_provision_intent(
            &record.authority.principal_id,
            &prepared.controller_realm_id,
            &prepared.agent_id,
            &genesis.realm_id,
            &prepared.controller_authorization_ref,
            &record.slug,
            &digest,
            arkret_models_identity::handle::HandleVisibility::Private,
            None,
            arkret_bootstrap::AgentProvisionIntentOptions {
                controller_station_id: record.authority.station_id.clone(),
                created_at: crate::clock::now_utc(),
            },
        )?;
        let intent = arkret_event_draft::EventIntent::from_authored(&draft);
        let controller_create = evidence.pcr_genesis_unit.create().clone();
        let owned = record.clone();
        let check = fence.clone();
        let provision =
            with_event_submitter(&base, credential.clone(), move |submitter| async move {
                check_holder(&owned, &check)?;
                let events = submitter.author_independent_events(vec![intent]).await?;
                check_holder(&owned, &check)?;
                submitter.prepare_authority_authored_self_principal_submission(
                    events
                        .first()
                        .ok_or_else(|| anyhow::anyhow!("frozen provision is missing"))?,
                    &controller_create,
                )
            })
            .await
            .map_err(|error| anyhow::anyhow!(error.display()))?;
        check_holder(&record, &fence)?;
        let mut next = record.clone();
        next.authored = Some(AuthoredProvision {
            commit: AgentProvisionCommitRequestBody {
                phase: arkret_sdk::AgentProvisionCommitPhase::Commit,
                operation_id: record.operation_id.clone(),
                idempotency_key: record.idempotency_key.clone(),
                agent_id: prepared.agent_id.clone(),
                did: prepared.did.clone(),
                principal_control_realm_id: genesis.realm_id.clone(),
                slug: record.slug.clone(),
                requested_scope: record.requested_scope.clone(),
                allocation_handle: prepared.allocation_handle.clone(),
                provision_event: provision,
                pairing_ttl_ms: None,
            },
            genesis,
        });
        record = vault.advance_agent_provision(&record, next).await?;
    }
    // A lost accepted DID response still owes its exact operation replay.
    // Replay it before a complete commit outcome can close the local journal.
    if record.binding_operation.is_some() && record.outcome.is_none() {
        publish_binding(&record, &credential, &fence).await?;
    }
    let mut outcome = commit(&record, &credential, &fence).await?;
    if matches!(outcome, AgentProvisionOutcome::AwaitingPcrGenesis(_)) {
        let genesis = record
            .authored
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Agent ceremony has no frozen commit"))?
            .genesis
            .clone();
        let owned = record.clone();
        let check = fence.clone();
        with_event_submitter(&base, credential.clone(), move |submitter| async move {
            check_holder(&owned, &check)?;
            submitter
                .submit_signed_sdk_events_in_order(std::slice::from_ref(&genesis))
                .await
                .map(|_| ())
        })
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;
        outcome = commit(&record, &credential, &fence).await?;
    }
    if matches!(outcome, AgentProvisionOutcome::AwaitingDidBinding(_)) {
        if record.binding_operation.is_none() {
            check_holder(&record, &fence)?;
            let authored = record
                .authored
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Agent ceremony has no frozen commit"))?;
            let digest = arkret_signatures::agent::agent_requested_scope_digest(
                &authored.commit.agent_id,
                &record.authority.principal_id,
                &record.requested_scope,
            )?;
            let binding = super::super::prepare_binding_update(
                &record.inception,
                &record.keys,
                &record.authority.principal_id,
                &authored.commit.principal_control_realm_id,
                &digest,
            )?;
            let mut next = record.clone();
            next.binding_operation = Some(binding.submit_body);
            record = vault.advance_agent_provision(&record, next).await?;
        }
        publish_binding(&record, &credential, &fence).await?;
        outcome = commit(&record, &credential, &fence).await?;
    }
    let AgentProvisionOutcome::Complete(outcome) = outcome else {
        anyhow::bail!("Agent ceremony remains pending at its current authority stage")
    };
    check_holder(&record, &fence)?;
    let mut next = record.clone();
    next.outcome = Some(outcome.clone());
    vault.advance_agent_provision(&record, next).await?;
    Ok(outcome)
}
