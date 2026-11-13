//! Exact history exchanges through accepted own-Station Events. Public leaf
//! selection, native authorization and secret custody remain separate gates.

mod pending;
mod selected;
use arkret_event_draft::{EventContentEnvelopesExt as _, EventPayloadExt as _};
use arkret_models_crypto::{HistoryGrant, HistoryGrantEntry, HistoryKeySelector, HistoryRequest};
use arkret_sdk::http_client::own_station_results::OwnStationStateClient;
use arkret_sdk::{
    ActorId, CommittedEventFullView, CommittedEventRef, Event, EventKind, RealmId, ScopeRef,
};
use garth::mls::content_history::{HistoryExchangeVault, PendingHistoryRequest};
pub(crate) use selected::read_attachment_key;

use crate::runtime::input::StateStoreHandle;

fn reference(full: &CommittedEventFullView) -> CommittedEventRef {
    CommittedEventRef {
        event_id: full.event.event_id.clone(),
        commit_id: full.commit.commit_id.clone(),
        stream_ref: full.commit.stream_ref.clone(),
        stream_position: full.commit.stream_position,
    }
}

fn require_reader(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
) -> anyhow::Result<crate::secure_key_store::ActiveDeviceSeedScope> {
    let active = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("history reader has no active Device"))?;
    anyhow::ensure!(
        source.session()?.account_id() == &active.authority
            && state.read(
                |store| store.active_authority().as_ref() == Some(&active.authority)
                    && !store.current_reset_required()
            ),
        "history reader session changed"
    );
    Ok(active)
}

async fn current_endpoint(
    source: &OwnStationStateClient,
    endpoint: &arkret_models_crypto::ContentEndpoint,
) -> anyhow::Result<
    arkret_models_collaboration::events_payloads::key_backup::ControllerBackupTrustAnchor,
> {
    source.check_session()?;
    let account = endpoint
        .actor_id
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("history Device requires complete Account"))?;
    let arkret_sdk::MlsWelcomeRecipientEndpoint::Device { device_id } = &endpoint.endpoint else {
        anyhow::bail!("history Device native source unavailable");
    };
    let outcome =
        crate::transport::keys::query_keys(&source.http_client()?, account, device_id.as_str())
            .await?;
    let current = arkret_models_collaboration::events_payloads::key_backup::resolve_controller_backup_trust_anchor(&outcome, account, device_id)?;
    anyhow::ensure!(
        current.authorize_event_id == endpoint.authorization_event_ref,
        "history endpoint native authorization is no longer current"
    );
    source.check_session()?;
    Ok(current)
}

pub(crate) async fn context_for(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    scope: &ScopeRef,
    epoch: u64,
    group_state: &arkret_sdk::EventId,
) -> anyhow::Result<arkret_models_crypto::ContentRootContext> {
    require_reader(source, state)?;
    let current = crate::mls::send_gate::read_durable_mls_current(
        &crate::mls::send_gate::MlsSendGateInput::capture(state, scope),
        scope,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("history has no accepted MLS group"))?;
    anyhow::ensure!(epoch <= current.epoch, "history epoch exceeds current");
    crate::mls::content_roots::resolve_public_root_context(
        source,
        scope,
        &current.genesis_event_ref,
        epoch,
        group_state,
        current.cipher_suite.as_str(),
    )
    .await
}

async fn publish(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    event: &Event,
) -> anyhow::Result<()> {
    let active = require_reader(source, state)?;
    anyhow::ensure!(
        event.actor_id == ActorId::account(active.authority.clone()),
        "history publisher differs"
    );
    let authored = arkret_sdk::AuthoredEvent::from_verified_with_digest_suite(
        event.clone(),
        event.realm_id.digest_suite_code().digest_suite(),
    )?;
    crate::event_submit::EventSubmitter::new(source.http_client()?)
        .with_state_store(state.clone())
        .with_authority(active.authority)
        .submit_signed_sdk_events_in_order(&[authored])
        .await?;
    source.check_session()?;
    Ok(())
}

/// Called only after a verified history/current transaction is durable. Each
/// control hint is read again through the live native original boundary.
pub(crate) async fn reconcile(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    realm: &RealmId,
) -> anyhow::Result<()> {
    let active = require_reader(source, state)?;
    let actor = ActorId::account(active.authority.clone());
    let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
        device_id: active.device_id.clone(),
    };
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let vault = HistoryExchangeVault::new(secure.as_ref(), &actor, &endpoint);
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    if let Some(expired) = vault.request(&scope).await?
        && expired.has_private_key()
        && expired.event().as_mls_history_request()?.expires_at <= crate::clock::now_utc()
    {
        vault
            .consume_request(&scope, &expired.event().event_id)
            .await?;
    }
    let (cache, originals) = state.read(|store| {
        (
            store.historical_content_rosters.clone(),
            store.encrypted_originals_for(realm.as_str()),
        )
    });
    let mut missing = false;
    let mut cut = None::<CommittedEventRef>;
    for event in originals.iter().filter(|event| event.scope_ref == scope) {
        let dependency =
            garth::own_station_results::read_window_dependency_by_event_id(source, &event.event_id)
                .await?;
        let full = dependency.full()?;
        anyhow::ensure!(
            full.event == *event,
            "retained history differs from its native original"
        );
        let source_ref = reference(full);
        for path in selected::paths(
            source,
            state,
            &vault,
            &active.authority,
            &active.device_id,
            full,
        )
        .await?
        {
            if selected::held(
                source,
                state,
                &vault,
                &active.authority,
                &active.device_id,
                full,
                &path,
            )
            .await
            .is_err()
            {
                missing = true;
                if cut
                    .as_ref()
                    .is_none_or(|old| old.stream_position < source_ref.stream_position)
                {
                    cut = Some(source_ref.clone());
                }
            }
        }
    }
    if let Some(pending) = vault.request(&scope).await?
        && pending.has_private_key()
        && (!missing
            || pending.event().as_mls_history_request()?.expires_at <= crate::clock::now_utc())
    {
        vault
            .consume_request(&scope, &pending.event().event_id)
            .await?;
    }
    if !missing && cache.controls().is_empty() {
        return Ok(());
    }
    let current = crate::mls::send_gate::read_durable_mls_current(
        &crate::mls::send_gate::MlsSendGateInput::capture(state, &scope),
        &scope,
    )
    .await?;
    let Some(current) = current else {
        return Ok(());
    };
    let context = context_for(
        source,
        state,
        &scope,
        current.epoch,
        &current.current_mls_commit_event_ref,
    )
    .await?;
    let roster = crate::mls::historical_content::read_public_epoch(source, state, &context).await?;
    let recipient = roster
        .content_endpoint_for_device(&actor, &active.device_id)
        .map_err(anyhow::Error::msg)?;
    current_endpoint(source, &recipient).await?;
    if missing && let Some(cut) = cut {
        let old = vault.request(&scope).await?;
        let valid = old.as_ref().is_some_and(|old| {
            old.has_private_key()
                && old.event().as_mls_history_request().is_ok_and(|request| {
                    request.recipient == recipient
                        && request.history_cut.stream_position >= cut.stream_position
                        && request
                            .validate_at(old.event().created_at, crate::clock::now_utc())
                            .is_ok()
                })
        });
        let pending = if valid {
            old.unwrap()
        } else {
            let keys = arkret_crypto::hpke::generate_x25519_keypair()?;
            let payload = HistoryRequest {
                recipient: recipient.clone(),
                recipient_hpke_key_base64url: arkret_sdk::canonical::base64url_encode(
                    keys.public_key(),
                ),
                history_cut: cut,
                expires_at: crate::clock::now_utc_millis() + chrono::Duration::seconds(900),
            };
            let operation = crate::operation::TypedOperationBuilder::new_for_actor::<
                arkret_sdk::event_spec::MlsHistoryRequest,
            >(scope.clone(), actor.clone(), payload)
            .build_sdk_event("inkson")?;
            let authored = crate::event_submit::EventSubmitter::new(source.http_client()?)
                .with_state_store(state.clone())
                .with_authority(active.authority.clone())
                .author_for_direct_submission(&operation)
                .await?;
            vault
                .freeze_request(
                    PendingHistoryRequest::new(authored.event().clone(), keys.private_key())?,
                    crate::clock::now_utc(),
                )
                .await?
        };
        publish(source, state, pending.event()).await?;
    }
    let mut controls = cache.controls();
    controls.sort_by_key(|control| control.stream_position);
    for control in controls.iter().filter(|control| {
        control.stream_ref
            == arkret_sdk::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            }
    }) {
        let dependency = garth::own_station_results::read_window_dependency_by_event_id(
            source,
            &control.event_id,
        )
        .await?;
        let full = dependency.full()?;
        anyhow::ensure!(
            reference(full) == *control,
            "history control original differs"
        );
        match full.event.kind {
            EventKind::MlsHistoryRequest if full.event.actor_id != actor => {
                // This registered preview schedules work only. Atomic native
                // grant admission independently decides disclosure authority.
                let preview = source.http_client()?.authz_check(&arkret_models_collaboration::governance::authorization::AuthorizationCheckRequestBody {
                    actor_id: actor.clone(), action: EventKind::MlsHistoryGrant.as_str().into(),
                    resource: Some(arkret_sdk::WireResourceSelector::realm(realm.clone())), context: None,
                }).await?;
                source.check_session()?;
                if preview.decision != arkret_sdk::AuthorizationDecision::Allow {
                    continue;
                }
                let request = full.event.as_mls_history_request()?;
                if request
                    .validate_at(full.event.created_at, crate::clock::now_utc())
                    .is_err()
                {
                    continue;
                }
                // Public current roster attribution is independent of the
                // backend's current native read and disclosure qualification.
                if let arkret_sdk::MlsWelcomeRecipientEndpoint::Device { device_id } =
                    &request.recipient.endpoint
                {
                    if roster
                        .content_endpoint_for_device(&request.recipient.actor_id, device_id)
                        .ok()
                        .as_ref()
                        != Some(&request.recipient)
                    {
                        continue;
                    }
                } else {
                    continue;
                }
                current_endpoint(source, &request.recipient).await?;
                for event in originals.iter().filter(|event| event.scope_ref == scope) {
                    let original = garth::own_station_results::read_window_dependency_by_event_id(
                        source,
                        &event.event_id,
                    )
                    .await?;
                    let original = original.full()?;
                    if original.commit.stream_position > request.history_cut.stream_position {
                        continue;
                    }
                    let paths = selected::paths(
                        source,
                        state,
                        &vault,
                        &active.authority,
                        &active.device_id,
                        original,
                    )
                    .await?;
                    if paths.is_empty() {
                        continue;
                    }
                    let selectors: Vec<_> = paths
                        .iter()
                        .map(|path| HistoryKeySelector::ContentKey {
                            source_event_ref: event.event_id.clone(),
                            content_path: path.clone(),
                        })
                        .collect();
                    if let Some(frozen) = vault
                        .frozen_grant(&full.event.event_id, &selectors, None)
                        .await?
                    {
                        if !controls
                            .iter()
                            .any(|accepted| accepted.event_id == frozen.event_id)
                        {
                            publish(source, state, &frozen).await?;
                        }
                        continue;
                    }
                    let mut grant = HistoryGrant {
                        recipient: request.recipient.clone(),
                        recipient_hpke_key_base64url: request.recipient_hpke_key_base64url.clone(),
                        recipient_key_event_ref: full.event.event_id.clone(),
                        history_cut: request.history_cut.clone(),
                        expires_at: request.expires_at,
                        entries: vec![],
                    };
                    let mut complete = true;
                    for (path, selector) in paths.iter().zip(&selectors) {
                        let key = match selected::held(
                            source,
                            state,
                            &vault,
                            &active.authority,
                            &active.device_id,
                            original,
                            path,
                        )
                        .await
                        {
                            Ok(key) => key,
                            Err(_) => {
                                complete = false;
                                break;
                            }
                        };
                        let sealed = arkret_crypto::content_history::seal_history_key(
                            &grant,
                            selector,
                            &key.key()?,
                        )?;
                        grant.entries.push(HistoryGrantEntry {
                            selector: selector.clone(),
                            sealed_key_base64url: sealed,
                        });
                    }
                    if !complete {
                        continue;
                    }
                    grant.validate_for_request(&full.event.event_id, &request)?;
                    let operation = crate::operation::TypedOperationBuilder::new_for_actor::<
                        arkret_sdk::event_spec::MlsHistoryGrant,
                    >(scope.clone(), actor.clone(), grant)
                    .build_sdk_event("inkson")?;
                    let authored = crate::event_submit::EventSubmitter::new(source.http_client()?)
                        .with_state_store(state.clone())
                        .with_authority(active.authority.clone())
                        .author_for_direct_submission(&operation)
                        .await?;
                    let frozen = vault
                        .frozen_grant(&full.event.event_id, &selectors, Some(authored.event()))
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("history grant custody missing"))?;
                    publish(source, state, &frozen).await?;
                }
            }
            EventKind::MlsHistoryGrant => {
                let grant = full.event.as_mls_history_grant()?;
                if grant.recipient != recipient {
                    continue;
                }
                if grant.expires_at <= crate::clock::now_utc() {
                    continue;
                }
                let Some(pending) = vault.request(&scope).await? else {
                    continue;
                };
                if pending.event().event_id != grant.recipient_key_event_ref
                    || !pending.has_private_key()
                {
                    continue;
                }
                let request_original =
                    garth::own_station_results::read_window_dependency_by_event_id(
                        source,
                        &grant.recipient_key_event_ref,
                    )
                    .await?;
                anyhow::ensure!(
                    request_original.full()?.event == *pending.event(),
                    "history request original differs from local custody"
                );
                grant.validate_for_request(
                    &pending.event().event_id,
                    &pending.event().as_mls_history_request()?,
                )?;
                // Parents precede children regardless of entry order.
                let mut entries: Vec<_> = grant.entries.iter().collect();
                entries.sort_by_key(|entry| match &entry.selector {
                    HistoryKeySelector::ContentKey { content_path, .. } => {
                        content_path.matches('/').count()
                    }
                    _ => usize::MAX,
                });
                for entry in entries {
                    let HistoryKeySelector::ContentKey {
                        source_event_ref,
                        content_path,
                    } = &entry.selector
                    else {
                        continue;
                    };
                    let original = garth::own_station_results::read_window_dependency_by_event_id(
                        source,
                        source_event_ref,
                    )
                    .await?;
                    let full = original.full()?;
                    anyhow::ensure!(
                        full.event.scope_ref == scope
                            && full.commit.stream_ref == grant.history_cut.stream_ref
                            && full.commit.stream_position <= grant.history_cut.stream_position,
                        "granted source exceeds exact scope/cut"
                    );
                    let key = pending.open_entry(&grant, entry, crate::clock::now_utc())?;
                    let before = current_endpoint(source, &recipient).await?;
                    let retained = selected::verify(
                        source,
                        state,
                        &vault,
                        &active.authority,
                        &active.device_id,
                        full,
                        content_path,
                        &key,
                    )
                    .await?;
                    require_reader(source, state)?;
                    original.full()?;
                    anyhow::ensure!(
                        current_endpoint(source, &recipient).await? == before,
                        "history native recipient changed across selected-key verification"
                    );
                    let known = vault
                        .read_key(source_event_ref, content_path)
                        .await?
                        .is_some();
                    vault.retain_key(&retained).await?;
                    if !known {
                        cache.note_keys_changed();
                    }
                }
            }
            _ => {}
        }
    }
    pending::complete_covered_window(source, state, &vault, &scope, &originals).await?;
    require_reader(source, state)?;
    Ok(())
}
