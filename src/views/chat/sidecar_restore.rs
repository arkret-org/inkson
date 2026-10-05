use super::*;

/// The composer can be replaced after ensure. Keep private access preparation
/// on the chat effects scope and resume it for an already accepted source route.
pub(super) fn use_sidecar_reconciliation(
    base_url: String,
    realm_id: String,
    strand_id: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    token: Signal<String>,
    state_store: SyncSignal<LocalStateStore>,
    mut status_msg: Signal<String>,
) {
    let mut hosted = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    let mut seen = use_signal(String::new);
    use_effect(use_reactive!(|(
        base_url,
        realm_id,
        strand_id,
        authority,
        device_id,
    )| {
        let credential = token();
        let Some(session) = hosted().filter(|session| {
            session.controller_account_id == authority
                && session.matches_route(&realm_id, &strand_id)
        }) else {
            seen.set(String::new());
            return;
        };
        let key = format!(
            "{base_url}|{authority}|{device_id}|{realm_id}|{strand_id}|{}|{}|{}|{credential}",
            session.trace_id,
            session.mls_context.participant_authority_digest,
            session.membership_ready(),
        );
        if *seen.peek() == key {
            return;
        }
        seen.set(key.clone());
        if credential.is_empty() || session.membership_ready() {
            return;
        }
        let Ok(fence) = crate::transport::auth::AuthoringSessionFence::capture() else {
            return;
        };
        spawn(async move {
            let state = crate::app::runtime_adapter::state_store_handle(state_store);
            let mut prepared = false;
            let mut retry_seconds = 2;
            loop {
                let is_current = || {
                    *seen.peek() == key
                        && fence.check().is_ok()
                        && hosted.peek().as_ref().is_some_and(|current| {
                            current.trace_id == session.trace_id
                                && current.controller_account_id == authority
                                && current.matches_route(&realm_id, &strand_id)
                        })
                };
                if !is_current() {
                    return;
                }
                let result = async {
                    let api =
                        crate::transport::auth::authed_api_ready(&base_url, credential.clone())
                            .await?;
                    fence.check()?;
                    let view = api
                        .sdk_http_client()?
                        .agent_sidecar_get(&session.sidecar_id)
                        .await?;
                    crate::sidecar::validate_agent_sidecar_view(&view)?;
                    anyhow::ensure!(
                        view.sidecar.id == session.sidecar_id
                            && view.sidecar.realm_id.as_str() == realm_id
                            && view.sidecar.controller_account_id == authority,
                        "Sidecar reconciliation changed its private scope or controller"
                    );
                    if prepared {
                        Ok::<_, anyhow::Error>(view)
                    } else {
                        crate::mls::sidecar_bootstrap::reconcile_sidecar_mls(
                            &api, &state, &authority, &device_id, &view,
                        )
                        .await
                    }
                }
                .await;
                if !is_current() {
                    return;
                }
                match result {
                    Ok(view) => {
                        prepared = true;
                        retry_seconds = 2;
                        let mut open = hosted.peek().clone().unwrap();
                        open.native_mls_ready =
                            crate::sidecar::native_mls_ready_for_view(&state_store.read(), &view);
                        open.access_readiness = view.access_readiness;
                        open.pending_access_reconciliations = view.pending_access_reconciliations;
                        open.mls_context = view.mls_context;
                        let ready = open.membership_ready();
                        if hosted.peek().as_ref() != Some(&open) {
                            hosted.set(Some(open));
                        }
                        if ready {
                            status_msg.set("Private AI workspace ready".to_owned());
                            return;
                        }
                    }
                    Err(error) => {
                        prepared = false;
                        tracing::warn!(target: "sidecar", reason = %format_args!("{error:#}"), "Sidecar access preparation will resume");
                        status_msg.set(format!("Could not prepare private AI access: {error:#}"));
                        retry_seconds = (retry_seconds * 2).min(30);
                    }
                }
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(retry_seconds))
                    .await;
            }
        });
    }));
}

/// Opening a source Strand on another device must not require a new ensure
/// write. Discover the accepted mapping and retain this device's own MLS gate.
pub(super) fn use_sidecar_restore(
    base_url: String,
    realm_id: String,
    strand_id: String,
    authority: arkret_sdk::AccountId,
    token: Signal<String>,
    sync_cursor: Signal<String>,
    realm_live_epoch: Signal<u64>,
    state_store: SyncSignal<LocalStateStore>,
) {
    let mut hosted = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    let mut seen = use_signal(String::new);
    let mut generation = use_signal(|| 0_u64);
    use_effect(use_reactive!(|(
        base_url,
        realm_id,
        strand_id,
        authority,
    )| {
        let credential = token();
        let cursor = sync_cursor();
        let epoch = realm_live_epoch();
        let Ok(strand) = arkret_sdk::StrandId::new(strand_id.clone()) else {
            return;
        };
        let candidate = state_store
            .read()
            .verified_sidecar_for_source(&authority, &realm_id, &strand)
            .ok()
            .flatten();
        let checkpoint_hint = candidate.as_ref().and_then(|sidecar| {
            state_store
                .read()
                .mls_checkpoint_for_scope(&arkret_sdk::ScopeRef::Sidecar {
                    realm_id: sidecar.realm_id.clone(),
                    sidecar_id: sidecar.id.clone(),
                })
                .map(|checkpoint| {
                    format!("{}|{:?}", checkpoint.epoch, checkpoint.group_state_event_id)
                })
        });
        let key = format!(
            "{base_url}|{authority}|{realm_id}|{strand_id}|{cursor}|{epoch}|{}|{credential}|{checkpoint_hint:?}|{:?}",
            crate::identity::device_directory::session_cache_epoch(),
            candidate.as_ref().map(|sidecar| &sidecar.id)
        );
        if *seen.peek() == key {
            return;
        }
        seen.set(key);
        let next = generation.peek().wrapping_add(1);
        generation.set(next);
        let Some(candidate) = candidate else { return };
        if credential.is_empty() {
            return;
        }
        let Ok(fence) = crate::transport::auth::AuthoringSessionFence::capture() else {
            return;
        };
        spawn(async move {
            let result = async {
                let api = crate::transport::auth::authed_api_ready(&base_url, credential).await?;
                let view = api
                    .sdk_http_client()?
                    .agent_sidecar_get(&candidate.id)
                    .await?;
                crate::sidecar::validate_agent_sidecar_view(&view)?;
                fence.check()?;
                anyhow::ensure!(
                    view.sidecar.id == candidate.id
                        && view.sidecar.realm_id == candidate.realm_id
                        && view.sidecar.controller_account_id == authority,
                    "Sidecar restore read changed its controller or native identity"
                );
                if *generation.peek() != next {
                    return Ok::<(), anyhow::Error>(());
                }
                let store = state_store.read();
                anyhow::ensure!(
                    store
                        .verified_sidecar_for_source(&authority, &realm_id, &strand)?
                        .is_some_and(|current| current.id == candidate.id),
                    "Sidecar source mapping changed during restore"
                );
                let native_ready = crate::sidecar::native_mls_ready_for_view(&store, &view);
                let last_addressed = crate::sidecar::cached_sidecar_exchange_projections(
                    &store, &authority, &realm_id,
                )
                .ok()
                .and_then(|projections| {
                    projections
                        .into_iter()
                        .filter(|projection| {
                            projection.sidecar_id == candidate.id
                                && projection.source_track_ref.strand_id == strand
                        })
                        .max_by(|left, right| {
                            left.source_hlc
                                .cmp(&right.source_hlc)
                                .then_with(|| left.client_order_key.cmp(&right.client_order_key))
                        })
                })
                .map(|projection| {
                    projection
                        .addressed_agent_ids
                        .into_iter()
                        .map(|agent| agent.to_string())
                        .collect()
                })
                .unwrap_or_default();
                let existing = hosted.peek().clone().filter(|session| {
                    session.controller_account_id == authority
                        && session.sidecar_id == candidate.id
                        && session.matches_route(&realm_id, &strand_id)
                });
                let mut session = existing.unwrap_or_else(|| crate::sidecar::HostedSidecarState {
                    trace_id: uuid_v7(),
                    controller_account_id: authority,
                    addressed_agent_ids: last_addressed,
                    addressed_agent_label: "No agents addressed".to_owned(),
                    source_realm_id: realm_id,
                    source_strand_id: strand_id,
                    sidecar_id: candidate.id,
                    access_readiness: view.access_readiness,
                    pending_access_reconciliations: view.pending_access_reconciliations.clone(),
                    mls_context: view.mls_context.clone(),
                    native_mls_ready: false,
                    migrated_draft: String::new(),
                    opened_at: crate::clock::now_utc(),
                });
                session.access_readiness = view.access_readiness;
                session.pending_access_reconciliations = view.pending_access_reconciliations;
                session.mls_context = view.mls_context;
                session.native_mls_ready = native_ready;
                drop(store);
                hosted.set(Some(session));
                Ok(())
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(reason = %format_args!("{error:#}"), "Sidecar hosted restore remains pending");
            }
        });
    }));
}
