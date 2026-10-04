use super::*;

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
    let mut last_open_route = use_signal(String::new);
    let mut dismissed_route = use_signal(String::new);
    use_effect(use_reactive!(|(
        base_url,
        realm_id,
        strand_id,
        authority,
    )| {
        let credential = token();
        let cursor = sync_cursor();
        let epoch = realm_live_epoch();
        let route_key = format!("{authority}|{realm_id}|{strand_id}");
        let open = hosted().filter(|session| {
            session.controller_account_id == authority
                && session.matches_route(&realm_id, &strand_id)
        });
        if open.is_some() {
            if *last_open_route.peek() != route_key {
                last_open_route.set(route_key.clone());
            }
            if *dismissed_route.peek() == route_key {
                dismissed_route.set(String::new());
            }
        } else if *last_open_route.peek() == route_key {
            if *dismissed_route.peek() != route_key {
                dismissed_route.set(route_key.clone());
                let next_generation = generation.peek().wrapping_add(1);
                generation.set(next_generation);
            }
        }
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
        if open.is_none() && *dismissed_route.peek() == route_key {
            return;
        }
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
                let scope = arkret_sdk::ScopeRef::Sidecar {
                    realm_id: candidate.realm_id.clone(),
                    sidecar_id: candidate.id.clone(),
                };
                let native_ready =
                    view.mls_context.mls_group_id.as_ref().is_some_and(|group| {
                        let current = store.verified_sidecar_inputs(&realm_id).ok().and_then(
                            |(snapshot, _)| {
                                crate::current_projection::current_mls_group(
                                    &snapshot.current_state_entries,
                                    &scope,
                                )
                            },
                        );
                        store
                            .mls_checkpoint_for_scope_and_group(&scope, group)
                            .is_some_and(|checkpoint| {
                                Some(checkpoint.epoch) == view.mls_context.epoch
                                    && current.is_some_and(|current| {
                                        current.epoch == checkpoint.epoch
                                            && checkpoint.group_state_event_id.as_ref()
                                                == Some(&current.current_mls_commit_event_ref)
                                    })
                            })
                    });
                let existing = hosted.peek().clone().filter(|session| {
                    session.controller_account_id == authority
                        && session.sidecar_id == candidate.id
                        && session.matches_route(&realm_id, &strand_id)
                });
                let mut session = existing.unwrap_or_else(|| crate::sidecar::HostedSidecarState {
                    trace_id: uuid_v7(),
                    controller_account_id: authority,
                    addressed_agent_ids: Vec::new(),
                    addressed_agent_label: "No agents addressed".to_owned(),
                    source_realm_id: realm_id,
                    source_strand_id: strand_id,
                    sidecar_id: candidate.id,
                    access_readiness: view.access_readiness,
                    pending_access_reconciliations: view.pending_access_reconciliations.clone(),
                    mls_context: view.mls_context.clone(),
                    native_mls_ready: false,
                    display_mode: arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
                    migrated_draft: String::new(),
                    opened_at: crate::clock::now_utc(),
                });
                session.access_readiness = view.access_readiness;
                session.pending_access_reconciliations = view.pending_access_reconciliations;
                session.mls_context = view.mls_context;
                session.native_mls_ready = native_ready;
                if let Some(mode) = crate::sidecar::cached_sidecar_display_mode(&store, &session) {
                    session.display_mode = mode;
                }
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
