use arkret_wire::ProfileId;

use super::*;

#[derive(Clone, PartialEq)]
pub(super) struct MlsRuntimeEffectState {
    pub route_uses_realm_context: bool,
    pub context_realm_id: Option<String>,
    pub mls_key_package_publish_key_seen: Signal<Option<String>>,
    pub secure_store_bootstrap_ready: Signal<bool>,
    pub device_authorization_check_complete: Signal<bool>,
    pub needs_device_authorization: Signal<bool>,
    pub token: Signal<String>,
    pub principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub device_id: Signal<String>,
    pub server_description: Signal<Option<ServiceDescribe>>,
    pub sync_bootstrap_complete: Signal<bool>,
    pub sync_cursor: Signal<String>,
    pub realm_live_epoch: Signal<u64>,
    pub mls_admission_reconcile_in_flight: Signal<bool>,
    pub mls_admission_reconcile_pending: Signal<bool>,
    pub last_error: Signal<Option<String>>,
    pub mls_admission_diag_last: Signal<String>,
    pub realm_events_route_enabled: Signal<bool>,
    pub selected_realm_id: Signal<String>,
    pub device_queue: Signal<usize>,
    pub mls_welcome_bootstrap_key_seen: Signal<Option<String>>,
    pub crypto_state: Signal<String>,
    pub needs_mls_backup: Signal<bool>,
}

#[component]
pub(super) fn MlsRuntimeEffects(state: MlsRuntimeEffectState) -> Element {
    let MlsRuntimeEffectState {
        route_uses_realm_context,
        context_realm_id,
        mls_key_package_publish_key_seen,
        secure_store_bootstrap_ready,
        device_authorization_check_complete,
        needs_device_authorization,
        token,
        principal_id: _,
        device_id: _,
        server_description,
        sync_bootstrap_complete,
        sync_cursor,
        realm_live_epoch,
        mls_admission_reconcile_in_flight,
        mls_admission_reconcile_pending,
        last_error,
        mls_admission_diag_last,
        realm_events_route_enabled,
        selected_realm_id,
        device_queue,
        mls_welcome_bootstrap_key_seen,
        crypto_state,
        needs_mls_backup,
    } = state;
    let SessionContext {
        state_store,
        active_account,
        ..
    } = SessionContext::get();
    let mls_admission_retry_attempt = use_signal(|| 0_u32);
    let mls_key_package_publish_retry_attempt = use_signal(|| 0_u32);
    let sidecar_background_basis_seen = use_signal(|| Option::<String>::None);
    let sidecar_background_in_flight = use_signal(|| false);
    let sidecar_background_retry_attempt = use_signal(|| 0_u32);
    let mls_coverage_repair_in_flight = use_signal(std::collections::BTreeSet::<String>::new);
    let accepted_artifact_basis_seen = use_signal(|| Option::<String>::None);
    let accepted_artifact_convergence_in_flight = use_signal(|| false);
    let history_recovery_poll_tick = use_signal(|| 0_u64);
    let history_recovery_in_flight = use_signal(|| false);

    {
        let ready = secure_store_bootstrap_ready;
        let sync_ready = sync_bootstrap_complete;
        let sync_freshness = sync_cursor;
        let mut basis_seen = accepted_artifact_basis_seen;
        let mut in_flight = accepted_artifact_convergence_in_flight;
        let mut convergence_error = last_error;
        let convergence_store = state_store;
        use_effect(move || {
            let Some(account) = active_account() else {
                return;
            };
            let cursor = sync_freshness();
            let actor = account.full_id().to_string();
            let device = account.device_id.clone();
            let authority = account.authority.clone();
            if !ready()
                || !sync_ready()
                || cursor.trim().is_empty()
                || actor.trim().is_empty()
                || *in_flight.peek()
            {
                return;
            }
            let basis = format!("{actor}|{device}|{cursor}");
            if basis_seen.peek().as_deref() == Some(basis.as_str()) {
                return;
            }
            basis_seen.set(Some(basis.clone()));
            in_flight.set(true);
            spawn(async move {
                match crate::mls::runtime::converge_accepted_mls_artifacts(
                    convergence_store,
                    &authority,
                    &device,
                )
                .await
                {
                    Ok(applied) => {
                        if applied > 0 {
                            tracing::info!(applied, "accepted MLS artifacts converged durably");
                        }
                        match crate::mls::runtime::converge_external_history_candidate_decryptions(
                            convergence_store,
                            &authority,
                            &actor,
                            &device,
                            chrono::Utc::now(),
                        ) {
                            Ok(opened) if opened > 0 => {
                                tracing::info!(
                                    opened,
                                    "external history candidates opened accepted Events"
                                );
                            }
                            Ok(_) => {}
                            Err(error) => {
                                tracing::warn!(%error, "external history candidate convergence is pending");
                                convergence_error.set(Some(crate::history_ui::status_message(
                                    crate::history_ui::HistoryUiReason::ResponseVerificationPending,
                                    &format!("external candidate convergence: {error}"),
                                )));
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "accepted MLS artifact convergence is pending");
                        convergence_error.set(Some(crate::history_ui::status_message(
                            crate::history_ui::HistoryUiReason::ResponseVerificationPending,
                            &format!("accepted artifact convergence: {error}"),
                        )));
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(5)).await;
                        if basis_seen.peek().as_deref() == Some(basis.as_str()) {
                            basis_seen.set(None);
                        }
                    }
                }
                in_flight.set(false);
            });
        });
    }

    {
        let ready = secure_store_bootstrap_ready;
        let sync_ready = sync_bootstrap_complete;
        let mut poll_tick = history_recovery_poll_tick;
        let mut in_flight = history_recovery_in_flight;
        let mut recovery_error = last_error;
        let recovery_store = state_store;
        use_effect(move || {
            let Some(account) = active_account() else {
                return;
            };
            let _ = poll_tick();
            let base = account.server_url.to_string();
            let credential = token();
            let full_id = account.full_id().clone();
            let device = account.device_id.clone();
            let authority = account.authority.clone();
            if !ready()
                || !sync_ready()
                || base.trim().is_empty()
                || credential.trim().is_empty()
                || *in_flight.peek()
            {
                return;
            }
            in_flight.set(true);
            spawn(async move {
                let result = crate::transport::auth::with_authed_api(
                    &base,
                    credential,
                    move |api| async move {
                        let secure_store =
                            crate::secure_key_store::default_secure_key_store("inkson");
                        let outcome = crate::history_recovery::converge_member_history_recovery(
                            recovery_store,
                            &api,
                            secure_store.as_ref(),
                            &authority,
                            &full_id,
                            &device,
                            crate::clock::now_utc_canonical(),
                        )
                        .await?;
                        let opened =
                            crate::mls::runtime::converge_external_history_candidate_decryptions(
                                recovery_store,
                                &authority,
                                full_id.as_str(),
                                &device,
                                crate::clock::now_utc_canonical(),
                            )
                            .map_err(anyhow::Error::msg)?;
                        if outcome
                            != crate::history_recovery::HistoryRecoveryConvergenceOutcome::default()
                            || opened > 0
                        {
                            tracing::info!(
                                requests = outcome.requests_created_or_resumed,
                                source_attempts_staged = outcome.source_attempts_staged,
                                source_attempts_completed = outcome.source_attempts_completed,
                                response_records_installed = outcome.response_records_installed,
                                pending_errors = outcome.pending_errors,
                                opened,
                                "private history-key recovery tick completed"
                            );
                        }
                        Ok(())
                    },
                )
                .await
                .map_err(|error| anyhow::anyhow!(error.display()));
                if let Err(error) = result {
                    let detail = error.to_string();
                    tracing::warn!(%error, "private history-key convergence remains pending");
                    recovery_error.set(Some(crate::history_ui::status_message(
                        crate::history_ui::classify_runtime_error(&detail),
                        &detail,
                    )));
                }
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(10)).await;
                in_flight.set(false);
                poll_tick.set(poll_tick().wrapping_add(1));
            });
        });
    }

    {
        let mut seen_publish_key = mls_key_package_publish_key_seen;
        let mut publish_retry_attempt = mls_key_package_publish_retry_attempt;
        let secure_store_ready_for_publish = secure_store_bootstrap_ready;
        use_effect(move || {
            if !secure_store_ready_for_publish() {
                return;
            }
            // Subscribe to the accepted account before consulting the
            // process-local signer. The signer registry is not reactive; on
            // first enrollment it is activated immediately before this
            // signal is committed, so the account transition is what wakes
            // this effect after its unauthenticated first render.
            let Some(account) = active_account() else {
                return;
            };
            if crate::event_signer::active_signer().is_none() {
                return;
            }
            // Gate on device authorization. Publishing a KeyPackage requires an
            // ACCEPTED `ak.device.authorize` — soland rejects the upload with
            // `claim_generation_mismatch` ("accepted device authorization is
            // required") otherwise. The authorization probe and any
            // user-approved pairing/recovery run independently; without
            // this gate the upload can lose the race, fail, and — because the
            // publish is deduped on `seen_publish_key` (set before the spawn).
            // Failures clear that key after bounded backoff below; otherwise a
            // single transient error would leave every later invite stuck at
            // `mls_keypackage_not_found`.
            // Reading both signals subscribes this effect, so it re-fires and
            // publishes once the device becomes authorized.
            if !device_authorization_check_complete() || needs_device_authorization() {
                return;
            }
            let base = account.server_url.to_string();
            let session = token();
            let device = account.device_id.clone();
            let authority = account.authority.clone();
            let description = server_description();
            let pairwise_realms = {
                let store = state_store.read();
                store
                    .known_realm_ids()
                    .into_iter()
                    .filter(|realm_id| {
                        store.realm_projection_is_minimal_metadata(realm_id.as_str())
                    })
                    .collect::<Vec<_>>()
            };
            let Some(publish_key) = mls_key_package_publish_key(
                &account.server_url,
                &session,
                &account.authority,
                &account.device_id,
                profile_ready(description.as_ref(), ProfileId::E2EE_CLIENT_V1),
                sync_bootstrap_complete(),
            ) else {
                return;
            };
            let publish_hint = local_mls_key_package_publish_hint(&base, &authority, &device);
            let pairwise_secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let pairwise_basis = pairwise_realms
                .iter()
                .map(|realm_id| {
                    let marker = crate::mls::runtime::load_mls_pairwise_key_package_publish_marker(
                        pairwise_secure_store.as_ref(),
                        &authority,
                        &device,
                        realm_id,
                    )
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "none".to_owned());
                    format!("{}={marker}", realm_id.as_str())
                })
                .collect::<Vec<_>>()
                .join(",");
            let publish_key = format!("{publish_key}|kp={publish_hint}|pairwise={pairwise_basis}");
            if seen_publish_key().as_deref() == Some(publish_key.as_str()) {
                return;
            }
            seen_publish_key.set(Some(publish_key.clone()));
            spawn(async move {
                let attempted_publish_key = publish_key;
                let ordinary = ensure_local_mls_key_package_inventory(
                    base.clone(),
                    session.clone(),
                    authority.clone(),
                    device.clone(),
                )
                .await;
                let pairwise = match ordinary {
                    Ok(_) => {
                        let mut published = Vec::new();
                        let mut error = None;
                        for realm_id in pairwise_realms {
                            match ensure_pairwise_mls_key_package_published(
                                base.clone(),
                                session.clone(),
                                authority.clone(),
                                device.clone(),
                                realm_id,
                            )
                            .await
                            {
                                Ok(Some(key_package_id)) => published.push(key_package_id),
                                Ok(None) => {}
                                Err(current) => {
                                    error = Some(current);
                                    break;
                                }
                            }
                        }
                        error.map_or_else(|| Ok(published), Err)
                    }
                    Err(error) => Err(error),
                };
                match pairwise {
                    Ok(key_package_ids) => {
                        if *publish_retry_attempt.peek() != 0 {
                            publish_retry_attempt.set(0);
                        }
                        tracing::debug!(
                            pairwise_key_package_count = key_package_ids.len(),
                            "local ordinary and Realm-scoped pairwise MLS KeyPackages are published"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "MLS KeyPackage publish bootstrap failed");
                        let attempt = *publish_retry_attempt.peek();
                        let retry_after_secs = (2_u64 << attempt.min(5)).min(60);
                        publish_retry_attempt.set(attempt.saturating_add(1).min(5));
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                            retry_after_secs,
                        ))
                        .await;
                        if seen_publish_key.peek().as_deref()
                            == Some(attempted_publish_key.as_str())
                        {
                            seen_publish_key.set(None);
                        }
                    }
                }
            });
        });
    }
    {
        let mut basis_seen = sidecar_background_basis_seen;
        let mut in_flight = sidecar_background_in_flight;
        let mut retry_attempt = sidecar_background_retry_attempt;
        let ready = secure_store_bootstrap_ready;
        let sync_ready = sync_bootstrap_complete;
        let sync_freshness = sync_cursor;
        let mut live_epoch = realm_live_epoch;
        let background_store = state_store;
        use_effect(move || {
            let cursor = sync_freshness();
            if !ready() || !sync_ready() || *in_flight.peek() {
                return;
            }
            let Some(account) = active_account() else {
                return;
            };
            let base = account.server_url.to_string();
            let credential = token();
            let actor = account.full_id().to_string();
            let device = account.device_id.clone();
            let authority = account.authority.clone();
            if base.trim().is_empty()
                || credential.trim().is_empty()
                || actor.trim().is_empty()
                || device.as_str().is_empty()
            {
                return;
            }
            let basis = format!("{base}\u{1f}{actor}\u{1f}{device}\u{1f}{cursor}");
            if basis_seen().as_deref() == Some(basis.as_str()) {
                return;
            }
            basis_seen.set(Some(basis.clone()));
            in_flight.set(true);
            spawn(async move {
                match crate::sidecar::sync_sidecar_exchange_background(
                    &base,
                    credential,
                    &actor,
                    &authority,
                    &device,
                    background_store,
                )
                .await
                {
                    Ok(outcome) => {
                        if *retry_attempt.peek() != 0 {
                            retry_attempt.set(0);
                        }
                        if outcome.ingested_events > 0 || outcome.cache_entries_changed > 0 {
                            live_epoch.set(live_epoch().wrapping_add(1));
                        }
                        tracing::debug!(
                            sidecars = outcome.sidecar_views,
                            locators = outcome.recovered_locators,
                            ingested = outcome.ingested_events,
                            refolded = outcome.cache_entries_changed,
                            backfill_pending = outcome.backfill_required,
                            "account-scoped Sidecar background pass completed"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "account-scoped Sidecar background pass failed");
                        let attempt = *retry_attempt.peek();
                        let retry_after_secs = (2_u64 << attempt.min(5)).min(60);
                        retry_attempt.set(attempt.saturating_add(1).min(5));
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                            retry_after_secs,
                        ))
                        .await;
                        if basis_seen.peek().as_deref() == Some(basis.as_str()) {
                            basis_seen.set(None);
                        }
                    }
                }
                in_flight.set(false);
            });
        });
    }
    {
        // Admin-side MLS admission reconciliation — the producer counterpart of
        // the invitee Welcome bootstrap below. When a member actually joins an
        // encrypted Realm this device administers, (re)admit anyone not yet in
        // the MLS group so their `ak.mls.welcome` is finally produced. Closes
        // the invite-time race where admission ran before the invitee had
        // published a KeyPackage: re-runs when the durable Realm projection
        // changes, so a member who publishes their KeyPackage after joining is
        // picked up without tying an admission network pass to an opaque
        // account cursor re-mint.
        let admit_state_store = state_store;
        let admit_realm_live_epoch = realm_live_epoch;
        let mut admit_in_flight = mls_admission_reconcile_in_flight;
        let mut admit_pending = mls_admission_reconcile_pending;
        let mut admit_retry_attempt = mls_admission_retry_attempt;
        let mut admit_last_error = last_error;
        let mut admit_diag_last = mls_admission_diag_last;
        let secure_store_ready_for_admit = secure_store_bootstrap_ready;
        let admit_route_enabled = realm_events_route_enabled;
        use_effect(move || {
            if !secure_store_ready_for_admit() {
                return;
            }
            if !admit_route_enabled() {
                return;
            }
            let Some(account) = active_account() else {
                return;
            };
            let base = account.server_url.to_string();
            let description = server_description();
            if !profile_ready(description.as_ref(), ProfileId::E2EE_CLIENT_V1)
                || !sync_bootstrap_complete()
            {
                return;
            }
            let session = token();
            let actor = account.full_id().to_string();
            let device = account.device_id.clone();
            if base.trim().is_empty() || session.trim().is_empty() || actor.trim().is_empty() {
                return;
            }
            // Durable Realm changes are the admission freshness axis. The
            // account cursor is a resume checkpoint and may also advance for
            // typing/receipts/calls, none of which can create MLS candidates.
            let _ = admit_realm_live_epoch();
            let _ = admit_pending();
            let candidate_realms = {
                // Do not subscribe to every local-store write. The explicit
                // durable epoch above is the only projection trigger.
                let store = admit_state_store.peek();
                crate::views::realm_admin::mls_admission_candidate_realms_for_actor(&store, &actor)
            };
            if candidate_realms.is_empty() {
                // Make a stuck admin observable: an encrypted Realm with an
                // invitee waiting for a Welcome but the admin never admitting is
                // exactly this branch. wasm tracing is capped at WARN, so INFO/
                // DEBUG here would be invisible — emit a throttled WARN naming
                // the blocking cause. (mls-admission-debug)
                let Some(diag) = ({
                    let store = admit_state_store.peek();
                    let encrypted_local_realms = store
                        .load()
                        .realm_tree_projections
                        .keys()
                        .filter(|realm_id| {
                            realm_id.starts_with("ak:realm:")
                                && store.realm_projection_is_mls_encrypted(realm_id)
                        })
                        .count();
                    if encrypted_local_realms == 0 {
                        None
                    } else {
                        let encrypted_snapshot_realms = store
                            .mls_snapshots()
                            .keys()
                            .filter(|realm_id| {
                                realm_id.starts_with("ak:realm:")
                                    && store.realm_projection_is_mls_encrypted(realm_id)
                            })
                            .count();
                        Some(format!(
                            "candidate_realms=0 encrypted_local_realms={encrypted_local_realms} encrypted_snapshot_realms={encrypted_snapshot_realms}"
                        ))
                    }
                }) else {
                    return;
                };
                if admit_diag_last() != diag {
                    admit_diag_last.set(diag.clone());
                    tracing::warn!(
                        target: "mls_admission",
                        %diag,
                        "admission pre-filter blocked: no joined non-self member is visible in any local encrypted Realm"
                    );
                }
                return;
            }
            let candidate_diag = candidate_realms
                .iter()
                .map(|(realm_id, joined_sig)| format!("{realm_id}:joined=[{joined_sig}]"))
                .collect::<Vec<_>>()
                .join("|");
            if admit_diag_last() != candidate_diag {
                admit_diag_last.set(candidate_diag.clone());
                tracing::warn!(
                    target: "mls_admission",
                    candidate_count = candidate_realms.len(),
                    diag = %candidate_diag,
                    "admission pre-filter passed: reconciling local encrypted Realm candidates"
                );
            }
            // Read in-flight with `peek()` (NOT `()`) so this effect does not
            // subscribe to the guard and self-spin on set(true)/set(false).
            // If a real sync/realm-stream edge arrives while a reconcile is
            // running, remember one pending rerun; completion flips that bit
            // back to false and lets the subscribed effect run once more.
            if *admit_in_flight.peek() {
                // Write ONLY on a real false→true transition. This effect
                // subscribes to `admit_pending` (see the `admit_pending()`
                // read above), and a plain `set()` marks the signal dirty even
                // when the value is unchanged — so an unconditional set() here
                // would re-fire this very effect and spin the main thread
                // (same class as the in_flight self-spin fixed earlier).
                if !*admit_pending.peek() {
                    admit_pending.set(true);
                }
                return;
            }
            // Same guard on the reset path: an unconditional `set(false)` runs
            // on every non-in-flight pass and is the loop seed — it retriggers
            // the subscribed effect with no external change. Only clear a flag
            // that is actually set.
            if *admit_pending.peek() {
                admit_pending.set(false);
            }
            admit_in_flight.set(true);
            spawn(async move {
                let outcome =
                    crate::transport::auth::with_authed_api(&base, session, |api| async move {
                        let mut admitted_total = 0_usize;
                        let mut deferred_total = 0_usize;
                        let mut failures = Vec::<String>::new();
                        for (realm_id, _) in candidate_realms {
                            match crate::views::realm_admin::reconcile_mls_admissions_for_realm(
                                &api,
                                admit_state_store,
                                realm_id.clone(),
                                actor.clone(),
                                device.to_string(),
                            )
                            .await
                            {
                                Ok(reconcile) => {
                                    admitted_total += reconcile.admitted;
                                    deferred_total += reconcile.deferred;
                                }
                                Err(error) => failures
                                    .push(format!("{}: {error:?}", short_protocol_id(&realm_id))),
                            }
                        }
                        Ok::<_, anyhow::Error>((admitted_total, deferred_total, failures))
                    })
                    .await;
                let deferred = outcome
                    .as_ref()
                    .map(|(_, deferred, _)| *deferred)
                    .unwrap_or_default();
                match &outcome {
                    Ok((admitted, _, failures)) if *admitted > 0 => {
                        tracing::warn!(
                            target: "mls_admission",
                            admitted = *admitted,
                            "admitted joined members into MLS group"
                        );
                        if !failures.is_empty() {
                            tracing::warn!(
                                target: "mls_admission",
                                failures = %failures.join("; "),
                                "MLS admission reconcile had per-Realm failures after admitting some members"
                            );
                            admit_last_error.set(Some(format!(
                                "MLS admission reconcile: {}",
                                failures.join("; ")
                            )));
                        }
                    }
                    Ok((_, _, failures)) if !failures.is_empty() => {
                        tracing::warn!(
                            target: "mls_admission",
                            failures = %failures.join("; "),
                            "MLS admission reconcile failed for all attempted Realm candidates"
                        );
                        admit_last_error.set(Some(format!(
                            "MLS admission reconcile: {}",
                            failures.join("; ")
                        )));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(
                            target: "mls_admission",
                            ?error,
                            "MLS admission reconcile failed"
                        );
                        admit_last_error.set(Some(format!("MLS admission reconcile: {error:?}")));
                    }
                }

                if deferred > 0 {
                    // KeyPackage publication is not a Realm event, so waiting
                    // for an unrelated account cursor change is neither
                    // reliable nor bounded. Hold the single-flight guard
                    // across an explicit exponential delay, then release one
                    // coalesced retry: 2, 4, 8, 16, 32, 60 seconds.
                    let attempt = *admit_retry_attempt.peek();
                    let retry_after_secs = (2_u64 << attempt.min(5)).min(60);
                    admit_retry_attempt.set(attempt.saturating_add(1).min(5));
                    if !*admit_pending.peek() {
                        admit_pending.set(true);
                    }
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                        retry_after_secs,
                    ))
                    .await;
                } else if *admit_retry_attempt.peek() != 0 {
                    admit_retry_attempt.set(0);
                }
                admit_in_flight.set(false);
                if *admit_pending.peek() {
                    // This transition is the single subscribed retry edge.
                    admit_pending.set(false);
                }
            });
        });
    }
    {
        let bootstrap_route_uses_realm_context = route_uses_realm_context;
        let bootstrap_context_realm_id = context_realm_id.clone();
        let mut seen_bootstrap_key = mls_welcome_bootstrap_key_seen;
        let state_store_for_bootstrap = state_store;
        let crypto_state_for_bootstrap = crypto_state;
        let last_error_for_bootstrap = last_error;
        let needs_mls_backup_for_bootstrap = needs_mls_backup;
        let secure_store_ready_for_bootstrap = secure_store_bootstrap_ready;
        let welcome_device_queue = device_queue;
        let coverage_repair_in_flight = mls_coverage_repair_in_flight;
        use_effect(move || {
            // Account sync journals to-device envelopes in the shared store,
            // then publishes the durable inbox length through `device_queue`.
            // Subscribe explicitly so a Welcome delivered after an earlier
            // empty bootstrap probe re-runs this realm-specific consumer.
            let _pending_to_device_messages = welcome_device_queue();
            if !secure_store_ready_for_bootstrap() {
                return;
            }
            let selected = selected_realm_id();
            if !bootstrap_route_uses_realm_context {
                return;
            }
            let Some(account) = active_account() else {
                return;
            };
            let base = account.server_url.to_string();
            let authority = account.authority.clone();
            let device = account.device_id.clone();
            let bootstrap_realm_id = bootstrap_context_realm_id
                .clone()
                .filter(|space| !space.trim().is_empty())
                .unwrap_or(selected);
            let Ok(realm_id) = arkret_sdk::RealmId::new(bootstrap_realm_id.clone()) else {
                return;
            };
            let session = token();
            let actor = account.full_id().to_string();
            let description = server_description();
            let Some(bootstrap_key) = mls_welcome_bootstrap_key(
                &account.server_url,
                &session,
                &account.authority,
                &account.device_id,
                &realm_id,
                profile_ready(description.as_ref(), ProfileId::E2EE_CLIENT_V1),
                sync_bootstrap_complete(),
            ) else {
                return;
            };
            // BUG X4: the per-Realm bootstrap caches its `seen` key, so after
            // the user's first encrypted write *creates* the account MLS
            // secret (and this Realm's MLS snapshot) the detection would
            // never re-run and the backup prompt would never appear. Read a
            // `state_store` signal in the synchronous body (`has_local_mls_snapshot`)
            // so Dioxus re-fires this effect when the write saves the snapshot,
            // and fold both the local account-secret presence (`sec=`) and the
            // snapshot presence (`snap=`) into the key so the `seen` guard no
            // longer matches once they flip false→true. The matching local
            // Welcome hint is also folded in so a sync-delivered pending
            // Welcome retriggers the drain after an earlier empty probe.
            let state_for_bootstrap_key = state_store_for_bootstrap.read();
            let has_local_mls_snapshot = state_for_bootstrap_key
                .mls_snapshot_for(&bootstrap_realm_id)
                .is_some();
            let has_encrypted_realm_projection =
                state_for_bootstrap_key.realm_projection_is_mls_encrypted(&bootstrap_realm_id);
            let local_mls_epoch_floor = crate::mls::runtime::mls_restore_epoch_floor(
                &state_for_bootstrap_key,
                &bootstrap_realm_id,
            );
            let recovery_key_fingerprint = crate::views::recovery::local_recovery_key_fingerprint(
                &state_for_bootstrap_key,
                &authority.principal_id,
            )
            .unwrap_or_default();
            let local_pending_welcome_hint = crate::mls::runtime::local_mls_welcome_hint_for_realm(
                &state_for_bootstrap_key.to_device_inbox(),
                &bootstrap_realm_id,
            );
            let coverage_repair_hint =
                crate::mls::coverage_liveness::mls_coverage_repair_dedup_hint(
                    &state_for_bootstrap_key,
                    &bootstrap_realm_id,
                );
            drop(state_for_bootstrap_key);
            let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
                &authority,
            )
            .map(|secret| secret.is_some())
            .unwrap_or(false);
            let bootstrap_key = format!(
                "{bootstrap_key}|sec={has_local_account_secret}|snap={has_local_mls_snapshot}|enc={has_encrypted_realm_projection}|epoch={local_mls_epoch_floor}|rk={recovery_key_fingerprint}|welcome={local_pending_welcome_hint}|coverage={coverage_repair_hint}"
            );
            if seen_bootstrap_key().as_deref() == Some(bootstrap_key.as_str()) {
                return;
            }
            seen_bootstrap_key.set(Some(bootstrap_key.clone()));
            let seen_bootstrap_key_for_probe = seen_bootstrap_key;

            let state_store_task = state_store_for_bootstrap;
            let mut crypto_state_task = crypto_state_for_bootstrap;
            let mut last_error_task = last_error_for_bootstrap;
            let realm_label = short_protocol_id(&bootstrap_realm_id);
            // Detection-step clones: the originals are moved into the Welcome
            // bootstrap call below; we reuse these for the account-secret
            // unlock probe afterwards.
            let detect_base = base.clone();
            let detect_session = session.clone();
            let detect_actor = actor.clone();
            let detect_authority = authority.clone();
            let detect_device = device.clone();
            let creator_bootstrap_realm_id = bootstrap_realm_id.clone();
            let state_store_for_probe = state_store_for_bootstrap;
            let mut coverage_repair_in_flight_for_probe = coverage_repair_in_flight;
            spawn(async move {
                let mut bootstrap_retry_required = false;
                match bootstrap_mls_welcome_for_realm(
                    base,
                    session,
                    actor,
                    authority,
                    device,
                    bootstrap_realm_id,
                    state_store_task,
                    Some(needs_mls_backup_for_bootstrap),
                )
                .await
                {
                    Ok(outcome) if outcome.applied > 0 => {
                        crypto_state_task.set(format!(
                            "MLS Welcome applied for {realm_label}: {} group(s); local MLS state is durable; portable history candidates remain separate from active state",
                            outcome.applied
                        ));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        bootstrap_retry_required = true;
                        last_error_task.set(Some(format!("MLS Welcome bootstrap: {error}")));
                    }
                }

                // A Realm creator never gets a Welcome, so the branch above
                // does nothing for them. Their epoch-0 bootstrap runs once in
                // the create wizard; if that attempt was interrupted (component
                // unmount, network failure, closed tab) the Realm is left with
                // no pinned governance checkpoint and no local snapshot, and every
                // encrypted write fails permanently. Replay it here — the gate
                // is creator-only, so the trusted anchor still comes from the
                // `encryption-and-audit.md` §2.5.1.1 "Realm create" source, and
                // the pin still happens only after full bundle verification.
                if crate::mls::creator_bootstrap::creator_mls_bootstrap_pending(
                    &state_store_for_probe.read(),
                    &creator_bootstrap_realm_id,
                    &detect_actor,
                ) {
                    tracing::warn!(
                        realm = %creator_bootstrap_realm_id,
                        "creator MLS bootstrap pending; replaying epoch-0 setup + ak.mls.genesis",
                    );
                    let creator_bootstrap_error = match crate::transport::auth::authed_api_ready(
                        &detect_base,
                        detect_session.clone(),
                    )
                    .await
                    {
                        Ok(api) => crate::mls::creator_bootstrap::ensure_creator_realm_mls_genesis(
                            &api,
                            state_store_task,
                            &creator_bootstrap_realm_id,
                            &detect_authority,
                            &detect_device,
                        )
                        .await
                        .err()
                        .map(|error| error.to_string()),
                        Err(error) => Some(error.to_string()),
                    };
                    if let Some(error) = creator_bootstrap_error {
                        bootstrap_retry_required = true;
                        tracing::warn!(
                            realm = %creator_bootstrap_realm_id,
                            %error,
                            "creator MLS bootstrap failed; clearing the dedup key for a retry",
                        );
                        last_error_task.set(Some(format!("creator MLS bootstrap: {error}")));
                        // Mirror the KeyPackage / Sidecar bootstrap pattern:
                        // without this reset one failure pinned the dedup key
                        // and the creator bootstrap never ran again in the
                        // session, leaving every encrypted write stuck on
                        // "MLS state is not ready".
                    } else {
                        tracing::warn!(
                            realm = %creator_bootstrap_realm_id,
                            "creator MLS bootstrap completed",
                        );
                    }
                }

                // `encryption-and-audit.md` §2.4.1 — a scope a receiver has put
                // in `epoch_update_required` stays unsendable until an accepted
                // `ak.mls.commit` attests the governance Seals it is missing.
                // Every other commit trigger in this client hangs off a
                // membership frontier change, so a capability grant, a policy
                // update, or a single-member creator group had nothing to
                // resume it. Same replay shape as the bootstrap above.
                // Materialize the list before entering the async loop. A
                // `SyncSignal::read()` temporary used directly as the `for`
                // iterator input lives for the whole loop statement; the
                // repair later needs a write lock to persist the accepted
                // snapshot. Native parking_lot merely blocks there, while
                // wasm correctly panics because its single thread cannot
                // park. Keep the read guard in this synchronous scope only.
                let pending_coverage_repairs = {
                    let state = state_store_for_probe.read();
                    crate::mls::coverage_liveness::pending_mls_coverage_repairs(
                        &state,
                        &creator_bootstrap_realm_id,
                    )
                };
                for circle_id in pending_coverage_repairs {
                    let repair_key = format!(
                        "{}|{}",
                        creator_bootstrap_realm_id,
                        circle_id.as_deref().unwrap_or("-")
                    );
                    if coverage_repair_in_flight_for_probe
                        .peek()
                        .contains(&repair_key)
                    {
                        continue;
                    }
                    coverage_repair_in_flight_for_probe
                        .write()
                        .insert(repair_key.clone());
                    tracing::warn!(
                        realm = %creator_bootstrap_realm_id,
                        circle = circle_id.as_deref().unwrap_or("-"),
                        "MLS governance coverage is stale; advancing the epoch to resume encrypted sending",
                    );
                    let coverage_error = match crate::transport::auth::authed_api_ready(
                        &detect_base,
                        detect_session.clone(),
                    )
                    .await
                    {
                        Ok(api) => crate::mls::coverage_liveness::ensure_mls_governance_coverage(
                            &api,
                            state_store_task,
                            &creator_bootstrap_realm_id,
                            circle_id.as_deref(),
                            &detect_authority,
                            &detect_device,
                        )
                        .await
                        .err(),
                        Err(error) => Some(error.to_string()),
                    };
                    coverage_repair_in_flight_for_probe
                        .write()
                        .remove(&repair_key);
                    if let Some(error) = coverage_error {
                        tracing::warn!(
                            realm = %creator_bootstrap_realm_id,
                            circle = circle_id.as_deref().unwrap_or("-"),
                            %error,
                            "MLS coverage repair failed; the scope stays paused until the next attempt",
                        );
                        last_error_task.set(Some(format!("MLS coverage repair: {error}")));
                    }
                }

                // Account-wide recovery detection is intentionally centralized
                // in `MlsRecoveryEffects`. This Realm bootstrap used to repeat
                // the same asynchronous probe and write the same global prompt
                // signals. The two independent writers could observe different
                // projection moments during first-Realm creation and made a
                // transient `needs_mls_unlock=true` permanently sticky.
                if bootstrap_retry_required {
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(5)).await;
                    let mut seen_bootstrap_key_reset = seen_bootstrap_key_for_probe;
                    if seen_bootstrap_key_reset.peek().as_deref() == Some(bootstrap_key.as_str()) {
                        seen_bootstrap_key_reset.set(None);
                    }
                }
            });
        });
    }
    rsx! {}
}
