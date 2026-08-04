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
    pub account_did: Signal<String>,
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
    pub realm_key_sharing_in_flight: Signal<bool>,
    pub realm_key_request_dedup: Signal<Option<String>>,
    pub realm_key_answer_backoff_until: Signal<crate::keyed_cooldown::KeyedCooldown>,
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
        account_did,
        device_id,
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
        realm_key_sharing_in_flight,
        realm_key_request_dedup,
        realm_key_answer_backoff_until,
        mls_welcome_bootstrap_key_seen,
        crypto_state,
        needs_mls_backup,
    } = state;
    let SessionContext {
        state_store,
        base_url,
        ..
    } = SessionContext::get();
    let did_cache = use_context::<Signal<arkret_sdk::identity::DidResolutionCache>>();
    let mls_admission_retry_attempt = use_signal(|| 0_u32);
    let mls_key_package_publish_retry_attempt = use_signal(|| 0_u32);
    let realm_key_pull_retry_key = use_signal(|| Option::<String>::None);
    let realm_key_pull_retry_attempt = use_signal(|| 0_u32);
    let sidecar_background_basis_seen = use_signal(|| Option::<String>::None);
    let sidecar_background_in_flight = use_signal(|| false);
    let sidecar_background_retry_attempt = use_signal(|| 0_u32);
    let mls_coverage_repair_in_flight = use_signal(std::collections::BTreeSet::<String>::new);

    {
        let mut seen_publish_key = mls_key_package_publish_key_seen;
        let mut publish_retry_attempt = mls_key_package_publish_retry_attempt;
        let secure_store_ready_for_publish = secure_store_bootstrap_ready;
        use_effect(move || {
            if !secure_store_ready_for_publish() {
                return;
            }
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
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let description = server_description();
            let Some(publish_key) = mls_key_package_publish_key(
                &base,
                &session,
                &actor,
                &device,
                profile_ready(description.as_ref(), ProfileId::E2EE_CLIENT_V1),
                sync_bootstrap_complete(),
            ) else {
                return;
            };
            let publish_hint = local_mls_key_package_publish_hint(&base, &actor, &device);
            let publish_key = format!("{publish_key}|kp={publish_hint}");
            if seen_publish_key().as_deref() == Some(publish_key.as_str()) {
                return;
            }
            seen_publish_key.set(Some(publish_key.clone()));
            spawn(async move {
                let attempted_publish_key = publish_key;
                match ensure_local_mls_key_package_published(base, session, actor, device).await {
                    Ok(Some(key_package_id)) => {
                        if *publish_retry_attempt.peek() != 0 {
                            publish_retry_attempt.set(0);
                        }
                        tracing::debug!(
                            key_package_id = %short_protocol_id(&key_package_id),
                            "local MLS KeyPackage is published"
                        );
                    }
                    Ok(None) => {
                        if *publish_retry_attempt.peek() != 0 {
                            publish_retry_attempt.set(0);
                        }
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
            let base = base_url();
            let credential = token();
            let actor = account_did();
            let device = device_id();
            if base.trim().is_empty()
                || credential.trim().is_empty()
                || actor.trim().is_empty()
                || device.trim().is_empty()
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
            let description = server_description();
            if !profile_ready(description.as_ref(), ProfileId::E2EE_CLIENT_V1)
                || !sync_bootstrap_complete()
            {
                return;
            }
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
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
                                device.clone(),
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
        // History sharing (encryption-and-audit.md): drain the to-device inbox
        // for this Realm, (a) installing every inbound `ak.realm_key.share`'s
        // sealed `history_secret`s so pre-join content becomes decryptable
        // (tier-3), and (b) — as a provider — answering every inbound
        // `ak.realm_key.request` by sealing the retained history range back to
        // the requester. The local to-device inbox is the data source; failed
        // receiver pulls use an explicit bounded-rate retry. A single-flight
        // guard prevents overlap.
        let share_route_uses_realm_context = route_uses_realm_context;
        let share_context_realm_id = context_realm_id.clone();
        let mut share_state_store = state_store;
        let mut share_in_flight = realm_key_sharing_in_flight;
        let mut share_request_dedup = realm_key_request_dedup;
        let mut share_answer_backoff = realm_key_answer_backoff_until;
        let mut share_pull_retry_key = realm_key_pull_retry_key;
        let mut share_pull_retry_attempt = realm_key_pull_retry_attempt;
        let mut share_realm_live_epoch = realm_live_epoch;
        let share_device_queue = device_queue;
        let share_sync_cursor = sync_cursor;
        let secure_store_ready_for_share = secure_store_bootstrap_ready;
        let share_did_cache = did_cache;
        use_effect(move || {
            // Account sync publishes the durable to-device inbox length through
            // `device_queue`. Subscribe explicitly so a newly delivered key
            // share schedules an install pass even when the active Realm and
            // every other MLS signal remain unchanged.
            let _pending_to_device_messages = share_device_queue();
            // The queue length can remain stable when one durable envelope is
            // replaced by another. The account-sync cursor is the monotonic
            // projection freshness edge, so subscribe to it as well.
            let _to_device_projection_cursor = share_sync_cursor();
            if !secure_store_ready_for_share() {
                return;
            }
            let active_realm_id = share_route_uses_realm_context
                .then(|| {
                    share_context_realm_id
                        .clone()
                        .unwrap_or_else(&*selected_realm_id)
                })
                .filter(|realm_id| !realm_id.trim().is_empty());
            let description = server_description();
            if !profile_ready(description.as_ref(), ProfileId::E2EE_CLIENT_V1)
                || !sync_bootstrap_complete()
            {
                return;
            }
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            if base.trim().is_empty()
                || session.trim().is_empty()
                || actor.trim().is_empty()
                || device.trim().is_empty()
            {
                return;
            }
            // Cheap pre-filter: drain inbound realm-key envelopes globally by
            // their own Realm binding. Provider response is a to-device duty,
            // not a page-local action; the active Realm only matters for this
            // device's receiver-initiated pull.
            let (shares_by_realm, requests, pull_request_key) = {
                let store = share_state_store.read();
                let inbox = store.to_device_inbox();
                let answer_backoff = share_answer_backoff.peek().clone();
                let now_ms = crate::clock::now_unix_ms();
                let mut shares_by_realm = BTreeMap::<String, Vec<serde_json::Value>>::new();
                for message in &inbox {
                    let kind = message
                        .get("kind")
                        .or_else(|| message.get("type"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    if kind != arkret_sdk::EventKind::REALM_KEY_SHARE {
                        continue;
                    }
                    if let Some(share_realm_id) =
                        crate::mls::runtime::realm_key_share_message_realm_id(message)
                    {
                        shares_by_realm
                            .entry(share_realm_id)
                            .or_default()
                            .push(message.clone());
                    }
                }
                let requests: Vec<_> = inbox
                    .iter()
                    .filter_map(crate::views::realm_admin::parse_realm_key_request_envelope)
                    .filter(|request| {
                        request.payload.target_principal_id.as_str().trim() == actor.trim()
                            && crate::views::realm_admin::realm_key_source_ref_str(
                                &request.payload.target_source_ref,
                            )
                            .trim()
                                == device.trim()
                            && !answer_backoff.is_cooling(
                                &crate::views::realm_admin::realm_key_request_answer_dedup_key(
                                    request,
                                ),
                                now_ms,
                            )
                    })
                    .collect();
                let pull_request_key = active_realm_id.as_ref().and_then(|realm_id| {
                    crate::views::realm_admin::pending_history_request_dedup_key(
                        &store, realm_id, &actor,
                    )
                });
                (shares_by_realm, requests, pull_request_key)
            };
            let blocked_pull_key = share_pull_retry_key();
            let needs_pull = pull_request_key.as_deref().is_some_and(|key| {
                share_request_dedup().as_deref() != Some(key)
                    && blocked_pull_key.as_deref() != Some(key)
            });
            if shares_by_realm.is_empty() && requests.is_empty() && !needs_pull {
                return;
            }
            // This is a guard, not a reactive freshness source. Subscribing to
            // it would make set(false) immediately re-enter the network pass.
            if *share_in_flight.peek() {
                return;
            }
            share_in_flight.set(true);
            // (b) Answer inbound requests (network).
            spawn(async move {
                let mut pull_completed = false;
                let mut deferred_pull_key = None::<String>;
                // (a) Install inbound shares locally. SEC-02: before verifying
                // each share's `sender_device_signature` we MUST resolve the
                // sender device's authoritative directory key, so the
                // synchronous verifier can fail-closed on a Miss (an
                // unauthenticated empty signature is no longer tolerated). The
                // resolution is a `keys/query` per missing sender device, primed
                // here into the shared device-directory cache the verifier reads.
                if !shares_by_realm.is_empty() {
                    let sender_pairs: Vec<(String, String)> = shares_by_realm
                        .values()
                        .flat_map(|shares| shares.iter())
                        .filter_map(crate::mls::runtime::realm_key_share_sender_device_pair)
                        .collect();
                    if !sender_pairs.is_empty() {
                        let _ = crate::transport::auth::with_authed_api(
                            &base,
                            session.clone(),
                            |api| async move {
                                crate::sync_engine::prefetch_device_key_pairs(
                                    &api,
                                    sender_pairs,
                                    runtime_adapter::value_cell(share_did_cache),
                                    share_state_store,
                                )
                                .await;
                                Ok::<(), anyhow::Error>(())
                            },
                        )
                        .await;
                    }
                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                    let mut installed_by_realm = BTreeMap::<String, usize>::new();
                    let mut installed_share_ids = Vec::<String>::new();
                    for (share_realm_id, shares) in &shares_by_realm {
                        for share in shares {
                            let prepared = {
                                let store = share_state_store.read();
                                crate::mls::runtime::ingest_realm_key_share(
                                    &store,
                                    secure_store.as_ref(),
                                    share_realm_id,
                                    &actor,
                                    &device,
                                    share,
                                )
                            };
                            let pending_writes = match prepared {
                                Ok(pending) => pending,
                                Err(error) => {
                                    tracing::warn!(
                                        error = %error.user_message(),
                                        realm = %short_protocol_id(share_realm_id),
                                        "prepare history_secret install failed; keeping to-device message"
                                    );
                                    continue;
                                }
                            };
                            let mut committed = 0;
                            for pending in pending_writes {
                                if let Err(error) = pending.persist(secure_store.as_ref()).await {
                                    tracing::warn!(
                                        %error,
                                        realm = %short_protocol_id(share_realm_id),
                                        "durable history_secret install failed; keeping to-device message"
                                    );
                                    committed = 0;
                                    break;
                                }
                                committed += pending.new_secret_count();
                                share_state_store.write().publish_history_secrets(pending);
                            }
                            if committed == 0 {
                                continue;
                            }
                            *installed_by_realm
                                .entry(share_realm_id.to_string())
                                .or_default() += committed;
                            if let Some(operation_id) =
                                crate::mls::runtime::realm_key_share_message_operation_id(share)
                            {
                                installed_share_ids.push(operation_id);
                            }
                        }
                    }
                    if !installed_by_realm.is_empty() {
                        // A newly durable history secret changes the local
                        // decrypt projection even though no Realm Event was
                        // ingested. Advance the same freshness axis consumed by
                        // Kanban/chat projection effects so existing locked
                        // ciphertext is immediately reprojected and decrypted.
                        share_realm_live_epoch.with_mut(|epoch| *epoch = epoch.wrapping_add(1));
                    }
                    for operation_id in installed_share_ids {
                        let _ = share_state_store
                            .write()
                            .dismiss_realm_key_share_to_device_message(&operation_id);
                    }
                    for (share_realm_id, count) in installed_by_realm {
                        tracing::info!(
                            installed = count,
                            realm = %short_protocol_id(&share_realm_id),
                            "installed history_secret(s) from ak.realm_key.share"
                        );
                    }
                }
                for request_envelope in requests {
                    let realm = request_envelope.realm_id.clone();
                    let realm_for_log = realm.clone();
                    let request_id = request_envelope.request_id.clone();
                    let request_key = crate::views::realm_admin::realm_key_request_answer_dedup_key(
                        &request_envelope,
                    );
                    let request = request_envelope.payload;
                    let actor_c = actor.clone();
                    let device_c = device.clone();
                    let outcome = crate::transport::auth::with_authed_api(
                        &base,
                        session.clone(),
                        |api| async move {
                            crate::sync_engine::prefetch_device_key_pairs(
                                &api,
                                vec![(
                                    request.recipient_principal_id.as_str().to_owned(),
                                    request.recipient_device_id.as_str().to_owned(),
                                )],
                                runtime_adapter::value_cell(share_did_cache),
                                share_state_store,
                            )
                            .await;
                            crate::views::realm_admin::share_history_to_requester(
                                &api,
                                share_state_store,
                                realm,
                                actor_c,
                                device_c,
                                &request,
                            )
                            .await
                        },
                    )
                    .await;
                    match outcome {
                        Ok(true) => {
                            share_answer_backoff.write().clear_key(&request_key);
                            if let Some(request_id) = request_id {
                                let removed = share_state_store
                                    .write()
                                    .dismiss_realm_key_request_to_device_message(&request_id);
                                if removed > 0 {
                                    tracing::debug!(
                                        request_id = %short_protocol_id(&request_id),
                                        "dismissed answered ak.realm_key.request from local inbox"
                                    );
                                }
                            }
                        }
                        Ok(false) => {
                            let until_ms = crate::clock::now_unix_ms()
                                .saturating_add(REALM_KEY_SHARE_ANSWER_RETRY_BACKOFF_MS);
                            share_answer_backoff
                                .write()
                                .note_until(request_key, until_ms);
                        }
                        Err(error) => {
                            let until_ms = crate::clock::now_unix_ms()
                                .saturating_add(REALM_KEY_SHARE_ANSWER_RETRY_BACKOFF_MS);
                            share_answer_backoff
                                .write()
                                .note_until(request_key, until_ms);
                            tracing::warn!(
                                realm = %short_protocol_id(&realm_for_log),
                                ?error,
                                "ak.realm_key.share answer failed; backing off request retry"
                            );
                        }
                    }
                }
                // (c) Receiver-initiated pull: ask a joined provider device to
                // seal the missing pre-join history range to this device. Guarded
                // by `needs_pull` (dedup against the installed-secret signature) so
                // we emit at most one request per distinct gap state.
                if needs_pull && let Some(realm) = active_realm_id {
                    let realm_for_log = realm.clone();
                    let actor_c = actor.clone();
                    let device_c = device.clone();
                    let outcome = crate::transport::auth::with_authed_api(
                        &base,
                        session.clone(),
                        |api| async move {
                            crate::views::realm_admin::request_history_keys_for_realm(
                                &api,
                                share_state_store,
                                realm,
                                actor_c,
                                device_c,
                            )
                            .await
                        },
                    )
                    .await;
                    match outcome {
                        // Record the dedup key only after a request was actually
                        // emitted. `pending_history_request_dedup_key` and the
                        // async requester read state at different times; if the
                        // second read observes a transiently incomplete inbox /
                        // projection and returns `None`, deduping would suppress
                        // the only retry path for late-join history.
                        Ok(Some(_)) => {
                            if let Some(key) = pull_request_key.clone() {
                                share_request_dedup.set(Some(key));
                            }
                            pull_completed = true;
                        }
                        Ok(None) => {
                            deferred_pull_key = pull_request_key.clone();
                        }
                        Err(error) => {
                            deferred_pull_key = pull_request_key.clone();
                            tracing::debug!(
                                realm = %short_protocol_id(&realm_for_log),
                                ?error,
                                "history key request deferred; explicit backoff scheduled"
                            );
                        }
                    }
                }
                share_in_flight.set(false);
                if pull_completed {
                    if *share_pull_retry_attempt.peek() != 0 {
                        share_pull_retry_attempt.set(0);
                    }
                    if share_pull_retry_key.peek().is_some() {
                        share_pull_retry_key.set(None);
                    }
                } else if let Some(retry_key) = deferred_pull_key {
                    // A failed pull does not mutate sync state, so "next sync"
                    // was not a scheduler. Block only this dedup key, release
                    // the shared in-flight guard for inbound work, then wake a
                    // bounded-rate retry explicitly: 2..60 seconds.
                    let attempt = *share_pull_retry_attempt.peek();
                    let retry_after_secs = (2_u64 << attempt.min(5)).min(60);
                    share_pull_retry_attempt.set(attempt.saturating_add(1).min(5));
                    if share_pull_retry_key.peek().as_deref() != Some(retry_key.as_str()) {
                        share_pull_retry_key.set(Some(retry_key.clone()));
                    }
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                        retry_after_secs,
                    ))
                    .await;
                    if share_pull_retry_key.peek().as_deref() == Some(retry_key.as_str()) {
                        share_pull_retry_key.set(None);
                    }
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
            let bootstrap_realm_id = bootstrap_context_realm_id
                .clone()
                .filter(|space| !space.trim().is_empty())
                .unwrap_or(selected);
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let description = server_description();
            let Some(bootstrap_key) = mls_welcome_bootstrap_key(
                &base,
                &session,
                &actor,
                &device,
                &bootstrap_realm_id,
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
                &actor,
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
                &actor,
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
            let detect_device = device.clone();
            let creator_bootstrap_realm_id = bootstrap_realm_id.clone();
            let state_store_for_probe = state_store_for_bootstrap;
            let mut coverage_repair_in_flight_for_probe = coverage_repair_in_flight;
            spawn(async move {
                match bootstrap_mls_welcome_for_realm(
                    base,
                    session,
                    actor,
                    device,
                    bootstrap_realm_id,
                    state_store_task,
                    needs_mls_backup_for_bootstrap,
                )
                .await
                {
                    Ok(outcome) if outcome.applied > 0 => {
                        let backup_label = outcome
                            .backup_id
                            .as_deref()
                            .map(short_protocol_id)
                            .unwrap_or_else(|| "not uploaded".to_owned());
                        crypto_state_task.set(format!(
                            "MLS Welcome applied for {realm_label}: {} group(s); history backup {backup_label}",
                            outcome.applied
                        ));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        last_error_task.set(Some(format!("MLS Welcome bootstrap: {error}")));
                    }
                }

                // A Realm creator never gets a Welcome, so the branch above
                // does nothing for them. Their epoch-0 bootstrap runs once in
                // the create wizard; if that attempt was interrupted (component
                // unmount, network failure, closed tab) the Realm is left with
                // no pinned governance anchor and no local snapshot, and every
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
                    let creator_bootstrap_error = match crate::transport::auth::authed_api(
                        &detect_base,
                        detect_session.clone(),
                    ) {
                        Ok(api) => crate::mls::creator_bootstrap::ensure_creator_realm_mls_genesis(
                            &api,
                            state_store_task,
                            &creator_bootstrap_realm_id,
                            &detect_actor,
                            &detect_device,
                        )
                        .await
                        .err()
                        .map(|error| error.to_string()),
                        Err(error) => Some(error.to_string()),
                    };
                    if let Some(error) = creator_bootstrap_error {
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
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(5)).await;
                        let mut seen_bootstrap_key_reset = seen_bootstrap_key_for_probe;
                        if seen_bootstrap_key_reset.peek().as_deref()
                            == Some(bootstrap_key.as_str())
                        {
                            seen_bootstrap_key_reset.set(None);
                        }
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
                    let coverage_error = match crate::transport::auth::authed_api(
                        &detect_base,
                        detect_session.clone(),
                    ) {
                        Ok(api) => crate::mls::coverage_liveness::ensure_mls_governance_coverage(
                            &api,
                            state_store_task,
                            &creator_bootstrap_realm_id,
                            circle_id.as_deref(),
                            &detect_actor,
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
            });
        });
    }
    rsx! {}
}
