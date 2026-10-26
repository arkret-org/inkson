use std::rc::Rc;

use glory::prelude::*;

use super::*;
use crate::presentation::InksonContext;

pub(super) fn install(scope: &Scope, context: Rc<InksonContext>) {
    let mls_key_package_publish_key_seen = scope.cage(None::<String>);
    let secure_store_bootstrap_ready = context.secure_store_bootstrap_ready;
    let device_authorization_check_complete = context.device_authorization_check_complete;
    let needs_device_authorization = context.needs_device_authorization;
    let token = context.token;
    let server_description = context.server_description;
    let sync_bootstrap_complete = context.sync_bootstrap_complete;
    let sync_cursor = context.sync_cursor;
    let realm_live_epoch = context.realm_live_epoch;
    let mls_admission_reconcile_in_flight = scope.cage(false);
    let mls_admission_reconcile_pending = scope.cage(false);
    let last_error = context.last_error;
    let mls_admission_diag_last = scope.cage(String::new());
    let selected_realm_id = context.selected_realm_id;
    let device_queue = context.device_queue;
    let mls_welcome_bootstrap_key_seen = scope.cage(None::<String>);
    let crypto_state = context.crypto_state;
    let needs_mls_backup = context.needs_mls_backup;
    let active_account = context.active_account;
    let owned_agents_rev = context.owned_agents_rev;
    // Agent creation is an explicit durable intent. Discovery runs on every
    // route and reads current identity without subscribing to its own writes.
    {
        let context = context.clone();
        let task_scope = scope.clone();
        let task_context = context.clone();
        if let Err(error) = crate::runtime_helpers::spawn_owned(&task_scope, async move {
            let state_store = task_context.state_store.clone();
            loop {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(5)).await;
                if !secure_store_bootstrap_ready.get_untracked()
                    || !sync_bootstrap_complete.get_untracked()
                {
                    continue;
                }
                let Some(account) = active_account.get_untracked().clone() else {
                    continue;
                };
                let credential = token.get_untracked().clone();
                if credential.trim().is_empty() {
                    continue;
                }
                let Some(evidence) = state_store.read(|store| store.recovery_material_evidence())
                else {
                    continue;
                };
                if evidence.account_id != account.authority
                    || evidence.device_id != account.device_id
                {
                    continue;
                }
                let Ok(vault) = crate::outbound_store::InksonOutboundStore::open(
                    &account.authority,
                    crate::outbound_store::OutboundLane::Standard,
                ) else {
                    continue;
                };
                let records = match vault.pending_agent_provisions(&account.authority).await {
                    Ok(records) => records,
                    Err(_) => continue,
                };
                for original in records {
                    if original.device_id != account.device_id
                        || original.controller_did != *account.did()
                        || original.principal_endpoint != account.server_url.as_str()
                    {
                        continue;
                    }
                    match crate::agent_identity::provision::resume_ceremony(
                        original,
                        evidence.clone(),
                        credential.clone(),
                    )
                    .await
                    {
                        Ok(_) => {
                            if active_account
                                .get_untracked()
                                .as_ref()
                                .is_some_and(|current| current.authority == account.authority)
                            {
                                let next = (owned_agents_rev.get_untracked()).saturating_add(1);
                                {
                                    let next_value = next;
                                    owned_agents_rev.revise(|current| *current = next_value)
                                };
                            }
                        }
                        Err(error) => {
                            tracing::debug!(%error, "Original Agent ceremony remains pending")
                        }
                    }
                }
            }
        }) {
            task_scope.report_error(error);
        }
    }
    // Resume explicit Device creator intents on every route, including a
    // create wizard left pending by unavailable evidence. No implicit activation.
    let creator_resume_revision = scope.cage(0_u64);
    {
        let task_scope = scope.clone();
        if let Err(error) = crate::runtime_helpers::spawn_owned(&task_scope, async move {
            let mut changes = crate::outbound_store::subscribe_creator_committed_changes();
            while changes.changed().await.is_ok() {
                let next = (creator_resume_revision.get_untracked()).wrapping_add(1);
                {
                    let next_value = next;
                    creator_resume_revision.revise(|current| *current = next_value)
                };
            }
        }) {
            task_scope.report_error(error);
        }
    }
    let creator_resume_in_flight = scope.cage(false);
    let creator_resume_error = last_error;
    {
        let context = context.clone();
        let task_scope = scope.clone();
        scope.effect(move || {
        let state_store = context.state_store.clone();
        let _ = creator_resume_revision.get();
        let _ = sync_cursor.get();
        let ready = secure_store_bootstrap_ready.get() && sync_bootstrap_complete.get();
        let account = active_account.get();
        let credential = token.get();
        if !ready || credential.trim().is_empty() || creator_resume_in_flight.get_untracked() {
            return;
        }
        let Some(account) = account else {
            return;
        };
        { let next_value = true; creator_resume_in_flight.revise(|current| *current = next_value) };
        // A resource would observe checkpoint writes inside its future and
        // cancel itself at every install. Spawn the serial worker outside the
        // reactive read context; the durable FSM remains the recovery fence.
        if let Err(error) = crate::runtime_helpers::spawn_owned(&task_scope, async move {
            let result = async {
                let api = crate::transport::auth::authed_api_ready(account.server_url.as_str(), credential).await?;
                let submitter = api.event_submitter()?;
                let records = submitter.creator_bootstrap_records().await?;
                let mut pending = false;
                for record in records {
                    if !matches!(record.intent().effective_scope(), arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Circle { .. })
                        || record.intent().creator_device_id() != &account.device_id
                        || record.ready_receipt().is_some() || record.rejection().is_some()
                        || record.superseded_winner().is_some() || record.quarantine_diagnostic().is_some() {
                        continue;
                    }
                    let state = state_store.handle();
                    let resumed = match record.intent().effective_scope() {
                        arkret_sdk::ScopeRef::Circle { .. } => crate::mls::creator_bootstrap::ensure_creator_circle_mls_genesis(
                            &api, &state, record.intent().effective_scope(), &account.authority, &account.device_id, false,
                        ).await,
                        arkret_sdk::ScopeRef::Realm { realm_id } => crate::mls::creator_bootstrap::ensure_creator_realm_mls_genesis(
                            &api, &state, realm_id.as_str(), &account.authority, &account.device_id,
                        ).await,
                        _ => continue,
                    };
                    if let Err(error) = resumed {
                        pending = true;
                        { let next_value = Some(format!("Creator MLS bootstrap: {error}")); creator_resume_error.revise(|current| *current = next_value) };
                        tracing::debug!(scope = ?record.intent().effective_scope(), %error, "Creator remains pending");
                    }
                }
                Ok::<_, anyhow::Error>(pending)
            }.await;
            let retry = !matches!(result, Ok(false));
            if !retry
                && creator_resume_error
                    .get_untracked()
                    .as_ref()
                    .is_some_and(|error| error.starts_with("Creator MLS bootstrap:"))
            {
                { let next_value = None; creator_resume_error.revise(|current| *current = next_value) };
            }
            if retry {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(5)).await;
            }
            { let next_value = false; creator_resume_in_flight.revise(|current| *current = next_value) };
            if retry {
                let next = (creator_resume_revision.get_untracked()).wrapping_add(1);
                { let next_value = next; creator_resume_revision.revise(|current| *current = next_value) };
            }
        }) { task_scope.report_error(error); }
    });
    }
    let mls_admission_retry_attempt = scope.cage(0_u32);
    let mls_key_package_publish_retry_attempt = scope.cage(0_u32);
    let mls_coverage_repair_in_flight = scope.cage(std::collections::BTreeSet::<String>::new());
    let accepted_artifact_basis_seen = scope.cage(Option::<String>::None);
    let accepted_artifact_convergence_in_flight = scope.cage(false);

    {
        let ready = secure_store_bootstrap_ready;
        let sync_ready = sync_bootstrap_complete;
        let sync_freshness = sync_cursor;
        let basis_seen = accepted_artifact_basis_seen;
        let in_flight = accepted_artifact_convergence_in_flight;
        let convergence_error = last_error;
        let convergence_token = token;
        {
            let context = context.clone();
            let task_scope = scope.clone();
            scope.effect(move || {
                let state_store = context.state_store.clone();
                let convergence_store = state_store.clone();
                let Some(account) = active_account.get() else {
                    return;
                };
                let cursor = sync_freshness.get();
                let verified_realm_epoch = realm_live_epoch.get();
                let actor = account.principal_id().to_string();
                let device = account.device_id.clone();
                let authority = account.authority.clone();
                let base = account.server_url.to_string();
                let session = convergence_token.get();
                if session.trim().is_empty() {
                    return;
                }
                if !ready.get()
                    || !sync_ready.get()
                    || cursor.trim().is_empty()
                    || actor.trim().is_empty()
                    || in_flight.get()
                {
                    return;
                }
                // A Welcome can precede the independently verified Realm cut.
                // Retry when that cut advances, even without an Account cursor.
                let basis = format!("{actor}|{device}|{cursor}|{verified_realm_epoch}");
                if basis_seen.get_untracked().as_deref() == Some(basis.as_str()) {
                    return;
                }
                {
                    let next_value = Some(basis.clone());
                    basis_seen.revise(|current| *current = next_value)
                };
                {
                    let next_value = true;
                    in_flight.revise(|current| *current = next_value)
                };
                if let Err(error) = crate::runtime_helpers::spawn_owned(&task_scope, async move {
                    let convergence_store = convergence_store.handle();
                    // Resolving the accepted Commit a pending Welcome names is a
                    // read of the scope's own independent stream, so convergence
                    // needs an authenticated client, not only the local store.
                    let converged =
                        match crate::transport::auth::authed_api_ready(&base, session).await {
                            Ok(api) => {
                                crate::mls::runtime::converge_accepted_mls_artifacts(
                                    &api,
                                    &convergence_store,
                                    &authority,
                                    &device,
                                )
                                .await
                            }
                            Err(error) => Err(error.to_string()),
                        };
                    let retry = match converged {
                        Ok(applied) => {
                            if applied > 0 {
                                tracing::info!(applied, "accepted MLS artifacts converged durably");
                            }
                            // A pass can apply nothing while a retained Welcome waits
                            // for its independent Commit, claim, or private material.
                            // Retry even when no new Account cursor is forthcoming.
                            convergence_store.read(|store| {
                                crate::mls::runtime::has_pending_mls_welcome_for_endpoint(
                                    store, &authority, &device,
                                )
                            })
                        }
                        Err(error) => {
                            tracing::warn!(%error, "accepted MLS artifact convergence is pending");
                            {
                                let next_value =
                                    Some(format!("accepted artifact convergence: {error}"));
                                convergence_error.revise(|current| *current = next_value)
                            };
                            true
                        }
                    };
                    if retry {
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(5)).await;
                        if basis_seen.get_untracked().as_deref() == Some(basis.as_str()) {
                            {
                                let next_value = None;
                                basis_seen.revise(|current| *current = next_value)
                            };
                        }
                    }
                    {
                        let next_value = false;
                        in_flight.revise(|current| *current = next_value)
                    };
                }) {
                    task_scope.report_error(error);
                }
            });
        }
    }

    {
        let seen_publish_key = mls_key_package_publish_key_seen;
        let publish_retry_attempt = mls_key_package_publish_retry_attempt;
        let secure_store_ready_for_publish = secure_store_bootstrap_ready;
        {
            let context = context.clone();
            let task_scope = scope.clone();
            scope.effect(move || {
                let _ = context.state_revision.get();
                let state_store = context.state_store.clone();
                if !secure_store_ready_for_publish.get() {
                    return;
                }
                // Subscribe to the accepted account before consulting the
                // process-local signer. The signer registry is not reactive; on
                // first enrollment it is activated immediately before this
                // signal is committed, so the account transition is what wakes
                // this effect after its unauthenticated first render.
                let Some(account) = active_account.get() else {
                    return;
                };
                if crate::event_signer::active_signer().is_none() {
                    return;
                }
                // Gate on device authorization. Publishing a KeyPackage requires an
                // ACCEPTED `ak.device.authorize` — coland rejects the upload with
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
                if !device_authorization_check_complete.get() || needs_device_authorization.get() {
                    return;
                }
                let base = account.server_url.to_string();
                let session = token.get();
                let device = account.device_id.clone();
                let authority = account.authority.clone();
                if state_store.read(|store| store.session_grant().is_none()) {
                    return;
                }
                let description = server_description.get();
                let Some(publish_key) = mls_key_package_publish_key(
                    &account.server_url,
                    &session,
                    &account.authority,
                    &account.device_id,
                    StationFeature::PublishKeyPackage.ready(description.as_ref()),
                    sync_bootstrap_complete.get(),
                ) else {
                    return;
                };
                let publish_hint = local_mls_key_package_publish_hint(&base, &authority, &device);
                let publish_key = format!("{publish_key}|kp={publish_hint}");
                if seen_publish_key.get().as_deref() == Some(publish_key.as_str()) {
                    return;
                }
                {
                    let next_value = Some(publish_key.clone());
                    seen_publish_key.revise(|current| *current = next_value)
                };
                if let Err(error) = crate::runtime_helpers::spawn_owned(&task_scope, async move {
                    let attempted_publish_key = publish_key;
                    let published = ensure_local_mls_key_package_inventory(
                        base.clone(),
                        session.clone(),
                        authority.clone(),
                        device.clone(),
                    )
                    .await;
                    match published {
                        Ok(_) => {
                            if publish_retry_attempt.get_untracked() != 0 {
                                {
                                    let next_value = 0;
                                    publish_retry_attempt.revise(|current| *current = next_value)
                                };
                            }
                            tracing::debug!("local MLS KeyPackage inventory is published");
                        }
                        Err(error) => {
                            tracing::warn!(%error, "MLS KeyPackage publish bootstrap failed");
                            let attempt = publish_retry_attempt.get_untracked();
                            let retry_after_secs = (2_u64 << attempt.min(5)).min(60);
                            {
                                let next_value = attempt.saturating_add(1).min(5);
                                publish_retry_attempt.revise(|current| *current = next_value)
                            };
                            crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                                retry_after_secs,
                            ))
                            .await;
                            if seen_publish_key.get_untracked().as_deref()
                                == Some(attempted_publish_key.as_str())
                            {
                                {
                                    let next_value = None;
                                    seen_publish_key.revise(|current| *current = next_value)
                                };
                            }
                        }
                    }
                }) {
                    task_scope.report_error(error);
                }
            });
        }
    }
    {
        // Admin-side MLS admission reconciliation — the producer counterpart of
        // the invitee Welcome bootstrap below. When a member actually joins an
        // encrypted Realm this device administers, (re)admit anyone not yet in
        // the MLS group so their `ak.mls.welcome` is finally produced. Closes
        // the invite-time race where admission ran before the invitee had
        // published a KeyPackage: re-runs when the durable Realm projection
        // changes. Account sync is also a wake-up axis because a same-account
        // fresh device adds no Realm membership Event: its accepted device
        // authorization is what must trigger a targeted Add/Welcome attempt.
        let admit_realm_live_epoch = realm_live_epoch;
        let admit_account_cursor = sync_cursor;
        let admit_in_flight = mls_admission_reconcile_in_flight;
        let admit_pending = mls_admission_reconcile_pending;
        let admit_retry_attempt = mls_admission_retry_attempt;
        let admit_last_error = last_error;
        let admit_diag_last = mls_admission_diag_last;
        let secure_store_ready_for_admit = secure_store_bootstrap_ready;
        {
            let context = context.clone();
            let task_scope = scope.clone();
            scope.effect(move || {
            let state_store = context.state_store.clone();
            let admit_state_store = state_store.clone();
            if !secure_store_ready_for_admit.get() {
                return;
            }
            let Some(account) = active_account.get() else {
                return;
            };
            let base = account.server_url.to_string();
            let description = server_description.get();
            if !StationFeature::MlsAdmission.ready(description.as_ref())
                || !sync_bootstrap_complete.get()
            {
                return;
            }
            let session = token.get();
            let actor = account.principal_id().to_string();
            let device = account.device_id.clone();
            if base.trim().is_empty() || session.trim().is_empty() || actor.trim().is_empty() {
                return;
            }
            // Durable Realm changes are the admission freshness axis. The
            // account cursor additionally wakes same-account endpoint
            // admission after a device authorization. It remains only a
            // scheduling hint; reconciliation re-reads the durable device list
            // and accepted Realm history before authoring anything.
            let _ = admit_realm_live_epoch.get();
            let _ = admit_account_cursor.get();
            let _ = admit_pending.get();
            let candidate_realms = admit_state_store.read(|store| {
                // The durable Realm epoch is the projection trigger.
                crate::mls::admission_reconcile::mls_admission_candidate_realms_for_actor(
                    store, &actor,
                )
            });
            if candidate_realms.is_empty() {
                // Make a stuck admin observable. wasm tracing is capped at
                // WARN, so INFO/DEBUG here would be invisible — emit a
                // throttled WARN naming the blocking cause.
                let Some(diag) = admit_state_store.read(|store| {
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
                            .mls_local_checkpoints()
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
                if admit_diag_last.get() != diag {
                    { let next_value = diag.clone(); admit_diag_last.revise(|current| *current = next_value) };
                    tracing::warn!(
                        target: "mls_admission",
                        %diag,
                        "admission pre-filter blocked: no local encrypted Realm has an admission-capable MLS snapshot"
                    );
                }
                return;
            }
            let candidate_diag = candidate_realms
                .iter()
                .map(|(realm_id, joined_sig)| format!("{realm_id}:joined=[{joined_sig}]"))
                .collect::<Vec<_>>()
                .join("|");
            if admit_diag_last.get() != candidate_diag {
                { let next_value = candidate_diag.clone(); admit_diag_last.revise(|current| *current = next_value) };
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
            if admit_in_flight.get_untracked() {
                // Write ONLY on a real false→true transition. This effect
                // subscribes to `admit_pending` (see the `admit_pending.get()`
                // read above), and a plain `set()` marks the signal dirty even
                // when the value is unchanged — so an unconditional set() here
                // would re-fire this very effect and spin the main thread
                // (same class as the in_flight self-spin fixed earlier).
                if !admit_pending.get_untracked() {
                    { let next_value = true; admit_pending.revise(|current| *current = next_value) };
                }
                return;
            }
            // Same guard on the reset path: an unconditional `set(false)` runs
            // on every non-in-flight pass and is the loop seed — it retriggers
            // the subscribed effect with no external change. Only clear a flag
            // that is actually set.
            if admit_pending.get_untracked() {
                { let next_value = false; admit_pending.revise(|current| *current = next_value) };
            }
            { let next_value = true; admit_in_flight.revise(|current| *current = next_value) };
            if let Err(error) = crate::runtime_helpers::spawn_owned(&task_scope, async move {
                let outcome =
                    crate::transport::auth::with_authed_api(&base, session, |api| async move {
                        let mut admitted_total = 0_usize;
                        let mut deferred_total = 0_usize;
                        let mut failures = Vec::<String>::new();
                        for (realm_id, _) in candidate_realms {
                            match crate::mls::admission_reconcile::reconcile_mls_admissions_for_realm(
                                &api,
                                &admit_state_store.handle(),
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
                let retry_needed = outcome
                    .as_ref()
                    .map(|(_, deferred, failures)| *deferred > 0 || !failures.is_empty())
                    .unwrap_or(true);
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
                            { let next_value = Some(format!(
                                "MLS admission reconcile: {}",
                                failures.join("; ")
                            )); admit_last_error.revise(|current| *current = next_value) };
                        }
                    }
                    Ok((_, _, failures)) if !failures.is_empty() => {
                        tracing::warn!(
                            target: "mls_admission",
                            failures = %failures.join("; "),
                            "MLS admission reconcile failed for all attempted Realm candidates"
                        );
                        { let next_value = Some(format!(
                            "MLS admission reconcile: {}",
                            failures.join("; ")
                        )); admit_last_error.revise(|current| *current = next_value) };
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(
                            target: "mls_admission",
                            ?error,
                            "MLS admission reconcile failed"
                        );
                        { let next_value = Some(format!("MLS admission reconcile: {error:?}")); admit_last_error.revise(|current| *current = next_value) };
                    }
                }

                if retry_needed {
                    // KeyPackage publication and a transient canonical-history
                    // read failure need not produce another Realm event, so an
                    // unrelated account cursor is neither a reliable nor a
                    // bounded retry clock. Hold the single-flight guard across
                    // an explicit exponential delay, then release one
                    // coalesced retry: 2, 4, 8, 16, 32, 60 seconds.
                    let attempt = admit_retry_attempt.get_untracked();
                    let retry_after_secs = (2_u64 << attempt.min(5)).min(60);
                    { let next_value = attempt.saturating_add(1).min(5); admit_retry_attempt.revise(|current| *current = next_value) };
                    if !admit_pending.get_untracked() {
                        { let next_value = true; admit_pending.revise(|current| *current = next_value) };
                    }
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                        retry_after_secs,
                    ))
                    .await;
                } else if admit_retry_attempt.get_untracked() != 0 {
                    { let next_value = 0; admit_retry_attempt.revise(|current| *current = next_value) };
                }
                { let next_value = false; admit_in_flight.revise(|current| *current = next_value) };
                if admit_pending.get_untracked() {
                    // This transition is the single subscribed retry edge.
                    { let next_value = false; admit_pending.revise(|current| *current = next_value) };
                }
            }) { task_scope.report_error(error); }
        });
        }
    }
    {
        let seen_bootstrap_key = mls_welcome_bootstrap_key_seen;
        let crypto_state_for_bootstrap = crypto_state;
        let last_error_for_bootstrap = last_error;
        let needs_mls_backup_for_bootstrap = needs_mls_backup;
        let secure_store_ready_for_bootstrap = secure_store_bootstrap_ready;
        let welcome_device_queue = device_queue;
        let coverage_repair_in_flight = mls_coverage_repair_in_flight;
        // Route props are not Signals: explicitly subscribe to them so entering
        // a Realm from Contacts/Settings (or switching Realms) wakes bootstrap
        // even when the session, inbox and remembered selection are unchanged.
        {
            let context = context.clone();
            let task_scope = scope.clone();
            scope.effect(move || {
            let _ = context.state_revision.get();
            let state_store = context.state_store.clone();
            let state_store_for_bootstrap = state_store.clone();
            let route = context.route.get();
            let selected = selected_realm_id.get();
            let controls = state_store.read(|store| super::sidebar::principal_control_realm_ids(&store.load()));
            let bootstrap_route_uses_realm_context = super::realm_surface::route_uses_realm_context(&route)
                && !route.realm_id().is_some_and(|id| controls.contains(id));
            let bootstrap_context_realm_id = super::shell_model::resolve_realm_selection(route.realm_id(), &selected, &controls).effective_realm_id;
            // Account sync journals to-device envelopes in the shared store,
            // then publishes the durable inbox length through `device_queue`.
            // Subscribe explicitly so a Welcome delivered after an earlier
            // empty bootstrap probe re-runs this realm-specific consumer.
            let _pending_to_device_messages = welcome_device_queue.get();
            if !secure_store_ready_for_bootstrap.get() {
                return;
            }
            let selected = selected_realm_id.get();
            if !bootstrap_route_uses_realm_context {
                return;
            }
            let Some(account) = active_account.get() else {
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
            let session = token.get();
            let actor = account.principal_id().to_string();
            let description = server_description.get();
            let Some(bootstrap_key) = mls_welcome_bootstrap_key(
                &account.server_url,
                &session,
                &account.authority,
                &account.device_id,
                &realm_id,
                StationFeature::WelcomeBootstrap.ready(description.as_ref()),
                sync_bootstrap_complete.get(),
            ) else {
                return;
            };
            // BUG X4: the per-Realm bootstrap caches its `seen` key, so after
            // the user's first encrypted write *creates* the account MLS
            // secret (and this Realm's MLS snapshot) the detection would
            // never re-run and the backup prompt would never appear. Read a
            // `state_store` signal in the synchronous body (`has_local_mls_checkpoint`)
            // so the effect re-runs this effect when the write saves the snapshot,
            // and fold both the local account-secret presence (`sec=`) and the
            // snapshot presence (`snap=`) into the key so the `seen` guard no
            // longer matches once they flip false→true. The matching local
            // Welcome hint is also folded in so a sync-delivered pending
            // Welcome retriggers the drain after an earlier empty probe.
            let (has_local_mls_checkpoint, has_encrypted_realm_projection, local_mls_epoch_floor, recovery_key_fingerprint, local_pending_welcome_hint, coverage_repair_hint) = state_store_for_bootstrap.read(|state_for_bootstrap_key| {
            let has_local_mls_checkpoint = state_for_bootstrap_key
                .mls_checkpoint_for(&bootstrap_realm_id)
                .is_some();
            let has_encrypted_realm_projection =
                state_for_bootstrap_key.realm_projection_is_mls_encrypted(&bootstrap_realm_id);
            let local_mls_epoch_floor = crate::mls::runtime::mls_restore_epoch_floor(
                state_for_bootstrap_key,
                &bootstrap_realm_id,
            );
            let recovery_key_fingerprint =
                crate::views::recovery::local_recovery_key_fingerprint(state_for_bootstrap_key)
                    .unwrap_or_default();
            let local_pending_welcome_hint =
                crate::mls::welcome_delivery::local_mls_welcome_hint_for_realm(
                    &state_for_bootstrap_key.welcome_inbox_for_scope(
                        &arkret_sdk::ScopeRef::Realm {
                            realm_id: realm_id.clone(),
                        },
                    ),
                    &bootstrap_realm_id,
                );
            let coverage_repair_hint =
                crate::mls::coverage_liveness::mls_coverage_repair_dedup_hint(
                    state_for_bootstrap_key,
                    &bootstrap_realm_id,
                );
            (has_local_mls_checkpoint, has_encrypted_realm_projection, local_mls_epoch_floor, recovery_key_fingerprint, local_pending_welcome_hint, coverage_repair_hint)
            });
            let has_local_account_secret = crate::mls::runtime::load_account_mls_secret(
                crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
                &authority,
            )
            .map(|secret| secret.is_some())
            .unwrap_or(false);
            let bootstrap_key = format!(
                "{bootstrap_key}|sec={has_local_account_secret}|snap={has_local_mls_checkpoint}|enc={has_encrypted_realm_projection}|epoch={local_mls_epoch_floor}|rk={recovery_key_fingerprint}|welcome={local_pending_welcome_hint}|coverage={coverage_repair_hint}|keys={}",
                crate::app::local_mls_key_material_hint(&authority, &device).unwrap_or_default()
            );
            if seen_bootstrap_key.get().as_deref() == Some(bootstrap_key.as_str()) {
                return;
            }
            { let next_value = Some(bootstrap_key.clone()); seen_bootstrap_key.revise(|current| *current = next_value) };
            let seen_bootstrap_key_for_probe = seen_bootstrap_key;

            let state_store_task = state_store_for_bootstrap.clone();
            let crypto_state_task = crypto_state_for_bootstrap;
            let last_error_task = last_error_for_bootstrap;
            let realm_label = short_protocol_id(&bootstrap_realm_id);
            // Detection-step clones: the originals are moved into the Welcome
            // bootstrap call below; we reuse these for the account-secret
            // unlock probe afterwards.
            let detect_base = base.clone();
            let detect_session = session.clone();
            let detect_authority = authority.clone();
            let detect_device = device.clone();
            let creator_bootstrap_realm_id = bootstrap_realm_id.clone();
            let state_store_for_probe = state_store_for_bootstrap;
            let coverage_repair_in_flight_for_probe = coverage_repair_in_flight;
            let task_context = context.clone();
            if let Err(error) = crate::runtime_helpers::spawn_owned(&task_scope, async move {
                let state_store_task =
                    state_store_task.handle();
                let mut bootstrap_retry_required = false;
                let creator_result = match crate::transport::auth::authed_api_ready(
                    &detect_base,
                    detect_session.clone(),
                )
                .await
                {
                    Ok(api) => {
                        match crate::mls::creator_bootstrap::should_resume_creator_genesis(
                            &api,
                            &state_store_task,
                            &creator_bootstrap_realm_id,
                            &detect_authority,
                        )
                        .await
                        {
                            Ok(true) => Some((api, true)),
                            Ok(false) => Some((api, false)),
                            Err(error) => {
                                bootstrap_retry_required = true;
                                { let next_value = Some(error); last_error_task.revise(|current| *current = next_value) };
                                None
                            }
                        }
                    }
                    Err(error) => {
                        bootstrap_retry_required = true;
                        { let next_value = Some(error.to_string()); last_error_task.revise(|current| *current = next_value) };
                        None
                    }
                };
                if let Some((api, true)) = creator_result {
                    tracing::warn!(
                        realm = %creator_bootstrap_realm_id,
                        "creator MLS bootstrap pending; replaying epoch-0 setup + ak.mls.genesis",
                    );
                    let creator_bootstrap_error =
                        crate::mls::creator_bootstrap::ensure_creator_realm_mls_genesis(
                            &api,
                            &state_store_task,
                            &creator_bootstrap_realm_id,
                            &detect_authority,
                            &detect_device,
                        )
                        .await
                        .err();
                    if let Some(error) = creator_bootstrap_error {
                        bootstrap_retry_required = true;
                        tracing::warn!(
                            realm = %creator_bootstrap_realm_id,
                            %error,
                            "creator MLS bootstrap failed; clearing the dedup key for a retry",
                        );
                        { let next_value = Some(format!("creator MLS bootstrap: {error}")); last_error_task.revise(|current| *current = next_value) };
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
                } else if matches!(creator_result, Some((_, false))) {
                    match bootstrap_mls_welcome_for_realm(
                        task_context.clone(),
                        base,
                        session,
                        actor,
                        authority,
                        device,
                        bootstrap_realm_id,
                        &state_store_task,
                        Some(needs_mls_backup_for_bootstrap),
                    )
                    .await
                    {
                        Ok(outcome) if outcome.applied > 0 => {
                            { let next_value = format!(
                                "MLS Welcome applied for {realm_label}: {} group(s); local MLS state is durable",
                                outcome.applied
                            ); crypto_state_task.revise(|current| *current = next_value) };
                        }
                        Ok(_) => {}
                        Err(error) => {
                            bootstrap_retry_required = true;
                            tracing::warn!(realm = %realm_label, %error, "MLS Welcome bootstrap remains pending");
                            { let next_value = Some(format!("MLS Welcome bootstrap: {error}")); last_error_task.revise(|current| *current = next_value) };
                        }
                    }
                }

                // `encryption-and-audit.md` §2.4.1 — a scope a receiver has put
                // in `epoch_update_required` stays unsendable until an accepted
                // transition covers its current membership key-access revision.
                // Policy and endpoint changes do not advance that revision.
                // Materialize the list before entering the async loop. A
                // `SyncSignal::read()` temporary used directly as the `for`
                // iterator input lives for the whole loop statement; the
                // repair later needs a write lock to persist the accepted
                // snapshot. Native parking_lot merely blocks there, while
                // wasm correctly panics because its single thread cannot
                // park. Keep the read guard in this synchronous scope only.
                let pending_coverage_repairs = state_store_for_probe.read(|state| {
                    crate::mls::coverage_liveness::pending_mls_coverage_repairs(
                        state,
                        &creator_bootstrap_realm_id,
                    )
                });
                for circle_id in pending_coverage_repairs {
                    let repair_key = format!(
                        "{}|{}",
                        creator_bootstrap_realm_id,
                        circle_id.as_deref().unwrap_or("-")
                    );
                    if coverage_repair_in_flight_for_probe
                        .get_untracked()
                        .contains(&repair_key)
                    {
                        continue;
                    }
                    coverage_repair_in_flight_for_probe.revise(|keys| keys.insert(repair_key.clone()));
                    tracing::warn!(
                        realm = %creator_bootstrap_realm_id,
                        circle = circle_id.as_deref().unwrap_or("-"),
                        "MLS governance coverage is stale; advancing the epoch to resume encrypted sending",
                    );
                    let coverage_result = match crate::transport::auth::authed_api_ready(
                        &detect_base,
                        detect_session.clone(),
                    )
                    .await
                    {
                        Ok(api) => {
                            crate::mls::coverage_liveness::ensure_mls_governance_coverage(
                                &api,
                                &state_store_task,
                                &creator_bootstrap_realm_id,
                                circle_id.as_deref(),
                                &detect_authority,
                                &detect_device,
                            )
                            .await
                        }
                        Err(error) => Err(error.to_string()),
                    };
                    coverage_repair_in_flight_for_probe.revise(|keys| keys.remove(&repair_key));
                    let error_prefix = format!("MLS coverage repair [{repair_key}]:");
                    bootstrap_retry_required |= coverage_result != Ok(true);
                    if let Err(error) = coverage_result {
                        tracing::warn!(
                            realm = %creator_bootstrap_realm_id,
                            circle = circle_id.as_deref().unwrap_or("-"),
                            %error,
                            "MLS coverage repair failed; the scope stays paused until the next attempt",
                        );
                        { let next_value = Some(format!("{error_prefix} {error}")); last_error_task.revise(|current| *current = next_value) };
                    } else if coverage_result == Ok(true)
                        && last_error_task
                            .get_untracked()
                            .as_ref()
                            .is_some_and(|error| error.starts_with(&error_prefix))
                    {
                        { let next_value = None; last_error_task.revise(|current| *current = next_value) };
                    }
                }

                // An invitee can enter the Realm before its administrator has
                // finished the durable Commit -> Welcome saga. An empty first
                // probe is therefore a convergence state, not a completed
                // bootstrap. Keep polling the standard device-message plane
                // while the accepted encrypted Realm has no local group
                // snapshot; relying only on an unrelated account cursor edge
                // can strand the one-time Welcome indefinitely.
                let encrypted_realm_still_awaits_local_mls_state = state_store_for_probe.read(|state| {
                    state.realm_projection_is_mls_encrypted(&creator_bootstrap_realm_id)
                        && state
                            .mls_checkpoint_for(&creator_bootstrap_realm_id)
                            .is_none()
                });
                bootstrap_retry_required |= encrypted_realm_still_awaits_local_mls_state;

                // Account-wide recovery detection is intentionally centralized
                // in `MlsRecoveryEffects`. This Realm bootstrap used to repeat
                // the same asynchronous probe and write the same global prompt
                // signals. The two independent writers could observe different
                // projection moments during first-Realm creation and made a
                // transient `needs_mls_unlock=true` permanently sticky.
                if bootstrap_retry_required {
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(5)).await;
                    let seen_bootstrap_key_reset = seen_bootstrap_key_for_probe;
                    if seen_bootstrap_key_reset.get_untracked().as_deref() == Some(bootstrap_key.as_str()) {
                        { let next_value = None; seen_bootstrap_key_reset.revise(|current| *current = next_value) };
                    }
                }
            }) { task_scope.report_error(error); }
        });
        }
    }
}
