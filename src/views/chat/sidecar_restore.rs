use super::*;

#[cfg(test)]
thread_local! {
    static RESTORE_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A local wake revision, never an authority or a persisted checkpoint. The
/// upstream memo compares exact content/security inputs before notifying us.
fn use_restore_basis_revision(
    basis: Memo<super::timeline_projection::TimelineProjectionBasis>,
) -> Memo<u64> {
    let counter = use_hook(|| std::rc::Rc::new(std::cell::Cell::new(0_u64)));
    use_memo(move || {
        let _ = basis.read();
        let next = counter.get().wrapping_add(1);
        counter.set(next);
        next
    })
}

struct RestoreRetryEntry {
    running: bool,
    available_at: Option<chrono::DateTime<chrono::Utc>>,
    retries: std::collections::VecDeque<chrono::DateTime<chrono::Utc>>,
    schedule: arkret_sdk::RetrySchedule,
}

#[derive(Default)]
struct RestoreRetryBook {
    // This book serves only agent_sidecar_get. Complete AccountId includes the
    // Station/service identity; cards, devices and remounts share its budget.
    endpoints: std::collections::BTreeMap<arkret_sdk::AccountId, RestoreRetryEntry>,
}

enum RestoreAdmission {
    Admitted,
    Wait(std::time::Duration),
}

impl RestoreRetryBook {
    fn claim(
        &mut self,
        account: &arkret_sdk::AccountId,
        now: chrono::DateTime<chrono::Utc>,
        retrying: bool,
    ) -> RestoreAdmission {
        let entry = self
            .endpoints
            .entry(account.clone())
            .or_insert_with(|| RestoreRetryEntry {
                running: false,
                available_at: None,
                retries: Default::default(),
                schedule: arkret_sdk::RetrySchedule::arkret_default().with_jitter(
                    arkret_retry::SPEC_JITTER_RATIO,
                    now.timestamp_millis() as u64,
                ),
            });
        let window = chrono::Duration::seconds(arkret_retry::SPEC_RETRY_WINDOW.as_secs() as i64);
        while entry.retries.front().is_some_and(|at| now - *at >= window) {
            entry.retries.pop_front();
        }
        if entry.running {
            return RestoreAdmission::Wait(std::time::Duration::from_millis(250));
        }
        let mut available_at = entry.available_at.unwrap_or(now);
        let retry = retrying || entry.available_at.is_some();
        if retry && entry.retries.len() >= arkret_retry::SPEC_MAX_RETRIES as usize {
            if let Some(first) = entry.retries.front() {
                available_at = available_at.max(*first + window);
            }
        }
        if available_at > now {
            return RestoreAdmission::Wait((available_at - now).to_std().unwrap_or_default());
        }
        if retry {
            entry.retries.push_back(now);
        }
        entry.running = true;
        RestoreAdmission::Admitted
    }

    fn finish(
        &mut self,
        account: &arkret_sdk::AccountId,
        now: chrono::DateTime<chrono::Utc>,
        retry_hint: Option<Option<std::time::Duration>>,
    ) {
        let Some(entry) = self.endpoints.get_mut(account) else {
            return;
        };
        entry.running = false;
        if let Some(hint) = retry_hint {
            let delay = entry.schedule.next_delay_with_hint(hint);
            entry.available_at = Some(
                chrono::Duration::from_std(delay)
                    .ok()
                    .and_then(|delay| now.checked_add_signed(delay))
                    .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC),
            );
        } else {
            entry.available_at = None;
            entry.schedule.reset();
        }
    }
}

fn restore_retry_book() -> &'static std::sync::Mutex<RestoreRetryBook> {
    static BOOK: std::sync::OnceLock<std::sync::Mutex<RestoreRetryBook>> =
        std::sync::OnceLock::new();
    BOOK.get_or_init(Default::default)
}

struct RestoreAttempt(arkret_sdk::AccountId);

impl Drop for RestoreAttempt {
    fn drop(&mut self) {
        let mut book = restore_retry_book()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = book.endpoints.get_mut(&self.0) {
            entry.running = false;
        }
    }
}

fn restore_reqwest_transient(error: &reqwest::Error) -> bool {
    if error.is_timeout() {
        return true;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        error.is_connect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        // Fetch promise rejection is typed as Request; Builder, Decode and
        // Status failures remain permanent rather than becoming transport retries.
        error.is_request()
    }
}

fn restore_retry_hint(error: &anyhow::Error) -> Option<Option<std::time::Duration>> {
    if let Some((status, problem)) = crate::api_error::api_error_status_and_envelope(error) {
        if (status == reqwest::StatusCode::TOO_MANY_REQUESTS && problem.code() == "rate_limited")
            || (status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                && problem.code() == "temporarily_unavailable")
        {
            return Some(
                problem
                    .retry_after_ms()
                    .map(std::time::Duration::from_millis),
            );
        }
        return None;
    }
    error
        .chain()
        .any(|cause| {
            matches!(
                cause.downcast_ref::<arkret_sdk::http_client::Error>(),
                Some(arkret_sdk::http_client::Error::Http(_))
            ) || matches!(
                cause.downcast_ref::<arkret_sdk::Error>(),
                Some(arkret_sdk::Error::Http(_))
            ) || cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(restore_reqwest_transient)
        })
        .then_some(None)
}

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
    device_id: arkret_sdk::DeviceId,
    token: Signal<String>,
    timeline_basis: Memo<super::timeline_projection::TimelineProjectionBasis>,
    state_store: SyncSignal<LocalStateStore>,
) {
    let mut hosted = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    let mut seen = use_signal(String::new);
    let mut generation = use_signal(|| 0_u64);
    let basis_revision = use_restore_basis_revision(timeline_basis);
    use_effect(use_reactive!(|(
        base_url,
        realm_id,
        strand_id,
        authority,
        device_id,
    )| {
        let credential = token();
        let revision = basis_revision();
        let key = format!(
            "{base_url}|{authority}|{device_id}|{realm_id}|{strand_id}|{revision}|{}|{credential}",
            crate::identity::device_directory::session_cache_epoch(),
        );
        if *seen.peek() == key {
            return;
        }
        seen.set(key);
        let next = generation.peek().wrapping_add(1);
        generation.set(next);
        let Ok(strand) = arkret_sdk::StrandId::new(strand_id.clone()) else {
            return;
        };
        #[cfg(test)]
        RESTORE_LOOKUPS.with(|count| count.set(count.get() + 1));
        let candidate = state_store
            .peek()
            .verified_sidecar_for_source(&authority, &realm_id, &strand)
            .ok()
            .flatten();
        let Some(candidate) = candidate else { return };
        if credential.is_empty() {
            return;
        }
        let Ok(fence) = crate::transport::auth::AuthoringSessionFence::capture() else {
            return;
        };
        spawn(async move {
            let mut retrying = false;
            loop {
                if *generation.peek() != next || fence.check().is_err() {
                    return;
                }
                let admission = restore_retry_book()
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .claim(&authority, crate::clock::now_utc(), retrying);
                if let RestoreAdmission::Wait(delay) = admission {
                    crate::runtime_helpers::sleep_for(delay).await;
                    continue;
                }
                let attempt = RestoreAttempt(authority.clone());
                let result = async {
                    let api =
                        crate::transport::auth::authed_api_ready(&base_url, credential.clone())
                            .await?;
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
                    let store = state_store.peek();
                    anyhow::ensure!(
                        store
                            .verified_sidecar_for_source(&authority, &realm_id, &strand)?
                            .is_some_and(|current| current.id == candidate.id),
                        "Sidecar source mapping changed during restore"
                    );
                    let native_ready = crate::sidecar::native_mls_ready_for_view(&store, &view);
                    let existing = hosted.peek().clone().filter(|session| {
                        session.controller_account_id == authority
                            && session.sidecar_id == candidate.id
                            && session.matches_route(&realm_id, &strand_id)
                    });
                    let last_addressed = if existing.is_some() {
                        Vec::new()
                    } else {
                        crate::sidecar::cached_sidecar_exchange_projections(
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
                                    left.source_hlc.cmp(&right.source_hlc).then_with(|| {
                                        left.client_order_key.cmp(&right.client_order_key)
                                    })
                                })
                        })
                        .map(|projection| {
                            projection
                                .addressed_agent_ids
                                .into_iter()
                                .map(|agent| agent.to_string())
                                .collect()
                        })
                        .unwrap_or_default()
                    };
                    let mut session =
                        existing.unwrap_or_else(|| crate::sidecar::HostedSidecarState {
                            trace_id: uuid_v7(),
                            controller_account_id: authority.clone(),
                            addressed_agent_ids: last_addressed,
                            addressed_agent_label: "No agents addressed".to_owned(),
                            source_realm_id: realm_id.clone(),
                            source_strand_id: strand_id.clone(),
                            sidecar_id: candidate.id.clone(),
                            access_readiness: view.access_readiness,
                            pending_access_reconciliations: view
                                .pending_access_reconciliations
                                .clone(),
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
                    if hosted.peek().as_ref() != Some(&session) {
                        hosted.set(Some(session));
                    }
                    Ok(())
                }
                .await;
                let retry_hint = result.as_ref().err().and_then(restore_retry_hint);
                restore_retry_book()
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .finish(&authority, crate::clock::now_utc(), retry_hint);
                drop(attempt);
                match result {
                    Ok(()) => return,
                    Err(error) => {
                        tracing::debug!(reason = %format_args!("{error:#}"), retrying = retry_hint.is_some(), "Sidecar hosted restore remains pending");
                        if retry_hint.is_none() {
                            return;
                        }
                        retrying = true;
                    }
                }
            }
        });
    }));
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "tests/sidecar_restore_basis.rs"]
mod restore_basis_tests;
