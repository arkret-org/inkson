//! Route-owned Direct authority refresh over the durable current cut.
use super::*;

#[derive(Clone, PartialEq)]
struct DirectAuthorityRefreshKey {
    session: String,
    current_generation: u64,
    current_ready: bool,
    current_complete: bool,
    current_reset_required: bool,
    verified_realm_head: Option<arkret_sdk::CommitStreamHead>,
    retry_generation: u64,
    #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
    observation: DirectAuthorityObservation,
}

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
#[derive(Clone, PartialEq)]
struct DirectAuthorityObservation {
    cursor: String,
    realm_epoch: u64,
    cache_epoch: u64,
    ui_generation: u64,
    credential: [u8; 32],
    account: [u8; 32],
}

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
fn observe_direct_authority_key(
    previous: Option<&DirectAuthorityRefreshKey>,
    next: &DirectAuthorityRefreshKey,
) {
    let Some(previous) = previous else {
        tracing::warn!(phase = "initial", "Direct authority lifecycle observation");
        return;
    };
    tracing::warn!(
        phase = "key_changed",
        cursor_changed = previous.observation.cursor != next.observation.cursor,
        realm_epoch_changed = previous.observation.realm_epoch != next.observation.realm_epoch,
        cache_epoch_changed = previous.observation.cache_epoch != next.observation.cache_epoch,
        ui_generation_changed =
            previous.observation.ui_generation != next.observation.ui_generation,
        credential_changed = previous.observation.credential != next.observation.credential,
        account_changed = previous.observation.account != next.observation.account,
        current_generation_changed = previous.current_generation != next.current_generation,
        current_ready_changed = previous.current_ready != next.current_ready,
        current_complete_changed = previous.current_complete != next.current_complete,
        reset_changed = previous.current_reset_required != next.current_reset_required,
        verified_head_changed = previous.verified_realm_head != next.verified_realm_head,
        retry_changed = previous.retry_generation != next.retry_generation,
        "Direct authority lifecycle observation"
    );
}

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
struct DirectAuthorityHttpObservation {
    sequence: u64,
    owner: glory::ui::WeakScope,
    completed: bool,
}

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
impl DirectAuthorityHttpObservation {
    fn start(sequence: u64, owner: glory::ui::WeakScope) -> Self {
        tracing::warn!(
            phase = "http_started",
            sequence,
            "Direct authority lifecycle observation"
        );
        Self {
            sequence,
            owner,
            completed: false,
        }
    }

    fn finish(&mut self, success: bool) {
        self.completed = true;
        tracing::warn!(
            phase = "http_completed",
            sequence = self.sequence,
            success,
            "Direct authority lifecycle observation"
        );
    }
}

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
impl Drop for DirectAuthorityHttpObservation {
    fn drop(&mut self) {
        if !self.completed {
            tracing::warn!(
                phase = "http_interrupted",
                sequence = self.sequence,
                owner_alive = self.owner.upgrade().is_some(),
                "Direct authority lifecycle observation"
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum DirectAuthorityPhase {
    Preparing,
    Reading,
    Installing,
}

type DirectAuthorityFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;
type DirectAuthorityWork<R> =
    Rc<dyn Fn(R, Rc<std::cell::Cell<DirectAuthorityPhase>>) -> DirectAuthorityFuture>;

struct DirectAuthorityQueue<O, R> {
    owner: Option<O>,
    latest: Option<R>,
    task: Option<glory::core::TaskToken>,
    phase: Rc<std::cell::Cell<DirectAuthorityPhase>>,
    revision: u64,
}

impl<O, R> Default for DirectAuthorityQueue<O, R> {
    fn default() -> Self {
        Self {
            owner: None,
            latest: None,
            task: None,
            phase: Rc::new(std::cell::Cell::new(DirectAuthorityPhase::Preparing)),
            revision: 0,
        }
    }
}

struct DirectAuthorityTaskClaim<O, R> {
    queue: Rc<std::cell::RefCell<DirectAuthorityQueue<O, R>>>,
    revision: u64,
}

impl<O, R> Drop for DirectAuthorityTaskClaim<O, R> {
    fn drop(&mut self) {
        let request = {
            let mut queue = self.queue.borrow_mut();
            if queue.revision != self.revision {
                return;
            }
            queue.owner = None;
            queue.task = None;
            queue.latest.take()
        };
        drop(request);
    }
}

fn retire_direct_authority_request<O, R>(
    queue: &Rc<std::cell::RefCell<DirectAuthorityQueue<O, R>>>,
) {
    let (task, request) = {
        let mut queue = queue.borrow_mut();
        queue.revision = queue.revision.wrapping_add(1);
        queue.owner = None;
        (queue.task.take(), queue.latest.take())
    };
    // Cancelling drops the task claim, which may borrow the queue again.
    if let Some(task) = task {
        task.cancel();
    }
    drop(request);
}

fn queue_direct_authority_request<O: PartialEq + 'static, R: 'static>(
    scope: &Scope,
    queue: Rc<std::cell::RefCell<DirectAuthorityQueue<O, R>>>,
    owner: O,
    request: R,
    work: DirectAuthorityWork<R>,
) {
    {
        let mut state = queue.borrow_mut();
        if state.owner.as_ref() == Some(&owner)
            && state.phase.get() == DirectAuthorityPhase::Reading
        {
            // Keep the issued read alive, but retain only the latest complete key.
            let superseded = state.latest.replace(request);
            drop(state);
            drop(superseded);
            return;
        }
    }
    // Preparation and installation may mutate authenticated state. A changed
    // key cancels those stages; only an already issued read can finish stale.
    retire_direct_authority_request(&queue);
    let phase = Rc::new(std::cell::Cell::new(DirectAuthorityPhase::Preparing));
    let revision = {
        let mut state = queue.borrow_mut();
        state.owner = Some(owner);
        state.latest = Some(request);
        state.phase = phase.clone();
        state.revision
    };
    let claim = DirectAuthorityTaskClaim {
        queue: queue.clone(),
        revision,
    };
    let running = queue.clone();
    match scope.spawn(async move {
        let _claim = claim;
        loop {
            let request = {
                let mut queue = running.borrow_mut();
                if queue.revision != revision {
                    return;
                }
                queue.latest.take()
            };
            let Some(request) = request else { return };
            phase.set(DirectAuthorityPhase::Preparing);
            work(request, phase.clone()).await;
        }
    }) {
        Ok(task) => {
            let keep = {
                let mut queue = queue.borrow_mut();
                if queue.revision == revision && queue.owner.is_some() {
                    queue.task = Some(task);
                    true
                } else {
                    false
                }
            };
            if !keep {
                task.cancel();
            }
        }
        Err(error) => scope.report_error(error),
    }
}

#[derive(Clone, PartialEq)]
struct DirectAuthorityOwnerKey {
    base_url: String,
    realm_id: String,
    authority: arkret_sdk::AccountId,
    peer: arkret_sdk::contact_operations::ContactPeer,
    profile_id: String,
    device_id: arkret_sdk::DeviceId,
    generation: u64,
    cache_epoch: u64,
    credential: String,
}

struct DirectAuthorityRequest {
    owner: DirectAuthorityOwnerKey,
    key: DirectAuthorityRefreshKey,
    account: Option<crate::config::ActiveAccountContext>,
}

fn queue_direct_authority_retry(
    scope: &Scope,
    retry_generation: Cage<u64>,
    wait: impl std::future::Future<Output = ()> + 'static,
    still_current: impl FnOnce() -> bool + 'static,
) {
    let weak = scope.downgrade();
    if let Err(error) = scope.spawn(async move {
        wait.await;
        if weak.upgrade().is_some() && still_current() {
            retry_generation.revise(|value| *value = value.wrapping_add(1));
        }
    }) {
        scope.report_error(error);
    }
}
fn direct_authority_refresh<R: 'static>(
    scope: &Scope,
    seen: Cage<Option<DirectAuthorityRefreshKey>>,
    mut request: impl FnMut() -> Option<(DirectAuthorityRefreshKey, R)> + 'static,
    mut refresh: impl FnMut(Option<R>) + 'static,
) {
    scope.effect(move || {
        let Some((key, request)) = request() else {
            if seen.get_untracked().is_some() {
                seen.revise(|value| *value = None);
            }
            refresh(None);
            return;
        };
        if seen.get_untracked().as_ref() == Some(&key) {
            return;
        }
        #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
        observe_direct_authority_key(seen.get_untracked().as_ref(), &key);
        seen.revise(|value| *value = Some(key));
        refresh(Some(request));
    });
}
pub(super) fn direct_authority(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    base_url: String,
    realm_id: String,
    authority: arkret_sdk::AccountId,
    token: Cage<String>,
    frontier_state: Cage<String>,
    realm_live_epoch: Cage<u64>,
    state_store: crate::presentation::SharedStateStore,
) {
    let retry_generation = scope.cage(0_u64);
    let seen = scope.cage(None::<DirectAuthorityRefreshKey>);
    let queue = Rc::new(std::cell::RefCell::new(DirectAuthorityQueue::default()));
    #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
    let observation_sequence = Rc::new(std::cell::Cell::new(0_u64));
    let weak = scope.downgrade();
    let work: DirectAuthorityWork<DirectAuthorityRequest> = {
        let weak = weak.clone();
        let context = context.clone();
        let state_store = state_store.clone();
        Rc::new(move |request, phase| {
            let DirectAuthorityRequest {
                owner,
                key,
                account,
            } = request;
            let DirectAuthorityOwnerKey {
                base_url: base,
                realm_id: realm,
                authority,
                peer,
                generation,
                cache_epoch: epoch,
                credential,
                ..
            } = owner;
            let weak = weak.clone();
            let context = context.clone();
            let store = state_store.handle();
            #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
            let observation_id = {
                let next = observation_sequence.get().wrapping_add(1);
                observation_sequence.set(next);
                next
            };
            Box::pin(async move {
                let Ok(_guard) =
                    crate::mls::direct_binding::coordinate_query(&authority, &peer).await
                else {
                    return;
                };
                if weak.upgrade().is_none()
                    || !context.session_matches(generation, &account)
                    || seen.get_untracked().as_ref() != Some(&key)
                    || epoch != crate::identity::device_directory::session_cache_epoch()
                {
                    return;
                }
                let Ok(sequence) = crate::mls::direct_binding::begin_query(&authority, &peer)
                else {
                    return;
                };
                let retry_store = store.clone();
                let retry_authority = authority.clone();
                let retry_peer = peer.clone();
                let retry_realm = realm.clone();
                let query_context = context.clone();
                let query_weak = weak.clone();
                let query_account = account.clone();
                let query_key = key.clone();
                let query_authority = authority.clone();
                let result = crate::transport::auth::with_authed_sdk_client(
                    &base,
                    credential,
                    |http| async move {
                        anyhow::ensure!(
                            query_weak.upgrade().is_some()
                                && query_context.session_matches(generation, &query_account)
                                && seen.get_untracked().as_ref() == Some(&query_key)
                                && epoch
                                    == crate::identity::device_directory::session_cache_epoch(),
                            "Direct authority owner changed before query"
                        );
                        phase.set(DirectAuthorityPhase::Reading);
                        #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
                        let mut observation = DirectAuthorityHttpObservation::start(
                            observation_id,
                            query_weak.clone(),
                        );
                        let response = http
                            .direct_conversation_resolve(
                                &arkret_sdk::direct_conversation::DirectConversationResolveRequestBody {
                                    peer: peer.clone(),
                                },
                            )
                            .await;
                        #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
                        observation.finish(response.is_ok());
                        // A same-target read may finish after its key changes. It
                        // must not publish or install proof for that older cut.
                        anyhow::ensure!(
                            query_weak.upgrade().is_some()
                                && query_context.session_matches(generation, &query_account)
                                && seen.get_untracked().as_ref() == Some(&query_key)
                                && epoch
                                    == crate::identity::device_directory::session_cache_epoch(),
                            "Direct authority owner changed"
                        );
                        phase.set(DirectAuthorityPhase::Installing);
                        let outcome = response?;
                        let delay = match &outcome {
                            arkret_sdk::direct_conversation::DirectConversationResolveResponseBody::TemporarilyUnavailable { retry_after_ms } => {
                                Some(std::time::Duration::from_millis(
                                    retry_after_ms.unwrap_or(500).clamp(250, 30_000),
                                ))
                            }
                            _ => None,
                        };
                        anyhow::ensure!(
                            outcome.coordinates().is_none_or(|coordinates| {
                                coordinates.realm_id.as_str() == realm
                            }),
                            "Direct Conversation query returned another Realm"
                        );
                        crate::mls::direct_binding::install_resolved_message_context(
                            &http,
                            &store,
                            &query_authority,
                            epoch,
                            sequence,
                            peer,
                            &outcome,
                        )
                        .await?;
                        anyhow::Ok(delay)
                    },
                )
                .await;
                if weak.upgrade().is_none() || !context.session_matches(generation, &account) {
                    return;
                }
                match result {
                    Ok(Some(delay)) => {
                        let Some(owner) = weak.upgrade() else { return };
                        queue_direct_authority_retry(
                            &owner,
                            retry_generation,
                            crate::runtime_helpers::sleep_for(delay),
                            move || {
                                seen.get_untracked().as_ref() == Some(&key)
                                    && epoch
                                        == crate::identity::device_directory::session_cache_epoch()
                                    && crate::mls::direct_binding::query_is_current(
                                        &retry_authority,
                                        &retry_peer,
                                        sequence,
                                    )
                                    && retry_store.read(|store| {
                                        store.active_authority().as_ref() == Some(&retry_authority)
                                            && store.direct_conversation_peer(&retry_realm).as_ref()
                                                == Some(&retry_peer)
                                    })
                            },
                        );
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::debug!(?error, "Direct Conversation authoring remains pending");
                    }
                }
            })
        })
    };
    direct_authority_refresh(
        scope,
        seen,
        {
            let context = context.clone();
            let store = state_store;
            move || {
                let credential = token.get();
                let cursor = frontier_state.get();
                let realm_epoch = realm_live_epoch.get();
                let _ = context.state_revision.get();
                let generation = context.session_generation.get();
                let account = context.active_account.get();
                let active = account.as_ref()?;
                if credential.is_empty() || active.authority != authority {
                    return None;
                }
                let (
                    peer,
                    current_generation,
                    current_ready,
                    current_complete,
                    current_reset_required,
                    verified_realm_head,
                ) = store.read(|store| {
                    let peer = store.direct_conversation_peer(&realm_id)?;
                    let head =
                        arkret_sdk::RealmId::new(realm_id.clone())
                            .ok()
                            .and_then(|realm_id| {
                                store
                                    .verified_commit_stream_cursor(
                                        &arkret_sdk::CommitStreamRef::Realm { realm_id },
                                    )
                                    .ok()
                                    .flatten()
                            });
                    Some((
                        peer,
                        store.current_generation(),
                        store.current_product_view_ready(&realm_id),
                        store
                            .current_product_view()
                            .is_some_and(|view| view.realm_id == realm_id && view.complete_cut),
                        store.current_reset_required(),
                        head,
                    ))
                })?;
                let epoch = crate::identity::device_directory::session_cache_epoch();
                let key = DirectAuthorityRefreshKey {
                    session: format!(
                        "{base_url}|{realm_id}|{authority:?}|{peer:?}|{epoch}|{cursor}|{realm_epoch}|{credential}|{generation}|{account:?}"
                    ),
                    current_generation,
                    current_ready,
                    current_complete,
                    current_reset_required,
                    verified_realm_head,
                    retry_generation: retry_generation.get(),
                    #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
                    observation: {
                        use sha2::Digest as _;
                        DirectAuthorityObservation {
                            cursor,
                            realm_epoch,
                            cache_epoch: epoch,
                            ui_generation: generation,
                            credential: sha2::Sha256::digest(credential.as_bytes()).into(),
                            account: sha2::Sha256::digest(format!("{account:?}").as_bytes()).into(),
                        }
                    },
                };
                Some((
                    key.clone(),
                    DirectAuthorityRequest {
                        owner: DirectAuthorityOwnerKey {
                            base_url: base_url.clone(),
                            realm_id: realm_id.clone(),
                            authority: authority.clone(),
                            peer,
                            profile_id: active.profile_id.clone(),
                            device_id: active.device_id.clone(),
                            generation,
                            cache_epoch: epoch,
                            credential,
                        },
                        key,
                        account,
                    },
                ))
            }
        },
        move |request: Option<DirectAuthorityRequest>| {
            let Some(request) = request else {
                retire_direct_authority_request(&queue);
                return;
            };
            let Some(owner) = weak.upgrade() else { return };
            let identity = request.owner.clone();
            queue_direct_authority_request(&owner, queue.clone(), identity, request, work.clone());
        },
    );
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
