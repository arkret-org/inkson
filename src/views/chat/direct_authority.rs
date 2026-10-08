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
}

fn queue_direct_authority_retry(
    mut retry_generation: Signal<u64>,
    wait: impl std::future::Future<Output = ()> + 'static,
    still_current: impl FnOnce() -> bool + 'static,
) {
    spawn(async move {
        wait.await;
        if still_current() {
            let next = retry_generation.peek().wrapping_add(1);
            retry_generation.set(next);
        }
    });
}

// Current publication can finish after the stream cursor has stopped moving.
// Deduplicate the complete read dependencies, not just the transport cursor.
fn use_direct_authority_refresh<R: 'static>(
    mut seen: Signal<Option<DirectAuthorityRefreshKey>>,
    mut request: impl FnMut() -> Option<(DirectAuthorityRefreshKey, R)> + 'static,
    mut refresh: impl FnMut(R) + 'static,
) {
    use_effect(move || {
        let Some((key, request)) = request() else {
            if seen.peek().is_some() {
                seen.set(None);
            }
            return;
        };
        if seen.peek().as_ref() == Some(&key) {
            return;
        }
        seen.set(Some(key));
        refresh(request);
    });
}

pub(super) fn use_direct_authority(
    base_url: String,
    realm_id: String,
    authority: arkret_sdk::AccountId,
    token: Signal<String>,
    frontier_state: Signal<String>,
    realm_live_epoch: Signal<u64>,
    state_store: SyncSignal<LocalStateStore>,
) {
    let retry_generation = use_signal(|| 0_u64);
    let current_request_key = use_signal(|| None::<DirectAuthorityRefreshKey>);
    use_direct_authority_refresh(
        current_request_key,
        use_reactive!(|(base_url, realm_id, authority)| {
            let credential = token();
            let cursor = frontier_state();
            let realm_epoch = realm_live_epoch();
            let state = state_store.read();
            let peer = state.direct_conversation_peer(&realm_id)?;
            let current_generation = state.current_generation();
            let current_ready = state.current_product_view_ready(&realm_id);
            let current_complete = state
                .current_product_view()
                .is_some_and(|view| view.realm_id == realm_id && view.complete_cut);
            let current_reset_required = state.current_reset_required();
            let verified_realm_head =
                arkret_sdk::RealmId::new(realm_id.clone())
                    .ok()
                    .and_then(|realm_id| {
                        state
                            .verified_commit_stream_cursor(&arkret_sdk::CommitStreamRef::Realm {
                                realm_id,
                            })
                            .ok()
                            .flatten()
                    });
            drop(state);
            let epoch = crate::identity::device_directory::session_cache_epoch();
            if credential.is_empty() {
                return None;
            }
            let key = DirectAuthorityRefreshKey {
                session: format!(
                    "{base_url}|{realm_id}|{authority:?}|{peer:?}|{epoch}|{cursor}|{realm_epoch}|{credential}"
                ),
                current_generation,
                current_ready,
                current_complete,
                current_reset_required,
                verified_realm_head,
                retry_generation: retry_generation(),
            };
            Some((
                key.clone(),
                (base_url, realm_id, authority, credential, epoch, peer, key),
            ))
        }),
        move |(base_url, realm_id, authority, credential, epoch, peer, request_key)| {
            spawn(async move {
                let Ok(_query_guard) =
                    crate::mls::direct_binding::coordinate_query(&authority, &peer).await
                else {
                    return;
                };
                if current_request_key.peek().as_ref() != Some(&request_key)
                    || epoch != crate::identity::device_directory::session_cache_epoch()
                {
                    return;
                }
                let Ok(query_sequence) = crate::mls::direct_binding::begin_query(&authority, &peer)
                else {
                    return;
                };
                let state = crate::app::runtime_adapter::state_store_handle(state_store);
                let retry_state = state.clone();
                let retry_authority = authority.clone();
                let retry_peer = peer.clone();
                let retry_realm_id = realm_id.clone();
                let result = crate::transport::auth::with_authed_sdk_client(
                    &base_url,
                    credential,
                    |http| async move {
                        let outcome = http
                            .direct_conversation_resolve(
                                &arkret_sdk::direct_conversation::DirectConversationResolveRequestBody {
                                    peer: peer.clone(),
                                },
                            )
                            .await?;
                        let retry_delay = match &outcome {
                            arkret_sdk::direct_conversation::DirectConversationResolveOutcome::TemporarilyUnavailable { retry_after_ms } => {
                                Some(std::time::Duration::from_millis(
                                    retry_after_ms.unwrap_or(500).clamp(250, 30_000),
                                ))
                            }
                            _ => None,
                        };
                        #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                        {
                            use arkret_sdk::direct_conversation::DirectConversationResolveOutcome as Outcome;
                            let (variant, blockers, group_present) = match &outcome {
                                Outcome::Found { send_blockers, .. } =>
                                    ("found", send_blockers.len(), true),
                                Outcome::Provisional { group_state_ref, .. } =>
                                    ("provisional", 0, group_state_ref.is_some()),
                                Outcome::Suspended { blockers, group_state_ref, .. } =>
                                    ("suspended", blockers.len(), group_state_ref.is_some()),
                                Outcome::TemporarilyUnavailable { .. } =>
                                    ("temporarily_unavailable", 0, false),
                                Outcome::CreationRequired { .. } =>
                                    ("creation_required", 0, false),
                                Outcome::CreationBlocked { blockers } =>
                                    ("creation_blocked", blockers.len(), false),
                                Outcome::AwaitingFounder { .. } =>
                                    ("awaiting_founder", 0, false),
                            };
                            tracing::warn!(variant, blockers, group_present,
                                "Direct authoring resolver observation");
                        }
                        anyhow::ensure!(
                            outcome.coordinates().is_none_or(|coordinates| {
                                coordinates.realm_id.as_str() == realm_id
                            }),
                            "Direct Conversation query returned another Realm"
                        );
                        crate::mls::direct_binding::install_resolved_message_context(
                            &http,
                            &state,
                            &authority,
                            epoch,
                            query_sequence,
                            peer,
                            &outcome,
                        )
                        .await?;
                        anyhow::Ok(retry_delay)
                    },
                )
                .await;
                match result {
                    Ok(Some(delay)) => {
                        queue_direct_authority_retry(
                            retry_generation,
                            crate::runtime_helpers::sleep_for(delay),
                            move || {
                                retry_state.read(|state| {
                                current_request_key.peek().as_ref() == Some(&request_key)
                                    && state.active_authority().as_ref() == Some(&retry_authority)
                                && epoch == crate::identity::device_directory::session_cache_epoch()
                                && crate::mls::direct_binding::query_is_current(
                                    &retry_authority, &retry_peer, query_sequence,
                                )
                                && state.direct_conversation_peer(&retry_realm_id).as_ref() == Some(&retry_peer)
                        })
                            },
                        )
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::debug!(?error, "Direct Conversation authoring remains pending");
                    }
                }
            });
        },
    );
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    #[derive(Clone)]
    struct RefreshHarness {
        control: Rc<RefCell<Option<Signal<DirectAuthorityRefreshKey>>>>,
        active_control: Rc<RefCell<Option<Signal<bool>>>>,
        seen_control: Rc<RefCell<Option<Signal<Option<DirectAuthorityRefreshKey>>>>>,
        requests: Rc<RefCell<Vec<(u64, bool, bool)>>>,
    }

    fn refresh_harness(props: RefreshHarness) -> Element {
        let current = use_signal(|| DirectAuthorityRefreshKey {
            session: "unchanged account, peer, cursor and realm epoch".to_owned(),
            current_generation: 2,
            current_ready: false,
            current_complete: false,
            current_reset_required: false,
            verified_realm_head: None,
            retry_generation: 0,
        });
        let active = use_signal(|| true);
        *props.control.borrow_mut() = Some(current);
        *props.active_control.borrow_mut() = Some(active);
        let seen = use_signal(|| None::<DirectAuthorityRefreshKey>);
        *props.seen_control.borrow_mut() = Some(seen);
        use_direct_authority_refresh(
            seen,
            move || {
                if !active() {
                    return None;
                }
                let key = current();
                let request = (
                    key.current_generation,
                    key.current_ready,
                    key.current_complete,
                );
                Some((key, request))
            },
            move |request| props.requests.borrow_mut().push(request),
        );
        rsx! { div {} }
    }

    #[test]
    fn direct_authority_refreshes_after_current_publication_without_cursor_change() {
        let props = RefreshHarness {
            control: Rc::new(RefCell::new(None)),
            active_control: Rc::new(RefCell::new(None)),
            seen_control: Rc::new(RefCell::new(None)),
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let mut dom = VirtualDom::new_with_props(refresh_harness, props.clone());
        dom.rebuild_in_place();
        dom.process_events();
        assert_eq!(*props.requests.borrow(), vec![(2, false, false)]);

        // The durable generation advances before the complete product view is
        // installed. Each dependency edge must refresh the authoritative read.
        for (generation, ready, complete) in [(3, false, false), (3, false, true), (3, true, true)]
        {
            dom.in_runtime(|| {
                let mut current = props.control.borrow().unwrap();
                let mut key = current.peek().clone();
                key.current_generation = generation;
                key.current_ready = ready;
                key.current_complete = complete;
                current.set(key);
            });
            dom.process_events();
            assert_eq!(
                props.requests.borrow().last(),
                Some(&(generation, ready, complete))
            );
        }
        assert_eq!(props.requests.borrow().len(), 4);

        // Unrelated store notifications at the same cut must not issue another
        // request, even though the effect is woken again.
        dom.in_runtime(|| {
            let mut current = props.control.borrow().unwrap();
            let unchanged = current.peek().clone();
            current.set(unchanged);
        });
        dom.process_events();
        assert_eq!(props.requests.borrow().len(), 4);

        // A newly accepted binding can advance the Realm stream while the
        // Account frontier and the product current generation stay unchanged.
        dom.in_runtime(|| {
            let mut current = props.control.borrow().unwrap();
            let mut key = current.peek().clone();
            key.verified_realm_head = Some(arkret_sdk::CommitStreamHead {
                stream_ref: arkret_sdk::CommitStreamRef::Realm {
                    realm_id: arkret_sdk::RealmId::new(
                        "ak:realm:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3",
                    )
                    .unwrap(),
                },
                commit_id: arkret_sdk::RealmCommitId::new(
                    "ak:realm_commit:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3",
                )
                .unwrap(),
                stream_position: 7,
            });
            current.set(key);
        });
        dom.process_events();
        assert_eq!(props.requests.borrow().len(), 5);

        dom.in_runtime(|| {
            let mut current = props.control.borrow().unwrap();
            let mut key = current.peek().clone();
            key.retry_generation = 1;
            current.set(key);
        });
        dom.process_events();
        assert_eq!(props.requests.borrow().len(), 6);

        dom.in_runtime(|| {
            let mut active = props.active_control.borrow().unwrap();
            active.set(false);
        });
        dom.process_events();
        assert!(props.seen_control.borrow().unwrap().peek().is_none());
        assert_eq!(props.requests.borrow().len(), 6);
        dom.in_runtime(|| {
            let mut active = props.active_control.borrow().unwrap();
            active.set(true);
        });
        dom.process_events();
        assert_eq!(props.requests.borrow().len(), 7);
    }

    #[derive(Clone)]
    struct RetryHarness {
        receiver: Rc<RefCell<Option<tokio::sync::oneshot::Receiver<()>>>>,
        current: Rc<std::cell::Cell<bool>>,
        observed: Rc<std::cell::Cell<u64>>,
    }

    fn retry_harness(props: RetryHarness) -> Element {
        let retry_generation = use_signal(|| 0_u64);
        props.observed.set(retry_generation());
        use_effect(move || {
            let Some(receiver) = props.receiver.borrow_mut().take() else {
                return;
            };
            let current = props.current.clone();
            queue_direct_authority_retry(
                retry_generation,
                async move {
                    let _ = receiver.await;
                },
                move || current.get(),
            );
        });
        rsx! { div {} }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn temporary_direct_retry_wakes_current_scope_and_rejects_stale_or_dropped_scope() {
        for still_current in [true, false] {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            let props = RetryHarness {
                receiver: Rc::new(RefCell::new(Some(receiver))),
                current: Rc::new(std::cell::Cell::new(true)),
                observed: Rc::new(std::cell::Cell::new(0)),
            };
            let mut dom = VirtualDom::new_with_props(retry_harness, props.clone());
            dom.rebuild_in_place();
            dom.process_events();
            props.current.set(still_current);
            sender.send(()).unwrap();
            dom.process_events();
            dom.render_immediate_to_vec();
            dom.process_events();
            assert_eq!(props.observed.get(), u64::from(still_current));
        }

        let (sender, receiver) = tokio::sync::oneshot::channel();
        let props = RetryHarness {
            receiver: Rc::new(RefCell::new(Some(receiver))),
            current: Rc::new(std::cell::Cell::new(true)),
            observed: Rc::new(std::cell::Cell::new(0)),
        };
        let mut dom = VirtualDom::new_with_props(retry_harness, props.clone());
        dom.rebuild_in_place();
        dom.process_events();
        drop(dom);
        assert!(sender.send(()).is_err());
        assert_eq!(props.observed.get(), 0);
    }
}
