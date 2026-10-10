//! Fresh, independently verified mode reads. A failed read remains Unknown.
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use super::*;

pub(crate) type Modes =
    std::collections::BTreeMap<arkret_sdk::AccountId, arkret_sdk::AgentInteractionMode>;
type ModeRead<K> = Rc<dyn Fn(K) -> Pin<Box<dyn Future<Output = Modes>>>>;
type RetryWait = Rc<dyn Fn(u64) -> Pin<Box<dyn Future<Output = ()>>>>;

#[derive(Clone, PartialEq)]
pub(crate) struct AgentModeReadKey {
    pub base: String,
    pub authority: arkret_sdk::AccountId,
    pub realm: String,
    pub credential: String,
    pub session_epoch: u64,
    pub sync_ready: bool,
    pub ready: bool,
    pub complete: bool,
    pub reset: bool,
    pub head: Option<arkret_sdk::CommitStreamHead>,
    pub accounts: Vec<arkret_sdk::AccountId>,
}

// Only the governing Realm head invalidates a verified mode cut. The shared
// projection generation and live notification epoch also advance for Sidecar
// history and unrelated current rows; using either would cancel these reads
// without a change to their authority. Session, completeness and reset fences
// remain independent of the exact stream checkpoint.

// Update the fence during render, before an older request can publish. The
// generation also rejects leaving and returning to an identical scope (ABA).
fn use_mode_reads<K: Clone + PartialEq + 'static>(
    key: K,
    expected_count: usize,
    read: ModeRead<K>,
    wait: RetryWait,
    externally_current: Rc<dyn Fn(&K) -> bool>,
    _read_origin: &'static str,
) -> Modes {
    let mut modes = use_signal(|| (0_u64, Modes::new()));
    let fence = use_hook(|| Rc::new(RefCell::new((key.clone(), 0_u64, true))));
    let generation = {
        let mut current = fence.borrow_mut();
        if current.0 != key {
            current.0 = key.clone();
            current.1 = current.1.wrapping_add(1);
        }
        current.1
    };
    let snapshot_valid = externally_current(&key);
    let drop_fence = fence.clone();
    use_drop(move || drop_fence.borrow_mut().2 = false);
    use_effect(use_reactive(
        (&key, &expected_count),
        move |(key, expected_count)| {
            if fence.borrow().0 != key {
                return;
            }
            let generation = fence.borrow().1;
            modes.set((generation, Modes::new()));
            let fence = fence.clone();
            let read = read.clone();
            let wait = wait.clone();
            let externally_current = externally_current.clone();
            spawn(async move {
                let current = || {
                    let state = fence.borrow();
                    let mounted = state.2;
                    let key_matches = state.0 == key;
                    let generation_matches = state.1 == generation;
                    let session_current = externally_current(&key);
                    let valid = mounted && key_matches && generation_matches && session_current;
                    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                    if !valid {
                        tracing::warn!(
                            read_origin = _read_origin,
                            mounted,
                            key_matches,
                            generation_matches,
                            session_current,
                            "agent mode read superseded"
                        );
                    }
                    valid
                };
                // A changing governing head can invalidate an otherwise successful
                // HTTP response. Retry the verified operation, never its raw value.
                for attempt in 0..8 {
                    if !current() {
                        return;
                    }
                    let result = read(key.clone()).await;
                    if !current() {
                        return;
                    }
                    let complete = result.len() == expected_count;
                    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                    tracing::warn!(
                        read_origin = _read_origin,
                        attempt,
                        expected_count,
                        verified_count = result.len(),
                        complete,
                        "agent mode verified read diagnostics"
                    );
                    if modes.peek().1 != result {
                        modes.set((generation, result));
                    }
                    if complete {
                        return;
                    }
                    if attempt < 7 {
                        wait((500_u64 << attempt.min(2)).min(2_000)).await;
                    }
                }
            });
        },
    ));
    let (published_generation, snapshot) = modes();
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    {
        let signature = (
            generation,
            published_generation,
            snapshot_valid,
            snapshot.len(),
            expected_count,
        );
        let previous = use_hook(|| Rc::new(RefCell::new(None)));
        if previous.borrow().as_ref() != Some(&signature) {
            tracing::warn!(
                read_origin = _read_origin,
                snapshot_valid,
                generation_matches = published_generation == generation,
                verified_count = snapshot.len(),
                expected_count,
                "agent mode render snapshot"
            );
            *previous.borrow_mut() = Some(signature);
        }
    }
    if snapshot_valid && published_generation == generation {
        snapshot
    } else {
        Modes::new()
    }
}

pub(crate) fn use_agent_modes(key: AgentModeReadKey, read_origin: &'static str) -> Modes {
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    {
        let previous = use_hook(|| Rc::new(RefCell::new(key.clone())));
        let old = previous.borrow();
        if *old != key {
            tracing::warn!(
                read_origin,
                base_changed = old.base != key.base,
                authority_changed = old.authority != key.authority,
                realm_changed = old.realm != key.realm,
                credential_changed = old.credential != key.credential,
                session_epoch_changed = old.session_epoch != key.session_epoch,
                sync_ready_changed = old.sync_ready != key.sync_ready,
                ready_changed = old.ready != key.ready,
                complete_changed = old.complete != key.complete,
                reset_changed = old.reset != key.reset,
                head_changed = old.head != key.head,
                accounts_changed = old.accounts != key.accounts,
                expected_count = key.accounts.len(),
                "agent mode key invalidated"
            );
        }
        drop(old);
        *previous.borrow_mut() = key.clone();
    }
    use_mode_reads(
        key.clone(),
        key.accounts.len(),
        Rc::new(move |request: AgentModeReadKey| {
            Box::pin(async move {
                crate::transport::auth::with_authed_sdk_client(
                    &request.base,
                    request.credential,
                    |http| async move {
                        let realm = arkret_sdk::RealmId::new(request.realm)?;
                        let mut modes = Modes::new();
                        for account in request.accounts {
                            if let Ok((mode, ..)) =
                                crate::transport::agent_interaction::read(&http, &realm, &account)
                                    .await
                            {
                                modes.insert(account, mode);
                            }
                        }
                        Ok::<_, anyhow::Error>(modes)
                    },
                )
                .await
                .unwrap_or_default()
            })
        }),
        Rc::new(|ms| {
            Box::pin(crate::runtime_helpers::sleep_for(
                std::time::Duration::from_millis(ms),
            ))
        }),
        Rc::new(move |request: &AgentModeReadKey| {
            crate::identity::device_directory::session_cache_epoch() == request.session_epoch
        }),
        read_origin,
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    type ModeKeySignal = Rc<RefCell<Option<Signal<(String, String, u64)>>>>;

    #[derive(Clone)]
    struct Harness {
        key: ModeKeySignal,
        unrelated_revision: Rc<RefCell<Option<Signal<u64>>>>,
        observed: Rc<RefCell<Modes>>,
        calls: Rc<Cell<usize>>,
        read_ready: Rc<Cell<bool>>,
        waits: Rc<RefCell<Vec<tokio::sync::oneshot::Receiver<()>>>>,
        external_current: Rc<Cell<bool>>,
        account: arkret_sdk::AccountId,
        pending_reads:
            Rc<RefCell<std::collections::VecDeque<tokio::sync::oneshot::Receiver<Modes>>>>,
    }
    fn harness(props: Harness) -> Element {
        let key = use_signal(|| ("account-a".to_owned(), "realm-a".to_owned(), 0));
        *props.key.borrow_mut() = Some(key);
        let unrelated_revision = use_signal(|| 0_u64);
        *props.unrelated_revision.borrow_mut() = Some(unrelated_revision);
        let _ = unrelated_revision();
        let account = props.account.clone();
        let calls = props.calls.clone();
        let ready = props.read_ready.clone();
        let waits = props.waits.clone();
        let external = props.external_current.clone();
        let pending = props.pending_reads.clone();
        let result = use_mode_reads(
            key(),
            1,
            Rc::new(move |_| {
                calls.set(calls.get() + 1);
                let result = if ready.get() {
                    Modes::from([(account.clone(), arkret_sdk::AgentInteractionMode::Private)])
                } else {
                    Modes::new()
                };
                let receiver = pending.borrow_mut().pop_front();
                Box::pin(async move {
                    if let Some(receiver) = receiver {
                        receiver.await.unwrap_or_default()
                    } else {
                        result
                    }
                })
            }),
            Rc::new(move |_| {
                let receiver = waits.borrow_mut().remove(0);
                Box::pin(async move {
                    let _ = receiver.await;
                })
            }),
            Rc::new(move |_| external.get()),
            "test",
        );
        *props.observed.borrow_mut() = result;
        rsx! { div {} }
    }
    fn fixture() -> (Harness, Vec<tokio::sync::oneshot::Sender<()>>) {
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..20 {
            let (s, r) = tokio::sync::oneshot::channel();
            senders.push(s);
            receivers.push(r);
        }
        (
            Harness {
                key: Rc::new(RefCell::new(None)),
                unrelated_revision: Rc::new(RefCell::new(None)),
                observed: Rc::new(RefCell::new(Modes::new())),
                calls: Rc::new(Cell::new(0)),
                read_ready: Rc::new(Cell::new(false)),
                waits: Rc::new(RefCell::new(receivers)),
                external_current: Rc::new(Cell::new(true)),
                pending_reads: Rc::new(RefCell::new(std::collections::VecDeque::new())),
                account: arkret_sdk::AccountId::new(
                    arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
                    arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                ),
            },
            senders,
        )
    }
    fn drain(dom: &mut VirtualDom) {
        for _ in 0..4 {
            dom.process_events();
            dom.render_immediate_to_vec();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn agent_modes_inflight_read_survives_unrelated_projection_publication() {
        let (props, _senders) = fixture();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        props.pending_reads.borrow_mut().push_back(receiver);
        let mut dom = VirtualDom::new_with_props(harness, props.clone());
        dom.rebuild_in_place();
        drain(&mut dom);
        let mut revision = props.unrelated_revision.borrow().unwrap();
        for next in 1..=8 {
            dom.in_runtime(|| revision.set(next));
            drain(&mut dom);
        }
        assert_eq!(props.calls.get(), 1);
        let result = Modes::from([(
            props.account.clone(),
            arkret_sdk::AgentInteractionMode::Private,
        )]);
        sender.send(result.clone()).unwrap();
        drain(&mut dom);
        assert_eq!(*props.observed.borrow(), result);
        dom.in_runtime(|| revision.set(9));
        drain(&mut dom);
        assert_eq!(*props.observed.borrow(), result);
        assert_eq!(props.calls.get(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn agent_modes_same_key_unresolved_read_recovers_without_inventing_private() {
        let (props, mut senders) = fixture();
        let mut dom = VirtualDom::new_with_props(harness, props.clone());
        dom.rebuild_in_place();
        drain(&mut dom);
        assert!(props.observed.borrow().is_empty());
        assert_eq!(props.calls.get(), 1);
        props.read_ready.set(true);
        senders.remove(0).send(()).unwrap();
        drain(&mut dom);
        assert_eq!(
            props.observed.borrow().get(&props.account),
            Some(&arkret_sdk::AgentInteractionMode::Private)
        );
        assert_eq!(props.calls.get(), 2);
        drain(&mut dom);
        assert_eq!(props.calls.get(), 2, "stable verified result does not poll");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn agent_modes_retry_is_bounded_and_stale_scope_session_or_unmount_cannot_publish() {
        let (props, mut senders) = fixture();
        let mut dom = VirtualDom::new_with_props(harness, props.clone());
        dom.rebuild_in_place();
        drain(&mut dom);
        for _ in 0..7 {
            senders.remove(0).send(()).unwrap();
            drain(&mut dom);
        }
        assert_eq!(props.calls.get(), 8);
        assert!(props.observed.borrow().is_empty());
        for change in [0, 1, 2, 3] {
            let (props, mut senders) = fixture();
            let mut dom = VirtualDom::new_with_props(harness, props.clone());
            dom.rebuild_in_place();
            drain(&mut dom);
            if change == 3 {
                props.external_current.set(false);
            } else {
                let mut signal = props.key.borrow().unwrap();
                let original = dom.in_runtime(&*signal);
                let next = match change {
                    0 => ("account-b".into(), original.1.clone(), 0),
                    1 => (original.0.clone(), "realm-b".into(), 0),
                    _ => (original.0.clone(), original.1.clone(), 1),
                };
                dom.in_runtime(|| signal.set(next));
                drain(&mut dom);
                dom.in_runtime(|| signal.set(original));
                drain(&mut dom);
            }
            props.read_ready.set(true);
            let _ = senders.remove(0).send(());
            drain(&mut dom);
            assert!(
                props.observed.borrow().is_empty(),
                "old retry must not publish after scope ABA or session revocation"
            );
        }
        let (props, mut senders) = fixture();
        let mut dom = VirtualDom::new_with_props(harness, props.clone());
        dom.rebuild_in_place();
        drain(&mut dom);
        drop(dom);
        assert!(senders.remove(0).send(()).is_err());
        assert!(props.observed.borrow().is_empty());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn agent_modes_inflight_read_cannot_publish_after_account_realm_or_current_cut_aba() {
        for change in 0..3 {
            let (props, _senders) = fixture();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            props.pending_reads.borrow_mut().push_back(receiver);
            let mut dom = VirtualDom::new_with_props(harness, props.clone());
            dom.rebuild_in_place();
            drain(&mut dom);
            let mut signal = props.key.borrow().unwrap();
            let original = dom.in_runtime(&*signal);
            let next = match change {
                0 => ("account-b".into(), original.1.clone(), 0),
                1 => (original.0.clone(), "realm-b".into(), 0),
                _ => (original.0.clone(), original.1.clone(), 1),
            };
            dom.in_runtime(|| signal.set(next));
            drain(&mut dom);
            dom.in_runtime(|| signal.set(original));
            drain(&mut dom);
            let result = Modes::from([(
                props.account.clone(),
                arkret_sdk::AgentInteractionMode::Private,
            )]);
            let _ = sender.send(result);
            drain(&mut dom);
            assert!(
                props.observed.borrow().is_empty(),
                "old verified response must not authorize the returned view"
            );
        }
    }
}
