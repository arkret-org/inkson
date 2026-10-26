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
fn mode_reads<K: Clone + PartialEq + 'static>(
    scope: &Scope,
    key: Lotus<K>,
    expected_count: Rc<dyn Fn(&K) -> usize>,
    read: ModeRead<K>,
    wait: RetryWait,
    externally_current: Rc<dyn Fn(&K) -> bool>,
    _read_origin: &'static str,
) -> Bond<Modes> {
    let initial = glory::core::untracked(|| key.get());
    let modes = scope.cage((0_u64, Modes::new()));
    let fence = Rc::new(RefCell::new((initial, 0_u64, true)));
    let running: Rc<RefCell<Option<glory::core::TaskToken>>> = Rc::new(RefCell::new(None));
    let weak = scope.downgrade();
    let retired_fence = fence.clone();
    let retired_task = running.clone();
    scope
        .on_cleanup(move || {
            retired_fence.borrow_mut().2 = false;
            if let Some(task) = retired_task.borrow_mut().take() {
                task.cancel();
            }
        })
        .unwrap_or_else(|error| scope.report_error(error));
    let observed_key = key.clone();
    let observed_fence = fence.clone();
    let observed_external = externally_current.clone();
    scope.effect(move || {
        let key = observed_key.get();
        let generation = {
            let mut state = observed_fence.borrow_mut();
            if state.0 != key {
                state.0 = key.clone();
                state.1 = state.1.wrapping_add(1);
            }
            state.1
        };
        if let Some(task) = running.borrow_mut().take() {
            task.cancel();
        }
        modes.revise(|value| *value = (generation, Modes::new()));
        let Some(scope) = weak.upgrade() else { return };
        let fence = observed_fence.clone();
        let source = observed_key.clone();
        let read = read.clone();
        let wait = wait.clone();
        let external = observed_external.clone();
        let expected = expected_count(&key);
        if let Ok(task) = scope.spawn(async move {
            let current = || {
                let state = fence.borrow();
                state.2
                    && state.0 == key
                    && state.1 == generation
                    && glory::core::untracked(|| source.get()) == key
                    && external(&key)
            };
            for attempt in 0..8 {
                if !current() {
                    return;
                }
                let result = read(key.clone()).await;
                if !current() {
                    return;
                }
                let complete = result.len() == expected;
                if modes.get_untracked().1 != result {
                    modes.revise(|value| *value = (generation, result));
                }
                if complete {
                    return;
                }
                if attempt < 7 {
                    wait((500_u64 << attempt.min(2)).min(2000)).await;
                }
            }
        }) {
            *running.borrow_mut() = Some(task);
        }
    });
    scope.bond(move || {
        let key = key.get();
        let (published, snapshot) = modes.get();
        let state = fence.borrow();
        if state.2 && state.0 == key && published == state.1 && externally_current(&key) {
            snapshot
        } else {
            Modes::new()
        }
    })
}

pub(crate) fn agent_modes(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    key: Lotus<AgentModeReadKey>,
    read_origin: &'static str,
) -> Bond<Modes> {
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    mode_reads(
        scope,
        key,
        Rc::new(|key| key.accounts.len()),
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
            context.session_matches(generation, &account)
                && crate::identity::device_directory::session_cache_epoch() == request.session_epoch
        }),
        read_origin,
    )
}

#[cfg(test)]
mod tests {
    fn host() -> (glory::App, Rc<glory::core::executor::Executor>) {
        let executor = Rc::new(glory::core::executor::Executor::new(256));
        let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        (app, executor)
    }
    fn settle(app: &glory::App, executor: &glory::core::executor::Executor) {
        for _ in 0..64 {
            executor.poll_one();
            app.flush().unwrap();
        }
    }
    use std::cell::Cell;

    use super::*;
    #[test]
    fn verified_reads_preserve_unknown_and_retry_with_exact_key_and_owner_fences() {
        let (app, executor) = host();
        let scope = app.scope();
        let key = scope.cage(0_u64);
        let calls = Rc::new(Cell::new(0));
        let read_calls = calls.clone();
        let live = Rc::new(Cell::new(true));
        let current = live.clone();
        let modes = mode_reads(
            scope,
            Lotus::<u64>::from(key),
            Rc::new(|_| 1),
            Rc::new(move |_| {
                read_calls.set(read_calls.get() + 1);
                Box::pin(std::future::ready(Modes::new()))
            }),
            Rc::new(|_| Box::pin(std::future::ready(()))),
            Rc::new(move |_| current.get()),
            "test",
        );
        settle(&app, &executor);
        assert_eq!(calls.get(), 8);
        assert!(modes.get_untracked().is_empty());
        key.revise(|value| *value = 1);
        settle(&app, &executor);
        assert_eq!(calls.get(), 16);
        live.set(false);
        key.revise(|value| *value = 2);
        settle(&app, &executor);
        assert_eq!(calls.get(), 16);
        scope.dispose();
        assert!(!modes.is_alive());
    }
    #[test]
    fn inflight_response_cannot_authorize_a_returned_scope_or_unmounted_owner() {
        for retire in [false, true] {
            let (app, executor) = host();
            let scope = app.scope();
            let key = scope.cage(0_u64);
            let calls = Rc::new(Cell::new(0));
            let observed = calls.clone();
            let (sender, receiver) = tokio::sync::oneshot::channel::<Modes>();
            let receiver = Rc::new(RefCell::new(Some(receiver)));
            let modes = mode_reads(
                scope,
                Lotus::<u64>::from(key),
                Rc::new(|_| 1),
                Rc::new(move |_| {
                    observed.set(observed.get() + 1);
                    let receiver = receiver.borrow_mut().take();
                    Box::pin(async move {
                        if let Some(receiver) = receiver {
                            receiver.await.unwrap_or_default()
                        } else {
                            Modes::new()
                        }
                    })
                }),
                Rc::new(|_| Box::pin(std::future::pending())),
                Rc::new(|_| true),
                "test",
            );
            settle(&app, &executor);
            assert_eq!(calls.get(), 1);
            if retire {
                scope.dispose();
            } else {
                key.revise(|value| *value = 1);
                settle(&app, &executor);
                key.revise(|value| *value = 0);
                settle(&app, &executor);
            }
            let account = crate::test_support::authority("did:web:agent.example");
            let _ = sender.send(Modes::from([(
                account,
                arkret_sdk::AgentInteractionMode::Private,
            )]));
            settle(&app, &executor);
            if !retire {
                assert!(modes.get_untracked().is_empty());
            }
        }
    }
}
