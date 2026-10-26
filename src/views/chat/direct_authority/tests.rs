use std::cell::RefCell;
use std::rc::Rc;

use super::*;
#[derive(Clone)]
struct RefreshHarness {
    control: Rc<RefCell<Option<Cage<DirectAuthorityRefreshKey>>>>,
    active_control: Rc<RefCell<Option<Cage<bool>>>>,
    seen_control: Rc<RefCell<Option<Cage<Option<DirectAuthorityRefreshKey>>>>>,
    requests: Rc<RefCell<Vec<(u64, bool, bool)>>>,
}

fn refresh_harness(scope: &Scope, props: RefreshHarness) -> crate::presentation::View {
    let current = scope.cage(DirectAuthorityRefreshKey {
        session: "unchanged account, peer, cursor and realm epoch".to_owned(),
        current_generation: 2,
        current_ready: false,
        current_complete: false,
        current_reset_required: false,
        verified_realm_head: None,
        retry_generation: 0,
    });
    let active = scope.cage(true);
    *props.control.borrow_mut() = Some(current);
    *props.active_control.borrow_mut() = Some(active);
    let seen = scope.cage(None::<DirectAuthorityRefreshKey>);
    *props.seen_control.borrow_mut() = Some(seen);
    direct_authority_refresh(
        scope,
        seen,
        move || {
            if !active.get() {
                return None;
            }
            let key = current.get();
            let request = (
                key.current_generation,
                key.current_ready,
                key.current_complete,
            );
            Some((key, request))
        },
        move |request| {
            if let Some(request) = request {
                props.requests.borrow_mut().push(request);
            }
        },
    );
    crate::presentation::widgets::empty()
}

#[test]
fn direct_authority_refreshes_after_current_publication_without_cursor_change() {
    let props = RefreshHarness {
        control: Rc::new(RefCell::new(None)),
        active_control: Rc::new(RefCell::new(None)),
        seen_control: Rc::new(RefCell::new(None)),
        requests: Rc::new(RefCell::new(Vec::new())),
    };
    let app = glory::ui::App::memory();
    let render = props.clone();
    app.mount(glory::ui::widget(move |scope| {
        refresh_harness(scope, render.clone()).build(scope)
    }))
    .unwrap();
    app.flush().unwrap();
    assert_eq!(*props.requests.borrow(), vec![(2, false, false)]);

    // The durable generation advances before the complete product view is
    // installed. Each dependency edge must refresh the authoritative read.
    for (generation, ready, complete) in [(3, false, false), (3, false, true), (3, true, true)] {
        app.scope().owner().enter(|| {
            let current = props.control.borrow().unwrap();
            let mut key = current.get_untracked().clone();
            key.current_generation = generation;
            key.current_ready = ready;
            key.current_complete = complete;
            {
                let next_value = key;
                current.revise(|value| *value = next_value);
            };
        });
        app.flush().unwrap();
        assert_eq!(
            props.requests.borrow().last(),
            Some(&(generation, ready, complete))
        );
    }
    assert_eq!(props.requests.borrow().len(), 4);

    // Unrelated store notifications at the same cut must not issue another
    // request, even though the effect is woken again.
    app.scope().owner().enter(|| {
        let current = props.control.borrow().unwrap();
        let unchanged = current.get_untracked().clone();
        {
            let next_value = unchanged;
            current.revise(|value| *value = next_value);
        };
    });
    app.flush().unwrap();
    assert_eq!(props.requests.borrow().len(), 4);

    // A newly accepted binding can advance the Realm stream while the
    // Account frontier and the product current generation stay unchanged.
    app.scope().owner().enter(|| {
        let current = props.control.borrow().unwrap();
        let mut key = current.get_untracked().clone();
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
        {
            let next_value = key;
            current.revise(|value| *value = next_value);
        };
    });
    app.flush().unwrap();
    assert_eq!(props.requests.borrow().len(), 5);

    app.scope().owner().enter(|| {
        let current = props.control.borrow().unwrap();
        let mut key = current.get_untracked().clone();
        key.retry_generation = 1;
        {
            let next_value = key;
            current.revise(|value| *value = next_value);
        };
    });
    app.flush().unwrap();
    assert_eq!(props.requests.borrow().len(), 6);

    app.scope().owner().enter(|| {
        let active = props.active_control.borrow().unwrap();
        {
            let next_value = false;
            active.revise(|value| *value = next_value);
        };
    });
    app.flush().unwrap();
    assert!(
        props
            .seen_control
            .borrow()
            .unwrap()
            .get_untracked()
            .is_none()
    );
    assert_eq!(props.requests.borrow().len(), 6);
    app.scope().owner().enter(|| {
        let active = props.active_control.borrow().unwrap();
        {
            let next_value = true;
            active.revise(|value| *value = next_value);
        };
    });
    app.flush().unwrap();
    assert_eq!(props.requests.borrow().len(), 7);
}

#[test]
fn temporary_direct_retry_wakes_current_scope_and_rejects_stale_or_dropped_scope() {
    for still_current in [true, false] {
        let executor = Rc::new(glory::core::executor::Executor::new(32));
        let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let child = app.scope().child().unwrap();
        let retry = child.cage(0_u64);
        let observed = Rc::new(std::cell::Cell::new(0));
        let changed = observed.clone();
        child.effect(move || changed.set(retry.get()));
        let current = Rc::new(std::cell::Cell::new(true));
        let expected = current.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
        queue_direct_authority_retry(
            &child,
            retry,
            async move {
                let _ = receiver.await;
            },
            move || expected.get(),
        );
        while executor.poll_one() {}
        app.flush().unwrap();
        current.set(still_current);
        sender.send(()).unwrap();
        while executor.poll_one() {}
        app.flush().unwrap();
        assert_eq!(observed.get(), u64::from(still_current));
    }
    let executor = Rc::new(glory::core::executor::Executor::new(32));
    let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
    let child = app.scope().child().unwrap();
    let retry = child.cage(0_u64);
    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    queue_direct_authority_retry(
        &child,
        retry,
        async move {
            let _ = receiver.await;
        },
        || true,
    );
    while executor.poll_one() {}
    drop(child);
    assert!(sender.send(()).is_err());
    assert!(!retry.is_alive());
}

struct HeldDirectRequest {
    key: u64,
    preparation: Option<tokio::sync::oneshot::Receiver<()>>,
    response: tokio::sync::oneshot::Receiver<()>,
    installation: Option<tokio::sync::oneshot::Receiver<()>>,
}

struct HeldDirectCompletion {
    preparation: Option<tokio::sync::oneshot::Sender<()>>,
    response: tokio::sync::oneshot::Sender<()>,
    installation: Option<tokio::sync::oneshot::Sender<()>>,
}

fn held_direct_request(
    key: u64,
    prepare: bool,
    install: bool,
) -> (HeldDirectRequest, HeldDirectCompletion) {
    let (preparation_tx, preparation_rx) = tokio::sync::oneshot::channel();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let (installation_tx, installation_rx) = tokio::sync::oneshot::channel();
    (
        HeldDirectRequest {
            key,
            preparation: prepare.then_some(preparation_rx),
            response: response_rx,
            installation: install.then_some(installation_rx),
        },
        HeldDirectCompletion {
            preparation: prepare.then_some(preparation_tx),
            response: response_tx,
            installation: install.then_some(installation_tx),
        },
    )
}

#[derive(Clone, Default)]
struct DirectWorkObservations {
    issued: Rc<RefCell<Vec<u64>>>,
    responses: Rc<RefCell<Vec<u64>>>,
    published: Rc<RefCell<Vec<u64>>>,
}

fn held_direct_work(
    seen: Cage<Option<u64>>,
    observed: DirectWorkObservations,
) -> DirectAuthorityWork<HeldDirectRequest> {
    Rc::new(move |request, phase| {
        let observed = observed.clone();
        Box::pin(async move {
            if let Some(preparation) = request.preparation
                && preparation.await.is_err()
            {
                return;
            }
            if seen.get_untracked() != Some(request.key) {
                return;
            }
            phase.set(DirectAuthorityPhase::Reading);
            observed.issued.borrow_mut().push(request.key);
            if request.response.await.is_err() {
                return;
            }
            observed.responses.borrow_mut().push(request.key);
            if seen.get_untracked() != Some(request.key) {
                return;
            }
            phase.set(DirectAuthorityPhase::Installing);
            if let Some(installation) = request.installation
                && installation.await.is_err()
            {
                return;
            }
            if seen.get_untracked() == Some(request.key) {
                observed.published.borrow_mut().push(request.key);
            }
        })
    })
}

#[test]
fn direct_reads_finish_and_coalesce_to_latest_without_publishing_an_old_cut() {
    let executor = Rc::new(glory::core::executor::Executor::new(32));
    let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
    let child = app.scope().child().unwrap();
    let seen = child.cage(Some(1));
    let queue = Rc::new(RefCell::new(DirectAuthorityQueue::default()));
    let observed = DirectWorkObservations::default();
    let work = held_direct_work(seen, observed.clone());
    let (first, first_completion) = held_direct_request(1, false, false);
    queue_direct_authority_request(&child, queue.clone(), 7, first, work.clone());
    while executor.poll_one() {}
    assert_eq!(*observed.issued.borrow(), vec![1]);

    let (second, second_completion) = held_direct_request(2, false, false);
    let (latest, latest_completion) = held_direct_request(3, false, false);
    app.scope().owner().enter(|| {
        seen.revise(|key| *key = Some(2));
        queue_direct_authority_request(&child, queue.clone(), 7, second, work.clone());
        seen.revise(|key| *key = Some(3));
        queue_direct_authority_request(&child, queue.clone(), 7, latest, work);
    });
    while executor.poll_one() {}
    assert_eq!(*observed.issued.borrow(), vec![1]);
    assert!(second_completion.response.send(()).is_err());
    assert!(first_completion.response.send(()).is_ok());
    while executor.poll_one() {}
    assert_eq!(*observed.responses.borrow(), vec![1]);
    assert!(observed.published.borrow().is_empty());
    assert_eq!(*observed.issued.borrow(), vec![1, 3]);

    latest_completion.response.send(()).unwrap();
    while executor.poll_one() {}
    assert_eq!(*observed.responses.borrow(), vec![1, 3]);
    assert_eq!(*observed.published.borrow(), vec![3]);
    assert!(queue.borrow().owner.is_none());
    assert!(queue.borrow().latest.is_none());
    assert!(queue.borrow().task.is_none());
}

#[test]
fn direct_key_changes_cancel_preparation_and_installation() {
    for during_installation in [false, true] {
        let executor = Rc::new(glory::core::executor::Executor::new(32));
        let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let child = app.scope().child().unwrap();
        let seen = child.cage(Some(1));
        let queue = Rc::new(RefCell::new(DirectAuthorityQueue::default()));
        let observed = DirectWorkObservations::default();
        let work = held_direct_work(seen, observed.clone());
        let (first, first_completion) =
            held_direct_request(1, !during_installation, during_installation);
        let mut first_response = Some(first_completion.response);
        queue_direct_authority_request(&child, queue.clone(), 7, first, work.clone());
        while executor.poll_one() {}
        if during_installation {
            first_response.take().unwrap().send(()).unwrap();
            while executor.poll_one() {}
            assert_eq!(*observed.responses.borrow(), vec![1]);
            assert!(observed.published.borrow().is_empty());
        } else {
            assert!(observed.issued.borrow().is_empty());
        }
        let (latest, latest_completion) = held_direct_request(2, false, false);
        app.scope().owner().enter(|| {
            seen.revise(|key| *key = Some(2));
            queue_direct_authority_request(&child, queue.clone(), 7, latest, work);
        });
        if during_installation {
            assert!(first_completion.installation.unwrap().send(()).is_err());
        } else {
            assert!(first_completion.preparation.unwrap().send(()).is_err());
            assert!(first_response.take().unwrap().send(()).is_err());
        }
        while executor.poll_one() {}
        latest_completion.response.send(()).unwrap();
        while executor.poll_one() {}
        assert_eq!(*observed.published.borrow(), vec![2]);
    }
}

#[test]
fn direct_owner_replacement_cancels_issued_read_and_drops_queued_old_target() {
    let executor = Rc::new(glory::core::executor::Executor::new(32));
    let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
    let child = app.scope().child().unwrap();
    let seen = child.cage(Some(1));
    let queue = Rc::new(RefCell::new(DirectAuthorityQueue::default()));
    let observed = DirectWorkObservations::default();
    let work = held_direct_work(seen, observed.clone());
    let (first, first_completion) = held_direct_request(1, false, false);
    queue_direct_authority_request(&child, queue.clone(), 7, first, work.clone());
    while executor.poll_one() {}
    let (queued, queued_completion) = held_direct_request(2, false, false);
    let (replacement, replacement_completion) = held_direct_request(3, false, false);
    app.scope().owner().enter(|| {
        seen.revise(|key| *key = Some(2));
        queue_direct_authority_request(&child, queue.clone(), 7, queued, work.clone());
        seen.revise(|key| *key = Some(3));
        queue_direct_authority_request(&child, queue.clone(), 8, replacement, work);
    });
    assert!(first_completion.response.send(()).is_err());
    assert!(queued_completion.response.send(()).is_err());
    while executor.poll_one() {}
    assert_eq!(*observed.issued.borrow(), vec![1, 3]);
    replacement_completion.response.send(()).unwrap();
    while executor.poll_one() {}
    assert_eq!(*observed.published.borrow(), vec![3]);
}

#[test]
fn direct_retirement_and_scope_drop_cancel_real_reads_and_release_pending_claims() {
    for drop_scope in [false, true] {
        let executor = Rc::new(glory::core::executor::Executor::new(32));
        let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let child = app.scope().child().unwrap();
        let seen = child.cage(Some(1));
        let queue = Rc::new(RefCell::new(DirectAuthorityQueue::default()));
        let observed = DirectWorkObservations::default();
        let work = held_direct_work(seen, observed.clone());
        let (first, first_completion) = held_direct_request(1, false, false);
        queue_direct_authority_request(&child, queue.clone(), 7, first, work.clone());
        while executor.poll_one() {}
        let (latest, latest_completion) = held_direct_request(2, false, false);
        app.scope().owner().enter(|| {
            seen.revise(|key| *key = Some(2));
            queue_direct_authority_request(&child, queue.clone(), 7, latest, work);
        });
        if drop_scope {
            drop(child);
        } else {
            retire_direct_authority_request(&queue);
        }
        assert!(first_completion.response.send(()).is_err());
        assert!(latest_completion.response.send(()).is_err());
        while executor.poll_one() {}
        assert!(observed.responses.borrow().is_empty());
        assert!(observed.published.borrow().is_empty());
        assert!(queue.borrow().owner.is_none());
        assert!(queue.borrow().latest.is_none());
        assert!(queue.borrow().task.is_none());
    }
}
