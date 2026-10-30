use std::cell::{Cell, RefCell};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use super::*;

#[derive(Clone, Copy)]
struct SessionHandles {
    session: crate::app::SessionContext,
    token: Signal<String>,
    show_row: Signal<bool>,
}

#[derive(Clone, Copy)]
struct RowHandles {
    busy: Signal<bool>,
    status: Signal<ContactFeedback>,
}

struct State {
    path: PathBuf,
    show_shell: RefCell<Option<Signal<bool>>>,
    session: RefCell<Option<SessionHandles>>,
    row: RefCell<Option<RowHandles>>,
    started_once: Cell<bool>,
    polled: Cell<bool>,
    released: Cell<bool>,
    finished: Cell<bool>,
    dropped: Cell<bool>,
    published: Cell<bool>,
    callbacks: Cell<usize>,
    task_scope: Cell<Option<ScopeId>>,
    owner_scope: Cell<Option<ScopeId>>,
    waker: RefCell<Option<Waker>>,
}

#[derive(Clone)]
struct Probe(Rc<State>);

impl PartialEq for Probe {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

struct PendingContact {
    probe: Probe,
    handles: SessionHandles,
    row: RowHandles,
    stamp: ContactSessionStamp,
    callback: EventHandler<()>,
}

impl Future for PendingContact {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.probe.0.polled.set(true);
        self.probe
            .0
            .task_scope
            .set(Some(dioxus::core::current_scope_id()));
        if !self.probe.0.released.get() {
            *self.probe.0.waker.borrow_mut() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let published = finish_contact_feedback(
            &self.stamp,
            self.handles.session,
            self.handles.token,
            self.row.busy,
            self.row.status,
            ContactFeedback::new("contacts.new.sent"),
            Some(self.callback),
        );
        self.probe.0.published.set(published);
        self.probe.0.finished.set(true);
        Poll::Ready(())
    }
}

impl Drop for PendingContact {
    fn drop(&mut self) {
        self.probe.0.dropped.set(true);
    }
}

#[component]
fn Row(probe: Probe) -> Element {
    let handles = probe.0.session.borrow().unwrap();
    let mut busy = use_signal(|| false);
    let mut status = use_signal(ContactFeedback::default);
    use_contact_session_reset(handles.session, handles.token, busy, status);
    let row = RowHandles { busy, status };
    *probe.0.row.borrow_mut() = Some(row);
    let observed = probe.clone();
    let callback = use_callback(move |()| observed.0.callbacks.set(observed.0.callbacks.get() + 1));
    use_hook(move || {
        if !probe.0.started_once.replace(true) {
            // Begin before the first effect flush, as a newly visible control
            // can receive input during the initial bootstrap frame.
            busy.set(true);
            status.set(ContactFeedback::new("contacts.action.accepting"));
            assert!(
                spawn_contact_task(PendingContact {
                    stamp: ContactSessionStamp::capture(handles.session, handles.token),
                    probe,
                    handles,
                    row,
                    callback,
                })
                .is_some()
            );
        }
    });
    rsx! { div {} }
}

#[component]
fn Shell(probe: Probe) -> Element {
    let path = probe.0.path.clone();
    let state_store = use_signal_sync(move || crate::state::LocalStateStore::with_path(path));
    let active_account = use_signal(|| {
        Some(crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build())
    });
    let base_url = use_signal(|| "https://local.host".to_owned());
    let session_generation = use_signal(|| 0);
    let owned_agents_rev = use_signal(|| 0);
    let session = use_context_provider(|| crate::app::SessionContext {
        active_account,
        state_store,
        base_url,
        session_generation,
        owned_agents_rev,
    });
    let token = use_signal(|| "sx:first".to_owned());
    let inbox = use_signal(Vec::<ContactView>::new);
    use_context_provider(|| crate::app::ContactInbox(inbox));
    probe.0.owner_scope.set(Some(inbox.origin_scope()));
    let show_row = use_signal(|| true);
    *probe.0.session.borrow_mut() = Some(SessionHandles {
        session,
        token,
        show_row,
    });
    rsx! { if show_row() { Row { probe } } }
}

fn root(probe: Probe) -> Element {
    let show_shell = use_signal(|| true);
    *probe.0.show_shell.borrow_mut() = Some(show_shell);
    rsx! { if show_shell() { Shell { probe } } }
}

fn mount(path: PathBuf) -> (VirtualDom, Probe) {
    let probe = Probe(Rc::new(State {
        path,
        show_shell: RefCell::new(None),
        session: RefCell::new(None),
        row: RefCell::new(None),
        started_once: Cell::new(false),
        polled: Cell::new(false),
        released: Cell::new(false),
        finished: Cell::new(false),
        dropped: Cell::new(false),
        published: Cell::new(false),
        callbacks: Cell::new(0),
        task_scope: Cell::new(None),
        owner_scope: Cell::new(None),
        waker: RefCell::new(None),
    }));
    let mut dom = VirtualDom::new_with_props(root, probe.clone());
    dom.rebuild_in_place();
    settle(&mut dom);
    assert!(probe.0.polled.get());
    assert_eq!(probe.0.task_scope.get(), probe.0.owner_scope.get());
    assert_ne!(probe.0.task_scope.get(), Some(ScopeId::ROOT));
    (dom, probe)
}

fn settle(dom: &mut VirtualDom) {
    for _ in 0..3 {
        dom.render_immediate_to_vec();
    }
}

fn release(dom: &mut VirtualDom, probe: &Probe) {
    probe.0.released.set(true);
    let waker = probe.0.waker.borrow_mut().take();
    if let Some(waker) = waker {
        waker.wake();
    }
    settle(dom);
}

#[test]
fn contact_lifecycle_refresh_keeps_initial_and_pending_feedback() {
    let directory = tempfile::tempdir().unwrap();
    let (mut dom, probe) = mount(directory.path().join("holder.json"));
    let mut handles = probe.0.session.borrow().unwrap();
    let row = probe.0.row.borrow().unwrap();
    dom.in_runtime(|| {
        assert!(*row.busy.peek());
        assert_eq!(row.status.peek().key, "contacts.action.accepting");
        handles.token.set("sx:refreshed".into());
    });
    settle(&mut dom);
    dom.in_runtime(|| {
        assert!(*row.busy.peek());
        assert_eq!(row.status.peek().key, "contacts.action.accepting");
    });
    release(&mut dom, &probe);
    assert!(probe.0.finished.get() && probe.0.published.get());
    assert_eq!(probe.0.callbacks.get(), 1);
    dom.in_runtime(|| assert!(!*row.busy.peek()));
}

#[test]
fn contact_lifecycle_row_removal_preserves_the_original_pending_task() {
    let directory = tempfile::tempdir().unwrap();
    let (mut dom, probe) = mount(directory.path().join("holder.json"));
    let mut handles = probe.0.session.borrow().unwrap();
    dom.in_runtime(|| handles.show_row.set(false));
    settle(&mut dom);
    assert!(!probe.0.dropped.get());
    release(&mut dom, &probe);
    assert!(probe.0.finished.get());
    assert!(!probe.0.published.get());
    assert_eq!(probe.0.callbacks.get(), 0);
}

#[test]
fn contact_lifecycle_account_owner_removal_cancels_the_pending_task() {
    let directory = tempfile::tempdir().unwrap();
    let (mut dom, probe) = mount(directory.path().join("holder.json"));
    dom.in_runtime(|| probe.0.show_shell.borrow().unwrap().set(false));
    settle(&mut dom);
    assert!(probe.0.dropped.get());
    release(&mut dom, &probe);
    assert!(!probe.0.finished.get());
    assert_eq!(probe.0.callbacks.get(), 0);
}

#[test]
fn contact_lifecycle_old_completion_cannot_paint_a_recreated_row() {
    let directory = tempfile::tempdir().unwrap();
    let (mut dom, probe) = mount(directory.path().join("holder.json"));
    let mut handles = probe.0.session.borrow().unwrap();
    let old = probe.0.row.borrow().unwrap();
    dom.in_runtime(|| handles.show_row.set(false));
    settle(&mut dom);
    dom.in_runtime(|| assert!(old.busy.try_peek().is_err()));
    dom.in_runtime(|| handles.show_row.set(true));
    settle(&mut dom);
    release(&mut dom, &probe);
    assert!(probe.0.finished.get());
    assert!(!probe.0.published.get());
    assert_eq!(probe.0.callbacks.get(), 0);
    let row = probe.0.row.borrow().unwrap();
    dom.in_runtime(|| {
        assert!(!*row.busy.peek());
        assert!(row.status.peek().is_empty());
    });
}

#[test]
fn contact_lifecycle_identity_changes_reject_dispatch_and_late_feedback() {
    for variant in 0..9 {
        let directory = tempfile::tempdir().unwrap();
        let (mut dom, probe) = mount(directory.path().join("holder.json"));
        let mut handles = probe.0.session.borrow().unwrap();
        let original =
            dom.in_runtime(|| ContactSessionStamp::capture(handles.session, handles.token));
        dom.in_runtime(|| match variant {
            0 => handles.session.active_account.set(Some(
                crate::test_support::AccountFixture::new("ak:did_core:web:bob.example").build(),
            )),
            1 => handles.session.active_account.set(Some(
                crate::test_support::AccountFixture::new("ak:did_core:web:alice.example")
                    .station("ak:did_core:web:other-station.example")
                    .build(),
            )),
            2 => handles.session.active_account.set(Some(
                crate::test_support::AccountFixture::new("ak:did_core:web:alice.example")
                    .device("ak:device:01964137-0000-7000-8000-000000000002")
                    .build(),
            )),
            3 => handles.session.active_account.set(Some(
                crate::test_support::AccountFixture::new("ak:did_core:web:alice.example")
                    .profile_id("ak:profile:other".into())
                    .build(),
            )),
            4 => handles.session.active_account.set(Some(
                crate::test_support::AccountFixture::new("ak:did_core:web:alice.example")
                    .server_url("https://other.example")
                    .build(),
            )),
            5 => handles.session.base_url.set("https://other.example".into()),
            6 => handles.session.session_generation.set(1),
            7 => handles.token.set(String::new()),
            8 => handles.session.active_account.set(None),
            _ => unreachable!(),
        });
        settle(&mut dom);
        dom.in_runtime(|| {
            assert!(
                original
                    .require_current(handles.session, handles.token)
                    .is_err()
            )
        });
        release(&mut dom, &probe);
        assert!(probe.0.finished.get(), "variant {variant}");
        assert!(!probe.0.published.get(), "variant {variant}");
        assert_eq!(probe.0.callbacks.get(), 0, "variant {variant}");
    }
}
