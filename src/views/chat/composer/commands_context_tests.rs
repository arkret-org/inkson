use std::cell::RefCell;
use std::rc::Rc;

use super::*;

type Handles = (
    EventHandler<()>,
    Signal<String>,
    Signal<usize>,
    Signal<String>,
);

#[derive(Clone)]
struct Control {
    path: std::path::PathBuf,
    handles: Rc<RefCell<Option<Handles>>>,
}

fn command_harness(control: Control) -> Element {
    let state_store = use_signal_sync(|| LocalStateStore::with_path(control.path));
    let active_account = use_signal(|| None);
    let base_url = use_signal(String::new);
    let session_generation = use_signal(|| 0_u64);
    let owned_agents_rev = use_signal(|| 0_u64);
    use_context_provider(|| crate::app::SessionContext {
        active_account,
        state_store,
        base_url,
        session_generation,
        owned_agents_rev,
    });
    let authority = crate::test_support::authority("ak:did_core:web:alice.example");
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let controller =
        super::super::super::controller::use_chat_controller("", "", &authority, &device);
    let frontier = use_signal(String::new);
    let mut calls = use_signal(|| 0_usize);
    let callback = use_callback(move |()| {
        let next = *calls.peek() + 1;
        calls.set(next);
        send_plaintext_message(
            controller,
            frontier,
            PlaintextSendRequest {
                // Rejection is entirely local: this is neither a URL nor a
                // Realm identity, and inline text cannot trigger blob upload.
                base_url: "://invalid-command-fixture".to_owned(),
                api_token: String::new(),
                wait_for: None,
                realm_id: "invalid-realm".to_owned(),
                circle_id: None,
                strand_id: "invalid-strand".to_owned(),
                actor: "invalid-actor".to_owned(),
                local_id: "callback-fixture".to_owned(),
                body: "local command fixture".to_owned(),
                reply_to: None,
                mentions: Vec::new(),
                shared_agent_targets: Vec::new(),
            },
        );
    });
    // Exercise the real callback while the hook list is borrowed. Commands
    // must not allocate component hooks, regardless of their caller's phase.
    use_hook(move || callback.call(()));
    let sentinel = use_signal(|| "stable hook after command".to_owned());
    *control.handles.borrow_mut() = Some((callback, sentinel, calls, controller.status_msg));
    rsx! { div { "{calls}:{sentinel}:{controller.status_msg}" } }
}

#[tokio::test(flavor = "current_thread")]
async fn production_command_callback_does_not_allocate_hooks_and_survives_rerender() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control {
        path: dir.path().join("command-state.json"),
        handles: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(command_harness, control.clone());
    dom.rebuild_in_place();
    let (_, sentinel, ..) = control.handles.borrow().unwrap();
    for expected_calls in 1..=4 {
        if expected_calls > 1 {
            let callback = control.handles.borrow().unwrap().0;
            callback.call(());
        }
        for _ in 0..8 {
            dom.render_immediate_to_vec();
        }
        let (_, current_sentinel, calls, status) = control.handles.borrow().unwrap();
        assert_eq!(current_sentinel, sentinel);
        dom.in_runtime(|| {
            assert_eq!(*calls.peek(), expected_calls);
            assert_eq!(
                current_sentinel.peek().as_str(),
                "stable hook after command"
            );
            assert!(status.peek().starts_with("send failed:"));
        });
    }
}
