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

fn controller_callback_harness(control: Control) -> Element {
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
    let device_id =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let controller = use_chat_controller("", "", &authority, &device_id);
    let token = use_signal(String::new);
    let sync_cursor = use_signal(String::new);
    let frontier_state = use_signal(String::new);
    let context = ChatCommandContext {
        base_url: "://invalid-controller-fixture".to_owned(),
        principal_id: authority.principal_id.clone(),
        authority,
        device_id,
        selected_realm_id: "invalid-realm".to_owned(),
        selected_channel_id: "invalid-strand".to_owned(),
        selected_channel_security_encrypted: true,
        token,
        sync_cursor,
        frontier_state,
        known_agent_accounts: Default::default(),
        private_agent_scope: false,
    };
    let mut calls = use_signal(|| 0_usize);
    let callback = use_callback(move |()| {
        let next = *calls.peek() + 1;
        calls.set(next);
        // This production method reads the context before the malformed target
        // is refused. It cannot seal, spawn a request, or contact a server.
        controller.add_reaction(
            context.clone(),
            "missing-message".to_owned(),
            "invalid-event".to_owned(),
            "👍".to_owned(),
        );
    });
    // A callback may run while a hook initializer holds the hook-list borrow.
    // Context lookup in the command must not allocate another hook.
    use_hook(move || callback.call(()));
    let sentinel = use_signal(|| "stable hook after controller callback".to_owned());
    *control.handles.borrow_mut() = Some((callback, sentinel, calls, controller.status_msg));
    rsx! { div { "{calls}:{sentinel}:{controller.status_msg}" } }
}

#[test]
fn production_controller_callback_does_not_allocate_hooks_and_survives_rerender() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control {
        path: dir.path().join("controller-state.json"),
        handles: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(controller_callback_harness, control.clone());
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
                "stable hook after controller callback"
            );
            assert!(
                status
                    .peek()
                    .starts_with("Reaction skipped: invalid reaction target Event id:")
            );
        });
    }
}
