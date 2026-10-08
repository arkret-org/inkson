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

#[derive(Clone)]
struct UploadControl {
    path: std::path::PathBuf,
    base_url: String,
    is_private_sidecar: bool,
    handles: Rc<RefCell<Option<(EventHandler<()>, Signal<String>, Signal<String>)>>>,
}

fn upload_command_harness(control: UploadControl) -> Element {
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
    let mut controller =
        super::super::super::controller::use_chat_controller("", "", &authority, &device);
    let realm = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";
    let strand = "ak:strand:01964137-0000-7000-8000-000000000001";
    use_hook(move || {
        controller.selected_channel.set(strand.to_owned());
        controller.channels.set(vec![ChannelEntity {
            strand_id: strand.to_owned(),
            name: "Files".to_owned(),
            kind: "chat".to_owned(),
            category: String::new(),
            topic: None,
            unread: 0,
            is_default: true,
            is_private_sidecar: control.is_private_sidecar,
            security_encrypted: None,
            scope_circle: None,
        }]);
    });
    let target = control.base_url;
    let callback = use_callback(move |()| {
        let file = dioxus::html::FileData::new(dioxus::html::SerializedFileData {
            path: "private-note.txt".into(),
            size: 14,
            last_modified: 0,
            content_type: Some("text/plain".to_owned()),
            contents: Some(b"private bytes!".to_vec().into()),
        });
        upload_dropped_attachments(
            controller,
            target.clone(),
            "fixture-session".to_owned(),
            realm.to_owned(),
            vec![file],
        );
    });
    *control.handles.borrow_mut() =
        Some((callback, controller.compose_upload_status, controller.draft));
    rsx! { div { "{controller.compose_upload_status}" } }
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_attachment_with_unknown_current_sends_no_http_and_preserves_draft() {
    let directory = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let control = UploadControl {
        path: directory.path().join("unknown-current.json"),
        base_url: format!("http://{}", listener.local_addr().unwrap()),
        is_private_sidecar: false,
        handles: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(upload_command_harness, control.clone());
    dom.rebuild_in_place();
    let (callback, status, draft) = control.handles.borrow().unwrap();
    callback.call(());
    for _ in 0..100 {
        dom.render_immediate_to_vec();
        tokio::task::yield_now().await;
        if dom.in_runtime(|| !status.peek().is_empty()) {
            break;
        }
    }
    dom.in_runtime(|| {
        assert!(
            status
                .peek()
                .starts_with("Attachment upload requires verified conversation security:"),
            "{}",
            status.peek()
        );
        assert!(draft.peek().is_empty());
    });
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test(flavor = "current_thread")]
async fn private_sidecar_file_drop_never_inherits_verified_plaintext_parent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-sidecar.json");
    let account = crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build();
    let mut state = LocalStateStore::with_path(path.clone());
    state.switch_active_account(&account).unwrap();
    state.set_current_reset_required(false);
    let realm = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";
    let commit = arkret_sdk::RealmCommitId::from_digest([7; 32]);
    let head = serde_json::json!({
        "stream_ref":{"kind":"realm","realm_id":realm},
        "stream_position":1,"commit_id":commit,
    });
    let frame: arkret_sdk::sync::AccountSubscribeFrame = serde_json::from_value(serde_json::json!({
        "kind":"delta","cursor":"ak:cursor:YQ",
        "realms":{realm:{
            "current":{"realm_id":realm,"governance_generation":1,"stream_heads":[head.clone()],"entries":[]},
            "baseline":{"snapshot_cursor":"ak:cursor:YQ","cut_revision":1,"complete":true,
                "coverage":{"realm_id":realm,"stream_heads":[head],"complete_for_authorized_streams":true}}
        }}
    })).unwrap();
    let index =
        crate::state::CurrentIndex::open(&account.authority, 0, state.current_index_location())
            .await
            .unwrap();
    index.stage_frame(0, &frame).await.unwrap().finish();
    state.set_current_generation(1);
    state.flush().unwrap();
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    // Prove the parent is genuinely ready and plaintext; an incomplete parent
    // would mask the private-Sidecar scope inheritance bug.
    assert_eq!(index.read_complete_cut(realm).await.unwrap(), Some(1));
    assert!(
        index
            .read_mls_group_ready(&scope, &arkret_sdk::ActorId::account(account.authority))
            .await
            .unwrap()
            .is_none()
    );
    drop(index);
    drop(state);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let control = UploadControl {
        path,
        base_url: format!("http://{}", listener.local_addr().unwrap()),
        is_private_sidecar: true,
        handles: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(upload_command_harness, control.clone());
    dom.rebuild_in_place();
    let (callback, status, draft) = control.handles.borrow().unwrap();
    callback.call(());
    for _ in 0..100 {
        dom.render_immediate_to_vec();
        tokio::task::yield_now().await;
        if dom.in_runtime(|| !status.peek().is_empty()) {
            break;
        }
    }
    dom.in_runtime(|| {
        assert_eq!(
            status.peek().as_str(),
            "Attachment upload requires a verified conversation scope."
        );
        assert!(draft.peek().is_empty());
    });
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
