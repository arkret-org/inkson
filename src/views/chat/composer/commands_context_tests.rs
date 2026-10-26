use std::cell::RefCell;
use std::rc::Rc;

use super::*;

type Handles = (
    Rc<dyn Fn()>,
    Cage<String>,
    Cage<usize>,
    Cage<String>,
    Cage<String>,
    Cage<std::collections::BTreeMap<String, String>>,
    Cage<Vec<crate::attachments::DraftAttachment>>,
);

#[derive(Clone)]
struct Control {
    path: std::path::PathBuf,
    handles: Rc<RefCell<Option<Handles>>>,
}

fn fixture_context(
    scope: &Scope,
    path: &std::path::Path,
) -> Rc<crate::presentation::InksonContext> {
    crate::presentation::InksonContext::new(
        scope,
        crate::presentation::BootState {
            config_store: crate::config::LocalConfigStore::with_path(
                path.with_extension("config.json"),
            ),
            config: crate::config::ClientConfig::default(),
            state_store: crate::presentation::SharedStateStore::new(LocalStateStore::with_path(
                path.to_owned(),
            )),
            initial_credential: String::new(),
            realm_tree_nodes: Vec::new(),
        },
        Route::Dashboard,
        |_| {
            Box::pin(async {
                crate::runtime::session::CurrentSessionRefresh::retry_later("fixture")
            })
        },
    )
}
fn command_harness(scope: &Scope, control: Control) {
    let context = fixture_context(scope, &control.path);
    scope.retain(context.clone()).unwrap();
    let authority = crate::test_support::authority("ak:did_core:web:alice.example");
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let controller = super::super::super::controller::chat_controller(
        scope, context, "", "", &authority, &device,
    )
    .unwrap();
    let frontier = scope.cage(String::new());
    let calls = scope.cage(0usize);
    let callback: Rc<dyn Fn()> = Rc::new(move || {
        calls.revise(|value| *value += 1);
        send_plaintext_message(
            controller,
            frontier,
            PlaintextSendRequest {
                base_url: "://invalid-command-fixture".into(),
                api_token: String::new(),
                wait_for: None,
                realm_id: "invalid-realm".into(),
                circle_id: None,
                strand_id: "invalid-strand".into(),
                actor: "invalid-actor".into(),
                local_id: "callback-fixture".into(),
                body: "local command fixture".into(),
                reply_to: None,
                mentions: Vec::new(),
                shared_agent_targets: Vec::new(),
            },
        );
    });
    callback();
    let sentinel = scope.cage("stable state after command".to_owned());
    *control.handles.borrow_mut() = Some((
        callback,
        sentinel,
        calls,
        controller.status_msg,
        controller.draft,
        controller.pending_drafts,
        controller.attachments,
    ));
}
fn host() -> (glory::App, Rc<glory::core::executor::Executor>) {
    let executor = Rc::new(glory::core::executor::Executor::new(256));
    let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
    (app, executor)
}
fn pump(app: &glory::App, executor: &glory::core::executor::Executor) {
    for _ in 0..32 {
        let polled = executor.poll_one();
        app.flush().unwrap();
        if !polled {
            break;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_command_callback_does_not_allocate_hooks_and_survives_rerender() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control {
        path: dir.path().join("command-state.json"),
        handles: Rc::new(RefCell::new(None)),
    };
    let (app, executor) = host();
    command_harness(app.scope(), control.clone());
    let (_, sentinel, ..) = control.handles.borrow().clone().unwrap();
    for expected_calls in 1..=4 {
        if expected_calls > 1 {
            let callback = control.handles.borrow().clone().unwrap().0;
            callback();
        }
        for _ in 0..8 {
            pump(&app, &executor);
        }
        let (_, current_sentinel, calls, status, draft, pending_drafts, _) =
            control.handles.borrow().clone().unwrap();
        current_sentinel.revise(|value| *value = format!("sentinel identity {expected_calls}"));
        assert_eq!(
            sentinel.get_untracked(),
            format!("sentinel identity {expected_calls}")
        );
        sentinel.revise(|value| *value = "stable state after command".to_owned());
        {
            assert_eq!(calls.get_untracked(), expected_calls);
            assert_eq!(
                current_sentinel.get_untracked().as_str(),
                "stable state after command"
            );
            assert!(status.get_untracked().starts_with("send failed:"));
            assert_eq!(draft.get_untracked().as_str(), "local command fixture");
            assert!(pending_drafts.get_untracked().is_empty());
        };
    }
    {
        use futures_util::FutureExt;
        let (_, _, _, _, draft, pending, _) = control.handles.borrow().clone().unwrap();
        for (status, new_text, expected_text) in [
            (garth::SendQueueStatus::Committed, "", ""),
            (garth::SendQueueStatus::Queued, "", ""),
            (garth::SendQueueStatus::Forwarding, "", ""),
            (garth::SendQueueStatus::Failed, "", "submitted text"),
            (
                garth::SendQueueStatus::Rejected,
                "new unsent text",
                "new unsent text",
            ),
        ] {
            draft.revise(|value| *value = new_text.to_owned());
            pending.revise(|value| {
                value.insert("guard-fixture".to_owned(), "submitted text".to_owned())
            });
            let mut guard = PendingComposerDraft {
                attachments: control.handles.borrow().clone().unwrap().6,
                attachment_ids: Vec::new(),
                draft,
                pending,
                operation: "guard-fixture".to_owned(),
                body: "submitted text".to_owned(),
                submission: ComposerSubmissionState::Recoverable,
            };
            let completion = async move {
                guard.record_send_status(status);
            };
            // Before the future runs, its guard must still protect the pending
            // text. Capturing only a state field would drop the guard here.
            assert!(pending.get_untracked().contains_key("guard-fixture"));
            assert_eq!(draft.get_untracked().as_str(), new_text);
            assert!(completion.now_or_never().is_some());
            assert!(pending.get_untracked().is_empty());
            assert_eq!(draft.get_untracked().as_str(), expected_text);
        }
        draft.revise(|value| *value = String::new());
        pending.revise(|value| {
            value.insert("unknown-fixture".to_owned(), "submitted text".to_owned())
        });
        let mut guard = PendingComposerDraft {
            attachments: control.handles.borrow().clone().unwrap().6,
            attachment_ids: Vec::new(),
            draft,
            pending,
            operation: "unknown-fixture".to_owned(),
            body: "submitted text".to_owned(),
            submission: ComposerSubmissionState::Recoverable,
        };
        let unknown = garth::MessageAuthoringFailure::SubmissionOutcomeUnknown {
            detail: "response lost after exact-byte queue persisted".to_owned(),
        };
        guard.record_failure(&unknown);
        assert!(guard.submission == ComposerSubmissionState::DurablePending);
        drop(guard);
        assert!(pending.get_untracked().is_empty());
        assert!(
            draft.get_untracked().is_empty(),
            "the durable exact-byte queue owns the unknown result, so the composer must not invite duplicate authoring"
        );
    };
}

type UploadHandles = Rc<RefCell<Option<(Rc<dyn Fn()>, Cage<String>, Cage<String>)>>>;

#[derive(Clone)]
struct UploadControl {
    path: std::path::PathBuf,
    base_url: String,
    is_private_sidecar: bool,
    handles: UploadHandles,
}

fn upload_command_harness(scope: &Scope, control: UploadControl) {
    let context = fixture_context(scope, &control.path);
    scope.retain(context.clone()).unwrap();
    let authority = crate::test_support::authority("ak:did_core:web:alice.example");
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
    let controller = super::super::super::controller::chat_controller(
        scope, context, "", "", &authority, &device,
    )
    .unwrap();
    let realm = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";
    let strand = "ak:strand:01964137-0000-7000-8000-000000000001";
    {
        controller
            .selected_channel
            .revise(|value| *value = strand.to_owned());
        controller.channels.revise(|value| {
            *value = vec![ChannelEntity {
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
            }]
        });
    }

    let target = control.base_url;
    let path = control.path.with_extension("private-note.txt");
    std::fs::write(&path, b"private bytes!").unwrap();
    let file = super::super::files::AttachmentFile::open(&path).unwrap();
    let callback: Rc<dyn Fn()> = Rc::new(move || {
        upload_dropped_attachments(
            controller,
            target.clone(),
            "fixture-session".into(),
            Some(arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
            }),
            vec![file.clone()],
        )
    });
    *control.handles.borrow_mut() =
        Some((callback, controller.compose_upload_status, controller.draft));
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
    let (app, executor) = host();
    upload_command_harness(app.scope(), control.clone());
    let (callback, status, draft) = control.handles.borrow().clone().unwrap();
    callback();
    for _ in 0..100 {
        pump(&app, &executor);
        tokio::task::yield_now().await;
        if !status.get_untracked().is_empty() {
            break;
        }
    }
    {
        assert!(
            status.get_untracked().starts_with("Attachment upload:"),
            "{}",
            status.get_untracked()
        );
        assert!(draft.get_untracked().is_empty());
    };
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
    let fixture_commit = arkret_sdk::RealmCommitId::from_digest([7; 32]);
    let head = serde_json::json!({
        "stream_ref":{"kind":"realm","realm_id":realm},
        "stream_position":1,"commit_id":fixture_commit,
    });
    let frame: arkret_sdk::sync::AccountSubscribeFrame = serde_json::from_value(serde_json::json!({
        "kind":"delta","cursor":"ak:cursor:YQ",
        "realms":{realm:{
            "current":{"realm_id":realm,"governance_generation":"1","stream_heads":[head.clone()],"entries":[]},
            "baseline":{"snapshot_cursor":"ak:cursor:YQ","cut_revision":1,"complete":true,
                "coverage":{"realm_id":realm,"stream_heads":[head],"complete_for_authorized_streams":true}}
        }}
    })).unwrap();
    let index =
        crate::state::CurrentIndex::open(&account.authority, 0, state.current_index_location())
            .await
            .unwrap();
    let stage = index.stage_frame(0, &frame).await.unwrap();
    state.commit_current_stage_for_test(stage).unwrap();
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
    let (app, executor) = host();
    upload_command_harness(app.scope(), control.clone());
    let (callback, status, draft) = control.handles.borrow().clone().unwrap();
    callback();
    for _ in 0..100 {
        pump(&app, &executor);
        tokio::task::yield_now().await;
        if !status.get_untracked().is_empty() {
            break;
        }
    }
    assert_eq!(
        status.get_untracked().as_str(),
        "Attachment upload requires a verified conversation scope."
    );
    assert!(draft.get_untracked().is_empty());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
