use super::*;

type Boundary = (
    Cage<Option<crate::config::ActiveAccountContext>>,
    Cage<String>,
    Cage<String>,
    Cage<u64>,
);
fn file(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

async fn mounted() -> (tempfile::TempDir, TestApp, SettingsController, Boundary) {
    mounted_with_cleanup(true).await
}
async fn mounted_with_cleanup(
    subscribe_cleanup: bool,
) -> (tempfile::TempDir, TestApp, SettingsController, Boundary) {
    let directory = tempfile::Builder::new()
        .prefix("settings-controller-")
        .tempdir_in("D:/BuildCache/inkson-glory/tmp")
        .unwrap();
    let app = TestApp::new();
    let scope = app.scope();
    let config_store =
        crate::config::LocalConfigStore::with_path(directory.path().join("config.json"));
    let config = config_store.load();
    let store =
        crate::state::LocalStateStore::with_path(directory.path().join("settings-state.json"));
    let boot = crate::presentation::BootState {
        config_store,
        config,
        state_store: SharedStateStore::new(store),
        initial_credential: String::new(),
        realm_tree_nodes: Vec::new(),
    };
    let context = InksonContext::new(scope, boot, crate::routes::Route::Dashboard, |_| {
        Box::pin(async { crate::runtime::session::CurrentSessionRefresh::retry_later("unused") })
    });
    let controller = SettingsController::new(scope, context.clone());
    if subscribe_cleanup {
        avatar_selection_boundary(scope, controller.clone());
    }
    let boundary = (
        context.active_account,
        context.base_url,
        context.token,
        context.session_generation,
    );
    app.flush().unwrap();
    (directory, app, controller, boundary)
}
async fn settle(app: &mut TestApp) {
    for _ in 0..8 {
        app.flush().unwrap();
        tokio::task::yield_now().await;
    }
}
#[tokio::test(flavor = "current_thread")]
async fn cancellation_of_real_staging_discards_late_errors() {
    let (_directory, mut dom, controller, _) = mounted().await;
    {
        controller
            .clone()
            .stage_avatar_crop(file(b"invalid image"), "image/png".to_owned());
        assert!(controller.avatar_reading.get_untracked());
        controller.clone().cancel_avatar_crop();
    };
    settle(&mut dom).await;
    {
        assert!(controller.pending_avatar_crop.get_untracked().is_none());
        assert!(!controller.avatar_reading.get_untracked());
        assert!(controller.avatar_upload_status.get_untracked().is_empty());
    };
}

#[tokio::test(flavor = "current_thread")]
async fn replaced_read_cannot_report_its_error_over_new_selection() {
    let (_directory, mut dom, controller, _) = mounted().await;
    // The first file has an unsupported media type, while the replacement
    // reaches image decoding. The final error must belong to the replacement.
    {
        controller
            .clone()
            .stage_avatar_crop(file(b"old"), "text/plain".to_owned());
        controller
            .clone()
            .stage_avatar_crop(file(b"new"), "image/png".to_owned());
    };
    settle(&mut dom).await;
    {
        assert!(!controller.avatar_reading.get_untracked());
        assert!(controller.pending_avatar_crop.get_untracked().is_none());
        let status = controller.avatar_upload_status.get_untracked();
        assert!(!status.is_empty());
        assert!(!status.contains(&crate::i18n::tr("settings.avatar.invalid_image")));
    };
}

#[tokio::test(flavor = "current_thread")]
async fn staged_reads_do_not_replace_a_pending_avatar_write() {
    for removing in [false, true] {
        let (_directory, mut dom, controller, _) = mounted().await;
        {
            controller
                .avatar_upload_status
                .revise(|value| *value = "existing upload status".to_owned());
            controller
                .avatar_cache_status
                .revise(|value| *value = "existing removal status".to_owned());
            if removing {
                controller.avatar_removing.revise(|value| *value = true);
            } else {
                controller.avatar_uploading.revise(|value| *value = true);
            }
            controller
                .clone()
                .stage_avatar_crop(file(b"ignored"), "image/png".to_owned());
        };
        settle(&mut dom).await;
        {
            assert!(!controller.avatar_reading.get_untracked());
            assert_eq!(
                controller.avatar_upload_status.get_untracked().as_str(),
                "existing upload status"
            );
            assert_eq!(
                controller.avatar_cache_status.get_untracked().as_str(),
                "existing removal status"
            );
            assert_eq!(controller.avatar_removing.get_untracked(), removing);
            assert_eq!(controller.avatar_uploading.get_untracked(), !removing);
        };
    }
}

#[tokio::test(flavor = "current_thread")]
async fn real_session_boundary_subscribes_to_account_route_token_and_sign_out() {
    let (_directory, mut dom, controller, (account, base, token, _)) = mounted().await;
    {
        account.revise(|value| {
            *value = Some(
                crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build(),
            )
        });
        base.revise(|value| *value = "https://local.host".to_owned());
        token.revise(|value| *value = "old-session".to_owned());
    };
    settle(&mut dom).await;
    for change in 0..5 {
        let before = {
            controller.avatar_reading.revise(|value| *value = true);
            controller
                .avatar_upload_status
                .revise(|value| *value = "processing old account image".to_owned());
            controller.pending_avatar_crop.revise(|value| {
                *value = Some(PendingAvatarCrop {
                    bytes: vec![1],
                    media_type: "image/png".to_owned(),
                    preview_data_url: "data:image/png;base64,AQ==".to_owned(),
                    dimensions: (1, 1),
                })
            });
            controller.avatar_selection_epoch.get_untracked()
        };
        match change {
            0 => account.revise(|value| {
                *value = Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:bob.example").build(),
                )
            }),
            1 => account.revise(|value| {
                *value = Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:bob.example")
                        .station("ak:did_core:web:other.example")
                        .build(),
                )
            }),
            2 => base.revise(|value| *value = "https://other-route.example".to_owned()),
            3 => token.revise(|value| *value = String::new()),
            _ => account.revise(|value| *value = None),
        };
        settle(&mut dom).await;
        {
            assert_ne!(
                controller.avatar_selection_epoch.get_untracked(),
                before,
                "boundary change {change}"
            );
            assert!(!controller.avatar_reading.get_untracked());
            assert!(controller.pending_avatar_crop.get_untracked().is_none());
            assert!(controller.avatar_upload_status.get_untracked().is_empty());
        };
    }
}

#[tokio::test(flavor = "current_thread")]
async fn picking_or_cancelling_an_image_does_not_invalidate_other_operations() {
    let (_directory, mut dom, controller, _) = mounted().await;
    let session = controller.settings_session.capture();
    {
        controller
            .clone()
            .stage_avatar_crop(file(b"old"), "image/png".to_owned());
        controller.clone().cancel_avatar_crop();
    };
    settle(&mut dom).await;
    {
        assert!(controller.settings_session.is_current(&session));
    };
}

#[tokio::test(flavor = "current_thread")]
async fn live_roots_reject_completion_before_cleanup_effect_runs() {
    let (_directory, mut dom, controller, (account, base, token, generation)) = mounted().await;
    for change in 0..4 {
        {
            let started = controller.settings_session.capture();
            controller.avatar_uploading.revise(|value| *value = true);
            match change {
                0 => account.revise(|value| {
                    *value = Some(
                        crate::test_support::AccountFixture::new("ak:did_core:web:bob.example")
                            .build(),
                    )
                }),
                1 => base.revise(|value| *value = "https://changed-route.example".to_owned()),
                2 => token.revise(|value| *value = "replacement-session".to_owned()),
                _ => generation.revise(|value| *value = 1),
            }
            // No render or effect has run since the root signal changed. An
            // old completion released now must already be forbidden to land.
            assert!(controller.avatar_uploading.get_untracked());
            assert!(!controller.settings_session.is_current(&started));
        };
        settle(&mut dom).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn upload_first_poll_rejects_old_session_before_synchronous_crop_failure() {
    // Deliberately omit the UI cleanup effect. The production command itself
    // must reject stale completion, even before any cleanup can clear feedback.
    let (_directory, mut dom, controller, (account, ..)) = mounted_with_cleanup(false).await;
    {
        account.revise(|value| {
            *value = Some(
                crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build(),
            )
        });
        controller.avatar_uploading.revise(|value| *value = true);
        controller
            .avatar_upload_status
            .revise(|value| *value = "original-session-upload".to_owned());
        controller.clone().upload_cropped_avatar(
            "https://local.host".to_owned(),
            "old-session".to_owned(),
            "alice".to_owned(),
            PendingAvatarCrop {
                bytes: b"invalid image".to_vec(),
                media_type: "image/png".to_owned(),
                preview_data_url: String::new(),
                dimensions: (1, 1),
            },
            crate::avatar_crop::AvatarCrop {
                zoom: 1.0,
                pan_x: 0.0,
                pan_y: 0.0,
            },
        );
        // The spawned crop future has not been polled when the root changes.
        account.revise(|value| {
            *value = Some(
                crate::test_support::AccountFixture::new("ak:did_core:web:bob.example").build(),
            )
        });
    };
    settle(&mut dom).await;
    {
        assert_eq!(
            controller.avatar_upload_status.get_untracked().as_str(),
            "original-session-upload"
        );
        assert!(controller.avatar_uploading.get_untracked());
    };
}

#[tokio::test(flavor = "current_thread")]
async fn invite_writes_serialize_hide_secret_and_retain_failed_revoke_for_retry() {
    let (_directory, mut dom, controller, _) = mounted().await;
    let (send, receive) = tokio::sync::oneshot::channel();
    {
        let stamp = controller.settings_session.capture();
        controller.invite_locator.revise(|value| {
            *value = InviteLocatorState {
                session: Some(stamp),
                id: "owned-locator".into(),
                token: "secret".into(),
                ..Default::default()
            }
        });
        controller
            .clone()
            .run_invite_locator(true, |id| async move {
                assert_eq!(id, "owned-locator");
                receive.await.unwrap()
            });
        controller
            .clone()
            .run_invite_locator(false, |_| async { panic!("overlapping write") });
        let state = controller.invite_locator.get_untracked();
        assert!(state.busy);
        assert!(state.token.is_empty());
    };
    settle(&mut dom).await;
    send.send(Err("response lost".into())).unwrap();
    settle(&mut dom).await;
    {
        assert_eq!(
            controller.invite_locator.get_untracked().id,
            "owned-locator"
        );
        assert!(!controller.invite_locator.get_untracked().busy);
        controller
            .clone()
            .run_invite_locator(true, |_| async { Ok(None) });
    };
    settle(&mut dom).await;
    {
        let state = controller.invite_locator.get_untracked();
        assert!(state.id.is_empty());
        assert!(state.token.is_empty());
        assert!(!state.busy);
    };
}

#[tokio::test(flavor = "current_thread")]
async fn invite_delayed_completion_cannot_cross_any_session_coordinate() {
    for change in 0..8 {
        let (_directory, mut dom, controller, (account, base, token, generation)) =
            mounted_with_cleanup(false).await;
        let (send, receive) = tokio::sync::oneshot::channel();
        {
            account.revise(|value| {
                *value = Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:alice.example")
                        .build(),
                )
            });
            controller
                .clone()
                .run_invite_locator(false, |_| async move { receive.await.unwrap() });
        };
        settle(&mut dom).await;
        match change {
            0 => account.revise(|value| *value = None),
            1 => account.revise(|value| {
                *value = Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:bob.example").build(),
                )
            }),
            2 => account.revise(|value| {
                *value = Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:alice.example")
                        .station("ak:did_core:web:another.example")
                        .build(),
                )
            }),
            3 => base.revise(|value| *value = "https://another-route.example".into()),
            4 => token.revise(|value| *value = "new-session".into()),
            5 => account.revise(|value| {
                *value = Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:alice.example")
                        .device("ak:device:01964137-0000-7000-8000-000000000002")
                        .build(),
                )
            }),
            6 => account.revise(|value| {
                *value = Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:alice.example")
                        .server_url("https://other-server.example")
                        .build(),
                )
            }),
            _ => generation.revise(|value| *value = 1),
        };
        send.send(Ok(Some(arkret_sdk::InviteLocatorIssueResponseBody {
            locator_id: arkret_sdk::InviteLocatorId::new(
                "ak:invite_locator:0196419b-0000-7000-8000-000000000000",
            )
            .unwrap(),
            locator_token: "old-account-secret".into(),
            expires_at: chrono::Utc::now(),
            one_time_use: false,
        })))
        .unwrap();
        settle(&mut dom).await;
        {
            assert!(
                controller.invite_locator.get_untracked().token.is_empty(),
                "coordinate {change}"
            );
        };
    }
}

#[tokio::test(flavor = "current_thread")]
async fn invite_switch_before_first_poll_does_not_dispatch_old_operation() {
    let (_directory, mut dom, controller, (account, ..)) = mounted_with_cleanup(false).await;
    {
        controller
            .clone()
            .run_invite_locator(false, |_| async { panic!("stale invite dispatch") });
        account.revise(|value| {
            *value = Some(
                crate::test_support::AccountFixture::new("ak:did_core:web:bob.example").build(),
            )
        });
    };
    settle(&mut dom).await;
    {
        assert!(controller.invite_locator.get_untracked().token.is_empty());
    };
}

struct TestApp {
    app: glory::ui::App,
    executor: Rc<glory::core::executor::Executor>,
}
impl std::ops::Deref for TestApp {
    type Target = glory::ui::App;
    fn deref(&self) -> &Self::Target {
        &self.app
    }
}
impl TestApp {
    fn new() -> Self {
        let executor = Rc::new(glory::core::executor::Executor::new(256));
        let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        Self { app, executor }
    }
    fn flush(&self) -> glory::ui::Result {
        for _ in 0..256 {
            if !self.executor.poll_one() {
                break;
            }
        }
        self.app.flush()
    }
}
