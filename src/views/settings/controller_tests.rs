use std::cell::RefCell;
use std::rc::Rc;

use super::*;

#[derive(Clone)]
struct Control {
    path: std::path::PathBuf,
    subscribe_cleanup: bool,
    controller: Rc<RefCell<Option<SettingsController>>>,
    boundary: Rc<RefCell<Option<Boundary>>>,
}

type Boundary = (
    Signal<Option<crate::config::ActiveAccountContext>>,
    Signal<String>,
    Signal<String>,
    Signal<u64>,
);

fn harness(control: Control) -> Element {
    let active = use_signal(|| None);
    let base = use_signal(String::new);
    let token = use_signal(String::new);
    let generation = use_signal(|| 0_u64);
    let controller = SettingsController {
        invite_locator_id: use_signal(String::new),
        invite_locator_token: use_signal(String::new),
        invite_locator_status: use_signal(String::new),
        profile_avatar_blob_ref: use_signal(String::new),
        avatar_upload_status: use_signal(String::new),
        avatar_uploading: use_signal(|| false),
        avatar_cache_status: use_signal(String::new),
        avatar_removing: use_signal(|| false),
        avatar_reading: use_signal(|| false),
        settings_session: SettingsSessionSignals {
            active_account: active,
            base_url: base,
            token,
            generation,
        },
        avatar_selection_epoch: use_signal(AvatarSelectionEpoch::default),
        pending_avatar_crop: use_signal(|| None),
        avatar_crop_zoom: use_signal(|| 0),
        avatar_crop_x: use_signal(|| 0),
        avatar_crop_y: use_signal(|| 0),
        avatar_refresh_nonce: use_signal(|| 0),
        profile_display_name: use_signal(String::new),
        profile_bio: use_signal(String::new),
        profile_text_status: use_signal(String::new),
        profile_text_saving: use_signal(|| false),
        mimi_directory: use_signal(String::new),
        mimi_receipt: use_signal(String::new),
        mimi_directory_loading: use_signal(|| false),
        mimi_query_loading: use_signal(|| false),
        mimi_submit_loading: use_signal(|| false),
        mimi_proxy_loading: use_signal(|| false),
        mimi_submit_receipt: use_signal(String::new),
        mimi_proxy_receipt: use_signal(String::new),
        push_state: use_signal(String::new),
        theme: use_signal(String::new),
        state_store: use_signal_sync(|| crate::state::LocalStateStore::with_path(control.path)),
    };
    if control.subscribe_cleanup {
        use_avatar_selection_boundary(controller);
    }
    *control.boundary.borrow_mut() = Some((active, base, token, generation));
    *control.controller.borrow_mut() = Some(controller);
    rsx! { div {} }
}

fn file(bytes: &[u8]) -> dioxus::html::FileData {
    dioxus::html::FileData::new(dioxus::html::SerializedFileData {
        path: "fixture.png".into(),
        size: bytes.len() as u64,
        last_modified: 0,
        content_type: Some("image/png".to_owned()),
        contents: Some(bytes.to_vec().into()),
    })
}

async fn mounted() -> (tempfile::TempDir, VirtualDom, SettingsController, Boundary) {
    mounted_with_cleanup(true).await
}

async fn mounted_with_cleanup(
    subscribe_cleanup: bool,
) -> (tempfile::TempDir, VirtualDom, SettingsController, Boundary) {
    let directory = tempfile::tempdir().unwrap();
    let control = Control {
        path: directory.path().join("settings-state.json"),
        subscribe_cleanup,
        controller: Rc::new(RefCell::new(None)),
        boundary: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new_with_props(harness, control.clone());
    dom.rebuild_in_place();
    let controller = control.controller.borrow().unwrap();
    let boundary = control.boundary.borrow().unwrap();
    settle(&mut dom).await;
    (directory, dom, controller, boundary)
}

async fn settle(dom: &mut VirtualDom) {
    for _ in 0..8 {
        dom.render_immediate_to_vec();
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_of_real_staging_discards_late_errors() {
    let (_directory, mut dom, controller, _) = mounted().await;
    dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        controller.stage_avatar_crop(file(b"invalid image"), "image/png".to_owned());
        assert!(*controller.avatar_reading.peek());
        controller.cancel_avatar_crop();
    });
    settle(&mut dom).await;
    dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        assert!(controller.pending_avatar_crop.peek().is_none());
        assert!(!*controller.avatar_reading.peek());
        assert!(controller.avatar_upload_status.peek().is_empty());
    });
}

#[tokio::test(flavor = "current_thread")]
async fn replaced_read_cannot_report_its_error_over_new_selection() {
    let (_directory, mut dom, controller, _) = mounted().await;
    // The first file has an unsupported media type, while the replacement
    // reaches image decoding. The final error must belong to the replacement.
    dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        controller.stage_avatar_crop(file(b"old"), "text/plain".to_owned());
        controller.stage_avatar_crop(file(b"new"), "image/png".to_owned());
    });
    settle(&mut dom).await;
    dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        assert!(!*controller.avatar_reading.peek());
        assert!(controller.pending_avatar_crop.peek().is_none());
        let status = controller.avatar_upload_status.peek();
        assert!(!status.is_empty());
        assert!(!status.contains(&crate::i18n::tr("settings.avatar.invalid_image")));
    });
}

#[tokio::test(flavor = "current_thread")]
async fn staged_reads_do_not_replace_a_pending_avatar_write() {
    for removing in [false, true] {
        let (_directory, mut dom, mut controller, _) = mounted().await;
        dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
            controller
                .avatar_upload_status
                .set("existing upload status".to_owned());
            controller
                .avatar_cache_status
                .set("existing removal status".to_owned());
            if removing {
                controller.avatar_removing.set(true);
            } else {
                controller.avatar_uploading.set(true);
            }
            controller.stage_avatar_crop(file(b"ignored"), "image/png".to_owned());
        });
        settle(&mut dom).await;
        dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
            assert!(!*controller.avatar_reading.peek());
            assert_eq!(
                controller.avatar_upload_status.peek().as_str(),
                "existing upload status"
            );
            assert_eq!(
                controller.avatar_cache_status.peek().as_str(),
                "existing removal status"
            );
            assert_eq!(*controller.avatar_removing.peek(), removing);
            assert_eq!(*controller.avatar_uploading.peek(), !removing);
        });
    }
}

#[tokio::test(flavor = "current_thread")]
async fn real_session_boundary_subscribes_to_account_route_token_and_sign_out() {
    let (_directory, mut dom, mut controller, (mut account, mut base, mut token, _)) =
        mounted().await;
    dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        account.set(Some(
            crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build(),
        ));
        base.set("https://local.host".to_owned());
        token.set("old-session".to_owned());
    });
    settle(&mut dom).await;
    for change in 0..5 {
        let before = dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
            controller.avatar_reading.set(true);
            controller
                .avatar_upload_status
                .set("processing old account image".to_owned());
            controller.pending_avatar_crop.set(Some(PendingAvatarCrop {
                bytes: vec![1],
                media_type: "image/png".to_owned(),
                preview_data_url: "data:image/png;base64,AQ==".to_owned(),
                dimensions: (1, 1),
            }));
            *controller.avatar_selection_epoch.peek()
        });
        dom.in_scope(
            controller.pending_avatar_crop.origin_scope(),
            || match change {
                0 => account.set(Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:bob.example").build(),
                )),
                1 => account.set(Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:bob.example")
                        .station("ak:did_core:web:other.example")
                        .build(),
                )),
                2 => base.set("https://other-route.example".to_owned()),
                3 => token.set(String::new()),
                _ => account.set(None),
            },
        );
        settle(&mut dom).await;
        dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
            assert_ne!(
                *controller.avatar_selection_epoch.peek(),
                before,
                "boundary change {change}"
            );
            assert!(!*controller.avatar_reading.peek());
            assert!(controller.pending_avatar_crop.peek().is_none());
            assert!(controller.avatar_upload_status.peek().is_empty());
        });
    }
}

#[tokio::test(flavor = "current_thread")]
async fn picking_or_cancelling_an_image_does_not_invalidate_other_operations() {
    let (_directory, mut dom, controller, _) = mounted().await;
    let session = dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        controller.settings_session.capture()
    });
    dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        controller.stage_avatar_crop(file(b"old"), "image/png".to_owned());
        controller.cancel_avatar_crop();
    });
    settle(&mut dom).await;
    dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        assert!(controller.settings_session.is_current(&session));
    });
}

#[tokio::test(flavor = "current_thread")]
async fn live_roots_reject_completion_before_cleanup_effect_runs() {
    let (_directory, mut dom, mut controller, (mut account, mut base, mut token, mut generation)) =
        mounted().await;
    for change in 0..4 {
        dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
            let started = controller.settings_session.capture();
            controller.avatar_uploading.set(true);
            match change {
                0 => account.set(Some(
                    crate::test_support::AccountFixture::new("ak:did_core:web:bob.example").build(),
                )),
                1 => base.set("https://changed-route.example".to_owned()),
                2 => token.set("replacement-session".to_owned()),
                _ => generation.set(1),
            }
            // No render or effect has run since the root signal changed. An
            // old completion released now must already be forbidden to land.
            assert!(*controller.avatar_uploading.peek());
            assert!(!controller.settings_session.is_current(&started));
        });
        settle(&mut dom).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn upload_first_poll_rejects_old_session_before_synchronous_crop_failure() {
    // Deliberately omit the UI cleanup effect. The production command itself
    // must reject stale completion, even before any cleanup can clear feedback.
    let (_directory, mut dom, mut controller, (mut account, ..)) =
        mounted_with_cleanup(false).await;
    dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        account.set(Some(
            crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build(),
        ));
        controller.avatar_uploading.set(true);
        controller
            .avatar_upload_status
            .set("original-session-upload".to_owned());
        controller.upload_cropped_avatar(
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
        account.set(Some(
            crate::test_support::AccountFixture::new("ak:did_core:web:bob.example").build(),
        ));
    });
    settle(&mut dom).await;
    dom.in_scope(controller.pending_avatar_crop.origin_scope(), || {
        assert_eq!(
            controller.avatar_upload_status.peek().as_str(),
            "original-session-upload"
        );
        assert!(*controller.avatar_uploading.peek());
    });
}
