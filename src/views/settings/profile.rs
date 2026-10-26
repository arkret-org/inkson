//! Account identity, staged avatar cropping, and the server-issued invite locator.
use controller::SettingsController;
use glory::prelude::{Length, Style, image};

use super::model::session_identity_labels;
use super::*;

fn avatar_picker(
    scope: &Scope,
    context: Rc<InksonContext>,
    controller: SettingsController,
    key: &str,
    label_key: &str,
) -> View {
    let select = controller.clone();
    let pending = controller.pending_avatar_crop;
    let epoch = controller.avatar_selection_epoch;
    let status = controller.avatar_upload_status;
    let uploading = controller.avatar_uploading;
    let removing = controller.avatar_removing;
    let state = controller.avatar_file_read.clone().on_begin(move || {
        epoch.revise(|epoch| epoch.advance());
        status.revise(|value| *value = crate::i18n::tr("settings.avatar.processing"));
    });
    crate::components::avatar_uploader::image_file_picker_labeled_with_state(
        context.clone(),
        key.to_owned(),
        context.translated(scope, label_key).into(),
        scope
            .bond(move || !uploading.get() && !removing.get())
            .into(),
        Rc::new(move |image| {
            select
                .clone()
                .stage_avatar_crop(image.bytes, image.media_type)
        }),
        Rc::new(move |error| {
            pending.revise(|crop| *crop = None);
            status.revise(|value| *value = error);
        }),
        state,
    )
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let controller = SettingsController::new(scope, context.clone());
    controller::avatar_selection_boundary(scope, controller.clone());
    let hydrate = controller.clone();
    let hydrate_context = context.clone();
    let generation = context.session_generation.get();
    let account = context.active_account.get();
    let token = context.token.get();
    let base = context.base_url.get();
    spawn(scope, async move {
        let result = with_authed_sdk_client(&base, token, |http| async move {
            crate::transport::account::account_viewer(&http).await
        })
        .await;
        if !hydrate_context.session_matches(generation, &account) {
            return;
        }
        match result {
            Ok(viewer) => {
                if let Some(profile) = viewer.profile {
                    let profile = profile.into_inner();
                    hydrate
                        .profile_display_name
                        .revise(|value| *value = profile.display_name);
                    hydrate.profile_bio.revise(|value| {
                        *value = profile
                            .profile_fields
                            .get("biography")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    });
                }
            }
            Err(error) => tracing::warn!(?error, "settings profile hydration failed"),
        }
    });
    let name = controller.profile_display_name;
    let bio = controller.profile_bio;
    let text_busy = controller.profile_text_saving;
    let profile_enabled = scope.bond(move || !text_busy.get());
    let save = controller.clone();
    let save_context = context.clone();
    let file_picker = avatar_picker(
        scope,
        context.clone(),
        controller.clone(),
        "settings-avatar-input",
        "settings.avatar.upload",
    );
    let cancel_read = controller.clone();
    let reading = controller.avatar_reading;
    let cancel_read_control = reactive(reading, {
        let context = context.clone();
        move |scope, reading| {
            if !reading {
                return empty();
            }
            let cancel_read = cancel_read.clone();
            action(
                scope,
                context.clone(),
                "settings-avatar-read-cancel",
                "settings.avatar.cancel_crop",
                "secondary",
                true,
                move || cancel_read.clone().cancel_avatar_crop(),
            )
        }
    });
    let _avatar_state = controller.clone();
    let avatar_context = context.clone();
    let avatar_ref = controller.profile_avatar_blob_ref;
    let nonce = controller.avatar_refresh_nonce;
    let avatar = reactive(
        scope.bond(move || (avatar_ref.get(), nonce.get())),
        move |scope, (blob_ref, _)| {
            let context = avatar_context.clone();
            let principal = context
                .principal_id
                .get()
                .map(|value| value.to_string())
                .unwrap_or_default();
            crate::components::identity_avatar(
                scope,
                context,
                crate::components::IdentityAvatarProps {
                    seed: principal,
                    alt_text: crate::i18n::tr("settings.avatar.account_alt"),
                    blob_ref: (!blob_ref.is_empty()).then_some(blob_ref),
                    class: "avatar-img lg settings-avatar settings-avatar-preview settings-account-avatar".into(),
                    test_id: Some("settings-avatar-preview".into()),
                },
            )
        },
    );
    let crop_state = controller.clone();
    let crop_context = context.clone();
    let pending = controller.pending_avatar_crop;
    let uploading = controller.avatar_uploading;
    let removing = controller.avatar_removing;
    let reading = controller.avatar_reading;
    let zoom = controller.avatar_crop_zoom;
    let pan_x = controller.avatar_crop_x;
    let pan_y = controller.avatar_crop_y;
    let crop_enabled = scope.bond(move || !uploading.get() && !removing.get() && !reading.get());
    let cancel_enabled = scope.bond(move || !uploading.get() && !removing.get());
    let crop = reactive(pending, move |scope, selection| {
        let Some(selection) = selection else {
            return empty();
        };
        let context = crop_context.clone();
        let upload = crop_state.clone();
        let upload_context = context.clone();
        let cancel = crop_state.clone();
        let mut controls: Vec<View> = [
            (
                "settings-avatar-crop-zoom",
                "settings.avatar.zoom",
                zoom,
                100.0,
                300.0,
            ),
            (
                "settings-avatar-crop-x",
                "settings.avatar.pan_x",
                pan_x,
                -100.0,
                100.0,
            ),
            (
                "settings-avatar-crop-y",
                "settings.avatar.pan_y",
                pan_y,
                -100.0,
                100.0,
            ),
        ]
        .into_iter()
        .map(|(key, label, value, min, max)| {
            let selected = scope.bond(move || f64::from(value.get()));
            stack(
                "form-field",
                vec![
                    plain(context.translated(scope, label)),
                    Box::new(
                        sapid::slider(key)
                            .unstyled()
                            .class("avatar-crop-slider")
                            .name(context.translated(scope, label))
                            .value(selected)
                            .min(min)
                            .max(max)
                            .step(5.0)
                            .enabled(crop_enabled)
                            .on_value_change(move |next| {
                                value.revise(|value| {
                                    *value = (next.round() as i32).clamp(min as i32, max as i32)
                                })
                            }),
                    ),
                ],
            )
        })
        .collect();
        controls.insert(
            0,
            paragraph(
                "muted settings-avatar-source-size",
                format!(
                    "{} x {} / {}",
                    selection.dimensions.0, selection.dimensions.1, selection.media_type
                ),
            ),
        );
        controls.push(line(
            "actions",
            vec![
                avatar_picker(
                    scope,
                    context.clone(),
                    crop_state.clone(),
                    "settings-avatar-replace-input",
                    "settings.avatar.replace_image",
                ),
                action(
                    scope,
                    context.clone(),
                    "settings-avatar-crop-save",
                    "settings.avatar.upload_cropped",
                    "secondary",
                    crop_enabled,
                    move || {
                        if uploading.get_untracked()
                            || removing.get_untracked()
                            || reading.get_untracked()
                        {
                            return;
                        }
                        let Some(selection) = pending.get() else {
                            return;
                        };
                        uploading.revise(|value| *value = true);
                        upload.clone().upload_cropped_avatar(
                            upload_context.base_url.get(),
                            upload_context.token.get(),
                            upload_context.account_primary_handle.get(),
                            selection,
                            crate::avatar_crop::AvatarCrop {
                                zoom: zoom.get() as f32 / 100.0,
                                pan_x: pan_x.get() as f32 / 100.0,
                                pan_y: pan_y.get() as f32 / 100.0,
                            },
                        );
                    },
                ),
                action(
                    scope,
                    context.clone(),
                    "settings-avatar-crop-cancel",
                    "settings.avatar.cancel_crop",
                    "secondary",
                    cancel_enabled,
                    move || cancel.clone().cancel_avatar_crop(),
                ),
            ],
        ));
        let preview =
            match crate::content::scoped_image_url(scope, &context, &selection.preview_data_url) {
                Ok(source) => Box::new(
                    image()
                        .class("settings-avatar-crop-image")
                        .source(source)
                        .alt(context.translated(scope, "settings.avatar.selected_alt"))
                        .style(scope.bond(move || {
                            let scale = f64::from(zoom.get());
                            Style::new()
                                .position(glory::style::Position::Absolute)
                                .width(Length::Percent(scale))
                                .height(Length::Percent(scale))
                                .left(Length::Percent(
                                    (100.0 - scale) / 2.0 + f64::from(pan_x.get()) / 4.0,
                                ))
                                .top(Length::Percent(
                                    (100.0 - scale) / 2.0 + f64::from(pan_y.get()) / 4.0,
                                ))
                                .object_fit(glory::style::ObjectFit::Cover)
                        })),
                ) as View,
                Err(error) => paragraph("form-hint-warn", error),
            };
        let mut body = Some(glory::ui::group().fill(vec![
            stack("settings-avatar-crop-stage", vec![preview]),
            stack("settings-avatar-crop-controls", controls),
        ]));
        let close = crop_state.clone();
        Box::new(
            sapid::dialog("settings-avatar-crop")
                .unstyled()
                .class("settings-avatar-crop-dialog settings-avatar-crop-editor")
                .name(context.translated(scope, "settings.avatar.edit_dialog"))
                .open(true)
                .show_trigger(false)
                .show_close(false)
                .on_open_change(move |open| {
                    if !open && !uploading.get_untracked() && !removing.get_untracked() {
                        close.clone().cancel_avatar_crop();
                    }
                })
                .content(move || {
                    body.take()
                        .map(|value| Box::new(value) as View)
                        .unwrap_or_else(empty)
                }),
        ) as View
    });
    let clear = controller.clone();
    let clear_context = context.clone();
    let text_status = controller.profile_text_status;
    let upload_status = controller.avatar_upload_status;
    let cache_status = controller.avatar_cache_status;
    let identity = identity_grid(scope, context.clone());
    let invite_state = controller.clone();
    let invite_context = context.clone();
    let locator = controller.invite_locator;
    let invite = reactive(locator, move |scope, state| {
        let context = invite_context.clone();
        let issue = invite_state.clone();
        let revoke = invite_state.clone();
        let url = if state.token.is_empty() {
            String::new()
        } else {
            build_invite_locator_url(&context.base_url.get(), &state.token)
        };
        invite_locator_card(
            scope,
            context.clone(),
            InviteLocatorCardProps {
                has_session: !context.token.get().is_empty(),
                url,
                status: state.status,
                busy: state.busy,
                has_locator: !state.id.is_empty(),
                onrefresh: Rc::new(move |()| issue.clone().change_invite_locator(false)),
                onrevoke: Rc::new(move |()| revoke.clone().change_invite_locator(true)),
            },
        )
    });

    stack(
        "settings-card-grid",
        vec![
            stack(
                "event settings-card-span-2 settings-avatar-card",
                vec![
                    line(
                        "event-head",
                        vec![plain(
                            context.translated(scope, "settings.account.identity"),
                        )],
                    ),
                    stack(
                        "settings-profile-fields",
                        vec![
                            input(
                                scope,
                                context.clone(),
                                "settings-profile-display-name",
                                "settings.profile.display_name",
                                name,
                                profile_enabled,
                            ),
                            field(
                                scope,
                                context.clone(),
                                "settings-profile-biography",
                                "settings.profile.biography",
                                bio,
                                profile_enabled,
                                true,
                                move |next| bio.revise(|value| *value = next),
                            ),
                            line(
                                "actions",
                                vec![action(
                                    scope,
                                    context.clone(),
                                    "settings-profile-save",
                                    "settings.profile.save",
                                    "primary",
                                    profile_enabled,
                                    move || {
                                        save.clone().save_profile_text(
                                            save_context.base_url.get(),
                                            save_context.token.get(),
                                            save_context.account_primary_handle.get(),
                                        )
                                    },
                                )],
                            ),
                            status(text_status),
                        ],
                    ),
                    stack(
                        "settings-avatar-actions",
                        vec![
                            avatar,
                            stack(
                                "settings-avatar-controls",
                                vec![
                                    file_picker,
                                    cancel_read_control,
                                    crop,
                                    reactive(avatar_ref, move |scope, blob| {
                                        if blob.trim().is_empty() {
                                            return empty();
                                        }
                                        let clear = clear.clone();
                                        let clear_context = clear_context.clone();
                                        action(
                                            scope,
                                            context.clone(),
                                            "settings-avatar-clear",
                                            "settings.avatar.clear",
                                            "secondary",
                                            crop_enabled,
                                            move || {
                                                if uploading.get_untracked()
                                                    || removing.get_untracked()
                                                {
                                                    return;
                                                }
                                                removing.revise(|value| *value = true);
                                                clear.clone().cancel_avatar_crop();
                                                clear.clone().remove_avatar(
                                                    clear_context.base_url.get(),
                                                    clear_context.token.get(),
                                                    clear_context.account_primary_handle.get(),
                                                );
                                            },
                                        )
                                    }),
                                    status(upload_status),
                                    status(cache_status),
                                ],
                            ),
                        ],
                    ),
                    identity,
                ],
            ),
            invite,
        ],
    )
}

fn identity_grid(scope: &Scope, context: Rc<InksonContext>) -> View {
    let source_context = context.clone();
    reactive(
        scope.bond(move || {
            (
                source_context.token.get(),
                source_context.principal_id.get(),
                source_context.device_id.get(),
                source_context.personal_handles.get(),
                source_context.personal_handles_status.get(),
                source_context.locale.get(),
            )
        }),
        move |scope, (token, principal, device, handles, handle_status, _)| {
            let principal = principal.map(|value| value.to_string()).unwrap_or_default();
            let labels = session_identity_labels(
                !token.trim().is_empty(),
                &principal,
                &device,
                &handles,
                &handle_status,
            );
            let did_copy = labels.principal.clone();
            let device_copy = labels.device.clone();
            let handles_full = labels.handles_title.clone();
            let handles_context = context.clone();
            let handles_label = context.tr("settings.account.copy_handles");
            let handles_copy = labels.handles_title.clone();
            let handles_button = {
                #[cfg(target_arch = "wasm32")]
                {
                    let owner = scope.downgrade();
                    crate::components::button_hint(
                        context.clone(),
                        "settings-account-handles-hint".into(),
                        handles_label,
                        handles_full,
                        move |target| {
                            let Some(scope) = owner.upgrade() else {
                                return target.button(
                                    glory::ui::button()
                                        .name(handles_context.tr("settings.account.copy_handles"))
                                        .enabled(false)
                                        .fill(crate::components::ui_icon("copy")),
                                );
                            };
                            target.button(identity_copy_button(
                                &scope,
                                handles_context.clone(),
                                "settings-account-copy-handles",
                                "settings.account.copy_handles",
                                handles_copy.clone(),
                                "feedback.copied_handles",
                            ))
                        },
                    )
                }
                #[cfg(not(target_arch = "wasm32"))]
                {
                    Box::new(
                        identity_copy_button(
                            scope,
                            handles_context,
                            "settings-account-copy-handles",
                            "settings.account.copy_handles",
                            handles_copy,
                            "feedback.copied_handles",
                        )
                        .name(format!("{handles_label}: {handles_full}")),
                    ) as View
                }
            };
            stack(
                "metric-grid settings-account-identity-grid",
                vec![
                    line(
                        "metric settings-identity-row",
                        vec![
                            paragraph(
                                "settings-identity-label",
                                context.translated(scope, "app.account.did"),
                            ),
                            line(
                                "settings-identity-value",
                                vec![
                                    Box::new(
                                        glory::ui::text()
                                            .class("mono settings-account-did")
                                            .content(labels.principal),
                                    ),
                                    Box::new(identity_copy_button(
                                        scope,
                                        context.clone(),
                                        "settings-account-copy-did",
                                        "settings.account.copy_did",
                                        did_copy,
                                        "feedback.copied_did",
                                    )),
                                ],
                            ),
                        ],
                    ),
                    line(
                        "metric settings-identity-row",
                        vec![
                            paragraph(
                                "settings-identity-label",
                                context.translated(scope, "settings.account.handles"),
                            ),
                            line(
                                "settings-identity-value",
                                vec![
                                    Box::new(
                                        glory::ui::text()
                                            .class("mono settings-account-handles")
                                            .content(labels.handles_label),
                                    ),
                                    handles_button,
                                ],
                            ),
                        ],
                    ),
                    line(
                        "metric settings-identity-row",
                        vec![
                            paragraph(
                                "settings-identity-label",
                                context.translated(scope, "settings.account.current_device"),
                            ),
                            line(
                                "settings-identity-value",
                                vec![
                                    Box::new(
                                        glory::ui::text()
                                            .class("mono settings-account-device")
                                            .content(short_protocol_id(&labels.device)),
                                    ),
                                    Box::new(identity_copy_button(
                                        scope,
                                        context.clone(),
                                        "settings-account-copy-device",
                                        "settings.account.copy_device_id",
                                        device_copy,
                                        "feedback.copied_device_id",
                                    )),
                                ],
                            ),
                        ],
                    ),
                ],
            )
        },
    )
}
fn identity_copy_button(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label_key: &str,
    value: String,
    success_key: &'static str,
) -> glory::ui::Button {
    let owner = scope.downgrade();
    glory::ui::button()
        .class(format!("btn ghost icon settings-identity-copy {key}"))
        .name(context.translated(scope, label_key))
        .fill(crate::components::ui_icon("copy"))
        .on(glory::render::EventKind::Activate, move |_| {
            let Some(scope) = owner.upgrade() else {
                return;
            };
            let context = context.clone();
            let value = value.clone();
            let owner = scope.downgrade();
            let generation = context.session_generation.get_untracked();
            let account = context.active_account.get_untracked();
            spawn(&scope, async move {
                let result = crate::components::platform_io::copy_text(&value).await;
                if owner.upgrade().is_none() || !context.session_matches(generation, &account) {
                    return;
                }
                match result {
                    Ok(()) => crate::components::feedback::toast_success(success_key, vec![]),
                    Err(error) => tracing::warn!(%error,"identity clipboard write failed"),
                }
            });
        })
}
