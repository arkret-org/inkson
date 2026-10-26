//! Shared image selection, validated crop preview and scoped blob upload.
use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use glory::prelude::*;

use crate::presentation::widgets::{line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
#[derive(Clone, Debug, PartialEq)]
pub struct SelectedImage {
    pub bytes: Vec<u8>,
    pub media_type: String,
    pub filename: String,
}

/// A page-owned read lease, independent of the crop editor's lifetime.
#[derive(Clone)]
pub struct ImageReadState {
    owner: glory::ui::WeakScope,
    pub reading: Cage<bool>,
    revision: Cage<u64>,
    request: Cage<Option<glory::render::QueryToken>>,
    controller: Cage<Option<sapid::FileController>>,
    started: Option<Rc<dyn Fn()>>,
}

impl ImageReadState {
    pub fn new(scope: &Scope, reading: Cage<bool>) -> Self {
        Self {
            owner: scope.downgrade(),
            reading,
            revision: scope.cage(0),
            request: scope.cage(None),
            controller: scope.cage(None),
            started: None,
        }
    }

    pub fn on_begin(mut self, started: impl Fn() + 'static) -> Self {
        self.started = Some(Rc::new(started));
        self
    }

    fn invalidate(&self, clear_files: bool) {
        let Some(scope) = self.owner.upgrade() else {
            return;
        };
        self.revision.revise(|value| *value = value.wrapping_add(1));
        let request = self.request.get_untracked();
        self.request.revise(|value| *value = None);
        if let Some(request) = request
            && let Err(error) = scope.cancel_request(request)
        {
            tracing::warn!(%error, "image read reply could not be revoked");
        }
        if clear_files
            && let Some(controller) = self.controller.get_untracked()
            && let Err(error) = controller.clear()
        {
            tracing::warn!(%error, "image file selection could not be cleared");
        }
        self.reading.revise(|value| *value = false);
    }

    /// Revoke the reply and file lease; a host operation already in progress
    /// may finish, but cannot publish or begin another bounded chunk.
    pub fn cancel(&self) {
        self.invalidate(true);
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn begin(&self) -> u64 {
        let revision = self.begin_lease();
        self.selection_started();
        revision
    }

    fn begin_lease(&self) -> u64 {
        // The host has already installed the replacement FileToken. Clearing
        // files here would incorrectly revoke that new selection as well.
        self.invalidate(false);
        self.reading.revise(|value| *value = true);
        self.revision.get_untracked()
    }

    fn selection_started(&self) {
        if let Some(started) = &self.started {
            started();
        }
    }

    fn is_current(&self, revision: u64) -> bool {
        self.owner.upgrade().is_some()
            && self.revision.try_get().is_ok_and(|value| value == revision)
    }

    fn finish(&self, revision: u64) {
        if self.is_current(revision) {
            self.request.revise(|value| *value = None);
            self.reading.revise(|value| *value = false);
        }
    }
}
pub(crate) fn avatar_preview_data_url(bytes: &[u8], media_type: &str) -> String {
    let media_type = if media_type.trim().is_empty() {
        "application/octet-stream"
    } else {
        media_type
    };
    format!("data:{media_type};base64,{}", BASE64_STANDARD.encode(bytes))
}
fn validate_image(selected: SelectedImage) -> std::result::Result<SelectedImage, String> {
    if !selected.media_type.starts_with("image/") {
        return Err("Selected file is not an image.".into());
    }
    crate::avatar_crop::image_dimensions(&selected.bytes)
        .map_err(|error| format!("Could not decode image: {error}"))?;
    Ok(selected)
}
pub fn image_file_picker(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: String,
    on_selected: Rc<dyn Fn(SelectedImage)>,
    on_error: Rc<dyn Fn(String)>,
) -> View {
    image_file_picker_labeled(
        scope,
        context,
        key,
        "Upload image".into(),
        true.into(),
        on_selected,
        on_error,
    )
}
pub fn image_file_picker_labeled(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: String,
    label: Lotus<String>,
    enabled: Lotus<bool>,
    on_selected: Rc<dyn Fn(SelectedImage)>,
    on_error: Rc<dyn Fn(String)>,
) -> View {
    let state = ImageReadState::new(scope, scope.cage(false));
    image_file_picker_labeled_with_state(context, key, label, enabled, on_selected, on_error, state)
}

#[cfg(target_arch = "wasm32")]
pub fn image_file_picker_labeled_with_state(
    context: Rc<InksonContext>,
    key: String,
    label: Lotus<String>,
    enabled: Lotus<bool>,
    on_selected: Rc<dyn Fn(SelectedImage)>,
    on_error: Rc<dyn Fn(String)>,
    state: ImageReadState,
) -> View {
    use glory::render::{FileConfig, FileFilter, FileRead, MAX_FILE_BYTES};
    Box::new(widget(move |scope| {
        let controller = scope.cage(None::<sapid::FileController>);
        let owner = state.owner.clone();
        let state = state.clone();
        let context = context.clone();
        let on_selected = on_selected.clone();
        let on_error = on_error.clone();
        sapid::file_button()
            .unstyled()
            .class(format!("secondary avatar-upload-button {key}"))
            .label(label.clone())
            .enabled(enabled.clone())
            .configuration(FileConfig {
                filters: vec![FileFilter::Mime("image/*".into())],
                max_file_bytes: MAX_FILE_BYTES,
                max_total_bytes: MAX_FILE_BYTES,
                ..Default::default()
            })
            .controller_ref(controller)
            .on_files(move |files| {
                #[cfg(feature = "spec-conformance")]
                tracing::warn!(
                    files = files.len(),
                    owner_alive = owner.upgrade().is_some(),
                    controller_ready = owner.upgrade().is_some()
                        && controller.is_alive()
                        && controller.get_untracked().is_some(),
                    "Avatar file selection received"
                );
                let Some(file) = files.into_iter().next() else {
                    return;
                };
                let Some(scope) = owner.upgrade() else { return };
                let Some(controller) = controller.get() else {
                    return;
                };
                state
                    .controller
                    .revise(|active| *active = Some(controller.clone()));
                let serial = state.begin();
                let state = state.clone();
                let ctx = context.clone();
                let generation = ctx.session_generation.get();
                let account = ctx.active_account.get();
                let selected = on_selected.clone();
                let error = on_error.clone();
                let owner = scope.downgrade();
                let failed_owner = owner.clone();
                let failed = error.clone();
                let failed_state = state.clone();
                if let Err(spawn_error) = scope.owner().spawn(async move {
                    let result = async {
                        if !file.media_type.starts_with("image/") {
                            return Err("Selected file is not an image.".to_owned());
                        }
                        let mut bytes = Vec::new();
                        let mut offset = 0;
                        while offset < file.size {
                            let Some(scope) = owner.upgrade() else {
                                return Err("Image owner retired".into());
                            };
                            if !state.is_current(serial)
                                || !ctx.session_matches(generation, &account)
                            {
                                return Err("Image selection replaced".into());
                            }
                            let length = (file.size - offset).min(65536) as u32;
                            let (sender, receiver) = tokio::sync::oneshot::channel();
                            let request = controller
                                .read_in(
                                    &scope,
                                    FileRead {
                                        file: file.token,
                                        offset,
                                        length,
                                    },
                                    move |result| {
                                        let _ = sender.send(result);
                                    },
                                )
                                .map_err(|error| error.to_string())?;
                            state.request.revise(|value| *value = Some(request));
                            let chunk = receiver
                                .await
                                .map_err(|_| "Image read stopped".to_owned())?
                                .map_err(|error| error.to_string())?;
                            if chunk.is_empty() {
                                return Err("Image read ended before its declared size".into());
                            }
                            offset += chunk.len() as u64;
                            bytes.extend(chunk);
                        }
                        validate_image(SelectedImage {
                            bytes,
                            media_type: file.media_type,
                            filename: file.name,
                        })
                    }
                    .await;
                    if owner.upgrade().is_none()
                        || !state.is_current(serial)
                        || !ctx.session_matches(generation, &account)
                    {
                        #[cfg(feature = "spec-conformance")]
                        tracing::warn!(
                            owner_alive = owner.upgrade().is_some(),
                            session_current = ctx.session_matches(generation, &account),
                            "Avatar file selection retired before completion"
                        );
                        return;
                    }
                    #[cfg(feature = "spec-conformance")]
                    tracing::warn!(
                        success = result.is_ok(),
                        "Avatar file read completed for current selection"
                    );
                    state.finish(serial);
                    match result {
                        Ok(image) => selected(image),
                        Err(message) => error(message),
                    }
                }) {
                    failed_state.finish(serial);
                    if failed_owner.upgrade().is_some() {
                        failed(format!("Could not start image read: {spawn_error}"));
                    }
                }
            })
            .on_result(move |outcome| {
                #[cfg(feature = "spec-conformance")]
                {
                    let outcome_kind = match &outcome {
                        glory::render::FileOutcome::Selected(_) => "selected",
                        glory::render::FileOutcome::Cancelled => "cancelled",
                        glory::render::FileOutcome::Rejected(_) => "rejected",
                    };
                    tracing::warn!(outcome_kind, "Avatar file chooser completed");
                }
                if let glory::render::FileOutcome::Rejected(reason) = outcome {
                    tracing::warn!(?reason, "image selection rejected");
                }
            })
            .build(scope)
    }))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "avatar_uploader/image_read_tests.rs"]
mod image_read_tests;
#[cfg(not(target_arch = "wasm32"))]
pub fn image_file_picker_labeled_with_state(
    context: Rc<InksonContext>,
    key: String,
    label: Lotus<String>,
    enabled: Lotus<bool>,
    on_selected: Rc<dyn Fn(SelectedImage)>,
    on_error: Rc<dyn Fn(String)>,
    state: ImageReadState,
) -> View {
    let owner = state.owner.clone();
    Box::new(
        sapid::button()
            .unstyled()
            .class(format!("secondary avatar-upload-button {key}"))
            .name(label.clone())
            .fill(glory::ui::group().fill((super::ui_icon("image"), text().content(label))))
            .enabled(enabled)
            .on_press(move || {
                let Some(scope) = owner.upgrade() else { return };
                let owner = scope.downgrade();
                let context = context.clone();
                let serial = state.begin_lease();
                let state = state.clone();
                let generation = context.session_generation.get();
                let account = context.active_account.get();
                let selected = on_selected.clone();
                let error = on_error.clone();
                let failed = error.clone();
                let failed_state = state.clone();
                if let Err(spawn_error) = scope.owner().spawn(async move {
                    let result = super::platform_io::choose_image().await.and_then(|value| {
                        value
                            .map(|(bytes, media_type, filename)| {
                                validate_image(SelectedImage {
                                    bytes,
                                    media_type,
                                    filename,
                                })
                            })
                            .transpose()
                    });
                    if owner.upgrade().is_none()
                        || !state.is_current(serial)
                        || !context.session_matches(generation, &account)
                    {
                        return;
                    }
                    if !matches!(&result, Ok(None)) {
                        state.selection_started();
                    }
                    state.finish(serial);
                    match result {
                        Ok(Some(value)) => selected(value),
                        Ok(None) => {}
                        Err(message) => error(message),
                    }
                }) {
                    failed_state.finish(serial);
                    if failed_state.owner.upgrade().is_some() {
                        failed(format!("Could not start image read: {spawn_error}"));
                    }
                }
            }),
    )
}
#[derive(Clone)]
pub struct AvatarUploaderProps {
    pub current_blob_ref: String,
    pub alt_text: String,
    pub api_token: String,
    pub on_uploaded: Rc<dyn Fn(String)>,
    pub on_clear: Rc<dyn Fn(())>,
    pub upload_realm_id: Option<String>,
    pub test_id_prefix: String,
}
fn crop_slider(_scope: &Scope, label: &str, value: Cage<f64>, min: f64, max: f64) -> View {
    stack(
        "form-field",
        vec![
            paragraph("", label.to_owned()),
            Box::new(
                sapid::slider(format!(
                    "avatar-crop-{}",
                    label.to_ascii_lowercase().replace(' ', "-")
                ))
                .unstyled()
                .class("slider")
                .name(label.to_owned())
                .min(min)
                .max(max)
                .step(5.0)
                .value(value)
                .on_value_change(move |next| value.revise(|value| *value = next.clamp(min, max))),
            ),
        ],
    )
}
pub fn avatar_uploader(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: AvatarUploaderProps,
) -> View {
    let seed: Lotus<String> = props.alt_text.clone().into();
    avatar_uploader_with_seed(scope, context, props, seed)
}

/// Preview identity changes independently of the file and crop owners.
pub fn avatar_uploader_with_seed(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: AvatarUploaderProps,
    seed: Lotus<String>,
) -> View {
    let pending = scope.cage(None::<SelectedImage>);
    let zoom = scope.cage(125.0_f64);
    let pan_x = scope.cage(0.0_f64);
    let pan_y = scope.cage(0.0_f64);
    let status = scope.cage(String::new());
    let busy = scope.cage(false);
    let selected = Rc::new(move |image| {
        pending.revise(|value| *value = Some(image));
        zoom.revise(|value| *value = 125.0);
        pan_x.revise(|value| *value = 0.0);
        pan_y.revise(|value| *value = 0.0);
        status.revise(|value| *value = "Adjust crop, then save avatar.".into());
    });
    let picker = image_file_picker(
        scope,
        context.clone(),
        format!("{}-input", props.test_id_prefix),
        selected,
        Rc::new(move |error| status.revise(|value| *value = error)),
    );
    let avatar_context = context.clone();
    let current_blob = props.current_blob_ref.clone();
    let avatar = crate::presentation::widgets::reactive_distinct(seed, move |scope, seed| {
        super::generated_avatar::identity_avatar(
            scope,
            avatar_context.clone(),
            super::generated_avatar::IdentityAvatarProps {
                alt_text: if current_blob.trim().is_empty() {
                    format!("Generated avatar for {seed}")
                } else {
                    seed.clone()
                },
                seed,
                blob_ref: Some(current_blob.clone()),
                class: "avatar-img lg".into(),
                test_id: None,
            },
        )
    });
    let ctx = context.clone();
    let upload = props.on_uploaded;
    let api_token = props.api_token;
    let realm = props.upload_realm_id;
    let crop = reactive(pending, move |scope, selection| {
        let Some(selection) = selection else {
            return crate::presentation::widgets::empty();
        };
        let selected_image = selection.clone();
        let preview = scope.bond(move || {
            let crop = crate::avatar_crop::AvatarCrop {
                zoom: zoom.get() as f32 / 100.0,
                pan_x: pan_x.get() as f32 / 100.0,
                pan_y: pan_y.get() as f32 / 100.0,
            };
            crate::avatar_crop::crop_avatar_jpeg(&selected_image.bytes, crop)
                .map(|bytes| avatar_preview_data_url(&bytes, "image/jpeg"))
                .unwrap_or_else(|_| {
                    avatar_preview_data_url(&selected_image.bytes, &selected_image.media_type)
                })
        });
        let preview_context = ctx.clone();
        let preview_view =
            reactive(
                preview,
                move |scope, source| match crate::content::scoped_image_url(
                    scope,
                    &preview_context,
                    &source,
                ) {
                    Ok(source) => Box::new(image().source(source).name("Selected avatar")) as View,
                    Err(error) => paragraph("form-hint-warn", error),
                },
            );
        let ctx = ctx.clone();
        let owner = scope.downgrade();
        let upload = upload.clone();
        let api_token = api_token.clone();
        let realm = realm.clone();
        let enabled = scope.bond(move || !busy.get());
        let save = Box::new(
            sapid::button()
                .unstyled()
                .class("primary")
                .label("Save avatar")
                .enabled(enabled)
                .on_press(move || {
                    if busy.get() {
                        return;
                    }
                    let Some(scope) = owner.upgrade() else { return };
                    let owner = scope.downgrade();
                    let Some(selection) = pending.get() else {
                        return;
                    };
                    let context = ctx.clone();
                    let generation = context.session_generation.get();
                    let account = context.active_account.get();
                    let base = context.base_url.get();
                    let token = api_token.clone();
                    let realm = realm.clone();
                    let upload = upload.clone();
                    let crop = crate::avatar_crop::AvatarCrop {
                        zoom: zoom.get() as f32 / 100.0,
                        pan_x: pan_x.get() as f32 / 100.0,
                        pan_y: pan_y.get() as f32 / 100.0,
                    };
                    busy.revise(|value| *value = true);
                    status.revise(|value| *value = "Uploading avatar...".into());
                    let _ = scope.owner().spawn(async move {
                        let result = async {
                            let bytes =
                                crate::avatar_crop::crop_avatar_jpeg(&selection.bytes, crop)
                                    .map_err(|error| format!("Could not crop image: {error}"))?;
                            let api = crate::transport::auth::authed_api(&base, token)
                                .map_err(|error| error.to_string())?;
                            let clients = crate::transport::EndpointClients::from_http(
                                api.sdk_http_client().map_err(|error| error.to_string())?,
                            );
                            clients
                                .blob()
                                .upload_bytes_scoped(
                                    bytes,
                                    "image/jpeg",
                                    realm.as_deref(),
                                    Some(&selection.filename),
                                )
                                .await
                                .map(|response| response.blob_ref.to_string())
                                .map_err(|error| error.to_string())
                        }
                        .await;
                        if owner.upgrade().is_none()
                            || !context.session_matches(generation, &account)
                        {
                            return;
                        }
                        busy.revise(|value| *value = false);
                        match result {
                            Ok(blob_ref) => {
                                pending.revise(|value| *value = None);
                                status.revise(|value| *value = "Avatar uploaded.".into());
                                upload(blob_ref);
                            }
                            Err(error) => {
                                status.revise(|value| *value = format!("Upload failed: {error}"))
                            }
                        }
                    });
                }),
        ) as View;
        let cancel = Box::new(
            sapid::button()
                .unstyled()
                .class("secondary")
                .label("Cancel")
                .enabled(enabled)
                .on_press(move || {
                    pending.revise(|value| *value = None);
                    status.revise(|value| value.clear());
                }),
        ) as View;
        let dimensions = crate::avatar_crop::image_dimensions(&selection.bytes).unwrap_or((0, 0));
        stack(
            "avatar-crop-editor",
            vec![
                stack("avatar-crop-stage", vec![preview_view]),
                stack(
                    "avatar-crop-controls",
                    vec![
                        paragraph(
                            "muted",
                            format!(
                                "{} x {} / {}",
                                dimensions.0, dimensions.1, selection.media_type
                            ),
                        ),
                        crop_slider(scope, "Zoom", zoom, 100.0, 300.0),
                        crop_slider(scope, "Pan X", pan_x, -100.0, 100.0),
                        crop_slider(scope, "Pan Y", pan_y, -100.0, 100.0),
                        line("actions", vec![save, cancel]),
                    ],
                ),
            ],
        )
    });
    let mut controls = vec![picker, crop];
    if !props.current_blob_ref.trim().is_empty() {
        let clear = props.on_clear;
        controls.push(Box::new(
            sapid::button()
                .unstyled()
                .class("secondary")
                .label("Clear avatar")
                .enabled(scope.bond(move || !busy.get()))
                .on_press(move || {
                    pending.revise(|value| *value = None);
                    status.revise(|value| *value = "Avatar cleared.".into());
                    clear(());
                }),
        ) as View);
    }
    controls.push(paragraph("muted", status));
    stack(
        "avatar-uploader",
        vec![
            stack("avatar-uploader-preview", vec![avatar]),
            stack("avatar-uploader-controls", controls),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::avatar_preview_data_url;

    #[test]
    fn avatar_preview_data_url_preserves_media_type_and_bytes() {
        assert_eq!(
            avatar_preview_data_url(b"avatar", "image/png"),
            "data:image/png;base64,YXZhdGFy"
        );
    }

    #[test]
    fn avatar_preview_data_url_defaults_an_empty_media_type() {
        assert_eq!(
            avatar_preview_data_url(b"avatar", "   "),
            "data:application/octet-stream;base64,YXZhdGFy"
        );
    }
}
