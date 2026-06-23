//! Shared avatar upload control for actor, Realm, and Space profiles.
//!
//! The component owns the file picker, image validation, crop preview, blob
//! upload, and local status text. Callers own the profile write that stores
//! the returned `avatar_blob_ref`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use dioxus::prelude::*;

use crate::ui::button::{Button, ButtonVariant};
use crate::ui::label::Label;
use crate::ui::slider::Slider;

#[derive(Clone, Debug, PartialEq)]
struct PendingAvatarSelection {
    bytes: Vec<u8>,
    media_type: String,
    preview_data_url: String,
    dimensions: (u32, u32),
    filename: String,
}

fn avatar_preview_data_url(bytes: &[u8], media_type: &str) -> String {
    let media_type = if media_type.trim().is_empty() {
        "application/octet-stream"
    } else {
        media_type
    };
    format!("data:{media_type};base64,{}", BASE64_STANDARD.encode(bytes))
}

#[derive(Clone, PartialEq, Props)]
pub struct AvatarUploaderProps {
    pub current_blob_ref: String,
    pub alt_text: String,
    pub base_url: String,
    pub api_token: String,
    pub on_uploaded: EventHandler<String>,
    pub on_clear: EventHandler<()>,
    #[props(default)]
    pub upload_realm_id: Option<String>,
    #[props(default = "avatar-uploader".to_owned())]
    pub test_id_prefix: String,
}

#[component]
pub fn AvatarUploader(props: AvatarUploaderProps) -> Element {
    let AvatarUploaderProps {
        current_blob_ref,
        alt_text,
        base_url,
        api_token,
        on_uploaded,
        on_clear,
        upload_realm_id,
        test_id_prefix,
    } = props;

    let mut pending_selection = use_signal(|| None::<PendingAvatarSelection>);
    let mut crop_zoom = use_signal(|| 125_i32);
    let mut crop_x = use_signal(|| 0_i32);
    let mut crop_y = use_signal(|| 0_i32);
    let mut status = use_signal(String::new);

    let input_id = format!("{test_id_prefix}-input");
    let preview_test_id = format!("{test_id_prefix}-preview");
    let upload_label_test_id = format!("{test_id_prefix}-upload-label");
    let input_test_id = format!("{test_id_prefix}-input");
    let crop_editor_test_id = format!("{test_id_prefix}-crop-editor");
    let crop_stage_test_id = format!("{test_id_prefix}-crop-stage");
    let source_size_test_id = format!("{test_id_prefix}-source-size");
    let crop_zoom_test_id = format!("{test_id_prefix}-crop-zoom");
    let crop_x_test_id = format!("{test_id_prefix}-crop-x");
    let crop_y_test_id = format!("{test_id_prefix}-crop-y");
    let upload_cropped_test_id = format!("{test_id_prefix}-upload-cropped");
    let crop_cancel_test_id = format!("{test_id_prefix}-crop-cancel");
    let clear_test_id = format!("{test_id_prefix}-clear");
    let status_test_id = format!("{test_id_prefix}-status");

    rsx! {
        div {
            class: "avatar-uploader",
            "data-testid": "{test_id_prefix}",
            div { class: "avatar-uploader-preview",
                if !current_blob_ref.trim().is_empty() {
                    div {
                        class: "avatar-img lg",
                        "data-testid": "{preview_test_id}",
                        crate::content::renderer::AuthenticatedBlobImage {
                            blob_ref: current_blob_ref.trim().to_owned(),
                            alt_text: alt_text.clone(),
                        }
                    }
                } else {
                    div {
                        class: "avatar-img lg placeholder",
                        "data-testid": "{preview_test_id}",
                        "—"
                    }
                }
            }
            div { class: "avatar-uploader-controls",
                Label {
                    class: "secondary avatar-upload-button",
                    "data-testid": "{upload_label_test_id}",
                    html_for: "{input_id}",
                    crate::components::UiIcon { name: "image" }
                    span { "Upload image" }
                }
                input {
                    id: "{input_id}",
                    "data-testid": "{input_test_id}",
                    class: "avatar-uploader-file-input",
                    style: "display: none;",
                    "aria-hidden": "true",
                    tabindex: "-1",
                    r#type: "file",
                    accept: "image/*",
                    onchange: {
                        move |evt: Event<FormData>| {
                            let files = evt.files();
                            if files.is_empty() {
                                status.set("No image selected.".to_owned());
                                return;
                            }
                            let Some(file) = files.into_iter().next() else {
                                status.set("No image selected.".to_owned());
                                return;
                            };
                            let filename = file.name();
                            let content_type = file
                                .content_type()
                                .unwrap_or_else(|| "application/octet-stream".to_owned());
                            if !content_type.starts_with("image/") {
                                status.set("Selected file is not an image.".to_owned());
                                return;
                            }
                            status.set("Preparing image...".to_owned());
                            spawn(async move {
                                let bytes = match file.read_bytes().await {
                                    Ok(bytes) => bytes.to_vec(),
                                    Err(err) => {
                                        status.set(format!("Could not read image: {err}"));
                                        return;
                                    }
                                };
                                let dimensions = match crate::avatar_crop::image_dimensions(&bytes) {
                                    Ok(dimensions) => dimensions,
                                    Err(err) => {
                                        status.set(format!("Could not decode image: {err}"));
                                        return;
                                    }
                                };
                                let preview_data_url = avatar_preview_data_url(&bytes, &content_type);
                                pending_selection.set(Some(PendingAvatarSelection {
                                    bytes,
                                    media_type: content_type,
                                    preview_data_url,
                                    dimensions,
                                    filename,
                                }));
                                crop_zoom.set(125);
                                crop_x.set(0);
                                crop_y.set(0);
                                status.set("Adjust crop, then save avatar.".to_owned());
                            });
                        }
                    },
                }

                if let Some(selection) = pending_selection.read().clone() {
                    div {
                        class: "avatar-crop-editor",
                        "data-testid": "{crop_editor_test_id}",
                        div {
                            class: "avatar-crop-stage",
                            "data-testid": "{crop_stage_test_id}",
                            img {
                                src: "{selection.preview_data_url}",
                                alt: "Selected avatar",
                                style: format!(
                                    "width: 100%; height: 100%; object-fit: cover; transform-origin: center; transform: translate({}% , {}%) scale({});",
                                    crop_x() / 4,
                                    crop_y() / 4,
                                    crop_zoom() as f32 / 100.0,
                                ),
                            }
                        }
                        div { class: "avatar-crop-controls",
                            div { class: "muted", "data-testid": "{source_size_test_id}",
                                {format!("{} x {} / {}", selection.dimensions.0, selection.dimensions.1, selection.media_type)}
                            }
                            label { class: "form-field",
                                span { "Zoom" }
                                Slider {
                                    "data-testid": "{crop_zoom_test_id}",
                                    min: 100.0,
                                    max: 300.0,
                                    step: 5.0,
                                    value: crop_zoom() as f64,
                                    on_value_change: move |value: f64| {
                                        crop_zoom.set((value as i32).clamp(100, 300));
                                    },
                                }
                            }
                            label { class: "form-field",
                                span { "Pan X" }
                                Slider {
                                    "data-testid": "{crop_x_test_id}",
                                    min: -100.0,
                                    max: 100.0,
                                    step: 5.0,
                                    value: crop_x() as f64,
                                    on_value_change: move |value: f64| {
                                        crop_x.set((value as i32).clamp(-100, 100));
                                    },
                                }
                            }
                            label { class: "form-field",
                                span { "Pan Y" }
                                Slider {
                                    "data-testid": "{crop_y_test_id}",
                                    min: -100.0,
                                    max: 100.0,
                                    step: 5.0,
                                    value: crop_y() as f64,
                                    on_value_change: move |value: f64| {
                                        crop_y.set((value as i32).clamp(-100, 100));
                                    },
                                }
                            }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "{upload_cropped_test_id}",
                                    onclick: {
                                        let base = base_url.clone();
                                        let api_token = api_token.clone();
                                        let upload_realm_id = upload_realm_id.clone();
                                        move |_| {
                                            let Some(selection) = pending_selection.read().clone() else {
                                                status.set("No image selected.".to_owned());
                                                return;
                                            };
                                            let crop = crate::avatar_crop::AvatarCrop {
                                                zoom: crop_zoom() as f32 / 100.0,
                                                pan_x: crop_x() as f32 / 100.0,
                                                pan_y: crop_y() as f32 / 100.0,
                                            };
                                            let base = base.clone();
                                            let api_token = api_token.clone();
                                            let upload_realm_id = upload_realm_id.clone();
                                            status.set("Uploading avatar...".to_owned());
                                            spawn(async move {
                                                let bytes = match crate::avatar_crop::crop_avatar_jpeg(&selection.bytes, crop) {
                                                    Ok(bytes) => bytes,
                                                    Err(err) => {
                                                        status.set(format!("Could not crop image: {err}"));
                                                        return;
                                                    }
                                                };
                                                let api = match crate::views::helpers::authed_api(&base, api_token) {
                                                    Ok(api) => api,
                                                    Err(err) => {
                                                        status.set(format!("Upload failed: {err}"));
                                                        return;
                                                    }
                                                };
                                                match api
                                                    .upload_blob_bytes_scoped(
                                                        bytes,
                                                        "image/jpeg",
                                                        upload_realm_id.as_deref(),
                                                        Some(&selection.filename),
                                                    )
                                                    .await
                                                {
                                                    Ok(resp) => {
                                                        let blob_ref = resp.blob_ref.to_string();
                                                        pending_selection.set(None);
                                                        status.set("Avatar uploaded.".to_owned());
                                                        on_uploaded.call(blob_ref);
                                                    }
                                                    Err(err) => status.set(format!("Upload failed: {err}")),
                                                }
                                            });
                                        }
                                    },
                                    "Save avatar"
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "{crop_cancel_test_id}",
                                    onclick: move |_| {
                                        pending_selection.set(None);
                                        status.set(String::new());
                                    },
                                    "Cancel"
                                }
                            }
                        }
                    }
                }

                if !current_blob_ref.trim().is_empty() {
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "{clear_test_id}",
                        onclick: move |_| {
                            pending_selection.set(None);
                            status.set("Avatar cleared.".to_owned());
                            on_clear.call(());
                        },
                        "Clear avatar"
                    }
                }

                if !status().is_empty() {
                    div {
                        class: "muted",
                        "data-testid": "{status_test_id}",
                        "{status}"
                    }
                }
            }
        }
    }
}
