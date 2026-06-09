use std::collections::BTreeMap;

use dioxus::prelude::*;

use crate::api::CokretApi;
use crate::components::UiIcon;
use crate::file_transfer::{
    FileTransferItem, data_url_for_download, decrypt_file_transfer_item, display_filename,
    file_transfer_items_from_account_data, format_size, load_file_transfer_crypto_context,
    load_or_create_file_transfer_crypto_context, upload_actor_private_file,
};

#[component]
pub fn FileTransferPanel(
    base_url: String,
    token: Signal<String>,
    account_did: String,
    device_id: String,
) -> Element {
    let mut items = use_signal(Vec::<FileTransferItem>::new);
    let mut status = use_signal(|| "Ready".to_owned());
    let refreshing = use_signal(|| false);
    let mut uploading = use_signal(|| false);
    let download_urls = use_signal(BTreeMap::<String, String>::new);
    let backup_trigger_signal = crate::components::try_needs_mls_backup_signal();

    {
        let base_url = base_url.clone();
        let account_did = account_did.clone();
        let device_id = device_id.clone();
        use_effect(move || {
            refresh_items(
                base_url.clone(),
                token(),
                account_did.clone(),
                device_id.clone(),
                items,
                status,
                refreshing,
            );
        });
    }

    let item_count = items.read().len();
    let total_size: u64 = items
        .read()
        .iter()
        .map(|item| item.record.plaintext_size_bytes)
        .sum();

    rsx! {
        section { class: "file-transfer-shell", "data-testid": "file-transfer-panel",
            div { class: "file-transfer-header",
                div {
                    h1 { "Files" }
                    div { class: "muted", "{item_count} items / {format_size(total_size)}" }
                }
                div { class: "actions",
                    label {
                        class: if uploading() { "btn primary disabled" } else { "btn primary" },
                        "data-testid": "file-transfer-upload-button",
                        r#for: "file-transfer-input",
                        UiIcon { name: "share" }
                        span { "Upload" }
                    }
                    input {
                        id: "file-transfer-input",
                        "data-testid": "file-transfer-input",
                        class: "file-transfer-input",
                        r#type: "file",
                        multiple: true,
                        disabled: uploading(),
                        onchange: {
                            let base_url = base_url.clone();
                            let account_did = account_did.clone();
                            let device_id = device_id.clone();
                            let backup_trigger_signal = backup_trigger_signal;
                            move |evt: Event<FormData>| {
                                let files = evt.files();
                                if files.is_empty() {
                                    status.set("No file selected".to_owned());
                                    return;
                                }
                                let api_token = token();
                                let base_url = base_url.clone();
                                let actor = account_did.clone();
                                let device = device_id.clone();
                                uploading.set(true);
                                status.set("Uploading".to_owned());
                                spawn(async move {
                                    let api = match CokretApi::new(&base_url) {
                                        Ok(api) => api.with_bearer(api_token.clone()),
                                        Err(error) => {
                                            status.set(format!("Invalid server URL: {error}"));
                                            uploading.set(false);
                                            return;
                                        }
                                    };
                                    let crypto = match load_or_create_file_transfer_crypto_context(&actor, &device) {
                                        Ok(crypto) => crypto,
                                        Err(error) => {
                                            status.set(format!("File key unavailable: {error}"));
                                            uploading.set(false);
                                            return;
                                        }
                                    };
                                    let mut uploaded = Vec::new();
                                    let mut last_error = None;
                                    for file in files {
                                        let filename = file.name();
                                        let media_type = file
                                            .content_type()
                                            .unwrap_or_else(|| "application/octet-stream".to_owned());
                                        let bytes = match file.read_bytes().await {
                                            Ok(bytes) => bytes.to_vec(),
                                            Err(error) => {
                                                last_error = Some(format!("{error}"));
                                                continue;
                                            }
                                        };
                                        match upload_actor_private_file(
                                            &api,
                                            &crypto,
                                            &actor,
                                            &device,
                                            Some(&filename),
                                            &media_type,
                                            bytes,
                                        )
                                        .await
                                        {
                                            Ok(result) => uploaded.push(result.item),
                                            Err(error) => last_error = Some(error.to_string()),
                                        }
                                    }
                                    if !uploaded.is_empty() {
                                        let mut next = items();
                                        next.splice(0..0, uploaded);
                                        next.sort_by(|left, right| {
                                            right
                                                .record
                                                .created_at
                                                .cmp(&left.record.created_at)
                                                .then_with(|| right.account_data_key.cmp(&left.account_data_key))
                                        });
                                        items.set(next);
                                        if let Some(signal) = backup_trigger_signal {
                                            crate::components::maybe_flag_mls_backup_after_encrypted_write(
                                                base_url.clone(),
                                                api_token.clone(),
                                                actor.clone(),
                                                signal,
                                            )
                                            .await;
                                        }
                                    }
                                    uploading.set(false);
                                    match last_error {
                                        Some(error) if item_count == 0 && items.read().is_empty() => {
                                            status.set(format!("Upload failed: {error}"));
                                        }
                                        Some(error) => {
                                            status.set(format!("Uploaded with warning: {error}"));
                                        }
                                        None => status.set("Upload complete".to_owned()),
                                    }
                                });
                            }
                        },
                    }
                    button {
                        class: "btn secondary",
                        "data-testid": "file-transfer-refresh-button",
                        r#type: "button",
                        disabled: refreshing(),
                        onclick: {
                            let base_url = base_url.clone();
                            let account_did = account_did.clone();
                            let device_id = device_id.clone();
                            move |_| {
                                refresh_items(
                                    base_url.clone(),
                                    token(),
                                    account_did.clone(),
                                    device_id.clone(),
                                    items,
                                    status,
                                    refreshing,
                                );
                            }
                        },
                        UiIcon { name: "refresh" }
                        span { "Refresh" }
                    }
                }
            }

            div { class: "file-transfer-status", "data-testid": "file-transfer-status",
                span { class: status_class(&status()), "{status()}" }
            }

            if items.read().is_empty() {
                div { class: "file-transfer-empty event",
                    span { class: "file-transfer-empty-icon", UiIcon { name: "file" } }
                    span { "No files" }
                }
            } else {
                div { class: "file-transfer-list", "data-testid": "file-transfer-list",
                    for item in items.read().iter().cloned() {
                        FileTransferRow {
                            item,
                            base_url: base_url.clone(),
                            api_token: token(),
                            status,
                            download_urls,
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn FileTransferRow(
    item: FileTransferItem,
    base_url: String,
    api_token: String,
    mut status: Signal<String>,
    mut download_urls: Signal<BTreeMap<String, String>>,
) -> Element {
    let transfer_id = item.record.transfer_id.clone();
    let filename = display_filename(&item.record);
    let digest_tail = digest_tail(&item.record.content_digest);
    let download_ready = download_urls.read().get(&transfer_id).cloned();

    rsx! {
        article { class: "file-transfer-row event", "data-testid": "file-transfer-row",
            div { class: "file-transfer-row-main",
                div { class: "file-transfer-file-icon", UiIcon { name: "file" } }
                div { class: "file-transfer-file-copy",
                    strong { title: "{filename}", "{filename}" }
                    div { class: "muted",
                        span { "{item.record.media_type}" }
                        span { " / " }
                        span { "{format_size(item.record.plaintext_size_bytes)}" }
                        span { " / " }
                        span { "{state_label(&item.record.state)}" }
                    }
                }
            }
            div { class: "file-transfer-meta",
                span { class: "mono", title: "{item.record.origin_device_id}", {short_id(&item.record.origin_device_id)} }
                span { class: "mono", title: "{item.record.content_digest}", "sha256:{digest_tail}" }
                span { class: "mono", title: "{item.record.created_at}", "{item.record.created_at}" }
            }
            div { class: "file-transfer-actions",
                button {
                    class: "btn sm secondary",
                    "data-testid": "file-transfer-prepare-download",
                    r#type: "button",
                    onclick: {
                        let item = item.clone();
                        let base_url = base_url.clone();
                        let api_token = api_token.clone();
                        let transfer_id = transfer_id.clone();
                        move |_| {
                            let item = item.clone();
                            let base_url = base_url.clone();
                            let api_token = api_token.clone();
                            let transfer_id = transfer_id.clone();
                            status.set("Preparing download".to_owned());
                            spawn(async move {
                                let api = match CokretApi::new(&base_url) {
                                    Ok(api) => api.with_bearer(api_token),
                                    Err(error) => {
                                        status.set(format!("Invalid server URL: {error}"));
                                        return;
                                    }
                                };
                                match decrypt_file_transfer_item(&api, &item).await {
                                    Ok(bytes) => {
                                        let data_url = data_url_for_download(&bytes, &item.record.media_type);
                                        let mut next = download_urls();
                                        next.insert(transfer_id.clone(), data_url);
                                        download_urls.set(next);
                                        status.set("Download ready".to_owned());
                                    }
                                    Err(error) => status.set(format!("Download failed: {error}")),
                                }
                            });
                        }
                    },
                    UiIcon { name: "download" }
                    span { "Prepare" }
                }
                if let Some(url) = download_ready {
                    a {
                        class: "btn sm primary",
                        "data-testid": "file-transfer-download-link",
                        href: "{url}",
                        download: "{filename}",
                        UiIcon { name: "download" }
                        span { "Save" }
                    }
                }
            }
        }
    }
}

fn refresh_items(
    base_url: String,
    api_token: String,
    actor_did: String,
    _device_id: String,
    mut items: Signal<Vec<FileTransferItem>>,
    mut status: Signal<String>,
    mut refreshing: Signal<bool>,
) {
    if api_token.trim().is_empty() || actor_did.trim().is_empty() {
        items.set(Vec::new());
        status.set("Sign in required".to_owned());
        return;
    }
    refreshing.set(true);
    status.set("Refreshing".to_owned());
    spawn(async move {
        let api = match CokretApi::new(&base_url) {
            Ok(api) => api.with_bearer(api_token),
            Err(error) => {
                status.set(format!("Invalid server URL: {error}"));
                refreshing.set(false);
                return;
            }
        };
        let crypto = match load_file_transfer_crypto_context(&actor_did) {
            Ok(Some(crypto)) => crypto,
            Ok(None) => {
                items.set(Vec::new());
                status.set("Ready".to_owned());
                refreshing.set(false);
                return;
            }
            Err(error) => {
                status.set(format!("File key unavailable: {error}"));
                refreshing.set(false);
                return;
            }
        };
        match api.account_subscribe_snapshot(None).await {
            Ok(sync) => {
                let next = file_transfer_items_from_account_data(&sync.account_data, &crypto);
                let count = next.len();
                items.set(next);
                status.set(if count == 0 {
                    "Ready".to_owned()
                } else {
                    format!("Synced {count}")
                });
            }
            Err(error) => status.set(format!("Refresh failed: {error}")),
        }
        refreshing.set(false);
    });
}

fn status_class(value: &str) -> &'static str {
    if value.contains("failed") || value.contains("unavailable") || value.contains("Invalid") {
        "badge badge-error"
    } else if value.contains("Uploading")
        || value.contains("Refreshing")
        || value.contains("Preparing")
    {
        "badge badge-info"
    } else {
        "badge badge-success"
    }
}

fn state_label(state: &crate::file_transfer::FileTransferState) -> &'static str {
    match state {
        crate::file_transfer::FileTransferState::Available => "available",
        crate::file_transfer::FileTransferState::Downloaded => "downloaded",
        crate::file_transfer::FileTransferState::Dismissed => "dismissed",
        crate::file_transfer::FileTransferState::Deleted => "deleted",
    }
}

fn digest_tail(value: &str) -> String {
    value
        .rsplit(':')
        .next()
        .map(|digest| digest.chars().take(12).collect())
        .unwrap_or_default()
}

fn short_id(value: &str) -> String {
    let suffix = value.rsplit(':').next().unwrap_or(value);
    if suffix.len() <= 12 {
        suffix.to_owned()
    } else {
        format!("...{}", &suffix[suffix.len().saturating_sub(12)..])
    }
}
