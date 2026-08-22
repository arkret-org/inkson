use std::collections::BTreeMap;

use dioxus::prelude::*;

use crate::components::UiIcon;
use crate::file_transfer::{
    FileTransferItem, data_url_for_download, decrypt_file_transfer_item, display_filename,
    file_transfer_items_from_account_data, format_size, load_file_transfer_crypto_context,
    load_or_create_file_transfer_crypto_context, upload_actor_private_file,
};

#[component]
pub fn FileTransferPanel(
    token: Signal<String>,
    principal_id: String,
    device_id: String,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let session = crate::app::SessionContext::get();
    let base_url = session.base_url.read().clone();
    let state_store = session.state_store;
    let active_account = session.active_account;
    let Some(account) = active_account() else {
        return rsx! {};
    };
    let authority = account.authority;
    let mut items = use_signal(Vec::<FileTransferItem>::new);
    let mut status = use_signal(|| "Ready".to_owned());
    let refreshing = use_signal(|| false);
    let mut uploading = use_signal(|| false);
    let download_urls = use_signal(BTreeMap::<String, String>::new);
    let backup_trigger_signal = crate::components::try_needs_mls_backup_signal();

    {
        let base_url = base_url.clone();
        let principal_id = principal_id.clone();
        let device_id = device_id.clone();
        let authority = authority.clone();
        use_effect(move || {
            refresh_items(
                base_url.clone(),
                token(),
                authority.clone(),
                principal_id.clone(),
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
                            let principal_id = principal_id.clone();
                            let device_id = device_id.clone();
                            let authority = authority.clone();
                            move |evt: Event<FormData>| {
                                let files = evt.files();
                                if files.is_empty() {
                                    status.set("No file selected".to_owned());
                                    return;
                                }
                                let api_token = token();
                                let base_url = base_url.clone();
                                let actor = principal_id.clone();
                                let device = device_id.clone();
                                let authority = authority.clone();
                                uploading.set(true);
                                status.set("Uploading".to_owned());
                                spawn(async move {
                                    let api = match crate::transport::auth::with_authed_api(
                                        &base_url,
                                        api_token.clone(),
                                        |api| async move { Ok(api) },
                                    )
                                    .await
                                    {
                                        Ok(api) => api,
                                        Err(error) => {
                                            status.set(error.display());
                                            uploading.set(false);
                                            return;
                                        }
                                    };
                                    let crypto = match load_or_create_file_transfer_crypto_context(&authority) {
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
                                            Err(error) => {
                                                last_error = Some(
                                                    crate::api_error::display_user_facing(&error),
                                                );
                                            }
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
                                            crate::components::maybe_auto_backup_mls_after_encrypted_write(
                                                base_url.clone(),
                                                api_token.clone(),
                                                authority.clone(),
                                                actor.clone(),
                                                device.clone(),
                                                state_store,
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
                            let principal_id = principal_id.clone();
                            let device_id = device_id.clone();
                            let authority = authority.clone();
                            move |_| {
                                refresh_items(
                                    base_url.clone(),
                                    token(),
                                    authority.clone(),
                                    principal_id.clone(),
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
    api_token: String,
    mut status: Signal<String>,
    mut download_urls: Signal<BTreeMap<String, String>>,
) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
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
                        span { "{status_label(&item.record.status)}" }
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
                                let api = match crate::transport::auth::with_authed_api(
                                    &base_url,
                                    api_token,
                                    |api| async move { Ok(api) },
                                )
                                .await
                                {
                                    Ok(api) => api,
                                    Err(error) => {
                                        status.set(error.display());
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
    authority: arkret_sdk::PrincipalAuthorityKey,
    actor_id: String,
    _device_id: String,
    mut items: Signal<Vec<FileTransferItem>>,
    mut status: Signal<String>,
    mut refreshing: Signal<bool>,
) {
    if api_token.trim().is_empty() || actor_id.trim().is_empty() {
        items.set(Vec::new());
        status.set("Sign in required".to_owned());
        return;
    }
    refreshing.set(true);
    status.set("Refreshing".to_owned());
    spawn(async move {
        let api =
            match crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
                Ok(api)
            })
            .await
            {
                Ok(api) => api,
                Err(error) => {
                    status.set(error.display());
                    refreshing.set(false);
                    return;
                }
            };
        let crypto = match load_file_transfer_crypto_context(&authority) {
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
        let sync_result = match api.sdk_http_client() {
            Ok(http) => crate::client_core::account_subscribe_snapshot(&http, None).await,
            Err(error) => Err(error),
        };
        match sync_result {
            Ok(sync) => {
                let account_data = sync
                    .updates
                    .account_data
                    .iter()
                    .filter_map(|event| serde_json::to_value(&event.payload).ok())
                    .collect::<Vec<_>>();
                let next = file_transfer_items_from_account_data(&account_data, &crypto);
                let count = next.len();
                items.set(next);
                status.set(if count == 0 {
                    "Ready".to_owned()
                } else {
                    format!("Synced {count}")
                });
            }
            Err(error) => status.set(format!(
                "Refresh failed: {}",
                crate::api_error::display_user_facing(&error)
            )),
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

fn status_label(status: &crate::file_transfer::FileTransferStatus) -> &'static str {
    match status {
        crate::file_transfer::FileTransferStatus::Available => "available",
        crate::file_transfer::FileTransferStatus::Downloaded => "downloaded",
        crate::file_transfer::FileTransferStatus::Dismissed => "dismissed",
        crate::file_transfer::FileTransferStatus::Deleted => "deleted",
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
