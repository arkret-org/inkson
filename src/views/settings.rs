use dioxus::prelude::*;
use serde_json::json;

use crate::{
    config::LocalConfigStore,
    i18n::Locale,
    local_state::LocalStateStore,
    views::helpers::{authed_api, persist_config},
    workflows::{WorkflowStage, blocked_release_workflows, production_release_workflows},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettingsSection {
    Server,
    Storage,
    Encryption,
    Mimi,
    Push,
    Privacy,
    Theme,
    Release,
    Recovery,
}

#[component]
pub fn SettingsPanel(
    mut base_url: Signal<String>,
    mut account_did: Signal<String>,
    mut device_id: Signal<String>,
    token: Signal<String>,
    crypto_state: String,
    mut config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    push_state: Signal<String>,
    mut locale: Signal<Locale>,
    mut theme: Signal<String>,
    status: Signal<String>,
    push_ready: bool,
) -> Element {
    let mut active_section = use_signal(|| SettingsSection::Server);
    let mut presence_visible = use_signal(|| true);
    let mut read_receipts_visible = use_signal(|| true);
    let mut mls_group_policy = use_signal(|| "default".to_owned());
    let mut key_backup_status = use_signal(|| "Not configured".to_owned());
    let mut mimi_directory = use_signal(|| "Not loaded".to_owned());
    let mut mimi_receipt = use_signal(|| "No MIMI action receipt".to_owned());
    let workflows = production_release_workflows();
    let blocked_count = blocked_release_workflows().len();
    let muted_spaces = state_store.read().muted_spaces();
    let active_locale = locale();
    let active_locale_code = active_locale.code();
    let active_direction = active_locale.direction().as_str();
    let push_registration = state_store.read().push_registration();
    let push_label = crate::push::push_status_label(push_registration.as_ref());

    rsx! {
        div { class: "settings", "data-testid": "settings-panel",
            // Section selector
            div { class: "actions", "data-testid": "settings-sections",
                button {
                    class: if active_section() == SettingsSection::Server { "primary" } else { "secondary" },
                    "data-testid": "section-server",
                    onclick: move |_| active_section.set(SettingsSection::Server),
                    "Server"
                }
                button {
                    class: if active_section() == SettingsSection::Storage { "primary" } else { "secondary" },
                    "data-testid": "section-storage",
                    onclick: move |_| active_section.set(SettingsSection::Storage),
                    "Storage"
                }
                button {
                    class: if active_section() == SettingsSection::Encryption { "primary" } else { "secondary" },
                    "data-testid": "section-encryption",
                    onclick: move |_| active_section.set(SettingsSection::Encryption),
                    "Encryption"
                }
                button {
                    class: if active_section() == SettingsSection::Mimi { "primary" } else { "secondary" },
                    "data-testid": "section-mimi",
                    onclick: move |_| active_section.set(SettingsSection::Mimi),
                    "MIMI"
                }
                button {
                    class: if active_section() == SettingsSection::Push { "primary" } else { "secondary" },
                    "data-testid": "section-push",
                    onclick: move |_| active_section.set(SettingsSection::Push),
                    "Push"
                }
                button {
                    class: if active_section() == SettingsSection::Privacy { "primary" } else { "secondary" },
                    "data-testid": "section-privacy",
                    onclick: move |_| active_section.set(SettingsSection::Privacy),
                    "Privacy"
                }
                button {
                    class: if active_section() == SettingsSection::Theme { "primary" } else { "secondary" },
                    "data-testid": "section-theme",
                    onclick: move |_| active_section.set(SettingsSection::Theme),
                    "Theme"
                }
                button {
                    class: if active_section() == SettingsSection::Release { "primary" } else { "secondary" },
                    "data-testid": "section-release",
                    onclick: move |_| active_section.set(SettingsSection::Release),
                    "Release"
                }
                button {
                    class: if active_section() == SettingsSection::Recovery { "primary" } else { "secondary" },
                    "data-testid": "section-recovery",
                    onclick: move |_| active_section.set(SettingsSection::Recovery),
                    "Recovery"
                }
            }

            // ── Server / Account settings ────────────────────────
            if active_section() == SettingsSection::Server {
                div { class: "event", "data-testid": "server-settings",
                    div { class: "event-head", span { "Settings" } span { "client configuration" } }
                    label { "Server URL" }
                    input {
                        "data-testid": "settings-server-url-input",
                        value: "{base_url}",
                        oninput: move |event| {
                            let value = event.value();
                            base_url.set(value.clone());
                            persist_config(config_store, value, account_did(), device_id(), token());
                        }
                    }
                    label { "Account DID" }
                    input {
                        "data-testid": "settings-account-did-input",
                        value: "{account_did}",
                        oninput: move |event| {
                            let value = event.value();
                            account_did.set(value.clone());
                            persist_config(config_store, base_url(), value, device_id(), token());
                        }
                    }
                    label { "Device ID" }
                    input {
                        "data-testid": "settings-device-id-input",
                        value: "{device_id}",
                        oninput: move |event| {
                            let value = event.value();
                            device_id.set(value.clone());
                            persist_config(config_store, base_url(), account_did(), value, token());
                        }
                    }
                }
                div { class: "event", "data-testid": "session-panel",
                    div { class: "event-head", span { "Session" } span { "bearer" } }
                    div { class: "muted", if token().is_empty() { "No token" } else { "Token loaded" } }
                    div { "{crypto_state}" }
                }
            }

            // ── Storage section ──────────────────────────────────
            if active_section() == SettingsSection::Storage {
                div { class: "event", "data-testid": "storage-table",
                    div { class: "event-head", span { "Local Stores" } span { "status" } }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Config Store" }
                            span { "Active" }
                        }
                        div { class: "metric",
                            strong { "Config Size" }
                            span { "~{config_store.read().load().server_url.len()} bytes" }
                        }
                        div { class: "metric",
                            strong { "State Store" }
                            span { "Active" }
                        }
                        div { class: "metric",
                            strong { "Platform" }
                            span { if cfg!(target_arch = "wasm32") { "Web (localStorage)" } else { "Native (filesystem)" } }
                        }
                    }
                }

                // Storage risk indicators
                div { class: "event", "data-testid": "storage-risks",
                    div { class: "event-head", span { "Storage Risks" } span { "warnings" } }
                    if cfg!(target_arch = "wasm32") {
                        div { class: "metric",
                            strong { "Web localStorage Limit" }
                            span { class: "badge", "data-testid": "risk-badge",
                                style: "background: #e67e22; color: white; padding: 2px 8px; border-radius: 4px;",
                                "Warning"
                            }
                        }
                        div { class: "muted",
                            "localStorage has a ~5MB limit. Large sync data, drafts, and cached operations may exceed this limit. Consider using IndexedDB for production."
                        }
                        div { class: "metric",
                            strong { "No Encryption at Rest" }
                            span { class: "badge",
                                style: "background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px;",
                                "Critical"
                            }
                        }
                        div { class: "muted",
                            "Web localStorage is not encrypted. Session tokens and cached data are accessible to any script on the same origin. Use secure httpOnly cookies or IndexedDB with encryption for production."
                        }
                        div { class: "metric",
                            strong { "No Cross-Tab Sync" }
                            span { class: "badge",
                                style: "background: #f39c12; color: white; padding: 2px 8px; border-radius: 4px;",
                                "Info"
                            }
                        }
                        div { class: "muted",
                            "localStorage changes in one tab are not automatically reflected in other tabs. Consider using BroadcastChannel or storage events for multi-tab sync."
                        }
                    } else {
                        div { class: "metric",
                            strong { "Filesystem Storage" }
                            span { class: "badge",
                                style: "background: #27ae60; color: white; padding: 2px 8px; border-radius: 4px;",
                                "OK"
                            }
                        }
                        div { class: "muted",
                            "Native filesystem storage is used. Data persists across sessions. Ensure proper file permissions for security."
                        }
                    }
                }
            }

            // ── Encryption settings ──────────────────────────────
            if active_section() == SettingsSection::Encryption {
                div { class: "event", "data-testid": "encryption-settings",
                    div { class: "event-head", span { "Encryption" } span { "MLS / E2EE" } }
                    label { "MLS Group Policy" }
                    select {
                        value: "{mls_group_policy}",
                        onchange: move |evt| mls_group_policy.set(evt.value()),
                        option { value: "default", "Default" }
                        option { value: "always-encrypt", "Always Encrypt" }
                        option { value: "prefer-plaintext", "Prefer Plaintext" }
                    }
                    div { class: "muted", "Current: {crypto_state}" }
                    label { "Key Backup" }
                    div { class: "muted", "{key_backup_status}" }
                    if push_ready {
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "key-backup-setup",
                            onclick: move |_| key_backup_status.set("Setup not yet available".to_owned()),
                            "Setup Key Backup"
                        }
                    }
                    } else {
                        div { class: "muted", "Push registration controls are hidden until /server/describe advertises push.register_device." }
                    }
                }
            }

            // ── MIMI interop facade ──────────────────────────────
            if active_section() == SettingsSection::Mimi {
                div { class: "event", "data-testid": "mimi-interop-panel",
                    div { class: "event-head", span { "MIMI Provider Facade" } span { "interop projection" } }
                    div { class: "muted", "Profile: cx.profile.mimi_interop.v1" }
                    div { class: "metric-grid", "data-testid": "mimi-draft-pinning",
                        div { class: "metric", strong { "Protocol" } span { "draft-ietf-mimi-protocol-06" } }
                        div { class: "metric", strong { "Content" } span { "draft-ietf-mimi-content-08" } }
                        div { class: "metric", strong { "Room Policy" } span { "draft-ietf-mimi-room-policy-03" } }
                        div { class: "metric", strong { "Identifiers" } span { "draft-kohbrok-mimi-identifiers-01" } }
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "mimi-refresh-directory",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_provider_directory().await {
                                                Ok(directory) => {
                                                    let features = directory.mimi.features.join(", ");
                                                    mimi_directory.set(format!(
                                                        "{}\n{}\n{}\n{}",
                                                        directory.mimi.provider_id,
                                                        directory.supported_profiles.join(", "),
                                                        directory.mimi.protocol_draft,
                                                        features
                                                    ));
                                                    status.set("MIMI provider directory refreshed".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI directory failed: {error}");
                                                    mimi_directory.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Refresh Directory"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "mimi-group-info",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_group_info("01JSMIMI").await {
                                                Ok(response) => {
                                                    mimi_receipt.set(format!(
                                                        "group-info {} participants {}",
                                                        response.room_id,
                                                        response.participants.len()
                                                    ));
                                                    status.set("MIMI groupInfo loaded".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI groupInfo failed: {error}");
                                                    mimi_receipt.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Group Info"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "mimi-identifier-query",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_identifier_query(json!({
                                                "query": "mimi://remote.example/alice",
                                                "privacy_mode": "private_identifier_query"
                                            })).await {
                                                Ok(response) => {
                                                    mimi_receipt.set(format!(
                                                        "identifier {} reachable {} mapped {}",
                                                        response.query,
                                                        response.reachable,
                                                        response.mapped_did.unwrap_or_else(|| "none".to_owned())
                                                    ));
                                                    status.set("MIMI identifier query completed".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI identifier query failed: {error}");
                                                    mimi_receipt.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Identifier Query"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "mimi-submit-message",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_submit_message("01JSMIMI", json!({
                                                "source_format": "text/markdown;variant=GFM-MIMI",
                                                "body": "MIMI interop test from yougen",
                                                "mimi_room_uri": "mimi://mimi.example.com/rooms/01JSMIMI"
                                            })).await {
                                                Ok(response) => {
                                                    mimi_receipt.set(format!(
                                                        "submit-message {} {}",
                                                        response.mimi_message_id.unwrap_or_else(|| "no-message-id".to_owned()),
                                                        response.mapped_operation_id.unwrap_or_else(|| "no-operation".to_owned())
                                                    ));
                                                    status.set("MIMI test message submitted".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI submit failed: {error}");
                                                    mimi_receipt.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Submit Test Message"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "mimi-proxy-download",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_proxy_download(json!({
                                                "blob_ref": "cx:blob:sha256:e2e",
                                                "asset_privacy_policy": "provider_proxy"
                                            })).await {
                                                Ok(response) => {
                                                    mimi_receipt.set(format!(
                                                        "proxy-download {} {}",
                                                        response.blob_ref,
                                                        response.media_type.unwrap_or_else(|| "unknown".to_owned())
                                                    ));
                                                    status.set("MIMI proxy download prepared".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI proxy download failed: {error}");
                                                    mimi_receipt.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Proxy Download"
                        }
                    }
                    div { class: "event", "data-testid": "mimi-directory-result",
                        div { class: "event-head", span { "Directory" } span { "features" } }
                        pre { "{mimi_directory}" }
                    }
                    div { class: "event", "data-testid": "mimi-action-receipt",
                        div { class: "event-head", span { "Receipt" } span { "last action" } }
                        pre { "{mimi_receipt}" }
                    }
                }
            }

            // ── Push notification settings ───────────────────────
            if active_section() == SettingsSection::Push {
                div { class: "event", "data-testid": "push-settings",
                    div { class: "event-head", span { "Push Notifications" } span { "configure" } }
                    div { class: "muted", "Push notification preferences and gateway registration." }
                    div { class: "muted", "data-testid": "push-registration-state", "Current: {push_label}" }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "push-register-button",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let dev = device_id();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match crate::push::build_register_request(&dev) {
                                                Ok(request) => match api.register_push_device_with_request(&request).await {
                                                    Ok(push) => {
                                                        let local_push = chime::RegisterDeviceResponse {
                                                            ok: push.ok,
                                                            registration_id: push.registration_id.clone(),
                                                            expires_at: push.expires_at.clone(),
                                                            ..Default::default()
                                                        };
                                                        let local_state = crate::push::registration_state_from_response(
                                                            &request,
                                                            &local_push,
                                                        );
                                                        state_store.write().save_push_registration(local_state);
                                                        let label = push.registration_id.unwrap_or_else(|| "registered".to_owned());
                                                        push_state.set(label.clone());
                                                        status.set(format!("Push registered: {label}"));
                                                    }
                                                    Err(error) => {
                                                        let message = format!("push register failed: {error}");
                                                        push_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => {
                                                    let message = format!("push unavailable: {error}");
                                                    push_state.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("push API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Register Push"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "push-unregister-button",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let dev = device_id();
                                    let existing = state_store.read().push_registration();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match crate::push::build_unregister_request(&dev, existing.as_ref()) {
                                                Ok(request) => match api.unregister_push_device_with_request(&request).await {
                                                    Ok(_) => {
                                                        state_store.write().clear_push_registration();
                                                        push_state.set("Not registered".to_owned());
                                                        status.set("Push unregistered".to_owned());
                                                    }
                                                    Err(error) => {
                                                        let message = format!("push unregister failed: {error}");
                                                        push_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => status.set(format!("push unregister unavailable: {error}")),
                                            },
                                            Err(error) => status.set(format!("push API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Unregister Push"
                        }
                    }
                    div { class: "event", "data-testid": "push-mute-summary",
                        div { class: "event-head",
                            span { "Per-space mute rules" }
                            span { "{muted_spaces.len()} muted" }
                        }
                        if muted_spaces.is_empty() {
                            div { class: "muted", "No spaces muted. Use the Notifications view to mute a noisy space." }
                        } else {
                            for space_id in muted_spaces {
                                div { class: "actions", "data-testid": "settings-muted-space-row",
                                    span { "{space_id}" }
                                    button {
                                        class: "secondary",
                                        "data-testid": "settings-unmute-space",
                                        onclick: {
                                            let space_id = space_id.clone();
                                            move |_| {
                                                state_store.write().set_space_muted(space_id.clone(), false);
                                                status.set(format!("Unmuted {space_id} from push preferences"));
                                            }
                                        },
                                        "Unmute"
                                    }
                                }
                            }
                            button {
                                class: "secondary",
                                "data-testid": "settings-clear-muted-spaces",
                                onclick: move |_| {
                                    state_store.write().clear_muted_spaces();
                                    status.set("Cleared all per-space mute rules".to_owned());
                                },
                                "Clear All Mutes"
                            }
                        }
                    }
                }
            }

            // ── Privacy settings ─────────────────────────────────
            if active_section() == SettingsSection::Privacy {
                div { class: "event", "data-testid": "privacy-settings",
                    div { class: "event-head", span { "Privacy" } span { "visibility controls" } }
                    label {
                        input {
                            r#type: "checkbox",
                            checked: presence_visible(),
                            onchange: move |evt| presence_visible.set(evt.value() == "true"),
                        }
                        " Show presence to others"
                    }
                    label {
                        input {
                            r#type: "checkbox",
                            checked: read_receipts_visible(),
                            onchange: move |evt| read_receipts_visible.set(evt.value() == "true"),
                        }
                        " Send read receipts"
                    }
                    div { class: "muted", "Changes take effect on next sync." }
                }
            }

            // ── Theme selector ───────────────────────────────────
            if active_section() == SettingsSection::Theme {
                div { class: "event", "data-testid": "theme-settings",
                    div { class: "event-head", span { "Theme" } span { "appearance" } }
                    div { class: "actions",
                        button {
                            class: if theme() == "light" { "primary" } else { "secondary" },
                            "data-testid": "theme-light",
                            onclick: move |_| {
                                theme.set("light".to_owned());
                                state_store.write().save_private_data(&account_did(), "theme", "light");
                                status.set("Theme set to light".to_owned());
                            },
                            "Light"
                        }
                        button {
                            class: if theme() == "night" { "primary" } else { "secondary" },
                            "data-testid": "theme-night",
                            onclick: move |_| {
                                theme.set("night".to_owned());
                                state_store.write().save_private_data(&account_did(), "theme", "night");
                                status.set("Theme set to night".to_owned());
                            },
                            "Night"
                        }
                        button {
                            class: if theme() == "system" { "primary" } else { "secondary" },
                            "data-testid": "theme-system",
                            onclick: move |_| {
                                theme.set("system".to_owned());
                                state_store.write().save_private_data(&account_did(), "theme", "system");
                                status.set("Theme set to system".to_owned());
                            },
                            "System"
                        }
                    }
                    div { class: "muted", "Current: {theme}" }
                    div { class: "muted",
                        "Theme is actor-private account data. Shared board filters/layout still require an explicit shared View save."
                    }
                }
                div { class: "event", "data-testid": "language-settings",
                    div { class: "event-head",
                        span { "Language" }
                        span { "data-testid": "text-direction", "{active_direction}" }
                    }
                    div { class: "actions",
                        button {
                            class: if active_locale == Locale::En { "primary" } else { "secondary" },
                            "data-testid": "language-en",
                            onclick: move |_| {
                                locale.set(Locale::En);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::En.code());
                                status.set("Language set to en (ltr)".to_owned());
                            },
                            "English"
                        }
                        button {
                            class: if active_locale == Locale::Zh { "primary" } else { "secondary" },
                            "data-testid": "language-zh",
                            onclick: move |_| {
                                locale.set(Locale::Zh);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::Zh.code());
                                status.set("Language set to zh (ltr)".to_owned());
                            },
                            "中文"
                        }
                        button {
                            class: if active_locale == Locale::Ar { "primary" } else { "secondary" },
                            "data-testid": "language-ar",
                            onclick: move |_| {
                                locale.set(Locale::Ar);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::Ar.code());
                                status.set("Language set to ar (rtl)".to_owned());
                            },
                            "العربية"
                        }
                    }
                    div { class: "muted", "data-testid": "current-language", "Current: {active_locale_code}" }
                }
            }

            // ── CI / Release gate status ─────────────────────────
            if active_section() == SettingsSection::Release {
                div { class: "event", "data-testid": "release-gate-status",
                    div { class: "event-head", span { "Release Gate" } span { "{blocked_count} blockers" } }
                    for workflow in &workflows {
                        div { class: "event", "data-testid": "workflow-row",
                            div { class: "event-head",
                                span { "{workflow.stage.label()}" }
                                span { "{workflow.id}" }
                            }
                            div { class: "space-title", "{workflow.name}" }
                            div { class: "muted", "Client: {workflow.client_surface}" }
                            div { class: "muted", "Dependency: {workflow.server_dependency}" }
                            if workflow.stage == WorkflowStage::Blocked {
                                div { class: "actions",
                                    button {
                                        class: "secondary",
                                        "data-testid": "blocked-workflow-button",
                                        onclick: {
                                            let name = workflow.name;
                                            let dependency = workflow.server_dependency;
                                            move |_| status.set(format!("Blocked: {name} requires {dependency}"))
                                        },
                                        "Show blocker"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── Account recovery ─────────────────────────────────
            if active_section() == SettingsSection::Recovery {
                div { class: "event", "data-testid": "recovery-settings",
                    div { class: "event-head", span { "Account Recovery" } span { "policy" } }
                    div { class: "muted", "Configure recovery methods for your account." }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "recovery-setup-button",
                            onclick: move |_| {
                                // Recovery setup would open a flow
                            },
                            "Setup Recovery"
                        }
                    }
                }
            }
        }
    }
}
