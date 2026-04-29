use dioxus::prelude::*;

use crate::{
    config::LocalConfigStore,
    local_state::LocalStateStore,
    views::helpers::persist_config,
    workflows::{WorkflowStage, blocked_release_workflows, production_release_workflows},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettingsSection {
    Server,
    Storage,
    Encryption,
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
    status: Signal<String>,
) -> Element {
    let mut active_section = use_signal(|| SettingsSection::Server);
    let mut theme = use_signal(|| "system".to_owned());
    let mut presence_visible = use_signal(|| true);
    let mut read_receipts_visible = use_signal(|| true);
    let mut mls_group_policy = use_signal(|| "default".to_owned());
    let mut key_backup_status = use_signal(|| "Not configured".to_owned());
    let workflows = production_release_workflows();
    let blocked_count = blocked_release_workflows().len();
    let muted_spaces = state_store.read().muted_spaces();

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
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "key-backup-setup",
                            onclick: move |_| key_backup_status.set("Setup not yet available".to_owned()),
                            "Setup Key Backup"
                        }
                    }
                }
            }

            // ── Push notification settings ───────────────────────
            if active_section() == SettingsSection::Push {
                div { class: "event", "data-testid": "push-settings",
                    div { class: "event-head", span { "Push Notifications" } span { "configure" } }
                    div { class: "muted", "Push notification preferences and gateway registration." }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "push-register-button",
                            onclick: move |_| {
                                // Push register is handled elsewhere
                            },
                            "Register Push"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "push-unregister-button",
                            onclick: move |_| {
                                // Push unregister
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
                            onclick: move |_| theme.set("light".to_owned()),
                            "Light"
                        }
                        button {
                            class: if theme() == "dark" { "primary" } else { "secondary" },
                            onclick: move |_| theme.set("dark".to_owned()),
                            "Dark"
                        }
                        button {
                            class: if theme() == "system" { "primary" } else { "secondary" },
                            onclick: move |_| theme.set("system".to_owned()),
                            "System"
                        }
                    }
                    div { class: "muted", "Current: {theme}" }
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
