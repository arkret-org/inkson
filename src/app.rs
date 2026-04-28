use dioxus::prelude::*;

use crate::{
    api::ContrixApi,
    config::{ClientConfig, LocalConfigStore},
    crypto::compose_local_encrypted_message,
    models::SpacePreview,
};

const DEMO_SPACE: &str = "cx:space:01js0sp0000000000000000000";

const STYLE: &str = r#"
body { margin: 0; font-family: Inter, Segoe UI, sans-serif; background: #f4f6f8; color: #18212f; }
button, input, textarea { font: inherit; }
.shell { min-height: 100vh; display: grid; grid-template-columns: 288px minmax(0, 1fr) 340px; }
.sidebar { background: #192330; color: #f7fafc; padding: 22px; display: grid; grid-template-rows: auto auto 1fr auto; gap: 18px; }
.brand { font-size: 24px; font-weight: 700; }
.status { border: 1px solid #314255; border-radius: 8px; padding: 12px; color: #cbd5e1; overflow-wrap: anywhere; }
.search { display: grid; gap: 8px; }
.search input, .settings input, .composer textarea { width: 100%; box-sizing: border-box; border: 1px solid #cbd5df; border-radius: 6px; padding: 10px 12px; background: white; color: #18212f; }
.space-list { display: grid; gap: 8px; align-content: start; overflow: auto; }
.space-button { border: 1px solid #314255; border-radius: 8px; padding: 12px; color: white; background: #223247; text-align: left; cursor: pointer; }
.space-button.active { border-color: #5cc8a7; background: #284252; }
.space-title { font-weight: 700; }
.space-meta, .muted { color: #6b7787; font-size: 13px; }
.sidebar .space-meta, .sidebar .muted { color: #cbd5e1; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; }
.primary, .secondary { border: 0; border-radius: 6px; padding: 10px 12px; cursor: pointer; }
.primary { background: #0b6bcb; color: white; }
.secondary { background: #e7edf3; color: #18212f; }
.main { padding: 24px; display: grid; grid-template-rows: auto minmax(0, 1fr) auto; gap: 16px; min-width: 0; }
.topbar { display: flex; justify-content: space-between; gap: 14px; align-items: flex-start; }
.title { font-size: 28px; font-weight: 750; overflow-wrap: anywhere; }
.timeline { display: grid; gap: 10px; align-content: start; overflow: auto; }
.event { background: white; border: 1px solid #d8e0e8; border-radius: 8px; padding: 14px; display: grid; gap: 6px; }
.event-head { display: flex; justify-content: space-between; gap: 12px; color: #4e5b6b; font-size: 13px; }
.composer { background: white; border-top: 1px solid #d8e0e8; padding: 14px; display: grid; gap: 10px; border-radius: 8px; }
.composer textarea { min-height: 88px; resize: vertical; }
.panel { border-left: 1px solid #d8e0e8; background: #fbfcfd; padding: 22px; display: grid; gap: 16px; align-content: start; overflow: auto; }
.section { display: grid; gap: 10px; }
.section h2 { margin: 0; font-size: 16px; }
.metric-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.metric { background: white; border: 1px solid #d8e0e8; border-radius: 8px; padding: 10px; min-width: 0; }
.metric strong { display: block; font-size: 12px; color: #607086; margin-bottom: 4px; }
.metric span { overflow-wrap: anywhere; }
.settings { display: grid; gap: 10px; }
@media (max-width: 980px) {
  .shell { grid-template-columns: 1fr; }
  .sidebar, .panel { border: 0; }
  .main { min-height: 620px; }
}
"#;

#[derive(Clone, Copy, PartialEq)]
enum View {
    Timeline,
    Directory,
    Settings,
    Devices,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    Offline,
    Loading,
    Online,
    Reconnecting,
    Empty,
    Error,
}

impl ConnectionState {
    fn label(self) -> &'static str {
        match self {
            Self::Offline => "Offline",
            Self::Loading => "Loading",
            Self::Online => "Online",
            Self::Reconnecting => "Reconnecting",
            Self::Empty => "Empty",
            Self::Error => "Error",
        }
    }
}

#[component]
pub fn App() -> Element {
    let initial_config = LocalConfigStore::default().load();
    let config_store = use_signal(LocalConfigStore::default);
    let mut base_url = use_signal({
        let initial_config = initial_config.clone();
        move || initial_config.server_url
    });
    let account_did = use_signal({
        let initial_config = initial_config.clone();
        move || initial_config.account_did
    });
    let device_id = use_signal({
        let initial_config = initial_config.clone();
        move || initial_config.device_id
    });
    let token = use_signal(move || initial_config.session_token);
    let mut view = use_signal(|| View::Timeline);
    let status = use_signal(|| ConnectionState::Offline.label().to_owned());
    let sync_cursor = use_signal(|| "-".to_owned());
    let mut selected_space = use_signal(|| DEMO_SPACE.to_owned());
    let spaces = use_signal(Vec::<SpacePreview>::new);
    let mut timeline = use_signal(Vec::<String>::new);
    let mut draft = use_signal(String::new);
    let device_queue = use_signal(|| 0usize);
    let push_state = use_signal(|| "Not registered".to_owned());
    let repo_state = use_signal(|| "Not checked".to_owned());
    let mut crypto_state = use_signal(|| "MLS ready; plaintext fallback available".to_owned());

    let selected_preview = spaces()
        .iter()
        .find(|space| space.space_id == selected_space())
        .cloned();
    let title = selected_preview
        .as_ref()
        .map(|space| space.name.clone())
        .unwrap_or_else(|| "Contrix Demo Space".to_owned());

    rsx! {
        style { "{STYLE}" }
        div { class: "shell", "data-testid": "client-shell",
            aside { class: "sidebar", "data-testid": "sidebar",
                div { class: "brand", "clientx" }
                div { class: "status", "data-testid": "connection-status",
                    div { class: "space-title", "data-testid": "status-label", "{status}" }
                    div { class: "muted", "data-testid": "sync-cursor", "cursor {sync_cursor}" }
                }
                div { class: "search",
                    input {
                        "data-testid": "server-url-input",
                        value: "{base_url}",
                        oninput: move |event| {
                            let value = event.value();
                            base_url.set(value.clone());
                            persist_config(config_store, value, account_did(), device_id(), token());
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "connect-button",
                            onclick: move |_| connect(
                                base_url(),
                                account_did(),
                                device_id(),
                                status,
                                sync_cursor,
                                token,
                                spaces,
                                timeline,
                                device_queue,
                                repo_state,
                                crypto_state,
                                push_state,
                                config_store,
                            ),
                            "Connect"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "directory-nav-button",
                            onclick: move |_| view.set(View::Directory),
                            "Directory"
                        }
                    }
                }
                div { class: "space-list", "data-testid": "space-list",
                    for space in spaces() {
                        button {
                            class: if space.space_id == selected_space() { "space-button active" } else { "space-button" },
                            "data-testid": "space-button",
                            onclick: {
                                let id = space.space_id.clone();
                                move |_| {
                                    selected_space.set(id.clone());
                                    view.set(View::Timeline);
                                }
                            },
                            div { class: "space-title", "{space.name}" }
                            div { class: "space-meta", "{space.space_id}" }
                        }
                    }
                    if spaces().is_empty() {
                        div { class: "muted", "No spaces loaded. Connect to serverx." }
                    }
                }
                div { class: "actions",
                    button { class: "secondary", onclick: move |_| view.set(View::Timeline), "Timeline" }
                    button { class: "secondary", "data-testid": "settings-nav-button", onclick: move |_| view.set(View::Settings), "Settings" }
                    button { class: "secondary", "data-testid": "devices-nav-button", onclick: move |_| view.set(View::Devices), "Devices" }
                }
            }

            main { class: "main", "data-testid": "main-view",
                div { class: "topbar",
                    div {
                        div { class: "title", "data-testid": "space-title", "{title}" }
                        div { class: "muted", "data-testid": "selected-space-id", "{selected_space}" }
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "backfill-button",
                            onclick: move |_| {
                                let base = base_url();
                                let id = selected_space();
                                spawn(async move {
                                    if let Ok(api) = ContrixApi::new(&base) {
                                        let _ = api.backfill(&id).await;
                                    }
                                });
                            },
                            "Backfill"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "resolve-nav-button",
                            onclick: move |_| view.set(View::Directory),
                            "Resolve"
                        }
                    }
                }
                match view() {
                    View::Timeline => rsx! {
                        div { class: "timeline", "data-testid": "timeline",
                            for event in timeline() {
                                div { class: "event", "data-testid": "timeline-event",
                                    div { class: "event-head",
                                        span { "clientx" }
                                        span { "local" }
                                    }
                                    div { "{event}" }
                                }
                            }
                            if timeline().is_empty() {
                                div { class: "event",
                                    div { class: "event-head", span { "serverx" } span { "empty" } }
                                    div { "No timeline events yet. Compose a dev-mode message." }
                                }
                            }
                        }
                    },
                    View::Directory => rsx! {
                        DirectoryPanel {
                            base_url: base_url(),
                            selected_space,
                            spaces,
                            status,
                        }
                    },
                    View::Settings => rsx! {
                        SettingsPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            crypto_state: crypto_state(),
                            config_store,
                        }
                    },
                    View::Devices => rsx! {
                        DevicesPanel {
                            device_id: device_id(),
                            device_queue: device_queue(),
                            push_state: push_state(),
                            crypto_state: crypto_state(),
                        }
                    },
                }
                div { class: "composer",
                    textarea {
                        "data-testid": "composer-input",
                        value: "{draft}",
                        placeholder: "Write a plaintext dev-mode message",
                        oninput: move |event| draft.set(event.value())
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "send-button",
                            onclick: move |_| {
                                let body = draft().trim().to_owned();
                                if !body.is_empty() {
                                    timeline.write().push(body);
                                    draft.set(String::new());
                                }
                            },
                            "Send"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "encrypt-local-button",
                            onclick: move |_| {
                                let body = draft().trim().to_owned();
                                if !body.is_empty() {
                                    match compose_local_encrypted_message(
                                        &account_did(),
                                        &device_id(),
                                        &selected_space(),
                                        "cx:message:local-compose",
                                        &body,
                                    ) {
                                        Ok(message) => {
                                            timeline.write().push(format!(
                                                "encrypted {} epoch {} digest {}",
                                                message.payload.scheme.as_str(),
                                                message.payload.epoch,
                                                message.payload.payload_digest
                                            ));
                                            crypto_state.set(format!(
                                                "encrypted local payload for {}",
                                                message.payload.group_id
                                            ));
                                            draft.set(String::new());
                                        }
                                        Err(error) => crypto_state.set(format!("encrypt failed: {error}")),
                                    }
                                }
                            },
                            "Encrypt Local"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "report-queue-button",
                            onclick: move |_| {
                                let base = base_url();
                                let actor = account_did();
                                let device = device_id();
                                let bearer = token();
                                spawn(async move {
                                    if let Ok(api) = ContrixApi::new(&base) {
                                        let api = if bearer.is_empty() { api } else { api.with_bearer(bearer) };
                                        let _ = api.report_moderation(DEMO_SPACE, "local:event", "spam", &actor).await;
                                        let _ = api.send_to_device(&actor, &device).await;
                                    }
                                });
                            },
                            "Report / Queue"
                        }
                    }
                }
            }

            section { class: "panel", "data-testid": "right-panel",
                div { class: "section",
                    h2 { "Sync" }
                    div { class: "metric-grid", "data-testid": "sync-metrics",
                        Metric { label: "Spaces", value: spaces().len().to_string() }
                        Metric { label: "Device Queue", value: device_queue().to_string() }
                        Metric { label: "Repo", value: repo_state() }
                        Metric { label: "Push", value: push_state() }
                    }
                }
                div { class: "section",
                    h2 { "Device" }
                    div { class: "metric",
                        strong { "Account" }
                        span { "{account_did}" }
                    }
                    div { class: "metric",
                        strong { "Device ID" }
                        span { "{device_id}" }
                    }
                    div { class: "metric",
                        strong { "Crypto" }
                        span { "{crypto_state}" }
                    }
                }
            }
        }
    }
}

fn connect(
    base: String,
    actor: String,
    device: String,
    mut status: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut token: Signal<String>,
    mut spaces: Signal<Vec<SpacePreview>>,
    mut timeline: Signal<Vec<String>>,
    mut device_queue: Signal<usize>,
    mut repo_state: Signal<String>,
    mut crypto_state: Signal<String>,
    mut push_state: Signal<String>,
    config_store: Signal<LocalConfigStore>,
) {
    spawn(async move {
        status.set(ConnectionState::Loading.label().to_owned());
        match ContrixApi::new(&base) {
            Ok(api) => {
                match api.describe().await {
                    Ok(description) => status.set(format!(
                        "{}: {} / {}",
                        ConnectionState::Online.label(),
                        description.service_type,
                        description.protocol_version
                    )),
                    Err(error) => status.set(format!(
                        "{}: describe failed: {error}",
                        ConnectionState::Reconnecting.label()
                    )),
                }
                let authed = match api.dev_login(&actor, &device).await {
                    Ok(session) => {
                        token.set(session.access_token.clone());
                        persist_config(
                            config_store,
                            base.clone(),
                            actor.clone(),
                            device.clone(),
                            session.access_token.clone(),
                        );
                        crypto_state.set(format!("session {}", session.device_id));
                        api.clone().with_bearer(session.access_token)
                    }
                    Err(error) => {
                        crypto_state.set(format!("login failed: {error}"));
                        api.clone()
                    }
                };
                match api.search_spaces("").await {
                    Ok(search) if search.results.is_empty() => {
                        status.set(ConnectionState::Empty.label().to_owned());
                        spaces.set(search.results);
                    }
                    Ok(search) => spaces.set(search.results),
                    Err(error) => status.set(format!(
                        "{}: directory search failed: {error}",
                        ConnectionState::Reconnecting.label()
                    )),
                }
                if let Ok(sync) = authed.sync(None).await {
                    sync_cursor.set(sync.next_batch);
                    device_queue.set(sync.to_device.len());
                    timeline.set(
                        sync.spaces
                            .into_iter()
                            .map(|(id, body)| format!("{id}: {}", body["summary"]["summary"]))
                            .collect(),
                    );
                } else {
                    status.set(format!(
                        "{}: sync unavailable, showing cached/local state",
                        ConnectionState::Offline.label()
                    ));
                }
                if let Ok(repo) = api.repo_describe().await {
                    repo_state.set(repo.head_commit.unwrap_or_else(|| "empty".to_owned()));
                }
                let _ = api.identity_describe().await;
                let _ = api.identity_resolve(&actor).await;
                let _ = api.sync_describe().await;
                let _ = api.index_describe().await;
                let _ = api.snapshot_head(DEMO_SPACE).await;
                let _ = api.list_commits(20).await;
                let _ = api.get_operations(&[]).await;
                let _ = api.repo_sync("did:web:serverx.local", None).await;
                let _ = api.authz_check(&actor, "space.read", DEMO_SPACE).await;
                let _ = api.effective_grants(&actor).await;
                let _ = api.invites().await;
                let _ = api.profile_presence(&actor).await;
                let _ = authed.upload_keys(&device).await;
                let _ = authed.query_keys(&actor, &device).await;
                let _ = authed
                    .claim_keys(&actor, &device, "signed_curve25519")
                    .await;
                let _ = authed.receive_device_messages().await;
                if let Ok(blob) = authed.upload_blob(b"clientx encrypted bytes").await {
                    let _ = authed.get_blob_bytes(&blob.blob_ref).await;
                }
                match authed.register_push_device().await {
                    Ok(push) => {
                        push_state.set(
                            push.registration_id
                                .unwrap_or_else(|| "registered".to_owned()),
                        );
                        let _ = authed.unregister_push_device(&device).await;
                    }
                    Err(error) => push_state.set(format!("push failed: {error}")),
                }
            }
            Err(error) => status.set(format!(
                "{}: invalid URL: {error}",
                ConnectionState::Error.label()
            )),
        }
    });
}

#[component]
fn DirectoryPanel(
    base_url: String,
    mut selected_space: Signal<String>,
    mut spaces: Signal<Vec<SpacePreview>>,
    mut status: Signal<String>,
) -> Element {
    let mut query = use_signal(String::new);
    let search_base_url = base_url.clone();
    let resolve_base_url = base_url;
    rsx! {
        div { class: "timeline", "data-testid": "directory-panel",
            div { class: "event",
                div { class: "event-head", span { "Directory" } span { "search and exact resolve" } }
                div { class: "search",
                    input {
                        "data-testid": "directory-search-input",
                        value: "{query}",
                        placeholder: "Search spaces",
                        oninput: move |event| query.set(event.value())
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "directory-search-button",
                            onclick: move |_| {
                                let base = search_base_url.clone();
                                let q = query();
                                spawn(async move {
                                    if let Ok(api) = ContrixApi::new(&base) {
                                        match api.search_spaces(&q).await {
                                            Ok(search) => spaces.set(search.results),
                                            Err(error) => status.set(format!("search failed: {error}")),
                                        }
                                    }
                                });
                            },
                            "Search"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "resolve-selected-button",
                            onclick: move |_| {
                                let base = resolve_base_url.clone();
                                let id = selected_space();
                                spawn(async move {
                                    if let Ok(api) = ContrixApi::new(&base) {
                                        match api.resolve_space(&id).await {
                                            Ok(resolved) => {
                                                selected_space.set(resolved.space_preview.space_id);
                                                status.set(format!("resolved {}", resolved.join_rule));
                                            }
                                            Err(error) => status.set(format!("resolve failed: {error}")),
                                        }
                                    }
                                });
                            },
                            "Resolve Selected"
                        }
                    }
                }
            }
            for space in spaces() {
                div { class: "event", "data-testid": "directory-result",
                    div { class: "event-head", span { "{space.category.clone().unwrap_or_else(|| \"space\".to_owned())}" } span { if space.public { "public" } else { "private" } } }
                    div { class: "space-title", "{space.name}" }
                    div { class: "muted", "{space.description.clone().unwrap_or_default()}" }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "directory-select-button",
                            onclick: {
                                let id = space.space_id.clone();
                                move |_| selected_space.set(id.clone())
                            },
                            "Select"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn SettingsPanel(
    mut base_url: Signal<String>,
    mut account_did: Signal<String>,
    mut device_id: Signal<String>,
    token: Signal<String>,
    crypto_state: String,
    mut config_store: Signal<LocalConfigStore>,
) -> Element {
    rsx! {
        div { class: "settings", "data-testid": "settings-panel",
            div { class: "event",
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
    }
}

fn persist_config(
    mut config_store: Signal<LocalConfigStore>,
    server_url: String,
    account_did: String,
    device_id: String,
    session_token: String,
) {
    config_store.write().save(ClientConfig::from_fields(
        server_url,
        account_did,
        device_id,
        session_token,
    ));
}

#[component]
fn DevicesPanel(
    device_id: String,
    device_queue: usize,
    push_state: String,
    crypto_state: String,
) -> Element {
    rsx! {
        div { class: "timeline", "data-testid": "devices-panel",
            div { class: "event", "data-testid": "device-summary",
                div { class: "event-head", span { "Device" } span { "{device_id}" } }
                div { "Queue count: {device_queue}" }
                div { "Push: {push_state}" }
                div { "Keys: {crypto_state}" }
            }
            div { class: "event",
                div { class: "event-head", span { "Encryption" } span { "dev mode" } }
                div { "MLS local compose/decrypt helpers are active. Missing group state keeps ciphertext pending." }
            }
        }
    }
}

#[component]
fn Metric(label: String, value: String) -> Element {
    rsx! {
        div { class: "metric",
            strong { "{label}" }
            span { "{value}" }
        }
    }
}
