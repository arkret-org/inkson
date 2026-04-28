use dioxus::prelude::*;

use crate::{
    api::ContrixApi,
    components::Metric,
    config::LocalConfigStore,
    local_state::LocalStateStore,
    models::SpacePreview,
    views::{
        ConnectionState, View,
        helpers::{handle_from_did, persist_config},
    },
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
.search input, .settings input, .workflow-form input, .composer textarea { width: 100%; box-sizing: border-box; border: 1px solid #cbd5df; border-radius: 6px; padding: 10px 12px; background: white; color: #18212f; }
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
.settings, .workflow-form { display: grid; gap: 10px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
.badge-info { background: #e7edf3; color: #18212f; }
.badge-success { background: #d4edda; color: #155724; }
.badge-error { background: #f8d7da; color: #721c24; }
.badge-warning { background: #fff3cd; color: #856404; }
.error-banner { border-color: #f5c6cb; background: #fef2f2; }
.loading { opacity: 0.7; }
.tabs { display: flex; gap: 4px; margin-bottom: 8px; }
.tab { border: 1px solid #cbd5df; border-radius: 6px 6px 0 0; padding: 8px 16px; cursor: pointer; background: #e7edf3; }
.tab.active { background: white; border-bottom-color: white; font-weight: 600; }
@media (max-width: 980px) {
  .shell { grid-template-columns: 1fr; }
  .sidebar, .panel { border: 0; }
  .main { min-height: 620px; }
}
"#;

#[component]
pub fn App() -> Element {
    let initial_config = LocalConfigStore::default().load();
    let initial_local_state = LocalStateStore::default().load();
    let config_store = use_signal(LocalConfigStore::default);
    let mut state_store = use_signal(LocalStateStore::default);
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
    let mut view = use_signal(|| View::Dashboard);
    let status = use_signal(|| ConnectionState::Offline.label().to_owned());
    let sync_cursor = use_signal({
        let initial_local_state = initial_local_state.clone();
        move || {
            initial_local_state
                .sync_cursor
                .clone()
                .unwrap_or_else(|| "-".to_owned())
        }
    });
    let mut selected_space = use_signal(|| DEMO_SPACE.to_owned());
    let spaces = use_signal(Vec::<SpacePreview>::new);
    let mut timeline = use_signal(Vec::<String>::new);
    let mut draft = use_signal({
        let initial_local_state = initial_local_state.clone();
        move || {
            initial_local_state
                .drafts
                .get(DEMO_SPACE)
                .cloned()
                .unwrap_or_default()
        }
    });
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
                                ConnectContext {
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
                                    state_store,
                                },
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
                    button { class: "secondary", onclick: move |_| view.set(View::Dashboard), "Dashboard" }
                    button { class: "secondary", onclick: move |_| view.set(View::Timeline), "Timeline" }
                    button { class: "secondary", "data-testid": "product-nav-button", onclick: move |_| view.set(View::Product), "Product" }
                    button { class: "secondary", onclick: move |_| view.set(View::Contacts), "Contacts" }
                    button { class: "secondary", onclick: move |_| view.set(View::Directory), "Directory" }
                    button { class: "secondary", onclick: move |_| view.set(View::Kanban), "Kanban" }
                    button { class: "secondary", onclick: move |_| view.set(View::Chat), "Chat" }
                    button { class: "secondary", onclick: move |_| view.set(View::Forum), "Forum" }
                    button { class: "secondary", onclick: move |_| view.set(View::Audit), "Audit" }
                    button { class: "secondary", "data-testid": "settings-nav-button", onclick: move |_| view.set(View::Settings), "Settings" }
                    button { class: "secondary", "data-testid": "devices-nav-button", onclick: move |_| view.set(View::Devices), "Devices" }
                    button { class: "secondary", onclick: move |_| view.set(View::VerifyDevice), "Verify" }
                    button { class: "secondary", "data-testid": "readiness-nav-button", onclick: move |_| view.set(View::Readiness), "Release" }
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
                    View::Login => rsx! {
                        crate::views::login::LoginPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            status,
                            config_store,
                            on_login: move |_| view.set(View::Dashboard),
                        }
                    },
                    View::Register => rsx! {
                        crate::views::register::RegisterPanel {
                            base_url: base_url(),
                            on_register: move |_| view.set(View::Login),
                        }
                    },
                    View::Dashboard => rsx! {
                        crate::views::dashboard::DashboardPanel {
                            base_url: base_url(),
                            token,
                            spaces,
                            selected_space,
                            view,
                            device_queue: device_queue(),
                            repo_state: repo_state(),
                            sync_cursor: sync_cursor(),
                        }
                    },
                    View::Timeline => rsx! {
                        crate::views::timeline::TimelinePanel {
                            base_url: base_url(),
                            account_did: account_did(),
                            device_id: device_id(),
                            token,
                            selected_space: selected_space(),
                            timeline,
                            draft,
                            state_store,
                            crypto_state,
                            base_url_sig: base_url,
                        }
                    },
                    View::Directory => rsx! {
                        crate::views::directory::DirectoryPanel {
                            base_url: base_url(),
                            selected_space,
                            spaces,
                            status,
                            token,
                            view,
                        }
                    },
                    View::Product => rsx! {
                        crate::views::product::ProductPanel {
                            base_url: base_url(),
                            account_did: account_did(),
                            device_id: device_id(),
                            token,
                            selected_space,
                            spaces,
                            timeline,
                            status,
                            sync_cursor,
                            repo_state,
                            state_store,
                        }
                    },
                    View::Settings => rsx! {
                        crate::views::settings::SettingsPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            crypto_state: crypto_state(),
                            config_store,
                            status,
                        }
                    },
                    View::Devices => rsx! {
                        crate::views::devices::DevicesPanel {
                            base_url: base_url(),
                            token,
                            device_id: device_id(),
                            device_queue: device_queue(),
                            push_state,
                            crypto_state,
                        }
                    },
                    View::Readiness => rsx! {
                        crate::views::readiness::ReadinessPanel {
                            status,
                        }
                    },
                    View::VerifyDevice => rsx! {
                        crate::views::verify_device::VerifyDevicePanel {
                            base_url: base_url(),
                            token,
                            device_id: device_id(),
                        }
                    },
                    View::Contacts => rsx! {
                        crate::views::contacts::ContactsPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    View::SpaceAdmin => rsx! {
                        crate::views::space_admin::SpaceAdminPanel {
                            base_url: base_url(),
                            token,
                            selected_space: selected_space(),
                        }
                    },
                    View::Audit => rsx! {
                        crate::views::audit::AuditPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    View::Kanban => rsx! {
                        crate::views::kanban::KanbanPanel {
                            base_url: base_url(),
                            token,
                            selected_space: selected_space(),
                        }
                    },
                    View::Chat => rsx! {
                        crate::views::chat::ChatPanel {
                            base_url: base_url(),
                            token,
                            selected_space: selected_space(),
                        }
                    },
                    View::Forum => rsx! {
                        crate::views::forum::ForumPanel {
                            base_url: base_url(),
                            token,
                            selected_space: selected_space(),
                        }
                    },
                    View::SocialFeed => rsx! {
                        crate::views::social_feed::SocialFeedPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    View::MemoryReview => rsx! {
                        crate::views::memory_review::MemoryReviewPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    View::AgentRuns => rsx! {
                        crate::views::agent_runs::AgentRunsPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    View::Notifications => rsx! {
                        crate::views::notifications::NotificationsPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    View::Document => rsx! {
                        crate::views::document::DocumentPanel {
                            base_url: base_url(),
                            token,
                            selected_space: selected_space(),
                        }
                    },
                    View::Call => rsx! {
                        crate::views::call::CallPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
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

#[derive(Clone, Copy)]
struct ConnectContext {
    status: Signal<String>,
    sync_cursor: Signal<String>,
    token: Signal<String>,
    spaces: Signal<Vec<SpacePreview>>,
    timeline: Signal<Vec<String>>,
    device_queue: Signal<usize>,
    repo_state: Signal<String>,
    crypto_state: Signal<String>,
    push_state: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
}

fn connect(base: String, actor: String, device: String, ctx: ConnectContext) {
    spawn(async move {
        let mut status = ctx.status;
        let mut sync_cursor = ctx.sync_cursor;
        let mut token = ctx.token;
        let mut spaces = ctx.spaces;
        let mut timeline = ctx.timeline;
        let mut device_queue = ctx.device_queue;
        let mut repo_state = ctx.repo_state;
        let mut crypto_state = ctx.crypto_state;
        let mut push_state = ctx.push_state;
        let config_store = ctx.config_store;
        let mut state_store = ctx.state_store;

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
                        match api
                            .register_account(
                                &actor,
                                &handle_from_did(&actor),
                                Some("clientx"),
                                Some(&device),
                            )
                            .await
                        {
                            Ok(_) => match api.dev_login(&actor, &device).await {
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
                                Err(retry_error) => {
                                    crypto_state.set(format!(
                                        "login failed: {error}; retry failed: {retry_error}"
                                    ));
                                    api.clone()
                                }
                            },
                            Err(register_error) => {
                                crypto_state.set(format!(
                                    "login failed: {error}; register failed: {register_error}"
                                ));
                                api.clone()
                            }
                        }
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
                    {
                        let mut store = state_store.write();
                        store.save_sync_cursor(sync.next_batch.clone());
                        for (id, body) in &sync.spaces {
                            store.save_space_projection(id.clone(), body.clone());
                        }
                    }
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
