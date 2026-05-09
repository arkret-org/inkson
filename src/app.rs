use dioxus::prelude::*;
use dioxus_router::{Link, Router, hooks::*};

use crate::{
    api::ContrixApi,
    components::RightPanel,
    config::LocalConfigStore,
    conformance::{
        PROFILE_CHAT_ONLY_CLIENT, PROFILE_E2EE_CLIENT, PROFILE_FULL_CLIENT,
        PROFILE_KANBAN_ONLY_CLIENT, PROFILE_MINIMAL_CLIENT, PROFILE_PUSH_GATEWAY, profile_ready,
    },
    i18n::{Locale, TextDirection},
    local_state::LocalStateStore,
    models::{ServerDescription, SpacePreview},
    routes::Route,
    views::{
        ConnectionState,
        helpers::{authed_api_with_sync, handle_from_did, persist_config},
        timeline::TimelineEvent,
    },
};

const DEMO_SPACE: &str = "cx:space:0196419b-0000-7000-8000-000000000000";

const STYLE: &str = r#"
body { margin: 0; font-family: Inter, Segoe UI, sans-serif; background: #f4f6f8; color: #18212f; }
button, input, textarea { font: inherit; }
.shell { min-height: 100vh; display: grid; grid-template-columns: 288px minmax(0, 1fr) 340px; }
.shell.rtl { direction: rtl; grid-template-columns: 340px minmax(0, 1fr) 288px; }
.shell.rtl .sidebar { grid-column: 3; }
.shell.rtl .main { grid-column: 2; }
.shell.rtl .panel { grid-column: 1; border-left: 0; border-right: 1px solid #d8e0e8; }
.shell.rtl .actions { direction: rtl; }
.shell.rtl .event-head, .shell.rtl .topbar { flex-direction: row-reverse; }
.shell.rtl .space-button, .shell.rtl input, .shell.rtl textarea { text-align: right; }
.sidebar { background: #192330; color: #f7fafc; padding: 22px; display: grid; grid-template-rows: auto auto 1fr auto; gap: 18px; }
.brand { font-size: 24px; font-weight: 700; }
.status { border: 1px solid #314255; border-radius: 8px; padding: 12px; color: #cbd5e1; overflow-wrap: anywhere; }
.search { display: grid; gap: 8px; }
.search input, .settings input, .workflow-form input, .composer textarea, .composer input { width: 100%; box-sizing: border-box; border: 1px solid #cbd5df; border-radius: 6px; padding: 10px 12px; background: white; color: #18212f; }
.space-list { display: grid; gap: 8px; align-content: start; overflow: auto; }
.space-button { border: 1px solid #314255; border-radius: 8px; padding: 12px; color: white; background: #223247; text-align: left; cursor: pointer; }
.space-button.active { border-color: #5cc8a7; background: #284252; }
.space-title { font-weight: 700; }
.space-meta, .muted { color: #6b7787; font-size: 13px; }
.sidebar .space-meta, .sidebar .muted { color: #cbd5e1; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; }
.primary, .secondary { border: 0; border-radius: 6px; padding: 10px 12px; cursor: pointer; display: inline-block; text-decoration: none; text-align: center; }
.primary { background: #0b6bcb; color: white; }
.secondary { background: #e7edf3; color: #18212f; }
a.primary, a.secondary { line-height: 1.5; }
.main { padding: 24px; display: grid; grid-template-rows: auto minmax(0, 1fr) auto; gap: 16px; min-width: 0; }
.topbar { display: flex; justify-content: space-between; gap: 14px; align-items: flex-start; }
.topbar-search { min-width: 260px; max-width: 420px; flex: 1; }
.topbar-search input { width: 100%; box-sizing: border-box; border: 1px solid #cbd5df; border-radius: 6px; padding: 10px 12px; background: white; color: #18212f; }
.title { font-size: 28px; font-weight: 750; overflow-wrap: anywhere; }
.timeline { display: grid; gap: 10px; align-content: start; overflow: auto; }
.event { background: white; border: 1px solid #d8e0e8; border-radius: 8px; padding: 14px; display: grid; gap: 6px; }
.event-head { display: flex; justify-content: space-between; gap: 12px; color: #4e5b6b; font-size: 13px; }
.composer { background: white; border-top: 1px solid #d8e0e8; padding: 14px; display: grid; gap: 10px; border-radius: 8px; }
.composer textarea { min-height: 88px; resize: vertical; }
.panel { border-left: 1px solid #d8e0e8; background: #fbfcfd; padding: 22px; display: grid; gap: 16px; align-content: start; overflow: auto; min-width: 0; }
.right-panel { overflow-x: hidden; pointer-events: none; }
.right-panel a, .right-panel button, .right-panel input, .right-panel select, .right-panel textarea { pointer-events: auto; }
.right-panel .muted, .right-panel .metric span, .right-panel .hierarchy-row { overflow-wrap: anywhere; }
.section { display: grid; gap: 10px; }
.section-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.section h2 { margin: 0; font-size: 16px; }
.metric-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.metric { background: white; border: 1px solid #d8e0e8; border-radius: 8px; padding: 10px; min-width: 0; }
.metric strong { display: block; font-size: 12px; color: #607086; margin-bottom: 4px; }
.metric span { overflow-wrap: anywhere; }
.quick-nav { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.quick-nav__item { min-width: 0; }
.compact-button { padding: 7px 9px; font-size: 13px; }
.mobile-shellbar, .mobile-drawer { display: none; }
.hierarchy-boundary-note { background: #f8fafc; }
.hierarchy-list { display: grid; gap: 8px; }
.hierarchy-row { background: white; border: 1px solid #d8e0e8; border-radius: 8px; padding: 10px; display: grid; gap: 8px; pointer-events: none; }
.hierarchy-row__main { display: grid; gap: 3px; min-width: 0; }
.hierarchy-row__main strong { overflow-wrap: anywhere; }
.hierarchy-row__badges { display: flex; gap: 6px; flex-wrap: wrap; }
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

/* Accessibility: focus styles */
button:focus-visible, input:focus-visible, textarea:focus-visible, select:focus-visible {
  outline: 2px solid #0b6bcb;
  outline-offset: 2px;
}

/* High contrast mode */
@media (prefers-contrast: high) {
  .event { border-width: 2px; border-color: #18212f; }
  .primary { background: #0047b3; }
  .secondary { border: 2px solid #18212f; }
  .metric { border-width: 2px; }
  .badge { border: 1px solid #18212f; }
}

/* Reduced motion */
@media (prefers-reduced-motion: reduce) {
  * { animation: none !important; transition: none !important; }
}

/* Responsive: tablet */
@media (max-width: 1200px) {
  .shell { grid-template-columns: 240px minmax(0, 1fr) 280px; }
  .shell.rtl { grid-template-columns: 280px minmax(0, 1fr) 240px; }
  .metric-grid { grid-template-columns: 1fr; }
}

/* Responsive: mobile */
@media (max-width: 768px) {
  .shell { grid-template-columns: 1fr; }
  .shell.rtl { grid-template-columns: 1fr; }
  .shell.rtl .sidebar, .shell.rtl .main, .shell.rtl .panel { grid-column: auto; }
  .sidebar { display: none; }
  .panel { display: none; }
  .mobile-shellbar { display: flex; gap: 10px; align-items: center; justify-content: space-between; padding: 10px 12px; background: #101827; color: white; }
  .mobile-drawer.open { display: grid; gap: 8px; padding: 12px; background: #172033; }
  .main { min-height: 100vh; padding: 16px; }
  .title { font-size: 22px; }
  .actions { flex-direction: column; }
  .actions button { width: 100%; }
  .tabs { flex-wrap: wrap; }
}

/* Print styles */
@media print {
  .sidebar, .panel, .actions, .composer { display: none !important; }
  .shell { grid-template-columns: 1fr; }
  .event { break-inside: avoid; }
}

/* Product theme layer: calm security-oriented palette shared by all views. */
body {
  font-family: Inter, "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
  background: #eef3f8;
  color: #142033;
  letter-spacing: 0;
}
.shell {
  --cx-bg: #eef3f8;
  --cx-bg-soft: #f8fafc;
  --cx-bg-end: #e7eef7;
  --cx-surface: #ffffff;
  --cx-surface-raised: rgba(255, 255, 255, 0.94);
  --cx-ink: #142033;
  --cx-muted: #64748b;
  --cx-line: #d7e0ea;
  --cx-line-strong: #c5d1dd;
  --cx-brand: #2563eb;
  --cx-brand-strong: #1d4ed8;
  --cx-teal: #0f766e;
  --cx-green: #0f9f6e;
  --cx-amber: #d97706;
  --cx-red: #dc2626;
  --cx-nav: #101827;
  --cx-nav-soft: #172033;
  --cx-shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.08);
  --cx-shadow: 0 16px 40px rgba(15, 23, 42, 0.14);
  background: linear-gradient(135deg, var(--cx-bg) 0%, var(--cx-bg-soft) 64%, var(--cx-bg-end) 100%);
  color: var(--cx-ink);
}
.shell.theme-night {
  --cx-bg: #0f172a;
  --cx-bg-soft: #111827;
  --cx-bg-end: #0b1220;
  --cx-surface: #172033;
  --cx-surface-raised: rgba(23, 32, 51, 0.94);
  --cx-ink: #e5edf7;
  --cx-muted: #9fb0c3;
  --cx-line: #2a3a52;
  --cx-line-strong: #3a4b63;
  --cx-brand: #60a5fa;
  --cx-brand-strong: #3b82f6;
  --cx-teal: #2dd4bf;
  --cx-nav: #080d17;
  --cx-nav-soft: #111827;
  --cx-shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.28);
  --cx-shadow: 0 18px 48px rgba(0, 0, 0, 0.36);
}
@media (prefers-color-scheme: dark) {
  .shell.theme-system {
    --cx-bg: #0f172a;
    --cx-bg-soft: #111827;
    --cx-bg-end: #0b1220;
    --cx-surface: #172033;
    --cx-surface-raised: rgba(23, 32, 51, 0.94);
    --cx-ink: #e5edf7;
    --cx-muted: #9fb0c3;
    --cx-line: #2a3a52;
    --cx-line-strong: #3a4b63;
    --cx-brand: #60a5fa;
    --cx-brand-strong: #3b82f6;
    --cx-teal: #2dd4bf;
    --cx-nav: #080d17;
    --cx-nav-soft: #111827;
    --cx-shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.28);
    --cx-shadow: 0 18px 48px rgba(0, 0, 0, 0.36);
  }
}
.sidebar {
  background: var(--cx-nav);
  color: #e5edf7;
  border-right: 1px solid rgba(148, 163, 184, 0.16);
}
.brand {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 20px;
  font-weight: 800;
}
.brand::before {
  content: "Y";
  width: 34px;
  height: 34px;
  border-radius: 10px;
  display: grid;
  place-items: center;
  color: #fff;
  background: linear-gradient(135deg, var(--cx-brand-strong), var(--cx-teal));
  box-shadow: 0 12px 30px rgba(37, 99, 235, 0.24);
}
.status {
  border-color: #334155;
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.055);
  box-shadow: var(--cx-shadow-sm);
}
.space-button {
  border-color: #334155;
  border-radius: 12px;
  background: var(--cx-nav-soft);
}
.space-button.active {
  border-color: rgba(96, 165, 250, 0.52);
  background: rgba(37, 99, 235, 0.22);
}
.main {
  background: transparent;
}
.topbar {
  margin: -6px -6px 2px;
  padding: 14px 16px;
  border: 1px solid rgba(215, 224, 234, 0.86);
  border-radius: 16px;
  background: var(--cx-surface-raised);
  box-shadow: var(--cx-shadow-sm);
  backdrop-filter: blur(16px);
}
.title {
  color: var(--cx-ink);
  font-size: 30px;
  line-height: 1.12;
}
.muted,
.space-meta {
  color: var(--cx-muted);
}
.event,
.composer,
.metric,
.hierarchy-row {
  border-color: var(--cx-line);
  border-radius: 14px;
  background: var(--cx-surface);
  color: var(--cx-ink);
  box-shadow: var(--cx-shadow-sm);
}
.event-head {
  color: var(--cx-muted);
  font-weight: 650;
}
.panel {
  border-color: var(--cx-line);
  background: var(--cx-surface-raised);
  color: var(--cx-ink);
}
.search input,
.topbar-search input,
.settings input,
.workflow-form input,
.composer textarea,
.composer input,
.settings textarea,
.settings select,
.workflow-form textarea,
.workflow-form select {
  border-color: var(--cx-line-strong);
  border-radius: 10px;
  background: var(--cx-surface);
  color: var(--cx-ink);
}
.search input:focus,
.topbar-search input:focus,
.settings input:focus,
.workflow-form input:focus,
.composer textarea:focus,
.settings select:focus,
.workflow-form select:focus {
  border-color: var(--cx-brand);
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14);
}
.primary,
.secondary {
  border-radius: 10px;
  min-height: 38px;
  font-weight: 700;
  box-shadow: var(--cx-shadow-sm);
}
.primary {
  background: var(--cx-brand-strong);
  color: #fff;
}
.secondary {
  border: 1px solid var(--cx-line-strong);
  background: var(--cx-surface);
  color: var(--cx-ink);
}
.badge {
  border-radius: 999px;
  font-weight: 700;
}
.badge-info { background: #eff6ff; color: #1d4ed8; }
.badge-success { background: #eefbf5; color: #047857; }
.badge-error { background: #fff1f2; color: #b91c1c; }
.badge-warning { background: #fff8e5; color: #92400e; }
.badge.blue { background: #eff6ff; color: #1d4ed8; }
.badge.amber { background: #fff8e5; color: #92400e; }
.badge.red { background: #fff1f2; color: #b91c1c; }
.badge.green { background: #ecfdf5; color: #047857; }
.dashboard-layout {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(320px, 0.8fr);
  gap: 12px;
}
.board-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(260px, 1fr));
  gap: 12px;
  align-items: start;
}
.board-column { min-width: 0; }
.board-card { cursor: pointer; }
.card-detail-drawer { border-color: var(--cx-brand); }
.tabs {
  gap: 6px;
}
.tab {
  border-radius: 999px;
  background: var(--cx-surface);
  color: var(--cx-muted);
}
.tab.active {
  border-color: var(--cx-brand);
  background: var(--cx-brand);
  color: #fff;
}
@media (max-width: 900px) {
  .dashboard-layout { grid-template-columns: 1fr; }
  .board-grid { grid-template-columns: 1fr; }
}
"#;

#[component]
pub fn App() -> Element {
    rsx! {
        Router::<Route> {}
    }
}

#[component]
pub fn RouterView() -> Element {
    let initial_config = LocalConfigStore::default().load();
    let initial_state_store = LocalStateStore::default();
    let initial_local_state = initial_state_store.load();
    let initial_locale = initial_state_store
        .load_private_data(&initial_config.account_did, "locale")
        .map(|code| Locale::from_code(&code))
        .unwrap_or_default();
    let initial_theme = initial_state_store
        .load_private_data(&initial_config.account_did, "theme")
        .filter(|theme| matches!(theme.as_str(), "light" | "night" | "system"))
        .unwrap_or_else(|| "system".to_owned());
    let config_store = use_signal(LocalConfigStore::default);
    let state_store = use_signal(LocalStateStore::default);
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
    let navigator = use_navigator();
    let route = use_route::<Route>();
    let mut view = use_signal(|| route.to_view());
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
    let timeline = use_signal(Vec::<TimelineEvent>::new);
    let draft = use_signal({
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
    let push_state = use_signal({
        let initial_local_state = initial_local_state.clone();
        move || crate::push::push_status_label(initial_local_state.push_registration.as_ref())
    });
    let repo_state = use_signal(|| "Not checked".to_owned());
    let crypto_state = use_signal(|| "MLS ready; plaintext fallback available".to_owned());
    let network_state = use_signal(|| "online".to_owned());
    let last_error = use_signal(|| Option::<String>::None);
    let server_description = use_signal(|| Option::<ServerDescription>::None);
    let server_probe_status = use_signal(|| "server describe pending".to_owned());
    let locale = use_signal(move || initial_locale);
    let theme = use_signal(move || initial_theme);
    let mut mobile_nav_open = use_signal(|| false);
    let mut global_query = use_signal(String::new);

    use_future({
        let base = base_url();
        move || {
            let base = base.clone();
            async move {
                probe_server_description(base, server_description, server_probe_status).await;
            }
        }
    });

    let active_server_description = server_description();
    let minimal_ready = profile_ready(active_server_description.as_ref(), PROFILE_MINIMAL_CLIENT);
    let chat_ready = profile_ready(active_server_description.as_ref(), PROFILE_CHAT_ONLY_CLIENT);
    let kanban_ready = profile_ready(
        active_server_description.as_ref(),
        PROFILE_KANBAN_ONLY_CLIENT,
    );
    let full_ready = profile_ready(active_server_description.as_ref(), PROFILE_FULL_CLIENT);
    let e2ee_ready = profile_ready(active_server_description.as_ref(), PROFILE_E2EE_CLIENT);
    let push_ready = profile_ready(active_server_description.as_ref(), PROFILE_PUSH_GATEWAY);
    let event_write_ready = active_server_description
        .as_ref()
        .map(|description| description.supports_event_envelope_write_plane())
        .unwrap_or(false);

    let selected_preview = spaces()
        .iter()
        .find(|space| space.space_id == selected_space())
        .cloned();
    let title = selected_preview
        .as_ref()
        .map(|space| space.name.clone())
        .unwrap_or_else(|| "Contrix Demo Space".to_owned());
    let active_locale = locale();
    let active_direction = active_locale.direction();
    let direction_attr = active_direction.as_str();
    let locale_attr = active_locale.code();
    let active_theme = theme();
    let shell_class = format!(
        "shell {}{}",
        match active_theme.as_str() {
            "night" => "theme-night",
            "light" => "theme-light",
            _ => "theme-system",
        },
        if active_direction == TextDirection::Rtl {
            " rtl"
        } else {
            ""
        }
    );

    rsx! {
        style { "{STYLE}" }
        div {
            class: shell_class,
            "dir": direction_attr,
            "lang": locale_attr,
            "data-direction": direction_attr,
            "data-locale": locale_attr,
            "data-theme": active_theme,
            "data-testid": "client-shell",
            div { class: "mobile-shellbar", "data-testid": "mobile-shellbar",
                button {
                    class: "secondary",
                    "data-testid": "mobile-nav-toggle",
                    onclick: move |_| mobile_nav_open.toggle(),
                    if mobile_nav_open() { "Close" } else { "Menu" }
                }
                div { class: "brand", "yougen" }
                Link { class: "secondary", to: Route::Notifications, "Inbox" }
            }
            nav {
                class: if mobile_nav_open() { "mobile-drawer open" } else { "mobile-drawer" },
                "data-testid": "mobile-nav-drawer",
                Link { class: "secondary", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), "Dashboard" }
                Link { class: "secondary", to: Route::Directory, onclick: move |_| mobile_nav_open.set(false), "Directory" }
                Link { class: "secondary", to: Route::Kanban, onclick: move |_| mobile_nav_open.set(false), "Board" }
                Link { class: "secondary", to: Route::Chat, onclick: move |_| mobile_nav_open.set(false), "Discussions" }
                Link { class: "secondary", to: Route::Notifications, onclick: move |_| mobile_nav_open.set(false), "Inbox" }
                Link { class: "secondary", to: Route::Settings, onclick: move |_| mobile_nav_open.set(false), "Settings" }
            }
            aside { class: "sidebar", "data-testid": "sidebar", role: "navigation", "aria-label": "Main navigation",
                div { class: "brand", "yougen" }
                div { class: "status", "data-testid": "connection-status", role: "status", "aria-live": "polite",
                    div { class: "space-title", "data-testid": "status-label", "{status}" }
                    div { class: "muted", "data-testid": "sync-cursor", "cursor {sync_cursor}" }
                    div { class: "actions", style: "margin-top: 8px;",
                        span {
                            class: if network_state() == "online" { "badge badge-success" } else if network_state() == "reconnecting" { "badge badge-warning" } else { "badge badge-error" },
                            "data-testid": "network-state-badge",
                            "{network_state}"
                        }
                        if network_state() != "online" {
                            button {
                                class: "secondary",
                                "data-testid": "retry-connection-button",
                                style: "font-size: 12px; padding: 4px 8px;",
                                onclick: move |_| {
                                    let base = base_url();
                                    let actor = account_did();
                                    let device = device_id();
                                    connect(base, actor, device, ConnectContext {
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
                                        network_state,
                                        last_error,
                                        server_description,
                                        server_probe_status,
                                    });
                                },
                                "Retry"
                            }
                        }
                    }
                    if let Some(ref err) = last_error() {
                        div { class: "muted", style: "color: #721c24; font-size: 11px; margin-top: 4px;", "data-testid": "last-error",
                            "{err}"
                        }
                    }
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
                                    network_state,
                                    last_error,
                                    server_description,
                                    server_probe_status,
                                },
                            ),
                            "Connect"
                        }
                        Link {
                            class: "secondary",
                            "data-testid": "directory-nav-button",
                            to: Route::Directory,
                            "Directory"
                        }
                    }
                }
                div { class: "space-list", "data-testid": "space-list",
                    for space in spaces() {
                        Link {
                            class: if space.space_id == selected_space() { "space-button active" } else { "space-button" },
                            "data-testid": "space-button",
                            to: Route::TimelineSpace { space_id: space.space_id.clone() },
                            onclick: {
                                let id = space.space_id.clone();
                                move |_| selected_space.set(id.clone())
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
                    Link { class: "secondary", to: Route::Dashboard, "Dashboard" }
                    if minimal_ready {
                        Link { class: "secondary", to: Route::Timeline, "Timeline" }
                    }
                    if full_ready {
                        Link { class: "secondary", "data-testid": "product-nav-button", to: Route::Product, "Product" }
                    }
                    Link { class: "secondary", to: Route::Directory, "Directory" }
                    if kanban_ready {
                        Link { class: "secondary", to: Route::Kanban, "Kanban" }
                    }
                    if chat_ready {
                        Link { class: "secondary", to: Route::Chat, "Chat" }
                        Link { class: "secondary", to: Route::Forum, "Forum" }
                    }
                    if full_ready {
                        Link { class: "secondary", "data-testid": "memory-review-nav-button", to: Route::MemoryReview, "Memory" }
                        Link { class: "secondary", "data-testid": "agent-runs-nav-button", to: Route::AgentRuns, "Agents" }
                        Link { class: "secondary", to: Route::Audit, "Audit" }
                    }
                    if minimal_ready || push_ready {
                        Link { class: "secondary", "data-testid": "notifications-nav-button", to: Route::Notifications, "Notifications" }
                    }
                    Link { class: "secondary", "data-testid": "settings-nav-button", to: Route::Settings, "Settings" }
                    if e2ee_ready {
                        Link { class: "secondary", "data-testid": "devices-nav-button", to: Route::Devices, "Devices" }
                        Link { class: "secondary", to: Route::VerifyDevice, "Verify" }
                    }
                    Link { class: "secondary", "data-testid": "readiness-nav-button", to: Route::Readiness, "Release" }
                }
            }

            main { class: "main", "data-testid": "main-view", role: "main", "aria-label": "Main content",
                div { class: "topbar",
                    div {
                        div { class: "title", "data-testid": "space-title", "{title}" }
                        div { class: "muted", "data-testid": "selected-space-id", "{selected_space}" }
                    }
                    div { class: "topbar-search",
                        input {
                            "data-testid": "global-search-input",
                            value: "{global_query}",
                            placeholder: "Search Spaces, Cards, Discussions, Actors",
                            oninput: move |event| global_query.set(event.value()),
                            onkeydown: move |event| {
                                if event.key().to_string() == "Enter" && !global_query().trim().is_empty() {
                                    view.set(crate::views::View::Directory);
                                    let _ = navigator.push(Route::Directory);
                                }
                            },
                        }
                    }
                    div { class: "actions",
                        Link {
                            class: "secondary",
                            "data-testid": "topbar-inbox-button",
                            to: Route::Notifications,
                            "Inbox"
                        }
                        Link {
                            class: "primary",
                            "data-testid": "topbar-create-button",
                            to: Route::Product,
                            "Create"
                        }
                        span { class: "badge blue", "data-testid": "topbar-members", "3 members" }
                        button {
                            class: "secondary",
                            "data-testid": "backfill-button",
                            onclick: move |_| {
                                let base = base_url();
                                let id = selected_space();
                                let api_token = token();
                                let wait_for = active_sync_token(sync_cursor());
                                spawn(async move {
                                    if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                        let _ = api.backfill(&id).await;
                                    }
                                });
                            },
                            "Backfill"
                        }
                        Link {
                            class: "secondary",
                            "data-testid": "resolve-nav-button",
                            to: Route::Directory,
                            "Resolve"
                        }
                    }
                }
                if cfg!(target_arch = "wasm32") {
                    div { class: "event error-banner", "data-testid": "web-security-banner",
                        div { class: "event-head",
                            span { "Web Security Mode" }
                            span { "non-production" }
                        }
                        div { class: "space-title",
                            "Browser builds are running in compatibility mode, not production-secure E2EE."
                        }
                        div { class: "muted",
                            "WebCrypto-backed keys, IndexedDB MLS state, and secure backup/recovery are not implemented yet. Treat browser encryption as development-only."
                        }
                    }
                }
                match route {
                    Route::Login => rsx! {
                        crate::views::login::LoginPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            status,
                            config_store,
                            auto_capture_callback: false,
                            on_login: move |_| { let _ = navigator.push(Route::Dashboard); },
                        }
                    },
                    Route::AuthCallback => rsx! {
                        crate::views::login::LoginPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            status,
                            config_store,
                            auto_capture_callback: true,
                            on_login: move |_| { let _ = navigator.push(Route::Dashboard); },
                        }
                    },
                    Route::Register => rsx! {
                        crate::views::register::RegisterPanel {
                            base_url: base_url(),
                            on_register: move |_| { let _ = navigator.push(Route::Login); },
                        }
                    },
                    Route::Dashboard => rsx! {
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
                    Route::Timeline | Route::TimelineSpace { .. } => {
                        if let Some(sid) = route.space_id() {
                            selected_space.set(sid.to_owned());
                        }
                        if minimal_ready {
                            rsx! {
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
                                    sync_cursor,
                                    repo_state,
                                    base_url_sig: base_url,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "minimal_client" } }
                        }
                    },
                    Route::Directory => rsx! {
                        crate::views::directory::DirectoryPanel {
                            base_url: base_url(),
                            selected_space,
                            spaces,
                            status,
                            token,
                            view,
                        }
                    },
                    Route::Product => {
                        if full_ready {
                            rsx! {
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
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::Settings | Route::SettingsSection { .. } => rsx! {
                        crate::views::settings::SettingsPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            crypto_state: crypto_state(),
                            config_store,
                            state_store,
                            push_state,
                            locale,
                            theme,
                            status,
                            push_ready,
                        }
                    },
                    Route::Devices => {
                        if e2ee_ready {
                            rsx! {
                                crate::views::devices::DevicesPanel {
                                    base_url: base_url(),
                                    token,
                                    device_id: device_id(),
                                    device_queue: device_queue(),
                                    push_state,
                                    state_store,
                                    crypto_state,
                                    push_ready,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "e2ee_client" } }
                        }
                    },
                    Route::Readiness => rsx! {
                        crate::views::readiness::ReadinessPanel {
                            status,
                            server_description: active_server_description.clone(),
                            server_probe_status: server_probe_status(),
                        }
                    },
                    Route::VerifyDevice => {
                        if e2ee_ready {
                            rsx! {
                                crate::views::verify_device::VerifyDevicePanel {
                                    base_url: base_url(),
                                    token,
                                    device_id: device_id(),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "e2ee_client" } }
                        }
                    },
                    Route::SpaceAdmin { .. } => {
                        if full_ready {
                            rsx! {
                                crate::views::space_admin::SpaceAdminPanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    token,
                                    selected_space: selected_space(),
                                    sync_cursor,
                                    repo_state,
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::Audit => {
                        if full_ready {
                            rsx! {
                                crate::views::audit::AuditPanel {
                                    base_url: base_url(),
                                    token,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::Kanban | Route::KanbanSpace { .. } => {
                        if let Some(sid) = route.space_id() {
                            selected_space.set(sid.to_owned());
                        }
                        if kanban_ready {
                            rsx! {
                                crate::views::kanban::KanbanPanel {
                                    base_url: base_url(),
                                    token,
                                    account_did: account_did(),
                                    selected_space: selected_space(),
                                    sync_cursor,
                                    repo_state,
                                    state_store,
                                    event_write_ready,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "kanban_only_client" } }
                        }
                    },
                    Route::Chat | Route::ChatSpace { .. } => {
                        if let Some(sid) = route.space_id() {
                            selected_space.set(sid.to_owned());
                        }
                        if chat_ready {
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    token,
                                    selected_space: selected_space(),
                                    sync_cursor,
                                    repo_state,
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "chat_only_client" } }
                        }
                    },
                    Route::Forum => {
                        if chat_ready {
                            rsx! {
                                crate::views::forum::ForumPanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    token,
                                    selected_space: selected_space(),
                                    sync_cursor,
                                    repo_state,
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "chat_only_client" } }
                        }
                    },
                    Route::MemoryReview => {
                        if full_ready {
                            rsx! {
                                crate::views::memory_review::MemoryReviewPanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    token,
                                    selected_space: selected_space(),
                                    sync_cursor,
                                    repo_state,
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::AgentRuns => {
                        if full_ready {
                            rsx! {
                                crate::views::agent_runs::AgentRunsPanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    token,
                                    selected_space: selected_space(),
                                    sync_cursor,
                                    repo_state,
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::Notifications => rsx! {
                        crate::views::notifications::NotificationsPanel {
                            base_url: base_url(),
                            token,
                            state_store,
                        }
                    },
                    Route::Document | Route::DocumentSpace { .. } => {
                        if let Some(sid) = route.space_id() {
                            selected_space.set(sid.to_owned());
                        }
                        rsx! {
                            if full_ready {
                                crate::views::document::DocumentPanel {
                                    base_url: base_url(),
                                    token,
                                    selected_space: selected_space(),
                                }
                            } else {
                                ProfileGateNotice { profile: "full_client" }
                            }
                        }
                    },
                    Route::Call => rsx! {
                        crate::views::call::CallPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    Route::Recovery => rsx! {
                        crate::views::recovery::RecoveryPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    Route::Applets => rsx! {
                        crate::views::applets::AppletsPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    Route::Onboarding => rsx! {
                        crate::views::onboarding::OnboardingPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    Route::Quarantine => rsx! {
                        crate::views::quarantine::QuarantinePanel {
                            // Round 23 (M6): coauth and soland may share a
                            // host in single-server dev deployments — fall
                            // back to `base_url` until the topology probe
                            // surfaces a separate coauth URL.
                            coauth_url: base_url(),
                            // Admin scope is currently inferred from the
                            // login profile; until profile claims surface
                            // here we treat any signed-in user as admin so
                            // they can exercise the approve / reject path
                            // in dev. Production will gate this on the
                            // `coauth.admin` scope from the session grant.
                            is_admin: true,
                        }
                    },
                }
            }

            RightPanel {
                base_url: base_url(),
                token,
                selected_space: selected_space(),
                selected_preview: selected_preview.clone(),
                spaces_count: spaces().len(),
                device_queue: device_queue(),
                repo_state: repo_state(),
                push_state: push_state(),
                account_did: account_did(),
                device_id: device_id(),
                crypto_state: crypto_state(),
            }
        }
    }
}

#[component]
fn ProfileGateNotice(profile: &'static str) -> Element {
    rsx! {
        div { class: "timeline", "data-testid": "profile-gate-notice",
            div { class: "event error-banner",
                div { class: "event-head",
                    span { "Profile gated" }
                    span { "{profile}" }
                }
                div { class: "space-title", "This server has not declared the required capability set." }
                div { class: "muted", "Write controls for this surface are hidden until /server/describe advertises the matching profile requirements." }
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
    timeline: Signal<Vec<TimelineEvent>>,
    device_queue: Signal<usize>,
    repo_state: Signal<String>,
    crypto_state: Signal<String>,
    push_state: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    network_state: Signal<String>,
    last_error: Signal<Option<String>>,
    server_description: Signal<Option<ServerDescription>>,
    server_probe_status: Signal<String>,
}

async fn probe_server_description(
    base: String,
    mut server_description: Signal<Option<ServerDescription>>,
    mut server_probe_status: Signal<String>,
) {
    match ContrixApi::new(&base) {
        Ok(api) => match api.describe().await {
            Ok(description) => {
                server_probe_status.set(format!(
                    "server describe loaded: {} / {}",
                    description.service_type, description.protocol_version
                ));
                server_description.set(Some(description));
            }
            Err(error) => {
                server_probe_status.set(format!("server describe failed: {error}"));
                server_description.set(None);
            }
        },
        Err(error) => {
            server_probe_status.set(format!("server describe skipped: invalid URL: {error}"));
            server_description.set(None);
        }
    }
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
        let mut network_state = ctx.network_state;
        let mut last_error = ctx.last_error;
        let mut server_description = ctx.server_description;
        let mut server_probe_status = ctx.server_probe_status;

        status.set(ConnectionState::Loading.label().to_owned());
        network_state.set("reconnecting".to_owned());
        last_error.set(None);
        match ContrixApi::new(&base) {
            Ok(api) => {
                match api.describe().await {
                    Ok(description) => {
                        status.set(format!(
                            "{}: {} / {}",
                            ConnectionState::Online.label(),
                            description.service_type,
                            description.protocol_version
                        ));
                        network_state.set("online".to_owned());
                        server_probe_status.set(format!(
                            "server describe loaded: {} / {}",
                            description.service_type, description.protocol_version
                        ));
                        server_description.set(Some(description));
                    }
                    Err(error) => {
                        status.set(format!(
                            "{}: describe failed: {error}",
                            ConnectionState::Reconnecting.label()
                        ));
                        network_state.set("reconnecting".to_owned());
                        last_error.set(Some(format!("describe: {error}")));
                        server_probe_status.set(format!("server describe failed: {error}"));
                        server_description.set(None);
                    }
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
                        let handle = handle_from_did(&actor);
                        match api
                            .register_account(&actor, &handle, Some("yougen"), Some(&device))
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
                match api.search_spaces("", None).await {
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
                            // Thread the per-Space Anchor view (frontier /
                            // leaves / state_root / bottom cells) into the
                            // local store so Move builders + UI can read
                            // it. Bodies without an `anchor_view` field
                            // produce a Default view (empty frontier =
                            // sentinel) so we still record presence.
                            let view = crate::local_state::LocalAnchorView::from_sync_body(body);
                            store.set_anchor_view(id.clone(), view);
                        }
                    }
                    sync_cursor.set(sync.next_batch);
                    device_queue.set(sync.to_device.len());
                    timeline.set(
                        sync.spaces
                            .into_iter()
                            .map(|(id, body)| {
                                TimelineEvent::system_notice(
                                    format!("summary-{id}"),
                                    "serverx",
                                    format!(
                                        "{id}: {}",
                                        body["summary"]["summary"]
                                            .as_str()
                                            .unwrap_or("No summary available")
                                    ),
                                )
                            })
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
                if let Ok(blob) = authed.upload_blob(b"yougen encrypted bytes").await {
                    let _ = authed.get_blob_bytes(&blob.blob_ref).await;
                }
                match crate::push::build_register_request(&device) {
                    Ok(request) => match authed.register_push_device_with_request(&request).await {
                        Ok(push) => {
                            let mut local_push = chime::RegisterDeviceResponse::default();
                            local_push.ok = push.ok;
                            local_push.registration_id = push.registration_id.clone();
                            local_push.expires_at = push.expires_at.clone();
                            state_store.write().save_push_registration(
                                crate::push::registration_state_from_response(
                                    &request,
                                    &local_push,
                                ),
                            );
                            push_state.set(
                                push.registration_id
                                    .unwrap_or_else(|| "registered".to_owned()),
                            );
                        }
                        Err(error) => push_state.set(format!("push failed: {error}")),
                    },
                    Err(error) => push_state.set(format!("push unavailable: {error}")),
                }
            }
            Err(error) => {
                status.set(format!(
                    "{}: invalid URL: {error}",
                    ConnectionState::Error.label()
                ));
                network_state.set("offline".to_owned());
                last_error.set(Some(format!("invalid URL: {error}")));
                server_probe_status.set(format!("server describe skipped: invalid URL: {error}"));
                server_description.set(None);
            }
        }
    });
}

fn active_sync_token(sync_cursor: String) -> Option<String> {
    (!sync_cursor.trim().is_empty() && sync_cursor != "-").then_some(sync_cursor)
}
