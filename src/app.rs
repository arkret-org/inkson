use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::*;
use dioxus_router::{Link, Navigator, Router, hooks::*};
use serde_json::Value;

use crate::{
    api::{ContrixApi, is_auth_expired_error},
    components::UiIcon,
    config::{LocalConfigStore, normalize_device_id, normalize_server_url},
    conformance::{
        PROFILE_CHAT_ONLY_CLIENT, PROFILE_E2EE_CLIENT, PROFILE_FULL_CLIENT,
        PROFILE_KANBAN_ONLY_CLIENT, PROFILE_MINIMAL_CLIENT, PROFILE_PUSH_GATEWAY, profile_ready,
    },
    i18n::{Locale, TextDirection},
    local_state::LocalStateStore,
    models::{ServerDescription, SpacePreview},
    routes::Route,
    views::{ConnectionState, helpers::persist_config, timeline::TimelineEvent},
};

const UI_PREFERENCES_SCOPE: &str = "ui.browser";
const SIDEBAR_WIDTH_PREFERENCE_KEY: &str = "layout.sidebar.width";
const SPACE_SCOPE_PREFERENCE_KEY: &str = "layout.space.scope";
const DEFAULT_SIDEBAR_WIDTH: f64 = 272.0;
const MIN_SIDEBAR_WIDTH: f64 = 220.0;
const MAX_SIDEBAR_WIDTH: f64 = 420.0;

const STYLE: &str = r#"
body { margin: 0; font-family: Inter, Segoe UI, sans-serif; background: #eef3ed; color: #162018; }
button, input, textarea { font: inherit; }
.auth-shell { width: 100vw; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: #e7efe6; box-sizing: border-box; }
.auth-shell.theme-night { background: #0f172a; color: #e5edf7; }
.auth-card { width: min(420px, 100%); border: 1px solid #d2ddd2; border-radius: 8px; background: #fff; box-shadow: 0 16px 40px rgba(15, 23, 42, 0.12); }
.auth-shell.theme-night .auth-card { border-color: #2a3a52; background: #172033; }
.auth-panel { display: grid; gap: 22px; padding: 28px; }
.auth-brand { display: flex; align-items: center; gap: 12px; }
.auth-logo { width: 40px; height: 40px; border-radius: 8px; display: grid; place-items: center; background: #1f5a41; color: #fff; font-weight: 800; }
.auth-brand h1 { margin: 0; font-size: 24px; line-height: 1.15; letter-spacing: 0; }
.auth-brand p { margin: 3px 0 0; color: #617065; font-size: 13px; }
.auth-form { display: grid; gap: 10px; }
.auth-form label { color: #4a5d51; font-size: 13px; font-weight: 700; }
.auth-form input { width: 100%; box-sizing: border-box; border: 1px solid #c2d0c3; border-radius: 6px; padding: 11px 12px; background: #fff; color: #142018; }
.auth-shell.theme-night .auth-form input { border-color: #3a4b63; background: #111827; color: #e5edf7; }
.auth-primary, .auth-secondary { width: 100%; margin-top: 4px; }
.auth-status { color: #64748b; font-size: 13px; overflow-wrap: anywhere; }
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
.search input:not([type="checkbox"]):not([type="radio"]), .settings input:not([type="checkbox"]):not([type="radio"]), .workflow-form input:not([type="checkbox"]):not([type="radio"]), .composer textarea, .composer input:not([type="checkbox"]):not([type="radio"]) { width: 100%; box-sizing: border-box; border: 1px solid #cbd5df; border-radius: 6px; padding: 7px 12px; background: white; color: #18212f; }
.composer label, .settings label, .workflow-form label { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text, #4e5b6b); }
.composer label > input[type="checkbox"], .composer label > input[type="radio"], .settings label > input[type="checkbox"], .settings label > input[type="radio"], .workflow-form label > input[type="checkbox"], .workflow-form label > input[type="radio"] { width: auto; margin: 0; padding: 0; }
.space-list { display: grid; gap: 8px; align-content: start; overflow: auto; }
.space-button { border: 1px solid #314255; border-radius: 8px; padding: 12px; color: white; background: #223247; text-align: left; cursor: pointer; }
.space-button.active { border-color: #5cc8a7; background: #284252; }
.space-title { font-weight: 700; }
.space-meta, .muted { color: #6b7787; font-size: 13px; }
.sidebar .space-meta, .sidebar .muted { color: #cbd5e1; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; }
.primary, .secondary { border: 0; border-radius: 6px; padding: 10px 12px; cursor: pointer; display: inline-block; text-decoration: none; text-align: center; }
.primary { background: #1f6b4f; color: white; }
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
.section { display: grid; gap: 10px; }
.section-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.section h2 { margin: 0; font-size: 16px; }
.metric-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.metric { background: white; border: 1px solid #d8e0e8; border-radius: 8px; padding: 10px; min-width: 0; }
.metric strong { display: block; font-size: 12px; color: #607086; margin-bottom: 4px; }
.metric span { overflow-wrap: anywhere; }
.quick-nav { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.quick-nav__item { min-width: 0; }
.mobile-shellbar, .mobile-drawer { display: none; }
.mobile-status { display: grid; gap: 3px; padding: 8px 10px; border: 1px solid rgba(255,255,255,0.16); border-radius: 6px; color: #e2e8f0; }
.mobile-status .muted { color: #cbd5e1; }
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
.settings, .workflow-form { display: grid; gap: 10px; }
.settings-inline-form {
  display: grid;
  grid-template-columns: minmax(180px, 1.1fr) minmax(160px, 0.9fr) auto;
  gap: 8px;
  align-items: center;
}
.settings-list {
  display: grid;
  gap: 8px;
  padding: 0;
  margin: 0;
  list-style: none;
}
.settings-list-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px;
  align-items: center;
  padding: 10px 0;
  border-top: 1px solid var(--border, #d8e0e8);
}
.settings-list-row strong,
.settings-list-row .muted {
  overflow-wrap: anywhere;
}
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
button:focus-visible {
  outline: none;
  box-shadow: 0 0 0 3px rgba(31, 107, 79, 0.18);
}
input:focus-visible, textarea:focus-visible, select:focus-visible {
  outline: none;
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
  .mobile-drawer.open { display: grid; gap: 8px; padding: 12px; background: #172033; max-height: calc(100vh - 60px); overflow-y: auto; }
  .mobile-space-filter { width: 100%; padding: 8px 10px; border-radius: 6px; border: 1px solid #2a3a52; background: #0f172a; color: #e5edf7; }
  .mobile-space-filter::placeholder { color: #6b7a90; }
  .mobile-space-list { display: grid; gap: 6px; max-height: 50vh; overflow-y: auto; padding-right: 4px; }
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

/* App theme layer: calm security-oriented palette shared by all views. */
body {
  font-family: Inter, "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
  background: #eef3ed;
  color: #142018;
  letter-spacing: 0;
}
.shell {
  --cx-bg: #edf3ee;
  --cx-bg-soft: #f7faf7;
  --cx-bg-end: #e0ebe2;
  --cx-surface: #ffffff;
  --cx-surface-raised: rgba(255, 255, 255, 0.94);
  --cx-ink: #142018;
  --cx-muted: #627065;
  --cx-line: #d6e1d7;
  --cx-line-strong: #c0cec2;
  --cx-brand: #2b6b4f;
  --cx-brand-strong: #1f5a41;
  --cx-teal: #3a8a67;
  --cx-green: #4b946a;
  --cx-amber: #a56b13;
  --cx-red: #c64940;
  --cx-nav: #0f1914;
  --cx-nav-soft: #16241d;
  --cx-shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.08);
  --cx-shadow: 0 16px 40px rgba(15, 23, 42, 0.14);
  background: linear-gradient(135deg, var(--cx-bg) 0%, var(--cx-bg-soft) 64%, var(--cx-bg-end) 100%);
  color: var(--cx-ink);
}
.shell.theme-night {
  --cx-bg: #0d1511;
  --cx-bg-soft: #111b16;
  --cx-bg-end: #09100d;
  --cx-surface: #15211b;
  --cx-surface-raised: rgba(21, 33, 27, 0.94);
  --cx-ink: #e7f0ea;
  --cx-muted: #9caea2;
  --cx-line: #2b3d34;
  --cx-line-strong: #3b5246;
  --cx-brand: #71b58f;
  --cx-brand-strong: #4f9870;
  --cx-teal: #89d0ad;
  --cx-nav: #08100c;
  --cx-nav-soft: #0d1612;
  --cx-shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.28);
  --cx-shadow: 0 18px 48px rgba(0, 0, 0, 0.36);
}
@media (prefers-color-scheme: dark) {
  .shell.theme-system {
    --cx-bg: #0d1511;
    --cx-bg-soft: #111b16;
    --cx-bg-end: #09100d;
    --cx-surface: #15211b;
    --cx-surface-raised: rgba(21, 33, 27, 0.94);
    --cx-ink: #e7f0ea;
    --cx-muted: #9caea2;
    --cx-line: #2b3d34;
    --cx-line-strong: #3b5246;
    --cx-brand: #71b58f;
    --cx-brand-strong: #4f9870;
    --cx-teal: #89d0ad;
    --cx-nav: #08100c;
    --cx-nav-soft: #0d1612;
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
  content: "C";
  width: 34px;
  height: 34px;
  border-radius: 10px;
  display: grid;
  place-items: center;
  color: #fff;
  background: linear-gradient(135deg, var(--cx-brand-strong), var(--cx-teal));
  box-shadow: 0 12px 30px rgba(31, 107, 79, 0.24);
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
  border-color: rgba(113, 181, 143, 0.48);
  background: rgba(43, 107, 79, 0.18);
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
.metric {
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
.search input:not([type="checkbox"]):not([type="radio"]),
.topbar-search input:not([type="checkbox"]):not([type="radio"]),
.settings input:not([type="checkbox"]):not([type="radio"]),
.workflow-form input:not([type="checkbox"]):not([type="radio"]),
.composer textarea,
.composer input:not([type="checkbox"]):not([type="radio"]),
.settings textarea,
.settings select,
.workflow-form textarea,
.workflow-form select {
  border-color: var(--cx-line-strong);
  border-radius: 10px;
  background: var(--cx-surface);
  color: var(--cx-ink);
}
.search input:not([type="checkbox"]):not([type="radio"]):focus,
.topbar-search input:not([type="checkbox"]):not([type="radio"]):focus,
.auth-form input:not([type="checkbox"]):not([type="radio"]):focus,
.settings input:not([type="checkbox"]):not([type="radio"]):focus,
.workflow-form input:not([type="checkbox"]):not([type="radio"]):focus,
.composer textarea:focus,
.composer input:not([type="checkbox"]):not([type="radio"]):focus,
.settings textarea:focus,
.settings select:focus,
.workflow-form textarea:focus,
.workflow-form select:focus {
  border-color: var(--cx-brand);
  background: color-mix(in srgb, var(--cx-brand) 4%, var(--cx-surface));
  box-shadow: none;
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
.badge-info { background: #e8f3ec; color: #1f5a41; }
.badge-success { background: #eefbf5; color: #047857; }
.badge-error { background: #fff1f2; color: #b91c1c; }
.badge-warning { background: #fff8e5; color: #92400e; }
.badge.blue { background: #e8f3ec; color: #1f5a41; }
.badge.amber { background: #fff8e5; color: #92400e; }
.badge.red { background: #fff1f2; color: #b91c1c; }
.badge.green { background: #ecfdf5; color: #047857; }
.dashboard-layout {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(320px, 0.8fr);
  gap: 12px;
}
.home-hero {
  overflow: hidden;
  background:
    radial-gradient(circle at 12% 0%, rgba(43, 107, 79, 0.18), transparent 34%),
    radial-gradient(circle at 90% 10%, rgba(165, 107, 19, 0.12), transparent 30%),
    var(--cx-surface);
}
.home-hero-title {
  font-size: 30px;
  line-height: 1.08;
}
.home-hero-copy {
  max-width: 760px;
  color: var(--cx-muted);
  font-size: 14px;
  line-height: 1.55;
}
.home-card-list {
  display: grid;
  gap: 10px;
}
.home-card-list.compact {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}
.home-space-card {
  border-color: var(--cx-line);
  background: linear-gradient(180deg, rgba(255,255,255,0.96), rgba(248,250,252,0.94));
  color: var(--cx-ink);
}
.home-space-card .space-title {
  color: var(--cx-ink);
}
.home-space-card .space-meta,
.home-space-card .muted {
  color: var(--cx-muted);
}
.home-space-card.cross-org {
  border-color: rgba(58, 138, 103, 0.34);
  background: linear-gradient(135deg, rgba(236, 247, 239, 0.94), rgba(248, 244, 232, 0.92));
}
.home-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 4px;
}
.nested-card {
  background: rgba(248, 250, 252, 0.76);
}
.directory-axis-card {
  background:
    radial-gradient(circle at 100% 0%, rgba(43, 107, 79, 0.14), transparent 32%),
    var(--cx-surface);
}
.directory-search-card {
  position: sticky;
  top: 0;
  z-index: 1;
}
.board-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(260px, 1fr));
  gap: 12px;
  align-items: start;
}
.board-header {
  gap: 8px;
}
.board-column {
  min-width: 0;
  min-height: 220px;
  padding: 10px;
}
.board-card {
  cursor: grab;
  padding: 10px 12px;
}
.board-card:active {
  cursor: grabbing;
}
.board-card .event-head {
  align-items: flex-start;
}
.card-detail-drawer { border-color: var(--cx-brand); }
.chat-message-row {
  padding: 10px 12px;
  gap: 8px;
}
.chat-message-actions {
  opacity: 0;
  visibility: hidden;
  pointer-events: none;
}
.compact-composer {
  padding: 10px;
}
.compact-composer textarea {
  min-height: 64px;
}
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
.settings-shell {
  display: grid;
  grid-template-columns: minmax(260px, 320px) minmax(0, 1fr);
  gap: 14px;
  align-items: start;
}
.settings-sidebar-column,
.settings-content-column,
.settings-content-stack {
  display: grid;
  gap: 12px;
}
.settings-nav-cluster {
  display: grid;
  gap: 8px;
}
.settings-content-title {
  margin: 0;
  color: var(--text, var(--cx-ink));
  line-height: 1.08;
  font-size: 26px;
}
.settings-content-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.settings-content-title-row .help-tip {
  flex: 0 0 auto;
}
.settings-nav-list {
  display: grid;
  gap: 8px;
}
.settings-nav-divider {
  height: 1px;
  margin: 2px 0 4px;
  background: color-mix(in srgb, var(--border) 82%, transparent);
}
.settings-nav-item {
  display: grid;
  gap: 4px;
  padding: 10px 4px;
  border: 0;
  border-radius: 0;
  border-left: 2px solid transparent;
  border: 1px solid color-mix(in srgb, var(--border) 76%, transparent);
  border-width: 0 0 0 2px;
  background: transparent;
  color: inherit;
  text-decoration: none;
  box-shadow: none;
  transition: border-color 140ms ease, background-color 140ms ease, padding-left 140ms ease;
}
.settings-nav-item strong {
  color: var(--text, var(--cx-ink));
  font-size: 13px;
}
.settings-nav-item:hover {
  border-left-color: color-mix(in srgb, var(--accent) 48%, var(--border));
  background: color-mix(in srgb, var(--accent-soft) 18%, transparent);
  padding-left: 8px;
}
.settings-nav-item.active {
  border-left-color: color-mix(in srgb, var(--accent) 82%, var(--border));
  background: color-mix(in srgb, var(--accent-soft) 26%, transparent);
  padding-left: 10px;
}
.settings-content-hero {
  padding: 16px 18px;
  background:
    radial-gradient(circle at 100% 0, rgba(165, 107, 19, 0.12), transparent 26%),
    radial-gradient(circle at 0 0, rgba(43, 107, 79, 0.14), transparent 34%),
    var(--surface, var(--cx-surface));
}
.settings-card-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
.setup-shell {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(320px, 0.85fr);
  gap: 12px;
  align-items: start;
}
.new-space-shell {
  grid-template-columns: minmax(0, 1fr) minmax(300px, 360px);
}
.new-space-hero {
  padding: 18px;
}
.setup-column {
  display: grid;
  gap: 12px;
  align-content: start;
}
.setup-review-column {
  position: sticky;
  top: 12px;
}
.setup-step-list {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}
.setup-step-list button {
  min-width: 0;
  justify-content: flex-start;
  text-align: left;
}
.setup-step-index {
  display: inline-grid;
  place-items: center;
  width: 20px;
  height: 20px;
  border-radius: 999px;
  background: color-mix(in srgb, currentColor 14%, transparent);
  flex: 0 0 auto;
  font-size: 11px;
}
.setup-step-label {
  display: grid;
  gap: 1px;
  min-width: 0;
}
.setup-step-label strong,
.setup-step-label small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.setup-step-label small {
  color: inherit;
  opacity: 0.72;
  font-size: 11px;
  font-weight: 600;
}
.setup-form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
.setup-form-grid textarea {
  min-height: 96px;
  resize: vertical;
}
.setup-field {
  display: grid;
  gap: 6px;
  min-width: 0;
}
.setup-field label {
  color: var(--text, var(--cx-ink));
  font-size: 13px;
  font-weight: 700;
}
.setup-field-span-2 {
  grid-column: 1 / -1;
}
.setup-axis-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}
.setup-summary-list {
  display: grid;
  gap: 10px;
}
.setup-summary-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
}
.setup-summary-row strong {
  color: var(--text, var(--cx-ink));
  font-size: 13px;
}
.setup-summary-row span {
  overflow-wrap: anywhere;
  text-align: right;
}
.setup-summary-row-stack {
  display: grid;
  gap: 8px;
}
.setup-summary-row-stack span {
  text-align: left;
}
.setup-chip-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.setup-action-grid {
  display: grid;
  gap: 8px;
}
.setup-action-grid .primary,
.setup-action-grid .secondary {
  width: 100%;
}
.setup-nav-actions {
  justify-content: flex-end;
  margin-top: 4px;
}
.settings-card-span-2 {
  grid-column: 1 / -1;
}
@media (max-width: 900px) {
  .dashboard-layout { grid-template-columns: 1fr; }
  .board-grid { grid-template-columns: 1fr; }
  .home-card-list.compact { grid-template-columns: 1fr; }
  .settings-shell,
  .settings-card-grid,
  .settings-inline-form,
  .settings-list-row { grid-template-columns: 1fr; }
  .setup-review-column { position: static; }
}
@media (max-width: 1100px) {
  .setup-shell,
  .setup-form-grid,
  .setup-axis-grid {
    grid-template-columns: 1fr;
  }
  .setup-step-list { grid-template-columns: 1fr; }
  .setup-field-span-2 {
    grid-column: auto;
  }
}

/* Contrix design implementation layer. */
.shell {
  grid-template-columns: 316px minmax(0, 1fr) 352px;
}
.shell.rtl {
  grid-template-columns: 352px minmax(0, 1fr) 316px;
}
.sidebar {
  grid-template-rows: auto auto auto minmax(0, 1fr) auto;
  gap: 14px;
  padding: 18px;
  overflow: hidden;
}
.cx-sidebar-brand {
  display: grid;
  gap: 2px;
}
.brand-subtitle {
  color: #9fb0c3;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  margin-left: 44px;
}
.sidebar-context {
  display: grid;
  gap: 10px;
  border: 1px solid rgba(148, 163, 184, 0.22);
  border-radius: 18px;
  padding: 12px;
  background:
    radial-gradient(circle at top right, rgba(43, 107, 79, 0.22), transparent 42%),
    rgba(255, 255, 255, 0.055);
}
.context-row {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  min-width: 0;
}
.context-label {
  color: #9fb0c3;
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.07em;
}
.context-title {
  color: #f8fafc;
  font-size: 14px;
  font-weight: 800;
  overflow-wrap: anywhere;
}
.context-meta {
  color: #cbd5e1;
  font-size: 12px;
  line-height: 1.35;
  overflow-wrap: anywhere;
}
.server-connect {
  display: grid;
  gap: 9px;
}
.server-connect input {
  width: 100%;
  box-sizing: border-box;
  border: 1px solid rgba(148, 163, 184, 0.32);
  border-radius: 12px;
  padding: 10px 12px;
  background: rgba(15, 23, 42, 0.62);
  color: #f8fafc;
}
.sidebar-status {
  margin-top: 2px;
}
.topbar-eyebrow {
  color: var(--cx-muted);
  font-size: 12px;
  font-weight: 900;
  letter-spacing: 0.08em;
}
.shell.rtl .context-row,
.shell.rtl .topbar {
  direction: rtl;
}
"#;

const CLAUDE_STYLE: &str = include_str!("styles/claude_design.css");

const CLAUDE_APP_OVERRIDES: &str = r#"
:root {
  --sidebar-w: 272px;
  --sidebar-collapsed-w: 72px;
}

:root,
[data-theme="light"] {
  --bg: #f6eee7;
  --bg-elev: #ece2d9;
  --surface: rgba(255, 250, 245, 0.94);
  --surface-2: #f6efe8;
  --surface-3: #efe5dc;
  --surface-inv: #18212f;
  --hover: rgba(47, 39, 35, 0.04);
  --hover-strong: rgba(47, 39, 35, 0.07);

  --border: #e6d9cf;
  --border-strong: #d8c7bb;
  --border-faint: #f1e8df;

  --text: #2f2723;
  --text-2: #6f625a;
  --text-3: #9b8c84;
  --text-on-accent: #fffaf6;
  --text-inv: #f8f2ee;

  --accent: #d97706;
  --accent-strong: #b96505;
  --accent-soft: #fff4e6;
  --accent-2: #c65b72;
  --accent-ink: #7f3f02;

  --success: #317d6a;
  --success-soft: #e5f3ee;
  --success-ink: #1f5d4f;
  --warning: #b97824;
  --warning-soft: #fff4e1;
  --warning-ink: #7a4f15;
  --danger: #c44c2d;
  --danger-soft: #fce7e2;
  --danger-ink: #8c331b;
  --info: #586fcb;
  --info-soft: #edf0ff;
  --info-ink: #33479d;
  --neutral-soft: #f1e9e2;

  --proto-bg: #18141a;
  --proto-fg: #efe8e1;
  --proto-meta: #b6a49a;
  --proto-accent: #f1c37d;

  --shadow-xs: 0 1px 1px rgba(58, 41, 30, 0.05);
  --shadow-sm: 0 1px 2px rgba(58, 41, 30, 0.06), 0 1px 1px rgba(58, 41, 30, 0.04);
  --shadow-md: 0 8px 22px rgba(79, 57, 40, 0.10), 0 1px 2px rgba(58, 41, 30, 0.05);
  --shadow-lg: 0 24px 56px rgba(79, 57, 40, 0.14);
  --ring: 0 0 0 3px rgba(217, 119, 6, 0.18);

  --page-glow-a: rgba(245, 158, 11, 0.10);
  --page-glow-b: rgba(198, 91, 114, 0.08);
  --page-glow-c: rgba(88, 111, 203, 0.07);

  --nav-bg: #161c28;
  --nav-bg-2: #202a39;
  --nav-soft: rgba(255, 255, 255, 0.05);
  --nav-border: rgba(217, 119, 6, 0.18);
  --nav-text: #f8f2ee;
  --nav-muted: #cbbab1;
  --nav-label: #a89389;
  --nav-input-bg: rgba(10, 15, 25, 0.42);
  --nav-input-border: rgba(203, 186, 177, 0.18);
}

[data-theme="dark"],
[data-theme="night"] {
  --bg: #101722;
  --bg-elev: #223041;
  --surface: rgba(27, 36, 48, 0.94);
  --surface-2: #202b39;
  --surface-3: #283546;
  --surface-inv: #fffaf6;
  --hover: rgba(255, 255, 255, 0.04);
  --hover-strong: rgba(255, 255, 255, 0.08);

  --border: #3a4454;
  --border-strong: #4b586b;
  --border-faint: #202938;

  --text: #f8f2ee;
  --text-2: #cbbab1;
  --text-3: #a89389;
  --text-on-accent: #2c170b;
  --text-inv: #1c1e25;

  --accent: #f59e0b;
  --accent-strong: #f7ae3a;
  --accent-soft: rgba(245, 158, 11, 0.12);
  --accent-2: #fb7185;
  --accent-ink: #fde7ba;

  --success: #7bc9b5;
  --success-soft: rgba(123, 201, 181, 0.16);
  --success-ink: #d7f5ec;
  --warning: #f0be78;
  --warning-soft: rgba(240, 190, 120, 0.16);
  --warning-ink: #fae7c2;
  --danger: #ff7a59;
  --danger-soft: rgba(255, 122, 89, 0.16);
  --danger-ink: #ffd6cd;
  --info: #a7b7ff;
  --info-soft: rgba(167, 183, 255, 0.16);
  --info-ink: #dce4ff;
  --neutral-soft: #1f2a38;

  --proto-bg: #0f1218;
  --proto-fg: #f1e8e2;
  --proto-meta: #b7a49c;
  --proto-accent: #f2c98b;

  --shadow-xs: 0 1px 1px rgba(4, 8, 14, 0.38);
  --shadow-sm: 0 1px 2px rgba(4, 8, 14, 0.42);
  --shadow-md: 0 10px 24px rgba(4, 8, 14, 0.32), 0 1px 2px rgba(4, 8, 14, 0.40);
  --shadow-lg: 0 28px 64px rgba(4, 8, 14, 0.42);
  --ring: 0 0 0 3px rgba(245, 158, 11, 0.26);

  --page-glow-a: rgba(245, 158, 11, 0.14);
  --page-glow-b: rgba(251, 113, 133, 0.12);
  --page-glow-c: rgba(123, 201, 181, 0.08);

  --nav-bg: #111827;
  --nav-bg-2: #1a2230;
  --nav-soft: rgba(255, 255, 255, 0.04);
  --nav-border: rgba(245, 158, 11, 0.18);
  --nav-text: #f8f2ee;
  --nav-muted: #cbbab1;
  --nav-label: #a89389;
  --nav-input-bg: rgba(8, 12, 20, 0.56);
  --nav-input-border: rgba(168, 147, 137, 0.18);
}

.discussion-shell {
  display: grid;
  grid-template-columns: minmax(260px, 320px) minmax(0, 1fr) minmax(260px, 320px);
  grid-template-rows: minmax(0, 1fr) auto;
  gap: 12px;
  width: 100%;
  height: calc(100vh - 132px);
  min-height: 560px;
  padding: 12px;
  box-sizing: border-box;
  overflow: hidden;
}

.discussion-shell.left-collapsed {
  grid-template-columns: 48px minmax(0, 1fr) minmax(260px, 320px);
}

.discussion-shell.right-collapsed {
  grid-template-columns: minmax(260px, 320px) minmax(0, 1fr);
}

.discussion-shell.left-collapsed.right-collapsed {
  grid-template-columns: 48px minmax(0, 1fr);
}

.discussion-panel,
.discussion-composer {
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
  box-shadow: var(--shadow-xs);
}

.discussion-panel {
  min-height: 0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.discussion-sidebar-panel,
.discussion-left-rail {
  grid-column: 1;
  grid-row: 1 / span 2;
}

.discussion-main-panel {
  grid-column: 2;
  grid-row: 1;
}

.discussion-composer {
  grid-column: 2;
  grid-row: 2;
  display: grid;
  gap: 10px;
  padding: 12px;
}

.discussion-details-panel,
.discussion-right-rail {
  grid-column: 3;
  grid-row: 1 / span 2;
}

.discussion-rail {
  display: grid;
  place-items: start center;
  padding-top: 8px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
}

.discussion-panel-head,
.discussion-chat-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
}

.discussion-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.context-help-row {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.discussion-title-row h1,
.discussion-title-row h2 {
  margin: 0;
  color: var(--text);
  letter-spacing: 0;
}

.discussion-title-row h1 {
  font-size: 20px;
  line-height: 1.2;
}

.discussion-title-row h2 {
  font-size: 15px;
  line-height: 1.25;
}

.discussion-title-stack {
  min-width: 0;
  display: grid;
  gap: 4px;
}

.discussion-topic {
  max-width: 62ch;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.discussion-head-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 6px;
}

.discussion-panel-head-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}

.icon-button {
  width: 34px;
  height: 34px;
  padding: 0;
  justify-content: center;
}

.icon-button.active {
  border-color: var(--accent);
  background: var(--accent-soft);
  color: var(--text);
}

.discussion-filter {
  margin: 10px 12px 0;
  width: calc(100% - 24px);
}

.discussion-filter .segment {
  flex: 1 1 0;
  text-align: center;
}

.discussion-list {
  flex: 1;
  min-height: 0;
  display: grid;
  align-content: start;
  gap: 8px;
  padding: 12px;
  overflow-y: auto;
}

.discussion-track-row {
  appearance: none;
  width: 100%;
  min-height: 68px;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px;
  align-items: center;
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: transparent;
  color: var(--text);
  text-align: left;
  cursor: pointer;
}

.discussion-track-row:hover {
  background: var(--hover);
}

.discussion-track-row.active {
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 10%, transparent);
}

.discussion-track-main {
  min-width: 0;
  display: grid;
  gap: 4px;
}

.discussion-track-name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 700;
}

.discussion-track-topic {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text-2);
  font-size: 12px;
}

.discussion-track-meta,
.chat-chip-row {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 6px;
}

.discussion-new {
  display: grid;
  gap: 8px;
  padding: 12px;
  border-top: 1px solid var(--border);
}

.discussion-subhead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  color: var(--text-2);
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0;
}

.discussion-create-button {
  justify-content: center;
}

.mention-suggestions {
  display: flex;
  flex-direction: column;
  gap: 2px;
  margin-top: 6px;
  padding: 4px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
  box-shadow: var(--shadow-sm);
  max-height: 220px;
  overflow-y: auto;
}

.mention-suggestion-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: 100%;
  padding: 8px 10px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text);
  text-align: left;
  cursor: pointer;
}

.mention-suggestion-item:hover,
.mention-suggestion-item:focus-visible {
  background: var(--surface-2, color-mix(in srgb, var(--accent) 10%, transparent));
  outline: none;
}

.mention-suggestion-name {
  font-weight: 600;
}

.mention-suggestion-did {
  font-size: 12px;
  font-family: var(--font-mono, monospace);
}

.discussion-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 80;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgba(8, 13, 20, 0.64);
}

.discussion-modal {
  width: min(520px, 100%);
  max-height: min(760px, calc(100vh - 48px));
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
  box-shadow: var(--shadow-lg);
  overflow: hidden;
}

.discussion-modal-head,
.discussion-modal-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
}

.discussion-modal-head h2 {
  margin: 0;
  font-size: 16px;
  line-height: 1.25;
}

.discussion-modal-body {
  min-height: 0;
  overflow-y: auto;
  padding: 14px;
}

.discussion-modal-body textarea {
  min-height: 76px;
  resize: vertical;
}

.discussion-modal-actions {
  justify-content: flex-end;
  border-top: 1px solid var(--border);
  border-bottom: 0;
}

.discussion-checkbox-row {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text);
  font-weight: 700;
  cursor: pointer;
}

.discussion-checkbox-row input[type="checkbox"] {
  width: auto;
  min-width: 0;
  flex: 0 0 auto;
  margin: 0;
  padding: 0;
  border: 0;
  background: transparent;
  box-shadow: none;
  appearance: auto;
  accent-color: var(--accent, #1f6b4f);
}

.discussion-chat-feed {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 14px;
  overflow-y: auto;
  background: color-mix(in srgb, var(--surface-2) 48%, transparent);
}

.discussion-message {
  max-width: min(76%, 720px);
  align-self: flex-start;
}

.discussion-message.is-own {
  align-self: flex-end;
}

.discussion-message .msg-body {
  max-width: 100%;
  display: grid;
  gap: 7px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
}

.discussion-message.is-own .msg-body {
  border-color: color-mix(in srgb, var(--accent) 42%, var(--border));
  background: color-mix(in srgb, var(--accent-soft) 74%, var(--surface));
}

.discussion-message.is-failed .msg-body,
.discussion-message.is-own.is-failed .msg-body {
  border-color: color-mix(in srgb, var(--danger) 72%, var(--border));
  background: color-mix(in srgb, var(--danger-soft) 72%, var(--surface));
}

.discussion-message .msg-head {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 6px;
}

.discussion-message .msg-content {
  overflow-wrap: anywhere;
}

.message-failure-icon {
  display: inline-grid;
  place-items: center;
  color: var(--danger-ink);
  line-height: 1;
}

.message-error-row {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 7px 8px;
  border: 1px solid color-mix(in srgb, var(--danger) 42%, transparent);
  border-radius: 6px;
  background: color-mix(in srgb, var(--danger-soft) 84%, var(--surface));
  color: var(--danger-ink);
  font-size: 13px;
  overflow-wrap: anywhere;
}

.message-error-mark {
  flex: 0 0 auto;
  display: inline-grid;
  place-items: center;
  width: 18px;
  height: 18px;
  border-radius: 999px;
  background: var(--danger);
  color: var(--text-on-accent);
  font-weight: 800;
  line-height: 1;
}

.message-retry-button,
.chat-message-action {
  border: 0;
  background: transparent;
  box-shadow: none;
  padding: 0;
  min-height: 0;
  width: auto;
  color: inherit;
  cursor: pointer;
  font-weight: 750;
}

.message-retry-button {
  flex: 0 0 auto;
  margin-left: auto;
  color: var(--danger-ink);
  text-decoration: underline;
  text-underline-offset: 2px;
}

.chat-message-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 1px;
  opacity: 0;
  visibility: hidden;
  pointer-events: none;
  transition: opacity 120ms ease;
}

.discussion-message:hover .chat-message-actions,
.discussion-message:focus-within .chat-message-actions {
  opacity: 1;
  visibility: visible;
  pointer-events: auto;
}

.chat-message-action {
  color: var(--text-2);
  font-size: 11px;
  font-weight: 500;
  opacity: 0.78;
}

.chat-message-action:hover,
.chat-message-action:focus-visible,
.message-retry-button:hover,
.message-retry-button:focus-visible {
  color: var(--accent-ink);
  opacity: 1;
  text-decoration: underline;
  text-underline-offset: 2px;
}

.discussion-empty {
  margin: auto;
  color: var(--text-3);
}

.chat-revision-stack,
.chat-redact-confirm {
  display: grid;
  gap: 6px;
  padding: 8px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-2);
}

.emoji-button {
  min-width: 34px;
  justify-content: center;
}

.discussion-composer textarea {
  min-height: 72px;
  max-height: 180px;
  resize: vertical;
}

.discussion-status {
  min-height: 18px;
}

.discussion-detail-section {
  display: grid;
  gap: 10px;
  padding: 14px;
  border-bottom: 1px solid var(--border);
}

.discussion-detail-section:last-child {
  border-bottom: 0;
}

.contact-row {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 10px;
}

.participant-row {
  align-items: flex-start;
  padding: 8px;
  border: 1px solid transparent;
  border-radius: 8px;
}

.participant-row.self {
  border-color: color-mix(in srgb, var(--accent) 42%, var(--border));
  background: color-mix(in srgb, var(--accent-soft) 55%, transparent);
}

.participant-avatar {
  width: 30px;
  height: 30px;
  display: grid;
  place-items: center;
  border-radius: 8px;
  background: var(--surface-2);
  color: var(--text-2);
}

.participant-main {
  min-width: 0;
  display: grid;
  gap: 6px;
}

.participant-did {
  min-width: 0;
  overflow-wrap: anywhere;
}

.participant-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.participant-badge.self {
  background: var(--accent);
  color: #111827;
}

.participant-badge.admin {
  background: color-mix(in srgb, var(--warning) 22%, var(--surface-2));
  color: var(--text);
}

.participant-badge.member {
  background: var(--surface-2);
  color: var(--text-2);
}

.presence-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--text-3);
}

.presence-dot.online {
  background: var(--success);
}

.presence-dot.typing {
  background: var(--info);
}

.presence-dot.idle {
  background: var(--warning);
}

.discussion-detail-section .settings-row,
.detail-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
  padding: 0;
  border: 0;
  color: var(--text-2);
}

.detail-row strong {
  color: var(--text);
}

@media (max-width: 980px) {
  .discussion-shell,
  .discussion-shell.left-collapsed,
  .discussion-shell.right-collapsed,
  .discussion-shell.left-collapsed.right-collapsed {
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: auto minmax(0, 58vh) auto;
    height: auto;
    min-height: 0;
    overflow: visible;
  }

  .discussion-sidebar-panel,
  .discussion-main-panel,
  .discussion-composer {
    grid-column: 1;
    grid-row: auto;
  }

  .discussion-details-panel,
  .discussion-left-rail,
  .discussion-right-rail {
    display: none;
  }

  .discussion-message {
    max-width: 92%;
  }
}

.auth-shell {
  width: 100vw;
  min-height: 100vh;
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  place-items: center;
  padding: 24px;
  box-sizing: border-box;
  position: relative;
  isolation: isolate;
  background:
    radial-gradient(circle at 16% 18%, var(--page-glow-a), transparent 28%),
    radial-gradient(circle at 84% 12%, var(--page-glow-b), transparent 26%),
    radial-gradient(circle at 50% 0%, var(--page-glow-c), transparent 22%),
    linear-gradient(145deg, var(--bg), var(--bg-elev));
}

.auth-card {
  width: min(520px, 100%);
  max-width: none;
  margin: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  position: relative;
  overflow: hidden;
  background:
    radial-gradient(circle at top right, color-mix(in srgb, var(--accent-2) 14%, transparent), transparent 34%),
    radial-gradient(circle at bottom left, color-mix(in srgb, var(--accent) 12%, transparent), transparent 38%),
    linear-gradient(180deg, color-mix(in srgb, var(--surface) 98%, white), var(--surface));
  box-shadow: var(--shadow-lg);
  backdrop-filter: blur(18px);
}

.auth-panel {
  padding: 28px;
}

.auth-logo {
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  box-shadow: 0 14px 28px color-mix(in srgb, var(--accent) 28%, transparent);
}

.auth-brand h1 {
  color: var(--text);
  letter-spacing: -0.03em;
}

.auth-brand p,
.auth-status {
  color: var(--text-3);
}

.auth-form label {
  color: var(--text-2);
}

.auth-form {
  display: grid;
  gap: 10px;
}

.auth-form input,
.auth-form textarea,
.auth-form select {
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
  border: 1px solid var(--border-strong);
  border-radius: 10px;
  padding: 10px 12px;
  background: var(--surface);
  color: var(--text);
  transition: border-color 120ms ease, background-color 120ms ease;
}

.auth-form input:focus,
.auth-form textarea:focus,
.auth-form select:focus {
  outline: none;
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 4%, var(--surface));
  box-shadow: none;
}

.auth-form .actions {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}

.auth-mode-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}

.auth-mode-button {
  min-height: 58px;
  align-items: flex-start;
  justify-content: center;
}

.auth-mode-button.active {
  border-color: var(--accent);
  color: var(--accent);
  background: color-mix(in srgb, var(--accent) 9%, var(--surface));
}

.auth-result {
  display: grid;
  gap: 6px;
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--surface-2);
  overflow-wrap: anywhere;
}

.auth-result strong {
  font-size: 12px;
  color: var(--text-3);
}

.auth-checkline {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: var(--text-2);
}

.auth-checkline input {
  width: auto;
}

.shell.app {
  min-height: 0;
  height: 100vh;
  padding: 0;
  gap: 0;
  grid-template-columns: var(--sidebar-w) minmax(0, 1fr);
  color: var(--text);
  background: var(--bg);
}

.shell.app.rtl {
  direction: rtl;
  grid-template-columns: minmax(0, 1fr) var(--sidebar-w);
}

.shell.app.rtl .sidebar { grid-column: 2; }
.shell.app.rtl .workspace { grid-column: 1; }

.shell.app.sidebar-collapsed {
  grid-template-columns: var(--sidebar-collapsed-w) minmax(0, 1fr);
}

.shell.app.rtl.sidebar-collapsed {
  grid-template-columns: minmax(0, 1fr) var(--sidebar-collapsed-w);
}

.shell.app.sidebar-resizing {
  cursor: col-resize;
  user-select: none;
}

.mobile-shellbar,
.mobile-drawer {
  display: none;
}

.sidebar {
  --sidebar-item-size: 44px;
  --sidebar-item-gap: 6px;
  --sidebar-group-gap: 14px;
  --sidebar-icon-track: 20px;
  --sidebar-icon-size: 18px;
  background: var(--surface);
  color: var(--text);
  border-right: 1px solid var(--border);
  padding: 0;
  gap: 0;
  min-height: 0;
  overflow: auto;
  position: relative;
}

.sidebar-resize-handle {
  position: absolute;
  inset-block: 0;
  right: 0;
  z-index: 30;
  width: 10px;
  cursor: col-resize;
}

.sidebar-resize-handle:hover,
.shell.app.sidebar-resizing .sidebar-resize-handle {
  background: color-mix(in srgb, var(--accent) 24%, transparent);
}

.shell.rtl .sidebar-resize-handle {
  right: auto;
  left: 0;
}

.shell.app.sidebar-collapsed .sidebar-resize-handle {
  display: none;
}

.sidebar-resize-shield {
  position: fixed;
  inset: 0;
  z-index: 1000;
  cursor: col-resize;
  background: transparent;
}

.sidebar-header .brand::before,
.mobile-shellbar .brand::before {
  content: none !important;
  display: none !important;
}

.sidebar-header .brand {
  gap: 11px;
}

.sidebar-header .brand .logo {
  width: 34px;
  height: 34px;
  border-radius: 9px;
  font-size: 17px;
}

.sidebar-header .product-meta {
  min-width: 0;
}

.sidebar-header .product-name {
  color: var(--text);
  font-size: 16px;
  font-weight: 800;
  line-height: 1.1;
  letter-spacing: 0;
}

.sidebar-nav-group {
  display: grid;
  gap: var(--sidebar-item-gap);
  padding: 0 8px;
}

.sidebar-nav-group + .sidebar-nav-group {
  margin-top: var(--sidebar-group-gap);
}

.sidebar-nav-group-title {
  margin: 0 8px 2px;
  color: var(--nav-label);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
  display: flex;
  align-items: center;
}

.sidebar-nav-group-title .add {
  margin-left: auto;
  width: 16px;
  height: 16px;
  border-radius: 4px;
  display: grid;
  place-items: center;
  color: inherit;
}

.sidebar-nav-group-title .add:hover {
  background: var(--hover);
  color: var(--nav-text);
}

.sidebar-nav-item {
  width: 100%;
  min-height: 40px;
  border: 1px solid color-mix(in srgb, var(--nav-border) 74%, rgba(255, 255, 255, 0.06));
  border-radius: 12px;
  display: grid;
  grid-template-columns: var(--sidebar-icon-track) minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  color: var(--nav-text);
  background: var(--nav-soft);
  text-decoration: none;
  user-select: none;
}

.sidebar-nav-item:hover,
.sidebar-nav-item.is-active {
  border-color: color-mix(in srgb, var(--accent) 52%, var(--accent-2));
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--accent) 14%, transparent), color-mix(in srgb, var(--accent-2) 11%, transparent)),
    var(--nav-soft);
}

.sidebar-nav-item.is-active {
  color: var(--nav-text);
}

.sidebar-nav-item.is-dim {
  color: var(--nav-muted);
}

.sidebar-nav-item.is-cross-org {
  border-color: color-mix(in srgb, var(--warning) 42%, var(--accent-2));
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--accent) 12%, var(--surface)), color-mix(in srgb, var(--accent-2) 10%, var(--surface))),
    var(--nav-soft);
}
.sidebar-scope-toggle {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4px;
  padding: 0 8px 4px;
}
.scope-chip {
  min-height: 28px;
  border: 1px solid var(--nav-input-border);
  border-radius: 8px;
  background: var(--nav-input-bg);
  color: var(--nav-muted);
  font-size: 11px;
  font-weight: 700;
  cursor: pointer;
}
.scope-chip.active {
  border-color: color-mix(in srgb, var(--accent) 58%, var(--accent-2));
  background: color-mix(in srgb, var(--accent) 18%, transparent);
  color: var(--nav-text);
}
.space-tree-item {
  min-height: 36px;
}
.space-tree-item.is-scope-member:not(.is-active) {
  border-color: color-mix(in srgb, var(--accent) 30%, var(--nav-border));
  background: color-mix(in srgb, var(--accent) 8%, var(--nav-soft));
}

.sidebar-nav-item .grow {
  min-width: 0;
}

.sidebar-nav-item .badge,
.sidebar-nav-item .pill,
.sidebar-nav-item .kbd-tag {
  justify-self: end;
}

.sidebar-nav-icon,
.server-switch-button .server-switch-icon {
  width: var(--sidebar-icon-track);
  height: var(--sidebar-icon-track);
  display: inline-grid;
  place-items: center;
  color: var(--nav-muted);
}

.sidebar-nav-item:hover .sidebar-nav-icon,
.sidebar-nav-item.is-active .sidebar-nav-icon,
.server-switch-button:hover .server-switch-icon,
.server-switch-button[aria-expanded="true"] .server-switch-icon {
  color: var(--nav-text);
}

.sidebar-nav-icon .ui-icon,
.server-switch-button .server-switch-icon .ui-icon {
  width: var(--sidebar-icon-size);
  height: var(--sidebar-icon-size);
  vertical-align: 0;
}

.sidebar-collapse-toggle,
.panel-collapse-toggle,
.theme-toggle-button {
  flex: 0 0 auto;
}

.theme-toggle-button {
  min-width: 0;
}

.btn,
.primary,
.secondary {
  min-height: 32px;
}

.btn.sm {
  min-height: 32px;
  padding: 0 10px;
  font-size: 12px;
}

.btn.icon,
.btn.icon.sm {
  width: 32px;
  height: 32px;
  min-width: 32px;
  min-height: 32px;
  padding: 0;
}

.workspace-header {
  flex-wrap: nowrap;
  min-width: 0;
}

.workspace-header .actions {
  align-items: center;
  gap: 8px;
  flex-wrap: nowrap;
  flex-shrink: 0;
  min-width: 0;
}

.workspace-header .actions > * {
  flex-shrink: 0;
}

.workspace-header .actions > .search {
  flex: 0 1 auto;
  min-width: 140px;
}

.workspace-header > .sidebar-collapse-toggle {
  margin-inline-end: 4px;
  flex-shrink: 0;
}

.workspace-header .crumbs {
  flex: 1 1 0;
  min-width: 0;
  overflow: hidden;
}

.workspace-header .crumbs > * {
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.workspace-header .crumbs > .sep {
  flex-shrink: 0;
}

.workspace-header .actions .btn,
.workspace-header .actions .pill {
  height: 34px;
}

.topbar-create-button .topbar-new-space-label {
  display: inline;
}

.workspace-header .actions .btn {
  border-radius: 7px;
}

.workspace-header .actions .btn.icon {
  width: 34px;
  min-width: 34px;
}

.topbar-notifications-link {
  position: relative;
}

.topbar-notifications-link .ui-icon {
  width: 17px;
  height: 17px;
}

.topbar-notifications-badge {
  position: absolute;
  top: 4px;
  right: 4px;
  min-width: 8px;
  height: 8px;
  border-radius: 999px;
  border: 2px solid var(--surface);
  background: #2563eb;
  box-sizing: border-box;
  pointer-events: none;
}

.workspace-header .actions .pill {
  display: inline-flex;
  align-items: center;
}

.shell.app.sidebar-collapsed .sidebar {
  overflow-x: hidden;
}

.shell.app.sidebar-collapsed .sidebar-header {
  justify-content: center;
  padding-inline: 8px;
}

.shell.app.sidebar-collapsed .sidebar-header .brand {
  flex: 0 0 auto;
  width: var(--sidebar-item-size);
  height: var(--sidebar-item-size);
  justify-content: center;
}

.shell.app.sidebar-collapsed .sidebar-header .logo {
  width: 40px;
  height: 40px;
  border-radius: 12px;
}

.shell.app.sidebar-collapsed .sidebar-header .product-meta,
.shell.app.sidebar-collapsed .sidebar-context .grow,
.shell.app.sidebar-collapsed .sidebar-context .pill,
.shell.app.sidebar-collapsed .sidebar-context .mini,
.shell.app.sidebar-collapsed .cx-connect-section,
.shell.app.sidebar-collapsed .server-switch-title,
.shell.app.sidebar-collapsed .server-switch-state,
.shell.app.sidebar-collapsed .server-switch-menu,
.shell.app.sidebar-collapsed .sidebar-nav-group-title,
.shell.app.sidebar-collapsed .sidebar-nav-item .grow,
.shell.app.sidebar-collapsed .sidebar-nav-item .badge,
.shell.app.sidebar-collapsed .sidebar-nav-item .pill,
.shell.app.sidebar-collapsed .sidebar-nav-item .kbd-tag,
.shell.app.sidebar-collapsed .sidebar-status {
  display: none;
}

.shell.app.sidebar-collapsed .sidebar-context {
  margin-inline: 8px;
  padding: 6px;
}

.shell.app.sidebar-collapsed .server-switch {
  margin-inline: 0;
  padding: 0 10px;
  display: grid;
  justify-items: center;
}

.shell.app.sidebar-collapsed .server-switch-button,
.shell.app.sidebar-collapsed .sidebar-nav-item {
  width: var(--sidebar-item-size);
  height: var(--sidebar-item-size);
  min-height: var(--sidebar-item-size);
  grid-template-columns: 1fr;
  align-items: center;
  justify-items: center;
  padding: 0;
  gap: 0;
  margin-inline: auto;
}

.shell.app.sidebar-collapsed .server-switch-icon,
.shell.app.sidebar-collapsed .sidebar-nav-icon {
  width: var(--sidebar-icon-size);
  height: var(--sidebar-icon-size);
}

.shell.app.sidebar-collapsed .server-switch-icon .ui-icon,
.shell.app.sidebar-collapsed .sidebar-nav-icon .ui-icon {
  width: var(--sidebar-icon-size);
  height: var(--sidebar-icon-size);
}

.shell.app.sidebar-collapsed .sidebar-nav-group {
  padding: 0 10px;
  justify-items: center;
}

.cx-connect-section {
  padding-top: 0;
}

.server-switch {
  position: relative;
  margin-inline: 8px;
  margin-bottom: 12px;
}

.server-switch-button {
  width: 100%;
  border: 1px solid var(--nav-border);
  border-radius: 12px;
  display: grid;
  grid-template-columns: var(--sidebar-icon-track) minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
  padding: 12px 10px;
  color: var(--nav-text);
  background:
    radial-gradient(circle at top right, color-mix(in srgb, var(--accent) 18%, transparent), transparent 42%),
    var(--nav-soft);
  text-align: start;
  cursor: pointer;
}

.server-switch-button:hover,
.server-switch-button[aria-expanded="true"] {
  border-color: color-mix(in srgb, var(--accent) 52%, var(--accent-2));
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--accent) 14%, transparent), color-mix(in srgb, var(--accent-2) 10%, transparent)),
    var(--nav-soft);
}

.server-switch-button[aria-expanded="true"] {
  border-bottom-left-radius: 0;
  border-bottom-right-radius: 0;
  border-bottom-color: transparent;
}

.server-switch-button .server-switch-icon {
  display: inline-grid;
  place-items: center;
  color: var(--nav-muted);
}

.server-switch-state {
  display: inline-flex;
  align-items: center;
  color: var(--nav-muted);
}

.server-switch-title {
  display: grid;
  min-width: 0;
  gap: 0;
}

.server-switch-title .k {
  color: var(--nav-label);
  font-size: 10px;
  font-weight: 900;
  letter-spacing: 0.08em;
}

.server-switch-title .v,
.server-option-main {
  overflow: hidden;
  color: var(--nav-text);
  font-size: 14px;
  font-weight: 800;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.server-switch-title .id,
.server-option-meta {
  overflow: hidden;
  color: var(--nav-muted);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.server-switch-menu {
  display: grid;
  gap: 10px;
  margin-top: 0;
  padding: 10px;
  border: 1px solid color-mix(in srgb, var(--accent) 52%, var(--accent-2));
  border-top: 1px dashed color-mix(in srgb, var(--accent) 28%, var(--nav-border));
  border-radius: 0 0 12px 12px;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--accent) 6%, transparent), transparent 60%),
    var(--nav-soft);
  box-shadow: var(--shadow-md);
}

.server-option-list {
  display: grid;
  gap: 6px;
}

.server-option-text {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.server-option {
  width: 100%;
  border: 1px solid color-mix(in srgb, var(--nav-border) 60%, transparent);
  border-radius: 10px;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
  padding: 8px;
  color: var(--nav-text);
  background: var(--nav-soft);
  text-align: start;
  cursor: pointer;
}

.server-option:hover,
.server-option.active {
  border-color: color-mix(in srgb, var(--accent) 58%, var(--accent-2));
  background: color-mix(in srgb, var(--accent) 13%, var(--nav-soft));
}

.cx-connect-form {
  display: grid;
  gap: 8px;
  padding: 0 10px 10px;
}

.cx-connect-form .actions {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}

.cx-server-input,
.workspace-header .search input {
  width: 100%;
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--surface);
  color: var(--text);
  font: inherit;
}

.cx-server-input {
  padding: 7px 9px;
  font-size: 12px;
}

.cx-server-input:focus,
.server-connect input:focus {
  outline: none;
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 4%, var(--surface));
  box-shadow: none;
}

.primary,
.secondary {
  appearance: none;
  border: 1px solid var(--border-strong);
  border-radius: 6px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 6px 12px;
  color: var(--text);
  background: var(--surface);
  font-size: 13px;
  line-height: 1.5;
  text-decoration: none;
  cursor: pointer;
}

.primary {
  background: linear-gradient(135deg, var(--accent) 0%, var(--accent-2) 100%);
  border-color: transparent;
  color: var(--text-on-accent);
  box-shadow: 0 14px 28px color-mix(in srgb, var(--accent) 24%, transparent);
}

.secondary {
  background: var(--surface);
  color: var(--text);
}

.primary:hover {
  background: linear-gradient(135deg, var(--accent-strong) 0%, color-mix(in srgb, var(--accent-2) 92%, white) 100%);
}
.secondary:hover { background: var(--surface-2); }

.ui-icon {
  display: inline-block;
  flex: 0 0 auto;
  width: 16px;
  height: 16px;
  vertical-align: -2px;
}

.section-tools,
.icon-actions,
.toolbar-row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.section-tools {
  justify-content: flex-end;
}

.toolbar-row {
  justify-content: space-between;
  flex-wrap: wrap;
}

.help-tip {
  display: inline-grid;
  place-items: center;
  width: 18px;
  height: 18px;
  border: 1px solid var(--border-strong);
  border-radius: 50%;
  color: var(--text-3);
  font-size: 11px;
  font-weight: 800;
  line-height: 1;
  cursor: help;
  user-select: none;
}

.help-tip:hover,
.help-tip:focus-visible {
  color: var(--text);
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 8%, transparent);
  outline: none;
}

.segmented-control {
  display: inline-flex;
  min-width: 0;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--surface-2);
}

.segment {
  appearance: none;
  border: 0;
  border-right: 1px solid var(--border);
  padding: 5px 9px;
  min-width: 48px;
  background: transparent;
  color: var(--text-2);
  cursor: pointer;
  font: inherit;
  font-size: 12px;
}

.segment:last-child {
  border-right: 0;
}

.segment.active {
  background: var(--surface);
  color: var(--text);
  box-shadow: inset 0 -2px 0 var(--accent);
}

.quick-nav--icons {
  grid-template-columns: repeat(3, 32px);
  justify-content: start;
}

.quick-nav--icons .quick-nav__item {
  width: 32px;
  height: 32px;
  padding: 0;
}

.notification-toolbar .event-head {
  align-items: center;
}

.account-menu-wrap {
  position: relative;
  display: inline-flex;
}

.account-menu-button {
  position: relative;
}

.account-menu-button .dot-online {
  position: absolute;
  right: 4px;
  bottom: 4px;
  margin: 0;
  box-shadow: 0 0 0 2px var(--surface);
}

.account-menu {
  position: absolute;
  top: calc(100% + 8px);
  right: 0;
  z-index: 60;
  width: min(420px, 92vw);
  display: grid;
  gap: 10px;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
  color: var(--text);
  box-shadow: var(--shadow-lg);
}

.shell.rtl .account-menu {
  right: auto;
  left: 0;
}

.account-menu__head {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.account-menu__head .grow {
  display: grid;
  gap: 4px;
  min-width: 0;
}

.account-menu__head .who {
  display: block;
  font-weight: 700;
  overflow-wrap: anywhere;
}

.account-menu__head .handle {
  display: block;
  color: var(--text-3);
  font-size: 12px;
  overflow-wrap: anywhere;
}

.account-menu__rows {
  display: grid;
  gap: 6px;
}

.account-menu__row {
  display: grid;
  grid-template-columns: 92px minmax(0, 1fr);
  gap: 8px;
  align-items: baseline;
  font-size: 12px;
}

.account-menu__row strong {
  color: var(--text-3);
  font-size: 11px;
  letter-spacing: 0.06em;
}

.account-menu__row span {
  overflow-wrap: anywhere;
}

.account-menu__section {
  display: grid;
  gap: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--border);
}

.account-menu__section-head {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  color: var(--text-3);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.06em;
}

.account-menu__actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  padding-top: 8px;
  border-top: 1px solid var(--border);
}

.badge.green,
.badge-success {
  background: var(--success-soft);
  color: var(--success-ink);
}

.badge.blue {
  background: var(--info-soft);
  color: var(--info-ink);
}

.badge.amber,
.badge-warning {
  background: var(--warning-soft);
  color: var(--warning-ink);
}

.badge-error {
  background: var(--danger-soft);
  color: var(--danger-ink);
}

.status.sidebar-status {
  margin: 0 10px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 10px;
  color: var(--text-2);
  background: var(--surface-2);
}

.status.sidebar-status .space-title {
  color: var(--text);
  font-size: 12px;
}

.status.sidebar-status .actions {
  gap: 6px;
}

.main.workspace {
  padding: 0;
  display: flex;
  gap: 0;
  min-width: 0;
  min-height: 0;
}

.topbar.workspace-header {
  margin: 0;
  border-radius: 0;
  box-shadow: none;
  align-items: center;
  justify-content: flex-start;
}

.workspace-header .search {
  width: min(34vw, 330px);
  cursor: text;
}

.workspace-header .search input {
  border: 0;
  padding: 0;
  background: transparent;
  color: var(--text);
  outline: none;
  font-size: 12px;
}

.workspace-body > .timeline {
  overflow: visible;
  align-content: start;
  gap: 16px;
}

.event {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: none;
  padding: 14px 16px;
  color: var(--text);
}

.event.nested-card {
  padding: 10px 12px;
  background: var(--surface-2);
}

.event-head {
  color: var(--text-3);
  font-size: 11px;
  letter-spacing: 0.05em;
}

.space-title,
.title {
  color: var(--text);
}

.space-meta,
.muted {
  color: var(--text-2);
}

.sidebar .muted {
  color: var(--text-3);
}

.dashboard-two-col {
  display: grid;
  grid-template-columns: minmax(0, 1.4fr) minmax(320px, 1fr);
  gap: 16px;
}

.home-card-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.space-button.home-space-card {
  background: var(--surface);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px;
  display: block;
}

.space-button.home-space-card.active {
  background: var(--accent-soft);
  border-color: transparent;
  color: var(--accent-ink);
}

.m-list-item .grow {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.m-list-item .title,
.m-list-item .sub {
  display: block;
}

.error-banner {
  border-color: rgba(185, 28, 28, 0.2);
  background: var(--danger-soft);
  color: var(--danger-ink);
}

.panel-toggle-row {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
}

.panel-toggle-label {
  color: var(--text-3);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.07em;
}

.shell.app {
  background:
    radial-gradient(circle at 12% 0%, var(--page-glow-a), transparent 24%),
    radial-gradient(circle at 88% 10%, var(--page-glow-b), transparent 24%),
    linear-gradient(135deg, var(--bg) 0%, var(--bg-elev) 62%, color-mix(in srgb, var(--bg-elev) 92%, var(--accent-2) 8%) 100%);
}

.shell.app.theme-light,
.shell.app.theme-night {
  color-scheme: light dark;
}

.sidebar {
  background: linear-gradient(180deg, var(--nav-bg), var(--nav-bg-2));
  color: var(--nav-text);
  border-right: 1px solid var(--nav-border);
}

.brand::before,
.avatar.bot,
.avatar.agent {
  background: linear-gradient(135deg, var(--accent) 0%, var(--accent-2) 100%);
  color: var(--text-on-accent);
}

.brand::before {
  box-shadow: 0 14px 30px color-mix(in srgb, var(--accent) 28%, transparent);
}

.brand-subtitle,
.context-label,
.sidebar-nav-group-title {
  color: var(--nav-label);
}

.context-title,
.sidebar-nav-item {
  color: var(--nav-text);
}

.context-meta,
.sidebar .space-meta,
.sidebar .muted,
.mobile-status .muted {
  color: var(--nav-muted);
}

.sidebar-context {
  border-color: var(--nav-border);
  background:
    radial-gradient(circle at top right, color-mix(in srgb, var(--accent) 22%, transparent), transparent 42%),
    var(--nav-soft);
}

.status,
.space-button,
.sidebar-nav-item {
  border-color: color-mix(in srgb, var(--nav-border) 74%, rgba(255, 255, 255, 0.06));
}

.space-button,
.sidebar-nav-item {
  color: var(--nav-text);
  background: var(--nav-soft);
}

.server-connect input {
  border-color: var(--nav-input-border);
  background: var(--nav-input-bg);
  color: var(--nav-text);
}

.space-button.active,
.sidebar-nav-item:hover,
.sidebar-nav-item.is-active {
  border-color: color-mix(in srgb, var(--accent) 52%, var(--accent-2));
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--accent) 14%, transparent), color-mix(in srgb, var(--accent-2) 11%, transparent)),
    var(--nav-soft);
}

.sidebar-nav-item.is-cross-org,
.home-space-card.cross-org {
  border-color: color-mix(in srgb, var(--warning) 42%, var(--accent-2));
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--accent) 12%, var(--surface)), color-mix(in srgb, var(--accent-2) 10%, var(--surface))),
    var(--nav-soft);
}

.topbar {
  border-color: color-mix(in srgb, var(--border) 86%, var(--accent) 14%);
  background: color-mix(in srgb, var(--surface) 94%, white);
}

.home-hero,
.directory-axis-card,
.settings-header-card {
  background:
    radial-gradient(circle at 12% 0%, color-mix(in srgb, var(--accent) 18%, transparent), transparent 34%),
    radial-gradient(circle at 90% 10%, color-mix(in srgb, var(--accent-2) 12%, transparent), transparent 30%),
    var(--surface);
}

.home-space-card {
  background: linear-gradient(180deg, color-mix(in srgb, var(--surface) 98%, white), color-mix(in srgb, var(--surface-2) 92%, var(--accent) 8%));
}

.nested-card,
.settings-page-chip {
  background: color-mix(in srgb, var(--surface-2) 92%, white);
}

.badge-info,
.badge.blue {
  background: var(--info-soft);
  color: var(--info-ink);
}

.badge.amber,
.badge-warning {
  background: var(--warning-soft);
  color: var(--warning-ink);
}

.badge.red,
.badge-error {
  background: var(--danger-soft);
  color: var(--danger-ink);
}

.badge.green,
.badge-success {
  background: var(--success-soft);
  color: var(--success-ink);
}

.tab.active {
  border-color: color-mix(in srgb, var(--accent) 70%, var(--accent-2));
  background: linear-gradient(135deg, var(--accent) 0%, var(--accent-2) 100%);
  color: var(--text-on-accent);
}

@media (prefers-color-scheme: dark) {
  .auth-shell.theme-system,
  .shell.theme-system {
    --bg: #101722;
    --bg-elev: #223041;
    --surface: rgba(27, 36, 48, 0.94);
    --surface-2: #202b39;
    --surface-3: #283546;
    --surface-inv: #fffaf6;
    --hover: rgba(255, 255, 255, 0.04);
    --hover-strong: rgba(255, 255, 255, 0.08);
    --border: #3a4454;
    --border-strong: #4b586b;
    --border-faint: #202938;
    --text: #f8f2ee;
    --text-2: #cbbab1;
    --text-3: #a89389;
    --text-on-accent: #2c170b;
    --text-inv: #1c1e25;
    --accent: #f59e0b;
    --accent-strong: #f7ae3a;
    --accent-soft: rgba(245, 158, 11, 0.12);
    --accent-2: #fb7185;
    --accent-ink: #fde7ba;
    --success: #7bc9b5;
    --success-soft: rgba(123, 201, 181, 0.16);
    --success-ink: #d7f5ec;
    --warning: #f0be78;
    --warning-soft: rgba(240, 190, 120, 0.16);
    --warning-ink: #fae7c2;
    --danger: #ff7a59;
    --danger-soft: rgba(255, 122, 89, 0.16);
    --danger-ink: #ffd6cd;
    --info: #a7b7ff;
    --info-soft: rgba(167, 183, 255, 0.16);
    --info-ink: #dce4ff;
    --neutral-soft: #1f2a38;
    --proto-bg: #0f1218;
    --proto-fg: #f1e8e2;
    --proto-meta: #b7a49c;
    --proto-accent: #f2c98b;
    --shadow-xs: 0 1px 1px rgba(4, 8, 14, 0.38);
    --shadow-sm: 0 1px 2px rgba(4, 8, 14, 0.42);
    --shadow-md: 0 10px 24px rgba(4, 8, 14, 0.32), 0 1px 2px rgba(4, 8, 14, 0.40);
    --shadow-lg: 0 28px 64px rgba(4, 8, 14, 0.42);
    --ring: 0 0 0 3px rgba(245, 158, 11, 0.26);
    --page-glow-a: rgba(245, 158, 11, 0.14);
    --page-glow-b: rgba(251, 113, 133, 0.12);
    --page-glow-c: rgba(123, 201, 181, 0.08);
    --nav-bg: #111827;
    --nav-bg-2: #1a2230;
    --nav-soft: rgba(255, 255, 255, 0.04);
    --nav-border: rgba(245, 158, 11, 0.18);
    --nav-text: #f8f2ee;
    --nav-muted: #cbbab1;
    --nav-label: #a89389;
    --nav-input-bg: rgba(8, 12, 20, 0.56);
    --nav-input-border: rgba(168, 147, 137, 0.18);
    color-scheme: dark;
  }
}

@media (max-width: 1200px) {
  .workspace-header .crumbs .crumb-tag,
  .workspace-header .crumbs .id.muted.mono {
    display: none;
  }

  .workspace-header .search {
    width: min(26vw, 240px);
  }

  .topbar-create-button .topbar-new-space-label {
    display: none;
  }

  .topbar-create-button {
    padding-inline: 10px;
  }
}

@media (max-width: 860px) {
  .auth-shell {
    padding: 16px;
    align-items: start;
  }

  .auth-card {
    width: 100%;
  }

  .auth-panel {
    padding: 22px;
  }

  .auth-mode-grid,
  .auth-form .actions {
    grid-template-columns: 1fr;
  }

  .shell.app {
    grid-template-columns: 1fr;
    height: 100vh;
  }

  .mobile-shellbar {
    height: var(--topbar-h);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 0 12px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }

  .mobile-shellbar .brand {
    font-size: 14px;
    font-weight: 700;
  }

  .mobile-drawer {
    position: fixed;
    inset: var(--topbar-h) 0 auto 0;
    z-index: 50;
    display: none;
    flex-direction: column;
    gap: 8px;
    padding: 12px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    box-shadow: var(--shadow-md);
  }

  .mobile-drawer.open {
    display: flex;
  }

  .sidebar {
    display: none;
  }

  .main.workspace {
    height: calc(100vh - var(--topbar-h));
  }

  .workspace-header .search,
  .workspace-header .crumbs .id {
    display: none;
  }

  .workspace-header .actions {
    gap: 4px;
  }

  .workspace-body {
    padding: 14px 12px 40px;
  }

  .dashboard-two-col {
    grid-template-columns: 1fr;
  }
}

/* ─────────────────────────────────────────────────────────────────────
   Agent Workspace (cx.profile.agent_workspace.v1)
   See views/agent_workspace.rs.
   ───────────────────────────────────────────────────────────────────── */

.agent-workspace-dashboard {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding: 16px;
  max-width: 1100px;
  margin: 0 auto;
}

.agent-workspace-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.agent-workspace-header h1 {
  margin: 0;
  font-size: 1.5rem;
}

.agent-workspace-header-actions {
  display: flex;
  gap: 8px;
}

.agent-workspace-pending.sticky {
  position: sticky;
  top: 0;
  z-index: 5;
  background: var(--surface, #fff);
  border: 2px solid #ff8b3d;
  border-radius: 10px;
  padding: 14px 16px;
  box-shadow: 0 2px 8px rgba(255, 139, 61, 0.15);
}

.agent-workspace-section-title {
  margin: 0 0 8px 0;
  font-size: 1.05rem;
  font-weight: 600;
}

.agent-workspace-section-title.pending {
  color: #b3580f;
}

.agent-workspace-section-subtitle {
  margin: 0 0 12px 0;
  font-size: 0.875rem;
  color: var(--text-muted, #666);
}

.agent-workspace-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 12px;
}

.agent-task-card {
  border: 1px solid var(--border, #d9dee5);
  border-radius: 10px;
  padding: 12px 14px;
  background: var(--surface, #fff);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.agent-task-card.emphasis-pending {
  border-color: #ff8b3d;
  background: #fff8f1;
}

.agent-task-card.emphasis-muted {
  opacity: 0.7;
}

.agent-task-card-header {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
  font-size: 0.85rem;
  color: var(--text-muted, #666);
}

.agent-task-card-source {
  font-weight: 600;
  color: var(--text, #1a1a1a);
}

.agent-task-card-instruction {
  font-size: 0.95rem;
  line-height: 1.4;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.agent-task-card-banner {
  background: #fff3e0;
  border-left: 3px solid #ff8b3d;
  padding: 6px 10px;
  font-size: 0.85rem;
  color: #b3580f;
  border-radius: 4px;
}

.agent-task-card-actions {
  display: flex;
  gap: 8px;
  margin-top: 4px;
  flex-wrap: wrap;
}

.fsm-chip-row {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.fsm-chip {
  display: inline-flex;
  flex-direction: column;
  align-items: flex-start;
  padding: 4px 8px;
  border-radius: 999px;
  font-size: 0.75rem;
  line-height: 1.2;
  border: 1px solid currentColor;
  background: var(--surface, #fff);
}

.fsm-chip-kind {
  font-size: 0.65rem;
  text-transform: uppercase;
  opacity: 0.75;
  letter-spacing: 0.05em;
}

.fsm-chip-label {
  font-weight: 600;
}

.fsm-chip-green {
  color: #1f7a3a;
  background: #e8f5ec;
}

.fsm-chip-orange {
  color: #b3580f;
  background: #fff3e0;
  border-color: #ff8b3d;
}

.fsm-chip-blue {
  color: #1b4f8f;
  background: #e8f0fb;
}

.fsm-chip-grey {
  color: #555;
  background: #eee;
}

.agent-workspace-empty {
  border: 1px dashed var(--border, #d9dee5);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
  color: var(--text-muted, #666);
}

.agent-workspace-empty-hint {
  font-size: 0.85rem;
  margin-top: 8px;
}

.agent-workspace-agent-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.agent-workspace-agent-row {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 8px;
  align-items: center;
  padding: 6px 8px;
  border-radius: 6px;
  background: var(--surface-subtle, #f8f9fb);
}

.agent-workspace-agent-dot {
  color: #1f7a3a;
}

.agent-workspace-agent-name {
  font-weight: 600;
}

.agent-workspace-agent-consulting-pill {
  display: inline-block;
  font-size: 0.7rem;
  padding: 1px 6px;
  border-radius: 999px;
  background: #e8f0fb;
  color: #1b4f8f;
  margin-right: 6px;
}

/* Task detail */

.agent-task-detail {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 16px;
  max-width: 900px;
  margin: 0 auto;
}

.agent-task-detail-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.agent-task-detail-banner {
  background: #fff3e0;
  border: 1px solid #ff8b3d;
  border-radius: 8px;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.agent-task-detail-banner-actions {
  display: flex;
  gap: 8px;
}

.agent-task-detail-anchor {
  font-size: 0.85rem;
  color: var(--text-muted, #666);
}

.agent-task-detail-section {
  border: 1px solid var(--border, #d9dee5);
  border-radius: 8px;
  padding: 12px 14px;
}

.agent-task-detail-section h2 {
  margin: 0 0 8px 0;
  font-size: 1rem;
}

.agent-task-detail-instruction,
.agent-task-detail-draft {
  background: var(--surface-subtle, #f8f9fb);
  border-radius: 6px;
  padding: 10px;
  white-space: pre-wrap;
  font-family: var(--font-mono, monospace);
  font-size: 0.85rem;
  line-height: 1.4;
}

.agent-task-detail-draft-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 10px;
}

.agent-task-detail-conversation {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
  max-height: 280px;
  overflow-y: auto;
}

.agent-task-detail-conversation-line {
  font-size: 0.9rem;
  padding: 4px 6px;
}

.agent-task-detail-conversation-line .speaker {
  font-weight: 600;
}

.agent-task-detail-conversation-line .ts {
  font-size: 0.75rem;
  color: var(--text-muted, #666);
  margin-left: 8px;
}

.agent-task-detail-conversation-compose {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px;
  margin-top: 8px;
}

.agent-task-detail-audit {
  list-style: none;
  padding: 0;
  margin: 0;
  font-family: var(--font-mono, monospace);
  font-size: 0.75rem;
  color: var(--text-muted, #666);
}

/* Private routing indicator in compose (chat / discussion). */

.private-compose-mode {
  border: 2px solid #6d3eaf;
  background: #f7f1ff;
  border-radius: 8px;
  padding: 8px;
}

.private-compose-mode .private-routing-banner {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.85rem;
  color: #4b2784;
  background: #ede2ff;
  padding: 6px 10px;
  border-radius: 6px;
  margin-bottom: 6px;
}

.private-compose-mode .private-routing-banner::before {
  content: "🔒";
}

.private-compose-summary-warning {
  font-size: 0.8rem;
  color: #b3580f;
  margin-top: 4px;
}

/* Mobile: stack the dashboard, scroll FSM chips horizontally. */
@media (max-width: 768px) {
  .agent-workspace-cards {
    grid-template-columns: 1fr;
  }
  .fsm-chip-row {
    overflow-x: auto;
    flex-wrap: nowrap;
    padding-bottom: 4px;
  }
}

/* Dark mode tweaks. */
@media (prefers-color-scheme: dark) {
  .agent-task-card { background: #1f2229; }
  .agent-task-card-banner { background: #3a2410; color: #ffb787; }
  .agent-workspace-pending.sticky { background: #1f2229; }
  .agent-task-detail-banner { background: #3a2410; }
  .agent-task-detail-instruction, .agent-task-detail-draft { background: #15171c; }
  .agent-workspace-agent-row { background: #1a1d22; }
  .fsm-chip-green { background: #0e2a18; color: #74d68f; }
  .fsm-chip-orange { background: #3a2410; color: #ffb787; }
  .fsm-chip-blue { background: #15243a; color: #92baf7; }
  .fsm-chip-grey { background: #2a2c30; color: #bbb; }
  .private-compose-mode { background: #251a3a; border-color: #9a76d8; }
  .private-compose-mode .private-routing-banner { background: #2f2152; color: #cdb6f6; }
}

/* ─────────────────────────────────────────────────────────────────────
   Publish-to-source + Add-agent modals + Settings page
   (AW-3.4 + AW-3.7 + AW-3.8 + AW-3.12)
   ───────────────────────────────────────────────────────────────────── */

.publish-to-source-modal-backdrop,
.add-agent-modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.publish-to-source-modal,
.add-agent-modal {
  background: var(--surface, #fff);
  border-radius: 12px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
  width: min(560px, 90vw);
  max-height: 85vh;
  display: flex;
  flex-direction: column;
}

.publish-to-source-modal-header,
.add-agent-modal-header {
  padding: 16px 20px 8px;
  border-bottom: 1px solid var(--border, #d9dee5);
}

.publish-to-source-modal-header h2,
.add-agent-modal-header h2 {
  margin: 0;
  font-size: 1.1rem;
}

.publish-to-source-modal-body,
.add-agent-modal-body {
  padding: 16px 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  overflow-y: auto;
}

.publish-to-source-modal-body fieldset,
.add-agent-modal-body fieldset {
  border: 1px solid var(--border, #d9dee5);
  border-radius: 8px;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.publish-to-source-modal-body legend,
.add-agent-modal-body legend {
  font-size: 0.85rem;
  font-weight: 600;
  padding: 0 6px;
}

.publish-to-source-modal-body label,
.add-agent-modal-body label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.95rem;
  cursor: pointer;
}

.publish-to-source-modal-preview {
  background: var(--surface-subtle, #f8f9fb);
  border-radius: 6px;
  padding: 10px;
  white-space: pre-wrap;
  font-family: var(--font-mono, monospace);
  font-size: 0.85rem;
  max-height: 200px;
  overflow-y: auto;
}

.publish-to-source-modal-disabled-note,
.add-agent-modal-empty {
  color: #b3580f;
  background: #fff3e0;
  border-radius: 6px;
  padding: 8px 10px;
  font-size: 0.85rem;
}

.publish-to-source-modal-footer,
.add-agent-modal-footer {
  padding: 12px 20px;
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  border-top: 1px solid var(--border, #d9dee5);
}

.add-agent-modal-disclosure {
  font-size: 0.8rem;
  color: var(--text-muted, #666);
  background: var(--surface-subtle, #f8f9fb);
  border-radius: 6px;
  padding: 8px 10px;
  margin: 0;
}

/* Settings page */

.agent-workspace-settings {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding: 16px;
  max-width: 800px;
  margin: 0 auto;
}

.agent-workspace-settings-header h1 {
  margin: 0;
  font-size: 1.4rem;
}

.agent-workspace-settings-section {
  border: 1px solid var(--border, #d9dee5);
  border-radius: 10px;
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.agent-workspace-settings-section h2 {
  margin: 0;
  font-size: 1rem;
}

.agent-workspace-settings-hint {
  font-size: 0.85rem;
  color: var(--text-muted, #666);
  margin: 0;
}

.agent-workspace-settings-section.danger-zone {
  border-color: #ef4444;
  background: #fff5f5;
}

.agent-workspace-settings-section.danger-zone summary {
  cursor: pointer;
}

.agent-workspace-settings-section.danger-zone button.danger {
  background: #ef4444;
  color: #fff;
  border: none;
  padding: 8px 14px;
  border-radius: 6px;
  cursor: pointer;
  align-self: flex-start;
}

/* Notification row */

.notification-row-agent-membership {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  text-decoration: none;
  color: inherit;
  border-radius: 6px;
}

.notification-row-agent-membership:hover {
  background: var(--surface-subtle, #f8f9fb);
}

.notification-row-agent-membership .notification-icon {
  font-size: 1.2rem;
}

.notification-row-agent-membership .notification-body {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.notification-row-agent-membership .notification-detail {
  font-size: 0.8rem;
  color: var(--text-muted, #666);
}

@media (prefers-color-scheme: dark) {
  .publish-to-source-modal,
  .add-agent-modal { background: #1f2229; }
  .publish-to-source-modal-preview,
  .add-agent-modal-disclosure { background: #15171c; }
  .agent-workspace-settings-section.danger-zone { background: #2a1818; border-color: #d44; }
  .publish-to-source-modal-disabled-note,
  .add-agent-modal-empty { background: #3a2410; color: #ffb787; }
  .notification-row-agent-membership:hover { background: #1a1d22; }
}
"#;

/// One-shot push-token provider bootstrap.
///
/// Runs once on first App render. On wasm32 we install
/// `WebPushTokenProvider::new()` (drives the service-worker +
/// `pushManager.subscribe` path described in `push.rs::WebPushTokenProvider`).
/// On native builds we install `FcmPushTokenProvider` / `ApnsPushTokenProvider`
/// stubs so `push_token_provider()` is `Some(_)` and the device-summary
/// `"no PushTokenProvider installed"` warning goes away. Subsequent
/// renders short-circuit via `OnceLock` semantics inside
/// `set_push_token_provider`.
fn ensure_default_push_token_provider() {
    if crate::push::push_token_provider().is_some() {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::WebPushTokenProvider::new(),
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "android"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::ApnsPushTokenProvider,
        ));
    }
    #[cfg(all(
        not(target_arch = "wasm32"),
        not(target_os = "android"),
        not(target_os = "ios")
    ))]
    {
        // Desktop / server builds: install the FCM provider as the
        // safe default. The default `FcmPushTokenProvider` stub returns
        // `Ok(None)` from `subscribe()`, which is the "no push token
        // available on this platform" signal `device-summary` reads —
        // not a misconfiguration. The point is to install *something*
        // so `push_token_provider().is_some()`.
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
}

#[component]
pub fn App() -> Element {
    ensure_default_push_token_provider();
    rsx! {
        Router::<Route> {}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpaceScopeMode {
    Exact,
    IncludeDescendants,
}

impl SpaceScopeMode {
    fn includes_descendants(self) -> bool {
        matches!(self, Self::IncludeDescendants)
    }

    fn label(self) -> &'static str {
        match self {
            Self::Exact => "Current Space only",
            Self::IncludeDescendants => "Current + descendants",
        }
    }

    fn preference_value(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::IncludeDescendants => "descendants",
        }
    }

    fn from_preference(value: &str) -> Self {
        match value {
            "descendants" => Self::IncludeDescendants,
            _ => Self::Exact,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SpaceTreeItem {
    space: SpacePreview,
    depth: usize,
    descendant_count: usize,
}

fn non_empty_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| non_empty_string(value.get(*key)))
}

fn string_array_field(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .flat_map(|field| {
            field
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn extract_parent_space_id(space_id: &str, body: &Value) -> Option<String> {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    for container in [
        summary,
        body,
        body.get("hierarchy").unwrap_or(&Value::Null),
        body.get("relationships").unwrap_or(&Value::Null),
    ] {
        if let Some(parent) = string_field(
            container,
            &[
                "parent_space_id",
                "parent_id",
                "parent",
                "space_parent_id",
                "root_space_id",
            ],
        )
        .filter(|parent| parent != space_id)
        {
            return Some(parent);
        }
    }

    body.get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|event| {
            let kind = event
                .get("kind")
                .or_else(|| event.get("type"))
                .and_then(Value::as_str)?;
            if kind != "cx.space.parent" {
                return None;
            }
            for container in [
                event.get("payload").unwrap_or(&Value::Null),
                event.get("content").unwrap_or(&Value::Null),
                event,
            ] {
                if let Some(parent) = string_field(
                    container,
                    &["parent_space_id", "parent_id", "parent", "target_parent_id"],
                )
                .filter(|parent| parent != space_id)
                {
                    return Some(parent);
                }
            }
            None
        })
}

fn extract_child_space_ids(space_id: &str, body: &Value) -> Vec<String> {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    let mut children = Vec::new();
    for container in [
        summary,
        body,
        body.get("hierarchy").unwrap_or(&Value::Null),
        body.get("relationships").unwrap_or(&Value::Null),
    ] {
        children.extend(string_array_field(
            container,
            &[
                "child_space_ids",
                "children",
                "child_ids",
                "space_child_ids",
            ],
        ));
    }

    for event in body
        .get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str);
        if kind != Some("cx.space.child") {
            continue;
        }
        for container in [
            event.get("payload").unwrap_or(&Value::Null),
            event.get("content").unwrap_or(&Value::Null),
            event,
        ] {
            if let Some(child) = string_field(
                container,
                &["child_space_id", "child_id", "child", "space_id"],
            ) {
                children.push(child);
            }
        }
    }

    children
        .into_iter()
        .filter(|child| child != space_id)
        .collect()
}

fn normalize_space_hierarchy(spaces: &mut [SpacePreview]) {
    let known: BTreeSet<String> = spaces.iter().map(|space| space.space_id.clone()).collect();
    let mut child_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for space in spaces.iter() {
        if let Some(parent) = space
            .parent_space_id
            .as_ref()
            .filter(|parent| known.contains(*parent) && *parent != &space.space_id)
        {
            child_map
                .entry(parent.clone())
                .or_default()
                .insert(space.space_id.clone());
        }

        for child in space
            .child_space_ids
            .iter()
            .filter(|child| known.contains(*child) && *child != &space.space_id)
        {
            child_map
                .entry(space.space_id.clone())
                .or_default()
                .insert(child.clone());
        }
    }

    for space in spaces.iter_mut() {
        space.child_space_ids = child_map
            .remove(&space.space_id)
            .map(|children| children.into_iter().collect())
            .unwrap_or_default();
    }
}

fn descendant_space_ids(spaces: &[SpacePreview], root_space_id: &str) -> Vec<String> {
    if root_space_id.trim().is_empty() {
        return Vec::new();
    }

    let known: BTreeSet<&str> = spaces.iter().map(|space| space.space_id.as_str()).collect();
    let mut child_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for space in spaces {
        if let Some(parent) = space
            .parent_space_id
            .as_deref()
            .filter(|parent| known.contains(*parent) && *parent != space.space_id.as_str())
        {
            child_map
                .entry(parent)
                .or_default()
                .push(space.space_id.as_str());
        }
        for child in space
            .child_space_ids
            .iter()
            .map(String::as_str)
            .filter(|child| known.contains(*child) && *child != space.space_id.as_str())
        {
            child_map
                .entry(space.space_id.as_str())
                .or_default()
                .push(child);
        }
    }
    for children in child_map.values_mut() {
        children.sort_unstable();
        children.dedup();
    }
    let mut result = Vec::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![root_space_id];
    while let Some(space_id) = stack.pop() {
        if !visited.insert(space_id.to_owned()) {
            continue;
        }
        result.push(space_id.to_owned());
        if let Some(children) = child_map.get(space_id) {
            for child in children.iter().rev() {
                stack.push(child);
            }
        }
    }
    result
}

fn scoped_space_ids(
    spaces: &[SpacePreview],
    root_space_id: &str,
    scope_mode: SpaceScopeMode,
) -> Vec<String> {
    if root_space_id.trim().is_empty() {
        Vec::new()
    } else if scope_mode.includes_descendants() {
        descendant_space_ids(spaces, root_space_id)
    } else {
        vec![root_space_id.to_owned()]
    }
}

fn space_tree_items(spaces: &[SpacePreview]) -> Vec<SpaceTreeItem> {
    let order: BTreeMap<&str, usize> = spaces
        .iter()
        .enumerate()
        .map(|(idx, space)| (space.space_id.as_str(), idx))
        .collect();
    let known: BTreeSet<&str> = spaces.iter().map(|space| space.space_id.as_str()).collect();
    let by_id: BTreeMap<&str, &SpacePreview> = spaces
        .iter()
        .map(|space| (space.space_id.as_str(), space))
        .collect();
    let mut child_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for space in spaces {
        if let Some(parent) = space
            .parent_space_id
            .as_deref()
            .filter(|parent| known.contains(*parent) && *parent != space.space_id.as_str())
        {
            child_map
                .entry(parent)
                .or_default()
                .push(space.space_id.as_str());
        }
        for child in space
            .child_space_ids
            .iter()
            .map(String::as_str)
            .filter(|child| known.contains(*child) && *child != space.space_id.as_str())
        {
            child_map
                .entry(space.space_id.as_str())
                .or_default()
                .push(child);
        }
    }
    for children in child_map.values_mut() {
        children.sort_by_key(|child| order.get(child).copied().unwrap_or(usize::MAX));
        children.dedup();
    }
    let mut roots: Vec<&str> = spaces
        .iter()
        .filter(|space| {
            space
                .parent_space_id
                .as_deref()
                .map(|parent| !known.contains(parent))
                .unwrap_or(true)
        })
        .map(|space| space.space_id.as_str())
        .collect();
    roots.sort_by_key(|id| order.get(id).copied().unwrap_or(usize::MAX));

    fn push_item<'a>(
        id: &'a str,
        depth: usize,
        by_id: &BTreeMap<&'a str, &'a SpacePreview>,
        child_map: &BTreeMap<&'a str, Vec<&'a str>>,
        order: &BTreeMap<&'a str, usize>,
        visited: &mut BTreeSet<String>,
        items: &mut Vec<SpaceTreeItem>,
    ) {
        if !visited.insert(id.to_owned()) {
            return;
        }
        let Some(space) = by_id.get(id).copied() else {
            return;
        };
        items.push(SpaceTreeItem {
            space: space.clone(),
            depth,
            descendant_count: descendant_space_ids(
                &by_id.values().copied().cloned().collect::<Vec<_>>(),
                id,
            )
            .len()
            .saturating_sub(1),
        });
        let mut children: Vec<&str> = child_map.get(id).cloned().unwrap_or_default();
        children.sort_by_key(|child| order.get(child).copied().unwrap_or(usize::MAX));
        for child in children {
            push_item(child, depth + 1, by_id, child_map, order, visited, items);
        }
    }

    let mut items = Vec::new();
    let mut visited = BTreeSet::new();
    for root in roots {
        push_item(
            root,
            0,
            &by_id,
            &child_map,
            &order,
            &mut visited,
            &mut items,
        );
    }
    for space in spaces {
        if !visited.contains(&space.space_id) {
            push_item(
                &space.space_id,
                0,
                &by_id,
                &child_map,
                &order,
                &mut visited,
                &mut items,
            );
        }
    }
    items
}

#[component]
pub fn RouterView() -> Element {
    let initial_config = LocalConfigStore::default().load();
    let initial_state_store = LocalStateStore::default();
    let initial_local_state = initial_state_store.load();
    let initial_spaces = space_previews_from_sync_spaces(&initial_local_state.space_projections);
    let initial_agent_workspace =
        agent_workspace_projection_from_sync_spaces(&initial_local_state.space_projections);
    let initial_sidebar_width = load_sidebar_width_preference(&initial_state_store);
    let initial_space_scope_mode = load_space_scope_preference(&initial_state_store);
    let initial_locale = initial_state_store
        .load_private_data(&initial_config.account_did, "locale")
        .map(|code| Locale::from_code(&code))
        .unwrap_or_default();
    let initial_theme = initial_state_store
        .load_private_data(&initial_config.account_did, "theme")
        .filter(|theme| matches!(theme.as_str(), "light" | "night" | "system"))
        .unwrap_or_else(|| "system".to_owned());
    let config_store = use_signal(LocalConfigStore::default);
    let mut state_store = use_signal(LocalStateStore::default);
    let base_url = use_signal({
        let initial_config = initial_config.clone();
        move || initial_config.server_url
    });
    let mut account_did = use_signal({
        let initial_config = initial_config.clone();
        move || initial_config.account_did
    });
    let device_id = use_signal({
        let initial_config = initial_config.clone();
        move || initial_config.device_id
    });
    let mut token = use_signal(move || initial_config.session_token);
    let navigator = use_navigator();
    let route = use_route::<Route>();
    let mut view = use_signal(|| route.to_view());
    let mut status = use_signal(|| ConnectionState::Offline.label().to_owned());
    let mut sync_cursor = use_signal({
        let initial_local_state = initial_local_state.clone();
        move || {
            initial_local_state
                .sync_cursor
                .clone()
                .unwrap_or_else(|| "-".to_owned())
        }
    });
    let mut selected_space = use_signal({
        let initial_spaces = initial_spaces.clone();
        move || {
            initial_spaces
                .first()
                .map(|space| space.space_id.clone())
                .unwrap_or_default()
        }
    });
    let mut spaces = use_signal({
        let initial_spaces = initial_spaces.clone();
        move || initial_spaces.clone()
    });
    let mut timeline = use_signal(Vec::<TimelineEvent>::new);
    let agent_workspace_pending = use_signal({
        let initial_agent_workspace = initial_agent_workspace.clone();
        move || initial_agent_workspace.pending.clone()
    });
    let agent_workspace_in_flight = use_signal({
        let initial_agent_workspace = initial_agent_workspace.clone();
        move || initial_agent_workspace.in_flight.clone()
    });
    let agent_workspace_recent = use_signal({
        let initial_agent_workspace = initial_agent_workspace.clone();
        move || initial_agent_workspace.recent.clone()
    });
    let agent_workspace_agents = use_signal({
        let initial_agent_workspace = initial_agent_workspace.clone();
        move || initial_agent_workspace.agents.clone()
    });
    let agent_workspace_details = use_signal({
        let initial_agent_workspace = initial_agent_workspace.clone();
        move || initial_agent_workspace.details.clone()
    });
    let draft = use_signal({
        let initial_local_state = initial_local_state.clone();
        let initial_spaces = initial_spaces.clone();
        move || {
            initial_spaces
                .first()
                .and_then(|space| initial_local_state.drafts.get(&space.space_id))
                .cloned()
                .unwrap_or_default()
        }
    });
    let mut device_queue = use_signal(|| 0usize);
    let push_state = use_signal({
        let initial_local_state = initial_local_state.clone();
        move || crate::push::push_status_label(initial_local_state.push_registration.as_ref())
    });
    let frontier_state = use_signal(|| "Not loaded".to_owned());
    let crypto_state = use_signal(|| "No authenticated session".to_owned());
    let network_state = use_signal(|| "offline".to_owned());
    let mut last_error = use_signal(|| Option::<String>::None);
    let server_description = use_signal(|| Option::<ServerDescription>::None);
    let server_probe_status = use_signal(|| "server not probed".to_owned());
    let locale = use_signal(move || initial_locale);
    // Provide i18n context for views that call `crate::i18n::tr(key)`.
    // The locale field stays in sync with `locale` via the use_effect
    // below; the dictionary tables are baked once at boot.
    let i18n_signal = use_context_provider::<crate::i18n::I18nSignal>(|| {
        crate::i18n::init_i18n_with_locale(initial_locale)
    });
    {
        let mut sig = i18n_signal;
        use_effect(move || {
            crate::i18n::set_locale(&mut sig, locale());
        });
    }
    // Shared `Signal<MlsPassphraseStore>` for per-Space MLS snapshot
    // passphrases. Both chat.rs (encrypt path) and timeline.rs
    // (decrypt-success audit emitter) read from this so a Send Secure
    // followed by a sync round-trip can be decrypted by the same client.
    // Default empty — the placeholder/sealed paths still work; once the
    // user enters a passphrase the real MLS encrypt + decrypt path
    // engages for that Space.
    use_context_provider::<Signal<crate::mls_passphrase::MlsPassphraseStore>>(|| {
        Signal::new(crate::mls_passphrase::MlsPassphraseStore::default())
    });
    // Cap-Gate-1: shared `Signal<CapabilityEngine>` for UI-side pre-gates.
    // Starts empty; views call `engine.ui_gate(...)` which returns an open
    // gate when no grants for the subject are loaded yet, so the existing
    // "trust the server" behavior is preserved until something hydrates
    // grants. The capability-grant hydrate path is a follow-up — once
    // `cx.capability.grant` projection events ship, the post-login flow
    // will `engine.write().add_grant(...)` and the kanban Archive /
    // Restore buttons will start gating themselves.
    use_context_provider::<Signal<crate::capability::CapabilityEngine>>(|| {
        Signal::new(crate::capability::CapabilityEngine::new())
    });
    // A2 / AW-3.10: the controller's owned-agent list. chat.rs +
    // timeline.rs composers read this Signal (via `use_context`) to
    // decide whether to mount the PrivateComposeBanner above the
    // textarea. Default empty until the SDK agent-workspace projection
    // hydrates it.
    let owned_agents_context = use_context_provider::<
        crate::views::agent_workspace::OwnedAgentsContext,
    >(|| Signal::new(initial_agent_workspace.agents.clone()));
    let mut theme = use_signal(move || initial_theme);
    let mut mobile_nav_open = use_signal(|| false);
    let mut mobile_space_query = use_signal(String::new);
    let mut sidebar_collapsed = use_signal(|| false);
    let mut sidebar_width = use_signal(move || initial_sidebar_width);
    let mut sidebar_resizing = use_signal(|| false);
    let mut server_menu_open = use_signal(|| false);
    let mut account_menu_open = use_signal(|| false);
    let mut account_session_state = use_signal(|| "Session idle".to_owned());
    let mut global_query = use_signal(String::new);
    let mut palette_open = use_signal(|| false);
    // A2 — popover next to topbar "My Agents" nav entry.
    let mut agent_workspace_info_open = use_signal(|| false);
    // A6.4 — `?` keyboard shortcut help overlay state.
    let mut shortcut_help_open = use_signal(|| false);
    let mut space_scope_mode = use_signal(move || initial_space_scope_mode);

    // On first render with a live session, fetch the directory + sync so
    // the sidebar's Space list shows up after a page reload. The list
    // intentionally isn't persisted in localStorage — `search_spaces`
    // results live only in the in-memory `spaces` signal, so without
    // this kick we'd render "No spaces loaded" until the user clicks
    // Refresh.
    //
    // The flag is consumed only after we confirm base+session are both
    // populated. Otherwise a fresh user who lands without a session and
    // then signs in (on the same mount) would never auto-connect, since
    // the one-shot would have already been spent during the empty-session
    // first render.
    // Background session-refresh poller. Re-mints the principal
    // `access_token` from the persisted coauth `session_grant` before it
    // dies, so an idle user doesn't get bounced to the login page on
    // their next interaction. The decision logic + IO live in
    // `session_refresh`; this future is just the dioxus driver.
    use_future({
        let mut token = token;
        let mut state_store = state_store;
        let mut status = status;
        let mut last_error = last_error;
        let navigator = navigator.clone();
        let config_store = config_store;
        let base_url = base_url;
        let account_did = account_did;
        let device_id = device_id;
        move || async move {
            loop {
                // Drive prepare/exchange/commit by hand so the
                // `state_store` WriteGuard is *not* held across the
                // network await. Holding it crashes every concurrent
                // signal mutation with `AlreadyBorrowedMut` — clicking
                // the sidebar scope toggle, persisting drafts, anything
                // that calls `state_store.write()` while the exchange
                // is in flight.
                let prepared = {
                    let mut store = state_store.write();
                    crate::session_refresh::prepare_refresh(&mut store)
                };
                let outcome = match prepared {
                    crate::session_refresh::RefreshPrepared::Done(outcome) => outcome,
                    crate::session_refresh::RefreshPrepared::Ready { grant, proof } => {
                        let result = crate::session_refresh::exchange_refresh(&grant, &proof).await;
                        let mut store = state_store.write();
                        crate::session_refresh::commit_refresh(&mut store, result)
                    }
                };
                match outcome {
                    crate::session_refresh::RefreshOutcome::Refreshed { access_token, .. } => {
                        token.set(access_token.clone());
                        persist_config(
                            config_store,
                            base_url(),
                            account_did(),
                            device_id(),
                            access_token,
                        );
                    }
                    crate::session_refresh::RefreshOutcome::LoginRequired { reason } => {
                        token.set(String::new());
                        persist_config(
                            config_store,
                            base_url(),
                            account_did(),
                            device_id(),
                            String::new(),
                        );
                        status.set("Session expired; sign in again".to_owned());
                        last_error.set(Some(format!("session refresh: {reason}")));
                        redirect_to_login(navigator.clone());
                    }
                    crate::session_refresh::RefreshOutcome::Transient { reason } => {
                        // Don't disturb the UI — log to last_error so a
                        // developer poking at the dev tools can see the
                        // last refresh issue, but keep the token alive
                        // for the next retry.
                        last_error.set(Some(format!("session refresh transient: {reason}")));
                    }
                    crate::session_refresh::RefreshOutcome::NoGrant
                    | crate::session_refresh::RefreshOutcome::Fresh => {}
                }
                crate::api::sleep_for(std::time::Duration::from_secs(
                    crate::session_refresh::POLL_INTERVAL_SECS,
                ))
                .await;
            }
        }
    });

    // SyncEngine generation counter. Declared up front so the
    // bootstrap connect() can pass it via `ConnectContext`. The engine
    // itself is spawned by the `use_effect` further down.
    let mut sync_generation = use_signal(|| 0u64);

    // Single-source-of-truth for the sidebar. Anything that wants to
    // change the visible Space list writes to
    // `state_store.space_projections` (sync engine, connect()'s initial
    // bootstrap, setup's optimistic post-create insert, future
    // push-notification ingestion). This effect derives the `spaces`
    // Signal from those projections so consumers can keep reading
    // `spaces()` as before — but the only path into the data is
    // through the store. Avoids the "stale ghost space" class of bugs
    // where signal writers forgot to also update the projection (or
    // vice versa) and the two slid out of sync.
    use_effect(move || {
        let projections = state_store.read().load().space_projections;
        spaces.set(space_previews_from_sync_spaces(&projections));
    });

    // Bootstrap handshake: on first render with a valid session, run
    // `connect()` exactly once to do the `/server/describe` +
    // `/account/me` probes and the initial server-authoritative full
    // sync. After that, the SyncEngine (below) owns continuous sync.
    let mut bootstrap_pending = use_signal(|| true);
    if bootstrap_pending() {
        let base = base_url();
        let session = token();
        if !base.trim().is_empty() && !session.trim().is_empty() {
            bootstrap_pending.set(false);
            connect(
                base,
                account_did(),
                device_id(),
                ConnectContext {
                    status,
                    sync_cursor,
                    token,
                    account_did,
                    selected_space,
                    spaces,
                    timeline,
                    agent_workspace_pending,
                    agent_workspace_in_flight,
                    agent_workspace_recent,
                    agent_workspace_agents,
                    agent_workspace_details,
                    owned_agents_context,
                    device_queue,
                    frontier_state,
                    crypto_state,
                    config_store,
                    state_store,
                    network_state,
                    last_error,
                    server_description,
                    server_probe_status,
                    theme,
                    sync_generation,
                    navigator,
                },
            );
        }
    }

    // SyncEngine — long-poll loop that keeps `space_projections` +
    // derived signals continuously aligned with `/sync`. Spawn per
    // generation so logout / server-switch / account-change can stop
    // the previous loop cleanly by bumping the counter.
    //
    // The use_effect re-runs whenever `sync_generation`, `base_url`, or
    // `token` changes. Each respawn passes the engine the generation
    // value it started with so a stale iteration can self-check and
    // exit before writing back to signals owned by the new generation.
    use_effect(move || {
        let current_gen = sync_generation();
        let base = base_url();
        let session = token();
        if base.trim().is_empty() || session.trim().is_empty() {
            return;
        }
        let ctx = crate::sync_engine::SyncEngineContext {
            base_url,
            token,
            state_store,
            spaces,
            timeline,
            sync_cursor,
            status,
            network_state,
            last_error,
            device_queue,
            theme,
            account_did,
            selected_space,
            agent_workspace_pending,
            agent_workspace_in_flight,
            agent_workspace_recent,
            agent_workspace_agents,
            agent_workspace_details,
            owned_agents_context,
        };
        spawn(async move {
            crate::sync_engine::run_sync_engine(current_gen, sync_generation, ctx).await;
        });
    });

    let routed_space_id = route.space_id().map(str::to_owned);
    let remembered_space_id = selected_space();
    let effective_space_id = routed_space_id.clone().or_else(|| {
        if remembered_space_id.trim().is_empty() {
            None
        } else {
            Some(remembered_space_id.clone())
        }
    });
    let active_space_id = effective_space_id.clone().unwrap_or_default();
    if let Some(route_space_id) = routed_space_id.as_deref() {
        if remembered_space_id != route_space_id {
            selected_space.set(route_space_id.to_owned());
        }
    }

    let active_server_description = server_description();
    let active_service_did = active_server_description
        .as_ref()
        .map(|description| description.service_did.clone())
        .unwrap_or_default();
    let has_session = !token().trim().is_empty();
    let active_server_label = normalize_server_url(&base_url());
    let account_label = if has_session {
        account_did()
    } else {
        "Not signed in".to_owned()
    };
    let account_detail = if has_session {
        format!("device {}", device_id())
    } else {
        "Refresh server metadata, then sign in".to_owned()
    };
    let account_did_value = account_did();
    let device_id_value = device_id();
    let frontier_label = frontier_state();
    let push_label = push_state();
    let crypto_label = crypto_state();
    let account_session_label = account_session_state();
    let queue_label = device_queue().to_string();
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
    let route_uses_space_context = route_uses_space_context(&route);
    let context_space_id = if route_uses_space_context {
        effective_space_id.clone()
    } else {
        None
    };
    let resolved_space_surface = resolve_space_surface(
        &route,
        &state_store(),
        &account_did(),
        context_space_id.as_deref(),
    );
    if let (Some(space_id), Some(surface)) = (routed_space_id.as_deref(), resolved_space_surface) {
        if matches!(
            &route,
            Route::TimelineSpace { .. }
                | Route::KanbanSpace { .. }
                | Route::ChatSpace { .. }
                | Route::DocumentSpace { .. }
        ) {
            let stored_surface =
                load_space_surface_preference(&state_store(), &account_did(), space_id);
            if stored_surface != surface {
                persist_space_surface_preference(
                    &mut state_store.write(),
                    &account_did(),
                    space_id,
                    surface,
                );
            }
        }
    }

    let loaded_spaces = spaces();
    let selected_preview = loaded_spaces
        .iter()
        .find(|space| context_space_id.as_deref() == Some(space.space_id.as_str()))
        .cloned();
    let active_scope_mode = space_scope_mode();
    let active_space_scope_ids =
        scoped_space_ids(&loaded_spaces, &active_space_id, active_scope_mode);
    let active_space_scope_set: BTreeSet<String> = active_space_scope_ids.iter().cloned().collect();
    let active_space_scope_count = active_space_scope_ids.len();
    let active_space_scope_label = if active_space_scope_count <= 1 {
        active_scope_mode.label().to_owned()
    } else {
        format!(
            "{} · {} Spaces",
            active_scope_mode.label(),
            active_space_scope_count
        )
    };
    let space_tree = space_tree_items(&loaded_spaces);
    let active_locale = locale();
    let active_direction = active_locale.direction();
    let direction_attr = active_direction.as_str();
    let locale_attr = active_locale.code();
    let active_theme = theme();
    let sidebar_is_collapsed = sidebar_collapsed();
    let sidebar_is_resizing = sidebar_resizing();
    let server_menu_is_open = server_menu_open();
    let server_options = server_options_for(&base_url());
    let sidebar_style = format!("--sidebar-w: {:.0}px;", sidebar_width());
    let theme_attr = active_theme.as_str();
    let theme_is_night = active_theme == "night";
    let theme_toggle_icon = if theme_is_night { "sun" } else { "moon" };
    let theme_toggle_title = if theme_is_night {
        "Switch to light theme"
    } else {
        "Switch to night theme"
    };
    let route_title = resolved_space_surface
        .map(SpaceSurface::title)
        .unwrap_or_else(|| route_label(&route));
    let document_title = if matches!(&route, Route::Dashboard) {
        "Yougen | Contrix".to_owned()
    } else {
        format!("{route_title} | Yougen | Contrix")
    };
    let shell_class = format!(
        "shell app {}{}{}{}",
        match active_theme.as_str() {
            "night" => "theme-night",
            "light" => "theme-light",
            _ => "theme-system",
        },
        if active_direction == TextDirection::Rtl {
            " rtl"
        } else {
            ""
        },
        if sidebar_is_collapsed {
            " sidebar-collapsed"
        } else {
            ""
        },
        if sidebar_is_resizing {
            " sidebar-resizing"
        } else {
            ""
        }
    );
    let is_auth_route = matches!(&route, Route::Login | Route::AuthCallback);
    if !has_session || is_auth_route {
        let auth_class = format!(
            "auth-shell {}{}",
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
        let login_navigator = navigator.clone();
        let callback_navigator = navigator.clone();

        return rsx! {
            style { "{STYLE}" }
            style { "{CLAUDE_STYLE}" }
            style { "{CLAUDE_APP_OVERRIDES}" }
            document::Title { "{document_title}" }
            main {
                class: auth_class,
                "dir": direction_attr,
                "lang": locale_attr,
                "data-direction": direction_attr,
                "data-locale": locale_attr,
                "data-theme": theme_attr,
                "data-testid": "auth-shell",
                div { class: "auth-card",
                    match &route {
                        Route::AuthCallback => rsx! {
                            crate::views::login::LoginPanel {
                                base_url,
                                account_did,
                                device_id,
                                token,
                                status,
                                config_store,
                                state_store,
                                auto_capture_callback: true,
                                on_login: move |_| { let _ = callback_navigator.push(Route::Dashboard); },
                            }
                        },
                        _ => rsx! {
                            crate::views::login::LoginPanel {
                                base_url,
                                account_did,
                                device_id,
                                token,
                                status,
                                config_store,
                                state_store,
                                auto_capture_callback: false,
                                on_login: move |_| { let _ = login_navigator.push(Route::Dashboard); },
                            }
                        },
                    }
                }
            }
        };
    }

    rsx! {
        style { "{STYLE}" }
        style { "{CLAUDE_STYLE}" }
        style { "{CLAUDE_APP_OVERRIDES}" }
        document::Title { "{document_title}" }
        div {
            class: shell_class,
            style: "{sidebar_style}",
            "dir": direction_attr,
            "lang": locale_attr,
            "data-direction": direction_attr,
            "data-locale": locale_attr,
            "data-theme": theme_attr,
            "data-testid": "client-shell",
            tabindex: "-1",
            // A6.4 — global key handler. `?` (Shift+/) opens the
            // shortcut-help overlay unless the event originated from a
            // text input / textarea / contenteditable surface. `Esc`
            // dismisses it.
            // A6.1 — `Cmd+F` (Ctrl+F on non-Mac) opens the global
            // cross-Space message search panel; we intercept the
            // browser's native find-in-page because the in-app panel
            // covers all spaces the user has access to.
            onkeydown: move |event| {
                let key = event.key().to_string();
                let modifiers = event.modifiers();
                let ctrl = modifiers.ctrl();
                let meta = modifiers.meta();
                if crate::views::global_search::key_event_is_search_trigger(&key, ctrl, meta) {
                    event.prevent_default();
                    event.stop_propagation();
                    let _ = navigator.push(Route::Search);
                    return;
                }
                if crate::components::shortcut_help::key_event_is_help_trigger(&key) {
                    // We can't reliably inspect event.target() in
                    // dioxus 0.7 (the target type is opaque); however
                    // text inputs already swallow the key event before
                    // it reaches the shell when they're focused — so
                    // this handler is only reached for "global" key
                    // presses. Toggle the overlay.
                    shortcut_help_open.set(true);
                    event.stop_propagation();
                } else if key == "Escape" && shortcut_help_open() {
                    shortcut_help_open.set(false);
                    event.stop_propagation();
                }
            },
            onmousemove: move |event| {
                if sidebar_resizing() && !sidebar_collapsed() {
                    let next_width = clamp_sidebar_width(event.client_coordinates().x);
                    sidebar_width.set(next_width);
                }
            },
            onmouseup: move |_| {
                if sidebar_resizing() {
                    let mut store = state_store.write();
                    save_sidebar_width_preference(&mut store, sidebar_width());
                }
                sidebar_resizing.set(false);
            },
            onmouseleave: move |_| {
                if sidebar_resizing() {
                    let mut store = state_store.write();
                    save_sidebar_width_preference(&mut store, sidebar_width());
                }
                sidebar_resizing.set(false);
            },
            div { class: "mobile-shellbar", "data-testid": "mobile-shellbar",
                button {
                    class: "btn icon sm ghost",
                    "data-testid": "mobile-nav-toggle",
                    title: if mobile_nav_open() { "Close menu" } else { "Open menu" },
                    "aria-label": if mobile_nav_open() { "Close menu" } else { "Open menu" },
                    onclick: move |_| mobile_nav_open.toggle(),
                    if mobile_nav_open() {
                        UiIcon { name: "x" }
                    } else {
                        UiIcon { name: "menu" }
                    }
                }
                div { class: "brand", "Contrix" }
                button {
                    class: "btn icon sm ghost",
                    "data-testid": "mobile-theme-toggle",
                    title: "{theme_toggle_title}",
                    "aria-label": "{theme_toggle_title}",
                    onclick: move |_| {
                        let next = if theme() == "night" { "light" } else { "night" }.to_owned();
                        theme.set(next.clone());
                        state_store.write().save_private_data(&account_did(), "theme", next.clone());
                        // A4a — best-effort cross-device sync via
                        // `cx.account_data.set(client.ui)`.
                        crate::views::settings::push_client_ui_account_data(
                            base_url(),
                            token(),
                            next,
                        );
                    },
                    UiIcon { name: theme_toggle_icon }
                }
                Link {
                    class: "btn icon sm ghost topbar-notifications-link",
                    "data-testid": "mobile-topbar-notifications-button",
                    to: Route::Notifications,
                    title: "Notifications",
                    "aria-label": "Notifications",
                    UiIcon { name: "inbox" }
                    span { class: "topbar-notifications-badge", "aria-hidden": "true" }
                }
            }
            nav {
                class: if mobile_nav_open() { "mobile-drawer open" } else { "mobile-drawer" },
                "data-testid": "mobile-nav-drawer",
                div { class: "mobile-status", "data-testid": "mobile-connection-status",
                    span { "data-testid": "mobile-status-label", "{status}" }
                    span { class: "muted mono", "data-testid": "mobile-sync-cursor", "cursor {sync_cursor}" }
                    button {
                        class: "primary",
                        "data-testid": "mobile-connect-button",
                        title: "Refresh server metadata and sync state",
                        "aria-label": "Refresh server metadata and sync state",
                        onclick: move |_| connect(
                            base_url(),
                            account_did(),
                            device_id(),
                            ConnectContext {
                                status,
                                sync_cursor,
                                token,
                                account_did,
                                selected_space,
                                spaces,
                                timeline,
                                agent_workspace_pending,
                                agent_workspace_in_flight,
                                agent_workspace_recent,
                                agent_workspace_agents,
                                agent_workspace_details,
                                owned_agents_context,
                                device_queue,
                                frontier_state,
                                crypto_state,
                                config_store,
                                state_store,
                                network_state,
                                last_error,
                                server_description,
                                server_probe_status,
                                theme,
                                sync_generation,
                                navigator,
                            },
                        ),
                        "Refresh"
                    }
                }
                Link { class: "secondary", "data-testid": "mobile-dashboard-nav-button", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.dashboard")} }
                Link { class: "secondary", "data-testid": "mobile-agent-workspace-nav-button", to: Route::AgentWorkspace, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.agent_workspace")} }
                Link { class: "secondary", "data-testid": "mobile-directory-nav-button", to: Route::Directory, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.directory")} }
                Link { class: "secondary", "data-testid": "mobile-settings-nav-button", to: Route::Settings, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.settings")} }
                if !loaded_spaces.is_empty() {
                    div { class: "muted", "{crate::i18n::tr(\"command_palette.spaces\")} ({space_tree.len()})" }
                    input {
                        class: "mobile-space-filter",
                        "data-testid": "mobile-space-filter",
                        value: "{mobile_space_query}",
                        placeholder: crate::i18n::tr("mobile.filter_spaces"),
                        oninput: move |event| mobile_space_query.set(event.value()),
                    }
                    div { class: "mobile-space-list", "data-testid": "mobile-space-list",
                        {
                            let q = mobile_space_query();
                            let q_lc = q.trim().to_lowercase();
                            let filtered: Vec<_> = space_tree
                                .iter()
                                .filter(|item| {
                                    q_lc.is_empty()
                                        || item.space.name.to_lowercase().contains(&q_lc)
                                        || item.space.space_id.to_lowercase().contains(&q_lc)
                                })
                                .collect();
                            if filtered.is_empty() {
                                rsx! {
                                    div { class: "muted", "data-testid": "mobile-space-empty", {crate::i18n::tr("mobile.no_match")} }
                                }
                            } else {
                                rsx! {
                                    for item in filtered.iter() {
                                        Link {
                                            class: "secondary",
                                            "data-testid": "mobile-space-nav-button",
                                            to: Route::Space { space_id: item.space.space_id.clone() },
                                            onclick: {
                                                let id = item.space.space_id.clone();
                                                move |_| {
                                                    selected_space.set(id.clone());
                                                    mobile_nav_open.set(false);
                                                    mobile_space_query.set(String::new());
                                                }
                                            },
                                            "{item.space.name}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            aside { class: "sidebar", "data-testid": "sidebar", role: "navigation", "aria-label": "Main navigation",
                div {
                    class: "sidebar-resize-handle",
                    "data-testid": "sidebar-resize-handle",
                    title: "Drag to resize menu",
                    "aria-hidden": "true",
                    onmousedown: move |event| {
                        event.prevent_default();
                        sidebar_resizing.set(true);
                    },
                }
                div { class: "sidebar-header",
                    Link { class: "brand", to: Route::Dashboard, "aria-label": "Yougen | Contrix Home",
                        span { class: "logo", "⌘" }
                        span { class: "product-meta",
                            span { class: "product-name", "Yougen | Contrix" }
                        }
                    }
                }

                div { class: "server-switch", "data-testid": "principal-context", "aria-label": "Current server context",
                    button {
                        class: "server-switch-button",
                        "data-testid": "server-switch-button",
                        title: "Switch server",
                        "aria-label": "Switch server",
                        "aria-expanded": if server_menu_is_open { "true" } else { "false" },
                        onclick: move |_| {
                            server_menu_open.toggle();
                            account_menu_open.set(false);
                        },
                        span { class: "server-switch-icon",
                            UiIcon { name: "server" }
                        }
                        span { class: "server-switch-title",
                            span { class: "v", "{active_server_label}" }
                        }
                        span { class: "server-switch-state",
                            if server_menu_is_open {
                                UiIcon { name: "chevron-up" }
                            } else {
                                UiIcon { name: "chevron-down" }
                            }
                        }
                    }

                    if server_menu_is_open && !sidebar_is_collapsed {
                        div { class: "server-switch-menu", "data-testid": "server-switch-menu",
                            div { class: "server-option-list", "aria-label": "Server choices",
                                for option_url in server_options.clone() {
                                    button {
                                        class: if same_server_url(&option_url, &base_url()) { "server-option active" } else { "server-option" },
                                        "data-testid": "server-option",
                                        title: "Switch to {option_url}",
                                        "aria-label": "Switch to {option_url}",
                                        onclick: {
                                            let option_url = option_url.clone();
                                            move |_| {
                                                let next_url = normalize_server_url(&option_url);
                                                select_server(next_url.clone(), ServerSelectionContext {
                                                    base_url,
                                                    token,
                                                    sync_cursor,
                                                    selected_space,
                                                    spaces,
                                                    timeline,
                                                    device_queue,
                                                    frontier_state,
                                                    crypto_state,
                                                    config_store,
                                                    state_store,
                                                    network_state,
                                                    last_error,
                                                    server_description,
                                                    server_probe_status,
                                                    status,
                                                    account_did,
                                                    device_id,
                                                    sync_generation,
                                                });
                                                server_menu_open.set(false);
                                                connect(
                                                    next_url,
                                                    account_did(),
                                                    device_id(),
                                                    ConnectContext {
                                                        status,
                                                        sync_cursor,
                                                        token,
                                                        account_did,
                                                        selected_space,
                                                        spaces,
                                                        timeline,
                                                        agent_workspace_pending,
                                                        agent_workspace_in_flight,
                                                        agent_workspace_recent,
                                                        agent_workspace_agents,
                                                        agent_workspace_details,
                                                        owned_agents_context,
                                                        device_queue,
                                                        frontier_state,
                                                        crypto_state,
                                                        config_store,
                                                        state_store,
                                                        network_state,
                                                        last_error,
                                                        server_description,
                                                        server_probe_status,
                                                        theme,
                                                        sync_generation,
                                                        navigator,
                                                    },
                                                );
                                            }
                                        },
                                        span { class: "server-option-text",
                                            span { class: "server-option-main mono", "{option_url}" }
                                        }
                                        if same_server_url(&option_url, &base_url()) {
                                            span { class: "pill muted xs", "current" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: "sidebar-nav-group",
                    Link { class: "sidebar-nav-item", to: Route::Dashboard,
                        span { class: "sidebar-nav-icon", UiIcon { name: "home" } }
                        span { class: "grow", "Home" }
                    }
                }

                div { class: "sidebar-nav-group", "data-testid": "space-list",
                    h4 { class: "sidebar-nav-group-title",
                        span { "Spaces" }
                        Link { class: "add", to: Route::SetupSection { section: "spaces".to_owned() }, "+" }
                    }
                    if !loaded_spaces.is_empty() && !sidebar_is_collapsed {
                        div { class: "sidebar-scope-toggle", "data-testid": "space-scope-toggle", role: "group", "aria-label": "Space selection scope",
                            button {
                                class: if active_scope_mode == SpaceScopeMode::Exact { "scope-chip active" } else { "scope-chip" },
                                "data-testid": "space-scope-exact",
                                title: "Select only the current Space",
                                "aria-pressed": if active_scope_mode == SpaceScopeMode::Exact { "true" } else { "false" },
                                onclick: move |_| {
                                    space_scope_mode.set(SpaceScopeMode::Exact);
                                    save_space_scope_preference(&mut state_store.write(), SpaceScopeMode::Exact);
                                },
                                "Only"
                            }
                            button {
                                class: if active_scope_mode == SpaceScopeMode::IncludeDescendants { "scope-chip active" } else { "scope-chip" },
                                "data-testid": "space-scope-descendants",
                                title: "Select the current Space and all descendant Spaces",
                                "aria-pressed": if active_scope_mode == SpaceScopeMode::IncludeDescendants { "true" } else { "false" },
                                onclick: move |_| {
                                    space_scope_mode.set(SpaceScopeMode::IncludeDescendants);
                                    save_space_scope_preference(&mut state_store.write(), SpaceScopeMode::IncludeDescendants);
                                },
                                "Tree"
                            }
                        }
                    }
                    if loaded_spaces.is_empty() {
                        div { class: "sidebar-nav-item is-dim", "data-testid": "space-empty-state",
                            span { class: "sidebar-nav-icon", UiIcon { name: "folder" } }
                            span { class: "grow truncate", if has_session { "No spaces loaded" } else { "Sign in to load spaces" } }
                        }
                        // Diagnostic line: when an authenticated user sees an
                        // empty sidebar, surface the latest connect status and
                        // (if any) last_error directly so QA / users can tell
                        // "sync failed" from "no spaces yet" without opening
                        // devtools. Truncated to keep the sidebar tidy.
                        if has_session && !sidebar_is_collapsed {
                            div { class: "sidebar-nav-meta",
                                "data-testid": "space-empty-state-status",
                                style: "padding: 4px 12px; font-size: 11px; line-height: 1.4; opacity: 0.7;",
                                {
                                    let status_text = status();
                                    let error_text = last_error();
                                    let trimmed_status = if status_text.len() > 96 {
                                        format!("{}…", &status_text[..96])
                                    } else {
                                        status_text
                                    };
                                    let trimmed_error = error_text
                                        .as_ref()
                                        .map(|err| if err.len() > 96 {
                                            format!("{}…", &err[..96])
                                        } else {
                                            err.clone()
                                        });
                                    rsx! {
                                        div { "data-testid": "space-empty-state-status-line",
                                            "{trimmed_status}"
                                        }
                                        if let Some(err) = trimmed_error {
                                            div {
                                                "data-testid": "space-empty-state-error-line",
                                                style: "color: var(--danger, #d33);",
                                                "{err}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        for item in space_tree.iter() {
                            {
                                let item_space = item.space.clone();
                                let depth_px = item.depth * 14;
                                let in_scope = active_space_scope_set.contains(&item_space.space_id);
                                let is_active = effective_space_id.as_deref() == Some(item_space.space_id.as_str());
                                let item_class = if is_active {
                                    "sidebar-nav-item space-tree-item is-active"
                                } else if in_scope {
                                    "sidebar-nav-item space-tree-item is-scope-member"
                                } else {
                                    "sidebar-nav-item space-tree-item"
                                };
                                // Spec client-preferences.md §3.7: when the
                                // user has a private Space remark, prefer its
                                // local_name; fall back to the public title.
                                // Use a "(remark)" badge so duplicate-titled
                                // Spaces can be distinguished without leaking
                                // the remark beyond this device.
                                let remark = state_store
                                    .read()
                                    .space_remark(&item_space.space_id);
                                let display_name = remark
                                    .as_ref()
                                    .map(|r| r.display_name(&item_space.name).to_owned())
                                    .unwrap_or_else(|| item_space.name.clone());
                                let has_remark = remark
                                    .as_ref()
                                    .is_some_and(|r| !r.local_name.trim().is_empty());
                                rsx! {
                            Link {
                                class: "{item_class}",
                                "data-testid": "space-button",
                                title: "{item_space.name}",
                                style: "padding-left: calc(10px + {depth_px}px);",
                                to: Route::Space { space_id: item_space.space_id.clone() },
                                onclick: {
                                    let id = item_space.space_id.clone();
                                    move |_| selected_space.set(id.clone())
                                },
                                span { class: "sidebar-nav-icon", UiIcon { name: "folder" } }
                                span { class: "grow truncate", "{display_name}" }
                                if has_remark {
                                    span {
                                        class: "pill muted xs",
                                        "data-testid": "space-remark-badge",
                                        title: "Local remark (private to this account)",
                                        "备注"
                                    }
                                }
                                if item.descendant_count > 0 {
                                    span { class: "pill muted xs", "{item.descendant_count}" }
                                } else {
                                    span { class: "pill muted xs", "Space" }
                                }
                            }
                                }
                            }
                        }
                    }
                }

            }

            if sidebar_is_resizing {
                div {
                    class: "sidebar-resize-shield",
                    "data-testid": "sidebar-resize-shield",
                    onmousemove: move |event| {
                        if !sidebar_collapsed() {
                            let next_width = clamp_sidebar_width(event.client_coordinates().x);
                            sidebar_width.set(next_width);
                        }
                    },
                    onmouseup: move |_| {
                        let mut store = state_store.write();
                        save_sidebar_width_preference(&mut store, sidebar_width());
                        sidebar_resizing.set(false);
                    },
                }
            }

            main { class: "main workspace", "data-testid": "main-view", role: "main", "aria-label": "Main content",
                div { class: "topbar workspace-header",
                    button {
                        class: "btn icon sm ghost sidebar-collapse-toggle",
                        "data-testid": "sidebar-collapse-toggle",
                        title: if sidebar_is_collapsed { "Show navigation" } else { "Hide navigation" },
                        "aria-label": if sidebar_is_collapsed { "Show navigation" } else { "Hide navigation" },
                        onclick: move |_| sidebar_collapsed.toggle(),
                        if sidebar_is_collapsed {
                            UiIcon { name: "panel-left-open" }
                        } else {
                            UiIcon { name: "panel-left-close" }
                        }
                    }
                    div { class: "crumbs", "data-testid": "topbar-crumbs",
                        Link { to: Route::SettingsSection { section: "server".to_owned() }, strong { "{active_server_label}" } }
                        span { class: "crumb-tag", if has_session { "Session" } else { "Server" } }
                        if let Some(space) = selected_preview.as_ref() {
                            span { class: "sep", "/" }
                            span { class: "id", "Spaces" }
                            span { class: "sep", "/" }
                            span { class: "id", "data-testid": "space-title", "{space.name}" }
                            span { class: "sep", "/" }
                            span { class: "id", "{route_title}" }
                            span { class: "id muted mono", "data-testid": "selected-space-id", "{space.space_id}" }
                        } else {
                            span { class: "sep", "/" }
                            span { class: "id", "data-testid": "space-title", "{route_title}" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "btn icon sm ghost theme-toggle-button",
                            "data-testid": "theme-toggle",
                            title: "{theme_toggle_title}",
                            "aria-label": "{theme_toggle_title}",
                            onclick: move |_| {
                                let next = if theme() == "night" { "light" } else { "night" }.to_owned();
                                theme.set(next.clone());
                                state_store.write().save_private_data(&account_did(), "theme", next.clone());
                                // A4a — best-effort cross-device sync
                                // via `cx.account_data.set(client.ui)`.
                                crate::views::settings::push_client_ui_account_data(
                                    base_url(),
                                    token(),
                                    next,
                                );
                            },
                            UiIcon { name: theme_toggle_icon }
                        }
                        div { class: "search",
                            span { "⌕" }
                            input {
                                "data-testid": "global-search-input",
                                value: "{global_query}",
                                placeholder: crate::i18n::tr("topbar.search_placeholder"),
                                onfocusin: move |_| palette_open.set(true),
                                oninput: move |event| {
                                    global_query.set(event.value());
                                    palette_open.set(true);
                                },
                                onkeydown: move |event| {
                                    let key = event.key().to_string();
                                    if key == "Escape" {
                                        palette_open.set(false);
                                        global_query.set(String::new());
                                    }
                                },
                            }
                            kbd { "⌘K" }
                            if palette_open() {
                                CommandPalette {
                                    query: global_query(),
                                    spaces: spaces(),
                                    on_navigate: move |route: Route| {
                                        view.set(Route::to_view(&route));
                                        let _ = navigator.push(route);
                                        palette_open.set(false);
                                        global_query.set(String::new());
                                    },
                                    on_pick_space: move |space_id: String| {
                                        selected_space.set(space_id.clone());
                                        view.set(crate::views::View::Timeline);
                                        let _ = navigator.push(Route::Space { space_id });
                                        palette_open.set(false);
                                        global_query.set(String::new());
                                    },
                                    on_close: move |_: ()| {
                                        palette_open.set(false);
                                    },
                                }
                            }
                        }
                        div { class: "sr-only", "data-testid": "connection-status", role: "status", "aria-live": "polite",
                            span { "data-testid": "status-label", "{status}" }
                            span { "data-testid": "network-state-badge", "{network_state}" }
                            span { class: "mono", "data-testid": "sync-cursor", "cursor {sync_cursor}" }
                            if let Some(ref err) = last_error() {
                                span { "data-testid": "last-error", "{err}" }
                            }
                        }
                        div { class: "topbar-agent-workspace-wrap", style: "position: relative; display: inline-flex; align-items: center;",
                            Link {
                                class: "btn icon sm ghost topbar-agent-workspace-link",
                                "data-testid": "topbar-agent-workspace-button",
                                to: Route::AgentWorkspace,
                                title: crate::i18n::tr("nav.agent_workspace"),
                                "aria-label": crate::i18n::tr("nav.agent_workspace"),
                                UiIcon { name: "user" }
                                span { class: "topbar-notifications-badge", "aria-hidden": "true" }
                            }
                            // A2 — info-icon + popover next to the My
                            // Agents nav entry. Pressing it toggles a
                            // small explanation card that surfaces the
                            // mirror-Space semantics so users
                            // understand the boundary before opening
                            // the surface.
                            button {
                                class: "btn icon sm ghost topbar-agent-workspace-info",
                                "data-testid": "topbar-agent-workspace-info-button",
                                title: crate::i18n::tr("agent_workspace.nav.info_title"),
                                "aria-label": crate::i18n::tr("agent_workspace.nav.info_button"),
                                "aria-expanded": format!("{}", agent_workspace_info_open()),
                                onclick: move |evt| {
                                    evt.stop_propagation();
                                    agent_workspace_info_open.toggle();
                                },
                                "?"
                            }
                            if agent_workspace_info_open() {
                                div {
                                    class: "topbar-agent-workspace-info-popover",
                                    "role": "dialog",
                                    "data-testid": "topbar-agent-workspace-info-popover",
                                    style: "position: absolute; top: calc(100% + 4px); right: 0; z-index: 30; min-width: 280px; max-width: 360px; padding: 12px; border-radius: 8px; background: var(--bg-elevated, #1a1d22); color: var(--text-strong, #fff); border: 1px solid var(--border-default, #333); box-shadow: 0 6px 24px rgba(0,0,0,0.35);",
                                    strong { "{crate::i18n::tr(\"agent_workspace.nav.info_title\")}" }
                                    p { style: "margin: 6px 0 8px 0; line-height: 1.4;",
                                        "{crate::i18n::tr(\"agent_workspace.nav.info_body\")}"
                                    }
                                    button {
                                        class: "secondary",
                                        "data-testid": "topbar-agent-workspace-info-dismiss",
                                        onclick: move |_| agent_workspace_info_open.set(false),
                                        "{crate::i18n::tr(\"common.close\")}"
                                    }
                                }
                            }
                        }
                        // A6.1 — global cross-Space message search
                        // entry. Mirrors the Cmd+F (Ctrl+F) chord so
                        // mouse-first users discover the affordance.
                        Link {
                            class: "btn icon sm ghost topbar-search-link",
                            "data-testid": "topbar-search-button",
                            to: Route::Search,
                            title: crate::i18n::tr("topbar.search_button"),
                            "aria-label": crate::i18n::tr("topbar.search_button"),
                            UiIcon { name: "search" }
                        }
                        Link {
                            class: "btn icon sm ghost topbar-notifications-link",
                            "data-testid": "topbar-notifications-button",
                            to: Route::Notifications,
                            title: crate::i18n::tr("nav.notifications"),
                            "aria-label": crate::i18n::tr("nav.notifications"),
                            UiIcon { name: "inbox" }
                            span { class: "topbar-notifications-badge", "aria-hidden": "true" }
                        }
                        Link {
                            class: "btn sm primary topbar-create-button",
                            "data-testid": "topbar-create-button",
                            to: Route::SetupSection { section: "spaces".to_owned() },
                            title: crate::i18n::tr("topbar.new_space"),
                            "aria-label": crate::i18n::tr("topbar.new_space"),
                            UiIcon { name: "plus" }
                            span { class: "topbar-new-space-label", {crate::i18n::tr("topbar.new_space")} }
                        }
                        div { class: "account-menu-wrap",
                            button {
                                class: "btn icon sm ghost account-menu-button",
                                "data-testid": "account-menu-button",
                                title: crate::i18n::tr("topbar.account_menu"),
                                "aria-label": crate::i18n::tr("topbar.account_menu"),
                                onclick: move |_| {
                                    server_menu_open.set(false);
                                    account_menu_open.toggle();
                                },
                                UiIcon { name: "user" }
                                if has_session {
                                    span { class: "dot-online", title: "online" }
                                }
                            }
                            if account_menu_open() {
                                div { class: "account-menu", "data-testid": "account-menu", role: "menu",
                                    div { class: "account-menu__head",
                                        span { class: "avatar", if has_session { "P" } else { "?" } }
                                        span { class: "grow",
                                            span { class: "who", "{account_label}" }
                                            span { class: "handle", "{account_detail}" }
                                        }
                                    }
                                    div { class: "account-menu__rows",
                                        div { class: "account-menu__row",
                                            strong { "DID" }
                                            span { class: "mono", "data-testid": "account-menu-did", "{account_did_value}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Device" }
                                            span { class: "mono", "data-testid": "account-menu-device", "{device_id_value}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Server" }
                                            span { "{active_server_label}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Frontier" }
                                            span { class: "mono", "data-testid": "account-menu-frontier", "{frontier_label}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Push" }
                                            span { class: "mono", "data-testid": "account-menu-push", "{push_label}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Queue" }
                                            span { class: "mono", "data-testid": "account-menu-queue", "{queue_label}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Crypto" }
                                            span { class: "mono", "data-testid": "account-menu-crypto", "{crypto_label}" }
                                        }
                                    }
                                    div { class: "account-menu__section",
                                        div { class: "account-menu__section-head",
                                            span { "Session" }
                                            span { "bearer" }
                                        }
                                        div { class: "account-menu__rows",
                                            div { class: "account-menu__row",
                                                strong { "Token" }
                                                span { class: "mono", "data-testid": "account-menu-session-token", if has_session { "Token loaded" } else { "No authenticated session" } }
                                            }
                                            div { class: "account-menu__row",
                                                strong { "Crypto" }
                                                span { class: "mono", "data-testid": "account-menu-session-crypto", "{crypto_label}" }
                                            }
                                            div { class: "account-menu__row",
                                                strong { "State" }
                                                span { class: "mono", "data-testid": "account-menu-session-state", "{account_session_label}" }
                                            }
                                        }
                                        div { class: "account-menu__actions",
                                            button {
                                                class: "btn sm ghost",
                                                "data-testid": "account-menu-session-refresh",
                                                disabled: !has_session,
                                                onclick: {
                                                    let base = base_url();
                                                    move |_| {
                                                        let base = base.clone();
                                                        let api_token = token();
                                                        let device = device_id();
                                                        account_session_state.set("Refreshing session".to_owned());
                                                        spawn(async move {
                                                            match ContrixApi::new(&base) {
                                                                Ok(api) => match api.with_bearer(api_token.clone()).account_me().await {
                                                                    Ok(account) => {
                                                                        let canonical_actor = account.did;
                                                                        account_did.set(canonical_actor.clone());
                                                                        persist_config(
                                                                            config_store,
                                                                            base.clone(),
                                                                            canonical_actor.clone(),
                                                                            device.clone(),
                                                                            api_token,
                                                                        );
                                                                        account_session_state.set(format!(
                                                                            "Session refresh ok: {}",
                                                                            canonical_actor
                                                                        ));
                                                                    }
                                                                    Err(error) => {
                                                                        if is_auth_expired_error(&error) {
                                                                            token.set(String::new());
                                                                            persist_config(
                                                                                config_store,
                                                                                base.clone(),
                                                                                account_did(),
                                                                                device.clone(),
                                                                                String::new(),
                                                                            );
                                                                            status.set("Session expired; sign in again".to_owned());
                                                                            last_error.set(Some("auth_expired: session expired".to_owned()));
                                                                            account_session_state.set(
                                                                                "Session expired. Sign in again.".to_owned()
                                                                            );
                                                                            redirect_to_login(navigator);
                                                                        } else {
                                                                            account_session_state.set(format!(
                                                                                "Session refresh failed: {error}"
                                                                            ));
                                                                        }
                                                                    }
                                                                },
                                                                Err(error) => account_session_state
                                                                    .set(format!("Invalid server URL: {error}")),
                                                            }
                                                        });
                                                    }
                                                },
                                                "Refresh"
                                            }
                                            button {
                                                class: "btn sm ghost",
                                                "data-testid": "account-menu-session-logout",
                                                disabled: !has_session,
                                                onclick: move |_| {
                                                    let base = base_url();
                                                    let actor = account_did();
                                                    let device = device_id();
                                                    let api_token = token();
                                                    account_session_state.set("Logging out".to_owned());
                                                    // Clear OIDC + session-grant state up
                                                    // front so a refresh-token-based silent
                                                    // re-auth cannot resurrect the session
                                                    // if the server-side logout call later
                                                    // fails or is cancelled.
                                                    state_store.write().set_oidc_tokens(None);
                                                    state_store.write().set_session_grant(None);
                                                    // Then wipe every account-scoped local
                                                    // projection cache (spaces, drafts,
                                                    // anchors, read markers, remarks…) so
                                                    // whoever signs in next on this browser
                                                    // can't see the previous session's data.
                                                    // Device-level state (local_identity,
                                                    // push_registration) is preserved.
                                                    state_store.write().clear_account_scoped();
                                                    let _ = crate::coauth::clear_persisted_oidc_scaffold();
                                                    // Wipe the in-memory UI signals too so the
                                                    // sidebar can't paint a frame of stale
                                                    // spaces between this click and the
                                                    // navigator.push(Login).
                                                    spaces.set(Vec::new());
                                                    timeline.set(Vec::new());
                                                    sync_cursor.set("-".to_owned());
                                                    selected_space.set(String::new());
                                                    device_queue.set(0);
                                                    last_error.set(None);
                                                    // Bump the SyncEngine generation so any
                                                    // in-flight long-poll exits on its next
                                                    // iteration check instead of applying a
                                                    // response after the wipe.
                                                    sync_generation.set(sync_generation() + 1);
                                                    spawn(async move {
                                                        let api_result = ContrixApi::new(&base)
                                                            .map(|api| api.with_bearer(api_token));
                                                        let logout_message = match api_result {
                                                            Ok(api) => match api.logout().await {
                                                                Ok(response) => format!(
                                                                    "Logout ok: revoked {}",
                                                                    response.revoked
                                                                ),
                                                                Err(error) => {
                                                                    format!("Logout failed: {error}")
                                                                }
                                                            },
                                                            Err(error) => {
                                                                format!("Invalid server URL: {error}")
                                                            }
                                                        };
                                                        token.set(String::new());
                                                        persist_config(
                                                            config_store,
                                                            base,
                                                            actor,
                                                            device,
                                                            String::new(),
                                                        );
                                                        account_session_state.set(logout_message);
                                                        account_menu_open.set(false);
                                                        redirect_to_login(navigator);
                                                    });
                                                },
                                                "Log out"
                                            }
                                        }
                                    }
                                    div { class: "account-menu__actions",
                                        Link {
                                            class: "btn sm",
                                            "data-testid": "account-menu-settings",
                                            to: Route::Settings,
                                            onclick: move |_| account_menu_open.set(false),
                                            UiIcon { name: "settings" }
                                            "Settings"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if route_uses_space_context && !active_space_id.is_empty() {
                    SpaceContextBar {
                        space_id: active_space_id.clone(),
                        scope_label: active_space_scope_label.clone(),
                        scope_count: active_space_scope_count,
                        current_surface: resolved_space_surface,
                        account_did: account_did(),
                        state_store,
                        minimal_ready,
                        kanban_ready,
                        chat_ready,
                        full_ready,
                    }
                }
                div { class: "workspace-body",
                match route {
                    Route::Login => rsx! {
                        crate::views::login::LoginPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            status,
                            config_store,
                            state_store,
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
                            state_store,
                            auto_capture_callback: true,
                            on_login: move |_| { let _ = navigator.push(Route::Dashboard); },
                        }
                    },
                    Route::Dashboard => rsx! {
                        crate::views::dashboard::DashboardPanel {
                            base_url: base_url(),
                            token,
                            spaces,
                            selected_space,
                            view,
                            state_store,
                            device_queue: device_queue(),
                            frontier_state: frontier_state(),
                            sync_cursor: sync_cursor(),
                        }
                    },
                    Route::Space { .. } => {
                        match resolved_space_surface.unwrap_or(SpaceSurface::Timeline) {
                            SpaceSurface::Timeline => {
                                if minimal_ready {
                                    rsx! {
                                        crate::views::timeline::TimelinePanel {
                                            base_url: base_url(),
                                            account_did: account_did(),
                                            device_id: device_id(),
                                            token,
                                            selected_space: active_space_id.clone(),
                                            selected_space_scope: active_space_scope_ids.clone(),
                                            timeline,
                                            draft,
                                            state_store,
                                            crypto_state,
                                            sync_cursor,
                                            frontier_state,
                                            base_url_sig: base_url,
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "minimal_client" } }
                                }
                            }
                            SpaceSurface::Board => {
                                if kanban_ready {
                                    rsx! {
                                        crate::views::kanban::KanbanPanel {
                                            base_url: base_url(),
                                            token,
                                            account_did: account_did(),
                                            selected_space: active_space_id.clone(),
                                            selected_space_scope: active_space_scope_ids.clone(),
                                            sync_cursor,
                                            frontier_state,
                                            state_store,
                                            event_write_ready,
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "kanban_only_client" } }
                                }
                            }
                            SpaceSurface::Discussion => {
                                if chat_ready {
                                    rsx! {
                                        crate::views::chat::ChatPanel {
                                            base_url: base_url(),
                                            plaintext_service_did: active_service_did.clone(),
                                            account_did: account_did(),
                                            token,
                                            selected_space: active_space_id.clone(),
                                            selected_space_scope: active_space_scope_ids.clone(),
                                            sync_cursor,
                                            frontier_state,
                                            state_store,
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "chat_only_client" } }
                                }
                            }
                            SpaceSurface::Document => {
                                if full_ready {
                                    rsx! {
                                        crate::views::document::DocumentPanel {
                                            base_url: base_url(),
                                            token,
                                            selected_space: active_space_id.clone(),
                                            state_store,
                                            account_did: account_did(),
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "full_client" } }
                                }
                            }
                        }
                    },
                    Route::Timeline | Route::TimelineSpace { .. } | Route::TimelineMessage { .. } => {
                        if let Some(sid) = route.space_id() {
                            if selected_space() != sid {
                                selected_space.set(sid.to_owned());
                            }
                        }
                        if minimal_ready {
                            rsx! {
                                crate::views::timeline::TimelinePanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    selected_space_scope: active_space_scope_ids.clone(),
                                    timeline,
                                    draft,
                                    state_store,
                                    crypto_state,
                                    sync_cursor,
                                    frontier_state,
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
                            status,
                            token,
                            view,
                            state_store,
                        }
                    },
                    Route::Setup | Route::SetupSection { .. } => {
                        if full_ready {
                            rsx! {
                                crate::views::setup::SetupPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    token,
                                    account_did,
                                    device_id,
                                    config_store,
                                    state_store,
                                    selected_space,
                                    status,
                                    section: route.setup_section().map(str::to_owned),
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
                    Route::VerifyDevice => {
                        if e2ee_ready {
                            rsx! {
                                crate::views::verify_device::VerifyDevicePanel {
                                    base_url: base_url(),
                                    token,
                                    device_id: device_id(),
                                    account_did: account_did(),
                                    selected_space: selected_space(),
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "e2ee_client" } }
                        }
                    },
                    Route::SpaceAdmin { .. } | Route::SpaceAdminSection { .. } => {
                        if let Some(sid) = route.space_id() {
                            if selected_space() != sid {
                                selected_space.set(sid.to_owned());
                            }
                        }
                        if full_ready {
                            rsx! {
                                crate::views::space_admin::SpaceAdminPanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    sync_cursor,
                                    frontier_state,
                                    state_store,
                                    active_section: route.space_admin_section().map(str::to_owned),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::Audit => rsx! {
                        crate::views::audit::AuditPanel { state_store }
                    },
                    Route::Kanban | Route::KanbanSpace { .. } | Route::KanbanTask { .. } => {
                        if let Some(sid) = route.space_id() {
                            if selected_space() != sid {
                                selected_space.set(sid.to_owned());
                            }
                        }
                        if kanban_ready {
                            rsx! {
                                crate::views::kanban::KanbanPanel {
                                    base_url: base_url(),
                                    token,
                                    account_did: account_did(),
                                    selected_space: active_space_id.clone(),
                                    selected_space_scope: active_space_scope_ids.clone(),
                                    sync_cursor,
                                    frontier_state,
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
                            if selected_space() != sid {
                                selected_space.set(sid.to_owned());
                            }
                        }
                        if chat_ready {
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    account_did: account_did(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    selected_space_scope: active_space_scope_ids.clone(),
                                    sync_cursor,
                                    frontier_state,
                                    state_store,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "chat_only_client" } }
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
                            if selected_space() != sid {
                                selected_space.set(sid.to_owned());
                            }
                        }
                        rsx! {
                            if full_ready {
                                crate::views::document::DocumentPanel {
                                    base_url: base_url(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    state_store,
                                    account_did: account_did(),
                                }
                            } else {
                                ProfileGateNotice { profile: "full_client" }
                            }
                        }
                    },
                    Route::Call => rsx! {
                        crate::views::call::CallPanel { state_store }
                    },
                    Route::Recovery => rsx! {
                        crate::views::recovery::RecoveryPanel {
                            base_url: base_url(),
                            token,
                            state_store,
                            account_did,
                            device_id,
                        }
                    },
                    Route::Onboarding => rsx! {
                        crate::views::onboarding::OnboardingPanel {
                            base_url: base_url(),
                            token,
                            account_did,
                            device_id,
                            state_store,
                        }
                    },
                    Route::Quarantine => rsx! {
                        crate::views::quarantine::QuarantinePanel {
                            // Coauth and soland may share a host in
                            // single-server dev deployments - fall back to
                            // `base_url` until the topology probe surfaces a
                            // separate coauth URL.
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
                    Route::Applets => rsx! {
                        crate::views::applets::AppletsPanel {
                            base_url: base_url(),
                            account_did,
                            token,
                            selected_space: selected_space(),
                            state_store,
                        }
                    },
                    Route::Agents => rsx! {
                        crate::views::agents::AgentsPanel {
                            base_url: base_url(),
                            account_did,
                            token,
                            selected_space: selected_space(),
                            state_store,
                        }
                    },
                    Route::AgentWorkspace => rsx! {
                        crate::views::agent_workspace::AgentWorkspaceDashboard {
                            pending: agent_workspace_pending,
                            in_flight: agent_workspace_in_flight,
                            recent: agent_workspace_recent,
                            agents: agent_workspace_agents,
                        }
                    },
                    Route::AgentTask { task_id } => rsx! {
                        crate::views::agent_workspace::AgentTaskDetailPage {
                            task_id: task_id.clone(),
                            detail: use_signal({
                                let task_id = task_id.clone();
                                let details = agent_workspace_details.read().clone();
                                move || details.get(&task_id).cloned()
                            }),
                        }
                    },
                    Route::AgentWorkspaceSettings => rsx! {
                        crate::views::agent_workspace::AgentWorkspaceSettings {
                            agents: agent_workspace_agents,
                            default_profile: use_signal(crate::views::agent_workspace::AgentMemberProfile::default),
                        }
                    },
                    // A6.1 — global cross-Space message search panel.
                    Route::Search => rsx! {
                        crate::views::global_search::GlobalSearchPanel {
                            base_url,
                            token,
                            initial_query: String::new(),
                        }
                    },
                }
            }
            }
            // A6.4 — shortcut help overlay; toggled by the `?` global
            // key handler on the shell div above.
            crate::components::shortcut_help::ShortcutHelpOverlay {
                visible: shortcut_help_open,
            }
        }
    }
}

#[component]
fn SpaceContextBar(
    space_id: String,
    scope_label: String,
    scope_count: usize,
    current_surface: Option<SpaceSurface>,
    account_did: String,
    state_store: Signal<LocalStateStore>,
    minimal_ready: bool,
    kanban_ready: bool,
    chat_ready: bool,
    full_ready: bool,
) -> Element {
    let _ = (&scope_label, scope_count);
    let relation = state_store
        .read()
        .load()
        .space_projections
        .get(&space_id)
        .and_then(space_mirror_relation);
    let source_chip = relation.as_ref().and_then(|relation| {
        relation.source_space_id.as_ref().map(|id| {
            (
                id.clone(),
                relation.source_label.clone().unwrap_or_else(|| id.clone()),
            )
        })
    });
    let mirror_chip = relation.as_ref().and_then(|relation| {
        relation.mirror_space_id.as_ref().map(|id| {
            (
                id.clone(),
                relation.mirror_label.clone().unwrap_or_else(|| id.clone()),
            )
        })
    });
    rsx! {
        div { class: "event", "data-testid": "space-context-bar",
            div { class: "actions",
                if let Some((source_space_id, source_label)) = source_chip {
                    Link {
                        class: "secondary",
                        "data-testid": "space-source-chip",
                        to: Route::Space { space_id: source_space_id },
                        UiIcon { name: "arrow-left" }
                        "Source: {source_label}"
                    }
                }
                if let Some((mirror_space_id, mirror_label)) = mirror_chip {
                    Link {
                        class: "secondary",
                        "data-testid": "space-mirror-chip",
                        to: Route::Space { space_id: mirror_space_id },
                        UiIcon { name: "arrow-right" }
                        "Mirror: {mirror_label}"
                    }
                }
                for surface in SpaceSurface::all() {
                    if surface.is_available(minimal_ready, kanban_ready, chat_ready, full_ready) {
                        Link {
                            class: if current_surface == Some(surface) { "primary" } else { "secondary" },
                            to: surface.route(space_id.clone()),
                            onclick: {
                                let account_did = account_did.clone();
                                let space_id = space_id.clone();
                                move |_| {
                                    persist_space_surface_preference(
                                        &mut state_store.write(),
                                        &account_did,
                                        &space_id,
                                        surface,
                                    );
                                }
                            },
                            UiIcon { name: surface.icon_name() }
                            "{surface.short_label()}"
                        }
                    } else {
                        button {
                            class: "secondary",
                            disabled: true,
                            UiIcon { name: surface.icon_name() }
                            "{surface.short_label()}"
                        }
                    }
                }
                Link {
                    class: if current_surface.is_none() { "primary" } else { "secondary" },
                    to: Route::SpaceAdmin { space_id: space_id.clone() },
                    UiIcon { name: "settings" }
                    "Admin"
                }
            }
        }
    }
}

/// Static list of jumpable destinations surfaced in the command palette.
/// Keep in sync with `routes::Route` — only views the user can act on are
/// listed.
fn palette_destinations() -> Vec<(&'static str, &'static str, Route)> {
    vec![
        ("Home", "dashboard, recent activity", Route::Dashboard),
        (
            "My Agents",
            "agent workspace, tasks, mention_redirect routing",
            Route::AgentWorkspace,
        ),
        (
            "Notifications",
            "inbox, mentions, approvals",
            Route::Notifications,
        ),
        ("Directory", "search spaces, orgs, actors", Route::Directory),
        (
            "Onboarding",
            "DID, handle, device, recovery",
            Route::Onboarding,
        ),
        (
            "Settings",
            "account, encryption, push, server",
            Route::Settings,
        ),
        (
            "Recovery",
            "vault, social, recovery key (preview)",
            Route::Recovery,
        ),
        (
            "Verify device",
            "QR / SAS device verification",
            Route::VerifyDevice,
        ),
        (
            "Quarantine",
            "review held invites (admin)",
            Route::Quarantine,
        ),
        (
            "Workspace setup",
            "bootstrap a Space and policy",
            Route::Setup,
        ),
    ]
}

fn palette_filter(query: &str, haystack: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let needle = query.trim().to_lowercase();
    let hay = haystack.to_lowercase();
    needle.split_whitespace().all(|token| hay.contains(token))
}

#[component]
fn CommandPalette(
    query: String,
    spaces: Vec<SpacePreview>,
    on_navigate: EventHandler<Route>,
    on_pick_space: EventHandler<String>,
    on_close: EventHandler<()>,
) -> Element {
    let dest_list = palette_destinations();
    let matched_dests: Vec<_> = dest_list
        .iter()
        .filter(|(label, hint, _)| palette_filter(&query, &format!("{label} {hint}")))
        .cloned()
        .collect();
    let matched_spaces: Vec<SpacePreview> = spaces
        .iter()
        .filter(|space| palette_filter(&query, &format!("{} {}", space.name, space.space_id)))
        .take(10)
        .cloned()
        .collect();

    rsx! {
        div {
            class: "command-palette",
            "data-testid": "command-palette",
            role: "listbox",
            "aria-label": "Command palette",
            if matched_spaces.is_empty() && matched_dests.is_empty() {
                div { class: "command-palette-empty", "data-testid": "command-palette-empty",
                    {crate::i18n::tr("command_palette.empty")}
                }
            }
            if !matched_spaces.is_empty() {
                div { class: "command-palette-group",
                    div { class: "command-palette-label", {crate::i18n::tr("command_palette.spaces")} }
                    for space in matched_spaces.iter() {
                        button {
                            class: "command-palette-item",
                            "data-testid": "command-palette-space",
                            role: "option",
                            onclick: {
                                let id = space.space_id.clone();
                                move |_| on_pick_space.call(id.clone())
                            },
                            span { class: "command-palette-item-title", "{space.name}" }
                            span { class: "command-palette-item-hint", "{space.space_id}" }
                        }
                    }
                }
            }
            if !matched_dests.is_empty() {
                div { class: "command-palette-group",
                    div { class: "command-palette-label", {crate::i18n::tr("command_palette.jump_to")} }
                    for (label, hint, route) in matched_dests.iter() {
                        button {
                            class: "command-palette-item",
                            "data-testid": "command-palette-dest",
                            role: "option",
                            onclick: {
                                let route = route.clone();
                                move |_| on_navigate.call(route.clone())
                            },
                            span { class: "command-palette-item-title", "{label}" }
                            span { class: "command-palette-item-hint", "{hint}" }
                        }
                    }
                }
            }
            div { class: "command-palette-footer",
                button {
                    class: "btn sm ghost",
                    "data-testid": "command-palette-close",
                    onclick: move |_| on_close.call(()),
                    {crate::i18n::tr("command_palette.close")}
                }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpaceSurface {
    Timeline,
    Board,
    Discussion,
    Document,
}

impl SpaceSurface {
    fn all() -> [Self; 4] {
        [
            Self::Timeline,
            Self::Board,
            Self::Discussion,
            Self::Document,
        ]
    }

    fn short_label(self) -> &'static str {
        match self {
            Self::Timeline => "Timeline",
            Self::Board => "Board",
            Self::Discussion => "Discussion",
            Self::Document => "Document",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Timeline => "Timeline View",
            Self::Board => "Board View",
            Self::Discussion => "Discussion View",
            Self::Document => "Document View",
        }
    }

    fn icon_name(self) -> &'static str {
        match self {
            Self::Timeline => "timeline",
            Self::Board => "board",
            Self::Discussion => "message",
            Self::Document => "file",
        }
    }

    fn preference_value(self) -> &'static str {
        match self {
            Self::Timeline => "timeline",
            Self::Board => "board",
            Self::Discussion => "discussion",
            Self::Document => "document",
        }
    }

    fn from_preference(value: &str) -> Option<Self> {
        match value {
            "timeline" => Some(Self::Timeline),
            "board" => Some(Self::Board),
            "discussion" => Some(Self::Discussion),
            "document" => Some(Self::Document),
            _ => None,
        }
    }

    fn route(self, space_id: String) -> Route {
        match self {
            Self::Timeline => Route::TimelineSpace { space_id },
            Self::Board => Route::KanbanSpace { space_id },
            Self::Discussion => Route::ChatSpace { space_id },
            Self::Document => Route::DocumentSpace { space_id },
        }
    }

    fn is_available(
        self,
        minimal_ready: bool,
        kanban_ready: bool,
        chat_ready: bool,
        full_ready: bool,
    ) -> bool {
        match self {
            Self::Timeline => minimal_ready,
            Self::Board => kanban_ready,
            Self::Discussion => chat_ready,
            Self::Document => full_ready,
        }
    }
}

fn space_surface_preference_key(space_id: &str) -> String {
    format!("space_surface:{space_id}")
}

fn load_space_surface_preference(
    state_store: &LocalStateStore,
    account_key: &str,
    space_id: &str,
) -> SpaceSurface {
    if account_key.trim().is_empty() {
        return SpaceSurface::Timeline;
    }

    state_store
        .load_private_data(account_key, &space_surface_preference_key(space_id))
        .as_deref()
        .and_then(SpaceSurface::from_preference)
        .unwrap_or(SpaceSurface::Timeline)
}

fn persist_space_surface_preference(
    state_store: &mut LocalStateStore,
    account_key: &str,
    space_id: &str,
    surface: SpaceSurface,
) {
    if account_key.trim().is_empty() {
        return;
    }

    state_store.save_private_data(
        account_key,
        space_surface_preference_key(space_id),
        surface.preference_value(),
    );
}

fn resolve_space_surface(
    route: &Route,
    state_store: &LocalStateStore,
    account_key: &str,
    _effective_space_id: Option<&str>,
) -> Option<SpaceSurface> {
    match route {
        Route::Space { space_id } => Some(load_space_surface_preference(
            state_store,
            account_key,
            space_id,
        )),
        Route::Timeline | Route::TimelineSpace { .. } | Route::TimelineMessage { .. } => {
            Some(SpaceSurface::Timeline)
        }
        Route::Kanban | Route::KanbanSpace { .. } | Route::KanbanTask { .. } => {
            Some(SpaceSurface::Board)
        }
        Route::Chat | Route::ChatSpace { .. } => Some(SpaceSurface::Discussion),
        Route::Document | Route::DocumentSpace { .. } => Some(SpaceSurface::Document),
        Route::SpaceAdmin { .. } | Route::SpaceAdminSection { .. } => None,
        _ => None,
    }
}

fn route_uses_space_context(route: &Route) -> bool {
    matches!(
        route,
        Route::Space { .. }
            | Route::Timeline
            | Route::TimelineSpace { .. }
            | Route::TimelineMessage { .. }
            | Route::Kanban
            | Route::KanbanSpace { .. }
            | Route::KanbanTask { .. }
            | Route::Chat
            | Route::ChatSpace { .. }
            | Route::Document
            | Route::DocumentSpace { .. }
            | Route::SpaceAdmin { .. }
            | Route::SpaceAdminSection { .. }
    )
}

fn route_label(route: &Route) -> &'static str {
    match route {
        Route::Dashboard => "Home",
        Route::Login | Route::AuthCallback => "Login",
        Route::Space { .. } => "Space",
        Route::Timeline | Route::TimelineSpace { .. } | Route::TimelineMessage { .. } => {
            "Timeline View"
        }
        Route::Directory => "Search",
        Route::Setup => "Workspace Setup",
        Route::SetupSection { section } => match section.as_str() {
            "spaces" => "New Space",
            _ => "Workspace Setup",
        },
        Route::Settings | Route::SettingsSection { .. } => "Settings",
        Route::VerifyDevice => "Verify Device",
        Route::SpaceAdmin { .. } => "Space Admin",
        Route::SpaceAdminSection { section, .. } => match section.as_str() {
            "members" => "Members Admin",
            "access" => "Access Policy",
            "security" => "Security & MLS",
            "governance" => "Governance",
            "federation" => "Federation Trust",
            "repair" => "Repair & Danger",
            _ => "Space Admin",
        },
        Route::Audit => "Audit",
        Route::Kanban | Route::KanbanSpace { .. } | Route::KanbanTask { .. } => "Board View",
        Route::Chat | Route::ChatSpace { .. } => "Discussion View",
        Route::Notifications => "Notifications",
        Route::Document | Route::DocumentSpace { .. } => "Document View",
        Route::Call => "Call",
        Route::Recovery => "Recovery",
        Route::Onboarding => "Onboarding",
        Route::Quarantine => "Invite Quarantine",
        Route::Applets => "Applets",
        Route::Agents => "Agents",
        Route::AgentWorkspace => "My Agents",
        Route::AgentTask { .. } => "Agent Task",
        Route::AgentWorkspaceSettings => "My Agents · Settings",
        Route::Search => "Search",
    }
}

fn server_key(server_url: &str) -> String {
    normalize_server_url(server_url)
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn same_server_url(left: &str, right: &str) -> bool {
    server_key(left) == server_key(right)
}

fn server_options_for(current_server_url: &str) -> Vec<String> {
    let mut options: Vec<String> = Vec::new();
    for url in [
        normalize_server_url(current_server_url),
        normalize_server_url("https://local.host/"),
    ] {
        if url.is_empty()
            || options
                .iter()
                .any(|existing| same_server_url(existing, &url))
        {
            continue;
        }
        options.push(url);
    }
    options
}

#[derive(Clone, Copy)]
struct ServerSelectionContext {
    base_url: Signal<String>,
    token: Signal<String>,
    sync_cursor: Signal<String>,
    selected_space: Signal<String>,
    spaces: Signal<Vec<SpacePreview>>,
    timeline: Signal<Vec<TimelineEvent>>,
    device_queue: Signal<usize>,
    frontier_state: Signal<String>,
    crypto_state: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    network_state: Signal<String>,
    last_error: Signal<Option<String>>,
    server_description: Signal<Option<ServerDescription>>,
    server_probe_status: Signal<String>,
    status: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    /// SyncEngine generation counter — bumped to retire the
    /// previous-server engine after the cache wipe + URL repoint.
    sync_generation: Signal<u64>,
}

fn select_server(server_url: String, ctx: ServerSelectionContext) {
    let server_url = normalize_server_url(&server_url);
    let mut base_url = ctx.base_url;
    let mut sync_cursor = ctx.sync_cursor;
    let mut selected_space = ctx.selected_space;
    let mut spaces = ctx.spaces;
    let mut timeline = ctx.timeline;
    let mut device_queue = ctx.device_queue;
    let mut frontier_state = ctx.frontier_state;
    let mut crypto_state = ctx.crypto_state;
    let mut network_state = ctx.network_state;
    let mut last_error = ctx.last_error;
    let mut server_description = ctx.server_description;
    let mut server_probe_status = ctx.server_probe_status;
    let mut status = ctx.status;
    let mut state_store = ctx.state_store;
    let mut sync_generation = ctx.sync_generation;

    // A space cached against the previous server's view is meaningless
    // on the new server (different service DID, different membership,
    // potentially overlapping cx:space ids that point at unrelated
    // rooms). Wipe the account-scoped cache before re-pointing the URL
    // so the next sync starts from a clean slate. Device-level state
    // (local_identity, push_registration) is preserved.
    state_store.write().clear_account_scoped();
    // Retire the previous server's SyncEngine. The use_effect's
    // base_url tracking would re-spawn anyway, but bumping here ensures
    // the in-flight long-poll exits before the new URL takes over.
    sync_generation.set(sync_generation() + 1);

    base_url.set(server_url.clone());
    sync_cursor.set("-".to_owned());
    selected_space.set(String::new());
    spaces.set(Vec::new());
    timeline.set(Vec::new());
    device_queue.set(0);
    frontier_state.set("Not loaded".to_owned());
    crypto_state.set("Refresh session for selected server".to_owned());
    server_description.set(None);
    server_probe_status.set("server not probed".to_owned());
    status.set(ConnectionState::Offline.label().to_owned());
    network_state.set("offline".to_owned());
    last_error.set(None);
    persist_config(
        ctx.config_store,
        server_url,
        (ctx.account_did)(),
        (ctx.device_id)(),
        (ctx.token)(),
    );
}

fn clamp_sidebar_width(width: f64) -> f64 {
    width.max(MIN_SIDEBAR_WIDTH).min(MAX_SIDEBAR_WIDTH)
}

fn load_sidebar_width_preference(state_store: &LocalStateStore) -> f64 {
    state_store
        .load_private_data(UI_PREFERENCES_SCOPE, SIDEBAR_WIDTH_PREFERENCE_KEY)
        .and_then(|value| value.parse::<f64>().ok())
        .map(clamp_sidebar_width)
        .unwrap_or(DEFAULT_SIDEBAR_WIDTH)
}

fn save_sidebar_width_preference(state_store: &mut LocalStateStore, width: f64) {
    state_store.save_private_data(
        UI_PREFERENCES_SCOPE,
        SIDEBAR_WIDTH_PREFERENCE_KEY,
        format!("{:.0}", clamp_sidebar_width(width)),
    );
}

fn load_space_scope_preference(state_store: &LocalStateStore) -> SpaceScopeMode {
    state_store
        .load_private_data(UI_PREFERENCES_SCOPE, SPACE_SCOPE_PREFERENCE_KEY)
        .as_deref()
        .map(SpaceScopeMode::from_preference)
        .unwrap_or(SpaceScopeMode::Exact)
}

fn save_space_scope_preference(state_store: &mut LocalStateStore, mode: SpaceScopeMode) {
    state_store.save_private_data(
        UI_PREFERENCES_SCOPE,
        SPACE_SCOPE_PREFERENCE_KEY,
        mode.preference_value(),
    );
}

#[derive(Clone, Copy)]
struct ConnectContext {
    status: Signal<String>,
    sync_cursor: Signal<String>,
    token: Signal<String>,
    account_did: Signal<String>,
    selected_space: Signal<String>,
    spaces: Signal<Vec<SpacePreview>>,
    timeline: Signal<Vec<TimelineEvent>>,
    agent_workspace_pending: Signal<Vec<crate::views::agent_workspace::AgentTaskSummary>>,
    agent_workspace_in_flight: Signal<Vec<crate::views::agent_workspace::AgentTaskSummary>>,
    agent_workspace_recent: Signal<Vec<crate::views::agent_workspace::AgentTaskSummary>>,
    agent_workspace_agents: Signal<Vec<crate::views::agent_workspace::OwnedAgentSummary>>,
    agent_workspace_details:
        Signal<BTreeMap<String, crate::views::agent_workspace::AgentTaskDetail>>,
    owned_agents_context: crate::views::agent_workspace::OwnedAgentsContext,
    device_queue: Signal<usize>,
    frontier_state: Signal<String>,
    crypto_state: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    network_state: Signal<String>,
    last_error: Signal<Option<String>>,
    server_description: Signal<Option<ServerDescription>>,
    server_probe_status: Signal<String>,
    /// A4a: shared UI theme signal so `/sync` can hydrate the theme
    /// from the remote `client.ui` account-data payload right after
    /// session bootstrap. Stub field — wire-up is tracked under A4a.
    theme: Signal<String>,
    /// SyncEngine generation counter. Bumped when `connect()` detects
    /// the canonical actor has changed since the last persisted run
    /// (account swap on the same device) so any in-flight engine for
    /// the previous account exits before applying its response.
    sync_generation: Signal<u64>,
    navigator: Navigator,
}

fn redirect_to_login(navigator: Navigator) {
    let _ = navigator.push(Route::Login);
}

fn connect(base: String, actor: String, device: String, ctx: ConnectContext) {
    let device = normalize_device_id(&device);
    spawn(async move {
        let mut status = ctx.status;
        let mut sync_cursor = ctx.sync_cursor;
        let mut token = ctx.token;
        let mut account_did = ctx.account_did;
        let mut selected_space = ctx.selected_space;
        let mut spaces = ctx.spaces;
        let mut timeline = ctx.timeline;
        let mut agent_workspace_pending = ctx.agent_workspace_pending;
        let mut agent_workspace_in_flight = ctx.agent_workspace_in_flight;
        let mut agent_workspace_recent = ctx.agent_workspace_recent;
        let mut agent_workspace_agents = ctx.agent_workspace_agents;
        let mut agent_workspace_details = ctx.agent_workspace_details;
        let mut owned_agents_context = ctx.owned_agents_context;
        let mut device_queue = ctx.device_queue;
        let mut frontier_state = ctx.frontier_state;
        let mut crypto_state = ctx.crypto_state;
        let config_store = ctx.config_store;
        let mut state_store = ctx.state_store;
        let mut network_state = ctx.network_state;
        let mut last_error = ctx.last_error;
        let mut server_description = ctx.server_description;
        let mut server_probe_status = ctx.server_probe_status;
        let mut theme = ctx.theme;
        let navigator = ctx.navigator;

        status.set(ConnectionState::Loading.label().to_owned());
        network_state.set("reconnecting".to_owned());
        last_error.set(None);
        match ContrixApi::new(&base) {
            Ok(api) => {
                // Probe `/server/describe` for status text, but treat failure
                // as non-fatal: a transient describe error (CORS preflight,
                // server warming up, brief 5xx) must not block the sync below
                // — otherwise an existing session with cached/server-side
                // spaces silently renders "No spaces loaded" until the user
                // manually retries.
                let description = match api.describe().await {
                    Ok(description) => {
                        let missing = description.missing_v1_principal_server_requirements();
                        if !missing.is_empty() {
                            let message =
                                format!("server describe rejected: missing {}", missing.join(", "));
                            status.set(format!("{}: {message}", ConnectionState::Error.label()));
                            network_state.set("offline".to_owned());
                            last_error.set(Some(message.clone()));
                            server_probe_status.set(message);
                            server_description.set(None);
                            return;
                        }
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
                        server_description.set(Some(description.clone()));
                        Some(description)
                    }
                    Err(error) => {
                        status.set(format!(
                            "{}: describe failed: {error}; trying sync",
                            ConnectionState::Reconnecting.label()
                        ));
                        network_state.set("reconnecting".to_owned());
                        last_error.set(Some(format!("describe: {error}")));
                        server_probe_status.set(format!("server describe failed: {error}"));
                        server_description.set(None);
                        None
                    }
                };

                let session_token = token();
                if session_token.trim().is_empty() {
                    let probe_label = description
                        .as_ref()
                        .map(|d| format!("{} / {}", d.service_type, d.protocol_version))
                        .unwrap_or_else(|| "server probe unavailable".to_owned());
                    status.set(format!("Refreshed: {probe_label}; sign-in required"));
                    network_state.set("online".to_owned());
                    sync_cursor.set("-".to_owned());
                    spaces.set(Vec::new());
                    timeline.set(Vec::new());
                    device_queue.set(0);
                    crypto_state.set("No authenticated session".to_owned());
                    persist_config(
                        config_store,
                        base.clone(),
                        actor.clone(),
                        device.clone(),
                        String::new(),
                    );
                    return;
                }

                let authed = api.clone().with_bearer(session_token.clone());
                // Resolve the canonical actor DID from `/account/me`. Three
                // outcomes:
                //   1. Ok with non-empty DID -> use it as canonical_actor.
                //   2. Err that looks like auth expiry -> wipe session, bounce
                //      to login. The session is provably dead.
                //   3. Anything else (Ok with empty DID, transient 5xx, parse
                //      error, network failure) -> fall back to the locally
                //      stored actor, log a diagnostic to last_error so the
                //      sidebar/status surface can show it, and keep going so
                //      sync still has a chance to populate spaces.
                let canonical_actor = match authed.account_me().await {
                    Ok(account) if !account.did.trim().is_empty() => account.did,
                    Ok(_) => {
                        last_error.set(Some(
                            "account_me: server returned empty actor DID; reusing local actor"
                                .to_owned(),
                        ));
                        actor.clone()
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        token.set(String::new());
                        persist_config(
                            config_store,
                            base.clone(),
                            actor.clone(),
                            device.clone(),
                            String::new(),
                        );
                        sync_cursor.set("-".to_owned());
                        selected_space.set(String::new());
                        spaces.set(Vec::new());
                        timeline.set(Vec::new());
                        device_queue.set(0);
                        crypto_state.set("Session expired".to_owned());
                        status.set("Session expired; sign in again".to_owned());
                        network_state.set("online".to_owned());
                        last_error.set(Some("auth_expired: session expired".to_owned()));
                        redirect_to_login(navigator);
                        return;
                    }
                    Err(error) => {
                        last_error.set(Some(format!("account_me: {error}")));
                        actor.clone()
                    }
                };
                if canonical_actor != actor {
                    // Account changed since the last persisted run (the
                    // server's `/account/me` disagrees with our cached
                    // actor). When the previous actor was non-empty this
                    // means a different human is signing in on the same
                    // device — every account-scoped cache (projections,
                    // drafts, anchor views, read markers, remarks…) is
                    // someone else's data and must be wiped before the
                    // sync below repopulates the store. Device-level
                    // state (local_identity, push_registration) is
                    // preserved.
                    if !actor.trim().is_empty() {
                        let mut store = state_store.write();
                        store.clear_account_scoped();
                        // Also wipe the in-memory UI signals so the
                        // sidebar can't paint the previous actor's
                        // spaces between this point and the sync that's
                        // about to run.
                        drop(store);
                        spaces.set(Vec::new());
                        timeline.set(Vec::new());
                        selected_space.set(String::new());
                        sync_cursor.set("-".to_owned());
                        device_queue.set(0);
                        // Retire the previous-account SyncEngine so its
                        // in-flight long-poll doesn't write back into
                        // the freshly-wiped state.
                        let mut sync_generation = ctx.sync_generation;
                        sync_generation.set(sync_generation() + 1);
                    }
                    account_did.set(canonical_actor.clone());
                }
                persist_config(
                    config_store,
                    base.clone(),
                    canonical_actor.clone(),
                    device.clone(),
                    session_token,
                );
                crypto_state.set(format!("session token loaded for {device}"));

                // `connect()` always issues a full sync (`since=None`) —
                // it's invoked on app boot, the mobile Refresh button,
                // and server switches, all of which represent
                // "re-establish the world from scratch". The SyncEngine
                // (see crate::sync_engine) owns the long-poll loop that
                // threads the cursor for incremental deltas.
                match authed.sync(None).await {
                    Ok(sync) => {
                        {
                            let mut store = state_store.write();
                            store.save_sync_cursor(sync.cursor.clone());
                            // Server-authoritative reconcile: drop every
                            // cached projection whose space_id isn't in
                            // the response. Without this, a Space the
                            // viewer left (or that was deleted server-side)
                            // would linger in the sidebar forever because
                            // `save_space_projection` is upsert-only.
                            let server_set: BTreeSet<String> =
                                sync.spaces.keys().cloned().collect();
                            let pruned =
                                store.retain_space_projections(|id| server_set.contains(id));
                            if !pruned.is_empty() {
                                tracing::info!(
                                    pruned_count = pruned.len(),
                                    "full sync pruned stale space projections",
                                );
                            }
                            // Explicit `left_spaces` deltas — soland emits
                            // these on incremental syncs too; for full sync
                            // they're redundant with `retain_space_projections`
                            // above but cheap to apply when soland evolves
                            // to send them on full sync.
                            for left_id in &sync.left_spaces {
                                store.forget_space(left_id);
                            }
                            for (id, body) in &sync.spaces {
                                store.save_space_projection(id.clone(), body.clone());
                                // Thread the per-Space Anchor view (frontier /
                                // leaves / state_root / bottom cells) into the
                                // local store so Move builders + UI can read
                                // it. Bodies without an `anchor_view` field
                                // produce a Default view (empty frontier =
                                // sentinel) so we still record presence.
                                let view =
                                    crate::local_state::LocalAnchorView::from_sync_body(body);
                                store.set_anchor_view(id.clone(), view);
                            }
                            // Hydrate Space remarks from the actor-private
                            // account_data projection (spec
                            // client-preferences.md §3.7). soland keys these
                            // entries by `cx.contacts.space.<space_id>` and
                            // returns the canonical SpaceRemark JSON in
                            // `content`. Entries for other namespaces are
                            // ignored here.
                            for entry in &sync.account_data {
                                let Some(data_type) =
                                    entry.get("data_type").and_then(serde_json::Value::as_str)
                                else {
                                    continue;
                                };
                                // A4a — hydrate `client.ui` theme from
                                // the remote payload. Cross-device wins:
                                // when remote carries a valid theme that
                                // differs from the local cached value
                                // we update the UI Signal +
                                // LocalConfigStore synchronously.
                                if data_type == "client.ui" {
                                    if let Some(content) = entry.get("content") {
                                        let local_theme = theme();
                                        if let Some(remote_theme) =
                                            crate::account_data::merge_client_ui_theme(
                                                &local_theme,
                                                content,
                                            )
                                        {
                                            theme.set(remote_theme.clone());
                                            store.save_private_data(
                                                &account_did(),
                                                "theme",
                                                remote_theme,
                                            );
                                        }
                                        if let Some(avatar_blob_ref) =
                                            crate::account_data::avatar_blob_ref_from_client_ui(
                                                content,
                                            )
                                        {
                                            store.save_private_data(
                                                &account_did(),
                                                "avatar_blob_ref",
                                                avatar_blob_ref,
                                            );
                                        } else if crate::account_data::avatar_blob_ref_tombstoned_from_client_ui(content) {
                                            store.save_private_data(
                                                &account_did(),
                                                "avatar_blob_ref",
                                                "",
                                            );
                                        }
                                    }
                                    continue;
                                }
                                if data_type == "cx.account.blocklist" {
                                    let Some(content) = entry.get("content") else {
                                        continue;
                                    };
                                    match crate::account_data::blocklist_entries_from_account_data(
                                        content,
                                    ) {
                                        Ok(entries) => {
                                            store.set_client_blocklist(entries);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                "ignoring malformed cx.account.blocklist account_data: {error}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                if let Some(actor_did) =
                                    crate::account_data::actor_did_from_contact_remark_key(
                                        data_type,
                                    )
                                {
                                    let Some(content) = entry.get("content") else {
                                        continue;
                                    };
                                    match serde_json::from_value::<crate::account_data::ContactRemark>(
                                        content.clone(),
                                    ) {
                                        Ok(remark) => {
                                            store.set_contact_remark(actor_did.to_owned(), remark);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                "ignoring malformed Contact remark for {actor_did}: {error}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                let Some(space_id) =
                                    crate::account_data::space_id_from_space_remark_key(data_type)
                                else {
                                    continue;
                                };
                                let Some(content) = entry.get("content") else {
                                    continue;
                                };
                                match serde_json::from_value::<crate::account_data::SpaceRemark>(
                                    content.clone(),
                                ) {
                                    Ok(remark) => {
                                        store.set_space_remark(space_id.to_owned(), remark);
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            "ignoring malformed Space remark for {space_id}: {error}"
                                        );
                                    }
                                }
                            }
                            // Force a synchronous flush so that if the user
                            // refreshes the tab immediately after a successful
                            // sync the next mount's `initial_state_store.load()`
                            // sees the new projections + cursor. Without this
                            // we rely on the per-call `flush()` inside each
                            // setter (which is best-effort on wasm) and on the
                            // WriteGuard's Drop, neither of which is guaranteed
                            // before the browser tears down the page.
                            if let Err(error) = store.flush() {
                                last_error.set(Some(format!("state_store flush failed: {error}")));
                            }
                        }
                        let synced_timeline = timeline_events_from_sync_spaces(&sync.spaces);
                        // `spaces` is derived from `state_store.space_projections`
                        // by a use_effect in `RouterView` — we don't set it
                        // here. Read a reconciled snapshot for status text
                        // and selected_space bookkeeping only.
                        let reconciled = space_previews_from_sync_spaces(
                            &state_store.read().load().space_projections,
                        );
                        if reconciled.is_empty() {
                            status.set(ConnectionState::Empty.label().to_owned());
                        } else {
                            status.set(format!(
                                "{}: synced {} space(s)",
                                ConnectionState::Online.label(),
                                reconciled.len()
                            ));
                        }
                        let first_space = reconciled.first().map(|space| space.space_id.clone());
                        let current = selected_space();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !reconciled.iter().any(|s| s.space_id == trimmed);
                        if needs_reset {
                            selected_space.set(first_space.unwrap_or_default());
                        }
                        timeline.set(synced_timeline);
                        let workspace_projection = agent_workspace_projection_from_sync_spaces(
                            &state_store.read().load().space_projections,
                        );
                        agent_workspace_pending.set(workspace_projection.pending);
                        agent_workspace_in_flight.set(workspace_projection.in_flight);
                        agent_workspace_recent.set(workspace_projection.recent);
                        agent_workspace_agents.set(workspace_projection.agents.clone());
                        owned_agents_context.set(workspace_projection.agents);
                        agent_workspace_details.set(workspace_projection.details);
                        device_queue.set(sync.to_device.len());
                        sync_cursor.set(sync.cursor);
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        token.set(String::new());
                        persist_config(
                            config_store,
                            base.clone(),
                            canonical_actor.clone(),
                            device.clone(),
                            String::new(),
                        );
                        sync_cursor.set("-".to_owned());
                        selected_space.set(String::new());
                        spaces.set(Vec::new());
                        timeline.set(Vec::new());
                        device_queue.set(0);
                        crypto_state.set("Session expired".to_owned());
                        status.set("Session expired; sign in again".to_owned());
                        network_state.set("online".to_owned());
                        last_error.set(Some("auth_expired: session expired".to_owned()));
                        redirect_to_login(navigator);
                        return;
                    }
                    Err(error) => {
                        // Sync failed — the `spaces` Signal already
                        // reflects what's in the local store via the
                        // derive effect; just refresh status text and
                        // make sure selected_space points at something
                        // still in scope.
                        let fallback = space_previews_from_sync_spaces(
                            &state_store.read().load().space_projections,
                        );
                        if fallback.is_empty() {
                            status.set(format!(
                                "{}: sync failed: {error}",
                                ConnectionState::Reconnecting.label()
                            ));
                        } else {
                            status.set(
                                "Refreshed: sync unavailable, showing cached/local Space list"
                                    .to_owned(),
                            );
                        }
                        let first_space = fallback.first().map(|space| space.space_id.clone());
                        let current = selected_space();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !fallback.iter().any(|s| s.space_id == trimmed);
                        if needs_reset {
                            selected_space.set(first_space.unwrap_or_default());
                        }
                        last_error.set(Some(format!("sync: {error}")));
                    }
                }
                match authed.events_describe().await {
                    Ok(events) => {
                        if let Some(frontier) = frontier_label(&events.frontier) {
                            frontier_state.set(frontier);
                        }
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        // Same definitive-session-loss handling as the sync 401
                        // branch above. Without this, an expired token that
                        // passed sync (because sync was served from a cache or
                        // a misrouted path) could silently leave the user with
                        // a stale frontier and no session-expiry redirect.
                        token.set(String::new());
                        persist_config(
                            config_store,
                            base.clone(),
                            canonical_actor.clone(),
                            device.clone(),
                            String::new(),
                        );
                        sync_cursor.set("-".to_owned());
                        selected_space.set(String::new());
                        spaces.set(Vec::new());
                        timeline.set(Vec::new());
                        device_queue.set(0);
                        crypto_state.set("Session expired".to_owned());
                        status.set("Session expired; sign in again".to_owned());
                        network_state.set("online".to_owned());
                        last_error.set(Some("auth_expired: session expired".to_owned()));
                        redirect_to_login(navigator);
                        return;
                    }
                    Err(error) => {
                        last_error.set(Some(format!("events_describe: {error}")));
                    }
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

pub fn space_previews_from_sync_spaces(spaces: &BTreeMap<String, Value>) -> Vec<SpacePreview> {
    let mut previews: Vec<SpacePreview> = spaces
        .iter()
        .filter(|(id, body)| id.starts_with("cx:space:") && !projection_looks_like_flow(body))
        .map(|(id, body)| {
            let summary = body.get("summary").unwrap_or(&Value::Null);
            let title = summary
                .get("title")
                .and_then(Value::as_str)
                .or_else(|| {
                    summary
                        .get("flow")
                        .and_then(|flow| flow.get("title"))
                        .and_then(Value::as_str)
                })
                .unwrap_or(id)
                .to_owned();
            let description = summary
                .get("summary")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let tags = summary
                .get("tags")
                .and_then(Value::as_array)
                .map(|tags| {
                    tags.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<BTreeSet<_>>()
                })
                .unwrap_or_default();
            SpacePreview {
                space_id: id.clone(),
                name: title,
                description,
                tags,
                public: true,
                category: summary
                    .get("category")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                parent_space_id: extract_parent_space_id(id, body),
                child_space_ids: extract_child_space_ids(id, body),
            }
        })
        .collect();
    normalize_space_hierarchy(&mut previews);
    previews
}

fn projection_looks_like_flow(body: &Value) -> bool {
    // Real-Space projections embed their primary flow under
    // `summary.flow` (with `flow_id` etc. inside it) — so peeking into
    // `summary` to spot a flow is a false positive. Only the body's own
    // top-level `flow_id` / `flow` / `tracks` / `kind`, or a
    // `summary.category` that is itself a flow category, identify a
    // flow-as-space projection.
    body.get("flow_id").is_some()
        || body.get("flow").is_some()
        || body.get("tracks").is_some()
        || matches!(
            body.get("kind").and_then(Value::as_str),
            Some("cx.flow.create" | "discussion" | "flow")
        )
        || matches!(
            body.get("summary")
                .and_then(|summary| summary.get("category"))
                .and_then(Value::as_str),
            Some("discussion" | "flow" | "card" | "announce" | "support" | "activity")
        )
}

pub fn timeline_events_from_sync_spaces(spaces: &BTreeMap<String, Value>) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for (id, body) in spaces {
        let mut summary_event = TimelineEvent::system_notice(
            format!("summary-{id}"),
            "server",
            format!(
                "{id}: {}",
                body["summary"]["summary"]
                    .as_str()
                    .unwrap_or("No summary available")
            ),
        );
        summary_event.space_id = Some(id.clone());
        events.push(summary_event);

        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };

        for event in timeline_events {
            if event.get("kind").and_then(Value::as_str) != Some("cx.message.create") {
                continue;
            }
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("event:unknown")
                .to_owned();
            let content = event.get("content").unwrap_or(&Value::Null);
            let body = content
                .get("body")
                .and_then(Value::as_str)
                .or_else(|| event.get("body").and_then(Value::as_str))
                .or_else(|| {
                    content
                        .get("blocks")
                        .and_then(Value::as_array)
                        .and_then(|blocks| blocks.first())
                        .and_then(|block| block.get("text"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("[message]")
                .to_owned();
            events.push(TimelineEvent {
                space_id: Some(id.clone()),
                id: event_id.clone(),
                sender: event
                    .get("sender")
                    .and_then(Value::as_str)
                    .unwrap_or("did:web:unknown")
                    .to_owned(),
                sender_display: event
                    .get("sender")
                    .and_then(Value::as_str)
                    .unwrap_or("server")
                    .to_owned(),
                body,
                timestamp: event
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                thread_id: event
                    .get("thread_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                event_id: Some(event_id),
                ..TimelineEvent::default()
            });
        }
    }
    events
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AgentWorkspaceProjection {
    pub pending: Vec<crate::views::agent_workspace::AgentTaskSummary>,
    pub in_flight: Vec<crate::views::agent_workspace::AgentTaskSummary>,
    pub recent: Vec<crate::views::agent_workspace::AgentTaskSummary>,
    pub agents: Vec<crate::views::agent_workspace::OwnedAgentSummary>,
    pub details: BTreeMap<String, crate::views::agent_workspace::AgentTaskDetail>,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct SpaceMirrorRelation {
    source_space_id: Option<String>,
    source_label: Option<String>,
    mirror_space_id: Option<String>,
    mirror_label: Option<String>,
}

pub fn agent_workspace_projection_from_sync_spaces(
    spaces: &BTreeMap<String, Value>,
) -> AgentWorkspaceProjection {
    use crate::views::agent_workspace::{AgentTaskDetail, OwnedAgentSummary};

    let labels = space_label_map(spaces);
    let mut all_tasks = Vec::new();
    let mut details = BTreeMap::new();
    let mut agents_by_did: BTreeMap<String, OwnedAgentSummary> = BTreeMap::new();

    for (space_id, body) in spaces {
        for event in projection_events(body) {
            let kind = string_field(event, &["kind", "type"]).unwrap_or_default();
            let payload = event_payload(event);
            if kind == "cx.agent.endpoint" || string_field(payload, &["agent_did"]).is_some() {
                if let Some(agent_did) = string_field(payload, &["agent_did", "did", "actor_id"]) {
                    let label = string_field(
                        payload,
                        &["display_name", "agent_label", "name", "handle", "label"],
                    )
                    .unwrap_or_else(|| agent_did.clone());
                    let source_label = labels
                        .get(space_id)
                        .cloned()
                        .unwrap_or_else(|| space_id.clone());
                    let entry = agents_by_did.entry(agent_did.clone()).or_insert_with(|| {
                        OwnedAgentSummary {
                            agent_did,
                            display_name: label,
                            active_in_sources: Vec::new(),
                            in_mirror_space: false,
                        }
                    });
                    if !entry.active_in_sources.iter().any(|s| s == &source_label) {
                        entry.active_in_sources.push(source_label);
                    }
                }
            }
        }

        let relation = space_mirror_relation(body);
        if let Some(agent_did) = string_field(
            body,
            &[
                "agent_did",
                "target_agent_id",
                "target_agent_did",
                "controller_agent_did",
            ],
        ) {
            let entry =
                agents_by_did
                    .entry(agent_did.clone())
                    .or_insert_with(|| OwnedAgentSummary {
                        agent_did: agent_did.clone(),
                        display_name: agent_did.clone(),
                        active_in_sources: Vec::new(),
                        in_mirror_space: true,
                    });
            if let Some(label) = relation.as_ref().and_then(|r| r.source_label.clone()) {
                if !entry.active_in_sources.iter().any(|s| s == &label) {
                    entry.active_in_sources.push(label);
                }
            }
            entry.in_mirror_space = relation
                .as_ref()
                .and_then(|r| r.source_space_id.as_ref())
                .is_some();
        }

        for task_value in projection_agent_tasks(body) {
            if let Some(summary) = agent_task_summary_from_value(space_id, task_value, &labels) {
                let detail = AgentTaskDetail {
                    source_anchor: string_field(
                        task_value,
                        &[
                            "source_anchor",
                            "context_anchor",
                            "anchor",
                            "source_event_id",
                        ],
                    ),
                    instruction_full: string_field(
                        task_value,
                        &["instruction", "instruction_full", "body", "prompt"],
                    )
                    .unwrap_or_else(|| summary.instruction_preview.clone()),
                    agent_draft: string_field(
                        task_value,
                        &["agent_draft", "draft", "draft_preview", "result", "output"],
                    ),
                    conversation: projection_conversation_lines(task_value),
                    audit_trail: string_array_field(
                        task_value,
                        &["audit_trail", "audit", "events", "source_events"],
                    ),
                    summary: summary.clone(),
                };
                details.insert(summary.agent_task_id.clone(), detail);
                all_tasks.push(summary);
            }
        }
    }

    let mut pending = Vec::new();
    let mut in_flight = Vec::new();
    let mut recent = Vec::new();
    for task in all_tasks {
        if task.needs_attention() {
            pending.push(task);
        } else if task.is_in_flight() {
            in_flight.push(task);
        } else {
            recent.push(task);
        }
    }
    recent.truncate(10);
    AgentWorkspaceProjection {
        pending,
        in_flight,
        recent,
        agents: agents_by_did.into_values().collect(),
        details,
    }
}

fn space_label_map(spaces: &BTreeMap<String, Value>) -> BTreeMap<String, String> {
    spaces
        .iter()
        .map(|(space_id, body)| {
            let label = body
                .get("summary")
                .and_then(|summary| string_field(summary, &["title", "name", "summary"]))
                .or_else(|| string_field(body, &["title", "name", "label"]))
                .unwrap_or_else(|| space_id.clone());
            (space_id.clone(), label)
        })
        .collect()
}

fn projection_events(body: &Value) -> Vec<&Value> {
    let mut events = Vec::new();
    for container in [
        body.get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .unwrap_or(&Value::Null),
        body.get("events").unwrap_or(&Value::Null),
        body.get("operations").unwrap_or(&Value::Null),
    ] {
        if let Some(items) = container.as_array() {
            events.extend(items.iter());
        }
    }
    events
}

fn event_payload(event: &Value) -> &Value {
    event
        .get("payload")
        .or_else(|| event.get("body"))
        .or_else(|| event.get("content"))
        .unwrap_or(event)
}

fn projection_agent_tasks(body: &Value) -> Vec<&Value> {
    let mut tasks = Vec::new();
    for container in [
        body.get("agent_tasks").unwrap_or(&Value::Null),
        body.get("tasks").unwrap_or(&Value::Null),
        body.get("agent_workspace")
            .and_then(|workspace| workspace.get("tasks"))
            .unwrap_or(&Value::Null),
        body.get("summary")
            .and_then(|summary| summary.get("agent_tasks"))
            .unwrap_or(&Value::Null),
    ] {
        if let Some(items) = container.as_array() {
            tasks.extend(items.iter());
        }
    }
    for event in projection_events(body) {
        let kind = string_field(event, &["kind", "type"]).unwrap_or_default();
        if kind.contains("agent_task") {
            tasks.push(event_payload(event));
        }
    }
    tasks
}

fn agent_task_summary_from_value(
    mirror_space_id: &str,
    value: &Value,
    labels: &BTreeMap<String, String>,
) -> Option<crate::views::agent_workspace::AgentTaskSummary> {
    use crate::views::agent_workspace::AgentTaskSummary;

    let task_id = string_field(
        value,
        &["agent_task_id", "task_id", "id", "object_id", "target_ref"],
    )?;
    let source_space_id = string_field(value, &["source_space_id", "source_space", "source_id"]);
    let source_space_label =
        string_field(value, &["source_space_label", "source_label"]).or_else(|| {
            source_space_id
                .as_ref()
                .and_then(|id| labels.get(id).cloned())
        });
    let instruction = string_field(
        value,
        &[
            "instruction_preview",
            "instruction",
            "prompt",
            "body",
            "summary",
        ],
    )
    .unwrap_or_else(|| task_id.clone());

    Some(AgentTaskSummary {
        agent_task_id: task_id,
        mirror_flow_id: string_field(value, &["mirror_flow_id", "mirror_space_id", "flow_id"])
            .unwrap_or_else(|| mirror_space_id.to_owned()),
        source_space_label,
        source_flow_label: string_field(value, &["source_flow_label", "source_flow_id", "flow"]),
        agent_label: string_field(
            value,
            &[
                "agent_label",
                "agent_display_name",
                "agent_did",
                "target_agent_id",
            ],
        )
        .unwrap_or_else(|| "agent".to_owned()),
        instruction_preview: clamp_preview(&instruction, 120),
        execution: parse_execution_state(
            string_field(value, &["execution_state", "execution", "state"])
                .as_deref()
                .unwrap_or("active"),
        ),
        transparency: parse_transparency_state(
            string_field(value, &["transparency_state", "transparency"])
                .as_deref()
                .unwrap_or("ok"),
        ),
        source_authority: parse_source_authority_state(
            string_field(
                value,
                &["source_authority_state", "source_authority", "authority"],
            )
            .as_deref()
            .unwrap_or("ok"),
        ),
        last_updated: string_field(value, &["updated_at", "last_updated", "created_at", "hlc"])
            .unwrap_or_else(|| "synced".to_owned()),
    })
}

fn projection_conversation_lines(
    value: &Value,
) -> Vec<crate::views::agent_workspace::TaskConversationLine> {
    value
        .get("conversation")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|line| {
            let text = string_field(line, &["text", "body", "content"])?;
            Some(crate::views::agent_workspace::TaskConversationLine {
                speaker_label: string_field(line, &["speaker_label", "speaker", "actor"])
                    .unwrap_or_else(|| "agent".to_owned()),
                text,
                timestamp: string_field(line, &["timestamp", "created_at", "hlc"])
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn parse_execution_state(value: &str) -> crate::views::agent_workspace::ExecutionState {
    use crate::views::agent_workspace::ExecutionState;
    match value {
        "pending_source_stub" | "pending" | "waiting_for_source" => {
            ExecutionState::PendingSourceStub
        }
        "completed" | "done" => ExecutionState::Completed,
        "cancelled_stub_rejected" | "stub_rejected" => ExecutionState::CancelledStubRejected,
        "cancelled_orphan" | "orphaned" => ExecutionState::CancelledOrphan,
        "cancelled_by_controller" | "cancelled" => ExecutionState::CancelledByController,
        _ => ExecutionState::Active,
    }
}

fn parse_transparency_state(value: &str) -> crate::views::agent_workspace::TransparencyState {
    use crate::views::agent_workspace::TransparencyState;
    match value {
        "lost" | "transparency_lost" => TransparencyState::Lost,
        "reconfirmed_after_loss" | "reconfirmed" => TransparencyState::ReconfirmedAfterLoss,
        _ => TransparencyState::Ok,
    }
}

fn parse_source_authority_state(
    value: &str,
) -> crate::views::agent_workspace::SourceAuthorityState {
    use crate::views::agent_workspace::SourceAuthorityState;
    match value {
        "revoked" | "source_authority_revoked" => SourceAuthorityState::Revoked,
        "reconfirmed_after_revoke" | "reconfirmed" => SourceAuthorityState::ReconfirmedAfterRevoke,
        _ => SourceAuthorityState::Ok,
    }
}

fn clamp_preview(value: &str, max_chars: usize) -> String {
    let mut out: String = value.chars().take(max_chars).collect();
    if value.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

fn space_mirror_relation(body: &Value) -> Option<SpaceMirrorRelation> {
    let source_space_id = string_field(
        body,
        &["source_space_id", "source_space", "public_source_space_id"],
    )
    .or_else(|| {
        body.get("agent_workspace")
            .and_then(|workspace| string_field(workspace, &["source_space_id", "source_space"]))
    });
    let mirror_space_id = string_field(
        body,
        &[
            "mirror_space_id",
            "private_mirror_space_id",
            "agent_mirror_space_id",
        ],
    )
    .or_else(|| {
        body.get("agent_workspace")
            .and_then(|workspace| string_field(workspace, &["mirror_space_id", "mirror_space"]))
    });
    if source_space_id.is_none() && mirror_space_id.is_none() {
        return None;
    }
    Some(SpaceMirrorRelation {
        source_label: string_field(body, &["source_space_label", "source_label"]).or_else(|| {
            body.get("agent_workspace").and_then(|workspace| {
                string_field(workspace, &["source_space_label", "source_label"])
            })
        }),
        mirror_label: string_field(body, &["mirror_space_label", "mirror_label"]).or_else(|| {
            body.get("agent_workspace").and_then(|workspace| {
                string_field(workspace, &["mirror_space_label", "mirror_label"])
            })
        }),
        source_space_id,
        mirror_space_id,
    })
}

fn frontier_label(frontier: &serde_json::Value) -> Option<String> {
    if let Some(items) = frontier.as_array() {
        return items
            .iter()
            .filter_map(|item| item.as_str())
            .next()
            .map(ToOwned::to_owned);
    }
    frontier
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The App component installs a default push-token provider on
    /// first render so `device-summary` never
    /// shows the `"no PushTokenProvider installed"` warning in
    /// production. The helper is idempotent (`OnceLock` inside
    /// `set_push_token_provider`) — calling it twice in the same
    /// process is safe.
    #[test]
    fn ensure_default_push_token_provider_installs_a_provider_and_is_idempotent() {
        // Provider state is process-wide via `OnceLock`. We don't
        // assert which concrete provider was installed (varies by
        // target_arch / target_os); we only assert the slot becomes
        // populated and stays populated across a second call.
        super::ensure_default_push_token_provider();
        let after_first = crate::push::push_token_provider();
        assert!(
            after_first.is_some(),
            "first ensure call must install a provider"
        );
        super::ensure_default_push_token_provider();
        assert!(
            crate::push::push_token_provider().is_some(),
            "second ensure call must keep the provider installed"
        );
    }

    fn preview(id: &str, name: &str, parent: Option<&str>) -> SpacePreview {
        SpacePreview {
            space_id: id.to_owned(),
            name: name.to_owned(),
            description: None,
            tags: Default::default(),
            public: true,
            category: None,
            parent_space_id: parent.map(ToOwned::to_owned),
            child_space_ids: Vec::new(),
        }
    }

    #[test]
    fn space_tree_uses_parent_links_for_nested_menu() {
        let spaces = vec![
            preview("cx:space:root", "Root", None),
            preview("cx:space:child", "Child", Some("cx:space:root")),
            preview("cx:space:deep", "Deep", Some("cx:space:child")),
        ];

        let items = space_tree_items(&spaces);

        assert_eq!(items.len(), 3);
        assert_eq!(items[0].space.space_id, "cx:space:root");
        assert_eq!(items[0].depth, 0);
        assert_eq!(items[0].descendant_count, 2);
        assert_eq!(items[1].space.space_id, "cx:space:child");
        assert_eq!(items[1].depth, 1);
        assert_eq!(items[2].space.space_id, "cx:space:deep");
        assert_eq!(items[2].depth, 2);
    }

    #[test]
    fn scoped_space_ids_support_exact_and_descendants() {
        let spaces = vec![
            preview("cx:space:root", "Root", None),
            preview("cx:space:child", "Child", Some("cx:space:root")),
            preview("cx:space:deep", "Deep", Some("cx:space:child")),
        ];

        assert_eq!(
            scoped_space_ids(&spaces, "cx:space:root", SpaceScopeMode::Exact),
            vec!["cx:space:root".to_owned()]
        );
        assert_eq!(
            scoped_space_ids(&spaces, "cx:space:root", SpaceScopeMode::IncludeDescendants),
            vec![
                "cx:space:root".to_owned(),
                "cx:space:child".to_owned(),
                "cx:space:deep".to_owned()
            ]
        );
    }

    #[test]
    fn sync_projection_parses_space_hierarchy_fields() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "cx:space:root".to_owned(),
            json!({
                "summary": {
                    "title": "Root",
                    "summary": "Root Space",
                    "child_space_ids": ["cx:space:child"]
                }
            }),
        );
        spaces.insert(
            "cx:space:child".to_owned(),
            json!({
                "summary": {
                    "title": "Child",
                    "summary": "Child Space",
                    "parent_space_id": "cx:space:root"
                }
            }),
        );

        let previews = space_previews_from_sync_spaces(&spaces);
        let root = previews
            .iter()
            .find(|space| space.space_id == "cx:space:root")
            .expect("root preview");
        let child = previews
            .iter()
            .find(|space| space.space_id == "cx:space:child")
            .expect("child preview");

        assert_eq!(root.child_space_ids, vec!["cx:space:child".to_owned()]);
        assert_eq!(child.parent_space_id.as_deref(), Some("cx:space:root"));
    }

    #[test]
    fn sync_projection_filters_flow_entries_out_of_space_list() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "cx:space:root".to_owned(),
            json!({
                "summary": {
                    "title": "Root",
                    "summary": "Root Space"
                }
            }),
        );
        spaces.insert(
            "cx:flow:discussion".to_owned(),
            json!({
                "flow_id": "cx:flow:discussion",
                "summary": {
                    "title": "Should not be a Space"
                }
            }),
        );
        spaces.insert(
            "cx:space:flow-projection".to_owned(),
            json!({
                "flow_id": "cx:flow:nested",
                "summary": {
                    "title": "Flow projection",
                    "category": "discussion"
                }
            }),
        );

        let previews = space_previews_from_sync_spaces(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].space_id, "cx:space:root");
    }

    /// Regression: soland inlines the primary flow under `summary.flow`
    /// for legitimate Spaces (so the client can render the room title
    /// without joining a separate fanout). A previous filter treated
    /// any `summary.flow` as a flow-as-space projection and dropped the
    /// Space from the sidebar entirely. Only top-level `flow*`/`tracks`
    /// or a flow-shaped `summary.category` should reject a `cx:space:`.
    #[test]
    fn sync_projection_keeps_real_space_with_inlined_primary_flow() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "cx:space:0196419b-0000-7000-8000-000000000000".to_owned(),
            json!({
                "ephemeral": [],
                "flows": [{
                    "flow_id": "cx:flow:0196419b-0000-7000-8000-000000000000",
                    "title": "Contrix Demo Space",
                }],
                "summary": {
                    "category": "collaboration",
                    "title": "Contrix Demo Space",
                    "summary": "Shared demo Space served by soland",
                    "tags": ["demo"],
                    "flow": {
                        "flow_id": "cx:flow:0196419b-0000-7000-8000-000000000000",
                        "title": "Contrix Demo Space",
                        "tracks": { "discussion": { "enabled": true } },
                    },
                },
                "timeline": { "events": [], "limited": false },
                "unread": { "highlight_count": 0, "notification_count": 0 },
            }),
        );

        let previews = space_previews_from_sync_spaces(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].space_id,
            "cx:space:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(previews[0].name, "Contrix Demo Space");
        assert_eq!(previews[0].category.as_deref(), Some("collaboration"));
    }

    #[test]
    fn space_previews_from_sync_spaces_filters_flow_like_projections() {
        // Replacement for the old `merge_space_previews_filters_flow_like_search_results`
        // test. The sync engine relies on `space_previews_from_sync_spaces`
        // (rather than the retired client-side merge filter) to keep
        // flow-like projections out of the sidebar — verify that here.
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "cx:flow:discussion".to_owned(),
            json!({
                "flow_id": "cx:flow:discussion",
                "summary": {"title": "Discussion", "category": "discussion"}
            }),
        );
        spaces.insert(
            "cx:space:real".to_owned(),
            json!({"summary": {"title": "Real Space"}}),
        );

        let previews = space_previews_from_sync_spaces(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].space_id, "cx:space:real");
    }
}
