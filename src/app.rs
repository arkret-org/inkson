use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use dioxus::prelude::*;
use dioxus_router::hooks::*;
use dioxus_router::{Link, Navigator, Router};
use serde_json::Value;

use crate::api::{ContrixApi, is_auth_expired_error};
use crate::components::{SecurityStateBadge, UiIcon};
use crate::config::{ClientConfig, LocalConfigStore, normalize_device_id, normalize_server_url};
use crate::conformance::{
    PROFILE_E2EE_CLIENT, PROFILE_FULL_CLIENT, PROFILE_KANBAN_MVP, PROFILE_MINIMAL_CLIENT,
    PROFILE_PUSH_GATEWAY, profile_ready,
};
use crate::i18n::{Locale, TextDirection};
use crate::local_state::{
    ClientLocalState, LocalStateStore, OidcTokenBundle, PersistedSessionGrant,
};
use crate::models::{
    ServerDescription, ServerDescriptionExt, SpacePreview, SpacePreviewKind,
    projection_realm_id_for_known_space,
};
use crate::routes::Route;
use crate::views::ConnectionState;
use crate::views::helpers::{persist_config, short_protocol_id};
use crate::views::timeline::TimelineEvent;

const UI_PREFERENCES_SCOPE: &str = "ui.browser";
const SIDEBAR_WIDTH_PREFERENCE_KEY: &str = "layout.sidebar.width";
const SPACE_SCOPE_PREFERENCE_KEY: &str = "layout.space.scope";
const BOOT_ACCESS_TOKEN_SKEW_SECS: i64 = 30;
const DEFAULT_SIDEBAR_WIDTH: f64 = 272.0;
const MIN_SIDEBAR_WIDTH: f64 = 220.0;
const MAX_SIDEBAR_WIDTH: f64 = 420.0;

const STYLE: &str = r#"
body { margin: 0; font-family: Inter, Segoe UI, sans-serif; background: #eef3ed; color: #162018; }
button, input, textarea, select { font: inherit; }
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
.settings select, .workflow-form select, .event select, .actions select { min-height: 40px; box-sizing: border-box; border: 1px solid #cbd5df; border-radius: 6px; padding: 8px 36px 8px 12px; background: white; color: #18212f; line-height: 1.35; }
.settings select, .workflow-form select { width: 100%; }
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
.settings, .workflow-form { display: grid; gap: 10px; align-content: start; }
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
.event select,
.actions select,
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
.event select:focus,
.actions select:focus,
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
.write-state-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
.write-state-badge.is-icon-only {
  width: 20px;
  height: 20px;
  justify-content: center;
  padding: 0;
}
.write-state-badge.is-icon-only:hover,
.write-state-badge.is-icon-only:focus-within {
  width: auto;
  padding: 2px 8px;
}
.write-state-label {
  display: none;
  min-width: 0;
}
.write-state-badge:hover .write-state-label,
.write-state-badge:focus-within .write-state-label {
  display: inline;
}
.write-state-icon {
  width: 12px;
  height: 12px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: 0 0 auto;
  font-size: 9px;
  font-weight: 900;
  line-height: 1;
}
.write-state-icon::before,
.write-state-icon::after {
  box-sizing: border-box;
}
.write-state-icon.is-queued,
.write-state-icon.is-submitted,
.write-state-icon.is-pending {
  border: 2px solid currentColor;
  border-right-color: transparent;
  animation: message-send-spin 760ms linear infinite;
}
.write-state-icon.is-optimistic {
  border: 2px dashed currentColor;
}
.write-state-icon.is-accepted {
  border: 2px solid currentColor;
}
.write-state-icon.is-accepted::after {
  content: "";
  width: 4px;
  height: 4px;
  border-radius: 999px;
  background: currentColor;
}
.write-state-icon.is-synced {
  border: 2px solid currentColor;
}
.write-state-icon.is-synced::after {
  content: "";
  width: 5px;
  height: 8px;
  margin-top: -2px;
  border-right: 2px solid currentColor;
  border-bottom: 2px solid currentColor;
  transform: rotate(45deg);
}
.write-state-icon.is-soft-failed,
.write-state-icon.is-conflict,
.write-state-icon.is-quarantined,
.write-state-icon.is-failed {
  background: currentColor;
  color: var(--surface);
}
.write-state-icon.is-soft-failed::before,
.write-state-icon.is-quarantined::before,
.write-state-icon.is-failed::before {
  content: "!";
  color: var(--surface);
}
.write-state-icon.is-conflict::before {
  content: "x";
  color: var(--surface);
  font-size: 10px;
  line-height: 1;
}
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
  z-index: var(--layer-sticky);
}

.workspace-body:has(> .kanban-panel) {
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  padding: 12px 16px 0;
  background: var(--bg);
}

.workspace-body > .kanban-panel {
  flex: 1 1 auto;
  display: flex;
  flex-direction: column;
  min-height: 0;
  gap: 10px;
  overflow: hidden;
  background: var(--bg);
}

.event.board-toolbar {
  flex: 0 0 auto;
  display: grid;
  gap: 8px;
  padding: 10px 12px;
}

.board-toolbar-main {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.board-toolbar-main {
  justify-content: flex-start;
}

.board-title-block {
  display: grid;
  gap: 2px;
  min-width: 180px;
  flex: 1 1 auto;
}

.board-kicker {
  display: flex;
  justify-content: flex-start;
  gap: 8px;
}

.board-toolbar-controls,
.board-list-compose,
.board-queue-actions {
  align-items: center;
  gap: 6px;
}

.board-toolbar-controls {
  flex: 1 1 auto;
  min-width: 0;
  flex-wrap: wrap;
  row-gap: 8px;
}

.board-select-label {
  flex: 0 0 auto;
  color: var(--text, var(--cx-ink));
  font-size: 13px;
  font-weight: 700;
  white-space: nowrap;
}

.board-list-compose {
  flex: 0 1 auto;
  min-width: 0;
  flex-wrap: nowrap;
}

.board-list-compose input {
  width: 180px;
  max-width: 20vw;
  min-width: 132px;
  min-height: 38px;
  box-sizing: border-box;
  border: 1px solid var(--border, var(--cx-line-strong));
  border-radius: 8px;
  padding: 8px 10px;
  background: var(--surface, var(--cx-surface));
  color: var(--cx-ink);
}

.board-popover-panel input {
  width: 100%;
  min-height: 38px;
  box-sizing: border-box;
  border: 1px solid var(--border, var(--cx-line-strong));
  border-radius: 8px;
  padding: 8px 10px;
  background: var(--surface, var(--cx-surface));
  color: var(--cx-ink);
}

.board-select-menu-host {
  position: relative;
  flex: 0 0 auto;
  min-width: 184px;
}

.board-select-menu-host.is-open {
  z-index: var(--layer-local-popover);
}

.board-select-native {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: 0;
  padding: 0;
  border: 0;
  opacity: 0;
  pointer-events: none;
}

.board-select-button {
  width: 184px;
  min-width: 172px;
  max-width: 240px;
  min-height: 38px;
  display: inline-flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  border: 1px solid color-mix(in srgb, var(--accent, var(--cx-brand)) 42%, var(--border-strong, var(--cx-line-strong)));
  border-radius: 9px;
  padding: 0 10px;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--accent, var(--cx-brand)) 16%, var(--surface, var(--cx-surface))), var(--surface, var(--cx-surface)));
  color: var(--text, var(--cx-ink));
  font-size: 13px;
  font-weight: 750;
  cursor: pointer;
  box-shadow: inset 0 1px 0 color-mix(in srgb, white 7%, transparent);
}

.board-select-button:hover {
  border-color: color-mix(in srgb, var(--accent, var(--cx-brand)) 70%, var(--border-strong, var(--cx-line-strong)));
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--accent, var(--cx-brand)) 22%, var(--surface, var(--cx-surface))), var(--surface, var(--cx-surface)));
}

.board-select-button:focus-visible,
.board-select-menu-host.is-open .board-select-button {
  outline: none;
  border-color: var(--accent, var(--cx-brand));
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent, var(--cx-brand)) 18%, transparent);
}

.board-select-button .ui-icon:first-child {
  flex: 0 0 auto;
  width: 15px;
  height: 15px;
  color: var(--accent, var(--cx-brand));
}

.board-select-button .ui-icon:last-child {
  flex: 0 0 auto;
  width: 15px;
  height: 15px;
  color: var(--text-3, var(--cx-muted));
}

.board-select-button-label {
  min-width: 0;
  flex: 1 1 auto;
  overflow: hidden;
  text-align: left;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.board-select-menu-panel {
  position: absolute;
  left: 0;
  top: calc(100% + 8px);
  z-index: calc(var(--layer-local-popover) + 1);
  width: min(240px, calc(100vw - 48px));
  max-height: min(360px, calc(100vh - 180px));
  overflow: auto;
  display: grid;
  gap: 4px;
  padding: 6px;
  border: 1px solid var(--border, var(--cx-line));
  border-radius: 10px;
  background: var(--surface-solid, var(--surface, var(--cx-surface)));
  box-shadow: var(--shadow-lg, var(--cx-shadow));
}

.board-select-menu-item {
  min-height: 36px;
  width: 100%;
  display: flex;
  align-items: center;
  gap: 9px;
  border: 1px solid transparent;
  border-radius: 7px;
  padding: 0 10px;
  color: var(--text, var(--cx-ink));
  background: transparent;
  font-size: 13px;
  font-weight: 700;
  text-align: left;
  cursor: pointer;
}

.board-select-menu-item:hover,
.board-select-menu-item:focus-visible {
  outline: none;
  border-color: color-mix(in srgb, var(--accent, var(--cx-brand)) 34%, transparent);
  background: color-mix(in srgb, var(--accent, var(--cx-brand)) 10%, var(--surface, var(--cx-surface)));
}

.board-select-menu-item.is-active {
  border-color: color-mix(in srgb, var(--accent, var(--cx-brand)) 48%, var(--border, var(--cx-line)));
  background: color-mix(in srgb, var(--accent, var(--cx-brand)) 18%, var(--surface, var(--cx-surface)));
}

.board-select-menu-item .ui-icon {
  flex: 0 0 auto;
  width: 15px;
  height: 15px;
  color: var(--accent, var(--cx-brand));
}

.board-select-menu-item span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.board-popover-host {
  position: relative;
}

.board-popover-host.is-open {
  z-index: var(--layer-local-popover);
}

.board-popover-trigger {
  position: relative;
  z-index: var(--layer-sticky);
}

.board-popover-scrim {
  position: fixed;
  inset: 0;
  z-index: var(--layer-local-scrim);
  background: transparent;
}

.board-popover-panel {
  position: absolute;
  right: 0;
  top: calc(100% + 6px);
  z-index: var(--layer-local-popover);
  width: min(360px, calc(100vw - 48px));
  display: grid;
  gap: 8px;
  padding: 10px;
  border: 1px solid var(--border, var(--cx-line));
  border-radius: 8px;
  background: var(--surface-solid, var(--surface, var(--cx-surface)));
  box-shadow: var(--shadow-md, var(--cx-shadow));
}

.board-projection-panel {
  width: min(520px, calc(100vw - 48px));
}

.board-queue-panel {
  width: min(520px, calc(100vw - 48px));
  max-height: min(460px, calc(100vh - 170px));
  overflow: auto;
}

.board-inline-field {
  margin: 0;
}

.board-conflict-alert {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-color: color-mix(in srgb, var(--warning) 46%, var(--border));
  background: color-mix(in srgb, var(--warning-soft) 72%, var(--surface));
}

.board-maintenance.is-empty {
  display: none;
}

.board-grid {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  flex: 1 1 auto;
  min-height: 0;
  overflow-x: auto;
  overflow-y: hidden;
  padding: 2px 2px 14px;
  scroll-snap-type: x proximity;
}
.board-empty-state {
  flex: 1 0 100%;
  min-width: min(680px, 100%);
}
.board-empty-state > .event {
  max-width: 680px;
  box-shadow: none;
  align-items: start;
}
.board-header {
  gap: 8px;
}
.board-header .space-title {
  margin-bottom: 0;
}
.board-diagnostics {
  width: 100%;
}
.board-diagnostics > summary {
  width: max-content;
  cursor: pointer;
  color: var(--cx-muted);
  font-size: 12px;
  font-weight: 700;
}
.board-diagnostics > .metric-grid,
.board-diagnostics > .actions,
.board-diagnostics > .muted {
  margin-top: 8px;
}
.event.board-column {
  flex: 0 0 300px;
  width: 300px;
  min-width: 300px;
  max-height: 100%;
  min-height: 0;
  overflow-y: auto;
  padding: 6px 8px 8px;
  display: grid;
  gap: 6px;
  align-content: start;
  border-radius: 8px;
  scroll-snap-align: start;
}
.board-column > .event-head.board-column-head {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 4px 8px;
}
.board-column-title {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.board-column-title .space-title {
  min-width: 0;
  color: var(--text, var(--cx-ink));
  font-size: 15px;
  font-weight: 800;
  line-height: 1.2;
  letter-spacing: 0;
  overflow-wrap: anywhere;
}

.board-column-title .column-drag-handle {
  width: 24px;
  height: 24px;
  flex-basis: 24px;
  border-radius: 6px;
}
.board-column-meta {
  margin-top: 2px;
  font-size: 12px;
  color: var(--cx-muted);
}
.board-column-actions {
  display: flex;
  justify-content: flex-end;
  min-height: 14px;
  padding-top: 2px;
}
.board-column-actions [data-testid="list-archive-button"],
.board-card-footer [data-testid="card-archive-button"] {
  opacity: 0;
  visibility: hidden;
  pointer-events: none;
  transition: opacity 120ms ease, visibility 120ms ease;
}
.board-column:hover .board-column-actions [data-testid="list-archive-button"],
.board-column:focus-within .board-column-actions [data-testid="list-archive-button"],
.board-card:hover .board-card-footer [data-testid="card-archive-button"],
.board-card:focus-within .board-card-footer [data-testid="card-archive-button"] {
  opacity: 1;
  visibility: visible;
  pointer-events: auto;
}
.board-add-card-row button {
  width: auto;
  min-height: 34px;
  padding: 6px 10px;
}
.kanban-inline-action {
  width: auto;
  min-height: 0;
  padding: 0;
  border: 0;
  background: transparent;
  box-shadow: none;
  color: var(--text-2, var(--cx-muted));
  font-size: 11px;
  font-weight: 500;
  line-height: 1.2;
  opacity: 0.76;
  cursor: pointer;
}
.kanban-inline-action:hover,
.kanban-inline-action:focus-visible {
  color: var(--accent-ink, var(--accent));
  opacity: 1;
  text-decoration: underline;
  text-underline-offset: 2px;
  background: transparent;
}
.kanban-inline-action:disabled {
  color: var(--text-3, var(--cx-muted));
  cursor: not-allowed;
  opacity: 0.38;
  text-decoration: none;
}
.event.board-card {
  cursor: grab;
  padding: 9px 10px;
  border-radius: 8px;
  box-shadow: none;
}
.event.is-failed {
  border-color: color-mix(in srgb, var(--danger) 72%, var(--border));
  background: color-mix(in srgb, var(--danger-soft) 72%, var(--surface));
}
.board-card:active {
  cursor: grabbing;
}
.board-card .event-head {
  align-items: flex-start;
}
.board-card-footer {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  min-height: 14px;
  margin-top: 2px;
}
.board-card-composer {
  display: grid;
  gap: 8px;
  min-width: 0;
}
.board-card-composer-card {
  border: 1px solid var(--cx-line, var(--border));
  border-radius: 8px;
  background: var(--cx-surface, var(--surface));
  box-shadow: var(--cx-shadow-sm, none);
  overflow: hidden;
}
.board-card-composer-input {
  display: block;
  width: 100%;
  min-height: 84px;
  max-height: 220px;
  box-sizing: border-box;
  padding: 10px 12px;
  border: 0;
  outline: 0;
  resize: vertical;
  overflow-y: auto;
  background: transparent;
  color: var(--cx-ink, var(--text));
  font: inherit;
  font-size: 14px;
  line-height: 1.35;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.board-card-composer-input::placeholder {
  color: var(--cx-muted, var(--text-3));
}
.board-card-composer-card:focus-within {
  border-color: var(--cx-brand, var(--accent));
  box-shadow: 0 0 0 1px var(--cx-brand, var(--accent));
}
.board-card-composer-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.board-card-composer-actions button {
  width: auto;
  min-height: 34px;
  padding: 6px 10px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.board-card-composer-actions .ui-icon {
  width: 15px;
  height: 15px;
}
.board-add-card-row {
  display: flex;
  justify-content: flex-start;
}
.board-maintenance {
  border-style: dashed;
  box-shadow: none;
}
.board-maintenance > summary {
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  gap: 10px;
  color: var(--cx-muted);
  font-size: 12px;
  font-weight: 700;
}
.board-maintenance > summary span:last-child {
  white-space: nowrap;
}
.board-maintenance > .muted,
.board-maintenance > .event {
  margin-top: 8px;
}
.card-detail-overlay {
  position: fixed;
  inset: 0;
  z-index: var(--layer-modal);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 50px 16px;
  background: rgba(8, 16, 12, 0.52);
  overflow: auto;
}
.card-detail-popup {
  position: relative;
  width: min(1240px, 100%);
  height: calc(100vh - 100px);
  max-height: calc(100vh - 100px);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  border: 1px solid var(--border, var(--cx-line));
  border-radius: 8px;
  background: var(--surface-solid, var(--surface, var(--cx-surface)));
  color: var(--text, var(--cx-ink));
  box-shadow: var(--shadow-lg, var(--cx-shadow));
}
.card-detail-overlay.is-docked {
  align-items: stretch;
  justify-content: flex-end;
  padding: 0;
  background: transparent;
  overflow: visible;
  pointer-events: none;
}
.card-detail-popup.is-docked {
  pointer-events: auto;
  width: 720px;
  max-width: 100vw;
  height: 100vh;
  max-height: 100vh;
  border-top: 0;
  border-right: 0;
  border-bottom: 0;
  border-radius: 0;
  box-shadow: -12px 0 34px rgba(0, 0, 0, 0.22);
}
.card-detail-resize-handle {
  position: absolute;
  top: 0;
  left: 0;
  width: 8px;
  height: 100%;
  z-index: 4;
  cursor: col-resize;
}
.card-detail-resize-handle:hover,
.card-detail-resize-handle:active {
  background: color-mix(in srgb, var(--accent) 38%, transparent);
}
.card-detail-resize-capture {
  position: fixed;
  inset: 0;
  z-index: calc(var(--layer-modal) + 1);
  cursor: col-resize;
}
.card-detail-header {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border, var(--cx-line));
  background: var(--surface-solid, var(--surface, var(--cx-surface)));
}
.card-detail-title-block {
  min-width: 0;
  display: grid;
  align-content: start;
  gap: 4px;
}
.card-detail-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  min-width: 0;
}
.card-detail-title-row h2 {
  margin: 0;
  font-size: 22px;
  line-height: 1.18;
  font-weight: 800;
  letter-spacing: 0;
  overflow-wrap: anywhere;
}
.card-detail-title-meta {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  min-width: 0;
}
.card-detail-status-dot {
  width: 16px;
  height: 16px;
  margin-top: 5px;
  border: 2px solid var(--text-3);
  border-radius: 999px;
}
.card-detail-id {
  max-width: 720px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: var(--font-mono);
  font-size: 11px;
}
.card-detail-close {
  flex: 0 0 auto;
  box-shadow: none;
}
.card-detail-header-actions {
  position: relative;
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  gap: 8px;
}
.card-detail-header-button {
  width: 34px;
  height: 34px;
  min-height: 34px;
  padding: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  box-shadow: none;
}
.card-detail-action-menu-wrap {
  position: relative;
}
.card-detail-action-menu {
  position: absolute;
  top: calc(100% + 8px);
  right: 0;
  z-index: 2;
  min-width: 220px;
  overflow: hidden;
  padding: 4px 0;
  border: 1px solid var(--border, var(--cx-line));
  border-radius: 8px;
  background: var(--surface-solid, var(--surface, var(--cx-surface)));
  box-shadow: 0 16px 34px rgba(0, 0, 0, 0.28);
}
.card-detail-action-menu.is-editing {
  min-width: min(360px, calc(100vw - 32px));
  padding: 10px;
  display: grid;
  gap: 10px;
}
.card-detail-action-menu-field {
  display: grid;
  gap: 5px;
}
.card-detail-action-menu-field label {
  color: var(--text-2, var(--cx-muted));
  font-size: 12px;
  font-weight: 800;
}
.card-detail-action-menu-field .input {
  width: 100%;
}
.card-detail-action-menu-item {
  width: 100%;
  min-height: 42px;
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 9px;
  padding: 9px 12px;
  border: 0;
  border-radius: 0;
  background: transparent;
  color: var(--text, var(--cx-ink));
  box-shadow: none;
  text-align: left;
}
.card-detail-action-menu-item:hover,
.card-detail-action-menu-item:focus-visible {
  background: var(--surface-2, rgba(148, 163, 184, 0.12));
}
.card-detail-action-menu-item:disabled {
  opacity: 0.48;
  cursor: not-allowed;
}
.card-detail-layout {
  flex: 1 1 auto;
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  overflow: hidden;
}
.card-detail-layout.no-sidebar {
  grid-template-columns: minmax(0, 1fr);
}
.card-detail-main {
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  align-content: stretch;
  gap: 22px;
  padding: 22px 24px 28px;
  overflow: auto;
}
.card-detail-sidebar {
  min-width: 0;
  min-height: 0;
  display: grid;
  align-content: start;
  gap: 14px;
  padding: 18px;
  overflow: auto;
  border-left: 1px solid var(--border, var(--cx-line));
  background: color-mix(in srgb, var(--surface-2) 58%, transparent);
}
.card-detail-section {
  display: grid;
  gap: 10px;
}
.card-detail-section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.card-detail-section-title {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  color: var(--text-2, var(--cx-muted));
  font-size: 13px;
  font-weight: 800;
}
.card-detail-mini-action {
  width: auto;
  min-height: 32px;
  padding: 5px 9px;
  display: inline-flex;
  align-items: center;
  align-self: center;
  flex: 0 0 auto;
  gap: 6px;
  border-radius: 8px;
  box-shadow: none;
}
.card-detail-edit-action {
  opacity: 0;
  transition: opacity 120ms ease;
}
.card-detail-section:hover .card-detail-edit-action,
.card-detail-section:focus-within .card-detail-edit-action,
.card-detail-description-panel:hover .card-detail-edit-action,
.card-detail-description-panel:focus-within .card-detail-edit-action {
  opacity: 1;
}
.card-detail-description {
  margin: 0;
  max-width: 72ch;
  color: var(--text, var(--cx-ink));
  line-height: 1.58;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.card-detail-summary {
  max-width: 72ch;
  color: var(--text, var(--cx-ink));
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.card-detail-empty {
  color: var(--text-3, var(--cx-muted));
  font-size: 13px;
  display: grid;
  gap: 10px;
  justify-items: start;
}
.card-detail-tab-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 6px;
}
.card-detail-sidebar-tabs {
  margin-bottom: 8px;
}
.card-detail-actor-list {
  display: grid;
  gap: 6px;
  list-style: none;
  margin: 0;
  padding: 0;
}
.card-detail-actor-row {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  border-radius: 8px;
  background: color-mix(in srgb, var(--surface-2, var(--cx-bg-soft)) 70%, transparent);
  font-size: 13px;
  color: var(--text, var(--cx-ink));
}
.card-detail-actor-dot {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--text-2, var(--cx-muted)) 60%, transparent);
}
.card-detail-actor-dot.participant {
  background: var(--accent, var(--cx-brand));
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent, var(--cx-brand)) 25%, transparent);
}
.card-detail-actor-row.participant {
  background: color-mix(in srgb, var(--accent, var(--cx-brand)) 8%, var(--surface-2, var(--cx-bg-soft)) 70%);
}
.card-detail-actor-did {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: var(--mono, ui-monospace, SFMono-Regular, Menlo, monospace);
  font-size: 12px;
  color: var(--text-2, var(--cx-muted));
}
.card-detail-tabs-section {
  min-height: 0;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
}
.card-detail-tabs {
  display: flex;
  align-items: center;
  gap: 6px;
  border-bottom: 1px solid var(--border, var(--cx-line));
}
.card-detail-tab {
  min-height: 36px;
  padding: 7px 12px;
  border: 0;
  border-bottom: 2px solid transparent;
  border-radius: 0;
  background: transparent;
  color: var(--text-2, var(--cx-muted));
  font-size: 13px;
  font-weight: 800;
  box-shadow: none;
}
.card-detail-tab.active {
  border-bottom-color: var(--accent, var(--cx-brand));
  color: var(--text, var(--cx-ink));
  background: transparent;
}
.card-detail-tab:disabled {
  cursor: default;
  opacity: 0.72;
}
.card-detail-description-panel,
.card-detail-synthesis-panel,
.card-detail-discussion-panel {
  min-height: 0;
}
.card-detail-description-panel {
  display: grid;
  align-content: start;
  align-items: start;
  gap: 8px;
}
.card-detail-synthesis-panel {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 10px;
  min-height: 0;
  overflow: auto;
}
.card-detail-discussion-panel {
  overflow: hidden;
}
.card-detail-synthesis-empty {
  color: var(--text-3, var(--cx-muted));
  font-size: 13px;
  display: grid;
  gap: 10px;
  justify-items: center;
  text-align: center;
}
.card-synthesis-track {
  width: 100%;
  max-width: none;
  display: grid;
  gap: 12px;
}
.card-synthesis-footer-action {
  margin-top: auto;
  display: flex;
  justify-content: flex-end;
}
.card-synthesis-entry {
  position: relative;
  width: 100%;
  box-sizing: border-box;
  display: grid;
  gap: 8px;
  padding: 10px 12px;
  border: 1px solid transparent;
  border-radius: 8px;
  border-left: 2px solid color-mix(in srgb, var(--accent, var(--cx-brand)) 72%, var(--border, var(--cx-line)));
}
.card-synthesis-entry.is-latest {
  background: color-mix(in srgb, var(--surface-2, var(--cx-bg-soft)) 54%, transparent);
}
.card-synthesis-entry.is-history {
  border-color: color-mix(in srgb, var(--warning, #f59e0b) 54%, var(--border, var(--cx-line)));
  border-left-color: var(--warning, #f59e0b);
  background: color-mix(in srgb, var(--warning-soft, #fff8e5) 34%, var(--surface, var(--cx-surface)));
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--warning, #f59e0b) 14%, transparent);
}
.card-synthesis-entry-head {
  position: relative;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 7px;
  color: var(--text-2, var(--cx-muted));
  font-size: 12px;
}
.card-synthesis-entry-edit {
  margin-left: auto;
  opacity: 0;
  pointer-events: none;
  transition: opacity 120ms ease;
}
.card-synthesis-entry:hover .card-synthesis-entry-edit,
.card-synthesis-entry:focus-within .card-synthesis-entry-edit {
  opacity: 1;
  pointer-events: auto;
}
.card-synthesis-history-wrap {
  position: relative;
  display: inline-flex;
}
.card-synthesis-history-trigger,
.card-synthesis-latest-button {
  border: 0;
  cursor: pointer;
  color: var(--text-on-accent, #ffffff);
  background: var(--accent, var(--cx-brand));
}
.card-synthesis-latest-button {
  background: color-mix(in srgb, var(--accent, var(--cx-brand)) 84%, #000 10%);
}
.card-synthesis-history-trigger:hover,
.card-synthesis-history-trigger:focus-visible,
.card-synthesis-latest-button:hover,
.card-synthesis-latest-button:focus-visible {
  filter: brightness(1.08);
  outline: none;
}
.card-synthesis-history-menu {
  position: absolute;
  z-index: var(--layer-local-popover);
  top: calc(100% + 6px);
  right: 0;
  width: min(340px, calc(100vw - 48px));
  max-height: 320px;
  display: grid;
  gap: 4px;
  padding: 6px;
  overflow-y: auto;
  border: 1px solid var(--border, var(--cx-line));
  border-radius: 8px;
  background: var(--surface-solid, var(--surface, var(--cx-surface)));
  box-shadow: 0 16px 34px rgba(0, 0, 0, 0.28);
}
.card-synthesis-history-title {
  padding: 4px 6px 6px;
  color: var(--text-2, var(--cx-muted));
  font-size: 12px;
  font-weight: 850;
}
.card-synthesis-history-item {
  width: 100%;
  display: grid;
  gap: 4px;
  padding: 8px;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: var(--text, var(--cx-ink));
  text-align: left;
  cursor: pointer;
  box-shadow: none;
}
.card-synthesis-history-item:hover,
.card-synthesis-history-item:focus-visible,
.card-synthesis-history-item.active {
  border-color: color-mix(in srgb, var(--accent, var(--cx-brand)) 42%, var(--border, var(--cx-line)));
  background: color-mix(in srgb, var(--accent-soft, rgba(245, 158, 11, 0.14)) 38%, var(--surface, var(--cx-surface)));
  outline: none;
}
.card-synthesis-history-meta {
  min-width: 0;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  font-size: 12px;
}
.card-synthesis-history-preview {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text-2, var(--cx-muted));
  font-size: 12px;
}
.card-synthesis-author {
  color: var(--text, var(--cx-ink));
  font-weight: 800;
}
.card-synthesis-time {
  color: var(--text-3, var(--cx-muted));
}
.card-synthesis-body {
  max-width: 72ch;
}
.card-detail-side-section {
  min-width: 0;
  display: grid;
  gap: 5px;
  padding: 12px;
  border: 1px solid var(--border, var(--cx-line));
  border-radius: 8px;
  background: var(--surface, var(--cx-surface));
  box-shadow: none;
}
.card-detail-side-fields {
  min-width: 0;
  display: grid;
  gap: 5px;
}
.card-detail-side-actions .secondary {
  min-height: 34px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  border-radius: 8px;
  box-shadow: none;
}
.card-detail-side-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}
.card-detail-side-actions .secondary {
  width: 100%;
}
.card-detail-visibility-note,
.card-detail-policy-note {
  display: grid;
  gap: 6px;
  padding: 10px 12px;
  border: 1px solid var(--border, var(--cx-line));
  border-radius: 8px;
  background: color-mix(in srgb, var(--warning-soft) 28%, var(--surface));
}
.card-detail-visibility-note {
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  color: var(--text-2, var(--cx-muted));
}
.card-detail-policy-note > div:first-child {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  align-items: center;
}
.card-detail-side-section h3 {
  margin: 0 0 4px;
  color: var(--text-2, var(--cx-muted));
  font-size: 12px;
  font-weight: 850;
}
.card-detail-field-list {
  display: grid;
  gap: 8px;
  margin: 0;
}
.card-detail-field-list > div {
  display: grid;
  grid-template-columns: 88px minmax(0, 1fr);
  gap: 10px;
  align-items: start;
}
.card-detail-field-list dt {
  color: var(--text-3, var(--cx-muted));
  font-size: 12px;
  font-weight: 750;
}
.card-detail-field-list dd {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
  font-weight: 700;
}
.card-detail-field-code {
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.45;
}
.card-detail-activity {
  gap: 9px;
}
.card-detail-activity-item {
  display: grid;
  grid-template-columns: 8px minmax(0, 1fr);
  gap: 9px;
  align-items: start;
  font-size: 12px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}
.card-detail-activity-dot {
  width: 8px;
  height: 8px;
  margin-top: 5px;
  border-radius: 999px;
  background: var(--accent);
}
.card-detail-edit-form {
  width: 100%;
  max-width: 72ch;
  box-sizing: border-box;
  min-height: 0;
  padding: 12px;
  border: 1px solid var(--border, var(--cx-line));
  border-radius: 8px;
  background: color-mix(in srgb, var(--surface-2, var(--cx-bg-soft)) 62%, transparent);
}
.card-detail-tabs-section .card-detail-edit-form,
.card-synthesis-entry .card-detail-edit-form {
  max-width: none;
}
.card-detail-inline-edit-form {
  margin-top: 2px;
}
.card-rich-editor {
  display: grid;
  --editor-bg: color-mix(in srgb, var(--surface, var(--cx-surface, #fff)) 92%, var(--bg, var(--cx-bg, #eef3ed)) 8%);
  --editor-bg-soft: color-mix(in srgb, var(--surface-2, var(--cx-bg-soft, #f7faf7)) 84%, var(--surface, var(--cx-surface, #fff)) 16%);
  --editor-bg-raised: color-mix(in srgb, var(--surface-3, var(--cx-surface, #fff)) 78%, var(--accent, var(--cx-brand, #2b6b4f)) 10%);
  --editor-line: var(--border, var(--cx-line, #d6e1d7));
  --editor-line-strong: var(--border-strong, var(--cx-line-strong, #c0cec2));
  --editor-ink: var(--text, var(--cx-ink, #142018));
  --editor-muted: var(--text-2, var(--cx-muted, #627065));
  --editor-accent: var(--accent, var(--cx-teal, #3a8a67));
  --editor-code-bg: color-mix(in srgb, var(--surface-inv, #18212f) 8%, var(--surface-2, var(--cx-bg-soft, #f7faf7)) 92%);
  --editor-code-ink: var(--accent-ink, var(--editor-accent));
  gap: 0;
}
.card-rich-editor-host {
  min-height: 240px;
}
.card-rich-editor-fallback {
  min-height: 180px;
  resize: vertical;
}
.card-rich-editor-fallback.toast-fallback-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  min-height: 1px;
  padding: 0;
  border: 0;
  opacity: 0;
  pointer-events: none;
}
.card-rich-editor-hint {
  font-size: 12px;
}
.card-rich-editor .toastui-editor-defaultUI {
  overflow: hidden;
  border: 1px solid var(--editor-line);
  border-radius: 8px;
  background: var(--editor-bg);
  color: var(--editor-ink);
  font-family: inherit;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
}
.card-rich-editor .toastui-editor-toolbar,
.card-rich-editor .toastui-editor-defaultUI-toolbar {
  height: auto;
  min-height: 44px;
  padding: 6px 10px;
  align-items: center;
  background: linear-gradient(180deg, var(--editor-bg-soft) 0%, var(--editor-bg) 100%);
  border-color: var(--editor-line);
}
.card-rich-editor .toastui-editor-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}
.card-rich-editor .toastui-editor-toolbar-group {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  margin: 0;
}
.card-rich-editor .toastui-editor-toolbar-divider {
  width: 1px;
  height: 20px;
  margin: 0 7px;
  background: var(--editor-line);
}
.card-rich-editor .toastui-editor-md-container,
.card-rich-editor .toastui-editor-ww-container,
.card-rich-editor .toastui-editor-main,
.card-rich-editor .toastui-editor-main-container,
.card-rich-editor .toastui-editor-contents,
.card-rich-editor .ProseMirror {
  background: var(--editor-bg);
  color: var(--editor-ink);
}
.card-rich-editor .toastui-editor-defaultUI .ProseMirror,
.card-rich-editor .toastui-editor-ww-container .toastui-editor-contents,
.card-rich-editor .toastui-editor-md-container .toastui-editor,
.card-rich-editor .toastui-editor-md-container .toastui-editor-md-preview {
  padding: 18px 24px;
}
.card-rich-editor .toastui-editor-md-container .toastui-editor-md-preview {
  border-left: 1px solid var(--editor-line);
}
.card-rich-editor .toastui-editor-md-tab-style > .toastui-editor-md-preview {
  border-left: 0;
}
.card-rich-editor .toastui-editor-contents p,
.card-rich-editor .toastui-editor-contents li,
.card-rich-editor .toastui-editor-contents table,
.card-rich-editor .toastui-editor-contents h1,
.card-rich-editor .toastui-editor-contents h2,
.card-rich-editor .toastui-editor-contents h3,
.card-rich-editor .toastui-editor-contents h4,
.card-rich-editor .toastui-editor-contents h5,
.card-rich-editor .toastui-editor-contents h6,
.card-rich-editor .toastui-editor-md-preview,
.card-rich-editor .toastui-editor-md-splitter,
.card-rich-editor .toastui-editor-md-code {
  color: var(--editor-ink);
}
.card-rich-editor .toastui-editor-contents h1,
.card-rich-editor .toastui-editor-contents h2 {
  border-bottom-color: var(--editor-line-strong);
}
.card-rich-editor .toastui-editor-contents a {
  color: var(--editor-accent);
}
.card-rich-editor .toastui-editor-contents blockquote {
  border-left-color: var(--editor-line-strong);
  color: #c9d5e6;
}
.card-rich-editor .toastui-editor-contents code,
.card-rich-editor .toastui-editor-contents pre,
.card-rich-editor .toastui-editor-md-code,
.card-rich-editor .toastui-editor-md-code-block,
.card-rich-editor .toastui-editor-md-code-block-line-background {
  background: var(--editor-code-bg);
  color: var(--editor-code-ink);
}
.card-rich-editor .toastui-editor-contents th,
.card-rich-editor .toastui-editor-contents td {
  border-color: var(--editor-line);
}
.card-rich-editor .toastui-editor-contents th {
  background: var(--editor-bg-soft);
}
.card-rich-editor .toastui-editor-md-container .toastui-editor,
.card-rich-editor .toastui-editor-md-container .toastui-editor * {
  color: var(--editor-ink);
}
.card-rich-editor .toastui-editor-md-delimiter,
.card-rich-editor .toastui-editor-md-meta,
.card-rich-editor .toastui-editor-md-block-quote,
.card-rich-editor .toastui-editor-md-table,
.card-rich-editor .toastui-editor-md-thematic-break {
  color: var(--editor-muted);
}
.card-rich-editor .toastui-editor-md-link,
.card-rich-editor .toastui-editor-md-link-url,
.card-rich-editor .toastui-editor-md-link-desc {
  color: var(--editor-accent);
}
.card-rich-editor .toastui-editor-md-splitter {
  background: var(--editor-line);
}
.card-rich-editor .toastui-editor-defaultUI button,
.card-rich-editor .toastui-editor-defaultUI-toolbar button {
  min-height: 0;
  border: 1px solid transparent;
  border-radius: 6px;
  background-color: transparent;
  color: var(--editor-ink);
  box-shadow: none;
}
.card-rich-editor .toastui-editor-defaultUI-toolbar button {
  width: 30px;
  height: 30px;
  margin: 0;
  padding: 0;
  opacity: 0.82;
}
.card-rich-editor .toastui-editor-defaultUI-toolbar button:not(:disabled):hover,
.card-rich-editor .toastui-editor-defaultUI-toolbar button.active {
  border-color: var(--editor-line-strong);
  background-color: var(--editor-bg-raised);
  opacity: 1;
}
.card-rich-editor .toastui-editor-defaultUI-toolbar button:focus-visible {
  outline: none;
  box-shadow: 0 0 0 3px rgba(125,211,252,0.18);
}
.card-rich-editor .toastui-editor-mode-switch {
  height: 34px;
  padding: 4px 8px;
  background: var(--editor-bg-soft);
  border-top: 1px solid var(--editor-line);
  text-align: right;
}
.card-rich-editor .toastui-editor-mode-switch .tab-item {
  width: auto;
  min-width: 86px;
  height: 24px;
  margin: 0 0 0 4px;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: var(--editor-muted);
  line-height: 22px;
}
.card-rich-editor .toastui-editor-mode-switch .tab-item.active {
  border-color: var(--editor-line-strong);
  background: var(--editor-bg-raised);
  color: var(--editor-ink);
}
.card-rich-editor .toastui-editor-defaultUI .toastui-editor-md-tab-container {
  height: 38px;
  background: var(--editor-bg-soft);
  border-color: var(--editor-line);
}
.card-rich-editor .toastui-editor-md-tab-container .toastui-editor-tabs {
  margin-left: 10px;
}
.card-rich-editor .toastui-editor-md-tab-container .tab-item {
  width: auto;
  min-width: 72px;
  height: 28px;
  margin-top: 10px;
  border-color: var(--editor-line);
  border-radius: 6px 6px 0 0;
  background: color-mix(in srgb, var(--editor-bg-soft) 84%, var(--editor-bg-raised) 16%);
  color: var(--editor-muted);
  line-height: 27px;
}
.card-rich-editor .toastui-editor-md-tab-container .tab-item.active {
  border-bottom-color: var(--editor-bg);
  background: var(--editor-bg);
  color: var(--editor-ink);
}
.card-rich-editor .toastui-editor-popup,
.card-rich-editor .toastui-editor-dropdown-toolbar {
  border-color: var(--editor-line);
  background: var(--editor-bg-soft);
  color: var(--editor-ink);
  box-shadow: 0 12px 32px rgba(0,0,0,0.28);
}
.card-rich-editor .toastui-editor-popup-body label,
.card-rich-editor .toastui-editor-popup-body .toastui-editor-table-description {
  color: var(--editor-ink);
}
.card-rich-editor .toastui-editor-popup-body input[type="text"],
.card-rich-editor .toastui-editor-popup-add-image .toastui-editor-file-name {
  border-color: var(--editor-line);
  background: var(--editor-bg);
  color: var(--editor-ink);
}
.card-rich-editor .toastui-editor-popup-body input[type="text"]:focus {
  outline: 1px solid var(--editor-accent);
}
.card-rich-editor .toastui-editor-popup-add-image .toastui-editor-tabs .tab-item {
  color: var(--editor-muted);
  border-bottom-color: var(--editor-line);
}
.card-rich-editor .toastui-editor-popup-add-image .toastui-editor-tabs .tab-item.active {
  color: var(--editor-accent);
  border-bottom-color: var(--editor-accent);
}
.card-detail-form-actions {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 8px;
}
.card-detail-edit-status {
  padding: 8px 10px;
  border: 1px solid color-mix(in srgb, var(--warning, #f59e0b) 42%, var(--border, var(--cx-line)));
  border-radius: 8px;
  background: color-mix(in srgb, var(--warning-soft, #fff8e5) 28%, transparent);
  color: var(--text, var(--cx-ink));
  font-size: 12px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}
/* Card detail forms inherit the shared workflow grid. Keep these actions
 * compact while preserving the global CTA treatment elsewhere. */
.card-detail-form-actions .primary,
.card-detail-form-actions .secondary {
  min-height: 34px;
  padding: 6px 14px;
  border-radius: 8px;
  box-shadow: none;
}
.card-detail-form-actions .primary:hover {
  box-shadow: none;
}
@media (max-width: 900px) {
  .card-detail-overlay {
    padding: 16px 10px;
  }
  .card-detail-popup {
    height: calc(100vh - 32px);
    max-height: calc(100vh - 32px);
  }
  .card-detail-overlay.is-docked {
    padding: 0;
  }
  .card-detail-popup.is-docked {
    width: 100vw !important;
    height: 100vh;
    max-height: 100vh;
  }
  .card-detail-layout {
    grid-template-columns: 1fr;
    overflow: auto;
  }
  .card-detail-main,
  .card-detail-sidebar {
    overflow: visible;
  }
  .card-detail-sidebar {
    border-left: 0;
    border-top: 1px solid var(--border, var(--cx-line));
  }
}
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
  align-content: start;
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
  .board-grid { margin-inline: -4px; padding-inline: 4px; }
  .board-column { flex-basis: min(82vw, 320px); width: min(82vw, 320px); min-width: min(82vw, 320px); }
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
  --layer-sticky: 10;
  --layer-local-scrim: 30;
  --layer-local-popover: 40;
  --layer-chrome: 100;
  --layer-global-scrim: 150;
  --layer-global-popover: 160;
  --layer-modal: 300;
  --layer-toast: 400;
  --layer-drag-shield: 900;
}

:root,
[data-theme="light"] {
  --bg: #f6eee7;
  --bg-elev: #ece2d9;
  --surface: rgba(255, 250, 245, 0.94);
  --surface-solid: #fffaf5;
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

  --nav-bg: #fff9f3;
  --nav-bg-2: #f2e8df;
  --nav-soft: rgba(255, 255, 255, 0.68);
  --nav-border: #dfcec1;
  --nav-text: #2f2723;
  --nav-muted: #7a6c64;
  --nav-label: #9b8c84;
  --nav-input-bg: rgba(255, 250, 245, 0.86);
  --nav-input-border: #d8c7bb;
}

[data-theme="dark"],
[data-theme="night"] {
  --bg: #101722;
  --bg-elev: #223041;
  --surface: rgba(27, 36, 48, 0.94);
  --surface-solid: #1b2430;
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

.card-detail-discussion-section {
  min-height: 0;
}

.discussion-shell.embedded,
.discussion-shell.embedded.left-collapsed,
.discussion-shell.embedded.right-collapsed,
.discussion-shell.embedded.left-collapsed.right-collapsed {
  grid-template-columns: minmax(0, 1fr);
  grid-template-rows: minmax(0, 1fr) auto;
  height: 100%;
  min-height: 0;
  padding: 0;
  gap: 8px;
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

.discussion-shell.embedded .discussion-main-panel {
  grid-column: 1;
  grid-row: 1;
}

.discussion-shell.embedded .discussion-chat-head {
  display: none;
}

.discussion-composer {
  grid-column: 2;
  grid-row: 2;
  display: grid;
  gap: 10px;
  padding: 12px;
}

.discussion-shell.embedded .discussion-composer {
  grid-column: 1;
  grid-row: 2;
  padding: 0;
  border: 0;
  border-radius: 0;
  background: transparent;
  box-shadow: none;
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
  position: relative;
  z-index: var(--layer-local-popover);
  display: flex;
  flex-direction: column;
  gap: 2px;
  margin-top: 6px;
  padding: 4px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-solid, var(--surface));
  box-shadow: var(--shadow-sm);
  max-height: 220px;
  overflow-y: auto;
}

.mention-picker {
  min-width: 0;
}

.mention-picker-head {
  display: flex;
  align-items: center;
  gap: 6px;
}

.mention-picker-query {
  min-width: 0;
  flex: 1 1 auto;
}

.mention-suggestion,
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
  min-width: 0;
}

.mention-suggestion:hover,
.mention-suggestion:focus-visible,
.mention-suggestion-item:hover,
.mention-suggestion-item:focus-visible {
  background: var(--surface-2, color-mix(in srgb, var(--accent) 10%, transparent));
  outline: none;
}

.mention-suggestion-name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
}

.discussion-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: var(--layer-modal);
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
  background: var(--surface-solid, var(--surface));
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

/* T7.2: watch level dropdown */
.watch-level-picker {
  position: relative;
}
.watch-level-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 10px;
  font-size: 13px;
}
.watch-level-toggle-caret {
  font-size: 10px;
  opacity: 0.7;
}
.watch-level-menu {
  position: absolute;
  right: 0;
  top: calc(100% + 4px);
  min-width: 200px;
  background: var(--surface-solid, var(--surface, #fff));
  border: 1px solid var(--border, #cbd5df);
  border-radius: 8px;
  box-shadow: var(--shadow-sm, 0 1px 2px rgba(0,0,0,0.08));
  padding: 4px;
  z-index: var(--layer-local-popover);
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.watch-level-option {
  display: block;
  width: 100%;
  text-align: left;
  padding: 8px 10px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text, #142018);
  cursor: pointer;
  font-size: 13px;
}
.watch-level-option:hover,
.watch-level-option:focus-visible {
  background: color-mix(in srgb, var(--accent, #1f6b4f) 12%, transparent);
  outline: none;
}
.watch-level-option.active {
  background: color-mix(in srgb, var(--accent, #1f6b4f) 18%, transparent);
  font-weight: 600;
}

/* T7.3: handle reassigned badge + binding context */
.handle-reassigned-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  background: rgba(198, 73, 64, 0.14);
  color: #a23a32;
  border: 1px solid rgba(198, 73, 64, 0.32);
  border-radius: 4px;
  padding: 1px 6px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.02em;
  text-transform: uppercase;
  cursor: help;
}
.binding-context {
  font-size: 12px;
  color: var(--muted, #627065);
}
.binding-context-host {
  opacity: 0.85;
}

/* T7.4: E2EE message status row */
.crypto-status-row {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  margin-top: 4px;
}
.crypto-status-icon {
  font-size: 14px;
}
.crypto-status-decrypting {
  color: var(--muted, #627065);
  font-style: italic;
}
.crypto-status-failed {
  color: #a23a32;
}
.crypto-status-key-missing {
  color: #8a5a10;
}
.crypto-status-needs-verification {
  color: #8a5a10;
}
.discussion-message.is-crypto-pending .msg-content {
  opacity: 0.55;
  filter: grayscale(0.4);
}
.crypto-status-action {
  background: transparent;
  border: 0;
  color: var(--accent, #1f6b4f);
  text-decoration: underline;
  cursor: pointer;
  padding: 0;
  font-size: 12px;
}

/* T7.5: tabbed right panel + mobile drawer */
.discussion-right-tabs {
  display: flex;
  gap: 4px;
  border-bottom: 1px solid var(--border, #cbd5df);
  margin: 0 -14px 12px;
  padding: 0 14px;
}
.discussion-right-tab {
  border: 0;
  border-bottom: 2px solid transparent;
  background: transparent;
  padding: 8px 10px;
  font-size: 13px;
  font-weight: 600;
  color: var(--muted, #627065);
  cursor: pointer;
}
.discussion-right-tab.active {
  color: var(--text, #142018);
  border-bottom-color: var(--accent, #1f6b4f);
}

@media (max-width: 768px) {
  .watch-level-menu { left: 0; right: auto; }
  .discussion-details-panel {
    position: fixed;
    inset: auto 0 0 0;
    max-height: 70vh;
    border-radius: 14px 14px 0 0;
    z-index: var(--layer-local-popover);
    background: var(--surface-solid, var(--surface));
    box-shadow: 0 -8px 24px rgba(0,0,0,0.18);
    overflow-y: auto;
  }
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

/* CXP-0007 P3B.2.4 — Circle-scope accent rail on Circle-scoped messages. */
.discussion-message.has-circle-accent-rail {
  position: relative;
  padding-left: 10px;
}

.discussion-message.has-circle-accent-rail .circle-accent-rail {
  position: absolute;
  left: 0;
  top: 4px;
  bottom: 4px;
  width: 3px;
  border-radius: 3px;
  background: var(--accent, #1f6b4f);
  cursor: help;
}

.discussion-message.has-circle-accent-rail .circle-accent-rail:hover {
  background: color-mix(in srgb, var(--accent, #1f6b4f) 85%, #18212f);
}

/* CXP-0007 P3B.2.3 — composer banner colour tokens. */
.circle-composer-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  margin-bottom: 8px;
  border: 1px solid color-mix(in srgb, var(--accent, #1f6b4f) 35%, var(--border, #d8e0e8));
  border-radius: 8px;
  background: color-mix(in srgb, var(--accent, #1f6b4f) 10%, var(--surface, #ffffff));
}

.circle-composer-banner .banner-icon {
  font-size: 18px;
}

.circle-composer-banner .banner-body {
  display: grid;
  gap: 2px;
}

.mention-token {
  display: inline-flex;
  align-items: center;
  max-width: 100%;
  margin: 0 1px;
  padding: 1px 6px;
  border: 1px solid transparent;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 800;
  line-height: 1.45;
  vertical-align: baseline;
  white-space: nowrap;
}
.mention-token.is-local {
  border-color: color-mix(in srgb, #22c55e 42%, var(--border));
  background: color-mix(in srgb, #22c55e 18%, transparent);
  color: #bbf7d0;
}
.mention-token.is-remote {
  border-color: color-mix(in srgb, var(--accent) 64%, var(--border));
  background: color-mix(in srgb, var(--accent) 24%, transparent);
  color: var(--accent-ink);
}

.message-failure-icon,
.message-status-icon {
  display: inline-grid;
  place-items: center;
  color: var(--danger-ink);
  line-height: 1;
}
.message-status-icon {
  width: 16px;
  height: 16px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 900;
}
.message-status-icon.is-pending {
  border: 2px solid color-mix(in srgb, var(--accent) 72%, var(--border));
  border-right-color: transparent;
  color: transparent;
  animation: message-send-spin 760ms linear infinite;
}
.message-status-icon.is-failed {
  background: var(--danger);
  color: var(--text-on-accent);
}
@keyframes message-send-spin {
  to {
    transform: rotate(360deg);
  }
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

.discussion-composer .compose-drop-zone {
  display: grid;
  gap: 8px;
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--surface-2) 44%, var(--surface));
}

.discussion-composer .compose-drop-zone:focus-within {
  border-color: color-mix(in srgb, var(--accent) 72%, var(--border));
  background: color-mix(in srgb, var(--accent-soft) 22%, var(--surface));
}

.discussion-composer .compose-drop-zone textarea {
  width: 100%;
  min-height: 74px;
  max-height: 180px;
  padding: 0;
  border: 0;
  border-radius: 0;
  background: transparent;
  color: var(--text);
  resize: vertical;
  outline: none;
  box-shadow: none;
}

.discussion-composer .mention-chip-row {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 6px;
}

.composer-tool-button {
  width: 30px;
  height: 30px;
  min-width: 30px;
  min-height: 30px;
  display: inline-grid;
  place-items: center;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: 7px;
  background: var(--surface);
  color: var(--text-2);
  cursor: pointer;
}

.composer-tool-button:hover,
.composer-tool-button:focus-visible {
  border-color: color-mix(in srgb, var(--accent) 64%, var(--border));
  color: var(--accent-ink);
  outline: none;
}

.discussion-composer .attachment-menu {
  position: absolute;
  left: 38px;
  bottom: calc(100% + 6px);
  z-index: var(--layer-local-popover);
  min-width: 180px;
  display: grid;
  gap: 4px;
  padding: 6px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-solid, var(--surface));
  box-shadow: var(--shadow-md);
}

.discussion-composer > .actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.discussion-shell.embedded .discussion-composer {
  position: relative;
}

.discussion-shell.embedded .discussion-composer .mention-chip-row {
  min-height: 30px;
  padding-right: 80px;
}

.discussion-shell.embedded .discussion-composer > .actions {
  height: 0;
  min-height: 0;
  margin-top: -48px;
  padding: 0 10px;
  justify-content: flex-end;
  overflow: visible;
  pointer-events: none;
  position: relative;
  z-index: 1;
}

.discussion-shell.embedded .discussion-composer > .actions > button {
  pointer-events: auto;
}

.discussion-shell.embedded .discussion-composer > .actions > button:not([data-testid="send-chat-button"]),
.discussion-shell.embedded .compose-security-panel,
.discussion-shell.embedded [data-testid="send-e2ee-move-button"] {
  display: none;
}

.compose-security-panel {
  width: 100%;
}

.compose-security-panel > summary {
  width: max-content;
  cursor: pointer;
  color: var(--text-2);
  font-size: 12px;
  font-weight: 700;
}

.compose-security-grid {
  display: grid;
  grid-template-columns: minmax(180px, 1fr) auto auto minmax(160px, 1fr) minmax(120px, 0.8fr) auto auto;
  gap: 8px;
  margin-top: 8px;
}

.compose-security-grid input {
  min-width: 0;
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
  color: var(--text);
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
  min-width: 0;
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
  min-width: 0;
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

.auth-primary {
  justify-self: stretch;
  width: 100%;
}

.auth-passkey {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
  min-width: 0;
}

.auth-passkey .primary,
.auth-passkey .secondary {
  width: 100%;
  min-width: 0;
  box-shadow: none;
}

.auth-session-state {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 5px;
  min-width: 0;
  overflow: hidden;
  padding: 10px 12px;
  border: 1px solid color-mix(in srgb, var(--border) 76%, transparent);
  border-radius: 8px;
  background: color-mix(in srgb, var(--surface-2) 68%, transparent);
  color: var(--text-3);
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.35;
}

.auth-session-state [data-testid^="session-"] {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.auth-session-state [data-testid="session-status"] {
  color: var(--text-2);
  font-family: var(--font-sans);
  font-size: 12px;
  font-weight: 700;
}

.auth-session-state .ghost {
  appearance: none;
  justify-self: start;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 30px;
  margin-top: 2px;
  padding: 5px 10px;
  border: 1px solid var(--border-strong);
  border-radius: 6px;
  background: transparent;
  color: var(--text-2);
  font: inherit;
  font-family: var(--font-sans);
  font-size: 12px;
  font-weight: 700;
}

.auth-session-state .ghost:hover {
  background: var(--hover);
  color: var(--text);
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

.shell.app > .sidebar {
  grid-column: 1;
  grid-row: 1;
}

.shell.app > .workspace {
  grid-column: 2;
  grid-row: 1;
}

.shell.app.rtl {
  direction: ltr;
  grid-template-columns: minmax(0, 1fr) var(--sidebar-w);
}

.shell.app.rtl > .sidebar {
  grid-column: 2;
}

.shell.app.rtl > .workspace {
  grid-column: 1;
}
.shell.app.rtl .sidebar,
.shell.app.rtl .workspace,
.shell.app.rtl .mobile-shellbar,
.shell.app.rtl .mobile-drawer {
  direction: rtl;
}

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
  z-index: var(--layer-sticky);
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
  z-index: var(--layer-drag-shield);
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

/* Prominent CTA for "create a new Realm" in the Realms & Spaces
 * sidebar header. The tiny 16px `.add` button blended into the
 * label and most users never noticed it; this variant matches the
 * brand-yellow primary button styling so it reads as the primary
 * call to action for the whole section. SVG icon (UiIcon "plus")
 * keeps the affordance crisp at all DPRs.
 */
.sidebar-nav-group-title .add-realm-cta {
  margin-left: auto;
  width: 28px;
  height: 28px;
  border-radius: 6px;
  display: inline-grid;
  place-items: center;
  color: #1a1a1a;
  background: linear-gradient(135deg, #ffb547 0%, #ff8a3d 100%);
  border: 1px solid color-mix(in srgb, #ff8a3d 60%, transparent);
  box-shadow: 0 1px 0 rgba(0, 0, 0, 0.15), 0 4px 10px rgba(255, 138, 61, 0.18);
  text-decoration: none;
  transition: transform 80ms ease, box-shadow 80ms ease, filter 80ms ease;
}
.sidebar-nav-group-title .add-realm-cta svg {
  width: 16px;
  height: 16px;
}
.sidebar-nav-group-title .add-realm-cta:hover,
.sidebar-nav-group-title .add-realm-cta:focus-visible {
  transform: translateY(-1px);
  filter: brightness(1.05);
  box-shadow: 0 2px 0 rgba(0, 0, 0, 0.2), 0 6px 14px rgba(255, 138, 61, 0.28);
  outline: none;
}
.sidebar-nav-group-title .add-realm-cta:active {
  transform: translateY(0);
  filter: brightness(0.96);
  box-shadow: 0 1px 0 rgba(0, 0, 0, 0.18);
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

/* Per-row sidebar action layout: the main Link spans most of the
 * row, the inline "+ add child Space" action sits to the right of
 * it and stays out of the way until hover. Both share the row's
 * background hover state so the affordance is visually unified. */
.sidebar-row {
  display: flex;
  align-items: stretch;
  gap: 2px;
}
.sidebar-row-main {
  flex: 1 1 auto;
  min-width: 0;
}
.sidebar-row-add-action {
  flex: 0 0 auto;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  padding: 0;
  margin: 6px 6px 6px 0;
  border-radius: 6px;
  /* Resting state uses a translucent brand tint so the affordance
   * is discoverable but not loud — at full opacity on hover the
   * button promotes to the same yellow CTA as the header "+R". */
  background: color-mix(in srgb, #ff8a3d 18%, transparent);
  border: 1px solid color-mix(in srgb, #ff8a3d 32%, transparent);
  color: #ffb547;
  text-decoration: none;
  opacity: 0;
  transition: opacity 80ms ease, background-color 80ms ease,
              color 80ms ease, transform 80ms ease,
              box-shadow 80ms ease, filter 80ms ease;
}
.sidebar-row-add-action svg {
  width: 14px;
  height: 14px;
}
.sidebar-row:hover .sidebar-row-add-action,
.sidebar-row:focus-within .sidebar-row-add-action {
  opacity: 1;
}
.sidebar-row-add-action:hover,
.sidebar-row-add-action:focus-visible {
  background: linear-gradient(135deg, #ffb547 0%, #ff8a3d 100%);
  border-color: color-mix(in srgb, #ff8a3d 70%, transparent);
  color: #1a1a1a;
  transform: translateY(-1px);
  box-shadow: 0 1px 0 rgba(0, 0, 0, 0.15), 0 4px 10px rgba(255, 138, 61, 0.22);
  outline: none;
}
.sidebar-row-add-action:active {
  transform: translateY(0);
  filter: brightness(0.96);
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

.sidebar-nav-icon.realm-security-secure {
  color: var(--success, #1f7a4d);
}

.sidebar-nav-icon.realm-security-unsafe {
  color: var(--danger, #b42318);
}

.sidebar-nav-item:hover .sidebar-nav-icon.realm-security-secure,
.sidebar-nav-item.is-active .sidebar-nav-icon.realm-security-secure {
  color: var(--success, #1f7a4d);
}

.sidebar-nav-item:hover .sidebar-nav-icon.realm-security-unsafe,
.sidebar-nav-item.is-active .sidebar-nav-icon.realm-security-unsafe {
  color: var(--danger, #b42318);
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
  position: relative;
  z-index: var(--layer-chrome);
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
  align-items: center;
  min-width: 0;
  container: workspace-header / inline-size;
}

.topbar-left {
  grid-column: 1;
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 10px;
  justify-self: stretch;
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

.workspace-header .actions > .topbar-command-search {
  flex: 0 1 auto;
  min-width: 0;
}

.topbar-left > .sidebar-collapse-toggle {
  margin-inline-end: 4px;
  flex-shrink: 0;
}

.topbar-context {
  flex: 1 1 auto;
  min-width: 0;
  max-width: 100%;
  overflow: hidden;
  display: flex;
  align-items: center;
  gap: 8px;
}

.topbar-context > * {
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.topbar-context-title {
  flex: 1 1 auto;
  color: var(--text);
  font-weight: 750;
}

.topbar-current-surface {
  display: none;
  align-items: center;
  gap: 5px;
  min-width: 0;
  flex: 0 0 auto;
  border: 1px solid color-mix(in srgb, var(--accent) 34%, var(--border));
  border-radius: 999px;
  padding: 3px 8px;
  color: var(--text);
  background: color-mix(in srgb, var(--accent) 12%, var(--surface));
  font-size: 11px;
  font-weight: 750;
}

.topbar-current-surface .ui-icon {
  width: 13px;
  height: 13px;
  color: var(--accent);
}

.space-context-bar {
  grid-column: 2;
  justify-self: center;
  flex: 0 0 auto;
  min-width: 0;
}

.space-nav-inline {
  align-items: center;
  gap: 8px;
  flex-wrap: nowrap;
}

.space-nav-inline .primary,
.space-nav-inline .secondary {
  min-height: 34px;
  padding: 0 12px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border-radius: 8px;
  white-space: nowrap;
}

.space-nav-inline .ui-icon {
  width: 16px;
  height: 16px;
}

.space-nav-menu-host {
  position: relative;
  display: none;
}

.space-nav-menu-button {
  position: relative;
  width: 36px;
  min-width: 36px;
  height: 34px;
  min-height: 34px;
  border-color: color-mix(in srgb, var(--accent) 40%, var(--border));
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--accent) 18%, var(--surface)), var(--surface));
  color: var(--accent);
}

.space-nav-menu-button::after {
  content: "";
  position: absolute;
  right: 6px;
  bottom: 6px;
  width: 5px;
  height: 5px;
  border-radius: 999px;
  background: var(--accent-2);
  box-shadow: 0 0 0 2px var(--surface);
}

.space-nav-menu-host.is-open .space-nav-menu-button {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 16%, transparent);
}

.space-nav-menu-scrim {
  position: fixed;
  inset: 0;
  z-index: var(--layer-local-popover);
  border: 0;
  padding: 0;
  background: transparent;
  cursor: default;
}

.space-nav-menu-panel {
  position: absolute;
  top: calc(100% + 8px);
  left: 50%;
  z-index: calc(var(--layer-local-popover) + 1);
  width: 190px;
  transform: translateX(-50%);
  display: grid;
  gap: 4px;
  padding: 6px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface-solid, var(--surface));
  box-shadow: var(--shadow-lg);
}

.space-nav-menu-item {
  min-height: 36px;
  display: flex;
  align-items: center;
  gap: 9px;
  border: 1px solid transparent;
  border-radius: 7px;
  padding: 0 10px;
  color: var(--text);
  background: transparent;
  font-size: 13px;
  font-weight: 700;
  text-align: left;
  text-decoration: none;
  cursor: pointer;
}

.space-nav-menu-item:hover,
.space-nav-menu-item:focus-visible {
  outline: none;
  border-color: color-mix(in srgb, var(--accent) 34%, transparent);
  background: color-mix(in srgb, var(--accent) 10%, var(--surface));
}

.space-nav-menu-item.is-active {
  color: var(--text);
  border-color: color-mix(in srgb, var(--accent) 44%, var(--border));
  background: color-mix(in srgb, var(--accent) 16%, var(--surface));
}

.space-nav-menu-item:disabled {
  color: var(--text-3);
  cursor: not-allowed;
  opacity: 0.58;
}

.space-nav-menu-item .ui-icon {
  width: 16px;
  height: 16px;
  color: var(--accent);
}

.workspace-header > .actions {
  grid-column: 3;
  justify-self: end;
}

@container workspace-header (max-width: 940px) {
  .workspace-header .space-nav-inline {
    display: none;
  }

  .workspace-header .space-nav-menu-host {
    display: block;
  }

  .workspace-header .topbar-current-surface {
    display: inline-flex;
  }

  .workspace-header .topbar-context-pill.muted {
    display: none;
  }
}

@container workspace-header (max-width: 700px) {
  .workspace-header .topbar-current-surface-label {
    display: none;
  }

  .workspace-header .space-nav-menu-panel {
    left: auto;
    right: 0;
    transform: none;
  }
}

.topbar-context-pill {
  flex: 0 0 auto;
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 3px 8px;
  color: var(--text-2);
  background: var(--surface-2);
  font-size: 11px;
  font-weight: 700;
}

.topbar-context-pill.muted {
  color: var(--text-3);
  background: transparent;
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

.topbar-command-search {
  position: relative;
  display: inline-flex;
  align-items: center;
}

.topbar-command-search.is-open {
  width: min(34vw, 360px);
  min-width: 260px;
}

.topbar-command-search-field {
  width: 100%;
  height: 34px;
  display: flex;
  align-items: center;
  gap: 8px;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0 7px 0 10px;
  background: var(--surface);
  color: var(--text-2);
}

.topbar-command-search-field:focus-within {
  border-color: color-mix(in srgb, var(--accent) 72%, var(--border));
  background: color-mix(in srgb, var(--accent-soft) 18%, var(--surface));
}

.topbar-command-search input {
  flex: 1 1 auto;
  min-width: 0;
  height: 100%;
  border: 0;
  padding: 0;
  background: transparent;
  color: var(--text);
  outline: none;
  font-size: 12px;
}

.topbar-command-search kbd {
  flex: 0 0 auto;
}

.topbar-command-search .command-palette {
  left: auto;
  right: 0;
  top: calc(100% + 8px);
  width: min(420px, calc(100vw - 32px));
  z-index: var(--layer-global-popover);
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

.account-menu-scrim {
  position: fixed;
  inset: -100vmax;
  z-index: var(--layer-global-scrim);
  background: transparent;
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
  z-index: var(--layer-global-popover);
  width: min(420px, 92vw);
  display: grid;
  gap: 10px;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-solid, var(--surface));
  color: var(--text);
  box-shadow: var(--shadow-lg);
  backdrop-filter: blur(18px);
  isolation: isolate;
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
  align-items: center;
  font-size: 12px;
}

.account-menu__row strong {
  color: var(--text-3);
  font-size: 11px;
  letter-spacing: 0.06em;
}

.account-menu__row > span,
.account-menu__value span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.account-menu__value {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.account-menu__copy {
  flex: 0 0 auto;
  width: 28px;
  height: 28px;
  padding: 0;
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
  flex-direction: column;
  gap: 0;
  min-width: 0;
  min-height: 0;
  height: 100vh;
  overflow: hidden;
}

.topbar.workspace-header {
  flex: 0 0 auto;
  margin: 0;
  border-radius: 0;
  box-shadow: none;
  align-items: center;
  justify-content: flex-start;
  gap: 10px;
  overflow: visible;
}

.workspace-body {
  flex: 1 1 auto;
  min-width: 0;
  min-height: 0;
  overflow: auto;
  padding: 16px;
}

.workspace-body > .timeline {
  overflow: visible;
  align-content: start;
  gap: 16px;
}

.workspace-body > .timeline.kanban-panel {
  display: flex;
  flex-direction: column;
  min-height: 100%;
  overflow: hidden;
  gap: 10px;
  background: var(--bg);
}

.workspace-body:has(> .timeline):has(> .composer[data-testid="composer"]) {
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.workspace-body:has(> .timeline):has(> .composer[data-testid="composer"]) > .timeline {
  flex: 1 1 auto;
  min-height: 0;
  overflow: auto;
}

.workspace-body:has(> .timeline):has(> .composer[data-testid="composer"]) > .composer[data-testid="composer"] {
  flex: 0 0 auto;
  margin-top: 16px;
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

.shell.app.theme-light {
  color-scheme: light;
}

.shell.app.theme-night {
  color-scheme: dark;
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
    --surface-solid: #1b2430;
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
  .topbar-context-pill.muted {
    display: none;
  }

  .topbar-command-search.is-open {
    width: min(32vw, 300px);
    min-width: 220px;
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
  .auth-form .actions,
  .auth-passkey {
    grid-template-columns: 1fr;
  }

  .shell.app {
    grid-template-columns: 1fr;
    height: 100vh;
  }

  .mobile-shellbar {
    height: var(--topbar-h);
    position: sticky;
    top: 0;
    z-index: var(--layer-chrome);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 0 12px;
    border-bottom: 1px solid var(--border);
    background: var(--surface-solid, var(--surface));
  }

  .mobile-shellbar .brand {
    font-size: 14px;
    font-weight: 700;
    color: var(--text);
  }

  .mobile-drawer {
    position: fixed;
    inset: var(--topbar-h) 0 auto 0;
    z-index: var(--layer-global-popover);
    display: none;
    flex-direction: column;
    gap: 8px;
    padding: 12px;
    border-bottom: 1px solid var(--border);
    background: var(--surface-solid, var(--surface));
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

  .shell.app > .workspace,
  .shell.app.rtl > .workspace {
    grid-column: 1;
    grid-row: 1;
  }

  .topbar-context-pill {
    display: none;
  }

  .topbar-command-search.is-open {
    width: min(58vw, 320px);
    min-width: 0;
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

  .workspace-body:has(> .kanban-panel) {
    overflow-y: auto;
    overflow-x: hidden;
    padding: 12px;
  }

  .workspace-body > .kanban-panel {
    overflow: visible;
  }

  .workspace-body > .timeline.kanban-panel {
    min-height: 0;
    overflow: visible;
  }

  .board-toolbar-main,
  .board-toolbar-controls,
  .board-list-compose {
    align-items: stretch;
    flex-direction: column;
    width: 100%;
  }

  .board-toolbar-controls > *,
  .board-list-compose > * {
    width: 100%;
    max-width: 100%;
  }

  .board-select-menu-host,
  .board-select-button,
  .board-list-compose input {
    width: 100%;
    min-width: 0;
    max-width: 100%;
  }

  .board-select-menu-panel {
    width: 100%;
    max-width: 100%;
  }

  .discussion-shell,
  .discussion-shell.left-collapsed,
  .discussion-shell.right-collapsed,
  .discussion-shell.left-collapsed.right-collapsed {
    grid-template-rows: minmax(0, 190px) minmax(180px, 28vh) auto;
  }

  .discussion-sidebar-panel {
    max-height: 190px;
  }

  .discussion-main-panel {
    min-height: 180px;
  }

  .discussion-composer {
    position: sticky;
    bottom: 0;
    z-index: var(--layer-sticky);
  }

  .compose-security-grid {
    grid-template-columns: 1fr;
  }
}

"#;

/// One-shot push-token provider bootstrap.
///
/// Runs once on first App render. On wasm32 we install
/// `WebPushTokenProvider::new()` (drives the service-worker +
/// `pushManager.subscribe` path described in `push.rs::WebPushTokenProvider`).
/// On native builds we install `FcmPushTokenProvider` / `ApnsPushTokenProvider`.
/// The host adapter supplies the actual OS token through
/// `set_fcm_push_token` / `set_apns_push_token` after Firebase/APNs returns
/// it; local dev can inject the same token via env vars. Subsequent renders
/// short-circuit via `OnceLock` semantics inside `set_push_token_provider`.
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
        // safe default. It reads `YOUGEN_FCM_PUSH_TOKEN`,
        // `FCM_PUSH_TOKEN`, or `CHASK_PUSH_KEY` for local bridge
        // testing, and otherwise reports "no token" without emitting a
        // placeholder to the gateway.
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

fn bool_field(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| value.get(*key)?.as_bool())
}

fn encryption_profile_is_encrypted(profile: &str) -> bool {
    let normalized = profile.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    !matches!(
        normalized.as_str(),
        "" | "none" | "plain" | "plaintext" | "unencrypted" | "disabled" | "off" | "false"
    )
}

fn plaintext_visibility_is_encrypted(visibility: &str) -> bool {
    let normalized = visibility
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    matches!(
        normalized.as_str(),
        "encrypted" | "e2ee" | "private_encrypted" | "mls" | "mls_rfc9420"
    )
}

fn plaintext_visibility_value(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| string_field(value, &["default", "mode", "visibility"]))
}

fn realm_projection_is_encrypted(body: &Value) -> bool {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    for container in [
        body,
        summary,
        body.get("object").unwrap_or(&Value::Null),
        body.get("realm").unwrap_or(&Value::Null),
        body.get("metadata").unwrap_or(&Value::Null),
    ] {
        if let Some(encrypted) = bool_field(
            container,
            &["encrypted", "is_encrypted", "e2ee", "end_to_end_encrypted"],
        ) {
            return encrypted;
        }
        if let Some(profile) = string_field(
            container,
            &["encryption_profile", "encryptionProfile", "encryption"],
        ) {
            return encryption_profile_is_encrypted(&profile);
        }
        if let Some(visibility) = container
            .get("plaintext_visibility")
            .and_then(plaintext_visibility_value)
        {
            return plaintext_visibility_is_encrypted(&visibility);
        }
    }

    for event in body
        .get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            body.get("state_after")
                .and_then(|state| state.get("events"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
    {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !kind.contains("realm.create") && !kind.contains("encryption") {
            continue;
        }
        for container in [
            event.get("payload").unwrap_or(&Value::Null),
            event
                .get("payload")
                .and_then(|payload| payload.get("object"))
                .unwrap_or(&Value::Null),
            event.get("content").unwrap_or(&Value::Null),
            event
                .get("content")
                .and_then(|content| content.get("object"))
                .unwrap_or(&Value::Null),
            event.get("object").unwrap_or(&Value::Null),
            event,
        ] {
            if let Some(profile) = string_field(
                container,
                &["encryption_profile", "encryptionProfile", "encryption"],
            ) {
                return encryption_profile_is_encrypted(&profile);
            }
        }
    }

    false
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
            if kind != "cx.realm.parent" {
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
        if kind != Some("cx.realm.child") {
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

fn browser_prefers_dark_theme() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|window| {
                window
                    .match_media("(prefers-color-scheme: dark)")
                    .ok()
                    .flatten()
            })
            .map(|query| query.matches())
            .unwrap_or(false)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}

fn browser_shell_color_scheme_is_dark() -> Option<bool> {
    #[cfg(target_arch = "wasm32")]
    {
        let window = web_sys::window()?;
        let document = window.document()?;
        let shell = document
            .query_selector("[data-testid=\"client-shell\"]")
            .ok()
            .flatten()?;
        let styles = window.get_computed_style(&shell).ok().flatten()?;
        let color_scheme = styles
            .get_property_value("color-scheme")
            .ok()?
            .to_ascii_lowercase();
        let has_dark = color_scheme.split_whitespace().any(|token| token == "dark");
        let has_light = color_scheme
            .split_whitespace()
            .any(|token| token == "light");
        if has_dark && !has_light {
            Some(true)
        } else if has_light && !has_dark {
            Some(false)
        } else {
            None
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

fn theme_renders_as_night(theme: &str, system_theme_is_night: bool) -> bool {
    theme == "night" || (theme == "system" && system_theme_is_night)
}

fn next_manual_theme(theme: &str) -> String {
    let is_night = if theme == "system" {
        browser_shell_color_scheme_is_dark().unwrap_or_else(browser_prefers_dark_theme)
    } else {
        theme == "night"
    };
    if is_night { "light" } else { "night" }.to_owned()
}

fn oidc_access_token_boot_usable(bundle: &OidcTokenBundle, now_unix: i64) -> bool {
    if bundle.access_token.trim().is_empty() {
        return false;
    }
    match bundle.expires_at_unix {
        Some(expires_at) => now_unix + BOOT_ACCESS_TOKEN_SKEW_SECS < expires_at,
        None => true,
    }
}

fn session_grant_access_token_boot_usable(
    grant: &PersistedSessionGrant,
    access_token: &str,
    now_unix: i64,
) -> bool {
    if access_token.trim().is_empty() {
        return false;
    }
    if grant
        .grant_expires_at
        .is_some_and(|expires_at| expires_at.timestamp() <= now_unix)
    {
        return false;
    }
    grant
        .session_expires_at
        .is_some_and(|expires_at| now_unix + BOOT_ACCESS_TOKEN_SKEW_SECS < expires_at.timestamp())
}

fn initial_session_token_from_state(
    local_state: &ClientLocalState,
    config: &ClientConfig,
    now_unix: i64,
) -> String {
    if let Some(bundle) = local_state.oidc_tokens.as_ref() {
        // Access tokens are short-lived cache material. On a hard page
        // reload, let the refresh-token/session-grant poller mint a fresh
        // bearer instead of racing boot API calls with an expired one.
        if oidc_access_token_boot_usable(bundle, now_unix) {
            return bundle.access_token.clone();
        }
    }
    if let Some(grant) = local_state.session_grant.as_ref() {
        return session_grant_access_token_boot_usable(grant, &config.session_token, now_unix)
            .then(|| config.session_token.clone())
            .unwrap_or_default();
    }
    if local_state.oidc_tokens.is_some() {
        return String::new();
    }
    config.session_token.clone()
}

fn has_bootstrap_refresh_material(store: &LocalStateStore, principal_server_url: &str) -> bool {
    let state = store.load();
    if state.oidc_tokens.is_some() {
        return true;
    }
    state.session_grant.as_ref().is_some_and(|grant| {
        crate::session_refresh::grant_matches_principal_server(grant, principal_server_url)
            && !crate::session_refresh::grant_is_dead(grant)
    })
}

#[component]
pub fn RouterView() -> Element {
    let initial_config = LocalConfigStore::default().load();
    let initial_state_store = LocalStateStore::default();
    let initial_local_state = initial_state_store.load();
    let initial_session_token = initial_session_token_from_state(
        &initial_local_state,
        &initial_config,
        chrono::Utc::now().timestamp(),
    );
    let initial_spaces = space_previews_from_sync_spaces(&initial_local_state.space_projections);
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
    // Move-into-signal initialisers. Each `use_signal(...)` runs once on
    // first render, so we pre-extract the fields and hand each closure a
    // ready-to-move `String` instead of repeatedly cloning the whole
    // `initial_config` struct.
    let initial_server_url = initial_config.server_url.clone();
    let initial_account_did = initial_config.account_did.clone();
    let initial_device_id = initial_config.device_id.clone();
    let base_url = use_signal(move || initial_server_url);
    let mut account_did = use_signal(move || initial_account_did);
    let device_id = use_signal(move || initial_device_id);
    let mut token = use_signal(move || initial_session_token);

    // Install the app-wide, single-flight bearer refresher exactly once.
    // Every auth-expired handler (connect, sync, chat send, Realm create,
    // the account-menu button, the background poller) re-mints through
    // this one closure via `crate::session::refresh_current_bearer()`, so
    // refresh policy lives in a single place and concurrent rollovers
    // coalesce instead of racing.
    use_hook(move || {
        crate::session::register_session_refresher(std::rc::Rc::new(move || {
            Box::pin(remint_principal_bearer(
                base_url,
                account_did,
                device_id,
                state_store,
                token,
                config_store,
            )) as crate::session::LocalRefreshFuture
        }));
    });

    let navigator = use_navigator();
    let route = use_route::<Route>();
    let mut view = use_signal(|| route.to_view());
    let mut status = use_signal(|| ConnectionState::Offline.label().to_owned());
    let initial_sync_cursor = initial_local_state
        .sync_cursor
        .clone()
        .unwrap_or_else(|| "-".to_owned());
    let initial_selected_space = initial_spaces
        .first()
        .map(|space| space.space_id.clone())
        .unwrap_or_default();
    let initial_draft = initial_spaces
        .first()
        .and_then(|space| initial_local_state.drafts.get(&space.space_id))
        .cloned()
        .unwrap_or_default();
    let initial_push_state =
        crate::push::push_status_label(initial_local_state.push_registration.as_ref());
    let initial_spaces_for_signal = initial_spaces.clone();
    let mut sync_cursor = use_signal(move || initial_sync_cursor);
    let mut selected_space = use_signal(move || initial_selected_space);
    let mut spaces = use_signal(move || initial_spaces_for_signal);
    let mut timeline = use_signal(Vec::<TimelineEvent>::new);
    let draft = use_signal(move || initial_draft);
    let mut device_queue = use_signal(|| 0usize);
    let push_state = use_signal(move || initial_push_state);
    let frontier_state = use_signal(|| "Not loaded".to_owned());
    let crypto_state = use_signal(|| "No authenticated session".to_owned());
    let network_state = use_signal(|| "offline".to_owned());
    let mut last_error = use_signal(|| Option::<String>::None);
    let server_description = use_signal(|| Option::<ServerDescription>::None);
    let server_probe_status = use_signal(|| "server not probed".to_owned());
    let locale = use_signal(move || initial_locale);
    #[cfg(target_arch = "wasm32")]
    {
        let mut state_store_for_secure_upgrade = state_store;
        use_future(move || async move {
            match crate::secure_key_store::upgrade_wasm_secure_key_store_async("yougen").await {
                Ok(Some(secure_store)) => {
                    let dpop_record = {
                        let store = state_store_for_secure_upgrade.read();
                        store.load_dpop_device_key_with_secure_store(secure_store.as_ref())
                    };
                    match dpop_record {
                        Ok(Some(record)) => {
                            if let Err(error) = state_store_for_secure_upgrade
                                .write()
                                .set_dpop_device_key_with_secure_store(
                                    Some(record),
                                    secure_store.as_ref(),
                                )
                            {
                                tracing::warn!(
                                    ?error,
                                    "IndexedDB DPoP key metadata refresh failed",
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(?error, "IndexedDB DPoP key load failed");
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(?error, "IndexedDB secure-key-store upgrade failed");
                }
            }
        });
    }
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
    let mut theme = use_signal(move || initial_theme);
    let system_theme_is_night = use_signal(browser_prefers_dark_theme);
    {
        let mut system_theme_is_night = system_theme_is_night;
        use_effect(move || {
            if theme() == "system"
                && let Some(is_night) = browser_shell_color_scheme_is_dark()
            {
                system_theme_is_night.set(is_night);
            }
        });
    }
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
    let mut topbar_search_expanded = use_signal(|| false);
    let mut sync_bootstrap_complete = use_signal(|| false);
    // A6.4 — `?` keyboard shortcut help overlay state.
    let mut shortcut_help_open = use_signal(|| false);
    let mut space_scope_mode = use_signal(move || initial_space_scope_mode);
    let mls_welcome_bootstrap_key_seen = use_signal(|| Option::<String>::None);
    // Step 3 of the account-MLS-secret auto-unlock flow: set by the bootstrap
    // effect when this device has no local account secret yet but the server
    // holds an `mls_account_secret` backup; consumed by `MlsUnlockPrompt`.
    let needs_mls_unlock = use_signal(|| false);
    let mls_unlock_detection_key_seen = use_signal(|| Option::<String>::None);

    // On first render with a live session, fetch the directory + sync so
    // the sidebar's Space list shows up after a page reload. The list
    // intentionally isn't persisted in localStorage — directory search
    // results live only in the in-memory `spaces` signal, so without
    // this kick we'd render "No spaces loaded" until the user clicks
    // Refresh.
    //
    // The flag is consumed only after we confirm base+session are both
    // populated. Otherwise a fresh user who lands without a session and
    // then signs in (on the same mount) would never auto-connect, since
    // the one-shot would have already been spent during the empty-session
    // first render.
    // Background session-refresh poller. Proactively re-mints the bearer
    // a little before it expires so requests rarely hit a cold 401. The
    // re-mint itself goes through the shared single-flight refresher
    // (`crate::session`), so this poller and any reactive 401-retry can
    // never fire two competing refreshes for the same rollover.
    use_future({
        let mut status = status;
        let mut last_error = last_error;
        let state_store = state_store;
        let account_did = account_did;
        let token = token;
        move || async move {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            loop {
                // Freshness gate — only re-mint when the active credential
                // is actually near expiry. We key off *both* signals and
                // refresh if either is due:
                //   * the OIDC access token's own `expires_at` (when the
                //     IdP advertised `expires_in`), and
                //   * the session grant's `session_expires_at`, which
                //     tracks the short-lived principal bearer itself.
                // The grant signal is what saves IdPs that omit
                // `expires_in` (where `due_for_refresh` can never fire) —
                // we still proactively refresh before the principal bearer
                // dies instead of waiting for a cold 401. (Read-only
                // borrow, dropped before any await, so concurrent
                // `state_store.write()` callers never hit
                // `AlreadyBorrowedMut`.)
                let due = {
                    let store = state_store.read();
                    let oidc_due = store
                        .load_oidc_tokens_with_secure_store(&account_did(), secure_store.as_ref())
                        .map(|bundle| crate::oidc::lifecycle::due_for_refresh(&bundle))
                        .unwrap_or(false);
                    let grant_due = matches!(
                        crate::session_refresh::refresh_decision(&store),
                        crate::session_refresh::RefreshDecision::Due
                    );
                    oidc_due || grant_due
                };
                if due {
                    if token().trim().is_empty() {
                        status.set("Restoring session...".to_owned());
                    }
                    match crate::session::refresh_current_bearer().await {
                        Some(_) => {
                            status.set("Online".to_owned());
                            last_error.set(None);
                        }
                        None => {
                            // Keep the current bearer alive; a reactive 401
                            // (or the login flow) handles a genuinely dead
                            // session. Surface the last issue for dev tools.
                            last_error.set(Some(
                                "background session refresh produced no new bearer".to_owned(),
                            ));
                        }
                    }
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

    // CXP-0007 P3B.4.3 — active multi-profile snapshot, threaded into
    // the sync engine context so the loop can detect a profile rotation
    // and exit cleanly. The shell is currently single-profile; the
    // signal stays default-empty until the account switcher writes to
    // it on the first user-driven add-account / switch action.
    let profiles_signal = use_signal(crate::config::MultiProfileConfig::default);

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
        let mut session = token();
        if !session.trim().is_empty() {
            let (has_oidc_bundle, stale_for_selected_server) = {
                let store = state_store.read();
                let has_oidc_bundle = store.oidc_tokens().is_some();
                let stale_grant = store
                    .session_grant()
                    .as_ref()
                    .map(|grant| {
                        !crate::session_refresh::grant_matches_principal_server(grant, &base)
                    })
                    .unwrap_or(false);
                (has_oidc_bundle, stale_grant)
            };
            let stale_for_selected_server = !has_oidc_bundle && stale_for_selected_server;
            if stale_for_selected_server {
                token.set(String::new());
                persist_config(
                    config_store,
                    base.clone(),
                    account_did(),
                    device_id(),
                    String::new(),
                );
                session.clear();
            }
        }
        let can_restore_session = {
            let store = state_store.read();
            has_bootstrap_refresh_material(&store, &base)
        };
        if !base.trim().is_empty() && (!session.trim().is_empty() || can_restore_session) {
            bootstrap_pending.set(false);
            sync_bootstrap_complete.set(false);
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
                    sync_bootstrap_complete,
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
        if base.trim().is_empty() || session.trim().is_empty() || !sync_bootstrap_complete() {
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
            profiles: profiles_signal,
        };
        spawn(async move {
            crate::sync_engine::run_sync_engine(current_gen, sync_generation, ctx).await;
        });
    });

    // D1: detect the account-MLS unlock requirement as soon as a logged-in
    // session finishes bootstrap, without waiting for the user to enter a
    // Space/Board/Document route that runs the per-space Welcome bootstrap.
    {
        let mut seen_detection_key = mls_unlock_detection_key_seen;
        let mut needs_mls_unlock = needs_mls_unlock;
        use_effect(move || {
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let generation = sync_generation();
            if session.trim().is_empty() {
                needs_mls_unlock.set(false);
                return;
            }
            if base.trim().is_empty()
                || actor.trim().is_empty()
                || device.trim().is_empty()
                || !sync_bootstrap_complete()
            {
                return;
            }
            let detection_key = format!("{generation}|{base}|{actor}|{device}");
            if seen_detection_key().as_deref() == Some(detection_key.as_str()) {
                return;
            }
            seen_detection_key.set(Some(detection_key));

            spawn(async move {
                let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
                let has_local_secret = crate::mls::runtime::load_device_snapshot_secret(
                    secure_store.as_ref(),
                    &actor,
                    &device,
                )
                .is_ok();
                if has_local_secret {
                    needs_mls_unlock.set(false);
                    return;
                }
                match crate::views::helpers::with_authed_api(&base, session, |api| async move {
                    crate::mls::account_recovery::fetch_mls_account_secret_backup(&api).await
                })
                .await
                {
                    Ok(Some(_)) => needs_mls_unlock.set(true),
                    Ok(None) => needs_mls_unlock.set(false),
                    Err(error) => {
                        tracing::warn!(
                            error = %error.display(),
                            "MLS account-secret login unlock detection failed"
                        );
                    }
                }
            });
        });
    }

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
    if let Some(route_space_id) = routed_space_id.as_deref()
        && remembered_space_id != route_space_id
    {
        selected_space.set(route_space_id.to_owned());
    }

    let active_server_description = server_description();
    let active_service_did = active_server_description
        .as_ref()
        .map(|description| description.service_did.as_str().to_owned())
        .unwrap_or_default();
    let has_session = !token().trim().is_empty();
    let active_server_label = normalize_server_url(&base_url());
    let account_did_value = account_did();
    let device_id_value = device_id();
    let account_did_label = short_protocol_id(&account_did_value);
    let device_id_label = short_protocol_id(&device_id_value);
    let account_label = if has_session {
        account_did_label.clone()
    } else {
        "Not signed in".to_owned()
    };
    let account_detail = if has_session {
        format!("device {device_id_label}")
    } else {
        "Refresh server metadata, then sign in".to_owned()
    };
    let frontier_label = frontier_state();
    let frontier_label_display = short_protocol_id(&frontier_label);
    let push_label = push_state();
    let crypto_label = crypto_state();
    let account_session_label = account_session_state();
    let queue_label = device_queue().to_string();
    let minimal_ready = profile_ready(active_server_description.as_ref(), PROFILE_MINIMAL_CLIENT);
    let kanban_ready = profile_ready(active_server_description.as_ref(), PROFILE_KANBAN_MVP);
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
    {
        let bootstrap_route_uses_space_context = route_uses_space_context;
        let bootstrap_context_space_id = context_space_id.clone();
        let mut seen_bootstrap_key = mls_welcome_bootstrap_key_seen;
        let state_store_for_bootstrap = state_store;
        let crypto_state_for_bootstrap = crypto_state;
        let last_error_for_bootstrap = last_error;
        let mut needs_mls_unlock_for_bootstrap = needs_mls_unlock;
        use_effect(move || {
            let selected = selected_space();
            if !bootstrap_route_uses_space_context {
                return;
            }
            let bootstrap_space_id = bootstrap_context_space_id
                .clone()
                .filter(|space| !space.trim().is_empty())
                .unwrap_or(selected);
            let base = base_url();
            let session = token();
            let actor = account_did();
            let device = device_id();
            let description = server_description();
            let Some(bootstrap_key) = mls_welcome_bootstrap_key(
                &base,
                &session,
                &actor,
                &device,
                &bootstrap_space_id,
                profile_ready(description.as_ref(), PROFILE_E2EE_CLIENT),
                sync_bootstrap_complete(),
            ) else {
                return;
            };
            if seen_bootstrap_key().as_deref() == Some(bootstrap_key.as_str()) {
                return;
            }
            seen_bootstrap_key.set(Some(bootstrap_key));

            let state_store_task = state_store_for_bootstrap;
            let mut crypto_state_task = crypto_state_for_bootstrap;
            let mut last_error_task = last_error_for_bootstrap;
            let space_label = short_protocol_id(&bootstrap_space_id);
            // Detection-step clones: the originals are moved into the Welcome
            // bootstrap call below; we reuse these for the account-secret
            // unlock probe afterwards.
            let detect_base = base.clone();
            let detect_session = session.clone();
            let detect_actor = actor.clone();
            let detect_device = device.clone();
            spawn(async move {
                match bootstrap_mls_welcome_for_space(
                    base,
                    session,
                    actor,
                    device,
                    bootstrap_space_id,
                    state_store_task,
                )
                .await
                {
                    Ok(outcome) if outcome.applied > 0 => {
                        let backup_label = outcome
                            .backup_id
                            .as_deref()
                            .map(short_protocol_id)
                            .unwrap_or_else(|| "not uploaded".to_owned());
                        crypto_state_task.set(format!(
                            "MLS Welcome applied for {space_label}: {} group(s); history backup {backup_label}",
                            outcome.applied
                        ));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        last_error_task.set(Some(format!("MLS Welcome bootstrap: {error}")));
                    }
                }

                // Step-3 detection: if this device has no local account MLS
                // secret yet AND the server holds an account-secret backup,
                // flag the unlock prompt. Detection errors must NOT block or
                // fail boot — log and leave the flag false.
                let has_local_secret = crate::mls::runtime::load_device_snapshot_secret(
                    crate::secure_key_store::default_secure_key_store("yougen").as_ref(),
                    &detect_actor,
                    &detect_device,
                )
                .is_ok();
                if !has_local_secret {
                    match crate::views::helpers::with_authed_api(
                        &detect_base,
                        detect_session,
                        |api| async move {
                            crate::mls::account_recovery::fetch_mls_account_secret_backup(&api)
                                .await
                        },
                    )
                    .await
                    {
                        Ok(Some(_)) => needs_mls_unlock_for_bootstrap.set(true),
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(
                                error = %error.display(),
                                "MLS account-secret unlock detection failed"
                            );
                        }
                    }
                }
            });
        });
    }
    let resolved_space_surface = resolve_space_surface(
        &route,
        &state_store(),
        &account_did(),
        context_space_id.as_deref(),
    );
    if let (Some(space_id), Some(surface)) = (routed_space_id.as_deref(), resolved_space_surface)
        && matches!(
            &route,
            Route::TimelineSpace { .. }
                | Route::KanbanSpace { .. }
                | Route::KanbanBoard { .. }
                | Route::KanbanBoardTask { .. }
                | Route::DocumentSpace { .. }
        )
    {
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

    let loaded_spaces = spaces();
    let selected_preview = loaded_spaces
        .iter()
        .find(|space| context_space_id.as_deref() == Some(space.space_id.as_str()))
        .cloned();
    let active_scope_mode = space_scope_mode();
    let active_space_scope_ids =
        scoped_space_ids(&loaded_spaces, &active_space_id, active_scope_mode);
    let active_projection_realm_id =
        projection_realm_id_for_known_space(&loaded_spaces, &active_space_id).unwrap_or_default();
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
    let space_projections = state_store.read().load().space_projections;
    let active_security_scope_id = if active_projection_realm_id.trim().is_empty() {
        active_space_id.as_str()
    } else {
        active_projection_realm_id.as_str()
    };
    let active_space_security_encrypted = crate::security_state::security_projection_for_scope_id(
        &space_projections,
        active_security_scope_id,
    )
    .or_else(|| {
        crate::security_state::security_projection_for_scope_id(
            &space_projections,
            &active_space_id,
        )
    })
    .map(crate::security_state::realm_projection_is_encrypted)
    .unwrap_or(false);
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
    let theme_is_night = theme_renders_as_night(&active_theme, system_theme_is_night());
    let theme_toggle_icon = if theme_is_night { "sun" } else { "moon" };
    let theme_toggle_title = if theme_is_night {
        "Switch to light theme"
    } else {
        "Switch to night theme"
    };
    let route_title = resolved_space_surface
        .map(SpaceSurface::title)
        .unwrap_or_else(|| route_label(&route));
    let topbar_context_title = selected_preview
        .as_ref()
        .map(|space| space.name.clone())
        .unwrap_or_else(|| {
            if route_uses_space_context {
                "Space".to_owned()
            } else {
                route_title.to_owned()
            }
        });
    let topbar_search_is_open =
        palette_open() || topbar_search_expanded() || !global_query().is_empty();
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
        let login_navigator = navigator;
        let callback_navigator = navigator;

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
            // dismisses transient overlays.
            // A6.1 — `Cmd+F` (Ctrl+F on non-Mac) opens the global
            // cross-Space message search panel; we intercept the
            // browser's native find-in-page because the in-app panel
            // covers all spaces the user has access to.
            onkeydown: move |event| {
                let key = event.key().to_string();
                let modifiers = event.modifiers();
                let ctrl = modifiers.ctrl();
                let meta = modifiers.meta();
                if (ctrl || meta) && key.eq_ignore_ascii_case("k") {
                    event.prevent_default();
                    event.stop_propagation();
                    topbar_search_expanded.set(true);
                    palette_open.set(true);
                    return;
                }
                if crate::views::global_search::key_event_is_search_trigger(&key, ctrl, meta) {
                    event.prevent_default();
                    event.stop_propagation();
                    let _ = navigator.push(Route::Search);
                    return;
                }
                if key == "Escape" {
                    if shortcut_help_open() {
                        shortcut_help_open.set(false);
                        event.prevent_default();
                        event.stop_propagation();
                        return;
                    }
                    if palette_open() || topbar_search_expanded() || !global_query().trim().is_empty() {
                        palette_open.set(false);
                        topbar_search_expanded.set(false);
                        global_query.set(String::new());
                        event.prevent_default();
                        event.stop_propagation();
                    }
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
                }
            },
            onclick: move |_| {
                if palette_open() || topbar_search_expanded() || !global_query().trim().is_empty() {
                    palette_open.set(false);
                    topbar_search_expanded.set(false);
                    global_query.set(String::new());
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
            // G3.Y3 — global policy-deny banner. Floats above the shell
            // so any 403 with a policy-shaped envelope is surfaced
            // without each call site wiring its own error UI. The
            // banner is pulled from a process-wide queue populated by
            // `api::decode_contrix_error`'s `maybe_dispatch_policy_deny`.
            crate::components::PolicyDenyBanner {}
            // CXP-0007 P3B.3 — global Circle-error toast, fed by the
            // HTTP layer's `maybe_dispatch_circle_error` next to the
            // policy-deny dispatcher. Renders nothing when no error
            // is queued.
            crate::components::CircleErrorToast { i18n: i18n_signal }
            // Step 3 of the account-MLS-secret auto-unlock flow: a
            // recovery-passphrase banner that restores encrypted history on
            // a fresh device. Renders nothing unless boot detection flagged
            // `needs_mls_unlock`.
            crate::components::MlsUnlockPrompt {
                base_url,
                token,
                actor_did: account_did,
                device_id,
                state_store,
                needs_mls_unlock,
            }
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
                        let current_theme = theme();
                        let next = next_manual_theme(&current_theme);
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
                        onclick: move |_| {
                            sync_generation.set(sync_generation() + 1);
                            sync_bootstrap_complete.set(false);
                            connect(
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
                                    sync_bootstrap_complete,
                                    navigator,
                                },
                            )
                        },
                        "Refresh"
                    }
                }
                Link { class: "secondary", "data-testid": "mobile-dashboard-nav-button", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.dashboard")} }
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
                                                sync_bootstrap_complete.set(false);
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
                                                        sync_bootstrap_complete,
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
                        span {
                            title: "Realms (security boundaries) and the Spaces nested inside them — spec realm-and-space.md.",
                            "Realms & Spaces"
                        }
                        // Header "+" creates a new Realm (no scope
                        // needed). For new Spaces use the per-row
                        // "+" hover action on a Realm or Space —
                        // that surfaces the parent context inline
                        // instead of dumping the user on a form with
                        // no idea where the Space will land.
                        Link {
                            class: "add-realm-cta",
                            "data-testid": "sidebar-new-realm-cta",
                            title: "Create a new Realm (security boundary). For a new Space, hover a Realm or Space row and click the + on that row.",
                            "aria-label": "Create a new Realm",
                            to: Route::SetupSection { section: "realms".to_owned() },
                            UiIcon { name: "plus" }
                        }
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
                                let add_child_title = match item_space.kind {
                                    SpacePreviewKind::Realm => "Create a new Space at the root of this Realm",
                                    SpacePreviewKind::Space => "Create a new Space under this one (this Space becomes the parent)",
                                };
                                let (icon_name, icon_class, icon_title) = match item_space.kind {
                                    SpacePreviewKind::Realm => {
                                        let is_encrypted = space_projections
                                            .get(&item_space.space_id)
                                            .is_some_and(realm_projection_is_encrypted);
                                        if is_encrypted {
                                            (
                                                "lock",
                                                "sidebar-nav-icon realm-security-secure",
                                                "Encrypted Realm",
                                            )
                                        } else {
                                            (
                                                "unlock",
                                                "sidebar-nav-icon realm-security-unsafe",
                                                "Unencrypted Realm",
                                            )
                                        }
                                    }
                                    SpacePreviewKind::Space => (
                                        "folder",
                                        "sidebar-nav-icon",
                                        "Space",
                                    ),
                                };
                                rsx! {
                            div { class: "sidebar-row",
                            Link {
                                class: "{item_class} sidebar-row-main",
                                "data-testid": "space-button",
                                title: "{item_space.name}",
                                style: "padding-left: calc(10px + {depth_px}px);",
                                to: Route::Space { space_id: item_space.space_id.clone() },
                                onclick: {
                                    let id = item_space.space_id.clone();
                                    move |_| selected_space.set(id.clone())
                                },
                                span {
                                    class: "{icon_class}",
                                    title: "{icon_title}",
                                    UiIcon { name: icon_name.to_owned() }
                                }
                                span { class: "grow truncate", "{display_name}" }
                                if has_remark {
                                    span {
                                        class: "pill muted xs",
                                        "data-testid": "space-remark-badge",
                                        title: "Local remark (private to this account)",
                                        "备注"
                                    }
                                }
                                // Two-tier classification badge: Realm
                                // (security boundary) vs Space (nav
                                // container inside a Realm). When a
                                // Realm has descendants, show the count
                                // instead of the kind tag so the user
                                // sees the tree structure at a glance.
                                if item.descendant_count > 0 && item_space.kind == SpacePreviewKind::Realm {
                                    span { class: "pill muted xs", "{item.descendant_count}" }
                                } else {
                                    match item_space.kind {
                                        SpacePreviewKind::Realm => rsx! {
                                            span {
                                                class: "pill muted xs",
                                                "data-testid": "space-kind-realm",
                                                title: "Realm — security / sync / E2EE boundary (spec realm-and-space.md §2)",
                                                "Realm"
                                            }
                                        },
                                        SpacePreviewKind::Space => rsx! {
                                            span {
                                                class: "pill muted xs",
                                                "data-testid": "space-kind-space",
                                                title: "Space — navigation container inside a Realm (spec realm-and-space.md §3)",
                                                "Space"
                                            }
                                        },
                                    }
                                }
                            }
                            // Contextual "+" — creates a new Space
                            // scoped to this row. For Realms this is
                            // "Space at the Realm root"; for Spaces
                            // this is "child Space under this one".
                            // Sets `selected_space` first so the
                            // NewSpace form can derive the prefilled
                            // realm_id + parent_space_id from it.
                            Link {
                                class: "sidebar-row-add-action",
                                "data-testid": "space-row-add-action",
                                title: "{add_child_title}",
                                "aria-label": "{add_child_title}",
                                to: Route::SetupSection { section: "new-space".to_owned() },
                                onclick: {
                                    let id = item_space.space_id.clone();
                                    move |_| selected_space.set(id.clone())
                                },
                                UiIcon { name: "plus" }
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
                    div { class: "topbar-left",
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
                        div { class: "topbar-context", "data-testid": "topbar-crumbs",
                            if route_uses_space_context && !active_space_id.is_empty() {
                                SecurityStateBadge {
                                    encrypted: active_space_security_encrypted,
                                    compact: false,
                                    test_id: Some("space-security-state".to_owned()),
                                }
                            }
                            span { class: "topbar-context-title", "data-testid": "space-title", "{topbar_context_title}" }
                            if route_uses_space_context && !active_space_id.is_empty() {
                                {
                                    let (current_surface_label, current_surface_icon) = match resolved_space_surface {
                                        Some(surface) => (surface.short_label(), surface.icon_name()),
                                        None => ("Settings", "settings"),
                                    };
                                    rsx! {
                                        span {
                                            class: "topbar-current-surface",
                                            "data-testid": "current-space-surface",
                                            title: "Current view: {current_surface_label}",
                                            UiIcon { name: current_surface_icon }
                                            span { class: "topbar-current-surface-label", "{current_surface_label}" }
                                        }
                                    }
                                }
                            }
                            if route_uses_space_context && active_space_scope_count > 1 {
                                span { class: "topbar-context-pill muted", "{active_space_scope_label}" }
                            }
                            if !active_space_id.is_empty() {
                                span { class: "sr-only mono", "data-testid": "selected-space-id", "{active_space_id}" }
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
                            full_ready,
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "btn icon sm ghost theme-toggle-button",
                            "data-testid": "theme-toggle",
                            title: "{theme_toggle_title}",
                            "aria-label": "{theme_toggle_title}",
                            onclick: move |_| {
                                let current_theme = theme();
                                let next = next_manual_theme(&current_theme);
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
                        div {
                            class: if topbar_search_is_open {
                                "topbar-command-search is-open"
                            } else {
                                "topbar-command-search"
                            },
                            onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                            onkeydown: move |event| {
                                if event.key().to_string() == "Escape" {
                                    palette_open.set(false);
                                    topbar_search_expanded.set(false);
                                    global_query.set(String::new());
                                    event.prevent_default();
                                    event.stop_propagation();
                                }
                            },
                            if !topbar_search_is_open {
                                button {
                                    r#type: "button",
                                    class: "btn icon sm ghost",
                                    "data-testid": "topbar-search-button",
                                    title: crate::i18n::tr("topbar.search_placeholder"),
                                    "aria-label": crate::i18n::tr("topbar.search_placeholder"),
                                    onclick: move |_| {
                                        topbar_search_expanded.set(true);
                                        palette_open.set(true);
                                    },
                                    UiIcon { name: "search" }
                                }
                            } else {
                                div { class: "topbar-command-search-field",
                                    UiIcon { name: "search" }
                                    input {
                                        "data-testid": "global-search-input",
                                        value: "{global_query}",
                                        placeholder: crate::i18n::tr("topbar.search_placeholder"),
                                        autofocus: true,
                                        onmounted: move |event| async move {
                                            let _ = event.set_focus(true).await;
                                        },
                                        onfocusin: move |_| palette_open.set(true),
                                        oninput: move |event| {
                                            global_query.set(event.value());
                                            palette_open.set(true);
                                        },
                                        onkeydown: move |event| {
                                            let key = event.key().to_string();
                                            if key == "Escape" {
                                                palette_open.set(false);
                                                topbar_search_expanded.set(false);
                                                global_query.set(String::new());
                                                event.prevent_default();
                                                event.stop_propagation();
                                            } else if key == "Enter"
                                                && !global_query().trim().is_empty()
                                            {
                                                view.set(Route::to_view(&Route::Directory));
                                                let _ = navigator.push(Route::Directory);
                                                palette_open.set(false);
                                                topbar_search_expanded.set(false);
                                            }
                                        },
                                    }
                                    kbd { "⌘K" }
                                    button {
                                        r#type: "button",
                                        class: "btn icon sm ghost topbar-command-search-close",
                                        title: crate::i18n::tr("common.close"),
                                        "aria-label": crate::i18n::tr("common.close"),
                                        onclick: move |_| {
                                            palette_open.set(false);
                                            topbar_search_expanded.set(false);
                                            global_query.set(String::new());
                                        },
                                        UiIcon { name: "x" }
                                    }
                                }
                                if palette_open() {
                                    CommandPalette {
                                        query: global_query(),
                                        spaces: spaces(),
                                        on_navigate: move |route: Route| {
                                            view.set(Route::to_view(&route));
                                            let _ = navigator.push(route);
                                            palette_open.set(false);
                                            topbar_search_expanded.set(false);
                                            global_query.set(String::new());
                                        },
                                        on_pick_space: move |space_id: String| {
                                            selected_space.set(space_id.clone());
                                            view.set(crate::views::View::Timeline);
                                            let _ = navigator.push(Route::Space { space_id });
                                            palette_open.set(false);
                                            topbar_search_expanded.set(false);
                                            global_query.set(String::new());
                                        },
                                        on_close: move |_: ()| {
                                            palette_open.set(false);
                                            topbar_search_expanded.set(false);
                                            global_query.set(String::new());
                                        },
                                    }
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
                        Link {
                            class: "btn icon sm ghost topbar-notifications-link",
                            "data-testid": "topbar-notifications-button",
                            to: Route::Notifications,
                            title: crate::i18n::tr("nav.notifications"),
                            "aria-label": crate::i18n::tr("nav.notifications"),
                            UiIcon { name: "inbox" }
                            span { class: "topbar-notifications-badge", "aria-hidden": "true" }
                        }
                        // M-UX-CONTEXT-1: the old "+ New Space"
                        // topbar shortcut is gone. Realm + Space
                        // creation now live in the sidebar where the
                        // tree hierarchy makes the parent explicit:
                        // a `+R` button at the section header for a
                        // new Realm, and a per-row `+` (on every Realm
                        // / Space) that scopes the new Space to that
                        // parent. A floating "+ New Space" with no
                        // parent context was confusing — it actually
                        // opened the Realm bootstrap flow.
                        div { class: "account-menu-wrap",
                            button {
                                class: "btn icon sm ghost account-menu-button",
                                "data-testid": "account-menu-button",
                                title: crate::i18n::tr("topbar.account_menu"),
                                "aria-label": crate::i18n::tr("topbar.account_menu"),
                                onclick: move |event: dioxus::events::MouseEvent| {
                                    event.stop_propagation();
                                    if palette_open() || topbar_search_expanded() || !global_query().trim().is_empty() {
                                        palette_open.set(false);
                                        topbar_search_expanded.set(false);
                                        global_query.set(String::new());
                                    }
                                    server_menu_open.set(false);
                                    account_menu_open.toggle();
                                },
                                UiIcon { name: "user" }
                                if has_session {
                                    span { class: "dot-online", title: "online" }
                                }
                            }
                            if account_menu_open() {
                                div {
                                    class: "account-menu-scrim",
                                    "aria-hidden": "true",
                                    onclick: move |_| account_menu_open.set(false),
                                }
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
                                            div { class: "account-menu__value",
                                                span { class: "mono", "data-testid": "account-menu-did", title: "{account_did_value}", "{account_did_label}" }
                                                button {
                                                    class: "btn icon sm ghost account-menu__copy",
                                                    "data-testid": "account-menu-copy-did",
                                                    title: "Copy DID",
                                                    "aria-label": "Copy DID",
                                                    onclick: {
                                                        let value = account_did_value.clone();
                                                        move |_| {
                                                            copy_text_to_clipboard(&value);
                                                            account_session_state.set("DID copied".to_owned());
                                                        }
                                                    },
                                                    UiIcon { name: "copy" }
                                                }
                                            }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Device" }
                                            div { class: "account-menu__value",
                                                span { class: "mono", "data-testid": "account-menu-device", title: "{device_id_value}", "{device_id_label}" }
                                                button {
                                                    class: "btn icon sm ghost account-menu__copy",
                                                    "data-testid": "account-menu-copy-device",
                                                    title: "Copy device ID",
                                                    "aria-label": "Copy device ID",
                                                    onclick: {
                                                        let value = device_id_value.clone();
                                                        move |_| {
                                                            copy_text_to_clipboard(&value);
                                                            account_session_state.set("Device ID copied".to_owned());
                                                        }
                                                    },
                                                    UiIcon { name: "copy" }
                                                }
                                            }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Server" }
                                            span { "{active_server_label}" }
                                        }
                                        div { class: "account-menu__row",
                                            strong { "Frontier" }
                                            span { class: "mono", "data-testid": "account-menu-frontier", title: "{frontier_label}", "{frontier_label_display}" }
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
                                    }
                                    div { class: "account-menu__actions",
                                        button {
                                            class: "btn sm ghost",
                                            "data-testid": "account-menu-session-refresh",
                                            "aria-label": "Refresh session",
                                            disabled: !has_session,
                                            onclick: {
                                                let base = base_url();
                                                move |_| {
                                                    let base = base.clone();
                                                    let api_token = token();
                                                    let actor = account_did();
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
                                                                        // The bearer expired between background
                                                                        // refresh ticks. Try a silent re-mint
                                                                        // (OIDC refresh_token / session-grant
                                                                        // exchange) before declaring the session
                                                                        // dead — clicking "Refresh session" must
                                                                        // *keep* the user signed in, not bounce
                                                                        // them to login on a routine token rollover.
                                                                        if let Some(fresh) = crate::session::refresh_current_bearer().await {
                                                                            let canonical_actor = match ContrixApi::new(&base) {
                                                                                Ok(api) => api
                                                                                    .with_bearer(fresh)
                                                                                    .account_me()
                                                                                    .await
                                                                                    .ok()
                                                                                    .map(|account| account.did)
                                                                                    .filter(|did| !did.trim().is_empty()),
                                                                                Err(_) => None,
                                                                            }
                                                                            .unwrap_or_else(|| actor.clone());
                                                                            account_did.set(canonical_actor.clone());
                                                                            account_session_state.set(format!(
                                                                                "Session refresh ok: {canonical_actor}"
                                                                            ));
                                                                        } else {
                                                                            token.set(String::new());
                                                                            persist_config(
                                                                                config_store,
                                                                                base.clone(),
                                                                                actor.clone(),
                                                                                device.clone(),
                                                                                String::new(),
                                                                            );
                                                                            status.set("Session expired; sign in again".to_owned());
                                                                            last_error.set(Some("auth_expired: session expired".to_owned()));
                                                                            account_session_state.set(
                                                                                "Session expired. Sign in again.".to_owned()
                                                                            );
                                                                            redirect_to_login(navigator);
                                                                        }
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
                                            "aria-label": "Log out",
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
                                                // G3.Y0 — this is the *hard* logout path
                                                // (user clicked "Log out"). Wipe the
                                                // device DPoP key so the next sign-in
                                                // rotates `cnf.jkt`. The soft path
                                                // (`session_refresh`'s LoginRequired
                                                // outcome) deliberately keeps the key.
                                                state_store.write().set_dpop_device_key(None);
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
                                            plaintext_service_did: active_service_did.clone(),
                                            token,
                                            account_did: account_did(),
                                            device_id: device_id(),
                                            selected_space: active_space_id.clone(),
                                            projection_realm_id: active_projection_realm_id.clone(),
                                            selected_space_scope: active_space_scope_ids.clone(),
                                            sync_cursor,
                                            frontier_state,
                                            state_store,
                                            event_write_ready,
                                        }
                                    }
                                } else {
                                    rsx! { ProfileGateNotice { profile: "kanban_mvp" } }
                                }
                            }
                            SpaceSurface::Document => {
                                if full_ready {
                                    rsx! {
                                        crate::views::document::DocumentPanel {
                                            base_url: base_url(),
                                            token,
                                            selected_space: active_space_id.clone(),
                                            document_ref: None,
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
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
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
                    Route::Chat { .. } => {
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
                        }
                        if minimal_ready {
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    selected_space_scope: active_space_scope_ids.clone(),
                                    sync_cursor,
                                    frontier_state,
                                    state_store,
                                    initial_flow_id: default_flow_id_for_scope(&active_space_id),
                                    embedded: false,
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
                    Route::Contacts => rsx! {
                        crate::views::contacts::ContactsPanel {
                            base_url: base_url(),
                            token,
                        }
                    },
                    Route::ContactsNew => rsx! {
                        crate::views::contacts::ContactNewPanel {
                            base_url: base_url(),
                            token,
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
                    Route::Settings | Route::SettingsSection { .. } | Route::NotificationsSettings => rsx! {
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
                    // G3.Y1 — device management + QR pairing live on
                    // their own routes so the e2e harness can deep-link
                    // into them without scrolling past unrelated
                    // settings sections.
                    Route::SettingsDevices | Route::SettingsDevicesPair => rsx! {
                        crate::views::settings::devices::SettingsDevicesPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            state_store,
                        }
                    },
                    Route::SettingsRecovery => rsx! {
                        crate::views::settings::recovery::SettingsRecoveryPanel {
                            account_did,
                            state_store,
                        }
                    },
                    Route::SettingsSecurity => rsx! {
                        crate::views::settings::security::SettingsSecurityPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            state_store,
                        }
                    },
                    Route::Recover => rsx! {
                        crate::views::settings::recover_restore::RecoverPanel {
                            base_url,
                            token,
                            account_did: account_did(),
                            device_id: device_id(),
                            state_store,
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
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
                        }
                        if full_ready {
                            rsx! {
                                crate::views::space_admin::SpaceAdminPanel {
                                    base_url: base_url(),
                                    account_did: account_did(),
                                    device_id: device_id(),
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
                    Route::Developer => rsx! {
                        crate::views::developer::DeveloperToolsPanel { state_store }
                    },
                    Route::Kanban
                    | Route::KanbanSpace { .. }
                    | Route::KanbanBoard { .. }
                    | Route::KanbanBoardTask { .. }
                    | Route::KanbanTask { .. } => {
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
                        }
                        if kanban_ready {
                            rsx! {
                                crate::views::kanban::KanbanPanel {
                                    base_url: base_url(),
                                    plaintext_service_did: active_service_did.clone(),
                                    token,
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    selected_space: active_space_id.clone(),
                                    projection_realm_id: active_projection_realm_id.clone(),
                                    selected_space_scope: active_space_scope_ids.clone(),
                                    sync_cursor,
                                    frontier_state,
                                    state_store,
                                    event_write_ready,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "kanban_mvp" } }
                        }
                    },
                    Route::Notifications => rsx! {
                        crate::views::notifications::NotificationsPanel {
                            base_url: base_url(),
                            token,
                            state_store,
                        }
                    },
                    Route::Document | Route::DocumentNew | Route::DocumentSpace { .. } => {
                        if let Some(sid) = route.space_id()
                            && selected_space() != sid
                        {
                            selected_space.set(sid.to_owned());
                        }
                        let document_ref = match &route {
                            Route::DocumentSpace { space_id } if space_id.starts_with("cx:morph:") => {
                                Some(space_id.clone())
                            }
                            _ => None,
                        };
                        rsx! {
                            if full_ready {
                                crate::views::document::DocumentPanel {
                                    base_url: base_url(),
                                    token,
                                    selected_space: active_space_id.clone(),
                                    document_ref,
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
                        crate::views::webrtc::WebRtcCallPanel {
                            base_url: base_url(),
                            token,
                            state_store,
                            selected_space: active_space_id.clone(),
                            account_did: account_did(),
                            device_id: device_id(),
                        }
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
                        if crate::views::applets::applets_enabled() {
                            crate::views::applets::AppletsPanel {
                                base_url: base_url(),
                                account_did,
                                token,
                                selected_space: selected_space(),
                                state_store,
                            }
                        } else {
                            DeferredFeatureGate { feature: "experimental-applets" }
                        }
                    },
                    Route::Agents => rsx! {
                        if crate::views::agents::agents_enabled() {
                            crate::views::agents::AgentsPanel {
                                base_url: base_url(),
                                account_did,
                                token,
                                selected_space: selected_space(),
                                state_store,
                            }
                        } else {
                            DeferredFeatureGate { feature: "experimental-agents" }
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
    full_ready: bool,
) -> Element {
    let _ = (&scope_label, scope_count);
    let mut menu_open = use_signal(|| false);
    let (current_nav_label, current_nav_icon) = match current_surface {
        Some(surface) => (surface.short_label(), surface.icon_name()),
        None => ("Settings", "settings"),
    };
    rsx! {
        div { class: "space-context-bar", "data-testid": "space-context-bar",
            div { class: "actions space-nav-inline", "data-testid": "space-context-inline",
                for surface in SpaceSurface::top_nav() {
                    if surface.is_available(minimal_ready, kanban_ready, full_ready) {
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
                    "Settings"
                }
            }
            div {
                class: if menu_open() { "space-nav-menu-host is-open" } else { "space-nav-menu-host" },
                "data-testid": "space-context-menu",
                button {
                    class: "btn icon sm secondary space-nav-menu-button",
                    "data-testid": "space-context-menu-button",
                    title: "Switch view: {current_nav_label}",
                    "aria-label": "Switch Space view",
                    "aria-expanded": "{menu_open()}",
                    onclick: move |_| menu_open.toggle(),
                    UiIcon { name: current_nav_icon }
                }
                if menu_open() {
                    button {
                        class: "space-nav-menu-scrim",
                        "aria-label": "Close Space view menu",
                        onclick: move |_| menu_open.set(false),
                    }
                    div {
                        class: "space-nav-menu-panel",
                        role: "menu",
                        "aria-label": "Space views",
                        for surface in SpaceSurface::top_nav() {
                            if surface.is_available(minimal_ready, kanban_ready, full_ready) {
                                Link {
                                    class: if current_surface == Some(surface) { "space-nav-menu-item is-active" } else { "space-nav-menu-item" },
                                    role: "menuitem",
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
                                            menu_open.set(false);
                                        }
                                    },
                                    UiIcon { name: surface.icon_name() }
                                    "{surface.short_label()}"
                                }
                            } else {
                                button {
                                    class: "space-nav-menu-item",
                                    role: "menuitem",
                                    disabled: true,
                                    UiIcon { name: surface.icon_name() }
                                    "{surface.short_label()}"
                                }
                            }
                        }
                        Link {
                            class: if current_surface.is_none() { "space-nav-menu-item is-active" } else { "space-nav-menu-item" },
                            role: "menuitem",
                            to: Route::SpaceAdmin { space_id: space_id.clone() },
                            onclick: move |_| menu_open.set(false),
                            UiIcon { name: "settings" }
                            "Settings"
                        }
                    }
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
            "Notifications",
            "inbox, mentions, approvals",
            Route::Notifications,
        ),
        ("Search", "messages across spaces", Route::Search),
        ("Directory", "search realms, orgs, actors", Route::Directory),
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
            "New Realm",
            "create security boundary",
            Route::SetupSection {
                section: "realms".to_owned(),
            },
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
                        {
                            let space_id_label = short_protocol_id(&space.space_id);
                            rsx! {
                                button {
                                    class: "command-palette-item",
                                    "data-testid": "command-palette-space",
                                    role: "option",
                                    "aria-label": "Open space {space.name}",
                                    onclick: {
                                        let id = space.space_id.clone();
                                        move |_| on_pick_space.call(id.clone())
                                    },
                                    span { class: "command-palette-item-title", "{space.name}" }
                                    span { class: "command-palette-item-hint", title: "{space.space_id}", "{space_id_label}" }
                                }
                            }
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
                            "aria-label": "Navigate to {label}",
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
                    "aria-label": "Close command palette",
                    onclick: move |_| on_close.call(()),
                    {crate::i18n::tr("command_palette.close")}
                }
            }
        }
    }
}

/// Translate a protocol-level profile id into the friendly product name
/// that end users see. The raw id remains available in the developer
/// details panel.
fn friendly_profile_label(profile: &str) -> String {
    let key = match profile {
        "minimal_client" => "profile_gate.friendly.minimal_client",
        "kanban_mvp" => "profile_gate.friendly.kanban_mvp",
        "chat_mvp" => "profile_gate.friendly.chat_mvp",
        "full_client" => "profile_gate.friendly.full_client",
        "e2ee_client" => "profile_gate.friendly.e2ee_client",
        _ => "profile_gate.friendly.unknown",
    };
    crate::i18n::tr(key)
}

#[component]
fn ProfileGateNotice(profile: &'static str) -> Element {
    let show_details = use_signal(|| false);
    let title = crate::i18n::tr("profile_gate.title");
    let body = crate::i18n::tr("profile_gate.body");
    let toggle_label = if *show_details.read() {
        crate::i18n::tr("friendly.identifier.hide_technical")
    } else {
        crate::i18n::tr("friendly.identifier.show_technical")
    };
    let friendly = friendly_profile_label(profile);
    let dev_label = crate::i18n::tr("developer.profile.required");
    let mut show_details = show_details;
    rsx! {
        div { class: "timeline", "data-testid": "profile-gate-notice",
            div { class: "event error-banner",
                div { class: "event-head",
                    span { "{title}" }
                    span { "{friendly}" }
                }
                div { class: "space-title", "{body}" }
                div { class: "profile-gate-details",
                    button {
                        r#type: "button",
                        class: "link-button",
                        "data-testid": "profile-gate-toggle-technical",
                        onclick: move |_| {
                            let current = *show_details.read();
                            show_details.set(!current);
                        },
                        "{toggle_label}"
                    }
                    if *show_details.read() {
                        div { class: "muted profile-gate-technical", "data-testid": "profile-gate-technical",
                            div { strong { "{dev_label}: " } code { "{profile}" } }
                            div { "Write controls for this surface are hidden until /server/describe advertises the matching profile requirements." }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn DeferredFeatureGate(feature: &'static str) -> Element {
    rsx! {
        div {
            class: "timeline",
            "data-testid": "deferred-feature-gate",
            "data-feature": "{feature}",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpaceSurface {
    Timeline,
    Board,
    Document,
}

impl SpaceSurface {
    fn top_nav() -> [Self; 3] {
        [Self::Timeline, Self::Board, Self::Document]
    }

    fn short_label(self) -> &'static str {
        match self {
            Self::Timeline => "Timeline",
            Self::Board => "Board",
            Self::Document => "Document",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Timeline => "Timeline View",
            Self::Board => "Board View",
            Self::Document => "Document View",
        }
    }

    fn icon_name(self) -> &'static str {
        match self {
            Self::Timeline => "timeline",
            Self::Board => "board",
            Self::Document => "file",
        }
    }

    fn preference_value(self) -> &'static str {
        match self {
            Self::Timeline => "timeline",
            Self::Board => "board",
            Self::Document => "document",
        }
    }

    fn from_preference(value: &str) -> Option<Self> {
        match value {
            "timeline" => Some(Self::Timeline),
            "board" => Some(Self::Board),
            "discussion" => Some(Self::Board),
            "document" => Some(Self::Document),
            _ => None,
        }
    }

    fn route(self, space_id: String) -> Route {
        match self {
            Self::Timeline => Route::TimelineSpace { space_id },
            Self::Board => Route::KanbanSpace { space_id },
            Self::Document => Route::DocumentSpace { space_id },
        }
    }

    fn is_available(self, minimal_ready: bool, kanban_ready: bool, full_ready: bool) -> bool {
        match self {
            Self::Timeline => minimal_ready,
            Self::Board => kanban_ready,
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

fn default_flow_id_for_scope(scope_id: &str) -> String {
    scope_id
        .strip_prefix("cx:realm:")
        .or_else(|| scope_id.strip_prefix("cx:space:"))
        .map(|suffix| format!("cx:flow:{suffix}"))
        .unwrap_or_else(|| scope_id.to_owned())
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
        Route::Chat { .. } => None,
        Route::Kanban
        | Route::KanbanSpace { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => Some(SpaceSurface::Board),
        Route::Document | Route::DocumentNew | Route::DocumentSpace { .. } => {
            Some(SpaceSurface::Document)
        }
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
            | Route::Chat { .. }
            | Route::Kanban
            | Route::KanbanSpace { .. }
            | Route::KanbanBoard { .. }
            | Route::KanbanBoardTask { .. }
            | Route::KanbanTask { .. }
            | Route::Document
            | Route::DocumentNew
            | Route::DocumentSpace { .. }
            | Route::SpaceAdmin { .. }
            | Route::SpaceAdminSection { .. }
    )
}

fn route_label(route: &Route) -> &'static str {
    match route {
        Route::Dashboard => "Home",
        Route::Login | Route::AuthCallback => "Login",
        // Route::Space resolves either a Realm or a Space projection
        // depending on the id prefix — see the sidebar two-tier
        // classification. Keep both protocol terms visible until a
        // separate Realm view splits off.
        Route::Space { .. } => "Realm / Space",
        Route::Timeline | Route::TimelineSpace { .. } | Route::TimelineMessage { .. } => {
            "Timeline View"
        }
        Route::Chat { .. } => "Discussion",
        Route::Contacts | Route::ContactsNew => "Contacts",
        Route::Directory => "Search",
        Route::Setup => "New Realm",
        Route::SetupSection { section } => match section.as_str() {
            "realms" | "spaces" => "New Realm",
            "new-space" => "New Space",
            _ => "Setup",
        },
        Route::Settings | Route::SettingsSection { .. } | Route::NotificationsSettings => {
            "Settings"
        }
        Route::VerifyDevice => "Verify Device",
        Route::SpaceAdmin { .. } => "Space Settings",
        Route::SpaceAdminSection { section, .. } => match section.as_str() {
            "members" => "Members Settings",
            "access" => "Access Policy",
            "security" => "Security & MLS",
            "governance" => "Governance",
            "federation" => "Federation Trust",
            "repair" => "Repair & Danger",
            _ => "Space Settings",
        },
        Route::Audit => "Audit",
        Route::Developer => "Developer Tools",
        Route::Kanban
        | Route::KanbanSpace { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => "Board View",
        Route::Notifications => "Notifications",
        Route::Document | Route::DocumentNew | Route::DocumentSpace { .. } => "Document View",
        Route::Call => "Call",
        Route::Recovery => "Recovery",
        Route::Recover => "Restore from backup",
        Route::SettingsDevices => "Devices",
        Route::SettingsDevicesPair => "Pair new device",
        Route::SettingsRecovery => "Recovery passphrase",
        Route::SettingsSecurity => "Key backup",
        Route::Onboarding => "Onboarding",
        Route::Quarantine => "Invite Quarantine",
        Route::Applets => "Applets",
        Route::Agents => "Agents",
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

fn mls_welcome_bootstrap_key(
    base_url: &str,
    session_token: &str,
    account_did: &str,
    device_id: &str,
    space_id: &str,
    e2ee_ready: bool,
    sync_bootstrap_complete: bool,
) -> Option<String> {
    if !e2ee_ready || !sync_bootstrap_complete {
        return None;
    }
    let base = server_key(base_url);
    let session = session_token.trim();
    let actor = account_did.trim();
    let device = device_id.trim();
    let space = space_id.trim();
    if base.is_empty()
        || session.is_empty()
        || actor.is_empty()
        || device.is_empty()
        || space.is_empty()
    {
        return None;
    }

    let mut token_hash = DefaultHasher::new();
    session.hash(&mut token_hash);
    Some(format!(
        "{base}|{actor}|{device}|{space}|{:016x}",
        token_hash.finish()
    ))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MlsWelcomeBootstrapOutcome {
    applied: usize,
    backup_id: Option<String>,
}

async fn bootstrap_mls_welcome_for_space(
    base_url: String,
    session_token: String,
    actor_did: String,
    device_id: String,
    space_id: String,
    mut state_store: Signal<LocalStateStore>,
) -> Result<MlsWelcomeBootstrapOutcome, String> {
    if session_token.trim().is_empty() || space_id.trim().is_empty() {
        return Ok(MlsWelcomeBootstrapOutcome::default());
    }

    let messages = crate::views::helpers::with_authed_api(
        &base_url,
        session_token.clone(),
        |api| async move { api.receive_device_messages().await },
    )
    .await
    .map_err(|error| error.display())?;

    // Runs on every target now that OpenMLS builds + runs under wasm32
    // (the browser uses the in-tree OpenMLS via the `js` feature). Previously
    // the wasm branch discarded the device messages and returned the default
    // outcome, which is why a fresh browser never applied a pending Welcome
    // and showed empty/locked encrypted spaces.
    let messages_value =
        serde_json::to_value(&messages).map_err(|error| format!("device messages: {error}"))?;
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let welcome_outcome = {
        let mut store = state_store.write();
        crate::mls::runtime::apply_welcome_messages_with_device_snapshot(
            &mut store,
            secure_store.as_ref(),
            &space_id,
            &actor_did,
            &device_id,
            &messages_value,
        )
    }
    .map_err(|error| error.user_message())?;

    // Welcomes were present but some/all failed to apply: report (do not fail
    // the boot when others succeeded). A totally-empty welcome set has
    // `failed == 0` and is silent.
    if welcome_outcome.failed > 0 {
        tracing::warn!(
            space = %space_id,
            applied = welcome_outcome.applied,
            failed = welcome_outcome.failed,
            first_error = welcome_outcome.first_error.as_deref().unwrap_or(""),
            "some MLS welcome(s) failed to apply"
        );
    }

    let applied = welcome_outcome.applied;
    if applied == 0 {
        return Ok(MlsWelcomeBootstrapOutcome::default());
    }

    let Some(snapshot) = state_store.read().mls_snapshot_for(&space_id) else {
        return Ok(MlsWelcomeBootstrapOutcome {
            applied,
            backup_id: None,
        });
    };
    let actor_for_backup = actor_did.clone();
    let device_for_backup = device_id.clone();
    let backup_id =
        crate::views::helpers::with_authed_api(&base_url, session_token, |api| async move {
            crate::mls::runtime::upload_mls_snapshot_backup(
                &api,
                &snapshot,
                &actor_for_backup,
                &device_for_backup,
            )
            .await
            .map_err(|err| anyhow::anyhow!(err.user_message()))
        })
        .await
        .map_err(|error| error.display())?;

    Ok(MlsWelcomeBootstrapOutcome {
        applied,
        backup_id: Some(backup_id),
    })
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
    let mut token = ctx.token;
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
    let server_changed = !same_server_url(&base_url(), &server_url);

    // A space cached against the previous server's view is meaningless
    // on the new server (different service DID, different membership,
    // potentially overlapping cx:space ids that point at unrelated
    // rooms). Wipe the account-scoped cache before re-pointing the URL
    // so the next sync starts from a clean slate. Device-level state
    // (local_identity, push_registration) is preserved.
    {
        let mut store = state_store.write();
        store.clear_account_scoped();
        if server_changed {
            store.set_session_grant(None);
            store.set_oidc_tokens(None);
        }
    }
    // Retire the previous server's SyncEngine. The use_effect's
    // base_url tracking would re-spawn anyway, but bumping here ensures
    // the in-flight long-poll exits before the new URL takes over.
    sync_generation.set(sync_generation() + 1);

    if server_changed {
        token.set(String::new());
    }
    let next_token = if server_changed {
        String::new()
    } else {
        token()
    };
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
        next_token,
    );
}

fn clamp_sidebar_width(width: f64) -> f64 {
    width.clamp(MIN_SIDEBAR_WIDTH, MAX_SIDEBAR_WIDTH)
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

async fn refresh_oidc_bearer_for_server(
    principal_server_url: &str,
    actor_did: &str,
    device_id: &str,
    previous: &crate::local_state::OidcTokenBundle,
) -> anyhow::Result<crate::local_state::OidcTokenBundle> {
    let refresh_token = previous
        .refresh_token
        .as_deref()
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("OIDC bundle has no refresh_token"))?;
    let auth_server_url = crate::coauth::resolve_principal_auth_server_url(principal_server_url)
        .await
        .map_err(|error| anyhow::anyhow!("resolve auth server: {error}"))?;
    let coauth = crate::coauth::CoauthApi::new(&auth_server_url)?;
    let topology = coauth.inspect_topology().await?;
    let plan = crate::coauth::build_oidc_code_exchange_plan(
        &topology,
        principal_server_url,
        actor_did,
        device_id,
    )?;
    let response = coauth
        .refresh_oidc_tokens(&plan.token_endpoint, &plan.client_id, refresh_token)
        .await?;
    Ok(crate::oidc::lifecycle::apply_refresh_response(
        previous, &response,
    ))
}

/// The single source of truth for re-minting the principal bearer.
///
/// Registered once at the app root and reached everywhere through
/// [`crate::session::refresh_current_bearer`]. Reads the live
/// base/actor/device from their signals (so it always targets the active
/// session), tries the OIDC `refresh_token` path first, then the
/// session-grant exchange. On success it writes the fresh bearer into the
/// `token` signal and persisted config and returns it; on definitive
/// failure it returns `None` and the caller routes to login.
///
/// Concurrency is handled by `crate::session`: callers coalesce onto one
/// in-flight invocation, so this never runs twice in parallel for a single
/// rollover.
async fn remint_principal_bearer(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut token: Signal<String>,
    config_store: Signal<LocalConfigStore>,
) -> Option<String> {
    let base = base_url();
    let actor = account_did();
    let device = device_id();

    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let oidc_bundle = {
        let store = state_store.read();
        store.load_oidc_tokens_with_secure_store(&actor, secure_store.as_ref())
    };
    if let Some(bundle) = oidc_bundle
        && crate::oidc::lifecycle::has_refresh_token(&bundle)
        && let Ok(next) = refresh_oidc_bearer_for_server(&base, &actor, &device, &bundle).await
    {
        // Abandon if the user switched servers while the refresh was in
        // flight — committing here would resurrect the old server's
        // credentials over the freshly selected session.
        if !same_server_url(&base, &base_url()) {
            return None;
        }
        let access_token = next.access_token.clone();
        state_store.write().set_oidc_tokens_with_secure_store(
            Some(next),
            &actor,
            secure_store.as_ref(),
        );
        token.set(access_token.clone());
        persist_config(
            config_store,
            base.clone(),
            actor.clone(),
            device.clone(),
            access_token.clone(),
        );
        return Some(access_token);
    }

    let prepared = {
        let mut store = state_store.write();
        crate::session_refresh::prepare_refresh_for_server_after_unauthorized(&mut store, &base)
    };
    let outcome = match prepared {
        crate::session_refresh::RefreshPrepared::Done(outcome) => outcome,
        crate::session_refresh::RefreshPrepared::Ready { grant, proof } => {
            let result = crate::session_refresh::exchange_refresh(&grant, &proof).await;
            // Same server-switch guard as the OIDC path: don't write the
            // old server's grant outcome onto a session that just moved.
            if !same_server_url(&base, &base_url()) {
                return None;
            }
            let mut store = state_store.write();
            crate::session_refresh::commit_refresh(&mut store, result)
        }
    };
    match outcome {
        crate::session_refresh::RefreshOutcome::Refreshed { access_token, .. } => {
            token.set(access_token.clone());
            persist_config(
                config_store,
                base.clone(),
                actor.clone(),
                device.clone(),
                access_token.clone(),
            );
            Some(access_token)
        }
        _ => None,
    }
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
    /// Set when the explicit bootstrap/manual connect attempt has completed.
    /// The background SyncEngine waits for this so it does not race the
    /// first full account-subscribe snapshot on the same render.
    sync_bootstrap_complete: Signal<bool>,
    navigator: Navigator,
}

fn redirect_to_login(navigator: Navigator) {
    let _ = navigator.push(Route::Login);
}

fn connect(base: String, actor: String, device: String, ctx: ConnectContext) {
    let device = normalize_device_id(&device);
    spawn(async move {
        let mut sync_bootstrap_complete = ctx.sync_bootstrap_complete;
        let mut status = ctx.status;
        let mut sync_cursor = ctx.sync_cursor;
        let mut token = ctx.token;
        let mut account_did = ctx.account_did;
        let mut selected_space = ctx.selected_space;
        let mut spaces = ctx.spaces;
        let mut timeline = ctx.timeline;
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
                            sync_bootstrap_complete.set(true);
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
                        // Round 4 — cache the advertised trust_domain so
                        // downstream signing flows (cross_signing.publish
                        // v2, S2S transcripts) can pull a canonical
                        // value off local state without an extra round
                        // trip. Cleared when describe fails so a stale
                        // domain can't leak into the next flow.
                        {
                            let mut store = state_store.write();
                            let mut snapshot = store.load();
                            // `TypedTrustDomainId` enforces a non-empty
                            // `cx:trust_domain:<scope>` shape at deserialize
                            // time, so the previous "is_empty" guard is
                            // structurally impossible. Always cache.
                            snapshot.server_trust_domain =
                                Some(description.trust_domain.as_str().to_owned());
                            store.save(snapshot);
                        }
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

                let mut session_token = token();
                if session_token.trim().is_empty() {
                    if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                        session_token = refreshed;
                    } else {
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
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                }

                let mut authed = api.clone().with_bearer(session_token.clone());
                // Resolve the canonical actor DID from `/account/me`. Three
                // outcomes:
                //   1. Ok with non-empty DID -> use it as canonical_actor.
                //   2. Err that looks like auth expiry -> wipe session, bounce to login. The
                //      session is provably dead.
                //   3. Anything else (Ok with empty DID, transient 5xx, parse error, network
                //      failure) -> fall back to the locally stored actor, log a diagnostic to
                //      last_error so the sidebar/status surface can show it, and keep going so sync
                //      still has a chance to populate spaces.
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
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            match authed.account_me().await {
                                Ok(account) if !account.did.trim().is_empty() => account.did,
                                Ok(_) => {
                                    last_error.set(Some(
                                        "account_me: refreshed session returned empty actor DID; reusing local actor"
                                            .to_owned(),
                                    ));
                                    actor.clone()
                                }
                                Err(retry_error) if !is_auth_expired_error(&retry_error) => {
                                    last_error.set(Some(format!("account_me: {retry_error}")));
                                    actor.clone()
                                }
                                Err(_) => {
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
                                    last_error
                                        .set(Some("auth_expired: session expired".to_owned()));
                                    redirect_to_login(navigator);
                                    sync_bootstrap_complete.set(true);
                                    return;
                                }
                            }
                        } else {
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
                            sync_bootstrap_complete.set(true);
                            return;
                        }
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
                    // device — every account-scoped record (projections,
                    // drafts, anchor views, read markers, remarks, and the
                    // previous identity's session grant + OIDC bundle) is
                    // someone else's data and must be wiped before the sync
                    // below repopulates the store. `adopt_account_scope`
                    // performs the wipe and stamps the new owner so a later
                    // login recognises the scope. Device-level state
                    // (local_identity, push_registration, DPoP key) is
                    // preserved.
                    if !actor.trim().is_empty() {
                        let mut store = state_store.write();
                        store.adopt_account_scope(&canonical_actor);
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
                    } else {
                        // No previous identity to displace — just record
                        // who the scope now belongs to (don't wipe: a
                        // just-established grant could be dropped).
                        state_store.write().stamp_account_scope_owner(&canonical_actor);
                    }
                    account_did.set(canonical_actor.clone());
                } else {
                    // Actor unchanged — record the scope owner so a later
                    // login for a different identity is recognised and the
                    // stale scope is reset.
                    state_store.write().stamp_account_scope_owner(&canonical_actor);
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
                let sync_result = match authed.account_subscribe_snapshot(None).await {
                    Ok(sync) => Ok(sync),
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            authed.account_subscribe_snapshot(None).await
                        } else {
                            Err(error)
                        }
                    }
                    Err(error) => Err(error),
                };
                match sync_result {
                    Ok(sync) => {
                        {
                            let mut store = state_store.write();
                            store.save_sync_cursor(sync.cursor.clone());
                            // Server-authoritative reconcile for top-level
                            // Realm membership. Nested Space containers are
                            // not always returned as top-level sync entries,
                            // so keep local container projections while their
                            // home Realm is still present.
                            let server_set: BTreeSet<String> =
                                sync.spaces.keys().cloned().collect();
                            let keep_set = full_sync_projection_keep_set(
                                &server_set,
                                &store.load().space_projections,
                            );
                            let pruned = store.retain_space_projections(|id| keep_set.contains(id));
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
                                store.ingest_move_event_states(id, body);
                            }
                            // Hydrate Space remarks from the actor-private
                            // account_data projection (spec
                            // client-preferences.md §3.7). soland keys these
                            // entries by `cx.contacts.space.<space_id>` and
                            // returns the canonical SpaceRemark JSON in
                            // `content`. Entries for other namespaces are
                            // ignored here.
                            let notification_projection = sync
                                .account_data
                                .iter()
                                .filter(|entry| {
                                    crate::views::notifications::is_notification_account_data(entry)
                                })
                                .cloned()
                                .collect::<Vec<_>>();
                            if !notification_projection.is_empty() {
                                store.save_notification_projection(notification_projection);
                            }
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
                        sync_bootstrap_complete.set(true);
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
                let events_result = match authed.events_describe().await {
                    Ok(events) => Ok(events),
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            authed.events_describe().await
                        } else {
                            Err(error)
                        }
                    }
                    Err(error) => Err(error),
                };
                match events_result {
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
                        sync_bootstrap_complete.set(true);
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
        sync_bootstrap_complete.set(true);
    });
}

fn copy_text_to_clipboard(text: &str) {
    let Ok(encoded) = serde_json::to_string(text) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const text = {encoded};
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = text;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}

pub fn space_previews_from_sync_spaces(spaces: &BTreeMap<String, Value>) -> Vec<SpacePreview> {
    let mut previews: Vec<SpacePreview> = spaces
        .iter()
        .filter(|(id, body)| {
            is_realm_or_space_projection_id(id) && !projection_looks_like_flow(body)
        })
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
            let kind = projection_preview_kind(id, body);
            let realm_id = match kind {
                SpacePreviewKind::Realm => String::new(),
                SpacePreviewKind::Space => projection_home_realm_id(body).unwrap_or_default(),
            };
            // Sidebar tree wiring: a Space without an explicit
            // `parent_space_id` is rendered under its home Realm. This
            // turns the Realm/Space classification into a single
            // tree the existing sidebar code can render without
            // restructure. Realms (and Spaces with real parents)
            // keep their existing parent_space_id resolution.
            let explicit_parent = extract_parent_space_id(id, body);
            let parent_space_id = match (&kind, &explicit_parent) {
                (SpacePreviewKind::Space, None) if !realm_id.is_empty() => Some(realm_id.clone()),
                _ => explicit_parent,
            };
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
                parent_space_id,
                child_space_ids: extract_child_space_ids(id, body),
                kind,
                realm_id,
            }
        })
        .collect();
    normalize_space_hierarchy(&mut previews);
    previews
}

fn is_realm_or_space_projection_id(id: &str) -> bool {
    id.starts_with("cx:realm:") || id.starts_with("cx:space:")
}

fn projection_preview_kind(id: &str, body: &Value) -> SpacePreviewKind {
    // Classify Realm vs Space. Wire signals:
    // - `__kind` (yougen-local tag from optimistic save)
    // - `schema` (server projection — cx.schema.realm.v1 vs cx.schema.space.v1)
    // - parent links on legacy nested Space projections
    // Anything else (legacy) defaults to Realm because
    // pre-M-SPACE-CREATE-1 yougen could only create Realms.
    match body
        .get("__kind")
        .and_then(Value::as_str)
        .or_else(|| body.get("schema").and_then(Value::as_str))
    {
        Some("space") | Some("cx.schema.space.v1") => SpacePreviewKind::Space,
        Some("realm") | Some("cx.schema.realm.v1") => SpacePreviewKind::Realm,
        _ if id.starts_with("cx:space:") && extract_parent_space_id(id, body).is_some() => {
            SpacePreviewKind::Space
        }
        _ => SpacePreviewKind::Realm,
    }
}

fn projection_home_realm_id(body: &Value) -> Option<String> {
    body.get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("summary")
                .and_then(|summary| summary.get("realm_id"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|realm_id| !realm_id.is_empty())
        .map(ToOwned::to_owned)
}

fn server_set_contains_realm_id(server_set: &BTreeSet<String>, realm_id: &str) -> bool {
    if server_set.contains(realm_id) {
        return true;
    }
    if let Some(suffix) = realm_id.strip_prefix("cx:realm:") {
        return server_set.contains(&format!("cx:space:{suffix}"));
    }
    if let Some(suffix) = realm_id.strip_prefix("cx:space:") {
        return server_set.contains(&format!("cx:realm:{suffix}"));
    }
    false
}

pub fn full_sync_projection_keep_set(
    server_set: &BTreeSet<String>,
    cached: &BTreeMap<String, Value>,
) -> BTreeSet<String> {
    let mut keep = server_set.clone();
    for (id, body) in cached {
        if should_retain_projection_after_full_sync(id, body, server_set) {
            keep.insert(id.clone());
        }
    }
    keep
}

pub fn should_retain_projection_after_full_sync(
    id: &str,
    body: &Value,
    server_set: &BTreeSet<String>,
) -> bool {
    if server_set.contains(id) {
        return true;
    }
    if !id.starts_with("cx:space:") || projection_preview_kind(id, body) != SpacePreviewKind::Space
    {
        return false;
    }
    projection_home_realm_id(body)
        .as_deref()
        .is_some_and(|realm_id| server_set_contains_realm_id(server_set, realm_id))
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
        let id_label = short_protocol_id(id);
        let mut summary_event = TimelineEvent::system_notice(
            format!("summary-{id}"),
            "server",
            format!(
                "{id_label}: {}",
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

pub fn merge_timeline_events(
    current: &[TimelineEvent],
    incoming: Vec<TimelineEvent>,
) -> Vec<TimelineEvent> {
    let mut merged = current.to_vec();
    for event in incoming {
        if let Some(existing) = merged.iter_mut().find(|existing| existing.id == event.id) {
            *existing = event;
        } else {
            merged.push(event);
        }
    }
    merged
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
    use serde_json::json;

    use super::*;

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

    fn oidc_bundle(access_token: &str, expires_at_unix: Option<i64>) -> OidcTokenBundle {
        OidcTokenBundle {
            access_token: access_token.to_owned(),
            refresh_token: Some("rt-test".to_owned()),
            token_type: "Bearer".to_owned(),
            expires_at_unix,
            id_token: None,
            scope: None,
            audience: Some("https://local.host".to_owned()),
            stored_at: chrono::Utc::now(),
        }
    }

    fn session_grant(session_expires_in: i64, grant_expires_in: i64) -> PersistedSessionGrant {
        let now = chrono::Utc::now();
        PersistedSessionGrant {
            grant_jwt: "grant.jwt".to_owned(),
            session_private_key_pem: "PEM".to_owned(),
            grant_id: "grant-1".to_owned(),
            audience: "https://local.host/api".to_owned(),
            principal_did: "did:web:alice.example".to_owned(),
            device_id: "cx:device:01964137-0000-7000-8000-000000000001".to_owned(),
            principal_server_url: "https://local.host".to_owned(),
            session_grant_exchange_path: "api/v1/auth/session-grant/exchange".to_owned(),
            grant_expires_at: Some(now + chrono::Duration::seconds(grant_expires_in)),
            session_expires_at: Some(now + chrono::Duration::seconds(session_expires_in)),
            stored_at: now,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn isolated_store(tag: &str) -> LocalStateStore {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("yougen-app-{tag}-{stamp}.json"));
        LocalStateStore::with_path(path)
    }

    #[test]
    fn boot_session_token_uses_fresh_oidc_access_token() {
        let now = 1_000;
        let mut state = ClientLocalState::default();
        state.oidc_tokens = Some(oidc_bundle("sx-fresh", Some(now + 120)));
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "legacy-token",
        );

        assert_eq!(
            initial_session_token_from_state(&state, &config, now),
            "sx-fresh"
        );
    }

    #[test]
    fn boot_session_token_ignores_expired_oidc_access_token() {
        let now = 1_000;
        let mut state = ClientLocalState::default();
        state.oidc_tokens = Some(oidc_bundle("sx-expired", Some(now - 1)));
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "legacy-token",
        );

        assert_eq!(initial_session_token_from_state(&state, &config, now), "");
    }

    #[test]
    fn boot_session_token_ignores_nearly_expired_oidc_access_token() {
        let now = 1_000;
        let mut state = ClientLocalState::default();
        state.oidc_tokens = Some(oidc_bundle(
            "sx-nearly-expired",
            Some(now + BOOT_ACCESS_TOKEN_SKEW_SECS),
        ));
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "legacy-token",
        );

        assert_eq!(initial_session_token_from_state(&state, &config, now), "");
    }

    #[test]
    fn boot_session_token_falls_back_to_legacy_config_without_oidc_bundle() {
        let state = ClientLocalState::default();
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "legacy-token",
        );

        assert_eq!(
            initial_session_token_from_state(&state, &config, 1_000),
            "legacy-token"
        );
    }

    #[test]
    fn boot_session_token_uses_fresh_session_grant_bearer() {
        let now = chrono::Utc::now().timestamp();
        let mut state = ClientLocalState::default();
        state.session_grant = Some(session_grant(120, 3600));
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "bridge-token",
        );

        assert_eq!(
            initial_session_token_from_state(&state, &config, now),
            "bridge-token"
        );
    }

    #[test]
    fn boot_session_token_falls_back_to_session_grant_when_oidc_is_expired() {
        let now = chrono::Utc::now().timestamp();
        let mut state = ClientLocalState::default();
        state.oidc_tokens = Some(oidc_bundle("sx-expired-oidc", Some(now - 1)));
        state.session_grant = Some(session_grant(120, 3600));
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "bridge-token",
        );

        assert_eq!(
            initial_session_token_from_state(&state, &config, now),
            "bridge-token"
        );
    }

    #[test]
    fn boot_session_token_ignores_expired_session_grant_bearer() {
        let now = chrono::Utc::now().timestamp();
        let mut state = ClientLocalState::default();
        state.session_grant = Some(session_grant(-1, 3600));
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "bridge-token",
        );

        assert_eq!(initial_session_token_from_state(&state, &config, now), "");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn bootstrap_can_start_with_oidc_refresh_material_without_bearer() {
        let mut store = isolated_store("bootstrap-oidc");
        let mut state = ClientLocalState::default();
        state.oidc_tokens = Some(oidc_bundle("sx-expired", Some(1)));
        store.save(state);

        assert!(has_bootstrap_refresh_material(&store, "https://local.host"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn bootstrap_can_start_with_session_grant_without_bearer() {
        let mut store = isolated_store("bootstrap-grant");
        store.set_session_grant(Some(session_grant(-1, 3600)));

        assert!(has_bootstrap_refresh_material(&store, "https://local.host"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn bootstrap_ignores_session_grant_for_other_server() {
        let mut store = isolated_store("bootstrap-other-server");
        let mut grant = session_grant(-1, 3600);
        grant.principal_server_url = "https://other.local.host".to_owned();
        store.set_session_grant(Some(grant));

        assert!(!has_bootstrap_refresh_material(
            &store,
            "https://local.host"
        ));
    }

    #[test]
    fn space_top_nav_excludes_discussion_surface() {
        let surfaces = SpaceSurface::top_nav();

        assert_eq!(
            surfaces,
            [
                SpaceSurface::Timeline,
                SpaceSurface::Board,
                SpaceSurface::Document
            ]
        );
        assert_eq!(
            SpaceSurface::from_preference("discussion"),
            Some(SpaceSurface::Board)
        );
    }

    #[test]
    fn setup_section_route_labels_match_realm_and_space_forms() {
        assert_eq!(route_label(&Route::Setup), "New Realm");
        assert_eq!(
            route_label(&Route::SetupSection {
                section: "realms".to_owned()
            }),
            "New Realm"
        );
        assert_eq!(
            route_label(&Route::SetupSection {
                section: "spaces".to_owned()
            }),
            "New Realm"
        );
        assert_eq!(
            route_label(&Route::SetupSection {
                section: "new-space".to_owned()
            }),
            "New Space"
        );
    }

    #[test]
    fn kanban_board_route_uses_space_context_for_mls_bootstrap() {
        let route = Route::KanbanBoard {
            space_id: "cx:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc".to_owned(),
            board_id: "cx:space:019e67ae-e633-7ef4-8a64-1f736d75d8ad".to_owned(),
        };

        assert!(route_uses_space_context(&route));
        assert_eq!(
            route.space_id(),
            Some("cx:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc")
        );
    }

    #[test]
    fn board_first_mls_bootstrap_key_never_prompts_for_passphrase() {
        let route = Route::KanbanBoard {
            space_id: "cx:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc".to_owned(),
            board_id: "cx:space:019e67ae-e633-7ef4-8a64-1f736d75d8ad".to_owned(),
        };
        let space_id = route.space_id().expect("board route carries a realm id");

        let key = mls_welcome_bootstrap_key(
            "http://localhost:8080",
            "secret-session-token",
            "did:web:yougen.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            space_id,
            true,
            true,
        )
        .expect("board route should be eligible for App-owned MLS Welcome bootstrap");
        let missing_welcome = crate::mls::runtime::MlsRuntimeStatus::MissingWelcome.user_message();

        assert!(!key.contains("secret-session-token"));
        assert!(!missing_welcome.to_ascii_lowercase().contains("passphrase"));
        assert!(missing_welcome.contains("MLS Welcome"));
        assert!(missing_welcome.contains("encrypted MLS history backup"));
    }

    #[test]
    fn mls_welcome_bootstrap_key_waits_for_e2ee_profile_and_sync() {
        let base = "https://local.host/";
        let session = "session-token";
        let actor = "did:web:yougen.example";
        let device = "cx:device:01964137-0000-7000-8000-000000000001";
        let space = "cx:realm:019e67a5-8edc-7347-9ca1-a0b880987bdc";

        assert_eq!(
            mls_welcome_bootstrap_key(base, session, actor, device, space, false, true),
            None
        );
        assert_eq!(
            mls_welcome_bootstrap_key(base, session, actor, device, space, true, false),
            None
        );
        assert_eq!(
            mls_welcome_bootstrap_key(base, "", actor, device, space, true, true),
            None
        );
        assert!(
            mls_welcome_bootstrap_key(base, session, actor, device, space, true, true).is_some()
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
            kind: SpacePreviewKind::Realm,
            realm_id: String::new(),
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
        assert_eq!(root.kind, SpacePreviewKind::Realm);
        assert_eq!(child.kind, SpacePreviewKind::Space);
    }

    #[test]
    fn sync_projection_marks_schema_space_with_home_realm() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "cx:realm:root".to_owned(),
            json!({
                "schema": "cx.schema.realm.v1",
                "summary": {"title": "Root"}
            }),
        );
        spaces.insert(
            "cx:space:child".to_owned(),
            json!({
                "schema": "cx.schema.space.v1",
                "realm_id": "cx:realm:root",
                "summary": {"title": "Child"}
            }),
        );

        let previews = space_previews_from_sync_spaces(&spaces);
        let child = previews
            .iter()
            .find(|space| space.space_id == "cx:space:child")
            .expect("child preview");

        assert_eq!(child.kind, SpacePreviewKind::Space);
        assert_eq!(child.realm_id, "cx:realm:root");
        assert_eq!(child.parent_space_id.as_deref(), Some("cx:realm:root"));
    }

    #[test]
    fn realm_projection_encryption_state_uses_profile_and_visibility() {
        assert!(realm_projection_is_encrypted(&json!({
            "summary": {"encryption_profile": "mls_rfc9420"}
        })));
        assert!(realm_projection_is_encrypted(&json!({
            "plaintext_visibility": {"default": "encrypted"}
        })));
        assert!(!realm_projection_is_encrypted(&json!({
            "encryption_profile": "none"
        })));
        assert!(!realm_projection_is_encrypted(&json!({
            "summary": {"title": "Legacy projection without encryption metadata"}
        })));
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
    fn sync_projection_keeps_realm_ids_from_account_subscribe() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "cx:realm:019e4cdc-b435-7e52-9ada-39d5ec134729".to_owned(),
            json!({
                "bottom_cells": [],
                "ephemeral": [],
                "flows": [{
                    "flow_id": "cx:flow:019e4cdc-b435-7e52-9ada-39d5ec134729",
                    "kind": "discussion",
                    "title": "Test"
                }],
                "state": [],
                "state_after": {
                    "events": [{
                        "flow_id": "cx:flow:019e4cdc-b435-7e52-9ada-39d5ec134729",
                        "kind": "discussion",
                        "title": "Test"
                    }]
                },
                "summary": {
                    "category": null,
                    "flow": {
                        "flow_id": "cx:flow:019e4cdc-b435-7e52-9ada-39d5ec134729",
                        "kind": "discussion",
                        "title": "Test"
                    },
                    "summary": null,
                    "tags": [],
                    "title": "Test"
                },
                "timeline": {"events": [], "limited": false},
                "unread": {"highlight_count": 0, "notification_count": 0}
            }),
        );

        let previews = space_previews_from_sync_spaces(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].space_id,
            "cx:realm:019e4cdc-b435-7e52-9ada-39d5ec134729"
        );
        assert_eq!(previews[0].name, "Test");
        assert_eq!(previews[0].kind, SpacePreviewKind::Realm);
    }

    #[test]
    fn merge_timeline_events_keeps_existing_messages_on_summary_only_delta() {
        let mut summary = TimelineEvent::system_notice("summary-cx:realm:test", "server", "old");
        summary.space_id = Some("cx:realm:test".to_owned());
        let message = TimelineEvent {
            id: "cx:event:message".to_owned(),
            space_id: Some("cx:realm:test".to_owned()),
            body: "welcome".to_owned(),
            ..TimelineEvent::default()
        };
        let mut updated_summary =
            TimelineEvent::system_notice("summary-cx:realm:test", "server", "new");
        updated_summary.space_id = Some("cx:realm:test".to_owned());

        let merged = merge_timeline_events(&[summary, message], vec![updated_summary]);

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].body, "new");
        assert_eq!(merged[1].body, "welcome");
    }

    #[test]
    fn full_sync_keep_set_preserves_local_space_under_joined_realm() {
        let mut server_set = BTreeSet::new();
        server_set.insert("cx:realm:root".to_owned());

        let mut cached = BTreeMap::new();
        cached.insert(
            "cx:realm:root".to_owned(),
            json!({"summary": {"title": "Root"}}),
        );
        cached.insert(
            "cx:space:child".to_owned(),
            json!({
                "__kind": "space",
                "realm_id": "cx:realm:root",
                "summary": {"title": "Child"}
            }),
        );
        cached.insert(
            "cx:space:stale".to_owned(),
            json!({
                "__kind": "space",
                "realm_id": "cx:realm:missing",
                "summary": {"title": "Stale"}
            }),
        );

        let keep = full_sync_projection_keep_set(&server_set, &cached);

        assert!(keep.contains("cx:realm:root"));
        assert!(keep.contains("cx:space:child"));
        assert!(!keep.contains("cx:space:stale"));
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
