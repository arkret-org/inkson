use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::*;
use dioxus_router::{Link, Router, hooks::*};
use serde_json::Value;

use crate::{
    api::ContrixApi,
    components::RightPanel,
    config::{LocalConfigStore, normalize_device_id},
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

const DEMO_SPACE: &str = "cx:space:0196419b-0000-7000-8000-000000000000";

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
.search input, .settings input, .workflow-form input, .composer textarea, .composer input { width: 100%; box-sizing: border-box; border: 1px solid #cbd5df; border-radius: 6px; padding: 10px 12px; background: white; color: #18212f; }
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
.mobile-status { display: grid; gap: 3px; padding: 8px 10px; border: 1px solid rgba(255,255,255,0.16); border-radius: 6px; color: #e2e8f0; }
.mobile-status .muted { color: #cbd5e1; }
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
.auth-form input:focus,
.settings input:focus,
.workflow-form input:focus,
.composer textarea:focus,
.composer input:focus,
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
.settings-header-card {
  display: grid;
  gap: 12px;
  border: 1px solid var(--cx-line);
  border-radius: 16px;
  padding: 14px;
  background:
    radial-gradient(circle at top left, rgba(43, 107, 79, 0.12), transparent 36%),
    var(--cx-surface);
  box-shadow: var(--cx-shadow-sm);
}
.settings-section-tabs {
  gap: 8px;
}
.settings-page-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}
.settings-page-chip {
  display: grid;
  gap: 2px;
  border: 1px solid var(--cx-line);
  border-radius: 12px;
  padding: 8px 10px;
  background: rgba(248, 250, 252, 0.76);
}
.settings-page-chip strong {
  font-size: 12px;
}
.settings-page-chip span {
  color: var(--cx-muted);
  font-size: 11px;
}
@media (max-width: 900px) {
  .dashboard-layout { grid-template-columns: 1fr; }
  .board-grid { grid-template-columns: 1fr; }
  .home-card-list.compact { grid-template-columns: 1fr; }
  .settings-page-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
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
  text-transform: uppercase;
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
  text-transform: uppercase;
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
.server-actions {
  display: grid;
  grid-template-columns: 1fr 1fr;
}
.nav-groups {
  display: grid;
  gap: 14px;
  overflow: auto;
  padding-right: 2px;
}
.nav-section {
  display: grid;
  gap: 7px;
}
.nav-section-title {
  color: #8fa2b8;
  font-size: 11px;
  font-weight: 900;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.nav-item {
  display: grid;
  gap: 3px;
  border: 1px solid transparent;
  border-radius: 14px;
  padding: 10px 11px;
  color: #e5edf7;
  text-decoration: none;
  background: rgba(255, 255, 255, 0.04);
}
.nav-item:hover,
.nav-item.active {
  border-color: rgba(113, 181, 143, 0.42);
  background: rgba(43, 107, 79, 0.16);
}
.nav-item.cross-org {
  border-color: rgba(165, 107, 19, 0.28);
  background:
    linear-gradient(135deg, rgba(58, 138, 103, 0.2), rgba(165, 107, 19, 0.1)),
    rgba(255, 255, 255, 0.04);
}
.nav-title {
  color: #f8fafc;
  font-size: 14px;
  font-weight: 800;
}
.nav-meta {
  color: #b6c4d4;
  font-size: 12px;
  line-height: 1.35;
}
.nav-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-top: 3px;
}
.sidebar-status {
  margin-top: 2px;
}
.topbar-eyebrow {
  color: var(--cx-muted);
  font-size: 12px;
  font-weight: 900;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.shell.rtl .context-row,
.shell.rtl .server-actions,
.shell.rtl .nav-item,
.shell.rtl .topbar {
  direction: rtl;
}
"#;

const CLAUDE_STYLE: &str = include_str!("../claude-design/styles.css");

const CLAUDE_APP_OVERRIDES: &str = r#"
:root {
  --sidebar-w: 272px;
  --right-pane-w: 340px;
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

[data-theme="dark"] {
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
  color: var(--text);
  background: var(--bg);
}

.shell.app.rtl {
  direction: rtl;
  grid-template-columns: var(--right-pane-w) minmax(0, 1fr) var(--sidebar-w);
}

.shell.app.rtl .sidebar { grid-column: 3; }
.shell.app.rtl .workspace { grid-column: 2; }
.shell.app.rtl .right-panel {
  grid-column: 1;
  border-left: 0;
  border-right: 1px solid var(--border);
}

.mobile-shellbar,
.mobile-drawer {
  display: none;
}

.sidebar {
  background: var(--surface);
  color: var(--text);
  border-right: 1px solid var(--border);
  padding: 0;
  gap: 0;
  min-height: 0;
  overflow: auto;
}

.sidebar-header .brand::before,
.mobile-shellbar .brand::before {
  content: none !important;
  display: none !important;
}

.sidebar-header .product-name {
  color: var(--text);
}

.sidebar-header .product-sub {
  color: var(--text-3);
}

.cx-connect-section {
  padding-top: 0;
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
  text-transform: uppercase;
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

.panel.right-panel {
  padding: 0;
  gap: 0;
  min-height: 0;
  pointer-events: auto;
}

.right-panel .section {
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
  gap: 10px;
}

.right-panel .section h2 {
  margin: 0;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-3);
  font-weight: 600;
}

.right-panel .metric-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.right-panel .metric {
  padding: 10px;
  border-radius: var(--radius-sm);
}

.right-panel .event {
  padding: 10px;
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
.nav-section-title {
  color: var(--nav-label);
}

.context-title,
.nav-title {
  color: var(--nav-text);
}

.context-meta,
.nav-meta,
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
.nav-item {
  border-color: color-mix(in srgb, var(--nav-border) 74%, rgba(255, 255, 255, 0.06));
}

.space-button,
.nav-item {
  color: var(--nav-text);
  background: var(--nav-soft);
}

.server-connect input {
  border-color: var(--nav-input-border);
  background: var(--nav-input-bg);
  color: var(--nav-text);
}

.space-button.active,
.nav-item:hover,
.nav-item.active {
  border-color: color-mix(in srgb, var(--accent) 52%, var(--accent-2));
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--accent) 14%, transparent), color-mix(in srgb, var(--accent-2) 11%, transparent)),
    var(--nav-soft);
}

.nav-item.cross-org,
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

@media (max-width: 1180px) {
  .shell.app.three-col {
    grid-template-columns: var(--sidebar-w) minmax(0, 1fr);
  }

  .right-panel {
    display: none;
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

  .shell.app,
  .shell.app.three-col {
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
    let mut selected_space = use_signal(String::new);
    let mut spaces = use_signal(Vec::<SpacePreview>::new);
    let mut timeline = use_signal(Vec::<TimelineEvent>::new);
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
    let crypto_state = use_signal(|| "No authenticated session".to_owned());
    let mut network_state = use_signal(|| "offline".to_owned());
    let last_error = use_signal(|| Option::<String>::None);
    let mut server_description = use_signal(|| Option::<ServerDescription>::None);
    let mut server_probe_status = use_signal(|| "server not probed".to_owned());
    let locale = use_signal(move || initial_locale);
    let theme = use_signal(move || initial_theme);
    let mut mobile_nav_open = use_signal(|| false);
    let mut global_query = use_signal(String::new);

    let active_server_description = server_description();
    let has_session = !token().trim().is_empty();
    let active_server_label = active_server_description
        .as_ref()
        .map(|description| {
            format!(
                "{} / {}",
                description.service_type, description.protocol_version
            )
        })
        .unwrap_or_else(|| base_url());
    let active_server_detail = active_server_description
        .as_ref()
        .map(|description| description.service_did.clone())
        .unwrap_or_else(|| {
            if base_url().trim().is_empty() {
                "No principal server selected".to_owned()
            } else {
                "Describe not loaded".to_owned()
            }
        });
    let account_label = if has_session {
        account_did()
    } else {
        "Not signed in".to_owned()
    };
    let account_detail = if has_session {
        format!("device {}", device_id())
    } else {
        "Connect a server, then use Login".to_owned()
    };
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
    let active_locale = locale();
    let active_direction = active_locale.direction();
    let direction_attr = active_direction.as_str();
    let locale_attr = active_locale.code();
    let active_theme = theme();
    let design_theme = match active_theme.as_str() {
        "night" => "dark",
        "light" => "light",
        _ => "light",
    };
    let route_title = route_label(&route);
    let title = selected_preview
        .as_ref()
        .map(|space| space.name.clone())
        .unwrap_or_else(|| route_title.to_owned());
    let shell_class = format!(
        "shell app three-col {}{}",
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
            main {
                class: auth_class,
                "dir": direction_attr,
                "lang": locale_attr,
                "data-direction": direction_attr,
                "data-locale": locale_attr,
                "data-theme": design_theme,
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
        div {
            class: shell_class,
            "dir": direction_attr,
            "lang": locale_attr,
            "data-direction": direction_attr,
            "data-locale": locale_attr,
            "data-theme": design_theme,
            "data-testid": "client-shell",
            div { class: "mobile-shellbar", "data-testid": "mobile-shellbar",
                button {
                    class: "secondary",
                    "data-testid": "mobile-nav-toggle",
                    onclick: move |_| mobile_nav_open.toggle(),
                    if mobile_nav_open() { "Close" } else { "Menu" }
                }
                div { class: "brand", "Contrix" }
                Link { class: "secondary", to: Route::Notifications, "Inbox" }
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
                }
                Link { class: "secondary", "data-testid": "mobile-dashboard-nav-button", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), "Dashboard" }
                Link { class: "secondary", "data-testid": "mobile-directory-nav-button", to: Route::Directory, onclick: move |_| mobile_nav_open.set(false), "Directory" }
                Link { class: "secondary", "data-testid": "mobile-timeline-nav-button", to: Route::Timeline, onclick: move |_| mobile_nav_open.set(false), "Timeline" }
                Link { class: "secondary", "data-testid": "mobile-product-nav-button", to: Route::Product, onclick: move |_| mobile_nav_open.set(false), "Create Space" }
                Link { class: "secondary", "data-testid": "mobile-kanban-nav-button", to: Route::Kanban, onclick: move |_| mobile_nav_open.set(false), "Board" }
                Link { class: "secondary", "data-testid": "mobile-chat-nav-button", to: Route::Chat, onclick: move |_| mobile_nav_open.set(false), "Discussions" }
                Link { class: "secondary", "data-testid": "mobile-notifications-nav-button", to: Route::Notifications, onclick: move |_| mobile_nav_open.set(false), "Inbox" }
                Link { class: "secondary", "data-testid": "mobile-settings-nav-button", to: Route::Settings, onclick: move |_| mobile_nav_open.set(false), "Settings" }
            }
            aside { class: "sidebar", "data-testid": "sidebar", role: "navigation", "aria-label": "Main navigation",
                div { class: "sidebar-header",
                    Link { class: "brand", to: Route::Dashboard, "aria-label": "Contrix Home",
                        span { class: "logo", "⌘" }
                        span { class: "product-meta",
                            span { class: "product-name", "Contrix" }
                            span { class: "product-sub", "v1 client" }
                        }
                    }
                }

                div { class: "sidebar-context", "data-testid": "principal-context", "aria-label": "Current principal server context",
                    Link { class: "context-line", to: Route::SettingsSection { section: "services".to_owned() },
                        span { class: "icon", "◌" }
                        span { class: "grow truncate",
                            span { class: "k", "Active Principal Server" }
                            span { class: "v", "{active_server_label}" }
                            span { class: "id mono", "{active_server_detail}" }
                        }
                        span { class: "pill muted xs", if has_session { "session" } else { "no session" } }
                    }
                    div { class: "context-sep" }
                    Link { class: "context-line", to: Route::Login,
                        span { class: "icon", "◇" }
                        span { class: "grow truncate",
                            span { class: "k", "Principal" }
                            span { class: "v", "{account_label}" }
                            span { class: "id mono", "{account_detail}" }
                        }
                        span { class: "mini", "›" }
                    }
                }

                div { class: "sidebar-section cx-connect-section",
                    div { class: "cx-connect-form",
                        input {
                            class: "cx-server-input",
                            "data-testid": "server-url-input",
                            value: "{base_url}",
                            "aria-label": "Principal Server URL",
                            oninput: move |event| {
                                let value = event.value();
                                base_url.set(value.clone());
                                token.set(String::new());
                                sync_cursor.set("-".to_owned());
                                spaces.set(Vec::new());
                                timeline.set(Vec::new());
                                server_description.set(None);
                                server_probe_status.set("server not probed".to_owned());
                                status.set(ConnectionState::Offline.label().to_owned());
                                network_state.set("offline".to_owned());
                                persist_config(config_store, value, account_did(), device_id(), String::new());
                            }
                        }
                        div { class: "actions server-actions",
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
                                to: Route::SettingsSection { section: "services".to_owned() },
                                "Services"
                            }
                        }
                    }
                }

                div { class: "sidebar-section", style: "padding-bottom: 0;",
                    Link {
                        class: "nav-item",
                        "data-testid": "directory-nav-button",
                        to: Route::Directory,
                        span { class: "icon", "⌕" }
                        span { class: "grow", "Search / Directory" }
                        span { class: "kbd-tag", "⌘K" }
                    }
                }

                div { class: "sidebar-section", "data-testid": "space-list",
                    h4 { "Personal" }
                    Link { class: "nav-item", to: Route::Dashboard,
                        span { class: "icon", "⌂" }
                        span { class: "grow", "Home" }
                    }
                    Link { class: "nav-item", "data-testid": "notifications-nav-button", to: Route::Notifications,
                        span { class: "icon", "□" }
                        span { class: "grow", "Inbox" }
                        span { class: "badge", "0" }
                    }
                    Link { class: "nav-item", to: Route::Directory,
                        span { class: "icon", "⌕" }
                        span { class: "grow", "Directory" }
                    }
                    Link { class: "nav-item", "data-testid": "settings-nav-button", to: Route::Settings,
                        span { class: "icon", "⚙" }
                        span { class: "grow", "Settings" }
                    }
                    if minimal_ready {
                        Link { class: "nav-item dim", "aria-label": "Timeline", to: Route::Timeline,
                            span { class: "icon", "≡" }
                            span { class: "grow", "Timeline" }
                        }
                    }
                    if kanban_ready {
                        Link { class: "nav-item dim", "aria-label": "Kanban", to: Route::Kanban,
                            span { class: "icon", "▦" }
                            span { class: "grow", "Kanban" }
                        }
                    }
                    if chat_ready {
                        Link { class: "nav-item dim", "aria-label": "Chat", to: Route::Chat,
                            span { class: "icon", "☰" }
                            span { class: "grow", "Chat" }
                        }
                    }
                    if full_ready {
                        Link { class: "nav-item dim", "aria-label": "Audit", to: Route::Audit,
                            span { class: "icon", "⌁" }
                            span { class: "grow", "Audit" }
                        }
                    }
                }

                div { class: "sidebar-section",
                    h4 {
                        span { "Spaces" }
                        Link { class: "add", to: Route::Product, "+" }
                    }
                    if spaces().is_empty() {
                        div { class: "nav-item dim", "data-testid": "space-empty-state",
                            span { class: "icon", "▣" }
                            span { class: "grow truncate", if has_session { "No spaces loaded" } else { "Sign in to load spaces" } }
                        }
                    } else {
                        for space in spaces().into_iter().take(5) {
                            Link {
                                class: if space.space_id == selected_space() { "nav-item active" } else { "nav-item" },
                                "data-testid": "space-button",
                                to: Route::TimelineSpace { space_id: space.space_id.clone() },
                                onclick: {
                                    let id = space.space_id.clone();
                                    move |_| selected_space.set(id.clone())
                                },
                                span { class: "icon", "▣" }
                                span { class: "grow truncate", "{space.name}" }
                                span { class: "pill muted xs", "Space" }
                            }
                        }
                    }
                }

                div { class: "sidebar-section",
                    h4 { "Cross-organization" }
                    div { class: "nav-item dim", "data-testid": "cross-org-empty-state",
                        span { class: "icon", "◎" }
                        span { class: "grow truncate", "No cross-org spaces loaded" }
                    }
                }

                div { class: "sidebar-section",
                    h4 {
                        span { "Personal Spaces" }
                        Link { class: "add", to: Route::Product, "+" }
                    }
                    div { class: "nav-item dim", "data-testid": "personal-spaces-empty-state",
                        span { class: "icon", "□" }
                        span { class: "grow truncate", "No personal spaces loaded" }
                    }
                }

                div { class: "sidebar-section",
                    h4 { "Protocol Tools" }
                    Link { class: "nav-item", "data-testid": "devices-nav-button", to: Route::Devices,
                        span { class: "icon", "◇" }
                        span { class: "grow", "Devices" }
                    }
                    Link { class: "nav-item", "data-testid": "readiness-nav-button", to: Route::Readiness,
                        span { class: "icon", "✓" }
                        span { class: "grow", "Readiness" }
                    }
                    Link { class: "nav-item", "data-testid": "product-nav-button", to: Route::Product,
                        span { class: "icon", "+" }
                        span { class: "grow", "Create Space" }
                    }
                }

                div { class: "status sidebar-status", "data-testid": "connection-status", role: "status", "aria-live": "polite",
                    div { class: "space-title", "data-testid": "status-label", "{status}" }
                    div { class: "muted mono", "data-testid": "sync-cursor", "cursor {sync_cursor}" }
                    div { class: "actions", style: "margin-top: 8px;",
                        span {
                            class: if network_state() == "online" { "badge badge-success" } else if network_state() == "reconnecting" { "badge badge-warning" } else { "badge badge-error" },
                            "data-testid": "network-state-badge",
                            "{network_state}"
                        }
                        if network_state() != "online" {
                            button {
                                class: "secondary compact-button",
                                "data-testid": "retry-connection-button",
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
                        div { class: "muted", style: "color: var(--danger-ink); font-size: 11px; margin-top: 4px;", "data-testid": "last-error",
                            "{err}"
                        }
                    }
                }

                Link { class: "sidebar-footer", to: Route::Settings,
                    span { class: "avatar", if has_session { "P" } else { "?" } }
                    span { class: "grow",
                        span { class: "who", "{account_label}" }
                        span { class: "handle", "{account_detail}" }
                    }
                    if has_session {
                        span { class: "dot-online", title: "online", style: "margin-right: 4px;" }
                    } else {
                        span { class: "pill muted xs", "offline" }
                    }
                    span { class: "btn icon sm ghost", "⚙" }
                }
            }

            main { class: "main workspace", "data-testid": "main-view", role: "main", "aria-label": "Main content",
                div { class: "topbar workspace-header",
                    div { class: "crumbs",
                        Link { to: Route::SettingsSection { section: "services".to_owned() }, strong { "{active_server_label}" } }
                        span { class: "crumb-tag", if has_session { "Session" } else { "Server" } }
                        span { class: "sep", "/" }
                        span { "{route_title}" }
                        span { class: "sep", "/" }
                        span { class: "id", "data-testid": "space-title", "{title}" }
                        if selected_preview.is_some() {
                            span { class: "id", "data-testid": "selected-space-id", "selected Space {selected_space}" }
                        }
                        span { class: "id", "Principal Server {base_url}" }
                    }
                    div { class: "actions",
                        div { class: "search",
                            span { "⌕" }
                            input {
                                "data-testid": "global-search-input",
                                value: "{global_query}",
                                placeholder: "Search spaces, flows, people, applets...",
                                oninput: move |event| global_query.set(event.value()),
                                onkeydown: move |event| {
                                    if event.key().to_string() == "Enter" && !global_query().trim().is_empty() {
                                        view.set(crate::views::View::Directory);
                                        let _ = navigator.push(Route::Directory);
                                    }
                                },
                            }
                            kbd { "⌘K" }
                        }
                        Link {
                            class: "btn sm",
                            "data-testid": "topbar-inbox-button",
                            to: Route::Notifications,
                            "Inbox"
                        }
                        Link {
                            class: "btn sm primary",
                            "data-testid": "topbar-create-button",
                            to: Route::Product,
                            "+ Space"
                        }
                        span { class: "pill muted xs", "data-testid": "topbar-members", "{spaces().len()} spaces" }
                    }
                }
                div { class: "workspace-body",
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
                        if let Some(sid) = route.space_id() {
                            selected_space.set(sid.to_owned());
                        }
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

fn route_label(route: &Route) -> &'static str {
    match route {
        Route::Dashboard => "Home",
        Route::Login | Route::AuthCallback => "Login",
        Route::Timeline | Route::TimelineSpace { .. } => "Timeline",
        Route::Directory => "Directory",
        Route::Product => "Create Space",
        Route::Settings | Route::SettingsSection { .. } => "Settings",
        Route::Devices => "Devices",
        Route::VerifyDevice => "Verify Device",
        Route::Readiness => "Readiness",
        Route::SpaceAdmin { .. } => "Space Admin",
        Route::Audit => "Audit",
        Route::Kanban | Route::KanbanSpace { .. } => "Kanban",
        Route::Chat | Route::ChatSpace { .. } => "Chat",
        Route::Notifications => "Inbox",
        Route::Document | Route::DocumentSpace { .. } => "Files",
        Route::Call => "Call",
        Route::Recovery => "Recovery",
        Route::Applets => "Applets",
        Route::Onboarding => "Onboarding",
        Route::Quarantine => "Quarantine",
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
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    network_state: Signal<String>,
    last_error: Signal<Option<String>>,
    server_description: Signal<Option<ServerDescription>>,
    server_probe_status: Signal<String>,
}

fn connect(base: String, actor: String, device: String, ctx: ConnectContext) {
    let device = normalize_device_id(&device);
    spawn(async move {
        let mut status = ctx.status;
        let mut sync_cursor = ctx.sync_cursor;
        let token = ctx.token;
        let mut spaces = ctx.spaces;
        let mut timeline = ctx.timeline;
        let mut device_queue = ctx.device_queue;
        let mut repo_state = ctx.repo_state;
        let mut crypto_state = ctx.crypto_state;
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
                let description = match api.describe().await {
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
                        server_description.set(Some(description.clone()));
                        description
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
                        return;
                    }
                };

                let session_token = token();
                if session_token.trim().is_empty() {
                    status.set(format!(
                        "Connected: {} / {}; login required",
                        description.service_type, description.protocol_version
                    ));
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
                persist_config(
                    config_store,
                    base.clone(),
                    actor.clone(),
                    device.clone(),
                    session_token,
                );
                crypto_state.set(format!("session token loaded for {device}"));

                match authed.search_spaces("", None).await {
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
                    let synced_timeline = timeline_events_from_sync_spaces(&sync.spaces);
                    {
                        let mut current_spaces = spaces.write();
                        for preview in space_previews_from_sync_spaces(&sync.spaces) {
                            if let Some(existing) = current_spaces
                                .iter_mut()
                                .find(|space| space.space_id == preview.space_id)
                            {
                                *existing = preview;
                            } else {
                                current_spaces.push(preview);
                            }
                        }
                    }
                    timeline.set(synced_timeline);
                    device_queue.set(sync.to_device.len());
                    sync_cursor.set(sync.next_batch);
                } else {
                    status.set(format!(
                        "Connected: authenticated sync unavailable, showing cached/local state"
                    ));
                }
                if let Ok(events) = authed.events_describe().await {
                    if let Some(frontier) = frontier_label(&events.frontier) {
                        repo_state.set(frontier);
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

fn space_previews_from_sync_spaces(spaces: &BTreeMap<String, Value>) -> Vec<SpacePreview> {
    spaces
        .iter()
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
            }
        })
        .collect()
}

fn timeline_events_from_sync_spaces(spaces: &BTreeMap<String, Value>) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for (id, body) in spaces {
        events.push(TimelineEvent::system_notice(
            format!("summary-{id}"),
            "serverx",
            format!(
                "{id}: {}",
                body["summary"]["summary"]
                    .as_str()
                    .unwrap_or("No summary available")
            ),
        ));

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
