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
    views::{ConnectionState, helpers::persist_config, timeline::TimelineEvent},
};

const DEMO_SPACE: &str = "cx:space:0196419b-0000-7000-8000-000000000000";

const STYLE: &str = r#"
body { margin: 0; font-family: Inter, Segoe UI, sans-serif; background: #f4f6f8; color: #18212f; }
button, input, textarea { font: inherit; }
.auth-shell { width: 100vw; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: #eef3f8; box-sizing: border-box; }
.auth-shell.theme-night { background: #0f172a; color: #e5edf7; }
.auth-card { width: min(420px, 100%); border: 1px solid #d7e0ea; border-radius: 8px; background: #fff; box-shadow: 0 16px 40px rgba(15, 23, 42, 0.12); }
.auth-shell.theme-night .auth-card { border-color: #2a3a52; background: #172033; }
.auth-panel { display: grid; gap: 22px; padding: 28px; }
.auth-brand { display: flex; align-items: center; gap: 12px; }
.auth-logo { width: 40px; height: 40px; border-radius: 8px; display: grid; place-items: center; background: #1d4ed8; color: #fff; font-weight: 800; }
.auth-brand h1 { margin: 0; font-size: 24px; line-height: 1.15; letter-spacing: 0; }
.auth-brand p { margin: 3px 0 0; color: #64748b; font-size: 13px; }
.auth-form { display: grid; gap: 10px; }
.auth-form label { color: #475569; font-size: 13px; font-weight: 700; }
.auth-form input { width: 100%; box-sizing: border-box; border: 1px solid #c5d1dd; border-radius: 6px; padding: 11px 12px; background: #fff; color: #142033; }
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
  content: "C";
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
.home-hero {
  overflow: hidden;
  background:
    radial-gradient(circle at 12% 0%, rgba(37, 99, 235, 0.18), transparent 34%),
    radial-gradient(circle at 90% 10%, rgba(15, 118, 110, 0.14), transparent 30%),
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
  border-color: rgba(15, 118, 110, 0.34);
  background: linear-gradient(135deg, rgba(236, 253, 245, 0.92), rgba(239, 246, 255, 0.94));
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
    radial-gradient(circle at 100% 0%, rgba(15, 118, 110, 0.12), transparent 32%),
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
    radial-gradient(circle at top left, rgba(37, 99, 235, 0.12), transparent 36%),
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
    radial-gradient(circle at top right, rgba(37, 99, 235, 0.22), transparent 42%),
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
  border-color: rgba(96, 165, 250, 0.44);
  background: rgba(37, 99, 235, 0.18);
}
.nav-item.cross-org {
  border-color: rgba(45, 212, 191, 0.34);
  background:
    linear-gradient(135deg, rgba(20, 184, 166, 0.18), rgba(37, 99, 235, 0.1)),
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
  background: var(--accent);
  border-color: transparent;
  color: var(--text-on-accent);
}

.secondary {
  background: var(--surface);
  color: var(--text);
}

.primary:hover { background: var(--accent-strong); }
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

@media (max-width: 1180px) {
  .shell.app.three-col {
    grid-template-columns: var(--sidebar-w) minmax(0, 1fr);
  }

  .right-panel {
    display: none;
  }
}

@media (max-width: 860px) {
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
    let is_auth_route = matches!(&route, Route::Login | Route::AuthCallback | Route::Register);
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
        let register_navigator = navigator.clone();

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
                        Route::Register => rsx! {
                            crate::views::register::RegisterPanel {
                                base_url,
                                account_did,
                                device_id,
                                config_store,
                                on_register: move |_| { let _ = register_navigator.push(Route::Login); },
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
                Link { class: "secondary", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), "Dashboard" }
                Link { class: "secondary", to: Route::Directory, onclick: move |_| mobile_nav_open.set(false), "Directory" }
                Link { class: "secondary", to: Route::Kanban, onclick: move |_| mobile_nav_open.set(false), "Board" }
                Link { class: "secondary", to: Route::Chat, onclick: move |_| mobile_nav_open.set(false), "Discussions" }
                Link { class: "secondary", to: Route::Notifications, onclick: move |_| mobile_nav_open.set(false), "Inbox" }
                Link { class: "secondary", to: Route::Settings, onclick: move |_| mobile_nav_open.set(false), "Settings" }
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
                    Route::Register => rsx! {
                        crate::views::register::RegisterPanel {
                            base_url,
                            account_did,
                            device_id,
                            config_store,
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
        Route::Register => "Register",
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
