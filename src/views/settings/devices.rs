//! G3.Y1 — Device management (`/settings/devices`) and QR-driven
//! pairing (`/settings/devices/pair`).
//!
//! Surfaces:
//! - `device-list` — wrapper element listing the principal's active devices from `GET
//!   /_arkret/self/account/viewer` via [`crate::transport::TransportClient::list_devices`]
//! - `device-row` per row, with `data-device-id` and a `device-row-current` boolean tag on the row
//!   matching the local `LocalStateStore::device_id`
//! - `device-revoke-button` per row, which opens a confirmation modal
//! - `device-revoke-confirm-button` / `device-revoke-status` after the user confirms; revoke
//!   submits the spec-canonical durable `ak.device.revoke` Control Move on the principal control
//!   stream (envelope `seal_basis` minted from `ak.self.seals.read.frontier.v1`, SPEC-SOL-003) with
//!   a [`crate::transport::TransportClient::revoke_device`], then rotates the account MLS history
//!   secret and rewraps local `mls_history` backups.
//!
//! The pair strand on `/settings/devices/pair` carries:
//! - `pair-device-start-button` — on the device being added, generates a pairing request payload.
//! - `pair-device-qr` — SVG QR code (pure-Rust `qrcode` crate) with the encoded payload mirrored as
//!   plain text in `pair-device-secret` so e2e harnesses that don't OCR can read it directly.
//! - `pair-device-status` — feedback area.
//! - `accept-pairing-input` / `accept-pairing-button` / `accept-pairing-status` — existing-device
//!   side: paste or scan the new-device request and approve through the spec account pairing route.
//!
//! Spec references:
//! - `crypto-media/device-lifecycle.md` §2.1 (5-step pairing), §2.2 (revoke), §5.1–§5.2 (PCR
//!   genesis + device possession transcript), §6 (device list)
//! - `identity/key-management.md` §5.0–§5.2 (`ak.device.authorize` / `ak.device.revoke`)
//!
//! ## Endpoints
//!
//! - `GET /_arkret/self/account/viewer` — implemented (soland)
//! - `POST /_arkret/gate/account/device-pair` — spec-level device pairing.

use arkret_wire::event_kind_str;
use dioxus::prelude::*;
use dioxus_router::Link;
use dioxus_router::hooks::use_route;
use serde_json::{Value, json};

use crate::components::{EmptyState, EmptyStateKind, HelpTip, QrSharePanel, UiIcon};
use crate::i18n::{tr, tr_args};
use crate::identity::device_pairing::approve_device_pairing;
use crate::operation::uuid_v7;
use crate::routes::Route;
use crate::state::LocalStateStore;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

#[derive(Clone, Debug, PartialEq)]
struct DeviceRow {
    device_id: String,
    display_name: String,
    verification_state: String,
    authorized_at: String,
}

fn parse_devices(value: &Value) -> Vec<DeviceRow> {
    value
        .get("devices")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let device_id = item.get("device_id").and_then(Value::as_str)?.to_owned();
                    let display_name = item
                        .get("display_name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim()
                        .to_owned();
                    let verification_state = item
                        .get("verification_state")
                        .and_then(Value::as_str)
                        .unwrap_or("unresolved")
                        .to_owned();
                    let authorized_at = item
                        .get("authorized_at")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    Some(DeviceRow {
                        device_id,
                        display_name,
                        verification_state,
                        authorized_at,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
/// Compact base64url handoff token embedded in the pairing QR deep-link.
/// Mirrors the agent-pairing token (`{"r":request_id,"c":code}`); the resolving
/// device decodes it and calls `ak.open.device_pairing.read.resolve.v1`.
fn build_device_pairing_handoff_token(
    device_pairing_request_id: &str,
    pairing_code: &str,
) -> String {
    let canonical = arkret_sdk::canonical::canonical_json_bytes(&json!({
        "r": device_pairing_request_id,
        "c": pairing_code,
    }))
    .expect("a JSON object containing strings always canonicalizes");
    arkret_sdk::base64url_encode(canonical)
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
/// The short HTTPS deep-link the new device renders as its QR. The fragment
/// carries only the handoff token — never in the query string — so it stays out
/// of server/proxy logs. Mirrors `build_agent_pairing_deep_link`.
fn build_device_pairing_deep_link(
    base_url: &str,
    token: &str,
    target_proof: &arkret_sdk::DevicePairingTargetProof,
) -> String {
    let base = base_url.trim_end_matches('/');
    let proof = arkret_sdk::canonical::canonical_json_bytes(target_proof)
        .map(arkret_sdk::base64url_encode)
        .expect("a typed target proof always canonicalizes");
    format!("{base}/_arkret/open/device-pairing/resolve#token={token}&proof={proof}")
}

/// Parse a scanned/pasted pairing deep-link (or a bare token) into the compact
/// handoff token expected by `ak.open.device_pairing.read.resolve.v1`.
fn extract_device_pairing_token(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((_, fragment)) = trimmed.split_once("#token=") {
        let token = fragment.split(['&', ' ']).next().unwrap_or("").trim();
        if !token.is_empty() {
            return Some(token.to_owned());
        }
    }
    // Bare token pasted directly (no URL wrapper).
    if !trimmed.contains(['/', ' ', '#']) {
        return Some(trimmed.to_owned());
    }
    None
}

fn extract_device_pairing_target_proof(
    input: &str,
) -> Option<arkret_sdk::DevicePairingTargetProof> {
    let (_, encoded) = input.trim().split_once("&proof=")?;
    let encoded = encoded.split(['&', ' ']).next()?.trim();
    let bytes = arkret_sdk::base64url_decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[component]
pub fn SettingsDevicesPanel(
    principal_id: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let session = crate::app::SessionContext::get();
    let base_url = session.base_url;
    let state_store = session.state_store;
    let Some(account) = session.active_account() else {
        return rsx! {};
    };
    let authority = account.authority;
    let route = use_route::<Route>();
    let pair_mode = matches!(route, Route::SettingsDevicesPair);

    let mut devices = use_signal(Vec::<DeviceRow>::new);
    let mut load_status = use_signal(String::new);
    let revoke_target = use_signal(|| Option::<String>::None);
    let revoke_status = use_signal(String::new);
    let revoke_passphrase = use_signal(crate::fresh_device_recovery::RecoveryWordsInput::default);

    // Auto-load guard so the device list populates on mount (and once a
    // session credential arrives) without the user clicking Refresh first.
    let mut auto_loaded = use_signal(|| false);

    // ── Pair (current device side) state ─────────────────────────────
    let pair_payload = use_signal(String::new);
    let pair_status = use_signal(String::new);
    // Staged short-link handle + code (for the new device's status poll).
    let pair_request_id = use_signal(String::new);
    let pair_code = use_signal(String::new);
    let pair_action_busy = use_signal(|| false);

    // ── Accept (already-authorized device side) state ─────────────────
    let accept_input = use_signal(String::new);
    let accept_status = use_signal(String::new);
    let accept_action_busy = use_signal(|| false);
    // Resolved pairing bootstrap JSON (empty = not yet resolved), held between
    // the resolve step and the human code-compare + approve step.
    let accept_resolved = use_signal(String::new);

    let local_device_id = device_id();
    let has_session = !token().trim().is_empty();

    let refresh_devices = {
        let base = base_url();
        let api_token = token();
        move |_evt: MouseEvent| {
            let base = base.clone();
            let api_token = api_token.clone();
            load_status.set("Loading…".to_owned());
            spawn(async move {
                match with_authed_sdk_client(&base, api_token, |http| async move {
                    crate::transport::keys::list_devices(&http).await
                })
                .await
                {
                    Ok(value) => {
                        let value = serde_json::to_value(&value).unwrap_or_default();
                        let rows = parse_devices(&value);
                        let count = rows.len();
                        devices.set(rows);
                        load_status.set(format!("Loaded {count} device(s)"));
                    }
                    Err(err) => {
                        load_status.set(format!("Load failed: {}", err.display()));
                    }
                }
            });
        }
    };

    // Auto-load the device list on mount. Reads `token()` so it re-runs
    // when the session credential arrives; the `auto_loaded` guard keeps it to
    // a single fetch. Skipped in pair mode (which has no list).
    {
        let base = base_url();
        let api_token = token();
        use_effect(move || {
            if pair_mode || api_token.trim().is_empty() || auto_loaded() {
                return;
            }
            auto_loaded.set(true);
            let base = base.clone();
            let api_token = api_token.clone();
            load_status.set("Loading…".to_owned());
            spawn(async move {
                match with_authed_sdk_client(&base, api_token, |http| async move {
                    crate::transport::keys::list_devices(&http).await
                })
                .await
                {
                    Ok(value) => {
                        let value = serde_json::to_value(&value).unwrap_or_default();
                        let rows = parse_devices(&value);
                        let count = rows.len();
                        devices.set(rows);
                        load_status.set(format!("Loaded {count} device(s)"));
                    }
                    Err(err) => {
                        load_status.set(format!("Load failed: {}", err.display()));
                    }
                }
            });
        });
    }

    rsx! {
        div { class: "settings-content-stack", "data-testid": "settings-devices-panel",
            div { class: "event device-access-toolbar",
                div { class: "device-access-toolbar-head",
                    div {
                        strong { {tr("settings.devices.title")} }
                        span { class: "muted", {tr("settings.devices.subtitle")} }
                    }
                    div { class: "device-access-session-state",
                        span { class: if has_session { "badge success" } else { "badge warning" },
                            if has_session { {tr("settings.devices.session_active")} } else { {tr("settings.devices.session_inactive")} }
                        }
                        HelpTip { text: tr("settings.devices.help") }
                    }
                }
                nav {
                    class: "device-access-tabs",
                    "aria-label": tr("settings.devices.tabs_aria_label"),
                    Link {
                        class: if !pair_mode { "device-access-tab active" } else { "device-access-tab" },
                        "aria-current": if !pair_mode { "page" } else { "false" },
                        to: Route::SettingsDevices,
                        UiIcon { name: "monitor" }
                        {tr("settings.devices.tab_list")}
                    }
                    Link {
                        class: if pair_mode { "device-access-tab active" } else { "device-access-tab" },
                        "aria-current": if pair_mode { "page" } else { "false" },
                        to: Route::SettingsDevicesPair,
                        UiIcon { name: "plus" }
                        {tr("settings.devices.tab_add")}
                    }
                }
                if !pair_mode {
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: "btn device-access-refresh",
                        "data-testid": "device-list-refresh",
                        onclick: refresh_devices,
                        UiIcon { name: "refresh" }
                        {tr("settings.devices.refresh")}
                    }
                }
            }

            if pair_mode {
                {render_pair_strand(
                    principal_id,
                    device_id,
                    authority.clone(),
                    base_url,
                    token,
                    pair_payload,
                    pair_status,
                    pair_request_id,
                    pair_code,
                    pair_action_busy,
                    accept_input,
                    accept_status,
                    accept_resolved,
                    accept_action_busy,
                )}
            } else {
                {render_device_list(
                    devices,
                    local_device_id.clone(),
                    load_status,
                    revoke_target,
                    revoke_status,
                    base_url,
                    principal_id,
                    device_id,
                    token,
                    state_store,
                    authority.clone(),
                    revoke_passphrase,
                )}
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_device_list(
    devices: Signal<Vec<DeviceRow>>,
    local_device_id: String,
    load_status: Signal<String>,
    revoke_target: Signal<Option<String>>,
    revoke_status: Signal<String>,
    base_url: Signal<String>,
    principal_id: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    state_store: SyncSignal<LocalStateStore>,
    authority: arkret_sdk::AccountId,
    revoke_passphrase: Signal<crate::fresh_device_recovery::RecoveryWordsInput>,
) -> Element {
    let rows = devices();
    let has_rows = !rows.is_empty();
    let status_msg = load_status();
    let revoke_msg = revoke_status();
    let pending_revoke = revoke_target();
    rsx! {
        div { class: "event device-list-card", "data-testid": "device-list",
            div { class: "event-head",
                span { {tr("settings.devices.active_title")} }
                span { "{status_msg}" }
            }
            if !has_rows {
                EmptyState {
                    kind: EmptyStateKind::Empty,
                    title: tr("settings.devices.empty_title"),
                    message: Some(tr("settings.devices.empty_message")),
                    test_id: Some("device-list-empty".to_owned()),
                }
            } else {
                div { class: "device-list-table", role: "table",
                    div { class: "device-list-header", role: "row",
                        span { role: "columnheader", {tr("settings.devices.column_device")} }
                        span { role: "columnheader", {tr("settings.devices.column_verification")} }
                        span { role: "columnheader", {tr("settings.devices.column_authorized")} }
                        span { role: "columnheader", {tr("settings.devices.column_actions")} }
                    }
                    for row in rows.iter() {
                        {render_device_row(
                            row.clone(),
                            local_device_id.clone(),
                            revoke_target,
                        )}
                    }
                }
            }
            if !revoke_msg.is_empty() {
                div { class: "muted", "data-testid": "device-revoke-status", "{revoke_msg}" }
            }
        }

        if let Some(target) = pending_revoke.clone() {
            {render_revoke_modal(
                target,
                base_url,
                token,
                revoke_target,
                revoke_status,
                devices,
                load_status,
                state_store,
                principal_id,
                device_id,
                authority,
                revoke_passphrase,
            )}
        }

    }
}

/// `device-lifecycle.md` §2.1.1 step 3 — everything the approval UI MUST put
/// in front of the user before the explicit confirmation: the requesting
/// device's metadata, its `device_id` and key fingerprint, the full pairing
/// code and the `gate_audience`.
///
/// The whole set is projected from the resolved `DevicePairingBootstrap` in
/// one place so no surface can render the pairing code without the identity
/// context that makes comparing it meaningful.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PairingApprovalReview {
    display_name: String,
    device_id: String,
    key_fingerprint: String,
    platform: String,
    gate_audience: String,
    pairing_code: String,
    expires_at: String,
}

impl PairingApprovalReview {
    fn from_bootstrap(bootstrap: &arkret_sdk::DevicePairingBootstrap) -> Self {
        let unknown = tr("settings.devices.accept_unnamed_device");
        Self {
            display_name: bootstrap
                .display_name
                .as_ref()
                .map(|name| name.as_str().to_owned())
                .unwrap_or_else(|| unknown.clone()),
            device_id: bootstrap.new_device_pubkey.kid.as_str().to_owned(),
            key_fingerprint: device_key_fingerprint(&bootstrap.new_device_pubkey),
            platform: bootstrap
                .device_metadata
                .as_ref()
                .and_then(|metadata| metadata.platform.as_ref())
                .map(|platform| platform.as_str().to_owned())
                .unwrap_or_else(|| unknown.clone()),
            gate_audience: bootstrap.gate_audience_uri.clone(),
            pairing_code: bootstrap.pairing_code.as_str().to_owned(),
            expires_at: bootstrap.expires_at.to_rfc3339(),
        }
    }
}

/// Human-comparable fingerprint of the requesting device's public key.
/// Grouped in fours so a person can read it aloud against the new device's
/// screen without losing their place.
fn device_key_fingerprint(public_key: &arkret_sdk::PublicKey) -> String {
    let digest = arkret_sdk::canonical::sha256_hex(public_key.key.as_str().as_bytes());
    digest
        .chars()
        .take(32)
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Element-style verification shield for the device list. Maps the
/// `verification_state` (`device-lifecycle.md` §6) to a colored pill:
/// verified → green shield, unverified → amber, revoked → red. Unknown or
/// missing values fail closed to unverified.
fn device_verification_badge(state: &str) -> Element {
    let raw = state.trim().to_ascii_lowercase();
    let normalized = match raw.as_str() {
        "verified" | "unverified" | "revoked" => raw.as_str(),
        _ => "unverified",
    };
    let (class, glyph, label) = match normalized {
        "verified" => ("badge success", "🛡", tr("settings.devices.state_verified")),
        "unverified" => (
            "badge warning",
            "⚠",
            tr("settings.devices.state_unverified"),
        ),
        "revoked" => ("badge danger", "⊘", tr("settings.devices.state_revoked")),
        _ => unreachable!("verification state normalized"),
    };
    rsx! {
        span {
            class: "{class} device-verification-badge",
            "data-testid": "device-verification-badge",
            "data-verification": "{normalized}",
            title: tr_args("settings.devices.state_title", &[("state", label.clone())]),
            "{glyph} {label}"
        }
    }
}

fn render_device_row(
    row: DeviceRow,
    local_device_id: String,
    mut revoke_target: Signal<Option<String>>,
) -> Element {
    let is_current = !local_device_id.is_empty() && local_device_id == row.device_id;
    let row_class = if is_current {
        "device-row current"
    } else {
        "device-row"
    };
    // `data-testid` keeps the single canonical "device-row" value for
    // generic matchers, while `data-testid-current` carries the
    // current-device flag as a sibling attribute. The cotest scenario
    // can target either: `[data-testid="device-row"][data-current="true"]`
    // or the dedicated `device-row-current` testid below.
    let device_id_for_button = row.device_id.clone();
    let device_id_label = short_protocol_id(&row.device_id);
    // Friendly name is the primary label; the short device-id fragment
    // (`#<suffix>`) disambiguates devices that share a display name, and
    // the DID stays reachable via the row tooltip.
    let id_suffix = crate::identity::device_name::device_id_short_suffix(&row.device_id);
    let has_name = !row.display_name.is_empty();
    let primary_label = if has_name {
        row.display_name.clone()
    } else {
        device_id_label.clone()
    };
    rsx! {
        div {
            class: "{row_class}",
            "data-testid": "device-row",
            "data-device-id": "{row.device_id}",
            "data-current": if is_current { "true" } else { "false" },
            role: "row",
            div { class: "device-list-cell device-list-cell-identity", role: "cell",
                span { class: "device-list-cell-label", {tr("settings.devices.column_device")} }
                div { class: "device-identity",
                    strong {
                        title: "{row.device_id}",
                        "data-testid": "device-row-name",
                        "{primary_label}"
                    }
                    if !id_suffix.is_empty() {
                        span {
                            class: "muted device-id-suffix",
                            "data-testid": "device-row-id-suffix",
                            "#{id_suffix}"
                        }
                    }
                }
                if has_name {
                    div {
                        class: "muted device-id-secondary",
                        title: "{row.device_id}",
                        "{device_id_label}"
                    }
                }
                if is_current {
                    span {
                        class: "badge green",
                        "data-testid": "device-row-current",
                        "data-device-id": "{row.device_id}",
                        {tr("settings.devices.this_device")}
                    }
                }
            }
            div { class: "device-list-cell", role: "cell",
                span { class: "device-list-cell-label", {tr("settings.devices.column_verification")} }
                {device_verification_badge(&row.verification_state)}
            }
            div { class: "device-list-cell", role: "cell",
                span { class: "device-list-cell-label", {tr("settings.devices.column_authorized")} }
                span { class: "device-authorized-at", if row.authorized_at.is_empty() { "—" } else { "{row.authorized_at}" } }
            }
            div { class: "device-list-cell device-list-cell-actions", role: "cell",
                span { class: "device-list-cell-label", {tr("settings.devices.column_actions")} }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "device-revoke-button",
                    disabled: is_current,
                    onclick: move |_| {
                        revoke_target.set(Some(device_id_for_button.clone()));
                    },
                    if is_current { {tr("settings.devices.revoke_self_blocked")} } else { {tr("settings.devices.revoke")} }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_revoke_modal(
    target: String,
    base_url: Signal<String>,
    token: Signal<String>,
    mut revoke_target: Signal<Option<String>>,
    mut revoke_status: Signal<String>,
    mut devices: Signal<Vec<DeviceRow>>,
    mut load_status: Signal<String>,
    state_store: SyncSignal<LocalStateStore>,
    principal_id: Signal<String>,
    device_id: Signal<String>,
    authority: arkret_sdk::AccountId,
    mut revoke_passphrase: Signal<crate::fresh_device_recovery::RecoveryWordsInput>,
) -> Element {
    let confirm_target = target.clone();
    let target_label = short_protocol_id(&target);
    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    revoke_target.set(None);
                }
            },
            "data-testid": "device-revoke-modal",
            "aria-labelledby": "device-revoke-title",
            div { class: "modal event device-revoke-dialog",
                div { class: "modal-head event-head",
                    h3 { id: "device-revoke-title", {tr("settings.devices.revoke_title")} }
                    span { class: "muted device-revoke-target", title: "{target}", "{target_label}" }
                }
                div { class: "modal-body workflow-form device-revoke-modal-body",
                    p {
                        {tr("settings.devices.revoke_body_before")}
                        code { {event_kind_str::DEVICE_REVOKE} }
                        {tr("settings.devices.revoke_body_after")}
                    }
                    p { class: "muted", "data-testid": "device-revoke-threat-note",
                        {tr("settings.devices.revoke_threat_note")}
                    }
                    Label { html_for: "device-revoke-passphrase", {tr("settings.devices.revoke_recovery_label")} }
                    Input {
                        id: "device-revoke-passphrase",
                        "data-testid": "device-revoke-passphrase-input",
                        r#type: "password",
                        value: "{revoke_passphrase().as_str()}",
                        autocomplete: "off",
                        placeholder: tr("settings.devices.revoke_recovery_placeholder"),
                        oninput: move |event: FormEvent| {
                            revoke_passphrase.write().replace(event.value());
                        },
                    }
                }
                div { class: "modal-foot actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "device-revoke-cancel-button",
                        onclick: move |_| {
                            revoke_target.set(None);
                        },
                        {tr("common.cancel")}
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "device-revoke-confirm-button",
                        disabled: revoke_passphrase().is_empty(),
                        onclick: move |_| {
                            let base = base_url();
                            let api_token = token();
                            let actor = principal_id();
                            let current_device = device_id();
                            let target_id = confirm_target.clone();
                            let target_for_status = target_id.clone();
                            let target_label = short_protocol_id(&target_for_status);
                            let Some(recovery_words) = revoke_passphrase().normalized() else {
                                revoke_status.set(
                                    "Enter your 24-word Recovery Key before revoking — it is required to rotate the MLS history secret.".to_owned(),
                                );
                                return;
                            };
                            let snapshots = state_store.read().mls_local_checkpoints();
                            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                            let authority = authority.clone();
                            revoke_status.set(format!("Revoking {target_label}…"));
                            spawn(async move {
                                let target_label = short_protocol_id(&target_for_status);
                                let rotation_result = with_authed_api(
                                    &base,
                                    api_token.clone(),
                                    move |api| async move {
                                        crate::mls::account_recovery::execute_device_revoke_security_rotation(
                                            &api,
                                            secure_store,
                                            &crate::app::runtime_adapter::state_store_handle(
                                                state_store,
                                            ),
                                            &authority,
                                            &actor,
                                            &current_device,
                                            &target_id,
                                            recovery_words.as_str(),
                                            &snapshots,
                                        )
                                        .await
                                    },
                                )
                                .await;
                                match rotation_result {
                                    Ok(rotation) => {
                                        revoke_status.set(format!(
                                            "Revoked {target_label} through transaction {}. Rotated MLS history secret to v{} with {} replacement backup object(s); both old series were durably erased.",
                                            rotation.transaction_id,
                                            rotation.new_secret_version,
                                            rotation.replacement_backup_count,
                                        ));
                                        revoke_passphrase.write().clear();
                                        revoke_target.set(None);
                                        // Re-fetch to reflect the new
                                        // active set. Failure here is
                                        // non-fatal; the status text
                                        // already records the revoke.
                                        let base_refresh = base.clone();
                                        let token_refresh = api_token.clone();
                                        spawn(async move {
                                            if let Ok(value) = with_authed_sdk_client(
                                                &base_refresh,
                                                token_refresh,
                                                |http| async move {
                                                    crate::transport::keys::list_devices(&http).await
                                                },
                                            )
                                            .await
                                            {
                                                let value =
                                                    serde_json::to_value(&value).unwrap_or_default();
                                                let rows = parse_devices(&value);
                                                let count = rows.len();
                                                devices.set(rows);
                                                load_status.set(format!("Loaded {count} device(s)"));
                                            }
                                        });
                                    }
                                    Err(err) => {
                                        revoke_status.set(format!(
                                            "Revoke transaction for {target_label} failed safely and can be resumed: {}",
                                            err.display()
                                        ));
                                    }
                                }
                            });
                        },
                        {tr("settings.devices.revoke_confirm")}
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_pair_strand(
    principal_id: Signal<String>,
    device_id: Signal<String>,
    authority: arkret_sdk::AccountId,
    base_url: Signal<String>,
    token: Signal<String>,
    mut pair_payload: Signal<String>,
    mut pair_status: Signal<String>,
    mut pair_request_id: Signal<String>,
    mut pair_code: Signal<String>,
    mut pair_action_busy: Signal<bool>,
    mut accept_input: Signal<String>,
    mut accept_status: Signal<String>,
    mut accept_resolved: Signal<String>,
    mut accept_action_busy: Signal<bool>,
) -> Element {
    let actor_id = principal_id();
    let payload_value = pair_payload();
    let status_value = pair_status();
    let pair_code_value = pair_code();
    let pair_busy = pair_action_busy();
    let accept_resolved_value = accept_resolved();
    let resolved_approval = serde_json::from_str::<
        crate::identity::device_pairing::ResolvedPairingApproval,
    >(&accept_resolved_value)
    .ok()
    .map(|value| PairingApprovalReview::from_bootstrap(&value.bootstrap));
    let accept_busy = accept_action_busy();

    // Render a QR for the current payload (if any). `qrcode` returns
    // the rendered SVG as a String which Dioxus wraps in
    // `dangerous_inner_html` — safe here because the SVG body is
    // produced by the crate from a string we constructed.
    let qr_svg = if payload_value.is_empty() {
        String::new()
    } else {
        match qrcode::QrCode::with_error_correction_level(
            payload_value.as_bytes(),
            qrcode::EcLevel::M,
        ) {
            Ok(code) => code
                .render::<qrcode::render::svg::Color<'_>>()
                .min_dimensions(192, 192)
                .quiet_zone(true)
                .build(),
            Err(_) => String::new(),
        }
    };

    let payload_for_state = payload_value.clone();

    rsx! {
        div { class: "device-pairing-layout",
        // On the new device, create the out-of-band QR/link that an already
        // authorized device must scan or open.
        div { class: "event pair-device-card", "data-testid": "pair-device-card",
            div { class: "event-head",
                div {
                    span { class: "device-pairing-eyebrow", {tr("settings.devices.pair_this_browser")} }
                    h3 { {tr("settings.devices.pair_title")} }
                }
                span { class: "badge warning", {tr("settings.devices.pair_required_badge")} }
            }
            p { class: "muted",
                {tr("settings.devices.pair_body")}
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "pair-device-start-button",
                    disabled: actor_id.trim().is_empty() || pair_busy,
                    onclick: move |_| {
                        if pair_action_busy() {
                            return;
                        }
                        let actor = principal_id();
                        if actor.trim().is_empty() {
                            pair_status.set("No active session. Sign in first.".to_owned());
                            return;
                        }
                        let requesting_device_id = device_id();
                        if requesting_device_id.trim().is_empty() {
                            pair_status.set("This browser has no local device id yet. Sign in again or reload before pairing.".to_owned());
                            return;
                        }
                        let signer = match crate::event_signer::bind_active_signer_device_id(
                            &requesting_device_id,
                        ) {
                            Ok(Some(signer)) => signer,
                            Ok(None) => {
                                pair_status.set(
                                    "This browser has no device identity signer yet. Reload before pairing."
                                        .to_owned(),
                                );
                                return;
                            }
                            Err(err) => {
                                pair_status.set(format!(
                                    "Binding this device signer failed: {err}"
                                ));
                                return;
                            }
                        };
                        let Some(public_key_material) = signer.public_key_base64url() else {
                            pair_status.set(
                                "This device signer cannot expose a device public key for pairing."
                                    .to_owned(),
                            );
                            return;
                        };
                        let client_nonce = uuid_v7().replace('-', "");
                        pair_action_busy.set(true);
                        pair_status.set("Staging pairing request…".to_owned());
                        let base = base_url();
                        let api_token = token();
                        let public_key_material = public_key_material.to_owned();
                        let authority = authority.clone();
                        spawn(async move {
                            let client_nonce = match arkret_sdk::DevicePairingNonce::new(client_nonce)
                            {
                                Ok(nonce) => nonce,
                                Err(error) => {
                                    pair_status.set(format!(
                                        "Building the pairing nonce failed: {error}"
                                    ));
                                    pair_action_busy.set(false);
                                    return;
                                }
                            };
                            // 1) Stage the device key server-side (unauthenticated
                            // `open` endpoint) to obtain a short handle + code. The
                            // QR then carries only a short deep-link, not the whole
                            // pubkey payload — matching agent pairing.
                            let stage_body = match (
                                arkret_sdk::NonEmptyString::new("OKP".to_owned()),
                                arkret_sdk::NonEmptyString::new(requesting_device_id.clone()),
                                arkret_sdk::NonEmptyString::new("Ed25519".to_owned()),
                                arkret_sdk::Base64UrlString::new(public_key_material.clone()),
                                arkret_sdk::NonEmptyString::new("New device".to_owned()),
                                arkret_sdk::NonEmptyString::new("browser".to_owned()),
                            ) {
                                (Ok(kty), Ok(kid), Ok(algorithm), Ok(key), Ok(display_name), Ok(platform)) => {
                                    arkret_sdk::DevicePairingStageRequestBody {
                                        new_device_pubkey: arkret_sdk::PublicKey {
                                            kty,
                                            kid,
                                            algorithm,
                                            key,
                                            key_digest: None,
                                        },
                                        client_nonce: client_nonce.clone(),
                                        display_name: Some(display_name),
                                        device_metadata: Some(arkret_sdk::DeviceMetadata {
                                            platform: Some(platform),
                                            ..Default::default()
                                        }),
                                    }
                                }
                                _ => {
                                    pair_status.set(
                                        "Building the typed pairing request failed.".to_owned(),
                                    );
                                    pair_action_busy.set(false);
                                    return;
                                }
                            };
                            let challenge_public_key = stage_body.new_device_pubkey.clone();
                            let challenge_stage_body = stage_body.clone();
                            let stage_outcome = crate::transport::auth::with_endpoint_clients(
                                &base,
                                api_token.clone(),
                                None,
                                |clients| async move {
                                    clients.keys().device_pairing_stage(&stage_body).await
                                },
                            )
                            .await;
                            let stage_outcome = match stage_outcome {
                                Ok(outcome) => outcome,
                                Err(err) => {
                                    pair_status.set(format!(
                                        "Staging pairing request failed: {}",
                                        err.display()
                                    ));
                                    pair_action_busy.set(false);
                                    return;
                                }
                            };
                            let request_id =
                                stage_outcome.device_pairing_request_id.to_string();
                            let server_code = stage_outcome.pairing_code.to_string();
                            let challenge =
                                arkret_sdk::signatures::device_pairing::ServerDevicePairingChallenge::from_stage(
                                    &challenge_stage_body,
                                    &stage_outcome,
                                );
                            let (_, transcript_digest) =
                                match arkret_sdk::signatures::device_pairing::server_device_pairing_transcript(
                                    &challenge_public_key,
                                    &challenge,
                                ) {
                                    Ok(value) => value,
                                    Err(err) => {
                                        pair_status.set(format!(
                                            "Building pairing challenge failed: {err}"
                                        ));
                                        pair_action_busy.set(false);
                                        return;
                                    }
                                };
                            let requesting_device = match arkret_sdk::DeviceId::new(requesting_device_id.clone()) {
                                Ok(device) => device,
                                Err(error) => {
                                    pair_status.set(format!("Invalid target device: {error}"));
                                    pair_action_busy.set(false);
                                    return;
                                }
                            };
                            let target_proof = match crate::identity::device_pairing::sign_target_proof(
                                &signer,
                                &authority,
                                &requesting_device,
                                transcript_digest.clone(),
                            ).await {
                                Ok(attestation) => attestation,
                                Err(err) => {
                                    pair_status.set(format!(
                                        "Signing target device attestation failed: {err}"
                                    ));
                                    pair_action_busy.set(false);
                                    return;
                                }
                            };

                            // 2) Short deep-link QR + code for out-of-band scan.
                            let handoff =
                                build_device_pairing_handoff_token(&request_id, &server_code);
                            let deep_link = build_device_pairing_deep_link(
                                &base,
                                &handoff,
                                &target_proof,
                            );
                            pair_payload.set(deep_link);
                            pair_request_id.set(request_id.clone());
                            pair_code.set(server_code.clone());
                            pair_status.set(
                                "Pairing link created. Scan or open it on an authorized device, then compare the code before approving."
                                    .to_owned(),
                            );
                            pair_action_busy.set(false);
                        });
                    },
                    if pair_busy { {tr("settings.devices.pair_requesting")} } else { {tr("settings.devices.pair_request")} }
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "pair-device-clear-button",
                    disabled: payload_for_state.is_empty() || pair_busy,
                    onclick: move |_| {
                        pair_payload.set(String::new());
                        pair_request_id.set(String::new());
                        pair_code.set(String::new());
                        pair_status.set("Approval request cleared from this screen.".to_owned());
                    },
                    {tr("settings.devices.pair_hide_link")}
                }
            }
            if !payload_value.is_empty() {
                div { class: "pair-device-handoff",
                    div { class: "device-pair-approval-code-block",
                        span { class: "muted", {tr("device_pair.compare_code")} }
                        span {
                            class: "device-pair-approval-code mono",
                            "data-testid": "pair-device-code",
                            "{pair_code_value}"
                        }
                    }
                    QrSharePanel {
                        qr_svg,
                        url: payload_value.clone(),
                        qr_aria_label: tr("settings.devices.pair_qr_aria_label"),
                        url_aria_label: tr("settings.devices.pair_link_aria_label"),
                        qr_test_id: "pair-device-qr".to_owned(),
                        url_test_id: "pair-device-secret".to_owned(),
                        copy_test_id: "pair-device-copy-button".to_owned(),
                        url_rows: 4,
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: "btn pair-device-status-action",
                        "data-testid": "pair-device-status-button",
                        disabled: pair_busy,
                        onclick: move |_| {
                            if pair_action_busy() {
                                return;
                            }
                            let request_id = pair_request_id();
                            let code = pair_code();
                            let handoff_link = pair_payload();
                            let principal = principal_id();
                            if request_id.trim().is_empty() {
                                pair_status.set("Request approval first.".to_owned());
                                return;
                            }
                            let base = base_url();
                            let api_token = token();
                            pair_action_busy.set(true);
                            pair_status.set("Checking approval status…".to_owned());
                            spawn(async move {
                                let status_body: arkret_sdk::DevicePairingStatusRequestBody =
                                    match serde_json::from_value(json!({
                                        "device_pairing_request_id": request_id,
                                        "pairing_code": code,
                                    })) {
                                        Ok(body) => body,
                                        Err(err) => {
                                            pair_status.set(format!(
                                                "Building status request failed: {err}"
                                            ));
                                            pair_action_busy.set(false);
                                            return;
                                        }
                                    };
                                match crate::transport::auth::with_endpoint_clients(
                                    &base,
                                    api_token,
                                    None,
                                    |clients| async move {
                                        clients.keys().device_pairing_status(&status_body).await
                                    },
                                )
                                .await
                                {
                                    Ok(outcome) => {
                                        if outcome.state == arkret_sdk::DevicePairingState::Authorized {
                                            let verification = async {
                                                let attestation = extract_device_pairing_target_proof(&handoff_link)
                                                    .ok_or_else(|| anyhow::anyhow!("saved pairing handoff omitted target attestation"))?;
                                                let principal = arkret_sdk::Did::new(principal)?;
                                                let http = crate::transport::TransportClient::unauthenticated(&base)?
                                                    .sdk_http_client()?;
                                                crate::identity::device_pairing::verify_authorized_pairing_event(
                                                    &http,
                                                    &principal,
                                                    &outcome,
                                                    &attestation,
                                                ).await
                                            }.await;
                                            if let Err(error) = verification {
                                                pair_status.set(format!(
                                                    "Pairing authorization could not be verified: {error}"
                                                ));
                                                pair_action_busy.set(false);
                                                return;
                                            }
                                        }
                                        let msg = match outcome.state {
                                            arkret_sdk::DevicePairingState::Authorized => {
                                                "Approved. This device now appears in your device list.".to_owned()
                                            }
                                            arkret_sdk::DevicePairingState::PendingAuthorization => {
                                                "Still waiting for approval on another authorized device.".to_owned()
                                            }
                                            arkret_sdk::DevicePairingState::Expired => {
                                                "This request expired. Create a new approval request.".to_owned()
                                            }
                                        };
                                        pair_status.set(msg);
                                    }
                                    Err(err) => {
                                        pair_status.set(format!(
                                            "Status check failed: {}",
                                            err.display()
                                        ));
                                    }
                                }
                                pair_action_busy.set(false);
                            });
                        },
                        UiIcon { name: "refresh" }
                        if pair_busy { {tr("settings.devices.pair_checking")} } else { {tr("settings.devices.pair_check")} }
                    }
                }
            }
            if !status_value.is_empty() {
                div { class: "device-pairing-status", "data-testid": "pair-device-status", role: "status",
                    UiIcon { name: "activity" }
                    span { "{status_value}" }
                }
            }
        }

        // Role 3 — on an ALREADY-AUTHORIZED device: scan/paste the out-of-band
        // pairing link, resolve it, compare the code, then approve.
        div { class: "event accept-pairing-card", "data-testid": "accept-pairing-card",
            div { class: "event-head",
                strong { {tr("settings.devices.accept_title")} }
                span { {tr("device_pair.subtitle")} }
            }
            p { class: "muted",
                {tr("settings.devices.accept_body")}
            }
            Textarea {
                "data-testid": "accept-pairing-input",
                rows: "2",
                cols: "48",
                value: "{accept_input}",
                disabled: accept_busy,
                placeholder: tr("settings.devices.accept_placeholder"),
                oninput: move |event: FormEvent| accept_input.set(event.value()),
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "accept-pairing-resolve-button",
                    disabled: accept_input().trim().is_empty() || accept_busy,
                    onclick: move |_| {
                        if accept_action_busy() {
                            return;
                        }
                        let Some(pairing_token) = extract_device_pairing_token(&accept_input())
                        else {
                            accept_status.set(
                                "Paste a valid pairing link or token first.".to_owned(),
                            );
                            return;
                        };
                        let Some(target_proof) =
                            extract_device_pairing_target_proof(&accept_input())
                        else {
                            accept_status.set(
                                "The pairing link is missing its target-device attestation."
                                    .to_owned(),
                            );
                            return;
                        };
                        let base = base_url();
                        let api_token = token();
                        accept_action_busy.set(true);
                        accept_status.set("Resolving pairing link…".to_owned());
                        spawn(async move {
                            let resolve_body = arkret_sdk::DevicePairingResolveRequestBody {
                                pairing_token,
                            };
                            match crate::transport::auth::with_endpoint_clients(
                                &base,
                                api_token,
                                None,
                                |clients| async move {
                                    clients.keys().device_pairing_resolve(&resolve_body).await
                                },
                            )
                            .await
                            {
                                Ok(bootstrap) => {
                                    let server_challenge = arkret_sdk::signatures::device_pairing::ServerDevicePairingChallenge::from_bootstrap(&bootstrap);
                                    if let Err(error) = arkret_sdk::signatures::device_pairing::verify_server_device_pairing_target_proof(
                                        &bootstrap.new_device_pubkey,
                                        &server_challenge,
                                        &target_proof,
                                        chrono::Utc::now(),
                                    ) {
                                        accept_resolved.set(String::new());
                                        accept_status.set(format!(
                                            "Resolved pairing challenge is invalid: {error}"
                                        ));
                                        accept_action_busy.set(false);
                                        return;
                                    }
                                    let request_payload = crate::identity::device_pairing::ResolvedPairingApproval {
                                        bootstrap,
                                        target_proof,
                                    };
                                    match serde_json::to_string(&request_payload) {
                                        Ok(payload) => accept_resolved.set(payload),
                                        Err(error) => {
                                            accept_resolved.set(String::new());
                                            accept_status.set(format!(
                                                "Resolved pairing material is invalid: {error}"
                                            ));
                                            accept_action_busy.set(false);
                                            return;
                                        }
                                    }
                                    accept_status.set(
                                        "Resolved. Compare the code below with the new device, then approve.".to_owned(),
                                    );
                                }
                                Err(err) => {
                                    accept_resolved.set(String::new());
                                    accept_status.set(format!(
                                        "Could not resolve pairing link: {}",
                                        err.display()
                                    ));
                                }
                            }
                            accept_action_busy.set(false);
                        });
                    },
                    if accept_busy { {tr("settings.devices.accept_resolving")} } else { {tr("settings.devices.accept_resolve")} }
                }
                if let Some(review) = resolved_approval.clone() {
                    div {
                        class: "device-pair-approval-review",
                        "data-testid": "accept-pairing-review",
                        role: "group",
                        "aria-label": tr("device_pair.aria_label"),
                        strong { {tr("device_pair.title")} }
                        p { class: "muted", {tr("device_pair.body")} }
                        dl { class: "device-pair-approval-facts",
                            dt { {tr("settings.devices.accept_device_name")} }
                            dd { "data-testid": "accept-pairing-device-name", "{review.display_name}" }
                            dt { {tr("settings.devices.accept_device_id")} }
                            dd { class: "mono", "data-testid": "accept-pairing-device-id", "{review.device_id}" }
                            dt { {tr("settings.devices.accept_key_fingerprint")} }
                            dd { class: "mono", "data-testid": "accept-pairing-key-fingerprint", "{review.key_fingerprint}" }
                            dt { {tr("device_pair.platform")} }
                            dd { "data-testid": "accept-pairing-platform", "{review.platform}" }
                            dt { {tr("settings.devices.accept_gate_audience")} }
                            dd { class: "mono", "data-testid": "accept-pairing-gate-audience", "{review.gate_audience}" }
                            dt { {tr("device_pair.expires")} }
                            dd { "data-testid": "accept-pairing-expires", "{review.expires_at}" }
                        }
                        span { class: "muted", {tr("device_pair.compare_code")} }
                    }
                    span {
                        class: "device-pair-approval-code mono",
                        "data-testid": "accept-pairing-code",
                        "{review.pairing_code}"
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "accept-pairing-button",
                        disabled: accept_busy,
                        onclick: move |_| {
                            if accept_action_busy() {
                                return;
                            }
                            let request_payload: crate::identity::device_pairing::ResolvedPairingApproval =
                                match serde_json::from_str(&accept_resolved()) {
                                    Ok(value) => value,
                                    Err(err) => {
                                        accept_status.set(format!(
                                            "Resolved pairing became invalid: {err}"
                                        ));
                                        return;
                                    }
                                };
                            let base = base_url();
                            let api_token = token();
                            accept_action_busy.set(true);
                            accept_status.set("Approving device pairing…".to_owned());
                            spawn(async move {
                                match crate::transport::auth::with_authed_api(
                                    &base,
                                    api_token,
                                    |api| async move {
                                        approve_device_pairing(&api, &request_payload).await
                                    },
                                )
                                .await
                                {
                                    Ok(value) => {
                                        let _ = value;
                                        accept_resolved.set(String::new());
                                        accept_input.set(String::new());
                                        accept_status.set(
                                            "Device paired. It will appear in the device list shortly."
                                                .to_owned(),
                                        );
                                    }
                                    Err(err) => {
                                        accept_status.set(tr_args(
                                            "device_pair.err_approval_failed",
                                            &[("error", err.display())],
                                        ));
                                    }
                                }
                                accept_action_busy.set(false);
                            });
                        },
                        if accept_busy { {tr("device_pair.approving")} } else { {tr("device_pair.approve")} }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "accept-pairing-reject-button",
                        disabled: accept_busy,
                        onclick: move |_| {
                            accept_resolved.set(String::new());
                            accept_input.set(String::new());
                            accept_status.set(tr("settings.devices.accept_rejected"));
                        },
                        {tr("device_pair.reject")}
                    }
                }
            }
            div { class: "muted", "data-testid": "accept-pairing-status", "{accept_status}" }
        }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn target_proof() -> arkret_sdk::DevicePairingTargetProof {
        serde_json::from_value(json!({
            "device_id": "ak:device:01964137-0000-7000-8000-0000000000c1",
            "device_public_key_did": "did:key:z6MkogKw38hXxUkpMWitoBubBGHZzeGrQJ4oHF36iegUbmpA",
            "hpke_key": "z6LSriWhVBzW9Vz2PvqbieSz7Aa2hPLzTKJuDwXTMKFeomeW",
            "algorithms": ["HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305", "ak.mls.ciphersuite.v1"],
            "device_key_algorithm": "Ed25519",
            "authorization_binding_kind": "accepted_device",
            "pairing_challenge_transcript_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "device_signature": "Y2hhbGxlbmdlLXNpZ25hdHVyZQ"
        }))
        .unwrap()
    }

    #[test]
    fn parses_device_list_response() {
        let payload = json!({
            "actor": "did:web:alice.example",
            "devices": [
                {
                    "device_id": "device-1",
                    "display_name": "Chrome · Windows",
                    "status": "active",
                    "verification_state": "verified",
                    "authorized_at": "2026-05-01T00:00:00.000Z"
                },
                {
                    "device_id": "device-2",
                    "status": "active",
                    "verification_state": "unresolved",
                    "authorized_at": "2026-05-05T12:34:56.000Z"
                }
            ]
        });
        let rows = parse_devices(&payload);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].device_id, "device-1");
        assert_eq!(rows[0].display_name, "Chrome · Windows");
        assert_eq!(rows[0].authorized_at, "2026-05-01T00:00:00.000Z");
        // Missing display_name parses to an empty string (UI falls back
        // to the short device id).
        assert_eq!(rows[1].display_name, "");
        assert_eq!(rows[1].verification_state, "unresolved");
    }

    #[test]
    fn parse_devices_does_not_invent_current_device_state() {
        let payload = json!({
            "principal_id": "ak:did_core:web:alice.example",
            "devices": [
                {
                    "device_id": "device-1",
                    "display_name": "Laptop",
                    "status": "active",
                    "verification_state": "verified"
                },
                {
                    "device_id": "device-2",
                    "display_name": "Phone",
                    "status": "active",
                    "verification_state": "verified"
                }
            ]
        });
        let rows = parse_devices(&payload);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn extract_device_pairing_token_handles_link_and_bare() {
        let attestation = target_proof();
        let link = build_device_pairing_deep_link("https://host.example", "abc123", &attestation);
        assert_eq!(
            extract_device_pairing_token(&link),
            Some("abc123".to_owned())
        );
        assert_eq!(
            extract_device_pairing_target_proof(&link),
            Some(attestation)
        );
        assert_eq!(
            extract_device_pairing_token("  bare-token-xyz  "),
            Some("bare-token-xyz".to_owned())
        );
        assert_eq!(extract_device_pairing_token("   "), None);
    }

    #[test]
    fn parse_devices_handles_missing_fields_gracefully() {
        let rows = parse_devices(&json!({}));
        assert!(rows.is_empty());
    }
}
