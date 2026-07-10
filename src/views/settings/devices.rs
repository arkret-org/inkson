//! G3.Y1 — Device management (`/settings/devices`) and QR-driven
//! pairing (`/settings/devices/pair`).
//!
//! Surfaces:
//! - `device-list` — wrapper element listing the principal's active devices from `GET
//!   /_arkret/self/account/viewer` via [`crate::api::CokretApi::list_devices`]
//! - `device-row` per row, with `data-device-id` and a `device-row-current` boolean tag on the row
//!   matching the local `LocalStateStore::device_id`
//! - `device-revoke-button` per row, which opens a confirmation modal
//! - `device-revoke-confirm-button` / `device-revoke-status` after the user confirms; revoke
//!   submits the spec-canonical durable `ck.device.revoke` Control Move on the principal control
//!   stream (envelope `seal_basis` minted from `ck.self.events.query.frontier`, SPEC-SOL-003) with
//!   a [`crate::api::CokretApi::revoke_device`], then rotates the account MLS history secret and
//!   rewraps local `mls_history` backups.
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
//! - `crypto-media/device-lifecycle.md` §2.1 (5-step pairing), §2.2 (revoke), §5.1–§5.2
//!   (cross-signing binding), §6 (device list)
//! - `identity/key-management.md` §5.0–§5.2 (`ck.device.authorize` / `ck.device.revoke`)
//!
//! ## Endpoints
//!
//! - `GET /_arkret/self/account/viewer` — implemented (soland)
//! - `POST /_arkret/gate/account/device-pair` — spec-level device pairing.

use dioxus::prelude::*;
use dioxus_router::Link;
use dioxus_router::hooks::use_route;
use serde_json::{Value, json};

use crate::components::{EmptyState, EmptyStateKind, HelpTip};
use crate::device_pairing::{
    PendingPairingRequest, pairing_request_body, parse_pending_pairing_requests,
};
use crate::local_state::LocalStateStore;
use crate::operation::uuid_v7;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{short_protocol_id, with_authed_api, with_authed_sdk_client};

#[derive(Clone, Debug, PartialEq)]
struct DeviceRow {
    device_id: String,
    display_name: String,
    is_current: bool,
    verification_state: String,
    created_at: String,
}

fn parse_devices(value: &Value) -> (Option<String>, Vec<DeviceRow>) {
    let explicit_current = value
        .get("current_device_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let rows: Vec<DeviceRow> = value
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
                    let is_current = item
                        .get("is_current_session_device")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let verification_state = item
                        .get("verification_state")
                        .or_else(|| item.get("status"))
                        .and_then(Value::as_str)
                        .unwrap_or("unverified")
                        .to_owned();
                    let created_at = item
                        .get("created_at")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    Some(DeviceRow {
                        device_id,
                        display_name,
                        is_current,
                        verification_state,
                        created_at,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let current = explicit_current.or_else(|| rows.first().map(|row| row.device_id.clone()));
    (current, rows)
}

/// Build the QR / paste payload that an already-authorized device approves.
/// The new device owns `requesting_device_id` and its device-identity public
/// key; the existing device turns this payload into
/// `ck.gate.account.command.pair_device`.
fn build_pair_payload(
    account_did: &str,
    requesting_device_id: &str,
    public_key_material: &str,
    pairing_code: &str,
    challenge_signature: &str,
) -> String {
    let payload = json!({
        "schema": "ak.device.pair.request.v1",
        "account_did": account_did,
        "pairing_code": pairing_code,
        "new_device_pubkey": {
            "kty": "OKP",
            "kid": requesting_device_id,
            "alg": "EdDSA",
            "public_key": public_key_material,
        },
        "challenge_signature": challenge_signature,
        "display_name": "New device",
        "device_metadata": {
            "platform": "browser",
        },
        "issued_at": chrono::Utc::now().to_rfc3339(),
    });
    payload.to_string()
}

fn build_pairing_verification_content(
    request_payload: &Value,
    requesting_device_id: &str,
    gate_audience: &str,
    expires_at: &str,
) -> Value {
    let canonical = arkret_sdk::canonical::canonical_json_bytes(request_payload)
        .unwrap_or_else(|_| request_payload.to_string().into_bytes());
    json!({
        "transaction_id": uuid_v7(),
        "from_device": requesting_device_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "expires_at": expires_at,
        "methods": ["ak.sas.v1", "ak.qr.v1"],
        "purpose": "same_principal_device_authorization",
        "pairing_code": request_payload.get("pairing_code").cloned().unwrap_or(Value::Null),
        "new_device_pubkey": request_payload.get("new_device_pubkey").cloned().unwrap_or(Value::Null),
        "challenge_signature": request_payload.get("challenge_signature").cloned().unwrap_or(Value::Null),
        "gate_audience": gate_audience,
        "request_canonical_digest": arkret_sdk::canonical::sha256_digest(&canonical),
        "device_metadata": request_payload
            .get("device_metadata")
            .cloned()
            .unwrap_or_else(|| json!({})),
    })
}

#[component]
pub fn SettingsDevicesPanel(
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::get().base_url;
    let state_store = crate::app::SessionContext::get().state_store;
    let route = use_route::<Route>();
    let pair_mode = matches!(route, Route::SettingsDevicesPair);

    let mut devices = use_signal(Vec::<DeviceRow>::new);
    let mut current_device = use_signal(String::new);
    let mut load_status = use_signal(String::new);
    let revoke_target = use_signal(|| Option::<String>::None);
    let revoke_status = use_signal(String::new);
    let revoke_passphrase = use_signal(String::new);

    // Auto-load guard so the device list populates on mount (and once a
    // session credential arrives) without the user clicking Refresh first.
    let mut auto_loaded = use_signal(|| false);

    // ── Pair (current device side) state ─────────────────────────────
    let pair_payload = use_signal(String::new);
    let pair_status = use_signal(String::new);
    let mut pending_pair_requests = use_signal(Vec::<PendingPairingRequest>::new);
    let mut pending_pair_status = use_signal(String::new);

    // ── Accept (receiving device side) state ─────────────────────────
    let accept_input = use_signal(String::new);
    let accept_status = use_signal(String::new);

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
                    crate::keys_api::list_devices(&http).await
                })
                .await
                {
                    Ok(value) => {
                        let value = serde_json::to_value(&value).unwrap_or_default();
                        let (cur, rows) = parse_devices(&value);
                        if let Some(c) = cur {
                            current_device.set(c);
                        }
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
                    crate::keys_api::list_devices(&http).await
                })
                .await
                {
                    Ok(value) => {
                        let value = serde_json::to_value(&value).unwrap_or_default();
                        let (cur, rows) = parse_devices(&value);
                        if let Some(c) = cur {
                            current_device.set(c);
                        }
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

    {
        let state_store_for_pending = state_store;
        use_effect(move || {
            if !pair_mode {
                return;
            }
            let rows =
                parse_pending_pairing_requests(&state_store_for_pending.read().to_device_inbox());
            let count = rows.len();
            pending_pair_requests.set(rows);
            pending_pair_status.set(format!("Loaded {count} to-device request(s)"));
        });
    }

    rsx! {
        div { class: "settings-content-stack", "data-testid": "settings-devices-panel",
            div { class: "event settings-control-panel",
                div { class: "event-head",
                    span { "Device access" }
                    span { if has_session { "authenticated" } else { "not signed in" } }
                    HelpTip { text: "Manage the devices bound to your account. Revoking a device removes it from the active set and triggers MLS leaf removal in any E2EE Realm the device participates in.".to_owned() }
                }
                div { class: "actions",
                    Link {
                        class: if !pair_mode { "primary" } else { "secondary" },
                        to: Route::SettingsDevices,
                        "Devices"
                    }
                    Link {
                        class: if pair_mode { "primary" } else { "secondary" },
                        to: Route::SettingsDevicesPair,
                        "Pair new device"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "device-list-refresh",
                        onclick: refresh_devices,
                        "Refresh"
                    }
                }
            }

            if pair_mode {
                {render_pair_strand(
                    account_did,
                    device_id,
                    base_url,
                    token,
                    state_store,
                    pair_payload,
                    pair_status,
                    pending_pair_requests,
                    pending_pair_status,
                    accept_input,
                    accept_status,
                )}
            } else {
                {render_device_list(
                    devices,
                    current_device,
                    local_device_id.clone(),
                    load_status,
                    revoke_target,
                    revoke_status,
                    base_url,
                    account_did,
                    device_id,
                    token,
                    state_store,
                    revoke_passphrase,
                )}
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_device_list(
    devices: Signal<Vec<DeviceRow>>,
    current_device: Signal<String>,
    local_device_id: String,
    load_status: Signal<String>,
    revoke_target: Signal<Option<String>>,
    revoke_status: Signal<String>,
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
    revoke_passphrase: Signal<String>,
) -> Element {
    let rows = devices();
    let cur = current_device();
    let has_rows = !rows.is_empty();
    let status_msg = load_status();
    let revoke_msg = revoke_status();
    let pending_revoke = revoke_target();
    rsx! {
        div { class: "event", "data-testid": "device-list",
            div { class: "event-head",
                span { "Active devices" }
                span { "{status_msg}" }
            }
            if !has_rows {
                EmptyState {
                    kind: EmptyStateKind::Empty,
                    title: "No devices loaded yet".to_owned(),
                    message: Some("Loading your devices… or click Refresh to retry.".to_owned()),
                    test_id: Some("device-list-empty".to_owned()),
                }
            } else {
                table { class: "data-table",
                    thead {
                        tr {
                            th { "Device" }
                            th { "Verification" }
                            th { "Created" }
                            th { "Actions" }
                        }
                    }
                    tbody {
                        for row in rows.iter() {
                            {render_device_row(
                                row.clone(),
                                cur.clone(),
                                local_device_id.clone(),
                                revoke_target,
                            )}
                        }
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
                account_did,
                device_id,
                revoke_passphrase,
            )}
        }

    }
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
        "verified" => ("badge success", "🛡", "Verified".to_owned()),
        "unverified" => ("badge warning", "⚠", "Unverified".to_owned()),
        "revoked" => ("badge danger", "⊘", "Revoked".to_owned()),
        _ => unreachable!("verification state normalized"),
    };
    rsx! {
        span {
            class: "{class} device-verification-badge",
            "data-testid": "device-verification-badge",
            "data-verification": "{normalized}",
            title: "Device verification state: {label}",
            "{glyph} {label}"
        }
    }
}

fn render_device_row(
    row: DeviceRow,
    server_current: String,
    local_device_id: String,
    mut revoke_target: Signal<Option<String>>,
) -> Element {
    // "current" is true when soland says so (server-authoritative
    // current_device_id) OR when our local_state.device_id matches —
    // both legitimately identify the device the user is sitting at.
    let is_current = row.is_current
        || (!server_current.is_empty() && server_current == row.device_id)
        || (!local_device_id.is_empty() && local_device_id == row.device_id);
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
    // the full id stays reachable via the row tooltip.
    let id_suffix = crate::device_name::device_id_short_suffix(&row.device_id);
    let has_name = !row.display_name.is_empty();
    let primary_label = if has_name {
        row.display_name.clone()
    } else {
        device_id_label.clone()
    };
    rsx! {
        tr {
            class: "{row_class}",
            "data-testid": "device-row",
            "data-device-id": "{row.device_id}",
            "data-current": if is_current { "true" } else { "false" },
            td {
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
                        "this device"
                    }
                }
            }
            td { {device_verification_badge(&row.verification_state)} }
            td { "{row.created_at}" }
            td {
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "device-revoke-button",
                    disabled: is_current,
                    onclick: move |_| {
                        revoke_target.set(Some(device_id_for_button.clone()));
                    },
                    if is_current { "Cannot self-revoke" } else { "Revoke" }
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
    mut state_store: Signal<LocalStateStore>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    mut revoke_passphrase: Signal<String>,
) -> Element {
    let confirm_target = target.clone();
    let cancel_target = target.clone();
    let target_label = short_protocol_id(&target);
    rsx! {
        div { class: "modal-overlay", "data-testid": "device-revoke-modal",
            div { class: "modal",
                div { class: "event-head",
                    span { "Revoke device" }
                    span { title: "{target}", "{target_label}" }
                }
                p {
                    "This will write "
                    code { "ak.device.revoke" }
                    " to your principal control Realm, remove the device from any E2EE Realm it participates in, and rotate the account MLS history secret. The action cannot be undone."
                }
                p { class: "muted", "data-testid": "device-revoke-threat-note",
                    "Revocation is not a remote wipe. It cannot remotely erase secrets or cached history already copied onto that device. Treat a lost or compromised device as able to read any plaintext or old account MLS secret it retained before revocation."
                }
                Label { html_for: "device-revoke-passphrase", "Recovery Key (24 words)" }
                Input {
                    id: "device-revoke-passphrase",
                    "data-testid": "device-revoke-passphrase-input",
                    r#type: "password",
                    value: "{revoke_passphrase}",
                    autocomplete: "off",
                    placeholder: "Your 24-word Recovery Key — required to rotate encrypted history backups",
                    oninput: move |event: FormEvent| revoke_passphrase.set(event.value()),
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "device-revoke-cancel-button",
                        onclick: move |_| {
                            let _ = &cancel_target;
                            revoke_target.set(None);
                        },
                        "Cancel"
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "device-revoke-confirm-button",
                        disabled: revoke_passphrase().trim().is_empty(),
                        onclick: move |_| {
                            let base = base_url();
                            let api_token = token();
                            let actor = account_did();
                            let current_device = device_id();
                            let target_id = confirm_target.clone();
                            let target_for_status = target_id.clone();
                            let target_label = short_protocol_id(&target_for_status);
                            // P1: pre-validate the Recovery Key BEFORE the
                            // irreversible `revoke_device` call. The account-secret
                            // rotation that follows re-wraps the new secret under
                            // these bytes, and every restore path only accepts the
                            // 24-word format — so reject anything else up front to
                            // avoid the unrecoverable "device revoked, but the new
                            // backup can never be decrypted" half-state.
                            let Some(recovery_secret) =
                                crate::recovery_crypto::normalize_recovery_key_input(
                                    &revoke_passphrase(),
                                )
                            else {
                                revoke_status.set(
                                    "Enter your 24-word Recovery Key before revoking — it is required to rotate the MLS history secret.".to_owned(),
                                );
                                return;
                            };
                            let passphrase_bytes = recovery_secret.into_bytes();
                            let snapshots = state_store.read().mls_snapshots();
                            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                            let actor_for_rotation = actor.clone();
                            let device_for_rotation = current_device.clone();
                            let secure_store_for_rotation = secure_store.clone();
                            revoke_status.set(format!("Revoking {target_label}…"));
                            spawn(async move {
                                let target_label = short_protocol_id(&target_for_status);
                                let target_inner = target_id.clone();
                                let actor_for_revoke = actor.clone();
                                let device_for_revoke = current_device.clone();
                                let revoke_result =
                                    with_authed_api(&base, api_token.clone(), move |api| async move {
                                        api.revoke_device(
                                            &actor_for_revoke,
                                            &device_for_revoke,
                                            &target_inner,
                                        )
                                        .await
                                    })
                                    .await;
                                if let Err(err) = revoke_result {
                                    revoke_status.set(format!(
                                        "Revoke failed: {}",
                                        err.display()
                                    ));
                                    return;
                                }

                                let rotation_result = with_authed_api(
                                    &base,
                                    api_token.clone(),
                                    move |api| async move {
                                        crate::mls::account_recovery::upload_mls_account_secret_rotation_after_device_revoke(
                                            &api,
                                            secure_store_for_rotation.as_ref(),
                                            &actor_for_rotation,
                                            &device_for_rotation,
                                            &passphrase_bytes,
                                            &snapshots,
                                        )
                                        .await
                                    },
                                )
                                .await;
                                match rotation_result {
                                    Ok(rotation) => {
                                        let mut local_state = state_store.write();
                                        if let Err(err) = crate::mls::runtime::commit_account_mls_secret_rotation(
                                            &mut local_state,
                                            secure_store.as_ref(),
                                            &actor,
                                            &rotation.rotation,
                                        ) {
                                            revoke_status.set(format!(
                                                "Revoked {target_label}; MLS secret rotation uploaded but local commit failed: {err}"
                                            ));
                                            return;
                                        }
                                        let history_count = rotation.history_backup_ids.len();
                                        let version = rotation.rotation.new_version;
                                        let deleted_count =
                                            rotation.deleted_superseded_backup_ids.len();
                                        revoke_status.set(format!(
                                            "Revoked {target_label}. Rotated MLS history secret to v{version}; uploaded {history_count} fresh history backup(s); deleted {deleted_count} superseded old backup(s)."
                                        ));
                                        revoke_passphrase.set(String::new());
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
                                                    crate::keys_api::list_devices(&http).await
                                                },
                                            )
                                            .await
                                            {
                                                let value =
                                                    serde_json::to_value(&value).unwrap_or_default();
                                                let (_cur, rows) = parse_devices(&value);
                                                let count = rows.len();
                                                devices.set(rows);
                                                load_status.set(format!("Loaded {count} device(s)"));
                                            }
                                        });
                                    }
                                    Err(err) => {
                                        revoke_status.set(format!(
                                            "Revoked {target_label}; MLS secret rotation failed: {}",
                                            err.display()
                                        ));
                                    }
                                }
                            });
                        },
                        "Confirm revoke"
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_pair_strand(
    account_did: Signal<String>,
    device_id: Signal<String>,
    base_url: Signal<String>,
    token: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut pair_payload: Signal<String>,
    mut pair_status: Signal<String>,
    mut pending_pair_requests: Signal<Vec<PendingPairingRequest>>,
    mut pending_pair_status: Signal<String>,
    mut accept_input: Signal<String>,
    mut accept_status: Signal<String>,
) -> Element {
    let actor_id = account_did();
    let payload_value = pair_payload();
    let status_value = pair_status();
    let pending_rows = pending_pair_requests();
    let pending_status_value = pending_pair_status();

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
    let refresh_pending_requests = {
        let state_store_for_refresh = state_store;
        move |_| {
            let rows =
                parse_pending_pairing_requests(&state_store_for_refresh.read().to_device_inbox());
            let count = rows.len();
            pending_pair_requests.set(rows);
            pending_pair_status.set(format!("Loaded {count} to-device request(s)"));
        }
    };

    rsx! {
        // Role 1 — on an ALREADY-AUTHORIZED device: approve incoming requests.
        // Listed first because this is the action a signed-in device performs;
        // a global prompt also surfaces these without visiting this page.
        div { class: "event", "data-testid": "pending-pairing-requests-card",
            div { class: "event-head",
                span { "Approve a device" }
                span { "{pending_status_value}" }
            }
            p { class: "muted",
                "On a device that is already signed in, approve a request from a device you are adding. Compare the pairing code on both devices before approving."
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "pending-pairing-refresh-button",
                    onclick: refresh_pending_requests,
                    "Refresh requests"
                }
            }
            if pending_rows.is_empty() {
                div {
                    class: "muted",
                    "data-testid": "pending-pairing-empty",
                    "No pending pairing requests for this account."
                }
            } else {
                div { class: "settings-list", "data-testid": "pending-pairing-list",
                    for row in pending_rows {
                        {
                            let request_key = row.request_key.clone();
                            let request_key_for_label = request_key.clone();
                            let approve_payload = row.request_payload.clone();
                            let approve_device = row.requesting_device_id.clone();
                            let approve_code = row.pairing_code.clone();
                            let reject_device = row.requesting_device_id.clone();
                            let reject_code = row.pairing_code.clone();
                            let device_label = if row.display_name.trim().is_empty() {
                                short_protocol_id(&row.requesting_device_id)
                            } else {
                                row.display_name.clone()
                            };
                            let platform = row.platform.clone();
                            let code_label = if row.pairing_code.trim().is_empty() {
                                "(no code)".to_owned()
                            } else {
                                row.pairing_code.clone()
                            };
                            rsx! {
                                div {
                                    class: "metric",
                                    "data-testid": "pending-pairing-request",
                                    "data-pairing-request-id": "{request_key_for_label}",
                                    strong { "{device_label}" }
                                    span { class: "muted mono", "{short_protocol_id(&row.requesting_device_id)}" }
                                    if !platform.trim().is_empty() {
                                        span { class: "muted", "Platform {platform}" }
                                    }
                                    span { class: "muted", "Compare this code on both devices" }
                                    strong {
                                        class: "device-pair-approval-code mono",
                                        "data-testid": "pending-pairing-code",
                                        "{code_label}"
                                    }
                                    span { class: "muted", "Expires {row.expires_at}" }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "reject-pairing-request-button",
                                            onclick: move |_| {
                                                state_store
                                                    .write()
                                                    .dismiss_pairing_to_device_message(
                                                        &reject_device,
                                                        &reject_code,
                                                    );
                                                let rows = parse_pending_pairing_requests(
                                                    &state_store.read().to_device_inbox(),
                                                );
                                                let count = rows.len();
                                                pending_pair_requests.set(rows);
                                                pending_pair_status.set(format!(
                                                    "Rejected request. {count} pending."
                                                ));
                                            },
                                            "Reject"
                                        }
                                        Button {
                                            variant: ButtonVariant::Primary,
                                            "data-testid": "approve-pairing-request-button",
                                            onclick: move |_| {
                                                let base = base_url();
                                                let api_token = token();
                                                let request_key = request_key.clone();
                                                let approve_payload = approve_payload.clone();
                                                let approve_device = approve_device.clone();
                                                let approve_code = approve_code.clone();
                                                pending_pair_status.set(format!(
                                                    "Approving to-device request {request_key}..."
                                                ));
                                                spawn(async move {
                                                    let body = match pairing_request_body(&approve_payload) {
                                                        Ok(body) => body,
                                                        Err(err) => {
                                                            pending_pair_status.set(format!(
                                                                "Cannot approve: {err}"
                                                            ));
                                                            return;
                                                        }
                                                    };
                                                    match with_authed_api(&base, api_token, |api| async move {
                                                        api.account_device_pair(&body).await
                                                    })
                                                    .await
                                                    {
                                                        Ok(value) => {
                                                            state_store
                                                                .write()
                                                                .dismiss_pairing_to_device_message(
                                                                    &approve_device,
                                                                    &approve_code,
                                                                );
                                                            let rows = parse_pending_pairing_requests(
                                                                &state_store.read().to_device_inbox(),
                                                            );
                                                            pending_pair_requests.set(rows);
                                                            pending_pair_status.set(format!(
                                                                "To-device pairing request approved. Server response: {value:?}"
                                                            ));
                                                        }
                                                        Err(err) => {
                                                            pending_pair_status.set(format!(
                                                                "Approving to-device pairing request failed: {}",
                                                                err.display()
                                                            ));
                                                        }
                                                    }
                                                });
                                            },
                                            "Approve"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Role 2 — on the NEW device: create a request, then have an
        // already-authorized device approve it (above) or scan/paste it.
        div { class: "event", "data-testid": "pair-device-card",
            div { class: "event-head",
                span { "Pair a new device" }
                span { "{status_value}" }
            }
            p { class: "muted",
                "On the browser or device you are adding, create a request here. Then approve it on an already-authorized device above, or paste/scan the request there."
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "pair-device-start-button",
                    disabled: actor_id.trim().is_empty(),
                    onclick: move |_| {
                        let actor = account_did();
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
                        let Some(public_key_material) = signer.public_key_multibase() else {
                            pair_status.set(
                                "This device signer cannot expose a device public key for pairing."
                                    .to_owned(),
                            );
                            return;
                        };
                        let pairing_code = uuid_v7().replace('-', "");
                        let challenge_signature = uuid_v7().replace('-', "");
                        let payload = build_pair_payload(
                            &actor,
                            &requesting_device_id,
                            &public_key_material,
                            &pairing_code,
                            &challenge_signature,
                        );
                        let request_body: Value = match serde_json::from_str(&payload) {
                            Ok(value) => value,
                            Err(err) => {
                                pair_status.set(format!("Pairing payload generation failed: {err}"));
                                return;
                            }
                        };
                        pair_payload.set(payload.clone());
                        pair_status.set(format!(
                            "Sending pairing request for {requesting_device_id}..."
                        ));
                        let base = base_url();
                        let api_token = token();
                        spawn(async move {
                            let gate_audience = base.clone();
                            let request_body_for_delivery = request_body.clone();
                            let requesting_device_id_for_delivery = requesting_device_id.clone();
                            let actor_for_delivery = actor.clone();
                            match with_authed_api(&base, api_token, |api| {
                                let gate_audience = gate_audience.clone();
                                let request_body = request_body_for_delivery.clone();
                                let requesting_device_id =
                                    requesting_device_id_for_delivery.clone();
                                let actor = actor_for_delivery.clone();
                                async move {
                                    let devices_value = serde_json::to_value(
                                        &crate::keys_api::list_devices(&api.sdk_http_client()?)
                                            .await?,
                                    )?;
                                    let (_, rows) = parse_devices(&devices_value);
                                    let expires_at = crate::clock::rfc3339_secs_in(10 * 60);
                                    let content = build_pairing_verification_content(
                                        &request_body,
                                        &requesting_device_id,
                                        &gate_audience,
                                        &expires_at,
                                    );
                                    let mut delivered = 0usize;
                                    let mut failed = 0usize;
                                    let http = api.sdk_http_client()?;
                                    for row in rows {
                                        if row.device_id == requesting_device_id
                                            || row.verification_state != "verified"
                                        {
                                            continue;
                                        }
                                        let txn_id = format!(
                                            "ak.key.verification.request:{}:{}",
                                            requesting_device_id, row.device_id
                                        );
                                        match crate::keys_api::send_device_message_envelope(
                                            &http,
                                            &txn_id,
                                            &actor,
                                            &row.device_id,
                                            "ak.key.verification.request",
                                            &expires_at,
                                            content.clone(),
                                        )
                                        .await
                                        {
                                            Ok(_) => delivered += 1,
                                            Err(error) => {
                                                tracing::debug!(
                                                    ?error,
                                                    target_device = %row.device_id,
                                                    "failed to send pairing verification request"
                                                );
                                                failed += 1;
                                            }
                                        }
                                    }
                                    if delivered == 0 && failed > 0 {
                                        anyhow::bail!(
                                            "all pairing request deliveries failed ({failed} target(s))"
                                        );
                                    }
                                    Ok::<_, anyhow::Error>((delivered, failed))
                                }
                            })
                                .await
                            {
                                Ok((0, _)) => {
                                    pair_status.set(format!(
                                        "Pairing request generated for {requesting_device_id}. No authorized sibling device was available for to-device delivery; use the QR or paste payload on an existing device."
                                    ));
                                }
                                Ok((delivered, 0)) => {
                                    pair_status.set(format!(
                                        "Pairing request sent to {delivered} authorized device(s). Compare the matching code before approving."
                                    ));
                                }
                                Ok((delivered, failed)) => {
                                    pair_status.set(format!(
                                        "Pairing request sent to {delivered} authorized device(s); {failed} delivery attempt(s) failed. QR/paste remains available."
                                    ));
                                }
                                Err(err) => {
                                    pair_status.set(format!(
                                        "Pairing request generated locally, but to-device delivery failed: {}. Use the QR or paste payload on an existing device.",
                                        err.display()
                                    ));
                                }
                            }
                        });
                    },
                    "Create request"
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "pair-device-clear-button",
                    disabled: payload_for_state.is_empty(),
                    onclick: move |_| {
                        pair_payload.set(String::new());
                        pair_status.set("Pairing payload cleared.".to_owned());
                    },
                    "Clear payload"
                }
            }
            if !payload_value.is_empty() {
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "QR code" }
                        div {
                            "data-testid": "pair-device-qr",
                            // SVG produced by the `qrcode` crate.
                            dangerous_inner_html: "{qr_svg}",
                        }
                    }
                    div { class: "metric",
                        strong { "Request payload" }
                        Textarea {
                            "data-testid": "pair-device-secret",
                            readonly: true,
                            rows: "5",
                            cols: "48",
                            "{payload_value}"
                        }
                    }
                }
            }
            div { class: "muted", "data-testid": "pair-device-status", "{status_value}" }
        }

        // Receiving-device input lives on the same panel so the e2e
        // harness can simulate both devices in one process; in real
        // deployments the new device opens the same URL in its own
        // browser context and only this card is filled in.
        div { class: "event", "data-testid": "accept-pairing-card",
            div { class: "event-head",
                span { "Accept pairing on this device" }
                span { "for new sibling" }
            }
            p { class: "muted",
                "Use this section only on an already-authorized device. Paste the new-device request and approve it through "
                code { "/_arkret/gate/account/device-pair" }
                "."
            }
            Textarea {
                "data-testid": "accept-pairing-input",
                rows: "5",
                cols: "48",
                value: "{accept_input}",
                oninput: move |event: FormEvent| accept_input.set(event.value()),
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "accept-pairing-button",
                    disabled: accept_input().trim().is_empty(),
                    onclick: move |_| {
                        let payload = accept_input();
                        if payload.trim().is_empty() {
                            accept_status.set("Paste a payload first.".to_owned());
                            return;
                        }
                        let request_payload: Value = match serde_json::from_str(&payload) {
                            Ok(value) => value,
                            Err(err) => {
                                accept_status.set(format!("Pairing payload is not valid JSON: {err}"));
                                return;
                            }
                        };
                        let body = match pairing_request_body(&request_payload) {
                            Ok(body) => body,
                            Err(err) => {
                                accept_status.set(format!("Pairing payload is invalid: {err}"));
                                return;
                            }
                        };
                        let base = base_url();
                        let api_token = token();
                        accept_status.set("Approving sibling device pairing…".to_owned());
                        spawn(async move {
                            match with_authed_api(&base, api_token, |api| async move {
                                api.account_device_pair(&body).await
                            })
                            .await
                            {
                                Ok(value) => {
                                    accept_status.set(format!(
                                        "Sibling device paired. Server response: {value:?}"
                                    ));
                                }
                                Err(err) => {
                                    accept_status.set(format!(
                                        "device-pair failed: {}",
                                        err.display()
                                    ));
                                }
                            }
                        });
                    },
                    "Accept payload"
                }
            }
            div { class: "muted", "data-testid": "accept-pairing-status", "{accept_status}" }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_device_list_response() {
        let payload = json!({
            "actor": "did:web:alice.example",
            "current_device_id": "device-1",
            "devices": [
                {
                    "device_id": "device-1",
                    "display_name": "Chrome · Windows",
                    "is_current_session_device": true,
                    "verification_state": "verified",
                    "created_at": "2026-05-01T00:00:00Z"
                },
                {
                    "device_id": "device-2",
                    "is_current_session_device": false,
                    "verification_state": "unverified",
                    "created_at": "2026-05-05T12:34:56Z"
                }
            ]
        });
        let (cur, rows) = parse_devices(&payload);
        assert_eq!(cur.as_deref(), Some("device-1"));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].device_id, "device-1");
        assert_eq!(rows[0].display_name, "Chrome · Windows");
        assert!(rows[0].is_current);
        // Missing display_name parses to an empty string (UI falls back
        // to the short device id).
        assert_eq!(rows[1].display_name, "");
        assert_eq!(rows[1].verification_state, "unverified");
    }

    #[test]
    fn parse_devices_uses_first_device_when_current_missing() {
        let payload = json!({
            "principal_id": "did:web:alice.example",
            "devices": [
                {
                    "device_id": "device-1",
                    "display_name": "Laptop",
                    "status": "active"
                },
                {
                    "device_id": "device-2",
                    "display_name": "Phone",
                    "status": "active"
                }
            ]
        });
        let (cur, rows) = parse_devices(&payload);
        assert_eq!(cur.as_deref(), Some("device-1"));
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn pair_payload_carries_required_fields() {
        let raw = build_pair_payload(
            "did:web:alice",
            "device-1",
            "abc-123",
            "pairing-code",
            "challenge-signature",
        );
        let parsed: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["schema"], "ak.device.pair.request.v1");
        assert_eq!(parsed["account_did"], "did:web:alice");
        assert_eq!(parsed["pairing_code"], "pairing-code");
        assert_eq!(parsed["new_device_pubkey"]["kid"], "device-1");
        assert_eq!(parsed["new_device_pubkey"]["public_key"], "abc-123");
        assert_eq!(parsed["challenge_signature"], "challenge-signature");
        assert!(parsed["issued_at"].as_str().is_some());
    }

    #[test]
    fn pairing_verification_content_carries_gate_payload() {
        let request_payload = json!({
            "pairing_code": "pairing-code",
            "new_device_pubkey": {
                "kid": "ak:device:new",
                "alg": "EdDSA",
                "public_key": "abc-123"
            },
            "challenge_signature": "challenge-signature",
            "device_metadata": {
                "platform": "browser"
            }
        });
        let content = build_pairing_verification_content(
            &request_payload,
            "ak:device:new",
            "https://server.example",
            "2026-06-12T12:00:00Z",
        );
        assert_eq!(content["purpose"], "same_principal_device_authorization");
        assert_eq!(content["from_device"], "ak:device:new");
        assert_eq!(content["pairing_code"], "pairing-code");
        assert_eq!(content["challenge_signature"], "challenge-signature");
        assert_eq!(
            content["new_device_pubkey"]["public_key"],
            request_payload["new_device_pubkey"]["public_key"]
        );
        assert!(content["request_canonical_digest"].as_str().is_some());
    }

    #[test]
    fn parse_devices_handles_missing_fields_gracefully() {
        let (cur, rows) = parse_devices(&json!({}));
        assert!(cur.is_none());
        assert!(rows.is_empty());
    }
}
