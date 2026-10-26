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
//!   Realm with exact current authorization evidence using a
//!   [`crate::transport::TransportClient::revoke_device`], then rotates the account MLS history
//!   secret and rewraps local `mls_history` backups.
//!
//! The pair flow on `/settings/devices/pair` carries:
//! - New-device request generation belongs exclusively to onboarding, before login. This
//!   authenticated settings page only approves another device.
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
//! - `GET /_arkret/self/account/viewer` — implemented (coland)
//! - `POST /_arkret/gate/account/device-pair` — spec-level device pairing.

use std::rc::Rc;

use glory::prelude::*;
use serde_json::Value;

use super::widgets::{input, *};
use crate::i18n::{tr, tr_args};
use crate::identity::device_pairing::approve_device_pairing;
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::views::helpers::short_protocol_id;

#[derive(Clone, Debug, PartialEq)]
struct DeviceRow {
    device_id: String,
    display_name: String,
    verification_state: String,
    verification_source: Option<String>,
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
                    let verification_source = item
                        .get("verification_source")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let authorized_at = item
                        .get("authorized_at")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    Some(DeviceRow {
                        device_id,
                        display_name,
                        verification_state,
                        verification_source,
                        authorized_at,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct PairingApprovalReview {
    display_name: String,
    device_id: String,
    key_fingerprint: String,
    platform: String,
    account_id: String,
    gate_audience: String,
    pairing_code: String,
    expires_at: String,
}

impl PairingApprovalReview {
    fn from_resolved(resolved: &crate::identity::device_pairing::ResolvedPairingApproval) -> Self {
        let bootstrap = &resolved.bootstrap;
        let unknown = tr("settings.devices.accept_unnamed_device");
        Self {
            display_name: bootstrap
                .display_name
                .as_ref()
                .map(|name| name.as_str().to_owned())
                .unwrap_or_else(|| unknown.clone()),
            device_id: bootstrap.new_device_public_key.kid.as_str().to_owned(),
            key_fingerprint: device_key_fingerprint(&bootstrap.new_device_public_key),
            platform: bootstrap
                .device_metadata
                .as_ref()
                .and_then(|metadata| metadata.platform.as_ref())
                .map(|platform| platform.as_str().to_owned())
                .unwrap_or_else(|| unknown.clone()),
            // The account is read from the signed target proof, never from the
            // anonymous bootstrap: it is the value device-lifecycle.md 5.4.1
            // item 5 makes the approving user responsible for recognising, and
            // the same core under another Station is a different account.
            account_id: resolved.target_proof.account_id.to_string(),
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
/// `verification_state` (`device-lifecycle.md` §10.1) to a colored pill:
/// verified → green shield, unresolved → amber, stale → red. Unknown or
/// missing values fail closed to unresolved.

// Each task is bound to the live page; closing it cancels stale reads and pairing work.
#[derive(Clone)]
struct DevicePage {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    devices: Cage<Vec<DeviceRow>>,
    load_status: Cage<String>,
    revoke_target: Cage<Option<String>>,
    revoke_status: Cage<String>,
    revoke_passphrase: Cage<crate::fresh_device_recovery::RecoveryWordsInput>,
    auto_loaded: Cage<bool>,
    accept_input: Cage<String>,
    accept_code_input: Cage<String>,
    accept_status: Cage<String>,
    accept_resolved: Cage<String>,
    accept_action_busy: Cage<bool>,
}
impl DevicePage {
    fn refresh(&self) {
        let context = self.context.clone();
        let page_owner = self.owner.clone();
        let devices = self.devices;
        let load_status = self.load_status;
        let base = context.base_url.get();
        let api_token = context.token.get();
        let generation = context.session_generation.get();
        let account = context.active_account.get();
        load_status.revise(|value| {
            *value = "Loading…".to_owned();
        });
        if let Some(scope) = page_owner.upgrade() {
            spawn(&scope, async move {
                let result = with_authed_sdk_client(&base, api_token, |http| async move {
                    crate::transport::keys::list_devices(&http).await
                })
                .await;
                if !context.session_matches(generation, &account) {
                    return;
                }
                match result {
                    Ok(value) => {
                        let rows = parse_devices(&serde_json::to_value(&value).unwrap_or_default());
                        let count = rows.len();
                        devices.revise(|value| {
                            *value = rows;
                        });
                        load_status.revise(|value| {
                            *value = format!("Loaded {count} device(s)");
                        });
                    }
                    Err(error) => load_status.revise(|value| {
                        *value = format!("Load failed: {}", error.display());
                    }),
                }
            });
        }
    }
    fn claim(&self) {
        let context = self.context.clone();
        let page_owner = self.owner.clone();
        let accept_code_input = self.accept_code_input;
        let accept_status = self.accept_status;
        let accept_resolved = self.accept_resolved;
        let accept_action_busy = self.accept_action_busy;
        let base_url = context.base_url;
        let token = context.token;
        let Some(account) = context.active_account.get() else {
            return;
        };
        let _authority = account.authority;
        if accept_action_busy.get() {
            return;
        }
        let raw = accept_code_input.get().trim().to_owned();
        let pairing_code = match arkret_sdk::DevicePairingCode::new(raw) {
            Ok(code) => code,
            Err(error) => {
                accept_status.revise(|value| {
                    *value = format!("That is not a valid pairing code: {error}");
                });
                return;
            }
        };
        let base = base_url.get();
        let api_token = token.get();
        accept_action_busy.revise(|value| {
            *value = true;
        });
        accept_status.revise(|value| {
            *value = "Looking up the pairing code…".to_owned();
        });
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    let claim_body = arkret_sdk::DevicePairingCodeClaimRequestBody { pairing_code };
                    match crate::transport::auth::with_endpoint_clients(
                        &base,
                        api_token,
                        None,
                        |clients| async move {
                            clients.keys().device_pairing_claim_code(&claim_body).await
                        },
                    )
                    .await
                    {
                        Ok(claimed) => {
                            let Some(scope) = crate::secure_key_store::active_device_seed_scope()
                            else {
                                accept_resolved.revise(|value| {
                                    *value = String::new();
                                });
                                accept_status.revise(|value| {
                                    *value = "No active account can approve a pairing request."
                                        .to_owned()
                                });
                                accept_action_busy.revise(|value| {
                                    *value = false;
                                });
                                return;
                            };
                            if claimed.device_pairing_request_id
                                != claimed.bootstrap.device_pairing_request_id
                            {
                                accept_resolved.revise(|value| {
                                    *value = String::new();
                                });
                                accept_status.revise(|value| {
                                    *value =
                                        "The claimed code returned two different pairing requests."
                                            .to_owned()
                                });
                                accept_action_busy.revise(|value| {
                                    *value = false;
                                });
                                return;
                            }
                            // Exactly the transcript the scanned-link
                            // path verifies: the code entry never gets
                            // a shorter check for having been typed.
                            let server_challenge = arkret_sdk::signatures::device_pairing::ServerDevicePairingChallenge::from_bootstrap(&claimed.bootstrap);
                            if let Err(error) = arkret_sdk::signatures::device_pairing::verify_server_device_pairing_target_proof(
                                        &claimed.bootstrap.new_device_public_key,
                                        &server_challenge,
                                        &scope.authority,
                                        &claimed.target_proof,
                                        chrono::Utc::now(),
                                    ) {
                                        accept_resolved.revise(|value| { *value = String::new(); });
                                        accept_status.revise(|value| { *value = format!(
                                            "Claimed pairing challenge is invalid: {error}"
                                        ); });
                                        accept_action_busy.revise(|value| { *value = false; });
                                        return;
                                    }
                            let request_payload =
                                crate::identity::device_pairing::ResolvedPairingApproval {
                                    bootstrap: claimed.bootstrap,
                                    target_proof: claimed.target_proof,
                                };
                            match serde_json::to_string(&request_payload) {
                                Ok(payload) => {
                                    accept_resolved.revise(|value| {
                                        *value = payload;
                                    });
                                    accept_status.revise(|value| { *value = "Found. Compare the code and account below with the new device, then approve.".to_owned(); });
                                }
                                Err(error) => {
                                    accept_resolved.revise(|value| {
                                        *value = String::new();
                                    });
                                    accept_status.revise(|value| {
                                        *value =
                                            format!("Claimed pairing material is invalid: {error}")
                                    });
                                }
                            }
                        }
                        Err(err) => {
                            accept_resolved.revise(|value| {
                                *value = String::new();
                            });
                            accept_status.revise(|value| { *value = format!(
                                        "No pending pairing request matches that code: {}. Unknown, expired, already approved and other-account codes are deliberately indistinguishable.",
                                        err.display()
                                    ); });
                        }
                    }
                    accept_action_busy.revise(|value| {
                        *value = false;
                    });
                });
            }
        };
    }

    fn resolve(&self) {
        let context = self.context.clone();
        let page_owner = self.owner.clone();
        let accept_input = self.accept_input;
        let accept_status = self.accept_status;
        let accept_resolved = self.accept_resolved;
        let accept_action_busy = self.accept_action_busy;
        let base_url = context.base_url;
        let token = context.token;
        let Some(account) = context.active_account.get() else {
            return;
        };
        let _authority = account.authority;
        if accept_action_busy.get() {
            return;
        }
        let Some(pairing_token) = extract_device_pairing_token(&accept_input.get()) else {
            accept_status.revise(|value| {
                *value = "Paste a valid pairing link or token first.".to_owned();
            });
            return;
        };
        let Ok(pairing_token) = arkret_sdk::NonEmptyString::new(pairing_token) else {
            accept_status.revise(|value| {
                *value = "Paste a valid pairing link or token first.".to_owned();
            });
            return;
        };
        let Some(target_proof) = extract_device_pairing_target_proof(&accept_input.get()) else {
            accept_status.revise(|value| {
                *value = "The pairing link is missing its target-device attestation.".to_owned()
            });
            return;
        };
        let base = base_url.get();
        let api_token = token.get();
        accept_action_busy.revise(|value| {
            *value = true;
        });
        accept_status.revise(|value| {
            *value = "Resolving pairing link…".to_owned();
        });
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    let resolve_body =
                        arkret_sdk::DevicePairingResolveRequestBody { pairing_token };
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
                            let Some(scope) = crate::secure_key_store::active_device_seed_scope()
                            else {
                                accept_resolved.revise(|value| {
                                    *value = String::new();
                                });
                                accept_status.revise(|value| {
                                    *value = "No active account can approve a pairing request."
                                        .to_owned()
                                });
                                accept_action_busy.revise(|value| {
                                    *value = false;
                                });
                                return;
                            };
                            let server_challenge = arkret_sdk::signatures::device_pairing::ServerDevicePairingChallenge::from_bootstrap(&bootstrap);
                            if let Err(error) = arkret_sdk::signatures::device_pairing::verify_server_device_pairing_target_proof(
                                        &bootstrap.new_device_public_key,
                                        &server_challenge,
                                        &scope.authority,
                                        &target_proof,
                                        chrono::Utc::now(),
                                    ) {
                                        accept_resolved.revise(|value| { *value = String::new(); });
                                        accept_status.revise(|value| { *value = format!(
                                            "Resolved pairing challenge is invalid: {error}"
                                        ); });
                                        accept_action_busy.revise(|value| { *value = false; });
                                        return;
                                    }
                            let request_payload =
                                crate::identity::device_pairing::ResolvedPairingApproval {
                                    bootstrap,
                                    target_proof,
                                };
                            match serde_json::to_string(&request_payload) {
                                Ok(payload) => accept_resolved.revise(|value| {
                                    *value = payload;
                                }),
                                Err(error) => {
                                    accept_resolved.revise(|value| {
                                        *value = String::new();
                                    });
                                    accept_status.revise(|value| {
                                        *value =
                                            format!("Resolved pairing material is invalid: {error}")
                                    });
                                    accept_action_busy.revise(|value| {
                                        *value = false;
                                    });
                                    return;
                                }
                            }
                            accept_status.revise(|value| { *value = "Resolved. Compare the code below with the new device, then approve.".to_owned(); });
                        }
                        Err(err) => {
                            accept_resolved.revise(|value| {
                                *value = String::new();
                            });
                            accept_status.revise(|value| { *value = format!(
                                        "Could not resolve pairing link: {}. The link may be invalid, expired, or already accepted. Check authorization status on the new device before creating another request.",
                                        err.display()
                                    ); });
                        }
                    }
                    accept_action_busy.revise(|value| {
                        *value = false;
                    });
                });
            }
        };
    }

    fn approve(&self) {
        let context = self.context.clone();
        let page_owner = self.owner.clone();
        let auto_loaded = self.auto_loaded;
        let accept_input = self.accept_input;
        let accept_code_input = self.accept_code_input;
        let accept_status = self.accept_status;
        let accept_resolved = self.accept_resolved;
        let accept_action_busy = self.accept_action_busy;
        let base_url = context.base_url;
        let token = context.token;
        if accept_action_busy.get() {
            return;
        }
        let request_payload: crate::identity::device_pairing::ResolvedPairingApproval =
            match serde_json::from_str(&accept_resolved.get()) {
                Ok(value) => value,
                Err(err) => {
                    accept_status.revise(|value| {
                        *value = format!("Resolved pairing became invalid: {err}");
                    });
                    return;
                }
            };
        let base = base_url.get();
        let api_token = token.get();
        accept_action_busy.revise(|value| {
            *value = true;
        });
        accept_status.revise(|value| {
            *value = "Approving device pairing…".to_owned();
        });
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    match crate::transport::auth::with_authed_api(
                        &base,
                        api_token,
                        |api| async move { approve_device_pairing(&api, &request_payload).await },
                    )
                    .await
                    {
                        Ok(value) => {
                            auto_loaded.revise(|value| {
                                *value = false;
                            });
                            accept_resolved.revise(|value| {
                                *value = String::new();
                            });
                            accept_input.revise(|value| {
                                *value = String::new();
                            });
                            accept_code_input.revise(|value| {
                                *value = String::new();
                            });
                            let accepted_event = value.authorized_event_ref.event_id;
                            accept_status.revise(|value| { *value = format!("Device authorization accepted ({}). On the new device, check authorization status and sign in again. Encrypted Realms become available after KeyPackage publication and Welcome processing.", accepted_event); });
                        }
                        Err(err) => {
                            accept_status.revise(|value| {
                                *value = tr_args(
                                    "device_pair.err_approval_failed",
                                    &[("error", err.display())],
                                )
                            });
                        }
                    }
                    accept_action_busy.revise(|value| {
                        *value = false;
                    });
                });
            }
        };
    }

    fn reject(&self) {
        let _context = self.context.clone();
        let _page_owner = self.owner.clone();
        let _devices = self.devices;
        let accept_input = self.accept_input;
        let accept_code_input = self.accept_code_input;
        let accept_status = self.accept_status;
        let accept_resolved = self.accept_resolved;
        accept_resolved.revise(|value| {
            *value = String::new();
        });
        accept_input.revise(|value| {
            *value = String::new();
        });
        accept_code_input.revise(|value| {
            *value = String::new();
        });
        accept_status.revise(|value| {
            *value = tr("settings.devices.accept_rejected");
        });
    }

    fn revoke(&self) {
        let context = self.context.clone();
        let page_owner = self.owner.clone();
        let devices = self.devices;
        let load_status = self.load_status;
        let revoke_target = self.revoke_target;
        let revoke_status = self.revoke_status;
        let revoke_passphrase = self.revoke_passphrase;
        let base_url = context.base_url;
        let token = context.token;
        let device_id = context.device_id;
        let state_store = context.state_store.clone();
        let Some(account) = context.active_account.get() else {
            return;
        };
        let authority = account.authority;
        let confirm_target = self.revoke_target.get().unwrap_or_default();
        let base = base_url.get();
        let api_token = token.get();
        let current_device = device_id.get();
        let target_id = confirm_target.clone();
        let target_for_status = target_id.clone();
        let target_label = short_protocol_id(&target_for_status);
        let Some(recovery_words) = revoke_passphrase.get().normalized() else {
            revoke_status.revise(|value| { *value = "Enter your 24-word Recovery Key before revoking — it is required to rotate the MLS history secret.".to_owned(); });
            return;
        };
        let snapshots = state_store.read(|store| store.mls_local_checkpoints());
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let authority = authority.clone();
        revoke_status.revise(|value| {
            *value = format!("Revoking {target_label}…");
        });
        {
            let current_owner = page_owner.clone();
            if let Some(scope) = current_owner.upgrade() {
                super::widgets::spawn(&scope, async move {
                    let target_label = short_protocol_id(&target_for_status);
                    let rotation_result =
                        with_authed_api(&base, api_token.clone(), move |api| async move {
                            crate::mls::account_recovery::execute_device_revoke_security_rotation(
                                &api,
                                secure_store,
                                &state_store.handle(),
                                &authority,
                                &current_device,
                                &target_id,
                                recovery_words.as_str(),
                                &snapshots,
                            )
                            .await
                        })
                        .await;
                    match rotation_result {
                        Ok(rotation) => {
                            revoke_status.revise(|value| { *value = format!(
                                            "Revoked {target_label} through transaction {}. Rotated MLS history secret to v{} with {} replacement backup object(s); old backup material was durably erased.",
                                            rotation.transaction_id,
                                            rotation.new_secret_version,
                                            rotation.replacement_backup_count,
                                        ); });
                            revoke_passphrase.revise(|value| value.clear());
                            revoke_target.revise(|value| {
                                *value = None;
                            });
                            // Re-fetch to reflect the new
                            // active set. Failure here is
                            // non-fatal; the status text
                            // already records the revoke.
                            let base_refresh = base.clone();
                            let token_refresh = api_token.clone();
                            {
                                let current_owner = page_owner.clone();
                                if let Some(scope) = current_owner.upgrade() {
                                    super::widgets::spawn(&scope, async move {
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
                                            devices.revise(|value| {
                                                *value = rows;
                                            });
                                            load_status.revise(|value| {
                                                *value = format!("Loaded {count} device(s)")
                                            });
                                        }
                                    });
                                }
                            };
                        }
                        Err(err) => {
                            revoke_status.revise(|value| { *value = format!(
                                            "Revoke transaction for {target_label} failed safely and can be resumed: {}",
                                            err.display()
                                        ); });
                        }
                    }
                });
            }
        };
    }
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>, pair_mode: bool) -> View {
    let state = DevicePage {
        context: context.clone(),
        owner: scope.downgrade(),
        devices: scope.cage(Vec::new()),
        load_status: scope.cage(String::new()),
        revoke_target: scope.cage(None),
        revoke_status: scope.cage(String::new()),
        revoke_passphrase: scope.cage(crate::fresh_device_recovery::RecoveryWordsInput::default()),
        auto_loaded: scope.cage(false),
        accept_input: scope.cage(String::new()),
        accept_code_input: scope.cage(String::new()),
        accept_status: scope.cage(String::new()),
        accept_resolved: scope.cage(String::new()),
        accept_action_busy: scope.cage(false),
    };
    if !pair_mode {
        let effect_state = state.clone();
        scope.effect(move || {
            let _ = effect_state.context.session_generation.get();
            if !effect_state.context.token.get().trim().is_empty() {
                effect_state.refresh();
            }
        });
    }
    let list_context = context.clone();
    let list_state = state.clone();
    let device_id = context.device_id;
    let list = reactive(state.devices, move |scope, rows| {
        let context = list_context.clone();
        if rows.is_empty() {
            return crate::components::empty_state(
                scope,
                context.clone(),
                crate::components::EmptyStateProps {
                    title: context.tr("settings.devices.empty_title"),
                    kind: crate::components::EmptyStateKind::Empty,
                    message: Some(context.tr("settings.devices.empty_message")),
                    badge_override: None,
                    test_id: Some("device-list-empty".into()),
                },
            );
        }
        let mut children = vec![line(
            "device-list-header",
            [
                "settings.devices.column_device",
                "settings.devices.column_verification",
                "settings.devices.column_authorized",
                "settings.devices.column_actions",
            ]
            .into_iter()
            .map(|key| plain(context.translated(scope, key)))
            .collect(),
        )];
        for row in rows {
            let current = row.device_id == device_id.get();
            let target = row.device_id.clone();
            let revoke = list_state.revoke_target;
            let has_name = !row.display_name.is_empty();
            let name = if has_name {
                row.display_name.clone()
            } else {
                short_protocol_id(&row.device_id)
            };
            let mut identity = vec![
                paragraph(
                    "device-list-cell-label",
                    context.translated(scope, "settings.devices.column_device"),
                ),
                line(
                    "device-identity",
                    vec![
                        paragraph("device-name device-row-name", name),
                        paragraph(
                            "muted device-id-suffix device-row-id-suffix",
                            format!(
                                "#{}",
                                crate::identity::device_name::device_id_short_suffix(
                                    &row.device_id
                                )
                            ),
                        ),
                    ],
                ),
            ];
            if has_name {
                identity.push(paragraph(
                    "muted device-id-secondary",
                    short_protocol_id(&row.device_id),
                ));
            }
            if current {
                identity.push(paragraph(
                    "badge green device-row-current",
                    context.translated(scope, "settings.devices.this_device"),
                ));
            }
            let (badge, glyph, key) =
                match row.verification_state.trim().to_ascii_lowercase().as_str() {
                    "verified" => (
                        "badge success device-verification-badge",
                        "🛡",
                        "settings.devices.state_verified",
                    ),
                    "stale" => (
                        "badge danger device-verification-badge",
                        "⊘",
                        "settings.devices.state_stale",
                    ),
                    _ => (
                        "badge warning device-verification-badge",
                        "⚠",
                        "settings.devices.state_unresolved",
                    ),
                };
            let mut verification = vec![
                paragraph(
                    "device-list-cell-label",
                    context.translated(scope, "settings.devices.column_verification"),
                ),
                paragraph(badge, format!("{glyph} {}", context.tr(key))),
            ];
            if let Some(source) =
                device_verification_source_label(row.verification_source.as_deref())
            {
                verification.push(paragraph(
                    "muted device-verification-source",
                    context
                        .tr("settings.devices.source_title")
                        .replace("{source}", &source),
                ));
            }
            children.push(line(
                if current {
                    "device-row device-list-row current device-list-row-current"
                } else {
                    "device-row device-list-row"
                },
                vec![
                    stack("device-list-cell device-list-cell-identity", identity),
                    stack("device-list-cell", verification),
                    stack(
                        "device-list-cell",
                        vec![
                            paragraph(
                                "device-list-cell-label",
                                context.translated(scope, "settings.devices.column_authorized"),
                            ),
                            paragraph(
                                "device-authorized-at",
                                if row.authorized_at.is_empty() {
                                    "—".into()
                                } else {
                                    row.authorized_at
                                },
                            ),
                        ],
                    ),
                    stack(
                        "device-list-cell device-list-cell-actions",
                        vec![
                            paragraph(
                                "device-list-cell-label",
                                context.translated(scope, "settings.devices.column_actions"),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "device-revoke-button",
                                if current {
                                    "settings.devices.revoke_self_blocked"
                                } else {
                                    "settings.devices.revoke"
                                },
                                "secondary",
                                !current,
                                move || revoke.revise(|value| *value = Some(target.clone())),
                            ),
                        ],
                    ),
                ],
            ));
        }
        stack("device-list-table", children)
    });
    let dialog_state = state.clone();
    let dialog_context = context.clone();
    let modal = reactive(state.revoke_target, move |scope, target| {
        let Some(target) = target else {
            return empty();
        };
        let context = dialog_context.clone();
        let state = dialog_state.clone();
        let words = state.revoke_passphrase;
        let word_text = scope.bond(move || words.get().as_str().to_owned());
        let word_input: View = Box::new(
            sapid::field("device-revoke-passphrase")
                .unstyled()
                .class("field")
                .label(context.translated(scope, "settings.devices.revoke_recovery_label"))
                .control(move |field| {
                    sapid::text_field()
                        .unstyled()
                        .field(field)
                        .purpose(Purpose::Password)
                        .value(word_text)
                        .on_value_change(move |next| words.revise(|value| value.replace(next)))
                }),
        );
        let enabled = scope.bond(move || !words.get().is_empty());
        let cancel = state.revoke_target;
        let submit = state.clone();
        let body = stack(
            "modal-body workflow-form device-revoke-modal-body",
            vec![
                paragraph("muted device-revoke-target", short_protocol_id(&target)),
                paragraph(
                    "",
                    context.translated(scope, "settings.devices.revoke_body_before"),
                ),
                paragraph(
                    "muted",
                    context.translated(scope, "settings.devices.revoke_threat_note"),
                ),
                word_input,
                line(
                    "modal-foot actions",
                    vec![
                        action(
                            scope,
                            context.clone(),
                            "device-revoke-cancel-button",
                            "common.cancel",
                            "secondary",
                            true,
                            move || {
                                cancel.revise(|value| {
                                    *value = None;
                                })
                            },
                        ),
                        action(
                            scope,
                            context.clone(),
                            "device-revoke-confirm-button",
                            "settings.devices.revoke_confirm",
                            "primary",
                            enabled,
                            move || submit.revoke(),
                        ),
                    ],
                ),
            ],
        );
        confirmation(
            scope,
            context.clone(),
            "device-revoke-modal",
            context.translated(scope, "settings.devices.revoke_title"),
            body,
            move || {
                cancel.revise(|value| {
                    *value = None;
                })
            },
        )
    });
    let busy = state.accept_action_busy;
    let enabled = scope.bond(move || !busy.get());
    let claim_state = state.clone();
    let resolve_state = state.clone();
    let approve_state = state.clone();
    let reject_state = state.clone();
    let resolved = state.accept_resolved;
    let review_context = context.clone();
    let review = reactive(resolved, move |scope, json| {
        let Ok(payload) =
            serde_json::from_str::<crate::identity::device_pairing::ResolvedPairingApproval>(&json)
        else {
            return empty();
        };
        let review = PairingApprovalReview::from_resolved(&payload);
        let context = review_context.clone();
        stack(
            "device-pair-approval-review",
            vec![
                heading(4, "", context.translated(scope, "device_pair.title")),
                paragraph("muted", context.translated(scope, "device_pair.body")),
                line(
                    "device-pair-approval-facts",
                    vec![
                        plain(review.display_name),
                        plain(review.device_id),
                        plain(review.key_fingerprint),
                        plain(review.platform),
                        plain(review.account_id),
                        plain(review.gate_audience),
                        plain(review.expires_at),
                    ],
                ),
                paragraph(
                    "muted",
                    context.translated(scope, "device_pair.compare_code"),
                ),
                heading(2, "device-pair-approval-code mono", review.pairing_code),
            ],
        )
    });
    let pair = card(
        scope,
        context.clone(),
        "settings.devices.accept_title",
        vec![
            paragraph(
                "muted",
                context.translated(scope, "settings.devices.accept_body"),
            ),
            field(
                scope,
                context.clone(),
                "accept-pairing-input",
                "settings.devices.accept_placeholder",
                state.accept_input,
                enabled,
                true,
                {
                    let input = state.accept_input;
                    move |next| {
                        input.revise(|value| {
                            *value = next;
                        })
                    }
                },
            ),
            stack(
                "accept-pairing-code-entry",
                vec![
                    paragraph(
                        "muted",
                        context.translated(scope, "settings.devices.accept_code_body"),
                    ),
                    input(
                        scope,
                        context.clone(),
                        "accept-pairing-code-input",
                        "settings.devices.accept_code_title",
                        state.accept_code_input,
                        enabled,
                    ),
                    action(
                        scope,
                        context.clone(),
                        "accept-pairing-code-claim-button",
                        "settings.devices.accept_code_claim",
                        "secondary",
                        {
                            let code = state.accept_code_input;
                            scope.bond(move || enabled.get() && !code.get().trim().is_empty())
                        },
                        move || claim_state.claim(),
                    ),
                ],
            ),
            action(
                scope,
                context.clone(),
                "accept-pairing-resolve-button",
                "settings.devices.accept_resolve",
                "secondary",
                {
                    let input = state.accept_input;
                    scope.bond(move || enabled.get() && !input.get().trim().is_empty())
                },
                move || resolve_state.resolve(),
            ),
            review,
            reactive(resolved, {
                let context = context.clone();
                move |scope, value| {
                    if value.is_empty() {
                        return empty();
                    }
                    let approve = approve_state.clone();
                    let reject = reject_state.clone();
                    line(
                        "actions",
                        vec![
                            action(
                                scope,
                                context.clone(),
                                "accept-pairing-button",
                                "device_pair.approve",
                                "primary",
                                enabled,
                                move || approve.approve(),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "accept-pairing-reject-button",
                                "device_pair.reject",
                                "secondary",
                                enabled,
                                move || reject.reject(),
                            ),
                        ],
                    )
                }
            }),
            status(state.accept_status),
        ],
    );
    let list_link = context.clone();
    let pair_link = context.clone();
    let refresh = state.clone();
    let has_session = !context.token.get().trim().is_empty();
    let mut toolbar = vec![
        line(
            "device-access-toolbar-head",
            vec![
                stack(
                    "device-access-heading",
                    vec![
                        paragraph(
                            "device-access-title",
                            context.translated(scope, "settings.devices.title"),
                        ),
                        paragraph(
                            "muted",
                            context.translated(scope, "settings.devices.subtitle"),
                        ),
                    ],
                ),
                line(
                    "device-access-session-state",
                    vec![
                        paragraph(
                            if has_session {
                                "badge success"
                            } else {
                                "badge warning"
                            },
                            context.translated(
                                scope,
                                if has_session {
                                    "settings.devices.session_active"
                                } else {
                                    "settings.devices.session_inactive"
                                },
                            ),
                        ),
                        crate::components::help_tip(
                            scope,
                            context.clone(),
                            crate::components::HelpTipProps {
                                text: context.tr("settings.devices.help"),
                            },
                        ),
                    ],
                ),
            ],
        ),
        line(
            "device-access-tabs",
            vec![
                Box::new(
                    crate::presentation::widgets::internal_link()
                        .class(if pair_mode {
                            "device-access-tab device-access-list"
                        } else {
                            "device-access-tab device-access-list active"
                        })
                        .target(Route::SettingsDevices.to_string())
                        .name(context.translated(scope, "settings.devices.tab_list"))
                        .fill(glory::ui::group().fill(
                            (
                                crate::components::ui_icon("monitor"),
                                glory::ui::text().content(
                                    context.translated(scope, "settings.devices.tab_list"),
                                ),
                            ),
                        ))
                        .on(glory::render::EventKind::Activate, move |_| {
                            list_link.navigate(Route::SettingsDevices)
                        }),
                ),
                Box::new(
                    crate::presentation::widgets::internal_link()
                        .class(if pair_mode {
                            "device-access-tab device-access-add active"
                        } else {
                            "device-access-tab device-access-add"
                        })
                        .target(Route::SettingsDevicesPair.to_string())
                        .name(context.translated(scope, "settings.devices.tab_add"))
                        .fill(
                            glory::ui::group().fill((
                                crate::components::ui_icon("plus"),
                                glory::ui::text()
                                    .content(context.translated(scope, "settings.devices.tab_add")),
                            )),
                        )
                        .on(glory::render::EventKind::Activate, move |_| {
                            pair_link.navigate(Route::SettingsDevicesPair)
                        }),
                ),
            ],
        ),
    ];
    if !pair_mode {
        toolbar.push(Box::new(
            sapid::button()
                .unstyled()
                .class("btn secondary device-access-refresh device-list-refresh")
                .name(context.translated(scope, "settings.devices.refresh"))
                .fill(
                    glory::ui::group().fill((
                        crate::components::ui_icon("refresh"),
                        glory::ui::text()
                            .content(context.translated(scope, "settings.devices.refresh")),
                    )),
                )
                .on_press(move || refresh.refresh()),
        ));
    }
    stack(
        "settings-content-stack settings-devices-panel",
        vec![
            stack("event device-access-toolbar", toolbar),
            if pair_mode {
                pair
            } else {
                stack(
                    "event device-list-card device-list",
                    vec![
                        line(
                            "event-head",
                            vec![
                                plain(context.translated(scope, "settings.devices.active_title")),
                                plain(state.load_status),
                            ],
                        ),
                        list,
                        status(state.revoke_status),
                        modal,
                    ],
                )
            },
        ],
    )
}

fn device_verification_source_label(source: Option<&str>) -> Option<String> {
    match source? {
        "genesis" => Some(tr("settings.devices.source_genesis")),
        "pairing_code" => Some(tr("settings.devices.source_pairing_code")),
        "recovery" => Some(tr("settings.devices.source_recovery")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn target_proof() -> arkret_sdk::DevicePairingTargetProof {
        serde_json::from_value(json!({
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:webvh:z6mkfixturestationexample"
            },
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
                    "verification_source": "pairing_code",
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
        assert_eq!(rows[0].verification_source.as_deref(), Some("pairing_code"));
        assert_eq!(rows[0].authorized_at, "2026-05-01T00:00:00.000Z");
        // Missing display_name parses to an empty string (UI falls back
        // to the short device id).
        assert_eq!(rows[1].display_name, "");
        assert_eq!(rows[1].verification_state, "unresolved");
        assert_eq!(rows[1].verification_source, None);
    }

    #[test]
    fn verification_source_labels_are_closed_and_do_not_invent_provenance() {
        assert_eq!(
            device_verification_source_label(Some("genesis")),
            Some(tr("settings.devices.source_genesis"))
        );
        assert_eq!(
            device_verification_source_label(Some("pairing_code")),
            Some(tr("settings.devices.source_pairing_code"))
        );
        assert_eq!(
            device_verification_source_label(Some("recovery")),
            Some(tr("settings.devices.source_recovery"))
        );
        assert_eq!(device_verification_source_label(Some("session")), None);
        assert_eq!(device_verification_source_label(None), None);
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
        let proof = arkret_sdk::base64url_encode(
            arkret_sdk::canonical::canonical_json_bytes(&attestation).unwrap(),
        );
        let link = format!(
            "https://host.example/_arkret/open/device-pairing/resolve#token=abc123&proof={proof}"
        );
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
