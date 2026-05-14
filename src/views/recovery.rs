//! Recovery surface — Encrypted Cloud Vault + Recovery Key + Social
//! Recovery panels. Wires the three recovery layers from
//! `crypto-media/devices-and-auth.md` §4 to real state:
//!
//! - **Encrypted Cloud Vault**: the passphrase is stretched on-device with
//!   Argon2id (`recovery_crypto::derive_vault_kek`) and the resulting key
//!   encrypts a JSON payload with XChaCha20-Poly1305 before being POSTed
//!   to `PUT /api/v1/keys/backups/{backup_id}` via
//!   [`crate::api::ContrixApi::put_key_backup`]. The server never sees the
//!   passphrase or the plaintext.
//! - **Recovery Key**: 256 bits of entropy, formatted as Crockford-base32
//!   groups. The plaintext only lives in memory between Generate and the
//!   user's Copy / Print interaction; only a SHA-256 fingerprint plus
//!   rotation timestamp are persisted via `LocalStateStore::save_private_data`.
//! - **Social Recovery**: guardian list + Shamir threshold + last-rehearsal
//!   timestamp persisted as JSON under the same private_data store.
//!
//! Everything writeable goes through `private_data`, which is itself
//! encrypted at rest under the account DID via `xor_encrypt` (and on
//! wasm32 mirrored to localStorage). The Recovery view never persists
//! the passphrase or the Recovery Key in cleartext.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    components::HelpTip,
    key_backup::build_recovery_vault_backup_body,
    local_state::LocalStateStore,
    operation::uuid_v7,
    recovery_crypto::{
        VAULT_ARGON2_M_KIB, VAULT_ARGON2_P, VAULT_ARGON2_T, derive_vault_kek, encrypt_vault,
        estimate_passphrase_strength, fingerprint_recovery_key, generate_recovery_key,
    },
    views::helpers::authed_api,
};

const RECOVERY_STATE_KEY: &str = "recovery.state.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncBadge {
    Local,
    Pending,
    Synced,
    Failed,
}

impl SyncBadge {
    fn label(self) -> &'static str {
        match self {
            Self::Local => "Local only",
            Self::Pending => "Uploading…",
            Self::Synced => "Synced",
            Self::Failed => "Sync failed",
        }
    }

    fn class(self) -> &'static str {
        match self {
            Self::Local => "badge",
            Self::Pending => "badge amber",
            Self::Synced => "badge green",
            Self::Failed => "badge red",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Guardian {
    label: String,
    did: String,
    note: String,
    #[serde(default)]
    confirmed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryState {
    /// Latest Encrypted Cloud Vault backup id, once `put_key_backup` has
    /// accepted at least one upload. Empty until first upload.
    #[serde(default)]
    vault_backup_id: String,
    /// RFC-3339 UTC timestamp of the last successful vault upload.
    #[serde(default)]
    vault_uploaded_at: String,
    /// SHA-256 fingerprint of the current Recovery Key (never the plaintext).
    #[serde(default)]
    recovery_key_fingerprint: String,
    /// RFC-3339 UTC timestamp of the last Recovery Key rotation.
    #[serde(default)]
    recovery_key_rotated_at: String,
    /// 3 of 5, 2 of 3, etc. — encoded as `threshold / total`.
    #[serde(default = "default_threshold")]
    sss_threshold: u32,
    #[serde(default = "default_total")]
    sss_total: u32,
    #[serde(default)]
    guardians: Vec<Guardian>,
    /// RFC-3339 UTC of the last "Rehearse social recovery" click.
    #[serde(default)]
    last_rehearsed_at: String,
}

fn default_threshold() -> u32 {
    3
}
fn default_total() -> u32 {
    5
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self {
            vault_backup_id: String::new(),
            vault_uploaded_at: String::new(),
            recovery_key_fingerprint: String::new(),
            recovery_key_rotated_at: String::new(),
            sss_threshold: default_threshold(),
            sss_total: default_total(),
            guardians: Vec::new(),
            last_rehearsed_at: String::new(),
        }
    }
}

fn load_state(state_store: &Signal<LocalStateStore>, account_key: &str) -> RecoveryState {
    if account_key.is_empty() {
        return RecoveryState::default();
    }
    match state_store.read().load_private_data(account_key, RECOVERY_STATE_KEY) {
        Some(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        None => RecoveryState::default(),
    }
}

fn save_state(
    state_store: &mut Signal<LocalStateStore>,
    account_key: &str,
    state: &RecoveryState,
) {
    if account_key.is_empty() {
        return;
    }
    if let Ok(payload) = serde_json::to_string(state) {
        state_store
            .write()
            .save_private_data(account_key, RECOVERY_STATE_KEY, payload);
    }
}

fn fmt_relative(iso: &str) -> String {
    if iso.is_empty() {
        return "never".to_owned();
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(iso).ok();
    let Some(parsed) = parsed else {
        return iso.to_owned();
    };
    let now = chrono::Utc::now();
    let dur = now.signed_duration_since(parsed.with_timezone(&chrono::Utc));
    let secs = dur.num_seconds().max(0);
    if secs < 60 {
        "just now".to_owned()
    } else if secs < 3_600 {
        format!("{} min ago", secs / 60)
    } else if secs < 86_400 {
        format!("{} hr ago", secs / 3_600)
    } else {
        format!("{} days ago", secs / 86_400)
    }
}

fn passphrase_strength_label(score: u8) -> &'static str {
    match score {
        0 => "—",
        1 => "Weak",
        2 => "Fair",
        3 => "Good",
        4 => "Strong",
        _ => "Very strong",
    }
}

#[component]
pub fn RecoveryPanel(
    base_url: String,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
    account_did: Signal<String>,
    device_id: Signal<String>,
) -> Element {
    let actor_key = account_did();
    let initial = load_state(&state_store, &actor_key);

    // Vault section state
    let mut passphrase = use_signal(String::new);
    let mut confirm_pass = use_signal(String::new);
    let mut vault_status = use_signal(String::new);
    let mut vault_sync = use_signal(|| {
        if initial.vault_uploaded_at.is_empty() {
            SyncBadge::Local
        } else {
            SyncBadge::Synced
        }
    });
    let mut vault_backup_id = use_signal(|| initial.vault_backup_id.clone());
    let mut vault_uploaded_at = use_signal(|| initial.vault_uploaded_at.clone());

    // Recovery key state — plaintext only in memory after Generate.
    let mut live_recovery_key = use_signal(String::new);
    let mut recovery_key_fp = use_signal(|| initial.recovery_key_fingerprint.clone());
    let mut recovery_key_rotated_at = use_signal(|| initial.recovery_key_rotated_at.clone());
    let mut recovery_key_status = use_signal(String::new);

    // Social recovery state
    let mut threshold = use_signal(|| initial.sss_threshold);
    let mut total = use_signal(|| initial.sss_total);
    let mut guardians = use_signal(|| initial.guardians.clone());
    let mut new_guardian_label = use_signal(String::new);
    let mut new_guardian_did = use_signal(String::new);
    let mut new_guardian_note = use_signal(String::new);
    let mut last_rehearsed = use_signal(|| initial.last_rehearsed_at.clone());
    let mut social_status = use_signal(String::new);

    let strength = estimate_passphrase_strength(&passphrase());

    let snapshot_state = move || RecoveryState {
        vault_backup_id: vault_backup_id(),
        vault_uploaded_at: vault_uploaded_at(),
        recovery_key_fingerprint: recovery_key_fp(),
        recovery_key_rotated_at: recovery_key_rotated_at(),
        sss_threshold: threshold(),
        sss_total: total(),
        guardians: guardians(),
        last_rehearsed_at: last_rehearsed(),
    };

    rsx! {
        div { class: "timeline", "data-testid": "recovery-panel", role: "region", "aria-label": "Recovery and key backup",
            div { class: "event",
                div { class: "event-head",
                    span { "Recovery options" }
                    span { "Encrypted Vault · Social Recovery · Recovery Key" }
                    HelpTip { text: "Contrix never stores your passphrase on the server. Backups are encrypted on-device before upload. Any one recovery path is enough to re-authorize a new device on your account." }
                }
                div { class: "metric-grid", "data-testid": "recovery-overview",
                    div { class: "metric",
                        strong { "Primary" }
                        span { "Encrypted Cloud Vault" }
                        div { class: "muted", "Argon2id + xchacha20poly1305" }
                    }
                    div { class: "metric",
                        strong { "Backup" }
                        span { "SSS {threshold} of {total}" }
                        div { class: "muted", "{guardians().len()} guardian(s) recorded" }
                    }
                    div { class: "metric",
                        strong { "Recovery Key" }
                        span {
                            if recovery_key_fp().is_empty() { "not generated" } else { "fingerprint stored" }
                        }
                        div { class: "muted",
                            if recovery_key_rotated_at().is_empty() { "Generate one to enable single-key recovery" } else { "Last rotated {fmt_relative(&recovery_key_rotated_at())}" }
                        }
                    }
                    div { class: "metric",
                        strong { "Last rehearsal" }
                        span { "{fmt_relative(&last_rehearsed())}" }
                        div { class: "muted", "Rehearse at least every 30 days" }
                    }
                }
            }

            // Encrypted Cloud Vault — devices-and-auth §4.1
            div { class: "event", "data-testid": "vault-section",
                div { class: "event-head",
                    span { "Encrypted Cloud Vault" }
                    span { class: vault_sync().class(), "data-testid": "vault-sync-badge", {vault_sync().label()} }
                    HelpTip { text: "Your passphrase is stretched on-device with Argon2id (m=64MiB, t=3, p=4) and the resulting key encrypts the recovery payload with XChaCha20-Poly1305 before it leaves the device. The salt and nonce travel with the ciphertext; the passphrase does not." }
                }
                div { class: "workflow-form",
                    label { r#for: "vault-passphrase", "Vault passphrase" }
                    input {
                        id: "vault-passphrase",
                        "data-testid": "vault-passphrase",
                        r#type: "password",
                        value: "{passphrase}",
                        placeholder: "Choose a strong passphrase (16+ chars recommended)",
                        autocomplete: "new-password",
                        oninput: move |evt| passphrase.set(evt.value()),
                    }
                    label { r#for: "vault-passphrase-confirm", "Confirm passphrase" }
                    input {
                        id: "vault-passphrase-confirm",
                        "data-testid": "vault-passphrase-confirm",
                        r#type: "password",
                        value: "{confirm_pass}",
                        autocomplete: "new-password",
                        oninput: move |evt| confirm_pass.set(evt.value()),
                    }
                    div { class: "muted", "data-testid": "vault-passphrase-strength",
                        "Strength: {passphrase_strength_label(strength)} ({strength}/5)"
                    }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Key derivation" }
                        span { "Argon2id (m=64MiB, t=3, p=4)" }
                        div { class: "muted", "OWASP-recommended parameters" }
                    }
                    div { class: "metric",
                        strong { "Encryption" }
                        span { "xchacha20poly1305" }
                        div { class: "muted", "192-bit nonce, AEAD authenticated" }
                    }
                    div { class: "metric",
                        strong { "Latest upload" }
                        span {
                            "data-testid": "vault-uploaded-at",
                            "{fmt_relative(&vault_uploaded_at())}"
                        }
                        div { class: "muted",
                            if vault_backup_id().is_empty() { "No backup uploaded yet" } else { "backup_id: {vault_backup_id()}" }
                        }
                    }
                    div { class: "metric",
                        strong { "Storage" }
                        span { "PUT /api/v1/keys/backups" }
                        div { class: "muted", "Ciphertext only; the server cannot decrypt" }
                    }
                }
                if !vault_status().is_empty() {
                    div { class: "muted", "data-testid": "vault-status", "{vault_status}" }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "vault-rekey",
                        disabled: strength < 2 || passphrase() != confirm_pass() || passphrase().is_empty(),
                        onclick: {
                            let base = base_url.clone();
                            let mut store = state_store;
                            let actor_key = actor_key.clone();
                            move |_| {
                                let pass = passphrase();
                                let confirm = confirm_pass();
                                if pass.is_empty() || pass != confirm {
                                    vault_status.set("Passphrase and confirmation must match.".to_owned());
                                    return;
                                }
                                vault_sync.set(SyncBadge::Pending);
                                vault_status.set("Stretching passphrase with Argon2id…".to_owned());

                                let base = base.clone();
                                let api_token = token();
                                let actor = actor_key.clone();
                                let device = device_id();
                                let next_backup_id = if vault_backup_id().is_empty() {
                                    format!("cx:backup:{}", uuid_v7())
                                } else {
                                    vault_backup_id()
                                };
                                let payload_plaintext = serde_json::json!({
                                    "schema_version": 1,
                                    "actor_did": actor,
                                    "device_id": device,
                                    "recovery_key_fingerprint": recovery_key_fp(),
                                    "minted_at": chrono::Utc::now().to_rfc3339(),
                                })
                                .to_string();
                                let pass_bytes = pass.into_bytes();
                                let backup_id_for_async = next_backup_id.clone();
                                let actor_for_async = actor.clone();
                                let actor_key_for_async = actor_key.clone();
                                let device_for_async = device.clone();

                                spawn(async move {
                                    let kek = match derive_vault_kek(&pass_bytes) {
                                        Ok(k) => k,
                                        Err(err) => {
                                            vault_sync.set(SyncBadge::Failed);
                                            vault_status.set(format!("Argon2id failed: {err}"));
                                            return;
                                        }
                                    };
                                    let ct = match encrypt_vault(&kek, payload_plaintext.as_bytes()) {
                                        Ok(c) => c,
                                        Err(err) => {
                                            vault_sync.set(SyncBadge::Failed);
                                            vault_status.set(format!("AEAD encrypt failed: {err}"));
                                            return;
                                        }
                                    };
                                    let body = build_recovery_vault_backup_body(
                                        &backup_id_for_async,
                                        &actor_for_async,
                                        &device_for_async,
                                        &ct.ciphertext_b64,
                                        &ct.digest_sha256,
                                        &ct.salt_b64,
                                        &ct.nonce_b64,
                                        VAULT_ARGON2_M_KIB,
                                        VAULT_ARGON2_T,
                                        VAULT_ARGON2_P,
                                    );
                                    let api = match authed_api(&base, api_token) {
                                        Ok(api) => api,
                                        Err(err) => {
                                            vault_sync.set(SyncBadge::Failed);
                                            vault_status.set(format!("API unavailable: {err}"));
                                            return;
                                        }
                                    };
                                    match api.put_key_backup(&backup_id_for_async, body).await {
                                        Ok(_) => {
                                            let now = chrono::Utc::now().to_rfc3339();
                                            vault_backup_id.set(backup_id_for_async.clone());
                                            vault_uploaded_at.set(now.clone());
                                            vault_sync.set(SyncBadge::Synced);
                                            vault_status.set(format!(
                                                "Uploaded backup {backup_id_for_async} ({} bytes ciphertext)",
                                                ct.ciphertext.len()
                                            ));
                                            passphrase.set(String::new());
                                            confirm_pass.set(String::new());
                                            let mut next = snapshot_state();
                                            next.vault_backup_id = backup_id_for_async;
                                            next.vault_uploaded_at = now;
                                            save_state(&mut store, &actor_key_for_async, &next);
                                        }
                                        Err(err) => {
                                            vault_sync.set(SyncBadge::Failed);
                                            vault_status.set(format!("Upload failed: {err}"));
                                        }
                                    }
                                });
                            }
                        },
                        "Encrypt and upload"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "vault-rotate-passphrase",
                        disabled: vault_backup_id().is_empty(),
                        title: "Reuses the existing backup_id but re-derives a fresh KEK / nonce.",
                        onclick: move |_| {
                            vault_status.set("Enter a new passphrase above and click Encrypt and upload to rotate.".to_owned());
                        },
                        "Rotate passphrase"
                    }
                }
            }

            // Recovery key — fallback path
            div { class: "event", "data-testid": "recovery-key-section",
                div { class: "event-head",
                    span { "Recovery Key" }
                    span { "high-entropy string · keep offline" }
                }
                div { class: "muted",
                    "A fallback for when every device is lost and no guardian is reachable. Contrix never stores this on the server — only a SHA-256 fingerprint stays in local state for verification. Generate one and write it down or print it."
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Current Recovery Key" }
                        span { "data-testid": "recovery-key-current",
                            if !live_recovery_key().is_empty() {
                                "{live_recovery_key()}"
                            } else if !recovery_key_fp().is_empty() {
                                "·······-·······-·······-·······-·······-·······"
                            } else {
                                "not generated"
                            }
                        }
                        div { class: "muted",
                            if !live_recovery_key().is_empty() {
                                "Plaintext is only shown until you navigate away or generate a new one."
                            } else if !recovery_key_fp().is_empty() {
                                "Plaintext is no longer in memory. Regenerate to view a new value."
                            } else {
                                "Generate one to enable single-key fallback recovery"
                            }
                        }
                    }
                    div { class: "metric",
                        strong { "Last rotated" }
                        span { "data-testid": "recovery-key-rotated-at", "{fmt_relative(&recovery_key_rotated_at())}" }
                        div { class: "muted", "Recommended: rotate at least every 90 days" }
                    }
                    div { class: "metric",
                        strong { "Fingerprint" }
                        span { "data-testid": "recovery-key-fp",
                            if recovery_key_fp().is_empty() { "—" } else {
                                {
                                    let fp = recovery_key_fp();
                                    let suffix = fp.split(':').nth(1).unwrap_or("");
                                    if suffix.len() >= 12 {
                                        format!("sha256:{}…", &suffix[..12])
                                    } else {
                                        fp
                                    }
                                }
                            }
                        }
                        div { class: "muted", "SHA-256 of the Recovery Key (locally stored, never uploaded)" }
                    }
                }
                if !recovery_key_status().is_empty() {
                    div { class: "muted", "data-testid": "recovery-key-status", "{recovery_key_status}" }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "recovery-key-regenerate",
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |_| {
                                match generate_recovery_key() {
                                    Ok(key) => {
                                        let fp = fingerprint_recovery_key(&key);
                                        let now = chrono::Utc::now().to_rfc3339();
                                        live_recovery_key.set(key);
                                        recovery_key_fp.set(fp);
                                        recovery_key_rotated_at.set(now);
                                        recovery_key_status.set(
                                            "New Recovery Key generated. Copy it now — it is only displayed once.".to_owned()
                                        );
                                        let next = snapshot_state();
                                        save_state(&mut store, &actor_key, &next);
                                    }
                                    Err(err) => {
                                        recovery_key_status.set(format!("Generate failed: {err}"));
                                    }
                                }
                            }
                        },
                        if recovery_key_fp().is_empty() { "Generate" } else { "Regenerate" }
                    }
                    button {
                        class: "secondary",
                        "data-testid": "recovery-key-clear-live",
                        disabled: live_recovery_key().is_empty(),
                        title: "Drop the plaintext from memory. The fingerprint stays in local state.",
                        onclick: move |_| {
                            live_recovery_key.set(String::new());
                            recovery_key_status.set("Plaintext cleared from memory.".to_owned());
                        },
                        "Clear from screen"
                    }
                }
            }

            // Social recovery — devices-and-auth §4.2
            div { class: "event", "data-testid": "social-recovery-section",
                div { class: "event-head",
                    span { "Social Recovery · Shamir's Secret Sharing" }
                    span { "{threshold} of {total} threshold" }
                    HelpTip { text: "The recovery secret is split into N shares; any T of them can reconstruct it. Guardians can be individuals, organizations' IT, family members, or trusted HSMs. Rotating the polynomial invalidates every prior share." }
                }
                div { class: "workflow-form",
                    label { r#for: "sss-threshold", "Threshold (T)" }
                    input {
                        id: "sss-threshold",
                        "data-testid": "sss-threshold",
                        r#type: "number",
                        min: "2",
                        max: "10",
                        value: "{threshold}",
                        oninput: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |evt: Event<FormData>| {
                                if let Ok(v) = evt.value().parse::<u32>() {
                                    threshold.set(v.clamp(2, 10));
                                    save_state(&mut store, &actor_key, &snapshot_state());
                                }
                            }
                        },
                    }
                    label { r#for: "sss-total", "Total shares (N)" }
                    input {
                        id: "sss-total",
                        "data-testid": "sss-total",
                        r#type: "number",
                        min: "2",
                        max: "10",
                        value: "{total}",
                        oninput: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |evt: Event<FormData>| {
                                if let Ok(v) = evt.value().parse::<u32>() {
                                    total.set(v.clamp(2, 10));
                                    save_state(&mut store, &actor_key, &snapshot_state());
                                }
                            }
                        },
                    }
                }
                if guardians().is_empty() {
                    div { class: "muted", "data-testid": "no-guardians", "No guardians added yet. Add at least {threshold} to enable social recovery." }
                } else {
                    div { class: "metric-grid", "data-testid": "guardian-list",
                        for (idx , g) in guardians().iter().enumerate() {
                            div { class: "metric", "data-testid": "guardian-row",
                                strong { "{g.label}" }
                                span { class: "mono", "{g.did}" }
                                div { class: "muted",
                                    if g.note.is_empty() {
                                        if g.confirmed { "share confirmed" } else { "share pending" }
                                    } else {
                                        "{g.note}"
                                    }
                                }
                                div { class: "actions",
                                    button {
                                        class: "secondary",
                                        "data-testid": "guardian-toggle-confirm",
                                        onclick: {
                                            let actor_key = actor_key.clone();
                                            let mut store = state_store;
                                            move |_| {
                                                let mut next = guardians();
                                                if let Some(slot) = next.get_mut(idx) {
                                                    slot.confirmed = !slot.confirmed;
                                                }
                                                guardians.set(next);
                                                save_state(&mut store, &actor_key, &snapshot_state());
                                            }
                                        },
                                        if g.confirmed { "Mark pending" } else { "Mark confirmed" }
                                    }
                                    button {
                                        class: "secondary",
                                        "data-testid": "guardian-remove",
                                        onclick: {
                                            let actor_key = actor_key.clone();
                                            let mut store = state_store;
                                            move |_| {
                                                let mut next = guardians();
                                                if idx < next.len() {
                                                    next.remove(idx);
                                                }
                                                guardians.set(next);
                                                save_state(&mut store, &actor_key, &snapshot_state());
                                            }
                                        },
                                        "Remove"
                                    }
                                }
                            }
                        }
                    }
                }
                div { class: "workflow-form", "data-testid": "guardian-add-form",
                    label { r#for: "guardian-label", "Guardian label" }
                    input {
                        id: "guardian-label",
                        "data-testid": "guardian-label",
                        value: "{new_guardian_label}",
                        placeholder: "e.g. Mei / Backup HSM",
                        oninput: move |evt| new_guardian_label.set(evt.value()),
                    }
                    label { r#for: "guardian-did", "DID or handle" }
                    input {
                        id: "guardian-did",
                        "data-testid": "guardian-did",
                        value: "{new_guardian_did}",
                        placeholder: "did:web:..., did:plc:..., or @handle",
                        oninput: move |evt| new_guardian_did.set(evt.value()),
                    }
                    label { r#for: "guardian-note", "Note (optional)" }
                    input {
                        id: "guardian-note",
                        "data-testid": "guardian-note",
                        value: "{new_guardian_note}",
                        placeholder: "Person · Organization · Family · HSM",
                        oninput: move |evt| new_guardian_note.set(evt.value()),
                    }
                }
                if !social_status().is_empty() {
                    div { class: "muted", "data-testid": "social-status", "{social_status}" }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "social-add-guardian",
                        disabled: new_guardian_label().trim().is_empty() || new_guardian_did().trim().is_empty(),
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |_| {
                                let mut next = guardians();
                                next.push(Guardian {
                                    label: new_guardian_label().trim().to_owned(),
                                    did: new_guardian_did().trim().to_owned(),
                                    note: new_guardian_note().trim().to_owned(),
                                    confirmed: false,
                                });
                                let added_label = new_guardian_label();
                                guardians.set(next);
                                new_guardian_label.set(String::new());
                                new_guardian_did.set(String::new());
                                new_guardian_note.set(String::new());
                                save_state(&mut store, &actor_key, &snapshot_state());
                                social_status.set(format!("Added guardian \"{added_label}\". Share confirmation is tracked locally."));
                            }
                        },
                        "+ Add guardian"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "social-recover-now",
                        disabled: guardians().len() < threshold() as usize,
                        title: if (guardians().len() as u32) < threshold() {
                            "Add enough guardians to meet the threshold before rehearsing."
                        } else {
                            "Records a Last rehearsed timestamp; integrate with guardian outreach when wired to the server."
                        },
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |_| {
                                let now = chrono::Utc::now().to_rfc3339();
                                last_rehearsed.set(now);
                                save_state(&mut store, &actor_key, &snapshot_state());
                                social_status.set("Rehearsal logged. Outreach to guardians is a future server-side feature.".to_owned());
                            }
                        },
                        "Rehearse social recovery"
                    }
                }
            }

            // Recovery write path
            div { class: "event", "data-testid": "recovery-writeback-explainer",
                div { class: "event-head",
                    span { "What happens when recovery succeeds" }
                    span { "method-specific evidence" }
                }
                div { class: "muted",
                    "The new device generates its own key, the recovery is recorded against your account, your DID/key log is updated with method-specific evidence, the new device is re-authorized, and your encrypted Spaces roll their epoch to include it. Existing devices are notified."
                }
            }
        }
    }
}
