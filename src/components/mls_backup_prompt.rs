use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::recovery_crypto::{generate_recovery_key, normalize_recovery_key_input};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::with_authed_api;

const MLS_RECOVERY_BACKUP_STATE_KEY: &str = "mls.recovery_backup.v1";
const MLS_PRIVATE_PLAINTEXT_BACKUP_DEBOUNCE: Duration = Duration::from_millis(1500);
const MLS_PRIVATE_PLAINTEXT_BACKUP_MIN_INTERVAL: Duration = Duration::from_secs(300);
static MLS_BACKUP_AFTER_WRITE_PROBES: LazyLock<Mutex<BTreeSet<String>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));
static MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS: LazyLock<
    Mutex<BTreeMap<String, MlsPrivatePlaintextBackupJob>>,
> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

// Recovery tasks can finish after the prompt scope is gone; dropped signals panic on `set()`.
fn try_set_signal<T: 'static>(mut signal: Signal<T>, value: T) {
    if let Ok(mut slot) = signal.try_write() {
        *slot = value;
    }
}

fn try_set_status(mut status: Signal<String>, value: impl Into<String>) {
    if let Ok(mut slot) = status.try_write() {
        *slot = value.into();
    }
}

/// Copy the recovery words to the clipboard so the user never has to manually
/// select the textarea (a partial selection would silently drop words). Prefers
/// the async Clipboard API, falling back to `execCommand` on insecure contexts.
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

/// Download the recovery words as a plain-text file. Same goal as the copy
/// button — guarantee the user captures all 24 words rather than relying on a
/// hand-made selection — for users who would rather keep a file than the
/// clipboard. The object URL is revoked after the click so the blob is not
/// retained in memory.
fn download_text_as_file(filename: &str, text: &str) {
    let (Ok(encoded_text), Ok(encoded_name)) =
        (serde_json::to_string(text), serde_json::to_string(filename))
    else {
        return;
    };
    let script = format!(
        r#"(() => {{
    const text = {encoded_text};
    const name = {encoded_name};
    const blob = new Blob([text], {{ type: "text/plain;charset=utf-8" }});
    const url = URL.createObjectURL(blob);
    const node = document.createElement("a");
    node.href = url;
    node.download = name;
    document.body.appendChild(node);
    node.click();
    document.body.removeChild(node);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    return true;
}})()"#
    );
    let _ = document::eval(&script);
}

#[derive(Clone, Default)]
struct MlsPrivatePlaintextBackupJob {
    base_url: String,
    token: String,
    actor_did: String,
    device_id: String,
    latest_sidecar_json: Vec<u8>,
    latest_digest: String,
    last_uploaded_digest: Option<String>,
    last_upload_at: Option<chrono::DateTime<chrono::Utc>>,
    cached_previous_body: Option<serde_json::Value>,
    scheduled: bool,
    in_flight: bool,
}

fn mls_backup_after_write_probe_key(base_url: &str, actor_did: &str) -> String {
    format!(
        "{}|{}",
        base_url.trim().trim_end_matches('/'),
        actor_did.trim()
    )
}

fn mark_mls_backup_after_write_probe_started(key: String) -> bool {
    match MLS_BACKUP_AFTER_WRITE_PROBES.lock() {
        Ok(mut probes) => probes.insert(key),
        Err(_) => true,
    }
}

pub(crate) fn schedule_mls_private_plaintext_backup_after_encrypted_write(
    base_url: String,
    token: String,
    actor_did: String,
    device_id: String,
    state_store: Signal<LocalStateStore>,
) {
    if base_url.trim().is_empty()
        || token.trim().is_empty()
        || actor_did.trim().is_empty()
        || device_id.trim().is_empty()
    {
        return;
    }
    let sidecar_json = {
        let store = state_store.read();
        if !mls_recovery_backup_configured(&store, &actor_did) || store.private_plaintext_is_empty()
        {
            return;
        }
        store.private_plaintext_snapshot_json()
    };
    let digest = crate::canonical::sha256_digest(&sidecar_json);
    let key = mls_backup_after_write_probe_key(&base_url, &actor_did);
    let should_spawn = match MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS.lock() {
        Ok(mut jobs) => {
            let job = jobs.entry(key.clone()).or_default();
            if job.last_uploaded_digest.as_deref() == Some(digest.as_str()) {
                return;
            }
            job.base_url = base_url;
            job.token = token;
            job.actor_did = actor_did;
            job.device_id = device_id;
            job.latest_sidecar_json = sidecar_json;
            job.latest_digest = digest;
            if job.scheduled || job.in_flight {
                false
            } else {
                job.scheduled = true;
                true
            }
        }
        Err(_) => false,
    };
    if should_spawn {
        spawn(async move {
            run_mls_private_plaintext_backup_job(key).await;
        });
    }
}

async fn run_mls_private_plaintext_backup_job(key: String) {
    loop {
        let Some(delay) = next_mls_private_plaintext_backup_delay(&key) else {
            return;
        };
        crate::api::sleep_for(delay).await;
        let Some(job_snapshot) = take_mls_private_plaintext_backup_job_snapshot(&key) else {
            return;
        };
        if job_snapshot.last_uploaded_digest.as_deref() == Some(job_snapshot.latest_digest.as_str())
        {
            finish_mls_private_plaintext_backup_job(
                &key,
                &job_snapshot.latest_digest,
                None,
                None,
                None,
            );
            return;
        }
        let upload_digest = job_snapshot.latest_digest.clone();
        let upload_result = upload_mls_private_plaintext_backup_job_snapshot(job_snapshot).await;
        let rerun = match upload_result {
            Ok((backup_id, body)) => {
                tracing::debug!(
                    backup_id = %backup_id,
                    "MLS private plaintext sidecar backup uploaded after encrypted write"
                );
                finish_mls_private_plaintext_backup_job(
                    &key,
                    &upload_digest,
                    Some(body),
                    Some(upload_digest.clone()),
                    Some(chrono::Utc::now()),
                )
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "MLS private plaintext sidecar backup after encrypted write failed"
                );
                finish_mls_private_plaintext_backup_job(&key, &upload_digest, None, None, None)
            }
        };
        if !rerun {
            return;
        }
    }
}

fn next_mls_private_plaintext_backup_delay(key: &str) -> Option<Duration> {
    let jobs = MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS.lock().ok()?;
    let job = jobs.get(key)?;
    let Some(last_upload_at) = job.last_upload_at else {
        return Some(MLS_PRIVATE_PLAINTEXT_BACKUP_DEBOUNCE);
    };
    let elapsed = chrono::Utc::now().signed_duration_since(last_upload_at);
    let min_interval = chrono::Duration::from_std(MLS_PRIVATE_PLAINTEXT_BACKUP_MIN_INTERVAL)
        .unwrap_or_else(|_| chrono::Duration::seconds(300));
    if elapsed >= min_interval {
        Some(MLS_PRIVATE_PLAINTEXT_BACKUP_DEBOUNCE)
    } else {
        let remaining = min_interval - elapsed;
        Some(Duration::from_millis(
            u64::try_from(remaining.num_milliseconds()).unwrap_or(0),
        ))
    }
}

fn take_mls_private_plaintext_backup_job_snapshot(
    key: &str,
) -> Option<MlsPrivatePlaintextBackupJob> {
    let mut jobs = MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS.lock().ok()?;
    let job = jobs.get_mut(key)?;
    job.scheduled = false;
    job.in_flight = true;
    Some(job.clone())
}

fn finish_mls_private_plaintext_backup_job(
    key: &str,
    uploaded_digest: &str,
    cached_previous_body: Option<serde_json::Value>,
    last_uploaded_digest: Option<String>,
    last_upload_at: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    let Ok(mut jobs) = MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS.lock() else {
        return false;
    };
    let Some(job) = jobs.get_mut(key) else {
        return false;
    };
    job.in_flight = false;
    if let Some(body) = cached_previous_body {
        job.cached_previous_body = Some(body);
    }
    if let Some(digest) = last_uploaded_digest {
        job.last_uploaded_digest = Some(digest);
    }
    if let Some(uploaded_at) = last_upload_at {
        job.last_upload_at = Some(uploaded_at);
    }
    if job.latest_digest != uploaded_digest
        && job.last_uploaded_digest.as_deref() != Some(job.latest_digest.as_str())
    {
        job.scheduled = true;
        true
    } else {
        false
    }
}

async fn upload_mls_private_plaintext_backup_job_snapshot(
    job: MlsPrivatePlaintextBackupJob,
) -> anyhow::Result<(String, serde_json::Value)> {
    with_authed_api(&job.base_url, job.token, |api| async move {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        let previous_body = match job.cached_previous_body {
            Some(body) => Some(body),
            None => {
                crate::mls::account_recovery::fetch_mls_private_plaintext_backup_body(
                    &api,
                    &job.actor_did,
                    &job.device_id,
                )
                .await?
            }
        };
        crate::mls::account_recovery::upload_mls_private_plaintext_backup_with_previous(
            &api,
            secure_store.as_ref(),
            &job.actor_did,
            &job.device_id,
            &job.latest_sidecar_json,
            previous_body.as_ref(),
        )
        .await
    })
    .await
    .map_err(|err| anyhow::anyhow!(err.display()))
}

pub(crate) fn mls_recovery_backup_configured(
    state_store: &LocalStateStore,
    actor_did: &str,
) -> bool {
    if actor_did.trim().is_empty() {
        return false;
    }
    state_store
        .load_private_data(actor_did, MLS_RECOVERY_BACKUP_STATE_KEY)
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| {
            value
                .get("backup_id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .map(str::to_owned)
        })
        .is_some_and(|backup_id| !backup_id.is_empty())
}

pub(crate) fn mark_mls_recovery_backup_configured(
    state_store: &mut LocalStateStore,
    actor_did: &str,
    backup_id: &str,
) {
    if actor_did.trim().is_empty() || backup_id.trim().is_empty() {
        return;
    }
    let payload = serde_json::json!({
        "schema_version": 1,
        "backup_id": backup_id,
        "configured_at": chrono::Utc::now().to_rfc3339(),
    });
    state_store.save_private_data(
        actor_did,
        MLS_RECOVERY_BACKUP_STATE_KEY,
        payload.to_string(),
    );
}

/// X11.2 — context-provided handle to the app-root `needs_mls_backup`
/// `Signal<bool>` so deep encrypted-write success paths (kanban card detail
/// update, chat secure send) can flip the backup prompt on directly, WITHOUT
/// relying on the fragile boot-time detection effect (whose `detection_key`
/// rarely flips). Provided once at the app root; consumed via
/// [`try_needs_mls_backup_signal`] from free functions / event handlers that
/// run inside a Dioxus scope.
///
/// Newtype-wrapped so the context lookup can't collide with any other bare
/// `Signal<bool>` a future view might provide.
#[derive(Clone, Copy)]
pub struct MlsBackupSignal(pub Signal<bool>);

/// Best-effort: read the context-provided `needs_mls_backup` signal. Returns
/// `None` when no provider is mounted (e.g. unit tests) so callers can stay
/// non-fatal.
pub fn try_needs_mls_backup_signal() -> Option<Signal<bool>> {
    try_consume_context::<MlsBackupSignal>().map(|wrap| wrap.0)
}

/// X11.2 — shared first-write trigger. After a successful ENCRYPTED write,
/// the caller spawns this: if the server holds NO `mls_account_secret`
/// backup yet AND a local account secret exists, flip `needs_mls_backup` on
/// so [`MlsBackupPrompt`] surfaces promptly. Best-effort and self-contained:
/// swallows every error and never blocks the write path. The server probe is
/// intentionally session-deduped per `(base_url, actor_did)`: the prompt only
/// needs a first-write kick, not a backup-list request after every message.
pub async fn maybe_flag_mls_backup_after_encrypted_write(
    base_url: String,
    token: String,
    actor_did: String,
    needs_mls_backup: Signal<bool>,
) {
    if base_url.trim().is_empty() || token.trim().is_empty() || actor_did.trim().is_empty() {
        return;
    }
    if needs_mls_backup() {
        return;
    }
    // Local account secret must exist (encryption has been used) — otherwise
    // there's nothing to back up yet.
    let has_local_secret = {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &actor_did)
            .map(|secret| secret.is_some())
            .unwrap_or(false)
    };
    if !has_local_secret {
        return;
    }
    let probe_key = mls_backup_after_write_probe_key(&base_url, &actor_did);
    if !mark_mls_backup_after_write_probe_started(probe_key) {
        return;
    }
    // Surface the prompt as soon as the local account secret exists. The
    // server probe below will close it again if a recovery-key backup is
    // already present. This avoids a silent window after creating an encrypted
    // Realm where the app has recoverable material locally but the async
    // backup-list check has not completed yet.
    try_set_signal(needs_mls_backup, true);
    // Server must NOT already hold an `mls_account_secret` backup. (When it
    // does, the restore/unlock path owns the flow — backup and restore are
    // mutually exclusive by this exact check, so we can't double-prompt.)
    let payload = match with_authed_api(&base_url, token, |api| async move {
        crate::mls::account_recovery::fetch_mls_restore_payload(&api).await
    })
    .await
    {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                error = %err.display(),
                "MLS backup detection could not list key backups after encrypted write"
            );
            try_set_signal(needs_mls_backup, true);
            return;
        }
    };
    if crate::mls::account_recovery::select_mls_account_secret_backup(&payload).is_some() {
        try_set_signal(needs_mls_backup, false);
        return;
    }
    try_set_signal(needs_mls_backup, true);
}

/// One-time account-MLS-secret BACKUP prompt — the mirror of
/// [`crate::components::MlsUnlockPrompt`].
///
/// Mounted once near the app shell and rendered ONLY when `needs_mls_backup`
/// is `true` — which the boot/per-Realm detection in `App` sets when this
/// account has a LOCAL account MLS secret (encryption has been used) but the
/// server holds NO `mls_account_secret` backup yet. The client generates a
/// high-entropy recovery key and we call
/// [`crate::mls::account_recovery::upload_mls_account_secret_backup_with_passphrase`]
/// to wrap + upload the account secret so a future fresh browser can recover
/// encrypted history. The wire recipient method remains spec-conformant
/// `secret_storage` + `passphrase_kdf`; the user-facing flow does not ask the
/// user to invent or confirm a passphrase.
#[component]
pub fn MlsBackupPrompt(
    base_url: Signal<String>,
    token: Signal<String>,
    actor_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    needs_mls_backup: Signal<bool>,
) -> Element {
    let mut generated_recovery_key = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut copied = use_signal(|| false);

    if !needs_mls_backup() {
        return rsx! {};
    }

    let can_submit = !busy()
        && generated_recovery_key().trim().is_empty()
        && !base_url().trim().is_empty()
        && !token().trim().is_empty()
        && !actor_did().trim().is_empty();

    let on_backup = move |_| {
        if busy() {
            return;
        }
        let recovery_key = match generate_recovery_key() {
            Ok(key) => key,
            Err(err) => {
                status.set(format!(
                    "{} {err}",
                    crate::i18n::tr("mls_backup.status.generate_failed")
                ));
                return;
            }
        };
        let recovery_secret = normalize_recovery_key_input(&recovery_key)
            .expect("generated recovery key is valid BIP-39");
        let base = base_url();
        let session = token();
        let actor = actor_did();
        let device = device_id();
        let mut state_store_for_marker = state_store;
        // X5.3 — snapshot the local-plaintext sidecar so we can also back it up
        // cross-device after the account secret upload succeeds. Read it here
        // (synchronously, before the spawn) so we don't borrow the store across
        // the network awaits.
        let sidecar_json = if state_store.read().private_plaintext_is_empty() {
            None
        } else {
            Some(state_store.read().private_plaintext_snapshot_json())
        };
        busy.set(true);
        status.set(crate::i18n::tr("mls_backup.status.uploading"));
        spawn(async move {
            let recovery_key_for_display = recovery_key.clone();
            let actor_for_sidecar = actor.clone();
            let device_for_sidecar = device.clone();
            let base_for_sidecar = base.clone();
            let session_for_sidecar = session.clone();
            let result = with_authed_api(&base, session, |api| async move {
                let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
                crate::mls::account_recovery::upload_mls_account_secret_backup_with_passphrase(
                    &api,
                    secure_store.as_ref(),
                    &actor,
                    &device,
                    recovery_secret.as_bytes(),
                )
                .await
            })
            .await;
            try_set_signal(busy, false);
            match result {
                Ok(backup_id) => {
                    if let Ok(mut store) = state_store_for_marker.try_write() {
                        mark_mls_recovery_backup_configured(
                            &mut store,
                            &actor_for_sidecar,
                            &backup_id,
                        );
                    }
                    // X5.3 — best-effort: also back up the encrypted sidecar so a
                    // fresh browser recovers the author's own content. Failure
                    // only logs (the account secret backup already succeeded).
                    if let Some(sidecar_json) = sidecar_json {
                        let actor = actor_for_sidecar;
                        let device = device_for_sidecar;
                        let outcome = with_authed_api(
                            &base_for_sidecar,
                            session_for_sidecar,
                            |api| async move {
                                let secure_store =
                                    crate::secure_key_store::default_secure_key_store("yougen");
                                crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                                    &api,
                                    secure_store.as_ref(),
                                    &actor,
                                    &device,
                                    &sidecar_json,
                                )
                                .await
                            },
                        )
                        .await;
                        // Best-effort: the account secret backup already
                        // succeeded, so a sidecar failure must not block the
                        // success path. Swallow it (the next encrypted write or
                        // the kanban write-path trigger will retry the upload).
                        let _ = outcome;
                    }
                    try_set_signal(generated_recovery_key, recovery_key_for_display);
                    try_set_status(status, crate::i18n::tr("mls_backup.status.created"));
                }
                Err(err) => {
                    // Keep the prompt open so the user can retry.
                    try_set_status(status, err.display());
                }
            }
        });
    };

    let generated_now = generated_recovery_key();

    rsx! {
        Dialog {
            open: true,
            on_open_change: move |open: bool| {
                if !open {
                    needs_mls_backup.set(false);
                }
            },
            "data-testid": "mls-backup-modal",
            "aria-labelledby": "mls-backup-title",
            "aria-label": crate::i18n::tr("mls_backup.aria_label"),
            div {
                class: "modal event mls-recovery-modal mls-backup-banner",
                "data-testid": "mls-backup-banner",
                div { class: "modal-head event-head",
                    h3 { id: "mls-backup-title", {crate::i18n::tr("mls_backup.title")} }
                    span { class: "muted", {crate::i18n::tr("mls_backup.subtitle")} }
                }
                div { class: "modal-body mls-recovery-modal-body",
                    div { class: "muted",
                        {crate::i18n::tr("mls_backup.description")}
                    }
                    div { class: "muted", "data-testid": "mls-backup-passphrase-loss-warning",
                        strong { {crate::i18n::tr("mls_backup.warning.passphrase_loss")} }
                    }
                    if !generated_now.trim().is_empty() {
                        div { class: "workflow-form",
                            Label { html_for: "mls-backup-generated-key",
                                {crate::i18n::tr("mls_backup.generated_key_label")}
                            }
                            Textarea {
                                id: "mls-backup-generated-key",
                                "data-testid": "mls-backup-generated-key",
                                rows: "3",
                                readonly: true,
                                value: "{generated_now}",
                            }
                            div { class: "mls-backup-key-actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "mls-backup-copy-key",
                                    onclick: {
                                        let key = generated_now.clone();
                                        move |_| {
                                            copy_text_to_clipboard(&key);
                                            copied.set(true);
                                        }
                                    },
                                    if copied() {
                                        {crate::i18n::tr("mls_backup.copy_key_done")}
                                    } else {
                                        {crate::i18n::tr("mls_backup.copy_key")}
                                    }
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "mls-backup-download-key",
                                    onclick: {
                                        let key = generated_now.clone();
                                        move |_| {
                                            download_text_as_file("cokret-recovery-key.txt", &key);
                                        }
                                    },
                                    {crate::i18n::tr("mls_backup.download_key")}
                                }
                            }
                            div { class: "form-hint-warn", "data-testid": "mls-backup-generated-key-warning",
                                {crate::i18n::tr("mls_backup.generated_key_warning")}
                            }
                        }
                    }
                    if !status().is_empty() {
                        div { class: "muted", "data-testid": "mls-backup-status", "{status}" }
                    }
                }
                div { class: "modal-foot mls-backup-row",
                    if generated_now.trim().is_empty() {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "mls-backup-submit",
                            disabled: !can_submit,
                            onclick: on_backup,
                            if busy() {
                                {crate::i18n::tr("mls_backup.button_busy")}
                            } else {
                                {crate::i18n::tr("mls_backup.button_idle")}
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "mls-backup-dismiss",
                            disabled: busy(),
                            onclick: move |_| needs_mls_backup.set(false),
                            {crate::i18n::tr("mls_backup.button_dismiss")}
                        }
                    } else {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "mls-backup-saved",
                            onclick: move |_| {
                                generated_recovery_key.set(String::new());
                                needs_mls_backup.set(false);
                            },
                            {crate::i18n::tr("mls_backup.button_saved")}
                        }
                    }
                }
            }
        }
    }
}
