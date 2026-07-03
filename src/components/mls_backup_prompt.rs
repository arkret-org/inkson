use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::recovery_crypto::{
    generate_recovery_key, normalize_recovery_key_input, recovery_key_confirmation_matches,
};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::with_authed_api;
// Shared JS-interop helper (single source, YGN-DRY-04).
pub(crate) use yoface::utils::dom::copy_text_to_clipboard;

const MLS_RECOVERY_BACKUP_STATE_KEY: &str = "mls.recovery_backup.v1";
const MLS_PRIVATE_PLAINTEXT_BACKUP_DEBOUNCE: Duration = Duration::from_millis(1500);
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

/// Download the recovery words as a plain-text file. Same goal as the copy
/// button — guarantee the user captures all 24 words rather than relying on a
/// hand-made selection — for users who would rather keep a file than the
/// clipboard. The object URL is revoked after the click so the blob is not
/// retained in memory.
pub(crate) fn download_text_as_file(filename: &str, text: &str) {
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

/// Pull the human-readable localpart out of the account's primary personal
/// handle (`<localpart>:<domain>(:<port>)?`) for use in the recovery-key
/// download filename. Returns an empty string when no handle is known yet.
pub(crate) fn recovery_localpart_from_handles(handles: &[String]) -> String {
    handles
        .iter()
        .find_map(|handle| {
            crate::identity_handle::parse_user_handle(handle).map(|parsed| parsed.localpart)
        })
        .unwrap_or_default()
}

/// Build a per-account download filename for the recovery-key `.txt`, so that
/// multiple accounts (or repeated generations for one account) don't all land
/// as `cokret-recovery-key.txt` / `…(1).txt` in the Downloads folder, where the
/// 24 words become impossible to tell apart.
///
/// `localpart` is the human handle localpart (see
/// [`recovery_localpart_from_handles`]); it is sanitised to a filesystem-safe
/// stem (`:` from the wire handle is illegal on Windows, so the caller never
/// passes the full `<localpart>:<domain>` form). Falls back to the bare name
/// when the localpart is empty.
pub(crate) fn recovery_key_filename(localpart: &str) -> String {
    let sanitized: String = localpart
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect();
    // Strip leading/trailing separators so we never emit a dotfile
    // (`.foo.txt`) or a dangling dash.
    let sanitized = sanitized.trim_matches(|ch| ch == '-' || ch == '.');
    if sanitized.is_empty() {
        "cokret-recovery-key.txt".to_owned()
    } else {
        format!("cokret-recovery-key-{sanitized}.txt")
    }
}

pub(crate) fn recovery_key_filename_from_handles(handles: &[String]) -> String {
    let localpart = recovery_localpart_from_handles(handles);
    recovery_key_filename(&localpart)
}

#[derive(Clone, Default)]
struct MlsPrivatePlaintextBackupJob {
    base_url: String,
    token: String,
    actor_id: String,
    device_id: String,
    latest_sidecar_json: Vec<u8>,
    latest_digest: String,
    last_uploaded_digest: Option<String>,
    cached_previous_body: Option<serde_json::Value>,
    scheduled: bool,
    in_flight: bool,
}

fn mls_backup_after_write_probe_key(base_url: &str, actor_id: &str) -> String {
    format!(
        "{}|{}",
        base_url.trim().trim_end_matches('/'),
        actor_id.trim()
    )
}

fn mark_mls_backup_after_write_probe_started(key: String) -> bool {
    match MLS_BACKUP_AFTER_WRITE_PROBES.lock() {
        Ok(mut probes) => probes.insert(key),
        Err(_) => {
            // COR-02: a poisoned lock means a prior holder panicked. Surface it
            // (it would otherwise be invisible) and treat the probe as already
            // started so we don't re-spawn against corrupt shared state.
            tracing::warn!(
                "MLS backup after-write probe set lock poisoned; skipping probe (treat as started)"
            );
            true
        }
    }
}

pub(crate) fn schedule_mls_private_plaintext_backup_after_encrypted_write(
    base_url: String,
    token: String,
    actor_id: String,
    device_id: String,
    state_store: Signal<LocalStateStore>,
) {
    if base_url.trim().is_empty()
        || token.trim().is_empty()
        || actor_id.trim().is_empty()
        || device_id.trim().is_empty()
    {
        return;
    }
    let sidecar_json = {
        let store = state_store.read();
        if !mls_recovery_backup_configured(&store, &actor_id) || store.private_plaintext_is_empty()
        {
            return;
        }
        store.private_plaintext_snapshot_json()
    };
    let digest = crate::canonical::sha256_digest(&sidecar_json);
    let key = mls_backup_after_write_probe_key(&base_url, &actor_id);
    let should_spawn = match MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS.lock() {
        Ok(mut jobs) => {
            let job = jobs.entry(key.clone()).or_default();
            if job.last_uploaded_digest.as_deref() == Some(digest.as_str()) {
                return;
            }
            job.base_url = base_url;
            job.token = token;
            job.actor_id = actor_id;
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
        Err(_) => {
            // COR-02: poisoned job map → a prior task panicked. Log it so the
            // dropped backup task is observable rather than silently lost.
            tracing::warn!(
                "MLS private plaintext backup job map lock poisoned; backup not scheduled this round"
            );
            false
        }
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
            finish_mls_private_plaintext_backup_job(&key, &job_snapshot.latest_digest, None, None);
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
                )
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "MLS private plaintext sidecar backup after encrypted write failed"
                );
                finish_mls_private_plaintext_backup_job(&key, &upload_digest, None, None)
            }
        };
        if !rerun {
            return;
        }
    }
}

fn next_mls_private_plaintext_backup_delay(key: &str) -> Option<Duration> {
    let jobs = mls_private_plaintext_backup_jobs_lock_or_warn()?;
    jobs.get(key)?;
    Some(MLS_PRIVATE_PLAINTEXT_BACKUP_DEBOUNCE)
}

/// COR-02: acquire the backup-job map lock, logging a `warn!` (instead of
/// silently returning `None`) when the lock is poisoned so a panicked prior
/// holder — and the consequently dropped backup task — is observable.
fn mls_private_plaintext_backup_jobs_lock_or_warn()
-> Option<std::sync::MutexGuard<'static, BTreeMap<String, MlsPrivatePlaintextBackupJob>>> {
    match MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS.lock() {
        Ok(guard) => Some(guard),
        Err(_) => {
            tracing::warn!(
                "MLS private plaintext backup job map lock poisoned; dropping this backup step"
            );
            None
        }
    }
}

fn take_mls_private_plaintext_backup_job_snapshot(
    key: &str,
) -> Option<MlsPrivatePlaintextBackupJob> {
    let mut jobs = mls_private_plaintext_backup_jobs_lock_or_warn()?;
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
) -> bool {
    let Some(mut jobs) = mls_private_plaintext_backup_jobs_lock_or_warn() else {
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
                    &job.actor_id,
                    &job.device_id,
                )
                .await?
            }
        };
        crate::mls::account_recovery::upload_mls_private_plaintext_backup_with_previous(
            &api,
            secure_store.as_ref(),
            &job.actor_id,
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
    actor_id: &str,
) -> bool {
    if actor_id.trim().is_empty() {
        return false;
    }
    state_store
        .load_private_data(actor_id, MLS_RECOVERY_BACKUP_STATE_KEY)
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
    actor_id: &str,
    backup_id: &str,
) {
    if actor_id.trim().is_empty() || backup_id.trim().is_empty() {
        return;
    }
    let payload = serde_json::json!({
        "schema_version": 1,
        "backup_id": backup_id,
        "configured_at": chrono::Utc::now().to_rfc3339(),
    });
    state_store.save_private_data(actor_id, MLS_RECOVERY_BACKUP_STATE_KEY, payload.to_string());
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
/// so [`MlsBackupPrompt`] surfaces promptly. Call
/// [`maybe_auto_backup_mls_after_encrypted_write`] when a `LocalStateStore` is
/// available so the public-key auto-backup path can run first. Best-effort and
/// self-contained: swallows every error and never blocks the write path. The
/// server probe is intentionally session-deduped per `(base_url, actor_id)`:
/// the prompt only needs a first-write kick, not a backup-list request after
/// every message.
pub async fn maybe_flag_mls_backup_after_encrypted_write(
    base_url: String,
    token: String,
    actor_id: String,
    needs_mls_backup: Signal<bool>,
) {
    maybe_backup_or_flag_mls_backup_after_encrypted_write(
        base_url,
        token,
        actor_id,
        None,
        needs_mls_backup,
    )
    .await;
}

/// First-write trigger with the no-prompt path enabled. Once the user has
/// confirmed a Recovery Key, the cached recovery public key can seal future
/// account-secret backups without asking for the 24 words again.
pub async fn maybe_auto_backup_mls_after_encrypted_write(
    base_url: String,
    token: String,
    actor_id: String,
    device_id: String,
    state_store: Signal<LocalStateStore>,
    needs_mls_backup: Signal<bool>,
) {
    maybe_backup_or_flag_mls_backup_after_encrypted_write(
        base_url,
        token,
        actor_id,
        Some((device_id, state_store)),
        needs_mls_backup,
    )
    .await;
}

async fn maybe_backup_or_flag_mls_backup_after_encrypted_write(
    base_url: String,
    token: String,
    actor_id: String,
    auto_backup: Option<(String, Signal<LocalStateStore>)>,
    needs_mls_backup: Signal<bool>,
) {
    if base_url.trim().is_empty() || token.trim().is_empty() || actor_id.trim().is_empty() {
        return;
    }
    if needs_mls_backup() {
        return;
    }
    // Local account secret must exist (encryption has been used) — otherwise
    // there's nothing to back up yet.
    let has_local_secret = {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &actor_id)
            .map(|secret| secret.is_some())
            .unwrap_or(false)
    };
    if !has_local_secret {
        return;
    }
    let probe_key = mls_backup_after_write_probe_key(&base_url, &actor_id);
    if !mark_mls_backup_after_write_probe_started(probe_key) {
        return;
    }
    // If this browser already confirmed a Recovery Key, use the cached public
    // key to seal the first account-secret backup without asking for the words
    // again. Missing public key falls through to the explicit prompt below.
    let auto_backup_inputs = auto_backup.as_ref().and_then(|(device_id, state_store)| {
        let store = state_store.read();
        let recovery_public_key =
            crate::views::recovery::local_recovery_public_key(&store, &actor_id)?;
        let sidecar_json = if store.private_plaintext_is_empty() {
            None
        } else {
            Some(store.private_plaintext_snapshot_json())
        };
        Some((
            *state_store,
            device_id.clone(),
            recovery_public_key,
            sidecar_json,
        ))
    });
    // Server must NOT already hold an `mls_account_secret` backup. (When it
    // does, the restore/unlock path owns the strand — backup and restore are
    // mutually exclusive by this exact check, so we can't double-prompt.)
    let payload = match with_authed_api(&base_url, token.clone(), |api| async move {
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
    if let Some(existing_backup) =
        crate::mls::account_recovery::select_preferred_mls_account_secret_backup(&payload)
    {
        if let Some((state_store, ..)) = auto_backup_inputs.as_ref()
            && let Some(backup_id) = existing_backup
                .get("backup_id")
                .and_then(serde_json::Value::as_str)
        {
            let mut state_store = *state_store;
            if let Ok(mut store) = state_store.try_write() {
                mark_mls_recovery_backup_configured(&mut store, &actor_id, backup_id);
            }
        }
        try_set_signal(needs_mls_backup, false);
        return;
    }
    if let Some((mut state_store, device_id, recovery_public_key, sidecar_json)) =
        auto_backup_inputs
    {
        let actor_for_upload = actor_id.clone();
        let device_for_upload = device_id.clone();
        let upload_result = with_authed_api(&base_url, token.clone(), |api| async move {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_public_key(
                &api,
                secure_store.as_ref(),
                &actor_for_upload,
                &device_for_upload,
                &recovery_public_key,
            )
            .await
        })
        .await;
        match upload_result {
            Ok(backup_id) => {
                if let Ok(mut store) = state_store.try_write() {
                    mark_mls_recovery_backup_configured(&mut store, &actor_id, &backup_id);
                }
                if let Some(sidecar_json) = sidecar_json {
                    let actor = actor_id.clone();
                    let device = device_id;
                    let _ = with_authed_api(&base_url, token, |api| async move {
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
                    })
                    .await;
                }
                try_set_signal(needs_mls_backup, false);
                return;
            }
            Err(err) => {
                tracing::warn!(
                    error = %err.display(),
                    "automatic MLS account-secret backup with recovery public key failed"
                );
            }
        }
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
/// [`crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key`]
/// to wrap + upload the account secret so a future fresh browser can recover
/// encrypted history. The wire recipient method remains spec-conformant
/// `secret_storage` + `recovery_public_key`; the user-facing strand does not ask
/// the user to invent or confirm a separate passphrase.
#[allow(clippy::too_many_arguments)]
fn upload_mls_backup_with_recovery_key(
    base: String,
    session: String,
    actor: String,
    device: String,
    recovery_secret: String,
    sidecar_json: Option<Vec<u8>>,
    state_store: Signal<LocalStateStore>,
    needs_mls_backup: Signal<bool>,
    recovery_key_input: Signal<String>,
    mut status: Signal<String>,
    mut busy: Signal<bool>,
    mut backup_created: Signal<bool>,
    generated_in_this_strand: bool,
) {
    let mut state_store_for_marker = state_store;
    busy.set(true);
    backup_created.set(false);
    status.set(crate::i18n::tr("mls_backup.status.uploading"));
    spawn(async move {
        let actor_for_sidecar = actor.clone();
        let device_for_sidecar = device.clone();
        let base_for_sidecar = base.clone();
        let session_for_sidecar = session.clone();
        let result = with_authed_api(&base, session, |api| async move {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(
                &api,
                secure_store.as_ref(),
                &actor,
                &device,
                &recovery_secret,
            )
            .await
        })
        .await;
        try_set_signal(busy, false);
        match result {
            Ok(backup_id) => {
                if let Ok(mut store) = state_store_for_marker.try_write() {
                    mark_mls_recovery_backup_configured(&mut store, &actor_for_sidecar, &backup_id);
                }
                if let Some(sidecar_json) = sidecar_json {
                    let actor = actor_for_sidecar;
                    let device = device_for_sidecar;
                    let outcome =
                        with_authed_api(&base_for_sidecar, session_for_sidecar, |api| async move {
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
                        })
                        .await;
                    let _ = outcome;
                }
                try_set_signal(backup_created, true);
                try_set_status(status, crate::i18n::tr("mls_backup.status.created"));
                if !generated_in_this_strand {
                    try_set_signal(recovery_key_input, String::new());
                    crate::api::sleep_for(std::time::Duration::from_millis(750)).await;
                    try_set_signal(needs_mls_backup, false);
                }
            }
            Err(err) => {
                try_set_status(status, err.display());
            }
        }
    });
}

#[component]
pub fn MlsBackupPrompt(
    base_url: Signal<String>,
    token: Signal<String>,
    actor_id: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    needs_mls_backup: Signal<bool>,
    /// Server truth for account-level recovery. `Some(true)` means the account
    /// already has a Recovery Key root, even if this browser has no local
    /// fingerprint cached.
    account_recovery_configured: Signal<Option<bool>>,
    /// Primary account handle claim, used only to name the recovery-key download file readably.
    account_primary_handle: Signal<String>,
) -> Element {
    let mut generated_recovery_key = use_signal(String::new);
    let mut generated_recovery_key_confirm = use_signal(String::new);
    let mut recovery_key_input = use_signal(String::new);
    let mut status = use_signal(String::new);
    let busy = use_signal(|| false);
    let mut copied = use_signal(|| false);
    let backup_created = use_signal(|| false);

    {
        let mut generated_recovery_key = generated_recovery_key;
        let mut generated_recovery_key_confirm = generated_recovery_key_confirm;
        let mut recovery_key_input = recovery_key_input;
        let mut status = status;
        let mut busy = busy;
        let mut copied = copied;
        let mut backup_created = backup_created;
        use_effect(move || {
            if needs_mls_backup() {
                return;
            }
            generated_recovery_key.set(String::new());
            generated_recovery_key_confirm.set(String::new());
            recovery_key_input.set(String::new());
            status.set(String::new());
            busy.set(false);
            copied.set(false);
            backup_created.set(false);
        });
    }

    if !needs_mls_backup() {
        return rsx! {};
    }

    let actor_for_state = actor_id();
    let local_recovery_key_configured = crate::views::recovery::local_recovery_key_fingerprint(
        &state_store.read(),
        &actor_for_state,
    )
    .is_some();
    let recovery_key_configured =
        local_recovery_key_configured || matches!(account_recovery_configured(), Some(true));
    let generated_now = generated_recovery_key();
    let generated_confirm_now = generated_recovery_key_confirm();
    let recovery_key_input_value = recovery_key_input();
    let has_recovery_key_for_submit = if recovery_key_configured {
        !recovery_key_input().trim().is_empty() || !generated_now.trim().is_empty()
    } else {
        true
    };
    let can_submit = !busy()
        && !backup_created()
        && has_recovery_key_for_submit
        && !base_url().trim().is_empty()
        && !token().trim().is_empty()
        && !actor_id().trim().is_empty();

    let on_backup = move |_| {
        if busy() {
            return;
        }
        let base = base_url();
        let session = token();
        let actor = actor_id();
        let device = device_id();
        let local_recovery_key_configured =
            crate::views::recovery::local_recovery_key_fingerprint(&state_store.read(), &actor)
                .is_some();
        let recovery_key_configured =
            local_recovery_key_configured || matches!(account_recovery_configured(), Some(true));
        let generated = generated_recovery_key();
        let generated_in_this_strand = !generated.trim().is_empty() || !recovery_key_configured;
        let recovery_key = if recovery_key_configured {
            if generated.trim().is_empty() {
                recovery_key_input()
            } else {
                generated
            }
        } else {
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
            let mut state_store_for_recovery_key = state_store;
            if crate::views::recovery::save_generated_recovery_key_metadata(
                &mut state_store_for_recovery_key,
                &actor,
                &recovery_key,
            )
            .is_none()
            {
                status.set(
                    "Recovery Key generated, but local metadata could not be saved.".to_owned(),
                );
                return;
            }
            copied.set(false);
            generated_recovery_key.set(recovery_key.clone());
            generated_recovery_key_confirm.set(String::new());
            recovery_key
        };
        let Some(recovery_secret) = normalize_recovery_key_input(&recovery_key) else {
            status.set(crate::i18n::tr("mls_backup.status.invalid_recovery_key"));
            return;
        };
        // X5.3 — snapshot the local-plaintext sidecar so we can also back it up
        // cross-device after the account secret upload succeeds. Read it here
        // (synchronously, before the spawn) so we don't borrow the store across
        // the network awaits.
        let sidecar_json = if state_store.read().private_plaintext_is_empty() {
            None
        } else {
            Some(state_store.read().private_plaintext_snapshot_json())
        };
        upload_mls_backup_with_recovery_key(
            base,
            session,
            actor,
            device,
            recovery_secret,
            sidecar_json,
            state_store,
            needs_mls_backup,
            recovery_key_input,
            status,
            busy,
            backup_created,
            generated_in_this_strand,
        );
    };

    let on_regenerate = move |_| {
        if busy() {
            return;
        }
        let base = base_url();
        let session = token();
        let actor = actor_id();
        let device = device_id();
        if base.trim().is_empty() || session.trim().is_empty() || actor.trim().is_empty() {
            status.set(crate::i18n::tr("mls_backup.status.invalid_recovery_key"));
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
        let mut state_store_for_recovery_key = state_store;
        if crate::views::recovery::save_generated_recovery_key_metadata(
            &mut state_store_for_recovery_key,
            &actor,
            &recovery_key,
        )
        .is_none()
        {
            status.set("Recovery Key generated, but local metadata could not be saved.".to_owned());
            return;
        }
        let Some(recovery_secret) = normalize_recovery_key_input(&recovery_key) else {
            status.set(crate::i18n::tr("mls_backup.status.invalid_recovery_key"));
            return;
        };
        copied.set(false);
        generated_recovery_key_confirm.set(String::new());
        generated_recovery_key.set(recovery_key);
        let sidecar_json = if state_store.read().private_plaintext_is_empty() {
            None
        } else {
            Some(state_store.read().private_plaintext_snapshot_json())
        };
        upload_mls_backup_with_recovery_key(
            base,
            session,
            actor,
            device,
            recovery_secret,
            sidecar_json,
            state_store,
            needs_mls_backup,
            recovery_key_input,
            status,
            busy,
            backup_created,
            true,
        );
    };

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
                role: "dialog",
                "aria-modal": "true",
                div { class: "modal-head event-head",
                    h3 { id: "mls-backup-title", {crate::i18n::tr("mls_backup.title")} }
                    span { class: "muted", {crate::i18n::tr("mls_backup.subtitle")} }
                }
                div { class: "modal-body mls-recovery-modal-body",
                    if recovery_key_configured {
                        div { class: "muted",
                            {crate::i18n::tr("mls_backup.description_existing")}
                        }
                        div { class: "muted", "data-testid": "mls-backup-passphrase-loss-warning",
                            strong { {crate::i18n::tr("mls_backup.warning.existing_key")} }
                        }
                    } else {
                        div { class: "muted",
                            {crate::i18n::tr("mls_backup.description")}
                        }
                        div { class: "muted", "data-testid": "mls-backup-passphrase-loss-warning",
                            strong { {crate::i18n::tr("mls_backup.warning.passphrase_loss")} }
                        }
                    }
                    if recovery_key_configured && generated_now.trim().is_empty() && !backup_created() {
                        div { class: "workflow-form",
                            Label { html_for: "mls-backup-existing-key",
                                {crate::i18n::tr("mls_backup.existing_key_label")}
                            }
                            Textarea {
                                id: "mls-backup-existing-key",
                                "data-testid": "mls-backup-existing-key",
                                rows: "3",
                                value: "{recovery_key_input_value}",
                                placeholder: crate::i18n::tr("mls_backup.existing_key_placeholder"),
                                oninput: move |event: FormEvent| recovery_key_input.set(event.value()),
                            }
                            div { class: "muted",
                                {crate::i18n::tr("mls_backup.existing_key_hint")}
                            }
                        }
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
                                            let primary_handle = account_primary_handle();
                                            let fname =
                                                recovery_key_filename_from_handles(std::slice::from_ref(
                                                    &primary_handle,
                                                ));
                                            download_text_as_file(&fname, &key);
                                        }
                                    },
                                    {crate::i18n::tr("mls_backup.download_key")}
                                }
                            }
                            div { class: "form-hint-warn", "data-testid": "mls-backup-generated-key-warning",
                                {crate::i18n::tr("mls_backup.generated_key_warning")}
                            }
                            Label { html_for: "mls-backup-confirm-key",
                                {crate::i18n::tr("mls_backup.confirm_key_label")}
                            }
                            Textarea {
                                id: "mls-backup-confirm-key",
                                "data-testid": "mls-backup-confirm-key",
                                rows: "3",
                                value: "{generated_confirm_now}",
                                placeholder: crate::i18n::tr("mls_backup.confirm_key_placeholder"),
                                oninput: move |event: FormEvent| generated_recovery_key_confirm.set(event.value()),
                            }
                            div { class: "muted", "data-testid": "mls-backup-confirm-key-hint",
                                {crate::i18n::tr("mls_backup.confirm_key_hint")}
                            }
                        }
                    }
                    if !status().is_empty() {
                        div { class: "muted", "data-testid": "mls-backup-status", "{status}" }
                    }
                }
                div { class: "modal-foot mls-backup-row",
                    if backup_created() && generated_now.trim().is_empty() {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "mls-backup-saved",
                            onclick: move |_| needs_mls_backup.set(false),
                            {crate::i18n::tr("mls_backup.button_done")}
                        }
                    } else if generated_now.trim().is_empty() || !backup_created() {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "mls-backup-submit",
                            disabled: !can_submit,
                            onclick: on_backup,
                            if busy() {
                                {crate::i18n::tr("mls_backup.button_busy")}
                            } else if !generated_now.trim().is_empty() {
                                {crate::i18n::tr("mls_backup.button_retry")}
                            } else if recovery_key_configured {
                                {crate::i18n::tr("mls_backup.button_existing")}
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
                            variant: ButtonVariant::Secondary,
                            "data-testid": "mls-backup-regenerate",
                            disabled: busy(),
                            onclick: on_regenerate,
                            {crate::i18n::tr("mls_backup.button_regenerate")}
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "mls-backup-saved",
                            disabled: generated_confirm_now.trim().is_empty(),
                            onclick: move |_| {
                                if !recovery_key_confirmation_matches(
                                    &generated_recovery_key(),
                                    &generated_recovery_key_confirm(),
                                ) {
                                    status.set(crate::i18n::tr("mls_backup.status.confirm_mismatch"));
                                    return;
                                }
                                generated_recovery_key.set(String::new());
                                generated_recovery_key_confirm.set(String::new());
                                needs_mls_backup.set(false);
                            },
                            {crate::i18n::tr("mls_backup.button_confirm_saved")}
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MLS_PRIVATE_PLAINTEXT_BACKUP_DEBOUNCE, MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS,
        MlsPrivatePlaintextBackupJob, finish_mls_private_plaintext_backup_job,
        next_mls_private_plaintext_backup_delay, recovery_key_filename,
        recovery_key_filename_from_handles, recovery_localpart_from_handles,
    };

    #[test]
    fn changed_private_plaintext_backup_reruns_after_debounce() {
        let key = "test-private-plaintext-rerun-after-change".to_owned();
        {
            let mut jobs = MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS.lock().unwrap();
            jobs.remove(&key);
            jobs.insert(
                key.clone(),
                MlsPrivatePlaintextBackupJob {
                    latest_digest: "new-sidecar".to_owned(),
                    last_uploaded_digest: Some("old-sidecar".to_owned()),
                    in_flight: true,
                    ..Default::default()
                },
            );
        }

        assert!(finish_mls_private_plaintext_backup_job(
            &key,
            "old-sidecar",
            None,
            Some("old-sidecar".to_owned())
        ));
        assert_eq!(
            next_mls_private_plaintext_backup_delay(&key),
            Some(MLS_PRIVATE_PLAINTEXT_BACKUP_DEBOUNCE)
        );

        MLS_PRIVATE_PLAINTEXT_BACKUP_JOBS
            .lock()
            .unwrap()
            .remove(&key);
    }

    #[test]
    fn localpart_comes_from_handle_not_did_ulid() {
        // The readable localpart is taken from the personal handle; the DID's
        // `:users:<ULID>` segment is never used.
        assert_eq!(
            recovery_localpart_from_handles(&["alice:example.com".to_owned()]),
            "alice"
        );
        // Ported authority: localpart is still just the user part.
        assert_eq!(
            recovery_localpart_from_handles(&["bob.smith_1:example.com:8443".to_owned()]),
            "bob.smith_1"
        );
        // First parseable handle wins; junk is skipped.
        assert_eq!(
            recovery_localpart_from_handles(&[
                "not a handle".to_owned(),
                "carol:example.com".to_owned(),
            ]),
            "carol"
        );
    }

    #[test]
    fn localpart_empty_when_no_usable_handle() {
        assert_eq!(recovery_localpart_from_handles(&[]), "");
        assert_eq!(
            recovery_localpart_from_handles(&["did:web:example.com:users:01ABC".to_owned()]),
            ""
        );
    }

    #[test]
    fn filename_uses_localpart() {
        assert_eq!(
            recovery_key_filename("alice"),
            "cokret-recovery-key-alice.txt"
        );
        assert_eq!(
            recovery_key_filename("bob.smith_1"),
            "cokret-recovery-key-bob.smith_1.txt"
        );
    }

    #[test]
    fn filename_sanitises_unsafe_chars_and_separators() {
        // `+`/`~` are valid in a localpart but become `-`; leading/trailing
        // separators are stripped so we never emit a dotfile or dangling dash.
        assert_eq!(
            recovery_key_filename("a+b~c"),
            "cokret-recovery-key-a-b-c.txt"
        );
        assert_eq!(
            recovery_key_filename(".hidden."),
            "cokret-recovery-key-hidden.txt"
        );
    }

    #[test]
    fn filename_from_handles_uses_primary_handle_localpart() {
        assert_eq!(
            recovery_key_filename_from_handles(&["alice:local.host".to_owned()]),
            "cokret-recovery-key-alice.txt"
        );
        assert_eq!(
            recovery_key_filename_from_handles(&[
                "did:web:local.host:users:01ABC".to_owned(),
                "bob:local.host".to_owned(),
            ],),
            "cokret-recovery-key-bob.txt"
        );
    }

    #[test]
    fn filename_falls_back_when_no_primary_handle() {
        assert_eq!(recovery_key_filename(""), "cokret-recovery-key.txt");
        assert_eq!(recovery_key_filename("   "), "cokret-recovery-key.txt");
        assert_eq!(
            recovery_key_filename_from_handles(&[]),
            "cokret-recovery-key.txt"
        );
    }
}
