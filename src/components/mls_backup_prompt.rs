use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use dioxus::prelude::*;
// Shared JS-interop helper (single source).
pub(crate) use yoface::utils::dom::copy_text_to_clipboard;

use crate::components::backup_job_scheduler::{
    BackupJob, BackupJobScheduler, BackupSchedulerConfig,
};
use crate::recovery_crypto::{
    generate_recovery_key, normalize_recovery_key_input, recovery_key_confirmation_matches,
};
use crate::state::LocalStateStore;
use crate::transport::auth::with_authed_api;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::dialog::Dialog;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::ui_signal::try_set_signal;

const MLS_RECOVERY_BACKUP_STATE_KEY: &str = "mls.recovery_backup.v1";
const MLS_RECOVERY_BACKUP_DEBOUNCE: Duration = Duration::from_millis(1500);
const MLS_RECOVERY_BACKUP_MIN_INTERVAL: Duration = Duration::from_secs(10);
/// Entry cap for the after-write backup probe single-flight set. Keyed by
/// `(base_url, actor_id)`, so a single browser session only ever holds a couple
/// of entries; the cap just bounds a pathological key space.
const MLS_BACKUP_AFTER_WRITE_PROBE_MAX_ENTRIES: usize = 64;
static MLS_BACKUP_AFTER_WRITE_PROBES: LazyLock<Mutex<crate::keyed_cooldown::SeenSet>> =
    LazyLock::new(|| {
        Mutex::new(crate::keyed_cooldown::SeenSet::new(
            MLS_BACKUP_AFTER_WRITE_PROBE_MAX_ENTRIES,
        ))
    });
/// The post-write recovery backup job debounces bursts and spaces successful
/// uploads so ordinary writes do not compete with foreground authoring for the
/// same account transport and PCR frontier. A failed upload is not retried
/// until strictly newer material arrives.
const MLS_RECOVERY_BACKUP_CONFIG: BackupSchedulerConfig = BackupSchedulerConfig {
    debounce: MLS_RECOVERY_BACKUP_DEBOUNCE,
    min_interval: Some(MLS_RECOVERY_BACKUP_MIN_INTERVAL),
    retry_base: MLS_RECOVERY_BACKUP_DEBOUNCE,
    retry_cap: MLS_RECOVERY_BACKUP_DEBOUNCE,
};

static MLS_RECOVERY_BACKUP_SCHEDULER: BackupJobScheduler<MlsRecoveryBackupPayload> =
    BackupJobScheduler::new("mls_recovery_backup", MLS_RECOVERY_BACKUP_CONFIG);

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
/// handle (`<prepared-localpart>:<lowercase-A-label-domain>`) for use in the recovery-key
/// download filename. Returns an empty string when no handle is known yet.
pub(crate) fn recovery_localpart_from_handles(handles: &[String]) -> String {
    handles
        .iter()
        .find_map(|handle| {
            crate::identity::handle::parse_user_handle(handle).map(|parsed| parsed.localpart)
        })
        .unwrap_or_default()
}

/// Build a per-account download filename for the recovery-key `.txt`, so that
/// multiple accounts (or repeated generations for one account) don't all land
/// as `arkret-recovery-key.txt` / `…(1).txt` in the Downloads folder, where the
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
        "arkret-recovery-key.txt".to_owned()
    } else {
        format!("arkret-recovery-key-{sanitized}.txt")
    }
}

pub(crate) fn recovery_key_filename_from_handles(handles: &[String]) -> String {
    let localpart = recovery_localpart_from_handles(handles);
    recovery_key_filename(&localpart)
}

type LocalAuthoritativeHistoryBackupRecords = Vec<(
    arkret_sdk::HistoryEffectiveScope,
    Vec<arkret_sdk::LocalAuthoritativeHistorySecret>,
)>;

/// Per-account payload carried by the shared scheduler. Credentials, the
/// latest portable history and sidecar snapshots, and the cached sidecar tail
/// used to chain the next upload.
#[derive(Clone, Default)]
struct MlsRecoveryBackupPayload {
    base_url: String,
    token: String,
    authority: Option<arkret_sdk::AccountId>,
    principal_control_realm_id: Option<arkret_sdk::RealmId>,
    actor_id: String,
    device_id: String,
    recovery_public_key: Vec<u8>,
    latest_history_records: LocalAuthoritativeHistoryBackupRecords,
    latest_sidecar_json: Option<Vec<u8>>,
    cached_previous_body: Option<serde_json::Value>,
}

type MlsRecoveryBackupJob = BackupJob<MlsRecoveryBackupPayload>;

fn mls_backup_after_write_probe_key(base_url: &str, actor_id: &str) -> String {
    format!(
        "{}|{}",
        base_url.trim().trim_end_matches('/'),
        actor_id.trim()
    )
}

fn mark_mls_backup_after_write_probe_started(key: String) -> bool {
    match MLS_BACKUP_AFTER_WRITE_PROBES.lock() {
        Ok(mut probes) => probes.mark(key),
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

fn sole_projected_principal_control_realm_id(
    projections: &BTreeMap<String, serde_json::Value>,
) -> anyhow::Result<arkret_sdk::RealmId> {
    let candidates = projections
        .iter()
        .filter(|(_, projection)| {
            crate::realm_tree::realm_projection_control_purpose(projection)
                == Some("principal_control")
        })
        .map(|(realm_id, _)| realm_id)
        .collect::<Vec<_>>();
    let [realm_id] = candidates.as_slice() else {
        anyhow::bail!(
            "expected one accepted principal-control Realm projection, found {}",
            candidates.len()
        );
    };
    arkret_sdk::RealmId::new((*realm_id).clone()).map_err(|error| {
        anyhow::anyhow!("projected principal-control Realm id is invalid: {error}")
    })
}

fn recovery_backup_control_realm_id(
    store: &LocalStateStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
) -> anyhow::Result<arkret_sdk::RealmId> {
    if let Some(evidence) = store.recovery_material_evidence() {
        if evidence.account_id != *authority
            || evidence.account_id.principal_id.as_str() != actor_id
        {
            anyhow::bail!("frozen recovery evidence belongs to a different account");
        }
        return Ok(evidence.principal_control_realm_id);
    }

    // A paired sibling device does not inherit the founding device's frozen
    // PCR genesis evidence. Its account-scoped sync does carry accepted Realm
    // projections, so use the sole create-locked principal-control Realm. The
    // registered purpose + profile check is performed by the projection
    // classifier; zero or multiple candidates remain fail-closed.
    sole_projected_principal_control_realm_id(&store.load().realm_tree_projections)
}

pub(crate) fn schedule_mls_recovery_backups_after_encrypted_write(
    base_url: String,
    token: String,
    authority: arkret_sdk::AccountId,
    actor_id: String,
    device_id: String,
    state_store: SyncSignal<LocalStateStore>,
) {
    if base_url.trim().is_empty()
        || token.trim().is_empty()
        || actor_id.trim().is_empty()
        || device_id.trim().is_empty()
    {
        return;
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (sidecar_json, history_records, recovery_public_key, principal_control_realm_id) = {
        let store = state_store.read();
        if !mls_recovery_backup_configured(&store) {
            return;
        }
        let principal_control_realm_id =
            match recovery_backup_control_realm_id(&store, &authority, &actor_id) {
                Ok(realm_id) => realm_id,
                Err(error) => {
                    tracing::warn!(%error, "MLS recovery backup control Realm is unavailable");
                    return;
                }
            };
        let Some(recovery_public_key) = crate::views::recovery::local_recovery_public_key(&store)
        else {
            return;
        };
        let history_records = match store
            .local_authoritative_history_secrets_for_backup(secure_store.as_ref(), &authority)
        {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(%error, "local-authoritative MLS history backup snapshot failed");
                return;
            }
        };
        let sidecar_json =
            (!store.private_plaintext_is_empty()).then(|| store.private_plaintext_snapshot_json());
        (
            sidecar_json,
            history_records,
            recovery_public_key,
            principal_control_realm_id,
        )
    };
    if sidecar_json.is_none() && history_records.is_empty() {
        return;
    }
    let digest_input = match serde_json::to_vec(&(&sidecar_json, &history_records)) {
        Ok(input) => input,
        Err(error) => {
            tracing::warn!(%error, "MLS recovery backup digest input could not be encoded");
            return;
        }
    };
    let digest = crate::canonical::sha256_digest(&digest_input);
    let key = mls_backup_after_write_probe_key(&base_url, &actor_id);
    let should_spawn = MLS_RECOVERY_BACKUP_SCHEDULER.schedule(&key, digest, |payload| {
        payload.base_url = base_url;
        payload.token = token;
        payload.authority = Some(authority);
        payload.principal_control_realm_id = Some(principal_control_realm_id);
        payload.actor_id = actor_id;
        payload.device_id = device_id;
        payload.recovery_public_key = recovery_public_key;
        payload.latest_history_records = history_records;
        payload.latest_sidecar_json = sidecar_json;
        // `cached_previous_body` is preserved across reschedules.
    });
    if should_spawn {
        spawn(async move {
            run_mls_recovery_backup_job(key).await;
        });
    }
}

async fn run_mls_recovery_backup_job(key: String) {
    loop {
        let Some(delay) = MLS_RECOVERY_BACKUP_SCHEDULER.next_delay(&key, chrono::Utc::now()) else {
            return;
        };
        crate::runtime_helpers::sleep_for(delay).await;
        let Some(job) = MLS_RECOVERY_BACKUP_SCHEDULER.begin_attempt(&key) else {
            return;
        };
        if job.last_uploaded_digest.as_deref() == Some(job.latest_digest.as_str()) {
            // Latest already uploaded: clear in-flight (re-arming only if newer
            // material slipped in) and stop this loop.
            let _ = MLS_RECOVERY_BACKUP_SCHEDULER.finish_rerun_if_newer(
                &key,
                &job.latest_digest,
                |_| {},
            );
            return;
        }
        let upload_digest = job.latest_digest.clone();
        let rerun = match upload_mls_recovery_backup_job_snapshot(job).await {
            Ok((history_count, sidecar)) => {
                tracing::debug!(
                    history_count,
                    sidecar_backup_id = ?sidecar
                        .as_ref()
                        .map(|(backup_id, _)| backup_id.as_str()),
                    "MLS recovery backups uploaded after encrypted write"
                );
                MLS_RECOVERY_BACKUP_SCHEDULER.finish_rerun_if_newer(&key, &upload_digest, |job| {
                    if let Some((_, body)) = sidecar {
                        job.payload.cached_previous_body = Some(body);
                    }
                    job.last_uploaded_digest = Some(upload_digest.clone());
                    job.last_upload_at = Some(chrono::Utc::now());
                })
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "MLS recovery backup after encrypted write failed"
                );
                // Debounce-only family: a failed upload of the current digest is
                // NOT retried; re-arm only if strictly newer material arrived.
                MLS_RECOVERY_BACKUP_SCHEDULER.finish_rerun_if_newer(&key, &upload_digest, |_| {})
            }
        };
        if !rerun {
            return;
        }
    }
}

async fn upload_mls_recovery_backup_job_snapshot(
    job: MlsRecoveryBackupJob,
) -> anyhow::Result<(usize, Option<(String, serde_json::Value)>)> {
    let MlsRecoveryBackupPayload {
        base_url,
        token,
        authority,
        principal_control_realm_id,
        actor_id,
        device_id,
        recovery_public_key,
        latest_history_records,
        latest_sidecar_json,
        cached_previous_body,
    } = job.payload;
    let authority =
        authority.ok_or_else(|| anyhow::anyhow!("MLS backup job omitted the active authority"))?;
    let principal_control_realm_id = principal_control_realm_id
        .ok_or_else(|| anyhow::anyhow!("MLS backup job omitted frozen PCR authority"))?;
    with_authed_api(&base_url, token, |api| async move {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let history_count = crate::mls::account_recovery::upload_local_authoritative_mls_history_records_with_recovery_public_key(
            &api,
            latest_history_records,
            &authority,
            &principal_control_realm_id,
            &actor_id,
            &device_id,
            &recovery_public_key,
        )
        .await?
        .len();
        let sidecar = if let Some(latest_sidecar_json) = latest_sidecar_json {
            let previous_body = match cached_previous_body {
                Some(body) => Some(body),
                None => {
                    crate::mls::account_recovery::fetch_mls_private_plaintext_backup_body(
                        &api, &actor_id, &device_id,
                    )
                    .await?
                }
            };
            Some(
                crate::mls::account_recovery::upload_mls_private_plaintext_backup_with_previous(
                    &api,
                    secure_store.as_ref(),
                    &authority,
                    &principal_control_realm_id,
                    &actor_id,
                    &device_id,
                    &latest_sidecar_json,
                    previous_body.as_ref(),
                )
                .await?,
            )
        } else {
            None
        };
        Ok::<_, anyhow::Error>((history_count, sidecar))
    })
    .await
    .map_err(|err| anyhow::anyhow!(err.display_diagnostic()))
}

pub(crate) fn mls_recovery_backup_configured(state_store: &LocalStateStore) -> bool {
    state_store
        .load_plain_local_data(MLS_RECOVERY_BACKUP_STATE_KEY)
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
    backup_id: &str,
) {
    if backup_id.trim().is_empty() {
        return;
    }
    let payload = serde_json::json!({
        "schema_version": 1,
        "backup_id": backup_id,
        "configured_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
    });
    state_store.save_plain_local_data(MLS_RECOVERY_BACKUP_STATE_KEY, payload.to_string());
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

/// X11.2 — shared first-write trigger with the no-prompt path enabled. After a
/// successful encrypted write, detect a missing `mls_account_secret` backup;
/// once the user has confirmed a Recovery Key, its cached public key can seal
/// the backup without asking for the 24 words again. The local backup marker
/// also acts as the completion fence for concurrent probes: a stale probe that
/// started before Recovery Key setup completed must not turn the prompt back
/// on after setup uploaded the account-secret backup.
pub async fn maybe_auto_backup_mls_after_encrypted_write(
    base_url: String,
    token: String,
    authority: arkret_sdk::AccountId,
    actor_id: String,
    device_id: String,
    state_store: crate::runtime::input::StateStoreHandle,
    needs_mls_backup: Signal<bool>,
) {
    maybe_backup_or_flag_mls_backup_after_encrypted_write(
        base_url,
        token,
        authority,
        actor_id,
        Some((device_id, state_store)),
        needs_mls_backup,
    )
    .await;
}

async fn maybe_backup_or_flag_mls_backup_after_encrypted_write(
    base_url: String,
    token: String,
    authority: arkret_sdk::AccountId,
    actor_id: String,
    auto_backup: Option<(String, crate::runtime::input::StateStoreHandle)>,
    needs_mls_backup: Signal<bool>,
) {
    if base_url.trim().is_empty() || token.trim().is_empty() || actor_id.trim().is_empty() {
        return;
    }
    if needs_mls_backup() {
        return;
    }
    let state_store_for_completion_fence = auto_backup.as_ref().map(|(_, store)| store.clone());
    let backup_completed_while_probe_was_running = || {
        state_store_for_completion_fence
            .as_ref()
            .is_some_and(|store| store.read(mls_recovery_backup_configured))
    };
    // Local account secret must exist (encryption has been used) — otherwise
    // there's nothing to back up yet.
    let has_local_secret = {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &authority)
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
        state_store.read(|store| {
            let recovery_public_key = crate::views::recovery::local_recovery_public_key(store)?;
            let recovery_material_evidence = store.recovery_material_evidence()?;
            if recovery_material_evidence.account_id.principal_id.as_str() != actor_id
                || recovery_material_evidence.device_id.as_str() != device_id
            {
                return None;
            }
            let sidecar_json = if store.private_plaintext_is_empty() {
                None
            } else {
                Some(store.private_plaintext_snapshot_json())
            };
            Some((
                state_store.clone(),
                device_id.clone(),
                recovery_material_evidence,
                recovery_public_key,
                sidecar_json,
            ))
        })
    });
    // Server must NOT already hold an `mls_account_secret` backup. (When it
    // does, the restore/unlock path owns the flow — backup and restore are
    // mutually exclusive by this exact check, so we can't double-prompt.)
    let actor_for_probe = actor_id.clone();
    let payload = match with_authed_api(&base_url, token.clone(), |api| async move {
        crate::mls::account_recovery::fetch_mls_restore_payload(&api, &actor_for_probe).await
    })
    .await
    {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                error = %err.display_diagnostic(),
                "MLS backup detection could not list key backups after encrypted write"
            );
            if backup_completed_while_probe_was_running() {
                try_set_signal(needs_mls_backup, false);
            } else {
                try_set_signal(needs_mls_backup, true);
            }
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
            state_store.write(|store| mark_mls_recovery_backup_configured(store, backup_id));
        }
        try_set_signal(needs_mls_backup, false);
        return;
    }
    if let Some((
        state_store,
        device_id,
        recovery_material_evidence,
        recovery_public_key,
        sidecar_json,
    )) = auto_backup_inputs
    {
        let actor_for_upload = actor_id.clone();
        let device_for_upload = device_id.clone();
        let authority_for_upload = authority.clone();
        let principal_control_realm_id = recovery_material_evidence
            .principal_control_realm_id
            .clone();
        let principal_control_realm_id_for_sidecar = principal_control_realm_id.clone();
        let upload_result = with_authed_api(&base_url, token.clone(), |api| async move {
            crate::recovery_flow::verify_recovery_authority_evidence(
                &api,
                &recovery_material_evidence,
            )
            .await?;
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_public_key(
                &api,
                secure_store.as_ref(),
                &authority_for_upload,
                &principal_control_realm_id,
                &actor_for_upload,
                &device_for_upload,
                &recovery_public_key,
            )
            .await
        })
        .await;
        match upload_result {
            Ok(backup_id) => {
                state_store.write(|store| mark_mls_recovery_backup_configured(store, &backup_id));
                if let Some(sidecar_json) = sidecar_json {
                    let actor = actor_id.clone();
                    let device = device_id;
                    let _ = with_authed_api(&base_url, token, |api| async move {
                        let secure_store =
                            crate::secure_key_store::default_secure_key_store("inkson");
                        crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                            &api,
                            secure_store.as_ref(),
                            &authority,
                            &principal_control_realm_id_for_sidecar,
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
                    error = %err.display_diagnostic(),
                    "automatic MLS account-secret backup with recovery public key failed"
                );
            }
        }
    }

    if backup_completed_while_probe_was_running() {
        try_set_signal(needs_mls_backup, false);
    } else {
        try_set_signal(needs_mls_backup, true);
    }
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
/// `secret_storage` + `recovery_public_key`; the user-facing flow does not ask
/// the user to invent or confirm a separate passphrase.
#[allow(clippy::too_many_arguments)]
fn upload_mls_backup_with_recovery_key(
    base: String,
    session: String,
    authority: arkret_sdk::AccountId,
    actor: String,
    device: String,
    recovery_secret: String,
    sidecar_json: Option<Vec<u8>>,
    state_store: SyncSignal<LocalStateStore>,
    needs_mls_backup: Signal<bool>,
    recovery_key_input: Signal<String>,
    mut status: Signal<String>,
    mut busy: Signal<bool>,
    mut backup_created: Signal<bool>,
    generated_in_this_flow: bool,
) {
    let mut state_store_for_marker = state_store;
    let history_records = {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        state_store
            .read()
            .local_authoritative_history_secrets_for_backup(secure_store.as_ref(), &authority)
            .map_err(anyhow::Error::msg)
    };
    let Some(recovery_material_evidence) = state_store.read().recovery_material_evidence() else {
        try_set_signal(status, "Frozen PCR authority evidence is required");
        return;
    };
    if recovery_material_evidence.account_id.principal_id.as_str() != actor
        || recovery_material_evidence.device_id.as_str() != device
    {
        try_set_signal(
            status,
            "Frozen PCR authority evidence does not match this account",
        );
        return;
    }
    let principal_control_realm_id = recovery_material_evidence
        .principal_control_realm_id
        .clone();
    busy.set(true);
    backup_created.set(false);
    status.set(crate::i18n::tr("mls_backup.status.uploading"));
    spawn(async move {
        let actor_for_sidecar = actor.clone();
        let authority_for_sidecar = authority.clone();
        let device_for_sidecar = device.clone();
        let base_for_sidecar = base.clone();
        let session_for_sidecar = session.clone();
        let principal_control_realm_id_for_sidecar = principal_control_realm_id.clone();
        let result = with_authed_api(&base, session, |api| async move {
            crate::recovery_flow::verify_recovery_authority_evidence(
                &api,
                &recovery_material_evidence,
            )
            .await?;
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let backup_id =
                crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(
                &api,
                secure_store.as_ref(),
                &authority,
                &principal_control_realm_id,
                &actor,
                &device,
                &recovery_secret,
            )
            .await?;
            let (_, recovery_public_key) =
                crate::hpke_backup::derive_recovery_keypair_from_recovery_key(&recovery_secret)
                    .map_err(|error| anyhow::anyhow!("derive recovery HPKE keypair: {error}"))?;
            crate::mls::account_recovery::upload_local_authoritative_mls_history_records_with_recovery_public_key(
                &api,
                history_records?,
                &authority,
                &principal_control_realm_id,
                &actor,
                &device,
                &recovery_public_key,
            )
            .await?;
            Ok::<_, anyhow::Error>(backup_id)
        })
        .await;
        try_set_signal(busy, false);
        match result {
            Ok(backup_id) => {
                if let Ok(mut store) = state_store_for_marker.try_write() {
                    mark_mls_recovery_backup_configured(&mut store, &backup_id);
                }
                if let Some(sidecar_json) = sidecar_json {
                    let actor = actor_for_sidecar;
                    let device = device_for_sidecar;
                    let outcome =
                        with_authed_api(&base_for_sidecar, session_for_sidecar, |api| async move {
                            let secure_store =
                                crate::secure_key_store::default_secure_key_store("inkson");
                            crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                                &api,
                                secure_store.as_ref(),
                                &authority_for_sidecar,
                                &principal_control_realm_id_for_sidecar,
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
                try_set_signal(status, crate::i18n::tr("mls_backup.status.created"));
                if !generated_in_this_flow {
                    try_set_signal(recovery_key_input, String::new());
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(750)).await;
                    try_set_signal(needs_mls_backup, false);
                }
            }
            Err(err) => {
                try_set_signal(status, err.display());
            }
        }
    });
}

#[component]
pub fn MlsBackupPrompt(
    token: Signal<String>,
    device_id: Signal<String>,
    needs_mls_backup: Signal<bool>,
    /// Server truth for account-level recovery. `Some(true)` means the account
    /// already has a Recovery Key root, even if this browser has no local
    /// fingerprint cached.
    account_recovery_configured: Signal<Option<bool>>,
    /// Primary account handle claim, used only to name the recovery-key download file readably.
    account_primary_handle: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let session = crate::app::SessionContext::get();
    let base_url = session.base_url;
    let state_store = session.state_store;
    let Some(account) = session.active_account() else {
        return rsx! {};
    };
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

    let local_recovery_key_configured =
        crate::views::recovery::local_recovery_key_fingerprint(&state_store.read()).is_some();
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
        && !token().trim().is_empty();

    let account_for_backup = account.clone();
    let on_backup = move |_| {
        if busy() {
            return;
        }
        let base = base_url();
        let session = token();
        let authority = account_for_backup.authority.clone();
        let actor = account_for_backup.did().to_string();
        let device = account_for_backup.device_id.to_string();
        let local_recovery_key_configured =
            crate::views::recovery::local_recovery_key_fingerprint(&state_store.read()).is_some();
        let recovery_key_configured =
            local_recovery_key_configured || matches!(account_recovery_configured(), Some(true));
        let generated = generated_recovery_key();
        let generated_in_this_flow = !generated.trim().is_empty() || !recovery_key_configured;
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
            authority,
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
            generated_in_this_flow,
        );
    };

    let account_for_regenerate = account;
    let on_regenerate = move |_| {
        if busy() {
            return;
        }
        let base = base_url();
        let session = token();
        let authority = account_for_regenerate.authority.clone();
        let actor = account_for_regenerate.did().to_string();
        let device = account_for_regenerate.device_id.to_string();
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
            authority,
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
        BackupJob, MLS_RECOVERY_BACKUP_MIN_INTERVAL, MLS_RECOVERY_BACKUP_SCHEDULER,
        recovery_key_filename, recovery_key_filename_from_handles, recovery_localpart_from_handles,
        sole_projected_principal_control_realm_id,
    };

    fn principal_control_projection() -> serde_json::Value {
        serde_json::json!({
            "state_after": {
                "events": [{
                    "kind": arkret_sdk::EventKind::RealmCreate.as_str(),
                    "payload": {
                        "object": {
                            "purpose": "principal_control",
                            "schema_refs": [arkret_wire::ProfileId::PRINCIPAL_CONTROL_REALM_V1]
                        }
                    }
                }]
            }
        })
    }

    #[test]
    fn sibling_device_uses_the_only_projected_principal_control_realm() {
        let realm_id = "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc".to_owned();
        let projections =
            std::collections::BTreeMap::from([(realm_id.clone(), principal_control_projection())]);

        let selected = sole_projected_principal_control_realm_id(&projections)
            .expect("one accepted principal-control projection is authoritative");
        assert_eq!(selected.as_str(), realm_id);
    }

    #[test]
    fn sibling_device_rejects_ambiguous_projected_principal_control_realms() {
        let projections = std::collections::BTreeMap::from([
            (
                "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc".to_owned(),
                principal_control_projection(),
            ),
            (
                "ak:realm:AdM0E7Gz4z3xDbVnW7yQcEJnaVeXjYprj0Fb4b4kFXR0".to_owned(),
                principal_control_projection(),
            ),
        ]);

        assert!(sole_projected_principal_control_realm_id(&projections).is_err());
    }

    #[test]
    fn changed_recovery_backup_reruns_after_success_interval() {
        let key = "test-recovery-backup-rerun-after-change";
        MLS_RECOVERY_BACKUP_SCHEDULER.with_jobs_mut(|jobs| {
            jobs.insert(
                key.to_owned(),
                BackupJob {
                    latest_digest: "new-sidecar".to_owned(),
                    last_uploaded_digest: Some("old-sidecar".to_owned()),
                    in_flight: true,
                    ..Default::default()
                },
            )
        });

        // A strictly NEWER digest ("new-sidecar") is pending, so finishing the
        // attempt on the OLD digest re-arms the loop. A successful recovery
        // upload also spaces the next run so foreground encrypted writes are
        // not competing continuously with backup frontier reads.
        assert!(
            MLS_RECOVERY_BACKUP_SCHEDULER.finish_rerun_if_newer(key, "old-sidecar", |job| {
                job.last_uploaded_digest = Some("old-sidecar".to_owned());
                job.last_upload_at = Some(chrono::Utc::now());
            },)
        );
        let delay = MLS_RECOVERY_BACKUP_SCHEDULER
            .next_delay(key, chrono::Utc::now())
            .expect("scheduled recovery backup has a next delay");
        assert!(delay >= MLS_RECOVERY_BACKUP_MIN_INTERVAL - std::time::Duration::from_secs(1));
        assert!(delay <= MLS_RECOVERY_BACKUP_MIN_INTERVAL);

        MLS_RECOVERY_BACKUP_SCHEDULER.with_jobs_mut(|jobs| jobs.remove(key));
    }

    #[test]
    fn localpart_comes_from_handle_not_did_ulid() {
        // The readable localpart is taken from the personal handle; the DID's
        // `:users:<ULID>` segment is never used.
        assert_eq!(
            recovery_localpart_from_handles(&["alice:example.com".to_owned()]),
            "alice"
        );
        // Punctuation allowed by the canonical localpart profile is preserved.
        assert_eq!(
            recovery_localpart_from_handles(&["bob.smith_1:example.com".to_owned()]),
            "bob.smith_1"
        );
        // A port is not part of the canonical handle domain.
        assert_eq!(
            recovery_localpart_from_handles(&["bob:example.com:8443".to_owned()]),
            ""
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
            "arkret-recovery-key-alice.txt"
        );
        assert_eq!(
            recovery_key_filename("bob.smith_1"),
            "arkret-recovery-key-bob.smith_1.txt"
        );
    }

    #[test]
    fn filename_sanitises_unsafe_chars_and_separators() {
        // `+`/`~` are valid in a localpart but become `-`; leading/trailing
        // separators are stripped so we never emit a dotfile or dangling dash.
        assert_eq!(
            recovery_key_filename("a+b~c"),
            "arkret-recovery-key-a-b-c.txt"
        );
        assert_eq!(
            recovery_key_filename(".hidden."),
            "arkret-recovery-key-hidden.txt"
        );
    }

    #[test]
    fn filename_from_handles_uses_primary_handle_localpart() {
        assert_eq!(
            recovery_key_filename_from_handles(&["alice:local.host".to_owned()]),
            "arkret-recovery-key-alice.txt"
        );
        assert_eq!(
            recovery_key_filename_from_handles(&[
                "did:web:local.host:users:01ABC".to_owned(),
                "bob:local.host".to_owned(),
            ],),
            "arkret-recovery-key-bob.txt"
        );
    }

    #[test]
    fn filename_falls_back_when_no_primary_handle() {
        assert_eq!(recovery_key_filename(""), "arkret-recovery-key.txt");
        assert_eq!(recovery_key_filename("   "), "arkret-recovery-key.txt");
        assert_eq!(
            recovery_key_filename_from_handles(&[]),
            "arkret-recovery-key.txt"
        );
    }
}
