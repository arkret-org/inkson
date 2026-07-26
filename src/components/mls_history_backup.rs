//! Continuous `mls_history` key-backup after MLS epoch changes
//! (spec `identity/key-management.md` §7.10 — automatic continuous backup).
//!
//! Product rule: once the 24-word Recovery Key is configured, backup is
//! automatic and continuous — no manual trigger. The account MLS secret and
//! the private-plaintext sidecar already re-upload after encrypted writes
//! (`mls_backup_prompt::schedule_mls_private_plaintext_backup_after_encrypted_write`);
//! this module closes the remaining gap: re-uploading the per-Realm
//! `mls_history` group-state envelope after every accepted `ak.mls.commit`
//! (epoch advance) so a fresh device can recover up-to-date epoch material.
//!
//! Wire shape (soland-audited):
//! - `PUT /_arkret/self/keys/backups/{backup_id}`, `backup_kind="mls_history"`, wrapped under the
//!   named `secret_storage` key `mls_group_secrets_backup_key` (built by
//!   [`crate::mls::persistence::MlsSnapshotEnvelope::to_key_backup_body`]).
//! - One SERIES per Realm, extended via the successor chain (`series_seq` strictly +1, `supersedes`
//!   + `supersedes_digest`) instead of minting a fresh series per upload — restore then reads ONLY
//!   the series tail per Realm, respecting soland's per-principal 24h full-ciphertext download
//!   quota (default 64).
//! - The tail envelope folds the Realm's complete recoverable group state, so no per-epoch envelope
//!   pile-up is needed.
//!
//! Job mechanics (single-flight, digest dedupe, debounce, min-interval,
//! exponential-backoff retries, park-after-N-failures, three-state finish) are
//! the shared [`crate::components::backup_job_scheduler`] machinery; this module
//! supplies only the per-Realm payload + digest + the upload wire call, plus a
//! status snapshot available to recovery/debug surfaces.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use serde_json::Value;

use crate::components::backup_job_scheduler::{
    BackupJob, BackupJobScheduler, BackupSchedulerConfig, upsert_backup_job,
};
use crate::state::LocalStateStore;
use crate::transport::auth::with_authed_api;

const MLS_HISTORY_BACKUP_DEBOUNCE: Duration = Duration::from_millis(1500);
const MLS_HISTORY_BACKUP_MIN_INTERVAL: Duration = Duration::from_secs(300);
const MLS_HISTORY_BACKUP_RETRY_BASE: Duration = Duration::from_secs(5);
const MLS_HISTORY_BACKUP_RETRY_CAP: Duration = Duration::from_secs(600);
/// After this many consecutive failures the job parks (stops rescheduling
/// itself). The pending state stays visible in the status snapshot and the
/// next accepted commit / schedule call re-arms the job with fresh
/// credentials and a reset failure counter.
const MLS_HISTORY_BACKUP_MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Per-Realm payload carried by the shared scheduler. Credentials + the latest
/// snapshot to upload + the cached series-tail body used to chain the next
/// successor.
#[derive(Clone, Default)]
struct MlsHistoryBackupPayload {
    base_url: String,
    token: String,
    actor_id: String,
    device_id: String,
    realm_id: String,
    latest_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    /// Full body of the current series tail (the envelope this device last
    /// uploaded or fetched). Chaining the next successor needs the FULL
    /// predecessor body (`supersedes_digest` is computed over it), and caching
    /// it here avoids an unlock-proof read per upload. Preserved across
    /// reschedules.
    cached_tail_body: Option<Value>,
}

type MlsHistoryBackupJob = BackupJob<MlsHistoryBackupPayload>;

static MLS_HISTORY_BACKUP_SCHEDULER: BackupJobScheduler<MlsHistoryBackupPayload> =
    BackupJobScheduler::new(
        "mls_history_backup",
        BackupSchedulerConfig {
            debounce: MLS_HISTORY_BACKUP_DEBOUNCE,
            min_interval: Some(MLS_HISTORY_BACKUP_MIN_INTERVAL),
            retry_base: MLS_HISTORY_BACKUP_RETRY_BASE,
            retry_cap: MLS_HISTORY_BACKUP_RETRY_CAP,
        },
    );

/// Last terminal outcomes, kept separately from the per-realm job map so the
/// diagnostics can show "last failure" even after the failing job was
/// superseded by a successful upload of newer material.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MlsHistoryBackupLastOutcome {
    last_error: Option<String>,
    last_error_at: Option<DateTime<Utc>>,
    last_uploaded_at: Option<DateTime<Utc>>,
}

static MLS_HISTORY_BACKUP_LAST_OUTCOME: LazyLock<Mutex<MlsHistoryBackupLastOutcome>> =
    LazyLock::new(|| Mutex::new(MlsHistoryBackupLastOutcome::default()));

/// Status snapshot for recovery/debug surfaces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MlsHistoryBackupStatus {
    /// Realms whose newest local MLS snapshot has not been uploaded yet
    /// (scheduled, retrying, or parked after repeated failures).
    pub pending_realms: usize,
    /// An upload attempt is currently on the wire.
    pub in_flight: bool,
    /// Human-readable reason of the most recent upload failure.
    pub last_error: Option<String>,
    /// RFC-3339 timestamp of the most recent upload failure.
    pub last_error_at: Option<String>,
    /// RFC-3339 timestamp of the most recent successful upload.
    pub last_uploaded_at: Option<String>,
}

/// Current continuous-backup status (pure read; no network).
pub fn mls_history_backup_status() -> MlsHistoryBackupStatus {
    let mut status = MlsHistoryBackupStatus::default();
    MLS_HISTORY_BACKUP_SCHEDULER.with_jobs(|jobs| {
        for job in jobs.values() {
            if job.is_pending() {
                status.pending_realms += 1;
            }
            status.in_flight |= job.in_flight;
        }
    });
    if let Ok(last) = MLS_HISTORY_BACKUP_LAST_OUTCOME.lock() {
        status.last_error = last.last_error.clone();
        status.last_error_at = last
            .last_error_at
            .map(arkret_sdk::canonical::format_timestamp_canonical);
        status.last_uploaded_at = last
            .last_uploaded_at
            .map(arkret_sdk::canonical::format_timestamp_canonical);
    }
    status
}

fn mls_history_backup_job_key(base_url: &str, actor_id: &str, realm_id: &str) -> String {
    format!(
        "{}|{}|{}",
        base_url.trim().trim_end_matches('/'),
        actor_id.trim(),
        realm_id.trim()
    )
}

fn mls_snapshot_digest(snapshot: &crate::mls::persistence::MlsSnapshotEnvelope) -> String {
    let bytes = serde_json::to_vec(snapshot).unwrap_or_default();
    crate::canonical::sha256_digest(&bytes)
}

/// Upsert the job entry for a freshly observed snapshot. Returns `true` when
/// the caller must spawn the job loop (no loop is scheduled or in flight).
/// Pure on the map so the dedupe/single-flight decision is unit-testable.
/// `cached_tail_body` is intentionally not touched — it survives reschedules
/// so the next successor chains cheaply.
#[allow(clippy::too_many_arguments)]
fn upsert_mls_history_backup_job(
    jobs: &mut BTreeMap<String, MlsHistoryBackupJob>,
    key: &str,
    base_url: String,
    token: String,
    actor_id: String,
    device_id: String,
    realm_id: String,
    snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    digest: String,
) -> bool {
    upsert_backup_job(jobs, key, digest, |payload| {
        payload.base_url = base_url;
        payload.token = token;
        payload.actor_id = actor_id;
        payload.device_id = device_id;
        payload.realm_id = realm_id;
        payload.latest_snapshot = Some(snapshot);
    })
}

/// Hook: call after a `ak.mls.commit` was ACCEPTED by the server and the local
/// MLS snapshot advanced (persist-on-accept), or after a Welcome application
/// persisted a fresh snapshot. Debounced + deduped; no-op until the 24-word
/// Recovery Key strand has configured server-side recovery
/// (`mls_recovery_backup_configured`), matching the sidecar backup gate.
pub(crate) fn schedule_mls_history_backup_after_commit(
    base_url: String,
    token: String,
    actor_id: String,
    device_id: String,
    realm_id: String,
    state_store: SyncSignal<LocalStateStore>,
) {
    if base_url.trim().is_empty()
        || token.trim().is_empty()
        || actor_id.trim().is_empty()
        || device_id.trim().is_empty()
        || realm_id.trim().is_empty()
    {
        return;
    }
    let snapshot = {
        let store = state_store.read();
        if !crate::components::mls_recovery_backup_configured(&store, &actor_id) {
            return;
        }
        let Some(snapshot) = store.mls_snapshot_for(&realm_id) else {
            return;
        };
        snapshot
    };
    let digest = mls_snapshot_digest(&snapshot);
    let key = mls_history_backup_job_key(&base_url, &actor_id, &realm_id);
    let should_spawn = MLS_HISTORY_BACKUP_SCHEDULER
        .with_jobs_mut(|jobs| {
            upsert_mls_history_backup_job(
                jobs, &key, base_url, token, actor_id, device_id, realm_id, snapshot, digest,
            )
        })
        .unwrap_or(false);
    if should_spawn {
        spawn(async move {
            run_mls_history_backup_job(key).await;
        });
    }
}

/// Immediate (non-debounced) chained upload for the existing one-shot call
/// sites (Welcome bootstrap, Realm creation, admin device-remove commit).
/// Replaces their old `upload_mls_snapshot_backup` calls, which minted a NEW
/// genesis series on every invocation; this appends to the Realm's existing
/// series instead and seeds the tail cache so the continuous job chains
/// cheaply afterwards. Deliberately NOT gated on
/// `mls_recovery_backup_configured` — these sites uploaded unconditionally
/// before and that behaviour is preserved.
pub(crate) async fn upload_mls_history_backup_now(
    api: &crate::transport::TransportClient,
    base_url: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
) -> anyhow::Result<String> {
    let key = mls_history_backup_job_key(base_url, actor_id, realm_id);
    let cached_tail = MLS_HISTORY_BACKUP_SCHEDULER
        .with_jobs(|jobs| {
            jobs.get(&key)
                .and_then(|job| job.payload.cached_tail_body.clone())
        })
        .flatten();
    let previous = match cached_tail {
        Some(body) => Some(body),
        None => {
            crate::mls::account_recovery::fetch_mls_history_tail_for_realm(
                api, actor_id, device_id, realm_id,
            )
            .await?
        }
    };
    let (backup_id, body) = crate::mls::account_recovery::upload_mls_history_backup_with_previous(
        api,
        snapshot,
        actor_id,
        device_id,
        previous.as_ref(),
    )
    .await?;
    record_mls_history_backup_uploaded(&key, snapshot, body);
    Ok(backup_id)
}

/// Record a successful upload (from the job or an immediate call site):
/// remember the uploaded body as the new series tail and mark the snapshot
/// digest as uploaded so the debounced job does not re-send identical state.
fn record_mls_history_backup_uploaded(
    key: &str,
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    body: Value,
) {
    MLS_HISTORY_BACKUP_SCHEDULER.record_success(key, mls_snapshot_digest(snapshot), |payload| {
        payload.cached_tail_body = Some(body)
    });
    if let Ok(mut last) = MLS_HISTORY_BACKUP_LAST_OUTCOME.lock() {
        last.last_uploaded_at = Some(Utc::now());
    }
}

async fn run_mls_history_backup_job(key: String) {
    loop {
        let Some(delay) = MLS_HISTORY_BACKUP_SCHEDULER.next_delay(&key, Utc::now()) else {
            return;
        };
        crate::runtime_helpers::sleep_for(delay).await;
        let Some(job) = MLS_HISTORY_BACKUP_SCHEDULER.begin_attempt(&key) else {
            return;
        };
        if job.last_uploaded_digest.as_deref() == Some(job.latest_digest.as_str()) {
            if !MLS_HISTORY_BACKUP_SCHEDULER.finish_and_rearm_if_pending(&key) {
                return;
            }
            continue;
        }
        match upload_mls_history_backup_job_snapshot(job).await {
            Ok((backup_id, snapshot, body)) => {
                tracing::debug!(
                    backup_id = %backup_id,
                    "continuous mls_history backup uploaded after MLS commit"
                );
                record_mls_history_backup_uploaded(&key, &snapshot, body);
                if !MLS_HISTORY_BACKUP_SCHEDULER.finish_and_rearm_if_pending(&key) {
                    return;
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "continuous mls_history backup upload failed; backing off"
                );
                if !finish_mls_history_backup_job_failure(&key, &err.to_string()) {
                    return;
                }
            }
        }
    }
}

/// Failure: surface the error to the status panel, then hand the job-map
/// transition (bump the backoff counter, drop a stale series-tail cache, and
/// reschedule — unless the park threshold is reached) to the shared scheduler.
fn finish_mls_history_backup_job_failure(key: &str, error: &str) -> bool {
    let now = Utc::now();
    if let Ok(mut last) = MLS_HISTORY_BACKUP_LAST_OUTCOME.lock() {
        last.last_error = Some(error.to_owned());
        last.last_error_at = Some(now);
    }
    MLS_HISTORY_BACKUP_SCHEDULER.finish_failure(
        key,
        MLS_HISTORY_BACKUP_MAX_CONSECUTIVE_FAILURES,
        |payload| {
            // A series conflict means our cached predecessor no longer matches
            // the server's chain (e.g. a sibling device extended it, or a
            // rotation opened a fresh series and deleted ours). Drop the cache
            // so the retry re-reads the real tail instead of failing forever.
            if error.contains("series") {
                payload.cached_tail_body = None;
            }
        },
    )
}

async fn upload_mls_history_backup_job_snapshot(
    job: MlsHistoryBackupJob,
) -> anyhow::Result<(String, crate::mls::persistence::MlsSnapshotEnvelope, Value)> {
    let MlsHistoryBackupPayload {
        base_url,
        token,
        actor_id,
        device_id,
        realm_id,
        latest_snapshot,
        cached_tail_body,
    } = job.payload;
    let snapshot =
        latest_snapshot.ok_or_else(|| anyhow::anyhow!("mls_history backup job has no snapshot"))?;
    let snapshot_for_upload = snapshot.clone();
    let (backup_id, body) = with_authed_api(&base_url, token, |api| async move {
        let previous = match cached_tail_body {
            Some(body) => Some(body),
            None => {
                crate::mls::account_recovery::fetch_mls_history_tail_for_realm(
                    &api, &actor_id, &device_id, &realm_id,
                )
                .await?
            }
        };
        crate::mls::account_recovery::upload_mls_history_backup_with_previous(
            &api,
            &snapshot_for_upload,
            &actor_id,
            &device_id,
            previous.as_ref(),
        )
        .await
    })
    .await
    .map_err(|err| anyhow::anyhow!(err.display()))?;
    Ok((backup_id, snapshot, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(epoch: u64) -> crate::mls::persistence::MlsSnapshotEnvelope {
        crate::mls::persistence::encrypt_state(
            "ak:realm:01964137-0000-7000-8000-000000000001",
            "group-1",
            epoch,
            b"state bytes",
            "secret",
            b"salt-016-bytes!!",
        )
    }

    fn upsert(
        jobs: &mut BTreeMap<String, MlsHistoryBackupJob>,
        key: &str,
        epoch: u64,
    ) -> (bool, String) {
        let snap = snapshot(epoch);
        let digest = mls_snapshot_digest(&snap);
        let spawned = upsert_mls_history_backup_job(
            jobs,
            key,
            "https://soland.example".into(),
            "token".into(),
            "did:web:alice.example".into(),
            "ak:device:01964137-0000-7000-8000-000000000001".into(),
            "ak:realm:01964137-0000-7000-8000-000000000001".into(),
            snap,
            digest.clone(),
        );
        (spawned, digest)
    }

    #[test]
    fn schedule_dedupes_and_single_flights() {
        let mut jobs = BTreeMap::new();
        // First schedule spawns the loop.
        let (spawned, digest) = upsert(&mut jobs, "k", 1);
        assert!(spawned);
        // Same digest while scheduled: no second loop.
        let (spawned_again, _) = upsert(&mut jobs, "k", 1);
        assert!(!spawned_again);
        assert!(jobs.get("k").unwrap().scheduled);
        // Already-uploaded digest: nothing to do at all.
        jobs.get_mut("k").unwrap().scheduled = false;
        jobs.get_mut("k").unwrap().last_uploaded_digest = Some(digest);
        // NOTE: same epoch re-encrypts to a different envelope (fresh salt /
        // recorded_at), so re-derive the uploaded digest instead of epoch reuse.
        let latest = jobs.get("k").unwrap().latest_digest.clone();
        jobs.get_mut("k").unwrap().last_uploaded_digest = Some(latest.clone());
        let snap = jobs
            .get("k")
            .unwrap()
            .payload
            .latest_snapshot
            .clone()
            .unwrap();
        let spawned_third = upsert_mls_history_backup_job(
            &mut jobs,
            "k",
            "https://soland.example".into(),
            "token".into(),
            "did:web:alice.example".into(),
            "ak:device:01964137-0000-7000-8000-000000000001".into(),
            "ak:realm:01964137-0000-7000-8000-000000000001".into(),
            snap,
            latest,
        );
        assert!(!spawned_third);
        assert!(!jobs.get("k").unwrap().scheduled);
        // A NEW digest while idle re-arms the loop and resets the backoff.
        jobs.get_mut("k").unwrap().consecutive_failures = 3;
        let (respawned, _) = upsert(&mut jobs, "k", 2);
        assert!(respawned);
        assert_eq!(jobs.get("k").unwrap().consecutive_failures, 0);
    }
}
