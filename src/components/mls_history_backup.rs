//! Continuous `mls_history` key-backup after MLS epoch changes
//! (spec `identity/key-management.md` §7.10 — automatic continuous backup).
//!
//! Product rule: once the 24-word Recovery Key is configured, backup is
//! automatic and continuous — no manual trigger. The account MLS secret and
//! the private-plaintext sidecar already re-upload after encrypted writes
//! (`mls_backup_prompt::schedule_mls_private_plaintext_backup_after_encrypted_write`);
//! this module closes the remaining gap: re-uploading the per-Realm
//! `mls_history` group-state envelope after every accepted `ck.mls.commit`
//! (epoch advance) so a fresh device can recover up-to-date epoch material.
//!
//! Wire shape (soland-audited):
//! - `PUT /_cokret/self/keys/backups/{backup_id}`, `backup_class="mls_history"`,
//!   wrapped under the named `secret_storage` key
//!   `mls_group_secrets_backup_key` (built by
//!   [`crate::mls::persistence::MlsSnapshotEnvelope::to_key_backup_body`]).
//! - One SERIES per Realm, extended via the successor chain
//!   (`series_seq` strictly +1, `supersedes` + `supersedes_digest`) instead of
//!   minting a fresh series per upload — restore then reads ONLY the series
//!   tail per Realm, respecting soland's per-principal 24h full-ciphertext
//!   download quota (default 64).
//! - The tail envelope folds the Realm's complete recoverable group state, so
//!   no per-epoch envelope pile-up is needed.
//!
//! Job mechanics mirror the sidecar backup job (digest dedupe, debounce,
//! min-interval, single-flight) and add exponential-backoff retries plus a
//! status snapshot consumed by the `/settings/security` status panel.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use serde_json::Value;

use crate::local_state::LocalStateStore;
use crate::views::helpers::with_authed_api;

const MLS_HISTORY_BACKUP_DEBOUNCE: Duration = Duration::from_millis(1500);
const MLS_HISTORY_BACKUP_MIN_INTERVAL: Duration = Duration::from_secs(300);
const MLS_HISTORY_BACKUP_RETRY_BASE: Duration = Duration::from_secs(5);
const MLS_HISTORY_BACKUP_RETRY_CAP: Duration = Duration::from_secs(600);
/// After this many consecutive failures the job parks (stops rescheduling
/// itself). The pending state stays visible in the status snapshot and the
/// next accepted commit / schedule call re-arms the job with fresh
/// credentials and a reset failure counter.
const MLS_HISTORY_BACKUP_MAX_CONSECUTIVE_FAILURES: u32 = 5;

#[derive(Clone, Default)]
struct MlsHistoryBackupJob {
    base_url: String,
    token: String,
    actor_did: String,
    device_id: String,
    realm_id: String,
    latest_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    latest_digest: String,
    last_uploaded_digest: Option<String>,
    last_upload_at: Option<DateTime<Utc>>,
    /// Full body of the current series tail (the envelope this device last
    /// uploaded or fetched). Chaining the next successor needs the FULL
    /// predecessor body (`supersedes_digest` is computed over it), and caching
    /// it here avoids an unlock-proof read per upload.
    cached_tail_body: Option<Value>,
    consecutive_failures: u32,
    scheduled: bool,
    in_flight: bool,
}

static MLS_HISTORY_BACKUP_JOBS: LazyLock<Mutex<BTreeMap<String, MlsHistoryBackupJob>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Last terminal outcomes, kept separately from the per-realm job map so the
/// status panel can show "last failure" even after the failing job was
/// superseded by a successful upload of newer material.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MlsHistoryBackupLastOutcome {
    last_error: Option<String>,
    last_error_at: Option<DateTime<Utc>>,
    last_uploaded_at: Option<DateTime<Utc>>,
}

static MLS_HISTORY_BACKUP_LAST_OUTCOME: LazyLock<Mutex<MlsHistoryBackupLastOutcome>> =
    LazyLock::new(|| Mutex::new(MlsHistoryBackupLastOutcome::default()));

/// Status snapshot for the `/settings/security` panel.
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
    if let Ok(jobs) = MLS_HISTORY_BACKUP_JOBS.lock() {
        for job in jobs.values() {
            if !job.latest_digest.is_empty()
                && job.last_uploaded_digest.as_deref() != Some(job.latest_digest.as_str())
            {
                status.pending_realms += 1;
            }
            status.in_flight |= job.in_flight;
        }
    }
    if let Ok(last) = MLS_HISTORY_BACKUP_LAST_OUTCOME.lock() {
        status.last_error = last.last_error.clone();
        status.last_error_at = last.last_error_at.map(|at| at.to_rfc3339());
        status.last_uploaded_at = last.last_uploaded_at.map(|at| at.to_rfc3339());
    }
    status
}

fn mls_history_backup_job_key(base_url: &str, actor_did: &str, realm_id: &str) -> String {
    format!(
        "{}|{}|{}",
        base_url.trim().trim_end_matches('/'),
        actor_did.trim(),
        realm_id.trim()
    )
}

fn mls_snapshot_digest(snapshot: &crate::mls::persistence::MlsSnapshotEnvelope) -> String {
    let bytes = serde_json::to_vec(snapshot).unwrap_or_default();
    crate::canonical::sha256_digest(&bytes)
}

/// Exponential-backoff delay for the n-th consecutive failure (n ≥ 1):
/// `base * 2^(n-1)`, capped.
fn mls_history_backup_retry_delay(consecutive_failures: u32) -> Duration {
    if consecutive_failures == 0 {
        return MLS_HISTORY_BACKUP_DEBOUNCE;
    }
    let factor = 1u32 << consecutive_failures.saturating_sub(1).min(16);
    MLS_HISTORY_BACKUP_RETRY_BASE
        .saturating_mul(factor)
        .min(MLS_HISTORY_BACKUP_RETRY_CAP)
}

/// Next wake-up delay for a job run: the debounce window, stretched to honour
/// the min-interval since the last successful upload, and to the backoff
/// window after consecutive failures.
fn mls_history_backup_next_delay(
    last_upload_at: Option<DateTime<Utc>>,
    consecutive_failures: u32,
    now: DateTime<Utc>,
) -> Duration {
    let mut delay = MLS_HISTORY_BACKUP_DEBOUNCE;
    if let Some(last) = last_upload_at {
        let min_interval = chrono::Duration::from_std(MLS_HISTORY_BACKUP_MIN_INTERVAL)
            .unwrap_or_else(|_| chrono::Duration::seconds(300));
        let elapsed = now.signed_duration_since(last);
        if elapsed < min_interval {
            let remaining = min_interval - elapsed;
            delay = delay.max(Duration::from_millis(
                u64::try_from(remaining.num_milliseconds()).unwrap_or(0),
            ));
        }
    }
    delay.max(mls_history_backup_retry_delay(consecutive_failures))
}

/// Upsert the job entry for a freshly observed snapshot. Returns `true` when
/// the caller must spawn the job loop (no loop is scheduled or in flight).
/// Pure on the map so the dedupe/single-flight decision is unit-testable.
#[allow(clippy::too_many_arguments)]
fn upsert_mls_history_backup_job(
    jobs: &mut BTreeMap<String, MlsHistoryBackupJob>,
    key: &str,
    base_url: String,
    token: String,
    actor_did: String,
    device_id: String,
    realm_id: String,
    snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    digest: String,
) -> bool {
    let job = jobs.entry(key.to_owned()).or_default();
    if job.last_uploaded_digest.as_deref() == Some(digest.as_str()) {
        return false;
    }
    job.base_url = base_url;
    job.token = token;
    job.actor_did = actor_did;
    job.device_id = device_id;
    job.realm_id = realm_id;
    job.latest_snapshot = Some(snapshot);
    job.latest_digest = digest;
    // A fresh schedule carries fresh credentials — give a parked job a clean
    // backoff slate instead of inheriting stale-token failures.
    job.consecutive_failures = 0;
    if job.scheduled || job.in_flight {
        false
    } else {
        job.scheduled = true;
        true
    }
}

/// Hook: call after a `ck.mls.commit` was ACCEPTED by the server and the local
/// MLS snapshot advanced (persist-on-accept), or after a Welcome application
/// persisted a fresh snapshot. Debounced + deduped; no-op until the 24-word
/// Recovery Key flow has configured server-side recovery
/// (`mls_recovery_backup_configured`), matching the sidecar backup gate.
pub(crate) fn schedule_mls_history_backup_after_commit(
    base_url: String,
    token: String,
    actor_did: String,
    device_id: String,
    realm_id: String,
    state_store: Signal<LocalStateStore>,
) {
    if base_url.trim().is_empty()
        || token.trim().is_empty()
        || actor_did.trim().is_empty()
        || device_id.trim().is_empty()
        || realm_id.trim().is_empty()
    {
        return;
    }
    let snapshot = {
        let store = state_store.read();
        if !crate::components::mls_recovery_backup_configured(&store, &actor_did) {
            return;
        }
        let Some(snapshot) = store.mls_snapshot_for(&realm_id) else {
            return;
        };
        snapshot
    };
    let digest = mls_snapshot_digest(&snapshot);
    let key = mls_history_backup_job_key(&base_url, &actor_did, &realm_id);
    let should_spawn = match MLS_HISTORY_BACKUP_JOBS.lock() {
        Ok(mut jobs) => upsert_mls_history_backup_job(
            &mut jobs, &key, base_url, token, actor_did, device_id, realm_id, snapshot, digest,
        ),
        Err(_) => false,
    };
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
    api: &crate::api::CokretApi,
    base_url: &str,
    actor_did: &str,
    device_id: &str,
    realm_id: &str,
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
) -> anyhow::Result<String> {
    let key = mls_history_backup_job_key(base_url, actor_did, realm_id);
    let cached_tail = MLS_HISTORY_BACKUP_JOBS
        .lock()
        .ok()
        .and_then(|jobs| jobs.get(&key).and_then(|job| job.cached_tail_body.clone()));
    let previous = match cached_tail {
        Some(body) => Some(body),
        None => {
            crate::mls::account_recovery::fetch_mls_history_tail_for_realm(
                api, actor_did, device_id, realm_id,
            )
            .await?
        }
    };
    let (backup_id, body) = crate::mls::account_recovery::upload_mls_history_backup_with_previous(
        api,
        snapshot,
        actor_did,
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
    let now = Utc::now();
    if let Ok(mut jobs) = MLS_HISTORY_BACKUP_JOBS.lock() {
        let job = jobs.entry(key.to_owned()).or_default();
        job.cached_tail_body = Some(body);
        job.last_uploaded_digest = Some(mls_snapshot_digest(snapshot));
        job.last_upload_at = Some(now);
        job.consecutive_failures = 0;
    }
    if let Ok(mut last) = MLS_HISTORY_BACKUP_LAST_OUTCOME.lock() {
        last.last_uploaded_at = Some(now);
    }
}

async fn run_mls_history_backup_job(key: String) {
    loop {
        let Some(delay) = next_mls_history_backup_delay(&key) else {
            return;
        };
        crate::api::sleep_for(delay).await;
        let Some(job) = take_mls_history_backup_job_snapshot(&key) else {
            return;
        };
        if job.last_uploaded_digest.as_deref() == Some(job.latest_digest.as_str()) {
            if !finish_mls_history_backup_job_idle(&key) {
                return;
            }
            continue;
        }
        let upload_digest = job.latest_digest.clone();
        match upload_mls_history_backup_job_snapshot(job).await {
            Ok((backup_id, snapshot, body)) => {
                tracing::debug!(
                    backup_id = %backup_id,
                    "continuous mls_history backup uploaded after MLS commit"
                );
                record_mls_history_backup_uploaded(&key, &snapshot, body);
                if !finish_mls_history_backup_job_success(&key, &upload_digest) {
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

fn next_mls_history_backup_delay(key: &str) -> Option<Duration> {
    let jobs = MLS_HISTORY_BACKUP_JOBS.lock().ok()?;
    let job = jobs.get(key)?;
    Some(mls_history_backup_next_delay(
        job.last_upload_at,
        job.consecutive_failures,
        Utc::now(),
    ))
}

fn take_mls_history_backup_job_snapshot(key: &str) -> Option<MlsHistoryBackupJob> {
    let mut jobs = MLS_HISTORY_BACKUP_JOBS.lock().ok()?;
    let job = jobs.get_mut(key)?;
    job.scheduled = false;
    job.in_flight = true;
    Some(job.clone())
}

/// Latest digest already uploaded — clear in-flight; keep looping only when a
/// NEWER digest arrived while we were checking.
fn finish_mls_history_backup_job_idle(key: &str) -> bool {
    let Ok(mut jobs) = MLS_HISTORY_BACKUP_JOBS.lock() else {
        return false;
    };
    let Some(job) = jobs.get_mut(key) else {
        return false;
    };
    job.in_flight = false;
    if job.last_uploaded_digest.as_deref() != Some(job.latest_digest.as_str()) {
        job.scheduled = true;
        true
    } else {
        false
    }
}

fn finish_mls_history_backup_job_success(key: &str, uploaded_digest: &str) -> bool {
    let Ok(mut jobs) = MLS_HISTORY_BACKUP_JOBS.lock() else {
        return false;
    };
    let Some(job) = jobs.get_mut(key) else {
        return false;
    };
    job.in_flight = false;
    // `record_mls_history_backup_uploaded` already stored the uploaded digest
    // and tail body; rerun only if newer material arrived during the upload.
    if job.latest_digest != uploaded_digest
        && job.last_uploaded_digest.as_deref() != Some(job.latest_digest.as_str())
    {
        job.scheduled = true;
        true
    } else {
        false
    }
}

/// Failure: bump the backoff counter, surface the error to the status panel,
/// and reschedule — unless the park threshold is reached (the pending digest
/// stays visible and the next schedule call re-arms the job).
fn finish_mls_history_backup_job_failure(key: &str, error: &str) -> bool {
    let now = Utc::now();
    if let Ok(mut last) = MLS_HISTORY_BACKUP_LAST_OUTCOME.lock() {
        last.last_error = Some(error.to_owned());
        last.last_error_at = Some(now);
    }
    let Ok(mut jobs) = MLS_HISTORY_BACKUP_JOBS.lock() else {
        return false;
    };
    let Some(job) = jobs.get_mut(key) else {
        return false;
    };
    job.in_flight = false;
    job.consecutive_failures = job.consecutive_failures.saturating_add(1);
    // A series conflict means our cached predecessor no longer matches the
    // server's chain (e.g. a sibling device extended it, or a rotation opened
    // a fresh series and deleted ours). Drop the cache so the retry re-reads
    // the real tail instead of failing forever.
    if error.contains("series") {
        job.cached_tail_body = None;
    }
    if job.consecutive_failures >= MLS_HISTORY_BACKUP_MAX_CONSECUTIVE_FAILURES {
        return false;
    }
    job.scheduled = true;
    true
}

async fn upload_mls_history_backup_job_snapshot(
    job: MlsHistoryBackupJob,
) -> anyhow::Result<(
    String,
    crate::mls::persistence::MlsSnapshotEnvelope,
    Value,
)> {
    let snapshot = job
        .latest_snapshot
        .clone()
        .ok_or_else(|| anyhow::anyhow!("mls_history backup job has no snapshot"))?;
    let snapshot_for_upload = snapshot.clone();
    let (backup_id, body) = with_authed_api(&job.base_url, job.token.clone(), |api| async move {
        let previous = match job.cached_tail_body {
            Some(body) => Some(body),
            None => {
                crate::mls::account_recovery::fetch_mls_history_tail_for_realm(
                    &api,
                    &job.actor_did,
                    &job.device_id,
                    &job.realm_id,
                )
                .await?
            }
        };
        crate::mls::account_recovery::upload_mls_history_backup_with_previous(
            &api,
            &snapshot_for_upload,
            &job.actor_did,
            &job.device_id,
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
            "ck:realm:01964137-0000-7000-8000-000000000001",
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
            "ck:device:01964137-0000-7000-8000-000000000001".into(),
            "ck:realm:01964137-0000-7000-8000-000000000001".into(),
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
        let snap = jobs.get("k").unwrap().latest_snapshot.clone().unwrap();
        let spawned_third = upsert_mls_history_backup_job(
            &mut jobs,
            "k",
            "https://soland.example".into(),
            "token".into(),
            "did:web:alice.example".into(),
            "ck:device:01964137-0000-7000-8000-000000000001".into(),
            "ck:realm:01964137-0000-7000-8000-000000000001".into(),
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

    #[test]
    fn retry_delay_backs_off_exponentially_and_caps() {
        assert_eq!(
            mls_history_backup_retry_delay(0),
            MLS_HISTORY_BACKUP_DEBOUNCE
        );
        assert_eq!(mls_history_backup_retry_delay(1), Duration::from_secs(5));
        assert_eq!(mls_history_backup_retry_delay(2), Duration::from_secs(10));
        assert_eq!(mls_history_backup_retry_delay(3), Duration::from_secs(20));
        assert_eq!(
            mls_history_backup_retry_delay(12),
            MLS_HISTORY_BACKUP_RETRY_CAP
        );
        assert_eq!(
            mls_history_backup_retry_delay(40),
            MLS_HISTORY_BACKUP_RETRY_CAP
        );
    }

    #[test]
    fn next_delay_honours_min_interval_and_backoff() {
        let now = Utc::now();
        // No prior upload, no failures: plain debounce.
        assert_eq!(
            mls_history_backup_next_delay(None, 0, now),
            MLS_HISTORY_BACKUP_DEBOUNCE
        );
        // Recent upload: wait out the remaining min-interval.
        let recent = now - chrono::Duration::seconds(60);
        let delay = mls_history_backup_next_delay(Some(recent), 0, now);
        assert!(delay >= Duration::from_secs(230) && delay <= Duration::from_secs(240));
        // Old upload: back to debounce.
        let old = now - chrono::Duration::seconds(3600);
        assert_eq!(
            mls_history_backup_next_delay(Some(old), 0, now),
            MLS_HISTORY_BACKUP_DEBOUNCE
        );
        // Failures stretch the wait even right after an old upload.
        assert_eq!(
            mls_history_backup_next_delay(Some(old), 2, now),
            Duration::from_secs(10)
        );
    }
}
