//! Generic single-flight, debounced, backoff-retried backup-job scheduler.
//!
//! Recovery backup uploaders use a process-global
//! `BTreeMap<key, Job>` behind a `Mutex`, a
//! `scheduled` / `in_flight` single-flight pair, digest-based dedupe
//! (`last_uploaded_digest == latest_digest`), a debounce window, and a
//! three-state (idle / success / failure) finish transition. This module owns
//! that mechanism once. Each uploader supplies only:
//!   * its payload type `T` (credentials + the material to upload + any cached predecessor body
//!     used to chain the next upload), refreshed on schedule;
//!   * the digest it dedupes on; and
//!   * the actual network upload.
//!
//! The per-account post-write recovery job debounces, applies its configured
//! success interval, and does not retry a failed upload; strictly newer
//! material re-arms it.
//!
//! Backoff note: `garth::RetrySchedule` is a *stateful* ladder that advances on each
//! `next_delay()` call. This scheduler instead recomputes the wait each loop
//! iteration from the stored `consecutive_failures` counter — the same counter
//! the park threshold needs — and folds in the debounce and min-interval
//! floors. The stateless-recompute model is what the loop-top delay computation
//! and the exact retry ladder (asserted in unit tests) require, so the doubling
//! is kept here rather than delegated to `garth::RetrySchedule`.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use chrono::{DateTime, Utc};

/// Timing knobs for a scheduler family.
#[derive(Clone, Copy)]
pub(crate) struct BackupSchedulerConfig {
    /// Base debounce window (and the `consecutive_failures == 0` retry delay).
    pub(crate) debounce: Duration,
    /// Optional minimum spacing between successful uploads. `None` disables it
    /// (the private-plaintext job debounces only).
    pub(crate) min_interval: Option<Duration>,
    /// First-failure backoff delay; doubles per consecutive failure.
    pub(crate) retry_base: Duration,
    /// Backoff ceiling.
    pub(crate) retry_cap: Duration,
}

impl BackupSchedulerConfig {
    /// Exponential-backoff delay for the n-th consecutive failure (n ≥ 1):
    /// `retry_base * 2^(n-1)`, capped at `retry_cap`. n == 0 → debounce.
    pub(crate) fn retry_delay(&self, consecutive_failures: u32) -> Duration {
        if consecutive_failures == 0 {
            return self.debounce;
        }
        let factor = 1u32 << consecutive_failures.saturating_sub(1).min(16);
        self.retry_base.saturating_mul(factor).min(self.retry_cap)
    }

    /// Next wake-up delay for a job run: the debounce window, stretched to
    /// honour the min-interval since the last successful upload (when
    /// configured), and to the backoff window after consecutive failures.
    pub(crate) fn next_delay(
        &self,
        last_upload_at: Option<DateTime<Utc>>,
        consecutive_failures: u32,
        now: DateTime<Utc>,
    ) -> Duration {
        let mut delay = self.debounce;
        if let Some(min_interval) = self.min_interval
            && let Some(last) = last_upload_at
        {
            let min_interval = chrono::Duration::from_std(min_interval)
                .unwrap_or_else(|_| chrono::Duration::seconds(300));
            let elapsed = now.signed_duration_since(last);
            if elapsed < min_interval {
                let remaining = min_interval - elapsed;
                delay = delay.max(Duration::from_millis(
                    u64::try_from(remaining.num_milliseconds()).unwrap_or(0),
                ));
            }
        }
        delay.max(self.retry_delay(consecutive_failures))
    }
}

/// Per-key job state. `T` carries the uploader-specific payload (credentials,
/// the material to upload, and any cached predecessor body).
#[derive(Clone, Default)]
pub(crate) struct BackupJob<T> {
    pub(crate) payload: T,
    pub(crate) latest_digest: String,
    pub(crate) last_uploaded_digest: Option<String>,
    pub(crate) last_upload_at: Option<DateTime<Utc>>,
    pub(crate) consecutive_failures: u32,
    pub(crate) scheduled: bool,
    pub(crate) in_flight: bool,
}

impl<T> BackupJob<T> {
    /// The newest local material has not been uploaded yet.
    pub(crate) fn is_pending(&self) -> bool {
        !self.latest_digest.is_empty()
            && self.last_uploaded_digest.as_deref() != Some(self.latest_digest.as_str())
    }
}

/// Pure upsert used by [`BackupJobScheduler::schedule`] and unit tests: refresh
/// the payload (via `refresh`, which preserves cached fields it does not touch)
/// and the latest digest, reset the backoff, and decide whether a fresh loop
/// must be spawned (single-flight). Returns `true` iff the caller must spawn.
///
/// Dedupe: if the newest digest is already the last uploaded one, nothing is
/// scheduled.
pub(crate) fn upsert_backup_job<T: Default>(
    jobs: &mut BTreeMap<String, BackupJob<T>>,
    key: &str,
    digest: String,
    refresh: impl FnOnce(&mut T),
) -> bool {
    let job = jobs.entry(key.to_owned()).or_default();
    if job.last_uploaded_digest.as_deref() == Some(digest.as_str()) {
        return false;
    }
    refresh(&mut job.payload);
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

/// Owns the process-global job table + timing policy for one backup family.
/// Constructed as a `static` via the `const fn` constructor.
pub(crate) struct BackupJobScheduler<T: 'static> {
    jobs: Mutex<BTreeMap<String, BackupJob<T>>>,
    config: BackupSchedulerConfig,
    /// Human label for poisoned-lock diagnostics.
    label: &'static str,
}

impl<T: Clone + Default + 'static> BackupJobScheduler<T> {
    pub(crate) const fn new(label: &'static str, config: BackupSchedulerConfig) -> Self {
        Self {
            jobs: Mutex::new(BTreeMap::new()),
            config,
            label,
        }
    }

    /// COR-02: acquire the job-map lock, logging a `warn!` (instead of silently
    /// returning `None`) when the lock is poisoned so a panicked prior holder —
    /// and the consequently dropped backup step — is observable.
    fn lock(&self) -> Option<MutexGuard<'_, BTreeMap<String, BackupJob<T>>>> {
        match self.jobs.lock() {
            Ok(guard) => Some(guard),
            Err(_) => {
                tracing::warn!(
                    scheduler = self.label,
                    "backup job map lock poisoned; dropping this backup step"
                );
                None
            }
        }
    }

    /// Read-only visit of the job table (status snapshots).
    #[cfg(test)]
    pub(crate) fn with_jobs<R>(
        &self,
        f: impl FnOnce(&BTreeMap<String, BackupJob<T>>) -> R,
    ) -> Option<R> {
        self.lock().map(|jobs| f(&jobs))
    }

    #[cfg(test)]
    pub(crate) fn with_jobs_mut<R>(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, BackupJob<T>>) -> R,
    ) -> Option<R> {
        self.lock().map(|mut jobs| f(&mut jobs))
    }

    /// Schedule (or re-arm) the job for `key`. See [`upsert_backup_job`].
    pub(crate) fn schedule(&self, key: &str, digest: String, refresh: impl FnOnce(&mut T)) -> bool {
        let Some(mut jobs) = self.lock() else {
            return false;
        };
        upsert_backup_job(&mut jobs, key, digest, refresh)
    }

    /// Next wake-up delay for the job, or `None` if the job is gone.
    pub(crate) fn next_delay(&self, key: &str, now: DateTime<Utc>) -> Option<Duration> {
        let jobs = self.lock()?;
        let job = jobs.get(key)?;
        Some(
            self.config
                .next_delay(job.last_upload_at, job.consecutive_failures, now),
        )
    }

    /// Begin an attempt: clear `scheduled`, set `in_flight`, and hand back a
    /// clone of the job (whose payload the loop uploads).
    pub(crate) fn begin_attempt(&self, key: &str) -> Option<BackupJob<T>> {
        let mut jobs = self.lock()?;
        let job = jobs.get_mut(key)?;
        job.scheduled = false;
        job.in_flight = true;
        Some(job.clone())
    }

    /// Clear `in_flight` and re-arm only if the newest material is still
    /// unsent. Used by scheduler state-machine tests after
    /// [`record_success`] has advanced `last_uploaded_digest`). Returns `true`
    /// iff the loop should keep going.
    ///
    /// [`record_success`]: Self::record_success
    #[cfg(test)]
    pub(crate) fn finish_and_rearm_if_pending(&self, key: &str) -> bool {
        let Some(mut jobs) = self.lock() else {
            return false;
        };
        let Some(job) = jobs.get_mut(key) else {
            return false;
        };
        job.in_flight = false;
        if job.is_pending() {
            job.scheduled = true;
            true
        } else {
            false
        }
    }

    /// Record a successful upload: stash the uploaded digest + timestamp, reset
    /// the backoff, and let the uploader stash payload-specific state (e.g. the
    /// series tail body) via `stash`. Does NOT clear `in_flight`; the loop then
    /// calls [`finish_and_rearm_if_pending`] to advance.
    ///
    /// [`finish_and_rearm_if_pending`]: Self::finish_and_rearm_if_pending
    #[cfg(test)]
    pub(crate) fn record_success(
        &self,
        key: &str,
        uploaded_digest: String,
        stash: impl FnOnce(&mut T),
    ) {
        let now = Utc::now();
        if let Some(mut jobs) = self.lock() {
            let job = jobs.entry(key.to_owned()).or_default();
            job.last_uploaded_digest = Some(uploaded_digest);
            job.last_upload_at = Some(now);
            job.consecutive_failures = 0;
            stash(&mut job.payload);
        }
    }

    /// Failure finish for the retrying family: bump the backoff counter, run
    /// `on_failure` (e.g. drop a stale cached predecessor), clear `in_flight`,
    /// and re-arm unless the park threshold is reached. Returns `true` iff the
    /// loop should keep going (retry the same digest after a backoff wait).
    #[cfg(test)]
    pub(crate) fn finish_failure(
        &self,
        key: &str,
        max_consecutive_failures: u32,
        on_failure: impl FnOnce(&mut T),
    ) -> bool {
        let Some(mut jobs) = self.lock() else {
            return false;
        };
        let Some(job) = jobs.get_mut(key) else {
            return false;
        };
        job.in_flight = false;
        job.consecutive_failures = job.consecutive_failures.saturating_add(1);
        on_failure(&mut job.payload);
        if job.consecutive_failures >= max_consecutive_failures {
            return false;
        }
        job.scheduled = true;
        true
    }

    /// Finish an attempt for the debounce-only (non-retrying) family: run
    /// `stash` (to record a successful upload's cached body + digest, or nothing
    /// on failure/idle), clear `in_flight`, and re-arm ONLY if a digest strictly
    /// newer than `attempted_digest` arrived during the attempt. A failed upload
    /// of the current digest is NOT retried. Returns `true` iff the loop should
    /// keep going.
    pub(crate) fn finish_rerun_if_newer(
        &self,
        key: &str,
        attempted_digest: &str,
        stash: impl FnOnce(&mut BackupJob<T>),
    ) -> bool {
        let Some(mut jobs) = self.lock() else {
            return false;
        };
        let Some(job) = jobs.get_mut(key) else {
            return false;
        };
        stash(job);
        job.in_flight = false;
        if job.latest_digest != attempted_digest && job.is_pending() {
            job.scheduled = true;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct TestPayload {
        cached: Option<String>,
    }

    const TEST_CONFIG: BackupSchedulerConfig = BackupSchedulerConfig {
        debounce: Duration::from_millis(1500),
        min_interval: Some(Duration::from_secs(300)),
        retry_base: Duration::from_secs(5),
        retry_cap: Duration::from_secs(600),
    };

    static TEST_SCHEDULER: BackupJobScheduler<TestPayload> =
        BackupJobScheduler::new("test", TEST_CONFIG);

    #[test]
    fn retry_delay_backs_off_exponentially_and_caps() {
        assert_eq!(TEST_CONFIG.retry_delay(0), Duration::from_millis(1500));
        assert_eq!(TEST_CONFIG.retry_delay(1), Duration::from_secs(5));
        assert_eq!(TEST_CONFIG.retry_delay(2), Duration::from_secs(10));
        assert_eq!(TEST_CONFIG.retry_delay(3), Duration::from_secs(20));
        assert_eq!(TEST_CONFIG.retry_delay(12), Duration::from_secs(600));
        assert_eq!(TEST_CONFIG.retry_delay(40), Duration::from_secs(600));
    }

    #[test]
    fn next_delay_honours_min_interval_and_backoff() {
        let now = Utc::now();
        assert_eq!(
            TEST_CONFIG.next_delay(None, 0, now),
            Duration::from_millis(1500)
        );
        let recent = now - chrono::Duration::seconds(60);
        let delay = TEST_CONFIG.next_delay(Some(recent), 0, now);
        assert!(delay >= Duration::from_secs(230) && delay <= Duration::from_secs(240));
        let old = now - chrono::Duration::seconds(3600);
        assert_eq!(
            TEST_CONFIG.next_delay(Some(old), 0, now),
            Duration::from_millis(1500)
        );
        assert_eq!(
            TEST_CONFIG.next_delay(Some(old), 2, now),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn debounce_only_config_never_stretches_or_backs_off() {
        let cfg = BackupSchedulerConfig {
            debounce: Duration::from_millis(1500),
            min_interval: None,
            retry_base: Duration::from_millis(1500),
            retry_cap: Duration::from_millis(1500),
        };
        let now = Utc::now();
        // No min-interval stretch even right after an upload.
        assert_eq!(
            cfg.next_delay(Some(now), 0, now),
            Duration::from_millis(1500)
        );
    }

    #[test]
    fn upsert_dedupes_and_single_flights() {
        let mut jobs: BTreeMap<String, BackupJob<TestPayload>> = BTreeMap::new();
        // First schedule spawns the loop.
        assert!(upsert_backup_job(&mut jobs, "k", "d1".into(), |_| {}));
        assert!(jobs.get("k").unwrap().scheduled);
        // Same digest while scheduled: no second loop.
        assert!(!upsert_backup_job(&mut jobs, "k", "d1".into(), |_| {}));
        // Already-uploaded digest: nothing to do at all.
        jobs.get_mut("k").unwrap().scheduled = false;
        jobs.get_mut("k").unwrap().last_uploaded_digest = Some("d2".into());
        assert!(!upsert_backup_job(&mut jobs, "k", "d2".into(), |_| {}));
        assert!(!jobs.get("k").unwrap().scheduled);
        // A NEW digest while idle re-arms the loop and resets the backoff.
        jobs.get_mut("k").unwrap().consecutive_failures = 3;
        assert!(upsert_backup_job(&mut jobs, "k", "d3".into(), |_| {}));
        assert_eq!(jobs.get("k").unwrap().consecutive_failures, 0);
    }

    #[test]
    fn upsert_refresh_preserves_untouched_cached_fields() {
        let mut jobs: BTreeMap<String, BackupJob<TestPayload>> = BTreeMap::new();
        upsert_backup_job(&mut jobs, "k", "d1".into(), |p| {
            p.cached = Some("tail".into())
        });
        // A reschedule that does not touch `cached` must preserve it.
        upsert_backup_job(&mut jobs, "k", "d2".into(), |_| {});
        assert_eq!(
            jobs.get("k").unwrap().payload.cached.as_deref(),
            Some("tail")
        );
    }

    #[test]
    fn retrying_family_three_state_finish_transitions() {
        let key = "backup-job-scheduler-three-state";
        TEST_SCHEDULER.with_jobs_mut(|jobs| jobs.remove(key));

        // Seed a pending, in-flight job.
        TEST_SCHEDULER.with_jobs_mut(|jobs| {
            jobs.insert(
                key.to_owned(),
                BackupJob {
                    latest_digest: "new".into(),
                    last_uploaded_digest: Some("old".into()),
                    in_flight: true,
                    ..Default::default()
                },
            )
        });

        // Success: record advances the uploaded digest; finish sees no NEWER
        // material (latest still "new") so it does not re-arm.
        TEST_SCHEDULER.record_success(key, "new".into(), |p| p.cached = Some("body".into()));
        assert!(!TEST_SCHEDULER.finish_and_rearm_if_pending(key));
        TEST_SCHEDULER
            .with_jobs(|jobs| {
                let job = jobs.get(key).unwrap();
                assert!(!job.in_flight);
                assert_eq!(job.consecutive_failures, 0);
                assert_eq!(job.payload.cached.as_deref(), Some("body"));
            })
            .unwrap();

        // Failure: bump the counter and re-arm until the park threshold.
        TEST_SCHEDULER.with_jobs_mut(|jobs| jobs.get_mut(key).unwrap().in_flight = true);
        assert!(TEST_SCHEDULER.finish_failure(key, 5, |_| {}));
        assert_eq!(
            TEST_SCHEDULER
                .with_jobs(|jobs| jobs.get(key).unwrap().consecutive_failures)
                .unwrap(),
            1
        );

        // Park: at the threshold the loop stops rescheduling. Simulate a fresh
        // attempt (as `begin_attempt` would): clear `scheduled`, set in-flight.
        TEST_SCHEDULER.with_jobs_mut(|jobs| {
            let job = jobs.get_mut(key).unwrap();
            job.scheduled = false;
            job.in_flight = true;
            job.consecutive_failures = 4;
        });
        assert!(!TEST_SCHEDULER.finish_failure(key, 5, |_| {}));
        assert!(
            !TEST_SCHEDULER
                .with_jobs(|jobs| jobs.get(key).unwrap().scheduled)
                .unwrap()
        );

        TEST_SCHEDULER.with_jobs_mut(|jobs| jobs.remove(key));
    }

    #[test]
    fn debounce_only_family_reruns_only_when_newer_arrives() {
        let key = "backup-job-scheduler-rerun-if-newer";
        TEST_SCHEDULER.with_jobs_mut(|jobs| jobs.remove(key));

        // Attempted "old" while a NEWER "new" is pending → re-arm.
        TEST_SCHEDULER.with_jobs_mut(|jobs| {
            jobs.insert(
                key.to_owned(),
                BackupJob {
                    latest_digest: "new".into(),
                    last_uploaded_digest: Some("prev".into()),
                    in_flight: true,
                    ..Default::default()
                },
            )
        });
        assert!(TEST_SCHEDULER.finish_rerun_if_newer(key, "old", |job| {
            job.last_uploaded_digest = Some("old".into());
        }));

        // Attempted the current latest, nothing newer → stop (no retry).
        TEST_SCHEDULER.with_jobs_mut(|jobs| {
            let job = jobs.get_mut(key).unwrap();
            job.in_flight = true;
            job.scheduled = false;
        });
        assert!(!TEST_SCHEDULER.finish_rerun_if_newer(key, "new", |_| {}));

        TEST_SCHEDULER.with_jobs_mut(|jobs| jobs.remove(key));
    }
}
