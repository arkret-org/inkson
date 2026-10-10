//! Disposable retry admission for an exact captured logout intent. It never
//! writes credentials, swaps holders, or equates a refused request with logout.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::{LogoutRunOutcome, PendingLogout};

type IntentId = [u8; 32];

pub(super) enum Admission {
    Attempt(Attempt),
    Deferred,
    Blocked,
    Terminated,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Blocked,
    Terminated,
}

struct Entry {
    state: State,
    running: bool,
    created_at: DateTime<Utc>,
    window_started: DateTime<Utc>,
    available_at: DateTime<Utc>,
    schedule: arkret_sdk::RetrySchedule,
}

#[derive(Default)]
struct RetryBook {
    intents: BTreeMap<IntentId, Entry>,
    // Logout has one Account Authority operation per complete account. Sharing
    // this budget across captured devices/origins is stricter than the spec's
    // actor/service/endpoint maximum, and a remount cannot reset the budget.
    budgets: BTreeMap<arkret_sdk::AccountId, VecDeque<DateTime<Utc>>>,
}

static RETRIES: OnceLock<Mutex<RetryBook>> = OnceLock::new();

fn book() -> &'static Mutex<RetryBook> {
    RETRIES.get_or_init(|| Mutex::new(RetryBook::default()))
}

fn intent_id(record: &PendingLogout) -> anyhow::Result<IntentId> {
    let mut bytes = serde_json::to_vec(record)?;
    let id = Sha256::digest(&bytes).into();
    bytes.zeroize();
    Ok(id)
}

pub(super) fn claim(record: &PendingLogout, now: DateTime<Utc>) -> anyhow::Result<Admission> {
    let id = intent_id(record)?;
    let decision = book()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .claim(record, id, now);
    Ok(match decision {
        Decision::Admitted => Admission::Attempt(Attempt {
            id,
            finished: false,
        }),
        Decision::Deferred => Admission::Deferred,
        Decision::Blocked => Admission::Blocked,
        Decision::Terminated => Admission::Terminated,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Admitted,
    Deferred,
    Blocked,
    Terminated,
}

impl RetryBook {
    fn claim(&mut self, record: &PendingLogout, id: IntentId, now: DateTime<Utc>) -> Decision {
        let policy = arkret_sdk::RetryPolicy::arkret_default();
        let window = Duration::from_std(policy.retry_window()).unwrap_or(Duration::MAX);
        self.intents.retain(|_, entry| {
            entry.running
                || now - entry.created_at < Duration::hours(super::AUTOMATIC_RETRY_MAX_AGE_HOURS)
        });
        self.budgets.retain(|_, attempts| {
            while attempts.front().is_some_and(|at| now - *at >= window) {
                attempts.pop_front();
            }
            !attempts.is_empty()
        });
        let entry = self.intents.entry(id).or_insert_with(|| Entry {
            state: State::Pending,
            running: false,
            created_at: record.created_at,
            window_started: now,
            available_at: now,
            schedule: arkret_sdk::RetrySchedule::arkret_default().with_jitter(
                policy.jitter_ratio(),
                u64::from_le_bytes([id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7]]),
            ),
        });
        match entry.state {
            State::Blocked => return Decision::Blocked,
            State::Terminated => return Decision::Terminated,
            State::Pending => {}
        }
        if entry.running || now < entry.available_at {
            return Decision::Deferred;
        }
        if now - entry.window_started >= window {
            entry.schedule.reset();
            entry.window_started = now;
        }
        let attempts = self.budgets.entry(record.authority.clone()).or_default();
        // One initial presentation and at most five automatic retries in the
        // sliding window. Distinct old journals cannot multiply that limit.
        if attempts.len() > policy.max_retries() as usize {
            return Decision::Deferred;
        }
        attempts.push_back(now);
        entry.running = true;
        Decision::Admitted
    }

    fn finish(
        &mut self,
        id: &IntentId,
        outcome: LogoutRunOutcome,
        now: DateTime<Utc>,
        hint: Option<std::time::Duration>,
    ) {
        let Some(entry) = self.intents.get_mut(id) else {
            return;
        };
        entry.running = false;
        match outcome {
            LogoutRunOutcome::Completed => entry.state = State::Terminated,
            LogoutRunOutcome::Blocked => entry.state = State::Blocked,
            LogoutRunOutcome::Retain => {
                let delay = entry.schedule.next_delay_with_hint(hint);
                entry.available_at = Duration::from_std(delay)
                    .ok()
                    .and_then(|delay| now.checked_add_signed(delay))
                    .unwrap_or(DateTime::<Utc>::MAX_UTC);
            }
        }
    }
}

pub(super) struct Attempt {
    id: IntentId,
    finished: bool,
}

impl Attempt {
    pub(super) fn finish(
        &mut self,
        outcome: LogoutRunOutcome,
        now: DateTime<Utc>,
        hint: Option<std::time::Duration>,
    ) {
        book()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .finish(&self.id, outcome, now, hint);
        self.finished = true;
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.finished {
            // Cancellation is uncertain, so retain the same captured intent
            // and apply backoff before permitting another presentation.
            book()
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .finish(&self.id, LogoutRunOutcome::Retain, Utc::now(), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_intent_is_single_flight_and_refusal_survives_remount() {
        let now = Utc::now();
        let record = super::super::tests::base_record(now);
        let id = intent_id(&record).unwrap();
        let mut book = RetryBook::default();
        assert_eq!(book.claim(&record, id, now), Decision::Admitted);
        assert_eq!(book.claim(&record, id, now), Decision::Deferred);
        book.finish(&id, LogoutRunOutcome::Blocked, now, None);
        assert_eq!(
            book.claim(&record, id, now + Duration::minutes(10)),
            Decision::Blocked
        );
        let mut replacement = record.clone();
        replacement.grant_jwt = Some("different captured grant".into());
        let new_id = intent_id(&replacement).unwrap();
        assert_ne!(id, new_id);
        assert_eq!(
            book.claim(&replacement, new_id, now + Duration::minutes(10)),
            Decision::Admitted
        );
    }

    #[test]
    fn transient_retry_obeys_sdk_hint_backoff_and_shared_sliding_budget() {
        let now = Utc::now();
        let record = super::super::tests::base_record(now);
        let id = intent_id(&record).unwrap();
        let mut book = RetryBook::default();
        assert_eq!(book.claim(&record, id, now), Decision::Admitted);
        book.finish(
            &id,
            LogoutRunOutcome::Retain,
            now,
            Some(std::time::Duration::from_secs(120)),
        );
        assert_eq!(
            book.claim(&record, id, now + Duration::seconds(119)),
            Decision::Deferred
        );
        let mut at = now + Duration::seconds(120);
        for _ in 0..5 {
            assert_eq!(book.claim(&record, id, at), Decision::Admitted);
            book.finish(&id, LogoutRunOutcome::Retain, at, None);
            let next = book.intents[&id].available_at;
            assert!(next >= at + Duration::seconds(1));
            assert_eq!(book.claim(&record, id, at), Decision::Deferred);
            at = next;
        }
        assert_eq!(book.claim(&record, id, at), Decision::Deferred);
        let mut other_device = record.clone();
        other_device.device_id =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000099").unwrap();
        assert_eq!(
            book.claim(&other_device, intent_id(&other_device).unwrap(), at),
            Decision::Deferred
        );
        assert_eq!(
            book.claim(&record, id, now + Duration::minutes(5)),
            Decision::Admitted
        );
    }
}
