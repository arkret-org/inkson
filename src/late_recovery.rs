//! Round R2/R3 (T16) — late key recovery user-facing helpers.
//!
//! When the backend transitions a previously-undecryptable event to
//! `late_recovered` (e.g. an MLS welcome arrived after the messages were
//! delivered, so the client now has the epoch keys for older ciphertext),
//! the timeline / chat view MUST surface a banner so the user understands
//! why old messages just popped into view:
//!
//! > "Older messages were just decrypted, X minutes after they arrived."
//!
//! Two extra requirements from spec §4 (Round R2/R3 close-out):
//!
//! 1. If the *actor* who would have written the message was already
//!    revoked / removed before the keys arrived, the server REJECTS the
//!    decrypt (`late_recovery_rejected_membership`). The client also
//!    filters defensively — see [`should_filter_recovered_event`] — so a
//!    misconfigured server can't dribble revoked-actor content into the
//!    UI.
//! 2. The banner message is i18n'd; the actual translation lives in
//!    [`crate::i18n`] under `timeline.late_recovery.banner`. This module
//!    only owns the projection + the minutes computation.

use chrono::{DateTime, Duration, Utc};

/// One late-recovered event surfaced to the timeline. Constructed from
/// the server's `recovery.recovered_at` + the event's
/// `original_received_at` timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LateRecoveredEvent {
    pub event_id: String,
    pub actor_did: String,
    /// When the event originally landed at the client (encrypted but
    /// undecryptable).
    pub original_received_at: DateTime<Utc>,
    /// When the late-recovery decrypt succeeded.
    pub recovered_at: DateTime<Utc>,
    /// True iff the actor was revoked / removed before
    /// `recovered_at`. Forces the defensive client-side filter.
    pub actor_revoked_at_recovery: bool,
}

impl LateRecoveredEvent {
    /// Lag between original arrival and successful late decrypt, rounded
    /// down to whole minutes for display. Always >= 0.
    pub fn lag_minutes(&self) -> i64 {
        let raw = self
            .recovered_at
            .signed_duration_since(self.original_received_at);
        raw.max(Duration::zero()).num_minutes()
    }

    /// Format the user-facing banner string. The i18n layer should call
    /// this with a translation template like
    /// `"Older messages were just decrypted, {minutes} minute(s) after they arrived."`
    /// and substitute the numeric value. The default template here is
    /// English-only.
    pub fn banner_text(&self) -> String {
        let mins = self.lag_minutes();
        if mins <= 1 {
            "Older messages were just decrypted, about a minute after they arrived.".to_owned()
        } else if mins < 60 {
            format!("Older messages were just decrypted, {mins} minutes after they arrived.")
        } else {
            let hours = mins / 60;
            format!("Older messages were just decrypted, about {hours} hour(s) after they arrived.")
        }
    }
}

/// Defensive client-side filter for late-recovered content. The server
/// already rejects late-recovery decrypts whose actor was revoked /
/// removed before the recovery completed (`late_recovery_rejected_membership`).
/// This helper enforces the same boundary client-side so a misconfigured
/// or compromised server cannot surface the recovered content anyway.
pub fn should_filter_recovered_event(event: &LateRecoveredEvent) -> bool {
    event.actor_revoked_at_recovery
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ev(orig_min: i64, rec_min: i64, revoked: bool) -> LateRecoveredEvent {
        let base = Utc.with_ymd_and_hms(2026, 5, 20, 0, 0, 0).unwrap();
        LateRecoveredEvent {
            event_id: "cx:event:01904100-0000-7000-8000-000000000001".to_owned(),
            actor_did: "did:web:alice.example".to_owned(),
            original_received_at: base + Duration::minutes(orig_min),
            recovered_at: base + Duration::minutes(rec_min),
            actor_revoked_at_recovery: revoked,
        }
    }

    #[test]
    fn lag_minutes_is_non_negative() {
        let e = ev(10, 5, false);
        assert_eq!(e.lag_minutes(), 0);
    }

    #[test]
    fn lag_minutes_computes_diff() {
        let e = ev(0, 30, false);
        assert_eq!(e.lag_minutes(), 30);
    }

    #[test]
    fn banner_text_pluralises() {
        assert!(ev(0, 30, false).banner_text().contains("30"));
        assert!(ev(0, 1, false).banner_text().contains("about a minute"));
        assert!(ev(0, 180, false).banner_text().contains("hour"));
    }

    #[test]
    fn revoked_actor_is_filtered() {
        let revoked = ev(0, 30, true);
        let allowed = ev(0, 30, false);
        assert!(should_filter_recovered_event(&revoked));
        assert!(!should_filter_recovered_event(&allowed));
    }
}
