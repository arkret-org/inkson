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
//! 1. If the *actor* who would have written the message was already revoked / removed before the
//!    keys arrived, the server REJECTS the decrypt (`late_recovery_rejected_membership`). The
//!    client also filters defensively — see [`should_filter_recovered_event`] — so a misconfigured
//!    server can't dribble revoked-actor content into the UI.
//! 2. The banner message is i18n'd; the actual translation lives in [`crate::i18n`] under
//!    `timeline.late_recovery.banner`. This module only owns the projection + the minutes
//!    computation.
//!
//! Round 4 (spec a77b995) — the banner is now sourced from the
//! `ck.audit.policy_access` event whose `access_kind ==
//! e2ee_late_recovery` carries
//! [`late_recovery_original_event_id`](cokret_sdk::AuditPolicyAccessPayload::late_recovery_original_event_id).
//! See [`LateRecoveredEvent::from_audit_policy_access`] for the typed
//! construction path; the renderer prefers this entry point so the
//! banner is bound to the audited recovery event id (and therefore
//! auditable).

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

impl LateRecoveredEvent {
    /// Round 4 — construct from a `ck.audit.policy_access` payload
    /// whose `access_kind` is
    /// [`AccessKind::E2EELateRecovery`](cokret_sdk::AccessKind::E2EELateRecovery).
    /// Returns `None` if the access_kind is not e2ee_late_recovery or
    /// the required `late_recovery_original_event_id` is missing — the
    /// SDK validator already rejects malformed payloads so callers
    /// receive a typed `payload.validate_minimal()` error before this
    /// runs; this helper only does the typed lift.
    ///
    /// `original_received_at` is the wall-clock time the original
    /// (undecryptable) event landed at the client — the caller provides
    /// it from the local ingest cache because the SDK payload carries
    /// only the recovery timestamp.
    pub fn from_audit_policy_access(
        payload: &cokret_sdk::AuditPolicyAccessPayload,
        original_received_at: DateTime<Utc>,
        actor_revoked_at_recovery: bool,
    ) -> Option<Self> {
        if !matches!(
            payload.access_kind,
            cokret_sdk::AccessKind::E2EELateRecovery
        ) {
            return None;
        }
        let event_id = payload
            .late_recovery_original_event_id
            .as_ref()?
            .as_str()
            .to_owned();
        Some(Self {
            event_id,
            actor_did: payload.actor.as_str().to_owned(),
            original_received_at,
            recovered_at: payload.observed_at,
            actor_revoked_at_recovery,
        })
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
    use chrono::TimeZone;

    use super::*;

    fn ev(orig_min: i64, rec_min: i64, revoked: bool) -> LateRecoveredEvent {
        let base = Utc.with_ymd_and_hms(2026, 5, 20, 0, 0, 0).unwrap();
        LateRecoveredEvent {
            event_id: "ck:event:01904100-0000-7000-8000-000000000001".to_owned(),
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

    #[test]
    fn from_audit_policy_access_carries_late_recovery_original_event_id() {
        use cokret_sdk::{AccessKind, AuditPolicyAccessPayload, Did, EventId, RealmId};
        let base = Utc.with_ymd_and_hms(2026, 5, 20, 0, 0, 0).unwrap();
        let payload = AuditPolicyAccessPayload {
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            actor: Did::new("did:web:alice.example").unwrap(),
            access_kind: AccessKind::E2EELateRecovery,
            late_recovery_original_event_id: Some(
                EventId::new("ck:event:01904100-0000-7000-8000-000000000007").unwrap(),
            ),
            observed_at: base + Duration::minutes(30),
        };
        let ev = LateRecoveredEvent::from_audit_policy_access(&payload, base, false).unwrap();
        assert_eq!(ev.event_id, "ck:event:01904100-0000-7000-8000-000000000007");
        assert_eq!(ev.lag_minutes(), 30);
        assert!(!should_filter_recovered_event(&ev));
    }

    #[test]
    fn from_audit_policy_access_rejects_wrong_access_kind() {
        use cokret_sdk::{AccessKind, AuditPolicyAccessPayload, Did, RealmId};
        let base = Utc.with_ymd_and_hms(2026, 5, 20, 0, 0, 0).unwrap();
        let payload = AuditPolicyAccessPayload {
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            actor: Did::new("did:web:alice.example").unwrap(),
            access_kind: AccessKind::Audit,
            late_recovery_original_event_id: None,
            observed_at: base,
        };
        assert!(LateRecoveredEvent::from_audit_policy_access(&payload, base, false).is_none());
    }
}
