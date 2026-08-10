//! Round R2/R3 (T16) — late key recovery user-facing helpers.
//!
//! When the backend transitions a previously-undecryptable event to
//! `late_recovered` (e.g. an MLS welcome arrived after the messages were
//! delivered, so the client now has the epoch keys for older ciphertext),
//! message readers MUST surface a banner so the user understands
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
//! 2. The banner message is i18n'd by renderers; this module only owns the projection + the minutes
//!    computation.
//!
//! Round 4 (spec a77b995) — the banner is now sourced from the
//! `ak.audit.policy_access` event whose `access_kind ==
//! e2ee_late_recovery` carries
//! [`late_recovery_original_event_id`](arkret_sdk::AuditPolicyAccessPayload::late_recovery_original_event_id).
//! See [`LateRecoveredEvent::from_audit_policy_access`] for the typed
//! construction path; the renderer prefers this entry point so the
//! banner is bound to the audited recovery event id (and therefore
//! auditable).

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

/// One late-recovered event surfaced to message readers. Constructed from
/// the server's `recovery.recovered_at` + the event's
/// `original_received_at` timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LateRecoveredEvent {
    pub event_id: String,
    pub actor_id: String,
    /// When the event originally landed at the client (encrypted but
    /// undecryptable).
    pub original_received_at: DateTime<Utc>,
    /// When the late-recovery decrypt succeeded.
    pub recovered_at: DateTime<Utc>,
    /// True iff the actor was revoked / removed before
    /// `recovered_at`. Forces the defensive client-side filter.
    pub actor_revoked_at_recovery: bool,
}

/// Minimal pure guard inputs for the late -> late_recovered transition.
///
/// The caller resolves these booleans from sealed T0 membership/policy state,
/// the recovery-source policy, and disappearing/retention projections. This
/// module keeps only the fail-closed transition decision so UI and storage
/// paths share one ordering and one reason vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LateRecoveryGuardInput {
    /// Receiver was a joined Realm member at the target event's T0/epoch.
    pub receiver_joined_at_event_epoch: bool,
    /// The late key source is allowed by the Realm recovery/share policy.
    pub key_share_source_authorized: bool,
    /// Disappearing expiry has passed beyond grace for the target event.
    pub event_expired: bool,
    /// Retention policy has destroyed, or requires destroying, the content key.
    pub content_key_destroyed_by_retention: bool,
}

impl LateRecoveryGuardInput {
    pub fn expired_or_retained_out(self) -> bool {
        self.event_expired || self.content_key_destroyed_by_retention
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LateRecoveryRejection {
    Membership,
    ShareNotAuthorized,
    Expired,
}

impl LateRecoveryRejection {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Membership => arkret_sdk::ReasonCode::LATE_RECOVERY_REJECTED_MEMBERSHIP,
            Self::ShareNotAuthorized => arkret_sdk::ReasonCode::LATE_RECOVERY_SHARE_NOT_AUTHORIZED,
            Self::Expired => arkret_sdk::ReasonCode::LATE_RECOVERY_REJECTED_EXPIRED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LateRecoveryDecision {
    Accept,
    Reject(LateRecoveryRejection),
}

impl LateRecoveryDecision {
    pub const fn is_accept(self) -> bool {
        match self {
            Self::Accept => true,
            Self::Reject(_) => false,
        }
    }

    pub const fn rejection_reason_code(self) -> Option<&'static str> {
        match self {
            Self::Accept => None,
            Self::Reject(reason) => Some(reason.reason_code()),
        }
    }
}

/// Evaluate the normative late key recovery guards before moving a local
/// event from `decryption_failed` to `late_recovered`.
///
/// Guard order mirrors spec section 2.3.5: membership at T0/epoch, recovery
/// source authorization, then expiry/retention. The first failure is returned
/// so callers can log one distinguishable `late_recovery_*` reason.
pub fn evaluate_late_recovery_guards(input: LateRecoveryGuardInput) -> LateRecoveryDecision {
    if !input.receiver_joined_at_event_epoch {
        return LateRecoveryDecision::Reject(LateRecoveryRejection::Membership);
    }
    if !input.key_share_source_authorized {
        return LateRecoveryDecision::Reject(LateRecoveryRejection::ShareNotAuthorized);
    }
    if input.expired_or_retained_out() {
        return LateRecoveryDecision::Reject(LateRecoveryRejection::Expired);
    }
    LateRecoveryDecision::Accept
}

/// Decision for a concrete projection/decrypt path. `NotLateRecovery` keeps
/// ordinary first-pass decrypt behavior unchanged; `LateRecovered` means the
/// event is explicitly marked as late recovery and passed every guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LateRecoveryTransitionDecision {
    NotLateRecovery,
    LateRecovered,
    Reject(LateRecoveryRejection),
}

impl LateRecoveryTransitionDecision {
    pub const fn allows_plaintext(self) -> bool {
        matches!(self, Self::NotLateRecovery | Self::LateRecovered)
    }

    pub const fn is_late_recovery(self) -> bool {
        !matches!(self, Self::NotLateRecovery)
    }

    pub const fn rejection_reason_code(self) -> Option<&'static str> {
        match self {
            Self::Reject(reason) => Some(reason.reason_code()),
            Self::NotLateRecovery | Self::LateRecovered => None,
        }
    }
}

/// Convert a synced/projection event into the late-recovery transition
/// decision used by decrypt retry and local plaintext replay paths.
///
/// Once a late-recovery marker is present, missing membership/source evidence
/// is treated as false so the transition fails closed in spec order. Expiry and
/// retention guards reject only when the projection explicitly says the event
/// is expired or the content key has been destroyed.
pub fn evaluate_late_recovery_transition_event(event: &Value) -> LateRecoveryTransitionDecision {
    let mut contexts = Vec::new();
    collect_late_recovery_contexts(event, &mut contexts, 0);
    if !late_recovery_marker_present(&contexts) {
        return LateRecoveryTransitionDecision::NotLateRecovery;
    }

    match evaluate_late_recovery_guards(LateRecoveryGuardInput {
        receiver_joined_at_event_epoch: bool_from_contexts(
            &contexts,
            &[
                "receiver_joined_at_event_epoch",
                "receiver_member_at_event_epoch",
                "receiver_visible_at_t0",
                "receiver_joined_at_t0",
                "t0_membership_joined",
            ],
        )
        .unwrap_or(false),
        key_share_source_authorized: bool_from_contexts(
            &contexts,
            &[
                "key_share_source_authorized",
                "late_key_source_authorized",
                "source_authorized",
                "source_rechecked_current_share_policy",
                "current_share_policy_allows_delivery",
            ],
        )
        .unwrap_or(false),
        event_expired: event_expired_for_late_recovery(&contexts),
        content_key_destroyed_by_retention: bool_from_contexts(
            &contexts,
            &[
                "content_key_destroyed_by_retention",
                "retention_destroyed_content_key",
                "retention_requires_key_destroy",
                "content_key_destroyed",
            ],
        )
        .unwrap_or(false),
    }) {
        LateRecoveryDecision::Accept => LateRecoveryTransitionDecision::LateRecovered,
        LateRecoveryDecision::Reject(reason) => LateRecoveryTransitionDecision::Reject(reason),
    }
}

/// Guarded conversion for `ak.audit.policy_access` late-recovery markers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LateRecoveryAuditAccessConversion {
    NotLateRecovery,
    LateRecovered(LateRecoveredEvent),
    Reject(LateRecoveryRejection),
}

/// Build the user-facing late recovery marker from a synced
/// `ak.audit.policy_access` event only after the same late-recovery guards pass.
pub fn late_recovered_event_from_audit_policy_access_event(
    event: &Value,
    actor_revoked_at_recovery: bool,
) -> LateRecoveryAuditAccessConversion {
    let Some(payload_value) = audit_policy_access_payload_value(event) else {
        return LateRecoveryAuditAccessConversion::NotLateRecovery;
    };
    match evaluate_late_recovery_transition_event(event) {
        LateRecoveryTransitionDecision::NotLateRecovery => {
            return LateRecoveryAuditAccessConversion::NotLateRecovery;
        }
        LateRecoveryTransitionDecision::Reject(reason) => {
            return LateRecoveryAuditAccessConversion::Reject(reason);
        }
        LateRecoveryTransitionDecision::LateRecovered => {}
    }

    let Ok(payload) =
        serde_json::from_value::<arkret_sdk::AuditPolicyAccessPayload>(payload_value.clone())
    else {
        return LateRecoveryAuditAccessConversion::NotLateRecovery;
    };
    if payload.validate_minimal().is_err() {
        return LateRecoveryAuditAccessConversion::NotLateRecovery;
    }
    let original_received_at =
        timestamp_from_contexts(event, &["original_received_at", "original_arrived_at"])
            .unwrap_or(payload.observed_at);
    LateRecoveredEvent::from_audit_policy_access(
        &payload,
        original_received_at,
        actor_revoked_at_recovery,
    )
    .map(LateRecoveryAuditAccessConversion::LateRecovered)
    .unwrap_or(LateRecoveryAuditAccessConversion::NotLateRecovery)
}

fn collect_late_recovery_contexts<'a>(value: &'a Value, out: &mut Vec<&'a Value>, depth: usize) {
    if depth > 4 || !value.is_object() {
        return;
    }
    out.push(value);
    for key in [
        "payload",
        "content",
        "body",
        "data",
        "recovery",
        "late_recovery",
        "late_recovery_guards",
        "audit",
        "audit_policy_access",
        "audit_envelope",
    ] {
        if let Some(child) = value.get(key).filter(|child| child.is_object()) {
            collect_late_recovery_contexts(child, out, depth + 1);
        }
    }
}

fn late_recovery_marker_present(contexts: &[&Value]) -> bool {
    contexts.iter().any(|value| {
        value.get("late_recovery").is_some_and(|marker| {
            marker.as_bool() == Some(true) || marker.is_object() || marker.is_string()
        }) || string_from_value(value, &["access_kind"]) == Some("e2ee_late_recovery")
            || value
                .get("late_recovery_original_event_id")
                .and_then(Value::as_str)
                .is_some_and(|event_id| !event_id.trim().is_empty())
            || string_from_value(
                value,
                &["decryption_state", "crypto_state", "recovery_state"],
            )
            .is_some_and(|state| {
                matches!(
                    state,
                    "decryption_failed"
                        | "late_recovery"
                        | "late_recovered"
                        | "late_recovery_pending"
                )
            })
            || string_from_value(value, &["recovery_reason_code"]) == Some("late_key_arrival")
    })
}

fn string_from_value<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
    })
}

fn bool_from_contexts(contexts: &[&Value], keys: &[&str]) -> Option<bool> {
    contexts.iter().find_map(|value| {
        keys.iter()
            .find_map(|key| value.get(*key).and_then(Value::as_bool))
    })
}

fn event_expired_for_late_recovery(contexts: &[&Value]) -> bool {
    bool_from_contexts(
        contexts,
        &[
            "event_expired",
            "expired",
            "expiry_stub",
            "disappearing_expired",
        ],
    ) == Some(true)
        || contexts.iter().any(|value| {
            string_from_value(value, &["expiry_state", "retention_state"]).is_some_and(|state| {
                matches!(
                    state,
                    "expired" | "retention_destroyed" | "content_key_destroyed"
                )
            })
        })
}

fn timestamp_from_contexts(value: &Value, keys: &[&str]) -> Option<DateTime<Utc>> {
    let mut contexts = Vec::new();
    collect_late_recovery_contexts(value, &mut contexts, 0);
    contexts
        .iter()
        .find_map(|context| string_from_value(context, keys))
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|parsed| parsed.with_timezone(&Utc))
}

fn audit_policy_access_payload_value(event: &Value) -> Option<&Value> {
    if string_from_value(event, &["kind", "type", "event_type"]) == Some("ak.audit.policy_access") {
        return event
            .get("payload")
            .or_else(|| event.get("content"))
            .or(Some(event));
    }
    for key in ["payload", "content", "audit_policy_access"] {
        let Some(candidate) = event.get(key).filter(|candidate| candidate.is_object()) else {
            continue;
        };
        if string_from_value(candidate, &["kind", "type", "event_type"])
            == Some("ak.audit.policy_access")
            || string_from_value(candidate, &["access_kind"]) == Some("e2ee_late_recovery")
        {
            return Some(candidate);
        }
    }
    None
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
    /// Round 4 — construct from a `ak.audit.policy_access` payload
    /// whose `access_kind` is
    /// [`AccessKind::E2EELateRecovery`](arkret_sdk::AccessKind::E2EELateRecovery).
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
        payload: &arkret_sdk::AuditPolicyAccessPayload,
        original_received_at: DateTime<Utc>,
        actor_revoked_at_recovery: bool,
    ) -> Option<Self> {
        if !matches!(
            payload.access_kind,
            arkret_sdk::AccessKind::E2EELateRecovery
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
            actor_id: payload.actor.as_str().to_owned(),
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
            event_id: "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
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
        use arkret_sdk::{AccessKind, AuditPolicyAccessPayload, DidFullId, EventId, RealmId};
        let base = Utc.with_ymd_and_hms(2026, 5, 20, 0, 0, 0).unwrap();
        let payload = AuditPolicyAccessPayload {
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            actor: crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
            access_kind: AccessKind::E2EELateRecovery,
            late_recovery_original_event_id: Some(
                EventId::new("ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN").unwrap(),
            ),
            observed_at: base + Duration::minutes(30),
        };
        let ev = LateRecoveredEvent::from_audit_policy_access(&payload, base, false).unwrap();
        assert_eq!(
            ev.event_id,
            "ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN"
        );
        assert_eq!(ev.lag_minutes(), 30);
        assert!(!should_filter_recovered_event(&ev));
    }

    #[test]
    fn from_audit_policy_access_rejects_wrong_access_kind() {
        use arkret_sdk::{AccessKind, AuditPolicyAccessPayload, DidFullId, RealmId};
        let base = Utc.with_ymd_and_hms(2026, 5, 20, 0, 0, 0).unwrap();
        let payload = AuditPolicyAccessPayload {
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            actor: crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
            access_kind: AccessKind::Audit,
            late_recovery_original_event_id: None,
            observed_at: base,
        };
        assert!(LateRecoveredEvent::from_audit_policy_access(&payload, base, false).is_none());
    }

    fn base_guard_input() -> LateRecoveryGuardInput {
        LateRecoveryGuardInput {
            receiver_joined_at_event_epoch: true,
            key_share_source_authorized: true,
            event_expired: false,
            content_key_destroyed_by_retention: false,
        }
    }

    #[test]
    fn late_recovery_rejects_receiver_not_member_at_event_epoch() {
        let decision = evaluate_late_recovery_guards(LateRecoveryGuardInput {
            receiver_joined_at_event_epoch: false,
            ..base_guard_input()
        });
        assert_eq!(
            decision,
            LateRecoveryDecision::Reject(LateRecoveryRejection::Membership)
        );
        assert_eq!(
            decision.rejection_reason_code(),
            Some(arkret_sdk::ReasonCode::LATE_RECOVERY_REJECTED_MEMBERSHIP)
        );
    }

    #[test]
    fn late_recovery_rejects_unauthorized_key_share_source() {
        let decision = evaluate_late_recovery_guards(LateRecoveryGuardInput {
            key_share_source_authorized: false,
            ..base_guard_input()
        });
        assert_eq!(
            decision,
            LateRecoveryDecision::Reject(LateRecoveryRejection::ShareNotAuthorized)
        );
        assert_eq!(
            decision.rejection_reason_code(),
            Some(arkret_sdk::ReasonCode::LATE_RECOVERY_SHARE_NOT_AUTHORIZED)
        );
    }

    #[test]
    fn late_recovery_rejects_expiry_or_retention() {
        for input in [
            LateRecoveryGuardInput {
                event_expired: true,
                ..base_guard_input()
            },
            LateRecoveryGuardInput {
                content_key_destroyed_by_retention: true,
                ..base_guard_input()
            },
        ] {
            let decision = evaluate_late_recovery_guards(input);
            assert_eq!(
                decision,
                LateRecoveryDecision::Reject(LateRecoveryRejection::Expired)
            );
            assert_eq!(
                decision.rejection_reason_code(),
                Some(arkret_sdk::ReasonCode::LATE_RECOVERY_REJECTED_EXPIRED)
            );
        }
    }

    #[test]
    fn late_recovery_accepts_when_all_guards_pass() {
        let decision = evaluate_late_recovery_guards(base_guard_input());
        assert!(decision.is_accept());
        assert_eq!(decision.rejection_reason_code(), None);
    }

    #[test]
    fn transition_event_rejects_in_spec_order() {
        let both_membership_and_share_fail = serde_json::json!({
            "kind": "ak.message.create",
            "decryption_state": "decryption_failed",
            "late_recovery": {
                "receiver_visible_at_t0": false,
                "source_rechecked_current_share_policy": false,
                "event_expired": true
            }
        });
        assert_eq!(
            evaluate_late_recovery_transition_event(&both_membership_and_share_fail),
            LateRecoveryTransitionDecision::Reject(LateRecoveryRejection::Membership)
        );

        let share_and_expiry_fail = serde_json::json!({
            "kind": "ak.message.create",
            "decryption_state": "decryption_failed",
            "late_recovery": {
                "receiver_visible_at_t0": true,
                "source_rechecked_current_share_policy": false,
                "event_expired": true
            }
        });
        assert_eq!(
            evaluate_late_recovery_transition_event(&share_and_expiry_fail),
            LateRecoveryTransitionDecision::Reject(LateRecoveryRejection::ShareNotAuthorized)
        );

        let expiry_fails_last = serde_json::json!({
            "kind": "ak.message.create",
            "decryption_state": "decryption_failed",
            "late_recovery": {
                "receiver_visible_at_t0": true,
                "source_rechecked_current_share_policy": true,
                "event_expired": true
            }
        });
        assert_eq!(
            evaluate_late_recovery_transition_event(&expiry_fails_last),
            LateRecoveryTransitionDecision::Reject(LateRecoveryRejection::Expired)
        );
    }

    #[test]
    fn transition_event_accepts_only_marked_late_recovery() {
        let ordinary = serde_json::json!({
            "kind": "ak.message.create",
            "content": {"encrypted_content": true}
        });
        assert_eq!(
            evaluate_late_recovery_transition_event(&ordinary),
            LateRecoveryTransitionDecision::NotLateRecovery
        );

        let late = serde_json::json!({
            "kind": "ak.message.create",
            "decryption_state": "decryption_failed",
            "late_recovery": {
                "receiver_visible_at_t0": true,
                "source_rechecked_current_share_policy": true,
                "event_expired": false,
                "content_key_destroyed_by_retention": false
            }
        });
        assert_eq!(
            evaluate_late_recovery_transition_event(&late),
            LateRecoveryTransitionDecision::LateRecovered
        );
    }

    #[test]
    fn audit_policy_access_conversion_is_guarded() {
        let base = Utc.with_ymd_and_hms(2026, 5, 20, 0, 0, 0).unwrap();
        let event = serde_json::json!({
            "kind": "ak.audit.policy_access",
            "event_id": "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
            "original_received_at": "2026-05-19T23:45:00.000Z",
            "late_recovery": {
                "receiver_visible_at_t0": true,
                "source_rechecked_current_share_policy": true
            },
            "payload": {
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "actor": "did:web:alice.example",
                "access_kind": "e2ee_late_recovery",
                "late_recovery_original_event_id": "ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN",
                "observed_at": arkret_sdk::canonical::format_timestamp_canonical(base)
            }
        });

        let conversion = late_recovered_event_from_audit_policy_access_event(&event, false);
        match conversion {
            LateRecoveryAuditAccessConversion::LateRecovered(recovered) => {
                assert_eq!(
                    recovered.event_id,
                    "ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN"
                );
                assert_eq!(recovered.lag_minutes(), 15);
            }
            other => panic!("expected guarded audit conversion, got {other:?}"),
        }

        let rejected = serde_json::json!({
            "kind": "ak.audit.policy_access",
            "late_recovery": {
                "receiver_visible_at_t0": false,
                "source_rechecked_current_share_policy": true
            },
            "payload": {
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "actor": "did:web:alice.example",
                "access_kind": "e2ee_late_recovery",
                "late_recovery_original_event_id": "ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN",
                "observed_at": arkret_sdk::canonical::format_timestamp_canonical(base)
            }
        });
        assert_eq!(
            late_recovered_event_from_audit_policy_access_event(&rejected, false),
            LateRecoveryAuditAccessConversion::Reject(LateRecoveryRejection::Membership)
        );
    }
}
