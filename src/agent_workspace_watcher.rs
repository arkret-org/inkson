//! `cx.profile.agent_workspace.v1` cross-Space watcher.
//!
//! Spec: `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md §4.3 / §4.8`
//! (observe-then-write reconciliation pattern).
//!
//! This module exposes the **detection protocol** the client uses to map
//! cross-Space source events to the corresponding mirror-Space FSM
//! transition Moves. Three observed source-Space event shapes drive
//! mirror-Space transitions:
//!
//!   - `cx.redaction(target=mention_redirect)` → `transparency` cell
//!     transitions `ok → lost` for the mapped agent_task.
//!   - `cx.capability.revoke(grant=<agent_grant>)` → `source_authority`
//!     cell transitions `ok → revoked` for every agent_task that targets
//!     that agent in any mirror Space owned by the controller.
//!   - `cx.member.state(actor=<agent>, state=removed)` → same as
//!     capability revoke.
//!
//! All transitions follow the **read-then-write** protocol: the watcher
//! MUST first read the cell's current head, then write a transition
//! whose `from` matches that head. FSM `from` precondition combined with
//! `from = <current head>` is what makes multi-watcher concurrent calls
//! idempotent. See spec §4.8.
//!
//! The full integration into yougen's sync loop (subscribing to source
//! Space events, picking the matching agent_task, signing & submitting
//! the transition Move) is tracked in `contrix-spec/_todos.md` AW-3.11
//! follow-up. This module supplies the **classification logic** so that
//! integration is a small mechanical step: feed each anchored source
//! event through `classify_source_event`, dispatch the returned
//! `WatcherIntent` against the mirror Move builder.

use serde_json::Value;

/// What the watcher MUST do in response to an observed source-Space event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatcherIntent {
    /// Map all of `agent_task_ids` (in this controller's mirror Space) to
    /// `transparency.transition(from=ok, to=lost, evidence=[<source_event_id>])`.
    /// Read-then-write: caller MUST read each task's transparency cell head
    /// before writing; if already `lost` or `reconfirmed_after_loss`, no-op.
    MarkTransparencyLost {
        source_event_id: String,
        redirect_pair_id: String,
    },
    /// Map all agent_tasks in mirror Spaces whose `target_agent_id` matches
    /// the revoked grant subject to `source_authority.transition(from=ok,
    /// to=revoked, evidence=[<source_event_id>])`.
    MarkSourceAuthorityRevoked {
        source_event_id: String,
        agent_did: String,
        reason: SourceAuthorityRevokeReason,
    },
    /// No-op: event is not relevant to any local mirror Space task.
    NoOp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceAuthorityRevokeReason {
    /// Triggered by `cx.capability.revoke`.
    CapabilityRevoke,
    /// Triggered by `cx.member.state(state=removed)`.
    MemberRemoved,
}

/// Classify a single anchored source-Space event into a [`WatcherIntent`].
///
/// `event_kind` and `payload` are the wire kind + payload as carried in the
/// source Space's event log. The watcher driver iterates over anchored
/// events from the source Space and feeds each through this function.
///
/// **Filter narrowness**: this function is intentionally narrow — it only
/// produces a [`WatcherIntent`] for the three kinds defined in the spec.
/// Any other event kind returns [`WatcherIntent::NoOp`]. Callers MAY
/// short-circuit on the kind string before calling.
pub fn classify_source_event(event_id: &str, event_kind: &str, payload: &Value) -> WatcherIntent {
    match event_kind {
        "cx.redaction" => classify_redaction(event_id, payload),
        "cx.capability.revoke" => classify_capability_revoke(event_id, payload),
        "cx.member.state" => classify_member_state(event_id, payload),
        _ => WatcherIntent::NoOp,
    }
}

fn classify_redaction(event_id: &str, payload: &Value) -> WatcherIntent {
    // We only care about redactions whose target carries a
    // mention_redirect content block. The exact wire shape depends on
    // redaction payload (which references the redacted event); the
    // most precise signal is the `redirect_pair_id` on the redacted
    // mention_redirect content. The caller MUST resolve the target
    // event and pass the pair_id; if either is absent, we cannot map.
    let redirect_pair_id = payload
        .pointer("/redacted_mention_redirect/redirect_pair_id")
        .and_then(Value::as_str);
    match redirect_pair_id {
        Some(pair_id) => WatcherIntent::MarkTransparencyLost {
            source_event_id: event_id.to_owned(),
            redirect_pair_id: pair_id.to_owned(),
        },
        None => WatcherIntent::NoOp,
    }
}

fn classify_capability_revoke(event_id: &str, payload: &Value) -> WatcherIntent {
    let agent_did = payload
        .pointer("/grant_subject")
        .and_then(Value::as_str)
        .or_else(|| payload.pointer("/subject").and_then(Value::as_str));
    match agent_did {
        Some(did) if did.starts_with("did:") => WatcherIntent::MarkSourceAuthorityRevoked {
            source_event_id: event_id.to_owned(),
            agent_did: did.to_owned(),
            reason: SourceAuthorityRevokeReason::CapabilityRevoke,
        },
        _ => WatcherIntent::NoOp,
    }
}

fn classify_member_state(event_id: &str, payload: &Value) -> WatcherIntent {
    let state = payload.pointer("/state").and_then(Value::as_str);
    if state != Some("removed") {
        return WatcherIntent::NoOp;
    }
    let actor = payload
        .pointer("/actor_id")
        .and_then(Value::as_str)
        .or_else(|| payload.pointer("/actor").and_then(Value::as_str));
    match actor {
        Some(did) if did.starts_with("did:") => WatcherIntent::MarkSourceAuthorityRevoked {
            source_event_id: event_id.to_owned(),
            agent_did: did.to_owned(),
            reason: SourceAuthorityRevokeReason::MemberRemoved,
        },
        _ => WatcherIntent::NoOp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unrelated_event_kinds_are_noop() {
        let result =
            classify_source_event("cx:event:01", "cx.message.create", &json!({ "body": "hi" }));
        assert_eq!(result, WatcherIntent::NoOp);
    }

    #[test]
    fn redaction_with_redirect_pair_id_marks_transparency_lost() {
        let result = classify_source_event(
            "cx:event:01",
            "cx.redaction",
            &json!({
                "redacted_mention_redirect": {
                    "redirect_pair_id": "01964200-0000-7000-8000-aaaaaaaaaaaa"
                }
            }),
        );
        match result {
            WatcherIntent::MarkTransparencyLost {
                source_event_id,
                redirect_pair_id,
            } => {
                assert_eq!(source_event_id, "cx:event:01");
                assert_eq!(redirect_pair_id, "01964200-0000-7000-8000-aaaaaaaaaaaa");
            }
            other => panic!("expected MarkTransparencyLost, got {other:?}"),
        }
    }

    #[test]
    fn redaction_without_redirect_pair_id_is_noop() {
        let result = classify_source_event(
            "cx:event:01",
            "cx.redaction",
            &json!({ "target": "cx:event:02" }),
        );
        assert_eq!(result, WatcherIntent::NoOp);
    }

    #[test]
    fn capability_revoke_marks_source_authority_revoked() {
        let result = classify_source_event(
            "cx:event:02",
            "cx.capability.revoke",
            &json!({ "grant_subject": "did:web:agent.example" }),
        );
        match result {
            WatcherIntent::MarkSourceAuthorityRevoked {
                source_event_id,
                agent_did,
                reason,
            } => {
                assert_eq!(source_event_id, "cx:event:02");
                assert_eq!(agent_did, "did:web:agent.example");
                assert_eq!(reason, SourceAuthorityRevokeReason::CapabilityRevoke);
            }
            other => panic!("expected MarkSourceAuthorityRevoked, got {other:?}"),
        }
    }

    #[test]
    fn member_state_removed_with_did_marks_revoked() {
        let result = classify_source_event(
            "cx:event:03",
            "cx.member.state",
            &json!({
                "actor_id": "did:web:agent.example",
                "state": "removed"
            }),
        );
        match result {
            WatcherIntent::MarkSourceAuthorityRevoked {
                reason: SourceAuthorityRevokeReason::MemberRemoved,
                agent_did,
                ..
            } => assert_eq!(agent_did, "did:web:agent.example"),
            other => panic!("expected MemberRemoved variant, got {other:?}"),
        }
    }

    #[test]
    fn member_state_added_is_noop() {
        // Only `state=removed` triggers source_authority revoke; "joined"
        // / "active" / etc. are normal membership events.
        let result = classify_source_event(
            "cx:event:04",
            "cx.member.state",
            &json!({
                "actor_id": "did:web:agent.example",
                "state": "joined"
            }),
        );
        assert_eq!(result, WatcherIntent::NoOp);
    }

    #[test]
    fn classify_does_not_panic_on_malformed_payload() {
        // Defensive: any well-formed JSON Value must be safe to feed.
        let inputs = [json!(null), json!(0), json!("scalar"), json!([]), json!({})];
        for kind in ["cx.redaction", "cx.capability.revoke", "cx.member.state"] {
            for payload in &inputs {
                let _ = classify_source_event("cx:event:x", kind, payload);
            }
        }
    }
}
