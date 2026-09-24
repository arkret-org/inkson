//! Pure readers over one account-subscribe frame and the Realm projections it
//! carries.
//!
//! Everything here answers a question the delivered frame already settles — does
//! this Realm entry carry durable projection state, which `(actor, device)`
//! pairs a projection's member-identity proofs name, which device signed an
//! accepted human Event — so it is decided identically on every surface. No store, transport,
//! clock or UI participates; the inputs are the decoded SDK frame types and the
//! JSON projection bodies derived from them.
//!
//! These are host projection helpers, not protocol types: they read shapes the
//! SDK defines and never construct wire objects of their own.

use std::collections::BTreeSet;

pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeFrame, AccountSubscribeFrameKind,
    AccountSubscribeSnapshotResult,
};
use arkret_wire::{DeviceId, Did, Event, project_did_to_core_id};
use serde_json::Value;

/// True when a Realm projection body carries at least one surface worth
/// persisting, as opposed to a bare presence in the frame.
pub fn realm_projection_is_durable(body: &Value) -> bool {
    const DURABLE_SURFACES: [&str; 7] = [
        "timeline",
        "state_at_window_start",
        "current",
        "baseline",
        "account_data",
        "summary",
        "member_roster",
    ];
    let Some(object) = body.as_object() else {
        return false;
    };
    DURABLE_SURFACES
        .iter()
        .any(|surface| object.get(*surface).is_some_and(|value| !value.is_null()))
        || object
            .get("unread_notifications")
            .is_some_and(|value| !value.is_null())
}

/// The authority-committed rows a Realm entry delivered.
///
/// Each full row is a `CommittedEventFullView`: the Station's `RealmCommit` plus the exact
/// Event it covers. The array is per-stream, so nothing here derives a
/// Realm-global order from it.
pub fn sync_realm_timeline_commits(body: &Value) -> Vec<Value> {
    body.get("timeline")
        .and_then(|timeline| timeline.get("commits"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The Events a Realm entry's committed rows carry, in delivery order.
pub fn sync_realm_timeline_events(body: &Value) -> Vec<Value> {
    sync_realm_timeline_commits(body)
        .into_iter()
        .filter_map(|item| item.get("event").cloned())
        .collect()
}

/// Recursively scan a projection `Value` for `ak.member.identity.update`
/// proofs, extracting `(controller_principal_id, device_id)` from each
/// `member_identity.proof.verification_method`. Depth-bounded.
pub fn collect_member_identity_proof_devices_from_value(
    value: &Value,
    depth: usize,
    out: &mut BTreeSet<(String, String)>,
) {
    const MAX_DEPTH: usize = 12;
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            if let Some(proof) = map.get("proof").and_then(Value::as_object)
                && let Some(method) = proof.get("verification_method").and_then(Value::as_str)
                && let Some((controller, device)) = split_verification_method(method)
            {
                out.insert((controller, device));
            }
            for nested in map.values() {
                collect_member_identity_proof_devices_from_value(nested, depth + 1, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_member_identity_proof_devices_from_value(item, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// Split a `did:method:identifier#device` verification-method URL into its
/// controller DID and device fragment. Returns `None` when there is no
/// fragment (no device selector).
pub fn split_verification_method(verification_method: &str) -> Option<(String, String)> {
    let (controller, fragment) = verification_method.split_once('#')?;
    let controller = controller
        .split_once('?')
        .map_or(controller, |(head, _)| head)
        .trim();
    let device = fragment.trim();
    if controller.is_empty() || device.is_empty() {
        return None;
    }
    Some((controller.to_owned(), device.to_owned()))
}

/// The device that signed an accepted human Event, when its producer proof is
/// controlled by the Event's own signing principal.
pub fn accepted_human_event_signing_device(event: &Event) -> Option<DeviceId> {
    let Some(proof) = event.producer_proof.as_ref() else {
        return None;
    };
    let (controller, fragment) = proof.verification_method.as_str().split_once('#')?;
    let controller = Did::new(controller.to_owned()).ok()?;
    let controller = project_did_to_core_id(&controller).ok()?;
    if &controller != event.actor_id.signing_principal_id() {
        return None;
    }
    DeviceId::new(fragment.to_owned()).ok()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_bare_realm_presence_is_not_a_durable_projection() {
        assert!(!realm_projection_is_durable(&json!({})));
        assert!(!realm_projection_is_durable(&json!({"timeline": null})));
        assert!(realm_projection_is_durable(
            &json!({"summary": {"title": "x"}})
        ));
        assert!(realm_projection_is_durable(&json!({"current": []})));
    }

    #[test]
    fn timeline_events_are_read_out_of_committed_rows() {
        let body = json!({
            "timeline": {
                "commits": [
                    {"commit": {"stream_position": 4}, "event": {"kind": "ak.message.create"}},
                    {"commit": {"stream_position": 5}, "event": {"kind": "ak.reaction.add"}}
                ],
                "limited": false
            }
        });
        let events = sync_realm_timeline_events(&body);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["kind"], "ak.message.create");
        // Positions belong to the row's own stream and are never flattened
        // into a cross-stream sequence here.
        let commits = sync_realm_timeline_commits(&body);
        assert_eq!(commits[1]["commit"]["stream_position"], 5);
    }

    #[test]
    fn verification_method_split_requires_both_halves() {
        assert_eq!(
            split_verification_method("did:web:alice.example#ak:device:01"),
            Some((
                "did:web:alice.example".to_owned(),
                "ak:device:01".to_owned()
            ))
        );
        assert_eq!(split_verification_method("did:web:alice.example"), None);
        assert_eq!(split_verification_method("#ak:device:01"), None);
    }
}
