use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::*;
use serde_json::Value;

use super::types::CallParticipant;
use crate::views::helpers::short_protocol_id;

pub(super) fn operation_body(payload: &Value) -> &Value {
    payload
        .get("body")
        .or_else(|| payload.get("payload"))
        .unwrap_or(payload)
}

/// Derive the realm's anchored media-service DIDs and preferred focus from
/// the local `ck.realm.media_service` projection.
pub(super) fn media_service_selection(
    state: &crate::local_state::ClientLocalState,
    realm_id: &str,
) -> (Vec<String>, String) {
    let mut dids = BTreeSet::new();
    let mut focus_ids = Vec::<String>::new();
    for record in &state.raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if kind != "ck.realm.media_service" || record.realm_id.as_deref() != Some(realm_id) {
            continue;
        }
        let body = operation_body(&record.payload);
        if let Some(service_id) = body.get("service_id").and_then(|v| v.as_str()) {
            dids.insert(service_id.to_owned());
        }
        if let Some(foci) = body.get("foci").and_then(|v| v.as_array()) {
            for focus in foci {
                let Some(focus_id) = focus.get("focus_id").and_then(|v| v.as_str()) else {
                    continue;
                };
                if !focus_id.trim().is_empty() && !focus_ids.iter().any(|known| known == focus_id) {
                    focus_ids.push(focus_id.to_owned());
                }
            }
        }
    }
    let media_dids: Vec<String> = dids.into_iter().collect();
    let focus_id = focus_ids
        .into_iter()
        .next()
        .unwrap_or_else(|| default_focus_id(&media_dids));
    (media_dids, focus_id)
}

/// Fallback used only before the media-service projection is hydrated. A
/// real media join still fails closed when the anchored issuer DID set is
/// empty.
pub(super) fn default_focus_id(media_dids: &[String]) -> String {
    media_dids
        .first()
        .and_then(|did| did.rsplit(':').next())
        .map(|host| host.to_owned())
        .unwrap_or_else(|| "default".to_owned())
}

pub(super) fn participant_list_from_input(input: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    input
        .split(['\n', ',', ';'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| seen.insert((*value).to_owned()))
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn call_state_participant_identities(
    state: &crate::local_state::ClientLocalState,
    realm_id: &str,
    call_id: &str,
) -> BTreeSet<String> {
    let mut identities = BTreeSet::new();
    for record in &state.raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if kind != "ck.call.state" || record.realm_id.as_deref() != Some(realm_id) {
            continue;
        }
        let body = operation_body(&record.payload);
        if body.get("call_id").and_then(|v| v.as_str()) != Some(call_id) {
            continue;
        }
        let Some(participants) = body.get("participants").and_then(|v| v.as_array()) else {
            continue;
        };
        for participant in participants {
            if let Some(identity) = participant
                .get("participant_identity")
                .and_then(|v| v.as_str())
                && !identity.trim().is_empty()
            {
                identities.insert(identity.to_owned());
            }
        }
    }
    identities
}

/// Read the `participant_identity → device_id` map from the durable
/// `ck.call.state.participants[]` projection for this call. Used to build a
/// remote sender's SFrame [`FrameKeyContext`] (`media-service-binding.md` §8.1
/// binds the sender's own `(participant_identity, device_id)`): when a remote
/// connects, its `device_id` is looked up here so the receiver can recompute
/// that sender's frame key from the shared MLS exporter. Entries missing either
/// field are skipped (the remote's key cannot be derived → fail-closed for that
/// one remote).
pub(super) fn call_state_participant_device_map(
    state: &crate::local_state::ClientLocalState,
    realm_id: &str,
    call_id: &str,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for record in &state.raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if kind != "ck.call.state" || record.realm_id.as_deref() != Some(realm_id) {
            continue;
        }
        let body = operation_body(&record.payload);
        if body.get("call_id").and_then(|v| v.as_str()) != Some(call_id) {
            continue;
        }
        let Some(participants) = body.get("participants").and_then(|v| v.as_array()) else {
            continue;
        };
        for participant in participants {
            let identity = participant
                .get("participant_identity")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let device_id = participant
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if !identity.trim().is_empty() && !device_id.trim().is_empty() {
                map.insert(identity.to_owned(), device_id.to_owned());
            }
        }
    }
    map
}

/// Build the MEDIA-2 expected-participant identity set from durable call
/// state, seeding the local token-exchange identity before the state sync
/// loop has replayed our own write.
pub(super) fn expected_participant_set(
    durable_identities: &BTreeSet<String>,
    local_participant_identity: &str,
) -> BTreeSet<String> {
    let mut expected = durable_identities.clone();
    if !local_participant_identity.trim().is_empty() {
        expected.insert(local_participant_identity.to_owned());
    }
    expected
}

pub(super) fn build_roster(actor: &str, peers: &[String]) -> Vec<CallParticipant> {
    let mut ids = BTreeSet::new();
    let mut roster = Vec::new();
    for did in std::iter::once(actor).chain(peers.iter().map(String::as_str)) {
        let did = did.trim();
        if did.is_empty() || !ids.insert(did.to_owned()) {
            continue;
        }
        roster.push(CallParticipant {
            actor_id: did.to_owned(),
            display_name: short_protocol_id(did),
            muted: false,
            speaking: false,
            screen_sharing: false,
        });
    }
    roster
}

pub(super) fn set_local_state(
    participants: &mut Signal<Vec<CallParticipant>>,
    actor: &str,
    muted: bool,
    sharing: bool,
) {
    let mut roster = participants();
    for p in &mut roster {
        if p.actor_id == actor {
            p.muted = muted;
            p.screen_sharing = sharing;
        }
    }
    participants.set(roster);
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::views::call::CallStage;

    #[test]
    fn stage_strings_stable() {
        assert_eq!(CallStage::Idle.as_str(), "idle");
        assert_eq!(CallStage::OutgoingRinging.as_str(), "ringing");
        assert_eq!(CallStage::IncomingRinging.as_str(), "ringing");
        assert_eq!(CallStage::Connecting.as_str(), "connecting");
        assert_eq!(CallStage::Active.as_str(), "active");
        assert_eq!(CallStage::Ended.as_str(), "ended");
    }

    #[test]
    fn participant_input_dedupes() {
        assert_eq!(
            participant_list_from_input(
                "did:web:bob.example\ndid:web:carol.example, did:web:bob.example"
            ),
            vec!["did:web:bob.example", "did:web:carol.example"]
        );
    }

    #[test]
    fn roster_includes_actor_once() {
        let roster = build_roster(
            "did:web:alice.example",
            &[
                "did:web:bob.example".to_owned(),
                "did:web:alice.example".to_owned(),
            ],
        );
        assert_eq!(roster.len(), 2);
        assert_eq!(roster[0].actor_id, "did:web:alice.example");
    }

    #[test]
    fn default_focus_id_derives_from_service_did() {
        assert_eq!(
            default_focus_id(&["did:web:media.example".to_owned()]),
            "media.example"
        );
        assert_eq!(default_focus_id(&[]), "default");
    }

    #[test]
    fn media_service_selection_reads_declared_focus() {
        let mut state = crate::local_state::ClientLocalState::default();
        state
            .raw_operations
            .push(crate::local_state::RawOperationRecord {
                operation_id: "op-1".to_owned(),
                realm_id: Some("ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.realm.media_service",
                    "body": {
                        "service_id": "did:web:media.example",
                        "foci": [
                            {"focus_id": "fra-1", "type": "livekit"},
                            {"focus_id": "us-east-1", "type": "livekit"}
                        ]
                    }
                }),
            });
        let (dids, focus_id) =
            media_service_selection(&state, "ck:realm:01904100-0000-7000-8000-9b64700c6ee8");
        assert_eq!(dids, vec!["did:web:media.example"]);
        assert_eq!(focus_id, "fra-1");
    }

    #[test]
    fn call_state_participant_identities_read_sfu_handles() {
        let mut state = crate::local_state::ClientLocalState::default();
        state.raw_operations.push(crate::local_state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.call.state",
                "body": {
                    "call_id": "ck:call:0196441c-0000-7000-8000-000000000000",
                    "state": "connecting",
                    "participants": [
                        {"actor_id": "did:web:alice.example", "participant_identity": "ck:rtc_participant:alice"}
                    ]
                }
            }),
        });
        let identities = call_state_participant_identities(
            &state,
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "ck:call:0196441c-0000-7000-8000-000000000000",
        );
        assert!(identities.contains("ck:rtc_participant:alice"));
        assert!(!identities.contains("did:web:alice.example"));
    }

    #[test]
    fn call_state_participant_device_map_pairs_identity_and_device() {
        let mut state = crate::local_state::ClientLocalState::default();
        state
            .raw_operations
            .push(crate::local_state::RawOperationRecord {
                operation_id: "op-1".to_owned(),
                realm_id: Some("ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.call.state",
                    "body": {
                        "call_id": "ck:call:0196441c-0000-7000-8000-000000000000",
                        "state": "active",
                        "participants": [
                            {
                                "actor_id": "did:web:alice.example",
                                "device_id": "ck:device:01904100-0000-7000-8000-00000000000a",
                                "participant_identity": "ck:rtc_participant:alice"
                            },
                            {
                                // Missing device_id -> skipped (cannot derive its key).
                                "actor_id": "did:web:carol.example",
                                "participant_identity": "ck:rtc_participant:carol"
                            }
                        ]
                    }
                }),
            });
        let map = call_state_participant_device_map(
            &state,
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "ck:call:0196441c-0000-7000-8000-000000000000",
        );
        assert_eq!(
            map.get("ck:rtc_participant:alice").map(String::as_str),
            Some("ck:device:01904100-0000-7000-8000-00000000000a")
        );
        // The participant with no device_id is fail-closed: not in the map.
        assert!(!map.contains_key("ck:rtc_participant:carol"));
    }

    #[test]
    fn expected_participant_set_uses_rtc_identities() {
        let mut durable = BTreeSet::new();
        durable.insert("ck:rtc_participant:remote".to_owned());
        let expected = expected_participant_set(&durable, "ck:rtc_participant:self");
        assert!(expected.contains("ck:rtc_participant:self"));
        assert!(expected.contains("ck:rtc_participant:remote"));
        assert!(!expected.contains("did:web:alice.example"));
    }
}
