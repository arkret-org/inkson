use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::*;
use serde_json::Value;

use super::types::CallParticipant;
use crate::media::rtc::MediaGovernanceEvidence;
use crate::views::helpers::{handle_display_from_did, short_protocol_id};

pub(super) fn operation_body(payload: &Value) -> &Value {
    payload
        .get("body")
        .or_else(|| payload.get("payload"))
        .unwrap_or(payload)
}

fn call_state_recording_artifact_boundary(
    body: &Value,
) -> Result<(), crate::media::rtc::RtcClientError> {
    if !body_mentions_recording_artifact(body) {
        return Ok(());
    }
    if let Some(result) = body.get("recording_result")
        && value_has_backend_direct_recording_ref(result)
    {
        return Err(crate::media::rtc::RtcClientError::RecordingArtifactPipelineBypassed);
    }
    let payload: arkret_sdk::CallStatePayload = serde_json::from_value(body.clone())
        .map_err(|_| crate::media::rtc::RtcClientError::RecordingArtifactPipelineBypassed)?;
    payload
        .validate_recording_result_artifact()
        .map_err(|_| crate::media::rtc::RtcClientError::RecordingArtifactPipelineBypassed)
}

fn call_state_transcript_artifact_boundary(
    body: &Value,
) -> Result<(), crate::media::rtc::RtcClientError> {
    if !body_mentions_transcript_artifact(body) {
        return Ok(());
    }
    if let Some(result) = body.get("transcript_result")
        && value_has_backend_direct_transcript_ref(result)
    {
        return Err(crate::media::rtc::RtcClientError::TranscriptionArtifactPipelineBypassed);
    }
    let payload: arkret_sdk::CallStatePayload = serde_json::from_value(body.clone())
        .map_err(|_| crate::media::rtc::RtcClientError::TranscriptionArtifactPipelineBypassed)?;
    payload
        .validate_transcript_result_storage()
        .map_err(|_| crate::media::rtc::RtcClientError::TranscriptionArtifactPipelineBypassed)
}

fn call_state_media_artifact_boundary(
    body: &Value,
) -> Result<(), crate::media::rtc::RtcClientError> {
    call_state_recording_artifact_boundary(body)?;
    call_state_transcript_artifact_boundary(body)
}

fn body_mentions_recording_artifact(body: &Value) -> bool {
    body.get("recording_result").is_some()
        || matches!(
            body.get("recording_state").and_then(Value::as_str),
            Some("ready" | "failed")
        )
}

fn body_mentions_transcript_artifact(body: &Value) -> bool {
    body.get("transcript_result").is_some()
        || matches!(
            body.get("transcript_state").and_then(Value::as_str),
            Some("stopped" | "ready" | "failed")
        )
}

fn value_has_backend_direct_recording_ref(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            let lower = value.to_ascii_lowercase();
            lower.contains("http://")
                || lower.contains("https://")
                || lower.contains("s3://")
                || lower.contains("gs://")
                || lower.contains("s3.amazonaws.com")
                || lower.contains("storage.googleapis.com")
                || lower.contains("livekit")
        }
        Value::Array(values) => values.iter().any(value_has_backend_direct_recording_ref),
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "url" | "download_url" | "recording_url" | "destination" | "external_url"
            ) || value_has_backend_direct_recording_ref(value)
        }),
        _ => false,
    }
}

fn value_has_backend_direct_transcript_ref(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            let lower = value.to_ascii_lowercase();
            lower.contains("http://")
                || lower.contains("https://")
                || lower.contains("s3://")
                || lower.contains("gs://")
                || lower.contains("s3.amazonaws.com")
                || lower.contains("storage.googleapis.com")
                || lower.contains("livekit")
        }
        Value::Array(values) => values.iter().any(value_has_backend_direct_transcript_ref),
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "url"
                    | "download_url"
                    | "transcript_url"
                    | "transcript_artifact_url"
                    | "destination"
                    | "external_url"
            ) || value_has_backend_direct_transcript_ref(value)
        }),
        _ => false,
    }
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

pub(super) fn media_governance_evidence(
    state: &crate::local_state::ClientLocalState,
    realm_id: &str,
    media_plaintext_ui_confirmed: bool,
) -> Option<MediaGovernanceEvidence> {
    let media_service_payload = latest_body_for_kind(state, realm_id, "ck.realm.media_service")?;
    let policy_components_payload =
        latest_body_for_kind(state, realm_id, "ck.realm.policy_components");
    let plaintext_visible_services_payload =
        latest_body_for_kind(state, realm_id, "ck.realm.plaintext_visible_services")
            .and_then(|body| serde_json::from_value(body).ok());
    let governance_binding = state
        .raw_operations
        .iter()
        .rev()
        .filter(|record| record.realm_id.as_deref() == Some(realm_id))
        .find_map(|record| {
            let kind = record
                .payload
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !matches!(kind, "ck.mls.commit" | "ck.mls.genesis") {
                return None;
            }
            operation_body(&record.payload)
                .get("governance_binding")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
        })?;
    Some(MediaGovernanceEvidence {
        governance_binding,
        media_service_payload,
        policy_components_payload,
        plaintext_visible_services_payload,
        media_plaintext_ui_confirmed,
    })
}

pub(super) fn media_service_decrypts_enabled(
    state: &crate::local_state::ClientLocalState,
    realm_id: &str,
) -> bool {
    latest_body_for_kind(state, realm_id, "ck.realm.policy_components")
        .as_ref()
        .and_then(|body| {
            body.get("media_service_decrypts")
                .or_else(|| body.pointer("/components/media_service_decrypts"))
                .or_else(|| body.pointer("/media/media_service_decrypts"))
        })
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn latest_body_for_kind(
    state: &crate::local_state::ClientLocalState,
    realm_id: &str,
    expected_kind: &str,
) -> Option<Value> {
    state
        .raw_operations
        .iter()
        .rev()
        .find(|record| {
            record.realm_id.as_deref() == Some(realm_id)
                && record.payload.get("kind").and_then(Value::as_str) == Some(expected_kind)
        })
        .map(|record| operation_body(&record.payload).clone())
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
        if call_state_media_artifact_boundary(body).is_err() {
            continue;
        }
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
        if call_state_media_artifact_boundary(body).is_err() {
            continue;
        }
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

/// Read the `actor_id -> device_id` map from durable call state. This is
/// needed for moderator-forced mute, whose wire shape must target both actor
/// and device.
pub(super) fn call_state_participant_actor_device_map(
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
        if call_state_media_artifact_boundary(body).is_err() {
            continue;
        }
        if body.get("call_id").and_then(|v| v.as_str()) != Some(call_id) {
            continue;
        }
        let Some(participants) = body.get("participants").and_then(|v| v.as_array()) else {
            continue;
        };
        for participant in participants {
            let actor_id = participant
                .get("actor_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let device_id = participant
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if !actor_id.trim().is_empty() && !device_id.trim().is_empty() {
                map.insert(actor_id.to_owned(), device_id.to_owned());
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

pub(super) fn build_roster(
    actor: &str,
    peers: &[String],
    actor_devices: &BTreeMap<String, String>,
) -> Vec<CallParticipant> {
    let mut ids = BTreeSet::new();
    let mut roster = Vec::new();
    for did in std::iter::once(actor).chain(peers.iter().map(String::as_str)) {
        let did = did.trim();
        if did.is_empty() || !ids.insert(did.to_owned()) {
            continue;
        }
        roster.push(CallParticipant {
            actor_id: did.to_owned(),
            device_id: actor_devices.get(did).cloned(),
            display_name: handle_display_from_did(did).unwrap_or_else(|| short_protocol_id(did)),
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
            &BTreeMap::new(),
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
                realm_id: Some("ak:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
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
            media_service_selection(&state, "ak:realm:01904100-0000-7000-8000-9b64700c6ee8");
        assert_eq!(dids, vec!["did:web:media.example"]);
        assert_eq!(focus_id, "fra-1");
    }

    #[test]
    fn call_state_participant_identities_read_sfu_handles() {
        let mut state = crate::local_state::ClientLocalState::default();
        state.raw_operations.push(crate::local_state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.call.state",
                "body": {
                    "call_id": "ak:call:0196441c-0000-7000-8000-000000000000",
                    "state": "connecting",
                    "participants": [
                        {"actor_id": "did:web:alice.example", "participant_identity": "ak:rtc_participant:alice"}
                    ]
                }
            }),
        });
        let identities = call_state_participant_identities(
            &state,
            "ak:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "ak:call:0196441c-0000-7000-8000-000000000000",
        );
        assert!(identities.contains("ak:rtc_participant:alice"));
        assert!(!identities.contains("did:web:alice.example"));
    }

    #[test]
    fn call_state_participant_device_map_pairs_identity_and_device() {
        let mut state = crate::local_state::ClientLocalState::default();
        state
            .raw_operations
            .push(crate::local_state::RawOperationRecord {
                operation_id: "op-1".to_owned(),
                realm_id: Some("ak:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.call.state",
                    "body": {
                        "call_id": "ak:call:0196441c-0000-7000-8000-000000000000",
                        "state": "active",
                        "participants": [
                            {
                                "actor_id": "did:web:alice.example",
                                "device_id": "ak:device:01904100-0000-7000-8000-00000000000a",
                                "participant_identity": "ak:rtc_participant:alice"
                            },
                            {
                                // Missing device_id -> skipped (cannot derive its key).
                                "actor_id": "did:web:carol.example",
                                "participant_identity": "ak:rtc_participant:carol"
                            }
                        ]
                    }
                }),
            });
        let map = call_state_participant_device_map(
            &state,
            "ak:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "ak:call:0196441c-0000-7000-8000-000000000000",
        );
        assert_eq!(
            map.get("ak:rtc_participant:alice").map(String::as_str),
            Some("ak:device:01904100-0000-7000-8000-00000000000a")
        );
        // The participant with no device_id is fail-closed: not in the map.
        assert!(!map.contains_key("ak:rtc_participant:carol"));
    }

    #[test]
    fn call_state_participant_actor_device_map_pairs_actor_and_device() {
        let mut state = crate::local_state::ClientLocalState::default();
        state
            .raw_operations
            .push(crate::local_state::RawOperationRecord {
                operation_id: "op-1".to_owned(),
                realm_id: Some("ak:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.call.state",
                    "body": {
                        "call_id": "ak:call:0196441c-0000-7000-8000-000000000000",
                        "state": "active",
                        "participants": [
                            {
                                "actor_id": "did:web:alice.example",
                                "device_id": "ak:device:01904100-0000-7000-8000-00000000000a",
                                "participant_identity": "ak:rtc_participant:alice"
                            }
                        ]
                    }
                }),
            });
        let map = call_state_participant_actor_device_map(
            &state,
            "ak:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "ak:call:0196441c-0000-7000-8000-000000000000",
        );
        assert_eq!(
            map.get("did:web:alice.example").map(String::as_str),
            Some("ak:device:01904100-0000-7000-8000-00000000000a")
        );
    }

    #[test]
    fn recording_artifact_boundary_rejects_backend_url() {
        let body = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "state": "ended",
            "recording_state": "ready",
            "recording_result": {
                "recording_start_event_id": "ak:event:019a7360-0000-7000-8000-000000000003",
                "recording_url": "https://s3.amazonaws.com/bucket/recording.mp4"
            }
        });
        assert_eq!(
            call_state_recording_artifact_boundary(&body),
            Err(crate::media::rtc::RtcClientError::RecordingArtifactPipelineBypassed)
        );
    }

    #[test]
    fn recording_artifact_boundary_accepts_arkret_blob_artifact() {
        assert!(call_state_recording_artifact_boundary(&valid_recording_call_state()).is_ok());
    }

    #[test]
    fn transcript_artifact_boundary_rejects_backend_url() {
        let body = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "state": "ended",
            "transcript_state": "ready",
            "transcript_result": {
                "transcript_start_event_id": "ak:event:019a7360-0000-7000-8000-000000000003",
                "transcript_artifact_url": "https://backend.example/transcript.vtt"
            }
        });
        assert_eq!(
            call_state_transcript_artifact_boundary(&body),
            Err(crate::media::rtc::RtcClientError::TranscriptionArtifactPipelineBypassed)
        );
    }

    #[test]
    fn call_state_projection_skips_backend_recording_result() {
        let mut state = crate::local_state::ClientLocalState::default();
        state.raw_operations.push(crate::local_state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:019a7360-0000-7000-8000-000000000000".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.call.state",
                "body": {
                    "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
                    "state": "ended",
                    "recording_state": "ready",
                    "recording_result": {
                        "recording_start_event_id": "ak:event:019a7360-0000-7000-8000-000000000003",
                        "recording_url": "https://backend.example/egress/out.mp4"
                    },
                    "participants": [
                        {
                            "actor_id": "did:web:alice.example",
                            "device_id": "ak:device:019a7360-0000-7000-8000-000000000008",
                            "participant_identity": "ak:rtc_participant:alice"
                        }
                    ]
                }
            }),
        });
        let identities = call_state_participant_identities(
            &state,
            "ak:realm:019a7360-0000-7000-8000-000000000000",
            "ak:call:019a7360-0000-7000-8000-000000000001",
        );
        assert!(identities.is_empty());
    }

    #[test]
    fn call_state_projection_skips_backend_transcript_result() {
        let mut state = crate::local_state::ClientLocalState::default();
        state.raw_operations.push(crate::local_state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:019a7360-0000-7000-8000-000000000000".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.call.state",
                "body": {
                    "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
                    "state": "ended",
                    "transcript_state": "ready",
                    "transcript_result": {
                        "transcript_start_event_id": "ak:event:019a7360-0000-7000-8000-000000000003",
                        "transcript_artifact_url": "https://backend.example/transcript.vtt"
                    },
                    "participants": [
                        {
                            "actor_id": "did:web:alice.example",
                            "device_id": "ak:device:019a7360-0000-7000-8000-000000000008",
                            "participant_identity": "ak:rtc_participant:alice"
                        }
                    ]
                }
            }),
        });
        let identities = call_state_participant_identities(
            &state,
            "ak:realm:019a7360-0000-7000-8000-000000000000",
            "ak:call:019a7360-0000-7000-8000-000000000001",
        );
        assert!(identities.is_empty());
    }

    fn valid_recording_call_state() -> serde_json::Value {
        let realm_id = "ak:realm:019a7360-0000-7000-8000-000000000000";
        let call_id = "ak:call:019a7360-0000-7000-8000-000000000001";
        let recording_id = "rtc-recording-019a7360-0000-7000-8000-000000000002";
        let start_event_id = "ak:event:019a7360-0000-7000-8000-000000000003";
        let content_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let ciphertext_digest =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let retention = json!({
            "retention_expires_at": "2026-06-20T00:00:00Z",
            "deletion_trigger": "retention_expiry",
            "audit_lock": false,
            "consent_confirmed": true
        });
        json!({
            "call_id": call_id,
            "state": "ended",
            "recording_state": "ready",
            "recording_result": {
                "content_digest": content_digest,
                "duration_ms": 42000,
                "media_type": "video/mp4",
                "retention_policy_id": "ak:policy:019a7360-0000-7000-8000-000000000005",
                "retention": retention,
                "recording_start_event_id": start_event_id,
                "artifact": {
                    "schema": "ck.schema.call_recording_artifact.v1",
                    "realm_id": realm_id,
                    "call_id": call_id,
                    "recording_id": recording_id,
                    "recording_start_event_id": start_event_id,
                    "artifact_kind": "recording",
                    "blob_ref": "ak:blob:019a7360-0000-7000-8000-000000000004",
                    "content_digest": content_digest,
                    "ciphertext_digest": ciphertext_digest,
                    "size_bytes": 1048576,
                    "duration_ms": 42000,
                    "media_type": "video/mp4",
                    "encryption": {
                        "alg": "mls_exporter_aead_xchacha20poly1305_stream",
                        "exporter_label": "ck-rtc-recording-key/v1",
                        "context": {
                            "realm_id": realm_id,
                            "call_id": call_id,
                            "focus_id": "fra-1",
                            "recording_id": recording_id,
                            "media_service_did": "did:web:recorder.example",
                            "recording_start_event_id": start_event_id
                        },
                        "ciphertext_digest": ciphertext_digest
                    },
                    "retention_policy_id": "ak:policy:019a7360-0000-7000-8000-000000000005",
                    "retention": retention,
                    "produced_by": "did:web:recorder.example",
                    "recording_initiator_capability_ref": "ak:grant:019a7360-0000-7000-8000-000000000006",
                    "created_at": "2026-06-19T00:00:00Z",
                    "deletion_audit": {
                        "trigger": "retention_expiry",
                        "outcome": "completed",
                        "requested_at": "2026-06-20T00:00:00Z",
                        "completed_at": "2026-06-20T00:00:01Z",
                        "erasure_receipt_ref": "ak:receipt:019a7360-0000-7000-8000-000000000007"
                    }
                }
            }
        })
    }

    #[test]
    fn expected_participant_set_uses_rtc_identities() {
        let mut durable = BTreeSet::new();
        durable.insert("ak:rtc_participant:remote".to_owned());
        let expected = expected_participant_set(&durable, "ak:rtc_participant:self");
        assert!(expected.contains("ak:rtc_participant:self"));
        assert!(expected.contains("ak:rtc_participant:remote"));
        assert!(!expected.contains("did:web:alice.example"));
    }
}
