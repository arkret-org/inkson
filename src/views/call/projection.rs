use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::event_kind_str;
use dioxus::prelude::*;
use serde_json::Value;

use super::types::CallParticipantView;
use crate::media::rtc::MediaGovernanceEvidence;
use crate::views::helpers::short_protocol_id;

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
    if let Some(result) = body
        .get("recording_transition")
        .and_then(|transition| transition.get("result"))
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
    if let Some(result) = body
        .get("transcript_transition")
        .and_then(|transition| transition.get("result"))
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
    body.get("recording_transition")
        .and_then(|transition| transition.get("result"))
        .is_some()
        || matches!(
            body.get("recording_transition")
                .and_then(|transition| transition.get("to"))
                .and_then(Value::as_str),
            Some("ready" | "failed")
        )
}

fn body_mentions_transcript_artifact(body: &Value) -> bool {
    body.get("transcript_transition")
        .and_then(|transition| transition.get("result"))
        .is_some()
        || matches!(
            body.get("transcript_transition")
                .and_then(|transition| transition.get("to"))
                .and_then(Value::as_str),
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

/// Derive the realm's anchored media-service IDs and preferred focus from
/// the local `ak.realm.media_service` projection.
pub(super) fn media_service_selection(
    state: &crate::state::ClientLocalState,
    realm_id: &str,
) -> (Vec<String>, String) {
    let mut service_ids = BTreeSet::new();
    let mut focus_ids = Vec::<String>::new();
    for record in &state.raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if kind != event_kind_str::REALM_MEDIA_SERVICE
            || record.realm_id.as_deref() != Some(realm_id)
        {
            continue;
        }
        let body = operation_body(&record.payload);
        if let Some(service_id) = body.get("service_id").and_then(|v| v.as_str()) {
            service_ids.insert(service_id.to_owned());
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
    let media_service_ids: Vec<String> = service_ids.into_iter().collect();
    let focus_id = focus_ids
        .into_iter()
        .next()
        .unwrap_or_else(|| default_focus_id(&media_service_ids));
    (media_service_ids, focus_id)
}

pub(super) fn media_governance_evidence(
    state: &crate::state::ClientLocalState,
    realm_id: &str,
    media_plaintext_ui_confirmed: bool,
) -> Option<MediaGovernanceEvidence> {
    let media_service_payload =
        latest_body_for_kind(state, realm_id, event_kind_str::REALM_MEDIA_SERVICE)?;
    let policy_bundle_payload =
        latest_body_for_kind(state, realm_id, event_kind_str::REALM_POLICY_BUNDLE);
    let plaintext_visible_services_payload = latest_body_for_kind(
        state,
        realm_id,
        event_kind_str::REALM_PLAINTEXT_VISIBLE_SERVICES,
    )
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
            if !matches!(
                kind,
                event_kind_str::MLS_COMMIT | event_kind_str::MLS_GENESIS
            ) {
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
        policy_bundle_payload,
        plaintext_visible_services_payload,
        media_plaintext_ui_confirmed,
    })
}

pub(super) fn media_service_decrypts_enabled(
    state: &crate::state::ClientLocalState,
    realm_id: &str,
) -> bool {
    latest_body_for_kind(state, realm_id, event_kind_str::REALM_POLICY_BUNDLE)
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
    state: &crate::state::ClientLocalState,
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
/// real media join still fails closed when the anchored issuer service-ID set is
/// empty.
pub(super) fn default_focus_id(media_service_ids: &[String]) -> String {
    media_service_ids
        .first()
        .and_then(|service_id| service_id.rsplit(':').next())
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
    state: &crate::state::ClientLocalState,
    realm_id: &str,
    call_id: &str,
) -> BTreeSet<String> {
    call_roster_participants(state, realm_id, call_id)
        .filter_map(|participant| {
            participant
                .get("participant_id")
                .and_then(Value::as_str)
                .filter(|identity| !identity.trim().is_empty())
                .map(ToOwned::to_owned)
        })
        .collect()
}

/// Fold the roster OR-Set from exact `roster_delta` events. A leave tombstones
/// its observed add tag so replay order cannot resurrect a removed leg.
fn call_roster_participants<'a>(
    state: &'a crate::state::ClientLocalState,
    realm_id: &str,
    call_id: &str,
) -> impl Iterator<Item = &'a Value> {
    let mut participants = BTreeMap::<String, &'a Value>::new();
    let mut removed_tags = BTreeSet::<String>::new();
    for record in &state.raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if kind != event_kind_str::CALL_STATE || record.realm_id.as_deref() != Some(realm_id) {
            continue;
        }
        let body = operation_body(&record.payload);
        if call_state_media_artifact_boundary(body).is_err() {
            continue;
        }
        if body.get("call_id").and_then(|v| v.as_str()) != Some(call_id) {
            continue;
        }
        let Some(delta) = body.get("roster_delta") else {
            continue;
        };
        match delta.get("op").and_then(Value::as_str) {
            Some("join") => {
                let Some(participant) = delta.get("participant") else {
                    continue;
                };
                let tag = record
                    .payload
                    .get("event_id")
                    .and_then(Value::as_str)
                    .unwrap_or(record.operation_id.as_str());
                if !removed_tags.contains(tag) {
                    participants.insert(tag.to_owned(), participant);
                }
            }
            Some("leave") => {
                let Some(tag) = delta.get("observed_tag").and_then(Value::as_str) else {
                    continue;
                };
                removed_tags.insert(tag.to_owned());
                participants.remove(tag);
            }
            _ => {}
        }
    }
    participants.into_values()
}

/// Read the `participant_id → device_id` map from the durable
/// call roster OR-Set projection for this call. Used to build a
/// remote sender's SFrame [`FrameKeyContext`] (`media-service-binding.md` §8.1
/// binds the sender's own `(participant_id, device_id)`): when a remote
/// connects, its `device_id` is looked up here so the receiver can recompute
/// that sender's frame key from the shared MLS exporter. Entries missing either
/// field are skipped (the remote's key cannot be derived → fail-closed for that
/// one remote).
pub(super) fn call_state_participant_device_map(
    state: &crate::state::ClientLocalState,
    realm_id: &str,
    call_id: &str,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for participant in call_roster_participants(state, realm_id, call_id) {
        let identity = participant
            .get("participant_id")
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
    map
}

/// Read the `actor_id -> device_id` map from durable call state. This is
/// needed for moderator-forced mute, whose wire shape must target both actor
/// and device.
pub(super) fn call_state_participant_actor_device_map(
    state: &crate::state::ClientLocalState,
    realm_id: &str,
    call_id: &str,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for participant in call_roster_participants(state, realm_id, call_id) {
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
    map
}

/// Build the MEDIA-2 expected-participant identity set from durable call
/// state, seeding the local token-exchange identity before the state sync
/// loop has replayed our own write.
pub(super) fn expected_participant_set(
    durable_identities: &BTreeSet<String>,
    local_participant_id: &str,
) -> BTreeSet<String> {
    let mut expected = durable_identities.clone();
    if !local_participant_id.trim().is_empty() {
        expected.insert(local_participant_id.to_owned());
    }
    expected
}

pub(super) fn build_roster(
    actor: &str,
    peers: &[String],
    actor_devices: &BTreeMap<String, String>,
) -> anyhow::Result<Vec<CallParticipantView>> {
    let mut ids = BTreeSet::new();
    let mut roster = Vec::new();
    for actor_id in std::iter::once(actor).chain(peers.iter().map(String::as_str)) {
        let actor_id = arkret_sdk::DidCoreId::new(actor_id.trim().to_owned())?.to_string();
        if !ids.insert(actor_id.clone()) {
            continue;
        }
        roster.push(CallParticipantView {
            device_id: actor_devices.get(&actor_id).cloned(),
            display_name: short_protocol_id(&actor_id),
            actor_id,
            muted: false,
            speaking: false,
            screen_sharing: false,
        });
    }
    Ok(roster)
}

pub(super) fn set_local_state(
    participants: &mut Signal<Vec<CallParticipantView>>,
    actor: &str,
    muted: bool,
    sharing: bool,
) {
    let Ok(actor) = arkret_sdk::DidCoreId::new(actor.trim().to_owned()) else {
        return;
    };
    let mut roster = participants();
    for p in &mut roster {
        if p.actor_id == actor.as_str() {
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
                "ak:did_core:web:bob.example\nak:did_core:web:carol.example, ak:did_core:web:bob.example"
            ),
            vec![
                "ak:did_core:web:bob.example",
                "ak:did_core:web:carol.example"
            ]
        );
    }

    #[test]
    fn roster_includes_actor_once() {
        let roster = build_roster(
            "ak:did_core:web:alice.example",
            &[
                "ak:did_core:web:bob.example".to_owned(),
                "ak:did_core:web:alice.example".to_owned(),
            ],
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(roster.len(), 2);
        assert_eq!(roster[0].actor_id, "ak:did_core:web:alice.example");
    }

    #[test]
    fn default_focus_id_derives_from_service_id() {
        assert_eq!(
            default_focus_id(&["did:web:media.example".to_owned()]),
            "media.example"
        );
        assert_eq!(default_focus_id(&[]), "default");
    }

    #[test]
    fn media_service_selection_reads_declared_focus() {
        let mut state = crate::state::ClientLocalState::default();
        state.raw_operations.push(crate::state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.realm.media_service",
                "body": {
                    "service_id": "ak:did_core:web:media.example",
                    "foci": [
                        {"focus_id": "fra-1", "type": "livekit"},
                        {"focus_id": "us-east-1", "type": "livekit"}
                    ]
                }
            }),
        });
        let (dids, focus_id) = media_service_selection(
            &state,
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
        );
        assert_eq!(dids, vec!["ak:did_core:web:media.example"]);
        assert_eq!(focus_id, "fra-1");
    }

    #[test]
    fn call_state_participant_identities_read_sfu_handles() {
        let mut state = crate::state::ClientLocalState::default();
        state.raw_operations.push(crate::state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.call.state",
                "event_id": "ak:event:ASm7jqNYNKkkSZtwu8PWbZHjEuA0e0fwxgveLiRW88t5",
                "body": {
                    "call_id": "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
                    "roster_delta": {
                        "op": "join",
                        "participant": {
                            "actor_id": "ak:did_core:web:alice.example",
                            "participant_id": "ak:rtc_participant:alice"
                        }
                    }
                }
            }),
        });
        let identities = call_state_participant_identities(
            &state,
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        );
        assert!(identities.contains("ak:rtc_participant:alice"));
        assert!(!identities.contains("did:web:alice.example"));
    }

    #[test]
    fn call_state_participant_device_map_pairs_identity_and_device() {
        let mut state = crate::state::ClientLocalState::default();
        state.raw_operations.push(crate::state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.call.state",
                "event_id": "ak:event:Af_bFBCAZvUH8R-cwurL2MobOvPPrqNmLsods7_Ww5RL",
                "body": {
                    "call_id": "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
                    "roster_delta": {
                        "op": "join",
                        "participant": {
                            "actor_id": "ak:did_core:web:alice.example",
                            "device_id": "ak:device:01904100-0000-7000-8000-00000000000a",
                            "participant_id": "ak:rtc_participant:alice"
                        }
                    }
                }
            }),
        });
        let map = call_state_participant_device_map(
            &state,
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        );
        assert_eq!(
            map.get("ak:rtc_participant:alice").map(String::as_str),
            Some("ak:device:01904100-0000-7000-8000-00000000000a")
        );
    }

    #[test]
    fn call_state_participant_actor_device_map_pairs_actor_and_device() {
        let mut state = crate::state::ClientLocalState::default();
        state.raw_operations.push(crate::state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.call.state",
                "event_id": "ak:event:AdOGA9FXdJkglUZwIc7veJCh_CdvCt3PkUOC-1psvRhF",
                "body": {
                    "call_id": "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
                    "roster_delta": {
                        "op": "join",
                        "participant": {
                            "actor_id": "ak:did_core:web:alice.example",
                            "device_id": "ak:device:01904100-0000-7000-8000-00000000000a",
                            "participant_id": "ak:rtc_participant:alice"
                        }
                    }
                }
            }),
        });
        let map = call_state_participant_actor_device_map(
            &state,
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        );
        assert_eq!(
            map.get("ak:did_core:web:alice.example").map(String::as_str),
            Some("ak:device:01904100-0000-7000-8000-00000000000a")
        );
    }

    #[test]
    fn recording_artifact_boundary_rejects_backend_url() {
        let body = json!({
            "call_id": "ak:call:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz0",
            "recording_transition": {
                "recording_id": "rtc-recording-019a7360-0000-7000-8000-000000000002",
                "from": "stopped",
                "to": "ready",
                "result": {
                    "recording_start_event_id": "ak:event:AQ_TuICTz2cVFhqtuEZTue46AK_LsqKsKlTPixxkuedX",
                    "recording_url": "https://s3.amazonaws.com/bucket/recording.mp4"
                }
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
            "call_id": "ak:call:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz0",
            "transcript_transition": {
                "recording_id": "rtc-transcript-019a7360-0000-7000-8000-000000000002",
                "from": "stopped",
                "to": "ready",
                "result": {
                    "transcript_start_event_id": "ak:event:AQ_TuICTz2cVFhqtuEZTue46AK_LsqKsKlTPixxkuedX",
                    "transcript_artifact_url": "https://backend.example/transcript.vtt"
                }
            }
        });
        assert_eq!(
            call_state_transcript_artifact_boundary(&body),
            Err(crate::media::rtc::RtcClientError::TranscriptionArtifactPipelineBypassed)
        );
    }

    #[test]
    fn call_state_projection_skips_backend_recording_result() {
        let mut state = crate::state::ClientLocalState::default();
        state.raw_operations.push(crate::state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:AafktYXx8-v8PgfMovcpfbkFAJzUiT8l2GHJJ9UmF3fP".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.call.state",
                "event_id": "ak:event:AfJbDJqGER5UOnt8W9wrLdj9CgXQ2nZr-dcA7zvYA_Wo",
                "body": {
                    "call_id": "ak:call:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz0",
                    "recording_transition": {
                        "recording_id": "rtc-recording-019a7360-0000-7000-8000-000000000002",
                        "from": "stopped",
                        "to": "ready",
                        "result": {
                            "recording_start_event_id": "ak:event:AQ_TuICTz2cVFhqtuEZTue46AK_LsqKsKlTPixxkuedX",
                            "recording_url": "https://backend.example/egress/out.mp4"
                        }
                    },
                    "roster_delta": {
                        "op": "join",
                        "participant": {
                            "actor_id": "ak:did_core:web:alice.example",
                            "device_id": "ak:device:019a7360-0000-7000-8000-000000000008",
                            "participant_id": "ak:rtc_participant:alice"
                        }
                    }
                }
            }),
        });
        let identities = call_state_participant_identities(
            &state,
            "ak:realm:AafktYXx8-v8PgfMovcpfbkFAJzUiT8l2GHJJ9UmF3fP",
            "ak:call:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz0",
        );
        assert!(identities.is_empty());
    }

    #[test]
    fn call_state_projection_skips_backend_transcript_result() {
        let mut state = crate::state::ClientLocalState::default();
        state.raw_operations.push(crate::state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:AafktYXx8-v8PgfMovcpfbkFAJzUiT8l2GHJJ9UmF3fP".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.call.state",
                "event_id": "ak:event:ATD6cb_3TgprxaV53cyR2YNads-FjjMmsIfwddWP23Z6",
                "body": {
                    "call_id": "ak:call:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz0",
                    "transcript_transition": {
                        "recording_id": "rtc-transcript-019a7360-0000-7000-8000-000000000002",
                        "from": "stopped",
                        "to": "ready",
                        "result": {
                            "transcript_start_event_id": "ak:event:AQ_TuICTz2cVFhqtuEZTue46AK_LsqKsKlTPixxkuedX",
                            "transcript_artifact_url": "https://backend.example/transcript.vtt"
                        }
                    },
                    "roster_delta": {
                        "op": "join",
                        "participant": {
                            "actor_id": "ak:did_core:web:alice.example",
                            "device_id": "ak:device:019a7360-0000-7000-8000-000000000008",
                            "participant_id": "ak:rtc_participant:alice"
                        }
                    }
                }
            }),
        });
        let identities = call_state_participant_identities(
            &state,
            "ak:realm:AafktYXx8-v8PgfMovcpfbkFAJzUiT8l2GHJJ9UmF3fP",
            "ak:call:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz0",
        );
        assert!(identities.is_empty());
    }

    fn valid_recording_call_state() -> serde_json::Value {
        let realm_id = "ak:realm:AafktYXx8-v8PgfMovcpfbkFAJzUiT8l2GHJJ9UmF3fP";
        let call_id = "ak:call:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz0";
        let recording_id = "rtc-recording-019a7360-0000-7000-8000-000000000002";
        let start_event_id = "ak:event:AQ_TuICTz2cVFhqtuEZTue46AK_LsqKsKlTPixxkuedX";
        let content_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // The recording result's content_digest is the artifact blob digest;
        // the two are the same commitment, so the fixture derives one from the
        // other instead of carrying two independent constants.
        let blob_ref = format!("ak:blob:{content_digest}");
        let retention = json!({
            "retention_expires_at": "2026-06-20T00:00:00.000Z",
            "deletion_trigger": "retention_expiry",
            "audit_lock": false,
            "consent_confirmed": true
        });
        json!({
            "call_id": call_id,
            "recording_transition": {
                "recording_id": recording_id,
                "from": "stopped",
                "to": "ready",
                "result": {
                "content_digest": content_digest,
                "duration_ms": 42000,
                "media_type": "video/mp4",
                "retention_policy_id": "ak:policy:019a7360-0000-7000-8000-000000000005",
                "retention": retention,
                "recording_start_event_id": start_event_id,
                "artifact": {
                    "schema": "ak.schema.call_recording_artifact.v1",
                    "realm_id": realm_id,
                    "call_id": call_id,
                    "recording_id": recording_id,
                    "recording_start_event_id": start_event_id,
                    "blob_ref": blob_ref,
                    "size_bytes": 1048576,
                    "duration_ms": 42000,
                    "media_type": "video/mp4",
                    "encryption": {
                        "encryption_algorithm": "mls_exporter_aead_xchacha20poly1305_stream",
                        "exporter_label": "ak.rtc-recording-key/v1",
                        "context": {
                            "realm_id": realm_id,
                            "call_id": call_id,
                            "focus_id": "fra-1",
                            "recording_id": recording_id,
                            "media_service_id": "ak:did_core:web:recorder.example",
                            "recording_start_event_id": start_event_id
                        }
                    },
                    "retention_policy_id": "ak:policy:019a7360-0000-7000-8000-000000000005",
                    "retention": retention,
                    "produced_by": "ak:did_core:web:recorder.example",
                    "recording_initiator_capability_ref": "ak:grant:AY8a0-KhSVbHOk2IStjbvFlEdGofW0ZyqMsOoZu6_Cqv",
                    "created_at": "2026-06-19T00:00:00.000Z",
                    "deletion_audit": {
                        "trigger": "retention_expiry",
                        "outcome": "completed",
                        "requested_at": "2026-06-20T00:00:00.000Z",
                        "completed_at": "2026-06-20T00:00:01.000Z",
                        "erasure_receipt_ref": "ak:receipt:019a7360-0000-7000-8000-000000000007"
                    }
                }}
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
