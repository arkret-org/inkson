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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
    rows: &[arkret_wire::TypedCurrentRow],
    realm_id: &str,
    call_id: &str,
) -> BTreeSet<String> {
    call_roster_participants(rows, realm_id, call_id)
        .filter_map(|participant| {
            participant
                .get("participant_id")
                .and_then(Value::as_str)
                .filter(|identity| !identity.trim().is_empty())
                .map(ToOwned::to_owned)
        })
        .collect()
}

/// Use only the complete authority-accepted current assertion set.
fn call_roster_participants(
    rows: &[arkret_wire::TypedCurrentRow],
    realm_id: &str,
    call_id: &str,
) -> impl Iterator<Item = Value> {
    rows.iter().find_map(|row| match row {
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::CallRoster { call_id: current_call },
            source_stream_ref, revision, value,
        } if current_call.as_str() == call_id && source_stream_ref.realm_id().as_str() == realm_id => {
            let current: arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue =
                serde_json::from_value(value.clone()).ok()?;
            current.validate_for_axis(source_stream_ref, revision).ok()?;
            Some(current.effective_participants().ok()?.into_iter()
                .filter_map(|participant| serde_json::to_value(participant).ok()).collect::<Vec<_>>())
        }
        _ => None,
    }).unwrap_or_default().into_iter()
}

/// Read the `participant_id → device_id` map from the durable
/// complete Call roster current for this call. Used to build a
/// remote sender's SFrame [`FrameKeyContext`] (`media-service-binding.md` §8.1
/// binds the sender's own `(participant_id, device_id)`): when a remote
/// connects, its `device_id` is looked up here so the receiver can recompute
/// that sender's frame key from the shared MLS exporter. Entries missing either
/// field are skipped (the remote's key cannot be derived → fail-closed for that
/// one remote).
pub(super) fn call_state_participant_device_map(
    rows: &[arkret_wire::TypedCurrentRow],
    realm_id: &str,
    call_id: &str,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for participant in call_roster_participants(rows, realm_id, call_id) {
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
    rows: &[arkret_wire::TypedCurrentRow],
    realm_id: &str,
    call_id: &str,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for participant in call_roster_participants(rows, realm_id, call_id) {
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

    fn accepted_roster_rows() -> Vec<arkret_wire::TypedCurrentRow> {
        let realm = "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs";
        let event = "ak:event:ASm7jqNYNKkkSZtwu8PWbZHjEuA0e0fwxgveLiRW88t5";
        let mut source = json!({
            "realm_id":realm, "stream_ref":{"kind":"realm","realm_id":realm},
            "stream_position":1,
            "previous_commit_ref":"ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "event_ref":event, "governance_generation":0, "authority_ref":event,
            "committed_at":"2026-10-15T00:00:00.000Z"
        });
        let commit_id =
            arkret_wire::RealmCommitId::from_digest(arkret_sdk::canonical::sha256_bytes(
                &arkret_sdk::canonical::canonical_json_bytes(&source).unwrap(),
            ));
        source["commit_id"] = json!(commit_id);
        source["signature"] = json!({
            "context":"ak.realm_commit_signature.v1", "signature_algorithm":"Ed25519",
            "verification_method":"did:web:station.example#authority",
            "signed_digest":format!("sha256:{}", "0".repeat(64)),
            "created_at":"2026-10-15T00:00:00.000Z", "sig":"A".repeat(86)
        });
        vec![serde_json::from_value(json!({
            "selector":{"kind":"call_roster","call_id":"ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz"},
            "source_stream_ref":{"kind":"realm","realm_id":realm},
            "revision":{"commit_id":commit_id,"stream_position":1},
            "value":{"assertions":[{"tag_id":format!("{event}:7"),"source_commit":source,"value":{
                "op":"join","participant":{
                    "actor_id":"ak:did_core:web:anonymous.example",
                    "device_id":"ak:device:01904100-0000-7000-8000-00000000000a",
                    "participant_id":"ak:rtc_participant:01904100-0000-7000-8000-00000000000a",
                    "focus_id":"focus",
                    "participant_binding":{
                        "expires_at":"2026-10-15T00:05:00.000Z", "issuer_kid":"did:web:station.example#authority",
                        "subject_binding_digest":format!("sha256:{}", "0".repeat(64)), "sig":"A".repeat(86)
                    }
                }
            }}]}
        })).unwrap()]
    }

    #[test]
    fn call_state_participant_identities_read_sfu_handles() {
        let rows = accepted_roster_rows();
        let identities = call_state_participant_identities(
            &rows,
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        );
        assert!(identities.contains("ak:rtc_participant:01904100-0000-7000-8000-00000000000a"));
        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn call_state_participant_device_map_pairs_identity_and_device() {
        let rows = accepted_roster_rows();
        let map = call_state_participant_device_map(
            &rows,
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        );
        assert_eq!(
            map["ak:rtc_participant:01904100-0000-7000-8000-00000000000a"],
            "ak:device:01904100-0000-7000-8000-00000000000a"
        );
    }

    #[test]
    fn call_state_participant_actor_device_map_pairs_actor_and_device() {
        let rows = accepted_roster_rows();
        let map = call_state_participant_actor_device_map(
            &rows,
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        );
        assert_eq!(
            map["ak:did_core:web:anonymous.example"],
            "ak:device:01904100-0000-7000-8000-00000000000a"
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
    fn call_current_projection_rejects_unregistered_delta_fields() {
        let mut rows = accepted_roster_rows();
        let arkret_wire::TypedCurrentRow::Value { value, .. } = &mut rows[0];
        value["assertions"][0]["value"]["backend_recording_url"] =
            json!("https://backend.example/private");
        assert!(
            call_state_participant_identities(
                &rows,
                "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
                "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz"
            )
            .is_empty()
        );
    }

    #[test]
    fn call_current_projection_requires_exact_realm_and_call() {
        let mut rows = accepted_roster_rows();
        assert!(
            call_state_participant_identities(
                &rows,
                "wrong-realm",
                "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz"
            )
            .is_empty()
        );
        assert!(
            call_state_participant_identities(
                &rows,
                "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
                "wrong-call"
            )
            .is_empty()
        );
        let arkret_wire::TypedCurrentRow::Value { revision, .. } = &mut rows[0];
        revision.stream_position += 1;
        assert!(
            call_state_participant_identities(
                &rows,
                "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
                "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz"
            )
            .is_empty()
        );
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
