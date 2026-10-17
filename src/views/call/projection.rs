use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::*;
use serde_json::Value;

use super::types::CallParticipantView;
pub(super) use crate::media::rtc::current_media_governance_evidence as media_governance_evidence;
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

/// Read the anchored descriptor from the same verified current view as Call state.
pub(super) fn media_service_selection(
    store: &crate::state::LocalStateStore,
    realm_id: &str,
) -> (Vec<String>, String) {
    let descriptor = store
        .current_product_view()
        .filter(|view| view.realm_id == realm_id)
        .and_then(|view| view.media_service().ok().flatten());
    let Some(descriptor) = descriptor else {
        return (Vec::new(), String::new());
    };
    let focus = descriptor
        .foci
        .first()
        .map(|focus| focus.focus_id.to_string())
        .unwrap_or_default();
    (vec![descriptor.service_id.to_string()], focus)
}

pub(super) fn media_service_decrypts_enabled(
    store: &crate::state::LocalStateStore,
    realm_id: &str,
) -> bool {
    store
        .current_product_view()
        .filter(|view| view.realm_id == realm_id && view.complete_cut)
        .and_then(|view| {
            crate::current_projection::current_realm_policy_bundle_value(&view.entries)
        })
        .as_ref()
        .and_then(|body| {
            body.get("media_service_decrypts")
                .or_else(|| body.pointer("/components/media_service_decrypts"))
                .or_else(|| body.pointer("/media/media_service_decrypts"))
        })
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(super) fn participant_list_from_input(input: &str) -> Vec<String> {
    if let Ok(actors) = serde_json::from_str::<Vec<arkret_sdk::ActorId>>(input) {
        return actors
            .into_iter()
            .map(|actor| actor.to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
    if let Ok(actor) = serde_json::from_str::<arkret_sdk::ActorId>(input) {
        return vec![actor.to_string()];
    }
    if input.lines().all(|line| {
        line.trim().is_empty() || serde_json::from_str::<arkret_sdk::ActorId>(line).is_ok()
    }) {
        return input
            .lines()
            .filter_map(|line| serde_json::from_str::<arkret_sdk::ActorId>(line).ok())
            .map(|actor| actor.to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
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
    state: &crate::state::LocalStateStore,
    realm_id: &str,
    call_id: &str,
) -> BTreeSet<String> {
    call_roster_participants(state, realm_id, call_id)
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|participant| {
            participant
                .participant_id
                .filter(|id| !id.trim().is_empty())
        })
        .collect()
}

/// Consume the complete verified assertion axis, never the local history tail.
fn call_roster_participants(
    store: &crate::state::LocalStateStore,
    realm_id: &str,
    call_id: &str,
) -> anyhow::Result<Option<Vec<arkret_sdk::CallParticipant>>> {
    let Some(view) = store
        .current_product_view()
        .filter(|view| view.realm_id == realm_id)
    else {
        return Ok(None);
    };
    view.call_roster(&arkret_sdk::CallId::new(call_id.to_owned())?)
}

/// A refresh resumes only an active accepted public roster leg.
/// Resolve this authenticated full Account/device from a complete accepted roster.
pub(super) fn accepted_refresh_context(
    store: &crate::state::LocalStateStore,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    realm: &str,
    call: &str,
    focus: &str,
) -> anyhow::Result<Option<arkret_sdk::CallMediaJoinContext>> {
    let actor = arkret_sdk::ActorId::account(account.clone());
    let roster = call_roster_participants(store, realm, call)?
        .ok_or_else(|| anyhow::anyhow!("accepted Call current is not ready for media join"))?;
    for participant in roster {
        if participant.actor_id != actor
            || participant.device_id != device.as_str()
            || participant.focus_id.as_deref() != Some(focus)
            || participant.participant_binding.is_none()
        {
            continue;
        }
        if let Some(participant_id) = participant.participant_id {
            return Ok(Some(arkret_sdk::CallMediaJoinContext::Refresh(
                arkret_sdk::CallRefreshJoinContext {
                    kind: arkret_sdk::CallRefreshJoinKind::Refresh,
                    participant_id,
                },
            )));
        }
    }
    Ok(None)
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
    state: &crate::state::LocalStateStore,
    realm_id: &str,
    call_id: &str,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for participant in call_roster_participants(state, realm_id, call_id)
        .ok()
        .flatten()
        .unwrap_or_default()
    {
        if let Some(identity) = participant.participant_id
            && !identity.trim().is_empty()
            && !participant.device_id.trim().is_empty()
        {
            map.insert(identity, participant.device_id);
        }
    }
    map
}

/// Read the `actor_id -> device_id` map from durable call state. This is
/// needed for moderator-forced mute, whose wire shape must target both actor
/// and device.
pub(super) fn call_state_participant_actor_device_map(
    state: &crate::state::LocalStateStore,
    realm_id: &str,
    call_id: &str,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for participant in call_roster_participants(state, realm_id, call_id)
        .ok()
        .flatten()
        .unwrap_or_default()
    {
        if !participant.device_id.trim().is_empty() {
            map.insert(participant.actor_id.to_string(), participant.device_id);
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
        let complete = serde_json::from_str::<arkret_sdk::ActorId>(actor_id)
            .ok()
            .or_else(|| {
                crate::mls_api_helpers::account_id_from_selector(actor_id)
                    .map(arkret_sdk::ActorId::account)
            })
            .or_else(|| {
                (actor_id == actor)
                    .then(|| crate::mls_api_helpers::local_account_actor_id(actor_id).ok())
                    .flatten()
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Call participant requires a complete ActorId including its Station"
                )
            })?;
        let actor_id = complete.to_string();
        if !ids.insert(actor_id.clone()) {
            continue;
        }
        roster.push(CallParticipantView {
            device_id: actor_devices.get(&actor_id).cloned(),
            display_name: short_protocol_id(complete.signing_principal_id().as_str()),
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
    let Some(actor) = serde_json::from_str::<arkret_sdk::ActorId>(actor)
        .ok()
        .or_else(|| crate::mls_api_helpers::local_account_actor_id(actor).ok())
    else {
        return;
    };
    let mut roster = participants();
    for p in &mut roster {
        if p.actor_id == actor.to_string() {
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
    fn roster_keeps_complete_accounts_and_deduplicates_exact_actor() {
        let actor = |station: &str| {
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                "ak:did_core:web:alice.example".parse().unwrap(),
                station.parse().unwrap(),
            ))
            .to_string()
        };
        let local = actor("ak:did_core:web:station-a.example");
        let remote = actor("ak:did_core:web:station-b.example");
        let roster =
            build_roster(&local, &[remote.clone(), local.clone()], &BTreeMap::new()).unwrap();
        assert_eq!(roster.len(), 2);
        assert_eq!(roster[0].actor_id, local);
        assert_eq!(roster[1].actor_id, remote);
        assert!(
            build_roster(
                &local,
                &["ak:did_core:web:alice.example".to_owned()],
                &BTreeMap::new()
            )
            .is_err()
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
