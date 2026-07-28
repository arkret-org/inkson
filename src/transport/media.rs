use crate::event_submit::EventSubmitter;
use crate::models::{MediaIceConfigOutcome, MediaIceConfigRequestBody, SubmitEventResult};

pub struct MediaEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl<'a> MediaEndpoints<'a> {
    pub(crate) fn new(transport: &'a super::TransportClient) -> Self {
        Self { transport }
    }

    pub async fn ice_config(
        &self,
        request: &MediaIceConfigRequestBody,
    ) -> anyhow::Result<MediaIceConfigOutcome> {
        self.transport
            .http()
            .media_ice_config(request)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn token_exchange(
        &self,
        request: &arkret_sdk::CallMediaTokenExchangeRequestBody,
    ) -> anyhow::Result<arkret_sdk::CallMediaTokenExchangeOutcome> {
        self.transport
            .http()
            .media_token_exchange(request)
            .await
            .map_err(anyhow::Error::from)
    }
}

pub async fn submit_call_recording_start(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    call_id: &str,
    recording_id: &str,
    mode: arkret_sdk::RecordingMode,
) -> anyhow::Result<SubmitEventResult> {
    submit_call_capture_start(
        submitter,
        realm_id,
        actor_id,
        call_id,
        recording_id,
        arkret_sdk::RecordingCaptureKind::Recording,
        mode,
    )
    .await
}

pub async fn submit_call_transcription_start(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    call_id: &str,
    transcript_id: &str,
    mode: arkret_sdk::RecordingMode,
) -> anyhow::Result<SubmitEventResult> {
    submit_call_capture_start(
        submitter,
        realm_id,
        actor_id,
        call_id,
        transcript_id,
        arkret_sdk::RecordingCaptureKind::Transcript,
        mode,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn submit_call_capture_start(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    call_id: &str,
    recording_id: &str,
    capture_kind: arkret_sdk::RecordingCaptureKind,
    mode: arkret_sdk::RecordingMode,
) -> anyhow::Result<SubmitEventResult> {
    let event = crate::webrtc::build_call_recording_start(
        realm_id,
        actor_id,
        call_id,
        recording_id,
        capture_kind,
        mode,
        true,
    )
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}
