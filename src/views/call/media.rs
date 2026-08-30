use std::cell::RefCell;
use std::rc::Rc;

use super::types::SharedTransport;
use crate::media::rtc::{JoinedMediaSession, MediaJoinRequest, PerSenderFrameKeys, RtcClientError};
use crate::rtc_transport::new_transport;
use crate::transport::auth::with_authed_api;

// ── Controller helpers ──────────────────────────────────────────────────

/// Run the media join and wrap the resulting transport in shared state.
///
/// `realm_mls_snapshot` is this device's persisted MLS snapshot for the
/// call's realm, read by the caller (and the store read-guard dropped)
/// before this async fn runs so the snapshot restore never holds a `Signal`
/// guard across an `.await`. It is `None` when the realm has not synced an
/// MLS group on this device, which makes the SFrame key derivation fail
/// closed.
pub(super) async fn join_and_build_transport(
    base: &str,
    api_token: &str,
    join: &MediaJoinRequest,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    realm_mls_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<(JoinedMediaSession, SharedTransport, Rc<PerSenderFrameKeys>), RtcClientError> {
    let (session, per_sender_keys) =
        join_via_api(base, api_token, join, authority, device, realm_mls_snapshot).await?;
    let transport = new_transport(&session);
    Ok((
        session,
        Rc::new(RefCell::new(transport)),
        Rc::new(per_sender_keys),
    ))
}

/// Build an authed API client and run `join_call_media`. The MLS exporter
/// is the realm's live, synchronised MLS group restored from this device's
/// persisted snapshot (the same group the message E2EE path uses), so the
/// SFrame exporter secret matches every other member's. When the realm has
/// not synced an MLS group on this device yet, the exporter construction
/// fails closed (`e2ee_key_source_unauthorised`) instead of fabricating an
/// isolated group.
///
/// This path is platform-uniform: the browser (wasm) build links the same SDK
/// MLS stack the chat/reaction send path already uses to restore the group and
/// read its epoch exporter secret, so the web call surface derives the SFrame
/// keyprovider seed in-process from the realm's real exporter secret — never a
/// self-minted key and never a backend bridge. A realm with no synced snapshot
/// on this device still fails closed on every platform.
async fn join_via_api(
    base: &str,
    api_token: &str,
    join: &MediaJoinRequest,
    authority: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    realm_mls_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<(JoinedMediaSession, PerSenderFrameKeys), RtcClientError> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let exporter = crate::media::rtc::RealmMlsExporter::for_realm(
        realm_mls_snapshot,
        secure_store.as_ref(),
        authority,
        device,
    )?;
    // Bind the SFrame frame key to the realm group's real MLS epoch instead
    // of the hard-coded `0` the dialer seeds the request with, so the key
    // rotates with the group epoch.
    let mut join = join.clone();
    join.epoch_id = exporter.epoch();
    let api = crate::transport::auth::authed_api(base, api_token.to_owned())
        .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
    let session = crate::media::rtc::join_call_media(&api, &join, &exporter).await?;
    // Retain the live MLS exporter (and the leg's static SFrame context) so the
    // transport can recompute every remote sender's frame key on
    // ParticipantConnected (§8.1). Building the deriver here keeps the exporter
    // alive past the local-key derivation instead of dropping it.
    let realm_id = arkret_sdk::RealmId::new(join.realm_id.clone())
        .map_err(|_| RtcClientError::FocusMismatch)?;
    let call_id =
        arkret_sdk::CallId::new(join.call_id.clone()).map_err(|_| RtcClientError::FocusMismatch)?;
    let per_sender_keys = PerSenderFrameKeys::new(
        exporter,
        realm_id,
        call_id.clone(),
        session.focus_id.clone(),
        session.epoch_id,
    );
    Ok((session, per_sender_keys))
}

/// Install the SFrame key and start local capture on a freshly built
/// transport.
///
/// Returns the transport's error when the keyprovider seed cannot be
/// installed (MEDIA-1: only the MLS-exporter-derived 32-byte key is accepted),
/// which the caller turns into a fail-closed end state rather than driving the
/// FSM to a fake `Active`/`Connecting`. On both web and desktop the SFU path
/// accepts the verified key here (desktop injects it into the webview LiveKit
/// E2EE provider during `connect_sfu`). Local capture is best-effort (a denied
/// camera/mic permission should not abort the call setup), so its failure is
/// not propagated.
pub(super) fn install_and_capture(
    transport: &SharedTransport,
    session: &JoinedMediaSession,
) -> Result<(), RtcClientError> {
    let mut t = transport.borrow_mut();
    // §8.1: the local key is sender-bound, installed under our own identity.
    t.install_frame_key(&session.participant_identity, &session.frame_key)?;
    let _ = t.start_local_capture();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn submit_call_state_participant(
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    target_state: arkret_sdk::CallLifecycleState,
    session: &JoinedMediaSession,
) -> Result<(), String> {
    let call_id = arkret_sdk::CallId::new(call_id.to_owned()).map_err(|err| err.to_string())?;
    let state_transition = arkret_sdk::CallStateTransition {
        from: match target_state {
            arkret_sdk::CallLifecycleState::Connecting => arkret_sdk::CallLifecycleState::Ringing,
            arkret_sdk::CallLifecycleState::Active => arkret_sdk::CallLifecycleState::Connecting,
            _ => return Err("call participant submission requires connecting or active".to_owned()),
        },
        to: target_state,
    };
    let (focus, roster_delta) = if target_state == arkret_sdk::CallLifecycleState::Connecting {
        let binding = &session.participant_binding;
        let participant_binding = arkret_sdk::ParticipantBinding {
            scheme: binding.scheme.clone(),
            realm_id: binding.realm_id.clone(),
            call_id: binding.call_id.as_str().to_owned(),
            focus_id: binding.focus_id.clone(),
            actor_id: binding.actor_id.clone(),
            device_id: binding.device_id.as_str().to_owned(),
            participant_id: binding.participant_id.clone(),
            issued_at: binding.issued_at,
            expires_at: binding.expires_at,
            issuer_kid: binding.issuer_kid.clone(),
            sig: binding.sig.clone(),
        };
        let participant = arkret_sdk::CallParticipant {
            actor_id: crate::mls_api_helpers::local_account_actor_id(actor)
                .map_err(|err| err.to_string())?,
            device_id: device.to_owned(),
            joined_at: None,
            foci_preferred: Some(vec![session.focus_id.clone()]),
            participant_id: session.participant_identity.clone(),
            participant_binding,
            media: Some(arkret_sdk::CallParticipantMedia {
                audio: Some(session.desired_media.audio),
                video: Some(session.desired_media.video),
                screen: Some(session.desired_media.screen),
            }),
        };
        (
            Some(arkret_sdk::CallFocus {
                mode: arkret_models_collaboration::events_payloads::call::CallMode::Sfu,
                session_focus: Some(
                    arkret_sdk::NonEmptyString::new(session.focus_id.clone())
                        .map_err(|err| err.to_string())?,
                ),
            }),
            Some(arkret_sdk::CallRosterDelta::Join { participant }),
        )
    } else {
        (None, None)
    };
    let payload = arkret_sdk::CallStatePayload {
        call_id: call_id.clone(),
        state_transition: Some(state_transition),
        focus,
        recording_transition: None,
        transcript_transition: None,
        roster_delta,
        moderation_delta: None,
        mute_override: None,
    };
    payload.validate().map_err(str::to_owned)?;
    let op = crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::CallState>(
        realm_id, actor, payload,
    )
    .target_ref(call_id.as_str())
    .build_sdk_event("inkson")
    .map_err(|err| err.to_string())?;
    with_authed_api(base, api_token.to_owned(), move |api| async move {
        api.event_submitter()?.submit_sdk_event(&op).await?;
        Ok(())
    })
    .await
    .map_err(|err| err.display())
}

pub(super) fn media_error_label(err: RtcClientError) -> String {
    format!("call failed: {} ({})", err.as_wire(), err.i18n_key())
}
