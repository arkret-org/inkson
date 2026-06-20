use std::cell::RefCell;
use std::rc::Rc;

use serde_json::json;

use super::types::SharedTransport;
use crate::media::rtc::{JoinedMediaSession, MediaJoinRequest, PerSenderFrameKeys, RtcClientError};
use crate::rtc_transport::new_transport;
use crate::views::helpers::with_authed_api;

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
    actor: &str,
    device: &str,
    realm_mls_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<(JoinedMediaSession, SharedTransport, Rc<PerSenderFrameKeys>), RtcClientError> {
    let (session, per_sender_keys) =
        join_via_api(base, api_token, join, actor, device, realm_mls_snapshot).await?;
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
    actor: &str,
    device: &str,
    realm_mls_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<(JoinedMediaSession, PerSenderFrameKeys), RtcClientError> {
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let exporter = crate::media::rtc::RealmMlsExporter::for_realm(
        realm_mls_snapshot,
        secure_store.as_ref(),
        actor,
        device,
    )?;
    // Bind the SFrame frame key to the realm group's real MLS epoch instead
    // of the hard-coded `0` the dialer seeds the request with, so the key
    // rotates with the group epoch.
    let mut join = join.clone();
    join.epoch_id = exporter.epoch();
    let api = crate::views::helpers::authed_api(base, api_token.to_owned())
        .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
    let session = crate::media::rtc::join_call_media(&api, &join, &exporter).await?;
    // Retain the live MLS exporter (and the leg's static SFrame context) so the
    // transport can recompute every remote sender's frame key on
    // ParticipantConnected (§8.1). Building the deriver here keeps the exporter
    // alive past the local-key derivation instead of dropping it.
    let realm_id = cokret_sdk::RealmId::new(join.realm_id.clone())
        .map_err(|_| RtcClientError::FocusMismatch)?;
    let call_id =
        cokret_sdk::CallId::new(join.call_id.clone()).map_err(|_| RtcClientError::FocusMismatch)?;
    let per_sender_keys = PerSenderFrameKeys::new(
        exporter,
        realm_id,
        call_id,
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
    state: &str,
    mode: &str,
    session: &JoinedMediaSession,
) -> Result<(), String> {
    let participant_binding = serde_json::to_value(&session.participant_binding)
        .map_err(|err| format!("participant_binding serialize failed: {err}"))?;
    let desired = session.desired_media;
    let participant = json!({
        "actor_id": actor,
        "device_id": device,
        "joined_at": crate::clock::now_rfc3339_secs(),
        "foci_preferred": [session.focus_id.clone()],
        "participant_identity": session.participant_identity.clone(),
        "participant_binding": participant_binding,
        "media": {
            "audio": desired.audio,
            "video": desired.video,
            "screen": desired.screen,
        },
    });
    let body = json!({
        "call_id": call_id,
        "state": state,
        "mode": mode,
        "session_focus": session.focus_id.clone(),
        "participants": [participant],
    });
    let op = crate::operation::OperationBuilder::new(realm_id, actor, "ck.call.state")
        .target_ref(call_id)
        .body(body)
        .build_sdk_event("yougen")
        .map_err(|err| err.to_string())?;
    with_authed_api(base, api_token.to_owned(), move |api| async move {
        api.submit_sdk_event(&op).await?;
        Ok(())
    })
    .await
    .map_err(|err| err.display())
}

pub(super) fn media_error_label(err: RtcClientError) -> String {
    format!("call failed: {} ({})", err.as_wire(), err.i18n_key())
}
