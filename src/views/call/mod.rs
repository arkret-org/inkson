//! Production call surface — voice / video / conference.
//!
//! This panel drives the full media plane: token exchange + ICE config +
//! MLS-exporter SFrame keying (`crate::media::rtc::join_call_media`), the
//! platform WebRTC transport (`crate::rtc_transport`), and the call FSM
//! (idle → ringing → connecting → active → ended). It handles both the 1:1
//! P2P path (offer/answer/candidate relayed over `ak.call.signal`) and SFU
//! group calls (room join + participant cross-check), plus moderator
//! controls and opt-in recording.
//!
//! Split from the original single-file `call.rs` into focused submodules:
//! call FSM / media types, the main panel, moderator controls, the signaling
//! receive/relay glue, the media-join controller helpers, and the local
//! call-state projection helpers. The external module path
//! (`crate::views::call::*`) and item visibility are preserved via the
//! re-exports below.

mod media;
mod moderator;
mod panel;
mod projection;
mod signaling;
mod surface;
mod task;
mod types;

/// The host consumes the registered own-Station media binding result, tied
/// to its active account and the Realm's accepted issuer. Direct DID material
/// is not media credential authority for the ordinary logged-in client.
#[must_use]
pub const fn media_route_adapter_available() -> bool {
    true
}

pub use panel::{CallPanelProps, call_panel};
pub fn page(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    route: crate::routes::Route,
) -> crate::presentation::View {
    let crate::routes::Route::Call {
        call_id,
        peer,
        realm_id,
        video,
        incoming,
    } = route
    else {
        return crate::presentation::widgets::empty();
    };
    let realm = if realm_id.is_empty() {
        context.selected_realm_id.get()
    } else {
        realm_id
    };
    let principal = context
        .principal_id
        .get()
        .map(|value| value.to_string())
        .unwrap_or_default();
    let device = context.device_id.get();
    call_panel(
        scope,
        context,
        CallPanelProps {
            selected_realm_id: realm,
            principal_id: principal,
            device_id: device,
            call_id,
            peer,
            want_video: video == "1",
            incoming: incoming == "1",
        },
    )
}
pub use types::{CallParticipantView, CallStage, RecordingState};
