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
mod types;

/// Whether the host can turn an accepted media-service binding into the
/// authenticated `garth::RouteResolution` required before token exchange.
///
/// Inkson does not currently ship that host adapter. Keeping this explicit at
/// the product boundary prevents call buttons and inbound-ring navigation from
/// reaching a path that can only construct `verified_media_routes: []` and is
/// therefore guaranteed to fail closed.
#[must_use]
pub const fn media_route_adapter_available() -> bool {
    false
}

pub use panel::CallPanel;
pub use types::{CallParticipant, CallStage, RecordingState};
