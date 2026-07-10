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

pub use panel::CallPanel;
pub use types::{CallParticipant, CallStage, RecordingState};
