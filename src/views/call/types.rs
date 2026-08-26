use std::cell::RefCell;
use std::rc::Rc;

use crate::rtc_transport::MediaTransport;

/// Client-side call lifecycle FSM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallStage {
    Idle,
    IncomingRinging,
    OutgoingRinging,
    Connecting,
    Active,
    Ended,
}

impl CallStage {
    pub fn as_str(self) -> &'static str {
        match self {
            CallStage::Idle => "idle",
            CallStage::IncomingRinging | CallStage::OutgoingRinging => "ringing",
            CallStage::Connecting => "connecting",
            CallStage::Active => "active",
            CallStage::Ended => "ended",
        }
    }
}

/// Recording marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordingState {
    Off,
    Recording,
}

impl RecordingState {
    pub fn as_data_state(self) -> &'static str {
        match self {
            RecordingState::Off => "off",
            RecordingState::Recording => "recording",
        }
    }
}

/// Transcript capture marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptionState {
    Off,
    Transcribing,
}

impl TranscriptionState {
    pub fn as_data_state(self) -> &'static str {
        match self {
            TranscriptionState::Off => "off",
            TranscriptionState::Transcribing => "transcribing",
        }
    }
}

/// Roster entry for the participant grid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallParticipantView {
    pub actor_id: String,
    pub device_id: Option<String>,
    pub display_name: String,
    pub muted: bool,
    pub speaking: bool,
    pub screen_sharing: bool,
}

/// Boxed platform transport kept behind `Rc<RefCell<…>>` so the
/// component can drive its synchronous methods from event handlers while
/// the `!Send` JS handles (wasm) stay on the single UI task.
pub(super) type SharedTransport = Rc<RefCell<Box<dyn MediaTransport>>>;

#[derive(Clone, Copy, PartialEq)]
pub(super) enum CallStartMode {
    P2p,
    Sfu,
}
