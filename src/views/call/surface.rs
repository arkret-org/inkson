//! The retained call phase uses native Sapid controls and the original layout.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use glory::prelude::*;

use super::types::{CallParticipantView, CallStage, RecordingState, TranscriptionState};
use crate::presentation::{InksonContext, View, widgets};

type Callback = Rc<RefCell<Box<dyn FnMut()>>>;

#[derive(Default, Clone)]
pub(super) struct Callbacks(BTreeMap<&'static str, Callback>);
impl Callbacks {
    pub fn add(&mut self, key: &'static str, callback: impl FnMut() + 'static) {
        self.0
            .insert(key, Rc::new(RefCell::new(Box::new(callback))));
    }
    fn button(
        &self,
        key: &'static str,
        label: impl Into<Lotus<String>>,
        enabled: impl Into<Lotus<bool>>,
        destructive: bool,
    ) -> View {
        let callback = self.0.get(key).cloned();
        let class = if destructive {
            format!("btn danger btn-danger {key}")
        } else if matches!(
            key,
            "call-start-voice-button" | "call-accept-button" | "call-capture-confirm-button"
        ) {
            format!("primary {key}")
        } else {
            format!("btn secondary btn-secondary {key}")
        };
        Box::new(
            sapid::button()
                .unstyled()
                .class(class)
                .label(label)
                .enabled(enabled)
                .on_press(move || {
                    if let Some(callback) = &callback {
                        (callback.borrow_mut())();
                    }
                }),
        )
    }
    fn toggle(
        &self,
        scope: &Scope,
        key: &'static str,
        label: impl Into<Lotus<String>>,
        pressed: Cage<bool>,
    ) -> View {
        let callback = self.0.get(key).cloned();
        Box::new(
            sapid::toggle()
                .unstyled()
                .class(scope.bond(move || {
                    let primary = (key == "call-mute-button" && pressed.get())
                        || (key == "call-camera-button" && !pressed.get());
                    if primary {
                        format!("primary {key}")
                    } else {
                        format!("btn secondary btn-secondary {key}")
                    }
                }))
                .label(label)
                .pressed(pressed)
                .on_pressed_change(move |_| {
                    if let Some(callback) = &callback {
                        (callback.borrow_mut())();
                    }
                }),
        )
    }
}
#[derive(Clone, Copy)]
pub(super) struct CallSurface {
    pub stage: Cage<CallStage>,
    pub status: Cage<String>,
    pub last_error: Cage<String>,
    pub mic_muted: Cage<bool>,
    pub camera_on: Cage<bool>,
    pub screen_sharing: Cage<bool>,
    pub recording: Cage<RecordingState>,
    pub transcription: Cage<TranscriptionState>,
    pub pending_capture: Cage<Option<String>>,
    pub participants: Cage<Vec<CallParticipantView>>,
    pub active_call_id: Cage<String>,
    pub active_realm: Cage<String>,
    pub peer_input: Cage<String>,
    pub group_input: Cage<String>,
    pub want_video_signal: Cage<bool>,
    pub media_plaintext_confirmed: Cage<bool>,
    pub call_seq: Cage<u64>,
}
fn block(class: &str, children: Vec<View>) -> View {
    Box::new(view().class(class.to_owned()).fill(children))
}
fn label(class: &str, value: impl Into<Lotus<String>>) -> View {
    Box::new(text().class(class.to_owned()).content(value))
}
fn field(
    scope: &Scope,
    key: &str,
    title: impl Into<Lotus<String>>,
    value: Cage<String>,
    multiline: bool,
    state: CallSurface,
) -> View {
    let reset = key == "realm";
    let key = key.to_owned();
    let mut field = sapid::field(format!("call-{}-{key}", scope.id().slot()))
        .unstyled()
        .class(format!("form-row call-{key}-field"))
        .label(title);
    if key == "peer" {
        field = field.description(scope.bond(move || {
            if value.get().is_empty() {
                "ak:did_core:web:bob.example".to_owned()
            } else {
                String::new()
            }
        }));
    }
    Box::new(field.control(move |control| {
        sapid::text_field()
            .unstyled()
            .class(format!("input call-{key}-input"))
            .field(control)
            .value(value)
            .multiline(multiline)
            .on_value_change(move |next| {
                value.revise(|value| *value = next);
                if reset {
                    state
                        .media_plaintext_confirmed
                        .revise(|value| *value = false);
                }
            })
    }))
}
fn media_consent(_scope: &Scope, state: CallSurface, required: Bond<bool>) -> View {
    widgets::reactive_distinct(required, move |_, required| {
        if required {
            Box::new(
                sapid::checkbox()
                    .unstyled()
                    .class("checkbox-row call-media-plaintext-confirm")
                    .label("Media service can decrypt this call")
                    .checked(state.media_plaintext_confirmed)
                    .on_checked_change(move |next| {
                        state
                            .media_plaintext_confirmed
                            .revise(|value| *value = next)
                    }),
            )
        } else {
            widgets::empty()
        }
    })
}
pub(super) fn surface(
    scope: &Scope,
    context: Rc<InksonContext>,
    state: CallSurface,
    callbacks: Callbacks,
    decryption: Bond<bool>,
    actor: String,
    device: String,
) -> View {
    let account_context = context.clone();
    let account_label = scope.bond(move || {
        let _ = account_context.state_revision.get();
        account_context
            .state_store
            .read(|store| crate::views::helpers::actor_display_label(store, &actor))
    });
    let device_label = crate::views::helpers::short_protocol_id(&device);
    let signal_context = context.clone();
    let signal_count = label(
        "mono call-signal-count",
        scope.bond(move || {
            signal_context
                .snapshot()
                .raw_operations
                .iter()
                .filter(|record| {
                    record
                        .payload
                        .get("kind")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|kind| kind.starts_with("ak.call."))
                })
                .count()
                .to_string()
        }),
    );
    let header = block(
        "event-head",
        vec![
            widgets::plain("Calls"),
            label(
                "badge call-stage",
                scope.bond(move || state.stage.get().as_str().to_owned()),
            ),
            signal_count,
        ],
    );
    let identity = block(
        "event-head",
        vec![
            label(
                "mono call-active-id",
                scope.bond(move || {
                    let id = state.active_call_id.get();
                    if id.is_empty() {
                        "no active call".into()
                    } else {
                        id
                    }
                }),
            ),
            label("mono", account_label),
            label("mono", device_label),
        ],
    );
    let phase_context = context.clone();
    let phase_callbacks = callbacks.clone();
    let phase = widgets::reactive_distinct(state.stage, move |scope, phase| {
        let context = phase_context.clone();
        let callbacks = phase_callbacks.clone();
        match phase {
            CallStage::Idle => {
                let can_voice = scope.bond(move || {
                    !state.active_realm.get().trim().is_empty()
                        && !state.peer_input.get().trim().is_empty()
                        && (!decryption.get() || state.media_plaintext_confirmed.get())
                });
                let can_group = scope.bond(move || {
                    !state.active_realm.get().trim().is_empty()
                        && (!decryption.get() || state.media_plaintext_confirmed.get())
                });
                block(
                    "event call-dialer",
                    vec![
                        field(
                            scope,
                            "realm",
                            context.translated(scope, "friendly.realm"),
                            state.active_realm,
                            false,
                            state,
                        ),
                        field(scope, "peer", "Peer (1:1)", state.peer_input, false, state),
                        field(
                            scope,
                            "group",
                            "Group participants (SFU)",
                            state.group_input,
                            true,
                            state,
                        ),
                        media_consent(scope, state, decryption),
                        block(
                            "actions",
                            vec![
                                callbacks.toggle(
                                    scope,
                                    "call-want-video-toggle",
                                    scope.bond(move || {
                                        if state.want_video_signal.get() {
                                            "Video: on"
                                        } else {
                                            "Video: off"
                                        }
                                        .to_owned()
                                    }),
                                    state.want_video_signal,
                                ),
                                callbacks.button(
                                    "call-start-voice-button",
                                    "Start 1:1 call",
                                    can_voice,
                                    false,
                                ),
                                callbacks.button(
                                    "call-start-group-button",
                                    "Start group call",
                                    can_group,
                                    false,
                                ),
                            ],
                        ),
                    ],
                )
            }
            CallStage::OutgoingRinging => block(
                "event call-outgoing-banner",
                vec![
                    label("event-head", "Calling"),
                    label("mono", state.peer_input),
                    callbacks.button("call-cancel-button", "Cancel", true, true),
                ],
            ),
            CallStage::IncomingRinging => block(
                "event call-incoming-banner",
                vec![
                    label("event-head", "Incoming call"),
                    label("mono", state.peer_input),
                    media_consent(scope, state, decryption),
                    block(
                        "actions",
                        vec![
                            callbacks.button(
                                "call-accept-button",
                                "Accept",
                                scope.bond(move || {
                                    !decryption.get() || state.media_plaintext_confirmed.get()
                                }),
                                false,
                            ),
                            callbacks.button("call-decline-button", "Decline", true, true),
                        ],
                    ),
                ],
            ),
            CallStage::Connecting => block(
                "event call-connecting-panel",
                vec![
                    label("event-head", "Connecting"),
                    label("badge badge-info", "SDP / ICE"),
                ],
            ),
            CallStage::Active => {
                let grid = widgets::reactive(state.participants, |_, participants| {
                    block(
                        "call-grid",
                        participants
                            .into_iter()
                            .map(|p| {
                                let mut badges = vec![];
                                if p.muted {
                                    badges.push(label("badge", "muted"));
                                }
                                if p.speaking {
                                    badges.push(label("badge badge-success", "speaking"));
                                }
                                if p.screen_sharing {
                                    badges.push(label("badge badge-info", "screen"));
                                }
                                block(
                                    if p.speaking {
                                        "call-tile speaking"
                                    } else {
                                        "call-tile"
                                    },
                                    vec![
                                        label("call-tile-name mono", p.display_name),
                                        block("call-tile-badges", badges),
                                    ],
                                )
                            })
                            .collect(),
                    )
                });
                let capture_callbacks = callbacks.clone();
                let capture = widgets::reactive_distinct(state.pending_capture, move |_, kind| {
                    if let Some(kind) = kind {
                        block(
                            "event call-capture-confirmation",
                            vec![
                                label(
                                    "event-head",
                                    if kind == "recording" {
                                        "Confirm recording"
                                    } else {
                                        "Confirm transcription"
                                    },
                                ),
                                label("badge danger", "capture"),
                                block(
                                    "actions",
                                    vec![
                                        capture_callbacks.button(
                                            "call-capture-confirm-button",
                                            "Confirm",
                                            true,
                                            false,
                                        ),
                                        capture_callbacks.button(
                                            "call-capture-cancel-button",
                                            "Cancel",
                                            true,
                                            false,
                                        ),
                                    ],
                                ),
                            ],
                        )
                    } else {
                        widgets::empty()
                    }
                });
                block(
                    "event call-active-panel",
                    vec![
                        block(
                            "event-head",
                            vec![
                                label("", "In call"),
                                label("badge green", "active"),
                                label(
                                    "badge call-mic-status",
                                    scope.bond(move || {
                                        if state.mic_muted.get() {
                                            "mic muted"
                                        } else {
                                            "mic live"
                                        }
                                        .to_owned()
                                    }),
                                ),
                                label(
                                    "badge call-screen-status",
                                    scope.bond(move || {
                                        if state.screen_sharing.get() {
                                            "screen sharing"
                                        } else {
                                            "screen off"
                                        }
                                        .to_owned()
                                    }),
                                ),
                                label(
                                    "badge call-recording-status",
                                    scope.bond(move || {
                                        format!("rec: {}", state.recording.get().as_data_state())
                                    }),
                                ),
                                label(
                                    "badge call-transcription-status",
                                    scope.bond(move || {
                                        format!("tx: {}", state.transcription.get().as_data_state())
                                    }),
                                ),
                            ],
                        ),
                        grid,
                        block(
                            "actions call-controls",
                            vec![
                                callbacks.toggle(
                                    scope,
                                    "call-mute-button",
                                    scope.bond(move || {
                                        if state.mic_muted.get() {
                                            "Unmute"
                                        } else {
                                            "Mute"
                                        }
                                        .to_owned()
                                    }),
                                    state.mic_muted,
                                ),
                                callbacks.toggle(
                                    scope,
                                    "call-camera-button",
                                    scope.bond(move || {
                                        if state.camera_on.get() {
                                            "Camera off"
                                        } else {
                                            "Camera on"
                                        }
                                        .to_owned()
                                    }),
                                    state.camera_on,
                                ),
                                callbacks.toggle(
                                    scope,
                                    "call-screen-share-button",
                                    scope.bond(move || {
                                        if state.screen_sharing.get() {
                                            "Stop sharing"
                                        } else {
                                            "Share screen"
                                        }
                                        .to_owned()
                                    }),
                                    state.screen_sharing,
                                ),
                                callbacks.button(
                                    "call-record-button",
                                    scope.bond(move || {
                                        if state.recording.get() == RecordingState::Recording {
                                            "Stop recording"
                                        } else {
                                            "Record"
                                        }
                                        .to_owned()
                                    }),
                                    true,
                                    false,
                                ),
                                callbacks.button(
                                    "call-transcribe-button",
                                    scope.bond(move || {
                                        if state.transcription.get()
                                            == TranscriptionState::Transcribing
                                        {
                                            "Stop transcribing"
                                        } else {
                                            "Transcribe"
                                        }
                                        .to_owned()
                                    }),
                                    true,
                                    false,
                                ),
                                callbacks.button("call-leave-button", "Leave", true, true),
                            ],
                        ),
                        capture,
                        super::moderator::moderator_controls(
                            scope,
                            context,
                            state.active_realm,
                            state.active_call_id,
                            state.participants,
                            state.call_seq,
                        ),
                    ],
                )
            }
            CallStage::Ended => block(
                "event call-ended-panel",
                vec![
                    label("", "Call ended"),
                    callbacks.button("call-reset-button", "New call", true, false),
                ],
            ),
        }
    });
    let status = widgets::reactive(state.status, |_, value| {
        if value.is_empty() {
            widgets::empty()
        } else {
            Box::new(
                view()
                    .role(Role::Status)
                    .class("muted call-status")
                    .fill(widgets::plain(value)),
            )
        }
    });
    let error = widgets::reactive(state.last_error, |_, value| {
        if value.is_empty() {
            widgets::empty()
        } else {
            Box::new(
                view()
                    .role(Role::Alert)
                    .class("muted error call-error")
                    .fill(widgets::plain(value)),
            )
        }
    });
    block(
        "timeline call-panel",
        vec![block("event", vec![header, identity, phase, status, error])],
    )
}
