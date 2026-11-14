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
        label: impl Into<Vary<String>>,
        enabled: impl Into<Vary<bool>>,
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
        label: impl Into<Vary<String>>,
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
fn label(class: &str, value: impl Into<Vary<String>>) -> View {
    Box::new(text().class(class.to_owned()).content(value))
}
fn field(
    scope: &Scope,
    key: &str,
    title: impl Into<Vary<String>>,
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
    let target_context = context.clone();
    let target = scope.bond(move || {
        let _ = target_context.state_revision.get();
        let _ = target_context.locale.get();
        let realm = state.active_realm.get();
        let peer = state.peer_input.get();
        let title = target_context.state_store.read(|store| {
            if peer.is_empty() {
                target_context
                    .realm_tree_nodes
                    .get()
                    .iter()
                    .find(|node| {
                        node.id == realm && node.kind == crate::models::RealmTreeNodeKind::Realm
                    })
                    .map(|node| node.title.clone())
                    .filter(|title| !title.trim().is_empty())
                    .unwrap_or_else(|| crate::views::helpers::short_protocol_id(&realm))
            } else {
                crate::views::helpers::actor_display_label(store, &peer)
            }
        });
        if title.is_empty() {
            crate::i18n::tr("call.choose_target")
        } else {
            title
        }
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
    let mut identity = Some(identity);
    let identity: View = Box::new(
        sapid::collapsible(format!("call-details-{}", scope.id().slot()))
            .unstyled()
            .class("call-technical-details")
            .label(context.translated(scope, "call.technical_details"))
            .default_open(false)
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .content(move || identity.take().unwrap_or_else(widgets::empty)),
    );
    let call_target = block("call-target", vec![label("call-target-name", target)]);
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
                    arkret_sdk::RealmId::new(state.active_realm.get()).is_ok()
                        && !super::projection::participant_list_from_input(&state.group_input.get())
                            .is_empty()
                        && (!decryption.get() || state.media_plaintext_confirmed.get())
                });
                let mut technical = Some(block(
                    "call-manual-fields",
                    vec![
                        field(scope, "realm", "Realm", state.active_realm, false, state),
                        field(scope, "peer", "Peer (1:1)", state.peer_input, false, state),
                        field(
                            scope,
                            "group",
                            "Group participants (SFU)",
                            state.group_input,
                            true,
                            state,
                        ),
                    ],
                ));
                let manual: View = Box::new(
                    sapid::collapsible(format!("call-manual-{}", scope.id().slot()))
                        .unstyled()
                        .class("call-manual-targets")
                        .label(context.translated(scope, "call.manual_targets"))
                        .default_open(state.active_realm.get_untracked().is_empty())
                        .content_policy(sapid::ContentPolicy::KeepMounted)
                        .content(move || technical.take().unwrap_or_else(widgets::empty)),
                );
                let targets = call_targets(scope, context.clone(), state);
                block(
                    "event call-dialer",
                    vec![
                        targets,
                        manual,
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
        vec![block(
            "event",
            vec![header, call_target, phase, status, error, identity],
        )],
    )
}

fn call_targets(scope: &Scope, context: Rc<InksonContext>, state: CallSurface) -> View {
    let source_context = context.clone();
    let source = scope.bond(move || {
        (
            state.active_realm.get(),
            source_context.state_revision.get(),
        )
    });
    widgets::reactive_distinct(source, move |scope, (realm, _)| {
        let rows = context.state_store.read(|store| {
            let snapshot = store.load();
            crate::views::member_display::realm_member_roster(
                snapshot.realm_tree_projections.get(&realm),
            )
        });
        let own = context
            .principal_id
            .get_untracked()
            .map(|id| id.to_string())
            .unwrap_or_default();
        let mut choices = Vec::new();
        for row in rows
            .into_iter()
            .filter(|row| row.membership == Some(arkret_sdk::sync::MemberRosterMembership::Join))
        {
            let peer = row.actor_id.signing_principal_id().to_string();
            if peer == own {
                continue;
            }
            let name = context.state_store.read(|store| {
                crate::views::member_display::resolve_member_display(store, &realm, &row).label
            });
            let selected = peer.clone();
            choices.push(Box::new(
                sapid::checkbox()
                    .unstyled()
                    .class("checkbox-row call-target-choice")
                    .label(name)
                    .checked(scope.bond(move || {
                        super::projection::participant_list_from_input(&state.group_input.get())
                            .contains(&selected)
                    }))
                    .on_checked_change(move |checked| {
                        let mut peers = super::projection::participant_list_from_input(
                            &state.group_input.get_untracked(),
                        );
                        peers.retain(|value| value != &peer);
                        if checked {
                            peers.push(peer.clone());
                        }
                        state.group_input.revise(|value| *value = peers.join("\n"));
                    }),
            ) as View);
        }
        if choices.is_empty() {
            return label(
                "muted call-target-hint",
                context.translated(scope, "call.context_hint"),
            );
        }
        let mut choices = Some(block("call-target-choices", choices));
        Box::new(
            sapid::collapsible(format!("call-members-{}", scope.id().slot()))
                .unstyled()
                .class("call-member-picker")
                .label(context.translated(scope, "call.choose_members"))
                .default_open(state.peer_input.get_untracked().is_empty())
                .content_policy(sapid::ContentPolicy::KeepMounted)
                .content(move || choices.take().unwrap_or_else(widgets::empty)),
        )
    })
}
