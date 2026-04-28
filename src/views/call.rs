use dioxus::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallState {
    Idle,
    Ringing,
    Connecting,
    InCall,
    Ended,
}

#[component]
pub fn CallPanel(
    base_url: String,
    token: Signal<String>,
) -> Element {
    let mut call_state = use_signal(|| CallState::Idle);
    let mut target_did = use_signal(String::new);
    let mut audio_enabled = use_signal(|| true);
    let mut video_enabled = use_signal(|| false);
    let mut screen_share = use_signal(|| false);
    let mut call_duration = use_signal(|| 0u32);
    let mut ice_servers = use_signal(|| {
        vec![
            "stun:stun.l.google.com:19302".to_owned(),
            "turn:turn.example.com:3478".to_owned(),
        ]
    });
    let mut new_ice_server = use_signal(String::new);
    let mut status_msg = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "call-panel",
            // Call initiation
            div { class: "event", "data-testid": "call-init",
                div { class: "event-head", span { "Call" } span { match call_state() {
                    CallState::Idle => "idle",
                    CallState::Ringing => "ringing",
                    CallState::Connecting => "connecting",
                    CallState::InCall => "in-call",
                    CallState::Ended => "ended",
                }}}
                div { class: "workflow-form",
                    label { "Target DID" }
                    input {
                        "data-testid": "call-target-input",
                        value: "{target_did}",
                        placeholder: "did:web:bob.example",
                        oninput: move |evt| target_did.set(evt.value()),
                    }
                    div { class: "actions",
                        if call_state() == CallState::Idle {
                            button {
                                class: "primary",
                                "data-testid": "start-call-button",
                                onclick: move |_| {
                                    if target_did().is_empty() {
                                        status_msg.set("Enter a target DID".to_owned());
                                        return;
                                    }
                                    call_state.set(CallState::Ringing);
                                    status_msg.set(format!("Calling {}...", target_did()));
                                    // Simulate connection
                                    call_state.set(CallState::Connecting);
                                    call_state.set(CallState::InCall);
                                    call_duration.set(0);
                                },
                                "Start Call"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "start-video-button",
                                onclick: move |_| {
                                    if target_did().is_empty() {
                                        status_msg.set("Enter a target DID".to_owned());
                                        return;
                                    }
                                    video_enabled.set(true);
                                    call_state.set(CallState::Ringing);
                                    status_msg.set(format!("Video calling {}...", target_did()));
                                    call_state.set(CallState::InCall);
                                },
                                "Video Call"
                            }
                        }
                        if call_state() == CallState::InCall || call_state() == CallState::Ringing || call_state() == CallState::Connecting {
                            button {
                                class: "secondary",
                                "data-testid": "end-call-button",
                                onclick: move |_| {
                                    call_state.set(CallState::Ended);
                                    status_msg.set("Call ended".to_owned());
                                },
                                "End Call"
                            }
                        }
                        if call_state() == CallState::Ringing {
                            button {
                                class: "primary",
                                "data-testid": "accept-call-button",
                                onclick: move |_| {
                                    call_state.set(CallState::InCall);
                                    status_msg.set("Call connected".to_owned());
                                },
                                "Accept"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "reject-call-button",
                                onclick: move |_| {
                                    call_state.set(CallState::Ended);
                                    status_msg.set("Call rejected".to_owned());
                                },
                                "Reject"
                            }
                        }
                    }
                }
            }

            // In-call controls
            if call_state() == CallState::InCall {
                div { class: "event", "data-testid": "call-controls",
                    div { class: "event-head", span { "Controls" } span { "in-call" } }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Audio" }
                            span { if audio_enabled() { "On" } else { "Off" } }
                        }
                        div { class: "metric",
                            strong { "Video" }
                            span { if video_enabled() { "On" } else { "Off" } }
                        }
                        div { class: "metric",
                            strong { "Screen" }
                            span { if screen_share() { "Sharing" } else { "Off" } }
                        }
                        div { class: "metric",
                            strong { "Duration" }
                            span { "{call_duration()}s" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: if audio_enabled() { "primary" } else { "secondary" },
                            "data-testid": "toggle-audio",
                            onclick: move |_| audio_enabled.set(!audio_enabled()),
                            if audio_enabled() { "Mute" } else { "Unmute" }
                        }
                        button {
                            class: if video_enabled() { "primary" } else { "secondary" },
                            "data-testid": "toggle-video",
                            onclick: move |_| video_enabled.set(!video_enabled()),
                            if video_enabled() { "Stop Video" } else { "Start Video" }
                        }
                        button {
                            class: if screen_share() { "primary" } else { "secondary" },
                            "data-testid": "toggle-screen",
                            onclick: move |_| screen_share.set(!screen_share()),
                            if screen_share() { "Stop Share" } else { "Share Screen" }
                        }
                        button {
                            class: "secondary",
                            "data-testid": "end-call-in-controls",
                            onclick: move |_| {
                                call_state.set(CallState::Ended);
                                status_msg.set("Call ended".to_owned());
                            },
                            "End Call"
                        }
                    }
                }
            }

            // ICE server configuration
            div { class: "event", "data-testid": "ice-config",
                div { class: "event-head", span { "ICE Servers" } span { "STUN/TURN" } }
                for server in ice_servers() {
                    div { class: "muted", "data-testid": "ice-server", "{server}" }
                }
                div { class: "workflow-form",
                    input {
                        "data-testid": "new-ice-server-input",
                        value: "{new_ice_server}",
                        placeholder: "stun:stun.example.com:3478",
                        oninput: move |evt| new_ice_server.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "add-ice-server",
                            onclick: move |_| {
                                let server = new_ice_server().trim().to_owned();
                                if !server.is_empty() {
                                    ice_servers.write().push(server);
                                    new_ice_server.set(String::new());
                                }
                            },
                            "Add ICE Server"
                        }
                    }
                }
            }

            // Call ended summary
            if call_state() == CallState::Ended {
                div { class: "event", "data-testid": "call-ended",
                    div { class: "event-head", span { "Call Ended" } span { "" } }
                    div { class: "muted", "Duration: {call_duration()}s" }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "new-call-button",
                            onclick: move |_| {
                                call_state.set(CallState::Idle);
                                call_duration.set(0);
                                status_msg.set(String::new());
                            },
                            "New Call"
                        }
                    }
                }
            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "call-status", "{status_msg}" }
            }
        }
    }
}
