use dioxus::prelude::*;

use crate::{models::IceConfigResponse, views::helpers::authed_api};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallState {
    Idle,
    Ringing,
    Connecting,
    InCall,
    Ended,
}

#[component]
pub fn CallPanel(base_url: String, token: Signal<String>) -> Element {
    let start_call_base = base_url.clone();
    let video_call_base = base_url.clone();
    let refresh_ice_base = base_url.clone();
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
    let ice_ttl = use_signal(|| Option::<u64>::None);
    let mut new_ice_server = use_signal(String::new);
    let mut status_msg = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "call-panel",
            // Protocol model banner — claude-design desktop/call.html
            // crypto-media/webrtc-signaling.md §2 (signaling Ephemeral; media path != trust path)
            div { class: "event", "data-testid": "call-protocol-banner",
                div { class: "event-head",
                    span { "Realtime media model" }
                    span { "signaling = ephemeral · summary = durable" }
                }
                div { class: "muted",
                    "信令（offer/answer/ICE）通过 Sync Service Ephemeral channel 发送，不进入 Space history。通话结束后才写入 cx.morph.create morph_type=call 作为 durable record。媒体路径（TURN / SFU）不获得 Space 权限；MCU / 录制必须显式授权才能进入明文路径。"
                }
                div { class: "metric-grid", "data-testid": "call-protocol-metrics",
                    div { class: "metric",
                        strong { "Mode" }
                        span { "SFU (default ≥3 peers)" }
                        div { class: "muted", "p2p / mesh / sfu / mcu — 见 webrtc-signaling §3" }
                    }
                    div { class: "metric",
                        strong { "Media E2EE" }
                        span { "MLS-bound" }
                        div { class: "muted", "SFU 转发密文；不持有 Space 权限" }
                    }
                    div { class: "metric",
                        strong { "Recording" }
                        span { "denied by default" }
                        div { class: "muted", "需 capability=record_call + 全员同意" }
                    }
                    div { class: "metric",
                        strong { "Membership" }
                        span { "branch-scoped" }
                        div { class: "muted", "由 Flow discussion branch member 集合决定" }
                    }
                }
                // Three canonical call events — webrtc-signaling.md §4
                div { class: "actions", "data-testid": "call-event-kinds",
                    span { class: "muted", "Wire events:" }
                    span { class: "badge blue", "cx.call.signal · ephemeral (offer/answer/ICE)" }
                    span { class: "badge", "cx.call.state · ephemeral (ringing / in_call / ended)" }
                    span { class: "badge red", "cx.call.recording.start · durable + capability gated" }
                }
            }

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
                                    refresh_ice_servers(
                                        start_call_base.clone(),
                                        token(),
                                        ice_servers,
                                        ice_ttl,
                                        status_msg,
                                    );
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
                                    refresh_ice_servers(
                                        video_call_base.clone(),
                                        token(),
                                        ice_servers,
                                        ice_ttl,
                                        status_msg,
                                    );
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
                if let Some(ttl_seconds) = ice_ttl() {
                    div { class: "muted", "data-testid": "ice-ttl", "Config TTL: {ttl_seconds}s" }
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
                            "data-testid": "refresh-ice-config",
                            onclick: move |_| {
                                refresh_ice_servers(
                                    refresh_ice_base.clone(),
                                    token(),
                                    ice_servers,
                                    ice_ttl,
                                    status_msg,
                                );
                            },
                            "Load from Server"
                        }
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
                    div { class: "event-head", span { "Call Ended" } span { "writing cx.morph.create" } }
                    div { class: "muted", "Duration: {call_duration()}s" }
                    // Call Morph fields — claude-design desktop/call.html
                    // crypto-media/webrtc-signaling.md §4 (Call Morph)
                    div { class: "metric-grid", "data-testid": "call-morph-fields",
                        div { class: "metric",
                            strong { "morph_type" }
                            span { "call" }
                            div { class: "muted", "extensions/applet-integration not required" }
                        }
                        div { class: "metric",
                            strong { "fields.mode" }
                            span { "sfu" }
                            div { class: "muted", "p2p / mesh / sfu / mcu" }
                        }
                        div { class: "metric",
                            strong { "fields.state" }
                            span { "ended" }
                            div { class: "muted", "ringing → connecting → in_call → ended" }
                        }
                        div { class: "metric",
                            strong { "fields.recording" }
                            span { "none" }
                            div { class: "muted", "录制需独立 capability + 全员授权" }
                        }
                    }
                    div { class: "muted",
                        "通话摘要 / 参会者 / 共享文档引用 都作为 morph fields 落到 Space history；信令（offer/answer/ICE/speaking_update）已丢弃，不进入审计链。"
                    }
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
                        button {
                            class: "secondary",
                            "data-testid": "request-recording-button",
                            onclick: move |_| {
                                status_msg.set("recording 申请要求 capability=record_call + 全员显式同意".to_owned());
                            },
                            "Request recording grant"
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

fn refresh_ice_servers(
    base_url: String,
    access_token: String,
    mut ice_servers: Signal<Vec<String>>,
    mut ice_ttl: Signal<Option<u64>>,
    mut status_msg: Signal<String>,
) {
    spawn(async move {
        match authed_api(&base_url, access_token) {
            Ok(api) => match api.ice_config().await {
                Ok(config) => {
                    let servers = flatten_ice_servers(&config);
                    let count = servers.len();
                    if !servers.is_empty() {
                        ice_servers.set(servers);
                    }
                    ice_ttl.set(Some(config.ttl_seconds));
                    status_msg.set(format!(
                        "Loaded {count} ICE endpoint(s) from server (ttl {}s)",
                        config.ttl_seconds
                    ));
                }
                Err(error) => status_msg.set(format!("ICE config failed: {error}")),
            },
            Err(error) => status_msg.set(format!("Invalid URL: {error}")),
        }
    });
}

fn flatten_ice_servers(config: &IceConfigResponse) -> Vec<String> {
    config
        .ice_servers
        .iter()
        .flat_map(|server| server.urls.iter().cloned())
        .collect()
}
