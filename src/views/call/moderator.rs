use dioxus::prelude::*;

use super::signaling::emit_async;
use super::types::CallParticipantView;
use crate::ui::button::{Button, ButtonVariant};

fn moderation_signal(
    action: arkret_sdk::CallModerationAction,
    target_actor_id: Option<String>,
    target_device_id: Option<String>,
) -> Option<arkret_sdk::CallSignalData> {
    Some(arkret_sdk::CallSignalData::Moderation(
        arkret_sdk::CallModerationSignalData {
            action,
            target_actor_id: target_actor_id
                .as_deref()
                .map(crate::mls_api_helpers::principal_core_id)
                .transpose()
                .ok()?,
            target_device_id: target_device_id
                .map(arkret_sdk::DeviceId::new)
                .transpose()
                .ok()?,
            reason: None,
        },
    ))
}

/// Moderator controls (kick / ban / end-for-all). Moderator force-mute is
/// deferred in v1; these controls use the existing moderation signal.
#[component]
#[allow(clippy::too_many_arguments)]
pub(super) fn ModeratorControls(
    token: Signal<String>,
    realm_id: String,
    call_id: String,
    actor: String,
    device: String,
    participants: Signal<Vec<CallParticipantView>>,
    call_seq: Signal<u64>,
) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
    // Signal sealing burns the persisted MLS nonce counter, so every emit
    // needs the store, not just the key material descriptor.
    let signal_store = crate::app::runtime_adapter::state_store_handle(
        crate::app::SessionContext::get().state_store,
    );
    rsx! {
        div { class: "event", "data-testid": "call-moderator-controls",
            div { class: "event-head",
                span { "Moderator" }
                span { class: "muted", "kick / ban / end" }
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Destructive,
                    "data-testid": "call-end-for-all-button",
                    onclick: {
                        let base = base_url.clone();
                        let actor = actor.clone();
                        let device = device.clone();
                        let realm_id = realm_id.clone();
                        let call_id = call_id.clone();
                        let signal_store = signal_store.clone();
                        move |_| {
                            let Some(signal) = moderation_signal(
                                arkret_sdk::CallModerationAction::EndForAll,
                                None,
                                None,
                            ) else {
                                return;
                            };
                            emit_async(
                                &base, &token(), &realm_id, &call_id, &actor, &device,
                                signal,
                                call_seq,
                                signal_store.clone(),
                            );
                        }
                    },
                    "End for all"
                }
            }
            for p in participants().iter() {
                {
                    let target = p.actor_id.clone();
                    let target_device = p.device_id.clone();
                    let label = p.display_name.clone();
                    let base = base_url.clone();
                    let actor = actor.clone();
                    let device = device.clone();
                    let realm_id = realm_id.clone();
                    let call_id = call_id.clone();
                    rsx! {
                        div { class: "event-head", "data-testid": "call-moderator-row", "data-target": "{target}",
                            span { class: "mono", "{label}" }
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "call-kick-{target}",
                                onclick: {
                                    let base = base.clone();
                                    let actor = actor.clone();
                                    let device = device.clone();
                                    let realm_id = realm_id.clone();
                                    let call_id = call_id.clone();
                                    let target = target.clone();
                                    let target_device = target_device.clone();
                                    let signal_store = signal_store.clone();
                                    move |_| {
                                        let Some(target_device_id) = target_device.clone() else {
                                            return;
                                        };
                                        let Some(signal) = moderation_signal(
                                            arkret_sdk::CallModerationAction::Kick,
                                            Some(target.clone()),
                                            Some(target_device_id),
                                        ) else {
                                            return;
                                        };
                                        emit_async(
                                            &base, &token(), &realm_id, &call_id, &actor, &device,
                                            signal,
                                            call_seq,
                                            signal_store.clone(),
                                        );
                                    }
                                },
                                "Kick"
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "call-ban-{target}",
                                onclick: {
                                    let base = base.clone();
                                    let actor = actor.clone();
                                    let device = device.clone();
                                    let realm_id = realm_id.clone();
                                    let call_id = call_id.clone();
                                    let target = target.clone();
                                    let signal_store = signal_store.clone();
                                    move |_| {
                                        let Some(signal) = moderation_signal(
                                            arkret_sdk::CallModerationAction::Ban,
                                            Some(target.clone()),
                                            None,
                                        ) else {
                                            return;
                                        };
                                        emit_async(
                                            &base, &token(), &realm_id, &call_id, &actor, &device,
                                            signal,
                                            call_seq,
                                            signal_store.clone(),
                                        );
                                    }
                                },
                                "Ban"
                            }
                        }
                    }
                }
            }
        }
    }
}
