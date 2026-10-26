use std::rc::Rc;

use glory::prelude::*;

use super::signaling::emit_async;
use super::types::CallParticipantView;
use crate::presentation::{InksonContext, View, widgets};
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
                .map(serde_json::from_str::<arkret_sdk::ActorId>)
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

pub(super) fn moderator_controls(
    _scope: &Scope,
    context: Rc<InksonContext>,
    realm: Cage<String>,
    call: Cage<String>,
    participants: Cage<Vec<CallParticipantView>>,
    sequence: Cage<u64>,
) -> View {
    let end_context = context.clone();
    let end = sapid::button()
        .unstyled()
        .class("danger call-end-for-all-button")
        .label("End for all")
        .on_press(move || {
            let Some(account) = end_context.active_account.get() else {
                return;
            };
            if let Some(signal) =
                moderation_signal(arkret_sdk::CallModerationAction::EndForAll, None, None)
            {
                emit_async(
                    &end_context.base_url.get(),
                    &end_context.token.get(),
                    &realm.get(),
                    &call.get(),
                    account.principal_id().as_str(),
                    account.device_id.as_str(),
                    signal,
                    sequence,
                    end_context.state_store.handle(),
                );
            }
        });
    let rows = widgets::reactive(participants, move |_, participants| {
        widgets::stack(
            "call-moderator-rows",
            participants
                .into_iter()
                .map(|participant| {
                    let mut children = vec![widgets::paragraph("mono", participant.display_name)];
                    for (action, label) in [
                        (arkret_sdk::CallModerationAction::Kick, "Kick"),
                        (arkret_sdk::CallModerationAction::Ban, "Ban"),
                    ] {
                        let context = context.clone();
                        let target = participant.actor_id.clone();
                        let device = participant.device_id.clone();
                        let enabled =
                            action != arkret_sdk::CallModerationAction::Kick || device.is_some();
                        children.push(Box::new(
                            sapid::button()
                                .unstyled()
                                .class("danger")
                                .label(label)
                                .enabled(enabled)
                                .on_press(move || {
                                    let Some(account) = context.active_account.get() else {
                                        return;
                                    };
                                    let Some(signal) = moderation_signal(
                                        action,
                                        Some(target.clone()),
                                        if action == arkret_sdk::CallModerationAction::Kick {
                                            device.clone()
                                        } else {
                                            None
                                        },
                                    ) else {
                                        return;
                                    };
                                    emit_async(
                                        &context.base_url.get(),
                                        &context.token.get(),
                                        &realm.get(),
                                        &call.get(),
                                        account.principal_id().as_str(),
                                        account.device_id.as_str(),
                                        signal,
                                        sequence,
                                        context.state_store.handle(),
                                    );
                                }),
                        ) as View);
                    }
                    widgets::line("event-head call-moderator-row", children)
                })
                .collect(),
        )
    });
    widgets::stack(
        "event call-moderator-controls",
        vec![
            widgets::line(
                "event-head",
                vec![
                    widgets::plain("Moderator"),
                    widgets::paragraph("muted", "kick / ban / end"),
                ],
            ),
            Box::new(end),
            rows,
        ],
    )
}
