//! Scheduled-send composer panel (spec `models/personal-productivity.md` §4).
//!
//! The panel is the plan-lifecycle UI: it creates, lists, modifies, and
//! cancels `ak.scheduled_send.v1` plans for the discussion the composer is
//! bound to. Writes go through encrypted account-data revision updates
//! loop; expiry dispatch itself is the session-wide driver in
//! [`crate::scheduled_send`].

use super::*;

#[derive(Clone)]
pub(super) struct ScheduledSendPanelContext {
    pub realm_id: String,
    pub strand_id: String,
    pub authority: arkret_sdk::AccountId,
    pub device_id: arkret_sdk::DeviceId,
    pub token: Cage<String>,
    pub draft: Cage<String>,
    pub status_msg: Cage<String>,
    pub writable: Lotus<bool>,
}

fn plan_body_preview(value: &arkret_sdk::ScheduledSendValue) -> String {
    value
        .message_payload
        .content
        .as_ref()
        .map(|content| content.body.clone())
        .unwrap_or_default()
}

/// Flat, comparable view of one staged plan for distinct reactive publication,
/// which the SDK value does not implement.
#[derive(Clone, PartialEq)]
struct ScheduledSendPlanView {
    scheduled_send_id: String,
    account_data_key: String,
    strand_id: String,
    send_at: String,
    body: String,
}

impl ScheduledSendPlanView {
    fn from_plan(plan: &crate::scheduled_send::DueScheduledSendPlan) -> Self {
        Self {
            scheduled_send_id: plan.value.scheduled_send_id.to_string(),
            account_data_key: plan.account_data_key.clone(),
            strand_id: plan.value.message_payload.strand_id.to_string(),
            send_at: plan.value.send_at.clone(),
            body: plan_body_preview(&plan.value),
        }
    }
}

pub(super) fn scheduled_send_panel(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    context: ScheduledSendPanelContext,
) -> View {
    use super::native::{block, button, date_time, field};
    use crate::presentation::widgets::{line, paragraph, reactive_distinct};
    let ScheduledSendPanelContext {
        realm_id,
        strand_id,
        authority,
        device_id,
        token,
        draft,
        status_msg,
        writable,
    } = context;
    let writable = scope.bond(move || writable.get());
    let base_url = app.base_url.get_untracked();
    let state_store = app.state_store.clone();
    let new_send_at = scope.cage(String::new());
    let editing_plan_id = scope.cage(None::<String>);
    let edit_send_at = scope.cage(String::new());
    let edit_body = scope.cage(String::new());
    let refresh = scope.cage(0_u64);
    let plan_store = state_store.clone();
    let plan_authority = authority.clone();
    let plan_strand = strand_id.clone();
    let revision = app.state_revision;
    let plans = scope.bond(move || {
        let _ = refresh.get();
        let _ = revision.get();
        plan_store.read(|store| {
            crate::scheduled_send::staged_scheduled_send_plans(&plan_authority, store)
                .iter()
                .filter(|plan| plan.value.message_payload.strand_id.as_str() == plan_strand)
                .map(ScheduledSendPlanView::from_plan)
                .collect::<Vec<_>>()
        })
    });
    let create_plan = {
        let state_store = state_store.clone();
        {
            let realm_id = realm_id.clone();
            let strand_id = strand_id.clone();
            let authority = authority.clone();
            let device_id = device_id.clone();
            let base_url = base_url.clone();
            move || {
                if !writable.get_untracked() {
                    return;
                }
                let body = draft.get().trim().to_owned();
                if body.is_empty() {
                    {
                        let next_value = crate::i18n::tr("chat.scheduled_send.needs_body");
                        status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
                let send_at =
                    match crate::clock::local_datetime_input_to_canonical(&new_send_at.get()) {
                        Ok(send_at) => send_at,
                        Err(error) => {
                            {
                                let next_value = format!("{error:#}");
                                status_msg.revise(|value| *value = next_value);
                            };
                            return;
                        }
                    };
                let content = match chat_content_block_for_body(&body) {
                    Ok(content) => content,
                    Err(error) => {
                        {
                            let next_value = format!("{error:#}");
                            status_msg.revise(|value| *value = next_value);
                        };
                        return;
                    }
                };
                let strand = match arkret_sdk::StrandId::new(strand_id.clone()) {
                    Ok(strand) => strand,
                    Err(error) => {
                        {
                            let next_value = format!("invalid strand id: {error}");
                            status_msg.revise(|value| *value = next_value);
                        };
                        return;
                    }
                };
                let payload =
                    arkret_sdk::MessageCreatePayload::with_content(strand, "discussion", content);
                let prepared = match crate::scheduled_send::prepare_scheduled_send_plan(
                    &authority, &device_id, None, &send_at, payload,
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        {
                            let next_value = format!("{error:#}");
                            status_msg.revise(|value| *value = next_value);
                        };
                        return;
                    }
                };
                let scheduled_send_id = prepared.value.scheduled_send_id.to_string();
                state_store.write(|value| {
                    value.stage_scheduled_send_account_data_entry(
                        &prepared.account_data_key,
                        prepared.encrypted_entry.clone(),
                    )
                });
                state_store.write(|value| {
                    value.set_scheduled_send_target_realm(&scheduled_send_id, &realm_id)
                });
                {
                    let next_value = String::new();
                    draft.revise(|value| *value = next_value);
                };
                {
                    let next_value = String::new();
                    new_send_at.revise(|value| *value = next_value);
                };
                refresh.revise(|value| *value = value.wrapping_add(1));
                {
                    let next_value = crate::i18n::tr("chat.scheduled_send.created");
                    status_msg.revise(|value| *value = next_value);
                };
                let api_token = token.get();
                let base = base_url.clone();
                let status_msg = status_msg;
                super::task::dispatch(async move {
                    let result = crate::transport::auth::with_event_submitter(
                        &base,
                        api_token,
                        |submitter| async move {
                            crate::transport::account::put_scheduled_send_plan(
                                &submitter,
                                &prepared.value,
                            )
                            .await
                        },
                    )
                    .await;
                    if let Err(error) = result {
                        {
                            let next_value =
                                format!("Scheduled send stayed local: {}", error.display());
                            status_msg.revise(|value| *value = next_value);
                        };
                    }
                });
            }
        }
    };
    let rows_app = app.clone();
    let rows = reactive_distinct(plans, move |scope, plans| {
        if plans.is_empty() {
            return paragraph(
                "muted scheduled-send-empty",
                rows_app.translated(scope, "chat.scheduled_send.empty"),
            );
        }
        let children=plans.into_iter().map(|plan|{
            let plan_id=plan.scheduled_send_id.clone();let plan_key=plan.account_data_key.clone();let editing_id=plan_id.clone();
            let phase=scope.bond(move||editing_plan_id.get().as_deref()==Some(editing_id.as_str()));
            let state_store=state_store.clone();let authority=authority.clone();let device_id=device_id.clone();let base_url=base_url.clone();let app=rows_app.clone();
            reactive_distinct(phase,move|scope,is_editing|{
                if is_editing {
                    let save={let state_store=state_store.clone();{
                                            let authority = authority.clone();
                                            let device_id = device_id.clone();
                                            let plan_id = plan_id.clone();
                                            let plan_key = plan_key.clone();
                                            let base = base_url.clone();
                                            let strand_id = plan.strand_id.clone();
                                            move || {
                                                if !writable.get_untracked() { return; }
                                                let send_at = match crate::clock::local_datetime_input_to_canonical(&edit_send_at.get()) {
                                                    Ok(send_at) => send_at,
                                                    Err(error) => {
                                                        { let next_value = format!("{error:#}"); status_msg.revise(|value| *value = next_value); };
                                                        return;
                                                    }
                                                };
                                                let body = edit_body.get().trim().to_owned();
                                                let content = match chat_content_block_for_body(&body) {
                                                    Ok(content) => content,
                                                    Err(error) => {
                                                        { let next_value = format!("{error:#}"); status_msg.revise(|value| *value = next_value); };
                                                        return;
                                                    }
                                                };
                                                let strand = match arkret_sdk::StrandId::new(strand_id.clone()) {
                                                    Ok(strand) => strand,
                                                    Err(error) => {
                                                        { let next_value = format!("invalid strand id: {error}"); status_msg.revise(|value| *value = next_value); };
                                                        return;
                                                    }
                                                };
                                                let payload = arkret_sdk::MessageCreatePayload::with_content(
                                                    strand,
                                                    "discussion",
                                                    content,
                                                );
                                                 let prepared = match crate::scheduled_send::prepare_scheduled_send_plan(
                                                     &authority,
                                                    &device_id,
                                                    Some(&plan_id),
                                                    &send_at,
                                                    payload,
                                                ) {
                                                    Ok(prepared) => prepared,
                                                    Err(error) => {
                                                        { let next_value = format!("{error:#}"); status_msg.revise(|value| *value = next_value); };
                                                        return;
                                                    }
                                                };
                                                state_store.write(|value| value.stage_scheduled_send_account_data_entry(
                                                        &plan_key,
                                                        prepared.encrypted_entry.clone(),
                                                    ));
                                                { let next_value = None; editing_plan_id.revise(|value| *value = next_value); };
                                                refresh.revise(|value|*value=value.wrapping_add(1));
                                                { let next_value = crate::i18n::tr("chat.scheduled_send.updated"); status_msg.revise(|value| *value = next_value); };
                                                let api_token = token.get();
                                                let base = base.clone();
                                                let status_msg = status_msg;
                                                super::task::dispatch(async move {
                                                    let result = crate::transport::auth::with_event_submitter(
                                                        &base,
                                                        api_token,
                                                        |submitter| async move {
                                                            crate::transport::account::put_scheduled_send_plan(
                                                                &submitter,
                                                                &prepared.value,
                                                            )
                                                            .await
                                                        },
                                                    )
                                                    .await;
                                                    if let Err(error) = result {
                                                        { let next_value = format!(
                                                            "Scheduled send update stayed local: {}",
                                                            error.display()
                                                        ); status_msg.revise(|value| *value = next_value); };
                                                    }
                                                });
                                            }
                                        }};
                    block("scheduled-send-row",vec![date_time(scope,app.clone(),format!("scheduled-send-edit-{}",plan_id),"Send at",edit_send_at),field("Message","scheduled-send-edit-body-input",edit_body,true,move|value|edit_body.revise(|text|*text=value)),line("actions",vec![button(app.translated(scope,"chat.scheduled_send.save"),"primary scheduled-send-save-button",writable,save),button(app.translated(scope,"chat.scheduled_send.dismiss_edit"),"secondary scheduled-send-edit-cancel-button",true,move||editing_plan_id.revise(|value|*value=None))])])
                } else {
                    let edit={
                                            let plan_id = plan_id.clone();
                                            let send_at_input = crate::clock::canonical_to_local_datetime_input(
                                                &plan.send_at,
                                            )
                                            .unwrap_or_default();
                                            let body = plan.body.clone();
                                            move || {
                                                if !writable.get_untracked() { return; }
                                                { let next_value = send_at_input.clone(); edit_send_at.revise(|value| *value = next_value); };
                                                { let next_value = body.clone(); edit_body.revise(|value| *value = next_value); };
                                                { let next_value = Some(plan_id.clone()); editing_plan_id.revise(|value| *value = next_value); };
                                            }
                                        };let cancel={let state_store=state_store.clone();{
                                            let plan_id = plan_id.clone();
                                            let plan_key = plan_key.clone();
                                            let base = base_url.clone();
                                            move || {
                                                if !writable.get_untracked() { return; }
                                                state_store.write(|value| value.remove_scheduled_send_account_data_entry(&plan_key));
                                                refresh.revise(|value|*value=value.wrapping_add(1));
                                                { let next_value = crate::i18n::tr("chat.scheduled_send.cancelled"); status_msg.revise(|value| *value = next_value); };
                                                let api_token = token.get();
                                                let base = base.clone();
                                                let plan_id = plan_id.clone();
                                                let status_msg = status_msg;
                                                super::task::dispatch(async move {
                                                    let result = crate::transport::auth::with_event_submitter(
                                                        &base,
                                                        api_token,
                                                        |submitter| async move {
                                                            crate::transport::account::cancel_scheduled_send_plan(
                                                                &submitter,
                                                                &plan_id,
                                                            )
                                                            .await
                                                        },
                                                    )
                                                    .await;
                                                    if let Err(error) = result {
                                                        { let next_value = format!(
                                                            "Scheduled send cancel failed: {}",
                                                            error.display()
                                                        ); status_msg.revise(|value| *value = next_value); };
                                                    }
                                                });
                                            }
                                        }};
                    block("scheduled-send-row",vec![paragraph("scheduled-send-at",plan.send_at.clone()),paragraph("scheduled-send-body",plan.body.clone()),line("actions",vec![button(app.translated(scope,"chat.scheduled_send.edit"),"secondary scheduled-send-edit-button",writable,edit),button(app.translated(scope,"chat.scheduled_send.cancel_plan"),"secondary scheduled-send-cancel-button",writable,cancel)])])
                }
            })
        }).collect();
        block("scheduled-send-plans", children)
    });
    let send_at_context = app.clone();
    let send_at_label = app.translated(scope, "chat.scheduled_send.send_at");
    block(
        "scheduled-send-panel",
        vec![
            block(
                "scheduled-send-create",
                vec![
                    Box::new(
                        sapid::field("scheduled-send-at-input")
                            .unstyled()
                            .class("form-field scheduled-send-at-input")
                            .label(send_at_label)
                            .control(move |field| {
                                let context = send_at_context.clone();
                                let strand_id = strand_id.clone();
                                glory::ui::widget(move |scope| {
                                    super::native::date_time_with_field(
                                        scope,
                                        context.clone(),
                                        format!("scheduled-send-{strand_id}"),
                                        send_at_label,
                                        new_send_at,
                                        Some(field.clone()),
                                    )
                                    .build(scope)
                                })
                            }),
                    ) as View,
                    button(
                        app.translated(scope, "chat.scheduled_send.create"),
                        "primary scheduled-send-create-button",
                        scope.bond(move || writable.get() && !new_send_at.get().trim().is_empty()),
                        create_plan,
                    ),
                ],
            ),
            rows,
        ],
    )
}
