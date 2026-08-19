//! Scheduled-send composer panel (spec `models/personal-productivity.md` §4).
//!
//! The panel is the plan-lifecycle UI: it creates, lists, modifies, and
//! cancels `ak.scheduled_send.v1` plans for the discussion the composer is
//! bound to. Writes go through the encrypted account-data `cas_register`
//! loop; expiry dispatch itself is the session-wide driver in
//! [`crate::scheduled_send`].

use super::*;

#[derive(Clone, PartialEq)]
pub(super) struct ScheduledSendPanelContext {
    pub realm_id: String,
    pub strand_id: String,
    pub account_did: String,
    pub device_id: String,
    pub token: Signal<String>,
    pub draft: Signal<String>,
    pub status_msg: Signal<String>,
}

fn plan_body_preview(value: &arkret_sdk::ScheduledSendValue) -> String {
    value
        .message_payload
        .content
        .as_ref()
        .map(|content| content.body.clone())
        .unwrap_or_default()
}

/// Flat, comparable view of one staged plan; `use_memo` requires `PartialEq`,
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

#[component]
pub(super) fn ScheduledSendPanel(context: ScheduledSendPanelContext) -> Element {
    let ScheduledSendPanelContext {
        realm_id,
        strand_id,
        account_did,
        device_id,
        token,
        mut draft,
        mut status_msg,
    } = context;
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let mut new_send_at = use_signal(String::new);
    let mut editing_plan_id: Signal<Option<String>> = use_signal(|| None);
    let mut edit_send_at = use_signal(String::new);
    let mut edit_body = use_signal(String::new);
    let mut refresh = use_signal(|| 0u64);

    let plans = use_memo({
        let account_did = account_did.clone();
        let strand_id = strand_id.clone();
        move || {
            refresh();
            crate::scheduled_send::staged_scheduled_send_plans(&account_did, &state_store.read())
                .iter()
                .filter(|plan| plan.value.message_payload.strand_id.as_str() == strand_id)
                .map(ScheduledSendPlanView::from_plan)
                .collect::<Vec<_>>()
        }
    });

    let create_plan = {
        let realm_id = realm_id.clone();
        let strand_id = strand_id.clone();
        let account_did = account_did.clone();
        let device_id = device_id.clone();
        let base_url = base_url.clone();
        move |_| {
            let body = draft().trim().to_owned();
            if body.is_empty() {
                status_msg.set(crate::i18n::tr("chat.scheduled_send.needs_body"));
                return;
            }
            let send_at = match crate::clock::local_datetime_input_to_canonical(&new_send_at()) {
                Ok(send_at) => send_at,
                Err(error) => {
                    status_msg.set(format!("{error:#}"));
                    return;
                }
            };
            let content = match chat_content_block_for_body(&body) {
                Ok(content) => content,
                Err(error) => {
                    status_msg.set(format!("{error:#}"));
                    return;
                }
            };
            let strand = match arkret_sdk::StrandId::new(strand_id.clone()) {
                Ok(strand) => strand,
                Err(error) => {
                    status_msg.set(format!("invalid strand id: {error}"));
                    return;
                }
            };
            let payload =
                arkret_sdk::MessageCreatePayload::with_content(strand, "discussion", content);
            let prepared = match crate::scheduled_send::prepare_scheduled_send_plan(
                &account_did,
                &device_id,
                None,
                &send_at,
                payload,
            ) {
                Ok(prepared) => prepared,
                Err(error) => {
                    status_msg.set(format!("{error:#}"));
                    return;
                }
            };
            let scheduled_send_id = prepared.value.scheduled_send_id.to_string();
            state_store.write().stage_scheduled_send_account_data_entry(
                &prepared.account_data_key,
                prepared.encrypted_entry.clone(),
            );
            state_store
                .write()
                .set_scheduled_send_target_realm(&scheduled_send_id, &realm_id);
            draft.set(String::new());
            new_send_at.set(String::new());
            refresh += 1;
            status_msg.set(crate::i18n::tr("chat.scheduled_send.created"));
            let api_token = token();
            let base = base_url.clone();
            let mut status_msg = status_msg;
            spawn(async move {
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
                    status_msg.set(format!("Scheduled send stayed local: {}", error.display()));
                }
            });
        }
    };

    rsx! {
        div { class: "scheduled-send-panel", "data-testid": "scheduled-send-panel",
            div { class: "scheduled-send-create",
                Label { html_for: "scheduled-send-at-input", {crate::i18n::tr("chat.scheduled_send.send_at")} }
                input {
                    id: "scheduled-send-at-input",
                    "data-testid": "scheduled-send-at-input",
                    r#type: "datetime-local",
                    value: "{new_send_at}",
                    oninput: move |event: FormEvent| new_send_at.set(event.value()),
                }
                Button {
                    variant: ButtonVariant::Primary,
                    r#type: "button",
                    "data-testid": "scheduled-send-create-button",
                    disabled: new_send_at().trim().is_empty(),
                    onclick: create_plan,
                    {crate::i18n::tr("chat.scheduled_send.create")}
                }
            }
            if plans.read().is_empty() {
                div { class: "muted", "data-testid": "scheduled-send-empty",
                    {crate::i18n::tr("chat.scheduled_send.empty")}
                }
            }
            for plan in plans.read().iter() {
                {
                    let plan_id = plan.scheduled_send_id.clone();
                    let plan_key = plan.account_data_key.clone();
                    let is_editing = editing_plan_id.read().as_deref() == Some(plan_id.as_str());
                    rsx! {
                        div {
                            class: "scheduled-send-row",
                            "data-testid": "scheduled-send-row",
                            "data-scheduled-send-id": "{plan_id}",
                            if is_editing {
                                input {
                                    "data-testid": "scheduled-send-edit-at-input",
                                    r#type: "datetime-local",
                                    value: "{edit_send_at}",
                                    oninput: move |event: FormEvent| edit_send_at.set(event.value()),
                                }
                                Textarea {
                                    "data-testid": "scheduled-send-edit-body-input",
                                    value: "{edit_body}",
                                    oninput: move |event: FormEvent| edit_body.set(event.value()),
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        r#type: "button",
                                        "data-testid": "scheduled-send-save-button",
                                        onclick: {
                                            let account_did = account_did.clone();
                                            let device_id = device_id.clone();
                                            let plan_id = plan_id.clone();
                                            let plan_key = plan_key.clone();
                                            let base = base_url.clone();
                                            let strand_id = plan.strand_id.clone();
                                            move |_| {
                                                let send_at = match crate::clock::local_datetime_input_to_canonical(&edit_send_at()) {
                                                    Ok(send_at) => send_at,
                                                    Err(error) => {
                                                        status_msg.set(format!("{error:#}"));
                                                        return;
                                                    }
                                                };
                                                let body = edit_body().trim().to_owned();
                                                let content = match chat_content_block_for_body(&body) {
                                                    Ok(content) => content,
                                                    Err(error) => {
                                                        status_msg.set(format!("{error:#}"));
                                                        return;
                                                    }
                                                };
                                                let strand = match arkret_sdk::StrandId::new(strand_id.clone()) {
                                                    Ok(strand) => strand,
                                                    Err(error) => {
                                                        status_msg.set(format!("invalid strand id: {error}"));
                                                        return;
                                                    }
                                                };
                                                let payload = arkret_sdk::MessageCreatePayload::with_content(
                                                    strand,
                                                    "discussion",
                                                    content,
                                                );
                                                let prepared = match crate::scheduled_send::prepare_scheduled_send_plan(
                                                    &account_did,
                                                    &device_id,
                                                    Some(&plan_id),
                                                    &send_at,
                                                    payload,
                                                ) {
                                                    Ok(prepared) => prepared,
                                                    Err(error) => {
                                                        status_msg.set(format!("{error:#}"));
                                                        return;
                                                    }
                                                };
                                                state_store
                                                    .write()
                                                    .stage_scheduled_send_account_data_entry(
                                                        &plan_key,
                                                        prepared.encrypted_entry.clone(),
                                                    );
                                                editing_plan_id.set(None);
                                                refresh += 1;
                                                status_msg.set(crate::i18n::tr("chat.scheduled_send.updated"));
                                                let api_token = token();
                                                let base = base.clone();
                                                let mut status_msg = status_msg;
                                                spawn(async move {
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
                                                        status_msg.set(format!(
                                                            "Scheduled send update stayed local: {}",
                                                            error.display()
                                                        ));
                                                    }
                                                });
                                            }
                                        },
                                        {crate::i18n::tr("chat.scheduled_send.save")}
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        "data-testid": "scheduled-send-edit-cancel-button",
                                        onclick: move |_| editing_plan_id.set(None),
                                        {crate::i18n::tr("chat.scheduled_send.dismiss_edit")}
                                    }
                                }
                            } else {
                                span { class: "scheduled-send-at", "{plan.send_at}" }
                                span { class: "scheduled-send-body", "{plan.body}" }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        "data-testid": "scheduled-send-edit-button",
                                        onclick: {
                                            let plan_id = plan_id.clone();
                                            let send_at_input = crate::clock::canonical_to_local_datetime_input(
                                                &plan.send_at,
                                            )
                                            .unwrap_or_default();
                                            let body = plan.body.clone();
                                            move |_| {
                                                edit_send_at.set(send_at_input.clone());
                                                edit_body.set(body.clone());
                                                editing_plan_id.set(Some(plan_id.clone()));
                                            }
                                        },
                                        {crate::i18n::tr("chat.scheduled_send.edit")}
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        "data-testid": "scheduled-send-cancel-button",
                                        onclick: {
                                            let plan_id = plan_id.clone();
                                            let plan_key = plan_key.clone();
                                            let base = base_url.clone();
                                            move |_| {
                                                state_store
                                                    .write()
                                                    .remove_scheduled_send_account_data_entry(&plan_key);
                                                refresh += 1;
                                                status_msg.set(crate::i18n::tr("chat.scheduled_send.cancelled"));
                                                let api_token = token();
                                                let base = base.clone();
                                                let plan_id = plan_id.clone();
                                                let mut status_msg = status_msg;
                                                spawn(async move {
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
                                                        status_msg.set(format!(
                                                            "Scheduled send cancel failed: {}",
                                                            error.display()
                                                        ));
                                                    }
                                                });
                                            }
                                        },
                                        {crate::i18n::tr("chat.scheduled_send.cancel_plan")}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
