// TRUST-CACHE: contact card / contact list per CKP B-E §1 — these
// surfaces MAY consult the locally cached `binding_state` (verified
// badge, mention autocomplete fields). On cache miss or any
// identity-handles.md §6.1.2 trigger the UI MUST downgrade to an
// "unverified" badge. For authority surfaces (wallet disclosure /
// accept invite / audit-trail review) callers MUST first-party verify
// the DID Document via `crate::did_resolver::build_default_resolver`
// instead of relying on the cached binding state surfaced here.

use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::use_navigator;

use crate::models::ContactListRow;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// Maximum length of the optional contact-request greeting (protocol contract:
/// `message` is `1..2000`).
const CONTACT_MESSAGE_MAX: usize = 2000;

/// Human-readable label for a contact scope token. Keeps the dropdown values
/// canonical (`direct_message`, `invite`, …) while the option text stays
/// natural Chinese.
fn scope_label(scope: &str) -> &'static str {
    match scope {
        "direct_message" => "私聊(可以给我发私信)",
        "invite" => "可邀请我入群",
        "voice_call" => "语音通话",
        "video_call" => "视频通话",
        _ => "私聊(可以给我发私信)",
    }
}

#[component]
pub fn ContactNewPanel(base_url: String, token: Signal<String>) -> Element {
    let mut target = use_signal(String::new);
    // "普通好友" 预设:成为好友默认既能私聊、也默认允许对方拉我入群(微信式)。
    // 两个 scope 默认都勾选;用户可取消其一做高级细选。
    let mut scope_direct_message = use_signal(|| true);
    let mut scope_invite = use_signal(|| true);
    // 跨 PS 寻址:对方所在 Principal Server 的 service DID。v1 DID 不内嵌 home PS,
    // 跨服务器添加时必填,同服务器留空。
    let mut recipient_service = use_signal(String::new);
    let mut message = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut sending = use_signal(|| false);

    let message_len = message.read().chars().count();
    let message_over = message_len > CONTACT_MESSAGE_MAX;
    let target_empty = target.read().trim().is_empty();
    let no_scope = !scope_direct_message() && !scope_invite();

    rsx! {
        div { class: "settings", "data-testid": "contact-request-panel",
            div { class: "settings-shell",
                section { class: "settings-content-stack",
                    div { class: "event",
                        div { class: "event-head",
                            span { "添加联系人" }
                            span { "需对方同意" }
                        }
                        div { class: "muted",
                            "输入对方的 DID 发送好友请求。成为好友默认既能私聊、也允许对方拉你入群(像微信好友一样)。如需更严格,可在下面取消勾选。"
                        }
                        Label { html_for: "contact-target-input-input", "对方 DID" }
                        Input {
                            id: "contact-target-input-input",
                            "data-testid": "contact-target-input",
                            value: "{target}",
                            placeholder: "did:web:alice.example",
                            oninput: move |event: FormEvent| target.set(event.value()),
                        }
                        Label { html_for: "contact-recipient-service-input", "对方所在服务器(跨服务器添加时填)" }
                        Input {
                            id: "contact-recipient-service-input",
                            "data-testid": "contact-recipient-service-input",
                            value: "{recipient_service}",
                            placeholder: "did:web:ps.bob.example(同服务器留空)",
                            oninput: move |event: FormEvent| recipient_service.set(event.value()),
                        }
                        div { class: "muted",
                            "对方在另一台服务器(Principal Server)时填它的 service DID;同服务器留空即可。"
                        }
                        Label { html_for: "contact-scope-checkboxes", "好友权限(普通好友默认两项都开)" }
                        div { id: "contact-scope-checkboxes", class: "settings-list",
                            label {
                                class: "metric",
                                "data-testid": "contact-scope-direct_message-row",
                                Checkbox {
                                    "data-testid": "contact-scope-direct_message",
                                    checked: if scope_direct_message() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                    on_checked_change: move |state: CheckboxState| scope_direct_message.set(bool::from(state)),
                                }
                                span { {scope_label("direct_message")} }
                            }
                            label {
                                class: "metric",
                                "data-testid": "contact-scope-invite-row",
                                Checkbox {
                                    "data-testid": "contact-scope-invite",
                                    checked: if scope_invite() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                    on_checked_change: move |state: CheckboxState| scope_invite.set(bool::from(state)),
                                }
                                span { {scope_label("invite")} }
                            }
                        }
                        if no_scope {
                            div {
                                class: "muted",
                                "data-testid": "contact-scope-empty-hint",
                                "至少需要选择一项权限。"
                            }
                        }
                        Label { html_for: "contact-message-input", "附言(可选)" }
                        Textarea {
                            id: "contact-message-input",
                            "data-testid": "contact-message-input",
                            value: "{message}",
                            placeholder: "打个招呼…",
                            rows: "3",
                            oninput: move |event: FormEvent| message.set(event.value()),
                        }
                        div {
                            class: if message_over { "muted contact-message-counter over" } else { "muted contact-message-counter" },
                            "data-testid": "contact-message-counter",
                            "{message_len} / {CONTACT_MESSAGE_MAX}"
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "send-contact-request-button",
                                disabled: target_empty || message_over || no_scope || sending(),
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let base = base.clone();
                                        let target_did = target().trim().to_owned();
                                        let mut scopes = Vec::new();
                                        if scope_direct_message() {
                                            scopes.push("direct_message".to_owned());
                                        }
                                        if scope_invite() {
                                            scopes.push("invite".to_owned());
                                        }
                                        let service_did = recipient_service().trim().to_owned();
                                        let greeting = message().trim().to_owned();
                                        sending.set(true);
                                        status.set("正在发送请求…".to_owned());
                                        spawn(async move {
                                            let greeting_opt = if greeting.is_empty() {
                                                None
                                            } else {
                                                Some(greeting.as_str())
                                            };
                                            let service_opt = if service_did.is_empty() {
                                                None
                                            } else {
                                                Some(service_did.as_str())
                                            };
                                            match with_authed_api(&base, api_token, |api| async move {
                                                api.request_contact_with_message(
                                                    &target_did,
                                                    &scopes,
                                                    greeting_opt,
                                                    service_opt,
                                                )
                                                .await
                                            })
                                            .await
                                            {
                                                Ok(_) => {
                                                    status.set(
                                                        "请求已发送,等待对方接受。".to_owned(),
                                                    );
                                                    message.set(String::new());
                                                }
                                                Err(err) => {
                                                    status.set(format!("发送失败:{}", err.display()))
                                                }
                                            }
                                            sending.set(false);
                                        });
                                    }
                                },
                                if sending() { "发送中…" } else { "发送请求" }
                            }
                        }
                        if !status.read().is_empty() {
                            div {
                                class: "muted",
                                "data-testid": "contact-request-status",
                                "{status}"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One row in the contacts list, plus the per-state action set (U1/U5).
#[component]
fn ContactRow(
    base_url: String,
    token: Signal<String>,
    contact: ContactListRow,
    on_changed: EventHandler<()>,
) -> Element {
    let nav = use_navigator();
    let mut row_status = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut confirm_block = use_signal(|| false);

    let peer = contact.peer.clone();
    let state = contact.state.clone();
    // 跨 PS 来源:若后端已在 list row 暴露发起方所在 PS,respond 时透传
    // requester_service_did 以反向投递;暂无则为 None,走同 PS 逻辑。
    let peer_service_did = contact
        .peer_service_did
        .clone()
        .filter(|s| !s.trim().is_empty());
    let peer_label = short_protocol_id(&peer);
    let is_pending_incoming = state == "pending_incoming";
    let is_pending_outgoing = state == "pending_outgoing" || state == "pending";
    let is_accepted = state == "accepted";
    let is_weak = state == "rejected" || state == "tombstoned" || state == "blocked";

    // Human-readable state label.
    let state_label = match state.as_str() {
        "pending_incoming" => "等待你处理",
        "pending_outgoing" | "pending" => "等待对方接受",
        "accepted" => "已是联系人",
        "rejected" => "已拒绝",
        "tombstoned" => "已删除",
        "blocked" => "已拉黑",
        other => other,
    };

    let row_class = if is_weak {
        "event contact-row weak"
    } else {
        "event contact-row"
    };

    rsx! {
        li {
            class: "{row_class}",
            "data-testid": "contact-row",
            "data-peer": "{peer}",
            "data-state": "{state}",
            div { class: "event-head",
                span { "{state_label}" }
                span { class: "mono", title: "{peer}", "{peer_label}" }
            }
            if !contact.bidirectional_scopes.is_empty() {
                div { class: "muted",
                    "共享权限:"
                    {contact.bidirectional_scopes.iter().map(|s| scope_label(s)).collect::<Vec<_>>().join("、")}
                }
            }
            if let Some(summary) = &contact.direct_conversation {
                div { class: "muted mono",
                    "私聊 {short_protocol_id(&summary.realm_id)} / {short_protocol_id(&summary.main_flow_id)}"
                }
            }

            div { class: "actions",
                if is_pending_incoming {
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "contact-accept-{peer}",
                        disabled: busy(),
                        onclick: {
                            let base = base_url.clone();
                            let peer = peer.clone();
                            let service = peer_service_did.clone();
                            move |_| {
                                run_contact_action(
                                    base.clone(),
                                    token(),
                                    ContactRowAction::Respond { requester: peer.clone(), verb: "accept".to_owned(), requester_service_did: service.clone() },
                                    "正在接受…".to_owned(),
                                    busy,
                                    row_status,
                                    on_changed,
                                );
                            }
                        },
                        "接受"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "contact-reject-{peer}",
                        disabled: busy(),
                        onclick: {
                            let base = base_url.clone();
                            let peer = peer.clone();
                            let service = peer_service_did.clone();
                            move |_| {
                                run_contact_action(
                                    base.clone(),
                                    token(),
                                    ContactRowAction::Respond { requester: peer.clone(), verb: "reject".to_owned(), requester_service_did: service.clone() },
                                    "正在拒绝…".to_owned(),
                                    busy,
                                    row_status,
                                    on_changed,
                                );
                            }
                        },
                        "拒绝"
                    }
                }

                if is_pending_outgoing {
                    span {
                        class: "muted",
                        "data-testid": "contact-pending-outgoing-{peer}",
                        "等待对方接受"
                    }
                    Button {
                        variant: ButtonVariant::Ghost,
                        "data-testid": "contact-withdraw-{peer}",
                        disabled: busy(),
                        onclick: {
                            let base = base_url.clone();
                            let peer = peer.clone();
                            move |_| {
                                run_contact_action(
                                    base.clone(),
                                    token(),
                                    ContactRowAction::Tombstone { peer: peer.clone(), block: false },
                                    "正在撤回…".to_owned(),
                                    busy,
                                    row_status,
                                    on_changed,
                                );
                            }
                        },
                        "撤回"
                    }
                }

                if is_accepted {
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "contact-message-{peer}",
                        disabled: busy(),
                        onclick: {
                            let base = base_url.clone();
                            let peer = peer.clone();
                            move |_| {
                                let base = base.clone();
                                let peer = peer.clone();
                                let api_token = token();
                                busy.set(true);
                                row_status.set("正在打开私聊…".to_owned());
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.direct_conversation_resolve(&peer, true).await
                                    })
                                    .await
                                    {
                                        Ok(outcome) => {
                                            match (outcome.realm_id, outcome.main_flow_id) {
                                                (Some(realm_id), Some(flow_id)) => {
                                                    row_status.set(String::new());
                                                    nav.push(Route::DirectConversation { realm_id, flow_id });
                                                }
                                                _ => row_status.set(
                                                    "私聊尚未就绪,请稍后再试。".to_owned(),
                                                ),
                                            }
                                        }
                                        Err(err) => {
                                            row_status.set(format!("打开私聊失败:{}", err.display()))
                                        }
                                    }
                                    busy.set(false);
                                });
                            }
                        },
                        "发消息"
                    }
                    Button {
                        variant: ButtonVariant::Destructive,
                        "data-testid": "contact-block-{peer}",
                        disabled: busy(),
                        onclick: move |_| confirm_block.set(true),
                        "拉黑"
                    }
                }
            }

            // U5 — block confirmation dialog.
            if confirm_block() {
                div {
                    class: "event contact-block-confirm",
                    "data-testid": "contact-block-confirm-{peer}",
                    div { class: "entity-title", "确定拉黑该联系人?" }
                    div { class: "muted", title: "{peer}", "{peer_label}" }
                    div { class: "muted",
                        "拉黑后会删除该联系人,并阻止对方再次向你发送请求或邀请。"
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Destructive,
                            "data-testid": "contact-block-confirm-button-{peer}",
                            disabled: busy(),
                            onclick: {
                                let base = base_url.clone();
                                let peer = peer.clone();
                                move |_| {
                                    confirm_block.set(false);
                                    run_contact_action(
                                        base.clone(),
                                        token(),
                                        ContactRowAction::Tombstone { peer: peer.clone(), block: true },
                                        "正在拉黑…".to_owned(),
                                        busy,
                                        row_status,
                                        on_changed,
                                    );
                                }
                            },
                            "确认拉黑"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "contact-block-cancel-button-{peer}",
                            onclick: move |_| confirm_block.set(false),
                            "取消"
                        }
                    }
                }
            }

            if !row_status.read().is_empty() {
                div {
                    class: "muted",
                    "data-testid": "contact-row-status-{peer}",
                    "{row_status}"
                }
            }
        }
    }
}

/// Action dispatched from a contact row. Keeps the async closure small and
/// `Clone`-friendly.
#[derive(Clone)]
enum ContactRowAction {
    Respond {
        requester: String,
        verb: String,
        /// Cross-PS reverse-delivery target; `None` for same-PS contacts.
        requester_service_did: Option<String>,
    },
    Tombstone {
        peer: String,
        block: bool,
    },
}

/// Run a respond/tombstone call for a contact row, then refresh the parent list
/// on success. Signals are `Copy`, so this is a free function the per-row
/// onclick handlers can call without fighting closure-capture rules.
fn run_contact_action(
    base: String,
    api_token: String,
    action: ContactRowAction,
    pending_msg: String,
    mut busy: Signal<bool>,
    mut row_status: Signal<String>,
    on_changed: EventHandler<()>,
) {
    busy.set(true);
    row_status.set(pending_msg);
    spawn(async move {
        let result = match action {
            ContactRowAction::Respond {
                requester,
                verb,
                requester_service_did,
            } => {
                with_authed_api(&base, api_token, |api| async move {
                    api.respond_contact_with_service(
                        &requester,
                        &verb,
                        requester_service_did.as_deref(),
                    )
                    .await
                })
                .await
                .map(|_| ())
            }
            ContactRowAction::Tombstone { peer, block } => {
                with_authed_api(&base, api_token, |api| async move {
                    api.tombstone_contact(&peer, block).await
                })
                .await
                .map(|_| ())
            }
        };
        match result {
            Ok(()) => {
                row_status.set(String::new());
                on_changed.call(());
            }
            Err(err) => row_status.set(format!("操作失败:{}", err.display())),
        }
        busy.set(false);
    });
}

#[component]
pub fn ContactsPanel(base_url: String, token: Signal<String>) -> Element {
    let mut contacts = use_signal(Vec::<ContactListRow>::new);
    let mut status = use_signal(|| "loading".to_owned());
    let mut error = use_signal(|| Option::<String>::None);
    let mut reload = use_signal(|| 0_u32);
    let mut loaded_generation = use_signal(|| u32::MAX);

    {
        let base = base_url.clone();
        use_effect(move || {
            let generation = reload();
            if loaded_generation() == generation {
                return;
            }
            loaded_generation.set(generation);
            let api_token = token();
            let base = base.clone();
            error.set(None);
            status.set("loading".to_owned());
            spawn(async move {
                match with_authed_api(&base, api_token, |api| async move { api.contacts().await })
                    .await
                {
                    Ok(response) => {
                        let count = response.contacts.len();
                        contacts.set(response.contacts);
                        status.set(format!("contacts {count}"));
                    }
                    Err(err) => {
                        error.set(Some(err.display()));
                        status.set("error".to_owned());
                    }
                }
            });
        });
    }

    let is_loading = status() == "loading";
    let contact_rows = contacts.read().clone();

    rsx! {
        div { class: "settings", "data-testid": "contacts-panel",
            div { class: "settings-shell",
                section { class: "settings-content-stack",
                    div { class: "event",
                        div { class: "event-head",
                            span { "联系人" }
                            span { "{status}" }
                        }

                        if let Some(message) = error.read().clone() {
                            div {
                                class: "event error-banner",
                                "data-testid": "contacts-error",
                                div { class: "muted", "加载联系人失败:{message}" }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "contacts-retry-button",
                                        onclick: move |_| reload.set(reload() + 1),
                                        "重试"
                                    }
                                }
                            }
                        } else if is_loading {
                            div { class: "muted", "data-testid": "contacts-loading", "正在加载联系人…" }
                        } else if contact_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "contacts-empty-state",
                                div { class: "members-empty-title", "还没有联系人" }
                                div { class: "muted members-empty-hint",
                                    "去“添加联系人”发送一个好友请求,对方接受后就会出现在这里。"
                                }
                            }
                        } else {
                            ul { class: "settings-list",
                                for contact in contact_rows {
                                    ContactRow {
                                        key: "{contact.peer}",
                                        base_url: base_url.clone(),
                                        token,
                                        contact: contact.clone(),
                                        on_changed: move |_| reload.set(reload() + 1),
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
