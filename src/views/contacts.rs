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

use crate::components::DismissiblePopup;
use crate::i18n::tr;
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

/// i18n key for a contact scope token. Keeps the dropdown values canonical
/// (`direct_message`, `invite`, …) while the option text is looked up via the
/// active locale (en is the authoritative default).
fn scope_label(scope: &str) -> String {
    let key = match scope {
        "direct_message" => "contacts.scope.direct_message",
        "invite" => "contacts.scope.invite",
        "voice_call" => "contacts.scope.voice_call",
        "video_call" => "contacts.scope.video_call",
        _ => "contacts.scope.direct_message",
    };
    tr(key)
}

/// Embeddable contact-request form. Used both as the modal body inside
/// [`ContactsPanel`] and (historically) as a standalone panel. `on_submitted`
/// fires after a request is accepted by the server so the host can close the
/// modal and reload the list.
#[component]
pub fn ContactNewPanel(
    base_url: String,
    token: Signal<String>,
    #[props(default)] on_submitted: Option<EventHandler<()>>,
) -> Element {
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
        div { class: "event", "data-testid": "contact-request-panel",
            div { class: "event-head",
                span { {tr("contacts.new.title")} }
                span { {tr("contacts.new.subtitle")} }
            }
            div { class: "muted", {tr("contacts.new.intro")} }
            Label { html_for: "contact-target-input-input", {tr("contacts.new.target_label")} }
            Input {
                id: "contact-target-input-input",
                "data-testid": "contact-target-input",
                value: "{target}",
                placeholder: "did:web:alice.example",
                oninput: move |event: FormEvent| target.set(event.value()),
            }
            Label { html_for: "contact-recipient-service-input", {tr("contacts.new.recipient_service_label")} }
            Input {
                id: "contact-recipient-service-input",
                "data-testid": "contact-recipient-service-input",
                value: "{recipient_service}",
                placeholder: tr("contacts.new.recipient_service_placeholder"),
                oninput: move |event: FormEvent| recipient_service.set(event.value()),
            }
            div { class: "muted", {tr("contacts.new.recipient_service_hint")} }
            Label { html_for: "contact-scope-checkboxes", {tr("contacts.new.scope_label")} }
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
                    {tr("contacts.new.scope_empty")}
                }
            }
            Label { html_for: "contact-message-input", {tr("contacts.new.message_label")} }
            Textarea {
                id: "contact-message-input",
                "data-testid": "contact-message-input",
                value: "{message}",
                placeholder: tr("contacts.new.message_placeholder"),
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
                            status.set(tr("contacts.new.sending"));
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
                                        status.set(tr("contacts.new.sent"));
                                        message.set(String::new());
                                        if let Some(cb) = on_submitted {
                                            cb.call(());
                                        }
                                    }
                                    Err(err) => status.set(
                                        tr("contacts.new.send_failed").replace("{error}", &err.display()),
                                    ),
                                }
                                sending.set(false);
                            });
                        }
                    },
                    if sending() { {tr("contacts.new.submit_busy")} } else { {tr("contacts.new.submit")} }
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
        "pending_incoming" => tr("contacts.state.pending_incoming"),
        "pending_outgoing" | "pending" => tr("contacts.state.pending_outgoing"),
        "accepted" => tr("contacts.state.accepted"),
        "rejected" => tr("contacts.state.rejected"),
        "tombstoned" => tr("contacts.state.tombstoned"),
        "blocked" => tr("contacts.state.blocked"),
        other => other.to_owned(),
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
                    {tr("contacts.shared_scopes")}
                    {contact.bidirectional_scopes.iter().map(|s| scope_label(s)).collect::<Vec<_>>().join("、")}
                }
            }
            if let Some(summary) = &contact.direct_conversation {
                div { class: "muted mono",
                    "{short_protocol_id(&summary.realm_id)} / {short_protocol_id(&summary.main_flow_id)}"
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
                                    tr("contacts.action.accepting"),
                                    busy,
                                    row_status,
                                    on_changed,
                                );
                            }
                        },
                        {tr("contacts.action.accept")}
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
                                    tr("contacts.action.rejecting"),
                                    busy,
                                    row_status,
                                    on_changed,
                                );
                            }
                        },
                        {tr("contacts.action.reject")}
                    }
                }

                if is_pending_outgoing {
                    span {
                        class: "muted",
                        "data-testid": "contact-pending-outgoing-{peer}",
                        {tr("contacts.state.pending_outgoing")}
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
                                    tr("contacts.action.withdrawing"),
                                    busy,
                                    row_status,
                                    on_changed,
                                );
                            }
                        },
                        {tr("contacts.action.withdraw")}
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
                                row_status.set(tr("contacts.dm.opening"));
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
                                                _ => row_status.set(tr("contacts.dm.not_ready")),
                                            }
                                        }
                                        Err(err) => {
                                            row_status.set(
                                                tr("contacts.dm.open_failed").replace("{error}", &err.display()),
                                            )
                                        }
                                    }
                                    busy.set(false);
                                });
                            }
                        },
                        {tr("contacts.action.message")}
                    }
                    Button {
                        variant: ButtonVariant::Destructive,
                        "data-testid": "contact-block-{peer}",
                        disabled: busy(),
                        onclick: move |_| confirm_block.set(true),
                        {tr("contacts.action.block")}
                    }
                }
            }

            // U5 — block confirmation dialog.
            if confirm_block() {
                div {
                    class: "event contact-block-confirm",
                    "data-testid": "contact-block-confirm-{peer}",
                    div { class: "entity-title", {tr("contacts.block.confirm_title")} }
                    div { class: "muted", title: "{peer}", "{peer_label}" }
                    div { class: "muted", {tr("contacts.block.confirm_body")} }
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
                                        tr("contacts.action.blocking"),
                                        busy,
                                        row_status,
                                        on_changed,
                                    );
                                }
                            },
                            {tr("contacts.block.confirm_button")}
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "contact-block-cancel-button-{peer}",
                            onclick: move |_| confirm_block.set(false),
                            {tr("contacts.block.cancel")}
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
            Err(err) => {
                row_status.set(tr("contacts.action_failed").replace("{error}", &err.display()))
            }
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
    // M0.2 — "添加联系人" is a popup modal, not a standalone /contacts/new page.
    let mut add_modal_open = use_signal(|| false);

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
                            span { {tr("contacts.title")} }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "add-contact-button",
                                    onclick: move |_| add_modal_open.set(true),
                                    {tr("contacts.add_button")}
                                }
                            }
                        }

                        if let Some(message) = error.read().clone() {
                            div {
                                class: "event error-banner",
                                "data-testid": "contacts-error",
                                div { class: "muted", {tr("contacts.load_error").replace("{error}", &message)} }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "contacts-retry-button",
                                        onclick: move |_| reload.set(reload() + 1),
                                        {tr("contacts.retry")}
                                    }
                                }
                            }
                        } else if is_loading {
                            div { class: "muted", "data-testid": "contacts-loading", {tr("contacts.loading")} }
                        } else if contact_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "contacts-empty-state",
                                div { class: "members-empty-title", {tr("contacts.empty_title")} }
                                div { class: "muted members-empty-hint", {tr("contacts.empty_hint")} }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "contacts-empty-add-button",
                                        onclick: move |_| add_modal_open.set(true),
                                        {tr("contacts.empty_add")}
                                    }
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

        if add_modal_open() {
            DismissiblePopup {
                overlay_class: "modal-backdrop".to_owned(),
                surface_class: "modal contact-new-modal".to_owned(),
                overlay_test_id: Some("add-contact-modal".to_owned()),
                aria_label: tr("contacts.new.title"),
                on_dismiss: move |_| add_modal_open.set(false),
                div { class: "modal-head",
                    h3 { {tr("contacts.new.title")} }
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: "icon-button close",
                        "aria-label": tr("common.close"),
                        "data-testid": "add-contact-modal-close",
                        onclick: move |_| add_modal_open.set(false),
                        "\u{2715}"
                    }
                }
                div { class: "modal-body",
                    ContactNewPanel {
                        base_url: base_url.clone(),
                        token,
                        on_submitted: move |_| {
                            add_modal_open.set(false);
                            reload.set(reload() + 1);
                        },
                    }
                }
            }
        }
    }
}
