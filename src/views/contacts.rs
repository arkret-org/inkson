use arkret_sdk::contact_operations::ContactScope;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::use_navigator;

use crate::components::DismissiblePopup;
use crate::i18n::tr;
use crate::models::ContactListRow;
use crate::routes::Route;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

/// Maximum length of the optional contact-request greeting (protocol contract:
/// `message` is `1..2000`).
const CONTACT_MESSAGE_MAX: usize = 2000;

/// i18n key for a contact scope token. Keeps the dropdown values canonical
/// (`direct_message`, `invite`, …) while the option text is looked up via the
/// active locale (en is the authoritative default).
fn scope_label(scope: &ContactScope) -> String {
    let key = match scope {
        ContactScope::DirectMessage => "contacts.scope.direct_message",
        ContactScope::Invite => "contacts.scope.invite",
        ContactScope::VoiceCall => "contacts.scope.voice_call",
        ContactScope::VideoCall => "contacts.scope.video_call",
        ContactScope::Presence => "contacts.scope.presence",
    };
    tr(key)
}

/// Embeddable contact-request form. Used both as the modal body inside
/// [`ContactsPanel`] and (historically) as a standalone panel. `on_submitted`
/// fires after a request is accepted by the server so the host can close the
/// modal and reload the list.
#[component]
pub fn ContactNewPanel(
    token: Signal<String>,
    #[props(default)] on_submitted: Option<EventHandler<()>>,
) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut target = use_signal(String::new);
    let mut message = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut sending = use_signal(|| false);

    let message_len = message.read().chars().count();
    let message_over = message_len > CONTACT_MESSAGE_MAX;
    let target_empty = target.read().trim().is_empty();

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
                placeholder: tr("contacts.new.target_placeholder"),
                oninput: move |event: FormEvent| target.set(event.value()),
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
                    disabled: target_empty || message_over || sending(),
                    onclick: {
                        let base = base_url.clone();
                        move |_| {
                            let api_token = token();
                            let base = base.clone();
                            let target_did = target().trim().to_owned();
                            let scopes = crate::transport::DEFAULT_CONTACT_SCOPE_NAMES
                                .iter().map(|scope| (*scope).to_owned()).collect::<Vec<_>>();
                            let greeting = message().trim().to_owned();
                            sending.set(true);
                            status.set(tr("contacts.new.sending"));
                            spawn(async move {
                                let greeting_opt = if greeting.is_empty() {
                                    None
                                } else {
                                    Some(greeting.as_str())
                                };
                                match with_authed_api(&base, api_token, |api| async move {
                                    api.request_contact_with_message(
                                        &target_did,
                                        &scopes,
                                        greeting_opt,
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
    token: Signal<String>,
    contact: ContactListRow,
    on_changed: EventHandler<()>,
    #[props(default)] advanced: bool,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let nav = use_navigator();
    let mut row_status = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut confirm_block = use_signal(|| false);
    let grants_invite = contact
        .granted_to_peer_scopes
        .contains(&ContactScope::Invite);
    let grants_direct_message = contact
        .granted_to_peer_scopes
        .contains(&ContactScope::DirectMessage);
    let grants_voice_call = contact
        .granted_to_peer_scopes
        .contains(&ContactScope::VoiceCall);
    let grants_video_call = contact
        .granted_to_peer_scopes
        .contains(&ContactScope::VideoCall);
    let grants_presence = contact
        .granted_to_peer_scopes
        .contains(&ContactScope::Presence);
    let mut scope_invite = use_signal(move || grants_invite);
    let mut scope_direct_message = use_signal(move || grants_direct_message);
    let mut scope_voice_call = use_signal(move || grants_voice_call);
    let mut scope_video_call = use_signal(move || grants_video_call);
    let mut scope_presence = use_signal(move || grants_presence);

    let peer_principal = crate::models::contact_peer_id(&contact).to_string();
    let peer_actor_id = contact.peer.contact_actor_id();
    let peer = peer_actor_id.to_string();
    // A shared Collaboration Realm is the authorization basis for reading the
    // peer's global Profile, and for a Contact that Realm is its Direct
    // Conversation. Before one exists there is no authorized read, so the
    // confirmation comparison stays undecided rather than claiming "unchanged".
    let shared_realm_id = contact
        .direct_conversation
        .as_ref()
        .map(|summary| summary.realm_id.clone());
    let state = contact.state;
    let peer_label = crate::views::helpers::contact_peer_label(&state_store.read(), &contact);
    let existing_remark = state_store.read().contact_remark(&peer_principal);
    let mut petname_input = use_signal(|| {
        existing_remark
            .as_ref()
            .map(|remark| remark.petname.clone())
            .unwrap_or_default()
    });
    // Read the peer's global Profile through the authorized surface. garth
    // decides whether a round trip is actually due, so entering the surface
    // again inside the freshness window costs nothing.
    let profile_resolve = {
        let base = base_url.clone();
        let realm_id = shared_realm_id.clone();
        let actor_id = peer_actor_id.clone();
        use_resource(use_reactive!(|(base, realm_id, actor_id)| {
            let base = base.clone();
            let realm_id = realm_id.clone();
            let actor_id = actor_id.clone();
            async move {
                let Some(realm_id) = realm_id else {
                    return;
                };
                if let Err(error) = crate::identity::contact_profile::refresh(
                    &base,
                    token(),
                    realm_id,
                    vec![actor_id],
                )
                .await
                {
                    tracing::debug!(%error, "authorized Contact Profile resolve failed");
                }
            }
        }))
    };
    // Reading the resource is what subscribes this row to it. The directory
    // behind it is process state, not a signal, so without this the first visit
    // would render before the read lands and never render again. It also makes
    // "not read yet" indistinguishable from "unavailable" for everything below,
    // which is the correct reading: an unfinished read decides nothing.
    let profile_read_landed = profile_resolve.read().is_some();
    let confirmation_state = profile_read_landed
        .then(|| {
            shared_realm_id.as_ref().map(|realm_id| {
                crate::identity::contact_profile::confirmed_display_name_state(
                    realm_id,
                    &peer_actor_id,
                    existing_remark.as_ref(),
                )
            })
        })
        .flatten();
    let live_profile_display = profile_read_landed
        .then(|| {
            shared_realm_id.as_ref().and_then(|realm_id| {
                crate::identity::contact_profile::current_display_name(realm_id, &peer_actor_id)
            })
        })
        .flatten();

    // A first-time Contact has no shared Realm at accept time, so accept could
    // not have initialized a baseline. Without an explicit action here the
    // holder would never be able to establish one, and the rename notice could
    // never fire. Offer the confirmation exactly when there is fresh evidence to
    // confirm and no baseline yet.
    let confirmable_display_name = matches!(
        confirmation_state,
        Some(
            arkret_models_collaboration::actor_profile_resolution::ConfirmedDisplayNameState::Unconfirmed
        )
    )
    .then(|| {
        shared_realm_id.as_ref().and_then(|realm_id| {
            crate::identity::contact_profile::current_verified_display_name(
                realm_id,
                &peer_actor_id,
            )
        })
    })
    .flatten();

    let confirmation_at_accept = existing_remark
        .is_none()
        .then(|| {
            shared_realm_id.as_ref().and_then(|realm_id| {
                crate::identity::contact_profile::current_verified_display_name(
                    realm_id,
                    &peer_actor_id,
                )
                .and_then(|display_name| {
                    arkret_sdk::DidCoreId::new(peer_principal.clone())
                        .ok()
                        .map(|principal_id| ContactAcceptConfirmation {
                            principal_id,
                            display_name,
                        })
                })
            })
        })
        .flatten();
    let is_pending_incoming = state == arkret_sdk::ContactState::PendingIncoming;
    let is_pending_outgoing = state == arkret_sdk::ContactState::PendingOutgoing;
    let is_accepted = state == arkret_sdk::ContactState::Accepted;
    let is_accepted_human = is_accepted
        && matches!(
            &contact.peer,
            arkret_sdk::contact_operations::ContactPeer::Human { .. }
        );
    let is_weak = matches!(
        state,
        arkret_sdk::ContactState::Rejected | arkret_sdk::ContactState::Tombstoned
    );
    let state_wire = crate::models::contact_state_wire(state);
    let selected_scopes = [
        (ContactScope::Invite, scope_invite()),
        (ContactScope::DirectMessage, scope_direct_message()),
        (ContactScope::VoiceCall, scope_voice_call()),
        (ContactScope::VideoCall, scope_video_call()),
        (ContactScope::Presence, scope_presence()),
    ]
    .into_iter()
    .filter_map(|(scope, selected)| selected.then_some(scope))
    .collect::<Vec<_>>();
    let mut current_grants = contact.granted_to_peer_scopes.clone();
    current_grants.sort();
    current_grants.dedup();
    let scope_changed = selected_scopes != current_grants;

    // Human-readable state label.
    let state_label = match state {
        arkret_sdk::ContactState::PendingIncoming => tr("contacts.state.pending_incoming"),
        arkret_sdk::ContactState::PendingOutgoing => tr("contacts.state.pending_outgoing"),
        arkret_sdk::ContactState::Accepted => tr("contacts.state.accepted"),
        arkret_sdk::ContactState::Rejected => tr("contacts.state.rejected"),
        arkret_sdk::ContactState::Tombstoned => tr("contacts.state.tombstoned"),
        arkret_sdk::ContactState::Expired => tr("contacts.state.expired"),
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
            "data-state": "{state_wire}",
            if let Some(message) = &contact.request_message {
                p { class: "contact-request-message", "data-testid": "contact-request-message", "{message}" }
            }
            div { class: "event-head",
                span { "{state_label}" }
                span { class: "mono", title: "{peer}", "{peer_label}" }
                // Y3 TRUST-CACHE: show cached / stale / degraded based on the
                // peer DID's state in the session-scoped resolution cache. UX
                // hint only; it does not replace authority validation (see the
                // TRUST-CACHE comment at the top of the file).

            }
            if let Some(display_name) = live_profile_display.clone() {
                div {
                    class: "muted",
                    "data-testid": "contact-profile-display-{peer}",
                    "{display_name}"
                }
            }
            // The holder confirmed a name once; the peer has since published a
            // different one. Show both and make the refresh an explicit act, so
            // a rename can never silently become the confirmed baseline.
            if let Some(
                arkret_models_collaboration::actor_profile_resolution::ConfirmedDisplayNameState::Changed {
                    confirmed,
                    current,
                },
            ) = confirmation_state.clone() {
                div {
                    class: "event contact-display-name-changed",
                    "data-testid": "contact-display-name-changed-{peer}",
                    div { class: "entity-title", {tr("contacts.confirmed_name.changed_title")} }
                    div {
                        class: "muted",
                        {crate::i18n::tr_args(
                            "contacts.confirmed_name.changed_body",
                            &[
                                ("confirmed", confirmed.clone()),
                                ("current", current.clone()),
                            ],
                        )}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "contact-confirm-name-{peer}",
                        onclick: {
                            let base = base_url.clone();
                            let peer_principal = peer_principal.clone();
                            let peer_key = peer.clone();
                            let existing = existing_remark.clone();
                            let current = current.clone();
                            move |_| {
                                let Ok(principal_id) =
                                    arkret_sdk::DidCoreId::new(peer_principal.clone())
                                else {
                                    row_status.set(tr("contacts.petname.invalid_principal"));
                                    return;
                                };
                                let edit =
                                    crate::account_data::ContactRemarkEdit::ConfirmDisplayName(
                                        current.clone(),
                                    );
                                let remark = edit.apply(
                                    principal_id.clone(),
                                    existing.as_ref(),
                                    chrono::Utc::now(),
                                );
                                state_store
                                    .write()
                                    .set_contact_remark(peer_key.clone(), remark);
                                row_status.set(tr("contacts.confirmed_name.confirmed"));
                                crate::views::settings::push_contact_remark_edit(
                                    base.clone(),
                                    token(),
                                    principal_id,
                                    edit,
                                );
                            }
                        },
                        {tr("contacts.confirmed_name.confirm")}
                    }
                }
            }
            if is_accepted_human && let Some(display_name) = confirmable_display_name.clone() {
                div {
                    class: "contact-confirm-identity",
                    "data-testid": "contact-confirm-identity-{peer}",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "contact-confirm-name-{peer}",
                        onclick: {
                            let base = base_url.clone();
                            let peer_principal = peer_principal.clone();
                            let peer_key = peer.clone();
                            let existing = existing_remark.clone();
                            let display_name = display_name.clone();
                            move |_| {
                                let Ok(principal_id) =
                                    arkret_sdk::DidCoreId::new(peer_principal.clone())
                                else {
                                    row_status.set(tr("contacts.petname.invalid_principal"));
                                    return;
                                };
                                let edit =
                                    crate::account_data::ContactRemarkEdit::ConfirmDisplayName(
                                        display_name.clone(),
                                    );
                                let remark = edit.apply(
                                    principal_id.clone(),
                                    existing.as_ref(),
                                    chrono::Utc::now(),
                                );
                                state_store
                                    .write()
                                    .set_contact_remark(peer_key.clone(), remark);
                                row_status.set(tr("contacts.confirmed_name.confirmed"));
                                crate::views::settings::push_contact_remark_edit(
                                    base.clone(),
                                    token(),
                                    principal_id,
                                    edit,
                                );
                            }
                        },
                        {crate::i18n::tr_args(
                            "contacts.confirmed_name.confirm_identity",
                            &[("current", display_name.clone())],
                        )}
                    }
                }
            }
            if advanced && !contact.bidirectional_scopes.is_empty() {
                div { class: "muted",
                    {tr("contacts.shared_scopes")}
                    {contact.bidirectional_scopes.iter().map(scope_label).collect::<Vec<_>>().join("、")}
                }
            }
            if advanced && is_accepted {
                div {
                    class: "contact-scope-editor",
                    "data-testid": "contact-scope-editor-{peer}",
                    div { class: "muted", {tr("contacts.scope_update.label")} }
                    div { class: "settings-list",
                        label { class: "metric",
                            Checkbox {
                                "data-testid": "contact-grant-direct_message-{peer}",
                                checked: if scope_direct_message() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: move |state: CheckboxState| scope_direct_message.set(bool::from(state)),
                            }
                            span { {scope_label(&ContactScope::DirectMessage)} }
                        }
                        label { class: "metric",
                            Checkbox {
                                "data-testid": "contact-grant-invite-{peer}",
                                checked: if scope_invite() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: move |state: CheckboxState| scope_invite.set(bool::from(state)),
                            }
                            span { {scope_label(&ContactScope::Invite)} }
                        }
                        label { class: "metric",
                            Checkbox {
                                "data-testid": "contact-grant-voice_call-{peer}",
                                checked: if scope_voice_call() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: move |state: CheckboxState| scope_voice_call.set(bool::from(state)),
                            }
                            span { {scope_label(&ContactScope::VoiceCall)} }
                        }
                        label { class: "metric",
                            Checkbox {
                                "data-testid": "contact-grant-video_call-{peer}",
                                checked: if scope_video_call() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: move |state: CheckboxState| scope_video_call.set(bool::from(state)),
                            }
                            span { {scope_label(&ContactScope::VideoCall)} }
                        }
                        label { class: "metric",
                            Checkbox {
                                "data-testid": "contact-grant-presence-{peer}",
                                checked: if scope_presence() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: move |state: CheckboxState| scope_presence.set(bool::from(state)),
                            }
                            span { {scope_label(&ContactScope::Presence)} }
                        }
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "contact-scope-save-{peer}",
                            disabled: busy() || !scope_changed,
                            onclick: {
                                let base = base_url.clone();
                                let peer = peer.clone();
                                let scopes = selected_scopes.clone();
                                move |_| {
                                    run_contact_action(
                                        base.clone(),
                                        token(),
                                        ContactRowAction::ScopeUpdate {
                                            peer: peer.clone(),
                                            scopes: scopes.clone(),
                                        },
                                        tr("contacts.scope_update.saving"),
                                        busy,
                                        row_status,
                                        on_changed,
                                        None,
                                    );
                                }
                            },
                            {tr("contacts.scope_update.save")}
                        }
                    }
                    if selected_scopes.is_empty() {
                        div { class: "muted", {tr("contacts.scope_update.empty_hint")} }
                    }
                }
            }
            if advanced && let Some(summary) = &contact.direct_conversation {
                div { class: "muted mono",
                    "{short_protocol_id(&summary.realm_id)} / {short_protocol_id(&summary.main_strand_id)}"
                }
            }

            div { class: "actions",
                if advanced && is_accepted_human {
                    Input {
                        r#type: "text",
                        "data-testid": "contact-petname-{peer}",
                        placeholder: tr("contacts.petname.placeholder"),
                        value: "{petname_input}",
                        maxlength: "128",
                        oninput: move |event: FormEvent| petname_input.set(event.value()),
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "contact-petname-save-{peer}",
                        onclick: {
                            let peer = peer_principal.clone();
                            let existing = existing_remark.clone();
                            let base = base_url.clone();
                            move |_| {
                                let petname = petname_input().trim().to_owned();
                                if !petname.is_empty()
                                    && let Err(error) = arkret_sdk::validate_single_line_display_text(
                                        &petname,
                                        128,
                                    )
                                {
                                    row_status.set(format!("{}: {error}", tr("contacts.petname.invalid")));
                                    return;
                                }
                                let Ok(principal_id) = arkret_sdk::DidCoreId::new(peer.clone()) else {
                                    row_status.set(tr("contacts.petname.invalid_principal"));
                                    return;
                                };
                                let edit = crate::account_data::ContactRemarkEdit::Petname(
                                    petname.clone(),
                                );
                                let remark = edit.apply(
                                    principal_id.clone(),
                                    existing.as_ref(),
                                    chrono::Utc::now(),
                                );
                                state_store
                                    .write()
                                    .set_contact_remark(peer.clone(), remark);
                                row_status.set(if petname.is_empty() {
                                    tr("contacts.petname.cleared")
                                } else {
                                    tr("contacts.petname.saved")
                                });
                                crate::views::settings::push_contact_remark_edit(
                                    base.clone(),
                                    token(),
                                    principal_id,
                                    edit,
                                );
                            }
                        },
                        {tr("contacts.petname.save")}
                    }
                    span { class: "pill muted xs", {tr("contacts.petname.badge")} }
                }
                if is_pending_incoming {
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "contact-accept-{peer}",
                        disabled: busy(),
                        onclick: {
                            let base = base_url.clone();
                            let peer = peer.clone();
                            let request_event_ref =
                                contact.request_event_ref.as_ref().map(ToString::to_string);
                            // Accept counts as the holder's first identity
                            // confirmation only when this surface already held
                            // verified Profile evidence and no record exists
                            // yet. A first-time Contact has no shared Realm to
                            // read through, so both fields stay absent and the
                            // accept still succeeds.
                            let confirmation = confirmation_at_accept.clone();
                            move |_| {
                                run_contact_action(
                                    base.clone(),
                                    token(),
                                    ContactRowAction::Respond { requester: peer.clone(), request_event_ref: request_event_ref.clone(), verb: "accept".to_owned() },
                                    tr("contacts.action.accepting"),
                                    busy,
                                    row_status,
                                    on_changed,
                                    confirmation.clone(),
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
                            let request_event_ref =
                                contact.request_event_ref.as_ref().map(ToString::to_string);
                            move |_| {
                                run_contact_action(
                                    base.clone(),
                                    token(),
                                    ContactRowAction::Respond { requester: peer.clone(), request_event_ref: request_event_ref.clone(), verb: "reject".to_owned() },
                                    tr("contacts.action.rejecting"),
                                    busy,
                                    row_status,
                                    on_changed,
                                    None,
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
                        disabled: true,
                        title: "Unavailable until the Contact lineage basis is exposed",
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
                                    None,
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
                                    let resolve_peer = peer.clone();
                                    let state_store =
                                        crate::app::runtime_adapter::state_store_handle(state_store);
                                    let resolve_store = state_store.clone();
                                    match with_authed_api(&base, api_token.clone(), |api| async move {
                                        crate::transport::account::direct_conversation_resolve(
                                            &api,
                                            &resolve_store,
                                            &resolve_peer,
                                            None,
                                            false,
                                        ).await
                                    })
                                    .await
                                    {
                                        Ok(outcome) => {
                                            use crate::transport::account::DirectConversationEntry;
                                            let local_blockers = state_store.read(|store| {
                                                crate::transport::account::direct_conversation_client_local_blockers(
                                                    store,
                                                    &peer,
                                                )
                                            });
                                            match crate::transport::account::direct_conversation_entry_with_local_blockers(
                                                &outcome,
                                                &local_blockers,
                                            ) {
                                                // Coordinates exist: open the conversation.
                                                DirectConversationEntry::Openable => {
                                                    match crate::transport::account::direct_conversation_coordinates(&outcome) {
                                                        Some(coordinates) => {
                                                            row_status.set(String::new());
                                                            nav.push(Route::DirectConversation {
                                                                realm_id: coordinates.realm_id.to_string(),
                                                                strand_id: coordinates.main_strand_id.to_string(),
                                                            });
                                                        }
                                                        None => row_status.set(tr("contacts.dm.not_ready")),
                                                    }
                                                }
                                                DirectConversationEntry::Suspended => {
                                                    if local_blockers.is_empty() {
                                                        if let Some(coordinates) = crate::transport::account::direct_conversation_coordinates(&outcome) {
                                                            let realm_id = coordinates.realm_id.clone();
                                                            let actor = crate::app::SessionContext::get()
                                                                .active_account()
                                                                .map(|account| account.did().clone());
                                                            match actor {
                                                                Some(actor) => match with_authed_api(
                                                                    &base,
                                                                    api_token.clone(),
                                                                    |api| async move {
                                                                        crate::transport::realm_write::rejoin_direct_conversation(
                                                                            &api.event_submitter()?,
                                                                            &realm_id,
                                                                            &actor,
                                                                        ).await
                                                                    },
                                                                ).await {
                                                                    Ok(_) => row_status.set("Direct Conversation self-rejoin accepted; normal MLS Add/Welcome reconciliation is pending.".to_owned()),
                                                                    Err(error) => row_status.set(format!("Direct Conversation self-rejoin unavailable: {}", error.display())),
                                                                },
                                                                None => row_status.set(tr("contacts.dm.not_ready")),
                                                            }
                                                        } else {
                                                            row_status.set(tr("contacts.dm.not_ready"));
                                                        }
                                                    } else {
                                                        row_status.set(format!(
                                                            "Direct Conversation is locally blocked: {}",
                                                            local_blockers
                                                                .iter()
                                                                .map(|blocker| blocker.as_str())
                                                                .collect::<Vec<_>>()
                                                                .join(", ")
                                                        ));
                                                    }
                                                }
                                                // This user is the founder: the conversation is
                                                // theirs to create.
                                                DirectConversationEntry::ReadyToCreate => {
                                                    let actor = crate::app::SessionContext::get()
                                                        .active_account()
                                                        .map(|account| account.authority.clone());
                                                    let peer_did = serde_json::from_str::<arkret_sdk::ActorId>(&peer).ok().and_then(|actor| actor.as_account_id().cloned());
                                                    match (actor, peer_did) {
                                                        (Some(actor), Some(peer_did)) => {
                                                            row_status.set(tr("contacts.dm.creating"));
                                                            let resolve_for_create = outcome.clone();
                                                            let resolve_store = state_store.clone();
                                                            let resolve_peer = peer.clone();
                                                            match with_authed_api(
                                                                &base,
                                                                api_token.clone(),
                                                                |api| async move {
                                                                    crate::transport::account::create_direct_conversation_from_resolve(
                                                                        &api.event_submitter()?,
                                                                        &resolve_for_create,
                                                                        &actor,
                                                                        &peer_did,
                                                                    )
                                                                    .await?;
                                                                    crate::transport::account::direct_conversation_resolve(
                                                                        &api,
                                                                        &resolve_store,
                                                                        &resolve_peer,
                                                                        None,
                                                                        false,
                                                                    ).await
                                                                },
                                                            )
                                                            .await
                                                            {
                                                                Ok(resolved) => {
                                                                    if let Some(coordinates) = crate::transport::account::direct_conversation_coordinates(&resolved) {
                                                                        row_status.set(String::new());
                                                                        nav.push(Route::DirectConversation {
                                                                            realm_id: coordinates.realm_id.to_string(),
                                                                            strand_id: coordinates.main_strand_id.to_string(),
                                                                        });
                                                                    } else {
                                                                        row_status.set(tr("contacts.dm.not_ready"));
                                                                    }
                                                                }
                                                                Err(error) => row_status.set(format!(
                                                                    "Direct Conversation creation failed: {}",
                                                                    error.display()
                                                                )),
                                                            }
                                                        }
                                                        _ => row_status.set(tr("contacts.dm.not_ready")),
                                                    }
                                                }
                                                // The other participant is the founder. Waiting never
                                                // grants create authority, so we show a waiting state
                                                // instead of offering a create action.
                                                DirectConversationEntry::AwaitingFounder => {
                                                    row_status.set(tr("contacts.dm.awaiting_founder"));
                                                }
                                                DirectConversationEntry::Unavailable => {
                                                    row_status.set(tr("contacts.dm.not_ready"));
                                                }
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
                    if crate::views::call::media_route_adapter_available() {
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "contact-call-voice-{peer}",
                            disabled: busy(),
                            onclick: {
                                let peer = peer_principal.clone();
                                move |_| {
                                    nav.push(Route::Call {
                                        call_id: String::new(),
                                        peer: peer.clone(),
                                        realm_id: String::new(),
                                        video: "0".to_owned(),
                                        incoming: "0".to_owned(),
                                    });
                                }
                            },
                            {tr("contacts.action.call_voice")}
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "contact-call-video-{peer}",
                            disabled: busy(),
                            onclick: {
                                let peer = peer_principal.clone();
                                move |_| {
                                    nav.push(Route::Call {
                                        call_id: String::new(),
                                        peer: peer.clone(),
                                        realm_id: String::new(),
                                        video: "1".to_owned(),
                                        incoming: "0".to_owned(),
                                    });
                                }
                            },
                            {tr("contacts.action.call_video")}
                        }
                    }
                    Button {
                        variant: ButtonVariant::Destructive,
                        "data-testid": "contact-block-{peer}",
                        disabled: true,
                        title: "Unavailable until the Contact lineage basis is exposed",
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
                                        None,
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
pub(crate) enum ContactRowAction {
    Respond {
        requester: String,
        request_event_ref: Option<String>,
        verb: String,
    },
    Tombstone {
        peer: String,
        block: bool,
    },
    ScopeUpdate {
        peer: String,
        scopes: Vec<ContactScope>,
    },
}

/// Run a Contact write for a row, then refresh the parent list on success.
/// Signals are `Copy`, so this is a free function the per-row onclick handlers
/// can call without fighting closure-capture rules.
/// A first identity confirmation to record if the action succeeds.
///
/// Only a surface that was already displaying verified Profile evidence for the
/// peer may set this. A later background read must never fill it in, because
/// that would dress a silent fetch up as the holder confirming an identity
/// (`client-preferences.md` section 3.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContactAcceptConfirmation {
    pub principal_id: arkret_sdk::DidCoreId,
    pub display_name: String,
}

pub(crate) fn run_contact_action(
    base: String,
    api_token: String,
    action: ContactRowAction,
    pending_msg: String,
    mut busy: Signal<bool>,
    mut row_status: Signal<String>,
    on_changed: EventHandler<()>,
    confirmation: Option<ContactAcceptConfirmation>,
) {
    busy.set(true);
    row_status.set(pending_msg);
    let confirmation_base = base.clone();
    let confirmation_token = api_token.clone();
    spawn(async move {
        let result = match action {
            ContactRowAction::Respond {
                requester,
                request_event_ref,
                verb,
            } => with_authed_sdk_client(&base, api_token, |http| async move {
                match request_event_ref {
                    Some(request_event_ref) => {
                        crate::transport::account::respond_contact_with_request_id(
                            &http,
                            &requester,
                            &request_event_ref,
                            &verb,
                        )
                        .await
                    }
                    None => {
                        crate::transport::account::respond_contact(&http, &requester, &verb).await
                    }
                }
            })
            .await
            .map(|_| ()),
            ContactRowAction::Tombstone { peer, block } => {
                with_authed_sdk_client(&base, api_token, |http| async move {
                    crate::transport::account::tombstone_contact(&http, &peer, block).await
                })
                .await
                .map(|_| ())
            }
            ContactRowAction::ScopeUpdate { peer, scopes } => {
                with_authed_sdk_client(&base, api_token, |http| async move {
                    crate::transport::account::update_contact_scopes(&http, &peer, scopes).await
                })
                .await
                .map(|_| ())
            }
        };
        match result {
            Ok(()) => {
                row_status.set(String::new());
                if let Some(confirmation) = confirmation {
                    crate::views::settings::push_contact_remark_edit(
                        confirmation_base,
                        confirmation_token,
                        confirmation.principal_id,
                        crate::account_data::ContactRemarkEdit::ConfirmDisplayName(
                            confirmation.display_name,
                        ),
                    );
                }
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
pub fn ContactsPanel(token: Signal<String>, #[props(default)] advanced: bool) -> Element {
    let mut contact_inbox = use_context::<crate::app::ContactInbox>();
    // A4 — base_url and the account-scoped state store come from session
    // context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let mut contacts = use_signal(Vec::<ContactListRow>::new);
    use_effect(move || contacts.set(contact_inbox.0()));
    let mut status = use_signal(|| "loading".to_owned());
    let mut error = use_signal(|| Option::<String>::None);
    let mut reload = use_signal(|| 0_u32);
    let mut loaded_generation = use_signal(|| u32::MAX);
    // M0.2 - "Add Contact" is a popup modal, not a standalone /contacts/new page.
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
                match with_authed_sdk_client(&base, api_token, |http| async move {
                    crate::transport::account::contacts(&http).await
                })
                .await
                {
                    Ok(response) => {
                        let count = response.contacts.len();
                        contact_inbox.0.set(response.contacts.clone());
                        state_store
                            .write()
                            .replace_accepted_human_contacts(&response.contacts);
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
    let blocklist = state_store.read().client_blocklist();
    let contact_rows = contacts
        .read()
        .iter()
        .filter(|row| !advanced || row.state == arkret_sdk::ContactState::Accepted)
        .filter(|row| {
            row.state != arkret_sdk::ContactState::PendingIncoming
                || !crate::account_data::hides_contact_request(
                    &blocklist,
                    &row.peer.contact_actor_id(),
                )
        })
        .cloned()
        .collect::<Vec<_>>();

    rsx! {
        div { class: "settings contacts-panel", "data-testid": "contacts-panel",
            div { class: "settings-shell",
                section { class: "settings-content-stack",
                    div { class: "event",
                        div { class: "event-head",
                            span { {tr(if advanced { "settings.section.contacts" } else { "contacts.title" })} }
                            if !advanced { div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "add-contact-button",
                                    onclick: move |_| add_modal_open.set(true),
                                    {tr("contacts.add_button")}
                                }
                            } }
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
                                div { class: "muted members-empty-hint", {tr(if advanced { "contacts.settings.empty" } else { "contacts.empty_hint" })} }
                                if !advanced { div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "contacts-empty-add-button",
                                        onclick: move |_| add_modal_open.set(true),
                                        {tr("contacts.empty_add")}
                                    }
                                } }
                            }
                        } else {
                            ul { class: "settings-list",
                                for contact in contact_rows {
                                    ContactRow {
                                        key: "{contact.peer.contact_actor_id()}",
                                        token,
                                        contact: contact.clone(),
                                        advanced,
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
