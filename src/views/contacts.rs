use std::rc::Rc;

use arkret_sdk::contact_operations::ContactScope;
use glory::{Cage, Scope};

use crate::i18n::tr;
use crate::models::ContactView;
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;
const CONTACT_MESSAGE_MAX: usize = 2000;

/// Retain UI copy and opaque values until rendering, so in-flight and completed
/// feedback follows the active locale without rerunning the Contact operation.
#[derive(Clone, Debug, Default)]
pub(crate) struct ContactFeedback {
    key: &'static str,
    literal: Option<(&'static str, String)>,
    api_error: Option<std::rc::Rc<crate::transport::auth::ApiCallError>>,
}

impl ContactFeedback {
    pub(crate) fn new(key: &'static str) -> Self {
        Self {
            key,
            ..Self::default()
        }
    }

    fn with_literal(mut self, name: &'static str, value: impl ToString) -> Self {
        self.literal = Some((name, value.to_string()));
        self
    }

    fn with_api_error(mut self, error: crate::transport::auth::ApiCallError) -> Self {
        self.api_error = Some(std::rc::Rc::new(error));
        self
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    pub(crate) fn render(&self) -> String {
        if self.is_empty() {
            return String::new();
        }
        // Only one opaque argument is inserted. Its own braces are never
        // interpreted as placeholders, and API diagnostics stay undisclosed.
        if let Some(error) = &self.api_error {
            crate::i18n::tr_args(self.key, &[("error", error.display())])
        } else if let Some((name, value)) = &self.literal {
            crate::i18n::tr_args(self.key, &[(*name, value.clone())])
        } else {
            tr(self.key)
        }
    }
}

fn save_contact_remark(
    context: Rc<InksonContext>,
    state_store: crate::presentation::SharedStateStore,
    busy: Cage<bool>,
    row_status: Cage<ContactFeedback>,
    base_url: String,
    api_token: String,
    principal_id: arkret_sdk::DidCoreId,
    edit: crate::account_data::ContactRemarkEdit,
    success_key: &'static str,
) {
    let Some(authority) = state_store.read(|store| store.active_authority()) else {
        return;
    };
    busy.revise(|value| {
        *value = true;
    });
    row_status.revise(|value| {
        *value = ContactFeedback::new("contacts.remark.saving");
    });
    {
        let generation = context.session_generation.get_untracked();
        let account = context.active_account.get_untracked();
        let task_owner = context.clone();
        let _ = task_owner.spawn(async move {
            let result = crate::views::settings::save_contact_remark_edit(
                base_url,
                api_token,
                authority.clone(),
                principal_id,
                edit,
            )
            .await;
            if state_store.read(|store| store.active_authority()).as_ref() != Some(&authority) {
                return;
            }
            if !context.session_matches(generation, &account)
                || !busy.is_alive()
                || !row_status.is_alive()
            {
                return;
            }
            match result {
                Ok(remark) => {
                    let principal = remark.subject.principal_id.to_string();
                    state_store.write(|store| store.set_contact_remark(principal, remark));
                    row_status.revise(|value| {
                        *value = ContactFeedback::new(success_key);
                    });
                }
                Err(error) => row_status.revise(|value| {
                    *value = ContactFeedback::new("contacts.action_failed").with_api_error(error);
                }),
            }
            busy.revise(|value| {
                *value = false;
            });
        });
    };
}

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
    context: Rc<InksonContext>,
    base: String,
    api_token: String,
    action: ContactRowAction,
    pending_key: &'static str,
    busy: Cage<bool>,
    row_status: Cage<ContactFeedback>,
    on_changed: Rc<dyn Fn(())>,
    confirmation: Option<ContactAcceptConfirmation>,
) {
    busy.revise(|value| {
        *value = true;
    });
    row_status.revise(|value| {
        *value = ContactFeedback::new(pending_key);
    });
    let confirmation_base = base.clone();
    let confirmation_token = api_token.clone();
    {
        let generation = context.session_generation.get_untracked();
        let account = context.active_account.get_untracked();
        let task_owner = context.clone();
        let _ = task_owner.spawn(async move {
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
                            crate::transport::account::respond_contact(&http, &requester, &verb)
                                .await
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
            if !context.session_matches(generation, &account)
                || !busy.is_alive()
                || !row_status.is_alive()
            {
                return;
            }
            match result {
                Ok(()) => {
                    row_status.revise(|value| {
                        *value = ContactFeedback::default();
                    });
                    if let Some(confirmation) = confirmation {
                        crate::views::settings::push_contact_remark_edit(
                            context.clone(),
                            confirmation_base,
                            confirmation_token,
                            confirmation.principal_id,
                            crate::account_data::ContactRemarkEdit::ConfirmDisplayName(
                                confirmation.display_name,
                            ),
                        );
                    }
                    on_changed(());
                }
                Err(err) => row_status.revise(|value| {
                    *value = ContactFeedback::new("contacts.action_failed").with_api_error(err);
                }),
            }
            busy.revise(|value| {
                *value = false;
            });
        });
    };
}

#[derive(Clone)]
struct ContactRowState {
    context: Rc<InksonContext>,
    contact: ContactView,
    busy: Cage<bool>,
    status: Cage<ContactFeedback>,
    confirm: Cage<bool>,
    petname: Cage<String>,
    confirmed_name: Option<String>,
    accept_confirmation: Option<ContactAcceptConfirmation>,
    on_changed: Rc<dyn Fn(())>,
}
#[allow(unused_variables)]
impl ContactRowState {
    fn confirm_changed(self) {
        let context = self.context.clone();
        let state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let token = context.token;
        let busy = self.busy;
        let row_status = self.status;
        let confirm_block = self.confirm;
        let petname_input = self.petname;
        let contact = self.contact.clone();
        let peer = contact.peer.contact_actor_id().to_string();
        let peer_principal = crate::models::contact_peer_id(&contact).to_string();
        let current = self.confirmed_name.clone().unwrap_or_default();
        let on_changed = self.on_changed.clone();
        let confirmation_at_accept = self.accept_confirmation.clone();
        let handler = {
            let base = base_url.clone();
            let peer_principal = peer_principal.clone();
            let current = current.clone();
            move |_| {
                let Ok(principal_id) = arkret_sdk::DidCoreId::new(peer_principal.clone()) else {
                    row_status.revise(|value| {
                        *value = ContactFeedback::new("contacts.petname.invalid_principal");
                    });
                    return;
                };
                let edit =
                    crate::account_data::ContactRemarkEdit::ConfirmDisplayName(current.clone());
                save_contact_remark(
                    context.clone(),
                    state_store,
                    busy,
                    row_status,
                    base.clone(),
                    token.get(),
                    principal_id,
                    edit,
                    "contacts.confirmed_name.confirmed",
                );
            }
        };
        handler(());
    }
    fn save_petname(self) {
        let context = self.context.clone();
        let state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let token = context.token;
        let busy = self.busy;
        let row_status = self.status;
        let confirm_block = self.confirm;
        let petname_input = self.petname;
        let contact = self.contact.clone();
        let peer = contact.peer.contact_actor_id().to_string();
        let peer_principal = crate::models::contact_peer_id(&contact).to_string();
        let current = self.confirmed_name.clone().unwrap_or_default();
        let on_changed = self.on_changed.clone();
        let confirmation_at_accept = self.accept_confirmation.clone();
        let handler = {
            let peer = peer_principal.clone();
            let base = base_url.clone();
            move |_| {
                let petname = petname_input.get().trim().to_owned();
                if !petname.is_empty()
                    && let Err(error) = arkret_sdk::validate_single_line_display_text(&petname, 128)
                {
                    row_status.revise(|value| {
                        *value = ContactFeedback::new("contacts.petname.invalid")
                            .with_literal("error", error);
                    });
                    return;
                }
                let Ok(principal_id) = arkret_sdk::DidCoreId::new(peer.clone()) else {
                    row_status.revise(|value| {
                        *value = ContactFeedback::new("contacts.petname.invalid_principal");
                    });
                    return;
                };
                let edit = crate::account_data::ContactRemarkEdit::Petname(petname.clone());
                save_contact_remark(
                    context.clone(),
                    state_store,
                    busy,
                    row_status,
                    base.clone(),
                    token.get(),
                    principal_id,
                    edit,
                    if petname.is_empty() {
                        "contacts.petname.cleared"
                    } else {
                        "contacts.petname.saved"
                    },
                );
            }
        };
        handler(());
    }
    fn accept(self) {
        let context = self.context.clone();
        let state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let token = context.token;
        let busy = self.busy;
        let row_status = self.status;
        let confirm_block = self.confirm;
        let petname_input = self.petname;
        let contact = self.contact.clone();
        let peer = contact.peer.contact_actor_id().to_string();
        let peer_principal = crate::models::contact_peer_id(&contact).to_string();
        let current = self.confirmed_name.clone().unwrap_or_default();
        let on_changed = self.on_changed.clone();
        let confirmation_at_accept = self.accept_confirmation.clone();
        let handler = {
            let base = base_url.clone();
            let peer = peer.clone();
            let request_event_ref = contact.request_event_ref.as_ref().map(ToString::to_string);
            // Accept counts as the holder's first identity
            // confirmation only when this surface already held
            // verified Profile evidence and no record exists
            // yet. A first-time Contact has no shared Realm to
            // read through, so both fields stay absent and the
            // accept still succeeds.
            let confirmation = confirmation_at_accept.clone();
            move |_| {
                run_contact_action(
                    context.clone(),
                    base.clone(),
                    token.get(),
                    ContactRowAction::Respond {
                        requester: peer.clone(),
                        request_event_ref: request_event_ref.clone(),
                        verb: "accept".to_owned(),
                    },
                    "contacts.action.accepting",
                    busy,
                    row_status,
                    on_changed,
                    confirmation.clone(),
                );
            }
        };
        handler(());
    }
    fn reject(self) {
        let context = self.context.clone();
        let state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let token = context.token;
        let busy = self.busy;
        let row_status = self.status;
        let confirm_block = self.confirm;
        let petname_input = self.petname;
        let contact = self.contact.clone();
        let peer = contact.peer.contact_actor_id().to_string();
        let peer_principal = crate::models::contact_peer_id(&contact).to_string();
        let current = self.confirmed_name.clone().unwrap_or_default();
        let on_changed = self.on_changed.clone();
        let confirmation_at_accept = self.accept_confirmation.clone();
        let handler = {
            let base = base_url.clone();
            let peer = peer.clone();
            let request_event_ref = contact.request_event_ref.as_ref().map(ToString::to_string);
            move |_| {
                run_contact_action(
                    context.clone(),
                    base.clone(),
                    token.get(),
                    ContactRowAction::Respond {
                        requester: peer.clone(),
                        request_event_ref: request_event_ref.clone(),
                        verb: "reject".to_owned(),
                    },
                    "contacts.action.rejecting",
                    busy,
                    row_status,
                    on_changed,
                    None,
                );
            }
        };
        handler(());
    }
    fn message(self) {
        let context = self.context.clone();
        let state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let token = context.token;
        let busy = self.busy;
        let row_status = self.status;
        let confirm_block = self.confirm;
        let petname_input = self.petname;
        let contact = self.contact.clone();
        let peer = contact.peer.contact_actor_id().to_string();
        let peer_principal = crate::models::contact_peer_id(&contact).to_string();
        let current = self.confirmed_name.clone().unwrap_or_default();
        let on_changed = self.on_changed.clone();
        let confirmation_at_accept = self.accept_confirmation.clone();
        let handler = {
            let base = base_url.clone();
            let peer = peer.clone();
            move |_| {
                let base = base.clone();
                let peer = peer.clone();
                let api_token = token.get();
                busy.revise(|value| {
                    *value = true;
                });
                row_status.revise(|value| {
                    *value = ContactFeedback::new("contacts.dm.opening");
                });
                let initiating_account = context.active_account.get();
                let fence = crate::transport::auth::AuthoringSessionFence::capture();
                {
                    let task_owner = context.clone();
                    let _=task_owner.spawn(async move {
                                    let Ok(fence) = fence else {
                                        let _ = busy.try_revise(|value| *value = false);
                                        return;
                                    };
                                    let completion_fence = fence.clone();
                                    let feedback_fence = fence.clone();
                                    let set_status = move |message: ContactFeedback| {
                                        if feedback_fence.check().is_err() { return; }
                                        let _ = row_status.try_revise(|value| *value = message);
                                    };
                                    let resolve_peer = peer.clone();
                                    let state_store =
                                        state_store.handle();
                                    let resolve_store = state_store.clone();
                                    let resolve_fence = fence.clone();
                                    match with_authed_api(&base, api_token.clone(), |api| async move {
                                        resolve_fence.check()?;
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
                                            if fence.check().is_err() { return; }
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
                                                            set_status(ContactFeedback::default());
                                                            if busy.is_alive(){context.navigate(Route::DirectConversation {
                                                                realm_id: coordinates.realm_id.to_string(),
                                                                strand_id: coordinates.main_strand_id.to_string(),
                                                            });};
                                                        }
                                                        None => set_status(ContactFeedback::new("contacts.dm.not_ready")),
                                                    }
                                                }
                                                DirectConversationEntry::Suspended => {
                                                    if local_blockers.is_empty() {
                                                        if let Some(coordinates) = crate::transport::account::direct_conversation_coordinates(&outcome) {
                                                            let realm_id = coordinates.realm_id.clone();
                                                            let actor = initiating_account.as_ref()
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
                                                                    Ok(_) => set_status(ContactFeedback::new("contacts.dm.rejoin_pending")),
                                                                    Err(error) => set_status(ContactFeedback::new("contacts.dm.rejoin_failed").with_api_error(error)),
                                                                },
                                                                None => set_status(ContactFeedback::new("contacts.dm.not_ready")),
                                                            }
                                                        } else {
                                                            set_status(ContactFeedback::new("contacts.dm.not_ready"));
                                                        }
                                                    } else {
                                                        set_status(ContactFeedback::new("contacts.dm.locally_blocked").with_literal(
                                                            "blockers",
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
                                                    let actor = initiating_account.as_ref()
                                                        .map(|account| account.authority.clone());
                                                    let peer_did = serde_json::from_str::<arkret_sdk::ActorId>(&peer).ok().and_then(|actor| actor.as_account_id().cloned());
                                                    match (actor, peer_did) {
                                                        (Some(actor), Some(peer_did)) => {
                                                            set_status(ContactFeedback::new("contacts.dm.creating"));
                                                            let resolve_for_create = outcome.clone();
                                                            let resolve_store = state_store.clone();
                                                            let resolve_peer = peer.clone();
                                                            match with_authed_api(
                                                                &base,
                                                                api_token.clone(),
                                                                |api| async move {
                                                                    let accepted = crate::transport::account::create_direct_conversation_from_resolve(
                                                                        &api.event_submitter()?,
                                                                        &resolve_for_create,
                                                                        &actor,
                                                                        &peer_did,
                                                                    )
                                                                    .await?;
                                                                    fence.check()?;
                                                                    if busy.is_alive(){context.navigate(Route::DirectConversation { realm_id:accepted.realm_id.to_string(), strand_id:accepted.main_strand_id.to_string() });};
                                                                    let resolved = crate::transport::account::direct_conversation_resolve(
                                                                        &api,
                                                                        &resolve_store,
                                                                        &resolve_peer,
                                                                        None,
                                                                        false,
                                                                    ).await?;
                                                                    fence.check()?;
                                                                    crate::app::direct_open::start_founder_genesis(&api, &resolve_store, &actor, &resolved, initiating_account.as_ref()).await;
                                                                    Ok(resolved)
                                                                },
                                                            )
                                                            .await
                                                            {
                                                                Ok(resolved) => {
                                                                    if crate::transport::account::direct_conversation_coordinates(&resolved).is_some() {
                                                                        set_status(ContactFeedback::default());

                                                                    } else {
                                                                        set_status(ContactFeedback::new("contacts.dm.not_ready"));
                                                                    }
                                                                }
                                                                Err(error) => set_status(ContactFeedback::new("contacts.dm.create_failed").with_api_error(error)),
                                                            }
                                                        }
                                                        _ => set_status(ContactFeedback::new("contacts.dm.not_ready")),
                                                    }
                                                }
                                                // The other participant is the founder. Waiting never
                                                // grants create authority, so we show a waiting state
                                                // instead of offering a create action.
                                                DirectConversationEntry::AwaitingFounder => {
                                                    set_status(ContactFeedback::new("contacts.dm.awaiting_founder"));
                                                }
                                                DirectConversationEntry::Unavailable => {
                                                    set_status(ContactFeedback::new("contacts.dm.not_ready"));
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            set_status(
                                                ContactFeedback::new("contacts.dm.open_failed").with_api_error(err),
                                            )
                                        }
                                    }
                                    if completion_fence.check().is_ok()
                                        { let _ = busy.try_revise(|value| *value = false); }
                                });
                };
            }
        };
        handler(());
    }
    fn block(self) {
        let context = self.context.clone();
        let state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let token = context.token;
        let busy = self.busy;
        let row_status = self.status;
        let confirm_block = self.confirm;
        let petname_input = self.petname;
        let contact = self.contact.clone();
        let peer = contact.peer.contact_actor_id().to_string();
        let peer_principal = crate::models::contact_peer_id(&contact).to_string();
        let current = self.confirmed_name.clone().unwrap_or_default();
        let on_changed = self.on_changed.clone();
        let confirmation_at_accept = self.accept_confirmation.clone();
        let handler = {
            let base = base_url.clone();
            let peer = peer.clone();
            move |_| {
                confirm_block.revise(|value| {
                    *value = false;
                });
                run_contact_action(
                    context.clone(),
                    base.clone(),
                    token.get(),
                    ContactRowAction::Tombstone {
                        peer: peer.clone(),
                        block: true,
                    },
                    "contacts.action.blocking",
                    busy,
                    row_status,
                    on_changed,
                    None,
                );
            }
        };
        handler(());
    }
}

pub fn contact_new_panel(
    scope: &Scope,
    context: Rc<InksonContext>,
    on_submitted: Option<Rc<dyn Fn(())>>,
) -> View {
    let target = scope.cage(String::new());
    let message = scope.cage(String::new());
    let sending = scope.cage(false);
    let status = scope.cage(ContactFeedback::default());
    let token = context.token;
    let base_url = context.base_url.get_untracked();
    let enabled = scope.bond(move || {
        !sending.get()
            && !target.get().trim().is_empty()
            && message.get().chars().count() <= CONTACT_MESSAGE_MAX
    });
    let request = {
        let context = context.clone();
        let owner = scope.downgrade();
        let base = base_url.clone();
        move |_| {
            let api_token = token.get();
            let base = base.clone();
            let target_did = target.get().trim().to_owned();
            let scopes = crate::transport::DEFAULT_CONTACT_SCOPE_NAMES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>();
            let greeting = message.get().trim().to_owned();
            sending.revise(|value| {
                *value = true;
            });
            status.revise(|value| {
                *value = ContactFeedback::new("contacts.new.sending");
            });
            {
                let Some(scope) = owner.upgrade() else {
                    return;
                };
                let context = context.clone();
                let generation = context.session_generation.get_untracked();
                let account = context.active_account.get_untracked();
                let on_submitted = on_submitted.clone();
                let _ = scope.owner().spawn(async move {
                    let greeting_opt = if greeting.is_empty() {
                        None
                    } else {
                        Some(greeting.as_str())
                    };
                    let result = with_authed_api(&base, api_token, |api| async move {
                        api.request_contact_with_message(&target_did, &scopes, greeting_opt)
                            .await
                    })
                    .await;
                    if !context.session_matches(generation, &account) {
                        return;
                    }
                    match result {
                        Ok(_) => {
                            status.revise(|value| {
                                *value = ContactFeedback::new("contacts.new.sent");
                            });
                            message.revise(|value| {
                                *value = String::new();
                            });
                            if let Some(cb) = on_submitted.as_ref() {
                                cb(());
                            }
                        }
                        Err(err) => status.revise(|value| {
                            *value = ContactFeedback::new("contacts.new.send_failed")
                                .with_api_error(err);
                        }),
                    }
                    sending.revise(|value| {
                        *value = false;
                    });
                });
            };
        }
    };
    stack(
        "event contact-request-panel",
        vec![
            line(
                "event-head",
                vec![
                    plain(context.translated(scope, "contacts.new.title")),
                    plain(context.translated(scope, "contacts.new.subtitle")),
                ],
            ),
            paragraph("muted", context.translated(scope, "contacts.new.intro")),
            input(
                scope,
                context.clone(),
                "contact-target-input",
                "contacts.new.target_label",
                target,
                scope.bond(move || !sending.get()),
            ),
            field(
                scope,
                context.clone(),
                "contact-message-input",
                "contacts.new.message_label",
                message,
                true,
                true,
                move |next| message.revise(|value| *value = next),
            ),
            paragraph(
                "muted contact-message-counter",
                scope.bond(move || {
                    format!(
                        "{} / {}",
                        message.get().chars().count(),
                        CONTACT_MESSAGE_MAX
                    )
                }),
            ),
            action(
                scope,
                context.clone(),
                "send-contact-request-button",
                "contacts.new.submit",
                "primary",
                enabled,
                {
                    let request = request;
                    move || request(())
                },
            ),
            paragraph(
                "muted contact-request-status",
                scope.bond(move || status.get().render()),
            ),
        ],
    )
}
fn contact_row(
    scope: &Scope,
    context: Rc<InksonContext>,
    contact: ContactView,
    advanced: bool,
    on_changed: Rc<dyn Fn(())>,
) -> View {
    let peer = contact.peer.contact_actor_id();
    let principal = crate::models::contact_peer_id(&contact).to_string();
    let busy = scope.cage(false);
    let status = scope.cage(ContactFeedback::default());
    let confirm = scope.cage(false);
    let remark = context
        .state_store
        .read(|store| store.contact_remark(&principal));
    let petname = scope.cage(
        remark
            .as_ref()
            .map(|r| r.petname.clone())
            .unwrap_or_default(),
    );
    let label = context
        .state_store
        .read(|store| crate::views::helpers::contact_peer_label(store, &contact));
    let shared = contact
        .direct_conversation
        .as_ref()
        .map(|c| c.realm_id.clone());
    let resolve = {
        let ctx = context.clone();
        let shared = shared.clone();
        let peer = peer.clone();
        crate::presentation::widgets::resource(scope, move || {
            let base = ctx.base_url.get();
            let token = ctx.token.get();
            let shared = shared.clone();
            let peer = peer.clone();
            async move {
                if let Some(realm) = shared {
                    crate::identity::contact_profile::refresh(&base, token, realm, vec![peer])
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Ok(())
            }
        })
    };
    let state = ContactRowState {
        context: context.clone(),
        contact: contact.clone(),
        busy,
        status,
        confirm,
        petname,
        confirmed_name: None,
        accept_confirmation: None,
        on_changed,
    };
    let enabled = scope.bond(move || !busy.get());
    let accepted = contact.state == arkret_sdk::ContactState::Accepted;
    let human = matches!(
        &contact.peer,
        arkret_sdk::contact_operations::ContactPeer::Human { .. }
    );
    let state_key = match contact.state {
        arkret_sdk::ContactState::PendingIncoming => "pending_incoming",
        arkret_sdk::ContactState::PendingOutgoing => "pending_outgoing",
        arkret_sdk::ContactState::Accepted => "accepted",
        arkret_sdk::ContactState::Rejected => "rejected",
        arkret_sdk::ContactState::Tombstoned => "tombstoned",
        arkret_sdk::ContactState::Expired => "expired",
    };
    let identity = match peer.as_account_id() {
        Some(account) => format!(
            "Principal: {} · Station: {}",
            account.principal_id, account.station_id
        ),
        None => peer.to_string(),
    };
    use sha2::Digest;
    let identity_id = match glory::render::SemanticId::new(format!(
        "contact-recipient-{}",
        hex::encode(sha2::Sha256::digest(peer.to_string().as_bytes())),
    )) {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return empty();
        }
    };
    let description_id = identity_id.clone();
    let row_name = label.clone();
    let mut nodes = vec![Box::new(
        glory::ui::text()
            .class("sr-only contact-row-identity")
            .content(identity)
            .semantics(Some(Box::new(glory::render::Semantics {
                id: Some(identity_id),
                ..Default::default()
            }))),
    ) as View];
    if let Some(message) = &contact.request_message {
        nodes.push(paragraph("contact-request-message", message.clone()));
    }
    nodes.push(line(
        "event-head",
        vec![
            plain(context.translated(scope, format!("contacts.state.{state_key}"))),
            paragraph("mono", label),
        ],
    ));
    {
        let ctx = context.clone();
        let shared = shared.clone();
        let peer = peer.clone();
        let remark = remark.clone();
        let st = state.clone();
        nodes.push(reactive(resolve.data, move |scope, read| {
            if !matches!(read, Some(Ok(()))) {
                return empty();
            }
            let Some(realm) = &shared else { return empty() };
            let current = crate::identity::contact_profile::current_display_name(realm, &peer);
            let verified =
                crate::identity::contact_profile::current_verified_display_name(realm, &peer);
            let confirmation = crate::identity::contact_profile::confirmed_display_name_state(
                realm,
                &peer,
                remark.as_ref(),
            );
            let mut children = vec![];
            if let Some(current) = current {
                children.push(paragraph("muted contact-profile-display", current));
            }
            use arkret_models_collaboration::actor_profile_resolution::ConfirmedDisplayNameState;
            match confirmation {
                ConfirmedDisplayNameState::Changed { confirmed, current } => {
                    let mut st = st.clone();
                    st.confirmed_name = Some(current.clone());
                    children.push(stack(
                        "event contact-display-name-changed",
                        vec![
                            plain(ctx.translated(scope, "contacts.confirmed_name.changed_title")),
                            paragraph(
                                "muted",
                                crate::i18n::tr_args(
                                    "contacts.confirmed_name.changed_body",
                                    &[("confirmed", confirmed), ("current", current)],
                                ),
                            ),
                            action(
                                scope,
                                ctx.clone(),
                                "contact-confirm-name",
                                "contacts.confirmed_name.confirm",
                                "secondary",
                                enabled,
                                move || st.clone().confirm_changed(),
                            ),
                        ],
                    ));
                }
                ConfirmedDisplayNameState::Unconfirmed if accepted && human => {
                    if let Some(name) = verified {
                        let mut st = st.clone();
                        st.confirmed_name = Some(name);
                        children.push(action(
                            scope,
                            ctx.clone(),
                            "contact-confirm-identity",
                            "contacts.confirmed_name.confirm",
                            "secondary",
                            enabled,
                            move || st.clone().confirm_changed(),
                        ));
                    }
                }
                _ => {}
            }
            stack("contact-identity", children)
        }));
    }
    if advanced && !contact.bidirectional_scopes.is_empty() {
        nodes.push(paragraph(
            "muted",
            format!(
                "{} {}",
                tr("contacts.shared_scopes"),
                contact
                    .bidirectional_scopes
                    .iter()
                    .map(scope_label)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    if advanced && accepted {
        let scopes = scope.cage(contact.granted_to_peer_scopes.clone());
        let mut fields = vec![];
        for (index, kind) in [
            ContactScope::DirectMessage,
            ContactScope::Invite,
            ContactScope::VoiceCall,
            ContactScope::VideoCall,
            ContactScope::Presence,
        ]
        .into_iter()
        .enumerate()
        {
            let k = kind;
            let selected = scope.bond(move || scopes.get().contains(&k));
            let k = kind;
            fields.push(Box::new(
                sapid::checkbox()
                    .unstyled()
                    .class("metric")
                    .label(scope_label(&kind))
                    .checked(selected)
                    .enabled(enabled)
                    .on_checked_change(move |on| {
                        scopes.revise(|scopes| {
                            scopes.retain(|s| s != &k);
                            if on {
                                scopes.push(k);
                            }
                            scopes.sort();
                            scopes.dedup();
                        })
                    }),
            ) as View);
            let _ = index;
        }
        let ctx = context.clone();
        let st = state.clone();
        let original = contact.granted_to_peer_scopes.clone();
        let changed = scope.bond(move || {
            let mut old = original.clone();
            old.sort();
            old.dedup();
            let mut selected = scopes.get();
            selected.sort();
            selected.dedup();
            !busy.get() && selected != old
        });
        let save_control = action(
            scope,
            context.clone(),
            "contact-scope-save",
            "contacts.scope_update.save",
            "secondary",
            changed,
            move || {
                run_contact_action(
                    ctx.clone(),
                    ctx.base_url.get_untracked(),
                    ctx.token.get_untracked(),
                    ContactRowAction::ScopeUpdate {
                        peer: st.contact.peer.contact_actor_id().to_string(),
                        scopes: scopes.get_untracked(),
                    },
                    "contacts.scope_update.saving",
                    busy,
                    status,
                    st.on_changed.clone(),
                    None,
                )
            },
        );
        nodes.push(stack(
            "contact-scope-editor",
            vec![
                paragraph(
                    "muted",
                    context.translated(scope, "contacts.scope_update.label"),
                ),
                stack("settings-list", fields),
                line("actions", vec![save_control]),
                reactive(scope.bond(move || scopes.get().is_empty()), {
                    let context = context.clone();
                    move |scope, is_empty| {
                        if is_empty {
                            paragraph(
                                "muted",
                                context.translated(scope, "contacts.scope_update.empty_hint"),
                            )
                        } else {
                            empty()
                        }
                    }
                }),
            ],
        ));
    }
    if advanced && let Some(summary) = &contact.direct_conversation {
        nodes.push(paragraph(
            "muted mono contact-direct-summary",
            format!(
                "{} / {}",
                short_protocol_id(&summary.realm_id),
                short_protocol_id(&summary.main_strand_id)
            ),
        ));
    }
    let mut actions = vec![];
    if advanced && accepted && human {
        actions.push(crate::views::settings::widgets::input_prompt(
            scope,
            context
                .translated(scope, "contacts.petname.placeholder")
                .into(),
            petname,
            Box::new(
                sapid::text_field()
                    .unstyled()
                    .class("input contact-petname")
                    .name(context.translated(scope, "contacts.petname.placeholder"))
                    .value(petname)
                    .enabled(enabled)
                    .on_value_change(move |next| petname.revise(|value| *value = next)),
            ),
        ));
        let st = state.clone();
        actions.push(action(
            scope,
            context.clone(),
            "contact-petname-save",
            "contacts.petname.save",
            "secondary",
            enabled,
            move || st.clone().save_petname(),
        ));
        actions.push(paragraph(
            "pill muted xs",
            context.translated(scope, "contacts.petname.badge"),
        ));
    }
    if contact.state == arkret_sdk::ContactState::PendingIncoming {
        for (key, label, accept) in [
            ("contact-accept", "contacts.action.accept", true),
            ("contact-reject", "contacts.action.reject", false),
        ] {
            let st = state.clone();
            actions.push(action(
                scope,
                context.clone(),
                key,
                label,
                if accept { "primary" } else { "secondary" },
                enabled,
                move || {
                    if accept {
                        st.clone().accept()
                    } else {
                        st.clone().reject()
                    }
                },
            ));
        }
    }
    if contact.state == arkret_sdk::ContactState::PendingOutgoing {
        actions.push(paragraph(
            "muted contact-pending-outgoing",
            context.translated(scope, "contacts.state.pending_outgoing"),
        ));
        actions.push(action(
            scope,
            context.clone(),
            // Withdraw remains closed until accepted contact lineage is available.
            "contact-withdraw",
            "contacts.action.withdraw",
            "ghost",
            false,
            || {},
        ));
    }
    if accepted {
        let st = state.clone();
        actions.push(action(
            scope,
            context.clone(),
            "contact-message",
            "contacts.action.message",
            "primary",
            enabled,
            move || st.clone().message(),
        ));
        if crate::views::call::media_route_adapter_available() {
            for (video, label) in [
                (false, "contacts.action.call_voice"),
                (true, "contacts.action.call_video"),
            ] {
                let ctx = context.clone();
                let principal = principal.clone();
                actions.push(action(
                    scope,
                    context.clone(),
                    if video {
                        "contact-call-video"
                    } else {
                        "contact-call-voice"
                    },
                    label,
                    "secondary",
                    enabled,
                    move || {
                        ctx.navigate(Route::Call {
                            call_id: String::new(),
                            peer: principal.clone(),
                            realm_id: String::new(),
                            video: if video { "1" } else { "0" }.into(),
                            incoming: "0".into(),
                        })
                    },
                ));
            }
        }
        actions.push(action(
            scope,
            context.clone(),
            "contact-block",
            "contacts.action.block",
            "destructive",
            false,
            move || confirm.revise(|v| *v = true),
        ));
    }
    nodes.push(line("actions", actions));
    {
        let st = state.clone();
        let ctx = context.clone();
        nodes.push(reactive(confirm, move |scope, open| {
            if open {
                let st = st.clone();
                stack(
                    "event contact-block-confirm",
                    vec![
                        plain(ctx.translated(scope, "contacts.block.confirm_title")),
                        paragraph(
                            "muted",
                            ctx.translated(scope, "contacts.block.confirm_body"),
                        ),
                        action(
                            scope,
                            ctx.clone(),
                            "contact-block-confirm-button",
                            "contacts.block.confirm_button",
                            "destructive",
                            enabled,
                            move || st.clone().block(),
                        ),
                        action(
                            scope,
                            ctx.clone(),
                            "contact-block-cancel-button",
                            "contacts.block.cancel",
                            "secondary",
                            true,
                            move || confirm.revise(|v| *v = false),
                        ),
                    ],
                )
            } else {
                empty()
            }
        }));
    }
    nodes.push(paragraph(
        "muted contact-row-status",
        scope.bond(move || status.get().render()),
    ));
    Box::new(
        glory::ui::view()
            .role(glory::render::Role::Group)
            .name(row_name)
            .semantics(Some(Box::new(glory::render::Semantics {
                described_by: Some(description_id),
                ..Default::default()
            })))
            .class(
                if matches!(
                    contact.state,
                    arkret_sdk::ContactState::Rejected | arkret_sdk::ContactState::Tombstoned
                ) {
                    "event contact-row weak"
                } else {
                    "event contact-row"
                },
            )
            .fill(nodes),
    )
}
pub fn page(scope: &Scope, context: Rc<InksonContext>, route: Route) -> View {
    let advanced = matches!(route, Route::SettingsSection { .. });
    contacts_panel(scope, context, advanced)
}
pub fn contacts_panel(scope: &Scope, context: Rc<InksonContext>, advanced: bool) -> View {
    let reload = scope.cage(0_u64);
    let modal = scope.cage(false);
    let load = {
        let ctx = context.clone();
        crate::presentation::widgets::resource(scope, move || {
            let _ = reload.get();
            let base = ctx.base_url.get();
            let token = ctx.token.get();
            let generation = ctx.session_generation.get();
            let account = ctx.active_account.get();
            let ctx = ctx.clone();
            async move {
                let response = with_authed_sdk_client(&base, token, |http| async move {
                    crate::transport::account::contacts(&http).await
                })
                .await
                .map_err(|e| e.display())?;
                if ctx.session_matches(generation, &account) {
                    ctx.contact_rows.revise(|v| *v = response.contacts.clone());
                    ctx.state_store
                        .write(|store| store.replace_accepted_human_contacts(&response.contacts));
                    Ok(response.contacts)
                } else {
                    Err(tr("contacts.load_error"))
                }
            }
        })
    };
    let body = {
        let ctx = context.clone();
        reactive(load.data, move |scope, result| {
            let rows = match result {
                None => {
                    return paragraph(
                        "muted contacts-loading",
                        ctx.translated(scope, "contacts.loading"),
                    );
                }
                Some(Err(error)) => {
                    return stack(
                        "event error-banner contacts-error",
                        vec![
                            paragraph("muted", error),
                            action(
                                scope,
                                ctx.clone(),
                                "contacts-retry-button",
                                "contacts.retry",
                                "secondary",
                                true,
                                move || reload.revise(|v| *v += 1),
                            ),
                        ],
                    );
                }
                Some(Ok(rows)) => rows,
            };
            let blocklist = ctx.state_store.read(|s| s.client_blocklist());
            let rows = rows
                .into_iter()
                .filter(|row| !advanced || row.state == arkret_sdk::ContactState::Accepted)
                .filter(|row| {
                    row.state != arkret_sdk::ContactState::PendingIncoming
                        || !crate::account_data::hides_contact_request(
                            &blocklist,
                            &row.peer.contact_actor_id(),
                        )
                })
                .collect::<Vec<_>>();
            if rows.is_empty() {
                return stack(
                    "members-empty contacts-empty-state",
                    vec![
                        paragraph(
                            "members-empty-title",
                            ctx.translated(scope, "contacts.empty_title"),
                        ),
                        paragraph(
                            "muted members-empty-hint",
                            ctx.translated(
                                scope,
                                if advanced {
                                    "contacts.settings.empty"
                                } else {
                                    "contacts.empty_hint"
                                },
                            ),
                        ),
                        if !advanced {
                            action(
                                scope,
                                ctx.clone(),
                                "contacts-empty-add-button",
                                "contacts.empty_add",
                                "primary",
                                true,
                                move || modal.revise(|v| *v = true),
                            )
                        } else {
                            empty()
                        },
                    ],
                );
            }
            stack(
                "settings-list",
                rows.into_iter()
                    .map(|row| {
                        contact_row(
                            scope,
                            ctx.clone(),
                            row,
                            advanced,
                            Rc::new(move |_| reload.revise(|v| *v += 1)),
                        )
                    })
                    .collect(),
            )
        })
    };
    let ctx = context.clone();
    let popup = reactive(modal, move |scope, open| {
        if !open {
            return empty();
        }
        let ctx = ctx.clone();
        confirmation(
            scope,
            ctx.clone(),
            "add-contact-modal",
            ctx.translated(scope, "contacts.new.title"),
            contact_new_panel(
                scope,
                ctx,
                Some(Rc::new(move |_| {
                    modal.revise(|v| *v = false);
                    reload.revise(|v| *v += 1);
                })),
            ),
            move || modal.revise(|v| *v = false),
        )
    });
    stack(
        "settings contacts-panel",
        vec![
            stack(
                "settings-shell",
                vec![stack(
                    "settings-content-stack",
                    vec![stack(
                        "event",
                        vec![
                            line(
                                "event-head",
                                vec![
                                    plain(context.translated(
                                        scope,
                                        if advanced {
                                            "settings.section.contacts"
                                        } else {
                                            "contacts.title"
                                        },
                                    )),
                                    if !advanced {
                                        action(
                                            scope,
                                            context.clone(),
                                            "add-contact-button",
                                            "contacts.add_button",
                                            "primary",
                                            true,
                                            move || modal.revise(|v| *v = true),
                                        )
                                    } else {
                                        empty()
                                    },
                                ],
                            ),
                            body,
                        ],
                    )],
                )],
            ),
            popup,
        ],
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod feedback_tests {
    use super::*;
    use crate::transport::auth::ApiCallError;
    #[test]
    fn retained_contact_feedback_rerenders_with_locale_and_keeps_opaque_values() {
        let problem: arkret_sdk::Problem = serde_json::from_value(serde_json::json!({
            "type": "https://arkret.org/problems/internal_error", "title": "Internal error",
            "status": 500, "detail": "private server detail / 原文", "code": "internal_error"
        }))
        .unwrap();
        let feedback = [
            ContactFeedback::new("contacts.action.accepting"),
            ContactFeedback::new("contacts.petname.saved"),
            ContactFeedback::new("contacts.petname.invalid")
                .with_literal("error", "{error} / contacts.title / 原文"),
            ContactFeedback::new("contacts.dm.locally_blocked")
                .with_literal("blockers", "{blockers}, local_block, consent_withdrawn"),
            ContactFeedback::new("contacts.action_failed").with_api_error(ApiCallError::Failed(
                crate::api_error::TransportClientError {
                    status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    error: problem,
                }
                .into(),
            )),
            ContactFeedback::new("contacts.action_failed").with_api_error(
                ApiCallError::Unavailable(anyhow::anyhow!("private unavailable diagnostic")),
            ),
            ContactFeedback::new("contacts.action_failed").with_api_error(
                ApiCallError::AuthExpired(anyhow::anyhow!("private session diagnostic")),
            ),
            ContactFeedback::new("contacts.new.send_failed").with_api_error(ApiCallError::Failed(
                anyhow::anyhow!("{}", "local validation {error} / contacts.title / 原文"),
            )),
        ];
        let english = [
            "Accepting…",
            "Petname saved",
            "Invalid petname: {error} / contacts.title / 原文",
            "This direct chat is blocked on this device: {blockers}, local_block, consent_withdrawn",
            "Action failed: Something went wrong while talking to the server. Try again.",
            "Action failed: The server is unavailable right now. Check the server address, or wait a moment and try again.",
            "Action failed: Your session has expired. Sign in again to continue.",
            "Failed to send: local validation {error} / contacts.title / 原文",
        ];
        let chinese = [
            "正在接受…",
            "备注名已保存",
            "备注名无效：{error} / contacts.title / 原文",
            "此私聊在本机被阻止：{blockers}, local_block, consent_withdrawn",
            "操作失败:与服务器通信时出现问题。请重试。",
            "操作失败:服务器当前不可用。请检查服务器地址,或稍等片刻后重试。",
            "操作失败:登录已过期。请重新登录以继续。",
            "发送失败:local validation {error} / contacts.title / 原文",
        ];
        let expected = |values: &[&str]| {
            let mut values = values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>();
            values.sort();
            values
        };
        for (locale, copy) in [
            (crate::i18n::UiLocale::En, &english),
            (crate::i18n::UiLocale::Zh, &chinese),
            (crate::i18n::UiLocale::En, &english),
        ] {
            crate::i18n::with_test_locale(locale, || {
                let mut actual = feedback
                    .iter()
                    .map(ContactFeedback::render)
                    .collect::<Vec<_>>();
                actual.sort();
                assert_eq!(actual, expected(copy));
                assert!(actual.iter().all(|value| !value.contains("private")));
            });
        }
    }
}
