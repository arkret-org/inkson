//! Opening a direct conversation from the contacts sidebar.
//!
//! Three sidebar rows can start one — an owned agent, a contact's agent, and a
//! human contact — and each carried its own ~50-line `spawn` inside its
//! `onclick`. The three bodies were the same resolve-then-route routine
//! differing only in how the peer is addressed and what the failure log calls
//! it, so a fix to one could miss the other two.

use dioxus::prelude::*;
use dioxus_router::Navigator;

use crate::routes::Route;
use crate::state::LocalStateStore;

/// Which subject a direct conversation is being opened with.
pub(super) enum DirectConversationTarget {
    /// One of the signed-in account's own agents.
    ///
    /// Its actor id is built at request time from the live authority's
    /// Station, and the request is refused outright if the controller account
    /// changed while the click was in flight — the resolved conversation would
    /// otherwise belong to a different controller than the row the user saw.
    OwnedAgent {
        agent_id: String,
        controller_principal_id: String,
    },
    /// An agent someone else controls, addressed by its own actor id plus its
    /// controller.
    ContactAgent {
        agent_id: String,
        controller: String,
    },
    /// A human contact.
    Peer { peer_id: String },
}

impl DirectConversationTarget {
    /// Subject for the failure log line — the agent or peer the row named.
    fn subject(&self) -> &str {
        match self {
            Self::OwnedAgent { agent_id, .. } | Self::ContactAgent { agent_id, .. } => agent_id,
            Self::Peer { peer_id } => peer_id,
        }
    }

    fn failure_message(&self) -> &'static str {
        match self {
            Self::OwnedAgent { .. } => "owned agent direct conversation open failed",
            Self::ContactAgent { .. } => "contact agent direct conversation open failed",
            Self::Peer { .. } => "direct conversation open failed",
        }
    }
}

/// Resolve the direct conversation with `target` and navigate to it.
///
/// `direct_chat_opening` is the per-row busy marker; it is cleared on every
/// exit path, including the failures, so a failed open does not leave the
/// sidebar permanently disabled.
pub(super) fn open_direct_conversation(
    base_url: String,
    api_token: String,
    state_store: SyncSignal<LocalStateStore>,
    navigator: Navigator,
    mut direct_chat_opening: Signal<Option<String>>,
    target: DirectConversationTarget,
) {
    spawn(async move {
        let subject = target.subject().to_owned();
        let failure_message = target.failure_message();
        let outcome =
            crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
                match target {
                    DirectConversationTarget::OwnedAgent {
                        agent_id,
                        controller_principal_id,
                    } => {
                        let authority = api.event_submitter()?.authority()?.clone();
                        anyhow::ensure!(
                            authority.principal_id
                                == crate::mls_api_helpers::principal_core_id(
                                    &controller_principal_id
                                )?,
                            "active controller account changed while opening Agent conversation"
                        );
                        let agent_actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                            crate::mls_api_helpers::principal_core_id(&agent_id)?,
                            authority.station_id.clone(),
                        ))
                        .to_string();
                        crate::transport::account::direct_conversation_resolve(
                            &api,
                            state_store,
                            &agent_actor,
                            Some(&serde_json::to_string(&authority)?),
                            true,
                        )
                        .await
                    }
                    DirectConversationTarget::ContactAgent {
                        agent_id,
                        controller,
                    } => {
                        crate::transport::account::direct_conversation_resolve(
                            &api,
                            state_store,
                            &agent_id,
                            Some(&controller),
                            false,
                        )
                        .await
                    }
                    DirectConversationTarget::Peer { peer_id } => {
                        crate::transport::account::direct_conversation_resolve(
                            &api,
                            state_store,
                            &peer_id,
                            None,
                            false,
                        )
                        .await
                    }
                }
            })
            .await;
        let route = match outcome {
            Ok(ref response)
                if let Some(coordinates) =
                    crate::transport::account::direct_conversation_coordinates(response) =>
            {
                Some(Route::DirectConversation {
                    realm_id: coordinates.realm_id.to_string(),
                    strand_id: coordinates.main_strand_id.to_string(),
                })
            }
            Ok(response) => {
                crate::components::feedback::toast_error(
                    "feedback.direct_open_failed",
                    vec![],
                    Some(format!("outcome: {response:?}")),
                );
                None
            }
            Err(err) => {
                tracing::error!(
                    error = %err.display_diagnostic(),
                    subject = %subject,
                    "{failure_message}"
                );
                crate::components::feedback::toast_error(
                    "feedback.direct_open_failed",
                    vec![],
                    Some(err.display_diagnostic()),
                );
                None
            }
        };
        direct_chat_opening.set(None);
        if let Some(route) = route {
            let _ = navigator.push(route);
        }
    });
}
