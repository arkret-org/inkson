//! Opening a direct conversation from the contacts sidebar.
//!
//! Three sidebar rows can start one — an owned agent, a contact's agent, and a
//! human contact — and each carried its own ~50-line `spawn` inside its
//! `onclick`. The three bodies were the same resolve-then-route routine
//! differing only in how the peer is addressed and what the failure log calls
//! it, so a fix to one could miss the other two.

use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::{InksonContext, SharedStateStore};
use crate::routes::Route;

fn spawn_direct_open_task(scope: &Scope, task: impl std::future::Future<Output = ()> + 'static) {
    if let Err(error) = scope.spawn(task) {
        scope.report_error(error);
    }
}

/// Which subject a direct conversation is being opened with.
#[derive(Clone)]
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
    scope: &Scope,
    context: Rc<InksonContext>,
    base_url: String,
    api_token: String,
    state_store: SharedStateStore,
    direct_chat_opening: Cage<Option<String>>,
    target: DirectConversationTarget,
) {
    let state_store = state_store.handle();
    let initiating_account = context.active_account.get();
    let generation = context.session_generation.get();
    let account = initiating_account.clone();
    let weak = scope.downgrade();
    let session_fence = crate::transport::auth::AuthoringSessionFence::capture();
    spawn_direct_open_task(scope, async move {
        let Ok(session_fence) = session_fence else {
            let _ = direct_chat_opening.try_revise(|opening| *opening = None);
            return;
        };
        let routed = std::rc::Rc::new(std::cell::Cell::new(false));
        let early_routed = routed.clone();
        let early_context = context.clone();
        let final_fence = session_fence.clone();
        let subject = target.subject().to_owned();
        let failure_message = target.failure_message();
        let outcome =
            crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
                session_fence.check()?;
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
                        ));
                        let outcome = crate::transport::account::direct_conversation_resolve(
                            &api,
                            &state_store,
                            &agent_actor.to_string(),
                            Some(&serde_json::to_string(&authority)?),
                            true,
                        )
                        .await?;
                        if matches!(
                            outcome,
                            arkret_sdk::DirectConversationResolveResponseBody::CreationRequired { .. }
                        ) {
                            let submitter = api.event_submitter()?;
                            let founder = submitter.authority()?.clone();
                            let peer = agent_actor.as_account_id().ok_or_else(|| {
                                anyhow::anyhow!("owned Agent requires an account-shaped actor id")
                            })?;
                            let accepted =
                                crate::transport::account::create_direct_conversation_from_resolve(
                                    &submitter, &outcome, &founder, peer,
                                )
                                .await?;
                            session_fence.check()?;
                            let _ = direct_chat_opening.try_revise(|opening| *opening = None);
                            early_context.navigate(Route::DirectConversation {
                                realm_id: accepted.realm_id.to_string(),
                                strand_id: accepted.main_strand_id.to_string(),
                            });
                            early_routed.set(true);
                            let founded = crate::transport::account::direct_conversation_resolve(
                                &api,
                                &state_store,
                                &agent_actor.to_string(),
                                Some(&serde_json::to_string(&authority)?),
                                true,
                            )
                            .await?;
                            session_fence.check()?;
                            start_founder_genesis(
                                &api,
                                &state_store,
                                &founder,
                                &founded,
                                initiating_account.as_ref(),
                            )
                            .await;
                            return Ok(founded);
                        }
                        Ok(outcome)
                    }
                    DirectConversationTarget::ContactAgent {
                        agent_id,
                        controller,
                    } => {
                        crate::transport::account::direct_conversation_resolve(
                            &api,
                            &state_store,
                            &agent_id,
                            Some(&controller),
                            false,
                        )
                        .await
                    }
                    DirectConversationTarget::Peer { peer_id } => {
                        let outcome = crate::transport::account::direct_conversation_resolve(
                            &api,
                            &state_store,
                            &peer_id,
                            None,
                            false,
                        )
                        .await?;
                        if matches!(
                            outcome,
                            arkret_sdk::DirectConversationResolveResponseBody::CreationRequired { .. }
                        ) {
                            let submitter = api.event_submitter()?;
                            let founder = submitter.authority()?.clone();
                            let peer: arkret_sdk::ActorId = serde_json::from_str(&peer_id)?;
                            let peer = peer.as_account_id().ok_or_else(|| {
                                anyhow::anyhow!("human Contact requires an AccountId")
                            })?;
                            let accepted =
                                crate::transport::account::create_direct_conversation_from_resolve(
                                    &submitter, &outcome, &founder, peer,
                                )
                                .await?;
                            session_fence.check()?;
                            let _ = direct_chat_opening.try_revise(|opening| *opening = None);
                            early_context.navigate(Route::DirectConversation {
                                realm_id: accepted.realm_id.to_string(),
                                strand_id: accepted.main_strand_id.to_string(),
                            });
                            early_routed.set(true);
                            let founded = crate::transport::account::direct_conversation_resolve(
                                &api,
                                &state_store,
                                &peer_id,
                                None,
                                false,
                            )
                            .await?;
                            session_fence.check()?;
                            start_founder_genesis(
                                &api,
                                &state_store,
                                &founder,
                                &founded,
                                initiating_account.as_ref(),
                            )
                            .await;
                            return Ok(founded);
                        }
                        Ok(outcome)
                    }
                }
            })
            .await;
        if weak.upgrade().is_none() || !context.session_matches(generation, &account) {
            return;
        }
        if final_fence.check_session_identity().is_ok() {
            let _ = direct_chat_opening.try_revise(|opening| *opening = None);
        }
        if final_fence.check().is_err() {
            return;
        }
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
                let key = match &response {
                    arkret_sdk::DirectConversationResolveResponseBody::TemporarilyUnavailable {
                        ..
                    } => "feedback.direct_temporarily_unavailable",
                    arkret_sdk::DirectConversationResolveResponseBody::AwaitingFounder {
                        ..
                    } => "feedback.direct_awaiting_founder",
                    arkret_sdk::DirectConversationResolveResponseBody::CreationBlocked {
                        ..
                    } => "feedback.direct_creation_blocked",
                    _ => "feedback.direct_open_failed",
                };
                crate::components::feedback::toast_error(
                    key,
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
        let _ = direct_chat_opening.try_revise(|opening| *opening = None);
        if !routed.get()
            && let Some(route) = route
        {
            context.navigate(route);
        }
    });
}

/// The founder authors the Direct Conversation's one scope-derived MLS Genesis
/// right after its founding unit is accepted: the bootstrap send and Add
/// phases both require that accepted Genesis
/// (`identity/contact-and-direct-conversation.md` 7.2 / 7.3). A failure here
/// does not block opening the conversation; the background creator bootstrap
/// resumes the founder's outstanding Genesis.
pub(crate) async fn start_founder_genesis(
    api: &crate::transport::TransportClient,
    state_store: &crate::runtime::input::StateStoreHandle,
    founder: &arkret_sdk::AccountId,
    founded: &arkret_sdk::DirectConversationResolveResponseBody,
    initiating_account: Option<&crate::config::ActiveAccountContext>,
) {
    let Some(coordinates) = crate::transport::account::direct_conversation_coordinates(founded)
    else {
        return;
    };
    let Some(account) = initiating_account else {
        return;
    };
    if &account.authority != founder {
        return;
    }
    crate::mls::direct_binding::diagnostic_stage("founder_genesis", "entered");
    let result = crate::mls::creator_bootstrap::start_creator_realm_mls_genesis(
        api,
        state_store,
        coordinates.realm_id.as_str(),
        founder,
        &account.device_id,
    )
    .await;
    crate::mls::direct_binding::diagnostic_stage(
        "founder_genesis",
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
    );
    if let Err(error) = result {
        tracing::warn!(
            realm = %coordinates.realm_id,
            %error,
            "Direct Conversation founder Genesis is pending"
        );
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use std::cell::Cell;

    use super::*;
    struct Pending(Rc<Cell<bool>>);
    impl std::future::Future for Pending {
        type Output = ();
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            std::task::Poll::Pending
        }
    }
    impl Drop for Pending {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    #[test]
    fn direct_open_task_is_cancelled_on_its_owner_retirement() {
        let executor = Rc::new(glory::core::executor::Executor::new(32));
        let app = glory::ui::App::with_host(executor, glory::render::memory::Memory::new);
        let dropped = Rc::new(Cell::new(false));
        let child = app.scope().child().expect("child owner");
        spawn_direct_open_task(&child, Pending(dropped.clone()));
        assert!(!dropped.get());
        drop(child);
        assert!(
            dropped.get(),
            "retired shell must cancel its direct-open command"
        );
    }
}
