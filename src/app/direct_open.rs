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

fn spawn_direct_open_task(
    opening: Signal<Option<String>>,
    task: impl std::future::Future<Output = ()> + 'static,
) {
    // Navigation leaves the application shell mounted. Keep its task with the
    // shell's state, so unmount cancels it instead of accessing dropped
    // signals from the root scope.
    dioxus::core::Runtime::current().in_scope(opening.origin_scope(), || {
        dioxus::core::spawn(task);
    });
}

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
    // The transport half of this flow takes the host-neutral handle, not the
    // Dioxus signal: `crate::transport` is engine code on its way to garth and
    // must not name a UI runtime type. Wrapping here is the host's job.
    let state_store = super::runtime_adapter::state_store_handle(state_store);
    let initiating_account = crate::app::SessionContext::get().active_account();
    let session_fence = crate::transport::auth::AuthoringSessionFence::capture();
    spawn_direct_open_task(direct_chat_opening, async move {
        let Ok(session_fence) = session_fence else {
            if let Ok(mut opening) = direct_chat_opening.try_write() {
                *opening = None;
            }
            return;
        };
        let routed = std::rc::Rc::new(std::cell::Cell::new(false));
        let early_routed = routed.clone();
        let early_navigator = navigator.clone();
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
                            arkret_sdk::DirectConversationResolveOutcome::CreationRequired { .. }
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
                            if let Ok(mut opening) = direct_chat_opening.try_write() {
                                *opening = None;
                            }
                            early_navigator.push(Route::DirectConversation {
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
                            arkret_sdk::DirectConversationResolveOutcome::CreationRequired { .. }
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
                            if let Ok(mut opening) = direct_chat_opening.try_write() {
                                *opening = None;
                            }
                            early_navigator.push(Route::DirectConversation {
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
        if final_fence.check_session_identity().is_ok()
            && let Ok(mut opening) = direct_chat_opening.try_write()
        {
            *opening = None;
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
                    arkret_sdk::DirectConversationResolveOutcome::TemporarilyUnavailable {
                        ..
                    } => "feedback.direct_temporarily_unavailable",
                    arkret_sdk::DirectConversationResolveOutcome::AwaitingFounder { .. } => {
                        "feedback.direct_awaiting_founder"
                    }
                    arkret_sdk::DirectConversationResolveOutcome::CreationBlocked { .. } => {
                        "feedback.direct_creation_blocked"
                    }
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
        if let Ok(mut opening) = direct_chat_opening.try_write() {
            *opening = None;
        }
        if !routed.get()
            && let Some(route) = route
        {
            let _ = navigator.push(route);
        }
    });
}

#[cfg(test)]
mod lifecycle_tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::*;

    #[derive(Clone, PartialEq)]
    struct Probe {
        mounted: Rc<RefCell<Option<Signal<bool>>>>,
        scope: Rc<Cell<Option<(ScopeId, ScopeId)>>>,
        dropped: Rc<Cell<bool>>,
    }

    struct OpeningTask {
        opening: Signal<Option<String>>,
        probe: Probe,
    }

    impl std::future::Future for OpeningTask {
        type Output = ();

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            self.probe.scope.set(Some((
                dioxus::core::current_scope_id(),
                self.opening.origin_scope(),
            )));
            *self.opening.write() = None;
            std::task::Poll::Pending
        }
    }

    impl Drop for OpeningTask {
        fn drop(&mut self) {
            self.probe.dropped.set(true);
        }
    }

    #[component]
    fn OpeningShell(probe: Probe) -> Element {
        let opening = use_signal(|| Some("opening".to_owned()));
        use_hook(move || {
            spawn_direct_open_task(opening, OpeningTask { opening, probe });
        });
        rsx! { div { "shell" } }
    }

    fn lifecycle_harness(probe: Probe) -> Element {
        let mounted = use_signal(|| true);
        *probe.mounted.borrow_mut() = Some(mounted);
        rsx! {
            if mounted() {
                OpeningShell { probe }
            }
        }
    }

    #[test]
    fn direct_open_task_uses_shell_scope_and_is_cancelled_on_shell_unmount() {
        let probe = Probe {
            mounted: Rc::new(RefCell::new(None)),
            scope: Rc::new(Cell::new(None)),
            dropped: Rc::new(Cell::new(false)),
        };
        let mut dom = VirtualDom::new_with_props(lifecycle_harness, probe.clone());
        dom.rebuild_in_place();
        dom.render_immediate_to_vec();
        let (task_scope, state_scope) = probe.scope.get().expect("opening task was polled");
        assert_eq!(task_scope, state_scope);
        assert_ne!(task_scope, ScopeId::ROOT);
        assert!(!probe.dropped.get());
        dom.in_runtime(|| probe.mounted.borrow().unwrap().set(false));
        dom.render_immediate_to_vec();
        assert!(probe.dropped.get(), "unmounted shell must cancel its task");
    }
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
    founded: &arkret_sdk::DirectConversationResolveOutcome,
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
    if let Err(error) = crate::mls::creator_bootstrap::start_creator_realm_mls_genesis(
        api,
        state_store,
        coordinates.realm_id.as_str(),
        founder,
        &account.device_id,
    )
    .await
    {
        tracing::warn!(
            realm = %coordinates.realm_id,
            %error,
            "Direct Conversation founder Genesis is pending"
        );
    }
}
