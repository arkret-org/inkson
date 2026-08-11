//! Account-first identity setup.
//!
//! The user-facing flow intentionally hides the handoff lease, DID inception,
//! PCR genesis, and recovery-material gate. Those protocol stages remain
//! durable and resumable, but the page presents only three user decisions:
//! choose an identity, save its Recovery Key, and finish.

use dioxus::prelude::*;
use dioxus_router::Link;
use dioxus_router::hooks::use_navigator;

use crate::recovery_crypto::{RecoveryKeyConfirmationDiff, recovery_key_confirmation_diff};
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum IdentityChoice {
    #[default]
    Choose,
    Create,
}

/// Which onboarding surface the durable stages select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OnboardingSurface {
    /// Choose an identity, then generate, save and confirm a new Recovery Key.
    IdentityCreation,
    /// The authenticated account is already bound, but this device is not.
    /// The Recovery Key proves root control and authorizes this device.
    RootRecovery,
    /// Finish a durable identity draft that is still completable from here.
    ResumeSetup,
    /// A durable identity draft that nothing on this device can finish. It is
    /// shown as a dead end with an explicit way out, never as a Recovery Key
    /// prompt: asking for 24 words that cannot be used is indistinguishable
    /// from a bug, and it locks a *new* account out of its own setup.
    StaleCheckpoint,
    /// No onboarding work is pending on this device.
    AccountSummary,
}

/// Select the onboarding surface from the durable stages.
///
/// The account handoff is the freshest statement of intent on this device: it
/// is written by the Account Authority callback that just authenticated
/// someone. A persisted identity draft that does not belong to that handoff is
/// therefore *not* the current user's unfinished work, and must never take the
/// surface away from them — that is how a newly registered account was shown
/// "Enter your Recovery Key" for a stranger's draft DID it could not have saved
/// words for.
///
/// Without a handoff, a draft is only completable when its account binding has
/// already been registered AND this device holds a live session for that exact
/// DID, which is what the remaining setup calls authenticate with. A
/// `CustodyConfirmed` draft always needs the handoff (its lease and handoff
/// credential are what bind the account), so it can never be resumed alone.
///
/// The session is read from the same two signals the resume panel's submit
/// authenticates with, NOT from the persisted session grant. Routing on a
/// different input than submitting is what put a live, resumable setup on the
/// dead-end surface: the durable grant snapshot races its own hydration (the
/// test-fixture injection documents that race), while `token` / `account_did`
/// are always settled before `secure_store_ready` unlatches this decision.
fn onboarding_surface(
    handoff: Option<&crate::state::PendingAccountHandoff>,
    checkpoint: Option<&crate::state::PendingPrincipalRegistration>,
    session_token_present: bool,
    active_account_did: &str,
) -> OnboardingSurface {
    let Some(checkpoint) = checkpoint else {
        return match handoff {
            Some(handoff) if handoff.bound_principal_id.is_some() => {
                OnboardingSurface::RootRecovery
            }
            Some(_) => OnboardingSurface::IdentityCreation,
            None => OnboardingSurface::AccountSummary,
        };
    };

    if let Some(handoff) = handoff {
        if handoff.bound_principal_id.is_some() {
            return OnboardingSurface::RootRecovery;
        }
        return if crate::identity::principal_registration::checkpoint_belongs_to_handoff(
            checkpoint, handoff,
        ) {
            OnboardingSurface::ResumeSetup
        } else {
            OnboardingSurface::IdentityCreation
        };
    }

    let binding_registered =
        checkpoint.stage != crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed;
    let holds_this_identity_session = session_token_present && active_account_did == checkpoint.did;
    if binding_registered && holds_this_identity_session {
        OnboardingSurface::ResumeSetup
    } else {
        OnboardingSurface::StaleCheckpoint
    }
}

#[component]
pub fn OnboardingPanel(
    secure_store_ready: bool,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    account_primary_handle: Signal<String>,
    needs_device_authorization: Signal<bool>,
    device_authorization_check_complete: Signal<bool>,
) -> Element {
    let state_store = crate::app::SessionContext::get().state_store;
    if !secure_store_ready {
        return rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                div { class: "event onboarding-card",
                    h2 { "Restoring identity setup" }
                    p { class: "muted", "Loading this account's saved setup…" }
                }
            }
        };
    }
    // The durable stages are routing inputs ONLY at mount, and the decision is
    // latched for the lifetime of this mount.
    //
    // Two independent regressions live here. Subscribing the parent to the
    // state store made every durable stage write re-route the surface; latching
    // additionally survives a parent re-render (changed props re-run this body
    // with the store already advanced). Both used to swap the in-flight
    // creation panel for the generic resume panel the moment
    // `create_and_bind_identity` persisted its first checkpoint —
    // unmounting the only holder of the in-memory Recovery Key, cancelling its
    // scoped task, and asking an uninterrupted setup for the same 24 words
    // twice. A real remount (reload/restart) re-reads the stages and
    // intentionally enters the resume surface.
    //
    // `routed` is only ever `peek`ed, so latching it during render notifies no
    // subscriber and cannot loop. An explicit discard bumps `reroute` (which IS
    // subscribed) to force exactly one re-decision.
    let mut routed = use_signal(|| None::<OnboardingSurface>);
    let mut reroute = use_signal(|| 0_u32);
    let _routing_generation = reroute();

    let latched = *routed.peek();
    let surface = match latched {
        Some(surface) => surface,
        None => {
            let session_token_present = !token.peek().trim().is_empty();
            let active_account_did = account_did.peek().trim().to_owned();
            let surface = {
                let store = state_store.peek();
                onboarding_surface(
                    store.pending_account_handoff().as_ref(),
                    store.pending_principal_registration().as_ref(),
                    session_token_present,
                    &active_account_did,
                )
            };
            routed.set(Some(surface));
            surface
        }
    };

    let on_discard = move |()| {
        routed.set(None);
        reroute += 1;
    };

    match surface {
        OnboardingSurface::RootRecovery => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                RootAnchoredDeviceRecovery {
                    state_store,
                    token,
                    account_did,
                    device_id,
                    needs_device_authorization,
                    device_authorization_check_complete,
                }
            }
        },
        OnboardingSurface::ResumeSetup => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                PendingPrincipalSetup {
                    token,
                    account_did,
                    device_id,
                    config_store,
                    needs_device_authorization,
                    device_authorization_check_complete,
                    on_discard,
                }
            }
        },
        OnboardingSurface::IdentityCreation => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                PendingAccountIdentityCreation {
                    token,
                    account_did,
                    device_id,
                    config_store,
                    account_primary_handle,
                    needs_device_authorization,
                    device_authorization_check_complete,
                }
            }
        },
        OnboardingSurface::StaleCheckpoint => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                StalePrincipalSetup { on_discard }
            }
        },
        OnboardingSurface::AccountSummary => {
            let did = account_did();
            rsx! {
                div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                    div { class: "event onboarding-card onboarding-finished", "data-testid": "account-strand",
                        if did.trim().is_empty() {
                            div { class: "onboarding-finish-mark", "aria-hidden": "true", "1" }
                            h2 { "Set up your identity" }
                            p { class: "muted", "Sign in first, then choose whether to create or link an identity." }
                            Link { class: "primary", to: Route::Login, "Sign in" }
                        } else {
                            div { class: "onboarding-finish-mark", "aria-hidden": "true", "✓" }
                            h2 { "You're all set" }
                            p { class: "muted", "Your account is linked to {short_protocol_id(&did)}." }
                            Link { class: "primary", to: Route::Dashboard, "Continue" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn RootAnchoredDeviceRecovery(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    mut token: Signal<String>,
    mut account_did: Signal<String>,
    device_id: Signal<String>,
    mut needs_device_authorization: Signal<bool>,
    mut device_authorization_check_complete: Signal<bool>,
) -> Element {
    let mut words = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut busy = use_signal(|| false);
    rsx! {
        div { class: "event onboarding-card", "data-testid": "root-anchored-device-recovery",
            div { class: "onboarding-step-mark", "aria-hidden": "true", "1" }
            h2 { "Recover this identity" }
            p { class: "muted",
                "This account already has an identity. Enter its 24-word Recovery Key to prove root control and authorize this device. No approval from another device or administrator is required."
            }
            Label { html_for: "root-recovery-words", "Recovery Key (24 words)" }
            Textarea {
                id: "root-recovery-words",
                value: words(),
                rows: 4,
                autocomplete: "off",
                oninput: move |event: FormEvent| words.set(event.value()),
            }
            Button {
                variant: ButtonVariant::Primary,
                disabled: busy() || words().split_whitespace().count() != 24,
                onclick: move |_| {
                    let Some(handoff) = state_store.read().pending_account_handoff() else {
                        status.set("The authenticated account recovery checkpoint is missing. Sign in again.".to_owned());
                        return;
                    };
                    let Some(principal_id) = handoff.bound_principal_id.clone() else {
                        status.set("This account does not require existing-identity recovery.".to_owned());
                        return;
                    };
                    let recovery_words = words();
                    let replacement_device_id = device_id();
                    busy.set(true);
                    status.set("Verifying Recovery Key and preparing a root-anchored device authorization…".to_owned());
                    spawn(async move {
                        let result = recover_bound_principal_device(
                            &handoff,
                            &principal_id,
                            &replacement_device_id,
                            &recovery_words,
                            state_store,
                        )
                        .await;
                        words.set(String::new());
                        busy.set(false);
                        match result {
                            Ok(completed) => {
                                if let Some(grant) = state_store.read().session_grant() {
                                    account_did.set(grant.principal_id.clone());
                                    token.set(grant.grant_jwt);
                                }
                                needs_device_authorization.set(false);
                                device_authorization_check_complete.set(true);
                                status.set(format!(
                                    "Identity recovered. Device receipt {} and the Standard session grant are durable.",
                                    completed.readiness.terminal_receipt_id
                                ));
                            }
                            Err(error) => status.set(format!("Recovery could not finish: {error}")),
                        }
                    });
                },
                if busy() { "Recovering…" } else { "Authorize this device" }
            }
            if !status().is_empty() {
                p { class: "muted", role: "status", "{status}" }
            }
        }
    }
}

async fn recover_bound_principal_device(
    handoff: &crate::state::PendingAccountHandoff,
    principal_id: &str,
    replacement_device_id: &str,
    recovery_words: &str,
    state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<crate::mls::account_recovery::CompletedFreshDeviceRecovery> {
    if replacement_device_id != handoff.device_id {
        anyhow::bail!("replacement device does not match the authenticated account handoff");
    }
    crate::event_signer::bind_active_signer_device_id(replacement_device_id)?;
    let api = crate::transport::TransportClient::unauthenticated(&handoff.principal_server_url)?;
    if let Some(mut completed) =
        crate::mls::account_recovery::resume_pending_root_anchored_recovery(
            &api,
            state_store,
            recovery_words,
        )
        .await?
    {
        completed.standard_grant_installed =
            issue_recovery_completion_grant(handoff, &completed.transaction_id, state_store)
                .await?;
        return Ok(completed);
    }
    let policy = crate::recovery_strand::fetch_active_recovery_policy(&api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the identity has no active Recovery Key policy"))?;
    let session = api
        .create_recovery_session(&arkret_models_crypto::RecoverySessionCreateRequestBody {
            principal_id: crate::mls_api_helpers::principal_core_id(principal_id)?,
            requesting_device_id: arkret_sdk::DeviceId::new(replacement_device_id.to_owned())?,
            trust_domain: arkret_sdk::TypedTrustDomainId::new(handoff.trust_domain.clone())?,
            expected_recovery_policy_ref: Some(arkret_models_crypto::RecoveryPolicyRef {
                policy_id: policy.policy_id.clone(),
                policy_version: policy.version,
            }),
        })
        .await?;
    let proof = crate::recovery_strand::build_recovery_unlock_proof_from_words(
        &session,
        &policy,
        recovery_words,
    )?;
    let proof_outcome = api
        .submit_recovery_proof(
            session.recovery_session_id.as_str(),
            &arkret_models_crypto::RecoverySessionProofSubmitRequestBody { proof },
        )
        .await?;
    let mut completed = crate::mls::account_recovery::execute_root_anchored_recovery(
        &api,
        state_store,
        &arkret_sdk::DidFullId::new(principal_id.to_owned())?,
        &session,
        &proof_outcome,
        recovery_words,
    )
    .await?;
    completed.standard_grant_installed =
        issue_recovery_completion_grant(handoff, &completed.transaction_id, state_store).await?;
    Ok(completed)
}

async fn issue_recovery_completion_grant(
    handoff: &crate::state::PendingAccountHandoff,
    transaction_id: &arkret_sdk::TransactionId,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<bool> {
    let holder = {
        let mut store = state_store.write();
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
            .ok_or_else(|| anyhow::anyhow!("recovery grant holder key is unavailable"))?
    };
    if handoff.holder_jkt != holder.jkt() {
        anyhow::bail!("account handoff holder key changed during recovery");
    }
    let account_handoff_grant = crate::identity::account_auth::load_account_handoff_grant()?
        .ok_or_else(|| anyhow::anyhow!("account handoff credential is unavailable"))?;
    let authority =
        crate::identity::account_auth::AuthorityResolver::discover(&handoff.principal_server_url)
            .await?;
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &authority.gate_account_base,
    )?;
    let account_http = arkret_sdk::http_client::ClientBuilder::new(account_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            holder.sdk_account_handoff_auth(account_handoff_grant),
        ))
        .build()?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(
        crate::security_transaction::security_transaction_engine(account_http, secure_store),
    );
    let (outcome, initial_session) = match workflow
        .retry_byte_identical_completion_grant(transaction_id)
        .await?
    {
        Some(outcome) => {
            let local = workflow
                .local_state(transaction_id)?
                .ok_or_else(|| anyhow::anyhow!("recovery grant request is not durable"))?;
            let canonical = local
                .accepted_completion_grant_request
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!("retry outcome omitted its durable initial-session request")
                })?;
            let request: arkret_wire::IssueRecoveryCompletionGrantRequest =
                serde_json::from_slice(canonical)?;
            let initial_session = serde_json::from_value(request.initial_session)?;
            (outcome, initial_session)
        }
        None => {
            let initial_session = arkret_sdk::InitialSessionGrantRequest {
                device_id: arkret_sdk::DeviceId::new(handoff.device_id.clone())?,
                session_public_key: holder.canonical_session_public_jwk()?,
                audience: arkret_sdk::DidCoreId::new(handoff.audience.clone())?,
                requested_scope: vec!["ak.self.account.read.viewer".to_owned()],
            };
            initial_session.validate()?;
            let request = workflow
                .build_completion_grant_issuance(transaction_id, initial_session.clone())?;
            let outcome = workflow
                .issue_completion_grant(transaction_id, &request)
                .await?;
            (outcome, initial_session)
        }
    };
    let session_grant_outcome = serde_json::from_value(outcome.session_grant_outcome)?;
    let session = garth::SessionGrantState::from_initial_registration_outcome(
        &initial_session,
        session_grant_outcome,
        chrono::Utc::now(),
    )?;
    let actor = session.principal_id.to_string();
    let persisted = crate::state::PersistedSessionGrant {
        grant_jwt: session.grant_jwt.clone(),
        session_private_key_pem: holder.session_signing_key_pkcs8_pem()?.to_string(),
        grant_id: session.grant_id.to_string(),
        audience: session.audience.to_string(),
        principal_id: actor.clone(),
        device_id: handoff.device_id.clone(),
        principal_server_url: handoff.principal_server_url.clone(),
        grant_expires_at: Some(session.expires_at),
        stored_at: chrono::Utc::now(),
    };
    let dpop_record = crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
        holder.seed_b64().as_str(),
    )?;
    {
        let mut store = state_store.write();
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        crate::secure_key_store::adopt_device_seed_scope_on_login(secure_store.as_ref(), &actor)?;
        store.adopt_pending_login(&actor);
        crate::views::login::persist_completed_login_dpop_key(
            &mut store,
            secure_store.as_ref(),
            &actor,
            &handoff.device_id,
            &dpop_record,
        )
        .map_err(anyhow::Error::msg)?;
        store.set_session_grant(Some(persisted));
        store.register_known_account(&actor);
        store.set_pending_account_handoff(None)?;
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }
    crate::identity::account_auth::clear_account_handoff_grant()?;
    Ok(true)
}

#[component]
fn SetupProgress(current: usize) -> Element {
    rsx! {
        ol { class: "onboarding-progress", "aria-label": "Setup progress",
            for (index, label) in ["Identity", "Recovery Key", "Ready"].iter().enumerate() {
                li {
                    class: if index + 1 == current {
                        "is-current"
                    } else if index + 1 < current {
                        "is-complete"
                    } else {
                        ""
                    },
                    span { class: "onboarding-progress-index", if index + 1 < current { "✓" } else { "{index + 1}" } }
                    span { "{label}" }
                }
            }
        }
    }
}

#[component]
fn PendingAccountIdentityCreation(
    mut token: Signal<String>,
    mut account_did: Signal<String>,
    mut device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    account_primary_handle: Signal<String>,
    mut needs_device_authorization: Signal<bool>,
    mut device_authorization_check_complete: Signal<bool>,
) -> Element {
    let mut state_store = crate::app::SessionContext::get().state_store;
    let navigator = use_navigator();
    let mut choice = use_signal(IdentityChoice::default);
    let mut recovery_key = use_signal(String::new);
    let mut confirmation = use_signal(String::new);
    let mut copied = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut complete = use_signal(|| false);
    let mut status = use_signal(String::new);

    // Completion clears the durable handoff/checkpoint. Render the success
    // surface from component-local state before reading either checkpoint so
    // their cleanup cannot transiently (or permanently, if the scoped task is
    // cancelled) turn the final onboarding page into an empty node.
    if complete() {
        return rsx! {
            div { class: "event onboarding-card", "data-testid": "account-handoff-onboarding",
                SetupProgress { current: 3 }
                div { class: "onboarding-finished", "data-testid": "onboarding-complete",
                    div { class: "onboarding-finish-mark", "aria-hidden": "true", "✓" }
                    h2 { "Identity ready" }
                    p { class: "muted", "Your account, this device, and recovery backup are ready." }
                    if !status().is_empty() {
                        div { class: "form-hint-warn", role: "status", "{status}" }
                    }
                    Link { class: "primary", to: Route::Dashboard, "Continue" }
                }
            }
        };
    }

    let handoff = state_store.read().pending_account_handoff();

    let Some(handoff) = handoff else {
        return rsx! {};
    };
    let pending_abandonment = state_store
        .read()
        .pending_principal_registration()
        .and_then(|checkpoint| checkpoint.identity_abandonment);
    let abandonment_challenge_expired = pending_abandonment
        .as_ref()
        .is_some_and(|pending| pending.challenge.expires_at <= chrono::Utc::now());

    if let Some(retry_after_ms) = handoff.retry_after_ms {
        let retry_after_seconds = retry_after_ms.div_ceil(1_000).max(1);
        return rsx! {
            div { class: "event onboarding-card onboarding-centered", "data-testid": "identity-creation-busy",
                h2 { "Setup is already in progress" }
                p { class: "muted", "Continue in the open setup, or wait about {retry_after_seconds} seconds and then sign in again on this device." }
                Link { class: "secondary", to: Route::Login, "Sign in again" }
            }
        };
    }

    let expired = handoff.expires_at <= chrono::Utc::now()
        || handoff
            .lease_expires_at
            .is_some_and(|expires_at| expires_at <= chrono::Utc::now());
    if expired {
        return rsx! {
            div { class: "event onboarding-card onboarding-centered", "data-testid": "account-handoff-expired",
                h2 { "Setup expired" }
                p { class: "muted", "Sign in again to continue. Your saved setup will be reused." }
                Link { class: "primary", to: Route::Login, "Sign in again" }
            }
        };
    }

    let current_step = if choice() == IdentityChoice::Create {
        2
    } else {
        1
    };
    let hosting_name = hosting_label(&handoff.principal_server_url);
    let handoff_for_creation = handoff.clone();
    let handoff_for_abandonment = handoff.clone();

    rsx! {
        div { class: "event onboarding-card", "data-testid": "account-handoff-onboarding",
            SetupProgress { current: current_step }

            if let Some(pending_abandonment) = pending_abandonment {
                div { class: "onboarding-heading",
                    span { class: "eyebrow", "Explicit abandonment" }
                    h2 { "Confirm giving up this provisional identity" }
                    p { class: "muted",
                        "The orphan anchor will be permanently unusable and cannot be deactivated or continued. A new identity root DID and PCR must be created."
                    }
                }
                div { class: "callout warn",
                    div { class: "body",
                        strong { "This cannot be undone." }
                        " Confirm only after re-authenticating the account."
                    }
                }
                div { class: "onboarding-footer-actions",
                    Link { class: "secondary", to: Route::Login, "Authenticate again" }
                    if abandonment_challenge_expired {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "restart-identity-abandonment-challenge",
                            disabled: busy(),
                            onclick: move |_| {
                                let Some(handoff) = state_store.read().pending_account_handoff() else {
                                    status.set("Authenticate the account again before renewing the abandonment challenge.".to_owned());
                                    return;
                                };
                                let Some(mut checkpoint) = state_store.read().pending_principal_registration() else {
                                    status.set("The provisional identity checkpoint is unavailable.".to_owned());
                                    return;
                                };
                                busy.set(true);
                                status.set("Renewing explicit abandonment challenge…".to_owned());
                                spawn(async move {
                                    let result = async {
                                        let dpop = {
                                            let mut store = state_store.write();
                                            crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
                                        };
                                        let pending = crate::identity::identity_abandonment::issue_challenge(
                                            &handoff,
                                            &checkpoint,
                                            &dpop,
                                        ).await?;
                                        checkpoint.identity_abandonment = Some(pending);
                                        let barrier = {
                                            let mut store = state_store.write();
                                            store.set_pending_principal_registration(Some(checkpoint))?;
                                            store.begin_durable_flush()?
                                        };
                                        barrier.wait().await?;
                                        crate::identity::account_auth::clear_account_handoff_grant()
                                    }.await;
                                    match result {
                                        Ok(()) => status.set("Challenge renewed. Authenticate once more with a fresh account handoff to confirm.".to_owned()),
                                        Err(error) => status.set(format!("Could not renew abandonment challenge: {error}")),
                                    }
                                    busy.set(false);
                                });
                            },
                            if busy() { "Renewing…" } else { "Renew expired challenge" }
                        }
                    } else {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "confirm-identity-abandonment",
                            disabled: busy(),
                            onclick: move |_| {
                                let Some(handoff) = state_store.read().pending_account_handoff() else {
                                    status.set("Authenticate the account again before confirming abandonment.".to_owned());
                                    return;
                                };
                                let Some(checkpoint) = state_store.read().pending_principal_registration() else {
                                    status.set("The provisional identity checkpoint is unavailable.".to_owned());
                                    return;
                                };
                                let pending = pending_abandonment.clone();
                                let navigator = navigator.clone();
                                busy.set(true);
                                status.set("Confirming explicit abandonment…".to_owned());
                                spawn(async move {
                                    let result = async {
                                        let dpop = {
                                            let mut store = state_store.write();
                                            crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
                                        };
                                        crate::identity::identity_abandonment::confirm(
                                            &handoff,
                                            &checkpoint,
                                            &pending,
                                            &dpop,
                                        ).await?;
                                        clear_pending_principal_setup(state_store).await
                                    }.await;
                                    match result {
                                        Ok(()) => {
                                            status.set("Provisional identity abandoned. Authenticate to create a new identity root.".to_owned());
                                            navigator.push(Route::Login);
                                        }
                                        Err(error) => status.set(format!("Identity abandonment failed: {error}")),
                                    }
                                    busy.set(false);
                                });
                            },
                            if busy() { "Confirming…" } else { "Permanently abandon identity" }
                        }
                    }
                }
                if !status().is_empty() {
                    div { class: "form-hint-warn", role: "status", "{status}" }
                }
            } else if choice() == IdentityChoice::Choose {
                div { class: "onboarding-heading",
                    span { class: "eyebrow", "Step 1" }
                    h2 { "Set up your identity" }
                    p { class: "muted", "Inkson creates one identity for this account and authorizes this device as its first device." }
                }

                div { class: "identity-choice-grid", role: "group", "aria-label": "Identity setup",
                    section { class: "identity-choice-card is-recommended",
                        h3 { "Create your identity" }
                        p { "It will be anchored by a Recovery Key and hosted with {hosting_name}. No device approval step is needed." }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "choose-new-identity",
                            onclick: move |_| {
                                choice.set(IdentityChoice::Create);
                                if recovery_key().is_empty() {
                                    match crate::recovery_crypto::generate_recovery_key() {
                                        Ok(key) => {
                                            recovery_key.set(key);
                                            confirmation.set(String::new());
                                            copied.set(false);
                                            status.set(String::new());
                                        }
                                        Err(error) => status.set(format!(
                                            "Could not create a Recovery Key: {error}"
                                        )),
                                    }
                                }
                            },
                            "Continue"
                        }
                    }
                }
                if !status().is_empty() {
                    div { class: "form-hint-warn", role: "alert", "{status}" }
                }
            } else {
                div { class: "onboarding-heading",
                    span { class: "eyebrow", "Step 2" }
                    h2 { "Save your Recovery Key" }
                    p { class: "muted", "Write down these 24 words in order. They will not be shown again." }
                }

                RecoveryKeyWords { recovery_key: recovery_key() }

                div { class: "onboarding-key-actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "onboarding-copy-recovery-key",
                        onclick: {
                            let key = recovery_key();
                            move |_| {
                                crate::components::mls_backup_prompt::copy_text_to_clipboard(&key);
                                copied.set(true);
                            }
                        },
                        if copied() { "Copied" } else { "Copy words" }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "onboarding-download-recovery-key",
                        onclick: {
                            let key = recovery_key();
                            let handoff_handle = handoff.account_handle.clone();
                            move |_| {
                                let handles = [handoff_handle.clone(), account_primary_handle()];
                                let filename = crate::components::mls_backup_prompt::recovery_key_filename_from_handles(
                                    &handles,
                                );
                                crate::components::mls_backup_prompt::download_text_as_file(
                                    &filename,
                                    &key,
                                );
                            }
                        },
                        "Download .txt"
                    }
                }

                div { class: "callout warn onboarding-recovery-warning",
                    div { class: "body",
                        strong { "Keep this offline." }
                        " Anyone with these words can recover the identity. Inkson cannot replace them for you."
                    }
                }

                div { class: "workflow-form onboarding-confirmation",
                    Label { html_for: "onboarding-recovery-key-confirm", "Re-enter the 24 words" }
                    Textarea {
                        id: "onboarding-recovery-key-confirm",
                        "data-testid": "onboarding-recovery-key-confirm",
                        rows: "3",
                        autocomplete: "off",
                        value: "{confirmation}",
                        disabled: busy(),
                        placeholder: "Type or paste the words you saved",
                        oninput: move |event: FormEvent| confirmation.set(event.value()),
                    }
                }

                if !status().is_empty() {
                    div {
                        class: if busy() { "muted" } else { "form-hint-warn" },
                        role: "status",
                        "aria-live": "polite",
                        "data-testid": "account-handoff-status",
                        "{status}"
                    }
                }

                div { class: "onboarding-footer-actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        disabled: busy(),
                        onclick: move |_| {
                            choice.set(IdentityChoice::Choose);
                            status.set(String::new());
                        },
                        "Back"
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "onboarding-bind-identity",
                        disabled: busy() || confirmation().trim().is_empty(),
                        onclick: move |_| {
                            match recovery_key_confirmation_diff(&recovery_key(), &confirmation()) {
                                RecoveryKeyConfirmationDiff::Match => {}
                                RecoveryKeyConfirmationDiff::WordCount { entered } => {
                                    status.set(format!(
                                        "Enter all 24 words. You entered {entered}."
                                    ));
                                    return;
                                }
                                RecoveryKeyConfirmationDiff::MismatchAt { index } => {
                                    status.set(format!(
                                        "Word {index} does not match. Check your saved copy."
                                    ));
                                    return;
                                }
                            }

                            let handoff = handoff_for_creation.clone();
                            let supplied_key = recovery_key();
                            let device = handoff.device_id.clone();
                            let base = handoff.principal_server_url.clone();
                            busy.set(true);
                            status.set("Finishing setup…".to_owned());
                            spawn(async move {
                                let result = create_and_bind_identity(
                                    &handoff,
                                    &supplied_key,
                                    &device,
                                    &base,
                                    config_store,
                                    state_store,
                                )
                                .await;

                                match result {
                                    Ok((actor, device, grant)) => {
                                        account_did.set(actor);
                                        device_id.set(device);
                                        token.set(grant);
                                        needs_device_authorization.set(false);
                                        device_authorization_check_complete.set(true);
                                        recovery_key.set(String::new());
                                        confirmation.set(String::new());
                                        status.set(String::new());
                                        complete.set(true);
                                        if let Err(error) = clear_pending_principal_setup(state_store).await {
                                            status.set(format!(
                                                "Setup finished, but local cleanup failed: {error}"
                                            ));
                                        }
                                    }
                                    Err(error) => {
                                        status.set(format!("Setup could not finish: {error}"));
                                    }
                                }
                                busy.set(false);
                            });
                        },
                        if busy() { "Finishing…" } else { "Save and continue" }
                    }
                    if state_store.read().pending_principal_registration().is_some() {
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "issue-identity-abandonment-challenge",
                            disabled: busy(),
                            onclick: move |_| {
                                let Some(mut checkpoint) = state_store.read().pending_principal_registration() else {
                                    status.set("No provisional identity is available to abandon.".to_owned());
                                    return;
                                };
                                let handoff = handoff_for_abandonment.clone();
                                busy.set(true);
                                status.set("Issuing explicit abandonment challenge…".to_owned());
                                spawn(async move {
                                    let result = async {
                                        let dpop = {
                                            let mut store = state_store.write();
                                            crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
                                        };
                                        let pending = crate::identity::identity_abandonment::issue_challenge(
                                            &handoff,
                                            &checkpoint,
                                            &dpop,
                                        ).await?;
                                        checkpoint.identity_abandonment = Some(pending);
                                        let barrier = {
                                            let mut store = state_store.write();
                                            store.set_pending_principal_registration(Some(checkpoint))?;
                                            store.begin_durable_flush()?
                                        };
                                        barrier.wait().await?;
                                        crate::identity::account_auth::clear_account_handoff_grant()
                                    }.await;
                                    match result {
                                        Ok(()) => status.set("Challenge saved. Authenticate again with a fresh account handoff to confirm.".to_owned()),
                                        Err(error) => status.set(format!("Could not issue abandonment challenge: {error}")),
                                    }
                                    busy.set(false);
                                });
                            },
                            "Give up this provisional identity"
                        }
                    }
                }
            }
        }
    }
}

/// What discarding a draft costs, which depends entirely on whether its account
/// binding was already registered. Before the binding, the draft is local and
/// worthless; after it, this device holds the only copy of the material that
/// finishes an identity the account is already committed to.
fn discard_consequence(binding_registered: bool) -> &'static str {
    if binding_registered {
        "This identity is already registered to your account, and this device holds the only copy of its unfinished setup. Discarding it cannot be undone."
    } else {
        "Nothing has been registered yet. Discarding starts over: sign in again, and this device creates a new identity with a new Recovery Key."
    }
}

/// The way out of a saved setup this device cannot finish.
///
/// Onboarding is otherwise a one-way surface: without this, a draft that the
/// server no longer honours (or whose 24 words are gone) leaves clearing the
/// browser's site data as the only escape.
#[component]
fn DiscardSavedSetup(disabled: bool, on_discard: EventHandler<()>) -> Element {
    let state_store = crate::app::SessionContext::get().state_store;
    let mut busy = use_signal(|| false);
    let mut status = use_signal(String::new);

    rsx! {
        div { class: "onboarding-discard",
            Button {
                variant: ButtonVariant::Secondary,
                "data-testid": "onboarding-discard-saved-setup",
                disabled: disabled || busy(),
                onclick: move |_| {
                    busy.set(true);
                    status.set(String::new());
                    spawn(async move {
                        match clear_pending_principal_setup(state_store).await {
                            // Deliberately stays busy on success: the parent
                            // re-routes and this control is unmounted.
                            Ok(()) => on_discard.call(()),
                            Err(error) => {
                                status.set(format!("Could not discard the saved setup: {error}"));
                                busy.set(false);
                            }
                        }
                    });
                },
                if busy() { "Discarding…" } else { "Discard saved setup" }
            }
            if !status().is_empty() {
                div {
                    class: "form-hint-warn",
                    role: "alert",
                    "data-testid": "onboarding-discard-status",
                    "{status}"
                }
            }
        }
    }
}

#[component]
fn StalePrincipalSetup(on_discard: EventHandler<()>) -> Element {
    let state_store = crate::app::SessionContext::get().state_store;
    // Read the draft once, without subscribing: the discard this surface offers
    // clears the very checkpoint being described, and a subscribed read would
    // repaint it as an empty node before the parent re-routes.
    let (did_label, binding_registered) = use_hook(move || {
        state_store
            .peek()
            .pending_principal_registration()
            .map(|checkpoint| {
                (
                    short_protocol_id(&checkpoint.did),
                    checkpoint.stage
                        != crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
                )
            })
            .unwrap_or_else(|| ("an earlier identity".to_owned(), false))
    });

    rsx! {
        div { class: "event onboarding-card", "data-testid": "stale-principal-setup",
            SetupProgress { current: 2 }
            div { class: "onboarding-heading",
                span { class: "eyebrow", "Continue setup" }
                h2 { "This saved setup can't be finished here" }
                p { class: "muted",
                    "An unfinished identity setup for {did_label} is stored on this device, but this browser no longer holds the account session it needs to continue."
                }
            }

            div { class: "callout warn",
                div { class: "body",
                    strong { "Sign in to continue it." }
                    " Signing in to the same account restores what this setup needs. "
                    "{discard_consequence(binding_registered)}"
                }
            }

            div { class: "onboarding-footer-actions",
                DiscardSavedSetup { disabled: false, on_discard }
                Link { class: "primary", to: Route::Login, "Sign in" }
            }
        }
    }
}

#[component]
fn RecoveryKeyWords(recovery_key: String) -> Element {
    let words: Vec<String> = recovery_key
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    rsx! {
        div { class: "recovery-key-hero onboarding-recovery-key",
            ol { class: "recovery-key-grid", "data-testid": "onboarding-recovery-key-display",
                for word in words {
                    li { class: "rk-word", "{word}", " " }
                }
            }
        }
    }
}

async fn create_and_bind_identity(
    handoff: &crate::state::PendingAccountHandoff,
    recovery_key: &str,
    device: &str,
    base_url: &str,
    config_store: Signal<crate::config::LocalConfigStore>,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<(String, String, String)> {
    // Keep the handoff panel mounted while the durable registration advances.
    // The checkpoint deliberately contains no Recovery Key, but this component
    // still has the user-confirmed key in memory. Switching to the generic
    // resume panel here made a successful, uninterrupted setup appear to ask
    // for the same 24 words twice.
    let stored_checkpoint = state_store.read().pending_principal_registration();
    let (checkpoint, checkpoint_changed) = match stored_checkpoint.as_ref() {
        Some(checkpoint)
            if crate::identity::principal_registration::checkpoint_belongs_to_handoff(
                checkpoint, handoff,
            ) =>
        {
            let checkpoint = checkpoint_for_handoff(checkpoint, handoff, recovery_key)?;
            let changed = stored_checkpoint.as_ref() != Some(&checkpoint);
            (checkpoint, changed)
        }
        Some(_) | None => {
            let checkpoint = if handoff.reserved_identity.is_some() {
                crate::identity::principal_registration::recover_registration_checkpoint_from_reservation(
                    handoff,
                    recovery_key,
                )?
            } else {
                crate::identity::principal_registration::prepare_registration_checkpoint(
                    handoff,
                    device,
                    recovery_key,
                )?
            };
            (checkpoint, true)
        }
    };
    if checkpoint_changed {
        let barrier = {
            let mut store = state_store.write();
            store.set_pending_principal_registration(Some(checkpoint.clone()))?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }

    let checkpoint = if checkpoint.stage
        == crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed
    {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("device signer is unavailable"))?;
        let signer = crate::event_signer::bind_active_signer_device_id(device)?.unwrap_or(signer);
        let device_public_key_multibase = signer
            .public_key_multibase()
            .ok_or_else(|| anyhow::anyhow!("device signer has no Ed25519 public key"))?;
        let device_public_key = format!("did:key:{device_public_key_multibase}");
        let hpke_key = {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let (_, public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair(
                secure_store.as_ref(),
                &checkpoint.did,
                device,
            )?;
            crate::identity::did_key::encode_x25519_multibase(&public_key)
        };
        let dpop = {
            let mut store = state_store.write();
            crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
        };
        let prepared = crate::identity::principal_registration::prepare_genesis_draft(
            &checkpoint,
            recovery_key,
            device_public_key,
            hpke_key,
            signer.as_ref(),
            &dpop,
            arkret_sdk::DidCoreId::new(handoff.audience.clone())?,
        )?;
        let barrier = {
            let mut store = state_store.write();
            store.set_pending_principal_registration(Some(prepared.clone()))?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
        prepared
    } else {
        checkpoint
    };

    let (registration, actor, grant_jwt) = if matches!(
        checkpoint.stage,
        crate::state::PendingPrincipalRegistrationStage::GenesisDraftPrepared
            | crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared
    ) {
        let dpop = {
            let mut store = state_store.write();
            crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
        };
        let completion =
            match crate::identity::principal_registration::complete_account_handoff_binding(
                handoff,
                &checkpoint,
                recovery_key,
                &dpop,
                state_store,
            )
            .await
            {
                Ok(completion) => completion,
                Err(error) if crate::api_error::is_pcr_genesis_already_accepted_error(&error) => {
                    // Create-once lost the race. Persist the model switch before
                    // any network continuation, discard the losing genesis draft,
                    // and recover the replacement device against the accepted PCR.
                    let mut recovery_handoff = handoff.clone();
                    recovery_handoff.bound_principal_id = Some(checkpoint.did.clone());
                    {
                        let mut store = state_store.write();
                        store.set_pending_account_handoff(Some(recovery_handoff.clone()))?;
                        store.set_pending_principal_registration(None)?;
                        let barrier = store.begin_durable_flush()?;
                        drop(store);
                        barrier.wait().await?;
                    }
                    crate::identity::account_auth::clear_prepared_identity_creation_request()?;
                    let recovered = recover_bound_principal_device(
                        &recovery_handoff,
                        &checkpoint.did,
                        device,
                        recovery_key,
                        state_store,
                    )
                    .await?;
                    anyhow::bail!(
                        "the earlier PCR genesis was already accepted; this device was recovered with receipt {}. Continue sign-in for the Standard session grant",
                        recovered.readiness.terminal_receipt_id
                    );
                }
                Err(error) => return Err(error),
            };
        let actor = completion.session_grant.principal_id.to_string();
        let grant_jwt = completion.session_grant.grant_jwt.clone();
        let persisted_grant = crate::state::PersistedSessionGrant {
            grant_jwt: grant_jwt.clone(),
            session_private_key_pem: completion.session_private_key_pem,
            grant_id: completion.session_grant.grant_id.to_string(),
            audience: completion.session_grant.audience.to_string(),
            principal_id: actor.clone(),
            device_id: device.to_owned(),
            principal_server_url: handoff.principal_server_url.clone(),
            grant_expires_at: Some(completion.session_grant.expires_at),
            stored_at: chrono::Utc::now(),
        };
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        crate::secure_key_store::adopt_device_seed_scope_on_login(secure_store.as_ref(), &actor)?;
        let mut accepted = checkpoint;
        accepted.binding_receipt = Some(serde_json::to_value(completion.binding_receipt)?);
        accepted.pcr_genesis_receipt = Some(serde_json::to_value(completion.pcr_genesis_receipt)?);
        if accepted.stage == crate::state::PendingPrincipalRegistrationStage::GenesisDraftPrepared {
            accepted
                .advance_registration_stage(
                    crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
                )
                .map_err(anyhow::Error::msg)?;
        }
        accepted
            .advance_registration_stage(crate::state::PendingPrincipalRegistrationStage::Accepted)
            .map_err(anyhow::Error::msg)?;
        {
            let mut store = state_store.write();
            store.adopt_pending_login(&actor);
            crate::views::login::persist_completed_login_dpop_key(
                &mut store,
                secure_store.as_ref(),
                &actor,
                device,
                &completion.dpop_device_key,
            )
            .map_err(anyhow::Error::msg)?;
            store.set_pending_principal_registration(Some(accepted.clone()))?;
            // Do not clear pending_account_handoff yet. Keeping it until
            // finish_principal_setup succeeds keeps this component (and its
            // in-memory Recovery Key) alive through the background work.
            store.set_session_grant(Some(persisted_grant));
            store.register_known_account(&actor);
        }
        (accepted, actor, grant_jwt)
    } else {
        // Registration already returned a verified PCR receipt and Standard
        // grant. Resume only the recovery-material gate.
        let persisted_grant = state_store
            .read()
            .session_grant()
            .filter(|grant| {
                grant.principal_id == checkpoint.did && grant.device_id == checkpoint.device_id
            })
            .ok_or_else(|| {
                anyhow::anyhow!("the saved setup session is unavailable; sign in again")
            })?;
        (
            checkpoint.clone(),
            checkpoint.did.clone(),
            persisted_grant.grant_jwt,
        )
    };

    crate::views::helpers::persist_config(
        config_store,
        handoff.principal_server_url.clone(),
        actor.clone(),
        device.to_owned(),
        grant_jwt.clone(),
    );

    finish_principal_setup(
        &registration,
        recovery_key,
        base_url,
        &grant_jwt,
        &actor,
        device,
        state_store,
    )
    .await?;

    Ok((actor, device.to_owned(), grant_jwt))
}

/// Drop the durable identity draft together with the handoff it is fenced to,
/// and the short-lived account handoff credential.
///
/// Shared by completion and by an explicit user discard. Both must clear the
/// handoff too: a draft is bound to one identity-creation lease, so a next
/// attempt has to re-authenticate for a fresh lease rather than reuse the one
/// this draft consumed.
async fn clear_pending_principal_setup(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<()> {
    let barrier = {
        let mut store = state_store.write();
        store.set_pending_principal_registration(None)?;
        store.set_pending_account_handoff(None)?;
        store.begin_durable_flush()?
    };
    barrier.wait().await?;
    crate::identity::account_auth::clear_account_handoff_grant()?;
    crate::identity::account_auth::clear_prepared_identity_creation_request()?;
    Ok(())
}

fn checkpoint_for_handoff(
    checkpoint: &crate::state::PendingPrincipalRegistration,
    handoff: &crate::state::PendingAccountHandoff,
    recovery_key: &str,
) -> anyhow::Result<crate::state::PendingPrincipalRegistration> {
    if checkpoint.handoff_request_id == handoff.request_id {
        // Exact continuity: same handoff request, nothing to prove.
        crate::identity::principal_registration::validate_checkpoint_recovery_key(
            checkpoint,
            recovery_key,
        )?;
        return Ok(checkpoint.clone());
    }
    // Everything below is a *renewal*: a different request id reaching a draft
    // this device already holds. The unsigned account_handle is deliberately
    // absent from these checks; only the typed server reservation can prove
    // continuity across distinct handoff request ids.
    if handoff.reserved_identity.is_none() {
        anyhow::bail!(
            "this account has no identity reserved here, so the setup saved on this device belongs to an earlier registration"
        );
    }
    if !crate::identity::principal_registration::checkpoint_belongs_to_handoff(checkpoint, handoff)
    {
        anyhow::bail!(
            "the server's reserved identity does not match the saved setup; the original local checkpoint is required"
        );
    }
    if checkpoint.stage != crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed {
        anyhow::bail!("a different identity setup is already pending");
    }
    let (Some(lease_id), Some(lease_fence)) = (&handoff.lease_id, handoff.lease_fence) else {
        anyhow::bail!("the renewed identity-creation lease is unavailable");
    };

    // A renewed lease carries forward any identity operation that the server
    // already reserved. Recovery must replay that exact public operation; a
    // newly-derived draft would correctly be rejected as a duplicate conflict.
    // `account_handle` is not consulted: the spec defines it as an unsigned UX
    // hint, while this typed reservation is the continuity evidence.
    if let Some(reserved_identity) = handoff.reserved_identity.as_ref() {
        let reserved_identity: arkret_sdk::ReservedIdentityCreation =
            serde_json::from_value(reserved_identity.clone()).map_err(|error| {
                anyhow::anyhow!("the server's identity reservation is invalid: {error}")
            })?;
        let did_operation: arkret_sdk::DidOperationSubmitRequestBody =
            serde_json::from_value(checkpoint.did_operation.clone())
                .map_err(|error| anyhow::anyhow!("the saved DID operation is invalid: {error}"))?;
        let expected_reservation =
            arkret_sdk::ReservedIdentityCreation::from_operation(did_operation)
                .map_err(|error| anyhow::anyhow!("the saved DID operation is invalid: {error}"))?;
        if expected_reservation != reserved_identity {
            anyhow::bail!(
                "the server's reserved identity does not match the saved setup; the original local checkpoint is required"
            );
        }
    }
    crate::identity::principal_registration::validate_checkpoint_recovery_key(
        checkpoint,
        recovery_key,
    )?;

    let mut checkpoint = checkpoint.clone();
    checkpoint.handoff_request_id = handoff.request_id.clone();
    checkpoint.lease_id = lease_id.clone();
    checkpoint.lease_fence = lease_fence;
    Ok(checkpoint)
}

async fn finish_principal_setup(
    registration: &crate::state::PendingPrincipalRegistration,
    recovery_key: &str,
    base_url: &str,
    session: &str,
    actor: &str,
    device: &str,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<()> {
    crate::identity::principal_registration::validate_checkpoint_recovery_key(
        registration,
        recovery_key,
    )?;
    let mut registration = registration.clone();
    let active_session = session.to_owned();

    if registration.stage != crate::state::PendingPrincipalRegistrationStage::Accepted {
        anyhow::bail!(
            "identity registration has not returned a verified PCR receipt and Standard grant"
        );
    }

    if registration.principal_service_binding.is_none() {
        let principal_id = arkret_sdk::DidFullId::new(actor.to_owned())?;
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("device signer is unavailable"))?;
        if signer.device_id() != Some(device) {
            anyhow::bail!("active signer does not match the founding PCR device");
        }
        let binding = crate::transport::auth::with_authed_sdk_client(
            base_url,
            active_session.clone(),
            move |http| async move {
                crate::identity::principal_registration::ensure_principal_service_binding(
                    &http,
                    &principal_id,
                    signer.as_ref(),
                )
                .await
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;
        registration.principal_service_binding = Some(binding);
        let barrier = {
            let mut store = state_store.write();
            store.set_pending_principal_registration(Some(registration.clone()))?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }

    let bootstrap_seal: arkret_sdk::Seal = match registration.pcr_bootstrap_seal.clone() {
        Some(seal) => seal,
        None => {
            let unit = registration
                .pcr_genesis_unit
                .clone()
                .context("identity registration checkpoint omits its PCR genesis unit")?;
            let signer = crate::event_signer::active_signer()
                .ok_or_else(|| anyhow::anyhow!("device signer is unavailable"))?;
            if signer.device_id() != Some(device) {
                anyhow::bail!("active signer does not match the founding PCR device");
            }
            let hlc = crate::signing_stamp::issue_protocol_hlc(
                actor,
                device,
                unit.create().realm_id.as_str(),
            )?;
            let seal = signer
                .sign_self_principal_bootstrap_seal(unit.create(), unit.founding_authorize(), hlc)
                .map_err(|error| anyhow::anyhow!("sign principal bootstrap Seal: {error}"))?;
            registration.pcr_bootstrap_seal = Some(seal.clone());
            let barrier = {
                let mut store = state_store.write();
                store.set_pending_principal_registration(Some(registration.clone()))?;
                store.begin_durable_flush()?
            };
            barrier.wait().await?;
            seal
        }
    };

    let recovery_actor = actor.to_owned();
    let recovery_device = device.to_owned();
    let recovery_key_value = recovery_key.to_owned();
    let principal_control_realm_id = bootstrap_seal.realm_id.clone();
    let bootstrap_seal_for_submit = bootstrap_seal.clone();
    crate::transport::auth::with_authed_api(base_url, active_session, |api| async move {
        crate::recovery_strand::submit_principal_bootstrap_seal(&api, &bootstrap_seal_for_submit)
            .await?;
        crate::recovery_strand::ensure_recovery_policy(
            &api,
            &recovery_actor,
            &recovery_device,
            &principal_control_realm_id,
            &recovery_key_value,
        )
        .await
    })
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))?;
    registration
        .advance_registration_stage(
            crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete,
        )
        .map_err(anyhow::Error::msg)?;
    let pcr_genesis_unit = registration
        .pcr_genesis_unit
        .clone()
        .context("recovery-material evidence omits PCR genesis unit")?;
    let recovery_material_evidence = crate::state::RecoveryMaterialEvidence {
        principal_id: arkret_sdk::DidFullId::new(actor.to_owned())?,
        device_id: arkret_sdk::DeviceId::new(device.to_owned())?,
        principal_control_realm_id: bootstrap_seal.realm_id.clone(),
        pcr_genesis_unit,
        bootstrap_seal,
    };
    {
        let barrier = {
            let mut store = state_store.write();
            store.set_pending_principal_registration(Some(registration))?;
            store.set_recovery_material_evidence(Some(recovery_material_evidence))?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }
    crate::event_submit::remember_verified_recovery_gate(actor, device);
    crate::views::recovery::save_generated_recovery_key_metadata(
        &mut state_store,
        actor,
        recovery_key,
    )
    .ok_or_else(|| anyhow::anyhow!("save public recovery metadata failed"))?;
    crate::views::recovery::local_recovery_public_key_result(&state_store.read(), actor)
        .map_err(|error| anyhow::anyhow!("verify public recovery metadata: {error}"))?;
    let recovery_metadata_barrier = state_store.read().begin_durable_flush()?;
    recovery_metadata_barrier.wait().await?;
    crate::identity::account_auth::clear_prepared_identity_creation_request()?;
    Ok(())
}

#[component]
fn PendingPrincipalSetup(
    mut token: Signal<String>,
    mut account_did: Signal<String>,
    mut device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    mut needs_device_authorization: Signal<bool>,
    mut device_authorization_check_complete: Signal<bool>,
    on_discard: EventHandler<()>,
) -> Element {
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    let mut recovery_key = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut complete = use_signal(|| false);
    let mut status = use_signal(String::new);

    if complete() {
        return rsx! {
            div { class: "event onboarding-card", "data-testid": "pending-principal-setup",
                SetupProgress { current: 3 }
                div { class: "onboarding-finished", "data-testid": "onboarding-complete",
                    div { class: "onboarding-finish-mark", "aria-hidden": "true", "✓" }
                    h2 { "Identity ready" }
                    p { class: "muted", "Your account and this device are ready." }
                    if !status().is_empty() {
                        div { class: "form-hint-warn", role: "status", "{status}" }
                    }
                    Link { class: "primary", to: Route::Dashboard, "Continue" }
                }
            }
        };
    }

    let checkpoint = state_store.read().pending_principal_registration();

    let Some(registration) = checkpoint else {
        return rsx! {};
    };
    let did_label = short_protocol_id(&registration.did);
    let binding_registered =
        registration.stage != crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed;

    rsx! {
        div { class: "event onboarding-card", "data-testid": "pending-principal-setup",
            SetupProgress { current: 2 }
            div { class: "onboarding-heading",
                span { class: "eyebrow", "Continue setup" }
                h2 { "Enter your Recovery Key" }
                p { class: "muted", "Use the same 24 words you saved for {did_label}." }
                p { class: "muted",
                    "Setting up a different account, or no longer have these words? Discard this setup and start again. "
                    "{discard_consequence(binding_registered)}"
                }
            }
            div { class: "workflow-form onboarding-confirmation",
                Label { html_for: "setup-recovery-key", "Recovery Key" }
                Textarea {
                    id: "setup-recovery-key",
                    "data-testid": "setup-recovery-key",
                    rows: "4",
                    autocomplete: "off",
                    value: "{recovery_key}",
                    disabled: busy(),
                    placeholder: "Enter all 24 words",
                    oninput: move |event: FormEvent| recovery_key.set(event.value()),
                }
            }
            if !status().is_empty() {
                div {
                    class: if busy() { "muted" } else { "form-hint-warn" },
                    role: "status",
                    "aria-live": "polite",
                    "data-testid": "setup-status",
                    "{status}"
                }
            }
            div { class: "onboarding-footer-actions",
                DiscardSavedSetup { disabled: busy(), on_discard }
                Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "setup-submit",
                        disabled: busy() || recovery_key().trim().is_empty(),
                        onclick: move |_| {
                            let registration = registration.clone();
                            let supplied_key = recovery_key();
                            let base = base_url.clone();
                            let session = token();
                            let actor = account_did();
                            let device = device_id();
                            let resumes_before_binding = registration.stage
                                == crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed;
                            if !resumes_before_binding
                                && (actor != registration.did || device != registration.device_id)
                            {
                                status.set("This saved setup belongs to a different account or device.".to_owned());
                                return;
                            }
                            busy.set(true);
                            status.set("Finishing setup…".to_owned());
                            spawn(async move {
                                let result = if resumes_before_binding {
                                    let handoff = state_store.read().pending_account_handoff();
                                    match handoff {
                                        Some(handoff) => create_and_bind_identity(
                                            &handoff,
                                            &supplied_key,
                                            &registration.device_id,
                                            &base,
                                            config_store,
                                            state_store,
                                        )
                                        .await,
                                        None => Err(anyhow::anyhow!(
                                            "the account handoff is unavailable; sign in again"
                                        )),
                                    }
                                } else {
                                    finish_principal_setup(
                                        &registration,
                                        &supplied_key,
                                        &base,
                                        &session,
                                        &actor,
                                        &device,
                                        state_store,
                                    )
                                    .await
                                    .map(|_| (actor, device, session))
                                };
                                match result {
                                    Ok((completed_actor, completed_device, completed_session)) => {
                                        account_did.set(completed_actor);
                                        device_id.set(completed_device);
                                        token.set(completed_session);
                                        // The atomic registration call returned only after the
                                        // PCR create, founding-device authorize, and Seal were
                                        // durably accepted for this exact active signer. Publish
                                        // that state directly so KeyPackage creation cannot race
                                        // a stale pre-registration connect probe.
                                        needs_device_authorization.set(false);
                                        device_authorization_check_complete.set(true);
                                        recovery_key.set(String::new());
                                        status.set(String::new());
                                        complete.set(true);
                                        if let Err(error) = clear_pending_principal_setup(state_store).await {
                                            status.set(format!(
                                                "Setup finished, but local cleanup failed: {error}"
                                            ));
                                        }
                                    }
                                    Err(error) => {
                                        status.set(format!("Setup could not finish: {error}"));
                                    }
                                }
                                busy.set(false);
                            });
                        },
                        if busy() { "Finishing…" } else { "Continue" }
                }
            }
        }
    }
}

fn hosting_label(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .filter(|host| !host.trim().is_empty())
        .unwrap_or_else(|| "your selected service".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosting_label_hides_protocol_details() {
        assert_eq!(
            hosting_label("https://identity.example/path"),
            "identity.example"
        );
        assert_eq!(hosting_label("not a url"), "your selected service");
    }

    #[test]
    fn onboarding_uses_full_phrase_confirmation() {
        let key = crate::recovery_crypto::generate_recovery_key().unwrap();
        assert_eq!(
            recovery_key_confirmation_diff(&key, &key),
            RecoveryKeyConfirmationDiff::Match
        );
    }

    #[test]
    fn onboarding_recovery_download_uses_account_handle() {
        let handle = "alice:local.host".to_owned();
        assert_eq!(
            crate::components::mls_backup_prompt::recovery_key_filename_from_handles(
                std::slice::from_ref(&handle),
            ),
            "arkret-recovery-key-alice.txt"
        );
    }

    fn test_checkpoint(
        handoff: &crate::state::PendingAccountHandoff,
        recovery_key: &str,
        stage: crate::state::PendingPrincipalRegistrationStage,
    ) -> crate::state::PendingPrincipalRegistration {
        let mut checkpoint =
            crate::identity::principal_registration::prepare_registration_checkpoint(
                handoff,
                &handoff.device_id,
                recovery_key,
            )
            .unwrap();
        checkpoint.stage = stage;
        checkpoint
    }

    #[test]
    fn a_fresh_handoff_never_yields_the_surface_to_a_foreign_draft() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let previous_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let stale = test_checkpoint(
            &previous_handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
        );
        let mut new_account_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            Some("lease-2"),
            Some(2),
        );
        new_account_handoff.account_handle = "bob:auth.example".to_owned();

        // The newly authenticated account must reach its own Recovery Key
        // generation, not be asked for 24 words it never saw.
        assert_eq!(
            onboarding_surface(Some(&new_account_handoff), Some(&stale), false, ""),
            OnboardingSurface::IdentityCreation
        );
        // Even a live session for the stale draft's DID cannot outrank the
        // handoff that just authenticated someone else on this device.
        assert_eq!(
            onboarding_surface(Some(&new_account_handoff), Some(&stale), true, &stale.did),
            OnboardingSurface::IdentityCreation
        );
    }

    #[test]
    fn an_interrupted_creation_resumes_on_its_own_handoff() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
        );

        assert_eq!(
            onboarding_surface(Some(&handoff), Some(&checkpoint), false, ""),
            OnboardingSurface::ResumeSetup
        );
    }

    #[test]
    fn a_draft_that_never_bound_its_account_cannot_resume_without_its_handoff() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
        );

        // The lease and the handoff credential are what bind the account, so a
        // live session for this DID cannot stand in for the missing handoff.
        assert_eq!(
            onboarding_surface(None, Some(&checkpoint), true, &checkpoint.did),
            OnboardingSurface::StaleCheckpoint
        );
    }

    #[test]
    fn every_post_registration_phase_resumes_from_its_own_session_after_handoff_clear() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        for stage in [
            crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
            crate::state::PendingPrincipalRegistrationStage::Accepted,
            crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete,
        ] {
            let checkpoint = test_checkpoint(&handoff, &recovery_key, stage);

            // Signing back in to an already-bound account clears the handoff
            // (`OidcCallbackOutcome::Login`) but leaves setup
            // unfinished. This is also the shape of the joint-e2e flow that
            // injects only a checkpoint and then performs a real OIDC login:
            // routing it to the dead end stranded a live, resumable setup.
            assert_eq!(
                onboarding_surface(None, Some(&checkpoint), true, &checkpoint.did),
                OnboardingSurface::ResumeSetup
            );
            // No session, or another account's session: nothing here can
            // authenticate the remaining setup calls.
            assert_eq!(
                onboarding_surface(None, Some(&checkpoint), false, ""),
                OnboardingSurface::StaleCheckpoint
            );
            // A signed-out device that still remembers which account it was:
            // the DID matches, but there is no session to bootstrap with.
            assert_eq!(
                onboarding_surface(None, Some(&checkpoint), false, &checkpoint.did),
                OnboardingSurface::StaleCheckpoint
            );
            assert_eq!(
                onboarding_surface(
                    None,
                    Some(&checkpoint),
                    true,
                    "did:webvh:z6mkother:principal.example"
                ),
                OnboardingSurface::StaleCheckpoint
            );
        }
    }

    #[test]
    fn discarding_a_registered_binding_is_flagged_as_irreversible() {
        // The two warnings are trivially easy to swap, and swapping them tells
        // a user that throwing away the only copy of a registered identity's
        // setup costs nothing.
        assert!(discard_consequence(true).contains("cannot be undone"));
        assert!(discard_consequence(false).contains("Nothing has been registered"));
    }

    #[test]
    fn onboarding_without_a_draft_follows_the_handoff() {
        let handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );

        assert_eq!(
            onboarding_surface(Some(&handoff), None, false, ""),
            OnboardingSurface::IdentityCreation
        );
        assert_eq!(
            onboarding_surface(None, None, true, "did:webvh:z6mkfixture:principal.example"),
            OnboardingSurface::AccountSummary
        );
    }

    #[test]
    fn renewed_handoff_reuses_the_server_reserved_identity() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let old_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let mut checkpoint =
            crate::identity::principal_registration::prepare_registration_checkpoint(
                &old_handoff,
                &old_handoff.device_id,
                &recovery_key,
            )
            .unwrap();
        let did_operation: arkret_sdk::DidOperationSubmitRequestBody =
            serde_json::from_value(checkpoint.did_operation.clone()).unwrap();
        let reserved_identity =
            arkret_sdk::ReservedIdentityCreation::from_operation(did_operation).unwrap();
        checkpoint.account_handle.clear();
        let mut new_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            Some("lease-2"),
            Some(2),
        );
        new_handoff.reserved_identity = Some(serde_json::to_value(reserved_identity).unwrap());

        let resumed = checkpoint_for_handoff(&checkpoint, &new_handoff, &recovery_key).unwrap();

        assert_eq!(resumed.handoff_request_id, new_handoff.request_id);
        assert_eq!(resumed.lease_id, "lease-2");
        assert_eq!(resumed.lease_fence, 2);
        assert_eq!(resumed.did, checkpoint.did);
        assert_eq!(resumed.did_operation, checkpoint.did_operation);
    }

    #[test]
    fn renewed_handoff_fails_closed_on_a_different_reservation() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let old_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
            &old_handoff,
            &old_handoff.device_id,
            &recovery_key,
        )
        .unwrap();
        let other_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let other_checkpoint =
            crate::identity::principal_registration::prepare_registration_checkpoint(
                &old_handoff,
                &old_handoff.device_id,
                &other_key,
            )
            .unwrap();
        let other_operation: arkret_sdk::DidOperationSubmitRequestBody =
            serde_json::from_value(other_checkpoint.did_operation).unwrap();
        let mut new_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            Some("lease-2"),
            Some(2),
        );
        new_handoff.reserved_identity = Some(
            serde_json::to_value(
                arkret_sdk::ReservedIdentityCreation::from_operation(other_operation).unwrap(),
            )
            .unwrap(),
        );

        let error = checkpoint_for_handoff(&checkpoint, &new_handoff, &recovery_key).unwrap_err();
        assert!(error.to_string().contains("does not match the saved setup"));
    }

    /// A handle can be registered again — delete the account, or reset the
    /// Account Authority's store, and the same handle returns as a different
    /// identity. This used to reuse the abandoned draft, which is exactly how a
    /// fresh registration ended up being asked for 24 words belonging to a DID
    /// the server no longer had.
    #[test]
    fn a_re_registered_handle_does_not_inherit_the_abandoned_draft() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let old_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
            &old_handoff,
            &old_handoff.device_id,
            &recovery_key,
        )
        .unwrap();
        // Same handle, new registration, and the server reserved nothing.
        let re_registration = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            Some("lease-2"),
            Some(2),
        );
        assert!(re_registration.reserved_identity.is_none());

        let error =
            checkpoint_for_handoff(&checkpoint, &re_registration, &recovery_key).unwrap_err();
        assert!(
            error.to_string().contains("an earlier registration"),
            "a re-registration must be told the draft is stale, not that it is someone \
             else's account: {error}"
        );
    }

    #[test]
    fn renewed_handoff_does_not_treat_account_handle_as_identity_evidence() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let old_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
            &old_handoff,
            &old_handoff.device_id,
            &recovery_key,
        )
        .unwrap();
        let mut new_account_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            Some("lease-2"),
            Some(2),
        );
        new_account_handoff.account_handle = "bob:auth.example".to_owned();
        let operation: arkret_sdk::DidOperationSubmitRequestBody =
            serde_json::from_value(checkpoint.did_operation.clone()).unwrap();
        new_account_handoff.reserved_identity = Some(
            serde_json::to_value(
                arkret_sdk::ReservedIdentityCreation::from_operation(operation).unwrap(),
            )
            .unwrap(),
        );

        let resumed =
            checkpoint_for_handoff(&checkpoint, &new_account_handoff, &recovery_key).unwrap();

        assert_eq!(resumed.did, checkpoint.did);
        assert_eq!(resumed.did_operation, checkpoint.did_operation);
        assert_eq!(resumed.account_handle, checkpoint.account_handle);
    }

    fn test_handoff(
        request_id: &str,
        lease_id: Option<&str>,
        lease_fence: Option<u64>,
    ) -> crate::state::PendingAccountHandoff {
        crate::state::PendingAccountHandoff {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            request_id: request_id.to_owned(),
            account_handle: "alice:auth.example".to_owned(),
            account_subject: Some(
                arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
            holder_jkt: "holder-jkt".to_owned(),
            audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            lease_id: lease_id.map(ToOwned::to_owned),
            lease_fence,
            lease_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
            reserved_identity: None,
            retry_after_ms: None,
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            // `ak:trust_domain:<scope>` — the hyphenated spelling stopped
            // parsing as an Arkret identifier and failed every test built on
            // this fixture inside `prepare_registration_checkpoint`.
            trust_domain: "ak:trust_domain:auth.example".to_owned(),
            bound_principal_id: None,
        }
    }
}
