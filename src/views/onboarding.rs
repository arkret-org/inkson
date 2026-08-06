//! Account-first identity setup.
//!
//! The user-facing flow intentionally hides the handoff lease, DID inception,
//! PCR bootstrap, and recovery-material gate. Those protocol stages remain
//! durable and resumable, but the page presents only three user decisions:
//! choose an identity, save its Recovery Key, and finish.

use dioxus::prelude::*;
use dioxus_router::Link;

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
    /// Finish a durable identity draft that is still completable from here.
    ResumeBootstrap,
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
/// DID, which is what the remaining bootstrap calls authenticate with. A
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
        return if handoff.is_some() {
            OnboardingSurface::IdentityCreation
        } else {
            OnboardingSurface::AccountSummary
        };
    };

    if let Some(handoff) = handoff {
        return if crate::identity::principal_registration::checkpoint_belongs_to_handoff(
            checkpoint, handoff,
        ) {
            OnboardingSurface::ResumeBootstrap
        } else {
            OnboardingSurface::IdentityCreation
        };
    }

    let binding_registered =
        checkpoint.stage != crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed;
    let holds_this_identity_session =
        session_token_present && active_account_did == checkpoint.did;
    if binding_registered && holds_this_identity_session {
        OnboardingSurface::ResumeBootstrap
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
    // `create_bind_and_bootstrap_identity` persisted its first checkpoint —
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
        OnboardingSurface::ResumeBootstrap => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                PendingPrincipalBootstrap {
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
    let state_store = crate::app::SessionContext::get().state_store;
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

    rsx! {
        div { class: "event onboarding-card", "data-testid": "account-handoff-onboarding",
            SetupProgress { current: current_step }

            if choice() == IdentityChoice::Choose {
                div { class: "onboarding-heading",
                    span { class: "eyebrow", "Step 1" }
                    h2 { "Choose your identity" }
                    p { class: "muted", "Link this account to a new identity or one you already control." }
                }

                div { class: "identity-choice-grid", role: "group", "aria-label": "Identity choice",
                    section { class: "identity-choice-card is-recommended",
                        span { class: "badge accent", "Recommended" }
                        h3 { "Create a new identity" }
                        p { "Inkson creates it on this device and hosts it with {hosting_name}." }
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
                            "Create new identity"
                        }
                    }

                    section { class: "identity-choice-card",
                        h3 { "Use an existing DID" }
                        p { "Approve the link from a device or DID wallet that already controls it." }
                        Button {
                            variant: ButtonVariant::Secondary,
                            disabled: true,
                            title: "This Account Authority does not advertise existing-DID approval yet.",
                            "data-testid": "choose-existing-identity",
                            "Not available on this server"
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

                            let handoff = handoff.clone();
                            let supplied_key = recovery_key();
                            let device = handoff.device_id.clone();
                            let base = handoff.principal_server_url.clone();
                            busy.set(true);
                            status.set("Finishing setup…".to_owned());
                            spawn(async move {
                                let result = create_bind_and_bootstrap_identity(
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

async fn create_bind_and_bootstrap_identity(
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
        Some(_) | None => (
            crate::identity::principal_registration::prepare_registration_checkpoint(
                handoff,
                device,
                recovery_key,
            )?,
            true,
        ),
    };
    if checkpoint_changed {
        let barrier = {
            let mut store = state_store.write();
            store.set_pending_principal_registration(Some(checkpoint.clone()))?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }

    let (registration, actor, grant_jwt) = if checkpoint.stage
        == crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed
    {
        let dpop = {
            let mut store = state_store.write();
            crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
        };
        let completion = crate::identity::principal_registration::complete_account_handoff_binding(
            handoff,
            &checkpoint,
            recovery_key,
            &dpop,
        )
        .await?;
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
        accepted.stage = crate::state::PendingPrincipalRegistrationStage::BindingRegistered;
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
        // A previous attempt completed the one-shot account binding but
        // failed later. Retry only the resumable bootstrap; re-registering
        // the already-bound DID would consume the handoff twice.
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
    // this device already holds. Each way that can fail gets its own message,
    // because the surface shows these to the person trying to finish setup and
    // "wrong account" and "wrong identity" call for different actions.
    if !checkpoint.account_handle.trim().is_empty()
        && checkpoint.account_handle != handoff.account_handle
    {
        anyhow::bail!("the saved identity setup belongs to a different service account");
    }
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
    // Older Inkson versions did not persist this field, so its absence is not
    // evidence that the server has no reservation; in that case the account
    // handle continuity check above still has to prove ownership.
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
) -> anyhow::Result<String> {
    crate::identity::principal_registration::validate_checkpoint_recovery_key(
        registration,
        recovery_key,
    )?;

    if registration.stage == crate::state::PendingPrincipalRegistrationStage::BindingRegistered {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("device signer is unavailable"))?;
        let signer = crate::event_signer::bind_active_signer_device_id(device)?.unwrap_or(signer);
        let device_public_key = signer
            .public_key_multibase()
            .ok_or_else(|| anyhow::anyhow!("device signer has no Ed25519 public key"))?;
        let hpke_key = {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let (_, public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair(
                secure_store.as_ref(),
                actor,
                device,
            )?;
            crate::identity::did_key::encode_x25519_multibase(&public_key)
        };
        let dpop = {
            let mut store = state_store.write();
            crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
        };
        let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
            &registration.gate_account_base,
        )?;
        let account_client = arkret_sdk::http_client::ClientBuilder::new(account_base)
            .allow_insecure_localhost()
            .auth(arkret_sdk::http_client::Auth::Dpop(
                dpop.sdk_dpop_auth_for_access_token(session.to_owned()),
            ))
            .build()?;
        let bootstrap_registration = registration.clone();
        let bootstrap_key = recovery_key.to_owned();
        crate::transport::auth::with_authed_sdk_client(
            base_url,
            session.to_owned(),
            |principal_client| async move {
                crate::identity::principal_registration::bootstrap_principal(
                    &bootstrap_registration,
                    &bootstrap_key,
                    device_public_key,
                    hpke_key,
                    signer.as_ref(),
                    &account_client,
                    &principal_client,
                )
                .await
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;

        let mut accepted = registration.clone();
        accepted.stage = crate::state::PendingPrincipalRegistrationStage::BootstrapAccepted;
        let barrier = {
            let mut store = state_store.write();
            store.set_pending_principal_registration(Some(accepted))?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }

    let recovery_actor = actor.to_owned();
    let recovery_device = device.to_owned();
    let recovery_key_value = recovery_key.to_owned();
    let backup_id =
        crate::transport::auth::with_authed_api(base_url, session.to_owned(), |api| async move {
            crate::recovery_strand::ensure_recovery_policy_and_did_recovery_backup(
                &api,
                &recovery_actor,
                &recovery_device,
                &recovery_key_value,
            )
            .await
        })
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;
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
    Ok(backup_id)
}

#[component]
fn PendingPrincipalBootstrap(
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
            div { class: "event onboarding-card", "data-testid": "pending-principal-bootstrap",
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
        div { class: "event onboarding-card", "data-testid": "pending-principal-bootstrap",
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
                Label { html_for: "bootstrap-recovery-key", "Recovery Key" }
                Textarea {
                    id: "bootstrap-recovery-key",
                    "data-testid": "bootstrap-recovery-key",
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
                    "data-testid": "bootstrap-status",
                    "{status}"
                }
            }
            div { class: "onboarding-footer-actions",
                DiscardSavedSetup { disabled: busy(), on_discard }
                Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "bootstrap-submit",
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
                                        Some(handoff) => create_bind_and_bootstrap_identity(
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
                                        // The atomic bootstrap call returned only after the
                                        // PCR create, founding-device authorize, and Seal were
                                        // durably accepted for this exact active signer. Publish
                                        // that state directly so KeyPackage creation cannot race
                                        // a stale pre-bootstrap connect probe.
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
        let mut checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
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
            OnboardingSurface::ResumeBootstrap
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
    fn a_registered_binding_resumes_from_its_own_session_after_the_handoff_is_cleared() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        for stage in [
            crate::state::PendingPrincipalRegistrationStage::BindingRegistered,
            crate::state::PendingPrincipalRegistrationStage::BootstrapAccepted,
        ] {
            let checkpoint = test_checkpoint(&handoff, &recovery_key, stage);

            // Signing back in to an already-bound account clears the handoff
            // (`OidcCallbackOutcome::Login`) but leaves the bootstrap
            // unfinished. This is also the shape of the joint-e2e flow that
            // injects only a checkpoint and then performs a real OIDC login:
            // routing it to the dead end stranded a live, resumable setup.
            assert_eq!(
                onboarding_surface(None, Some(&checkpoint), true, &checkpoint.did),
                OnboardingSurface::ResumeBootstrap
            );
            // No session, or another account's session: nothing here can
            // authenticate the remaining bootstrap calls.
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
    fn renewed_handoff_rejects_checkpoint_from_a_different_account() {
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

        let error =
            checkpoint_for_handoff(&checkpoint, &new_account_handoff, &recovery_key).unwrap_err();

        assert!(error.to_string().contains("different service account"));
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
            holder_jkt: "holder-jkt".to_owned(),
            audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            lease_id: lease_id.map(ToOwned::to_owned),
            lease_fence,
            lease_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
            reserved_identity: None,
            retry_after_ms: None,
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            enrollment_authority_did: "did:key:z6MkrJVnaZkeFzdQyKjzgRHjhBfE6ZscXDFHq8T7TYNy9v1t"
                .to_owned(),
            // `ak:trust_domain:<scope>` — the hyphenated spelling stopped
            // parsing as an Arkret identifier and failed every test built on
            // this fixture inside `prepare_registration_checkpoint`.
            trust_domain: "ak:trust_domain:auth.example".to_owned(),
        }
    }
}
