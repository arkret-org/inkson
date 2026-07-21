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

#[component]
pub fn OnboardingPanel(
    secure_store_ready: bool,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    account_primary_handle: Signal<String>,
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
    // Checkpoints are routing inputs only when this surface mounts. Do not
    // subscribe the parent to every durable stage write: an uninterrupted
    // child flow keeps the Recovery Key in memory and must remain mounted while
    // its background bootstrap advances. A real remount (reload/restart) reads
    // the latest checkpoint and intentionally enters the resume surface.
    let (pending_handoff, pending_registration) = {
        let store = state_store.peek();
        (
            store.pending_account_handoff(),
            store.pending_principal_registration(),
        )
    };

    if pending_registration.is_some() {
        return rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                PendingPrincipalBootstrap {
                    token,
                    account_did,
                    device_id,
                    config_store,
                    account_primary_handle,
                }
            }
        };
    }

    if pending_handoff.is_some() {
        return rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                PendingAccountIdentityCreation {
                    token,
                    account_did,
                    device_id,
                    config_store,
                    account_primary_handle,
                }
            }
        };
    }

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
                                        account_primary_handle.set(handoff.account_handle.clone());
                                        account_did.set(actor);
                                        device_id.set(device);
                                        token.set(grant);
                                        recovery_key.set(String::new());
                                        confirmation.set(String::new());
                                        status.set(String::new());
                                        complete.set(true);
                                        if let Err(error) = clear_completed_principal_setup(state_store).await {
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
        Some(checkpoint) => {
            let checkpoint = checkpoint_for_handoff(checkpoint, handoff, recovery_key)?;
            let changed = stored_checkpoint.as_ref() != Some(&checkpoint);
            (checkpoint, changed)
        }
        None => (
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

async fn clear_completed_principal_setup(
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
        crate::identity::principal_registration::validate_checkpoint_recovery_key(
            checkpoint,
            recovery_key,
        )?;
        return Ok(checkpoint.clone());
    }
    if checkpoint.stage != crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed {
        anyhow::bail!("a different identity setup is already pending");
    }
    let (Some(lease_id), Some(lease_fence)) = (&handoff.lease_id, handoff.lease_fence) else {
        anyhow::bail!("the renewed identity-creation lease is unavailable");
    };

    if checkpoint.principal_server_url != handoff.principal_server_url
        || checkpoint.gate_account_base != handoff.gate_account_base
        || checkpoint.device_id != handoff.device_id
        || checkpoint.enrollment_authority_did != handoff.enrollment_authority_did
        || checkpoint.trust_domain != handoff.trust_domain
    {
        anyhow::bail!("the server's reserved identity belongs to a different setup context");
    }
    // A renewed lease carries forward any identity operation that the server
    // already reserved. Recovery must replay that exact public operation; a
    // newly-derived draft would correctly be rejected as a duplicate conflict.
    // Older Inkson versions did not persist this field, so its absence is not
    // evidence that the server has no reservation. Reusing the local operation
    // is safe in both cases: it either matches the reservation or becomes it.
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
    mut account_primary_handle: Signal<String>,
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

    rsx! {
        div { class: "event onboarding-card", "data-testid": "pending-principal-bootstrap",
            SetupProgress { current: 2 }
            div { class: "onboarding-heading",
                span { class: "eyebrow", "Continue setup" }
                h2 { "Enter your Recovery Key" }
                p { class: "muted", "Use the same 24 words you saved for {did_label}." }
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
            div { class: "onboarding-footer-actions is-end",
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
                                        .await
                                        .map(|completed| (completed, Some(handoff.account_handle))),
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
                                    .map(|_| ((actor, device, session), None))
                                };
                                match result {
                                    Ok(((completed_actor, completed_device, completed_session), handle)) => {
                                        if let Some(handle) = handle {
                                            account_primary_handle.set(handle);
                                        }
                                        account_did.set(completed_actor);
                                        device_id.set(completed_device);
                                        token.set(completed_session);
                                        recovery_key.set(String::new());
                                        status.set(String::new());
                                        complete.set(true);
                                        if let Err(error) = clear_completed_principal_setup(state_store).await {
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

    #[test]
    fn renewed_handoff_reuses_the_server_reserved_identity() {
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
        let did_operation: arkret_sdk::DidOperationSubmitRequestBody =
            serde_json::from_value(checkpoint.did_operation.clone()).unwrap();
        let reserved_identity =
            arkret_sdk::ReservedIdentityCreation::from_operation(did_operation).unwrap();
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
        assert_eq!(
            resumed.bootstrap_create_event_id,
            checkpoint.bootstrap_create_event_id
        );
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

    #[test]
    fn renewed_handoff_reuses_a_legacy_checkpoint_without_a_saved_reservation() {
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
        let new_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            Some("lease-2"),
            Some(2),
        );

        let legacy_resumed =
            checkpoint_for_handoff(&checkpoint, &new_handoff, &recovery_key).unwrap();
        assert_eq!(legacy_resumed.did_operation, checkpoint.did_operation);
        assert_eq!(legacy_resumed.handoff_request_id, new_handoff.request_id);
        assert_eq!(legacy_resumed.lease_id, "lease-2");
        assert_eq!(legacy_resumed.lease_fence, 2);
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
            trust_domain: "ak:trust-domain:test".to_owned(),
        }
    }
}
