//! The sign-in panel's two writes, out of the `rsx!` and named.
//!
//! Opening server sign-in is a two-hundred-line command that reaches the
//! secure key store, the OIDC authorization endpoint and the durable state
//! store. It used to live inside the closure the button calls, so nothing
//! about it was reachable without mounting `LoginPanel`.

use super::*;

/// Signals the sign-in panel's writes fold their outcome back into.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct LoginController {
    pub(super) is_busy: Signal<bool>,
    pub(super) auth_status: Signal<String>,
}

impl LoginController {
    /// Open server sign-in for `principal`.
    ///
    /// The click already resolved which account is returning and set the
    /// in-progress status; everything from here is network and durable state.
    pub(super) fn launch_sign_in(
        self,
        principal: String,
        ui_locale: String,
        returning_principal: Option<arkret_sdk::Did>,
        persisted_account: Option<crate::config::ActiveAccountContext>,
        reset_state_store: SyncSignal<crate::state::LocalStateStore>,
        session: crate::runtime::session::SessionCoordinator,
    ) {
        let Self {
            mut is_busy,
            mut auth_status,
            ..
        } = self;
        let mut reset_state_store = reset_state_store;
        spawn(async move {
            #[cfg(target_arch = "wasm32")]
            if let Err(error) =
                crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await
            {
                tracing::warn!(%error, "secure store unavailable before sign-in");
                is_busy.set(false);
                auth_status.set(format!(
                    "Could not open browser secure storage for sign-in: {error}. Close other Inkson tabs and try again."
                ));
                return;
            }
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let returning_device = if let Some(expected) = persisted_account.as_ref() {
                match returning_device_id(secure_store.as_ref(), expected) {
                    Ok(device) => device,
                    Err(error) => {
                        is_busy.set(false);
                        auth_status.set(error);
                        return;
                    }
                }
            } else {
                None
            };
            let (pending_handoff, pending_checkpoint) = {
                let store = reset_state_store.read();
                (
                    store.pending_account_handoff(),
                    store.pending_principal_registration(),
                )
            };
            let checkpoint_disposition = pending_checkpoint.as_ref().map(|checkpoint| {
                crate::identity::account_auth::registration_checkpoint_disposition(
                    checkpoint,
                    pending_handoff.as_ref(),
                    Utc::now(),
                )
            });
            if checkpoint_disposition
                == Some(garth::RegistrationCheckpointDisposition::DiscardStale)
                && let Some(checkpoint) = pending_checkpoint.as_ref()
            {
                if let Err(error) =
                    crate::identity::account_auth::clear_prepared_identity_creation_request_for_checkpoint(
                        checkpoint,
                    )
                {
                    tracing::warn!(%error, "clear stale identity-creation request artifact failed");
                }
                if let Err(error) = reset_state_store
                    .write()
                    .set_pending_principal_registration(None)
                {
                    tracing::warn!(%error, "prune stale identity-creation checkpoint failed");
                }
            }
            record_registration_checkpoint_disposition(
                pending_handoff.as_ref(),
                checkpoint_disposition,
            );
            let pending_device = pending_handoff
                .as_ref()
                .map(|handoff| handoff.device_id.clone())
                .or_else(|| {
                    reset_state_store
                        .read()
                        .pending_login()
                        .map(|pending| pending.device_id.to_string())
                })
                .filter(|device| crate::config::is_valid_device_id(device));
            let resume_account_handoff = if let Some(pending_device) = pending_device.as_deref() {
                let mut store = reset_state_store.write();
                recover_pending_handoff_for_sign_in(
                    &mut store,
                    secure_store.as_ref(),
                    pending_device,
                )
            } else {
                false
            };
            let pending_pairing_candidate = if resume_account_handoff {
                match pending_handoff
                    .as_ref()
                    .map(|handoff| pending_pairing_for_handoff(secure_store.as_ref(), handoff))
                {
                    Some(Ok(candidate)) => candidate,
                    Some(Err(error)) => {
                        is_busy.set(false);
                        auth_status.set(error);
                        return;
                    }
                    None => None,
                }
            } else {
                None
            };
            #[allow(clippy::expect_used)]
            let device = if resume_account_handoff {
                pending_device.expect("resumable handoff has a device id")
            } else {
                crate::config::new_device_id()
            };
            let pending_device_id = match arkret_sdk::DeviceId::new(device.clone()) {
                Ok(device_id) => device_id,
                Err(error) => {
                    is_busy.set(false);
                    auth_status.set(format!("The generated device id is invalid: {error}"));
                    return;
                }
            };
            // Only a checkpoint this exact transaction can still finish owns
            // the authentication. A stale, terminal, fenced-out or foreign
            // draft never suppresses the returning candidate: the old
            // account/device is carried as a candidate and compared against
            // the Bound handoff returned by the Account Authority.
            #[allow(clippy::expect_used)]
            let (expected_principal, expected_device) = if checkpoint_disposition
                == Some(garth::RegistrationCheckpointDisposition::ContinuesIdentityCreation)
            {
                (None, None)
            } else if let Some(pairing) = pending_pairing_candidate {
                (Some(pairing.principal_did), Some(pairing.device_id))
            } else {
                (
                    returning_principal,
                    returning_device.map(|device| {
                        arkret_sdk::DeviceId::new(device)
                            .expect("secure-store device id was validated when loaded")
                    }),
                )
            };
            let pending_store =
                crate::secure_key_store::PendingLocalStore::new(pending_device_id.clone());
            if !resume_account_handoff {
                if let Err(error) =
                    crate::identity::device_pairing::clear_pending_device_pairing_verification(
                        &pending_store,
                        secure_store.as_ref(),
                    )
                {
                    is_busy.set(false);
                    auth_status.set(format!(
                        "Could not clear the previous pending device pairing: {error}"
                    ));
                    return;
                }
                if let Err(error) = pending_store.delete(secure_store.as_ref()) {
                    is_busy.set(false);
                    auth_status.set(format!("Could not rotate the pending sign-in key: {error}"));
                    return;
                }
            }
            if let Err(error) = pending_store
                .save_device_id_durable(secure_store.as_ref())
                .await
            {
                is_busy.set(false);
                auth_status.set(format!(
                    "Could not durably prepare the pending sign-in device: {error}"
                ));
                return;
            }
            let prepared_authorization = match prepare_oidc_authorization(
                &principal,
                device.trim(),
                OidcEntryPoint::SignIn,
                expected_principal.as_ref(),
                expected_device.as_ref(),
                &ui_locale,
            )
            .await
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    is_busy.set(false);
                    auth_status.set(error);
                    return;
                }
            };

            // Invalidation synchronously unmounts this route and pushes Login.
            // Complete the pending-scope transition in one no-await JS turn;
            // an URL-only detached task performs external navigation after it.
            if resume_account_handoff {
                // An unfinished identity-creation lease is fenced to this DPoP
                // holder. Rotating the key here makes the same browser look like
                // another device and leaves it stuck behind its own lease until
                // expiry. Re-authentication for this one resumable flow is a
                // soft continuation, so retain the holder key.
                crate::secure_key_store::set_active_device_seed_scope(None);
                let resumed = reset_state_store
                    .write()
                    .resume_pending_login(&pending_device_id);
                debug_assert!(resumed, "validated handoff resume must remain valid");
            } else {
                // Pre-DID: keep all bootstrap material in the transaction's
                // `pending.<device_id>` namespace until accepted-context
                // promotion re-homes it under the resolved principal.
                reset_state_store
                    .write()
                    .begin_pending_login(&pending_device_id, None);
                if let Err(error) = crate::secure_key_store::reset_device_seed_scope_for_signin(
                    secure_store.as_ref(),
                    &pending_device_id,
                ) {
                    tracing::warn!(%error, "reset device seed scope for sign-in failed");
                }
                reset_state_store.write().set_dpop_device_key(None);
            }
            pending_store.activate();
            prepared_authorization.launch_detached();
            session.invalidate("starting an account sign-in transaction");
        });
    }

    /// Refresh the current session credential on demand.
    pub(super) fn refresh_session(
        self,
        session: crate::runtime::session::SessionCoordinator,
        mut token: Signal<String>,
        on_login: EventHandler<()>,
    ) {
        let Self {
            mut is_busy,
            mut auth_status,
            ..
        } = self;
        spawn(async move {
            match session.refresh().await {
                crate::runtime::session::CurrentSessionRefresh::Credential(session_credential) => {
                    token.set(session_credential);
                    auth_status.set("Session restored".to_owned());
                    on_login.call(());
                }
                crate::runtime::session::CurrentSessionRefresh::SignInRequired { reason } => {
                    auth_status.set(format!("Sign in required: {reason}"));
                }
                crate::runtime::session::CurrentSessionRefresh::LoginRequired { reason } => {
                    auth_status.set(format!("Session could not be restored: {reason}"));
                }
                crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
                    auth_status.set(format!("Session refresh pending: {reason}"));
                }
            }
            is_busy.set(false);
        });
    }
}
