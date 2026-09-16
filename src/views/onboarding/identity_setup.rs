//! Identity creation, principal setup and the checkpoints between them.
//!
//! These are the durable protocol stages the panel deliberately hides: the
//! handoff lease, DID inception, PCR genesis and the recovery-material gate.
//! Each is a resumable command, none of them touches `rsx!`, and every one was
//! previously only reachable by mounting `PendingAccountIdentityCreation`.

use super::*;

pub(super) async fn activate_pending_registration_signer(
    checkpoint: &crate::state::PendingPrincipalRegistration,
    device: &str,
    pending_store: &crate::secure_key_store::PendingLocalStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<std::sync::Arc<crate::event_signer::InksonEventSigner>> {
    let signing_material =
        if checkpoint.stage == crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed {
            pending_store
                .create_fresh_signing_seed_durable(secure_store)
                .await?
        } else {
            pending_store
                .load_signing_seed(secure_store)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "prepared registration checkpoint has no durable pending device signer"
                    )
                })?
        };
    let signer = crate::event_signer::activate_device_signer_from_seed_for_device(
        signing_material.seed,
        None,
        Some(device),
    )?;
    let principal_did = checkpoint.did.clone();
    Ok(
        crate::event_signer::bind_active_signer_principal_device_id(&principal_did, device)?
            .unwrap_or(signer),
    )
}

pub(super) async fn create_and_bind_identity(
    handoff: &crate::state::PendingAccountHandoff,
    recovery_key: &str,
    device: &str,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    mut status: Signal<String>,
) -> anyhow::Result<IdentityCreationCommandOutcome> {
    let pending_device_id = arkret_sdk::DeviceId::new(device.to_owned())?;
    let pending_store = crate::secure_key_store::PendingLocalStore::new(pending_device_id);
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    // Keep the handoff panel mounted while the durable registration advances.
    // The checkpoint deliberately contains no Recovery Key, but this component
    // still has the user-confirmed key in memory. Switching to the generic
    // resume panel here made a successful, uninterrupted setup appear to ask
    // for the same 24 words twice.
    let stored_checkpoint = state_store.read().pending_principal_registration();
    let (checkpoint, checkpoint_changed) = match stored_checkpoint.as_ref() {
        Some(checkpoint)
            if (crate::identity::principal_registration::checkpoint_belongs_to_handoff(
                checkpoint, handoff,
            ) && checkpoint.device_id == device
                && checkpoint.handoff_request_id == handoff.request_id)
                || crate::identity::account_auth::checkpoint_continues_bound_creation(
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

    let checkpoint = if matches!(
        checkpoint.stage,
        crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed
            | crate::state::PendingPrincipalRegistrationStage::GenesisDraftPrepared
            | crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared
    ) {
        // Every pre-register re-entry must restore the exact pending signer
        // before validating or submitting the durable draft. A prepared
        // checkpoint can survive a reload or an uncertain register response,
        // while the process-wide signer cannot.
        let signer = activate_pending_registration_signer(
            &checkpoint,
            device,
            &pending_store,
            secure_store.as_ref(),
        )
        .await?;
        let device_public_key_multibase = signer
            .public_key_multibase()
            .ok_or_else(|| anyhow::anyhow!("device signer has no Ed25519 public key"))?;
        let device_public_key = format!("did:key:{device_public_key_multibase}");
        let hpke_key = {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let authority = arkret_sdk::AccountId::new(
                arkret_sdk::project_did_to_core_id(&checkpoint.did)?,
                handoff.audience_id.clone(),
            );
            let device_id = arkret_sdk::DeviceId::new(device.to_owned())?;
            let (_, public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair_durable(
                secure_store.as_ref(),
                &authority,
                &device_id,
            )
            .await?;
            crate::identity::did_key::encode_x25519_multibase(&public_key)
        };
        let (dpop, dpop_record) = crate::identity::account_auth::grant_dpop::prepare_pending_device_key_with_secure_store_durable(
            secure_store.as_ref(),
            &pending_store,
        )
        .await?;
        state_store
            .write()
            .set_pending_dpop_device_key_with_secure_store(
                Some(dpop_record),
                secure_store.as_ref(),
                &pending_store,
            )?;
        let prepared = crate::identity::principal_registration::prepare_genesis_draft(
            &checkpoint,
            recovery_key,
            device_public_key,
            hpke_key,
            signer.as_ref(),
            &dpop,
            handoff.audience_id.clone(),
        )?;
        if prepared != checkpoint {
            let barrier = {
                let mut store = state_store.write();
                store.set_pending_principal_registration(Some(prepared.clone()))?;
                store.begin_durable_flush()?
            };
            barrier.wait().await?;
        }
        prepared
    } else {
        checkpoint
    };

    let (registration, completed) = if matches!(
        checkpoint.stage,
        crate::state::PendingPrincipalRegistrationStage::GenesisDraftPrepared
            | crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared
    ) {
        let (dpop, dpop_record) = crate::identity::account_auth::grant_dpop::prepare_pending_device_key_with_secure_store_durable(
            secure_store.as_ref(),
            &pending_store,
        )
        .await?;
        state_store
            .write()
            .set_pending_dpop_device_key_with_secure_store(
                Some(dpop_record),
                secure_store.as_ref(),
                &pending_store,
            )?;
        let completion =
            match crate::identity::principal_registration::complete_account_handoff_binding(
                handoff,
                &checkpoint,
                recovery_key,
                &dpop,
                &crate::app::runtime_adapter::state_store_handle(state_store),
                |delay| {
                    let seconds = delay.as_millis().div_ceil(1_000).max(1);
                    status.set(format!(
                        "The Account Authority asked this device to wait {seconds} seconds. Retrying automatically…"
                    ));
                },
            )
            .await
            {
                Ok(completion) => completion,
                Err(error) if crate::api_error::is_pcr_genesis_already_accepted_error(&error) => {
                    // Create-once lost the race. Persist the model switch before
                    // any network continuation, discard the losing genesis draft,
                    // and recover the replacement device against the accepted PCR.
                    let mut recovery_handoff = handoff.clone();
                    recovery_handoff.bound_principal_id =
                        Some(arkret_sdk::project_did_to_core_id(&checkpoint.did)?);
                    recovery_handoff.bound_principal_did = Some(checkpoint.did.clone());
                    {
                        let mut store = state_store.write();
                        store.set_pending_account_handoff(Some(recovery_handoff.clone()))?;
                        store.set_pending_principal_registration(None)?;
                        let barrier = store.begin_durable_flush()?;
                        drop(store);
                        barrier.wait().await?;
                    }
                    crate::identity::account_auth::clear_prepared_identity_creation_request_for_checkpoint(
                        &checkpoint,
                    )?;
                    let (_recovery, completed) = recover_bound_principal_device(
                        &recovery_handoff,
                        &checkpoint.did,
                        device,
                        recovery_key,
                        state_store,
                    )
                    .await?;
                    return Ok(IdentityCreationCommandOutcome::Completed(Box::new(completed)));
                }
                Err(error) => return Err(error),
            };
        let principal_did = checkpoint.did.clone();
        let principal_core_id = arkret_sdk::project_did_to_core_id(&principal_did)?;
        if completion.session_grant.account_id.principal_id != principal_core_id {
            anyhow::bail!("initial session grant principal does not match the registered identity");
        }
        let grant_jwt = completion.session_grant.grant_jwt.clone();
        let account = resolve_handoff_active_account(
            handoff,
            &principal_did,
            arkret_sdk::DeviceId::new(device.to_owned())?,
            state_store,
            Some((
                grant_jwt.clone(),
                crate::identity::account_auth::grant_dpop::device_handle_from_seed(
                    &completion.dpop_device_key.seed_b64,
                    &completion.dpop_device_key.jkt,
                )?,
            )),
        )
        .await?;
        let persisted_grant = crate::state::PersistedSessionGrant {
            grant_jwt: grant_jwt.clone(),
            session_private_key_pem: completion.session_private_key_pem,
            grant_id: completion.session_grant.grant_id.to_string(),
            audience_id: completion.session_grant.audience_id.clone(),
            granted_scope: completion.session_grant.granted_scope.clone(),
            account_id: completion.session_grant.account_id.clone(),
            device_id: arkret_sdk::DeviceId::new(device.to_owned())?,
            station_url: url::Url::parse(&handoff.station_url)?,
            grant_expires_at: Some(completion.session_grant.expires_at),
            stored_at: chrono::Utc::now(),
        };
        let dpop_device_key = completion.dpop_device_key.clone();
        let mut accepted = checkpoint;
        accepted.binding_receipt = Some(completion.binding_receipt.clone());
        accepted.pcr_genesis_receipt = Some(completion.pcr_genesis_receipt.clone());
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
            let prepared_keys = crate::views::login::prepare_completed_login_dpop_key(
                secure_store.as_ref(),
                &account,
                device,
                &completion.dpop_device_key,
            )
            .await
            .map_err(anyhow::Error::msg)?;
            let account_store = crate::secure_key_store::UserLocalStore::new(
                account.authority.clone(),
                account.device_id.clone(),
            )?;
            crate::state::store_session_grant_in_user_secure_store_durable(
                &account_store,
                secure_store.as_ref(),
                &persisted_grant,
            )
            .await?;
            let mut store = state_store.write();
            crate::views::login::commit_completed_login_dpop_key(
                &mut store,
                secure_store.as_ref(),
                &account,
                &completion.dpop_device_key,
                prepared_keys,
            )
            .map_err(anyhow::Error::msg)?;
            store.set_pending_principal_registration(Some(accepted.clone()))?;
            // Do not clear pending_account_handoff yet. Keeping it until
            // finish_principal_setup succeeds keeps this component (and its
            // in-memory Recovery Key) alive through the background work.
            let barrier = store.begin_durable_flush()?;
            drop(store);
            barrier.wait().await?;
        }
        (
            accepted,
            CompletedIdentityCreation {
                account,
                persisted_grant,
                dpop_device_key,
                origin:
                    crate::identity::account_auth::transition::OnboardingCompletionOrigin::FreshBind,
                initial_mls_backup_id: None,
            },
        )
    } else {
        // Registration already returned a verified PCR receipt. Rebuild the
        // continuation from server truth plus a closed durable inventory;
        // exact restoration is only the fast path.
        let account = resolve_handoff_active_account(
            handoff,
            &checkpoint.did,
            arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?,
            state_store,
            None,
        )
        .await?;
        let inventory =
            collect_bound_completion_resume_inventory(handoff, &checkpoint, &account, state_store)
                .await;
        let correlation =
            crate::identity::account_auth::transition::LoginCorrelation::for_handoff(handoff)
                .with_principal_id(account.principal_id().clone())
                .with_device_id(account.device_id.as_str());
        let disposition = match garth::classify_bound_completion_resume(inventory.facts) {
            Ok(disposition) => disposition,
            Err(error) => {
                crate::identity::account_auth::transition::record_onboarding_completion_transition(
                    crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeRestore,
                    crate::identity::account_auth::transition::OnboardingCompletionOutcome::RetryableHydration,
                    "resume_material_read_error",
                    &correlation,
                    Some(&inventory.facts),
                );
                let detail = if inventory.read_errors.is_empty() {
                    format!("could not read resume material {:?}", error.material)
                } else {
                    inventory.read_errors.join("; ")
                };
                return Ok(IdentityCreationCommandOutcome::Terminal(ResumeTerminal {
                    kind: ResumeTerminalKind::HydrationFailed,
                    reason: detail,
                    inventory: inventory.checklist(),
                }));
            }
        };
        use garth::BoundCompletionResumeDisposition as Disposition;
        match disposition {
            Disposition::RestoreRuntime => {
                crate::identity::account_auth::transition::record_onboarding_completion_transition(
                    crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeRestore,
                    crate::identity::account_auth::transition::OnboardingCompletionOutcome::Classified,
                    "restore_runtime",
                    &correlation,
                    Some(&inventory.facts),
                );
                let restored = restore_accepted_account_runtime(&account, &handoff.holder_jkt)
                    .context("restore the accepted onboarding session")?;
                (
                    checkpoint.clone(),
                    CompletedIdentityCreation {
                        account,
                        persisted_grant: restored.persisted_grant,
                        dpop_device_key: restored.dpop_device_key,
                        origin: crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeRestore,
                        initial_mls_backup_id: None,
                    },
                )
            }
            Disposition::ReissueGrant => {
                crate::identity::account_auth::transition::record_onboarding_completion_transition(
                    crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeReissue,
                    crate::identity::account_auth::transition::OnboardingCompletionOutcome::Classified,
                    "reissue_grant",
                    &correlation,
                    Some(&inventory.facts),
                );
                let completed = match reissue_accepted_onboarding_session(
                    handoff,
                    &account,
                    state_store,
                )
                .await
                {
                    Ok(completed) => completed,
                    Err(AcceptedSessionReissueError::Retryable(error)) => {
                        crate::identity::account_auth::transition::record_onboarding_completion_transition(
                            crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeReissue,
                            crate::identity::account_auth::transition::OnboardingCompletionOutcome::RetryableHydration,
                            "session_reissue_retryable",
                            &correlation,
                            Some(&inventory.facts),
                        );
                        return Ok(IdentityCreationCommandOutcome::Terminal(ResumeTerminal {
                            kind: ResumeTerminalKind::RetryableFailure,
                            reason: format!("Reissue the accepted onboarding session: {error:#}"),
                            inventory: inventory.checklist(),
                        }));
                    }
                    Err(AcceptedSessionReissueError::ReauthRequired(error)) => {
                        crate::identity::account_auth::transition::record_onboarding_completion_transition(
                            crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeReissue,
                            crate::identity::account_auth::transition::OnboardingCompletionOutcome::ReauthRequired,
                            "session_reissue_holder_unavailable",
                            &correlation,
                            Some(&inventory.facts),
                        );
                        return Ok(IdentityCreationCommandOutcome::Terminal(ResumeTerminal {
                            kind: ResumeTerminalKind::ReauthRequired,
                            reason: format!(
                                "A fresh sign-in is required before this accepted setup can continue: {error:#}"
                            ),
                            inventory: inventory.checklist(),
                        }));
                    }
                    Err(AcceptedSessionReissueError::Contradiction(error)) => {
                        crate::identity::account_auth::transition::record_onboarding_completion_transition(
                            crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeReissue,
                            crate::identity::account_auth::transition::OnboardingCompletionOutcome::Contradiction,
                            "session_reissue_contradiction",
                            &correlation,
                            Some(&inventory.facts),
                        );
                        return Ok(IdentityCreationCommandOutcome::Terminal(ResumeTerminal {
                            kind: ResumeTerminalKind::Contradiction,
                            reason: format!(
                                "The accepted setup cannot issue a session for the retained account and device: {error:#}"
                            ),
                            inventory: inventory.checklist(),
                        }));
                    }
                };
                (checkpoint.clone(), completed)
            }
            Disposition::RecoverWithPolicy => {
                crate::identity::account_auth::transition::record_onboarding_completion_transition(
                    crate::identity::account_auth::transition::OnboardingCompletionOrigin::RecoveryCompletion,
                    crate::identity::account_auth::transition::OnboardingCompletionOutcome::RecoveryRequired,
                    "recover_with_policy",
                    &correlation,
                    Some(&inventory.facts),
                );
                let (_, completed) = recover_bound_principal_device(
                    handoff,
                    &checkpoint.did,
                    device,
                    recovery_key,
                    state_store,
                )
                .await
                .context("recover the accepted device with its active policy")?;
                return Ok(IdentityCreationCommandOutcome::Completed(Box::new(
                    completed,
                )));
            }
            Disposition::StrandedIdentity => {
                crate::identity::account_auth::transition::record_onboarding_completion_transition(
                    crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeRestore,
                    crate::identity::account_auth::transition::OnboardingCompletionOutcome::Stranded,
                    "accepted_signer_and_recovery_policy_absent",
                    &correlation,
                    Some(&inventory.facts),
                );
                return Ok(IdentityCreationCommandOutcome::Terminal(ResumeTerminal {
                    kind: ResumeTerminalKind::StrandedIdentity,
                    reason: "The founding device key is not present on this device, and the server confirms that no Recovery Key policy was completed for this identity. The client API has no credential that can continue it.".to_owned(),
                    inventory: inventory.checklist(),
                }));
            }
            Disposition::ReauthRequired => {
                crate::identity::account_auth::transition::record_onboarding_completion_transition(
                    crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeReissue,
                    crate::identity::account_auth::transition::OnboardingCompletionOutcome::ReauthRequired,
                    "handoff_missing_or_expired",
                    &correlation,
                    Some(&inventory.facts),
                );
                return Ok(IdentityCreationCommandOutcome::Terminal(ResumeTerminal {
                    kind: ResumeTerminalKind::ReauthRequired,
                    reason: "The accepted setup no longer has a live account handoff. Sign in again to obtain a fresh handoff; the accepted identity and device checkpoint will be retained.".to_owned(),
                    inventory: inventory.checklist(),
                }));
            }
            Disposition::Contradiction { reason } => {
                crate::identity::account_auth::transition::record_onboarding_completion_transition(
                    crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeRestore,
                    crate::identity::account_auth::transition::OnboardingCompletionOutcome::Contradiction,
                    "resume_facts_contradict_checkpoint",
                    &correlation,
                    Some(&inventory.facts),
                );
                return Ok(IdentityCreationCommandOutcome::Terminal(ResumeTerminal {
                    kind: ResumeTerminalKind::Contradiction,
                    reason: format!(
                        "The accepted setup contradicts the retained account state: {reason:?}."
                    ),
                    inventory: inventory.checklist(),
                }));
            }
        }
    };

    let mut completed = completed;
    completed.initial_mls_backup_id = finish_principal_setup(
        &registration,
        recovery_key,
        &completed,
        &handoff.holder_jkt,
        state_store,
    )
    .await?;
    Ok(IdentityCreationCommandOutcome::Completed(Box::new(
        completed,
    )))
}

/// Drop the durable identity draft together with the handoff it is fenced to,
/// and the short-lived account handoff credential.
///
/// Shared by completion and by an explicit user discard. Both must clear the
/// handoff too: a draft is bound to one identity-creation lease, so a next
/// attempt has to re-authenticate for a fresh lease rather than reuse the one
/// this draft consumed.
pub(super) async fn clear_pending_principal_setup(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<()> {
    let pending_registration = state_store.read().pending_principal_registration();
    let pending_handoff = state_store.read().pending_account_handoff();
    let barrier = {
        let mut store = state_store.write();
        store.set_pending_principal_registration(None)?;
        store.set_pending_account_handoff(None)?;
        store.begin_durable_flush()?
    };
    barrier.wait().await?;
    if let Some(handoff) = pending_handoff.as_ref() {
        crate::identity::account_auth::clear_pending_identity_creation_recovery_key(handoff)?;
        crate::identity::account_auth::clear_account_handoff_grant(handoff)?;
    }
    if let Some(checkpoint) = pending_registration.as_ref() {
        crate::identity::account_auth::clear_prepared_identity_creation_request_for_checkpoint(
            checkpoint,
        )?;
    }
    Ok(())
}

pub(super) fn checkpoint_for_handoff(
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
    if crate::identity::account_auth::checkpoint_continues_bound_creation(checkpoint, handoff) {
        crate::identity::principal_registration::validate_checkpoint_recovery_key(
            checkpoint,
            recovery_key,
        )?;
        let mut renewed = checkpoint.clone();
        renewed.handoff_request_id = handoff.request_id.clone();
        return Ok(renewed);
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
            "the server's reserved identity does not match the local checkpoint; the original checkpoint is required"
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
        let expected_reservation = arkret_sdk::ReservedIdentityCreation::from_anchor(
            checkpoint.principal_registration_anchor.clone(),
        )
        .map_err(|error| anyhow::anyhow!("the saved registration anchor is invalid: {error}"))?;
        if expected_reservation != *reserved_identity {
            anyhow::bail!(
                "the server's reserved identity does not match the local checkpoint; the original checkpoint is required"
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryMaterialContinuation {
    SubmitAndPersist,
    FinalizeDurableEvidence,
}

#[derive(Debug)]
pub(super) struct BootstrapSealReplayContradiction;

impl std::fmt::Display for BootstrapSealReplayContradiction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the bootstrap Seal replay changed after its checkpoint was persisted")
    }
}

impl std::error::Error for BootstrapSealReplayContradiction {}

pub(super) fn validate_exact_bootstrap_seal_replay<T: serde::Serialize>(
    frozen: &T,
    replay: &T,
) -> anyhow::Result<()> {
    let frozen_bytes = serde_json::to_vec(frozen).context("encode the frozen bootstrap Seal")?;
    let replay_bytes = serde_json::to_vec(replay).context("encode the replayed bootstrap Seal")?;
    if frozen_bytes != replay_bytes {
        return Err(BootstrapSealReplayContradiction.into());
    }
    Ok(())
}

pub(super) fn recovery_material_continuation(
    stage: crate::state::PendingPrincipalRegistrationStage,
) -> anyhow::Result<RecoveryMaterialContinuation> {
    match stage {
        crate::state::PendingPrincipalRegistrationStage::Accepted => {
            Ok(RecoveryMaterialContinuation::SubmitAndPersist)
        }
        crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete => {
            Ok(RecoveryMaterialContinuation::FinalizeDurableEvidence)
        }
        _ => anyhow::bail!(
            "identity registration has not returned a verified PCR receipt and Standard grant"
        ),
    }
}

pub(super) fn validate_completed_recovery_material(
    registration: &crate::state::PendingPrincipalRegistration,
    account: &crate::config::ActiveAccountContext,
    evidence: &crate::state::RecoveryMaterialEvidence,
) -> anyhow::Result<()> {
    let unit = registration
        .pcr_genesis_unit
        .as_ref()
        .context("completed recovery checkpoint omits its PCR genesis unit")?;
    let seal = registration
        .pcr_bootstrap_seal
        .as_ref()
        .context("completed recovery checkpoint omits its bootstrap Seal")?;
    let receipt = registration
        .pcr_genesis_receipt
        .as_ref()
        .context("completed recovery checkpoint omits its PCR genesis receipt")?;
    let expected_authority =
        arkret_sdk::AccountId::new(account.principal_id().clone(), receipt.issuer_id.clone());
    if evidence.account_id != account.authority
        || evidence.principal_did != *account.did()
        || evidence.device_id != account.device_id
        || evidence.pcr_genesis_unit != *unit
        || evidence.bootstrap_seal != *seal
        || evidence.principal_control_realm_id != seal.realm_id
        || evidence.controller_authority.as_ref() != Some(&expected_authority)
    {
        anyhow::bail!("completed recovery-material evidence does not match the onboarding account");
    }
    Ok(())
}

pub(super) fn finish_pre_account_recovery_checkpoint(
    registration: &crate::state::PendingPrincipalRegistration,
) -> anyhow::Result<()> {
    crate::identity::account_auth::clear_prepared_identity_creation_request_for_checkpoint(
        registration,
    )?;
    Ok(())
}

pub(super) async fn finish_principal_setup(
    registration: &crate::state::PendingPrincipalRegistration,
    recovery_key: &str,
    completed: &CompletedIdentityCreation,
    expected_holder_jkt: &str,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<Option<String>> {
    crate::identity::principal_registration::validate_checkpoint_recovery_key(
        registration,
        recovery_key,
    )?;
    let mut registration = registration.clone();
    let account = &completed.account;
    let actor = account.principal_id().as_str();
    let device = account.device_id.as_str();
    let continuation = recovery_material_continuation(registration.stage)?;
    // Registration and current-principal already confirmed this Account. Its
    // storage must own frontier and recovery writes before setup completes;
    // runtime session publication remains in commit_completed_account.
    let barrier = {
        let mut store = state_store.write();
        activate_accepted_account_setup_storage(
            &mut store,
            account,
            registration.stage,
            recovery_key,
        )?;
        store.set_session_grant(Some(completed.persisted_grant.clone()));
        store.begin_durable_flush()?
    };
    barrier.wait().await?;

    if continuation == RecoveryMaterialContinuation::FinalizeDurableEvidence {
        let evidence = state_store
            .read()
            .recovery_material_evidence()
            .context("completed recovery checkpoint has no durable evidence")?;
        validate_completed_recovery_material(&registration, account, &evidence)?;
        finish_pre_account_recovery_checkpoint(&registration)?;
        return Ok(None);
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

    let recovery_actor = account.did().clone();
    let recovery_device = account.device_id.clone();
    let recovery_key_value = recovery_key.to_owned();
    let principal_control_realm_id = bootstrap_seal.realm_id.clone();
    let bootstrap_seal_for_submit = bootstrap_seal.clone();
    let frozen_bootstrap_seal = registration
        .pcr_bootstrap_seal
        .as_ref()
        .context("bootstrap Seal was not frozen in the durable checkpoint")?;
    validate_exact_bootstrap_seal_replay(frozen_bootstrap_seal, &bootstrap_seal_for_submit)?;
    let governance_state_store = crate::app::runtime_adapter::state_store_handle(state_store);
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let api = accepted_account_session_client_from_secure_store(
        account,
        expected_holder_jkt,
        &completed.persisted_grant,
        secure_store.as_ref(),
    )?;
    if onboarding_may_create_account_mls_root(completed.origin) {
        crate::mls::runtime::ensure_account_mls_secret_durable(
            secure_store.as_ref(),
            &account.authority,
        )
        .await
        .context("durably create the first-enrollment account MLS root")?;
    }
    crate::recovery_flow::submit_principal_bootstrap_seal(&api, &bootstrap_seal_for_submit).await?;
    // The accepted genesis unit, its frozen bootstrap Seal, and the receipt
    // issuer already form the complete holder-side PCR authority evidence.
    // Persist that verified evidence before publishing the recovery policy:
    // policy materialization may transiently wait for a newer control Seal,
    // and a retry must use these exact frozen bytes instead of attempting the
    // forbidden current actor-history resolution path.
    let pcr_genesis_unit = registration
        .pcr_genesis_unit
        .clone()
        .context("recovery-material evidence omits PCR genesis unit")?;
    let principal_id = account.principal_id().clone();
    let station_id = registration
        .pcr_genesis_receipt
        .as_ref()
        .context("recovery-material evidence omits PCR genesis receipt")?
        .issuer_id
        .clone();
    let controller_authority = arkret_sdk::AccountId::new(principal_id.clone(), station_id);
    let recovery_material_evidence = crate::state::RecoveryMaterialEvidence {
        account_id: completed.persisted_grant.account_id.clone(),
        principal_did: account.did().clone(),
        device_id: arkret_sdk::DeviceId::new(device.to_owned())?,
        principal_control_realm_id: bootstrap_seal.realm_id.clone(),
        pcr_genesis_unit,
        bootstrap_seal: bootstrap_seal.clone(),
        controller_authority: Some(controller_authority),
    };
    {
        let barrier = {
            let mut store = state_store.write();
            store.set_pending_principal_registration(Some(registration.clone()))?;
            store.set_recovery_material_evidence(Some(recovery_material_evidence))?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }

    // The founding Seal materializes two distinct Station-verified authoring
    // roots: keys/query carries Data evidence, while the authenticated account
    // viewer carries Control evidence adjacent to the exact authorize Event.
    // Install and durably checkpoint both before authoring the ordinary
    // Control-plane recovery policy. Neither root is a fallback for the other.
    crate::identity::device_directory::reset_session_cache();
    crate::identity::authoring_generation::reset_verified_authoring_generations();
    crate::authorization_lease::clear_leases();
    state_store.write().set_device_authoring_authority(None);
    let device_cache_epoch = crate::identity::device_directory::cache_epoch();
    let http = api.sdk_http_client()?;
    let viewer = crate::transport::keys::list_devices(&http)
        .await
        .context("read the accepted founding device Control evidence")?;
    let signer = crate::event_signer::active_signer()
        .context("accepted founding device signer is unavailable")?;
    let Some(persisted) =
        crate::identity::device_directory::authenticated_device_authoring_authority(
            &http,
            &viewer,
            &account.authority,
            &account.device_id,
            signer.as_ref(),
        )
        .await?
    else {
        crate::identity::device_directory::reset_session_cache();
        crate::identity::authoring_generation::reset_verified_authoring_generations();
        anyhow::bail!(
            "accepted founding device projection does not contain exact Data and Control authoring evidence"
        );
    };
    if !crate::identity::device_directory::restore_persisted_device_authoring_authority(
        device_cache_epoch,
        &account.authority,
        &account.device_id,
        &persisted,
    ) {
        crate::identity::device_directory::reset_session_cache();
        crate::identity::authoring_generation::reset_verified_authoring_generations();
        anyhow::bail!("accepted founding device authoring evidence lost its cache epoch");
    }
    let barrier = {
        let mut store = state_store.write();
        store.set_device_authoring_authority(Some(persisted));
        store.begin_durable_flush()?
    };
    barrier.wait().await?;

    // Evidence hydration deliberately advances the device-cache epoch above.
    // Refresh the accepted PCR frontier only afterwards so its digest suite is
    // cached under the same epoch that will author the recovery-policy Move.
    crate::recovery_flow::refresh_principal_bootstrap_frontier(
        &api,
        &governance_state_store,
        &bootstrap_seal_for_submit,
    )
    .await?;

    crate::recovery_flow::ensure_recovery_policy(
        &api,
        &recovery_actor,
        &account.authority,
        &recovery_device,
        &principal_control_realm_id,
        registration
            .pcr_genesis_unit
            .as_ref()
            .context("recovery policy publication omits its accepted PCR genesis unit")?,
        &recovery_key_value,
    )
    .await?;
    let initial_mls_backup_id = if onboarding_may_create_account_mls_root(completed.origin) {
        let backup_id =
            crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(
                &api,
                secure_store.as_ref(),
                &account.authority,
                &principal_control_realm_id,
                account.did().as_str(),
                account.device_id.as_str(),
                &recovery_key_value,
            )
            .await
            .context("upload the first-enrollment account MLS recovery backup")?;
        Some(backup_id)
    } else {
        None
    };
    registration
        .advance_registration_stage(
            crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete,
        )
        .map_err(anyhow::Error::msg)?;
    let completed_registration = registration.clone();
    {
        let barrier = {
            let mut store = state_store.write();
            store.set_pending_principal_registration(Some(registration))?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }
    finish_pre_account_recovery_checkpoint(&completed_registration)?;
    Ok(initial_mls_backup_id)
}

pub(super) fn hosting_label(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .filter(|host| !host.trim().is_empty())
        .unwrap_or_else(|| "your selected service".to_owned())
}
