//! Server-authoritative onboarding reconciliation.

use dioxus::prelude::*;

use crate::state::{
    LocalStateStore, PendingAccountHandoff, PendingIdentityAbandonment,
    PendingPrincipalRegistrationStage,
};

fn account_client(
    handoff: &PendingAccountHandoff,
    dpop: &super::grant_dpop::DpopHandle,
    grant: String,
) -> anyhow::Result<arkret_sdk::http_client::Client> {
    if handoff.holder_jkt != dpop.jkt() {
        anyhow::bail!("account handoff holder key changed before onboarding reconciliation");
    }
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &handoff.gate_account_base,
    )?;
    Ok(arkret_sdk::http_client::ClientBuilder::new(account_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            dpop.sdk_account_handoff_auth(grant),
        ))
        .build()?)
}

pub async fn refresh_pending_onboarding(
    mut state_store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<()> {
    let handoff = state_store
        .peek()
        .pending_account_handoff()
        .ok_or_else(|| anyhow::anyhow!("no account handoff is pending"))?;
    let pending_device_id = arkret_sdk::DeviceId::new(handoff.device_id.clone())?;
    let pending_store = crate::secure_key_store::PendingLocalStore::new(pending_device_id);
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let dpop = super::grant_dpop::load_or_recover_pending_device_key_with_secure_store(
        &mut state_store.write(),
        secure_store.as_ref(),
        &pending_store,
    )?
    .ok_or_else(|| anyhow::anyhow!("account handoff holder key is unavailable"))?;
    let grant = super::load_account_handoff_grant(&handoff)?
        .ok_or_else(|| anyhow::anyhow!("account handoff credential is unavailable"))?;
    let snapshot = account_client(&handoff, &dpop, grant)?
        .auth_account_onboarding_snapshot()
        .await?;
    snapshot.validate()?;
    let reconciled = reconcile_snapshot(handoff, snapshot)?;
    persist_reconciled_handoff(&mut state_store.write(), reconciled)
}

fn reconcile_snapshot(
    mut handoff: PendingAccountHandoff,
    snapshot: arkret_sdk::AccountOnboardingSnapshot,
) -> anyhow::Result<PendingAccountHandoff> {
    if snapshot.handoff_request_id.to_string() != handoff.request_id {
        anyhow::bail!("onboarding snapshot belongs to a different account handoff");
    }
    if handoff.account_subject.as_ref() != Some(&snapshot.account_subject) {
        anyhow::bail!("onboarding snapshot belongs to a different account subject");
    }

    let (binding_state, lease_state) = match &snapshot.binding {
        arkret_sdk::AccountHandoffBinding::IdentityCreationActive {
            identity_creation_lease,
        } => (
            "identity_creation_active",
            Some(identity_creation_lease.state.as_str()),
        ),
        arkret_sdk::AccountHandoffBinding::IdentityCreationBusy { .. } => {
            ("identity_creation_busy", None)
        }
        arkret_sdk::AccountHandoffBinding::Bound { .. } => ("bound", None),
    };
    tracing::info!(
        handoff_request_id = %snapshot.handoff_request_id,
        binding_state,
        lease_state,
        goal = ?snapshot.goal.kind(),
        "applying authoritative account onboarding snapshot"
    );

    match snapshot.binding {
        arkret_sdk::AccountHandoffBinding::IdentityCreationActive {
            identity_creation_lease,
        } => {
            handoff.lease_id = Some(identity_creation_lease.identity_creation_lease_id);
            handoff.lease_fence = Some(identity_creation_lease.fence);
            handoff.lease_expires_at = Some(identity_creation_lease.expires_at);
            handoff.identity_creation_state = Some(identity_creation_lease.state);
            handoff.reserved_identity = identity_creation_lease.reserved_identity;
            handoff.retry_after_ms = None;
            handoff.bound_principal_id = None;
        }
        arkret_sdk::AccountHandoffBinding::Bound {
            principal_id,
            full_id,
        } => {
            if arkret_sdk::project_full_id_to_core_id(&full_id)? != principal_id {
                anyhow::bail!("bound onboarding full_id does not project to its principal_id");
            }
            handoff.lease_id = None;
            handoff.lease_fence = None;
            handoff.lease_expires_at = None;
            handoff.identity_creation_state = None;
            handoff.reserved_identity = None;
            handoff.retry_after_ms = None;
            // Downstream signer, secure-store and recovery scopes require the
            // method-full DID. Persisting only the stable core id makes the
            // same founding device look like an unknown replacement device.
            handoff.bound_principal_id = Some(full_id.to_string());
        }
        arkret_sdk::AccountHandoffBinding::IdentityCreationBusy { .. } => {
            anyhow::bail!("onboarding snapshot no longer grants this holder the active lease");
        }
    }

    handoff.identity_abandonment = match snapshot.goal {
        arkret_sdk::AccountOnboardingGoal::CompleteIdentity => None,
        arkret_sdk::AccountOnboardingGoal::AbandonProvisionalIdentity {
            challenge,
            fresh_authentication_required,
        } => Some(PendingIdentityAbandonment {
            challenge,
            fresh_authentication_required,
        }),
    };
    Ok(handoff)
}

/// Persist one server-projected handoff and prune every local artifact that
/// cannot belong to the resulting flow. Callers may pass a handoff response
/// that has no projected goal yet; the mounted onboarding surface immediately
/// follows it with [`refresh_pending_onboarding`].
pub fn persist_reconciled_handoff(
    store: &mut LocalStateStore,
    mut handoff: PendingAccountHandoff,
) -> anyhow::Result<()> {
    if handoff.lease_id.is_some() {
        let server_state = handoff
            .identity_creation_state
            .ok_or_else(|| anyhow::anyhow!("account handoff omits its server onboarding state"))?;
        if server_state.has_reserved_identity() != handoff.reserved_identity.is_some() {
            anyhow::bail!("account handoff server state contradicts its reserved identity");
        }
    }

    if let Some(mut checkpoint) = store.pending_principal_registration() {
        let belongs = crate::identity::principal_registration::checkpoint_belongs_to_handoff(
            &checkpoint,
            &handoff,
        );
        let bound_continuation = checkpoint_continues_bound_creation(&checkpoint, &handoff);
        let allowed = bound_continuation
            || checkpoint_allowed_by_server_state(
                checkpoint.stage,
                handoff.identity_creation_state,
            );
        let mut stored_artifacts =
            vec![arkret_sdk::IdentityCreationLocalArtifactKind::RegistrationCheckpoint];
        if checkpoint.stage == PendingPrincipalRegistrationStage::RegisterRequestPrepared {
            stored_artifacts
                .push(arkret_sdk::IdentityCreationLocalArtifactKind::PreparedRegistrationRequest);
        }
        if let Some(pending) = handoff.identity_abandonment.as_ref() {
            stored_artifacts
                .push(arkret_sdk::IdentityCreationLocalArtifactKind::AbandonmentChallenge);
            if !pending.fresh_authentication_required {
                stored_artifacts
                    .push(arkret_sdk::IdentityCreationLocalArtifactKind::FreshAccountHandoff);
            }
        }
        let valid_artifacts = if belongs && allowed {
            stored_artifacts.clone()
        } else {
            Vec::new()
        };
        let keep_checkpoint = if bound_continuation {
            // `bound` closes the Account Authority saga, not Inkson's local
            // readiness gate. The exact prepared request may still need its
            // idempotent response replay, and Accepted/RecoveryMaterialComplete
            // still carry the first Seal + recovery-policy continuation.
            true
        } else if let (Some(lease_id), Some(fence), Some(expires_at), Some(state)) = (
            handoff.lease_id.clone(),
            handoff.lease_fence,
            handoff.lease_expires_at,
            handoff.identity_creation_state,
        ) {
            let lease = arkret_sdk::IdentityCreationLease {
                identity_creation_lease_id: lease_id,
                fence,
                state,
                expires_at,
                reserved_identity: handoff.reserved_identity.clone(),
            };
            let goal = if handoff.identity_abandonment.is_some() {
                arkret_sdk::IdentityCreationGoal::AbandonProvisionalIdentity
            } else {
                arkret_sdk::IdentityCreationGoal::CompleteIdentity
            };
            let plan = garth::reconcile_identity_creation(
                &lease,
                goal,
                // Durable reconciliation never treats a public checkpoint as
                // proof that this process holds the Recovery Key. The mounted
                // UI supplies a separate, validated secret state.
                arkret_sdk::IdentityCreationRecoveryKeyState::Unavailable,
                stored_artifacts,
                valid_artifacts,
            )?;
            tracing::debug!(
                server_state = lease.state.as_str(),
                ?goal,
                ?plan.keep_artifacts,
                ?plan.discard_artifacts,
                ?plan.missing_artifacts,
                ?plan.next_step,
                "reconciled local onboarding artifacts from server state"
            );
            plan.keep_artifacts
                .contains(&arkret_sdk::IdentityCreationLocalArtifactKind::RegistrationCheckpoint)
        } else {
            false
        };
        if keep_checkpoint {
            checkpoint.identity_abandonment = handoff.identity_abandonment.clone();
            store.set_pending_principal_registration(Some(checkpoint))?;
        } else {
            crate::identity::account_auth::clear_prepared_identity_creation_request_for_checkpoint(
                &checkpoint,
            )?;
            store.set_pending_principal_registration(None)?;
        }
    }
    if handoff.identity_creation_state.is_none() {
        handoff.identity_abandonment = None;
    }
    store.set_pending_account_handoff(Some(handoff))
}

pub(crate) fn checkpoint_allowed_by_server_state(
    checkpoint: PendingPrincipalRegistrationStage,
    server: Option<arkret_sdk::IdentityCreationLeaseState>,
) -> bool {
    use PendingPrincipalRegistrationStage as Local;
    use arkret_sdk::IdentityCreationLeaseState as Server;

    match server {
        Some(Server::Active) => matches!(
            checkpoint,
            Local::CustodyConfirmed | Local::GenesisDraftPrepared
        ),
        Some(Server::Reserved) => matches!(
            checkpoint,
            Local::CustodyConfirmed | Local::GenesisDraftPrepared | Local::RegisterRequestPrepared
        ),
        Some(Server::DidPublished | Server::PcrAccepted | Server::AccountBound) => {
            checkpoint == Local::RegisterRequestPrepared
        }
        Some(Server::Completed) | None => false,
    }
}

/// A server `Bound` projection and a later local creation checkpoint are two
/// facts about the same transaction. Preserve the checkpoint only when every
/// identity/account/device fence is exact; a foreign or earlier draft must
/// still be discarded fail-closed.
pub(crate) fn checkpoint_continues_bound_creation(
    checkpoint: &crate::state::PendingPrincipalRegistration,
    handoff: &PendingAccountHandoff,
) -> bool {
    let Some(bound) = handoff.bound_principal_id.as_deref() else {
        return false;
    };
    let Ok(bound_full_id) = arkret_sdk::DidFullId::new(bound.to_owned()) else {
        return false;
    };
    checkpoint.did == bound_full_id.as_str()
        && checkpoint.device_id == handoff.device_id
        && checkpoint.principal_server_url == handoff.principal_server_url
        && checkpoint.gate_account_base == handoff.gate_account_base
        && checkpoint.trust_domain == handoff.trust_domain
        && checkpoint.account_subject.is_some()
        && checkpoint.account_subject == handoff.account_subject
        && matches!(
            checkpoint.stage,
            PendingPrincipalRegistrationStage::RegisterRequestPrepared
                | PendingPrincipalRegistrationStage::Accepted
                | PendingPrincipalRegistrationStage::RecoveryMaterialComplete
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound_continuation_fixture(
        stage: PendingPrincipalRegistrationStage,
    ) -> (
        LocalStateStore,
        PendingAccountHandoff,
        crate::state::PendingPrincipalRegistration,
    ) {
        let mut handoff = PendingAccountHandoff {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            request_id: "ak:request:019f0000-0000-7000-8000-000000000010".to_owned(),
            account_handle: "alice:auth.example".to_owned(),
            account_subject: Some(
                arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
            holder_jkt: "holder-jkt".to_owned(),
            audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            lease_id: Some("lease-1".to_owned()),
            lease_fence: Some(1),
            lease_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
            identity_creation_state: Some(arkret_sdk::IdentityCreationLeaseState::Active),
            reserved_identity: None,
            identity_abandonment: None,
            retry_after_ms: None,
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            trust_domain: "ak:trust_domain:auth.example".to_owned(),
            bound_principal_id: None,
        };
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let mut checkpoint =
            crate::identity::principal_registration::prepare_registration_checkpoint(
                &handoff,
                &handoff.device_id,
                &recovery_key,
            )
            .unwrap();
        checkpoint.stage = stage;
        handoff.lease_id = None;
        handoff.lease_fence = None;
        handoff.lease_expires_at = None;
        handoff.identity_creation_state = None;
        handoff.bound_principal_id = Some(checkpoint.did.clone());
        (
            crate::state::isolated_store_for_tests("bound-onboarding-continuation"),
            handoff,
            checkpoint,
        )
    }

    #[test]
    fn server_state_closes_invalid_local_stage_combinations() {
        use PendingPrincipalRegistrationStage as Local;
        use arkret_sdk::IdentityCreationLeaseState as Server;

        assert!(checkpoint_allowed_by_server_state(
            Local::GenesisDraftPrepared,
            Some(Server::Active)
        ));
        assert!(!checkpoint_allowed_by_server_state(
            Local::RegisterRequestPrepared,
            Some(Server::Active)
        ));
        assert!(checkpoint_allowed_by_server_state(
            Local::RegisterRequestPrepared,
            Some(Server::DidPublished)
        ));
        assert!(!checkpoint_allowed_by_server_state(
            Local::Accepted,
            Some(Server::DidPublished)
        ));
        assert!(!checkpoint_allowed_by_server_state(
            Local::RecoveryMaterialComplete,
            Some(Server::Completed)
        ));
    }

    #[test]
    fn bound_snapshot_keeps_the_method_full_principal_id() {
        let (_store, handoff, checkpoint) =
            bound_continuation_fixture(PendingPrincipalRegistrationStage::RegisterRequestPrepared);
        let full_id = arkret_sdk::DidFullId::new(checkpoint.did.clone()).unwrap();
        let core_id = arkret_sdk::project_full_id_to_core_id(&full_id).unwrap();
        let snapshot = arkret_sdk::AccountOnboardingSnapshot {
            handoff_request_id: arkret_sdk::RequestId::new(handoff.request_id.clone()).unwrap(),
            account_subject: handoff.account_subject.clone().unwrap(),
            observed_at: chrono::Utc::now(),
            binding: arkret_sdk::AccountHandoffBinding::Bound {
                principal_id: core_id,
                full_id: full_id.clone(),
            },
            goal: arkret_sdk::AccountOnboardingGoal::CompleteIdentity,
        };

        let reconciled = reconcile_snapshot(handoff, snapshot).unwrap();

        assert_eq!(
            reconciled.bound_principal_id.as_deref(),
            Some(full_id.as_str())
        );
        assert!(reconciled.lease_id.is_none());
        assert!(reconciled.identity_creation_state.is_none());
    }

    #[test]
    fn bound_server_projection_preserves_exact_post_binding_checkpoint() {
        for stage in [
            PendingPrincipalRegistrationStage::RegisterRequestPrepared,
            PendingPrincipalRegistrationStage::Accepted,
            PendingPrincipalRegistrationStage::RecoveryMaterialComplete,
        ] {
            let (mut store, handoff, checkpoint) = bound_continuation_fixture(stage);
            store
                .set_pending_principal_registration(Some(checkpoint.clone()))
                .unwrap();

            persist_reconciled_handoff(&mut store, handoff.clone()).unwrap();

            assert_eq!(
                store.pending_principal_registration().as_ref(),
                Some(&checkpoint),
                "bound must preserve the exact {stage:?} continuation"
            );
            assert_eq!(
                store
                    .pending_account_handoff()
                    .and_then(|pending| pending.bound_principal_id),
                handoff.bound_principal_id
            );
        }
    }

    #[test]
    fn bound_server_projection_discards_foreign_device_or_account_checkpoint() {
        for mismatch in ["device", "account"] {
            let (mut store, handoff, mut checkpoint) =
                bound_continuation_fixture(PendingPrincipalRegistrationStage::Accepted);
            match mismatch {
                "device" => {
                    checkpoint.device_id =
                        "ak:device:019f0000-0000-7000-8000-000000000099".to_owned();
                }
                "account" => {
                    checkpoint.account_subject =
                        Some(arkret_sdk::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap());
                }
                _ => unreachable!(),
            }
            store
                .set_pending_principal_registration(Some(checkpoint))
                .unwrap();

            persist_reconciled_handoff(&mut store, handoff).unwrap();

            assert!(
                store.pending_principal_registration().is_none(),
                "a foreign {mismatch} checkpoint must fail closed"
            );
        }
    }

    #[test]
    fn fresh_reauthentication_preserves_the_same_bound_transaction() {
        let (mut store, mut handoff, mut checkpoint) =
            bound_continuation_fixture(PendingPrincipalRegistrationStage::Accepted);
        checkpoint.handoff_request_id =
            "ak:request:019f0000-0000-7000-8000-000000000009".to_owned();
        handoff.request_id = "ak:request:019f0000-0000-7000-8000-000000000010".to_owned();
        store
            .set_pending_principal_registration(Some(checkpoint.clone()))
            .unwrap();

        persist_reconciled_handoff(&mut store, handoff).unwrap();

        assert_eq!(
            store.pending_principal_registration().as_ref(),
            Some(&checkpoint),
            "a fresh authenticated request id must not delete the same bound DID/device/account continuation"
        );
    }
}
