//! Resuming an interrupted account setup.
//!
//! Setup can be interrupted after any durable stage, so the panel has to
//! reconstruct what the previous run already accepted before it decides what is
//! left to do. Collecting that inventory, reissuing the accepted session and
//! restoring the runtime it implies are all reads and network calls, not view
//! concerns.

use super::*;

pub(super) async fn recover_bound_principal_device(
    handoff: &crate::state::PendingAccountHandoff,
    principal_did: &arkret_sdk::Did,
    replacement_device_id: &str,
    recovery_words: &str,
    state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<(
    crate::mls::account_recovery::CompletedFreshDeviceRecovery,
    CompletedIdentityCreation,
)> {
    if replacement_device_id != handoff.device_id {
        anyhow::bail!("replacement device does not match the authenticated account handoff");
    }
    activate_recovery_replacement_signer(handoff).await?;
    crate::event_signer::bind_active_signer_principal_device_id(
        principal_did,
        replacement_device_id,
    )?;
    let api = issue_recovery_session_transport(handoff, state_store).await?;
    let store_handle = crate::app::runtime_adapter::state_store_handle(state_store);
    if let Some(mut completed) = crate::mls::account_recovery::resume_pending_pcr_policy_recovery(
        &api,
        &store_handle,
        recovery_words,
    )
    .await?
    {
        let account =
            issue_recovery_completion_grant(handoff, &completed.transaction_id, state_store)
                .await?;
        completed.standard_grant_installed = true;
        return Ok((completed, account));
    }
    let policy = crate::recovery_strand::fetch_active_recovery_policy(&api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the identity has no active Recovery Key policy"))?;
    let session = api
        .create_recovery_session(&arkret_models_crypto::RecoverySessionCreateRequestBody {
            request_id: arkret_sdk::RequestId::new(handoff.request_id.clone())?,
            account_id: arkret_sdk::AccountId::new(
                handoff
                    .bound_principal_id
                    .clone()
                    .context("bound recovery handoff has no principal id")?,
                handoff.audience_id.clone(),
            ),
            requesting_device_id: arkret_sdk::DeviceId::new(replacement_device_id.to_owned())?,
            trust_domain: arkret_sdk::TrustDomainId::new(handoff.trust_domain.clone())?,
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
    let mut completed = crate::mls::account_recovery::execute_pcr_policy_recovery(
        &api,
        &store_handle,
        principal_did,
        &session,
        &proof_outcome,
        recovery_words,
    )
    .await?;
    let account =
        issue_recovery_completion_grant(handoff, &completed.transaction_id, state_store).await?;
    completed.standard_grant_installed = true;
    Ok((completed, account))
}

pub(super) async fn issue_recovery_session_transport(
    handoff: &crate::state::PendingAccountHandoff,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<crate::transport::TransportClient> {
    let holder = {
        let mut store = state_store.write();
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
            .ok_or_else(|| anyhow::anyhow!("recovery grant holder key is unavailable"))?
    };
    if holder.jkt() != handoff.holder_jkt {
        anyhow::bail!("account handoff holder key changed before recovery grant issuance");
    }
    let handoff_grant = crate::identity::account_auth::load_account_handoff_grant(handoff)?
        .ok_or_else(|| anyhow::anyhow!("account handoff credential is unavailable"))?;
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base_url(
        &handoff.gate_account_base_url,
    )?;
    let account_http = arkret_sdk::http_client::ClientBuilder::new(account_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            holder.sdk_account_handoff_auth(handoff_grant),
        ))
        .build()?;
    let principal_id = handoff
        .bound_principal_id
        .as_ref()
        .context("bound recovery handoff has no principal")?;
    let request =
        arkret_sdk::SessionGrantRequestBody::Recovery(arkret_sdk::RecoverySessionGrantRequest {
            credential_class: arkret_sdk::SessionGrantCredentialClass::RecoverySession,
            request_id: arkret_sdk::RequestId::new(handoff.request_id.clone())?,
            principal_id: principal_id.clone(),
            device_id: arkret_sdk::DeviceId::new(handoff.device_id.clone())?,
            audience_id: handoff.audience_id.clone(),
        });
    request.validate()?;
    let outcome = account_http.auth_issue_session_grant(&request).await?;
    let expected_session_public_key = holder.canonical_session_public_jwk()?;
    let expected_granted_scope = arkret_sdk::RECOVERY_SESSION_GRANT_OPERATIONS
        .iter()
        .map(|operation| (*operation).to_owned())
        .collect::<Vec<_>>();
    if outcome.account_id.principal_id != *principal_id
        || outcome.device_id.as_ref().map(arkret_sdk::DeviceId::as_str)
            != Some(handoff.device_id.as_str())
        || outcome.audience_id != handoff.audience_id
        || outcome.session_public_key != expected_session_public_key
        || outcome.expires_at > handoff.expires_at
        || outcome.granted_scope != expected_granted_scope
    {
        anyhow::bail!("recovery SessionGrant outcome changed its frozen authority binding");
    }
    crate::transport::TransportClient::unauthenticated(&handoff.station_url)?
        .with_session_grant_dpop(outcome.session_grant, holder)
}

pub(super) async fn activate_recovery_replacement_signer(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<()> {
    let principal_id = handoff
        .bound_principal_id
        .as_ref()
        .context("bound recovery handoff has no principal")?;
    let authority = arkret_sdk::AccountId::new(principal_id.clone(), handoff.audience_id.clone());
    let device_id = arkret_sdk::DeviceId::new(handoff.device_id.clone())?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let user_store = crate::secure_key_store::UserLocalStore::new(authority, device_id.clone())?;
    let signing_seed = match user_store.load_signing_seed(secure_store.as_ref())? {
        Some(material) => material,
        None => {
            // This is the explicit RecoverWithPolicy branch. The old accepted
            // signer is proved absent and the recovery transaction will
            // authorize this fresh replacement key before it becomes active.
            let pending_store = crate::secure_key_store::PendingLocalStore::new(device_id.clone());
            pending_store.activate();
            pending_store
                .create_fresh_signing_seed_durable(secure_store.as_ref())
                .await?
        }
    };
    crate::event_signer::activate_device_signer_from_seed_for_device(
        signing_seed.seed,
        Some(secure_store.as_ref()),
        Some(device_id.as_str()),
    )?;
    Ok(())
}

pub(super) async fn issue_recovery_completion_grant(
    handoff: &crate::state::PendingAccountHandoff,
    transaction_id: &arkret_sdk::TransactionId,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<CompletedIdentityCreation> {
    let holder = {
        let mut store = state_store.write();
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
            .ok_or_else(|| anyhow::anyhow!("recovery grant holder key is unavailable"))?
    };
    if handoff.holder_jkt != holder.jkt() {
        anyhow::bail!("account handoff holder key changed during recovery");
    }
    let account_handoff_grant = crate::identity::account_auth::load_account_handoff_grant(handoff)?
        .ok_or_else(|| anyhow::anyhow!("account handoff credential is unavailable"))?;
    let authority =
        crate::identity::account_auth::AuthorityResolver::discover(&handoff.station_url).await?;
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base_url(
        &authority.gate_account_base_url,
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
            let initial_session = arkret_sdk::InitialSessionGrantIntent {
                device_id: arkret_sdk::DeviceId::new(handoff.device_id.clone())?,
                session_public_key: holder.canonical_session_public_jwk()?,
                audience_id: handoff.audience_id.clone(),
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
    let principal_id = handoff
        .bound_principal_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("account handoff omits its bound principal"))?;
    let principal_did = handoff
        .bound_principal_did
        .clone()
        .ok_or_else(|| anyhow::anyhow!("account handoff omits its bound principal DID"))?;
    if session.account_id.principal_id != principal_id {
        anyhow::bail!("recovery session grant principal does not match the account handoff");
    }
    let persisted = crate::state::PersistedSessionGrant {
        grant_jwt: session.grant_jwt.clone(),
        session_private_key_pem: holder.session_signing_key_pkcs8_pem()?.to_string(),
        grant_id: session.grant_id.to_string(),
        audience_id: session.audience_id.clone(),
        account_id: session.account_id.clone(),
        device_id: arkret_sdk::DeviceId::new(handoff.device_id.clone())?,
        station_url: url::Url::parse(&handoff.station_url)?,
        grant_expires_at: Some(session.expires_at),
        stored_at: chrono::Utc::now(),
    };
    let dpop_record = crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
        holder.seed_b64().as_str(),
    )?;
    let account = resolve_handoff_active_account(
        handoff,
        &principal_did,
        persisted.device_id.clone(),
        state_store,
    )
    .await?;
    {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let prepared_keys = crate::views::login::prepare_completed_login_dpop_key(
            secure_store.as_ref(),
            &account,
            &handoff.device_id,
            &dpop_record,
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
            &persisted,
        )
        .await?;
        crate::views::login::commit_completed_login_dpop_key(
            &mut state_store.write(),
            secure_store.as_ref(),
            &account,
            &dpop_record,
            prepared_keys,
        )
        .map_err(anyhow::Error::msg)?;
    }
    Ok(CompletedIdentityCreation {
        account,
        persisted_grant: persisted,
        dpop_device_key: dpop_record,
        origin: crate::identity::account_auth::transition::OnboardingCompletionOrigin::RecoveryCompletion,
        initial_mls_backup_id: None,
    })
}

pub(super) struct RestoredAcceptedAccountRuntime {
    pub(super) persisted_grant: crate::state::PersistedSessionGrant,
    pub(super) dpop_device_key: crate::state::DpopDeviceKeyRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResumeTerminalKind {
    HydrationFailed,
    RetryableFailure,
    ReauthRequired,
    StrandedIdentity,
    Contradiction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResumeTerminal {
    pub(super) kind: ResumeTerminalKind,
    pub(super) reason: String,
    pub(super) inventory: Vec<String>,
}

pub(super) enum IdentityCreationCommandOutcome {
    Completed(Box<CompletedIdentityCreation>),
    Terminal(ResumeTerminal),
}

pub(super) struct BoundCompletionResumeInventory {
    pub(super) facts: garth::BoundCompletionResumeFacts,
    pub(super) read_errors: Vec<String>,
}

impl BoundCompletionResumeInventory {
    pub(super) fn checklist(&self) -> Vec<String> {
        use garth::BoundCompletionMaterialState as State;

        fn line(label: &str, state: State) -> String {
            let value = match state {
                State::Present => "present",
                State::Absent => "absent",
                State::ReadError => "read error",
                State::NotRequired => "not required",
            };
            format!("{label}: {value}")
        }
        vec![
            line("Accepted device id", self.facts.device_id),
            line("Accepted device signer", self.facts.signing_seed),
            line("Grant-binding key", self.facts.grant_binding_key),
            line("Session grant", self.facts.session_grant),
            line("Recovery policy", self.facts.recovery_policy),
            line("Recovery evidence", self.facts.recovery_evidence),
            line("Device HPKE private key", self.facts.hpke_private_key),
        ]
    }
}

pub(super) fn observe_resume_material<T, E: std::fmt::Display>(
    label: &str,
    result: Result<Option<T>, E>,
    read_errors: &mut Vec<String>,
) -> (garth::BoundCompletionMaterialState, Option<T>) {
    match result {
        Ok(Some(value)) => (garth::BoundCompletionMaterialState::Present, Some(value)),
        Ok(None) => (garth::BoundCompletionMaterialState::Absent, None),
        Err(error) => {
            read_errors.push(format!("{label}: {error}"));
            (garth::BoundCompletionMaterialState::ReadError, None)
        }
    }
}

pub(super) fn accepted_account_session_client(
    account: &crate::config::ActiveAccountContext,
    expected_holder_jkt: &str,
    grant: &crate::state::PersistedSessionGrant,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<crate::transport::TransportClient> {
    if !crate::identity::session_refresh::grant_matches_station(grant, account.server_url.as_str())
        || !crate::identity::session_refresh::grant_matches_principal_did(grant, account.did())
        || grant.device_id != account.device_id
        || grant.audience_id != account.authority.station_id
    {
        anyhow::bail!("session grant does not belong to the accepted onboarding account");
    }
    if crate::identity::session_refresh::grant_is_dead(grant) {
        anyhow::bail!("session grant is no longer live");
    }
    if dpop.jkt() != expected_holder_jkt {
        anyhow::bail!("grant-binding key does not match the accepted account handoff");
    }
    crate::transport::TransportClient::new(
        account.server_url.as_str(),
        crate::transport::RequestContext::new(grant.grant_jwt.clone()),
    )?
    .with_dpop_device(dpop.clone())
}

pub(super) fn accepted_account_session_client_from_secure_store(
    account: &crate::config::ActiveAccountContext,
    expected_holder_jkt: &str,
    grant: &crate::state::PersistedSessionGrant,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<crate::transport::TransportClient> {
    let user_store = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )?;
    let dpop = crate::identity::account_auth::grant_dpop::load_user_device_key_with_secure_store(
        &user_store,
        secure_store,
    )?
    .context("accepted onboarding account has no durable grant-binding key")?;
    accepted_account_session_client(account, expected_holder_jkt, grant, &dpop)
}

pub(super) async fn collect_bound_completion_resume_inventory(
    handoff: &crate::state::PendingAccountHandoff,
    checkpoint: &crate::state::PendingPrincipalRegistration,
    account: &crate::config::ActiveAccountContext,
    state_store: SyncSignal<crate::state::LocalStateStore>,
) -> BoundCompletionResumeInventory {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let mut read_errors = Vec::new();
    let user_store = match crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    ) {
        Ok(store) => Some(store),
        Err(error) => {
            read_errors.push(format!("account secure scope: {error}"));
            None
        }
    };

    let (device_id_state, stored_device_id) = observe_resume_material(
        "device id",
        user_store.as_ref().map_or_else(
            || {
                Err(crate::secure_key_store::SecureKeyStoreError::Backend(
                    "account secure scope is unavailable".to_owned(),
                ))
            },
            |store| store.load_device_id(secure_store.as_ref()),
        ),
        &mut read_errors,
    );
    let (signing_seed_state, _) = observe_resume_material(
        "accepted device signer",
        user_store.as_ref().map_or_else(
            || {
                Err(crate::secure_key_store::SecureKeyStoreError::Backend(
                    "account secure scope is unavailable".to_owned(),
                ))
            },
            |store| store.load_signing_seed(secure_store.as_ref()),
        ),
        &mut read_errors,
    );
    let (grant_binding_state, grant_binding) = observe_resume_material(
        "grant-binding key",
        user_store.as_ref().map_or_else(
            || {
                Err(
                    crate::identity::account_auth::grant_dpop::AuthDpopError::SecureStore(
                        "account secure scope is unavailable".to_owned(),
                    ),
                )
            },
            |store| {
                crate::identity::account_auth::grant_dpop::load_user_device_key_with_secure_store(
                    store,
                    secure_store.as_ref(),
                )
            },
        ),
        &mut read_errors,
    );
    let (session_grant_state, session_grant) = observe_resume_material(
        "session grant",
        user_store.as_ref().map_or_else(
            || {
                Err(crate::secure_key_store::SecureKeyStoreError::Backend(
                    "account secure scope is unavailable".to_owned(),
                ))
            },
            |store| {
                crate::state::load_session_grant_from_user_secure_store(
                    store,
                    secure_store.as_ref(),
                )
            },
        ),
        &mut read_errors,
    );
    let (hpke_state, _) = observe_resume_material(
        "device HPKE private key",
        crate::mls::runtime::load_device_hpke_private_key(
            secure_store.as_ref(),
            &account.authority,
            &account.device_id,
        ),
        &mut read_errors,
    );
    let recovery_evidence = state_store.peek().recovery_material_evidence();
    let recovery_evidence_state = if recovery_evidence.is_some() {
        garth::BoundCompletionMaterialState::Present
    } else {
        garth::BoundCompletionMaterialState::Absent
    };
    let recovery_policy_state = if signing_seed_state == garth::BoundCompletionMaterialState::Absent
    {
        let client = match (session_grant.as_ref(), grant_binding.as_ref()) {
            (Some(grant), Some(dpop)) => {
                accepted_account_session_client(account, &handoff.holder_jkt, grant, dpop)
            }
            (None, _) => Err(anyhow::anyhow!(
                "active recovery policy read requires an accepted account session grant"
            )),
            (_, None) => Err(anyhow::anyhow!(
                "active recovery policy read requires the accepted grant-binding key"
            )),
        };
        match client {
            Ok(api) => {
                observe_resume_material(
                    "active recovery policy",
                    crate::recovery_strand::fetch_active_recovery_policy(&api).await,
                    &mut read_errors,
                )
                .0
            }
            Err(error) => {
                read_errors.push(format!("active recovery policy client: {error}"));
                garth::BoundCompletionMaterialState::ReadError
            }
        }
    } else {
        garth::BoundCompletionMaterialState::NotRequired
    };
    let authority_matches = arkret_sdk::project_did_to_core_id(&checkpoint.did)
        .is_ok_and(|principal_id| principal_id == account.authority.principal_id)
        && handoff.audience_id == account.authority.station_id
        && handoff.bound_principal_id.as_ref() == Some(&account.authority.principal_id)
        && handoff.bound_principal_did.as_ref() == Some(&checkpoint.did);
    let device_slot_matches = stored_device_id
        .as_ref()
        .is_none_or(|device_id| device_id == &account.device_id);
    let grant_matches_account = session_grant.as_ref().is_some_and(|grant| {
        crate::identity::session_refresh::grant_matches_station(grant, account.server_url.as_str())
            && crate::identity::session_refresh::grant_matches_principal_did(grant, account.did())
            && grant.device_id == account.device_id
            && grant.audience_id == account.authority.station_id
    });
    let grant_is_live = session_grant
        .as_ref()
        .is_some_and(|grant| !crate::identity::session_refresh::grant_is_dead(grant));
    let grant_binding_matches_handoff = grant_binding
        .as_ref()
        .is_some_and(|binding| binding.jkt() == handoff.holder_jkt);
    let handoff_state = if handoff.expires_at <= chrono::Utc::now() {
        garth::BoundCompletionHandoffState::MissingOrExpired
    } else {
        garth::BoundCompletionHandoffState::ActiveBound
    };
    let checkpoint_stage = match checkpoint.stage {
        crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete => {
            garth::BoundCompletionCheckpointStage::RecoveryMaterialComplete
        }
        _ => garth::BoundCompletionCheckpointStage::Accepted,
    };
    BoundCompletionResumeInventory {
        facts: garth::BoundCompletionResumeFacts {
            handoff: handoff_state,
            checkpoint_stage,
            recovery_policy: recovery_policy_state,
            device_id: device_id_state,
            signing_seed: signing_seed_state,
            grant_binding_key: grant_binding_state,
            session_grant: session_grant_state,
            recovery_evidence: recovery_evidence_state,
            hpke_private_key: hpke_state,
            authority_matches,
            device_slot_matches,
            grant_matches_account,
            grant_is_live,
            grant_binding_matches_handoff,
        },
        read_errors,
    }
}

#[derive(Debug)]
pub(super) enum AcceptedSessionReissueError {
    Retryable(anyhow::Error),
    ReauthRequired(anyhow::Error),
    Contradiction(anyhow::Error),
}

pub(super) fn load_bound_handoff_holder_key(
    handoff: &crate::state::PendingAccountHandoff,
    account: &crate::config::ActiveAccountContext,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<crate::identity::account_auth::grant_dpop::DpopHandle, AcceptedSessionReissueError> {
    let pending_device = arkret_sdk::DeviceId::new(handoff.device_id.clone()).map_err(|error| {
        AcceptedSessionReissueError::Contradiction(
            anyhow::anyhow!(error)
                .context("the accepted account handoff contains an invalid device id"),
        )
    })?;
    let pending_store = crate::secure_key_store::PendingLocalStore::new(pending_device);
    let pending =
        crate::identity::account_auth::grant_dpop::load_or_recover_pending_device_key_with_secure_store(
            &mut state_store.write(),
            secure_store,
            &pending_store,
        )
        .map_err(|error| {
            AcceptedSessionReissueError::Retryable(
                anyhow::anyhow!(error).context("read the retained account handoff holder key"),
            )
        })?;
    let holder = match pending {
        Some(holder) => holder,
        None => {
            let user_store = crate::secure_key_store::UserLocalStore::new(
                account.authority.clone(),
                account.device_id.clone(),
            )
            .map_err(|error| {
                AcceptedSessionReissueError::Contradiction(
                    anyhow::anyhow!(error).context("open the accepted account secure scope"),
                )
            })?;
            let stored_device = user_store
                .load_device_id(secure_store)
                .map_err(|error| {
                    AcceptedSessionReissueError::Retryable(
                        anyhow::anyhow!(error).context("read the accepted account device id"),
                    )
                })?
                .ok_or_else(|| {
                    AcceptedSessionReissueError::ReauthRequired(anyhow::anyhow!(
                        "accepted account device id is unavailable"
                    ))
                })?;
            if stored_device != account.device_id {
                return Err(AcceptedSessionReissueError::Contradiction(anyhow::anyhow!(
                    "accepted account secure scope belongs to another device"
                )));
            }
            crate::identity::account_auth::grant_dpop::load_user_device_key_with_secure_store(
                &user_store,
                secure_store,
            )
            .map_err(|error| {
                AcceptedSessionReissueError::Retryable(
                    anyhow::anyhow!(error).context("read the accepted account holder key"),
                )
            })?
            .ok_or_else(|| {
                AcceptedSessionReissueError::ReauthRequired(anyhow::anyhow!(
                    "account handoff holder key is unavailable"
                ))
            })?
        }
    };
    if holder.jkt() != handoff.holder_jkt {
        return Err(AcceptedSessionReissueError::ReauthRequired(
            anyhow::anyhow!("account handoff holder key does not match the active handoff")
                .context("the retained holder cannot authorize this account handoff"),
        ));
    }
    Ok(holder)
}

pub(super) async fn reissue_accepted_onboarding_session(
    handoff: &crate::state::PendingAccountHandoff,
    account: &crate::config::ActiveAccountContext,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> Result<CompletedIdentityCreation, AcceptedSessionReissueError> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let holder =
        load_bound_handoff_holder_key(handoff, account, state_store, secure_store.as_ref())?;
    let handoff_grant = crate::identity::account_auth::load_account_handoff_grant(handoff)
        .map_err(|error| {
            AcceptedSessionReissueError::Retryable(
                anyhow::anyhow!(error).context("read the account handoff credential"),
            )
        })?
        .ok_or_else(|| {
            AcceptedSessionReissueError::ReauthRequired(anyhow::anyhow!(
                "account handoff credential is unavailable for session reissue"
            ))
        })?;
    let authority =
        crate::identity::account_auth::AuthorityResolver::discover(&handoff.station_url)
            .await
            .map_err(|error| {
                AcceptedSessionReissueError::Retryable(
                    anyhow::anyhow!(error).context("discover the Account Authority route"),
                )
            })?;
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base_url(
        &authority.gate_account_base_url,
    )
    .map_err(|error| AcceptedSessionReissueError::Contradiction(anyhow::anyhow!(error)))?;
    let mut correlation =
        crate::identity::account_auth::transition::LoginCorrelation::for_handoff(handoff)
            .with_principal_id(account.principal_id().clone())
            .with_device_id(account.device_id.as_str());
    let issued = crate::views::login::issue_bound_handoff_session(
        &handoff.station_url,
        &account_base,
        handoff,
        &handoff_grant,
        account.authority.principal_id.clone(),
        account.did().clone(),
        account.device_id.clone(),
        &holder,
        &mut correlation,
    )
    .await
    .map_err(|error| match error {
        crate::views::login::ReturningSessionExchangeError::Retryable(message) => {
            AcceptedSessionReissueError::Retryable(anyhow::anyhow!(message))
        }
        crate::views::login::ReturningSessionExchangeError::DeviceSetupRequired(message)
        | crate::views::login::ReturningSessionExchangeError::Blocked(_, message)
        | crate::views::login::ReturningSessionExchangeError::Fatal(message) => {
            AcceptedSessionReissueError::Contradiction(anyhow::anyhow!(message))
        }
    })?;
    if issued.account.did() != account.did()
        || issued.account.authority != account.authority
        || issued.account.device_id != account.device_id
    {
        return Err(AcceptedSessionReissueError::Contradiction(anyhow::anyhow!(
            "reissued onboarding session resolved a different account or device"
        )));
    }
    let prepared_keys = crate::views::login::prepare_completed_login_dpop_key(
        secure_store.as_ref(),
        account,
        &handoff.device_id,
        &issued.dpop_device_key,
    )
    .await
    .map_err(|error| {
        AcceptedSessionReissueError::Contradiction(
            anyhow::Error::msg(error).context("prepare the accepted account DPoP key"),
        )
    })?;
    let account_store = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )
    .map_err(|error| AcceptedSessionReissueError::Contradiction(anyhow::anyhow!(error)))?;
    crate::state::store_session_grant_in_user_secure_store_durable(
        &account_store,
        secure_store.as_ref(),
        &issued.session_grant,
    )
    .await
    .map_err(|error| AcceptedSessionReissueError::Retryable(anyhow::anyhow!(error)))?;
    {
        let mut store = state_store.write();
        crate::views::login::commit_completed_login_dpop_key(
            &mut store,
            secure_store.as_ref(),
            account,
            &issued.dpop_device_key,
            prepared_keys,
        )
        .map_err(|error| {
            AcceptedSessionReissueError::Retryable(
                anyhow::Error::msg(error).context("commit the accepted account DPoP key"),
            )
        })?;
    }
    Ok(CompletedIdentityCreation {
        account: account.clone(),
        persisted_grant: issued.session_grant,
        dpop_device_key: issued.dpop_device_key,
        origin:
            crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeReissue,
        initial_mls_backup_id: None,
    })
}

pub(super) fn restore_accepted_account_runtime(
    account: &crate::config::ActiveAccountContext,
    expected_holder_jkt: &str,
) -> anyhow::Result<RestoredAcceptedAccountRuntime> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    restore_accepted_account_runtime_with_secure_store(
        account,
        expected_holder_jkt,
        secure_store.as_ref(),
    )
}

pub(super) fn restore_accepted_account_runtime_with_secure_store(
    account: &crate::config::ActiveAccountContext,
    expected_holder_jkt: &str,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<RestoredAcceptedAccountRuntime> {
    let user_store = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )?;
    let stored_device = user_store
        .load_device_id(secure_store)?
        .context("accepted onboarding account has no durable device id")?;
    if stored_device != account.device_id {
        anyhow::bail!("accepted onboarding account device does not match its secure scope");
    }
    let signing_seed = user_store
        .load_signing_seed(secure_store)?
        .context("accepted onboarding account has no durable device signer")?;
    let dpop = crate::identity::account_auth::grant_dpop::load_user_device_key_with_secure_store(
        &user_store,
        secure_store,
    )?
    .context("accepted onboarding account has no durable grant-binding key")?;
    if dpop.jkt() != expected_holder_jkt {
        anyhow::bail!("accepted onboarding grant-binding key does not match the account handoff");
    }
    let dpop_device_key =
        crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
            dpop.seed_b64().as_str(),
        )?;
    let grant = crate::identity::session_refresh::load_account_session_grant_with_secure_store(
        account,
        secure_store,
    )?;

    // Publish the exact accepted scope only after every durable component has
    // been validated. A failed restore must not leave another account's signer
    // or a half-valid onboarding scope active.
    user_store.activate();
    if let Err(error) = crate::event_signer::activate_device_signer_from_seed_for_device(
        signing_seed.seed,
        Some(secure_store),
        Some(account.device_id.as_str()),
    )
    .and_then(|_| {
        crate::event_signer::bind_active_signer_principal_device_id(
            account.did(),
            account.device_id.as_str(),
        )
        .map(|_| ())
    }) {
        crate::event_signer::clear_active_device_signer();
        return Err(error);
    }
    Ok(RestoredAcceptedAccountRuntime {
        persisted_grant: grant,
        dpop_device_key,
    })
}
