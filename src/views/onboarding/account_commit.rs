//! Turning an accepted identity into the account the app runs as.
//!
//! Everything between "the server accepted the principal" and "this device is
//! signed in": reading back the retained Recovery Key, resolving the handoff's
//! active account, persisting the account config, and the single commit that
//! activates it. All of it is durable state, none of it is view state.

use super::*;

pub(super) fn load_valid_retained_recovery_key(
    handoff: &crate::state::PendingAccountHandoff,
    checkpoint: Option<&crate::state::PendingPrincipalRegistration>,
) -> Option<String> {
    let retained =
        match crate::identity::account_auth::load_pending_identity_creation_recovery_key(handoff) {
            Ok(Some(retained)) => retained,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(error = %error, "could not load retained onboarding Recovery Key");
                return None;
            }
        };
    let bound_continuation = checkpoint.is_some_and(|checkpoint| {
        crate::identity::account_auth::checkpoint_continues_bound_creation(checkpoint, handoff)
    });
    let server_accepts = match handoff.identity_creation_state {
        Some(arkret_sdk::IdentityCreationLeaseState::Active) => {
            arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
                retained.as_str(),
                "",
                0,
            )
            .is_ok()
        }
        Some(
            arkret_sdk::IdentityCreationLeaseState::Reserved
            | arkret_sdk::IdentityCreationLeaseState::DidPublished
            | arkret_sdk::IdentityCreationLeaseState::PcrAccepted
            | arkret_sdk::IdentityCreationLeaseState::AccountBound,
        ) => crate::identity::principal_registration::validate_reserved_identity_recovery_key(
            handoff,
            retained.as_str(),
        )
        .is_ok(),
        Some(arkret_sdk::IdentityCreationLeaseState::Completed) => false,
        None if bound_continuation => checkpoint.is_some_and(|checkpoint| {
            crate::identity::principal_registration::validate_checkpoint_recovery_key(
                checkpoint,
                retained.as_str(),
            )
            .is_ok()
        }),
        None => false,
    };
    let checkpoint_accepts = checkpoint.is_none_or(|checkpoint| {
        !crate::identity::principal_registration::checkpoint_belongs_to_handoff(checkpoint, handoff)
            || crate::identity::principal_registration::validate_checkpoint_recovery_key(
                checkpoint,
                retained.as_str(),
            )
            .is_ok()
    });
    if server_accepts && checkpoint_accepts {
        return Some(retained.to_string());
    }
    tracing::warn!(
        handoff_request_id = %handoff.request_id,
        "discarding retained onboarding Recovery Key that does not match authoritative state"
    );
    if let Err(error) =
        crate::identity::account_auth::clear_pending_identity_creation_recovery_key(handoff)
    {
        tracing::warn!(error = %error, "could not discard invalid retained onboarding Recovery Key");
    }
    None
}

pub(super) fn profile_id_for_authority(
    state_store: &crate::state::LocalStateStore,
    authority: &arkret_sdk::AccountId,
) -> String {
    state_store
        .known_profile_id_for_authority(authority)
        .unwrap_or_else(|| format!("ak:profile:{}", crate::operation::uuid_v7()))
}

fn check_handoff_current_principal(
    store: &crate::state::LocalStateStore,
    expected: &crate::state::PendingAccountHandoff,
    account: &crate::config::ActiveAccountContext,
) -> anyhow::Result<()> {
    let current = store
        .pending_account_handoff()
        .context("onboarding handoff was cancelled")?;
    anyhow::ensure!(
        current.request_id == expected.request_id
            && current.holder_jkt == expected.holder_jkt
            && current.audience_id == expected.audience_id
            && current.device_id == expected.device_id,
        "current principal response belongs to a superseded onboarding handoff"
    );
    if let Some(evidence) = store
        .recovery_material_evidence()
        .filter(|e| e.account_id == account.authority)
    {
        anyhow::ensure!(
            evidence.principal_control_realm_id == account.principal_control_realm_id,
            "current principal changes the accepted onboarding PCR"
        );
    }
    Ok(())
}

pub(super) async fn resolve_handoff_active_account(
    handoff: &crate::state::PendingAccountHandoff,
    did: &arkret_sdk::Did,
    device_id: arkret_sdk::DeviceId,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    issued_session: Option<(
        String,
        crate::identity::account_auth::grant_dpop::DpopHandle,
    )>,
) -> anyhow::Result<crate::config::ActiveAccountContext> {
    let authority = arkret_sdk::AccountId::new(
        arkret_sdk::project_did_to_core_id(did)?,
        handoff.audience_id.clone(),
    );
    let profile_id = profile_id_for_authority(&state_store.read(), &authority);
    let server_url = url::Url::parse(&crate::config::normalize_server_url(&handoff.station_url))?;
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let (credential, holder) = if let Some(session) = issued_session {
        session
    } else {
        // Credential restoration needs only the handoff's exact key-store
        // coordinates, never a provisional principal projection.
        let holder = load_bound_handoff_holder_key(
            handoff,
            &authority,
            &device_id,
            state_store,
            secure.as_ref(),
        )
        .map_err(|error| anyhow::anyhow!("restore onboarding holder: {error:?}"))?;
        let user =
            crate::secure_key_store::UserLocalStore::new(authority.clone(), device_id.clone())?;
        let stored =
            crate::state::load_session_grant_from_user_secure_store(&user, secure.as_ref())?;
        let usable = stored.filter(|grant| {
            grant.account_id == authority
                && grant.device_id == device_id
                && grant.audience_id == authority.station_id
                && crate::identity::session_refresh::grant_matches_station(
                    grant,
                    &handoff.station_url,
                )
                && !crate::identity::session_refresh::grant_is_dead(grant)
        });
        if let Some(grant) = usable {
            (grant.grant_jwt, holder)
        } else {
            let handoff_grant = crate::identity::account_auth::load_account_handoff_grant(handoff)?
                .context("bound onboarding requires its handoff credential to reissue a session")?;
            let account_base =
                crate::identity::session_refresh::sdk_base_url_from_gate_account_base_url(
                    &handoff.gate_account_base_url,
                )?;
            let mut correlation =
                crate::identity::account_auth::transition::LoginCorrelation::for_handoff(handoff)
                    .with_principal_id(authority.principal_id.clone())
                    .with_device_id(device_id.as_str());
            let issued = crate::views::login::issue_bound_handoff_session(
                &handoff.station_url,
                &account_base,
                handoff,
                &handoff_grant,
                authority.principal_id.clone(),
                did.clone(),
                device_id.clone(),
                &holder,
                &mut correlation,
            )
            .await
            .map_err(|error| anyhow::anyhow!("reissue bound onboarding session: {error:?}"))?;
            // The returning-session flow already obtained the fresh self result.
            anyhow::ensure!(
                issued.account.authority == authority && issued.account.device_id == device_id,
                "reissued onboarding session changed its Account or device"
            );
            check_handoff_current_principal(&state_store.read(), handoff, &issued.account)?;
            let prepared = crate::views::login::prepare_completed_login_dpop_key(
                secure.as_ref(),
                &issued.account,
                device_id.as_str(),
                &issued.dpop_device_key,
            )
            .await
            .map_err(anyhow::Error::msg)?;
            crate::state::store_session_grant_in_user_secure_store_durable(
                &user,
                secure.as_ref(),
                &issued.session_grant,
            )
            .await?;
            {
                let mut store = state_store.write();
                check_handoff_current_principal(&store, handoff, &issued.account)?;
                crate::views::login::commit_completed_login_dpop_key(
                    &mut store,
                    secure.as_ref(),
                    &issued.account,
                    &issued.dpop_device_key,
                    prepared,
                )
                .map_err(anyhow::Error::msg)?;
            }
            return Ok(issued.account);
        }
    };
    anyhow::ensure!(
        holder.jkt() == handoff.holder_jkt,
        "onboarding holder changed"
    );
    let http = crate::transport::TransportClient::unauthenticated(server_url.as_str())?
        .with_session_grant_dpop(credential, holder)?
        .sdk_http_client()?;
    let account = crate::transport::account::resolve_active_account_context(
        &http, profile_id, authority, device_id, server_url,
    )
    .await?;
    check_handoff_current_principal(&state_store.read(), handoff, &account)?;
    Ok(account)
}

pub(super) fn persist_completed_account_config(
    mut config_store: Signal<crate::config::LocalConfigStore>,
    account: &crate::config::ActiveAccountContext,
    session_credential: &str,
) -> anyhow::Result<()> {
    let mut profiles = config_store.read().load_profiles();
    let profile_id = profiles.upsert_and_activate(crate::config::AccountProfile::new(
        account.clone(),
        session_credential.to_owned(),
    ))?;
    if profile_id != account.profile_id {
        anyhow::bail!("completed account profile id does not match the active state namespace");
    }
    let mut store = config_store.write();
    store.save(crate::config::ClientConfig::authenticated(
        account.clone(),
        session_credential.to_owned(),
    ));
    if let Some(error) = store.persist_error() {
        anyhow::bail!("persist completed account config: {error}");
    }
    store.save_profiles(&profiles)?;
    Ok(())
}

#[derive(Clone, Debug)]
pub(super) struct CompletedIdentityCreation {
    pub(super) account: crate::config::ActiveAccountContext,
    pub(super) persisted_grant: crate::state::PersistedSessionGrant,
    pub(super) dpop_device_key: crate::state::DpopDeviceKeyRecord,
    pub(super) origin: crate::identity::account_auth::transition::OnboardingCompletionOrigin,
    pub(super) initial_mls_backup_id: Option<String>,
}

impl CompletedIdentityCreation {
    fn session_credential(&self) -> &str {
        &self.persisted_grant.grant_jwt
    }
}

pub(super) fn onboarding_may_create_account_mls_root(
    origin: crate::identity::account_auth::transition::OnboardingCompletionOrigin,
) -> bool {
    origin
        != crate::identity::account_auth::transition::OnboardingCompletionOrigin::RecoveryCompletion
}

/// Cross the accepted-account storage boundary before writing metadata keyed
/// by that account. Keeping the switch and write in one typed operation makes
/// it impossible for onboarding to leave Recovery Key metadata in the
/// anonymous pre-account namespace.
pub(super) fn activate_account_and_save_recovery_metadata(
    store: &mut crate::state::LocalStateStore,
    account: &crate::config::ActiveAccountContext,
    recovery_key: &str,
) -> anyhow::Result<()> {
    store.switch_active_account(account)?;
    crate::views::recovery::save_generated_recovery_key_metadata_in_store(store, recovery_key)
        .context("save Recovery Key metadata in the accepted account scope")?;
    Ok(())
}

pub(super) fn activate_accepted_account_setup_storage(
    store: &mut crate::state::LocalStateStore,
    account: &crate::config::ActiveAccountContext,
    stage: crate::state::PendingPrincipalRegistrationStage,
    recovery_key: &str,
) -> anyhow::Result<()> {
    recovery_material_continuation(stage)?;
    activate_account_and_save_recovery_metadata(store, account, recovery_key)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn commit_completed_account(
    completed: &CompletedIdentityCreation,
    recovery_key: &str,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    config_store: Signal<crate::config::LocalConfigStore>,
    mut active_account: Signal<Option<crate::config::ActiveAccountContext>>,
    token: Signal<String>,
    session: &crate::runtime::session::SessionCoordinator,
    session_generation: Signal<u64>,
    mut principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    mut device_id: Signal<String>,
    mut needs_device_authorization: Signal<bool>,
    mut device_authorization_check_complete: Signal<bool>,
) -> anyhow::Result<()> {
    let correlation = state_store
        .peek()
        .pending_account_handoff()
        .as_ref()
        .map(crate::identity::account_auth::transition::LoginCorrelation::for_handoff)
        .unwrap_or_default()
        .with_principal_id(completed.account.principal_id().clone())
        .with_device_id(completed.account.device_id.as_str());
    let result = async {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let user_store = crate::secure_key_store::UserLocalStore::new(
            completed.account.authority.clone(),
            completed.account.device_id.clone(),
        )?;
        let durable_device = user_store
            .load_device_id(secure_store.as_ref())?
            .context("completed account has no durable device id")?;
        if durable_device != completed.account.device_id {
            anyhow::bail!("completed account durable device id does not match its account scope");
        }
        user_store
            .load_signing_seed(secure_store.as_ref())?
            .context("completed account has no durable accepted-device signer")?;
        let durable_dpop =
            crate::identity::account_auth::grant_dpop::load_user_device_key_with_secure_store(
                &user_store,
                secure_store.as_ref(),
            )?
            .context("completed account has no durable grant-binding key")?;
        if durable_dpop.jkt() != completed.dpop_device_key.jkt {
            anyhow::bail!("completed account durable grant-binding key changed before commit");
        }
        let durable_grant =
            crate::identity::session_refresh::load_account_session_grant_with_secure_store(
                &completed.account,
                secure_store.as_ref(),
            )?;
        if durable_grant != completed.persisted_grant {
            anyhow::bail!("completed account durable session grant changed before commit");
        }

        // This order is the account-authority boundary: make the typed profile
        // durable first, then switch the authority namespace, then publish the
        // runtime signals. A retry repeats the same upsert and same-account
        // namespace switch.
        persist_completed_account_config(
            config_store,
            &completed.account,
            completed.session_credential(),
        )?;
        let barrier = {
            let mut store = state_store.write();
            store.set_session_grant(Some(completed.persisted_grant.clone()));
            activate_account_and_save_recovery_metadata(
                &mut store,
                &completed.account,
                recovery_key,
            )?;
            if let Some(backup_id) = completed.initial_mls_backup_id.as_deref() {
                crate::components::mark_mls_recovery_backup_configured(&mut store, backup_id);
            }
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
        crate::views::recovery::local_recovery_public_key_result(&state_store.read())
            .context("verify Recovery Key metadata in the accepted account scope")?;
        crate::event_submit::remember_verified_recovery_gate(
            &completed.account.authority,
            completed.account.device_id.as_str(),
        );

        crate::views::login::consume_completed_login_pending_store(
            secure_store.as_ref(),
            &crate::secure_key_store::PendingLocalStore::new(completed.account.device_id.clone()),
        )
        .map_err(anyhow::Error::msg)?;

        active_account.set(Some(completed.account.clone()));
        principal_id.set(Some(completed.account.principal_id().clone()));
        device_id.set(completed.account.device_id.to_string());
        crate::app::accept_authenticated_session(
            session,
            session_generation,
            token,
            completed.session_credential().to_owned(),
        );
        needs_device_authorization.set(false);
        device_authorization_check_complete.set(true);
        Ok(())
    }
    .await;
    crate::identity::account_auth::transition::record_onboarding_completion_transition(
        completed.origin,
        if result.is_ok() {
            crate::identity::account_auth::transition::OnboardingCompletionOutcome::Committed
        } else {
            crate::identity::account_auth::transition::OnboardingCompletionOutcome::Failed
        },
        if result.is_ok() {
            "completed_account_committed"
        } else {
            "completed_account_commit_failed"
        },
        &correlation,
        None,
    );
    result
}
