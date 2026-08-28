//! Account-first identity setup.
//!
//! The user-facing flow intentionally hides the handoff lease, DID inception,
//! PCR genesis, and recovery-material gate. Those protocol stages remain
//! durable and resumable, but the page presents only three user decisions:
//! choose an identity, save its Recovery Key, and finish.

use dioxus::prelude::*;
use dioxus_router::Link;
use dioxus_router::hooks::use_navigator;

use crate::components::QrSharePanel;
use crate::recovery_crypto::{RecoveryKeyConfirmationDiff, recovery_key_confirmation_diff};
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

const CURRENT_DEPLOYMENT_HUMAN_ANCHOR_METHOD: &str = "did:webvh";

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
    DeviceSetupRequired,
    /// A durable identity draft that nothing on this device can finish. It is
    /// shown as a dead end with an explicit way out, never as a Recovery Key
    /// prompt: asking for 24 words that cannot be used is indistinguishable
    /// from a bug, and it locks a *new* account out of its own setup.
    StaleCheckpoint,
    /// Coauth returned a state that contradicts its own lease payload. The UI
    /// must not guess a recovery path from local fields in this condition.
    ServerStateConflict,
    /// No onboarding work is pending on this device.
    AccountSummary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ServerReconciliationStatus {
    Loading,
    Ready,
    Failed(String),
}

/// Where the Recovery Key used by this mounted creation surface came from.
///
/// This is deliberately a mount-scoped fact, not a projection of the latest
/// server phase. During a first creation the server can advance from `active`
/// to `reserved` while the generated key is still safely held in this
/// component. Reinterpreting that transition as an interrupted setup would
/// replace the first-run confirmation UI with an "existing key" recovery UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryKeySource {
    GeneratedThisMount,
    RecoveredFromSecureStore,
    ExistingReservation,
}

impl RecoveryKeySource {
    fn for_initial_handoff(
        handoff: Option<&crate::state::PendingAccountHandoff>,
        retained_key_available: bool,
    ) -> Self {
        if retained_key_available {
            Self::RecoveredFromSecureStore
        } else if handoff.is_some_and(must_enter_reserved_recovery_key) {
            Self::ExistingReservation
        } else {
            Self::GeneratedThisMount
        }
    }

    const fn requires_existing_key(self) -> bool {
        matches!(self, Self::ExistingReservation)
    }

    const fn was_recovered_from_secure_store(self) -> bool {
        matches!(self, Self::RecoveredFromSecureStore)
    }
}

fn initial_identity_choice(
    handoff: Option<&crate::state::PendingAccountHandoff>,
    retained_key_available: bool,
) -> IdentityChoice {
    if retained_key_available || handoff.is_some_and(must_enter_reserved_recovery_key) {
        IdentityChoice::Create
    } else {
        IdentityChoice::Choose
    }
}

fn load_valid_retained_recovery_key(
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

/// Select the onboarding surface from the Coauth-authored lease state.
///
/// Local checkpoints may satisfy a server-required artifact, but they never
/// select or advance the protocol phase. A contradictory server snapshot is a
/// closed failure rather than an invitation to infer state from local data.
fn onboarding_surface(
    handoff: Option<&crate::state::PendingAccountHandoff>,
    checkpoint: Option<&crate::state::PendingPrincipalRegistration>,
) -> OnboardingSurface {
    if let Some(handoff) = handoff {
        if handoff.bound_principal_id.is_some() {
            return if handoff.lease_id.is_some()
                || handoff.identity_creation_state.is_some()
                || handoff.reserved_identity.is_some()
            {
                OnboardingSurface::ServerStateConflict
            } else if checkpoint.is_some_and(|checkpoint| {
                crate::identity::account_auth::checkpoint_continues_bound_creation(
                    checkpoint, handoff,
                )
            }) {
                OnboardingSurface::IdentityCreation
            } else {
                OnboardingSurface::DeviceSetupRequired
            };
        }
        let Some(server_state) = handoff.identity_creation_state else {
            return if handoff.lease_id.is_some() {
                OnboardingSurface::ServerStateConflict
            } else {
                OnboardingSurface::IdentityCreation
            };
        };
        if server_state.has_reserved_identity() != handoff.reserved_identity.is_some() {
            return OnboardingSurface::ServerStateConflict;
        }
        return match server_state {
            arkret_sdk::IdentityCreationLeaseState::Active
            | arkret_sdk::IdentityCreationLeaseState::Reserved
            | arkret_sdk::IdentityCreationLeaseState::DidPublished
            | arkret_sdk::IdentityCreationLeaseState::PcrAccepted
            | arkret_sdk::IdentityCreationLeaseState::AccountBound => {
                OnboardingSurface::IdentityCreation
            }
            arkret_sdk::IdentityCreationLeaseState::Completed => OnboardingSurface::AccountSummary,
        };
    }

    if checkpoint.is_some() {
        // A local checkpoint without a server handoff is never executable.
        // Re-authentication must obtain a fresh authoritative snapshot before
        // any registration or post-binding step can continue.
        OnboardingSurface::StaleCheckpoint
    } else {
        OnboardingSurface::AccountSummary
    }
}

/// A remembered DID is only an account summary when its authenticated session
/// is present too. The DID is persisted independently, so treating it as proof
/// of a completed account binding makes a signed-out, interrupted setup look
/// successfully finished.
fn account_summary_complete(session_token_present: bool, principal_id: &str) -> bool {
    session_token_present && !principal_id.trim().is_empty()
}

/// A latched creation surface can outlive its durable account handoff while an
/// async completion or reconciliation task is publishing state. That gap must
/// always render an explicit continuation instead of removing the entire main
/// panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissingCreationHandoffSurface {
    Finishing,
    Complete,
    SignInRequired,
}

fn missing_creation_handoff_surface(
    busy: bool,
    session_token_present: bool,
    principal_id: &str,
) -> MissingCreationHandoffSurface {
    if busy {
        MissingCreationHandoffSurface::Finishing
    } else if account_summary_complete(session_token_present, principal_id) {
        MissingCreationHandoffSurface::Complete
    } else {
        MissingCreationHandoffSurface::SignInRequired
    }
}

fn profile_id_for_authority(
    state_store: &crate::state::LocalStateStore,
    authority: &arkret_sdk::PrincipalAuthorityKey,
) -> String {
    state_store
        .known_profile_id_for_authority(authority)
        .unwrap_or_else(|| format!("ak:profile:{}", crate::operation::uuid_v7()))
}

async fn resolve_handoff_active_account(
    handoff: &crate::state::PendingAccountHandoff,
    full_id: &arkret_sdk::DidFullId,
    device_id: arkret_sdk::DeviceId,
    state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<crate::config::ActiveAccountContext> {
    let authority = arkret_sdk::PrincipalAuthorityKey::new(
        arkret_sdk::project_full_id_to_core_id(full_id)?,
        arkret_sdk::DidCoreId::new(handoff.audience.clone())?,
    );
    let profile_id = profile_id_for_authority(&state_store.read(), &authority);
    let server_url = url::Url::parse(&crate::config::normalize_server_url(
        &handoff.principal_server_url,
    ))?;
    let http = crate::transport::TransportClient::unauthenticated(server_url.as_str())?
        .sdk_http_client()?;
    crate::transport::account::resolve_active_account_context(
        &http, profile_id, authority, device_id, server_url,
    )
    .await
}

fn persist_completed_account_config(
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
struct CompletedIdentityCreation {
    account: crate::config::ActiveAccountContext,
    persisted_grant: crate::state::PersistedSessionGrant,
    dpop_device_key: crate::state::DpopDeviceKeyRecord,
    origin: crate::identity::account_auth::transition::OnboardingCompletionOrigin,
    initial_mls_backup_id: Option<String>,
}

impl CompletedIdentityCreation {
    fn session_credential(&self) -> &str {
        &self.persisted_grant.grant_jwt
    }
}

fn onboarding_may_create_account_mls_root(
    origin: crate::identity::account_auth::transition::OnboardingCompletionOrigin,
) -> bool {
    origin
        != crate::identity::account_auth::transition::OnboardingCompletionOrigin::RecoveryCompletion
}

/// Cross the accepted-account storage boundary before writing metadata keyed
/// by that account. Keeping the switch and write in one typed operation makes
/// it impossible for onboarding to leave Recovery Key metadata in the
/// anonymous pre-account namespace.
fn activate_account_and_save_recovery_metadata(
    store: &mut crate::state::LocalStateStore,
    account: &crate::config::ActiveAccountContext,
    recovery_key: &str,
) -> anyhow::Result<()> {
    store.switch_active_account(account)?;
    crate::views::recovery::save_generated_recovery_key_metadata_in_store(
        store,
        account.principal_id(),
        recovery_key,
    )
    .context("save Recovery Key metadata in the accepted account scope")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn commit_completed_account(
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
        .with_principal_id(completed.account.full_id().as_str())
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
                crate::components::mark_mls_recovery_backup_configured(
                    &mut store,
                    completed.account.principal_id(),
                    backup_id,
                );
            }
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
        crate::views::recovery::local_recovery_public_key_result(
            &state_store.read(),
            completed.account.principal_id(),
        )
        .context("verify Recovery Key metadata in the accepted account scope")?;
        crate::event_submit::remember_verified_recovery_gate(
            completed.account.principal_id().as_str(),
            completed.account.device_id.as_str(),
        );

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

/// A server reservation always outranks a local draft when selecting the key
/// entry mode. A full-page authentication callback loses the in-memory key;
/// generating a replacement phrase at that point can never control the
/// already-reserved identity, even when an older local checkpoint still exists.
fn must_enter_reserved_recovery_key(handoff: &crate::state::PendingAccountHandoff) -> bool {
    handoff
        .identity_creation_state
        .is_some_and(arkret_sdk::IdentityCreationLeaseState::has_reserved_identity)
}

#[component]
pub fn OnboardingPanel(
    secure_store_ready: bool,
    token: Signal<String>,
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    account_primary_handle: Signal<String>,
    needs_device_authorization: Signal<bool>,
    device_authorization_check_complete: Signal<bool>,
) -> Element {
    let session_context = crate::app::SessionContext::get();
    let state_store = session_context.state_store;
    if !secure_store_ready {
        return rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                div { class: "event onboarding-card",
                    h2 { "Restoring identity setup" }
                    p { class: "muted", "Reading this account's current server state…" }
                }
            }
        };
    }
    let mut server_reconciliation = use_signal(|| ServerReconciliationStatus::Loading);
    use_effect(move || {
        let should_refresh = state_store
            .peek()
            .pending_account_handoff()
            .is_some_and(|handoff| {
                handoff.retry_after_ms.is_none()
                    && (handoff.lease_id.is_some() || handoff.bound_principal_id.is_some())
            });
        if !should_refresh {
            server_reconciliation.set(ServerReconciliationStatus::Ready);
            return;
        }
        spawn(async move {
            match crate::identity::account_auth::refresh_pending_onboarding(state_store).await {
                Ok(()) => server_reconciliation.set(ServerReconciliationStatus::Ready),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "failed to reconcile onboarding from Account Authority snapshot"
                    );
                    server_reconciliation
                        .set(ServerReconciliationStatus::Failed(format!("{error:#}")));
                }
            }
        });
    });
    // Clone the small status value before rendering. Holding a Signal read
    // guard while the reconciliation task publishes its result causes Dioxus'
    // single-threaded RefCell to panic instead of scheduling a rerender.
    let reconciliation_status = server_reconciliation();
    match &reconciliation_status {
        ServerReconciliationStatus::Loading => {
            return rsx! {
                div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                    div { class: "event onboarding-card",
                        h2 { "Checking identity setup" }
                        p { class: "muted", "Loading the current Account Authority state…" }
                    }
                }
            };
        }
        ServerReconciliationStatus::Failed(error) => {
            return rsx! {
                div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                    div { class: "event onboarding-card onboarding-centered", "data-testid": "onboarding-reconciliation-failed",
                        h2 { "Identity setup could not be refreshed" }
                        p { class: "muted", "No local checkpoint was used to guess a next step." }
                        p { class: "error", "{error}" }
                        Link { class: "primary", to: Route::Login, "Authenticate again" }
                    }
                }
            };
        }
        ServerReconciliationStatus::Ready => {}
    }
    // The durable stages are routing inputs ONLY at mount, and the decision is
    // latched for the lifetime of this mount.
    //
    // Subscribing the parent to the state store made every durable stage write
    // re-route the surface. Latching additionally survives a parent re-render
    // while the single server-authoritative continuation advances, so the
    // component holding the in-memory Recovery Key is not unmounted midway.
    // A real remount first refreshes the server snapshot and validates any
    // retained key before selecting this same continuation again.
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
            let surface = {
                let store = state_store.peek();
                onboarding_surface(
                    store.pending_account_handoff().as_ref(),
                    store.pending_principal_registration().as_ref(),
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
        OnboardingSurface::DeviceSetupRequired => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                DeviceSetupRequired {
                    state_store,
                    token,
                    principal_id,
                    device_id,
                    config_store,
                    needs_device_authorization,
                    device_authorization_check_complete,
                }
            }
        },
        OnboardingSurface::IdentityCreation => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                PendingAccountIdentityCreation {
                    token,
                    principal_id,
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
        OnboardingSurface::ServerStateConflict => rsx! {
            div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                div { class: "event onboarding-card onboarding-centered", "data-testid": "onboarding-server-state-conflict",
                    h2 { "Identity setup state could not be verified" }
                    p { class: "muted",
                        "The Account Authority returned an inconsistent setup checkpoint. Local data was not used to guess the next step."
                    }
                    Link { class: "primary", to: Route::Login, "Authenticate again" }
                }
            }
        },
        OnboardingSurface::AccountSummary => {
            let did = principal_id();
            let did = crate::app::principal_id_owned(did);
            let principal_label = short_protocol_id(&did);
            let complete = account_summary_complete(!token().trim().is_empty(), &did);
            rsx! {
                div { class: "timeline onboarding-flow", "data-testid": "onboarding-panel",
                    div { class: "event onboarding-card onboarding-finished", "data-testid": "account-strand",
                        if !complete {
                            div { class: "onboarding-finish-mark", "aria-hidden": "true", "1" }
                            h2 { "Set up your identity" }
                            p { class: "muted", "Sign in first, then choose whether to create or link an identity." }
                            Link { class: "primary", to: Route::Login, "Sign in" }
                        } else {
                            div { class: "onboarding-finish-mark", "aria-hidden": "true", "✓" }
                            h2 { "You're all set" }
                            p { class: "muted", "Your account is linked to {principal_label}." }
                            Link { class: "primary", to: Route::Dashboard, "Continue" }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct DeviceSetupPairingRequest {
    request_id: arkret_sdk::DevicePairingRequestId,
    pairing_code: arkret_sdk::DevicePairingCode,
    device_id: arkret_sdk::DeviceId,
    deep_link: String,
    target_attestation: arkret_sdk::DevicePairingTargetAttestation,
    pending_key: bool,
}

fn device_pairing_handoff_token(
    request_id: &arkret_sdk::DevicePairingRequestId,
    pairing_code: &arkret_sdk::DevicePairingCode,
) -> anyhow::Result<String> {
    Ok(arkret_sdk::base64url_encode(
        arkret_sdk::canonical::canonical_json_bytes(&serde_json::json!({
            "r": request_id,
            "c": pairing_code,
        }))?,
    ))
}

fn device_pairing_deep_link(
    base_url: &str,
    token: &str,
    challenge_proof: &arkret_sdk::DevicePairingChallengeProof,
    target_attestation: &arkret_sdk::DevicePairingTargetAttestation,
) -> anyhow::Result<String> {
    let proof = arkret_sdk::base64url_encode(arkret_sdk::canonical::canonical_json_bytes(
        challenge_proof,
    )?);
    let attestation = arkret_sdk::base64url_encode(arkret_sdk::canonical::canonical_json_bytes(
        target_attestation,
    )?);
    Ok(format!(
        "{}/_arkret/open/device-pairing/resolve#token={token}&proof={proof}&attestation={attestation}",
        base_url.trim_end_matches('/'),
    ))
}

async fn stage_device_setup_pairing(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<DeviceSetupPairingRequest> {
    let full_id = handoff
        .bound_principal_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("bound account principal is missing"))?;
    let principal_id = arkret_sdk::project_full_id_to_core_id(&full_id)?;
    let principal_server_id = arkret_sdk::DidCoreId::new(handoff.audience.clone())?;
    let authority =
        arkret_sdk::PrincipalAuthorityKey::new(principal_id.clone(), principal_server_id);
    let handoff_device = arkret_sdk::DeviceId::new(handoff.device_id.clone())?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let user_store =
        crate::secure_key_store::UserLocalStore::new(authority.clone(), handoff_device.clone())?;
    let retained = user_store
        .load_device_id(secure_store.as_ref())?
        .zip(user_store.load_signing_seed(secure_store.as_ref())?);
    let (target_device, signing_seed, pending_key) = if let Some((device, material)) = retained {
        (device, material.seed, false)
    } else {
        let pending_store = crate::secure_key_store::PendingLocalStore::new(handoff_device.clone());
        pending_store.activate();
        let material = pending_store
            .create_fresh_signing_seed_durable(secure_store.as_ref())
            .await?;
        (handoff_device, material.seed, true)
    };
    crate::event_signer::activate_device_signer_from_seed_for_device(
        signing_seed,
        Some(secure_store.as_ref()),
        Some(target_device.as_str()),
    )?;
    let signer = crate::event_signer::bind_active_signer_device_id(target_device.as_str())?
        .ok_or_else(|| anyhow::anyhow!("the target device signer is unavailable"))?;
    let public_key = signer
        .public_key_base64url()
        .ok_or_else(|| anyhow::anyhow!("the target device key cannot be exported"))?;
    let mut client_nonce_bytes = [0_u8; 16];
    getrandom::fill(&mut client_nonce_bytes)
        .map_err(|error| anyhow::anyhow!("generate device-pairing nonce: {error}"))?;
    let client_nonce =
        arkret_sdk::DevicePairingNonce::new(arkret_sdk::base64url_encode(client_nonce_bytes))
            .map_err(anyhow::Error::msg)?;
    let stage_body = arkret_sdk::DevicePairingStageRequestBody {
        new_device_pubkey: arkret_sdk::PublicKey {
            kty: arkret_sdk::NonEmptyString::new("OKP".to_owned()).map_err(anyhow::Error::msg)?,
            kid: arkret_sdk::NonEmptyString::new(target_device.to_string())
                .map_err(anyhow::Error::msg)?,
            algorithm: arkret_sdk::NonEmptyString::new("Ed25519".to_owned())
                .map_err(anyhow::Error::msg)?,
            key: arkret_sdk::Base64UrlString::new(public_key.to_owned())
                .map_err(anyhow::Error::msg)?,
            key_digest: None,
        },
        client_nonce: client_nonce.clone(),
        display_name: Some(
            arkret_sdk::NonEmptyString::new("New browser".to_owned())
                .map_err(anyhow::Error::msg)?,
        ),
        device_metadata: Some(arkret_sdk::DeviceMetadata {
            platform: Some(
                arkret_sdk::NonEmptyString::new("browser".to_owned())
                    .map_err(anyhow::Error::msg)?,
            ),
            ..Default::default()
        }),
    };
    let http = crate::transport::TransportClient::unauthenticated(&handoff.principal_server_url)?
        .sdk_http_client()?;
    let stage = http.device_pairing_stage(&stage_body).await?;
    let challenge =
        arkret_sdk::signatures::device_pairing::ServerDevicePairingChallenge::from_stage(
            client_nonce,
            &stage,
        );
    let (challenge_bytes, transcript_digest) =
        arkret_sdk::signatures::device_pairing::server_device_pairing_transcript(
            &stage_body.new_device_pubkey,
            &challenge,
        )?;
    let challenge_proof = arkret_sdk::DevicePairingChallengeProof {
        transcript: arkret_sdk::DevicePairingChallengeTranscriptKind::ServerMediated,
        kid: target_device.clone(),
        signature_algorithm: arkret_sdk::NonEmptyString::new(signer.algorithm().to_owned())
            .map_err(anyhow::Error::msg)?,
        transcript_digest: transcript_digest.clone(),
        signature: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
            signer.sign_raw(&challenge_bytes)?,
        ))
        .map_err(anyhow::Error::msg)?,
    };
    let target_attestation = crate::identity::device_pairing::sign_target_attestation(
        &signer,
        &authority,
        &target_device,
        transcript_digest,
    )
    .await?;
    let token =
        device_pairing_handoff_token(&stage.device_pairing_request_id, &stage.pairing_code)?;
    let deep_link = device_pairing_deep_link(
        &handoff.principal_server_url,
        &token,
        &challenge_proof,
        &target_attestation,
    )?;
    Ok(DeviceSetupPairingRequest {
        request_id: stage.device_pairing_request_id,
        pairing_code: stage.pairing_code,
        device_id: target_device,
        deep_link,
        target_attestation,
        pending_key,
    })
}

async fn check_device_setup_pairing(
    handoff: &crate::state::PendingAccountHandoff,
    request: &DeviceSetupPairingRequest,
) -> anyhow::Result<arkret_sdk::DevicePairingState> {
    let full_id = handoff
        .bound_principal_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("bound account principal is missing"))?;
    let http = crate::transport::TransportClient::unauthenticated(&handoff.principal_server_url)?
        .sdk_http_client()?;
    let outcome = http
        .device_pairing_status(&arkret_sdk::DevicePairingStatusRequestBody {
            device_pairing_request_id: request.request_id.clone(),
            pairing_code: request.pairing_code.clone(),
        })
        .await?;
    if outcome.state != arkret_sdk::DevicePairingState::Authorized {
        return Ok(outcome.state);
    }
    crate::identity::device_pairing::verify_authorized_pairing_event(
        &http,
        &full_id,
        &outcome,
        &request.target_attestation,
    )
    .await?;
    if request.pending_key {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let pending = crate::secure_key_store::PendingLocalStore::new(request.device_id.clone());
        let authority = arkret_sdk::PrincipalAuthorityKey::new(
            arkret_sdk::project_full_id_to_core_id(&full_id)?,
            arkret_sdk::DidCoreId::new(handoff.audience.clone())?,
        );
        let user =
            crate::secure_key_store::UserLocalStore::new(authority, request.device_id.clone())?;
        pending
            .copy_to_durable(secure_store.as_ref(), &user)
            .await?;
        let promoted_device = user
            .load_device_id(secure_store.as_ref())?
            .ok_or_else(|| anyhow::anyhow!("authorized device was not retained"))?;
        if promoted_device != request.device_id {
            anyhow::bail!("another local device identity occupies this account namespace");
        }
    }
    crate::event_signer::bind_active_signer_principal_device_id(
        &full_id,
        request.device_id.as_str(),
    )?;
    Ok(outcome.state)
}

#[component]
fn DeviceSetupRequired(
    state_store: SyncSignal<crate::state::LocalStateStore>,
    token: Signal<String>,
    mut principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    mut device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    needs_device_authorization: Signal<bool>,
    device_authorization_check_complete: Signal<bool>,
) -> Element {
    let mut recovery_selected = use_signal(|| false);
    let mut pairing_request = use_signal(|| None::<DeviceSetupPairingRequest>);
    let mut pairing_status = use_signal(String::new);
    let mut pairing_busy = use_signal(|| false);
    let handoff = state_store.read().pending_account_handoff();
    let recovery_device_id = handoff
        .as_ref()
        .map(|handoff| handoff.device_id.clone())
        .unwrap_or_default();
    if recovery_selected() {
        return rsx! {
            PcrPolicyDeviceRecovery {
                state_store,
                token,
                principal_id,
                device_id,
                config_store,
                replacement_device_id: recovery_device_id,
                needs_device_authorization,
                device_authorization_check_complete,
            }
        };
    }
    let request = pairing_request.read().clone();
    let qr_svg = request.as_ref().map_or_else(String::new, |request| {
        qrcode::QrCode::with_error_correction_level(
            request.deep_link.as_bytes(),
            qrcode::EcLevel::M,
        )
        .map(|code| {
            code.render::<qrcode::render::svg::Color<'_>>()
                .min_dimensions(192, 192)
                .quiet_zone(true)
                .build()
        })
        .unwrap_or_default()
    });
    rsx! {
        div { class: "event onboarding-card", "data-testid": "device-setup-required",
            h2 { "Authorize this device" }
            p { class: "muted",
                "This account is already linked, but this browser has no currently accepted device key. Create an approval request and scan it from an authorized device."
            }
            p { class: "muted",
                "The account login alone cannot authorize a new device. No session was issued."
            }
            if handoff.as_ref().is_some_and(|handoff| handoff.bound_principal_id.is_some()) {
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "device-setup-pairing-start",
                    disabled: pairing_busy(),
                    onclick: move |_| {
                        let Some(handoff) = state_store.read().pending_account_handoff() else {
                            pairing_status.set("The authenticated account handoff is missing. Sign in again.".to_owned());
                            return;
                        };
                        pairing_busy.set(true);
                        pairing_status.set("Creating a device approval request…".to_owned());
                        spawn(async move {
                            match stage_device_setup_pairing(&handoff).await {
                                Ok(request) => {
                                    pairing_request.set(Some(request));
                                    pairing_status.set(
                                        "Approval request created. Compare the code on your authorized device before approving."
                                            .to_owned(),
                                    );
                                }
                                Err(error) => pairing_status.set(format!(
                                    "Could not create the device approval request: {error}"
                                )),
                            }
                            pairing_busy.set(false);
                        });
                    },
                    if pairing_busy() { "Preparing…" } else { "Request device approval" }
                }
            } else {
                p { class: "error", "The bound-account handoff is incomplete. No device flow was started." }
            }
            if let Some(request) = request {
                div { class: "device-pair-approval-code-block",
                    span { class: "muted", "Compare this code before approving" }
                    span {
                        class: "device-pair-approval-code mono",
                        "data-testid": "device-setup-pairing-code",
                        "{request.pairing_code}"
                    }
                }
                QrSharePanel {
                    qr_svg,
                    url: request.deep_link.clone(),
                    qr_aria_label: "Device approval QR code".to_owned(),
                    url_aria_label: "Device approval link".to_owned(),
                    qr_test_id: "device-setup-pairing-qr".to_owned(),
                    url_test_id: "device-setup-pairing-link".to_owned(),
                    copy_test_id: "device-setup-pairing-copy".to_owned(),
                    url_rows: 4,
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "device-setup-pairing-status",
                    disabled: pairing_busy(),
                    onclick: move |_| {
                        let Some(handoff) = state_store.read().pending_account_handoff() else {
                            pairing_status.set("The authenticated account handoff is missing. Sign in again.".to_owned());
                            return;
                        };
                        let Some(request) = pairing_request.read().clone() else {
                            pairing_status.set("Create an approval request first.".to_owned());
                            return;
                        };
                        pairing_busy.set(true);
                        pairing_status.set("Checking device approval…".to_owned());
                        spawn(async move {
                            match check_device_setup_pairing(&handoff, &request).await {
                                Ok(arkret_sdk::DevicePairingState::Authorized) => {
                                    let principal = handoff
                                        .bound_principal_id
                                        .as_ref()
                                        .and_then(|full_id| {
                                            arkret_sdk::project_full_id_to_core_id(full_id).ok()
                                        });
                                    principal_id.set(principal);
                                    device_id.set(request.device_id.to_string());
                                    pairing_status.set(
                                        "Device authorization is accepted and verified. No session was issued; sign in again to request one."
                                            .to_owned(),
                                    );
                                }
                                Ok(arkret_sdk::DevicePairingState::PendingAuthorization) => {
                                    pairing_status.set(
                                        "Still waiting for explicit approval on an authorized device."
                                            .to_owned(),
                                    );
                                }
                                Ok(arkret_sdk::DevicePairingState::Expired) => {
                                    pairing_request.set(None);
                                    pairing_status.set(
                                        "This approval request expired. Create a new request."
                                            .to_owned(),
                                    );
                                }
                                Err(error) => pairing_status.set(format!(
                                    "Device approval could not be verified: {error}"
                                )),
                            }
                            pairing_busy.set(false);
                        });
                    },
                    if pairing_busy() { "Checking…" } else { "Check approval status" }
                }
            }
            if !pairing_status().is_empty() {
                p { class: "muted", role: "status", "data-testid": "device-setup-status", "{pairing_status}" }
            }
            Link { class: "secondary", to: Route::Login, "Sign in again after approval" }
            Button {
                variant: ButtonVariant::Ghost,
                "data-testid": "device-setup-use-recovery-key",
                onclick: move |_| {
                    // The 24-word surface opens only from this explicit
                    // secondary choice, and only after the bound handoff
                    // already reached a typed admission outcome.
                    let handoff = state_store.read().pending_account_handoff();
                    let (correlation, bound) = handoff.as_ref().map_or_else(
                        || {
                            (
                                crate::identity::account_auth::transition::LoginCorrelation::default(),
                                false,
                            )
                        },
                        |handoff| {
                            (
                                crate::identity::account_auth::transition::LoginCorrelation::for_handoff(handoff),
                                handoff.bound_principal_id.is_some(),
                            )
                        },
                    );
                    if crate::identity::account_auth::transition::record_recovery_surface_opened(
                        crate::identity::account_auth::transition::RecoveryEntryReason::UserSelectedInDeviceSetup,
                        &correlation,
                        bound,
                    ) {
                        recovery_selected.set(true);
                    } else {
                        pairing_status.set(
                            "This account's sign-in has no authoritative device decision yet, so Recovery Key entry stays closed. Sign in again and retry device approval."
                                .to_owned(),
                        );
                    }
                },
                "Use Recovery Key instead"
            }
        }
    }
}

#[component]
fn PcrPolicyDeviceRecovery(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    mut token: Signal<String>,
    mut principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    mut device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    replacement_device_id: String,
    mut needs_device_authorization: Signal<bool>,
    mut device_authorization_check_complete: Signal<bool>,
) -> Element {
    let session_context = crate::app::SessionContext::get();
    let active_account = session_context.active_account;
    let session_generation = session_context.session_generation;
    let completion_session = use_context::<crate::runtime::services::RuntimeServices>()
        .session
        .clone();
    let mut words = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut busy = use_signal(|| false);
    rsx! {
        div { class: "event onboarding-card", "data-testid": "pcr-policy-device-recovery",
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
                    let Some(principal_full_id) = handoff.bound_principal_id.clone() else {
                        status.set("This account does not require existing-identity recovery.".to_owned());
                        return;
                    };
                    let recovery_words = words();
                    let replacement_device_id = replacement_device_id.clone();
                    let session = completion_session.clone();
                    busy.set(true);
                    status.set("Verifying Recovery Key and preparing a PCR-policy device recovery…".to_owned());
                    spawn(async move {
                        let result = recover_bound_principal_device(
                            &handoff,
                            &principal_full_id,
                            &replacement_device_id,
                            &recovery_words,
                            state_store,
                        )
                        .await;
                        words.set(String::new());
                        busy.set(false);
                        match result {
                            Ok((recovery, completed)) => {
                                match commit_completed_account(
                                    &completed,
                                    &recovery_words,
                                    state_store,
                                    config_store,
                                    active_account,
                                    token,
                                    &session,
                                    session_generation,
                                    principal_id,
                                    device_id,
                                    needs_device_authorization,
                                    device_authorization_check_complete,
                                )
                                .await
                                {
                                    Ok(()) => match clear_pending_principal_setup(state_store).await {
                                        Ok(()) => status.set(format!(
                                            "Identity recovered. Device receipt {} and the Standard session grant are durable.",
                                            recovery.readiness.terminal_receipt_id
                                        )),
                                        Err(error) => status.set(format!(
                                            "Identity recovered, but local cleanup failed: {error:#}"
                                        )),
                                    },
                                    Err(error) => status.set(format!(
                                        "Recovered device could not be committed: {error:#}"
                                    )),
                                }
                            }
                            Err(error) => status.set(format!("Recovery could not finish: {error:#}")),
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
    principal_id: &arkret_sdk::DidFullId,
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
        principal_id,
        replacement_device_id,
    )?;
    let api = issue_recovery_session_transport(handoff, state_store).await?;
    if let Some(mut completed) = crate::mls::account_recovery::resume_pending_pcr_policy_recovery(
        &api,
        state_store,
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
            principal_authority: arkret_sdk::PrincipalAuthorityKey::new(
                arkret_sdk::project_full_id_to_core_id(principal_id)?,
                crate::operation::authoring_principal_server_id()?,
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
        state_store,
        principal_id,
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

async fn issue_recovery_session_transport(
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
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &handoff.gate_account_base,
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
            principal_id: arkret_sdk::project_full_id_to_core_id(principal_id)?,
            device_id: arkret_sdk::DeviceId::new(handoff.device_id.clone())?,
            audience: arkret_sdk::DidCoreId::new(handoff.audience.clone())?,
        });
    request.validate()?;
    let outcome = account_http.auth_issue_session_grant(&request).await?;
    let expected_session_public_key = holder.canonical_session_public_jwk()?;
    let expected_granted_scope = arkret_sdk::RECOVERY_SESSION_GRANT_OPERATIONS
        .iter()
        .map(|operation| (*operation).to_owned())
        .collect::<Vec<_>>();
    if outcome.principal_id != arkret_sdk::project_full_id_to_core_id(principal_id)?
        || outcome.device_id.as_ref().map(arkret_sdk::DeviceId::as_str)
            != Some(handoff.device_id.as_str())
        || outcome.audience.as_str() != handoff.audience
        || outcome.session_public_key != expected_session_public_key
        || outcome.expires_at > handoff.expires_at
        || outcome.granted_scope != expected_granted_scope
        || outcome.scope_details.is_some()
    {
        anyhow::bail!("recovery SessionGrant outcome changed its frozen authority binding");
    }
    crate::transport::TransportClient::unauthenticated(&handoff.principal_server_url)?
        .with_session_grant_dpop(outcome.session_grant, holder)
}

async fn activate_recovery_replacement_signer(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<()> {
    let full_id = handoff
        .bound_principal_id
        .as_ref()
        .context("bound recovery handoff has no principal")?;
    let authority = arkret_sdk::PrincipalAuthorityKey::new(
        arkret_sdk::project_full_id_to_core_id(full_id)?,
        arkret_sdk::DidCoreId::new(handoff.audience.clone())?,
    );
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

async fn issue_recovery_completion_grant(
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
            let initial_session = arkret_sdk::InitialSessionGrantIntent {
                device_id: arkret_sdk::DeviceId::new(handoff.device_id.clone())?,
                session_public_key: holder.canonical_session_public_jwk()?,
                audience: arkret_sdk::DidCoreId::new(handoff.audience.clone())?,
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
    let principal_core_id = arkret_sdk::project_full_id_to_core_id(&principal_id)?;
    if session.principal_id != principal_core_id {
        anyhow::bail!("recovery session grant principal does not match the account handoff");
    }
    let persisted = crate::state::PersistedSessionGrant {
        grant_jwt: session.grant_jwt.clone(),
        session_private_key_pem: holder.session_signing_key_pkcs8_pem()?.to_string(),
        grant_id: session.grant_id.to_string(),
        audience: session.audience.to_string(),
        principal_id: session.principal_id.clone(),
        device_id: arkret_sdk::DeviceId::new(handoff.device_id.clone())?,
        principal_server_url: url::Url::parse(&handoff.principal_server_url)?,
        grant_expires_at: Some(session.expires_at),
        stored_at: chrono::Utc::now(),
    };
    let dpop_record = crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
        holder.seed_b64().as_str(),
    )?;
    let account = resolve_handoff_active_account(
        handoff,
        &principal_id,
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

struct RestoredAcceptedAccountRuntime {
    persisted_grant: crate::state::PersistedSessionGrant,
    dpop_device_key: crate::state::DpopDeviceKeyRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumeTerminalKind {
    HydrationFailed,
    RetryableFailure,
    ReauthRequired,
    StrandedIdentity,
    Contradiction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResumeTerminal {
    kind: ResumeTerminalKind,
    reason: String,
    inventory: Vec<String>,
}

enum IdentityCreationCommandOutcome {
    Completed(Box<CompletedIdentityCreation>),
    Terminal(ResumeTerminal),
}

struct BoundCompletionResumeInventory {
    facts: garth::BoundCompletionResumeFacts,
    read_errors: Vec<String>,
}

impl BoundCompletionResumeInventory {
    fn checklist(&self) -> Vec<String> {
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

fn observe_resume_material<T, E: std::fmt::Display>(
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

fn accepted_account_session_client(
    account: &crate::config::ActiveAccountContext,
    expected_holder_jkt: &str,
    grant: &crate::state::PersistedSessionGrant,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<crate::transport::TransportClient> {
    if !crate::identity::session_refresh::grant_matches_principal_server(
        grant,
        account.server_url.as_str(),
    ) || !crate::identity::session_refresh::grant_matches_full_principal(
        grant,
        account.full_id(),
    ) || grant.device_id != account.device_id
        || grant.audience != account.authority.principal_server_id.as_str()
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

fn accepted_account_session_client_from_secure_store(
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

async fn collect_bound_completion_resume_inventory(
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
    let authority_matches = arkret_sdk::project_full_id_to_core_id(&checkpoint.full_id)
        .is_ok_and(|principal_id| principal_id == account.authority.principal_id)
        && arkret_sdk::DidCoreId::new(handoff.audience.clone())
            .is_ok_and(|server_id| server_id == account.authority.principal_server_id)
        && handoff.bound_principal_id.as_ref() == Some(&checkpoint.full_id);
    let device_slot_matches = stored_device_id
        .as_ref()
        .is_none_or(|device_id| device_id == &account.device_id);
    let grant_matches_account = session_grant.as_ref().is_some_and(|grant| {
        crate::identity::session_refresh::grant_matches_principal_server(
            grant,
            account.server_url.as_str(),
        ) && crate::identity::session_refresh::grant_matches_full_principal(
            grant,
            account.full_id(),
        ) && grant.device_id == account.device_id
            && grant.audience == account.authority.principal_server_id.as_str()
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
enum AcceptedSessionReissueError {
    Retryable(anyhow::Error),
    ReauthRequired(anyhow::Error),
    Contradiction(anyhow::Error),
}

fn load_bound_handoff_holder_key(
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

async fn reissue_accepted_onboarding_session(
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
        crate::identity::account_auth::AuthorityResolver::discover(&handoff.principal_server_url)
            .await
            .map_err(|error| {
                AcceptedSessionReissueError::Retryable(
                    anyhow::anyhow!(error).context("discover the Account Authority route"),
                )
            })?;
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &authority.gate_account_base,
    )
    .map_err(|error| AcceptedSessionReissueError::Contradiction(anyhow::anyhow!(error)))?;
    let mut correlation =
        crate::identity::account_auth::transition::LoginCorrelation::for_handoff(handoff)
            .with_principal_id(account.full_id().as_str())
            .with_device_id(account.device_id.as_str());
    let issued = crate::views::login::issue_bound_handoff_session(
        &handoff.principal_server_url,
        &account_base,
        handoff,
        &handoff_grant,
        account.authority.principal_id.clone(),
        account.full_id().clone(),
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
    if issued.account.full_id() != account.full_id()
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

fn restore_accepted_account_runtime(
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

fn restore_accepted_account_runtime_with_secure_store(
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
            account.full_id(),
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
    mut principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    mut device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
    account_primary_handle: Signal<String>,
    mut needs_device_authorization: Signal<bool>,
    mut device_authorization_check_complete: Signal<bool>,
) -> Element {
    let session_context = crate::app::SessionContext::get();
    let active_account = session_context.active_account;
    let mut state_store = session_context.state_store;
    let session_generation = session_context.session_generation;
    let completion_session = use_context::<crate::runtime::services::RuntimeServices>()
        .session
        .clone();
    let initial_handoff = state_store.peek().pending_account_handoff();
    let initial_checkpoint = state_store.peek().pending_principal_registration();
    let initial_recovery_key = initial_handoff
        .as_ref()
        .and_then(|handoff| load_valid_retained_recovery_key(handoff, initial_checkpoint.as_ref()));
    let initial_key_source = RecoveryKeySource::for_initial_handoff(
        initial_handoff.as_ref(),
        initial_recovery_key.is_some(),
    );
    let initial_recovery_key_state = if initial_recovery_key.is_some() {
        arkret_sdk::IdentityCreationRecoveryKeyState::RecoveredPendingConfirmation
    } else {
        arkret_sdk::IdentityCreationRecoveryKeyState::Unavailable
    };
    let navigator = use_navigator();
    let initial_choice =
        initial_identity_choice(initial_handoff.as_ref(), initial_recovery_key.is_some());
    let mut choice = use_signal(move || initial_choice);
    let mut recovery_key = use_signal(|| initial_recovery_key.unwrap_or_default());
    let mut recovery_key_state = use_signal(|| initial_recovery_key_state);
    let mut confirmation = use_signal(String::new);
    let mut copied = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut complete = use_signal(|| false);
    let mut status = use_signal(String::new);
    let mut resume_terminal = use_signal(|| None::<ResumeTerminal>);
    // Never derive this from a later server phase in this mount. The server
    // remains authoritative for protocol progress; this signal only records
    // whether the in-memory key was generated here or must be supplied after
    // an actual reload/restart.
    let key_source = use_signal(|| initial_key_source);

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

    if let Some(terminal) = resume_terminal() {
        let heading = match terminal.kind {
            ResumeTerminalKind::HydrationFailed => "Setup state could not be read",
            ResumeTerminalKind::RetryableFailure => "Setup continuation did not finish",
            ResumeTerminalKind::ReauthRequired => "Setup needs authentication",
            ResumeTerminalKind::StrandedIdentity => "This accepted identity cannot continue here",
            ResumeTerminalKind::Contradiction => "Setup state is inconsistent",
        };
        let can_retry = matches!(
            terminal.kind,
            ResumeTerminalKind::HydrationFailed | ResumeTerminalKind::RetryableFailure
        );
        let can_clear = matches!(
            terminal.kind,
            ResumeTerminalKind::StrandedIdentity | ResumeTerminalKind::Contradiction
        );
        return rsx! {
            div {
                class: "event onboarding-card onboarding-centered",
                "data-testid": "onboarding-resume-diagnostics",
                h2 { "{heading}" }
                p { class: "muted", "{terminal.reason}" }
                ul { class: "muted", "data-testid": "onboarding-resume-inventory",
                    for item in terminal.inventory.iter() {
                        li { "{item}" }
                    }
                }
                div { class: "onboarding-footer-actions",
                    if can_retry {
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "retry-onboarding-resume",
                            onclick: move |_| {
                                resume_terminal.set(None);
                                status.set(String::new());
                            },
                            if terminal.kind == ResumeTerminalKind::HydrationFailed {
                                "Retry storage check"
                            } else {
                                "Retry exact continuation"
                            }
                        }
                    }
                    if terminal.kind == ResumeTerminalKind::ReauthRequired {
                        Link { class: "primary", to: Route::Login, "Sign in again" }
                    }
                    if can_clear {
                        Link { class: "secondary", to: Route::Login, "Sign in another account" }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "clear-stranded-onboarding",
                            disabled: busy(),
                            onclick: move |_| {
                                let navigator = navigator;
                                busy.set(true);
                                spawn(async move {
                                    match clear_pending_principal_setup(state_store).await {
                                        Ok(()) => {
                                            navigator.push(Route::Login);
                                        }
                                        Err(error) => status.set(format!(
                                            "Could not clear this setup: {error:#}"
                                        )),
                                    }
                                    busy.set(false);
                                });
                            },
                            if terminal.kind == ResumeTerminalKind::StrandedIdentity {
                                "Abandon this setup and register a new identity"
                            } else {
                                "Clear this setup"
                            }
                        }
                    }
                }
                if !status().is_empty() {
                    div { class: "form-hint-warn", role: "status", "{status}" }
                }
            }
        };
    }

    let handoff = state_store.read().pending_account_handoff();

    let Some(handoff) = handoff else {
        let did = principal_id();
        let did = crate::app::principal_id_owned(did);
        let fallback = missing_creation_handoff_surface(busy(), !token().trim().is_empty(), &did);
        let current_status = status();
        return rsx! {
            div {
                class: "event onboarding-card onboarding-centered",
                "data-testid": "onboarding-missing-account-handoff",
                match fallback {
                    MissingCreationHandoffSurface::Finishing => rsx! {
                        SetupProgress { current: 3 }
                        h2 { "Finishing identity setup" }
                        p { class: "muted", "The account binding was accepted. Inkson is finishing the local recovery and session records…" }
                        if !current_status.is_empty() {
                            div { class: "muted", role: "status", "{current_status}" }
                        }
                    },
                    MissingCreationHandoffSurface::Complete => rsx! {
                        SetupProgress { current: 3 }
                        div { class: "onboarding-finished", "data-testid": "onboarding-complete",
                            div { class: "onboarding-finish-mark", "aria-hidden": "true", "✓" }
                            h2 { "Identity ready" }
                            p { class: "muted", "Your account, this device, and recovery backup are ready." }
                            Link { class: "primary", to: Route::Dashboard, "Continue" }
                        }
                    },
                    MissingCreationHandoffSurface::SignInRequired => rsx! {
                        h2 { "Identity setup needs authentication" }
                        p { class: "muted", "The previous account handoff is no longer available. Sign in again so Inkson can resume from the current Account Authority state." }
                        if !current_status.is_empty() {
                            div { class: "form-hint-warn", role: "status", "{current_status}" }
                        }
                        Link { class: "primary", to: Route::Login, "Sign in again" }
                    },
                }
            }
        };
    };
    let pending_abandonment = handoff.identity_abandonment.clone().or_else(|| {
        state_store
            .read()
            .pending_principal_registration()
            .and_then(|checkpoint| checkpoint.identity_abandonment)
    });
    let abandonment_challenge_expired = pending_abandonment
        .as_ref()
        .is_some_and(|pending| pending.challenge.expires_at <= chrono::Utc::now());
    let abandonment_confirmation_ready = pending_abandonment.as_ref().is_some_and(|pending| {
        crate::identity::identity_abandonment::has_fresh_confirmation_handoff(&handoff, pending)
    });

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
                p { class: "muted", "Sign in again so Inkson can recalculate the flow from the current server state. A matching Recovery Key retained in this device's secure store will be re-confirmed; otherwise Inkson will ask for the original key or offer explicit abandonment." }
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
    let resumes_reserved_identity = key_source.peek().requires_existing_key();
    let reoffers_retained_key = key_source.peek().was_recovered_from_secure_store();
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
                                let Some(mut handoff) = state_store.read().pending_account_handoff() else {
                                    status.set("Authenticate the account again before renewing the abandonment challenge.".to_owned());
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
                                            &dpop,
                                        ).await?;
                                        handoff.identity_abandonment = Some(pending);
                                        let barrier = {
                                            let mut store = state_store.write();
                                            store.set_pending_account_handoff(Some(handoff.clone()))?;
                                            store.begin_durable_flush()?
                                        };
                                        barrier.wait().await?;
                                        crate::identity::account_auth::clear_account_handoff_grant(&handoff)
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
                            disabled: busy() || !abandonment_confirmation_ready,
                            onclick: move |_| {
                                let Some(handoff) = state_store.read().pending_account_handoff() else {
                                    status.set("Authenticate the account again before confirming abandonment.".to_owned());
                                    return;
                                };
                                let pending = pending_abandonment.clone();
                                let navigator = navigator;
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
                    if resumes_reserved_identity {
                        h2 { "An identity reservation is unfinished" }
                        p { class: "muted", "The server has an unfinished identity reservation. That does not mean Inkson knows you saved its Recovery Key. Enter the original key if you still have it, or explicitly abandon this reservation before creating another identity." }
                    } else {
                        h2 { "Set up your identity" }
                        p { class: "muted", "Inkson creates one identity for this account and authorizes this device as its first device." }
                    }
                }

                div { class: "identity-choice-grid", role: "group", "aria-label": "Identity setup",
                    section { class: "identity-choice-card is-recommended",
                        if resumes_reserved_identity {
                            h3 { "Verify the original Recovery Key" }
                            p { "The reserved identity is hosted with {hosting_name}. Inkson does not infer key possession from the reservation; it will verify the original key locally before continuing." }
                        } else {
                            h3 { "Create your identity" }
                            p { "It will be anchored by a Recovery Key and hosted with {hosting_name}. No device approval step is needed." }
                            p { class: "muted", "This deployment creates a {CURRENT_DEPLOYMENT_HUMAN_ANCHOR_METHOD} identity. Arkret also permits did:web and did:key human anchors in deployments that support them; they are not registration options here." }
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "choose-new-identity",
                            onclick: move |_| {
                                choice.set(IdentityChoice::Create);
                                if !resumes_reserved_identity && recovery_key().is_empty() {
                                    match crate::recovery_crypto::generate_recovery_key() {
                                        Ok(key) => {
                                            recovery_key.set(key);
                                            recovery_key_state.set(
                                                arkret_sdk::IdentityCreationRecoveryKeyState::GeneratedPendingConfirmation,
                                            );
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
                            if resumes_reserved_identity { "Enter existing key" } else { "Continue" }
                        }
                    }
                }
                if !status().is_empty() {
                    div { class: "form-hint-warn", role: "alert", "{status}" }
                }
            } else {
                div { class: "onboarding-heading",
                    if resumes_reserved_identity {
                        h2 { "Enter your existing Recovery Key" }
                        p { class: "muted", "Inkson cannot replace the key that controls this reserved identity. If it is lost, use the explicit abandonment action below." }
                    } else if reoffers_retained_key {
                        h2 { "Re-confirm your Recovery Key" }
                        p { class: "muted", "This device securely retained the same 24 words from the unfinished setup. Re-confirm them before continuing; their presence here does not mean Inkson assumes you memorized or backed them up." }
                    } else {
                        h2 { "Save your Recovery Key" }
                        p { class: "muted", "Write down these 24 words in order. They will not be shown again." }
                    }
                }

                if !resumes_reserved_identity {
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
                }

                div { class: "workflow-form onboarding-confirmation",
                    Label { html_for: "onboarding-recovery-key-confirm",
                        if resumes_reserved_identity { "Existing 24 words" } else { "Re-enter the 24 words" }
                    }
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
                            if !resumes_reserved_identity {
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
                            }

                            let handoff = handoff_for_creation.clone();
                            let supplied_key = if resumes_reserved_identity {
                                confirmation()
                            } else {
                                recovery_key()
                            };
                            let device = handoff.device_id.clone();
                            let session = completion_session.clone();
                            busy.set(true);
                            status.set("Finishing setup…".to_owned());
                            spawn(async move {
                                let result = async {
                                    if resumes_reserved_identity {
                                        crate::identity::principal_registration::validate_reserved_identity_recovery_key(
                                            &handoff,
                                            &supplied_key,
                                        )?;
                                    }
                                    crate::identity::account_auth::persist_pending_identity_creation_recovery_key(
                                        &handoff,
                                        &supplied_key,
                                    )
                                    .await?;
                                    let confirmed_state = if resumes_reserved_identity {
                                        arkret_sdk::IdentityCreationRecoveryKeyState::ExistingValidatedDurable
                                    } else {
                                        arkret_sdk::IdentityCreationRecoveryKeyState::GeneratedLocallyValidatedDurable
                                    };
                                    recovery_key_state.set(confirmed_state);
                                    if !confirmed_state.can_control_identity() {
                                        anyhow::bail!("Recovery Key is not ready for identity creation");
                                    }
                                    create_and_bind_identity(
                                        &handoff,
                                        &supplied_key,
                                        &device,
                                        state_store,
                                        status,
                                    )
                                    .await
                                }
                                .await;

                                match result {
                                    Ok(IdentityCreationCommandOutcome::Completed(completed)) => {
                                        if let Err(error) = commit_completed_account(
                                            &completed,
                                            &supplied_key,
                                            state_store,
                                            config_store,
                                            active_account,
                                            token,
                                            &session,
                                            session_generation,
                                            principal_id,
                                            device_id,
                                            needs_device_authorization,
                                            device_authorization_check_complete,
                                        )
                                        .await
                                        {
                                            status.set(format!(
                                                "Account completion could not be committed: {error:#}"
                                            ));
                                            busy.set(false);
                                            return;
                                        }
                                        recovery_key.set(String::new());
                                        recovery_key_state.set(
                                            arkret_sdk::IdentityCreationRecoveryKeyState::Unavailable,
                                        );
                                        confirmation.set(String::new());
                                        status.set(String::new());
                                        complete.set(true);
                                        if let Err(error) = clear_pending_principal_setup(state_store).await {
                                            status.set(format!(
                                                "Setup finished, but local cleanup failed: {error:#}"
                                            ));
                                        }
                                    }
                                    Ok(IdentityCreationCommandOutcome::Terminal(terminal)) => {
                                        status.set(String::new());
                                        resume_terminal.set(Some(terminal));
                                    }
                                    Err(error) => {
                                        let seal_replay_contradiction = error
                                            .downcast_ref::<BootstrapSealReplayContradiction>()
                                            .is_some();
                                        let command_error = format!("{error:#}");
                                        let correlation = crate::identity::account_auth::transition::LoginCorrelation::for_handoff(&handoff);
                                        crate::identity::account_auth::transition::record_onboarding_completion_transition(
                                            crate::identity::account_auth::transition::OnboardingCompletionOrigin::ResumeRestore,
                                            if seal_replay_contradiction {
                                                crate::identity::account_auth::transition::OnboardingCompletionOutcome::Contradiction
                                            } else {
                                                crate::identity::account_auth::transition::OnboardingCompletionOutcome::Failed
                                            },
                                            if seal_replay_contradiction {
                                                "bootstrap_seal_replay_changed"
                                            } else {
                                                "onboarding_continuation_failed"
                                            },
                                            &correlation,
                                            None,
                                        );
                                        resume_terminal.set(Some(ResumeTerminal {
                                            kind: if seal_replay_contradiction {
                                                ResumeTerminalKind::Contradiction
                                            } else {
                                                ResumeTerminalKind::RetryableFailure
                                            },
                                            reason: command_error,
                                            inventory: Vec::new(),
                                        }));
                                        status.set(String::new());
                                    }
                                }
                                busy.set(false);
                            });
                        },
                        if busy() { "Finishing…" } else if resumes_reserved_identity { "Continue setup" } else { "Save and continue" }
                    }
                    if handoff.reserved_identity.is_some() {
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "issue-identity-abandonment-challenge",
                            disabled: busy(),
                            onclick: move |_| {
                                let mut handoff = handoff_for_abandonment.clone();
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
                                            &dpop,
                                        ).await?;
                                        handoff.identity_abandonment = Some(pending);
                                        let barrier = {
                                            let mut store = state_store.write();
                                            store.set_pending_account_handoff(Some(handoff.clone()))?;
                                            store.begin_durable_flush()?
                                        };
                                        barrier.wait().await?;
                                        crate::identity::account_auth::clear_account_handoff_grant(&handoff)
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
        "This identity is already registered to your account. Sign in to resume it or use the authenticated abandonment flow; deleting only this browser's checkpoint would not abandon the server reservation."
    } else {
        "Nothing has been registered yet. Discarding starts over: sign in again, and this device creates a new identity with a new Recovery Key."
    }
}

/// The way out of an unfinished server reservation this device cannot finish.
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
                                status.set(format!("Could not discard the unfinished setup: {error}"));
                                busy.set(false);
                            }
                        }
                    });
                },
                if busy() { "Discarding…" } else { "Discard unfinished setup" }
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
                    short_protocol_id(checkpoint.full_id.as_str()),
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
                h2 { "This unfinished setup can't be finished here" }
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
                if !binding_registered {
                    DiscardSavedSetup { disabled: false, on_discard }
                }
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

async fn activate_pending_registration_signer(
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
    let principal_id = checkpoint.full_id.clone();
    Ok(
        crate::event_signer::bind_active_signer_principal_device_id(&principal_id, device)?
            .unwrap_or(signer),
    )
}

async fn create_and_bind_identity(
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
            let authority = arkret_sdk::PrincipalAuthorityKey::new(
                arkret_sdk::project_full_id_to_core_id(&checkpoint.full_id)?,
                arkret_sdk::DidCoreId::new(handoff.audience.clone())?,
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
            arkret_sdk::DidCoreId::new(handoff.audience.clone())?,
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
                state_store,
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
                    recovery_handoff.bound_principal_id = Some(checkpoint.full_id.clone());
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
                        &checkpoint.full_id,
                        device,
                        recovery_key,
                        state_store,
                    )
                    .await?;
                    return Ok(IdentityCreationCommandOutcome::Completed(Box::new(completed)));
                }
                Err(error) => return Err(error),
            };
        let principal_id = checkpoint.full_id.clone();
        let principal_core_id = arkret_sdk::project_full_id_to_core_id(&principal_id)?;
        if completion.session_grant.principal_id != principal_core_id {
            anyhow::bail!("initial session grant principal does not match the registered identity");
        }
        let grant_jwt = completion.session_grant.grant_jwt.clone();
        let account = resolve_handoff_active_account(
            handoff,
            &principal_id,
            arkret_sdk::DeviceId::new(device.to_owned())?,
            state_store,
        )
        .await?;
        let persisted_grant = crate::state::PersistedSessionGrant {
            grant_jwt: grant_jwt.clone(),
            session_private_key_pem: completion.session_private_key_pem,
            grant_id: completion.session_grant.grant_id.to_string(),
            audience: completion.session_grant.audience.to_string(),
            principal_id: completion.session_grant.principal_id.clone(),
            device_id: arkret_sdk::DeviceId::new(device.to_owned())?,
            principal_server_url: url::Url::parse(&handoff.principal_server_url)?,
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
            &checkpoint.full_id,
            arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?,
            state_store,
        )
        .await?;
        let inventory =
            collect_bound_completion_resume_inventory(handoff, &checkpoint, &account, state_store)
                .await;
        let correlation =
            crate::identity::account_auth::transition::LoginCorrelation::for_handoff(handoff)
                .with_principal_id(account.full_id().as_str())
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
                    &checkpoint.full_id,
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
async fn clear_pending_principal_setup(
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
        let did_operation = checkpoint.did_operation.clone();
        let expected_reservation =
            arkret_sdk::ReservedIdentityCreation::from_operation(did_operation)
                .map_err(|error| anyhow::anyhow!("the saved DID operation is invalid: {error}"))?;
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
enum RecoveryMaterialContinuation {
    SubmitAndPersist,
    FinalizeDurableEvidence,
}

#[derive(Debug)]
struct BootstrapSealReplayContradiction;

impl std::fmt::Display for BootstrapSealReplayContradiction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the bootstrap Seal replay changed after its checkpoint was persisted")
    }
}

impl std::error::Error for BootstrapSealReplayContradiction {}

fn validate_exact_bootstrap_seal_replay<T: serde::Serialize>(
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

fn recovery_material_continuation(
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

fn validate_completed_recovery_material(
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
    let expected_authority = arkret_sdk::PrincipalAuthorityKey::new(
        account.principal_id().clone(),
        receipt.issuer.clone(),
    );
    if evidence.principal_id != *account.full_id()
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

fn finish_pre_account_recovery_checkpoint(
    registration: &crate::state::PendingPrincipalRegistration,
) -> anyhow::Result<()> {
    crate::identity::account_auth::clear_prepared_identity_creation_request_for_checkpoint(
        registration,
    )?;
    Ok(())
}

async fn finish_principal_setup(
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

    if recovery_material_continuation(registration.stage)?
        == RecoveryMaterialContinuation::FinalizeDurableEvidence
    {
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

    let recovery_actor = account.full_id().clone();
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
    crate::recovery_strand::submit_principal_bootstrap_seal(&api, &bootstrap_seal_for_submit)
        .await?;
    crate::recovery_strand::ensure_principal_bootstrap_governance_checkpoint(
        &api,
        &governance_state_store,
        &bootstrap_seal_for_submit,
    )
    .await?;
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
    let principal_id = account.full_id().clone();
    let principal_core_id = account.principal_id().clone();
    let principal_server_id = registration
        .pcr_genesis_receipt
        .as_ref()
        .context("recovery-material evidence omits PCR genesis receipt")?
        .issuer
        .clone();
    let controller_authority =
        arkret_sdk::PrincipalAuthorityKey::new(principal_core_id, principal_server_id);
    let recovery_material_evidence = crate::state::RecoveryMaterialEvidence {
        principal_id,
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
    crate::recovery_strand::ensure_recovery_policy(
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
                account.full_id().as_str(),
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

    fn test_active_account() -> crate::config::ActiveAccountContext {
        let full_id =
            arkret_sdk::DidFullId::new("did:webvh:z6mkfixture:principal.example".to_owned())
                .unwrap();
        crate::config::ActiveAccountContext::new(
            "ak:profile:test".to_owned(),
            arkret_sdk::PrincipalAuthorityKey::new(
                arkret_sdk::project_full_id_to_core_id(&full_id).unwrap(),
                arkret_sdk::DidCoreId::new(
                    "ak:did_core:webvh:z6mkfixture:server.example".to_owned(),
                )
                .unwrap(),
            ),
            arkret_sdk::PrincipalResolutionProjection {
                full_id,
                method_history_head: "head-test".to_owned(),
                version_id: "version-test".to_owned(),
                resolution_event_ref: "event-test".to_owned(),
                updated_at: "2026-08-22T00:00:00Z".parse().unwrap(),
            },
            arkret_sdk::DeviceId::new("ak:device:019f0000-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
            url::Url::parse("https://principal.example").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn hosting_label_hides_protocol_details() {
        assert_eq!(
            hosting_label("https://identity.example/path"),
            "identity.example"
        );
        assert_eq!(hosting_label("not a url"), "your selected service");
    }

    #[test]
    fn only_first_enrollment_continuations_may_create_the_account_mls_root() {
        use crate::identity::account_auth::transition::OnboardingCompletionOrigin;

        assert!(onboarding_may_create_account_mls_root(
            OnboardingCompletionOrigin::FreshBind
        ));
        assert!(onboarding_may_create_account_mls_root(
            OnboardingCompletionOrigin::ResumeRestore
        ));
        assert!(onboarding_may_create_account_mls_root(
            OnboardingCompletionOrigin::ResumeReissue
        ));
        assert!(!onboarding_may_create_account_mls_root(
            OnboardingCompletionOrigin::RecoveryCompletion
        ));
    }

    #[test]
    fn accepted_and_durable_recovery_stages_are_both_resumable() {
        assert_eq!(
            recovery_material_continuation(
                crate::state::PendingPrincipalRegistrationStage::Accepted,
            )
            .unwrap(),
            RecoveryMaterialContinuation::SubmitAndPersist,
        );
        assert_eq!(
            recovery_material_continuation(
                crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete,
            )
            .unwrap(),
            RecoveryMaterialContinuation::FinalizeDurableEvidence,
        );
        assert!(
            recovery_material_continuation(
                crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
            )
            .is_err()
        );
    }

    fn restorable_resume_facts() -> garth::BoundCompletionResumeFacts {
        garth::BoundCompletionResumeFacts {
            handoff: garth::BoundCompletionHandoffState::ActiveBound,
            checkpoint_stage: garth::BoundCompletionCheckpointStage::Accepted,
            recovery_policy: garth::BoundCompletionMaterialState::NotRequired,
            device_id: garth::BoundCompletionMaterialState::Present,
            signing_seed: garth::BoundCompletionMaterialState::Present,
            grant_binding_key: garth::BoundCompletionMaterialState::Present,
            session_grant: garth::BoundCompletionMaterialState::Present,
            recovery_evidence: garth::BoundCompletionMaterialState::Absent,
            hpke_private_key: garth::BoundCompletionMaterialState::Present,
            authority_matches: true,
            device_slot_matches: true,
            grant_matches_account: true,
            grant_is_live: true,
            grant_binding_matches_handoff: true,
        }
    }

    #[test]
    fn accepted_resume_material_matrix_has_honest_routes() {
        use garth::{
            BoundCompletionMaterialState as Material,
            BoundCompletionResumeDisposition as Disposition,
        };

        let live = restorable_resume_facts();
        for facts in [
            garth::BoundCompletionResumeFacts {
                session_grant: Material::Absent,
                ..live
            },
            garth::BoundCompletionResumeFacts {
                grant_is_live: false,
                ..live
            },
            garth::BoundCompletionResumeFacts {
                grant_binding_key: Material::Absent,
                ..live
            },
            garth::BoundCompletionResumeFacts {
                grant_binding_matches_handoff: false,
                ..live
            },
        ] {
            assert_eq!(
                garth::classify_bound_completion_resume(facts).unwrap(),
                Disposition::ReissueGrant
            );
        }
        assert_eq!(
            garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
                signing_seed: Material::Absent,
                recovery_policy: Material::Present,
                ..live
            })
            .unwrap(),
            Disposition::RecoverWithPolicy
        );
        assert_eq!(
            garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
                signing_seed: Material::Absent,
                recovery_policy: Material::Absent,
                ..live
            })
            .unwrap(),
            Disposition::StrandedIdentity
        );
        assert_eq!(
            garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
                handoff: garth::BoundCompletionHandoffState::MissingOrExpired,
                ..live
            })
            .unwrap(),
            Disposition::ReauthRequired
        );
        assert_eq!(
            garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
                checkpoint_stage: garth::BoundCompletionCheckpointStage::RecoveryMaterialComplete,
                recovery_evidence: Material::Absent,
                ..live
            })
            .unwrap(),
            Disposition::Contradiction {
                reason: garth::BoundCompletionContradiction::CompletedStageMissingEvidence
            }
        );
        assert_eq!(
            garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
                recovery_policy: Material::NotRequired,
                ..live
            })
            .unwrap(),
            Disposition::RestoreRuntime,
            "a present signer/session must not read recovery-policy state"
        );
        assert!(
            garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
                signing_seed: Material::Absent,
                recovery_policy: Material::ReadError,
                ..live
            })
            .is_err(),
            "a missing signer still requires proved server recovery-policy state"
        );
    }

    #[test]
    fn resume_material_read_error_is_not_absence() {
        let mut errors = Vec::new();
        let (state, value) = observe_resume_material::<String, _>(
            "session grant",
            Err(std::io::Error::other("keyring locked")),
            &mut errors,
        );
        assert_eq!(state, garth::BoundCompletionMaterialState::ReadError);
        assert!(value.is_none());
        assert_eq!(errors, ["session grant: keyring locked"]);

        let classified =
            garth::classify_bound_completion_resume(garth::BoundCompletionResumeFacts {
                session_grant: state,
                ..restorable_resume_facts()
            });
        assert!(classified.is_err());
    }

    #[test]
    fn resume_inventory_reads_the_same_typed_memory_store_path_as_production() {
        let secure = crate::secure_key_store::MemorySecureKeyStore::default();
        let account = test_active_account();
        let user_store = crate::secure_key_store::UserLocalStore::new(
            account.authority.clone(),
            account.device_id.clone(),
        )
        .unwrap();
        let mut errors = Vec::new();
        let (missing, _) = observe_resume_material(
            "accepted device signer",
            user_store.load_signing_seed(&secure),
            &mut errors,
        );
        assert_eq!(missing, garth::BoundCompletionMaterialState::Absent);
        assert!(errors.is_empty());

        user_store.save_signing_seed(&secure, &[17_u8; 32]).unwrap();
        let (present, material) = observe_resume_material(
            "accepted device signer",
            user_store.load_signing_seed(&secure),
            &mut errors,
        );
        assert_eq!(present, garth::BoundCompletionMaterialState::Present);
        assert_eq!(material.unwrap().seed, [17_u8; 32]);
        assert!(errors.is_empty());
    }

    #[test]
    fn accepted_account_client_uses_the_accepted_dpop_session() {
        use base64::Engine as _;

        let account = test_active_account();
        let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([23_u8; 32]);
        let record =
            crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(&seed)
                .unwrap();
        let dpop = crate::identity::account_auth::grant_dpop::device_handle_from_seed(
            &record.seed_b64,
            &record.jkt,
        )
        .unwrap();
        let grant = crate::state::PersistedSessionGrant {
            grant_jwt: "signed.session.grant".to_owned(),
            session_private_key_pem: String::new(),
            grant_id: "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW".to_owned(),
            audience: account.authority.principal_server_id.to_string(),
            principal_id: account.authority.principal_id.clone(),
            device_id: account.device_id.clone(),
            principal_server_url: account.server_url.clone(),
            grant_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            stored_at: chrono::Utc::now(),
        };

        let api = accepted_account_session_client(&account, dpop.jkt(), &grant, &dpop).unwrap();

        assert_eq!(api.context().credential, grant.grant_jwt);
        assert_eq!(
            api.context().dpop.as_ref().map(|handle| handle.jkt()),
            Some(dpop.jkt())
        );

        let mut wrong_audience = grant;
        wrong_audience.audience = "ak:did_core:webvh:z6mkfixture:other.example".to_owned();
        assert!(
            accepted_account_session_client(&account, dpop.jkt(), &wrong_audience, &dpop,).is_err()
        );
    }

    #[test]
    fn completed_account_namespace_switch_is_replay_safe() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000020",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::Accepted,
        );
        let account = test_active_account();
        let mut store = crate::state::isolated_store_for_tests("completed-account-replay");
        store.begin_pending_login(&account.device_id, Some(&handoff.holder_jkt));
        store
            .set_pending_account_handoff(Some(handoff.clone()))
            .unwrap();
        store
            .set_pending_principal_registration(Some(checkpoint.clone()))
            .unwrap();

        assert!(store.switch_active_account(&account).unwrap());
        assert_eq!(store.pending_account_handoff(), Some(handoff.clone()));
        assert_eq!(
            store.pending_principal_registration(),
            Some(checkpoint.clone())
        );

        assert!(!store.switch_active_account(&account).unwrap());
        assert_eq!(store.pending_account_handoff(), Some(handoff));
        assert_eq!(store.pending_principal_registration(), Some(checkpoint));
    }

    #[test]
    fn recovery_metadata_is_written_after_the_account_namespace_switch() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let account = test_active_account();
        let mut store = crate::state::isolated_store_for_tests("account-recovery-metadata");

        activate_account_and_save_recovery_metadata(&mut store, &account, &recovery_key).unwrap();

        assert!(store.active_account_matches(account.principal_id()));
        assert!(crate::views::recovery::recovery_options_configured(
            &store,
            account.principal_id(),
        ));
        crate::views::recovery::local_recovery_public_key_result(&store, account.principal_id())
            .unwrap();
    }

    #[test]
    fn current_deployment_exposes_only_its_connected_human_anchor_method() {
        assert_eq!(CURRENT_DEPLOYMENT_HUMAN_ANCHOR_METHOD, "did:webvh");
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

    #[tokio::test]
    async fn prepared_registration_rehydrates_its_pending_signer_before_retry() {
        let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(None);
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
        );
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let pending_store = crate::secure_key_store::PendingLocalStore::new(
            arkret_sdk::DeviceId::new(handoff.device_id.clone()).unwrap(),
        );
        pending_store
            .save_signing_seed(&secure_store, &[7; 32])
            .unwrap();
        crate::event_signer::activate_device_signer_from_seed_for_device(
            [9; 32],
            None,
            Some("ak:device:019f0000-0000-7000-8000-000000000099"),
        )
        .unwrap();

        let signer = activate_pending_registration_signer(
            &checkpoint,
            &handoff.device_id,
            &pending_store,
            &secure_store,
        )
        .await
        .unwrap();

        assert_eq!(signer.signer_did(), checkpoint.full_id.as_str());
        assert_eq!(signer.device_id(), Some(handoff.device_id.as_str()));
        assert!(
            signer
                .verification_method()
                .ends_with(&format!("#{}", handoff.device_id))
        );
    }

    #[test]
    fn bootstrap_seal_retry_reuses_the_byte_exact_checkpoint_value() {
        let frozen = serde_json::json!({
            "id": "ak:seal:frozen",
            "notary_seq": 0,
            "hlc": "01970e589d21-0004-a13f9c2e"
        });

        validate_exact_bootstrap_seal_replay(&frozen, &frozen.clone()).unwrap();

        let changed = serde_json::json!({
            "id": "ak:seal:frozen",
            "notary_seq": 1,
            "hlc": "01970e589d21-0004-a13f9c2e"
        });
        let error = validate_exact_bootstrap_seal_replay(&frozen, &changed).unwrap_err();
        assert!(
            error
                .downcast_ref::<BootstrapSealReplayContradiction>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn prepared_registration_never_rotates_a_missing_pending_signer() {
        let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(None);
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
        );
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let pending_store = crate::secure_key_store::PendingLocalStore::new(
            arkret_sdk::DeviceId::new(handoff.device_id.clone()).unwrap(),
        );

        let error = activate_pending_registration_signer(
            &checkpoint,
            &handoff.device_id,
            &pending_store,
            &secure_store,
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("no durable pending device signer")
        );
        assert!(crate::event_signer::active_signer().is_none());
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
            onboarding_surface(Some(&new_account_handoff), Some(&stale)),
            OnboardingSurface::IdentityCreation
        );
        // Even a live session for the stale draft's DID cannot outrank the
        // handoff that just authenticated someone else on this device.
        assert_eq!(
            onboarding_surface(Some(&new_account_handoff), Some(&stale)),
            OnboardingSurface::IdentityCreation
        );
    }

    #[test]
    fn an_interrupted_creation_stays_in_the_server_handoff_flow() {
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
            onboarding_surface(Some(&handoff), Some(&checkpoint)),
            OnboardingSurface::IdentityCreation
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
            onboarding_surface(None, Some(&checkpoint)),
            OnboardingSurface::StaleCheckpoint
        );
    }

    #[test]
    fn every_local_phase_requires_a_server_handoff_before_resuming() {
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

            // A local checkpoint never authorizes continuation by itself,
            // even if a session for the same DID is present. Signing in must
            // first obtain a fresh Account Authority snapshot and handoff.
            assert_eq!(
                onboarding_surface(None, Some(&checkpoint)),
                OnboardingSurface::StaleCheckpoint
            );
        }
    }

    #[test]
    fn discarding_a_registered_binding_is_flagged_as_irreversible() {
        // The two warnings are trivially easy to swap, and swapping them tells
        // a user that throwing away the only copy of a registered identity's
        // setup costs nothing.
        assert!(discard_consequence(true).contains("authenticated abandonment"));
        assert!(discard_consequence(false).contains("Nothing has been registered"));
    }

    #[test]
    fn account_summary_requires_a_typed_active_account() {
        let account = test_active_account();
        assert!(!account_summary_complete(false, ""));
        assert!(account_summary_complete(true, account.full_id().as_str()));
    }

    #[test]
    fn a_latched_creation_surface_never_goes_empty_when_its_handoff_disappears() {
        let account = test_active_account();
        assert_eq!(
            missing_creation_handoff_surface(true, false, ""),
            MissingCreationHandoffSurface::Finishing
        );
        assert_eq!(
            missing_creation_handoff_surface(false, true, account.full_id().as_str()),
            MissingCreationHandoffSurface::Complete
        );
        assert_eq!(
            missing_creation_handoff_surface(false, false, ""),
            MissingCreationHandoffSurface::SignInRequired
        );
    }

    #[test]
    fn onboarding_without_a_draft_follows_the_handoff() {
        let handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );

        assert_eq!(
            onboarding_surface(Some(&handoff), None),
            OnboardingSurface::IdentityCreation
        );
        assert_eq!(
            onboarding_surface(None, None),
            OnboardingSurface::AccountSummary
        );
    }

    #[test]
    fn contradictory_bound_and_reserved_server_state_fails_closed() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let mut handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
        );
        handoff.bound_principal_id = Some(checkpoint.full_id.clone());
        handoff.reserved_identity = Some(
            arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation.clone())
                .unwrap(),
        );
        handoff.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

        assert_eq!(
            onboarding_surface(Some(&handoff), None),
            OnboardingSurface::ServerStateConflict
        );
        assert_eq!(
            onboarding_surface(Some(&handoff), Some(&checkpoint)),
            OnboardingSurface::ServerStateConflict
        );
        assert!(must_enter_reserved_recovery_key(&handoff));
    }

    #[test]
    fn exact_bound_creation_checkpoint_finishes_on_the_creation_surface() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        for stage in [
            crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
            crate::state::PendingPrincipalRegistrationStage::Accepted,
            crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete,
        ] {
            let mut handoff = test_handoff(
                "ak:request:019f0000-0000-7000-8000-000000000010",
                Some("lease-1"),
                Some(1),
            );
            let checkpoint = test_checkpoint(&handoff, &recovery_key, stage);
            handoff.lease_id = None;
            handoff.lease_fence = None;
            handoff.lease_expires_at = None;
            handoff.identity_creation_state = None;
            handoff.bound_principal_id = Some(checkpoint.full_id.clone());

            assert_eq!(
                onboarding_surface(Some(&handoff), Some(&checkpoint)),
                OnboardingSurface::IdentityCreation,
                "bound + exact {stage:?} checkpoint is the same registration transaction"
            );
        }
    }

    #[test]
    fn reauthenticated_bound_creation_renews_only_the_handoff_request_fence() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let original = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000009",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = test_checkpoint(
            &original,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::Accepted,
        );
        let mut reauthenticated = original;
        reauthenticated.request_id = "ak:request:019f0000-0000-7000-8000-000000000010".to_owned();
        reauthenticated.lease_id = None;
        reauthenticated.lease_fence = None;
        reauthenticated.lease_expires_at = None;
        reauthenticated.identity_creation_state = None;
        reauthenticated.bound_principal_id = Some(checkpoint.full_id.clone());

        let resumed = checkpoint_for_handoff(&checkpoint, &reauthenticated, &recovery_key).unwrap();

        assert_eq!(resumed.handoff_request_id, reauthenticated.request_id);
        assert_eq!(resumed.full_id, checkpoint.full_id);
        assert_eq!(resumed.device_id, checkpoint.device_id);
        assert_eq!(resumed.pcr_genesis_unit, checkpoint.pcr_genesis_unit);
    }

    #[test]
    fn bound_account_without_verified_creation_continuation_uses_recovery() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let mut handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::Accepted,
        );
        handoff.lease_id = None;
        handoff.lease_fence = None;
        handoff.lease_expires_at = None;
        handoff.identity_creation_state = None;
        handoff.bound_principal_id = Some(checkpoint.full_id.clone());

        assert_eq!(
            onboarding_surface(Some(&handoff), None),
            OnboardingSurface::DeviceSetupRequired
        );
        let mut foreign = checkpoint;
        foreign.device_id = "ak:device:019f0000-0000-7000-8000-000000000099".to_owned();
        assert_eq!(
            onboarding_surface(Some(&handoff), Some(&foreign)),
            OnboardingSurface::DeviceSetupRequired,
            "a foreign checkpoint must not inherit the first-device continuation"
        );
    }

    #[test]
    fn a_server_reservation_never_generates_a_replacement_recovery_key() {
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
        let mut renewed = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            Some("lease-2"),
            Some(2),
        );
        renewed.reserved_identity = Some(
            arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation.clone())
                .unwrap(),
        );
        renewed.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

        // The checkpoint matches the exact server reservation, so the single
        // handoff flow continues it instead of treating the local checkpoint
        // as an independent authority source.
        assert_eq!(
            onboarding_surface(Some(&renewed), Some(&checkpoint)),
            OnboardingSurface::IdentityCreation
        );
        assert!(must_enter_reserved_recovery_key(&renewed));
    }

    #[test]
    fn every_unfinished_server_phase_uses_one_handoff_flow() {
        let mut handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
        );
        let reserved_identity =
            arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation).unwrap();
        for state in [
            arkret_sdk::IdentityCreationLeaseState::Active,
            arkret_sdk::IdentityCreationLeaseState::Reserved,
            arkret_sdk::IdentityCreationLeaseState::DidPublished,
            arkret_sdk::IdentityCreationLeaseState::PcrAccepted,
            arkret_sdk::IdentityCreationLeaseState::AccountBound,
        ] {
            handoff.identity_creation_state = Some(state);
            handoff.reserved_identity = state
                .has_reserved_identity()
                .then(|| reserved_identity.clone());
            assert_eq!(
                onboarding_surface(Some(&handoff), None),
                OnboardingSurface::IdentityCreation,
                "server phase {state:?} must stay in the authoritative handoff flow"
            );
        }
    }

    #[test]
    fn retained_or_reserved_key_material_skips_identity_choice() {
        let mut handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        assert_eq!(
            initial_identity_choice(Some(&handoff), false),
            IdentityChoice::Choose
        );
        assert_eq!(
            initial_identity_choice(Some(&handoff), true),
            IdentityChoice::Create
        );
        handoff.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
        );
        handoff.reserved_identity = Some(
            arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation).unwrap(),
        );
        assert_eq!(
            initial_identity_choice(Some(&handoff), false),
            IdentityChoice::Create
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
        let did_operation = checkpoint.did_operation.clone();
        let reserved_identity =
            arkret_sdk::ReservedIdentityCreation::from_operation(did_operation).unwrap();
        checkpoint.account_handle.clear();
        let mut new_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            Some("lease-2"),
            Some(2),
        );
        new_handoff.reserved_identity = Some(reserved_identity);
        new_handoff.identity_creation_state =
            Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

        let resumed = checkpoint_for_handoff(&checkpoint, &new_handoff, &recovery_key).unwrap();

        assert_eq!(resumed.handoff_request_id, new_handoff.request_id);
        assert_eq!(resumed.lease_id, "lease-2");
        assert_eq!(resumed.lease_fence, 2);
        assert_eq!(resumed.full_id, checkpoint.full_id);
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
        let other_operation = other_checkpoint.did_operation;
        let mut new_handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            Some("lease-2"),
            Some(2),
        );
        new_handoff.reserved_identity =
            Some(arkret_sdk::ReservedIdentityCreation::from_operation(other_operation).unwrap());
        new_handoff.identity_creation_state =
            Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

        let error = checkpoint_for_handoff(&checkpoint, &new_handoff, &recovery_key).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match the local checkpoint")
        );
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
        let operation = checkpoint.did_operation.clone();
        new_account_handoff.reserved_identity =
            Some(arkret_sdk::ReservedIdentityCreation::from_operation(operation).unwrap());
        new_account_handoff.identity_creation_state =
            Some(arkret_sdk::IdentityCreationLeaseState::Reserved);

        let resumed =
            checkpoint_for_handoff(&checkpoint, &new_account_handoff, &recovery_key).unwrap();

        assert_eq!(resumed.full_id, checkpoint.full_id);
        assert_eq!(resumed.did_operation, checkpoint.did_operation);
        assert_eq!(resumed.account_handle, checkpoint.account_handle);
    }

    #[test]
    fn an_in_flight_server_reservation_does_not_turn_first_run_into_recovery() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let mut handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            Some("lease-1"),
            Some(1),
        );
        let key_source = RecoveryKeySource::for_initial_handoff(Some(&handoff), false);
        assert_eq!(key_source, RecoveryKeySource::GeneratedThisMount);

        // The first register attempt can durably reserve the DID before its
        // response fails. Reconciliation advances the authoritative server
        // state, but the mounted page still owns the generated key and must not
        // reinterpret it as an interrupted/recovery flow.
        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::RegisterRequestPrepared,
        );
        handoff.reserved_identity = Some(
            arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation).unwrap(),
        );
        handoff.identity_creation_state = Some(arkret_sdk::IdentityCreationLeaseState::Reserved);
        assert!(!key_source.requires_existing_key());

        // A reload with no validated key in secure storage must ask for the
        // original key. A reload that retained it returns to confirmation and
        // never claims that the server proved the user saved the words.
        assert_eq!(
            RecoveryKeySource::for_initial_handoff(Some(&handoff), false),
            RecoveryKeySource::ExistingReservation
        );
        assert_eq!(
            RecoveryKeySource::for_initial_handoff(Some(&handoff), true),
            RecoveryKeySource::RecoveredFromSecureStore
        );
        assert!(
            !RecoveryKeySource::RecoveredFromSecureStore.requires_existing_key(),
            "a securely retained key must return to confirmation, not existing-key recovery"
        );
        assert!(
            RecoveryKeySource::RecoveredFromSecureStore.was_recovered_from_secure_store(),
            "the UI must disclose that it is re-offering device-retained material"
        );
        assert!(
            !RecoveryKeySource::GeneratedThisMount.was_recovered_from_secure_store(),
            "a freshly generated key must keep first-run copy"
        );
    }

    #[test]
    fn onboarding_state_rejects_core_ids_in_full_id_slots() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let mut handoff = test_handoff(
            "ak:request:019f0000-0000-7000-8000-000000000020",
            Some("lease-1"),
            Some(1),
        );
        handoff.bound_principal_id =
            Some(arkret_sdk::DidFullId::new("did:web:alice.example".to_owned()).unwrap());
        let mut handoff_json = serde_json::to_value(&handoff).unwrap();
        handoff_json["bound_principal_id"] = serde_json::json!("ak:did_core:web:alice.example");
        assert!(
            serde_json::from_value::<crate::state::PendingAccountHandoff>(handoff_json).is_err(),
            "a bound-account full-DID slot must reject a core id"
        );

        let checkpoint = test_checkpoint(
            &handoff,
            &recovery_key,
            crate::state::PendingPrincipalRegistrationStage::CustodyConfirmed,
        );
        let mut checkpoint_json = serde_json::to_value(&checkpoint).unwrap();
        assert_eq!(checkpoint_json["did"], checkpoint.full_id.as_str());
        checkpoint_json["did"] = serde_json::json!("ak:did_core:web:alice.example");
        assert!(
            serde_json::from_value::<crate::state::PendingPrincipalRegistration>(checkpoint_json)
                .is_err(),
            "a registration full-DID slot must reject a core id"
        );
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
            oidc_state: None,
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
            identity_creation_state: Some(arkret_sdk::IdentityCreationLeaseState::Active),
            reserved_identity: None,
            identity_abandonment: None,
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
