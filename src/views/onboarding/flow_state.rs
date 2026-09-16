#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum IdentityChoice {
    #[default]
    Choose,
    Create,
}

/// Which onboarding surface the durable stages select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OnboardingSurface {
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

/// Where the Recovery Key used by this mounted creation surface came from.
///
/// This is deliberately a mount-scoped fact, not a projection of the latest
/// server phase. During a first creation the server can advance from `active`
/// to `reserved` while the generated key is still safely held in this
/// component. Reinterpreting that transition as an interrupted setup would
/// replace the first-run confirmation UI with an "existing key" recovery UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryKeySource {
    GeneratedThisMount,
    RecoveredFromSecureStore,
    ExistingReservation,
}

impl RecoveryKeySource {
    pub(super) fn for_initial_handoff(
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

    pub(super) const fn requires_existing_key(self) -> bool {
        matches!(self, Self::ExistingReservation)
    }

    pub(super) const fn was_recovered_from_secure_store(self) -> bool {
        matches!(self, Self::RecoveredFromSecureStore)
    }
}

pub(super) fn initial_identity_choice(
    handoff: Option<&crate::state::PendingAccountHandoff>,
    retained_key_available: bool,
) -> IdentityChoice {
    if retained_key_available || handoff.is_some_and(must_enter_reserved_recovery_key) {
        IdentityChoice::Create
    } else {
        IdentityChoice::Choose
    }
}

/// Select the onboarding surface from the Coauth-authored lease state.
///
/// Local checkpoints may satisfy a server-required artifact, but they never
/// select or advance the protocol phase. A contradictory server snapshot is a
/// closed failure rather than an invitation to infer state from local data.
pub(super) fn onboarding_surface(
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
            } else if matches!(
                handoff.bound_device_entry_state.as_ref(),
                Some(crate::state::BoundDeviceEntryState::NoReturningDevice)
            ) {
                OnboardingSurface::DeviceSetupRequired
            } else {
                // ReturningDevice must resume session issuance and
                // LocalEvidenceUnavailable must remain in diagnostics. An old
                // checkpoint with no closed normalization result also fails
                // closed here; none of these may open Recovery.
                OnboardingSurface::ServerStateConflict
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
pub(super) fn account_summary_complete(session_token_present: bool, principal_id: &str) -> bool {
    session_token_present && !principal_id.trim().is_empty()
}

/// A latched creation surface can outlive its durable account handoff while an
/// async completion or reconciliation task is publishing state. That gap must
/// always render an explicit continuation instead of removing the entire main
/// panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MissingCreationHandoffSurface {
    Finishing,
    Complete,
    SignInRequired,
}

pub(super) fn missing_creation_handoff_surface(
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

/// A server reservation always outranks a local draft when selecting the key
/// entry mode. A full-page authentication callback loses the in-memory key;
/// generating a replacement phrase at that point can never control the
/// already-reserved identity, even when an older local checkpoint still exists.
pub(super) fn must_enter_reserved_recovery_key(
    handoff: &crate::state::PendingAccountHandoff,
) -> bool {
    handoff
        .identity_creation_state
        .is_some_and(arkret_sdk::IdentityCreationLeaseState::has_reserved_identity)
}
