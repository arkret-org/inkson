//! Structured, secret-free login transition records and counters.
//!
//! One record is emitted for every authoritative step of the returning-login
//! path so a wrong recovery surface can be traced back to the account handoff,
//! the session issuance operation, the device gate and the input each stage
//! actually consumed. Records carry identifiers and typed reasons only; every
//! record is scanned against [`crate::secret_surface`] before it is logged, so
//! a credential can never reach the log even if a future call site passes one.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Stable stage names used for `from_state` and `next_state`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginStage {
    /// The user asked this installation to start an account sign-in.
    SignInStart,
    /// The Account Authority redirected back with an authorization code.
    OidcCallback,
    /// An account handoff outcome was validated into a typed disposition.
    AccountHandoff,
    /// The Account Authority holds an identity-creation lease for this
    /// authentication.
    IdentityCreation,
    /// Hydrated local evidence was normalized into one returning-device fact.
    LocalNormalization,
    /// A signed session grant request was issued or exactly replayed.
    SessionIssuance,
    /// An authorized session is active.
    Workspace,
    /// This installation must have a device accepted before it can hold a
    /// session.
    DeviceSetup,
    /// Root-anchored recovery, reachable only by explicit user choice.
    RootRecovery,
    /// Fail-closed diagnostics with an explicit way out.
    LoginDiagnostics,
}

impl LoginStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignInStart => "sign_in_start",
            Self::OidcCallback => "oidc_callback",
            Self::AccountHandoff => "account_handoff",
            Self::IdentityCreation => "identity_creation",
            Self::LocalNormalization => "local_normalization",
            Self::SessionIssuance => "session_issuance",
            Self::Workspace => "workspace",
            Self::DeviceSetup => "device_setup",
            Self::RootRecovery => "root_recovery",
            Self::LoginDiagnostics => "login_diagnostics",
        }
    }
}

/// Counter families that separate the outcomes an operator must be able to
/// tell apart without reading individual records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginTransitionOutcome {
    /// A session grant was issued or exactly replayed for this device.
    AuthorizedLogin,
    /// The account is bound but this installation holds no accepted device
    /// key, so pairing-first device setup is required.
    DeviceSetupRequired,
    /// The authority returned a typed device block (pending, revoked or
    /// generation mismatch).
    TypedBlock,
    /// A retryable transport/issuer outcome; the same signed request is
    /// replayed byte-for-byte.
    RetryExactIssue,
    /// Local and authoritative facts contradict each other, or an invariant
    /// was violated. Never a recovery prompt.
    Contradiction,
    /// The 24-word root recovery surface was opened.
    RecoverySurfaceOpened,
}

impl LoginTransitionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizedLogin => "authorized_login",
            Self::DeviceSetupRequired => "device_setup_required",
            Self::TypedBlock => "typed_block",
            Self::RetryExactIssue => "retry_exact_issue",
            Self::Contradiction => "contradiction",
            Self::RecoverySurfaceOpened => "recovery_surface_opened",
        }
    }

    fn counter(self) -> &'static AtomicU64 {
        match self {
            Self::AuthorizedLogin => &AUTHORIZED_LOGIN,
            Self::DeviceSetupRequired => &DEVICE_SETUP_REQUIRED,
            Self::TypedBlock => &TYPED_BLOCK,
            Self::RetryExactIssue => &RETRY_EXACT_ISSUE,
            Self::Contradiction => &CONTRADICTION,
            Self::RecoverySurfaceOpened => &RECOVERY_SURFACE_OPENED,
        }
    }
}

/// Why the root recovery surface opened. There is no implicit variant: a
/// missing local fact, an ordinary error and a device block can never open it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryEntryReason {
    /// The user chose the secondary "use Recovery Key" action inside Device
    /// Setup.
    UserSelectedInDeviceSetup,
}

impl RecoveryEntryReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserSelectedInDeviceSetup => "user_selected_in_device_setup",
        }
    }
}

/// Identifiers shared by every stage of one sign-in transaction.
///
/// All members are public identifiers or digests. The OIDC `state` is a
/// single-use CSRF value, so only its truncated digest is carried.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LoginCorrelation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_state_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handoff_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_grant_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_grant_id: Option<String>,
    /// Public digest of the exact session intent. Coauth forwards it to the
    /// Principal Server as the gate `intent_digest`, so one signed device gate
    /// receipt can be found from a client record without any secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_intent_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

impl LoginCorrelation {
    /// Seed a correlation from the durable account handoff that owns this
    /// sign-in transaction.
    pub fn for_handoff(handoff: &crate::state::PendingAccountHandoff) -> Self {
        let correlation = Self::default().with_handoff_request_id(&handoff.request_id);
        let correlation = match handoff.oidc_state.as_deref() {
            Some(state) => correlation.with_oidc_state(state),
            None => correlation,
        };
        match handoff.bound_principal_id.as_ref() {
            Some(principal_id) => correlation.with_principal_id(principal_id.as_str()),
            None => correlation,
        }
    }

    pub fn with_oidc_state(mut self, state: &str) -> Self {
        self.oidc_state_digest = Some(oidc_state_digest(state));
        self
    }

    pub fn with_handoff_request_id(mut self, request_id: &str) -> Self {
        self.handoff_request_id = Some(request_id.to_owned());
        self
    }

    pub fn with_principal_id(mut self, principal_id: &str) -> Self {
        self.principal_id = Some(principal_id.to_owned());
        self
    }

    pub fn with_device_id(mut self, device_id: &str) -> Self {
        self.device_id = Some(device_id.to_owned());
        self
    }
}

/// A single-use OIDC `state` never appears in a record; this truncated digest
/// is enough to join a client record to its callback.
fn oidc_state_digest(state: &str) -> String {
    crate::canonical::sha256_hex(state.as_bytes())
        .chars()
        .take(16)
        .collect()
}

#[derive(Debug, Serialize)]
struct LoginTransitionRecord<'a> {
    from_state: &'a str,
    authoritative_input: &'a str,
    next_state: &'a str,
    reason: &'a str,
    /// Present only when this transition closes an outcome family that has a
    /// counter. Intermediate stage transitions are recorded without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<&'a str>,
    correlation: &'a LoginCorrelation,
}

static AUTHORIZED_LOGIN: AtomicU64 = AtomicU64::new(0);
static DEVICE_SETUP_REQUIRED: AtomicU64 = AtomicU64::new(0);
static TYPED_BLOCK: AtomicU64 = AtomicU64::new(0);
static RETRY_EXACT_ISSUE: AtomicU64 = AtomicU64::new(0);
static CONTRADICTION: AtomicU64 = AtomicU64::new(0);
static RECOVERY_SURFACE_OPENED: AtomicU64 = AtomicU64::new(0);

/// Current value of every login transition counter, in the fixed order an
/// operator dashboard reads them.
pub fn login_transition_counters() -> Vec<(&'static str, u64)> {
    [
        LoginTransitionOutcome::AuthorizedLogin,
        LoginTransitionOutcome::DeviceSetupRequired,
        LoginTransitionOutcome::TypedBlock,
        LoginTransitionOutcome::RetryExactIssue,
        LoginTransitionOutcome::Contradiction,
        LoginTransitionOutcome::RecoverySurfaceOpened,
    ]
    .into_iter()
    .map(|outcome| (outcome.as_str(), outcome.counter().load(Ordering::Relaxed)))
    .collect()
}

/// Record one authoritative stage transition and advance its counter.
///
/// `authoritative_input` names the authority that produced the decision (a
/// server disposition, a typed admission, a normalization outcome or an
/// explicit user action) — never a raw local `Option` or bool.
pub fn record_login_transition(
    from_state: LoginStage,
    authoritative_input: &str,
    next_state: LoginStage,
    reason: &str,
    outcome: Option<LoginTransitionOutcome>,
    correlation: &LoginCorrelation,
) {
    if let Some(outcome) = outcome {
        outcome.counter().fetch_add(1, Ordering::Relaxed);
    }
    let record = LoginTransitionRecord {
        from_state: from_state.as_str(),
        authoritative_input,
        next_state: next_state.as_str(),
        reason,
        outcome: outcome.map(LoginTransitionOutcome::as_str),
        correlation,
    };
    let Ok(value) = serde_json::to_value(&record) else {
        tracing::warn!(
            next_state = record.next_state,
            "login transition record could not be serialized for the secret scan"
        );
        return;
    };
    if let Some(violation) = crate::secret_surface::find_json_violation("login_transition", &value)
    {
        tracing::error!(
            next_state = record.next_state,
            violation_path = violation.path(),
            "login transition record was withheld: it would have leaked a credential"
        );
        debug_assert!(
            false,
            "login transition record must never carry secret material"
        );
        return;
    }
    tracing::info!(
        from_state = record.from_state,
        authoritative_input = record.authoritative_input,
        next_state = record.next_state,
        reason = record.reason,
        outcome = record.outcome,
        oidc_state_digest = correlation.oidc_state_digest.as_deref(),
        handoff_request_id = correlation.handoff_request_id.as_deref(),
        session_grant_request_id = correlation.session_grant_request_id.as_deref(),
        session_grant_id = correlation.session_grant_id.as_deref(),
        session_intent_digest = correlation.session_intent_digest.as_deref(),
        principal_id = correlation.principal_id.as_deref(),
        device_id = correlation.device_id.as_deref(),
        "login transition"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnboardingCompletionOrigin {
    FreshBind,
    ResumeRestore,
    ResumeReissue,
    RecoveryCompletion,
}

impl OnboardingCompletionOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FreshBind => "fresh_bind",
            Self::ResumeRestore => "resume_restore",
            Self::ResumeReissue => "resume_reissue",
            Self::RecoveryCompletion => "recovery_completion",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnboardingCompletionOutcome {
    Classified,
    Committed,
    RetryableHydration,
    ReauthRequired,
    RecoveryRequired,
    Stranded,
    Contradiction,
    Failed,
}

impl OnboardingCompletionOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Classified => "classified",
            Self::Committed => "committed",
            Self::RetryableHydration => "retryable_hydration",
            Self::ReauthRequired => "reauth_required",
            Self::RecoveryRequired => "recovery_required",
            Self::Stranded => "stranded",
            Self::Contradiction => "contradiction",
            Self::Failed => "failed",
        }
    }
}

fn material_state_name(state: garth::BoundCompletionMaterialState) -> &'static str {
    match state {
        garth::BoundCompletionMaterialState::Present => "present",
        garth::BoundCompletionMaterialState::Absent => "absent",
        garth::BoundCompletionMaterialState::ReadError => "read_error",
        garth::BoundCompletionMaterialState::NotRequired => "not_required",
    }
}

#[derive(Debug, Serialize)]
struct OnboardingCompletionInventory<'a> {
    recovery_policy: &'a str,
    device_id: &'a str,
    signing_seed: &'a str,
    grant_binding_key: &'a str,
    session_grant: &'a str,
    recovery_evidence: &'a str,
    hpke_private_key: &'a str,
    authority_matches: bool,
    device_slot_matches: bool,
    grant_matches_account: bool,
    grant_is_live: bool,
    grant_binding_matches_handoff: bool,
}

#[derive(Debug, Serialize)]
struct OnboardingCompletionRecord<'a> {
    origin: &'a str,
    outcome: &'a str,
    reason: &'a str,
    correlation: &'a LoginCorrelation,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory: Option<OnboardingCompletionInventory<'a>>,
}

/// Record one secret-free onboarding completion classification or commit.
pub fn record_onboarding_completion_transition(
    origin: OnboardingCompletionOrigin,
    outcome: OnboardingCompletionOutcome,
    reason: &str,
    correlation: &LoginCorrelation,
    facts: Option<&garth::BoundCompletionResumeFacts>,
) {
    let inventory = facts.map(|facts| OnboardingCompletionInventory {
        recovery_policy: material_state_name(facts.recovery_policy),
        device_id: material_state_name(facts.device_id),
        signing_seed: material_state_name(facts.signing_seed),
        grant_binding_key: material_state_name(facts.grant_binding_key),
        session_grant: material_state_name(facts.session_grant),
        recovery_evidence: material_state_name(facts.recovery_evidence),
        hpke_private_key: material_state_name(facts.hpke_private_key),
        authority_matches: facts.authority_matches,
        device_slot_matches: facts.device_slot_matches,
        grant_matches_account: facts.grant_matches_account,
        grant_is_live: facts.grant_is_live,
        grant_binding_matches_handoff: facts.grant_binding_matches_handoff,
    });
    let record = OnboardingCompletionRecord {
        origin: origin.as_str(),
        outcome: outcome.as_str(),
        reason,
        correlation,
        inventory,
    };
    let Ok(value) = serde_json::to_value(&record) else {
        tracing::warn!(
            origin = record.origin,
            outcome = record.outcome,
            "onboarding completion transition could not be serialized"
        );
        return;
    };
    if let Some(violation) =
        crate::secret_surface::find_json_violation("onboarding_completion_transition", &value)
    {
        tracing::error!(
            origin = record.origin,
            outcome = record.outcome,
            violation_path = violation.path(),
            "onboarding completion transition was withheld: it would have leaked a credential"
        );
        debug_assert!(
            false,
            "onboarding completion transition must be secret-free"
        );
        return;
    }
    tracing::info!(
        origin = record.origin,
        outcome = record.outcome,
        reason = record.reason,
        handoff_request_id = correlation.handoff_request_id.as_deref(),
        principal_id = correlation.principal_id.as_deref(),
        device_id = correlation.device_id.as_deref(),
        inventory = ?record.inventory,
        "onboarding completion transition"
    );
}

/// Remember that one bound account handoff reached a typed admission outcome
/// — either an authority session-issuance result or a normalization result
/// that proved this installation holds no accepted device key. Bounded to the
/// most recent transactions; it is a runtime invariant aid, never durable
/// state.
pub fn note_bound_admission_outcome(handoff_request_id: &str) {
    let mut observed = observed_admission_outcomes();
    if push_bounded_admission_outcome(&mut observed, handoff_request_id) {
        store_admission_outcomes(observed);
    }
}

/// Append one request id to a bounded, de-duplicated ring. Returns whether the
/// ring changed.
fn push_bounded_admission_outcome(observed: &mut Vec<String>, handoff_request_id: &str) -> bool {
    if observed.iter().any(|seen| seen == handoff_request_id) {
        return false;
    }
    if observed.len() >= OBSERVED_ADMISSION_CAPACITY {
        observed.remove(0);
    }
    observed.push(handoff_request_id.to_owned());
    true
}

const OBSERVED_ADMISSION_CAPACITY: usize = 8;

#[cfg(target_arch = "wasm32")]
thread_local! {
    static OBSERVED_ADMISSION: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(target_arch = "wasm32")]
fn observed_admission_outcomes() -> Vec<String> {
    OBSERVED_ADMISSION.with(|cell| cell.borrow().clone())
}

#[cfg(target_arch = "wasm32")]
fn store_admission_outcomes(value: Vec<String>) {
    OBSERVED_ADMISSION.with(|cell| *cell.borrow_mut() = value);
}

#[cfg(not(target_arch = "wasm32"))]
static OBSERVED_ADMISSION: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

#[cfg(not(target_arch = "wasm32"))]
fn observed_admission_outcomes() -> Vec<String> {
    OBSERVED_ADMISSION
        .lock()
        .map(|observed| observed.clone())
        .unwrap_or_default()
}

#[cfg(not(target_arch = "wasm32"))]
fn store_admission_outcomes(value: Vec<String>) {
    if let Ok(mut observed) = OBSERVED_ADMISSION.lock() {
        *observed = value;
    }
}

/// Open the root recovery surface record. `reason` is mandatory, so an
/// implicit path cannot produce this record at all.
///
/// A bound handoff that never reached a typed admission outcome is a broken
/// invariant: debug and test builds fail immediately, release builds report a
/// contradiction and the caller must stay in login diagnostics.
pub fn record_recovery_surface_opened(
    reason: RecoveryEntryReason,
    correlation: &LoginCorrelation,
    bound_handoff: bool,
) -> bool {
    let admission_observed = correlation
        .handoff_request_id
        .as_deref()
        .is_some_and(|request_id| {
            observed_admission_outcomes()
                .iter()
                .any(|seen| seen == request_id)
        });
    if bound_handoff && !admission_observed {
        record_login_transition(
            LoginStage::DeviceSetup,
            "login_transition_invariant",
            LoginStage::LoginDiagnostics,
            "bound_handoff_reached_recovery_without_admission_outcome",
            Some(LoginTransitionOutcome::Contradiction),
            correlation,
        );
        debug_assert!(
            false,
            "a bound account handoff must reach a typed admission outcome before any recovery surface"
        );
        return false;
    }
    record_login_transition(
        LoginStage::DeviceSetup,
        "explicit_user_choice",
        LoginStage::RootRecovery,
        reason.as_str(),
        Some(LoginTransitionOutcome::RecoverySurfaceOpened),
        correlation,
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counters and the observed-admission ring are process-global. Tests that
    /// read or mutate them run one at a time.
    static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn correlation_never_carries_the_raw_oidc_state() {
        let correlation = LoginCorrelation::default().with_oidc_state("single-use-state-value");

        let digest = correlation.oidc_state_digest.clone().unwrap();
        assert_eq!(digest.len(), 16);
        assert!(!digest.contains("single-use-state-value"));
    }

    #[test]
    fn counters_separate_every_documented_outcome() {
        let _guard = GLOBAL_STATE.lock();
        let before = login_transition_counters();
        assert_eq!(
            before.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            vec![
                "authorized_login",
                "device_setup_required",
                "typed_block",
                "retry_exact_issue",
                "contradiction",
                "recovery_surface_opened",
            ]
        );

        record_login_transition(
            LoginStage::SessionIssuance,
            "session_grant_admission",
            LoginStage::Workspace,
            "accepted_device_session_issued",
            Some(LoginTransitionOutcome::AuthorizedLogin),
            &LoginCorrelation::default(),
        );

        let after = login_transition_counters();
        assert_eq!(after[0].1, before[0].1 + 1);
        for index in 1..after.len() {
            assert_eq!(after[index].1, before[index].1, "{}", after[index].0);
        }
    }

    #[test]
    fn a_recorded_transition_is_scanned_for_credentials() {
        let record = LoginTransitionRecord {
            from_state: LoginStage::SessionIssuance.as_str(),
            authoritative_input: "session_grant_admission",
            next_state: LoginStage::Workspace.as_str(),
            reason: "recovery_key=abandon hope",
            outcome: Some(LoginTransitionOutcome::AuthorizedLogin.as_str()),
            correlation: &LoginCorrelation::default(),
        };
        let value = serde_json::to_value(&record).unwrap();

        assert!(crate::secret_surface::find_json_violation("login_transition", &value).is_some());

        for leaked in [
            "account_handoff_grant=eyJhbGciOi",
            "grant_jwt=eyJhbGciOi",
            "session_credential=eyJhbGciOi",
            "password=1amTester!",
            "root_seed=AAAA",
            "private_key=AAAA",
        ] {
            let leaking = LoginTransitionRecord {
                reason: leaked,
                ..record
            };
            let value = serde_json::to_value(&leaking).unwrap();
            assert!(
                crate::secret_surface::find_json_violation("login_transition", &value).is_some(),
                "{leaked}"
            );
        }

        let clean = LoginTransitionRecord {
            reason: "accepted_device_session_issued",
            ..record
        };
        let clean = serde_json::to_value(&clean).unwrap();
        assert_eq!(
            crate::secret_surface::find_json_violation("login_transition", &clean),
            None
        );
    }

    #[test]
    fn onboarding_inventory_is_secret_free_and_rejects_secret_reasons() {
        let facts = garth::BoundCompletionResumeFacts {
            handoff: garth::BoundCompletionHandoffState::ActiveBound,
            checkpoint_stage: garth::BoundCompletionCheckpointStage::Accepted,
            recovery_policy: garth::BoundCompletionMaterialState::NotRequired,
            device_id: garth::BoundCompletionMaterialState::Present,
            signing_seed: garth::BoundCompletionMaterialState::Present,
            grant_binding_key: garth::BoundCompletionMaterialState::Absent,
            session_grant: garth::BoundCompletionMaterialState::Absent,
            recovery_evidence: garth::BoundCompletionMaterialState::Absent,
            hpke_private_key: garth::BoundCompletionMaterialState::ReadError,
            authority_matches: true,
            device_slot_matches: true,
            grant_matches_account: false,
            grant_is_live: false,
            grant_binding_matches_handoff: false,
        };
        let inventory = OnboardingCompletionInventory {
            recovery_policy: material_state_name(facts.recovery_policy),
            device_id: material_state_name(facts.device_id),
            signing_seed: material_state_name(facts.signing_seed),
            grant_binding_key: material_state_name(facts.grant_binding_key),
            session_grant: material_state_name(facts.session_grant),
            recovery_evidence: material_state_name(facts.recovery_evidence),
            hpke_private_key: material_state_name(facts.hpke_private_key),
            authority_matches: facts.authority_matches,
            device_slot_matches: facts.device_slot_matches,
            grant_matches_account: facts.grant_matches_account,
            grant_is_live: facts.grant_is_live,
            grant_binding_matches_handoff: facts.grant_binding_matches_handoff,
        };
        let clean = serde_json::to_value(OnboardingCompletionRecord {
            origin: OnboardingCompletionOrigin::ResumeReissue.as_str(),
            outcome: OnboardingCompletionOutcome::Classified.as_str(),
            reason: "reissue_grant",
            correlation: &LoginCorrelation::default(),
            inventory: Some(inventory),
        })
        .unwrap();
        assert_eq!(
            crate::secret_surface::find_json_violation("onboarding_completion_transition", &clean),
            None
        );

        let leaking = serde_json::to_value(OnboardingCompletionRecord {
            origin: OnboardingCompletionOrigin::ResumeReissue.as_str(),
            outcome: OnboardingCompletionOutcome::Failed.as_str(),
            reason: "grant_jwt=eyJhbGciOi",
            correlation: &LoginCorrelation::default(),
            inventory: None,
        })
        .unwrap();
        assert!(
            crate::secret_surface::find_json_violation(
                "onboarding_completion_transition",
                &leaking
            )
            .is_some()
        );
    }

    #[test]
    fn recovery_needs_an_admission_outcome_for_a_bound_handoff() {
        let _guard = GLOBAL_STATE.lock();
        let correlation = LoginCorrelation::default()
            .with_handoff_request_id("ak:request:019f0000-0000-7000-8000-0000000000a1");

        assert!(
            record_recovery_surface_opened(
                RecoveryEntryReason::UserSelectedInDeviceSetup,
                &correlation,
                false,
            ),
            "an unbound handoff has no admission outcome to wait for"
        );

        note_bound_admission_outcome("ak:request:019f0000-0000-7000-8000-0000000000a1");
        assert!(record_recovery_surface_opened(
            RecoveryEntryReason::UserSelectedInDeviceSetup,
            &correlation,
            true,
        ));
    }

    #[test]
    fn observed_admission_outcomes_stay_bounded_and_deduplicated() {
        let mut observed = Vec::new();
        for index in 0..(OBSERVED_ADMISSION_CAPACITY + 4) {
            assert!(push_bounded_admission_outcome(
                &mut observed,
                &format!("ak:request:bounded-{index}")
            ));
            assert!(observed.len() <= OBSERVED_ADMISSION_CAPACITY);
        }

        assert_eq!(observed.len(), OBSERVED_ADMISSION_CAPACITY);
        assert!(!push_bounded_admission_outcome(
            &mut observed,
            "ak:request:bounded-11"
        ));
        assert_eq!(
            observed.first().map(String::as_str),
            Some("ak:request:bounded-4"),
            "the oldest entry is evicted first"
        );
    }
}
