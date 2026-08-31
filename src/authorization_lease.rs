//! Client-held [`AuthorizationLease`](arkret_wire::AuthorizationLease) store.
//!
//! `zh/authz/offline-publication.md`: authorization leases are used only for
//! an explicitly delayed/offline publication window. Ordinary online Event
//! submission carries the complete signed Event and is admitted atomically
//! against current accepted state.
//!
//! The authenticated Station issues leases through the standard
//! `ak.self.authorization_leases.command.issue.v1` operation after a read-only
//! pre-admission pass. The client never mints, edits, or extends lease bytes.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use arkret_sdk::EventPayloadExt as _;
use arkret_wire::{AuthorizationLease, ControlProposalAuthorityAck};

/// No usable lease covers this Event's actor and signed scope.
#[derive(Clone, Debug, thiserror::Error)]
pub enum AuthorizationLeaseUnavailable {
    #[error(
        "no authorization lease is held for {actor_id} in this scope — \
         first publication is blocked until the account is re-authorized"
    )]
    Missing { actor_id: String },
    #[error(
        "the authorization lease for {actor_id} expired at {expires_at} — \
         first publication is blocked until the account is re-authorized"
    )]
    Expired {
        actor_id: String,
        expires_at: String,
    },
}

type LeaseKey = (String, String, String, String, String, String);

fn leases() -> &'static Mutex<BTreeMap<LeaseKey, AuthorizationLease>> {
    static LEASES: OnceLock<Mutex<BTreeMap<LeaseKey, AuthorizationLease>>> = OnceLock::new();
    LEASES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

type ControlProposalAckKey = (String, String, String);

fn local_control_proposal_acks()
-> &'static Mutex<BTreeMap<ControlProposalAckKey, ControlProposalAuthorityAck>> {
    static ACKS: OnceLock<Mutex<BTreeMap<ControlProposalAckKey, ControlProposalAuthorityAck>>> =
        OnceLock::new();
    ACKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn lease_key(lease: &AuthorizationLease) -> anyhow::Result<LeaseKey> {
    Ok((
        lease.actor_id.signing_principal_id().as_str().to_owned(),
        lease.device_id.as_str().to_owned(),
        serde_json::to_string(&lease.scope_ref)?,
        lease.action.clone(),
        serde_json::to_string(&lease.basis_ref)?,
        lease
            .authority_set_ref
            .authority_set_digest
            .as_str()
            .to_owned(),
    ))
}

/// Install an authority-issued lease for its own actor and scope.
///
/// The lease is validated structurally first: a malformed lease would be
/// rejected at ingress anyway, and holding one would make the client believe it
/// can still publish.
pub fn install_lease(lease: AuthorizationLease) -> anyhow::Result<()> {
    lease
        .validate_structural()
        .map_err(|error| anyhow::anyhow!("authorization lease is invalid: {error}"))?;
    let key = lease_key(&lease)?;
    let mut held = leases().lock().unwrap_or_else(PoisonError::into_inner);
    held.retain(|candidate, _| {
        candidate.0 != key.0
            || candidate.1 != key.1
            || candidate.2 != key.2
            || candidate.3 != key.3
            || candidate.4 != key.4
            || candidate.5 == key.5
    });
    if matches!(lease.basis_ref, arkret_wire::LeaseBasisRef::AnchorUnit(_)) {
        held.retain(|candidate, _| {
            candidate.0 != key.0
                || candidate.1 != key.1
                || candidate.2 != key.2
                || candidate.3 != key.3
                || candidate.4 == key.4
        });
    }
    held.insert(key, lease);
    Ok(())
}

/// Drop every held lease (sign-out, account switch, revocation notice).
pub fn clear_leases() {
    leases()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    local_control_proposal_acks()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
}

/// The unexpired lease bound to this Event's actor and signed scope.
///
/// The lease binds `actor_id` and `scope_ref` exactly — a lease may only narrow
/// an authorization that already exists in its basis, so it can never be reused
/// across scopes.
pub fn lease_for_event(
    event: &arkret_sdk::Event,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AuthorizationLease, AuthorizationLeaseUnavailable> {
    let missing = || AuthorizationLeaseUnavailable::Missing {
        actor_id: event.actor_id.signing_principal_id().as_str().to_owned(),
    };
    let scope = serde_json::to_string(&event.scope_ref).map_err(|_| missing())?;
    let expected_basis = if let Some(seal_ref) = &event.seal_ref {
        serde_json::to_string(&arkret_wire::LeaseBasisRef::Seal(seal_ref.clone()))
            .map_err(|_| missing())?
    } else if let Some(seal_basis) = &event.seal_basis {
        serde_json::to_string(&arkret_wire::LeaseBasisRef::Joined(seal_basis.clone()))
            .map_err(|_| missing())?
    } else {
        String::new()
    };
    let held = leases().lock().unwrap_or_else(PoisonError::into_inner);
    let mut matching = held
        .iter()
        .filter(|((actor_id, _, lease_scope, action, basis, _), lease)| {
            actor_id == event.actor_id.signing_principal_id().as_str()
                && lease_scope == &scope
                && (expected_basis.is_empty() || basis == &expected_basis)
                && lease_covers_event_kind(action, event.kind.as_str())
                && lease.actor_id == event.actor_id
                && lease.scope_ref == event.scope_ref
        })
        .map(|(_, lease)| lease)
        .collect::<Vec<_>>();
    matching.sort_by_key(|lease| lease.expires_at);
    let lease = matching
        .iter()
        .rev()
        .find(|lease| lease.expires_at > now)
        .copied()
        .or_else(|| matching.last().copied())
        .cloned()
        .ok_or_else(missing)?;
    if lease.expires_at <= now {
        return Err(AuthorizationLeaseUnavailable::Expired {
            actor_id: event.actor_id.signing_principal_id().as_str().to_owned(),
            expires_at: arkret_sdk::canonical::format_timestamp_canonical(lease.expires_at),
        });
    }
    Ok(lease)
}

fn lease_covers_event_kind(action: &str, event_kind: &str) -> bool {
    arkret_schema::capability_action(action)
        .is_some_and(|descriptor| descriptor.target_event_kinds.contains(&event_kind))
        || action == event_kind
}

/// Ask the authenticated Station to validate final signed Events and
/// issue one publication lease per Event, then install the returned leases.
pub async fn acquire_for_events(
    http: &arkret_sdk::http_client::Client,
    events: &[arkret_sdk::Event],
    digest_suites: &[arkret_sdk::DigestSuite],
) -> anyhow::Result<Vec<AuthorizationLease>> {
    if events.is_empty() {
        anyhow::bail!("authorization lease issuance requires at least one Event");
    }
    let request = arkret_wire::AuthorizationLeaseIssueRequestBody {
        events: events.to_vec(),
        intents: Vec::new(),
    };
    let idempotency_key = crate::operation::uuid_v7();
    for event in events {
        tracing::warn!(
            event_id = %event.event_id,
            kind = %event.kind.as_str(),
            seal_ref = ?event.seal_ref.as_ref().map(|seal| seal.as_str()),
            authorization_ref = ?event.authorization_ref,
            "requesting publication lease for signed Event"
        );
    }
    let outcome = http
        .issue_authorization_leases(
            &request,
            digest_suites,
            &arkret_sdk::http_client::ClientRequestOptions::new()
                .request_id(idempotency_key.clone())
                .idempotency_key(idempotency_key),
        )
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "publication lease issuance rejected by server");
            anyhow::Error::from(error)
        })?;
    tracing::warn!(
        leases = outcome.authorization_leases.len(),
        "publication leases issued"
    );
    for (event, lease) in events.iter().zip(&outcome.authorization_leases) {
        if lease.actor_id != event.actor_id
            || lease.scope_ref != event.scope_ref
            || !lease_covers_event_kind(&lease.action, event.kind.as_str())
        {
            anyhow::bail!(
                "authorization lease does not cover requested Event {}",
                event.event_id
            );
        }
        install_lease(lease.clone())?;
    }
    Ok(outcome.authorization_leases)
}

/// Ask the authenticated Station for authorization of one registered
/// non-Event operation. The server rederives the current basis and authority
/// policy; the client-provided intent is only the typed target.
pub async fn acquire_for_intent(
    http: &arkret_sdk::http_client::Client,
    intent: arkret_wire::AuthorizationLeaseIssueIntent,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<AuthorizationLease> {
    let request = arkret_wire::AuthorizationLeaseIssueRequestBody {
        events: Vec::new(),
        intents: vec![intent.clone()],
    };
    let idempotency_key = crate::operation::uuid_v7();
    let outcome = http
        .issue_authorization_leases(
            &request,
            &[digest_suite],
            &arkret_sdk::http_client::ClientRequestOptions::new()
                .request_id(idempotency_key.clone())
                .idempotency_key(idempotency_key),
        )
        .await
        .map_err(anyhow::Error::from)?;
    let [lease] = outcome.authorization_leases.as_slice() else {
        anyhow::bail!("authorization lease response must contain exactly one lease");
    };
    if lease.scope_ref != intent.scope_ref
        || lease.action != intent.action
        || lease.authorization_rule_id != intent.authorization_rule_id
        || lease.risk_tier != intent.risk_tier
        || lease.basis_ref != intent.basis_ref
    {
        anyhow::bail!("authorization lease does not match the requested operation intent");
    }
    install_lease(lease.clone())?;
    Ok(lease.clone())
}

/// Keep a still-valid held lease, otherwise acquire a replacement for the
/// complete atomic request so anchor-unit cardinality and order stay bound.
pub async fn ensure_for_events(
    http: &arkret_sdk::http_client::Client,
    events: &[arkret_sdk::Event],
    digest_suites: &[arkret_sdk::DigestSuite],
) -> anyhow::Result<()> {
    if events.is_empty() {
        anyhow::bail!("authorization lease issuance requires at least one Event");
    }
    if events
        .iter()
        .any(|event| event.seal_ref.is_none() && event.seal_basis.is_none())
    {
        acquire_for_events(http, events, digest_suites).await?;
        return Ok(());
    }
    let now = crate::clock::now_utc();
    if events
        .iter()
        .all(|event| lease_for_event(event, now).is_ok())
    {
        return Ok(());
    }
    acquire_for_events(http, events, digest_suites).await?;
    Ok(())
}

/// Wrap a signed Event into its initial publication.
pub fn initial_submission(
    event: &arkret_sdk::Event,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    let authorization_lease = lease_for_event(event, crate::clock::now_utc())?;
    Ok(arkret_wire::EventInitialSubmission {
        event: event.clone(),
        authorization_lease: Some(authorization_lease),
        // The submit gate attaches basis closure only when the receiver reports
        // a shortfall; a bounded superset is always acceptable, so nothing is
        // guessed here.
        cba_proof_bundles: Vec::new(),
        // Control Moves acquire their authority Ack separately, including
        // caller-proven closed anchors. DataEvents keep it absent.
        control_proposal_ack: None,
        membership_compensation_evidence: None,
    })
}

/// Build the publication wrapper required by a normal events.submit call.
///
/// A non-genesis Control Move resolves its [`ProposalAuthorityRoute`] first,
/// then either signs the authority Ack locally or asks the authenticated
/// Station for its independently signed one, and finally assembles the
/// canonical Ack set. DataEvents do not enter the proposal protocol and
/// therefore keep the Ack field absent.
pub async fn standard_initial_submission(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    let mut submission = arkret_wire::EventInitialSubmission::online(event.clone());
    let managed_genesis = is_agent_pcr_genesis(event);
    if event.kind.is_control_plane() {
        let authority_ack = match resolve_proposal_authority_route(http, event).await? {
            ProposalAuthorityRoute::AuthorityAuthoredSelfPrincipal => None,
            ProposalAuthorityRoute::LocalPrincipal(local) => {
                let signer = crate::event_signer::active_signer().ok_or_else(|| {
                    anyhow::anyhow!("PCR Control Proposal Ack requires an active device signer")
                })?;
                Some(local.issue_authority_ack(event, digest_suite, &signer)?)
            }
            ProposalAuthorityRoute::StationAdmission => None,
        };
        if let Some(authority_ack) = authority_ack {
            submission.control_proposal_ack = Some(
                arkret_wire::ControlProposalAck::from_authority_acks_protocol_bounds(vec![
                    authority_ack,
                ])?,
            );
        }
    }
    submission
        .validate_structural_in_context(
            if managed_genesis {
                arkret_wire::EventSubmitContext::AnchorUnit
            } else {
                arkret_wire::EventSubmitContext::Standard
            },
            digest_suite,
        )
        .map_err(anyhow::Error::from)?;
    Ok(submission)
}

/// Build an online publication for a human self-PCR Control Move from the
/// caller's already-verified durable bootstrap evidence.
///
/// Human PCR history is deliberately not available through every ordinary
/// Realm scan.  A caller that already verified the exact founding create and
/// bootstrap Seal must therefore carry that create into authority resolution
/// instead of trying to rediscover it through `events_read_all_pages`.
pub fn standard_authority_authored_self_principal_submission(
    event: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
    accepted_create: &arkret_sdk::Event,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    self_principal_pcr_authority_set_ref_from_events(event, std::slice::from_ref(accepted_create))?;
    let submission = arkret_wire::EventInitialSubmission::online(event.clone());
    submission
        .validate_structural_in_context(arkret_wire::EventSubmitContext::Standard, digest_suite)
        .map_err(anyhow::Error::from)?;
    Ok(submission)
}

/// Build an explicitly delayed/offline submission from a held lease.
///
/// Unlike [`standard_initial_submission`], this preserves the fixed lease
/// window and obtains any external Control Move Control Proposal Ack before the
/// Event can be queued for later delivery.
// The `expect` below asserts the invariant named in its message — this
// constructor always holds a lease; a `?` rewrite would add an error path no
// caller can reach.
#[allow(clippy::expect_used)]
pub async fn delayed_initial_submission(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    let mut submission = initial_submission(event)?;
    let managed_genesis = is_agent_pcr_genesis(event);
    if event.kind.is_control_plane() {
        let authority_ack = match resolve_proposal_authority_route(http, event).await? {
            ProposalAuthorityRoute::AuthorityAuthoredSelfPrincipal => None,
            ProposalAuthorityRoute::LocalPrincipal(local) => {
                let signer = crate::event_signer::active_signer().ok_or_else(|| {
                    anyhow::anyhow!("PCR Control Proposal Ack requires an active device signer")
                })?;
                Some(local.issue_authority_ack(event, digest_suite, &signer)?)
            }
            ProposalAuthorityRoute::StationAdmission => Some(
                http.issue_control_proposal_ack(
                    &arkret_wire::ControlProposalAckIssueRequest {
                        event: event.clone(),
                        authorization_lease: submission
                            .authorization_lease
                            .clone()
                            .expect("delayed submission was constructed with a lease"),
                        cba_proof_bundles: submission.cba_proof_bundles.clone(),
                    },
                    digest_suite,
                )
                .await
                .map_err(anyhow::Error::from)?
                .authority_ack,
            ),
        };
        if let Some(authority_ack) = authority_ack {
            submission.control_proposal_ack = Some(
                arkret_wire::ControlProposalAck::from_authority_acks_protocol_bounds(vec![
                    authority_ack,
                ])?,
            );
        }
    }
    submission
        .validate_structural_in_context(
            if managed_genesis {
                arkret_wire::EventSubmitContext::AnchorUnit
            } else {
                arkret_wire::EventSubmitContext::Standard
            },
            digest_suite,
        )
        .map_err(anyhow::Error::from)?;
    Ok(submission)
}

/// Build a delayed publication for an authority-authored human self-PCR Move.
///
/// The caller supplies the accepted founding create it has already verified as
/// part of the PCR bootstrap evidence. A recovery-material gate cannot depend
/// on the ordinary Realm scan exposing that create before the gate completes;
/// the signed create plus its accepted bootstrap Seal are the authority basis.
/// This constructor therefore validates the exact immutable self-PCR notary
/// locally and always omits a separate Control Proposal Ack.
pub fn delayed_authority_authored_self_principal_submission(
    event: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
    accepted_create: &arkret_sdk::Event,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    self_principal_pcr_authority_set_ref_from_events(event, std::slice::from_ref(accepted_create))?;
    let submission = initial_submission(event)?;
    submission
        .validate_structural_in_context(arkret_wire::EventSubmitContext::Standard, digest_suite)
        .map_err(anyhow::Error::from)?;
    Ok(submission)
}

/// Who signs a Control Move's Control Proposal Ack.
///
/// This is the single place in Inkson that answers the question. Every caller —
/// standard publication, Agent PCR writes, and fresh-device recovery —
/// resolves a route here instead of re-deriving an authority digest or picking a
/// signer from a Realm id, a `#fragment`, or an Event kind. A route can only be
/// built from accepted authority evidence, so a future policy or signer-binding
/// change has exactly one site to update.
pub(crate) enum ProposalAuthorityRoute {
    /// The current device authored a human principal's own PCR Control Move.
    /// The accepted successor Seal is the sole authority decision, so the
    /// submission must omit a second Control Proposal Ack.
    AuthorityAuthoredSelfPrincipal,
    /// The already-authenticated receiving Station performs the
    /// atomic admission check (or issues the delayed-publication Ack) from its
    /// accepted state. This branch performs no DID/PCR resolution in Inkson.
    StationAdmission,
    /// This device holds the whole proposal authority for the Realm.
    LocalPrincipal(LocalAccountAuthority),
}

/// A resolved local proposal authority: the immutable authority-set digest and
/// the principal whose device key must sign under it.
pub(crate) struct LocalAccountAuthority {
    authority_set_ref: arkret_sdk::Hash,
    signer_actor_id: arkret_sdk::DidCoreId,
}

impl LocalAccountAuthority {
    /// Sign, or reuse an already signed, authority Ack for this proposal.
    pub(crate) fn issue_authority_ack(
        &self,
        event: &arkret_sdk::Event,
        digest_suite: arkret_sdk::DigestSuite,
        signer: &crate::event_signer::InksonEventSigner,
    ) -> anyhow::Result<ControlProposalAuthorityAck> {
        let signer_principal = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
        if arkret_sdk::project_did_to_core_id(&signer_principal)? != self.signer_actor_id {
            anyhow::bail!("active signer does not project to the proposal authority actor");
        }
        let verification_method = signer.verification_method_for_principal(&signer_principal)?;
        let proposal_digest =
            arkret_sdk::Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
        let cache_key = (
            proposal_digest.to_string(),
            self.authority_set_ref.to_string(),
            verification_method.as_str().to_owned(),
        );
        if let Some(ack) = local_control_proposal_acks()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&cache_key)
            .cloned()
        {
            return Ok(ack);
        }

        let adapter = signer.payload_signer_adapter_for_principal(&signer_principal)?;
        let member = ControlProposalAuthorityAck::issue_with_signer(
            event.realm_id.clone(),
            proposal_digest,
            self.authority_set_ref.clone(),
            crate::clock::now_utc(),
            arkret_wire::ControlProposalDecisionPolicy::default(),
            &adapter,
        )?;
        local_control_proposal_acks()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(cache_key, member.clone());
        Ok(member)
    }
}

fn is_agent_pcr_control(event: &arkret_sdk::Event) -> bool {
    let Some(executor) = event.executed_by.as_ref() else {
        return false;
    };
    let Some((controller, fragment)) = event
        .authorization_ref
        .as_ref()
        .and_then(|reference| reference.as_str().rsplit_once('#'))
    else {
        return false;
    };
    if executor == &event.actor_id || fragment != "managed-controller" {
        return false;
    }
    arkret_sdk::Did::new(controller.to_owned())
        .ok()
        .and_then(|did| arkret_sdk::project_did_to_core_id(&did).ok())
        .is_some_and(|core_id| core_id == *event.actor_id.signing_principal_id())
}

pub(crate) fn is_agent_pcr_genesis(event: &arkret_sdk::Event) -> bool {
    event.kind == arkret_sdk::EventKind::RealmCreate && is_agent_pcr_control(event)
}

/// The two authority routes a Control Move can take, decided from the Event
/// alone. Resolving the route's material is a separate step because only the
/// managed branch needs accepted Realm history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProposalAuthorityRouteKind {
    /// A pre-join membership proposal is intentionally unable to read Realm
    /// history. The receiving Station validates its candidate basis
    /// and pending invite/application state directly.
    PreJoinStationAdmission,
    /// An ordinary Realm is admitted by the already-authenticated receiving
    /// Station. This is not a human current-DID/PCR lookup.
    StationAdmission,
    /// A Agent's Control Realm, written by its delegated controller.
    AgentPcr,
    /// A controller's own principal-control Realm.  Agent provisioning is a
    /// self-PCR Control Move, so the controller device signs its proposal Ack
    /// under the immutable notary declared by that Realm's accepted genesis.
    SelfPrincipalPcr,
}

fn classify_proposal_authority_route(
    event: &arkret_sdk::Event,
) -> anyhow::Result<ProposalAuthorityRouteKind> {
    let pre_join_membership_proposal = event.kind == arkret_sdk::EventKind::InviteAccept
        || (event.kind == arkret_sdk::EventKind::MemberState
            && serde_json::to_value(&event.payload)
                .ok()
                .and_then(|payload| {
                    payload
                        .get("membership")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .is_some_and(|membership| matches!(membership.as_str(), "join" | "knock")));
    if pre_join_membership_proposal {
        return Ok(ProposalAuthorityRouteKind::PreJoinStationAdmission);
    }
    // The managed-delegation shape is checked first: it names both a different
    // executor and the Agent's `#managed-controller` delegation, so it can only
    // ever be satisfied by a Agent PCR write. Deciding it before the
    // Realm-id comparison keeps the authority digest and the signer choice from
    // ever coming from two different answers.
    if is_agent_pcr_control(event) {
        return Ok(ProposalAuthorityRouteKind::AgentPcr);
    }
    let recovery_policy_set = if event.kind == arkret_sdk::EventKind::PolicySet {
        let payload = event
            .typed_payload::<arkret_sdk::event_spec::PolicySet>()
            .map_err(|error| anyhow::anyhow!("decode policy-set authority route: {error}"))?;
        matches!(payload.value, arkret_sdk::PolicyDocument::RecoveryPolicy(_))
    } else {
        false
    };
    if event.kind == arkret_sdk::EventKind::AgentProvision || recovery_policy_set {
        return Ok(ProposalAuthorityRouteKind::SelfPrincipalPcr);
    }
    Ok(ProposalAuthorityRouteKind::StationAdmission)
}

async fn resolve_proposal_authority_route(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<ProposalAuthorityRoute> {
    match classify_proposal_authority_route(event)? {
        ProposalAuthorityRouteKind::PreJoinStationAdmission => {
            Ok(ProposalAuthorityRoute::StationAdmission)
        }
        ProposalAuthorityRouteKind::StationAdmission => {
            let accepted = http
                .events_read_all_pages(event.realm_id.as_str())
                .await
                .map_err(anyhow::Error::from)?;
            let accepted_events = crate::models::require_complete_event_rows(
                &accepted.events,
                "proposal authority route resolution",
            )?;
            match self_principal_pcr_authority_set_ref_from_events(event, &accepted_events) {
                Ok(_) => Ok(ProposalAuthorityRoute::AuthorityAuthoredSelfPrincipal),
                Err(_) => Ok(ProposalAuthorityRoute::StationAdmission),
            }
        }
        ProposalAuthorityRouteKind::AgentPcr => {
            // The single-Event managed PCR genesis is a caller-proven closed
            // anchor unit. Its founding notary material is completely derived
            // from that signed create, so the delegated controller can issue
            // the Control Proposal Ack before the Event is durable. Successors
            // continue to resolve the same immutable authority from accepted
            // genesis history.
            let authority_set_ref = if is_agent_pcr_genesis(event) {
                arkret_bootstrap::AgentPcrGenesisAuthority::from_delegated_create(event, &|event| {
                    crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256)
                })
                .map(|authority| authority.authority_set_ref().clone())
                .map_err(|error| {
                    anyhow::anyhow!("Agent PCR candidate genesis authority is unavailable: {error}")
                })?
            } else {
                let accepted = http
                    .events_read_all_pages(event.realm_id.as_str())
                    .await
                    .map_err(anyhow::Error::from)?;
                let accepted_events = crate::models::require_complete_event_rows(
                    &accepted.events,
                    "Agent PCR authority resolution",
                )?;
                agent_pcr_authority_set_ref_from_events(event, &accepted_events)?
            };
            // A Agent PCR write is executed by the delegated
            // controller, so the controller's device key — not the Agent's —
            // signs under the founding notary profile.
            let signer_principal = event
                .executed_by
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Agent PCR controls always carry executed_by"))?;
            Ok(ProposalAuthorityRoute::LocalPrincipal(
                LocalAccountAuthority {
                    authority_set_ref,
                    signer_actor_id: signer_principal.signing_principal_id().clone(),
                },
            ))
        }
        ProposalAuthorityRouteKind::SelfPrincipalPcr => {
            let accepted = http
                .events_read_all_pages(event.realm_id.as_str())
                .await
                .map_err(anyhow::Error::from)?;
            let accepted_events = crate::models::require_complete_event_rows(
                &accepted.events,
                "self principal PCR authority resolution",
            )?;
            self_principal_pcr_authority_set_ref_from_events(event, &accepted_events)?;
            Ok(ProposalAuthorityRoute::AuthorityAuthoredSelfPrincipal)
        }
    }
}

fn self_principal_pcr_authority_set_ref_from_events(
    event: &arkret_sdk::Event,
    accepted_events: &[arkret_sdk::Event],
) -> anyhow::Result<arkret_sdk::Hash> {
    let mut creates = accepted_events.iter().filter(|candidate| {
        candidate.kind == arkret_sdk::EventKind::RealmCreate
            && candidate.realm_id == event.realm_id
            && candidate.actor_id == event.actor_id
    });
    let create = creates
        .next()
        .ok_or_else(|| anyhow::anyhow!("self principal PCR create Event is unavailable"))?;
    if creates.next().is_some() {
        anyhow::bail!("self principal PCR has multiple matching create Events");
    }
    let payload: arkret_sdk::RealmCreatePayload = serde_json::from_value(
        serde_json::to_value(&create.payload)
            .map_err(|error| anyhow::anyhow!("encode self PCR genesis: {error}"))?,
    )
    .map_err(|error| anyhow::anyhow!("decode self PCR genesis: {error}"))?;
    if payload.object.purpose != arkret_sdk::RealmPurpose::PrincipalControl {
        anyhow::bail!("Event is not in a principal-control Realm");
    }
    let arkret_sdk::NotaryValue::SingleSigner { signer, .. } = &payload.object.notary else {
        anyhow::bail!("self principal PCR genesis does not use a single-signer notary");
    };
    if signer.actor_id.signing_principal_id() != event.actor_id.signing_principal_id() {
        anyhow::bail!("self principal PCR notary does not match the provision Event actor");
    }
    arkret_sdk::Hash::new(crate::canonical::canonical_sha256(&payload.object.notary)?)
        .map_err(anyhow::Error::from)
}

fn agent_pcr_authority_set_ref_from_events(
    event: &arkret_sdk::Event,
    accepted_events: &[arkret_sdk::Event],
) -> anyhow::Result<arkret_sdk::Hash> {
    let mut creates = accepted_events.iter().filter(|candidate| {
        candidate.kind == arkret_sdk::EventKind::RealmCreate
            && candidate.realm_id == event.realm_id
            && candidate.actor_id == event.actor_id
            && candidate.executed_by == event.executed_by
            && candidate.authorization_ref == event.authorization_ref
    });
    let create = creates
        .next()
        .ok_or_else(|| anyhow::anyhow!("Agent PCR create Event is unavailable"))?;
    if creates.next().is_some() {
        anyhow::bail!("Agent PCR has multiple matching create Events");
    }
    // The proposal authority is immutable genesis material. The SDK's genesis
    // type accepts only the accepted create, so a later transition that needs
    // frozen pre-state (for example `ak.agent.key.revoke`) can never be dragged
    // into an authoring query.
    arkret_bootstrap::AgentPcrGenesisAuthority::from_accepted_create(create, &|event| {
        crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256)
    })
    .map(|authority| authority.authority_set_ref().clone())
    .map_err(|error| anyhow::anyhow!("Agent PCR genesis authority is unavailable: {error}"))
}

/// Lease / ingress receipt fixtures for tests in other modules.
///
/// A client cannot mint either object for real (see the module header), so
/// tests that need the publication evidence build a structurally valid pair
/// here rather than each growing its own hand-rolled shape.
#[cfg(test)]
pub(crate) mod test_support {
    use chrono::{DateTime, Utc};

    pub(crate) fn lease(
        realm_id: arkret_sdk::RealmId,
        actor_id: &str,
        action: &str,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> arkret_wire::AuthorizationLease {
        let scope_ref = arkret_sdk::ScopeRef::Realm { realm_id };
        let authority_set_policy = realm_admission_policy(scope_ref.clone(), action);
        let authority_set_ref = arkret_wire::AuthoritySetRef {
            authority_set_id: authority_set_policy.authority_set_id.clone(),
            authority_set_digest: authority_set_policy.digest().unwrap(),
        };
        let mut lease = arkret_wire::AuthorizationLease {
            authorization_lease_id: arkret_wire::AuthorizationLeaseId::new(
                "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
            )
            .unwrap(),
            basis_ref: arkret_wire::LeaseBasisRef::Seal(
                arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
            actor_id: crate::mls_api_helpers::local_account_actor_id(actor_id).unwrap(),
            device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb")
                .unwrap(),
            scope_ref,
            action: action.to_owned(),
            authorization_rule_id: "realm_admission".to_owned(),
            risk_tier: arkret_wire::RiskTier::Low,
            issued_at,
            expires_at,
            authority_set_ref,
            authority_set_policy,
            proofs: Vec::new(),
        };
        let digest = lease.lease_digest().unwrap();
        lease.proofs = vec![issuer_proof(
            "did:webvh:z6mkfixture:authority.example#key-1",
            digest,
            issued_at,
        )];
        lease
    }

    fn realm_admission_policy(
        scope_ref: arkret_sdk::ScopeRef,
        action: &str,
    ) -> arkret_wire::AuthoritySetPolicy {
        arkret_wire::AuthoritySetPolicy {
            schema: arkret_wire::SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            policy_kind: arkret_wire::AuthoritySetPolicyKind::RealmAdmission,
            scope_ref,
            source: arkret_wire::AuthoritySetPolicySource {
                source_kind: arkret_wire::AuthoritySetSourceKind::RealmControl,
                source_ref: format!("ak:seal:sha256:{}", "a".repeat(64)),
                source_digest: arkret_sdk::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![arkret_wire::AuthoritySetAuthorizationRule {
                rule_id: "realm_admission".to_owned(),
                issuer_role: arkret_wire::AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec![action.to_owned()],
                issuers: vec![arkret_wire::AuthoritySetIssuer {
                    verification_method: arkret_sdk::DidUrl::new(
                        "did:webvh:z6mkfixture:authority.example#key-1",
                    )
                    .unwrap(),
                }],
                threshold: 1,
            }],
        }
    }

    pub(crate) fn receipt(
        _lease: &arkret_wire::AuthorizationLease,
        received_at: DateTime<Utc>,
    ) -> arkret_wire::IngressReceipt {
        let mut receipt = arkret_wire::IngressReceipt {
            receipt_id: arkret_wire::ReceiptId::new(
                "ak:receipt:01904100-0000-7000-8000-cccccccccccc",
            )
            .unwrap(),
            event_digest: arkret_sdk::Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            qualified_ingress_did: arkret_sdk::Did::new(
                "did:webvh:z6mkfixture:ingress.example".to_owned(),
            )
            .unwrap(),
            received_at,
            ingress_frontier: vec![
                arkret_sdk::EventId::new(
                    "ak:event:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD".to_owned(),
                )
                .unwrap(),
            ],
            proofs: Vec::new(),
        };
        let digest = receipt.receipt_digest().unwrap();
        receipt.proofs = vec![issuer_proof(
            "did:webvh:z6mkfixture:ingress.example#key-1",
            digest,
            received_at,
        )];
        receipt
    }

    fn issuer_proof(
        verification_method: &str,
        payload_digest: arkret_sdk::Hash,
        created_at: DateTime<Utc>,
    ) -> arkret_sdk::PayloadProof {
        arkret_sdk::PayloadProof {
            kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned())
                .expect("test verification method is a DID URL"),
            payload_digest,
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use chrono::{TimeZone, Utc};

    use super::*;

    fn test_guard() -> MutexGuard<'static, ()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn scope() -> arkret_sdk::ScopeRef {
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
        }
    }

    fn event() -> arkret_sdk::Event {
        arkret_wire::test_support::raw_event(
            "ak.member.state",
            scope(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("000000000000-0000-00000000").unwrap(),
            serde_json::json!({}),
        )
        .unwrap()
    }

    /// A submit without a lease MUST NOT fall back to shipping the bare Event:
    /// the lease is the only thing that bounds the revocation window.
    #[test]
    fn submission_without_a_lease_fails_closed() {
        let _guard = test_guard();
        clear_leases();
        let error = initial_submission(&event()).unwrap_err().to_string();
        assert!(error.contains("re-authorized"), "{error}");
    }

    /// Only the strict managed-delegation shape routes to the controller's
    /// signer. Every near miss stays on the Agent's own authority, so a stray
    /// `#fragment` can never redirect who signs a receipt.
    #[test]
    fn agent_pcr_control_uses_the_delegated_local_authority() {
        let mut managed = event();
        managed.actor_id = arkret_sdk::ActorId::service(
            arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
        );
        let controller = arkret_sdk::Did::new("did:web:alice.example").unwrap();
        managed.executed_by = Some(
            crate::mls_api_helpers::local_account_actor_id(
                arkret_sdk::project_did_to_core_id(&controller)
                    .unwrap()
                    .as_str(),
            )
            .unwrap(),
        );
        managed.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );
        assert!(is_agent_pcr_control(&managed));

        managed.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#other-delegation").unwrap(),
        );
        assert!(!is_agent_pcr_control(&managed));

        managed.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );
        managed.executed_by = Some(managed.actor_id.clone());
        assert!(!is_agent_pcr_control(&managed));
    }

    /// Each authority route is selected by the Event alone, and
    /// none of them can be reached by a near miss of another's shape.
    #[test]
    fn every_authority_route_is_decided_from_accepted_event_authority() {
        let ordinary = event();
        assert_eq!(
            classify_proposal_authority_route(&ordinary).unwrap(),
            ProposalAuthorityRouteKind::StationAdmission,
            "an ordinary Realm write must not degrade to a local self-signature"
        );

        let mut provision = ordinary.clone();
        provision.kind = arkret_sdk::EventKind::AgentProvision;
        assert_eq!(
            classify_proposal_authority_route(&provision).unwrap(),
            ProposalAuthorityRouteKind::SelfPrincipalPcr,
            "Agent provisioning is authorized by the controller's self-PCR notary"
        );

        let mut managed = event();
        managed.actor_id = arkret_sdk::ActorId::service(
            arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
        );
        managed.executed_by = Some(
            crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:alice.example")
                .unwrap(),
        );
        managed.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );
        assert_eq!(
            classify_proposal_authority_route(&managed).unwrap(),
            ProposalAuthorityRouteKind::AgentPcr
        );

        // A delegation fragment that is not the managed-controller binding is
        // an ordinary Realm write, not a locally signable one.
        let mut foreign_delegation = managed.clone();
        foreign_delegation.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#other-delegation").unwrap(),
        );
        assert_eq!(
            classify_proposal_authority_route(&foreign_delegation).unwrap(),
            ProposalAuthorityRouteKind::StationAdmission
        );

        // Self-executed writes are never managed delegations, whatever the
        // authorization_ref claims.
        let mut self_executed = managed;
        self_executed.executed_by = Some(self_executed.actor_id.clone());
        assert_eq!(
            classify_proposal_authority_route(&self_executed).unwrap(),
            ProposalAuthorityRouteKind::StationAdmission
        );

        let mut invite_accept = event();
        invite_accept.kind = arkret_sdk::EventKind::InviteAccept;
        invite_accept.payload = serde_json::from_value(serde_json::json!({
            "invite_ref": "ak:invite:01904100-0000-7000-8000-aaaaaaaaaaaa"
        }))
        .unwrap();
        assert_eq!(
            classify_proposal_authority_route(&invite_accept).unwrap(),
            ProposalAuthorityRouteKind::PreJoinStationAdmission,
            "an invitee must not need membership-gated Realm history to submit acceptance"
        );

        let mut knock = event();
        knock.payload =
            serde_json::from_value(serde_json::json!({ "membership": "knock" })).unwrap();
        assert_eq!(
            classify_proposal_authority_route(&knock).unwrap(),
            ProposalAuthorityRouteKind::PreJoinStationAdmission,
            "a knock applicant must not need membership-gated Realm history"
        );
    }

    fn self_pcr_create_for_submission(provision: &arkret_sdk::Event) -> arkret_sdk::Event {
        let did = arkret_sdk::Did::new("did:web:alice.example").unwrap();
        let notary = crate::event_builders::agent_inception_notary(
            &did,
            &arkret_sdk::ed25519_pubkey_to_did_key_multibase(&[7_u8; 32]),
        )
        .unwrap();
        let genesis = arkret_sdk::RealmGenesis::principal_control(
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            None,
            arkret_sdk::ResolutionCommitment {
                did,
                method_history_head: format!("sha256:{}", "8".repeat(64)),
                version_id: "1-fixture".to_owned(),
            },
            arkret_sdk::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            vec![
                arkret_sdk::SchemaId::REALM_V1.to_owned(),
                arkret_sdk::ProfileId::PRINCIPAL_CONTROL_REALM_V1.to_owned(),
            ],
            arkret_sdk::CORE_REDUCER_PROFILE,
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::SecurityClass::HighAssurance,
            arkret_sdk::EncryptionProfile::MlsRfc9420,
            notary,
        )
        .unwrap();
        arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::RealmCreate.to_string(),
            arkret_sdk::ScopeRef::Realm {
                realm_id: provision.realm_id.clone(),
            },
            provision.actor_id.signing_principal_id().clone(),
            provision.actor_id.route_service_id().clone(),
            0,
            arkret_sdk::Hlc::new("000000000000-0000-00000000").unwrap(),
            serde_json::to_value(arkret_sdk::RealmCreatePayload::new(genesis)).unwrap(),
        )
        .unwrap()
    }

    /// Agent provisioning must remain authorable when the ordinary PCR scan
    /// omits bootstrap history. The caller-provided accepted create is the
    /// authority evidence; no network history lookup is part of this builder.
    #[test]
    fn authority_authored_online_submission_uses_durable_pcr_create() {
        let mut provision = event();
        provision.kind = arkret_sdk::EventKind::AgentProvision;
        provision.seal_basis = Some(arkret_sdk::SealBasis {
            leaves: vec![
                arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ],
        });
        provision
            .refresh_content_bound_identity_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap();
        let event_digest = arkret_sdk::Hash::new(
            provision
                .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        provision.proofs.push(
            arkret_sdk::ProducerEventProof {
                kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_sdk::DidUrl::new(
                    "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000001",
                )
                .unwrap(),
                event_digest,
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at: provision.created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "fixture..signature".to_owned(),
            }
            .into(),
        );
        let create = self_pcr_create_for_submission(&provision);

        let submission = standard_authority_authored_self_principal_submission(
            &provision,
            arkret_sdk::DigestSuite::Sha256,
            &create,
        )
        .unwrap();

        assert_eq!(submission.event, provision);
        assert!(submission.authorization_lease.is_none());
        assert!(submission.control_proposal_ack.is_none());

        let mut wrong_realm_create = create;
        wrong_realm_create.realm_id =
            arkret_sdk::RealmId::new("ak:realm:Abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        assert!(
            standard_authority_authored_self_principal_submission(
                &provision,
                arkret_sdk::DigestSuite::Sha256,
                &wrong_realm_create,
            )
            .is_err()
        );
    }

    #[test]
    fn agent_pcr_create_is_frozen_before_provision_commit() {
        let events = crate::event_submit::author_event_unit_for_test(
            crate::event_builders::build_agent_pcr_bootstrap_steps(
                "did:web:agent.example",
                arkret_sdk::ResolutionCommitment {
                    did: arkret_sdk::Did::new("did:web:agent.example").unwrap(),
                    method_history_head: format!("sha256:{}", "8".repeat(64)),
                    version_id: "1-Qmfixture".to_owned(),
                },
                crate::event_builders::agent_inception_notary(
                    &arkret_sdk::Did::new("did:web:agent.example").unwrap(),
                    &arkret_sdk::ed25519_pubkey_to_did_key_multibase(&[7_u8; 32]),
                )
                .unwrap(),
                "did:web:alice.example",
                "did:web:agent.example#managed-controller",
                "ak:trust_domain:did.web.example",
            )
            .expect("controller can freeze the exact PCR create locally"),
        )
        .expect("the PCR bootstrap unit authors");
        assert_eq!(events.len(), 1);
        assert!(events[0].refs.is_empty());
    }

    fn rebind_and_resign(lease: &mut AuthorizationLease, basis_ref: arkret_wire::LeaseBasisRef) {
        lease.basis_ref = basis_ref;
        let digest = lease.lease_digest().unwrap();
        lease.proofs[0].payload_digest = digest;
    }

    #[test]
    fn lookup_never_reuses_a_lease_across_basis() {
        let _guard = test_guard();
        clear_leases();
        let now = Utc.with_ymd_and_hms(2026, 7, 28, 1, 0, 0).unwrap();
        let expires_at = Utc.with_ymd_and_hms(2026, 7, 28, 8, 0, 0).unwrap();
        let realm_id = match scope() {
            arkret_sdk::ScopeRef::Realm { realm_id } => realm_id,
            _ => unreachable!(),
        };
        let mut first = test_support::lease(
            realm_id.clone(),
            "did:web:alice.example",
            "ak.member.state",
            now,
            expires_at,
        );
        let first_basis =
            arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap();
        rebind_and_resign(&mut first, arkret_wire::LeaseBasisRef::Seal(first_basis));
        install_lease(first).unwrap();

        let mut second = test_support::lease(
            realm_id,
            "did:web:alice.example",
            "ak.member.state",
            now,
            expires_at,
        );
        let second_basis =
            arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "c".repeat(64))).unwrap();
        rebind_and_resign(
            &mut second,
            arkret_wire::LeaseBasisRef::Seal(second_basis.clone()),
        );
        install_lease(second.clone()).unwrap();

        let mut target = event();
        target.seal_ref = Some(second_basis);
        let selected = lease_for_event(&target, now).unwrap();
        assert_eq!(selected.basis_ref, second.basis_ref);
        assert_eq!(leases().lock().unwrap().len(), 2);
    }

    #[test]
    fn authority_set_rotation_evicts_the_previous_partition() {
        let _guard = test_guard();
        clear_leases();
        let issued_at = Utc.with_ymd_and_hms(2026, 7, 28, 1, 0, 0).unwrap();
        let expires_at = Utc.with_ymd_and_hms(2026, 7, 28, 8, 0, 0).unwrap();
        let realm_id = match scope() {
            arkret_sdk::ScopeRef::Realm { realm_id } => realm_id,
            _ => unreachable!(),
        };
        let first = test_support::lease(
            realm_id,
            "did:web:alice.example",
            "ak.member.state",
            issued_at,
            expires_at,
        );
        install_lease(first.clone()).unwrap();

        let mut rotated = first;
        rotated.authority_set_policy.source.source_digest =
            arkret_sdk::Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap();
        rotated.authority_set_policy.source.generation_ref = "2".to_owned();
        rotated.authority_set_ref.authority_set_digest =
            rotated.authority_set_policy.digest().unwrap();
        let digest = rotated.lease_digest().unwrap();
        rotated.proofs[0].payload_digest = digest;
        let expected_digest = rotated.authority_set_ref.authority_set_digest.clone();
        install_lease(rotated).unwrap();

        let held = leases().lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(held.len(), 1);
        assert_eq!(
            held.values()
                .next()
                .unwrap()
                .authority_set_ref
                .authority_set_digest,
            expected_digest
        );
    }
}
