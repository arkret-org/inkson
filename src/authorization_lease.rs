//! Client-held [`AuthorizationLease`](arkret_wire::AuthorizationLease) store.
//!
//! `zh/authz/offline-publication.md`: authorization leases are used only for
//! an explicitly delayed/offline publication window. Ordinary online Event
//! submission carries the complete signed Event and is admitted atomically
//! against current accepted state.
//!
//! The authenticated Principal Server issues leases through the standard
//! `ak.self.authorization_leases.command.issue` operation after a read-only
//! pre-admission pass. The client never mints, edits, or extends lease bytes.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

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
        lease.actor_id.as_str().to_owned(),
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
        actor_id: event.actor_id.as_str().to_owned(),
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
            actor_id == event.actor_id.as_str()
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
            actor_id: event.actor_id.as_str().to_owned(),
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

/// Ask the authenticated Principal Server to validate final signed Events and
/// issue one publication lease per Event, then install the returned leases.
pub async fn acquire_for_events(
    http: &arkret_sdk::http_client::Client,
    events: &[arkret_sdk::Event],
) -> anyhow::Result<Vec<AuthorizationLease>> {
    if events.is_empty() {
        anyhow::bail!("authorization lease issuance requires at least one Event");
    }
    let request = arkret_wire::AuthorizationLeaseIssueRequest {
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

/// Ask the authenticated Principal Server for authorization of one registered
/// non-Event operation. The server rederives the current basis and authority
/// policy; the client-provided intent is only the typed target.
pub async fn acquire_for_intent(
    http: &arkret_sdk::http_client::Client,
    intent: arkret_wire::AuthorizationLeaseIssueIntent,
) -> anyhow::Result<AuthorizationLease> {
    let request = arkret_wire::AuthorizationLeaseIssueRequest {
        events: Vec::new(),
        intents: vec![intent.clone()],
    };
    let idempotency_key = crate::operation::uuid_v7();
    let outcome = http
        .issue_authorization_leases(
            &request,
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
) -> anyhow::Result<()> {
    if events.is_empty() {
        anyhow::bail!("authorization lease issuance requires at least one Event");
    }
    if events
        .iter()
        .any(|event| event.seal_ref.is_none() && event.seal_basis.is_none())
    {
        acquire_for_events(http, events).await?;
        return Ok(());
    }
    let now = crate::clock::now_utc();
    if events
        .iter()
        .all(|event| lease_for_event(event, now).is_ok())
    {
        return Ok(());
    }
    acquire_for_events(http, events).await?;
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
/// Principal Server for its independently signed one, and finally assembles the
/// canonical Ack set. DataEvents do not enter the proposal protocol and
/// therefore keep the Ack field absent.
pub async fn standard_initial_submission(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    let mut submission = arkret_wire::EventInitialSubmission::online(event.clone());
    let managed_genesis = is_managed_agent_pcr_genesis(event);
    if event.seal_basis.is_some() || managed_genesis {
        let authority_ack = match resolve_proposal_authority_route(http, event).await? {
            ProposalAuthorityRoute::LocalPrincipal(local) => {
                let signer = crate::event_signer::active_signer().ok_or_else(|| {
                    anyhow::anyhow!("PCR Control Proposal Ack requires an active device signer")
                })?;
                Some(local.issue_authority_ack(event, &signer)?)
            }
            ProposalAuthorityRoute::RemoteCurrentAuthority => None,
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
        .validate_structural_in_context(if managed_genesis {
            arkret_wire::EventSubmitContext::AnchorUnit
        } else {
            arkret_wire::EventSubmitContext::Standard
        })
        .map_err(anyhow::Error::from)?;
    Ok(submission)
}

/// Build an explicitly delayed/offline submission from a held lease.
///
/// Unlike [`standard_initial_submission`], this preserves the fixed lease
/// window and obtains any external Control Move Control Proposal Ack before the
/// Event can be queued for later delivery.
pub async fn delayed_initial_submission(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    let mut submission = initial_submission(event)?;
    let managed_genesis = is_managed_agent_pcr_genesis(event);
    if event.seal_basis.is_some() || managed_genesis {
        let authority_ack = match resolve_proposal_authority_route(http, event).await? {
            ProposalAuthorityRoute::LocalPrincipal(local) => {
                let signer = crate::event_signer::active_signer().ok_or_else(|| {
                    anyhow::anyhow!("PCR Control Proposal Ack requires an active device signer")
                })?;
                local.issue_authority_ack(event, &signer)?
            }
            ProposalAuthorityRoute::RemoteCurrentAuthority => {
                http.issue_control_proposal_ack(&arkret_wire::ControlProposalAckIssueRequest {
                    event: event.clone(),
                    authorization_lease: submission
                        .authorization_lease
                        .clone()
                        .expect("delayed submission was constructed with a lease"),
                    cba_proof_bundles: submission.cba_proof_bundles.clone(),
                })
                .await
                .map_err(anyhow::Error::from)?
                .authority_ack
            }
        };
        submission.control_proposal_ack = Some(
            arkret_wire::ControlProposalAck::from_authority_acks_protocol_bounds(vec![
                authority_ack,
            ])?,
        );
    }
    submission
        .validate_structural_in_context(if managed_genesis {
            arkret_wire::EventSubmitContext::AnchorUnit
        } else {
            arkret_wire::EventSubmitContext::Standard
        })
        .map_err(anyhow::Error::from)?;
    Ok(submission)
}

/// Who signs a Control Move's Control Proposal Ack.
///
/// This is the single place in Inkson that answers the question. Every caller —
/// standard publication, managed Agent PCR writes, and fresh-device recovery —
/// resolves a route here instead of re-deriving an authority digest or picking a
/// signer from a Realm id, a `#fragment`, or an Event kind. A route can only be
/// built from accepted authority evidence, so a future policy or signer-binding
/// change has exactly one site to update.
pub(crate) enum ProposalAuthorityRoute {
    /// The authenticated Principal Server holds the current authority.
    RemoteCurrentAuthority,
    /// This device holds the whole proposal authority for the Realm.
    LocalPrincipal(LocalPrincipalAuthority),
}

/// A resolved local proposal authority: the immutable authority-set digest and
/// the principal whose device key must sign under it.
pub(crate) struct LocalPrincipalAuthority {
    authority_set_ref: arkret_sdk::Hash,
    signer_principal: arkret_sdk::Did,
}

impl LocalPrincipalAuthority {
    /// A principal's own Control Realm: the notary is the principal alone, and
    /// its own device key signs.
    pub(crate) fn self_principal_control_realm(
        principal_id: &arkret_sdk::Did,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            authority_set_ref: arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(
                &arkret_wire::notary::NotaryValue::single_did(principal_id.clone()),
            )?)?,
            signer_principal: principal_id.clone(),
        })
    }

    /// Sign, or reuse an already signed, authority Ack for this proposal.
    pub(crate) fn issue_authority_ack(
        &self,
        event: &arkret_sdk::Event,
        signer: &crate::event_signer::InksonEventSigner,
    ) -> anyhow::Result<ControlProposalAuthorityAck> {
        let verification_method =
            signer.verification_method_for_principal(&self.signer_principal)?;
        let proposal_digest = arkret_sdk::Hash::new(event.event_digest()?)?;
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

        let adapter = signer.payload_signer_adapter_for_principal(&self.signer_principal)?;
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

fn is_managed_agent_pcr_control(event: &arkret_sdk::Event) -> bool {
    let managed_authorization_ref = format!("{}#managed-controller", event.actor_id);
    event
        .executed_by
        .as_ref()
        .is_some_and(|executor| executor != &event.actor_id)
        && event.authorization_ref.as_deref() == Some(managed_authorization_ref.as_str())
}

pub(crate) fn is_managed_agent_pcr_genesis(event: &arkret_sdk::Event) -> bool {
    event.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE
        && is_managed_agent_pcr_control(event)
}

/// The three authority routes a Control Move can take, decided from the Event
/// alone. Resolving the route's material is a separate step because only the
/// managed branch needs accepted Realm history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProposalAuthorityRouteKind {
    /// An ordinary Realm: the Principal Server is the current authority.
    RemoteCurrentAuthority,
    /// The actor's own Control Realm.
    SelfPrincipalControlRealm,
    /// A managed Agent's Control Realm, written by its delegated controller.
    ManagedAgentPcr,
}

fn classify_proposal_authority_route(
    event: &arkret_sdk::Event,
) -> anyhow::Result<ProposalAuthorityRouteKind> {
    // The managed-delegation shape is checked first: it names both a different
    // executor and the Agent's `#managed-controller` delegation, so it can only
    // ever be satisfied by a managed Agent PCR write. Deciding it before the
    // Realm-id comparison keeps the authority digest and the signer choice from
    // ever coming from two different answers.
    if is_managed_agent_pcr_control(event) {
        return Ok(ProposalAuthorityRouteKind::ManagedAgentPcr);
    }
    if event.realm_id
        == arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&event.actor_id))?
    {
        return Ok(ProposalAuthorityRouteKind::SelfPrincipalControlRealm);
    }
    Ok(ProposalAuthorityRouteKind::RemoteCurrentAuthority)
}

async fn resolve_proposal_authority_route(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<ProposalAuthorityRoute> {
    match classify_proposal_authority_route(event)? {
        ProposalAuthorityRouteKind::RemoteCurrentAuthority => {
            Ok(ProposalAuthorityRoute::RemoteCurrentAuthority)
        }
        ProposalAuthorityRouteKind::SelfPrincipalControlRealm => {
            Ok(ProposalAuthorityRoute::LocalPrincipal(
                LocalPrincipalAuthority::self_principal_control_realm(&event.actor_id)?,
            ))
        }
        ProposalAuthorityRouteKind::ManagedAgentPcr => {
            // The single-Event managed PCR genesis is a caller-proven closed
            // anchor unit. Its founding notary material is completely derived
            // from that signed create, so the delegated controller can issue
            // the Control Proposal Ack before the Event is durable. Successors
            // continue to resolve the same immutable authority from accepted
            // genesis history.
            let authority_set_ref = if is_managed_agent_pcr_genesis(event) {
                arkret_bootstrap::ManagedAgentPcrGenesisAuthority::from_delegated_create(
                    event,
                    &crate::operation::cell_write_projector,
                )
                .map(|authority| authority.authority_set_ref().clone())
                .map_err(|error| {
                    anyhow::anyhow!(
                        "managed Agent PCR candidate genesis authority is unavailable: {error}"
                    )
                })?
            } else {
                let accepted = http
                    .events_read_all_pages(event.realm_id.as_str())
                    .await
                    .map_err(anyhow::Error::from)?;
                managed_agent_pcr_authority_set_ref_from_events(event, &accepted.events)?
            };
            // A managed Agent PCR write is executed by the delegated
            // controller, so the controller's device key — not the Agent's —
            // signs under the founding notary profile.
            let signer_principal = event.executed_by.clone().ok_or_else(|| {
                anyhow::anyhow!("managed Agent PCR controls always carry executed_by")
            })?;
            Ok(ProposalAuthorityRoute::LocalPrincipal(
                LocalPrincipalAuthority {
                    authority_set_ref,
                    signer_principal,
                },
            ))
        }
    }
}

fn managed_agent_pcr_authority_set_ref_from_events(
    event: &arkret_sdk::Event,
    accepted_events: &[arkret_sdk::Event],
) -> anyhow::Result<arkret_sdk::Hash> {
    let mut creates = accepted_events.iter().filter(|candidate| {
        candidate.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE
            && candidate.realm_id == event.realm_id
            && candidate.actor_id == event.actor_id
            && candidate.executed_by == event.executed_by
            && candidate.authorization_ref == event.authorization_ref
    });
    let create = creates
        .next()
        .ok_or_else(|| anyhow::anyhow!("managed Agent PCR create Event is unavailable"))?;
    if creates.next().is_some() {
        anyhow::bail!("managed Agent PCR has multiple matching create Events");
    }
    // The proposal authority is immutable genesis material. The SDK's genesis
    // type accepts only the accepted create, so a later transition that needs
    // frozen pre-state (for example `ak.agent.key.revoke`) can never be dragged
    // into an authoring query.
    arkret_bootstrap::ManagedAgentPcrGenesisAuthority::from_accepted_create(
        create,
        &crate::operation::cell_write_projector,
    )
    .map(|authority| authority.authority_set_ref().clone())
    .map_err(|error| anyhow::anyhow!("managed Agent PCR genesis authority is unavailable: {error}"))
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
            actor_id: arkret_sdk::Did::new(actor_id).unwrap(),
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
        lease: &arkret_wire::AuthorizationLease,
        received_at: DateTime<Utc>,
    ) -> arkret_wire::IngressReceipt {
        let mut receipt = arkret_wire::IngressReceipt {
            receipt_id: arkret_wire::ReceiptId::new(
                "ak:receipt:01904100-0000-7000-8000-cccccccccccc",
            )
            .unwrap(),
            event_digest: arkret_sdk::Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            authorization_lease_id: lease.authorization_lease_id.clone(),
            received_at,
            service_id: arkret_sdk::Did::new("did:webvh:z6mkfixture:ingress.example").unwrap(),
            authority_set_ref: authority_set("ak.authority_set.realm_ingress.v1"),
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

    fn authority_set(id: &str) -> arkret_wire::AuthoritySetRef {
        arkret_wire::AuthoritySetRef {
            authority_set_id: id.to_owned(),
            authority_set_digest: arkret_sdk::Hash::new(format!("sha256:{}", "e".repeat(64)))
                .unwrap(),
        }
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
            realm_id: arkret_sdk::RealmId::new("ak:realm:01904100-0000-8000-8000-000000000001")
                .unwrap(),
        }
    }

    fn event() -> arkret_sdk::Event {
        arkret_sdk::Event::new(
            "ak.member.state",
            scope(),
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
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
    fn managed_agent_pcr_control_uses_the_delegated_local_authority() {
        let mut managed = event();
        managed.actor_id = arkret_sdk::Did::new("did:web:agent.example").unwrap();
        let controller = arkret_sdk::Did::new("did:web:alice.example").unwrap();
        managed.executed_by = Some(controller.clone());
        managed.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );
        assert!(is_managed_agent_pcr_control(&managed));

        managed.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#other-delegation").unwrap(),
        );
        assert!(!is_managed_agent_pcr_control(&managed));

        managed.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );
        managed.executed_by = Some(managed.actor_id.clone());
        assert!(!is_managed_agent_pcr_control(&managed));
    }

    /// Each of the three authority routes is selected by the Event alone, and
    /// none of them can be reached by a near miss of another's shape.
    #[test]
    fn every_authority_route_is_decided_from_accepted_event_authority() {
        let ordinary = event();
        assert_eq!(
            classify_proposal_authority_route(&ordinary).unwrap(),
            ProposalAuthorityRouteKind::RemoteCurrentAuthority,
            "an ordinary Realm write must not degrade to a local self-signature"
        );

        let mut self_pcr = event();
        self_pcr.realm_id =
            arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&self_pcr.actor_id))
                .unwrap();
        self_pcr.scope_ref = arkret_sdk::ScopeRef::Realm {
            realm_id: self_pcr.realm_id.clone(),
        };
        assert_eq!(
            classify_proposal_authority_route(&self_pcr).unwrap(),
            ProposalAuthorityRouteKind::SelfPrincipalControlRealm
        );

        let mut managed = event();
        managed.actor_id = arkret_sdk::Did::new("did:web:agent.example").unwrap();
        managed.executed_by = Some(arkret_sdk::Did::new("did:web:alice.example").unwrap());
        managed.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );
        assert_eq!(
            classify_proposal_authority_route(&managed).unwrap(),
            ProposalAuthorityRouteKind::ManagedAgentPcr
        );

        // A delegation fragment that is not the managed-controller binding is
        // an ordinary Realm write, not a locally signable one.
        let mut foreign_delegation = managed.clone();
        foreign_delegation.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#other-delegation").unwrap(),
        );
        assert_eq!(
            classify_proposal_authority_route(&foreign_delegation).unwrap(),
            ProposalAuthorityRouteKind::RemoteCurrentAuthority
        );

        // Self-executed writes are never managed delegations, whatever the
        // authorization_ref claims.
        let mut self_executed = managed;
        self_executed.executed_by = Some(self_executed.actor_id.clone());
        assert_eq!(
            classify_proposal_authority_route(&self_executed).unwrap(),
            ProposalAuthorityRouteKind::RemoteCurrentAuthority
        );
    }

    /// A principal's own Control Realm authority is the single-DID notary
    /// digest, derived in one place for both publication and recovery.
    #[test]
    fn self_principal_control_realm_authority_is_the_single_did_notary_digest() {
        let principal = arkret_sdk::Did::new("did:web:alice.example").unwrap();
        let authority = LocalPrincipalAuthority::self_principal_control_realm(&principal).unwrap();
        let expected = arkret_sdk::Hash::new(
            arkret_sdk::canonical::canonical_sha256(&arkret_wire::notary::NotaryValue::single_did(
                principal.clone(),
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(authority.authority_set_ref, expected);
        assert_eq!(authority.signer_principal, principal);
    }

    #[test]
    fn managed_agent_pcr_authority_preserves_the_complete_notary_profile() {
        let agent_id = "did:web:agent.example";
        let controller_id = "did:web:alice.example";
        // The PCR id is subject-derived from the Agent DID, not chosen.
        let realm_id =
            arkret_sdk::principal_control_realm_id(&arkret_sdk::Did::new(agent_id).unwrap());
        let realm_id = realm_id.as_str();
        let accepted = crate::event_builders::build_managed_agent_pcr_bootstrap_events(
            agent_id,
            controller_id,
            "did:web:agent.example#managed-controller",
            "ak:trust_domain:did.web.example",
            arkret_sdk::EventId::new("ak:event:01964137-0000-8000-8000-000000000098").unwrap(),
        )
        .unwrap();
        let mut target = event();
        target.realm_id = arkret_sdk::RealmId::new(realm_id).unwrap();
        target.scope_ref = arkret_sdk::ScopeRef::Realm {
            realm_id: target.realm_id.clone(),
        };
        target.actor_id = arkret_sdk::Did::new(agent_id).unwrap();
        target.executed_by = Some(arkret_sdk::Did::new(controller_id).unwrap());
        target.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );

        let authority =
            managed_agent_pcr_authority_set_ref_from_events(&target, &accepted).unwrap();
        let expected = arkret_sdk::Hash::new(
            arkret_sdk::canonical::canonical_sha256(&accepted[0].payload["object"]["notary"])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(authority, expected);
    }

    // `test_guard` serializes the process-wide submitter fixture. These tests
    // run on the `current_thread` flavor, so the std guard is never moved
    // across executor threads and cannot deadlock the runtime.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "current_thread")]
    async fn managed_agent_pcr_genesis_submission_carries_controller_receipt() {
        let _guard = test_guard();
        let agent_id = "did:web:agent.example";
        let controller_id = "did:web:alice.example";
        let mut events = crate::event_builders::build_managed_agent_pcr_bootstrap_events(
            agent_id,
            controller_id,
            "did:web:agent.example#managed-controller",
            "ak:trust_domain:did.web.example",
            arkret_sdk::EventId::new("ak:event:01964137-0000-8000-8000-000000000098").unwrap(),
        )
        .unwrap();
        let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
            [42_u8; 32],
            controller_id,
            "ak:device:01964137-0000-7000-8000-000000000097",
        ));
        let _signer = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));
        let previous_proof_mode = crate::operation::current_proof_mode();
        crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
        let signed = crate::event_signer::sign_sdk_event_with_active_context(
            &mut events[0],
            crate::event_signer::EventProofContext::new(),
        );
        crate::operation::set_proof_mode(previous_proof_mode);
        signed.unwrap();
        let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();

        let submission = standard_initial_submission(&http, &events[0])
            .await
            .unwrap();

        assert!(submission.authorization_lease.is_none());
        assert!(submission.control_proposal_ack.is_some());
    }

    #[test]
    fn managed_agent_pcr_authority_ignores_later_prestate_dependent_writes() {
        let agent_id = arkret_sdk::Did::new("did:web:agent.example").unwrap();
        let controller_id = arkret_sdk::Did::new("did:web:alice.example").unwrap();
        // The PCR id is subject-derived from the Agent DID, not chosen.
        let realm_id =
            arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&agent_id)).unwrap();
        let authorization_ref =
            arkret_sdk::DidUrl::new("did:web:agent.example#managed-controller").unwrap();
        let mut accepted = crate::event_builders::build_managed_agent_pcr_bootstrap_events(
            agent_id.as_str(),
            controller_id.as_str(),
            authorization_ref.as_str(),
            "ak:trust_domain:did.web.example",
            arkret_sdk::EventId::new("ak:event:01964137-0000-8000-8000-000000000098").unwrap(),
        )
        .unwrap();
        accepted.push(
            arkret_event_draft::build_agent_key_revoke_event(
                &arkret_sdk::AgentKeyRevokePayload {
                    agent_id: agent_id.clone(),
                    key_id: arkret_sdk::NonEmptyString::new("runtime-1").unwrap(),
                    revoked_by: controller_id.clone(),
                    revoked_at: Utc::now(),
                    reason: Some("replacement".to_owned()),
                },
                arkret_sdk::EventId::new("ak:event:01964137-0000-8000-8000-0000000000aa").unwrap(),
                arkret_sdk::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                agent_id.clone(),
                controller_id.clone(),
                authorization_ref,
                1,
                arkret_sdk::Hlc::new("000000000001-0000-00000000").unwrap(),
            )
            .unwrap(),
        );

        let mut target = event();
        target.realm_id = realm_id.clone();
        target.scope_ref = arkret_sdk::ScopeRef::Realm { realm_id };
        target.actor_id = agent_id;
        target.executed_by = Some(controller_id);
        target.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );

        managed_agent_pcr_authority_set_ref_from_events(&target, &accepted)
            .expect("later frozen-pre-state writes must not redefine the genesis authority");
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
