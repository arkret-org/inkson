//! Client-held [`AuthorizationLease`](arkret_wire::AuthorizationLease) store.
//!
//! `zh/authz/offline-publication.md`: an Event never travels alone on
//! `POST /_arkret/self/events`. Every initial publication is an
//! `EventInitialSubmission {event, authorization_lease, cba_proof_bundles?}`,
//! and the lease — not `created_at`, and not when a verifier first sees the
//! Event — is what bounds the revocation window.
//!
//! ## What this module does NOT do
//!
//! It does not mint leases. Minting one requires the issuer signing keys of the
//! authority set named by `authority_set_ref` and a `basis_ref` into the
//! accepted CBA basis, neither of which a client device holds by virtue of
//! being able to sign Events. A device that signed its own lease would be
//! asserting the revocation bound it is supposed to be constrained by.
//!
//! The lease therefore has to arrive from the authority. See the migration
//! notes: the spec registers no operation for a client to obtain one, so
//! [`install_lease`] is currently the only entry point and the submit path
//! fails closed with [`AuthorizationLeaseUnavailable`] until something calls
//! it. That is the required behaviour anyway once a lease expires: first
//! publication stops and the user must re-authorize.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use arkret_wire::{AuthorizationLease, ProposalMemberReceipt};

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

type LeaseKey = (String, String, String);

fn leases() -> &'static Mutex<BTreeMap<LeaseKey, AuthorizationLease>> {
    static LEASES: OnceLock<Mutex<BTreeMap<LeaseKey, AuthorizationLease>>> = OnceLock::new();
    LEASES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

type ProposalReceiptKey = (String, String, String);

fn local_proposal_receipts() -> &'static Mutex<BTreeMap<ProposalReceiptKey, ProposalMemberReceipt>>
{
    static RECEIPTS: OnceLock<Mutex<BTreeMap<ProposalReceiptKey, ProposalMemberReceipt>>> =
        OnceLock::new();
    RECEIPTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn key(actor_id: &str, scope_ref: &arkret_sdk::ScopeRef, action: &str) -> anyhow::Result<LeaseKey> {
    Ok((
        actor_id.to_owned(),
        serde_json::to_string(scope_ref)?,
        action.to_owned(),
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
    let key = key(lease.actor_id.as_str(), &lease.scope_ref, &lease.action)?;
    leases()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, lease);
    Ok(())
}

/// Drop every held lease (sign-out, account switch, revocation notice).
pub fn clear_leases() {
    leases()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    local_proposal_receipts()
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
    let held = leases().lock().unwrap_or_else(PoisonError::into_inner);
    let mut matching = held
        .iter()
        .filter(|((actor_id, lease_scope, action), lease)| {
            actor_id == event.actor_id.as_str()
                && lease_scope == &scope
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
    let outcome: arkret_wire::AuthorizationLeaseIssueOutcome = http
        .post_with_options(
            "/_arkret/self/authorization-leases",
            &request,
            &arkret_sdk::http_client::ClientRequestOptions::new()
                .request_id(idempotency_key.clone())
                .idempotency_key(idempotency_key),
        )
        .await
        .map_err(anyhow::Error::from)?;
    if outcome.authorization_leases.len() != events.len() {
        anyhow::bail!(
            "authorization lease response cardinality mismatch: expected {}, received {}",
            events.len(),
            outcome.authorization_leases.len()
        );
    }
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
        authorization_lease,
        // The submit gate attaches basis closure only when the receiver reports
        // a shortfall; a bounded superset is always acceptable, so nothing is
        // guessed here.
        cba_proof_bundles: Vec::new(),
        // Standard Control Moves acquire their authority receipt separately;
        // DataEvents and caller-proven anchor units must omit it.
        control_proposal_receipt: None,
    })
}

/// Build the publication wrapper required by a normal events.submit call.
///
/// A non-genesis Control Move first asks the authenticated Principal Server
/// for its independently signed member receipt, then assembles the canonical
/// receipt set. DataEvents do not enter the proposal protocol and therefore
/// keep the receipt field absent.
pub async fn standard_initial_submission(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    let mut submission = initial_submission(event)?;
    if event.seal_basis.is_some() {
        let member_receipt = if event.realm_id
            == arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&event.actor_id))?
        {
            local_principal_control_member_receipt(event)?
        } else {
            http.issue_control_proposal_receipt(
                &arkret_wire::ControlProposalReceiptIssueRequestBody {
                    event: event.clone(),
                    authorization_lease: submission.authorization_lease.clone(),
                    cba_proof_bundles: submission.cba_proof_bundles.clone(),
                },
            )
            .await
            .map_err(anyhow::Error::from)?
            .member_receipt
        };
        submission.control_proposal_receipt =
            Some(arkret_wire::ControlProposalReceipt::from_member_receipts(
                vec![member_receipt],
                arkret_wire::ControlProposalDecisionPolicy::protocol_maximum(),
            )?);
    }
    submission
        .validate_structural_in_context(arkret_wire::EventSubmitContext::Standard)
        .map_err(anyhow::Error::from)?;
    Ok(submission)
}

fn local_principal_control_member_receipt(
    event: &arkret_sdk::Event,
) -> anyhow::Result<ProposalMemberReceipt> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("PCR proposal receipt requires an active device signer"))?;
    let verification_method = signer.verification_method_for_principal(&event.actor_id)?;
    let proposal_digest = arkret_sdk::Hash::new(event.event_digest()?)?;
    let notary = arkret_wire::notary::NotaryValue::single_did(event.actor_id.clone());
    let authority_set_ref = arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
        arkret_sdk::canonical::canonical_json_bytes(&notary)?,
    ))?;
    let cache_key = (
        proposal_digest.to_string(),
        authority_set_ref.to_string(),
        verification_method.clone(),
    );
    if let Some(receipt) = local_proposal_receipts()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&cache_key)
        .cloned()
    {
        return Ok(receipt);
    }

    let received_at = crate::clock::now_utc();
    let mut member = ProposalMemberReceipt {
        realm_id: event.realm_id.clone(),
        proposal_digest,
        received_at,
        decision_due_at: received_at + chrono::Duration::seconds(30),
        absolute_due_at: received_at + chrono::Duration::seconds(90),
        authority_set_ref,
        signature: arkret_wire::PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method,
            payload_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: received_at,
            jws: String::new(),
        },
    };
    member.signature.payload_digest = member.member_digest()?;
    let transcript = member.canonical_bytes_for_signature()?;
    let (signed_method, jws) =
        signer.sign_detached_jws_for_principal(&event.actor_id, &transcript)?;
    if signed_method != member.signature.verification_method {
        anyhow::bail!("PCR proposal receipt signer binding changed during signing");
    }
    member.signature.jws = jws;
    member.validate_structural(arkret_wire::ControlProposalDecisionPolicy {
        receipt_sla: Some(chrono::Duration::hours(24)),
        decision_window: chrono::Duration::seconds(30),
        absolute_horizon: chrono::Duration::seconds(90),
        max_defers: 2,
    })?;
    local_proposal_receipts()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(cache_key, member.clone());
    Ok(member)
}

/// Lease / receipt fixtures for tests in other modules.
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
            schema: arkret_wire::AUTHORITY_SET_POLICY_SCHEMA.to_owned(),
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
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.to_owned(),
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
    use super::*;

    fn scope() -> arkret_sdk::ScopeRef {
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001")
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
        clear_leases();
        let error = initial_submission(&event()).unwrap_err().to_string();
        assert!(error.contains("re-authorized"), "{error}");
    }
}
