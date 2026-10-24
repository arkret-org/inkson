use anyhow::{Context, Result, ensure};
use arkret_identity::{AuthorityDidHistoryResolver, AuthorityHistoryUnavailable};
use arkret_sdk::contact_operations::*;
use arkret_test_kit::contact::{ContactCeremonyFixture, ContactParticipant};
use arkret_test_kit::service_identity::ServiceIdentityFixture;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Party {
    account_id: arkret_sdk::AccountId,
    realm_id: arkret_sdk::RealmId,
    verification_method: arkret_sdk::DidUrl,
    seed_b64url: String,
}

impl Party {
    fn participant<'a>(
        &self,
        authority: &'a ServiceIdentityFixture,
    ) -> Result<ContactParticipant<'a>> {
        Ok(ContactParticipant {
            account_id: self.account_id.clone(),
            realm_id: self.realm_id.clone(),
            verification_method: self.verification_method.clone(),
            signing_seed: arkret_sdk::base64url_decode(&self.seed_b64url)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Contact producer seed must contain 32 bytes"))?,
            authority,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildInput {
    requester: Party,
    responder: Party,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    ceremony: ContactCeremonyFixture,
    requester: ContactPeer,
    responder: ContactPeer,
    history: arkret_sdk::IdentityLogListResponseBody,
    observed_at: DateTime<Utc>,
}

impl AuthorityDidHistoryResolver for Material {
    fn resolve_complete_history(
        &self,
        did: &arkret_sdk::Did,
    ) -> std::result::Result<arkret_sdk::IdentityLogListResponseBody, AuthorityHistoryUnavailable>
    {
        if *did == self.history.did {
            Ok(self.history.clone())
        } else {
            Err(AuthorityHistoryUnavailable {
                message: "unrecognized Contact authority".into(),
            })
        }
    }
}

pub fn build(input: Value) -> Result<Value> {
    let input: BuildInput = serde_json::from_value(input)?;
    let at =
        DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).context("fixture time")?;
    let authority = authority(at)?;
    let requester = input.requester.participant(&authority)?;
    let responder = input.responder.participant(&authority)?;
    let ceremony = ContactCeremonyFixture::normal(&requester, &responder, at)?;
    let material = Material {
        ceremony,
        requester: requester.peer(),
        responder: responder.peer(),
        history: authority.history,
        observed_at: at,
    };
    verify_material(&material)?;
    Ok(serde_json::to_value(material)?)
}

fn authority(at: DateTime<Utc>) -> Result<ServiceIdentityFixture> {
    ServiceIdentityFixture::webvh(
        &"https://server.local/".parse()?,
        31,
        [31; 32],
        "signing-1",
        "2026-06-01T00:00:00Z".parse()?,
        at,
    )
}

fn verify_material(material: &Material) -> Result<Value> {
    use arkret_sdk::contact_authorization::{
        authenticate_contact_event_carrier, verify_contact_current_material,
        verify_contact_founding_bundle,
    };
    let f = &material.ceremony;
    let suite = arkret_sdk::DigestSuite::Sha256;
    let domain = &f.round.initial_identity.trust_domain_id;
    verify_contact_founding_bundle(&f.round, domain, suite, material.observed_at, material)?;
    for (carrier, holder) in [
        (&f.request, &material.requester),
        (&f.response, &material.responder),
        (&f.reject, &material.responder),
        (&f.scope_update, &material.responder),
        (&f.tombstone, &material.responder),
    ] {
        authenticate_contact_event_carrier(carrier, holder, suite, material.observed_at, material)?;
    }
    let mut state = ContactPrivateState::default();
    for op in &f.round.current_operations {
        state.apply_confirmed(op.clone())?;
    }
    state.establish(f.round.basis(), f.round.round_events.clone())?;
    let verify_direction =
        |state: &ContactPrivateState, proof: &ContactCurrentProof| -> Result<_> {
            let direction = state
                .direction(&proof.holder)
                .context("original current direction")?;
            Ok(verify_contact_current_material(
                &ContactCurrentMaterial {
                    initial_identity: state.initial_identity.clone(),
                    round_evidence: state.round_basis.clone(),
                    round_events: Some(state.round_events.clone()),
                    head_operation: direction.head_operation.clone(),
                    scope_grants: direction.scope_grants.clone(),
                    historical_intervals: vec![],
                    current_proof: proof.clone(),
                },
                &proof.holder,
                &proof.peer,
                domain,
                suite,
                material.observed_at,
                material,
            )?)
        };
    let PeerContactSubmitRequestBody::ScopeUpdate {
        signed_event,
        lineage,
        current_proof,
        ..
    } = &f.scope_update
    else {
        anyhow::bail!("scope carrier")
    };
    state.apply_confirmed(ContactOperationEvidence::ScopeUpdate {
        signed_event: signed_event.clone(),
        lineage: lineage.clone(),
    })?;
    let narrowed = verify_direction(&state, current_proof)?;
    let narrowed = narrowed.direction().context("narrowed current direction")?;
    ensure!(
        narrowed.open_interval(ContactScope::Invite).is_none()
            && narrowed
                .open_interval(ContactScope::DirectMessage)
                .is_some(),
        "scope narrowing mismatch"
    );
    let PeerContactSubmitRequestBody::Tombstone {
        signed_event,
        lineage,
        current_proof,
        ..
    } = &f.tombstone
    else {
        anyhow::bail!("tombstone carrier")
    };
    state.apply_confirmed(ContactOperationEvidence::Tombstone {
        signed_event: signed_event.clone(),
        lineage: lineage.clone(),
    })?;
    let closure = current_proof
        .closed_round
        .as_deref()
        .context("original closure missing")?;
    state.close_round(closure.clone())?;
    let closed = verify_direction(&state, current_proof)?;
    let opposite = verify_direction(&state, &f.terminal_acknowledgement)?;
    ensure!(
        closed
            .direction()
            .is_none_or(|d| d.open_interval(ContactScope::DirectMessage).is_none())
            && opposite
                .direction()
                .is_none_or(|d| d.open_interval(ContactScope::DirectMessage).is_none()),
        "original closure retained a grant"
    );
    let PeerContactSubmitRequestBody::Response {
        response_receipt, ..
    } = &f.response
    else {
        anyhow::bail!("response carrier")
    };
    f.outgoing_slot_absence
        .verify_digest(&response_receipt.outgoing_slot_absence_digest)?;
    ensure!(
        f.response_lineage.event_ref == response_receipt.response_event_ref
            && f.response_lineage.contact_round_id.as_ref() == Some(&f.round.contact_round_id)
            && f.response_lineage.issuer == material.responder
            && f.response_lineage.peer == material.requester
            && f.response_lineage.version == 1
            && f.response_lineage.predecessor_event_ref.is_none()
            && f.response_lineage.producer_signer == response_receipt.producer_signer
            && f.response_lineage.granted_to_peer_scopes
                == [ContactScope::Invite, ContactScope::DirectMessage],
        "response lineage changed original Event"
    );
    let signature = &f.response_lineage.signature;
    let point = arkret_signatures::webvh::validate_webvh_history_at(
        &material.history.did,
        &material.history.entries,
        signature.created_at,
    )?;
    let document = serde_json::from_value(point.document)?;
    arkret_identity::verify_jws_with_document_relationship(
        &f.response_lineage.canonical_signing_bytes()?,
        &signature.jws,
        &signature.verification_method,
        &material.history.did,
        &document,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )?;
    Ok(
        json!({"verified": true, "response": true, "reject": true, "scope_update": true, "tombstone": true}),
    )
}

pub fn verify(input: Value) -> Result<Value> {
    let material: Material = serde_json::from_value(input)?;
    verify_material(&material)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationInput {
    material: Material,
    operation_kind: ContactResultKind,
    body: Value,
    prepared: Option<ContactOperationResponseBody>,
}

pub fn operation(input: Value) -> Result<Value> {
    let input: OperationInput = serde_json::from_value(input)?;
    verify_material(&input.material)?;
    let m = &input.material;
    let f = &m.ceremony;
    let carrier = match input.operation_kind {
        ContactResultKind::Response => &f.response,
        ContactResultKind::Reject => &f.reject,
        ContactResultKind::ScopeUpdate => &f.scope_update,
        ContactResultKind::Tombstone => &f.tombstone,
        _ => anyhow::bail!("request uses its independent prepare/commit path"),
    };
    let original = match carrier {
        PeerContactSubmitRequestBody::Response { signed_event, .. }
        | PeerContactSubmitRequestBody::Reject { signed_event, .. }
        | PeerContactSubmitRequestBody::ScopeUpdate { signed_event, .. }
        | PeerContactSubmitRequestBody::Tombstone { signed_event, .. } => signed_event,
        _ => unreachable!(),
    };
    let event_draft = arkret_sdk::PreparedEventDraft {
        unsigned_event_base64url: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
            arkret_sdk::canonical::canonical_json_bytes(&original.digest_payload()?)?,
        ))
        .map_err(anyhow::Error::msg)?,
        event_digest: original.event_id.event_digest(),
    };
    let operation_id;
    let reservation_handle =
        arkret_sdk::ReservationHandle::new(format!("e2e-contact-{}", original.event_id))
            .map_err(anyhow::Error::msg)?;
    let expires_at = m.observed_at + chrono::Duration::minutes(15);
    ensure!(Utc::now() < expires_at, "Contact reservation expired");
    if input.body["phase"] == "prepare" {
        let request_ref = match &f.request {
            PeerContactSubmitRequestBody::Request { signed_event, .. } => &signed_event.event_id,
            _ => unreachable!(),
        };
        let (peer, request, round, version, predecessor, scopes) = match input.operation_kind {
            ContactResultKind::Response => {
                let body: ContactAcceptPrepareRequestBody = serde_json::from_value(input.body)?;
                operation_id = body.operation_id;
                (
                    body.peer,
                    Some(body.request_event_ref),
                    None,
                    None,
                    None,
                    Some(body.granted_to_peer_scopes),
                )
            }
            ContactResultKind::Reject => {
                let body: ContactRejectPrepareRequestBody = serde_json::from_value(input.body)?;
                operation_id = body.operation_id;
                (
                    body.peer,
                    Some(body.request_event_ref),
                    None,
                    None,
                    None,
                    None,
                )
            }
            ContactResultKind::ScopeUpdate => {
                let body: ContactScopeUpdatePrepareRequestBody =
                    serde_json::from_value(input.body)?;
                operation_id = body.operation_id;
                (
                    body.peer,
                    None,
                    Some(body.contact_round_id),
                    Some(body.version),
                    Some(body.predecessor_event_ref),
                    Some(body.granted_to_peer_scopes),
                )
            }
            ContactResultKind::Tombstone => {
                let body: ContactTombstonePrepareRequestBody = serde_json::from_value(input.body)?;
                ensure!(
                    !body.block_peer,
                    "fixture does not supply a blocklist transaction"
                );
                operation_id = body.operation_id;
                (
                    body.peer,
                    None,
                    Some(body.contact_round_id),
                    Some(body.version),
                    Some(body.predecessor_event_ref),
                    None,
                )
            }
            _ => unreachable!(),
        };
        ensure!(peer == m.requester, "Contact prepare changed peer");
        if let Some(request) = request {
            ensure!(
                request == *request_ref,
                "Contact prepare changed incoming request"
            );
        }
        if let Some(round) = round {
            ensure!(
                round == f.round.contact_round_id,
                "Contact prepare changed round"
            );
        }
        if let Some(version) = version {
            ensure!(
                original.payload["version"] == version,
                "Contact prepare changed version"
            );
        }
        if let Some(predecessor) = predecessor {
            ensure!(
                original.payload["predecessor_event_ref"] == predecessor.as_str(),
                "Contact prepare changed predecessor"
            );
        }
        if let Some(scopes) = scopes {
            ensure!(
                original.payload["granted_to_peer_scopes"] == serde_json::to_value(scopes)?,
                "Contact prepare changed scopes"
            );
        }
        let outcome = match input.operation_kind {
            ContactResultKind::Response => ContactPreparedResponseBody::Response {
                operation_id,
                reservation_handle,
                expires_at,
                event_draft,
            },
            ContactResultKind::Reject => ContactPreparedResponseBody::Reject {
                operation_id,
                reservation_handle,
                expires_at,
                event_draft,
            },
            ContactResultKind::ScopeUpdate => ContactPreparedResponseBody::ScopeUpdate {
                operation_id,
                reservation_handle,
                expires_at,
                event_draft,
            },
            ContactResultKind::Tombstone => ContactPreparedResponseBody::Tombstone {
                operation_id,
                reservation_handle,
                expires_at,
                event_draft,
            },
            _ => unreachable!(),
        };
        return Ok(serde_json::to_value(
            ContactOperationResponseBody::Prepared { outcome },
        )?);
    }
    let body: ContactCommitRequestBody = serde_json::from_value(input.body)?;
    let prepared = input
        .prepared
        .context("Contact commit has no reservation")?;
    let prepared_value = serde_json::to_value(&prepared)?;
    ensure!(
        prepared_value["operation_id"] == body.operation_id.as_str()
            && prepared_value["operation_kind"] == serde_json::to_value(input.operation_kind)?
            && prepared_value["reservation_handle"] == body.reservation_handle.as_str()
            && body.reservation_handle == reservation_handle,
        "Contact commit changed its reservation"
    );
    let ContactOperationResponseBody::Prepared { outcome } = prepared else {
        anyhow::bail!("Contact commit needs prepared outcome")
    };
    ensure!(
        outcome.event_draft()?.unsigned_event()?.digest_payload()?
            == body.signed_event.digest_payload()?
            && original.digest_payload()? == body.signed_event.digest_payload()?
            && original.event_id == body.signed_event.event_id,
        "Contact commit changed its reserved Event"
    );
    let mut signed_carrier = carrier.clone();
    let accepted_at = DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
        .context("acceptance time")?;
    let producer = match carrier {
        PeerContactSubmitRequestBody::Response {
            response_receipt, ..
        } => &response_receipt.producer_signer,
        PeerContactSubmitRequestBody::Reject { reject_receipt, .. } => {
            &reject_receipt.producer_signer
        }
        PeerContactSubmitRequestBody::ScopeUpdate { lineage, .. }
        | PeerContactSubmitRequestBody::Tombstone { lineage, .. } => &lineage.producer_signer,
        _ => unreachable!(),
    };
    producer.validate_for_event(&body.signed_event, &m.responder)?;
    let proof = body
        .signed_event
        .producer_proof
        .as_ref()
        .context("Contact commit omitted producer proof")?;
    ensure!(
        proof.verification_method == *producer.verification_method()
            && proof.created_at <= accepted_at,
        "Contact producer method or time mismatch"
    );
    arkret_signatures::proof::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_sdk::canonical::canonical_json_bytes(&body.signed_event.digest_payload()?)?,
        &body.signed_event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: producer.public_key_bytes()?.to_vec(),
        },
        arkret_sdk::DigestSuite::Sha256,
    )?;
    match &mut signed_carrier {
        PeerContactSubmitRequestBody::Response { signed_event, .. }
        | PeerContactSubmitRequestBody::Reject { signed_event, .. }
        | PeerContactSubmitRequestBody::ScopeUpdate { signed_event, .. }
        | PeerContactSubmitRequestBody::Tombstone { signed_event, .. } => {
            *signed_event = body.signed_event
        }
        _ => unreachable!(),
    }
    // Draft templates do not pre-accept a client signature. Issue the source
    // receipt only after verifying the actual holder proof, at this commit.
    let authority = authority(accepted_at)?;
    let refresh_current = |proof: &mut ContactCurrentProof| -> Result<()> {
        proof.issued_at = accepted_at;
        proof.cache_expires_at = accepted_at + chrono::Duration::minutes(15);
        proof.signature = authority.sign(&proof.canonical_signing_bytes()?, accepted_at)?;
        Ok(())
    };
    match &mut signed_carrier {
        PeerContactSubmitRequestBody::Response {
            response_receipt,
            current_proof,
            ..
        } => {
            response_receipt.accepted_at = accepted_at;
            response_receipt.signature =
                authority.sign(&response_receipt.canonical_signing_bytes()?, accepted_at)?;
            refresh_current(current_proof.as_mut().context("response current")?)?;
        }
        PeerContactSubmitRequestBody::Reject { reject_receipt, .. } => {
            reject_receipt.accepted_at = accepted_at;
            reject_receipt.signature =
                authority.sign(&reject_receipt.canonical_signing_bytes()?, accepted_at)?;
        }
        PeerContactSubmitRequestBody::ScopeUpdate {
            lineage,
            current_proof,
            ..
        }
        | PeerContactSubmitRequestBody::Tombstone {
            lineage,
            current_proof,
            ..
        } => {
            lineage.accepted_at = accepted_at;
            lineage.signature = authority.sign(&lineage.canonical_signing_bytes()?, accepted_at)?;
            refresh_current(current_proof)?;
        }
        _ => unreachable!(),
    }
    arkret_sdk::contact_authorization::authenticate_contact_event_carrier(
        &signed_carrier,
        &m.responder,
        arkret_sdk::DigestSuite::Sha256,
        Utc::now(),
        m,
    )?;
    operation_id = body.operation_id;
    let mut response_lineage = f.response_lineage.clone();
    response_lineage.accepted_at = accepted_at;
    response_lineage.signature =
        authority.sign(&response_lineage.canonical_signing_bytes()?, accepted_at)?;
    let outcome = match signed_carrier {
        PeerContactSubmitRequestBody::Response {
            response_receipt,
            current_proof,
            ..
        } => ContactAcceptedResponseBody::Response {
            operation_id,
            normal_response_acceptance_receipt: response_receipt,
            lineage: response_lineage,
            current_proof: current_proof.context("response current")?,
        },
        PeerContactSubmitRequestBody::Reject { reject_receipt, .. } => {
            ContactAcceptedResponseBody::Reject {
                operation_id,
                reject_acceptance_receipt: reject_receipt,
            }
        }
        PeerContactSubmitRequestBody::ScopeUpdate {
            lineage,
            current_proof,
            ..
        } => ContactAcceptedResponseBody::ScopeUpdate {
            operation_id,
            lineage,
            current_proof,
        },
        PeerContactSubmitRequestBody::Tombstone {
            lineage,
            current_proof,
            ..
        } => ContactAcceptedResponseBody::Tombstone {
            operation_id,
            lineage,
            current_proof,
        },
        _ => unreachable!(),
    };
    Ok(serde_json::to_value(
        ContactOperationResponseBody::Accepted { outcome },
    )?)
}
