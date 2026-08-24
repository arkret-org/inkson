use std::collections::BTreeMap;
use std::io::{self, Read};

use anyhow::{Context, Result, bail};
use arkret_wire::{SchemaId, event_kind_str};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct CanonicalInput {
    value: Value,
}

#[derive(Debug, Deserialize)]
struct MlsGovernanceProofInput {
    request: arkret_sdk::MlsGovernanceProofRequestBody,
    target_checkpoint: arkret_sdk::MlsGovernanceVerificationCheckpoint,
    content_scheme: arkret_wire::ContentScheme,
    durability_policy: Option<arkret_wire::DurabilityPolicy>,
    local_mls_leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
}

#[derive(Debug, Deserialize)]
struct ControlProposalAckInput {
    request: arkret_wire::ControlProposalAckIssueRequest,
    device_id: String,
    digest_suite: arkret_sdk::DigestSuite,
}

#[derive(Debug, Deserialize)]
struct IngressReceiptsInput {
    submissions: Vec<arkret_wire::EventInitialSubmission>,
    digest_suite: arkret_sdk::DigestSuite,
}

#[derive(Debug, Deserialize)]
struct RangeCompletenessInput {
    realm_id: arkret_sdk::RealmId,
    events: Vec<arkret_sdk::Event>,
}

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => canonical_json(input)?,
        "sha256-canonical-json" => sha256_canonical_json(input)?,
        "mls-governance-proof" => mls_governance_proof(input)?,
        "control-proposal-ack" => control_proposal_ack(input)?,
        "ingress-receipts" => ingress_receipts(input)?,
        "range-completeness" => range_completeness(input)?,
        _ => bail!("unknown inkson-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn range_completeness(input: Value) -> Result<Value> {
    use arkret_sdk::{
        Event, EventId, EventRequirements, Hash, PayloadProof, PayloadProofPurpose, PayloadSigner,
        ScopeRef,
    };
    use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions, sign_event};

    let input: RangeCompletenessInput =
        serde_json::from_value(input).context("parse range-completeness input")?;
    if input.events.len() < 2
        || input
            .events
            .iter()
            .any(|event| event.realm_id != input.realm_id)
    {
        bail!("range-completeness fixture requires at least two Events in one Realm");
    }
    let (from_frontier, to_frontier) = arkret_sdk::full_realm_range_frontiers(&input.events)
        .map_err(|error| anyhow::anyhow!("derive fixture completeness frontiers: {error}"))?;
    let range_events = arkret_sdk::full_realm_range_events(&input.events)
        .map_err(|error| anyhow::anyhow!("derive fixture completeness range: {error}"))?;
    let actor_seq_ranges = arkret_sdk::range_completeness_actor_seq_ranges(&range_events)
        .map_err(|error| anyhow::anyhow!("derive fixture actor ranges: {error}"))?;
    if actor_seq_ranges.is_empty() {
        bail!("range-completeness fixture has no reducer-input Events after its genesis frontier");
    }
    let digest_algorithm = input
        .events
        .iter()
        .find(|event| event.kind.as_str() == event_kind_str::REALM_CREATE)
        .and_then(|event| {
            event
                .payload
                .get("object")
                .and_then(|object| object.get("digest_algorithm"))
                .or_else(|| event.payload.get("digest_algorithm"))
        })
        .and_then(Value::as_str)
        .unwrap_or("sha256");
    let digest_suite = arkret_sdk::canonical::digest_suite(digest_algorithm)
        .map_err(|error| anyhow::anyhow!("derive fixture Realm digest suite: {error}"))?;
    let (root, covered_event_ids) =
        arkret_sdk::range_completeness_root_with_suite(&range_events, digest_suite)
            .map_err(|error| anyhow::anyhow!("derive fixture completeness root: {error}"))?;

    let issuer_full_id = arkret_sdk::DidFullId::new("did:web:server.local")?;
    let issuer = arkret_sdk::DidCoreId::new("ak:did_core:web:server.local")?;
    let verification_method = arkret_sdk::DidUrl::new(format!("{issuer_full_id}#notary-key"))
        .map_err(|error| anyhow::anyhow!("fixture verification method: {error}"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5a_u8; 32]);
    let signer = Ed25519PayloadSigner::new(
        signing_key.clone(),
        issuer_full_id.clone(),
        verification_method.clone(),
    );
    let observed_at = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut payload = arkret_sdk::RangeCompletenessAttestation {
        attestation_id: "ak:attestation:019fbeef-0000-7000-8000-000000000001".to_owned(),
        schema: SchemaId::RANGE_COMPLETENESS_ATTESTATION_V1.to_owned(),
        issuer: issuer.clone(),
        issuer_role: "events_api".to_owned(),
        realm_id: input.realm_id.clone(),
        event_range: arkret_sdk::RangeCompletenessAttestationEventRange {
            from_frontier: arkret_sdk::RangeCompletenessAttestationEventRangeFromFrontier {
                realm_frontier: from_frontier,
                extra: BTreeMap::new(),
            },
            to_frontier: arkret_sdk::RangeCompletenessAttestationEventRangeToFrontier {
                realm_frontier: to_frontier.clone(),
                extra: BTreeMap::new(),
            },
            actor_seq_ranges,
        },
        root,
        count: covered_event_ids.len() as u64,
        observed_at,
        witness_attestation: arkret_sdk::RangeCompletenessAttestationWitnessAttestation {
            witnesses: vec![
                arkret_sdk::RangeCompletenessAttestationWitnessAttestationWitnessesItem {
                    issuer: issuer.clone(),
                    verification_method: verification_method.clone(),
                    controlling_organization: issuer.clone(),
                    attested_at: Some(observed_at),
                    extra: BTreeMap::new(),
                },
            ],
        },
        proofs: Vec::new(),
    };
    let canonical_payload = payload.proof_payload_bytes()?;
    let mut payload_proof = PayloadProof {
        kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        payload_digest: Hash::new(arkret_sdk::canonical::sha256_digest(&canonical_payload))?,
        created_at: observed_at,
        domain: None,
        audience: None,
        proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
        jws: String::new(),
    };
    let binding = payload.proof_binding_bytes(&payload_proof)?;
    let signature = signer.sign_payload(&binding)?;
    payload_proof.jws = signature.jws;
    payload.proofs.push(payload_proof);
    let Value::Object(payload) = serde_json::to_value(payload)? else {
        bail!("typed completeness payload is not an object");
    };
    let event = Event {
        // Replaced by `finalize_with_digest_suite` below: the identity is derived
        // from the finished content, so nothing here may claim one.
        event_id: EventId::from_digest(digest_suite, [0; 32]),
        kind: arkret_wire::EventKind::AttestationRangeCompleteness,
        realm_id: input.realm_id.clone(),
        scope_ref: ScopeRef::Realm {
            realm_id: input.realm_id,
        },
        actor_id: issuer.clone(),
        principal_server_id: issuer.clone(),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        actor_seq: 0,
        created_at: observed_at,
        hlc: None,
        prev_refs: to_frontier,
        refs: Vec::new(),
        causal_refs: Vec::new(),
        preconditions: Vec::new(),
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        payload: payload.into_iter().collect(),
        unsigned: BTreeMap::new(),
        proofs: Vec::new(),
        requirements: EventRequirements::default(),
    };
    let mut event = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(event, digest_suite)
        .map_err(|error| anyhow::anyhow!("finalize fixture attestation Event: {error}"))?;
    let event_id = event.event_id().clone();
    sign_event(
        &mut event,
        &signer,
        &verification_method,
        SignEventOptions::new().with_created_at(observed_at),
    )?;

    let mut multikey = vec![0xed, 0x01];
    multikey.extend_from_slice(signing_key.verifying_key().as_bytes());
    let public_key_multibase = arkret_sdk::encode_multibase_base58btc(multikey);
    Ok(json!({
        "range_completeness": {
            "attestation_refs": [event_id],
            "attestations": [event]
        },
        "did_document": {
            "id": issuer,
            "verificationMethod": [{
                "id": verification_method,
                "type": "Multikey",
                "controller": issuer,
                "publicKeyMultibase": public_key_multibase
            }],
            "authentication": [verification_method],
            "assertionMethod": [verification_method]
        }
    }))
}

fn read_stdin_json() -> Result<Value> {
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .context("read stdin")?;
    serde_json::from_str(&stdin).context("parse stdin JSON")
}

fn canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse canonical input")?;
    let canonical = arkret_sdk::canonical::canonical_json_string(&input.value)
        .map_err(|err| anyhow::anyhow!("canonical JSON encode: {err}"))?;
    Ok(json!({ "canonical": canonical }))
}

fn sha256_canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse digest input")?;
    let digest = arkret_sdk::canonical::canonical_sha256(&input.value)
        .map_err(|err| anyhow::anyhow!("canonical JSON digest: {err}"))?;
    Ok(json!({ "digest": digest }))
}

fn mls_governance_proof(input: Value) -> Result<Value> {
    let input: MlsGovernanceProofInput =
        serde_json::from_value(input).context("parse MLS governance proof input")?;
    let group_genesis_binding = arkret_sdk::MlsGroupGenesisBinding {
        content_scheme: input.content_scheme,
        durability_policy: input.durability_policy,
    };
    let bundle = arkret_sdk::materialize_mls_governance_frontier(
        &input.request,
        &input.target_checkpoint,
        &group_genesis_binding,
        &input.local_mls_leaves,
        |_event, _digest_suite, _evidence, _dependencies| {
            Err(arkret_sdk::WireError::Protocol(
                "the inkson-wire fixture does not provide Native Agent historical authority"
                    .to_owned(),
            ))
        },
    )
    .map_err(|error| anyhow::anyhow!("materialize MLS governance frontier: {error}"))?;
    serde_json::to_value(bundle).context("serialize MLS governance proof bundle")
}

fn control_proposal_ack(input: Value) -> Result<Value> {
    let input: ControlProposalAckInput =
        serde_json::from_value(input).context("parse Control Proposal Ack input")?;
    input
        .request
        .validate_structural()
        .map_err(|error| anyhow::anyhow!("validate Control Proposal Ack request: {error}"))?;
    let event = &input.request.event;
    let controller = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    let signer = inkson::event_signer::build_ed25519_device_signer(
        [1_u8; 32],
        controller.as_str(),
        input.device_id,
    );
    let policy = arkret_wire::ControlProposalDecisionPolicy::default();
    let received_at = chrono::Utc::now();
    let proposal_digest =
        arkret_sdk::Hash::new(event.event_digest_with_digest_suite(input.digest_suite)?)
            .context("construct proposal Event digest")?;
    let notary_public_key = [2_u8; 32];
    let authority_set_ref = arkret_sdk::Hash::new(
        arkret_sdk::canonical::canonical_sha256(&arkret_sdk::NotaryValue::single_signer(
            arkret_sdk::NotarySignerDescriptor {
                actor_id: arkret_sdk::DidCoreId::new("ak:did_core:web:server.local".to_owned())?,
                verification_method: arkret_sdk::DidUrl::new(
                    "did:web:server.local#notary".to_owned(),
                )
                .map_err(anyhow::Error::msg)?,
                key_kind: arkret_sdk::NotaryKeyKind::Ed25519Raw32,
                jose_algorithm: arkret_sdk::NotaryJoseAlgorithm::Ed25519,
                frozen_public_key_b64u: arkret_sdk::base64url_encode(notary_public_key),
                frozen_public_key_digest: arkret_sdk::Hash::new(
                    arkret_sdk::canonical::sha256_digest(notary_public_key),
                )?,
            },
        ))
        .context("digest proposal authority set")?,
    )
    .context("construct proposal authority-set digest")?;
    let mut member = arkret_wire::ControlProposalAuthorityAck {
        realm_id: event.realm_id.clone(),
        proposal_digest,
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        authority_set_ref,
        signature: arkret_wire::PayloadSignature {
            verification_method: arkret_sdk::DidUrl::new(signer.verification_method().to_owned())
                .map_err(|error| {
                anyhow::anyhow!("proposal verification method: {error}")
            })?,
            payload_digest: arkret_sdk::Hash::new(format!("sha256:{}", "00".repeat(32)))
                .context("construct proposal placeholder digest")?,
            created_at: received_at,
            jws: String::new(),
        },
    };
    let signing_bytes = member
        .canonical_bytes_for_signature()
        .context("materialize proposal authority Ack transcript")?;
    member.signature.payload_digest = member
        .authority_ack_digest()
        .context("digest proposal authority Ack")?;
    member.signature.jws = format!(
        "{}..{}",
        arkret_sdk::base64url_encode(br#"{"alg":"Ed25519"}"#),
        arkret_sdk::base64url_encode(
            signer
                .sign_raw(&signing_bytes)
                .map_err(|error| anyhow::anyhow!("sign proposal authority Ack: {error}"))?
        )
    );
    member
        .validate_protocol_bounds()
        .map_err(|error| anyhow::anyhow!("validate proposal authority Ack: {error}"))?;
    serde_json::to_value(arkret_wire::ControlProposalAckIssueOutcome {
        authority_ack: member,
    })
    .context("serialize Control Proposal Ack outcome")
}

fn ingress_receipts(input: Value) -> Result<Value> {
    let input: IngressReceiptsInput =
        serde_json::from_value(input).context("parse ingress receipt input")?;
    let signer = inkson::event_signer::build_ed25519_signer([2_u8; 32], "did:web:server.local");
    let mut receipts = Vec::with_capacity(input.submissions.len());
    for submission in input.submissions {
        let authorization_lease = submission
            .authorization_lease
            .as_ref()
            .context("ingress receipt fixture requires a delayed authorization lease")?;
        let event_digest = arkret_sdk::Hash::new(
            submission
                .event
                .event_digest_with_digest_suite(input.digest_suite)?,
        )
        .context("construct ingress Event digest")?;
        let received_at = authorization_lease.issued_at;
        let receipt_unix_ms = u64::try_from(received_at.timestamp_millis())
            .context("ingress receipt time predates the Unix epoch")?;
        let mut receipt = arkret_wire::IngressReceipt {
            receipt_id: arkret_wire::ReceiptId::new_v7_at(receipt_unix_ms),
            event_digest: event_digest.clone(),
            authorization_lease_id: authorization_lease.authorization_lease_id.clone(),
            received_at,
            service_id: arkret_wire::project_full_id_to_core_id(
                &arkret_wire::DidFullId::new("did:web:server.local".to_owned())
                    .context("construct ingress service full id")?,
            )
            .context("project ingress service core id")?,
            authority_set_ref: authorization_lease.authority_set_ref.clone(),
            proofs: Vec::new(),
        };
        let mut proof = arkret_wire::PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_sdk::DidUrl::new(signer.verification_method().to_owned())
                .map_err(|error| {
                anyhow::anyhow!("ingress receipt verification method: {error}")
            })?,
            payload_digest: receipt.receipt_digest().context("digest ingress receipt")?,
            created_at: received_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        };
        let binding = receipt
            .proof_binding_bytes(&proof)
            .context("materialize ingress receipt proof transcript")?;
        proof.jws = format!(
            "{}..{}",
            arkret_sdk::base64url_encode(br#"{"alg":"Ed25519"}"#),
            arkret_sdk::base64url_encode(
                signer
                    .sign_raw(&binding)
                    .map_err(|error| anyhow::anyhow!("sign ingress receipt: {error}"))?
            )
        );
        receipt.proofs = vec![proof];
        receipt
            .validate_structural()
            .context("validate ingress receipt")?;
        receipt
            .validate_against_lease(authorization_lease, &event_digest)
            .context("validate ingress receipt binding")?;
        receipts.push(receipt);
    }
    serde_json::to_value(receipts).context("serialize ingress receipts")
}
