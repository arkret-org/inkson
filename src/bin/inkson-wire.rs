use std::collections::BTreeMap;
use std::io::{self, Read};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct CanonicalInput {
    value: Value,
}

#[derive(Debug, Deserialize)]
struct MlsGovernanceProofInput {
    request: arkret_sdk::MlsGovernanceProofRequestBodyBody,
    events: Vec<arkret_sdk::Event>,
    seals: Vec<arkret_sdk::Seal>,
}

#[derive(Debug, Deserialize)]
struct ProposalReceiptInput {
    request: arkret_wire::ProposalReceiptIssueRequest,
    device_id: String,
}

#[derive(Debug, Deserialize)]
struct IngressReceiptsInput {
    submissions: Vec<arkret_wire::EventInitialSubmission>,
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
        "proposal-receipt" => proposal_receipt(input)?,
        "ingress-receipts" => ingress_receipts(input)?,
        "range-completeness" => range_completeness(input)?,
        _ => bail!("unknown inkson-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn range_completeness(input: Value) -> Result<Value> {
    use arkret_sdk::{
        Event, EventId, EventRequirements, Hash, PayloadProofPurpose, PayloadSigner, Proof,
        ScopeRef,
    };
    use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions, sign_event_with_digest_suite};

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
        .find(|event| event.kind.as_str() == "ak.realm.create")
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

    let issuer = arkret_sdk::Did::new("did:web:server.local")?;
    let verification_method = arkret_sdk::DidUrl::new(format!("{issuer}#notary-key"))
        .map_err(|error| anyhow::anyhow!("fixture verification method: {error}"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5a_u8; 32]);
    let signer = Ed25519PayloadSigner::new(
        signing_key.clone(),
        issuer.clone(),
        verification_method.clone(),
    );
    let observed_at = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let event_id = EventId::new("ak:event:019fbeef-0000-7000-8000-000000000001".to_owned())?;
    let mut payload = arkret_sdk::RangeCompletenessAttestation {
        attestation_id: "ak:attestation:019fbeef-0000-7000-8000-000000000001".to_owned(),
        schema: "ak.schema.range_completeness_attestation.v1".to_owned(),
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
            kind: "single_source".to_owned(),
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
    let mut unsigned_payload = serde_json::to_value(&payload)?;
    unsigned_payload
        .as_object_mut()
        .context("typed completeness payload is not an object")?
        .remove("proofs");
    let canonical_payload = arkret_sdk::canonical::canonical_json_bytes(&unsigned_payload)?;
    let mut payload_proof = Proof {
        kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        event_digest: Hash::new(arkret_sdk::canonical::sha256_digest(&canonical_payload))?,
        created_at: observed_at,
        domain: None,
        audience: None,
        proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
        jws: String::new(),
    };
    let binding = payload_proof.canonical_binding_bytes(&issuer)?;
    let signature = signer.sign_payload(&binding)?;
    payload_proof.jws = signature.jws;
    payload.proofs.push(payload_proof);
    let Value::Object(payload) = serde_json::to_value(payload)? else {
        bail!("typed completeness payload is not an object");
    };
    let mut event = Event {
        event_id: event_id.clone(),
        kind: arkret_wire::EventKind::AttestationRangeCompleteness,
        realm_id: input.realm_id.clone(),
        scope_ref: ScopeRef::Realm {
            realm_id: input.realm_id,
        },
        actor_id: issuer.clone(),
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
        redacts: None,
        unsigned: BTreeMap::new(),
        proofs: Vec::new(),
        requirements: EventRequirements::default(),
    };
    sign_event_with_digest_suite(
        &mut event,
        &signer,
        &verification_method,
        digest_suite,
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
    let material = arkret_bootstrap::materialize_managed_agent_pcr_control(
        &input.events,
        &inkson::operation::cell_write_projector,
    )
    .map_err(|error| anyhow::anyhow!("materialize managed Agent PCR control: {error}"))?;
    let accepted_seal = input
        .seals
        .last()
        .context("managed Agent PCR proof has no accepted Seal")?;
    if accepted_seal.realm_id != material.realm_id
        || accepted_seal.state_root != material.state_root
        || accepted_seal.covered_event_digests != material.covered_event_digests
    {
        bail!("accepted Seal does not match the managed Agent PCR control material");
    }
    let control_state = material
        .joined
        .iter()
        .filter_map(|(cell, state)| match state {
            arkret_sdk::CellState::Value(value) => {
                Some(arkret_sdk::MlsGovernanceControlStateLeaf {
                    cell: cell.clone(),
                    state: arkret_sdk::MlsGovernanceControlStateValue {
                        value: value.clone(),
                    },
                })
            }
            arkret_sdk::CellState::Bottom(_) => None,
        })
        .collect::<Vec<_>>();
    let mut frontier_events = input
        .events
        .iter()
        .filter(|event| event.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE)
        .cloned()
        .collect::<Vec<_>>();
    frontier_events.sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
    if frontier_events.len() != 1 {
        bail!("managed Agent PCR proof requires exactly one Realm genesis frontier Event");
    }
    let zero = arkret_sdk::Hash::new(format!("sha256:{}", "00".repeat(32)))
        .context("construct zero digest")?;
    let materialized = arkret_sdk::MaterializedMlsGovernanceProofBundle {
        bundle_version: arkret_sdk::MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
        proof_request_digest: zero.clone(),
        bundle_digest: zero,
        materialization_profile: arkret_sdk::MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE
            .to_owned(),
        realm_id: input.request.realm_id.clone(),
        effective_scope: input.request.effective_scope.clone(),
        reducer_profile: input.request.reducer_profile.clone(),
        trusted_anchor_seal_id: input.request.trusted_anchor_seal_id.clone(),
        accepted_seal_id: accepted_seal.id.clone(),
        seal_path: input.seals,
        covered_event_digests: material.covered_event_digests,
        control_state,
        frontier_events,
    };
    let chunks = arkret_sdk::build_mls_governance_proof_chunks(&input.request, &materialized)
        .map_err(|error| anyhow::anyhow!("build MLS governance proof chunks: {error}"))?;
    let chunk = chunks
        .get(input.request.chunk_index as usize)
        .context("requested MLS governance proof chunk is out of range")?;
    serde_json::to_value(chunk).context("serialize MLS governance proof chunk")
}

fn proposal_receipt(input: Value) -> Result<Value> {
    let input: ProposalReceiptInput =
        serde_json::from_value(input).context("parse proposal receipt input")?;
    input
        .request
        .validate_structural()
        .map_err(|error| anyhow::anyhow!("validate proposal receipt request: {error}"))?;
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
        arkret_sdk::Hash::new(event.event_digest()?).context("construct proposal Event digest")?;
    let authority_set_ref = arkret_sdk::Hash::new(
        arkret_sdk::canonical::canonical_sha256(&arkret_sdk::NotaryValue::single_did(
            event.actor_id.clone(),
        ))
        .context("digest proposal authority set")?,
    )
    .context("construct proposal authority-set digest")?;
    let mut member = arkret_wire::ProposalMemberReceipt {
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
            extra: Default::default(),
        },
    };
    let signing_bytes = member
        .canonical_bytes_for_signature()
        .context("materialize proposal member receipt transcript")?;
    member.signature.payload_digest = member
        .member_receipt_digest()
        .context("digest proposal member receipt")?;
    member.signature.jws = format!(
        "{}..{}",
        arkret_sdk::base64url_encode(br#"{"alg":"Ed25519"}"#),
        arkret_sdk::base64url_encode(
            signer
                .sign_raw(&signing_bytes)
                .map_err(|error| anyhow::anyhow!("sign proposal member receipt: {error}"))?
        )
    );
    member
        .validate_protocol_bounds()
        .map_err(|error| anyhow::anyhow!("validate proposal member receipt: {error}"))?;
    serde_json::to_value(arkret_wire::ProposalReceiptIssueOutcome {
        member_receipt: member,
    })
    .context("serialize proposal receipt outcome")
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
        let event_digest = arkret_sdk::Hash::new(submission.event.event_digest()?)
            .context("construct ingress Event digest")?;
        let received_at = authorization_lease.issued_at;
        let receipt_unix_ms = u64::try_from(received_at.timestamp_millis())
            .context("ingress receipt time predates the Unix epoch")?;
        let mut receipt = arkret_wire::IngressReceipt {
            receipt_id: arkret_wire::ReceiptId::new_v7_at(receipt_unix_ms),
            event_digest: event_digest.clone(),
            authorization_lease_id: authorization_lease.authorization_lease_id.clone(),
            received_at,
            service_id: arkret_wire::Did::new("did:web:server.local".to_owned())
                .context("construct ingress service id")?,
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
