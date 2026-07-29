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

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => canonical_json(input)?,
        "sha256-canonical-json" => sha256_canonical_json(input)?,
        "mls-governance-proof" => mls_governance_proof(input)?,
        "proposal-receipt" => proposal_receipt(input)?,
        "ingress-receipts" => ingress_receipts(input)?,
        _ => bail!("unknown inkson-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
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
    let policy_root = arkret_sdk::derive_mls_policy_root(&material.joined)
        .map_err(|error| anyhow::anyhow!("derive MLS policy root: {error}"))?;
    let capability_root = arkret_sdk::derive_mls_capability_root(&material.joined)
        .map_err(|error| anyhow::anyhow!("derive MLS capability root: {error}"))?;
    let discussion_metadata_digest =
        arkret_sdk::derive_mls_discussion_metadata_digest(&control_state)
            .map_err(|error| anyhow::anyhow!("derive MLS discussion metadata digest: {error}"))?;
    let mut frontier_events = input
        .events
        .iter()
        .filter(|event| event.kind.as_str() == arkret_sdk::events::EventKind::REALM_CREATE)
        .cloned()
        .collect::<Vec<_>>();
    frontier_events.sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
    if frontier_events.len() != 1 {
        bail!("managed Agent PCR proof requires exactly one Realm genesis frontier Event");
    }
    let membership_frontier = frontier_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let governance_binding = arkret_sdk::MlsGovernanceBindingPayload::realm(
        input.request.realm_id.clone(),
        input.request.mls_group_id.clone(),
        input.request.previous_epoch,
        input.request.next_epoch,
        membership_frontier,
        input.seals.iter().map(|seal| seal.id.clone()).collect(),
        policy_root,
        capability_root,
        discussion_metadata_digest,
        input.request.binding_profile.clone(),
        input.request.reducer_profile.clone(),
    )
    .map_err(|error| anyhow::anyhow!("build MLS governance binding: {error}"))?;
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
        governance_binding,
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
            alg: "EdDSA".to_owned(),
            verification_method: signer.verification_method().to_owned(),
            payload_digest: arkret_sdk::Hash::new(format!("sha256:{}", "00".repeat(32)))
                .context("construct proposal placeholder digest")?,
            created_at: received_at,
            jws: String::new(),
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
        arkret_sdk::base64url_encode(br#"{"alg":"EdDSA"}"#),
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
        let event_digest = arkret_sdk::Hash::new(submission.event.event_digest()?)
            .context("construct ingress Event digest")?;
        let received_at = submission.authorization_lease.issued_at;
        let mut receipt = arkret_wire::IngressReceipt {
            receipt_id: arkret_wire::ReceiptId::new(arkret_wire::new_prefixed_uuid7("ak:receipt:"))
                .context("construct ingress receipt id")?,
            event_digest: event_digest.clone(),
            authorization_lease_id: submission
                .authorization_lease
                .authorization_lease_id
                .clone(),
            received_at,
            service_id: arkret_wire::Did::new("did:web:server.local".to_owned())
                .context("construct ingress service id")?,
            authority_set_ref: submission.authorization_lease.authority_set_ref.clone(),
            proofs: Vec::new(),
        };
        let mut proof = arkret_wire::PayloadProof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: signer.verification_method().to_owned(),
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
            arkret_sdk::base64url_encode(br#"{"alg":"EdDSA"}"#),
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
            .validate_against_lease(&submission.authorization_lease, &event_digest)
            .context("validate ingress receipt binding")?;
        receipts.push(receipt);
    }
    serde_json::to_value(receipts).context("serialize ingress receipts")
}
