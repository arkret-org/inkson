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
struct DidKeyFromSeedInput {
    seed_b64url: String,
}

#[derive(Debug, Deserialize)]
struct PrincipalLocatorInput {
    subject_id: arkret_sdk::DidCoreId,
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

#[derive(Debug, Deserialize)]
struct RealmActorFrontierInput {
    realm_id: arkret_sdk::RealmId,
    actor_id: arkret_sdk::DidCoreId,
    next_actor_seq: u64,
    frontier_event_ids: Vec<arkret_sdk::EventId>,
    digest_suite: arkret_sdk::DigestSuite,
}

#[derive(Debug, Deserialize)]
struct ValidateMockResponseInput {
    schema_ref: String,
    value: Value,
}

#[derive(Debug, Deserialize)]
struct RealmGenesisSealInput {
    realm_id: arkret_sdk::RealmId,
    events: Vec<arkret_sdk::Event>,
    producer_signing_keys: BTreeMap<String, arkret_sdk::DidKey>,
}

struct MockServiceAuthority {
    resolution: arkret_sdk::AuthenticatedServiceResolution,
    signing_key: ed25519_dalek::SigningKey,
    service_id: arkret_sdk::DidCoreId,
    did: arkret_sdk::Did,
    verification_method: arkret_sdk::DidUrl,
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
        "realm-actor-frontier" => realm_actor_frontier(input)?,
        "service-resolution" => service_resolution()?,
        "principal-locator" => principal_locator(input)?,
        "did-key-from-seed" => did_key_from_seed(input)?,
        "demo-realm-genesis" => demo_realm_genesis()?,
        "realm-genesis-seal" => realm_genesis_seal(input)?,
        "validate-mock-response" => validate_mock_response(input)?,
        _ => bail!("unknown inkson-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn did_key_from_seed(input: Value) -> Result<Value> {
    let input: DidKeyFromSeedInput =
        serde_json::from_value(input).context("parse did:key fixture seed input")?;
    let seed =
        arkret_sdk::base64url_decode(&input.seed_b64url).context("decode did:key fixture seed")?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("did:key fixture seed must contain 32 bytes"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let multibase =
        arkret_sdk::ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
    Ok(json!({ "did_key": format!("did:key:{multibase}") }))
}

fn demo_realm_genesis() -> Result<Value> {
    use inkson::operation::AuthoredEventExt as _;

    let authority = mock_service_authority()?;
    let producer_signing_key = ed25519_dalek::SigningKey::from_bytes(&[1_u8; 32]);
    let producer_key_material = arkret_sdk::ed25519_pubkey_to_did_key_multibase(
        producer_signing_key.verifying_key().as_bytes(),
    );
    let producer_did = arkret_sdk::Did::new(format!("did:key:{producer_key_material}"))?;
    let producer_id = arkret_wire::project_did_to_core_id(&producer_did)?;
    let notary_public_key = authority.signing_key.verifying_key().to_bytes();
    let notary = arkret_sdk::NotaryValue::single_signer(arkret_sdk::NotarySignerDescriptor {
        actor_id: authority.station_id.clone(),
        verification_method: authority.verification_method.clone(),
        key_kind: arkret_sdk::NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: arkret_sdk::NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u: arkret_sdk::base64url_encode(notary_public_key),
        frozen_public_key_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
            notary_public_key,
        ))?,
    });
    inkson::operation::set_authoring_station_id(Some(authority.station_id.clone()));
    let operation = inkson::event_builders::build_realm_create_event(
        arkret_sdk::GenesisSalt::new(arkret_sdk::base64url_encode([9_u8; 32]))?,
        producer_id.as_str(),
        notary,
        "Arkret Demo Realm",
        Some("SDK-authored E2E Realm fixture"),
        "listed",
        "invite",
        "all_history_for_current_members",
        "mls_rfc9420",
        "standard",
        "restricted",
        "sha256",
        "ak:trust_domain:local.host",
        Some("mls_rfc9420"),
    )?;
    inkson::operation::set_authoring_station_id(None);
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-04-28T12:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    let mut event = operation
        .into_intent()
        .with_created_at(created_at)
        .author_with_digest_suite(
            0,
            arkret_sdk::Hlc::new("019641370000-0000-e2e00001".to_owned())?,
            arkret_sdk::DigestSuite::Sha256,
        )?;
    event.sign_ed25519(
        producer_did.as_str(),
        format!("{producer_did}#device"),
        &producer_signing_key,
    )?;
    let realm_id = event.realm_id.clone();
    let verification_method = event
        .proofs
        .first()
        .and_then(arkret_sdk::EventProof::as_producer)
        .context("demo Realm genesis lacks producer proof")?
        .verification_method
        .clone();
    let facets = inkson::event_builders::RealmBootstrapFacets {
        station_id: authority.station_id.clone(),
        actor_id: producer_id.to_string(),
        notary_did: authority.did.to_string(),
        notary_service_origin: "https://server.local".to_owned(),
        title: "Arkret Demo Realm".to_owned(),
        summary: Some("SDK-authored E2E Realm fixture".to_owned()),
        discoverability: "listed".to_owned(),
        join_rule: "invite".to_owned(),
        history_access: "all_history_for_current_members".to_owned(),
        encryption_profile: "mls_rfc9420".to_owned(),
        federation_policy: "restricted".to_owned(),
        alias: None,
        content_scheme: Some("mls_exporter_aead_v1".to_owned()),
        plaintext_visible_services: Vec::new(),
    };
    let followups = inkson::event_builders::build_realm_bootstrap_facet_intents(
        &facets,
        realm_id.as_str(),
        arkret_sdk::DigestSuite::Sha256,
    )?;
    let mut events = vec![event.event().clone()];
    for (index, intent) in followups.into_iter().enumerate() {
        let actor_seq = index as u64 + 1;
        let created_at = created_at + chrono::Duration::seconds(actor_seq as i64);
        let prev_ref = events
            .last()
            .context("demo Realm genesis chain lost its previous Event")?
            .event_id
            .clone();
        let mut followup = intent
            .with_created_at(created_at)
            .with_prev_refs(vec![prev_ref])
            .author_with_digest_suite(
                actor_seq,
                arkret_sdk::Hlc::new(format!("019641370000-{actor_seq:04x}-e2e00001"))?,
                arkret_sdk::DigestSuite::Sha256,
            )?;
        followup.sign_ed25519(
            producer_did.as_str(),
            format!("{producer_did}#device"),
            &producer_signing_key,
        )?;
        events.push(followup.event().clone());
    }
    let mut fixture = realm_genesis_seal(json!({
        "realm_id": realm_id,
        "events": events,
        "producer_signing_keys": {
            verification_method.as_str(): format!("did:key:{producer_key_material}")
        }
    }))?;
    fixture
        .as_object_mut()
        .context("demo Realm fixture is not an object")?
        .insert("realm_id".to_owned(), json!(realm_id));
    Ok(fixture)
}

fn realm_genesis_seal(input: Value) -> Result<Value> {
    use std::collections::{BTreeMap, BTreeSet};

    use arkret_sdk::{CellRegistry as _, PayloadSigner as _};

    let mut input: RealmGenesisSealInput =
        serde_json::from_value(input).context("parse Realm genesis Seal input")?;
    anyhow::ensure!(
        input
            .events
            .iter()
            .all(|event| event.realm_id == input.realm_id),
        "Realm genesis Seal Events belong to another Realm"
    );

    let digest_suite = arkret_sdk::DigestSuite::Sha256;
    let authority = mock_service_authority()?;
    let signer_evidence = arkret_sdk::AuthenticatedSignerResolutionEvidence::Service {
        signer_id: authority.station_id.clone(),
        verification_method: authority.verification_method.clone(),
        authenticated_resolution: authority.resolution.clone(),
    };
    signer_evidence.validate_attester_binding()?;
    let signer_evidence_digest = signer_evidence.canonical_sha256_digest()?;
    let signer_evidence_ref = signer_evidence.evidence_ref()?;
    let admission_signer = arkret_signatures::Ed25519PayloadSigner::new(
        authority.signing_key.clone(),
        authority.did.clone(),
        authority.verification_method.clone(),
    );
    for event in &mut input.events {
        anyhow::ensure!(
            event.station_id == authority.station_id,
            "Realm genesis Event targets a different Station"
        );
        let producer = match event.proofs.as_slice() {
            [arkret_sdk::EventProof::Producer(producer)] => producer.clone(),
            _ => bail!("Realm genesis input must contain caller-submission Events"),
        };
        let producer_signing_key = input
            .producer_signing_keys
            .get(producer.verification_method.as_str())
            .with_context(|| {
                format!(
                    "missing producer signing key for {}",
                    producer.verification_method
                )
            })?
            .clone();
        let accepted_at = chrono::Utc::now();
        let mut admission = arkret_sdk::StationAdmissionProof {
            kind: arkret_sdk::StationAdmissionProofKind::StationAdmission,
            verification_method: authority.verification_method.clone(),
            event_digest: producer.event_digest.clone(),
            producer_proof_digest: arkret_sdk::StationAdmissionProof::producer_proof_digest(
                &producer,
            )?,
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key_did: producer_signing_key,
            producer_signer_resolution_evidence_ref: None,
            producer_signer_resolution_evidence_digest: None,
            signer_resolution_evidence_ref: signer_evidence_ref.clone(),
            signer_resolution_evidence_digest: signer_evidence_digest.clone(),
            accepted_at,
            jws: String::new(),
        };
        admission.jws = admission_signer
            .sign_payload(&admission.canonical_binding_bytes()?)?
            .jws;
        admission.validate_binding(&producer.event_digest, &producer, &event.station_id)?;
        event.proofs.push(admission.into());
    }
    let registry = arkret_sdk::lattice_registry::build_sdk_cell_registry();
    let pre_state = BTreeMap::new();
    let mut ops_by_cell =
        BTreeMap::<arkret_sdk::CellRef, Vec<arkret_state::lattice::ordered_log::IssuedOp>>::new();
    let mut event_digests = Vec::with_capacity(input.events.len());
    for event in &input.events {
        let digest = arkret_sdk::Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
        let writes = arkret_schema::project_registered_operation_writes(
            &arkret_sdk::ProjectedEventInput::from(event),
            digest_suite,
        )?;
        for write in writes {
            for effect in arkret_state::resolve_projected_write(
                &write,
                &input.realm_id,
                &pre_state,
                &registry,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            {
                ops_by_cell.entry(effect.cell_id.clone()).or_default().push(
                    arkret_state::lattice::ordered_log::IssuedOp {
                        issuer_id: event.actor_id.clone(),
                        op: arkret_state::SealedOp::from_projection(digest.clone(), &effect),
                    },
                );
            }
        }
        event_digests.push((event.event_id.clone(), digest));
    }

    let mut post_state = BTreeMap::new();
    for (cell, ops) in ops_by_cell {
        let binding = registry
            .resolve(&input.realm_id, &cell)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        post_state.insert(
            cell.clone(),
            arkret_state::join_cell(binding.lattice.as_ref(), &cell, &ops),
        );
    }
    let state_root = arkret_state::compute_state_root(&post_state, digest_suite)?;

    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        authority.signing_key,
        authority.did,
        authority.verification_method,
    );
    let physical_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let hlc = arkret_sdk::Hlc::new(format!("{physical_ms:012x}-0000-5ea10000"))?;
    let mut delta = event_digests
        .iter()
        .map(|(_, digest)| digest.clone())
        .collect::<Vec<_>>();
    delta.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    delta.dedup();
    let covered = delta.iter().cloned().collect::<BTreeSet<_>>();
    let control_event_set_root = arkret_state::control_event_set_root(&covered, digest_suite)?;
    let completeness_events = input
        .events
        .iter()
        .cloned()
        .map(|event| (event, digest_suite))
        .collect::<Vec<_>>();
    let completeness_root = arkret_state::control_event_completeness_root(
        &completeness_events,
        &covered,
        digest_suite,
    )?;
    let seal = arkret_sdk::Seal::sign_single_kind_with_roots(
        input.realm_id,
        Vec::new(),
        delta,
        control_event_set_root,
        completeness_root,
        state_root,
        hlc,
        arkret_sdk::SealKind::Normal,
        digest_suite,
        &signer,
    )?;
    seal.validate_id(digest_suite)?;
    seal.validate_structural()?;
    let event_digests = event_digests
        .into_iter()
        .map(|(event_id, digest)| json!({ "event_id": event_id, "digest": digest }))
        .collect::<Vec<_>>();
    Ok(json!({
        "seal": seal,
        "event_digests": event_digests,
        "accepted_events": input.events,
        "governance_dependencies": [arkret_sdk::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector: arkret_sdk::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: signer_evidence_digest,
            },
            authenticated_signer_resolution_evidence: Box::new(signer_evidence),
        }],
        "signer": signer.signer_did(),
    }))
}

fn mock_service_authority() -> Result<MockServiceAuthority> {
    use arkret_identity::{DidKeyResolver, DidResolver};
    use arkret_sdk::{
        AuthenticatedServiceResolution, Did, DidUrl, ResolutionCommitment,
        ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
        ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
        ServiceResolutionRecordCore, route_binding_describe_digest, sign_service_resolution_record,
    };
    use chrono::Duration;
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
    let key_material =
        arkret_sdk::ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
    let did = Did::new(format!("did:key:{key_material}"))?;
    let service_id = arkret_wire::project_did_to_core_id(&did)?;
    let verification_method =
        DidUrl::new(format!("{did}#{key_material}")).map_err(|error| anyhow::anyhow!(error))?;
    let document = DidKeyResolver::new().resolve_did(&did)?.document;
    let document_digest =
        arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(&document)?)?;
    let did_digest = arkret_sdk::canonical::sha256_digest(did.as_str().as_bytes());
    let history_position = format!("synthetic-did-{did_digest}");
    let commitment = ResolutionCommitment {
        did: did.clone(),
        method_history_head: history_position.clone(),
        version_id: history_position.clone(),
    };
    let describe_digest = route_binding_describe_digest(
        &service_id,
        "station",
        &commitment,
        "https://server.local/_arkret",
    )?;
    let issued_at = chrono::Utc::now() - Duration::seconds(1);
    let record = sign_service_resolution_record(
        ServiceResolutionRecordCore {
            service_id: service_id.clone(),
            service_kind: "station".to_owned(),
            did,
            method_history_head: history_position.clone(),
            version_id: history_position.clone(),
            resolution_event_ref: format!("did-key-did-{did_digest}"),
            record_sequence: 0,
            previous_record_digest: None,
            current_record_url: format!(
                "https://server.local{}",
                arkret_sdk::canonical_service_current_record_path(&service_id)
            ),
            base_url: "https://server.local/".to_owned(),
            describe_digest,
            issued_at,
            refresh_after: issued_at + Duration::minutes(30),
            expires_at: issued_at + Duration::hours(1),
        },
        verification_method.clone(),
        &signing_key,
    )?;
    let evidence = ResolutionMethodHistoryEvidence::DidKeyExpansion {
        adapter_version: "did:key:1".to_owned(),
        boundary: ResolutionMethodEvidenceBoundary {
            from_method_history_head: history_position.clone(),
            from_version_id: history_position.clone(),
            to_method_history_head: history_position.clone(),
            to_version_id: history_position,
        },
        evidence: ResolutionDidBindingEvidenceReceipt {
            kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
            method: "key".to_owned(),
            document_digest,
            method_proofs: Vec::new(),
        },
    };
    let resolution = AuthenticatedServiceResolution {
        service_resolution_record: record,
        method_history_evidence: evidence,
        normalized_did_document: document,
    };
    arkret_identity::verify_authenticated_service_resolution_history(
        &resolution,
        &service_id,
        chrono::Utc::now(),
    )?;
    Ok(MockServiceAuthority {
        resolution,
        signing_key,
        service_id,
        did: signer_did_from_method(&verification_method)?,
        verification_method,
    })
}

fn signer_did_from_method(method: &arkret_sdk::DidUrl) -> Result<arkret_sdk::Did> {
    let (controller, _) = method
        .as_str()
        .split_once('#')
        .context("mock service verification method has no fragment")?;
    arkret_sdk::Did::new(controller.to_owned()).map_err(anyhow::Error::msg)
}

fn service_resolution() -> Result<Value> {
    serde_json::to_value(mock_service_authority()?.resolution)
        .context("serialize service-resolution fixture")
}

fn principal_locator(input: Value) -> Result<Value> {
    let input: PrincipalLocatorInput =
        serde_json::from_value(input).context("parse principal-locator fixture input")?;
    let authority = mock_service_authority()?;
    let issued_at = chrono::DateTime::parse_from_rfc3339("2026-06-07T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    let expires_at = issued_at + chrono::Duration::minutes(15);
    let locator_ref_digest = arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
        b"inkson-e2e-invite-locator",
    ))?;
    let service_resolution = arkret_sdk::ServiceResolutionCarrier::CurrentRecordUrl {
        current_record_url: authority
            .resolution
            .service_resolution_record
            .record
            .current_record_url
            .clone(),
        pinned_record_digest: None,
    };
    let mut locator = arkret_sdk::PrincipalLocator {
        schema: arkret_sdk::PrincipalLocator::SCHEMA.to_owned(),
        subject_id: input.subject_id,
        recipient_id: authority.station_id,
        service_resolution,
        route_assistance: None,
        recipient_kind: None,
        issued_at,
        expires_at,
        locator_ref_digest,
        delivery_modes: Vec::new(),
        display_hint: None,
        proofs: Vec::new(),
    };
    let unsigned = serde_json::to_value(&locator)?;
    let payload_digest =
        arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(&unsigned)?)?;
    locator.proofs.push(arkret_sdk::PrincipalLocatorProof {
        proof_purpose: arkret_sdk::PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
        proof: arkret_sdk::DetachedPayloadProof {
            kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: authority.verification_method,
            payload_digest,
            created_at: issued_at,
            domain: None,
            audience: None,
            jws: "e30..c2ln".to_owned(),
        },
    });
    locator.validate_minimal()?;
    serde_json::to_value(locator).context("serialize principal-locator fixture")
}

fn validate_mock_response(input: Value) -> Result<Value> {
    const VALIDATION_ALIAS: &str = "inkson.mock.response";
    let input: ValidateMockResponseInput =
        serde_json::from_value(input).context("parse mock response validation input")?;
    let (artifact_path, fragment) = input
        .schema_ref
        .split_once('#')
        .map_or((input.schema_ref.as_str(), None), |(path, fragment)| {
            (path, Some(format!("#{fragment}")))
        });
    let schema = arkret_schema::embedded_json_artifact(artifact_path)
        .with_context(|| format!("load embedded response schema {artifact_path}"))?;
    let mut registry = arkret_schema::schema_registry_from_embedded_spec_artifacts()
        .context("load embedded protocol schema registry")?;
    if let Some(fragment) = fragment {
        registry
            .register_fragment(VALIDATION_ALIAS, schema, fragment)
            .with_context(|| format!("register response schema {}", input.schema_ref))?;
    } else {
        registry.register(VALIDATION_ALIAS, schema);
    }
    registry
        .validate_value(VALIDATION_ALIAS, &input.value)
        .with_context(|| {
            format!(
                "mock response violates {}: {}",
                input.schema_ref,
                serde_json::to_string(&input.value).unwrap_or_else(|_| "<unprintable>".to_owned())
            )
        })?;
    Ok(input.value)
}

fn realm_actor_frontier(input: Value) -> Result<Value> {
    let input: RealmActorFrontierInput =
        serde_json::from_value(input).context("parse Realm actor frontier input")?;
    let frontier = arkret_models_collaboration::event_sync::RealmActorFrontierView::new(
        input.realm_id,
        input.actor_id,
        input.next_actor_seq,
        input.frontier_event_ids,
        input.digest_suite,
    )
    .context("derive Realm actor frontier")?;
    serde_json::to_value(frontier).context("serialize Realm actor frontier")
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

    let issuer_did = arkret_sdk::Did::new("did:web:server.local")?;
    let issuer = arkret_sdk::DidCoreId::new("ak:did_core:web:server.local")?;
    let verification_method = arkret_sdk::DidUrl::new(format!("{issuer_did}#notary-key"))
        .map_err(|error| anyhow::anyhow!("fixture verification method: {error}"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5a_u8; 32]);
    let signer = Ed25519PayloadSigner::new(
        signing_key.clone(),
        issuer_did.clone(),
        verification_method.clone(),
    );
    let observed_at = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut payload = arkret_sdk::RangeCompletenessAttestation {
        attestation_id: "ak:attestation:019fbeef-0000-7000-8000-000000000001".to_owned(),
        schema: SchemaId::RANGE_COMPLETENESS_ATTESTATION_V1.to_owned(),
        issuer_id: issuer.clone(),
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
                    witness_id: issuer.clone(),
                    verification_method: verification_method.clone(),
                    controlling_organization_id: issuer.clone(),
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
        station_id: issuer.clone(),
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
        let qualified_ingress_did = arkret_wire::Did::new("did:web:server.local".to_owned())
            .context("construct ingress service DID")?;
        let mut receipt = arkret_wire::IngressReceipt {
            receipt_id: arkret_wire::ReceiptId::new_v7_at(receipt_unix_ms),
            event_digest: event_digest.clone(),
            qualified_ingress_did,
            received_at,
            ingress_frontier: vec![submission.event.event_id.clone()],
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
            .proof_binding_bytes(authorization_lease, &proof)
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
            .validate_against_lease(
                authorization_lease,
                &event_digest,
                &submission.event.event_id,
            )
            .context("validate ingress receipt binding")?;
        receipts.push(receipt);
    }
    serde_json::to_value(receipts).context("serialize ingress receipts")
}

#[cfg(test)]
mod tests {
    use super::{realm_actor_frontier, validate_mock_response};

    #[test]
    fn realm_actor_frontier_command_matches_the_spec_vector() {
        let output = realm_actor_frontier(serde_json::json!({
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "actor_id": "ak:did_core:web:alice.example",
            "next_actor_seq": 43,
            "frontier_event_ids": [
                "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            ],
            "digest_suite": "sha256"
        }))
        .expect("typed frontier command");

        assert_eq!(
            output["frontier_digest"],
            "sha256:cb4775b3b4590faa096cafd34b0dfd9abc77ad02729a451c0fe5dfdee10d5dc1"
        );
    }

    #[test]
    fn mock_response_validation_uses_embedded_schema_artifacts() {
        let valid = serde_json::json!({
            "schema_ref": "schemas/http-problem-details.schema.json",
            "value": {
                "type": "https://arkret.org/problems/not_found",
                "title": "Not found",
                "status": 404,
                "detail": "The requested resource was not found."
            }
        });
        validate_mock_response(valid).expect("valid embedded response schema");

        let unknown_field = serde_json::json!({
            "schema_ref": "schemas/service-describe.schema.json",
            "value": { "obsolete_second_model": true }
        });
        assert!(validate_mock_response(unknown_field).is_err());

        let fragment = serde_json::json!({
            "schema_ref": "schemas/account-operations.schema.json#/$defs/account_view",
            "value": {}
        });
        let error = validate_mock_response(fragment).expect_err("missing fields must fail");
        assert!(!format!("{error:#}").contains("unknown schema"));
    }
}
