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
struct DidKeyFromSeedInput {
    seed_b64url: String,
}

#[derive(Debug, Deserialize)]
struct PrincipalLocatorInput {
    subject_id: arkret_sdk::DidCoreId,
}

#[derive(Debug, Deserialize)]
struct ControlProposalAckInput {
    request: arkret_wire::ControlProposalAckIssueRequest,
    digest_suite: arkret_sdk::DigestSuite,
}

#[derive(Debug, Deserialize)]
struct IngressReceiptsInput {
    submissions: Vec<arkret_wire::EventInitialSubmission>,
    digest_suite: arkret_sdk::DigestSuite,
}

#[derive(Debug, Deserialize)]
struct RealmActorFrontierInput {
    realm_id: arkret_sdk::RealmId,
    actor_id: arkret_sdk::ActorId,
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
        "control-proposal-ack" => control_proposal_ack(input)?,
        "ingress-receipts" => ingress_receipts(input)?,
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
    let producer_evidence = arkret_sdk::AuthenticatedSignerResolutionEvidence::Service {
        signer_id: authority.service_id.clone(),
        verification_method: authority.verification_method.clone(),
        authenticated_resolution: authority.resolution.clone(),
    };
    let producer_evidence_ref = producer_evidence.evidence_ref()?;
    let notary_public_key = authority.signing_key.verifying_key().to_bytes();
    let notary = arkret_sdk::NotaryValue::new(
        arkret_sdk::NotarySignerDescriptor {
            actor_id: arkret_sdk::ActorId::service(authority.service_id.clone()),
            verification_method: authority.verification_method.clone(),
            key_kind: arkret_sdk::NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: arkret_sdk::NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: arkret_sdk::base64url_encode(notary_public_key),
        },
        1_000,
    )?;
    inkson::operation::set_authoring_station_id(Some(authority.service_id.clone()));
    let operation = inkson::event_builders::build_realm_create_event(
        arkret_sdk::GenesisSalt::new(arkret_sdk::base64url_encode([9_u8; 32]))?,
        authority.service_id.as_str(),
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
        authority.did.as_str(),
        authority.verification_method.as_str(),
        &authority.signing_key,
        producer_evidence_ref.clone(),
    )?;
    let realm_id = event.realm_id.clone();
    let facets = inkson::event_builders::RealmBootstrapFacets {
        station_id: authority.service_id.clone(),
        actor_id: authority.service_id.to_string(),
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
    let membership = inkson::event_builders::build_realm_bootstrap_membership_intent(
        &facets,
        realm_id.as_str(),
    )?;
    let mut events = vec![event.event().clone()];
    for (index, intent) in followups
        .into_iter()
        .chain(std::iter::once(membership))
        .enumerate()
    {
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
            authority.did.as_str(),
            authority.verification_method.as_str(),
            &authority.signing_key,
            producer_evidence_ref.clone(),
        )?;
        events.push(followup.event().clone());
    }
    let mut fixture = realm_genesis_seal(json!({
        "realm_id": realm_id,
        "events": events
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

    let input: RealmGenesisSealInput =
        serde_json::from_value(input).context("parse Realm genesis Seal input")?;
    anyhow::ensure!(
        input
            .events
            .iter()
            .all(|event| event.realm_id == input.realm_id),
        "Realm genesis Seal Events belong to another Realm"
    );
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&input.events)
        .map_err(|error| anyhow::anyhow!(error.reason_code()))?;

    let digest_suite = arkret_sdk::DigestSuite::Sha256;
    let authority = mock_service_authority()?;
    for event in &input.events {
        anyhow::ensure!(
            event.actor_id.route_service_id() == &authority.service_id,
            "Realm genesis Event targets a different Station"
        );
        let Some(producer) = event.producer_proof.as_ref() else {
            bail!("Realm genesis input must contain exactly one producer proof");
        };
        producer
            .signer_resolution_evidence_ref
            .as_ref()
            .context("Realm genesis producer proof omitted signer evidence")?
            .content_digest()?;
    }
    let registry = arkret_sdk::lattice_registry::build_sdk_state_registry();
    // Keep the registered unit order separate from the Seal delta. A Realm
    // bootstrap is one atomic command unit, but its ordinary D members are
    // initial state only and never become Seal-covered security Events.
    let mut event_digests = Vec::with_capacity(input.events.len());
    let mut unit_events = Vec::with_capacity(input.events.len());
    for event in &input.events {
        let digest = arkret_sdk::Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
        event_digests.push((event.event_id.clone(), digest.clone()));
        unit_events.push(arkret_state::OrderedControlUnitEvent {
            digest,
            event: event.clone(),
            digest_suite,
        });
    }
    let unit = arkret_state::OrderedControlUnit {
        events: unit_events,
    };
    let executed = arkret_state::execute_ordered_control_units(
        &input.realm_id,
        &BTreeMap::new(),
        &registry,
        std::slice::from_ref(&unit),
        digest_suite,
        true,
        |member, staged_state| {
            let writes = arkret_schema::project_registered_operation_writes(
                &arkret_sdk::ProjectedEventInput::from(&member.event),
                member.digest_suite,
            )
            .map_err(|error| {
                arkret_state::OrderedControlBatchAbort::Structural(error.to_string())
            })?;
            let mut effects = Vec::new();
            for write in &writes {
                effects.extend(
                    arkret_state::resolve_projected_write(
                        write,
                        &input.realm_id,
                        staged_state,
                        &registry,
                    )
                    .map_err(|error| {
                        arkret_state::OrderedControlBatchAbort::Structural(error.to_string())
                    })?,
                );
            }
            Ok(arkret_state::CommandEventResult::Applied(effects))
        },
    )
    .map_err(|error| anyhow::anyhow!("execute Realm genesis command unit: {error}"))?;
    let post_state = executed.post_state;
    let security_state = post_state
        .iter()
        .filter(|(cell, _)| {
            registry
                .resolve(&input.realm_id, cell)
                .is_ok_and(|binding| binding.execution == arkret_sdk::EventCellExecution::Security)
        })
        .map(|(cell, state)| (cell.clone(), state.clone()))
        .collect::<BTreeMap<_, _>>();
    let state_root = arkret_state::compute_state_root(
        arkret_state::GovernanceView::new(&security_state),
        digest_suite,
    )?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        authority.signing_key,
        authority.did,
        authority.verification_method,
    );
    let physical_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let hlc = arkret_sdk::Hlc::new(format!("{physical_ms:012x}-0000-5ea10000"))?;
    let mut delta = executed.committed_event_digests;
    delta.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    delta.dedup();
    let covered = delta.iter().cloned().collect::<BTreeSet<_>>();
    let control_event_set_root = arkret_state::control_event_set_root(&covered, digest_suite)?;
    let configuration_ref = input
        .events
        .first()
        .context("Realm genesis Seal has no configuration Event")?
        .event_id
        .clone();
    let command_results = executed.command_results;
    let covered_event_digests = delta.clone();
    let seal = arkret_sdk::Seal::sign_with_signer(
        arkret_sdk::UnsignedSeal {
            realm_id: input.realm_id,
            predecessor_ref: None,
            delta,
            control_event_set_root,
            state_root,
            notary_seq: 0,
            availability_receipt_digests: Vec::new(),
            covered_event_digests,
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: chrono::Utc::now(),
            hlc,
            configuration_ref,
            command_results,
            authorization_closures: Vec::new(),
            existence_anchors: Vec::new(),
        },
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
                content_digest: signer_evidence_ref.content_digest()?,
            },
            authenticated_signer_resolution_evidence: Box::new(signer_evidence),
        }],
        "signer": signer.signer_did(),
    }))
}

fn mock_service_authority() -> Result<MockServiceAuthority> {
    use arkret_identity::{
        DidResolver as _, DidWebvhDocumentOutcome, DidWebvhLogOutcome, DidWebvhResolver,
    };
    use rand_core::SeedableRng as _;
    let endpoint = url::Url::parse("https://server.local/")?;
    let at =
        chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")?.with_timezone(&chrono::Utc);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(31);
    let prepared = arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: at,
            did_key_fragment: Some("signing-1"),
        },
        &[31; 32],
    )?;
    let did = arkret_sdk::Did::new(prepared.did.clone())?;
    let service_id = arkret_wire::project_did_to_core_id(&did)?;
    let verification_method =
        arkret_sdk::DidUrl::new(prepared.did_key_id.clone()).map_err(anyhow::Error::msg)?;
    let mut resolver = DidWebvhResolver::new();
    resolver.insert_from_https_response(
        &did,
        DidWebvhDocumentOutcome {
            url: DidWebvhResolver::document_url(&did)?,
            content_type: "application/json".into(),
            body: serde_json::to_vec(&prepared.log_entry["state"])?,
        },
    )?;
    resolver.ingest_log(
        &did,
        DidWebvhLogOutcome {
            url: DidWebvhResolver::log_url(&did)?,
            content_type: "application/jsonl".into(),
            body: serde_json::to_vec(&prepared.log_entry)?,
        },
    )?;
    let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
        service_id.clone(),
        "station".into(),
        resolver.resolve_did(&did)?.document,
        vec![prepared.log_entry.clone()],
        vec![],
        chrono::Utc::now(),
    )?;
    Ok(MockServiceAuthority {
        resolution,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[31; 32]),
        service_id,
        did,
        verification_method,
    })
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
    let service_resolution = arkret_sdk::ServiceResolutionCarrier::ResolutionUrl {
        resolution_url: format!(
            "https://server.local{}",
            arkret_sdk::canonical_service_resolution_path(&authority.service_id)
        ),
    };
    let mut locator = arkret_sdk::PrincipalLocator {
        schema: arkret_sdk::PrincipalLocator::SCHEMA.to_owned(),
        account_id: arkret_sdk::AccountId::new(input.subject_id, authority.service_id),
        service_resolution,
        route_assistance: None,
        issued_at,
        expires_at,
        locator_ref_digest,
        display_hint: None,
        proofs: Vec::new(),
    };
    let mut proof = arkret_sdk::DetachedPayloadProof {
        kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: authority.verification_method,
        payload_digest: locator.payload_digest()?,
        created_at: issued_at,
        domain: None,
        audience: None,
        jws: String::new(),
    };
    proof.jws = arkret_sdk::signatures::sign_ed25519_detached_jws(
        &authority.signing_key,
        &locator.proof_signing_bytes(&proof)?,
    )?;
    locator.proofs.push(arkret_sdk::PrincipalLocatorProof {
        proof_purpose: arkret_sdk::PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
        proof,
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
    let schema = arkret_schema_conformance::spec_json_artifact(artifact_path)
        .with_context(|| format!("load embedded response schema {artifact_path}"))?;
    let mut registry = arkret_schema_conformance::schema_registry_from_configured_spec_artifacts()
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

fn control_proposal_ack(input: Value) -> Result<Value> {
    let input: ControlProposalAckInput =
        serde_json::from_value(input).context("parse Control Proposal Ack input")?;
    input
        .request
        .validate_structural()
        .map_err(|error| anyhow::anyhow!("validate Control Proposal Ack request: {error}"))?;
    let event = &input.request.event;
    let policy = arkret_wire::ControlProposalDecisionPolicy::default();
    let received_at = chrono::Utc::now();
    let proposal_digest =
        arkret_sdk::Hash::new(event.event_digest_with_digest_suite(input.digest_suite)?)
            .context("construct proposal Event digest")?;
    // The notary this Ack names is a development identity on the shared
    // derivation, not a constant: `[2u8; 32]` is not an Ed25519 curve point, and
    // `NotarySignerDescriptor::validate` does not decompress, so publishing one
    // produced an authority set no verifier could ever resolve.
    let notary_verification_method =
        arkret_sdk::DidUrl::new("did:web:server.local#notary".to_owned())
            .map_err(anyhow::Error::msg)?;
    let notary_public_key =
        arkret_signatures::development_verifying_key(notary_verification_method.as_str())
            .to_bytes();
    let authority_set_ref = arkret_sdk::Hash::new(
        arkret_sdk::canonical::canonical_sha256(&arkret_sdk::NotaryValue::new(
            arkret_sdk::NotarySignerDescriptor {
                actor_id: arkret_sdk::ActorId::service(arkret_sdk::DidCoreId::new(
                    "ak:did_core:web:server.local".to_owned(),
                )?),
                verification_method: notary_verification_method.clone(),
                key_kind: arkret_sdk::NotaryKeyKind::Ed25519Raw32,
                jose_algorithm: arkret_sdk::NotaryJoseAlgorithm::Ed25519,
                frozen_public_key_b64u: arkret_sdk::base64url_encode(notary_public_key),
            },
            1_000,
        )?)
        .context("digest proposal authority set")?,
    )
    .context("construct proposal authority-set digest")?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        arkret_signatures::development_signing_key(notary_verification_method.as_str()),
        arkret_sdk::Did::new("did:web:server.local")?,
        notary_verification_method,
    );
    let member = arkret_wire::ControlProposalAck::issue_with_signer(
        event.realm_id.clone(),
        proposal_digest,
        authority_set_ref,
        received_at,
        policy,
        &signer,
    )?;
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
        let fixture = arkret_schema_conformance::spec_json_artifact("fixtures/sync-fixture.json")
            .expect("embedded sync fixture");
        let instance = &fixture["schema_validation_cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "realm_actor_frontier_sibling_set_valid")
            .expect("normative frontier vector")["instance"];
        let output = realm_actor_frontier(serde_json::json!({
            "realm_id": instance["realm_id"],
            "actor_id": instance["actor_id"],
            "next_actor_seq": instance["next_actor_seq"],
            "frontier_event_ids": instance["frontier_event_ids"],
            "digest_suite": "sha256"
        }))
        .expect("typed frontier command");

        assert_eq!(&output, instance);
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
