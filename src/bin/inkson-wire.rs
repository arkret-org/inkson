use std::io::{self, Read};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

#[path = "inkson-wire/realm_fixture.rs"]
mod realm_fixture;

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
struct ValidateMockResponseInput {
    schema_ref: String,
    value: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceResolutionInput {
    service_kind: Option<arkret_wire::ServiceKind>,
}

struct MockServiceAuthority {
    resolution: arkret_sdk::AuthenticatedServiceResolution,
    signing_key: ed25519_dalek::SigningKey,
    service_id: arkret_sdk::DidCoreId,
    verification_method: arkret_sdk::DidUrl,
}

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => canonical_json(input)?,
        "sha256-canonical-json" => sha256_canonical_json(input)?,
        "service-resolution" => serde_json::to_value(service_resolution(input)?)?,
        "service-document" => {
            serde_json::to_value(service_resolution(input)?.normalized_did_document)?
        }
        "principal-locator" => principal_locator(input)?,
        "direct-conversation-pair-key" => direct_conversation_pair_key(input)?,
        "did-key-from-seed" => did_key_from_seed(input)?,
        "demo-realm-genesis" => demo_realm_genesis()?,
        "validate-mock-response" => validate_mock_response(input)?,
        "contact-request-prepare" => contact_request_prepare(input)?,
        "contact-request-commit" => contact_request_commit(input)?,
        "contact-request-sign" => contact_request_sign(input)?,
        "contact-request-verify" => contact_request_verify(input)?,
        "mock-realm-fixture" => realm_fixture::build(input)?,
        "mock-realm-verify" => realm_fixture::verify(input)?,
        "mock-current-principal" => realm_fixture::current_principal(input)?,
        "mock-realm-scan" => realm_fixture::scan(input)?,
        "mock-exact-current" => realm_fixture::exact_current(input)?,
        "mock-realm-submit" => realm_fixture::submit(input)?,
        "mock-realm-signer-keys" => realm_fixture::signer_keys(input)?,
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
    Ok(json!({ "did_key": format!("did:key:{multibase}"),
        "public_key_b64url": arkret_sdk::base64url_encode(signing_key.verifying_key().as_bytes()) }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectConversationPairInput {
    trust_domain: arkret_sdk::TrustDomainId,
    holder: arkret_sdk::AccountId,
    body: arkret_sdk::DirectConversationResolveRequestBody,
}

fn direct_conversation_pair_key(input: Value) -> Result<Value> {
    use arkret_sdk::{DirectConversationPairKeyParticipant, direct_conversation_pair_key};
    let input: DirectConversationPairInput = serde_json::from_value(input)?;
    let pair_key = direct_conversation_pair_key(
        input.trust_domain,
        DirectConversationPairKeyParticipant::unmapped(arkret_sdk::ActorId::Account {
            account_id: input.holder,
        }),
        DirectConversationPairKeyParticipant::unmapped(input.body.peer.contact_actor_id()),
    )?;
    Ok(json!({ "pair_key": pair_key }))
}

#[derive(Deserialize)]
struct ContactRequestPrepareInput {
    holder: arkret_sdk::AccountId,
    realm_id: arkret_sdk::RealmId,
    body: arkret_sdk::contact_operations::ContactPrepareRequestBody,
}

fn contact_request_prepare(input: Value) -> Result<Value> {
    use arkret_sdk::contact_operations::{
        ContactOperationOutcome, ContactPeer, ContactPreparedOutcome,
    };
    let input: ContactRequestPrepareInput = serde_json::from_value(input)?;
    let holder = ContactPeer::Human {
        account_id: input.holder.clone(),
    };
    anyhow::ensure!(
        holder.contact_actor_id() != input.body.peer.contact_actor_id(),
        "Contact peer must differ from holder"
    );
    anyhow::ensure!(
        !input.body.granted_to_peer_scopes.is_empty(),
        "Contact scopes must not be empty"
    );
    anyhow::ensure!(
        input.body.continuity_evidence.is_none(),
        "mock request supports only a first Contact round"
    );
    let payload = arkret_sdk::ContactRequestedPayload {
        peer: input.body.peer,
        granted_to_peer_scopes: input.body.granted_to_peer_scopes,
        introduction_evidence_digest: arkret_sdk::Hash::new(
            arkret_sdk::canonical::domain_prefixed_canonical_sha256(
                "ak.contact.introduction-evidence.v1",
                &input.body.introduction_evidence,
            )?,
        )?,
        previous_terminal_contact_round_id: None,
        message: input
            .body
            .message
            .map(|message| message.trim().to_owned())
            .filter(|message| !message.is_empty()),
    };
    let created_at = chrono::Utc::now();
    let event =
        arkret_event_draft::TypedEventDraft::<arkret_sdk::event_spec::ContactRequested>::new(
            arkret_sdk::ScopeRef::Realm {
                realm_id: input.realm_id,
            },
            holder.contact_actor_id(),
            payload,
        )?
        .author_with_digest_suite(created_at, arkret_sdk::DigestSuite::Sha256)?;
    let draft = arkret_sdk::PreparedEventDraft {
        unsigned_event_bytes: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
            arkret_sdk::canonical::canonical_json_bytes(&event.digest_payload()?)?,
        ))
        .map_err(anyhow::Error::msg)?,
        event_digest: arkret_sdk::Hash::new(
            event.event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?,
        )?,
    };
    draft.unsigned_event_for_kind(arkret_wire::event_kind_str::CONTACT_REQUESTED)?;
    serde_json::to_value(ContactOperationOutcome::Prepared {
        outcome: ContactPreparedOutcome::Request {
            operation_id: input.body.operation_id,
            reservation_handle: arkret_sdk::ReservationHandle::new(format!(
                "e2e-contact-{}",
                draft.event_id()?
            ))
            .map_err(anyhow::Error::msg)?,
            expires_at: created_at + chrono::Duration::minutes(15),
            event_draft: draft,
        },
    })
    .map_err(Into::into)
}

#[derive(Deserialize)]
struct ContactRequestCommitInput {
    prepared: arkret_sdk::contact_operations::ContactOperationOutcome,
    body: arkret_sdk::contact_operations::ContactCommitRequestBody,
    producer_verification_method: arkret_sdk::DidUrl,
    producer_public_key_b64url: arkret_sdk::Base64UrlString,
}

fn contact_request_commit(input: Value) -> Result<Value> {
    use arkret_sdk::contact_operations::*;
    let input: ContactRequestCommitInput = serde_json::from_value(input)?;
    let ContactOperationOutcome::Prepared {
        outcome:
            ContactPreparedOutcome::Request {
                operation_id,
                reservation_handle,
                event_draft,
                expires_at,
            },
    } = input.prepared
    else {
        bail!("Contact commit requires its exact request reservation")
    };
    // The mock replays an existing terminal outcome before reaching this helper.
    // Expiration refuses only a first acceptance, never a previously frozen result.
    anyhow::ensure!(
        chrono::Utc::now() < expires_at,
        "Contact request reservation expired"
    );
    anyhow::ensure!(
        input.body.operation_id == operation_id
            && input.body.reservation_handle == reservation_handle,
        "Contact commit changed its operation or reservation"
    );
    let event = input.body.signed_event;
    let unsigned =
        event_draft.unsigned_event_for_kind(arkret_wire::event_kind_str::CONTACT_REQUESTED)?;
    anyhow::ensure!(
        event.digest_payload()? == unsigned.digest_payload()?
            && event.event_id == *unsigned.event_id(),
        "Contact commit changed its reserved Event"
    );
    let proof = event
        .producer_proof
        .as_ref()
        .context("Contact commit omitted producer proof")?;
    anyhow::ensure!(
        proof.verification_method == input.producer_verification_method,
        "Contact producer method changed"
    );
    let producer = ContactProducerSigner::direct(
        input.producer_verification_method,
        input.producer_public_key_b64url,
    )?;
    let holder = ContactPeer::Human {
        account_id: event
            .actor_id
            .as_account_id()
            .context("Contact holder must be an account")?
            .clone(),
    };
    producer.validate_for_event(&event, &holder)?;
    arkret_signatures::proof::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_sdk::canonical::canonical_json_bytes(&event.digest_payload()?)?,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: producer.public_key_bytes()?.to_vec(),
        },
        arkret_sdk::DigestSuite::Sha256,
    )
    .map_err(|error| anyhow::anyhow!("Contact producer signature is invalid: {error}"))?;
    let authority = mock_service_authority()?;
    anyhow::ensure!(
        holder.delivery_station_id() == &authority.service_id,
        "Contact holder Station differs from mock authority"
    );
    let payload: arkret_sdk::ContactRequestedPayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    let accepted_at = chrono::Utc::now();
    let receipt = RequestAcceptanceReceipt::sign_with(
        RequestAcceptanceReceiptCore {
            holder,
            peer: payload.peer,
            slot_version: 1,
            slot_predecessor: None,
            previous_terminal_contact_round_id: None,
            request_event_ref: event.event_id.clone(),
            producer_signer: producer,
            source_checkpoint: arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(
                &event,
            )?)?,
            accepted_at,
            issuer_id: authority.service_id,
        },
        |bytes| {
            Ok(arkret_sdk::ProtocolSignature {
                verification_method: authority.verification_method,
                created_at: accepted_at,
                jws: arkret_sdk::signatures::sign_ed25519_detached_jws(
                    &authority.signing_key,
                    bytes,
                )
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?,
            })
        },
    )?;
    arkret_sdk::verify_contact_request_acceptance_receipt(
        &receipt,
        &event.event_id,
        &authority.signing_key.verifying_key(),
    )?;
    let list_row = ContactListRow {
        peer: receipt.core.peer.clone(),
        state: ContactState::PendingOutgoing,
        request_event_ref: Some(event.event_id.clone()),
        request_message: None,
        response_event_ref: None,
        tombstone_event_ref: None,
        next_prepare_input: None,
        granted_to_peer_scopes: payload.granted_to_peer_scopes,
        granted_by_peer_scopes: Vec::new(),
        bidirectional_scopes: Vec::new(),
        effective_scopes: None,
        continuity_evidence: None,
        direct_conversation: None,
        contact_agent_projections: Vec::new(),
        peer_endpoint: None,
    };
    list_row.validate_shape()?;
    let outcome = ContactOperationOutcome::Accepted {
        outcome: ContactAcceptedOutcome::Request {
            operation_id,
            request_acceptance_receipt: receipt,
        },
    };
    Ok(json!({"outcome": outcome, "list_row": list_row}))
}

#[derive(Deserialize)]
struct ContactRequestSignInput {
    prepared: arkret_sdk::contact_operations::ContactOperationOutcome,
    seed_b64url: String,
    holder_did: String,
    device_id: String,
}

fn contact_request_sign(input: Value) -> Result<Value> {
    let input: ContactRequestSignInput = serde_json::from_value(input)?;
    let arkret_sdk::contact_operations::ContactOperationOutcome::Prepared { outcome } =
        input.prepared
    else {
        bail!("Contact signer requires prepared outcome")
    };
    let mut event = outcome
        .event_draft()?
        .unsigned_event_for_kind(arkret_wire::event_kind_str::CONTACT_REQUESTED)?;
    let seed: [u8; 32] = arkret_sdk::base64url_decode(&input.seed_b64url)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Contact fixture seed must have 32 bytes"))?;
    let signer = inkson::event_signer::build_ed25519_device_signer(
        seed,
        &input.holder_did,
        &input.device_id,
    );
    anyhow::ensure!(
        event
            .actor_id
            .as_account_id()
            .context("Contact actor must be an account")?
            .principal_id
            == arkret_sdk::project_did_to_core_id(&arkret_sdk::Did::new(input.holder_did)?)?,
        "Contact draft holder differs from signer"
    );
    signer.sign_sdk_event_with_context(
        &mut event,
        inkson::event_signer::ProducerProofContext::for_native_unit(
            arkret_sdk::DigestSuite::Sha256,
        ),
    )?;
    serde_json::to_value(event.into_event()).map_err(Into::into)
}

#[derive(Deserialize)]
struct ContactRequestVerifyInput {
    outcome: arkret_sdk::contact_operations::ContactOperationOutcome,
    event: arkret_sdk::Event,
}

fn contact_request_verify(input: Value) -> Result<Value> {
    use arkret_sdk::contact_operations::{ContactAcceptedOutcome, ContactOperationOutcome};
    let input: ContactRequestVerifyInput = serde_json::from_value(input)?;
    let ContactOperationOutcome::Accepted {
        outcome:
            ContactAcceptedOutcome::Request {
                request_acceptance_receipt,
                ..
            },
    } = input.outcome
    else {
        bail!("Contact verifier requires accepted request")
    };
    let authority = mock_service_authority()?;
    request_acceptance_receipt
        .core
        .producer_signer
        .validate_for_event(&input.event, &request_acceptance_receipt.core.holder)?;
    anyhow::ensure!(
        request_acceptance_receipt.core.holder.contact_actor_id() == input.event.actor_id
            && serde_json::to_value(&request_acceptance_receipt.core.peer)?
                == input.event.payload["peer"],
        "Contact receipt changed holder or peer"
    );
    arkret_sdk::verify_contact_request_acceptance_receipt(
        &request_acceptance_receipt,
        &input.event.event_id,
        &authority.signing_key.verifying_key(),
    )?;
    Ok(json!({"verified": true}))
}

fn demo_realm_genesis() -> Result<Value> {
    let authority = mock_service_authority()?;
    inkson::operation::set_authoring_station_id(Some(authority.service_id.clone()));
    let operation = inkson::event_builders::build_realm_create_event(
        arkret_sdk::GenesisSalt::new(arkret_sdk::base64url_encode([9_u8; 32]))?,
        authority.service_id.as_str(),
        "listed",
        "invite",
        "all_history_for_current_members",
        "standard",
        "ak:trust_domain:server.local",
    )?;
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-09-19T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    let event = operation
        .into_intent()
        .with_created_at(created_at)
        .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?
        .into_event();
    Ok(json!({
        "realm_id": event.realm_id,
        "accepted_events": [event],
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
        verification_method,
    })
}

fn service_resolution(input: Value) -> Result<arkret_sdk::AuthenticatedServiceResolution> {
    let input: ServiceResolutionInput = serde_json::from_value(input)?;
    let kind = input
        .service_kind
        .unwrap_or(arkret_wire::ServiceKind::Station);
    let resolution = match kind {
        arkret_wire::ServiceKind::Station => mock_service_authority()?.resolution,
        arkret_wire::ServiceKind::DirectoryService => {
            let did = arkret_wire::Did::new("did:web:directory.local".to_owned())?;
            let key = ed25519_dalek::SigningKey::from_bytes(&[32; 32]);
            let method = format!("{did}#signing-1");
            let document: arkret_models_identity::DidDocument = serde_json::from_value(json!({
                "@context":["https://www.w3.org/ns/did/v1"],
                "id":did,
                "verificationMethod":[{"id":method,"type":"Multikey","controller":did,
                    "publicKeyMultibase":arkret_sdk::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())}],
                "assertionMethod":[method],
                "service":[{"id":format!("{did}#arkret"),"type":"ArkretService",
                    "serviceKind":kind.as_str(),"serviceEndpoint":"https://directory.local/"}]
            }))?;
            // Directory reads use independently fetched current did:web state;
            // they do not supply historical signer or Realm authority evidence.
            arkret_identity::build_authenticated_did_web_service_resolution(
                arkret_wire::project_did_to_core_id(&did)?,
                kind.as_str().to_owned(),
                document,
                chrono::Utc::now(),
            )?
        }
        _ => bail!("service fixture supports only Station and Directory roles"),
    };
    Ok(resolution)
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
