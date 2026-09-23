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
struct ValidateMockResponseInput {
    schema_ref: String,
    value: Value,
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
        "service-resolution" => service_resolution()?,
        "principal-locator" => principal_locator(input)?,
        "did-key-from-seed" => did_key_from_seed(input)?,
        "demo-realm-genesis" => demo_realm_genesis()?,
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
