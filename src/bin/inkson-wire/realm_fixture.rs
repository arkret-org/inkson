//! Restricted native fixtures for the ordinary own-Station read contract.
//! Every protocol carrier is an SDK type. These fixtures are not live admission.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};
use arkret_sdk::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{MockServiceAuthority, mock_service_authority};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildInput {
    salt: u8,
    title: String,
    #[serde(default = "default_seed")]
    seed_b64url: String,
    #[serde(default = "default_device")]
    device_id: String,
    #[serde(default)]
    board: bool,
    #[serde(default)]
    empty_board: bool,
    #[serde(default)]
    encrypted: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    snapshot: RealmStateSnapshot,
    committed_events: Vec<CommittedEventFullView>,
    signer_facts: Vec<arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact>,
    source_authorization: CommittedEventFullView,
    identity: FixtureIdentity,
    account_entry: arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
    ids: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    public_blobs: BTreeMap<String, Base64UrlString>,
    managed_agent: ManagedAgentFixture,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedAgentFixture {
    did: Did,
    account_id: AccountId,
    principal_control_realm_id: RealmId,
    inception_log_entry: Value,
    binding_log_entry: Value,
    provision: CommittedEventFullView,
    genesis: CommittedEventFullView,
    runtime_authorization: CommittedEventFullView,
    runtime_proof: arkret_models_collaboration::agent_scope::AgentRuntimeKeyPossessionProof,
    requested_scope: AgentKeyScope,
    controller_authorization_ref: DidUrl,
}

fn default_seed() -> String {
    base64url_encode([1; 32])
}
fn default_device() -> String {
    "ak:device:01964137-0000-7000-8000-0000000000a1".to_owned()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureIdentity {
    did: Did,
    account_id: AccountId,
    principal_control_realm_id: RealmId,
    document: Value,
    inception_log_entry: Value,
    resolution: PrincipalResolutionProjection,
}

struct Builder {
    authority: MockServiceAuthority,
    actor: ActorId,
    signer: Ed25519PayloadSigner,
    key: arkret_models_identity::signer_key_operations::ResolvedSignerKey,
    source_authorization: CommittedEventFullView,
    identity: FixtureIdentity,
    events: Vec<CommittedEventFullView>,
    facts: Vec<arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact>,
    rows: Vec<TypedCurrentRow>,
    ids: BTreeMap<String, String>,
    public_blobs: BTreeMap<String, Base64UrlString>,
    managed_agent: Option<ManagedAgentFixture>,
}

fn at(position: usize) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-09-19T00:00:00.000Z")
        .expect("fixed fixture timestamp")
        .with_timezone(&chrono::Utc)
        + chrono::Duration::milliseconds(position as i64)
}

fn unsigned<T: Serialize>(value: &T, excluded: &[&str]) -> Result<Value> {
    let mut value = serde_json::to_value(value)?;
    for key in excluded {
        value.as_object_mut().expect("closed object").remove(*key);
    }
    Ok(value)
}

fn commit(
    authority: &MockServiceAuthority,
    event: &Event,
    position: u64,
    predecessor: Option<RealmCommitId>,
    genesis: EventId,
    fact: Option<Hash>,
) -> Result<RealmCommit> {
    let mut value = RealmCommit {
        commit_id: RealmCommitId::from_digest([0; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))?,
        stream_position: position,
        previous_commit_ref: predecessor,
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis),
        committed_at: event.created_at,
        producer_signer_fact_digest: fact,
        signature: arkret_signatures::detached_object::sign_detached_object(
            &json!({}),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            authority.verification_method.clone(),
            event.created_at,
            &authority.signing_key,
        )?,
    };
    value.commit_id = RealmCommitId::from_digest(arkret_sdk::canonical::sha256_bytes(
        &arkret_sdk::canonical::canonical_json_bytes(&unsigned(
            &value,
            &["commit_id", "signature"],
        )?)?,
    ));
    value.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned(&value, &["signature"])?,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        authority.verification_method.clone(),
        event.created_at,
        &authority.signing_key,
    )?;
    value.verify_commit_id_matches_content()?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &value.signature,
        &unsigned(&value, &["signature"])?,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: authority.signing_key.verifying_key().to_bytes().to_vec(),
        },
    )?;
    Ok(value)
}

impl Builder {
    fn new(input: &BuildInput) -> Result<Self> {
        let authority = mock_service_authority()?;
        use arkret_identity::DidResolver as _;
        use rand_core::SeedableRng as _;
        let seed: [u8; 32] = base64url_decode(&input.seed_b64url)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("fixture producer seed must contain 32 bytes"))?;
        let endpoint = url::Url::parse("https://alice.example/")?;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let inception = arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
            &mut rng,
            &arkret_signatures::webvh::ServiceInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "alice",
                also_known_as: &[],
                version_time: at(0),
                did_key_fragment: Some("signing-1"),
            },
            &seed,
        )?;
        let did = Did::new(inception.did.clone())?;
        let mut resolver = arkret_identity::DidWebvhResolver::new();
        resolver.insert_from_https_response(
            &did,
            arkret_identity::DidWebvhDocumentOutcome {
                url: arkret_identity::DidWebvhResolver::document_url(&did)?,
                content_type: "application/json".into(),
                body: serde_json::to_vec(&inception.log_entry["state"])?,
            },
        )?;
        resolver.ingest_log(
            &did,
            arkret_identity::DidWebvhLogOutcome {
                url: arkret_identity::DidWebvhResolver::log_url(&did)?,
                content_type: "application/jsonl".into(),
                body: serde_json::to_vec(&inception.log_entry)?,
            },
        )?;
        resolver.resolve_did(&did)?;
        let principal = arkret_wire::project_did_to_core_id(&did)?;
        let producer_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let device_id = DeviceId::new(input.device_id.clone())?;
        let device_signer = inkson::event_signer::build_ed25519_device_signer(
            seed,
            did.as_str(),
            device_id.as_str(),
        );
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            seed,
            did.clone(),
            DidUrl::new(format!("{did}#{device_id}")).map_err(anyhow::Error::msg)?,
        );
        let actor = ActorId::account(AccountId::new(
            principal.clone(),
            authority.service_id.clone(),
        ));
        let multibase =
            ed25519_pubkey_to_did_key_multibase(producer_key.verifying_key().as_bytes());
        let mut authorize = DeviceAuthorizePayload {
            device_id: device_id.clone(),
            device_public_key_did: NonEmptyString::new(format!("did:key:{multibase}"))
                .map_err(anyhow::Error::msg)?,
            hpke_key: NonEmptyString::new(base64url_encode([17; 32]))
                .map_err(anyhow::Error::msg)?,
            algorithms: ["Ed25519", "HPKE-X25519-HKDF-SHA256-AES128GCM"]
                .into_iter()
                .map(|s| NonEmptyString::new(s).map_err(anyhow::Error::msg))
                .collect::<Result<_>>()?,
            device_key_algorithm: NonEmptyString::new("Ed25519").map_err(anyhow::Error::msg)?,
            authorized_by: DeviceOrPrincipalRef::Principal(principal.clone()),
            scopes: None,
            not_before: at(0),
            expires_at: None,
            authorization_binding_kind: DeviceAuthorizationBindingKind::RegistrationAnchor,
            authorized_generation_ref: 1,
            device_signature: SignatureMaterial::NonEmptyString(
                NonEmptyString::new("pending").map_err(anyhow::Error::msg)?,
            ),
            recovery_session_id: None,
            pairing_challenge_transcript_digest: None,
            applet_id: None,
        };
        let possession = device_signer
            .sign_raw(&authorize.device_possession_signature_input(actor.as_account_id().unwrap())?)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        authorize.device_signature = SignatureMaterial::NonEmptyString(
            NonEmptyString::new(base64url_encode(possession)).map_err(anyhow::Error::msg)?,
        );
        let descriptor = FoundingDeviceDescriptor {
            descriptor_version: 1,
            device_id,
            device_public_key_did: authorize.device_public_key_did.clone(),
            device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
            device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
            hpke_key: authorize.hpke_key.clone(),
            hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
            algorithms: authorize.algorithms.clone(),
            founding_authorize_payload_digest: device_authorize_payload_digest(
                &serde_json::to_value(&authorize)?,
                DigestSuite::Sha256,
            )?,
        };
        let version = inception.log_entry["versionId"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("principal inception version missing"))?
            .to_owned();
        let mut create = arkret_bootstrap::build_self_principal_pcr_create(
            arkret_bootstrap::SelfPrincipalPcrCreateInput {
                principal_id: principal,
                governance_station_id: authority.service_id.clone(),
                principal_did: did.clone(),
                genesis_salt: GenesisSalt::new(base64url_encode([33; 32]))?,
                trust_domain: TrustDomainId::new("ak:trust_domain:server.local")?,
                did_inception_ref: SemanticRef::new(
                    version.clone(),
                    arkret_bootstrap::DID_INCEPTION_REF_ROLE,
                ),
                initial_resolution: ResolutionCommitment {
                    did: did.clone(),
                    method_history_head: version.clone(),
                    version_id: version.clone(),
                },
                founding_device_descriptor: descriptor,
                initial_join_rule: JoinRule::Closed,
                initial_history_access: HistoryAccess::SinceJoin,
                initial_discoverability: Discoverability::Secret,
                created_at: at(0),
            },
        )?;
        let root = Ed25519PayloadSigner::from_did_key_seed(
            seed,
            Did::new(format!("did:key:{multibase}"))?,
            DidUrl::new(format!("did:key:{multibase}#{multibase}")).map_err(anyhow::Error::msg)?,
        );
        arkret_sdk::signatures::sign_event(
            &mut create,
            &root,
            arkret_sdk::signatures::SignEventOptions::new().with_created_at(at(0)),
        )?;
        let source_create = commit(&authority, &create, 0, None, create.event_id.clone(), None)?;
        let mut authorization = TypedEventDraft::<event_spec::DeviceAuthorize>::new(
            ScopeRef::Realm {
                realm_id: create.realm_id.clone(),
            },
            actor.clone(),
            authorize,
        )?
        .author_with_digest_suite(at(1), DigestSuite::Sha256)?;
        arkret_sdk::signatures::sign_event(
            &mut authorization,
            &signer,
            arkret_sdk::signatures::SignEventOptions::new().with_created_at(at(1)),
        )?;
        arkret_bootstrap::build_pcr_genesis_unit(
            create.into_event(),
            authorization.event().clone(),
        )?;
        let resolution = PrincipalResolutionProjection {
            did: did.clone(),
            method_history_head: version.clone(),
            version_id: version,
            resolution_event_ref: source_create.event_ref.to_string(),
            updated_at: at(0),
        };
        let source_commit = commit(
            &authority,
            &authorization,
            1,
            Some(source_create.commit_id),
            source_create.event_ref,
            None,
        )?;
        let source_authorization = CommittedEventFullView {
            commit: source_commit,
            event: authorization.into_event(),
        };
        let key = arkret_models_identity::signer_key_operations::ResolvedSignerKey {
            public_key_b64u: Base64UrlString::new(base64url_encode(
                producer_key.verifying_key().as_bytes(),
            ))
            .map_err(anyhow::Error::msg)?,
            authorization_ref: CommittedEventRef {
                event_id: source_authorization.event.event_id.clone(),
                commit_id: source_authorization.commit.commit_id.clone(),
                stream_ref: source_authorization.commit.stream_ref.clone(),
                stream_position: 1,
            },
            revision: CurrentRevision {
                commit_id: source_authorization.commit.commit_id.clone(),
                stream_position: 1,
            },
            governance_generation: 0,
        };
        key.validate()?;
        let identity = FixtureIdentity {
            did,
            account_id: actor.as_account_id().unwrap().clone(),
            principal_control_realm_id: source_authorization.event.realm_id.clone(),
            document: inception.log_entry["state"].clone(),
            inception_log_entry: inception.log_entry.clone(),
            resolution,
        };
        let mut result = Self {
            authority,
            actor,
            signer,
            key,
            source_authorization,
            identity,
            events: vec![],
            facts: vec![],
            rows: vec![],
            ids: BTreeMap::new(),
            public_blobs: BTreeMap::new(),
            managed_agent: None,
        };
        result.managed_agent = Some(result.build_managed_agent()?);
        Ok(result)
    }

    fn source_commit(
        &self,
        event: Event,
        position: u64,
        previous: Option<RealmCommitId>,
        genesis: EventId,
    ) -> Result<CommittedEventFullView> {
        event.verify_event_id_matches_content_with_digest_suite(DigestSuite::Sha256)?;
        ensure!(
            event.actual_signer() == &self.actor,
            "managed source must be executed by its real controller"
        );
        arkret_sdk::validate_event_payload(&event.kind, &serde_json::to_value(&event.payload)?)?;
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("managed source proof missing"))?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &canonical::canonical_json_bytes(&event.digest_payload()?)?,
            &event.actor_id,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: base64url_decode(self.key.public_key_b64u.as_str())?,
            },
            DigestSuite::Sha256,
        )?;
        let fact = arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact {
            event_id: event.event_id.clone(),
            actor: self.actor.clone(),
            device_id: self.source_authorization.event.payload["device_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("controller device missing"))?
                .parse()?,
            verification_method: proof.verification_method.clone(),
            key: self.key.clone(),
            accepted_at: event.created_at,
        };
        fact.validate_event_binding(&event, DigestSuite::Sha256)?;
        let accepted = commit(
            &self.authority,
            &event,
            position,
            previous,
            genesis,
            Some(fact.digest()?),
        )?;
        let full = CommittedEventFullView {
            event,
            commit: accepted,
        };
        fact.validate_commit_binding(&full, DigestSuite::Sha256)?;
        Ok(full)
    }

    fn build_managed_agent(&self) -> Result<ManagedAgentFixture> {
        use arkret_identity::DidResolver as _;
        use arkret_models_collaboration::agent_operations::{
            AgentPairingBootstrap, AgentPairingRuntimeIdentity,
        };
        use arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest;
        use arkret_models_identity::handle::HandleVisibility;
        use arkret_signatures::webvh::{
            AgentBindingUpdateInput, AgentInceptionInput, prepare_agent_binding_update,
            prepare_agent_inception,
        };
        let controller = self
            .actor
            .as_account_id()
            .ok_or_else(|| anyhow::anyhow!("controller Account missing"))?;
        let time = |seconds| at(0) + chrono::Duration::seconds(seconds);
        let next = ed25519_pubkey_to_did_key_multibase(
            &ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                .verifying_key()
                .to_bytes(),
        );
        let successor = ed25519_pubkey_to_did_key_multibase(
            &ed25519_dalek::SigningKey::from_bytes(&[43; 32])
                .verifying_key()
                .to_bytes(),
        );
        let endpoint = url::Url::parse("https://agents.example/")?;
        let inception = prepare_agent_inception(&AgentInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "assistant",
            controller_principal_id: &controller.principal_id,
            version_time: time(2),
            root_seed: &[41; 32],
            next_root_public_key_multibase: &next,
        })?;
        let did = Did::new(inception.did.clone())?;
        let agent_id = project_did_to_core_id(&did)?;
        let account_id = AccountId::new(agent_id.clone(), controller.station_id.clone());
        let delegation =
            DidUrl::new(format!("{did}#managed-controller")).map_err(anyhow::Error::msg)?;
        let requested_scope: AgentKeyScope = serde_json::from_value(json!({
            "actions":["ak.event.read"], "resources":[{"kind":"operation","operation":"ak.self.committed_event.read.scan.v1"}]
        }))?;
        let digest = arkret_models_collaboration::agent_scope::agent_requested_scope_digest(
            &agent_id,
            &controller.principal_id,
            &requested_scope,
        )?;
        let create =
            arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
                payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                    agent_id: agent_id.clone(),
                    governance_station_id: controller.station_id.clone(),
                    initial_resolution: arkret_models_identity::ResolutionCommitment {
                        did: did.clone(),
                        method_history_head: inception.version_id.clone(),
                        version_id: inception.version_id.clone(),
                    },
                    genesis_salt: GenesisSalt::new(base64url_encode([34; 32]))?,
                    trust_domain: TrustDomainId::new("ak:trust_domain:server.local")?,
                    initial_join_rule: JoinRule::Closed,
                    initial_history_access: HistoryAccess::SinceJoin,
                    initial_discoverability: Discoverability::Secret,
                },
                executed_by: self.actor.clone(),
                authorization_ref: AuthorizationRef::new(delegation.as_str())
                    .map_err(anyhow::Error::msg)?,
                created_at: time(3),
            })?;
        let sign = |mut authored: AuthoredEvent| -> Result<Event> {
            let created_at = authored.created_at;
            arkret_sdk::signatures::sign_event(
                &mut authored,
                &self.signer,
                arkret_sdk::signatures::SignEventOptions::new().with_created_at(created_at),
            )?;
            Ok(authored.into_event())
        };
        let genesis_event = sign(create)?;
        let pcr = genesis_event.realm_id.clone();
        let provision_event = sign(arkret_bootstrap::build_agent_provision_intent(
            &controller.principal_id,
            &self.identity.principal_control_realm_id,
            &agent_id,
            &pcr,
            &delegation,
            "assistant",
            &digest,
            HandleVisibility::Private,
            None,
            arkret_bootstrap::AgentProvisionIntentOptions {
                controller_station_id: controller.station_id.clone(),
                created_at: time(3),
            },
        )?)?;
        let source_genesis = match &self.source_authorization.commit.authority_ref {
            RealmCommitAuthorityRef::GenesisOrChangeEvent(event) => event.clone(),
            _ => bail!("fixture controller source unexpectedly uses authority handoff"),
        };
        let provision = self.source_commit(
            provision_event,
            2,
            Some(self.source_authorization.commit.commit_id.clone()),
            source_genesis,
        )?;
        let genesis = self.source_commit(
            genesis_event.clone(),
            0,
            None,
            genesis_event.event_id.clone(),
        )?;
        let binding = prepare_agent_binding_update(&AgentBindingUpdateInput {
            did: did.as_str(),
            local_id: &inception.local_id,
            previous_entries: std::slice::from_ref(&inception.log_entry),
            version_time: time(4),
            current_root_seed: &[42; 32],
            next_root_public_key_multibase: &successor,
            controller_principal_id: &controller.principal_id,
            principal_control_realm_id: &pcr,
            requested_scope_digest: &digest,
        })?;
        let mut resolver = arkret_identity::DidWebvhResolver::new();
        resolver.insert_from_https_response(
            &did,
            arkret_identity::DidWebvhDocumentOutcome {
                url: arkret_identity::DidWebvhResolver::document_url(&did)?,
                content_type: "application/json".into(),
                body: serde_json::to_vec(&binding.log_entry["state"])?,
            },
        )?;
        let mut log = serde_json::to_vec(&inception.log_entry)?;
        log.push(b'\n');
        log.extend(serde_json::to_vec(&binding.log_entry)?);
        resolver.ingest_log(
            &did,
            arkret_identity::DidWebvhLogOutcome {
                url: arkret_identity::DidWebvhResolver::log_url(&did)?,
                content_type: "application/jsonl".into(),
                body: log,
            },
        )?;
        resolver.resolve_did(&did)?;
        let method = DidUrl::new(format!("{did}#runtime-key-1")).map_err(anyhow::Error::msg)?;
        let pairing_id =
            OpaqueLocalId::new("fixture-assistant-pairing").map_err(anyhow::Error::msg)?;
        let approval_id =
            OpaqueLocalId::new("fixture-assistant-approval").map_err(anyhow::Error::msg)?;
        let expires_at = time(65);
        let bootstrap = AgentPairingBootstrap {
            arkret_base_url: "https://server.local".into(),
            service_id: controller.station_id.clone(),
            agent_id: agent_id.clone(),
            pairing_request_id: pairing_id.clone(),
            pairing_code: "12345678".into(),
            pairing_expires_at: expires_at,
            runtime_identity: Some(AgentPairingRuntimeIdentity {
                controller_account_id: controller.clone(),
                verification_method: method.clone(),
            }),
        };
        let runtime_key = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
        let candidate =
            arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
                &runtime_key,
                bootstrap,
                &method,
            )
            .proof_created_at(time(5))
            .proof_expires_at(time(60))
            .build_approval_request()?
            .body;
        let runtime_digest = agent_runtime_key_binding_digest(
            &agent_id,
            &pairing_id,
            &method,
            &candidate.public_key,
            None,
        )?;
        let transcript = candidate.proof_of_possession.validate_shape(
            &agent_id,
            &pairing_id,
            &method,
            &candidate.public_key,
            &runtime_digest,
            "12345678",
            expires_at,
            time(5),
        )?;
        ensure!(
            arkret_signatures::verify_detached_ed25519_signature(
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: runtime_key.verifying_key().to_bytes().to_vec()
                },
                &transcript,
                candidate.proof_of_possession.signature.as_str()
            ),
            "runtime candidate possession signature is invalid"
        );
        let approval_digest = arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
            ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1, &controller.principal_id, &agent_id, &pairing_id, &approval_id,
            expires_at, &controller.station_id, &runtime_digest)?;
        let authorize_payload = AgentKeyAuthorizePayload {
            agent_id: agent_id.clone(),
            key_id: NonEmptyString::new(method.as_str()).map_err(anyhow::Error::msg)?,
            verification_method: method,
            public_key: candidate.public_key,
            accountable_principal_id: controller.principal_id.clone(),
            agent_key_scope: requested_scope.clone(),
            audience: vec![controller.station_id.to_string()],
            issued_at: time(5),
            expires_at: None,
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::PairingRequest,
                evidence_ref: None,
                request_canonical_digest: Some(approval_digest),
                pairing_request_id: Some(pairing_id),
                approved_by: Some(controller.principal_id.clone()),
            },
            supersedes: vec![],
            revocation_check_ref: None,
            runtime_attestation: None,
        };
        let authorize = arkret_event_draft::build_agent_key_authorize_intent(
            &authorize_payload,
            ScopeRef::Realm {
                realm_id: pcr.clone(),
            },
            ActorId::account(account_id.clone()),
            self.actor.clone(),
            delegation.clone(),
            time(5),
        )?
        .author_with_digest_suite(DigestSuite::Sha256)?;
        let runtime_authorization = self.source_commit(
            sign(authorize)?,
            1,
            Some(genesis.commit.commit_id.clone()),
            genesis.event.event_id.clone(),
        )?;
        Ok(ManagedAgentFixture {
            did,
            account_id,
            principal_control_realm_id: pcr,
            inception_log_entry: inception.log_entry.clone(),
            binding_log_entry: binding.log_entry.clone(),
            provision,
            genesis,
            runtime_authorization,
            runtime_proof: candidate.proof_of_possession,
            requested_scope,
            controller_authorization_ref: delegation,
        })
    }

    fn validate_mls_genesis(&self, payload: &MlsGenesisPayload) -> Result<()> {
        payload.validate()?;
        ensure!(
            payload.creator_leaf_authority.authorization_event_ref
                == self.source_authorization.event.event_id,
            "MLS creator authorization differs from the fixture device source"
        );
        let device: DeviceId = self.source_authorization.event.payload["device_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("fixture source device missing"))?
            .parse()?;
        ensure!(
            payload.creator_leaf_authority.endpoint
                == MlsWelcomeRecipientEndpoint::Device { device_id: device },
            "MLS creator endpoint differs from the fixture device"
        );
        let bytes = |reference: &BlobRef| -> Result<Vec<u8>> {
            let encoded = self
                .public_blobs
                .get(reference.as_str())
                .ok_or_else(|| anyhow::anyhow!("MLS public material missing"))?;
            let bytes = base64url_decode(encoded.as_str())?;
            ensure!(
                format!("ak:blob:{}", canonical::sha256_digest(&bytes)) == reference.as_str(),
                "MLS public material content address differs"
            );
            Ok(bytes)
        };
        let tracker = MlsPublicGroupTracker::from_external(
            &bytes(&payload.group_info_ref)?,
            &bytes(&payload.ratchet_tree_ref)?,
            payload.mls_group_id()?.as_str(),
            0,
        )?;
        ensure!(
            tracker.governance_binding()? == payload.governance_binding,
            "MLS public group governance binding differs from Genesis"
        );
        ensure!(
            tracker.ciphersuite_canonical_id()? == payload.cipher_suite.as_str(),
            "MLS public group suite differs from Genesis"
        );
        let leaves = tracker.leaves()?;
        ensure!(
            leaves.len() == 1
                && leaves[0].leaf_index == 0
                && leaves[0].actor_id == self.actor
                && leaves[0].signature_key
                    == payload.creator_leaf_authority.leaf_signature_key_b64u
                && leaves[0].signature_key == self.key.public_key_b64u,
            "MLS Genesis creator leaf differs from the authorized fixture actor/key"
        );
        Ok(())
    }

    fn append(&mut self, mut authored: AuthoredEvent) -> Result<Event> {
        let accepted_at = authored.created_at;
        arkret_sdk::signatures::sign_event(
            &mut authored,
            &self.signer,
            arkret_sdk::signatures::SignEventOptions::new().with_created_at(accepted_at),
        )?;
        self.append_signed(authored.into_event())
    }

    fn append_signed(&mut self, event: Event) -> Result<Event> {
        let accepted_at = event.created_at;
        ensure!(
            event.actor_id == self.actor,
            "fixture Event belongs to another Account actor"
        );
        event.verify_event_id_matches_content_with_digest_suite(DigestSuite::Sha256)?;
        arkret_sdk::validate_event_payload(&event.kind, &serde_json::to_value(&event.payload)?)?;
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fixture Event omits its producer proof"))?;
        let fact = arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact {
            event_id: event.event_id.clone(),
            actor: event.actor_id.clone(),
            device_id: self.source_authorization.event.payload["device_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("authorization device missing"))?
                .parse()?,
            verification_method: proof.verification_method.clone(),
            key: self.key.clone(),
            accepted_at,
        };
        fact.validate_event_binding(&event, DigestSuite::Sha256)?;
        let predecessor = self.events.last().map(|view| view.commit.commit_id.clone());
        let genesis = self
            .events
            .first()
            .map(|view| view.event.event_id.clone())
            .unwrap_or_else(|| event.event_id.clone());
        let accepted = commit(
            &self.authority,
            &event,
            self.events.len() as u64,
            predecessor,
            genesis,
            Some(fact.digest()?),
        )?;
        let full = CommittedEventFullView {
            commit: accepted,
            event: event.clone(),
        };
        fact.validate_commit_binding(&full, DigestSuite::Sha256)?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &arkret_sdk::canonical::canonical_json_bytes(&event.digest_payload()?)?,
            &event.actor_id,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: self.signer.verifying_key().to_bytes().to_vec(),
            },
            DigestSuite::Sha256,
        )?;
        self.project(&full)?;
        self.events.push(full);
        self.facts.push(fact);
        Ok(event)
    }

    fn row<T: Serialize>(
        &mut self,
        full: &CommittedEventFullView,
        selector: CurrentSelector,
        value: T,
    ) -> Result<()> {
        self.rows.retain(
            |row| !matches!(row, TypedCurrentRow::Value { selector: old, .. } if old == &selector),
        );
        self.rows.push(TypedCurrentRow::Value {
            selector,
            source_stream_ref: full.commit.stream_ref.clone(),
            revision: CurrentRevision {
                commit_id: full.commit.commit_id.clone(),
                stream_position: full.commit.stream_position,
            },
            value: serde_json::to_value(value)?,
        });
        Ok(())
    }

    fn project(&mut self, full: &CommittedEventFullView) -> Result<()> {
        let payload = serde_json::to_value(&full.event.payload)?;
        match full.event.kind {
            EventKind::RealmCreate => {
                let payload: RealmCreatePayload = serde_json::from_value(payload)?;
                self.row(full, CurrentSelector::RealmGenesis, payload.object)?;
                self.row(
                    full,
                    CurrentSelector::RealmAuthorityRoot,
                    arkret_wire::RealmAuthorityRootValue {
                        controller_actor_id: full.event.actor_id.clone(),
                        controller_epoch: 0,
                        authority_generation: 0,
                        authority_event_ref: full.event.event_id.clone(),
                    },
                )?;
            }
            EventKind::RealmProfile => self.row(
                full,
                CurrentSelector::RealmProfile,
                serde_json::from_value::<RealmProfile>(payload)?,
            )?,
            EventKind::RealmPolicyBundle => self.row(
                full,
                CurrentSelector::RealmPolicyBundle,
                serde_json::from_value::<RealmPolicyBundlePayload>(payload)?,
            )?,
            EventKind::RealmJoinRule => {
                let payload: RealmJoinRulePayload = serde_json::from_value(payload)?;
                self.row(full, CurrentSelector::RealmJoinRule, payload.value)?;
            }
            EventKind::RealmHistoryAccess => {
                let payload: HistoryAccessPayload = serde_json::from_value(payload)?;
                self.row(full, CurrentSelector::RealmHistoryAccess, payload.to)?;
            }
            EventKind::RealmDiscovery => {
                let payload: RealmDiscoveryPayload = serde_json::from_value(payload)?;
                self.row(full, CurrentSelector::RealmDiscovery, payload.value)?;
            }
            EventKind::MemberState => {
                let payload: MembershipPayload = serde_json::from_value(payload)?;
                if let Some(binding) = &payload.agent_controller_binding {
                    let controller_actor = serde_json::to_value(&self.actor)?;
                    let agent = self
                        .managed_agent
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Agent membership source missing"))?;
                    ensure!(
                        payload.member_id == ActorId::account(agent.account_id.clone())
                            && binding.controller_account_id == self.identity.account_id
                            && binding.controller_terminal_event_ref.is_none()
                            && full.event.created_at
                                >= agent.runtime_authorization.commit.committed_at
                            && self.events.iter().any(|row| row.event.kind
                                == EventKind::MemberState
                                && row.event.event_id
                                    == binding.controller_membership_generation_ref
                                && row.event.payload.get("member_id") == Some(&controller_actor)
                                && row.event.payload.get("membership").and_then(Value::as_str)
                                    == Some("join")),
                        "Agent membership lacks its exact current controller and accepted managed source"
                    );
                }
                self.row(
                    full,
                    CurrentSelector::MemberState {
                        actor_id: payload.member_id,
                    },
                    arkret_wire::MemberStateCurrent {
                        membership: serde_json::from_value(serde_json::to_value(
                            payload.membership,
                        )?)?,
                        joined_at: Some(full.event.created_at),
                    },
                )?;
            }
            EventKind::MlsGenesis => {
                let payload: MlsGenesisPayload = serde_json::from_value(payload)?;
                self.validate_mls_genesis(&payload)?;
                ensure!(
                    !self
                        .events
                        .iter()
                        .any(|row| row.event.kind == EventKind::MlsGenesis),
                    "fixture scope already has MLS Genesis"
                );
                self.row(
                    full,
                    CurrentSelector::MlsGroup {
                        scope_ref: payload.effective_scope().clone(),
                    },
                    arkret_wire::MlsGroupCurrent {
                        effective_scope: payload.effective_scope().clone(),
                        genesis_event_ref: full.event.event_id.clone(),
                        cipher_suite: payload.cipher_suite,
                        current_mls_commit_event_ref: full.event.event_id.clone(),
                        epoch: 0,
                        current_key_access_revision: 0,
                        covered_key_access_revision: 0,
                        public_tree_ref: payload.ratchet_tree_ref,
                    },
                )?;
            }
            EventKind::SpaceCreate => {
                let payload: SpaceCreatePayload = serde_json::from_value(payload)?;
                let mut space = payload.object;
                let id = SpaceId::from_event_id(&full.event.event_id);
                let parent = space.parent_space_id.take();
                let policy = space.child_scope_policy.take();
                space.id = Some(id.clone());
                self.row(
                    full,
                    CurrentSelector::Space {
                        space_id: id.clone(),
                    },
                    space,
                )?;
                self.row(
                    full,
                    CurrentSelector::SpaceParent {
                        space_id: id.clone(),
                    },
                    json!({"parent_space_id": parent}),
                )?;
                self.row(
                    full,
                    CurrentSelector::SpaceChildScopePolicy { space_id: id },
                    policy,
                )?;
            }
            EventKind::StrandCreate => {
                let payload: StrandCreatePayload = serde_json::from_value(payload)?;
                let mut strand = payload.object;
                let id = StrandId::from_event_id(&full.event.event_id);
                strand.id = Some(id.clone());
                self.row(full, CurrentSelector::Strand { strand_id: id }, strand)?;
            }
            EventKind::StrandMove => {
                let payload: StrandMovePayload = serde_json::from_value(payload)?;
                self.row(
                    full,
                    CurrentSelector::StrandPosition {
                        board_space_id: payload.board_space_id,
                        strand_id: payload.strand_id,
                    },
                    Some(
                        arkret_models_collaboration::objects::strand::StrandPositionCurrent {
                            list_space_id: payload.target_space_id,
                            rank: payload.rank,
                        },
                    ),
                )?;
            }
            EventKind::RealmSetDefaultStrand => {
                let payload: RealmSetDefaultStrandPayload = serde_json::from_value(payload)?;
                self.row(
                    full,
                    CurrentSelector::RealmSetDefaultStrand,
                    json!({"default_strand_id": payload.strand_id}),
                )?;
            }
            EventKind::InviteCreate => {
                use arkret_models_collaboration::governance::membership_invite::{
                    InviteCreatePayload, InviteDirectedInviteeValue, InviteLiveTargetOccupant,
                };
                let payload: InviteCreatePayload = serde_json::from_value(payload)?;
                let invite_id = InviteId::from_event_id(&full.event.event_id);
                self.row(
                    full,
                    CurrentSelector::InviteLifecycle {
                        invite_id: invite_id.clone(),
                    },
                    InviteState::Pending,
                )?;
                self.row(
                    full,
                    CurrentSelector::InviteDirectedInvitee { invite_id },
                    InviteDirectedInviteeValue {
                        invitee_account_id: payload.invitee_account_id.clone(),
                    },
                )?;
                self.row(
                    full,
                    CurrentSelector::InviteLiveTarget {
                        invitee_account_id: payload.invitee_account_id,
                    },
                    Some(InviteLiveTargetOccupant {
                        create_event_id: full.event.event_id.clone(),
                    }),
                )?;
            }
            EventKind::RealmArchive | EventKind::RealmRestore => {
                // The registered lifecycle current value is the closed archived
                // boolean object; this bounded projection has no raw-row input.
                self.row(
                    full,
                    CurrentSelector::RealmArchive,
                    json!({ "archived": full.event.kind == EventKind::RealmArchive }),
                )?;
            }
            _ => bail!(
                "fixture cannot project unregistered fixture kind {}",
                full.event.kind
            ),
        }
        Ok(())
    }

    fn author<K: EventSpec>(&mut self, realm: &RealmId, payload: K::Payload) -> Result<Event> {
        let authored = TypedEventDraft::<K>::new(
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            self.actor.clone(),
            payload,
        )?
        .author_with_digest_suite(at(self.events.len() + 10), DigestSuite::Sha256)?;
        self.append(authored)
    }

    fn finish(self) -> Result<Fixture> {
        let last = self
            .events
            .last()
            .ok_or_else(|| anyhow::anyhow!("fixture cannot be empty"))?;
        let mut snapshot = RealmStateSnapshot {
            snapshot_id: RealmSnapshotId::from_digest([0; 32]),
            realm_id: last.event.realm_id.clone(),
            governance_generation: 0,
            visible_stream_heads: vec![CommitStreamHead {
                stream_ref: last.commit.stream_ref.clone(),
                stream_position: last.commit.stream_position,
                commit_id: last.commit.commit_id.clone(),
            }],
            current_state_entries: self.rows,
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: self
                    .events
                    .iter()
                    .rev()
                    .find(|full| full.event.kind == EventKind::RealmHistoryAccess)
                    .map(|full| {
                        serde_json::to_value(&full.event.payload)
                            .and_then(serde_json::from_value::<HistoryAccessPayload>)
                            .map(|payload| payload.to)
                    })
                    .transpose()?
                    .unwrap_or(HistoryAccess::AllHistoryForCurrentMembers),
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref: last.commit.stream_ref.clone(),
                    oldest_position: 0,
                }],
            },
            created_at: last.event.created_at,
            signature: arkret_signatures::detached_object::sign_detached_object(
                &json!({}),
                arkret_wire::DetachedSignatureContext::RealmSnapshot,
                self.authority.verification_method.clone(),
                last.event.created_at,
                &self.authority.signing_key,
            )?,
        };
        snapshot.snapshot_id = RealmSnapshotId::from_digest(arkret_sdk::canonical::sha256_bytes(
            &arkret_sdk::canonical::canonical_json_bytes(&unsigned(
                &snapshot,
                &["snapshot_id", "signature"],
            )?)?,
        ));
        snapshot.signature = arkret_signatures::detached_object::sign_detached_object(
            &unsigned(&snapshot, &["signature"])?,
            arkret_wire::DetachedSignatureContext::RealmSnapshot,
            self.authority.verification_method.clone(),
            snapshot.created_at,
            &self.authority.signing_key,
        )?;
        arkret_signatures::detached_object::verify_detached_object_signature(
            &snapshot.signature,
            &unsigned(&snapshot, &["signature"])?,
            arkret_wire::DetachedSignatureContext::RealmSnapshot,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: self
                    .authority
                    .signing_key
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
        )?;
        use arkret_state::AuthorityCommitStore as _;
        let store = arkret_state::MemoryAuthorityCommitStore::default();
        for full in &self.events {
            store.append(&full.event, full.commit.clone())?;
        }
        use arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry;
        use arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow;
        let current = AccountCurrentView {
            realm_id: snapshot.realm_id.clone(),
            governance_generation: snapshot.governance_generation,
            stream_heads: snapshot.visible_stream_heads.clone(),
            entries: snapshot.current_state_entries.clone(),
        };
        current.validate()?;
        // Garth stages shape/cut validation only here. Content IDs and real
        // signatures above are independent checks; live authentication occurs
        // when the browser consumes these through its bound own-Station client.
        garth::replica::RealmReplica::new(snapshot.realm_id.clone())
            .install_snapshot(snapshot.clone())?;
        ensure!(
            snapshot.snapshot_id
                == RealmSnapshotId::from_digest(arkret_sdk::canonical::sha256_bytes(
                    &arkret_sdk::canonical::canonical_json_bytes(&unsigned(
                        &snapshot,
                        &["snapshot_id", "signature"]
                    )?)?
                )),
            "snapshot content ID mismatch"
        );
        let account_entry = RealmSyncEntry {
            streams: Some(
                snapshot
                    .visible_stream_heads
                    .iter()
                    .map(|head| RealmStreamWindow {
                        stream_ref: head.stream_ref.clone(),
                        head_commit_ref: head.commit_id.clone(),
                        next_position: head.stream_position + 1,
                        limited: false,
                        window_limit: 100,
                        complete: true,
                        preview_only: None,
                        window_start_basis: None,
                        e2ee_epoch: None,
                    })
                    .collect(),
            ),
            current: Some(current),
            committed_events: Some(
                self.events
                    .iter()
                    .cloned()
                    .map(CommittedEventView::Full)
                    .collect(),
            ),
            ..Default::default()
        };
        Ok(Fixture {
            snapshot,
            committed_events: self.events,
            signer_facts: self.facts,
            source_authorization: self.source_authorization,
            identity: self.identity,
            account_entry,
            ids: self.ids,
            public_blobs: self.public_blobs,
            managed_agent: self
                .managed_agent
                .ok_or_else(|| anyhow::anyhow!("managed Agent source missing"))?,
        })
    }
}

pub(super) fn build(input: Value) -> Result<Value> {
    let input: BuildInput = serde_json::from_value(input)?;
    ensure!(
        [9, 10, 11, 12, 13].contains(&input.salt),
        "fixture salt is not registered"
    );
    let mut builder = Builder::new(&input)?;
    inkson::operation::set_authoring_station_id(Some(builder.authority.service_id.clone()));
    let did = builder.identity.did.to_string();
    let create = inkson::event_builders::build_realm_create_event(
        GenesisSalt::new(base64url_encode([input.salt; 32]))?,
        &did,
        "listed",
        "invite",
        if input.encrypted {
            "since_join"
        } else {
            "all_history_for_current_members"
        },
        "standard",
        "ak:trust_domain:server.local",
    )?
    .into_intent()
    .with_created_at(at(10))
    .author_with_digest_suite(DigestSuite::Sha256)?;
    let genesis = builder.append(create)?;
    let realm = genesis.realm_id.clone();
    let facets = inkson::event_builders::RealmBootstrapFacets {
        station_id: builder.authority.service_id.clone(),
        actor_id: did,
        notary_did: String::new(),
        notary_service_origin: "https://server.local".to_owned(),
        title: input.title,
        summary: Some(
            match input.salt {
                9 => "Shared demo Realm served by mocked server",
                11 => "Board and discussion scope",
                12 => "Related scope fixture",
                13 => "Mocks the live first-account PCR floor advisory condition",
                _ => "SDK typed fixture Realm",
            }
            .to_owned(),
        ),
        discoverability: "listed".to_owned(),
        join_rule: "invite".to_owned(),
        history_access: if input.encrypted {
            "since_join"
        } else {
            "all_history_for_current_members"
        }
        .to_owned(),
        federation_policy: "open".to_owned(),
        alias: None,
        plaintext_visible_services: vec![],
    };
    for intent in inkson::event_builders::build_realm_bootstrap_facet_intents(
        &facets,
        realm.as_str(),
        DigestSuite::Sha256,
    )? {
        builder.append(
            intent
                .with_created_at(at(builder.events.len() + 10))
                .author_with_digest_suite(DigestSuite::Sha256)?,
        )?;
    }
    let member =
        inkson::event_builders::build_realm_bootstrap_membership_intent(&facets, realm.as_str())?;
    builder.append(
        member
            .with_created_at(at(builder.events.len() + 10))
            .author_with_digest_suite(DigestSuite::Sha256)?,
    )?;
    // The creator's join and position zero belong to this registered atomic
    // unit, so since_join uses the stream-start floor (history-visibility 3.1).
    arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission {
        unit_kind: arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
        idempotency_key: serde_json::from_value::<UuidV7>(json!("01904100-0000-7000-8000-000000000009"))?,
        events: builder.events.iter().map(|full| EventAdmissionSubmission::new(full.event.clone())).collect(),
    }.validate()?;
    if input.board && !input.empty_board {
        let mut spaces: Vec<SpaceId> = Vec::new();
        for (key, title, kind, parent, rank) in [
            ("board", "Persisted demo board", "board", None, "U"),
            (
                "second_board",
                "Secondary planning board",
                "board",
                None,
                "V",
            ),
            ("todo", "To Do", "list", Some(0), "U"),
            ("progress", "In Progress", "list", Some(0), "f"),
            ("done", "Done", "list", Some(0), "p"),
            ("second_list", "Selected Backlog", "list", Some(1), "U"),
        ] {
            let mut space = Space::create_object(realm.clone(), kind, title, builder.actor.clone());
            space.created_at = at(builder.events.len() + 10);
            space.state = Some(SpaceState::Active);
            space.rank = Some(rank.to_owned());
            space.parent_space_id = parent.map(|index| spaces[index].clone());
            let event = builder
                .author::<event_spec::SpaceCreate>(&realm, SpaceCreatePayload::new(space))?;
            let id = SpaceId::from_event_id(&event.event_id);
            builder.ids.insert(key.to_owned(), id.to_string());
            spaces.push(id);
        }
        for (index, key, title, board, list, rank) in [
            (0, "review", "Legal review for public beta", 0, 2, "U"),
            (1, "scope", "Onboarding copy", 0, 3, "U"),
            (2, "security", "Security sign-off", 0, 4, "U"),
            (3, "secondary", "Secondary board card", 1, 5, "U"),
        ] {
            let mut strand = Strand::new_create(realm.clone(), title, builder.actor.clone());
            strand.created_at = at(builder.events.len() + 10);
            strand.state = Some(ObjectState::Active);
            strand.tracks = serde_json::from_value(json!({"discussion":{}}))?;
            if let Some(metadata) = strand.metadata.as_mut() {
                metadata
                    .fields
                    .insert("strand_kind".to_owned(), json!("card"));
                metadata.summary = Some(
                    [
                        "Finalize external processor wording before launch checklist can move.",
                        "Waiting on discussion-scoped feedback from support and docs reviewers.",
                        "Projection detected a stale column head after an offline move.",
                        "Only visible after the Board selector switches projection scope.",
                    ][index]
                        .to_owned(),
                );
                metadata.fields.insert(
                    "labels".to_owned(),
                    [
                        json!(["legal", "beta"]),
                        json!(["copy", "support"]),
                        json!(["security", "reviewed"]),
                        json!(["planning"]),
                    ][index]
                        .clone(),
                );
                metadata.fields.insert(
                    "due_at".to_owned(),
                    json!(["May 08", "May 10", "May 01", "May 12"][index]),
                );
                if index == 0 {
                    metadata
                        .fields
                        .insert("discussion_visibility".to_owned(), json!("locked"));
                    metadata.fields.insert("locked_reason".to_owned(), json!("You can see that a restricted discussion is linked, but not its name or members."));
                }
            }
            let event = builder.author::<event_spec::StrandCreate>(
                &realm,
                StrandCreatePayload { object: strand },
            )?;
            let id = StrandId::from_event_id(&event.event_id);
            builder.ids.insert(key.to_owned(), id.to_string());
            builder.author::<event_spec::StrandMove>(
                &realm,
                StrandMovePayload::new(
                    spaces[board].clone(),
                    id.clone(),
                    spaces[list].clone(),
                    rank,
                ),
            )?;
            if index == 0 {
                builder.author::<event_spec::RealmSetDefaultStrand>(
                    &realm,
                    RealmSetDefaultStrandPayload::new(realm.clone(), id),
                )?;
            }
        }
    }
    let agent = builder
        .managed_agent
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("managed Agent source missing"))?
        .clone();
    let controller_join = builder
        .events
        .iter()
        .find(|full| full.event.kind == EventKind::MemberState)
        .ok_or_else(|| anyhow::anyhow!("creator membership missing"))?
        .event
        .event_id
        .clone();
    let mut agent_join =
        arkret_models_collaboration::governance::membership_invite::MembershipPayload::join(
            realm.clone(),
            ActorId::account(agent.account_id.clone()),
            "Controller joins its provisioned Assistant",
        );
    agent_join.agent_controller_binding = Some(arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding {
        controller_account_id: builder.identity.account_id.clone(), controller_membership_generation_ref: controller_join,
        controller_terminal_event_ref: None,
    });
    let joined = TypedEventDraft::<event_spec::MemberState>::new(
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        builder.actor.clone(),
        agent_join,
    )?
    .author_with_digest_suite(at(0) + chrono::Duration::seconds(6), DigestSuite::Sha256)?;
    builder.append(joined)?;
    if input.encrypted {
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
        let seed: [u8; 32] = base64url_decode(&input.seed_b64url)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("MLS signer seed must contain 32 bytes"))?;
        let device: DeviceId = input.device_id.parse()?;
        let identity = ArkretMlsIdentity::new_human_device(
            builder.actor.clone(),
            device.clone(),
            ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(&seed)),
        )?;
        let mut group = identity.create_group_with_governance_binding(&scope, &binding)?;
        group.install_local_creator_binding(
            builder.actor.clone(),
            Some(builder.source_authorization.event.event_id.clone()),
        )?;
        let leaves = group.verified_leaf_bindings()?;
        ensure!(
            leaves.len() == 1 && leaves[0].leaf_index == 0 && leaves[0].actor_id == builder.actor,
            "MLS fixture must have one actual creator leaf"
        );
        let (info, tree) = group.public_group_state_bytes()?;
        let mut save_blob = |bytes: Vec<u8>| -> Result<BlobRef> {
            let reference = BlobRef::new(format!("ak:blob:{}", canonical::sha256_digest(&bytes)))?;
            builder.public_blobs.insert(
                reference.to_string(),
                Base64UrlString::new(base64url_encode(bytes)).map_err(anyhow::Error::msg)?,
            );
            Ok(reference)
        };
        let info_ref = save_blob(info)?;
        let tree_ref = save_blob(tree)?;
        let created_at = canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let payload = MlsGenesisPayload {
            cipher_suite: NonEmptyString::new("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
                .map_err(anyhow::Error::msg)?,
            group_info_ref: info_ref,
            ratchet_tree_ref: tree_ref,
            creator_leaf_authority: MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_b64u: leaves[0].signature_key.clone(),
                endpoint: MlsWelcomeRecipientEndpoint::Device { device_id: device },
                authorization_event_ref: builder.source_authorization.event.event_id.clone(),
            },
            governance_binding: binding,
            created_at,
        };
        let event =
            TypedEventDraft::<event_spec::MlsGenesis>::new(scope, builder.actor.clone(), payload)?
                .author_with_digest_suite(created_at, DigestSuite::Sha256)?;
        builder.append(event)?;
    }
    serde_json::to_value(builder.finish()?).map_err(Into::into)
}

fn validate_fixture(fixture: &Fixture) -> Result<Fixture> {
    let mut expected_blobs = BTreeSet::new();
    for full in &fixture.committed_events {
        if full.event.kind == EventKind::MlsGenesis {
            let payload: MlsGenesisPayload =
                serde_json::from_value(serde_json::to_value(&full.event.payload)?)?;
            expected_blobs.insert(payload.group_info_ref.to_string());
            expected_blobs.insert(payload.ratchet_tree_ref.to_string());
        }
    }
    ensure!(
        fixture.public_blobs.keys().eq(expected_blobs.iter()),
        "fixture public material is missing or unreferenced"
    );
    let device_id = fixture.source_authorization.event.payload["device_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("fixture source Device authorization is absent"))?
        .to_owned();
    let configuration = BuildInput {
        salt: 9,
        title: String::new(),
        seed_b64url: default_seed(),
        device_id,
        board: false,
        empty_board: true,
        encrypted: false,
    };
    let mut builder = Builder::new(&configuration)?;
    builder.public_blobs = fixture.public_blobs.clone();
    ensure!(
        serde_json::to_value(&fixture.identity)? == serde_json::to_value(&builder.identity)?,
        "fixture principal inception or Account binding changed"
    );
    ensure!(
        fixture.source_authorization == builder.source_authorization,
        "fixture source authorization changed"
    );
    for full in &fixture.committed_events {
        builder.append_signed(full.event.clone())?;
        ensure!(
            builder.events.last().unwrap() == full,
            "fixture original Commit changed"
        );
    }
    builder.ids = fixture.ids.clone();
    let verified = builder.finish()?;
    ensure!(
        serde_json::to_value(fixture)? == serde_json::to_value(&verified)?,
        "fixture snapshot, historical facts, or current cut changed"
    );
    Ok(verified)
}

pub(super) fn verify(input: Value) -> Result<Value> {
    let fixture: Fixture = serde_json::from_value(input)?;
    validate_fixture(&fixture)?;
    Ok(json!({ "verified": true }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanInput {
    fixture: Fixture,
    request: StreamScanRequest,
}

pub(super) fn scan(input: Value) -> Result<Value> {
    let input: ScanInput = serde_json::from_value(input)?;
    let fixture = validate_fixture(&input.fixture)?;
    let request = input.request;
    request.validate()?;
    ensure!(
        request.realm_id == fixture.snapshot.realm_id,
        "scan fixture Realm mismatch"
    );
    use arkret_state::AuthorityCommitStore as _;
    let store = arkret_state::MemoryAuthorityCommitStore::default();
    for row in fixture.committed_events {
        store.append(&row.event, row.commit)?;
    }
    let outcome = store.scan(&request)?;
    outcome.validate_for_request(&request)?;
    serde_json::to_value(outcome).map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerInput {
    fixture: Fixture,
    request: arkret_models_identity::signer_key_operations::SignerKeysQueryRequestBody,
}

pub(super) fn signer_keys(input: Value) -> Result<Value> {
    use arkret_models_identity::signer_key_operations::*;
    let input: SignerInput = serde_json::from_value(input)?;
    let fixture = validate_fixture(&input.fixture)?;
    input.request.validate()?;
    ensure!(
        input.request.realm_id == fixture.snapshot.realm_id,
        "signer query fixture Realm mismatch"
    );
    ensure!(
        input.request.recipient_account_id == fixture.identity.account_id,
        "signer query fixture recipient Account mismatch"
    );
    let mut results = Vec::new();
    for selector in &input.request.queries {
        let fact = input
            .fixture
            .signer_facts
            .iter()
            .find(|fact| match selector {
                SignerKeyQuerySelector::HistoricalEvent {
                    sender:
                        HistoricalSignerKeyQuerySender::AccountDevice {
                            actor,
                            device_id,
                            verification_method,
                            committed_event_ref,
                        },
                } => {
                    fact.actor == *actor
                        && fact.device_id == *device_id
                        && fact.verification_method == *verification_method
                        && fact.event_id == committed_event_ref.event_id
                        && fixture.committed_events.iter().any(|full| {
                            committed_event_ref.matches(&CommittedEventView::Full(full.clone()))
                        })
                }
                _ => false,
            });
        results.push(match fact {
            Some(fact) => SignerKeyQueryOutcome::HistoricalResolved {
                selector: selector.clone(),
                key: fact.key.clone(),
                accepted_at: fact.accepted_at,
            },
            None => SignerKeyQueryOutcome::Unavailable {
                selector: selector.clone(),
            },
        });
    }
    let outcome = SignerKeysQueryOutcome {
        request_id: input.request.request_id.clone(),
        realm_id: input.request.realm_id.clone(),
        recipient_account_id: input.request.recipient_account_id.clone(),
        results,
    };
    outcome.validate_for_request(&input.request)?;
    serde_json::to_value(outcome).map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactCurrentInput {
    fixture: Fixture,
    request: arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody,
}

pub(super) fn exact_current(input: Value) -> Result<Value> {
    use arkret_models_collaboration::exact_current_results::{
        ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
        NeverWrittenExactCurrentSelector,
    };
    let input: ExactCurrentInput = serde_json::from_value(input)?;
    input.request.validate()?;
    let fixture = validate_fixture(&input.fixture)?;
    ensure!(
        input.request.realm_id == fixture.snapshot.realm_id,
        "exact current request belongs to another Realm"
    );
    let ExactCurrentResultSelector::AgentInteraction(selector) = &input.request.selector else {
        bail!("restricted fixture only reads its managed Agent interaction selector");
    };
    ensure!(
        selector.agent_account_id == fixture.managed_agent.account_id,
        "exact current request belongs to another Agent Account"
    );
    ensure!(
        !fixture
            .committed_events
            .iter()
            .any(|full| full.event.kind == EventKind::AgentInteractionSet),
        "fixture has an Agent interaction write; never_written is forbidden"
    );
    let stream = CommitStreamRef::Realm {
        realm_id: input.request.realm_id.clone(),
    };
    let head = fixture
        .snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream)
        .ok_or_else(|| anyhow::anyhow!("fixture lacks the complete Realm stream head"))?
        .clone();
    let outcome = ExactCurrentResultsReadOutcome::NeverWritten {
        realm_id: fixture.snapshot.realm_id.clone(),
        governance_generation: fixture.snapshot.governance_generation,
        effective_stream_head: head,
        selector: NeverWrittenExactCurrentSelector::AgentInteraction(selector.clone()),
    };
    outcome.validate_for_request(&input.request, fixture.snapshot.governance_generation)?;
    // This read consumes the same immutable, fully verified cut. It cannot
    // manufacture a mode value, append Events, or advance a snapshot/current.
    ensure!(
        fixture.snapshot.snapshot_id == input.fixture.snapshot.snapshot_id,
        "exact current read changed the verified snapshot"
    );
    serde_json::to_value(outcome).map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitInput {
    fixture: Option<Fixture>,
    request: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
    #[serde(default = "default_seed")]
    seed_b64url: String,
    #[serde(default = "default_device")]
    device_id: String,
}

pub(super) fn submit(input: Value) -> Result<Value> {
    use arkret_models_collaboration::authority_commit::*;
    let input: SubmitInput = serde_json::from_value(input)?;
    input.request.validate()?;
    let configuration = BuildInput {
        salt: 9,
        title: String::new(),
        seed_b64url: input.seed_b64url,
        device_id: input.device_id,
        board: false,
        empty_board: true,
        encrypted: false,
    };
    let mut builder = Builder::new(&configuration)?;
    if let Some(fixture) = input.fixture {
        let fixture = validate_fixture(&fixture)?;
        builder.public_blobs = fixture.public_blobs.clone();
        ensure!(
            fixture.identity.account_id == builder.identity.account_id,
            "submit fixture Account mismatch"
        );
        for full in fixture.committed_events {
            builder.append_signed(full.event)?;
            ensure!(
                builder.events.last().unwrap().commit == full.commit,
                "fixture original Commit changed"
            );
        }
        builder.ids = fixture.ids;
    }
    let submissions = match &input.request {
        SelfAuthoritySubmitRequest::Event(submission) => vec![submission.clone()],
        SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit) => unit.events.clone(),
        _ => bail!("fixture does not implement this registered atomic unit"),
    };
    let mut commits = Vec::new();
    let mut duplicate = true;
    for submission in submissions {
        if let Some(full) = builder
            .events
            .iter()
            .find(|full| full.event.event_id == submission.event.event_id)
        {
            ensure!(
                full.event == submission.event,
                "fixture Event replay changes signed bytes"
            );
            commits.push(full.commit.clone());
            continue;
        }
        duplicate = false;
        builder.append_signed(submission.event)?;
        commits.push(builder.events.last().unwrap().commit.clone());
    }
    let outcome = match &input.request {
        SelfAuthoritySubmitRequest::Event(_) => {
            SelfAuthoritySubmitOutcome::Ordinary(AuthoritySubmitOutcome::Accepted {
                status: if duplicate {
                    AuthorityCommitStatus::Duplicate
                } else {
                    AuthorityCommitStatus::Committed
                },
                commit: commits.remove(0),
            })
        }
        SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(_) => {
            SelfAuthoritySubmitOutcome::OrdinaryRealmBootstrap(
                OrdinaryRealmBootstrapAcceptanceOutcome {
                    unit_kind: OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
                    status: if duplicate {
                        AggregateAcceptanceStatus::Duplicate
                    } else {
                        AggregateAcceptanceStatus::Committed
                    },
                    commits,
                },
            )
        }
        _ => unreachable!(),
    };
    outcome.validate_for_request(&input.request)?;
    Ok(json!({ "fixture": builder.finish()?, "outcome": outcome }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentPrincipalInput {
    fixture: Fixture,
    request: CurrentPrincipalRequestBody,
}

pub(super) fn current_principal(input: Value) -> Result<Value> {
    let input: CurrentPrincipalInput = serde_json::from_value(input)?;
    let fixture = validate_fixture(&input.fixture)?;
    input.request.validate()?;
    ensure!(
        input.request.account_id == fixture.identity.account_id,
        "current principal fixture Account mismatch"
    );
    let outcome = CurrentPrincipalOutcome {
        request_id: input.request.request_id.clone(),
        account_id: fixture.identity.account_id,
        principal_control_realm_id: fixture.identity.principal_control_realm_id,
        resolution_projection: fixture.identity.resolution,
    };
    outcome.validate_for_request(&input.request)?;
    serde_json::to_value(outcome).map_err(Into::into)
}
