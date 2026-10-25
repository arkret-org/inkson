use anyhow::{Result, bail, ensure};
use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentPauseRequestBody, AgentResumeRequestBody,
};
use arkret_models_collaboration::events_payloads::circle::CircleMemberStatePayload;
use arkret_models_collaboration::governance::circle::{
    CircleMemberDeleteRequestBody, CircleMemberRequestBody, CircleMembership,
};
use arkret_sdk::{AccountId, ActorId, Did, DidUrl, EventAdmissionSubmission, RealmId, ScopeRef};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Input {
    CircleMember {
        realm_id: RealmId,
        controller_account_id: AccountId,
        controller_did: Did,
        payload: CircleMemberStatePayload,
        #[serde(default)]
        delete: bool,
    },
    AccountData {
        realm_id: RealmId,
        controller_account_id: AccountId,
        controller_did: Did,
        payload: arkret_sdk::AccountDataSetPayload,
        #[serde(default)]
        delete: bool,
    },
    ReadCursor {
        controller_account_id: AccountId,
        controller_did: Did,
        payload: arkret_models_collaboration::objects::read_receipts::ReadCursor,
    },
    AgentLifecycle {
        transition: String,
        agent_account_id: AccountId,
        controller_account_id: AccountId,
        controller_did: Did,
        principal_control_realm_id: RealmId,
        controller_authorization_ref: DidUrl,
        previous_status: arkret_event_draft::AgentLifecycleState,
        reason: Option<arkret_sdk::AuditReasonText>,
    },
}

pub(super) fn build(value: Value) -> Result<Value> {
    let input: Input = serde_json::from_value(value)?;
    let at = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let (mut event, controller_account_id, controller_did, action, reason) = match input {
        Input::CircleMember {
            realm_id,
            controller_account_id,
            controller_did,
            payload,
            delete,
        } => {
            payload.validate()?;
            if delete {
                ensure!(
                    payload.membership == CircleMembership::Leave,
                    "DELETE requires a leave transition"
                );
            }
            let event = arkret_event_draft::TypedEventDraft::<
                arkret_sdk::event_spec::CircleMemberState,
            >::new(
                ScopeRef::Circle {
                    realm_id,
                    circle_id: payload.circle_id.clone(),
                },
                ActorId::account(controller_account_id.clone()),
                payload,
            )?
            .author_with_digest_suite(at, arkret_sdk::DigestSuite::Sha256)?;
            (
                event,
                controller_account_id,
                controller_did,
                if delete {
                    "circle_delete"
                } else {
                    "circle_add"
                }
                .to_owned(),
                None,
            )
        }
        Input::AccountData {
            realm_id,
            controller_account_id,
            controller_did,
            payload,
            delete,
        } => {
            payload.validate()?;
            ensure!(
                payload.tombstone == delete,
                "account data operation/tombstone mismatch"
            );
            let event =
                arkret_event_draft::TypedEventDraft::<arkret_sdk::event_spec::AccountDataSet>::new(
                    ScopeRef::Realm { realm_id },
                    ActorId::account(controller_account_id.clone()),
                    payload,
                )?
                .author_with_digest_suite(at, arkret_sdk::DigestSuite::Sha256)?;
            (
                event,
                controller_account_id,
                controller_did,
                if delete {
                    "account_data_delete"
                } else {
                    "account_data_replace"
                }
                .to_owned(),
                None,
            )
        }
        Input::ReadCursor {
            controller_account_id,
            controller_did,
            payload,
        } => {
            ensure!(
                payload.actor_id == ActorId::account(controller_account_id.clone()),
                "read cursor actor mismatch"
            );
            let event = arkret_event_draft::TypedEventDraft::<
                arkret_sdk::event_spec::ReadCursorAdvance,
            >::new(
                ScopeRef::Realm {
                    realm_id: payload.realm_id.clone(),
                },
                ActorId::account(controller_account_id.clone()),
                payload,
            )?
            .author_with_digest_suite(at, arkret_sdk::DigestSuite::Sha256)?;
            (
                event,
                controller_account_id,
                controller_did,
                "read_cursor".to_owned(),
                None,
            )
        }
        Input::AgentLifecycle {
            transition,
            agent_account_id,
            controller_account_id,
            controller_did,
            principal_control_realm_id,
            controller_authorization_ref,
            previous_status,
            reason,
        } => {
            let actor = ActorId::account(agent_account_id);
            let controller = ActorId::account(controller_account_id.clone());
            let scope = ScopeRef::Realm {
                realm_id: principal_control_realm_id,
            };
            let intent = match transition.as_str() {
                "deactivate" => arkret_event_draft::build_agent_deactivate_intent(
                    actor,
                    controller,
                    scope,
                    controller_authorization_ref,
                    previous_status,
                    reason.clone(),
                    at,
                )?,
                "pause" => {
                    ensure!(
                        previous_status == arkret_event_draft::AgentLifecycleState::Active,
                        "pause requires active state"
                    );
                    arkret_event_draft::build_agent_pause_intent(
                        actor,
                        controller,
                        scope,
                        controller_authorization_ref,
                        reason.clone(),
                        at,
                    )?
                }
                "resume" => {
                    ensure!(
                        previous_status == arkret_event_draft::AgentLifecycleState::Paused
                            && reason.is_none(),
                        "resume requires paused state without a reason"
                    );
                    arkret_event_draft::build_agent_resume_intent(
                        actor,
                        controller,
                        scope,
                        controller_authorization_ref,
                        at,
                    )?
                }
                _ => bail!("unsupported lifecycle transition"),
            };
            (
                intent.author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?,
                controller_account_id,
                controller_did,
                transition,
                reason,
            )
        }
    };
    ensure!(
        arkret_sdk::project_did_to_core_id(&controller_did)? == controller_account_id.principal_id,
        "fixture controller DID differs from its Account"
    );
    let signer = inkson::event_signer::build_ed25519_device_signer(
        [1; 32],
        controller_did.as_str(),
        "ak:device:01964137-0000-7000-8000-0000000000a1",
    );
    signer.sign_sdk_event_with_context(
        &mut event,
        inkson::event_signer::ProducerProofContext::for_native_unit(
            arkret_sdk::DigestSuite::Sha256,
        ),
    )?;
    let submission = EventAdmissionSubmission::new(event.into_event());
    match action.as_str() {
        "circle_delete" => Ok(serde_json::to_value(CircleMemberDeleteRequestBody {
            member_event: submission,
        })?),
        "circle_add" => Ok(serde_json::to_value(CircleMemberRequestBody {
            member_event: submission,
        })?),
        "account_data_replace" => Ok(serde_json::to_value(
            arkret_models_identity::account::AccountDataReplaceRequestBody {
                set_event: submission,
            },
        )?),
        "account_data_delete" => Ok(serde_json::to_value(
            arkret_models_identity::account::AccountDataDeleteRequestBody {
                set_event: submission,
            },
        )?),
        "read_cursor" => Ok(serde_json::to_value(
            arkret_models_collaboration::objects::read_receipts::ReadCursorAdvanceRequestBody {
                advance_event: submission,
            },
        )?),
        "pause" => Ok(serde_json::to_value(AgentPauseRequestBody {
            reason,
            lifecycle_event: submission,
        })?),
        "resume" => Ok(serde_json::to_value(AgentResumeRequestBody {
            lifecycle_event: submission,
        })?),
        "deactivate" => Ok(serde_json::to_value(AgentDeactivateRequestBody {
            reason,
            lifecycle_event: submission,
        })?),
        _ => unreachable!("action selected above"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyInput {
    event: arkret_sdk::Event,
    controller_account_id: AccountId,
    controller_did: Did,
    device_id: arkret_sdk::DeviceId,
    seed_b64url: String,
}

pub(super) fn verify(value: Value) -> Result<Value> {
    let input: VerifyInput = serde_json::from_value(value)?;
    let event = input.event;
    ensure!(
        arkret_sdk::project_did_to_core_id(&input.controller_did)?
            == input.controller_account_id.principal_id,
        "controller DID mismatch"
    );
    ensure!(
        event.actual_signer() == &ActorId::account(input.controller_account_id),
        "fixture signer Account mismatch"
    );
    event.verify_event_id_matches_content_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("producer proof missing"))?;
    ensure!(
        proof.verification_method.as_str()
            == format!("{}#{}", input.controller_did, input.device_id),
        "fixture verification method mismatch"
    );
    let seed: [u8; 32] = arkret_sdk::base64url_decode(&input.seed_b64url)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("fixture seed must contain 32 bytes"))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_sdk::canonical::canonical_json_bytes(&event.digest_payload()?)?,
        event.actual_signer(),
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
        arkret_sdk::DigestSuite::Sha256,
    )?;
    Ok(serde_json::json!({ "verified": true }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountDataValueInput {
    account_id: AccountId,
    key: String,
    plaintext: Value,
}

pub(super) fn account_data_value(value: Value) -> Result<Value> {
    let input: AccountDataValueInput = serde_json::from_value(value)?;
    ensure!(
        input.key == "ak.account.blocklist",
        "fixture supports the registered blocklist value"
    );
    super::validate_mock_response(
        serde_json::json!({ "schema_ref": "schemas/account-blocklist.schema.json", "value": input.plaintext }),
    )?;
    let actor = ActorId::account(input.account_id);
    let envelope = arkret_sdk::account_data_crypto::seal_account_data_value(
        &[18; 32],
        &actor,
        &input.key,
        &input.plaintext,
    )?;
    ensure!(
        arkret_sdk::account_data_crypto::open_account_data_value(
            &[18; 32], &actor, &input.key, &envelope
        )? == input.plaintext,
        "fixture AEAD round trip mismatch"
    );
    Ok(serde_json::to_value(envelope)?)
}

// Private author/verifier input; all protocol values use the SDK models.
pub(super) fn runtime_candidate(value: Value) -> Result<Value> {
    use arkret_models_collaboration::agent_operations::AgentPairingBootstrap;
    use arkret_models_collaboration::agent_scope::{
        AgentRuntimeApprovalRequestBody, agent_runtime_key_binding_digest,
    };
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        bootstrap: AgentPairingBootstrap,
        #[serde(default)]
        request: Option<AgentRuntimeApprovalRequestBody>,
        #[serde(default = "default_runtime_seed")]
        seed: u8,
    }
    fn default_runtime_seed() -> u8 {
        44
    }
    let input: Input = serde_json::from_value(value)?;
    let bootstrap = input.bootstrap;
    let identity = bootstrap
        .runtime_identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("runtime identity required"))?;
    if let Some(request) = input.request {
        request.validate()?;
        ensure!(
            request.agent_id == bootstrap.agent_id
                && request.pairing_request_id == bootstrap.pairing_request_id
                && request.pairing_code.as_str() == bootstrap.pairing_code,
            "pairing credential mismatch"
        );
        ensure!(
            request.proof_of_possession.audience_id == bootstrap.service_id,
            "pairing audience mismatch"
        );
        let digest = agent_runtime_key_binding_digest(
            &request.agent_id,
            &request.pairing_request_id,
            &request.verification_method,
            &request.public_key,
            request.runtime_attestation.as_ref(),
        )?;
        let transcript = request.proof_of_possession.validate_shape(
            &request.agent_id,
            &request.pairing_request_id,
            &request.verification_method,
            &request.public_key,
            &digest,
            &bootstrap.pairing_code,
            bootstrap.pairing_expires_at,
            chrono::Utc::now(),
        )?;
        ensure!(
            arkret_signatures::verify_detached_ed25519_signature(
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: arkret_sdk::base64url_decode(request.public_key.key.as_str())?
                },
                &transcript,
                request.proof_of_possession.signature.as_str()
            ),
            "invalid runtime possession signature"
        );
        return Ok(serde_json::json!({ "binding_digest": digest }));
    }
    let method = identity.verification_method.clone();
    let key = ed25519_dalek::SigningKey::from_bytes(&[input.seed; 32]);
    Ok(serde_json::to_value(
        arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
            &key, bootstrap, &method,
        )
        .build_approval_request()?
        .body,
    )?)
}
