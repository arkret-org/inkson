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
