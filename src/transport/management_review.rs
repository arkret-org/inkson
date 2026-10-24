//! Normal management review uses the registered SDK carriers. A pending
//! request retains a signed candidate; it does not submit that candidate.
use arkret_sdk::{
    AccountId, ActorId, AgentInteractionMode, AgentInteractionSetPayload, ApprovalContext,
    ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof, ApprovalSignatureProofKind,
    ApprovalTarget, CapabilityActionId, DidUrl, Event, ManagementOperation,
    ManagementReviewDecision, ManagementReviewDecisionRequestBody,
    ManagementReviewLookupRequestBody, ManagementReviewRequestBody, ManagementReviewResponseBody,
    ManagementReviewStatus, ManagementReviewTarget, RealmId, ScopeRef,
};
use zeroize::Zeroizing;

/// Process-only context; never a protocol carrier or persistent secret record.
#[derive(Clone)]
pub(crate) struct FrozenReview {
    pub request: ManagementReviewRequestBody,
    pub outcome: ManagementReviewResponseBody,
    pub account: AccountId,
    pub session_generation: u64,
    pub accepted_commit: Option<arkret_sdk::RealmCommit>,
}

/// Original signed request retained before its first network attempt.
#[derive(Clone)]
pub(crate) struct PreparedReview {
    pub request: ManagementReviewRequestBody,
    pub account: AccountId,
    pub session_generation: u64,
}

/// Original signed decision retained before dispatch. No Recovery Key is kept.
#[derive(Clone)]
pub(crate) struct PreparedDecision {
    pub body: ManagementReviewDecisionRequestBody,
    pub account: AccountId,
    pub session_generation: u64,
}

pub(crate) fn check_session(account: &AccountId, generation: u64) -> anyhow::Result<()> {
    let context = crate::app::SessionContext::get();
    anyhow::ensure!(
        (context.session_generation)() == generation
            && context.active_account().as_ref().map(|v| &v.authority) == Some(account),
        "Account or Device changed; load the review again"
    );
    Ok(())
}

pub(crate) fn candidate(
    request: &ManagementReviewRequestBody,
) -> anyhow::Result<(&Event, AccountId)> {
    request.validate()?;
    let ManagementReviewTarget::Event { event } = &request.target;
    anyhow::ensure!(
        event.scope_ref == request.effective_scope
            && matches!(&event.scope_ref, ScopeRef::Realm { realm_id } if realm_id == &event.realm_id)
            && event.executed_by.is_none()
            && event.actor_id == request.requester_actor_id,
        "Review does not retain its exact Realm and original controller producer"
    );
    let controller = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("Controller must be a complete Account"))?;
    let beneficiary =
        match request.management_operation {
            ManagementOperation::Join if event.kind == arkret_sdk::EventKind::MemberState => {
                let payload: arkret_sdk::MembershipPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                let binding = payload.agent_controller_binding.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Original Agent controller membership is unavailable")
                })?;
                anyhow::ensure!(
                    payload.membership == arkret_sdk::MembershipPayloadState::Join
                        && payload.membership_cause.is_none()
                        && &binding.controller_account_id == controller
                        && binding.controller_terminal_event_ref.is_none(),
                    "Candidate is not an original controller Agent join"
                );
                payload.member_id.as_account_id().cloned().ok_or_else(|| {
                    anyhow::anyhow!("Agent beneficiary must be a complete Account")
                })?
            }
            ManagementOperation::Publish
                if event.kind == arkret_sdk::EventKind::AgentInteractionSet =>
            {
                let payload: AgentInteractionSetPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                anyhow::ensure!(
                    &payload.controller_account_id == controller
                        && payload.interaction_mode == AgentInteractionMode::Public,
                    "Candidate is not the controller's original public intent"
                );
                payload.agent_account_id
            }
            _ => anyhow::bail!("Management operation has no supported original candidate"),
        };
    anyhow::ensure!(
        beneficiary != *controller && beneficiary.station_id == controller.station_id,
        "Agent beneficiary does not retain complete same-Station ownership"
    );
    let suite = event.realm_id.digest_suite_code().digest_suite();
    event.verify_event_id_matches_content_with_digest_suite(suite)?;
    event.verify_producer_proof_self_consistency(suite)?;
    Ok((event, beneficiary))
}

pub(crate) fn bind_outcome(
    request: &ManagementReviewRequestBody,
    outcome: &ManagementReviewResponseBody,
) -> anyhow::Result<()> {
    let (event, _) = candidate(request)?;
    anyhow::ensure!(
        outcome.request_id == request.request_id
            && outcome.target_digest.as_str() == crate::canonical::canonical_sha256(event)?,
        "Station review digest does not bind the displayed original candidate"
    );
    Ok(())
}

pub(crate) async fn freeze_and_request<F: FnOnce(PreparedReview)>(
    http: &arkret_sdk::http_client::Client,
    realm: RealmId,
    agent: AccountId,
    operation: ManagementOperation,
    retained: Option<PreparedReview>,
    retain: F,
) -> anyhow::Result<FrozenReview> {
    if let Some(prepared) = retained {
        return request_prepared(http, prepared).await;
    }
    let context = crate::app::SessionContext::get();
    let generation = (context.session_generation)();
    let controller = context
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("No active Account"))?
        .authority;
    anyhow::ensure!(
        agent != controller,
        "Select the Agent beneficiary, not its controller"
    );
    let submitter = crate::app::runtime_adapter::event_submitter(http.clone());
    let local = match operation {
        ManagementOperation::Join => {
            let binding = submitter
                .read_agent_controller_membership_binding(&realm)
                .await?;
            anyhow::ensure!(
                binding.controller_account_id == controller,
                "Controller binding changed"
            );
            crate::event_builders::build_owned_agent_join_event(
                realm.as_str(),
                controller.principal_id.as_str(),
                &ActorId::account(agent),
                binding,
            )?
        }
        ManagementOperation::Publish => {
            let (_, revision, owner) =
                crate::transport::agent_interaction::read(http, &realm, &agent).await?;
            anyhow::ensure!(
                owner.as_ref().is_none_or(|v| v == &controller),
                "Current Agent controller differs"
            );
            crate::operation::TypedOperationBuilder::new::<
                arkret_sdk::event_spec::AgentInteractionSet,
            >(
                realm.as_str(),
                controller.principal_id.as_str(),
                AgentInteractionSetPayload {
                    agent_account_id: agent,
                    controller_account_id: controller.clone(),
                    interaction_mode: AgentInteractionMode::Public,
                    expected_revision: revision,
                },
            )
            .build_sdk_event("inkson")?
        }
        _ => anyhow::bail!("Select join or public publication"),
    };
    // Existing authoring performs real controller Device signing once. No
    // enqueue, forwarding, membership transition, or Welcome is performed here.
    let signed = submitter.author_for_direct_submission(&local).await?;
    let request = ManagementReviewRequestBody {
        configuration_ref: None,
        request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()).to_string(),
        effective_scope: ScopeRef::Realm { realm_id: realm },
        management_operation: operation,
        requester_actor_id: ActorId::account(controller.clone()),
        target: ManagementReviewTarget::Event {
            event: Box::new(signed.into_event()),
        },
    };
    candidate(&request)?;
    check_session(&controller, generation)?;
    let prepared = PreparedReview {
        request,
        account: controller,
        session_generation: generation,
    };
    retain(prepared.clone());
    request_prepared(http, prepared).await
}

async fn request_prepared(
    http: &arkret_sdk::http_client::Client,
    prepared: PreparedReview,
) -> anyhow::Result<FrozenReview> {
    check_session(&prepared.account, prepared.session_generation)?;
    candidate(&prepared.request)?;
    let outcome = http.management_review_request(&prepared.request).await?;
    bind_outcome(&prepared.request, &outcome)?;
    check_session(&prepared.account, prepared.session_generation)?;
    Ok(FrozenReview {
        request: prepared.request,
        outcome,
        account: prepared.account,
        session_generation: prepared.session_generation,
        accepted_commit: None,
    })
}

pub(crate) async fn load(
    http: &arkret_sdk::http_client::Client,
    request: ManagementReviewRequestBody,
    realm: &RealmId,
) -> anyhow::Result<FrozenReview> {
    let (event, _) = candidate(&request)?;
    anyhow::ensure!(
        &event.realm_id == realm,
        "Shared request belongs to another Realm"
    );
    let context = crate::app::SessionContext::get();
    let generation = (context.session_generation)();
    let account = context
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("No active Account"))?
        .authority;
    let outcome = http
        .management_review_status(&ManagementReviewLookupRequestBody {
            request_id: request.request_id.clone(),
        })
        .await?;
    bind_outcome(&request, &outcome)?;
    check_session(&account, generation)?;
    Ok(FrozenReview {
        request,
        outcome,
        account,
        session_generation: generation,
        accepted_commit: None,
    })
}

/// Credential-free fetch, with the same native egress pin and browser host
/// classification as the existing DID discovery path. Never sends session headers.
async fn did_bytes(url: &str, limit: usize) -> anyhow::Result<Option<Vec<u8>>> {
    #[cfg(target_arch = "wasm32")]
    {
        use futures_util::future::{Either, select};
        let fetch = did_bytes_bounded(url, limit);
        let deadline = gloo_timers::future::TimeoutFuture::new(2_000);
        futures_util::pin_mut!(fetch, deadline);
        match select(fetch, deadline).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => anyhow::bail!("DID history fetch exceeded its deadline"),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        did_bytes_bounded(url, limit).await
    }
}

async fn did_bytes_bounded(url: &str, limit: usize) -> anyhow::Result<Option<Vec<u8>>> {
    let parsed = url::Url::parse(url)?;
    anyhow::ensure!(
        parsed.scheme() == "https" && parsed.username().is_empty() && parsed.password().is_none(),
        "DID history requires credential-free HTTPS"
    );
    #[cfg(not(target_arch = "wasm32"))]
    let client = {
        let guard = if cfg!(debug_assertions) {
            arkret_egress_reqwest::EgressGuard::local_development()
        } else {
            arkret_egress_reqwest::EgressGuard::public_https()
        };
        let locked = guard
            .lock_str_async(url, "management approval DID history")
            .await?;
        locked
            .apply_to_client_builder(
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(std::time::Duration::from_secs(2)),
            )
            .build()?
    };
    #[cfg(target_arch = "wasm32")]
    let client = {
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("DID host is absent"))?;
        anyhow::ensure!(
            parsed.scheme() == "https"
                && (arkret_sdk::identity::host_is_safe_for_outbound(host)
                    || (cfg!(debug_assertions)
                        && (host == "localhost"
                            || host.ends_with(".localhost")
                            || host
                                .parse::<std::net::IpAddr>()
                                .is_ok_and(|ip| ip.is_loopback())))),
            "DID history requires an allowed HTTPS host"
        );
        reqwest::Client::new()
    };
    let request = client.get(url);
    #[cfg(target_arch = "wasm32")]
    let request = request.fetch_credentials_omit();
    let response = request.send().await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    anyhow::ensure!(
        response.status().is_success() && response.url().as_str() == url,
        "DID history fetch or redirect refused"
    );
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    anyhow::ensure!(
        matches!(
            content_type.split(';').next().unwrap_or("").trim(),
            "application/json"
                | "application/jsonl"
                | "application/jsonlines"
                | "application/ld+json"
                | "application/did+json"
        ),
        "DID history content type refused"
    );
    anyhow::ensure!(
        response.content_length().is_none_or(|v| v <= limit as u64),
        "DID history exceeds its byte ceiling"
    );
    // The body may be chunked or omit Content-Length. Stop consuming as soon
    // as its hard ceiling is crossed, on native and browser transports alike.
    use futures_util::StreamExt;
    let stream = response.bytes_stream();
    futures_util::pin_mut!(stream);
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            chunk.len() <= limit.saturating_sub(bytes.len()),
            "DID history exceeds its byte ceiling"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(Some(bytes))
}

pub(crate) async fn approve<F: FnOnce(PreparedDecision)>(
    http: &arkret_sdk::http_client::Client,
    review: &FrozenReview,
    recovery_key: Zeroizing<String>,
    root_generation: u64,
    retained: Option<PreparedDecision>,
    retain: F,
) -> anyhow::Result<ManagementReviewResponseBody> {
    if let Some(prepared) = retained {
        anyhow::ensure!(
            prepared.body.decision == ManagementReviewDecision::Approve,
            "Resolve the original decision before selecting another"
        );
        return send_prepared_decision(http, review, &prepared).await;
    }
    check_session(&review.account, review.session_generation)?;
    let fresh = http
        .management_review_status(&ManagementReviewLookupRequestBody {
            request_id: review.request.request_id.clone(),
        })
        .await?;
    bind_outcome(&review.request, &fresh)?;
    anyhow::ensure!(
        fresh.status == ManagementReviewStatus::Pending
            && crate::clock::now_utc_canonical() < fresh.expires_at,
        "Review is no longer pending"
    );
    let (event, beneficiary) = candidate(&review.request)?;
    anyhow::ensure!(
        review.account.principal_id
            != review
                .request
                .requester_actor_id
                .signing_principal_id()
                .clone()
            && review.account.principal_id != event.actual_signer().signing_principal_id().clone()
            && review.account.principal_id != beneficiary.principal_id,
        "Requester, producer and beneficiary cannot approve"
    );
    let principal =
        crate::transport::account::current_principal_for_authority(http, &review.account).await?;
    let did = &principal.resolution_projection.did;
    anyhow::ensure!(
        did.method() == "webvh",
        "Approval requires a native principal control history"
    );
    let limit = arkret_sdk::identity::DID_WEB_MAX_DOCUMENT_BYTES * 32;
    let log = did_bytes(
        &arkret_sdk::identity::DidWebvhResolver::log_url(did)?,
        limit,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("Complete principal history is unavailable"))?;
    let witness = did_bytes(
        &arkret_sdk::identity::DidWebvhResolver::witness_url(did)?,
        limit,
    )
    .await?;
    let verified = arkret_sdk::identity::verify_did_webvh_v1_chain_and_witness_bytes(
        did,
        &log,
        witness.as_deref(),
    )?;
    let pinned = verified
        .log
        .raw_entries
        .iter()
        .find(|v| {
            v.get("versionId").and_then(serde_json::Value::as_str)
                == Some(principal.resolution_projection.version_id.as_str())
        })
        .ok_or_else(|| anyhow::anyhow!("History omits the accepted principal resolution"))?;
    anyhow::ensure!(
        crate::canonical::canonical_sha256(pinned)?
            == principal.resolution_projection.method_history_head,
        "History differs from accepted principal resolution"
    );
    let approved_at = crate::clock::now_utc_canonical();
    let point =
        arkret_sdk::webvh::validate_webvh_history_at(did, &verified.log.raw_entries, approved_at)?;
    let material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        &recovery_key,
        "",
        root_generation,
    )?;
    let multibase = &material.root_public_key_multikey;
    let method =
        DidUrl::new(format!("did:key:{multibase}#{multibase}")).map_err(anyhow::Error::msg)?;
    let control = arkret_sdk::identity::principal_control::native_identity_control_key_from_verified_selection(
        &point.did, &review.account.principal_id, std::slice::from_ref(&point.active_update_key_multibase), &method,
        arkret_sdk::identity::principal_control::DirectIdentityControlPurpose::ApprovalSignature,
    )?;
    anyhow::ensure!(
        control.public_key() == &material.root_public_key,
        "Recovery Key does not control the selected principal generation"
    );
    let action = match review.request.management_operation {
        ManagementOperation::Join => CapabilityActionId::AgentJoin,
        ManagementOperation::Publish => CapabilityActionId::AgentPublish,
        _ => anyhow::bail!("Management candidate is unsupported"),
    };
    let mut signature = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::Management {
                management_operation: review.request.management_operation,
                effective_scope: review.request.effective_scope.clone(),
                request_id: review.request.request_id.clone(),
            },
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: fresh.target_digest.clone(),
            operation: arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1.into(),
            action,
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actual_signer().clone(),
            approver_did: did.clone(),
            approved_at,
            nonce: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()).to_string(),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: method.clone(),
            jws: String::new(),
        },
    };
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        material.root_seed,
        method.to_string(),
    );
    signature.proof.jws = signer.sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&signature)?,
    );
    signature.validate()?;
    arkret_sdk::identity::principal_control::verify_native_control_event_approval(
        &control,
        &signature,
        event,
        arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        action,
        approved_at,
    )?;
    let after =
        crate::transport::account::current_principal_for_authority(http, &review.account).await?;
    anyhow::ensure!(
        principal.account_id == after.account_id
            && principal.principal_control_realm_id == after.principal_control_realm_id
            && crate::canonical::canonical_sha256(&principal.resolution_projection)?
                == crate::canonical::canonical_sha256(&after.resolution_projection)?,
        "Principal resolution changed during approval"
    );
    check_session(&review.account, review.session_generation)?;
    let prepared = PreparedDecision {
        body: ManagementReviewDecisionRequestBody {
            request_id: review.request.request_id.clone(),
            expected_status: ManagementReviewStatus::Pending,
            decision: ManagementReviewDecision::Approve,
            approval_signatures: vec![signature],
        },
        account: review.account.clone(),
        session_generation: review.session_generation,
    };
    retain(prepared.clone());
    send_prepared_decision(http, review, &prepared).await
}

async fn send_prepared_decision(
    http: &arkret_sdk::http_client::Client,
    review: &FrozenReview,
    prepared: &PreparedDecision,
) -> anyhow::Result<ManagementReviewResponseBody> {
    check_session(&prepared.account, prepared.session_generation)?;
    anyhow::ensure!(
        prepared.account == review.account
            && prepared.session_generation == review.session_generation
            && prepared.body.request_id == review.request.request_id,
        "Retained decision belongs to another selected review"
    );
    let fresh = http
        .management_review_status(&ManagementReviewLookupRequestBody {
            request_id: prepared.body.request_id.clone(),
        })
        .await?;
    bind_outcome(&review.request, &fresh)?;
    // A lost decision response is resolved from the original retained votes,
    // never by manufacturing another approval or renewing its timestamp.
    let observed = match prepared.body.decision {
        ManagementReviewDecision::Approve => {
            matches!(
                fresh.status,
                ManagementReviewStatus::Pending
                    | ManagementReviewStatus::Approved
                    | ManagementReviewStatus::Consumed
            ) && !prepared.body.approval_signatures.is_empty()
                && prepared
                    .body
                    .approval_signatures
                    .iter()
                    .all(|s| fresh.approval_signatures.contains(s))
        }
        ManagementReviewDecision::Cancel => fresh.status == ManagementReviewStatus::Cancelled,
        ManagementReviewDecision::Reject => fresh.status == ManagementReviewStatus::Rejected,
    };
    if observed {
        check_session(&prepared.account, prepared.session_generation)?;
        return Ok(fresh);
    }
    anyhow::ensure!(
        fresh.status == ManagementReviewStatus::Pending,
        "Review no longer accepts the retained decision"
    );
    let outcome = http.management_review_decide(&prepared.body).await?;
    bind_outcome(&review.request, &outcome)?;
    check_session(&prepared.account, prepared.session_generation)?;
    Ok(outcome)
}

pub(crate) async fn retry_decision(
    http: &arkret_sdk::http_client::Client,
    review: &FrozenReview,
    prepared: &PreparedDecision,
) -> anyhow::Result<ManagementReviewResponseBody> {
    send_prepared_decision(http, review, prepared).await
}

pub(crate) async fn decide_without_approval<F: FnOnce(PreparedDecision)>(
    http: &arkret_sdk::http_client::Client,
    review: &FrozenReview,
    decision: ManagementReviewDecision,
    retained: Option<PreparedDecision>,
    retain: F,
) -> anyhow::Result<ManagementReviewResponseBody> {
    anyhow::ensure!(
        decision != ManagementReviewDecision::Approve,
        "Approval requires a native control signature"
    );
    check_session(&review.account, review.session_generation)?;
    if let Some(prepared) = retained {
        anyhow::ensure!(
            prepared.body.decision == decision,
            "Resolve the original decision before selecting another"
        );
        return send_prepared_decision(http, review, &prepared).await;
    }
    let prepared = PreparedDecision {
        body: ManagementReviewDecisionRequestBody {
            request_id: review.request.request_id.clone(),
            expected_status: ManagementReviewStatus::Pending,
            decision,
            approval_signatures: vec![],
        },
        account: review.account.clone(),
        session_generation: review.session_generation,
    };
    retain(prepared.clone());
    send_prepared_decision(http, review, &prepared).await
}

pub(crate) async fn submit_approved(
    http: &arkret_sdk::http_client::Client,
    review: &FrozenReview,
) -> anyhow::Result<crate::models::SubmitEventResult> {
    check_session(&review.account, review.session_generation)?;
    anyhow::ensure!(
        review.request.requester_actor_id == ActorId::account(review.account.clone()),
        "Only the original requester may submit its candidate"
    );
    let current = http
        .management_review_status(&ManagementReviewLookupRequestBody {
            request_id: review.request.request_id.clone(),
        })
        .await?;
    bind_outcome(&review.request, &current)?;
    anyhow::ensure!(
        matches!(
            current.status,
            ManagementReviewStatus::Approved | ManagementReviewStatus::Consumed
        ) && !current.approval_signatures.is_empty(),
        "Review is not approved"
    );
    let (event, _) = candidate(&review.request)?;
    let submitter = crate::app::runtime_adapter::event_submitter(http.clone());
    let result = submitter
        .submit_management_review_event(event, current.approval_signatures, || {
            check_session(&review.account, review.session_generation)
        })
        .await?;
    check_session(&review.account, review.session_generation)?;
    anyhow::ensure!(
        !result.is_committed()
            || result
                .commit
                .as_ref()
                .is_some_and(|commit| commit.event_ref == event.event_id),
        "Reviewed commit does not bind the original Event"
    );
    Ok(result)
}
