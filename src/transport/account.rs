//! Typed account/self read and write transport.
//!
//! These are the pure-passthrough account/self operations that used to live as
//! thin inherent methods on [`crate::transport::TransportClient`]. They build a typed SDK
//! request body (and do input validation / small projections) and call the
//! shared SDK `http-client::Client` directly. Call sites reach them through
//! [`crate::transport::auth::with_authed_sdk_client`], which keeps the
//! session-refresh + terminal-session classification identical to the old
//! facade path while dropping the per-domain facade method.
//!
//! The account-data resource writes (`set_account_data`,
//! `update_account_data_with_merge`, `delete_account_data`, plus
//! `submit_read_cursor_advance`) are free functions taking an
//! [`crate::event_submit::EventSubmitter`], reached through
//! [`crate::transport::auth::with_event_submitter`]; the account-data actor-scope
//! lookup they need runs through `submitter.http()`.
//!
//! Only the `request_contact` family remains an inherent `TransportClient` method,
//! because it resolves contact addressing via the struct-cached
//! `describe_cached` (see `contact_request_addressing`).

use std::collections::BTreeMap;

use dioxus::prelude::{SyncSignal, WritableExt};
use serde_json::Value;

use crate::event_submit::EventSubmitter;
use crate::models::{ContactList, CurrentAccount, IdentityResolveOutcome};

pub(crate) fn did_for_request_field(
    field: &str,
    value: &str,
) -> anyhow::Result<arkret_sdk::DidCoreId> {
    let value = value.trim();
    crate::mls_api_helpers::principal_core_id(value)
        .map_err(|err| anyhow::anyhow!("invalid {field} DID `{value}`: {err}"))
}

pub async fn account_viewer(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_models_collaboration::account_lifecycle::AccountView> {
    http.account_viewer()
        .await
        .map_err(|error| anyhow::anyhow!("account viewer: {error}"))
}

pub async fn account_me(http: &arkret_sdk::http_client::Client) -> anyhow::Result<CurrentAccount> {
    let viewer = account_viewer(http).await?;
    Ok(current_account_from_viewer(viewer))
}

/// Fetch and verify the complete current principal resolution before it enters
/// the active-account model. The route is transport only; both identity
/// coordinates come from the already verified authority pair.
pub async fn resolve_active_account_context(
    http: &arkret_sdk::http_client::Client,
    profile_id: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    server_url: url::Url,
) -> anyhow::Result<crate::config::ActiveAccountContext> {
    let public_resolution = http
        .open_principal_resolution(&authority.principal_id, &authority.station_id)
        .await?;
    anyhow::ensure!(
        public_resolution.authority() == authority,
        "public principal resolution returned another account authority"
    );
    let station_resolution = http.open_service_resolution(&authority.station_id).await?;
    let (accepted_projection, _) =
        arkret_identity::verify_embedded_public_principal_resolution_history(
            &public_resolution,
            &station_resolution,
            chrono::Utc::now(),
        )?;
    crate::config::ActiveAccountContext::new(
        profile_id,
        authority,
        accepted_projection,
        device_id,
        server_url,
    )
}

/// Author and sign the authenticated principal's profile Event, then hand its
/// exact publication wrapper to `ak.self.account.command.update_profile.v1`.
/// Existing profiles use the accepted create-derived id and PCR returned by
/// account viewer. First creation additionally requires the durable accepted
/// PCR bootstrap evidence retained by the local account state.
pub async fn update_profile(
    submitter: &EventSubmitter,
    authority_evidence: &crate::state::RecoveryMaterialEvidence,
    first_profile_display_name: &str,
    display_name: Option<&str>,
    bio: Option<&str>,
    avatar_blob_ref: Option<&str>,
) -> anyhow::Result<arkret_models_identity::AccountUpdateProfileOutcome> {
    let mut patch = arkret_sdk::Patch::new();
    if let Some(display_name) = display_name {
        let display_name = display_name.trim();
        if display_name.is_empty() {
            patch.insert_op("display_name", arkret_sdk::PatchOp::unset())?;
        } else {
            patch.insert("display_name", display_name)?;
        }
    }
    if let Some(bio) = bio {
        let bio = bio.trim();
        if bio.is_empty() {
            patch.insert_op("profile_fields.bio", arkret_sdk::PatchOp::unset())?;
        } else {
            patch.insert("profile_fields.bio", bio)?;
        }
    }
    if let Some(avatar_blob_ref) = avatar_blob_ref {
        let avatar_blob_ref = avatar_blob_ref.trim();
        if avatar_blob_ref.is_empty() {
            patch.insert_op("avatar_blob_ref", arkret_sdk::PatchOp::unset())?;
        } else {
            arkret_sdk::BlobRef::new(avatar_blob_ref.to_owned()).map_err(|err| {
                anyhow::anyhow!("invalid avatar_blob_ref `{avatar_blob_ref}`: {err}")
            })?;
            patch.insert("avatar_blob_ref", avatar_blob_ref)?;
        }
    }
    patch
        .validate()
        .map_err(|err| anyhow::anyhow!("invalid profile patch: {err}"))?;

    let viewer = account_viewer(submitter.http()).await?;
    let principal_id = viewer.principal_id.clone();
    let evidence_principal_id = authority_evidence.account_id.principal_id.clone();
    authority_evidence
        .pcr_genesis_unit
        .validate_ordered_envelopes()?;
    if evidence_principal_id != principal_id
        || authority_evidence.pcr_genesis_unit.create().actor_id
            != arkret_sdk::ActorId::account(authority_evidence.account_id.clone())
        || authority_evidence.pcr_genesis_unit.create().realm_id
            != authority_evidence.principal_control_realm_id
        || authority_evidence
            .pcr_genesis_unit
            .founding_authorize()
            .realm_id
            != authority_evidence.principal_control_realm_id
        || authority_evidence.bootstrap_seal.realm_id
            != authority_evidence.principal_control_realm_id
    {
        anyhow::bail!(
            "durable profile-authoring evidence does not bind the authenticated principal's exact PCR"
        );
    }

    let (event, accepted_basis) = if let Some(profile) = viewer.profile {
        let profile = profile.into_inner();
        if patch.is_empty() {
            anyhow::bail!("profile update patch is empty");
        }
        if profile.principal_id != principal_id {
            anyhow::bail!("accepted account profile belongs to a different principal");
        }
        let profile_id = profile.id.ok_or_else(|| {
            anyhow::anyhow!("accepted account profile omits its create-derived id")
        })?;
        let principal_control_realm_id = profile
            .realm_id
            .ok_or_else(|| anyhow::anyhow!("accepted account profile omits its exact PCR realm"))?;
        if principal_control_realm_id != authority_evidence.principal_control_realm_id {
            anyhow::bail!(
                "accepted account profile and durable authoring evidence select different principal-control realms"
            );
        }
        let basis = arkret_models_collaboration::account_lifecycle::AccountProfileAcceptedBasis {
            profile_id: profile_id.clone(),
            principal_id: principal_id.clone(),
            principal_control_realm_id: principal_control_realm_id.clone(),
        };
        (
            crate::operation::ak_ops::account_profile_update(
                &principal_control_realm_id,
                &principal_id,
                profile_id,
                patch,
            )?,
            Some(basis),
        )
    } else {
        let display_name = display_name
            .map(str::trim)
            .unwrap_or_else(|| first_profile_display_name.trim());
        if display_name.is_empty() {
            anyhow::bail!(
                "first profile publication requires a caller-provided accepted display name"
            );
        }
        let mut profile_fields = BTreeMap::new();
        if let Some(bio) = bio.map(str::trim).filter(|value| !value.is_empty()) {
            profile_fields.insert("bio".to_owned(), Value::String(bio.to_owned()));
        }
        let avatar_blob_ref = avatar_blob_ref
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| arkret_sdk::BlobRef::new(value.to_owned()))
            .transpose()?;
        let principal_control_realm_id = authority_evidence.principal_control_realm_id.clone();
        let profile = arkret_models_identity::ActorProfile {
            id: None,
            schema: arkret_models_identity::ActorProfile::SCHEMA.to_owned(),
            realm_id: Some(principal_control_realm_id.clone()),
            principal_id: principal_id.clone(),
            actor_kind: arkret_sdk::ActorKind::User,
            display_name: display_name.to_owned(),
            handle: None,
            agent_slug: None,
            avatar_blob_ref,
            status: None,
            accountable_principal_ids: Vec::new(),
            resolution: None,
            profile_fields,
            created_at: crate::clock::now_utc(),
            updated_by: None,
            updated_at: None,
        };
        (
            crate::operation::ak_ops::account_profile_create(
                &principal_control_realm_id,
                &principal_id,
                profile,
            )?,
            None,
        )
    };
    let signed = submitter.author_for_direct_submission(&event).await?;
    let profile_event = crate::authorization_lease::standard_initial_submission(
        submitter.http(),
        &signed,
        signed.digest_suite(),
    )
    .await?;
    let mut successor_seal = Some(
        crate::transport::contacts::prepare_principal_successor_seal(submitter.http(), &signed)
            .await?,
    );
    let body = arkret_models_collaboration::account_lifecycle::AccountUpdateProfileRequestBody {
        profile_event,
    };
    body.validate_authoring_context(
        &authority_evidence.account_id,
        &authority_evidence.principal_control_realm_id,
        accepted_basis.as_ref(),
        signed.digest_suite(),
    )?;
    const FRONTIER_RETRY_ATTEMPTS: usize = 120;
    for attempt in 0..FRONTIER_RETRY_ATTEMPTS {
        match submitter
            .http()
            .account_update_profile(&body, signed.digest_suite())
            .await
        {
            Ok(outcome) => return Ok(outcome),
            Err(error) => {
                let error = anyhow::Error::from(error);
                if profile_frontier_pending(&error) && attempt + 1 < FRONTIER_RETRY_ATTEMPTS {
                    if let Some(context) = successor_seal.take() {
                        crate::transport::contacts::submit_principal_successor_seal(
                            submitter.http(),
                            context,
                            &signed,
                        )
                        .await?;
                    }
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(250)).await;
                    continue;
                }
                return Err(error);
            }
        }
    }
    unreachable!("bounded account profile retry loop always returns")
}

fn profile_frontier_pending(error: &anyhow::Error) -> bool {
    crate::api_error::api_error_status_and_envelope(error)
        .is_some_and(|(_, envelope)| envelope.code() == "frontier_unavailable")
}

pub async fn respond_contact(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
    action: &str,
) -> anyhow::Result<()> {
    let requester_actor: arkret_sdk::ActorId = serde_json::from_str(requester)?;
    let contacts = http.contacts_list().await?;
    let row = contacts
        .contacts
        .into_iter()
        .find(|row| {
            row.state == arkret_sdk::ContactState::PendingIncoming
                && row.peer.contact_actor_id() == requester_actor
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Contact {action} for `{requester}` requires a fresh pending_incoming list row"
            )
        })?;
    let receipt = row.request_receipt.ok_or_else(|| {
        anyhow::anyhow!("pending_incoming Contact row omitted its signed request_receipt")
    })?;
    submit_contact_response(http, receipt, action).await
}

pub async fn respond_contact_with_request_id(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
    request_event_ref: &str,
    action: &str,
) -> anyhow::Result<()> {
    let requester_actor: arkret_sdk::ActorId = serde_json::from_str(requester)?;
    let contacts = http.contacts_list().await?;
    let row = contacts
        .contacts
        .into_iter()
        .find(|row| {
            row.state == arkret_sdk::ContactState::PendingIncoming
                && row.peer.contact_actor_id() == requester_actor
                && row.request_event_ref.as_ref().is_some_and(|event_ref| {
                    event_ref.as_str() == request_event_ref.trim()
                })
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Contact {action} for `{requester}` requires a fresh list row carrying request Event `{request_event_ref}`"
            )
        })?;
    let receipt = row.request_receipt.ok_or_else(|| {
        anyhow::anyhow!("pending_incoming Contact row omitted its signed request_receipt")
    })?;
    submit_contact_response(http, receipt, action).await
}

async fn submit_contact_response(
    http: &arkret_sdk::http_client::Client,
    request_receipt: arkret_sdk::contact_operations::RequestAcceptanceReceipt,
    action: &str,
) -> anyhow::Result<()> {
    use arkret_sdk::contact_operations::{
        ContactAcceptAction, ContactAcceptPrepareRequestBody, ContactAcceptRequestBody,
        ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome, ContactPreparePhase,
        ContactPreparedOutcome, ContactRejectAction, ContactRejectPrepareRequestBody,
        ContactRejectRequestBody, ContactScope,
    };

    verify_contact_request_receipt(http, &request_receipt).await?;
    let nonce = crate::operation::uuid_v7();
    let operation_id =
        arkret_sdk::ProtocolOperationId::new(format!("ak:operation:contact.{action}.{nonce}"))
            .map_err(anyhow::Error::msg)?;
    let idempotency_key = arkret_sdk::IdempotencyKey::new(nonce).map_err(anyhow::Error::msg)?;

    if action == "accept" {
        let prepare = ContactAcceptRequestBody::Prepare(ContactAcceptPrepareRequestBody {
            phase: ContactPreparePhase::Prepare,
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            request_receipt,
            action: ContactAcceptAction::Accept,
            granted_to_peer_scopes: vec![ContactScope::DirectMessage],
        });
        let prepared = http.contacts_respond(&prepare).await?;
        let (returned_operation_id, reservation_handle, event_draft) = match prepared {
            ContactOperationOutcome::Prepared {
                outcome:
                    ContactPreparedOutcome::Response {
                        operation_id,
                        reservation_handle,
                        event_draft,
                        ..
                    },
            } => (operation_id, reservation_handle, event_draft),
            ContactOperationOutcome::Failed { outcome } => {
                anyhow::bail!("Contact accept prepare failed: {:?}", outcome.reason)
            }
            _ => anyhow::bail!("Contact accept prepare returned the wrong result kind"),
        };
        if returned_operation_id != operation_id {
            anyhow::bail!("Contact accept prepare changed operation_id");
        }
        let signed_event = crate::transport::contacts::sign_prepared_contact_event(
            &event_draft,
            arkret_wire::event_kind_str::CONTACT_ACCEPTED,
        )?;
        let seal_context =
            crate::transport::contacts::prepare_principal_successor_seal(http, &signed_event)
                .await?;
        let commit = ContactAcceptRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id,
            idempotency_key,
            reservation_handle,
            signed_event: signed_event.event().clone(),
            control_proposal_ack: None,
        });
        match http.contacts_respond(&commit).await? {
            ContactOperationOutcome::Accepted { .. } => {
                crate::transport::contacts::submit_principal_successor_seal(
                    http,
                    seal_context,
                    &signed_event,
                )
                .await
            }
            ContactOperationOutcome::Failed { outcome } => {
                anyhow::bail!("Contact accept commit failed: {:?}", outcome.reason)
            }
            _ => anyhow::bail!("Contact accept commit returned the wrong result kind"),
        }
    } else if action == "reject" {
        let prepare = ContactRejectRequestBody::Prepare(ContactRejectPrepareRequestBody {
            phase: ContactPreparePhase::Prepare,
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            request_receipt,
            action: ContactRejectAction::Reject,
        });
        let prepared: ContactOperationOutcome =
            http.post("/_arkret/self/contacts/reject", &prepare).await?;
        let (returned_operation_id, reservation_handle, event_draft) = match prepared {
            ContactOperationOutcome::Prepared {
                outcome:
                    ContactPreparedOutcome::Reject {
                        operation_id,
                        reservation_handle,
                        event_draft,
                        ..
                    },
            } => (operation_id, reservation_handle, event_draft),
            ContactOperationOutcome::Failed { outcome } => {
                anyhow::bail!("Contact reject prepare failed: {:?}", outcome.reason)
            }
            _ => anyhow::bail!("Contact reject prepare returned the wrong result kind"),
        };
        if returned_operation_id != operation_id {
            anyhow::bail!("Contact reject prepare changed operation_id");
        }
        let signed_event = crate::transport::contacts::sign_prepared_contact_event(
            &event_draft,
            arkret_wire::event_kind_str::CONTACT_REJECTED,
        )?;
        let seal_context =
            crate::transport::contacts::prepare_principal_successor_seal(http, &signed_event)
                .await?;
        let commit = ContactRejectRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id,
            idempotency_key,
            reservation_handle,
            signed_event: signed_event.event().clone(),
            control_proposal_ack: None,
        });
        match http
            .post::<_, ContactOperationOutcome>("/_arkret/self/contacts/reject", &commit)
            .await?
        {
            ContactOperationOutcome::Accepted { .. } => {
                crate::transport::contacts::submit_principal_successor_seal(
                    http,
                    seal_context,
                    &signed_event,
                )
                .await
            }
            ContactOperationOutcome::Failed { outcome } => {
                anyhow::bail!("Contact reject commit failed: {:?}", outcome.reason)
            }
            _ => anyhow::bail!("Contact reject commit returned the wrong result kind"),
        }
    } else {
        anyhow::bail!("unsupported Contact response action `{action}`")
    }
}

/// Verify the source-service receipt against the exact verified request Event and
/// the issuer key that was active when the source accepted it.  The list row is
/// only a carrier; none of its summary fields are an authority input here.
async fn verify_contact_request_receipt(
    http: &arkret_sdk::http_client::Client,
    receipt: &arkret_sdk::contact_operations::RequestAcceptanceReceipt,
) -> anyhow::Result<()> {
    receipt.validate_shape()?;
    let expected_request_digest = receipt.core.request_digest();
    let resolved = http
        .events_resolve(&arkret_sdk::EventsResolveRequestBody {
            event_ids: vec![receipt.core.request_event_ref.clone()],
            event_digests: vec![expected_request_digest.clone()],
            include_payload: Some(true),
            history_traversal_access: None,
            max_response_bytes: Some(arkret_sdk::MAX_PEER_RESOLVE_RESPONSE_BYTES),
        })
        .await?;
    let request = resolved
        .events
        .iter()
        .find(|event| event.event_id == receipt.core.request_event_ref)
        .ok_or_else(|| anyhow::anyhow!("Contact request receipt Event is not accepted"))?;
    let request_digest = arkret_sdk::Hash::new(
        request.event_digest_with_digest_suite(expected_request_digest.digest_suite()?)?,
    )?;
    if request_digest != expected_request_digest {
        anyhow::bail!("Contact request receipt does not bind the exact resolved Event");
    }
    let issuer_did = arkret_sdk::Did::new(
        receipt
            .signature
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller.to_owned())
            .ok_or_else(|| anyhow::anyhow!("Contact receipt verification method omits fragment"))?,
    )?;
    if arkret_sdk::project_did_to_core_id(&issuer_did)? != receipt.core.issuer_id {
        anyhow::bail!("Contact receipt proof controller differs from issuer");
    }
    let history =
        crate::identity::history::fetch_complete_identity_history(http, &issuer_did).await?;
    if history.did != issuer_did
        || history.method != arkret_sdk::DidMethodUri::Webvh
        || history.native_history == Some(false)
        || history.has_more
        || history.next_cursor.is_some()
    {
        anyhow::bail!("Contact receipt issuer did not return complete native did:webvh history");
    }
    let history_point = arkret_signatures::webvh::validate_webvh_history_at(
        &issuer_did,
        &history.entries,
        receipt.core.accepted_at,
    )
    .map_err(|error| anyhow::anyhow!("invalid Contact receipt issuer history: {error}"))?;
    let document: arkret_sdk::DidDocument = serde_json::from_value(history_point.document)?;
    let verification_method = receipt.signature.verification_method.as_str();
    if !did_document_assertion_method_contains(&document, verification_method) {
        anyhow::bail!(
            "Contact receipt verification method was not an assertionMethod at acceptance"
        );
    }
    let resolved_key =
        arkret_sdk::resolve_verification_method_key_from_document(&document, verification_method)?;
    if resolved_key.absolutize(&issuer_did)? != receipt.signature.verification_method {
        anyhow::bail!("Contact receipt verification method resolved to another issuer key");
    }
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&resolved_key.public_key.ed25519_bytes()?)?;
    arkret_sdk::verify_contact_request_acceptance_receipt(
        receipt,
        &request.event_id,
        &verifying_key,
    )?;
    Ok(())
}

fn did_document_assertion_method_contains(
    document: &arkret_sdk::DidDocument,
    expected: &str,
) -> bool {
    fn matches_reference(issuer: &arkret_sdk::Did, reference: &str, expected: &str) -> bool {
        if reference == expected {
            return true;
        }
        reference
            .strip_prefix('#')
            .is_some_and(|fragment| expected == format!("{}#{fragment}", issuer.as_str()))
    }

    document
        .raw_properties
        .get("assertionMethod")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|methods| {
            methods.iter().any(|method| match method {
                serde_json::Value::String(reference) => {
                    matches_reference(&document.id, reference, expected)
                }
                serde_json::Value::Object(object) => object
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|reference| matches_reference(&document.id, reference, expected)),
                _ => false,
            })
        })
}

pub async fn contacts(http: &arkret_sdk::http_client::Client) -> anyhow::Result<ContactList> {
    http.contacts_list().await.map_err(anyhow::Error::from)
}

/// Read the actor's `invite_receive_policy` ("who can invite me", U4).
///
/// Spec `invite-addressing.md` §5 / OpenAPI
/// `ak.self.invite_receive_policy.resource.get.v1`: served from the self plane at
/// `GET /_arkret/self/invite-receive-policy` and returns the bare
/// `arkret_sdk::InviteReceivePolicy` (soland echoes the stored override or
/// its recommended default). When the deployment does not yet wire this
/// surface the caller treats 404/501/405 as "use defaults" rather than a
/// hard error; the settings surface keeps the SDK fail-closed default.
pub async fn get_invite_receive_policy(
    http: &arkret_sdk::http_client::Client,
    account_id: &arkret_sdk::AccountId,
) -> anyhow::Result<crate::models::InviteReceivePolicy> {
    let policy: crate::models::InviteReceivePolicy =
        http.get("/_arkret/self/invite-receive-policy").await?;
    if &policy.account_id != account_id {
        anyhow::bail!("invite receive policy belongs to a different account");
    }
    Ok(policy)
}

/// Persist the actor's `invite_receive_policy` (U4).
///
/// Spec `ak.self.invite_receive_policy.resource.replace.v1`:
/// `PUT /_arkret/self/invite-receive-policy` with the bare
/// `arkret_sdk::InviteReceivePolicy` as the body. The handler enforces
/// `account_id == session account` and requires the `schema` constant, so the
/// caller MUST stamp both before calling (see the U4 view); the server
/// echoes the stored policy back.
pub async fn set_invite_receive_policy(
    http: &arkret_sdk::http_client::Client,
    policy: &crate::models::InviteReceivePolicy,
) -> anyhow::Result<crate::models::InviteReceivePolicy> {
    let stored: crate::models::InviteReceivePolicy = http
        .put("/_arkret/self/invite-receive-policy", policy)
        .await?;
    if stored.account_id != policy.account_id {
        anyhow::bail!("saved invite receive policy belongs to a different account");
    }
    Ok(stored)
}

/// Resolve the pair's stable Direct Conversation coordinates.
///
/// This is query-only and never authors anything. Creation is founder-only: only the participant
/// derived from the pair's root Contact round may author the founding unit, which is what removes
/// the cross-server creation race. Callers that turn out to be the founder submit separately via
/// [`direct_conversation_found`].
pub async fn direct_conversation_resolve(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    peer: &str,
    peer_controller: Option<&str>,
    enable_owned_agent_reply: bool,
) -> anyhow::Result<arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome> {
    let http = api.http();
    let peer_descriptor = direct_conversation_peer_descriptor(peer, peer_controller)?;
    let peer_actor = peer_descriptor.contact_actor_id();
    let body = arkret_sdk::direct_conversation_ops::DirectConversationResolveRequestBody {
        peer: peer_descriptor,
    };
    let outcome = http
        .direct_conversation_resolve(&body)
        .await
        .map_err(anyhow::Error::from)?;
    if enable_owned_agent_reply && direct_conversation_coordinates(&outcome).is_some() {
        preserve_resolved_direct_conversation(
            peer,
            &outcome,
            ensure_owned_agent_direct_reply(
                http,
                state_store,
                peer_actor.signing_principal_id().as_str(),
                &outcome,
            )
            .await,
        );
    }
    if direct_conversation_coordinates(&outcome).is_some() {
        remember_direct_conversation_peer(&mut state_store, peer, &outcome);
    }
    Ok(outcome)
}

/// Submit the exact caller-authored founding unit selected by Garth's runtime-neutral gate.
/// Ambiguous network failures are retried by passing the same `prepared` value again; this helper
/// never authors or substitutes coordinates.
pub async fn direct_conversation_found(
    submitter: &crate::event_submit::EventSubmitter,
    resolve: &arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome,
    prepared: arkret_sdk::direct_conversation_ops::DirectConversationFoundingUnitSubmission,
) -> anyhow::Result<arkret_sdk::direct_conversation_ops::DirectConversationFoundingAcceptanceOutcome>
{
    match garth::direct_conversation_founding_action(resolve, Some(prepared))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
    {
        garth::DirectConversationFoundingAction::Submit(unit) => {
            submitter
                .submit_direct_conversation_founding_durable(*unit)
                .await
        }
        _ => Err(anyhow::anyhow!(
            "Direct Conversation resolve state does not permit founding submission"
        )),
    }
}

/// Author, sign and durably submit the resolver-authorized closed founding
/// unit.  The resolver material is copied verbatim; Garth persists the exact
/// signed carrier before its first network attempt.
pub async fn create_direct_conversation_from_resolve(
    submitter: &crate::event_submit::EventSubmitter,
    resolve: &arkret_sdk::DirectConversationResolveOutcome,
    founder_account: &arkret_sdk::AccountId,
    peer_account: &arkret_sdk::AccountId,
) -> anyhow::Result<arkret_sdk::DirectConversationFoundingAcceptanceOutcome> {
    let arkret_sdk::DirectConversationResolveOutcome::CreationRequired {
        next_founding_input,
    } = resolve
    else {
        anyhow::bail!("Direct Conversation resolver did not grant founding authority");
    };
    anyhow::ensure!(
        submitter.authority()? == founder_account,
        "Direct Conversation founder differs from the authenticated AccountId"
    );
    let trust_domain = submitter.events_describe().await?.trust_domain;
    let notary = submitter.current_service_notary().await?;
    let steps = crate::event_builders::build_direct_conversation_founding_steps(
        founder_account,
        peer_account,
        notary,
        trust_domain,
        next_founding_input,
    )?;
    let signed = submitter.author_event_unit(steps).await?;
    let events: [arkret_sdk::EventInitialSubmission; 4] = signed
        .into_iter()
        .map(|event| arkret_sdk::EventInitialSubmission::online(event.into_event()))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Direct Conversation founding unit lost its closed length"))?;
    let prepared = arkret_sdk::DirectConversationFoundingUnitSubmission {
        unit_kind: arkret_sdk::DirectConversationFoundingUnitKind::DirectConversationFounding,
        idempotency_key: arkret_sdk::IdempotencyKey::new(crate::operation::uuid_v7())
            .map_err(anyhow::Error::msg)?,
        events,
        founding_authority_evidence: next_founding_input.founding_authority_evidence.clone(),
        cba_proof_bundles: Vec::new(),
    };
    direct_conversation_found(submitter, resolve, prepared).await
}

fn direct_conversation_peer_descriptor(
    peer: &str,
    peer_controller: Option<&str>,
) -> anyhow::Result<arkret_sdk::contact_operations::ContactPeer> {
    let actor_id: arkret_sdk::ActorId = serde_json::from_str(peer)?;
    Ok(match peer_controller {
        Some(controller_id) => arkret_sdk::contact_operations::ContactPeer::Agent {
            actor_id,
            controller_account_id: serde_json::from_str(controller_id)?,
        },
        None => arkret_sdk::contact_operations::ContactPeer::Human {
            account_id: actor_id.as_account_id().cloned().ok_or_else(|| {
                anyhow::anyhow!("human Contact peer requires a complete AccountId actor")
            })?,
        },
    })
}

fn direct_conversation_peer_cache_key(realm_id: &str, strand_id: &str) -> String {
    format!("direct_conversation.peer.{realm_id}.{strand_id}")
}

pub(crate) fn direct_conversation_coordinates(
    outcome: &arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome,
) -> Option<&arkret_sdk::direct_conversation_ops::DirectConversationCoordinates> {
    outcome.coordinates()
}

/// Product-level status for the Direct Conversation entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectConversationEntry {
    /// This user is the founder and may create the conversation now.
    ReadyToCreate,
    /// The other participant is the founder. Waiting never grants create authority here, so the UI
    /// shows a waiting state rather than offering a create action.
    AwaitingFounder,
    /// Coordinates exist; the conversation can be opened.
    Openable,
    /// Coordinates exist but sending is currently blocked.
    Suspended,
    /// The resolver could not classify the pair yet.
    Unavailable,
}

pub(crate) fn direct_conversation_entry(
    outcome: &arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome,
) -> DirectConversationEntry {
    use arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome as Outcome;
    match outcome {
        Outcome::CreationRequired { .. } => DirectConversationEntry::ReadyToCreate,
        Outcome::AwaitingFounder { .. } => DirectConversationEntry::AwaitingFounder,
        Outcome::Provisional { .. } | Outcome::Found { .. } => DirectConversationEntry::Openable,
        Outcome::Suspended { .. } => DirectConversationEntry::Suspended,
        Outcome::CreationBlocked { .. } | Outcome::TemporarilyUnavailable { .. } => {
            DirectConversationEntry::Unavailable
        }
    }
}

/// Holder-device-only blockers are merged after the wire outcome is decoded;
/// they are deliberately never inserted into the serializable resolver DTO.
pub(crate) fn direct_conversation_client_local_blockers(
    state_store: &crate::state::LocalStateStore,
    peer: &str,
    outcome: &arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome,
) -> std::collections::BTreeSet<
    arkret_sdk::direct_conversation_ops::DirectConversationClientLocalBlocker,
> {
    use arkret_sdk::direct_conversation_ops::DirectConversationClientLocalBlocker as Local;

    let mut blockers = std::collections::BTreeSet::new();
    if crate::account_data::is_blocked(&state_store.client_blocklist(), peer) {
        blockers.insert(Local::PersonalBlocked);
    }
    if let Some(coordinates) = outcome.coordinates() {
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: coordinates.realm_id.clone(),
        };
        let history_unavailable = scope
            .canonical_mls_group_id()
            .ok()
            .and_then(|group_id| {
                crate::state::mls_scope_snapshot_key_for_group(&scope, &group_id).ok()
            })
            .and_then(|scope_group_key| {
                crate::secure_key_store::load_history_secrets(&scope_group_key)
            })
            .is_none_or(|secrets| secrets.is_empty());
        if history_unavailable {
            blockers.insert(Local::HistoryKeyUnavailable);
        }
    }
    blockers
}

pub(crate) fn direct_conversation_entry_with_local_blockers(
    outcome: &arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome,
    local_blockers: &std::collections::BTreeSet<
        arkret_sdk::direct_conversation_ops::DirectConversationClientLocalBlocker,
    >,
) -> DirectConversationEntry {
    let entry = direct_conversation_entry(outcome);
    if local_blockers.is_empty() {
        entry
    } else if matches!(entry, DirectConversationEntry::Openable) {
        DirectConversationEntry::Suspended
    } else {
        entry
    }
}

const DIRECT_CONVERSATION_PEER_CACHE_OBFUSCATION_KEY: &str = "ak.local.direct_conversation.peer.v1";

fn remember_direct_conversation_peer(
    state_store: &mut SyncSignal<crate::state::LocalStateStore>,
    peer: &str,
    outcome: &arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome,
) {
    let Some(coordinates) = direct_conversation_coordinates(outcome) else {
        return;
    };
    state_store.write().save_private_data(
        DIRECT_CONVERSATION_PEER_CACHE_OBFUSCATION_KEY,
        direct_conversation_peer_cache_key(
            coordinates.realm_id.as_str(),
            coordinates.main_strand_id.as_str(),
        ),
        peer,
    );
}

pub(crate) fn cached_direct_conversation_peer(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    strand_id: &str,
) -> Option<String> {
    state_store.load_private_data(
        DIRECT_CONVERSATION_PEER_CACHE_OBFUSCATION_KEY,
        &direct_conversation_peer_cache_key(realm_id, strand_id),
    )
}

/// Opening a canonical Direct Conversation and changing an Agent's participation
/// policy are separate protocol operations.  The latter is best-effort here: a
/// stale selection state or restrictive current target policy may stop
/// the Agent from replying, but MUST NOT turn an already resolved conversation
/// into an unavailable navigation target.
fn preserve_resolved_direct_conversation(
    agent_id: &str,
    outcome: &arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome,
    reply_enablement: anyhow::Result<()>,
) {
    if let Err(error) = reply_enablement {
        tracing::warn!(
            error = %error,
            agent_id,
            realm_id = direct_conversation_coordinates(outcome).map(|value| value.realm_id.to_string()),
            strand_id = direct_conversation_coordinates(outcome).map(|value| value.main_strand_id.to_string()),
            "owned Agent Direct Conversation resolved, but reply participation could not be enabled"
        );
    }
}

async fn ensure_owned_agent_direct_reply(
    http: &arkret_sdk::http_client::Client,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    agent_id: &str,
    outcome: &arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome,
) -> anyhow::Result<()> {
    let coordinates = direct_conversation_coordinates(outcome)
        .ok_or_else(|| anyhow::anyhow!("owned-Agent Direct Conversation omitted realm_id"))?;
    let realm_id = coordinates.realm_id.clone();
    let strand_id = coordinates.main_strand_id.clone();
    let scope = arkret_sdk::ParticipationScope::Strand {
        realm_id,
        strand_id,
    };
    let existing = http
        .agent_participation_get(agent_id)
        .await
        .map_err(anyhow::Error::from)?;
    // Opening an already configured DM is a read/navigation operation.  Do
    // not author another byte-equivalent capability Control Move on every
    // contact click: each accepted governance write legitimately pauses E2EE
    // until the MLS covered-Seal accumulator advances.
    if !owned_agent_reply_update_needed(&existing, &scope) {
        return Ok(());
    }
    let mut selection = existing
        .agent_participation_entries
        .iter()
        .find(|entry| entry.scope == scope)
        .map(|entry| entry.selection)
        .unwrap_or_default();
    selection.reply_message = true;
    let updated = replace_agent_participation(http, agent_id, scope.clone(), selection).await?;
    if !participation_reply_is_effective(&updated, &scope) {
        anyhow::bail!("owned-Agent Direct Conversation reply participation remains disabled");
    }
    // The capability grant is a governance Control Move.  Arm the known
    // coverage repair immediately so the first human message does not have to
    // discover the stale MLS accumulator by failing once.
    state_store
        .write()
        .record_mls_coverage_stale(
            scope.realm_id().as_str().to_owned(),
            None,
            "agent reply participation grant changed the Realm governance frontier",
        )
        .map_err(anyhow::Error::msg)?;
    Ok(())
}

pub(crate) async fn replace_agent_participation(
    http: &arkret_sdk::http_client::Client,
    agent_id: &str,
    scope: arkret_sdk::ParticipationScope,
    selection: arkret_sdk::ParticipationBits,
) -> anyhow::Result<arkret_sdk::AgentParticipationOutcome> {
    let current = http.agent_participation_get(agent_id).await?;
    let expected_version = current
        .agent_participation_entries
        .iter()
        .find(|entry| entry.scope == scope)
        .map(|entry| entry.version)
        .unwrap_or(0);
    let request = arkret_sdk::ParticipationReplaceRequestBody {
        target_scope: scope,
        selection,
        expected_version,
    };
    http.agent_participation_replace(agent_id, &request)
        .await
        .map_err(Into::into)
}

fn participation_reply_is_effective(
    outcome: &arkret_sdk::AgentParticipationOutcome,
    scope: &arkret_sdk::ParticipationScope,
) -> bool {
    outcome
        .agent_participation_entries
        .iter()
        .any(|entry| &entry.scope == scope && entry.selection.reply_message)
}

fn owned_agent_reply_update_needed(
    outcome: &arkret_sdk::AgentParticipationOutcome,
    scope: &arkret_sdk::ParticipationScope,
) -> bool {
    !participation_reply_is_effective(outcome, scope)
}

/// List the holder-private consent cells visible to the authenticated
/// actor (cells where the actor is either holder or peer). Spec
/// `identity/consent-model.md` §3 / OpenAPI `ak.self.consent.read.list.v1`.
pub async fn consent_cells(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::ConsentCellList> {
    http.get(arkret_wire::PATH_SELF_CONSENT_CELLS)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn identity_describe(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::ServiceDescribe> {
    http.identity_describe()
        .await
        .map_err(|error| anyhow::anyhow!("identity describe: {error}"))
}

pub async fn identity_resolve(
    http: &arkret_sdk::http_client::Client,
    did: &str,
) -> anyhow::Result<IdentityResolveOutcome> {
    let subject = arkret_sdk::Did::new(did.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid did `{did}`: {err}"))?;
    let body = arkret_models_identity::IdentityResolveRequestBody {
        did: subject,
        requested_evidence_kinds: Vec::new(),
    };
    http.identity_resolve(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn sync_describe(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_models_discovery::ServiceDescribe> {
    http.account_describe().await.map_err(anyhow::Error::from)
}

fn current_account_from_viewer(
    viewer: arkret_models_collaboration::account_lifecycle::AccountView,
) -> CurrentAccount {
    let display_name = viewer.profile.as_ref().and_then(|profile| {
        let value = profile.display_name.trim();
        (!value.is_empty()).then(|| value.to_owned())
    });
    let created_at = viewer
        .profile
        .as_ref()
        .map(|profile| arkret_sdk::canonical::format_timestamp_canonical(profile.created_at))
        .unwrap_or_default();
    CurrentAccount {
        principal_id: viewer.principal_id.clone(),
        handle: primary_handle_from_viewer(&viewer),
        display_name,
        created_at,
    }
}

pub(crate) fn primary_handle_from_viewer(
    viewer: &arkret_models_collaboration::account_lifecycle::AccountView,
) -> String {
    viewer
        .primary_handle_claim
        .as_ref()
        .filter(|claim| {
            claim.subject_account_id.principal_id == viewer.principal_id
                && claim.binding_state == arkret_models_identity::HandleBindingState::Verified
        })
        .map(|claim| &claim.handle)
        .map(|handle| handle.canonical().trim())
        .filter(|handle| !handle.is_empty())
        .unwrap_or_default()
        .to_owned()
}

/// Tombstone a contact relationship via `contacts/tombstone`. When
/// `block_peer` is true the protocol additionally records a block so the
/// peer can no longer re-request; this is the block path (U5).
///
/// Protocol contract: the prepare request binds `block_peer`; the service
/// applies that holder-private policy side effect with the Contact commit.
pub async fn tombstone_contact(
    http: &arkret_sdk::http_client::Client,
    peer: &str,
    block_peer: bool,
) -> anyhow::Result<()> {
    use arkret_sdk::contact_operations::{
        ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome, ContactPreparePhase,
        ContactPreparedOutcome, ContactTombstonePrepareRequestBody, ContactTombstoneRequestBody,
    };

    let peer_actor: arkret_sdk::ActorId = serde_json::from_str(peer)?;
    let contacts = http.contacts_list().await?;
    let row = contacts
        .contacts
        .into_iter()
        .find(|row| {
            row.state == arkret_sdk::ContactState::Accepted
                && row.peer.contact_actor_id() == peer_actor
        })
        .ok_or_else(|| {
            anyhow::anyhow!("Contact tombstone for `{peer}` requires a fresh accepted list row")
        })?;
    let next = row.next_prepare_input.ok_or_else(|| {
        anyhow::anyhow!("accepted Contact row omitted its exact next_prepare_input")
    })?;
    next.validate_shape()?;
    let nonce = crate::operation::uuid_v7();
    let operation_id =
        arkret_sdk::ProtocolOperationId::new(format!("ak:operation:contact.tombstone.{nonce}"))
            .map_err(anyhow::Error::msg)?;
    let idempotency_key = arkret_sdk::IdempotencyKey::new(nonce).map_err(anyhow::Error::msg)?;
    let prepare = ContactTombstoneRequestBody::Prepare(ContactTombstonePrepareRequestBody {
        phase: ContactPreparePhase::Prepare,
        operation_id: operation_id.clone(),
        idempotency_key: idempotency_key.clone(),
        peer: row.peer,
        contact_round_id: next.contact_round_id,
        version: next.version,
        predecessor_event_ref: next.predecessor_event_ref,
        block_peer,
    });
    let prepared = http.contacts_tombstone(&prepare).await?;
    let (returned_operation_id, reservation_handle, event_draft) = match prepared {
        ContactOperationOutcome::Prepared {
            outcome:
                ContactPreparedOutcome::Tombstone {
                    operation_id,
                    reservation_handle,
                    event_draft,
                    ..
                },
        } => (operation_id, reservation_handle, event_draft),
        ContactOperationOutcome::Failed { outcome } => {
            anyhow::bail!("Contact tombstone prepare failed: {:?}", outcome.reason)
        }
        _ => anyhow::bail!("Contact tombstone prepare returned the wrong result kind"),
    };
    if returned_operation_id != operation_id {
        anyhow::bail!("Contact tombstone prepare changed operation_id");
    }
    let signed_event = crate::transport::contacts::sign_prepared_contact_event(
        &event_draft,
        arkret_wire::event_kind_str::CONTACT_TOMBSTONE,
    )?;
    let seal_context =
        crate::transport::contacts::prepare_principal_successor_seal(http, &signed_event).await?;
    let commit = ContactTombstoneRequestBody::Commit(ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id,
        idempotency_key,
        reservation_handle,
        signed_event: signed_event.event().clone(),
        control_proposal_ack: None,
    });
    match http.contacts_tombstone(&commit).await? {
        ContactOperationOutcome::Accepted { .. } => {
            crate::transport::contacts::submit_principal_successor_seal(
                http,
                seal_context,
                &signed_event,
            )
            .await
        }
        ContactOperationOutcome::Failed { outcome } => {
            anyhow::bail!("Contact tombstone commit failed: {:?}", outcome.reason)
        }
        _ => anyhow::bail!("Contact tombstone commit returned the wrong result kind"),
    }
}

/// Read one holder-private consent cell. Spec OpenAPI
/// `ak.self.consent.resource.get.v1`.
pub async fn consent_cell(
    http: &arkret_sdk::http_client::Client,
    holder: &str,
    peer: &str,
    scope: &str,
) -> anyhow::Result<arkret_sdk::ConsentCellView> {
    let path = format!(
        "{}/{}?peer={}&consent_scope={}",
        arkret_wire::PATH_SELF_CONSENT_CELLS,
        crate::wire_helpers::path_component(holder.trim()),
        crate::wire_helpers::path_component(peer.trim()),
        crate::wire_helpers::path_component(scope.trim()),
    );
    http.get(&path).await.map_err(anyhow::Error::from)
}

/// Grant scoped consent to `peer` from the holder cell. `expires_at` is an
/// optional RFC 3339 time window upper bound. Spec OpenAPI
/// `ak.self.consent.command.grant.v1`.
///
/// The Control Move is authored and signed here: its `consent_id` is the cell
/// subject and its `event_id` becomes the or_set add dot, so neither is the
/// server's to choose. A cell that already exists keeps its `consent_id`; a new
/// one gets a freshly minted producer-allocated id.
pub async fn grant_consent(
    submitter: &crate::event_submit::EventSubmitter,
    holder: &str,
    peer: &str,
    scope: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<arkret_sdk::ConsentCellView> {
    // Reuse the existing subject when there is one, so a re-grant lands in the
    // same cell instead of opening a second one for the same (peer, scope).
    let consent_id = match consent_cell(submitter.http(), holder, peer, scope).await {
        Ok(cell) => crate::operation::ak_ops::consent_id_from_cell_id(&cell.cell_id)?,
        Err(_) => arkret_sdk::ConsentId::new_v7_at(crate::clock::now_unix_ms()),
    };
    let holder_did = did_for_request_field("holder", holder)?;
    let principal_control_realm_id =
        crate::identity::principal_control::resolve_accepted(submitter.http(), &holder_did).await?;
    let event = crate::operation::ak_ops::consent_grant(
        principal_control_realm_id.as_str(),
        holder.trim(),
        &consent_id,
        peer,
        scope,
        expires_at,
    )?
    .build_sdk_event("inkson")?;
    let body = arkret_sdk::ConsentGrantRequestBody {
        grant_event: arkret_wire::EventInitialSubmission::online(
            submitter
                .author_for_direct_submission(&event)
                .await?
                .into_event(),
        ),
    };
    let path = format!(
        "{}/{}/grant",
        arkret_wire::PATH_SELF_CONSENT_CELLS,
        crate::wire_helpers::path_component(holder.trim()),
    );
    submitter
        .http()
        .post(&path, &body)
        .await
        .map_err(anyhow::Error::from)
}

/// Revoke scoped consent from `peer`. Spec OpenAPI
/// `ak.self.consent.command.revoke.v1`.
///
/// The current cell is read first because the Control Move MUST name the exact
/// dots being removed; there is nothing the server could substitute for that
/// without reintroducing the concurrent-revoke race the dot model exists to close.
pub async fn revoke_consent(
    submitter: &crate::event_submit::EventSubmitter,
    holder: &str,
    peer: &str,
    scope: &str,
) -> anyhow::Result<arkret_sdk::ConsentCellView> {
    let cell = consent_cell(submitter.http(), holder, peer, scope).await?;
    let consent_id = crate::operation::ak_ops::consent_id_from_cell_id(&cell.cell_id)?;
    let holder_did = did_for_request_field("holder", holder)?;
    let principal_control_realm_id =
        crate::identity::principal_control::resolve_accepted(submitter.http(), &holder_did).await?;
    let event = crate::operation::ak_ops::consent_revoke(
        principal_control_realm_id.as_str(),
        holder.trim(),
        &consent_id,
        &cell.active_grant_dots,
    )?
    .build_sdk_event("inkson")?;
    let body = arkret_sdk::ConsentRevokeRequestBody {
        revoke_event: arkret_wire::EventInitialSubmission::online(
            submitter
                .author_for_direct_submission(&event)
                .await?
                .into_event(),
        ),
    };
    let path = format!(
        "{}/{}/revoke",
        arkret_wire::PATH_SELF_CONSENT_CELLS,
        crate::wire_helpers::path_component(holder.trim()),
    );
    submitter
        .http()
        .post(&path, &body)
        .await
        .map_err(anyhow::Error::from)
}

/// Open an outbound consent request: ask `holder` to grant the
/// authenticated actor the given scope. The response is deliberately opaque.
/// Spec OpenAPI `ak.self.consent.command.request.v1`.
pub async fn request_consent(
    http: &arkret_sdk::http_client::Client,
    holder: &str,
    scope: &str,
) -> anyhow::Result<arkret_sdk::ConsentRequestOutcome> {
    let body = arkret_sdk::ConsentRequestRequestBody {
        holder_principal_id: crate::mls_api_helpers::principal_core_id(holder)?,
        consent_scope: Some(scope.trim().parse()?),
    };
    http.post(arkret_wire::PATH_SELF_CONSENT_REQUEST, &body)
        .await
        .map_err(anyhow::Error::from)
}

/// Submit a `did:webvh` DID operation (inception / rotation) to soland's
/// embedded identity provider. Spec op
/// `ak.root.identity.command.submit_did_operation.v1`
/// (`POST /_arkret/root/identity/submit-did-operation`). The body is the
/// SDK-built `submit_body` from `arkret_sdk::webvh::prepare_inception`.
pub async fn submit_did_operation(
    http: &arkret_sdk::http_client::Client,
    body: &arkret_models_identity::DidOperationSubmitRequestBody,
) -> anyhow::Result<arkret_models_identity::DidOperationSubmitOutcome> {
    http.identity_submit_did_operation(body)
        .await
        .map_err(anyhow::Error::from)
}

const MAX_ACCOUNT_DATA_CAS_ATTEMPTS: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct AccountDataSnapshot {
    pub revision: u64,
    pub entry: Option<arkret_sdk::AccountDataRow>,
}

fn account_data_snapshot_from_details(
    type_key: &str,
    details: &std::collections::BTreeMap<String, Value>,
) -> anyhow::Result<AccountDataSnapshot> {
    let details = serde_json::from_value::<arkret_sdk::AccountDataCasConflictDetails>(
        Value::Object(details.clone().into_iter().collect()),
    )
    .map_err(|error| anyhow::anyhow!("invalid account_data CAS details: {error}"))?;
    if details.account_data_key != type_key {
        anyhow::bail!(
            "account_data CAS details key mismatch: expected {type_key}, got {}",
            details.account_data_key
        );
    }
    if let Some(entry) = details.current_entry.as_ref()
        && (entry.account_data_key != type_key || entry.revision != details.current_revision)
    {
        anyhow::bail!("account_data CAS details current_entry does not match current revision");
    }
    Ok(AccountDataSnapshot {
        revision: details.current_revision,
        entry: details.current_entry,
    })
}

fn account_data_conflict_snapshot(
    type_key: &str,
    error: &arkret_sdk::http_client::Error,
) -> anyhow::Result<Option<AccountDataSnapshot>> {
    let arkret_sdk::http_client::Error::Api { status: 409, error } = error else {
        return Ok(None);
    };
    if error.error.code != "cas_conflict" {
        return Ok(None);
    }
    account_data_snapshot_from_details(type_key, &error.error.details).map(Some)
}

pub(crate) async fn account_data_snapshot(
    http: &arkret_sdk::http_client::Client,
    type_key: &str,
) -> anyhow::Result<AccountDataSnapshot> {
    match http.account_data_get(type_key).await {
        Ok(entry) => {
            if entry.account_data_key != type_key {
                anyhow::bail!("account_data response key mismatch");
            }
            Ok(AccountDataSnapshot {
                revision: entry.revision,
                entry: Some(entry),
            })
        }
        Err(arkret_sdk::http_client::Error::Api { status: 404, error }) => {
            account_data_snapshot_from_details(type_key, &error.error.details)
        }
        Err(error) => Err(error.into()),
    }
}

/// The holder whose account data this client writes.
///
/// `ak.account_data.set`'s actor-private cell subject is
/// `composite[envelope.actor_id, payload.key]`, so the Event's actor is not a
/// formality: it is half the cell address. The holder must sign, which is why this
/// is resolved here rather than left to the server — soland used to author these
/// Events under its own DID, which put every holder's value for one key into a
/// single cell keyed by the service.
fn account_data_holder() -> anyhow::Result<(arkret_sdk::Did, arkret_sdk::AccountId)> {
    let scope = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("no active account; cannot author an account_data Event"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active account signer is unavailable"))?;
    let did = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    anyhow::ensure!(
        arkret_sdk::project_did_to_core_id(&did)? == scope.authority.principal_id,
        "active signer does not match the account authority"
    );
    Ok((did, scope.authority))
}

/// Build and sign the `ak.account_data.set` the endpoint now requires.
async fn account_data_set_submission(
    submitter: &EventSubmitter,
    type_key: &str,
    value: Option<Value>,
    expected_revision: u64,
) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
    let (holder, _) = account_data_holder()?;
    let realm_id =
        crate::identity::principal_control::resolve_accepted(submitter.http(), &holder).await?;
    let builder = match value {
        Some(value) => crate::account_data::build_account_data_set(
            realm_id.as_str(),
            holder.as_str(),
            type_key,
            value,
            expected_revision,
        ),
        None => crate::account_data::build_account_data_tombstone(
            realm_id.as_str(),
            holder.as_str(),
            type_key,
            expected_revision,
        ),
    }?;
    let event = builder.build_sdk_event("inkson")?;
    let authored = submitter
        .author_independent_events(vec![event.into_intent()])
        .await?;
    submitter
        .prepare_initial_submissions(&authored)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("account_data submission was not prepared"))
}

/// Apply a domain merge against the latest Account Data value and retry
/// compare-and-set conflicts with the authoritative conflict snapshot.
pub(crate) async fn update_account_data_with_merge<F>(
    submitter: &EventSubmitter,
    type_key: &str,
    mut merge: F,
) -> anyhow::Result<Value>
where
    F: FnMut(&AccountDataSnapshot) -> anyhow::Result<Value>,
{
    let mut snapshot = account_data_snapshot(submitter.http(), type_key).await?;
    for attempt in 1..=MAX_ACCOUNT_DATA_CAS_ATTEMPTS {
        let body = arkret_sdk::AccountDataReplaceRequestBody {
            set_event: account_data_set_submission(
                submitter,
                type_key,
                Some(merge(&snapshot)?),
                snapshot.revision,
            )
            .await?,
        };
        match submitter.http().account_data_replace(type_key, &body).await {
            Ok(entry) => return serde_json::to_value(entry).map_err(anyhow::Error::from),
            Err(error) => {
                let Some(current) = account_data_conflict_snapshot(type_key, &error)? else {
                    return Err(error.into());
                };
                if attempt == MAX_ACCOUNT_DATA_CAS_ATTEMPTS {
                    anyhow::bail!(
                        "account_data CAS retry exhausted after {MAX_ACCOUNT_DATA_CAS_ATTEMPTS} attempts: {error}"
                    );
                }
                snapshot = current;
            }
        }
    }
    unreachable!("bounded account_data CAS loop always returns")
}

/// Replace a per-account whole value through the canonical CAS binding.
///
/// This is the explicit whole-value replacement strategy: the latest local
/// command remains the candidate after a conflict. Domains with richer merge
/// rules use `update_account_data_with_merge` directly.
pub async fn set_account_data(
    submitter: &EventSubmitter,
    type_key: &str,
    content: Value,
) -> anyhow::Result<Value> {
    update_account_data_with_merge(submitter, type_key, |_| Ok(content.clone())).await
}

/// Delete an account-data entry through the versioned physical-delete binding.
pub async fn delete_account_data(submitter: &EventSubmitter, type_key: &str) -> anyhow::Result<()> {
    let mut snapshot = account_data_snapshot(submitter.http(), type_key).await?;
    for attempt in 1..=MAX_ACCOUNT_DATA_CAS_ATTEMPTS {
        let body = arkret_sdk::AccountDataDeleteRequestBody {
            set_event: account_data_set_submission(submitter, type_key, None, snapshot.revision)
                .await?,
        };
        match submitter.http().account_data_delete(type_key, &body).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                let Some(current) = account_data_conflict_snapshot(type_key, &error)? else {
                    return Err(error.into());
                };
                if attempt == MAX_ACCOUNT_DATA_CAS_ATTEMPTS {
                    anyhow::bail!(
                        "account_data delete CAS retry exhausted after {MAX_ACCOUNT_DATA_CAS_ATTEMPTS} attempts: {error}"
                    );
                }
                snapshot = current;
            }
        }
    }
    unreachable!("bounded account_data delete CAS loop always returns")
}

/// Create or update a scheduled-send plan (spec `models/personal-productivity.md`
/// §4): the plan is validated, encrypted, and written to
/// `ak.scheduled_send.v1:<scheduled_send_id>` through the account-data
/// `cas_register` loop; a `cas_conflict` re-reads the authoritative entry,
/// merges on decrypted plaintext, and retries with the new
/// `expected_revision`.
pub async fn put_scheduled_send_plan(
    submitter: &EventSubmitter,
    value: &arkret_sdk::ScheduledSendValue,
) -> anyhow::Result<()> {
    crate::account_data::validate_scheduled_send_value(value)?;
    let key =
        crate::account_data::scheduled_send_account_data_key(value.scheduled_send_id.as_str())?;
    let (_, authority) = account_data_holder()?;
    update_account_data_with_merge(submitter, &key, |snapshot| {
        crate::account_data::merge_scheduled_send_account_data(
            &authority,
            &key,
            value,
            snapshot.entry.as_ref(),
        )
    })
    .await?;
    Ok(())
}

/// Cancel a scheduled-send plan by deleting its account-data entry through
/// the same CAS binding (spec §4: a plan is principal-private state, so
/// cancellation is the account-data delete, not a shared Event).
pub async fn cancel_scheduled_send_plan(
    submitter: &EventSubmitter,
    scheduled_send_id: &str,
) -> anyhow::Result<()> {
    let key = crate::account_data::scheduled_send_account_data_key(scheduled_send_id)?;
    delete_account_data(submitter, &key).await
}

pub async fn submit_read_cursor_advance(
    submitter: &EventSubmitter,
    marker: &crate::state::ReadMarkerRecord,
) -> anyhow::Result<arkret_sdk::ReadMarkerOutcome> {
    let payload = arkret_sdk::ReadCursor {
        id: arkret_sdk::ReadCursorId::new(marker.body.id.clone())?,
        schema: marker.body.schema.clone(),
        actor_id: crate::mls_api_helpers::local_account_actor_id(&marker.actor)?,
        device_id: arkret_sdk::DeviceId::new(marker.device_id.clone())?,
        realm_id: arkret_sdk::RealmId::new(marker.body.realm_id.clone())?,
        read_scope: marker.body.read_scope.clone(),
        position: marker.body.position.clone(),
        updated_at: marker.updated_at,
    };
    let event = crate::operation::TypedOperationBuilder::new::<
        arkret_sdk::event_spec::ReadCursorAdvance,
    >(marker.body.realm_id.clone(), marker.actor.clone(), payload)
    .created_at(marker.updated_at)
    .build_sdk_event("inkson")?;
    let authored = submitter
        .author_independent_events(vec![event.into_intent()])
        .await?;
    let advance_event = submitter
        .prepare_initial_submissions(&authored)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("read cursor submission was not prepared"))?;
    let body = arkret_sdk::ReadCursorAdvanceRequestBody { advance_event };
    submitter
        .http()
        .post("/_arkret/self/read-cursors", &body)
        .await
        .map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn account_data_cas_conflict_uses_authoritative_current_entry() {
        let current_entry = json!({
            "account_data_key": "ak.client.ui_state",
            "revision": 8,
            "content": {"ciphertext": "current"},
            "updated_at": "2026-07-30T00:00:00.000Z"
        });
        let error = arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(
                arkret_wire::ErrorEnvelope::new("cas_conflict", "expected_revision does not match")
                    .with_detail("account_data_key", json!("ak.client.ui_state"))
                    .with_detail("current_revision", json!(8))
                    .with_detail("current_entry", current_entry),
            ),
        };

        let snapshot = account_data_conflict_snapshot("ak.client.ui_state", &error)
            .unwrap()
            .expect("CAS conflict snapshot");
        assert_eq!(snapshot.revision, 8);
        assert_eq!(
            snapshot.entry.expect("live entry").content,
            json!({"ciphertext": "current"})
        );
    }

    #[test]
    fn account_data_cas_conflict_rejects_mismatched_entry_revision() {
        let error = arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(
                arkret_wire::ErrorEnvelope::new("cas_conflict", "expected_revision does not match")
                    .with_detail("account_data_key", json!("ak.client.ui_state"))
                    .with_detail("current_revision", json!(8))
                    .with_detail(
                        "current_entry",
                        json!({
                            "account_data_key": "ak.client.ui_state",
                            "revision": 7,
                            "content": {"ciphertext": "stale"},
                            "updated_at": "2026-07-30T00:00:00.000Z"
                        }),
                    ),
            ),
        };

        assert!(account_data_conflict_snapshot("ak.client.ui_state", &error).is_err());
    }

    #[test]
    fn account_viewer_projection_uses_signed_handle_claim() {
        let viewer: arkret_models_collaboration::account_lifecycle::AccountView =
            serde_json::from_value(json!({
                "principal_id": "ak:did_core:web:alice.example",
                "state": "active",
                "devices": [],
                "primary_handle_claim": {
                    "schema": "ak.schema.handle_claim.v1",
                    "handle": "alice:local.host",
                    "subject_account_id": {
                        "principal_id": "ak:did_core:web:alice.example",
                        "station_id": "ak:did_core:web:principal.example"
                    },
                    "issuer_id": "ak:did_core:web:principal.example",
                    "binding_state": "verified",
                    "created_at": "2026-06-12T08:00:00.000Z"
                },
                "profile": {
                    "id": "ak:actor_profile:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH",
                    "schema": "ak.schema.actor_profile.v1",
                    "realm_id": "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH",
                    "principal_id": "ak:did_core:web:alice.example",
                    "actor_kind": "user",
                    "display_name": "Alice",
                    "created_at": "2026-06-12T08:00:00.000Z"
                }
            }))
            .expect("account viewer shape");

        let account = current_account_from_viewer(viewer);

        assert_eq!(
            account.principal_id.as_str(),
            "ak:did_core:web:alice.example"
        );
        assert_eq!(account.handle, "alice:local.host");
        assert_eq!(account.display_name.as_deref(), Some("Alice"));
        assert_eq!(account.created_at, "2026-06-12T08:00:00.000Z");
    }

    #[test]
    fn account_viewer_projection_rejects_unverified_or_foreign_handle_claim() {
        for (subject, binding_state) in [
            ("ak:did_core:web:mallory.example", "verified"),
            ("ak:did_core:web:alice.example", "pending"),
        ] {
            let viewer: arkret_models_collaboration::account_lifecycle::AccountView =
                serde_json::from_value(json!({
                    "principal_id": "ak:did_core:web:alice.example",
                    "state": "active",
                    "devices": [],
                    "primary_handle_claim": {
                        "schema": "ak.schema.handle_claim.v1",
                        "handle": "alice:auth.local.host",
                        "subject_account_id": {
                            "principal_id": subject,
                            "station_id": "ak:did_core:web:principal.example"
                        },
                        "issuer_id": "ak:did_core:web:principal.example",
                        "binding_state": binding_state,
                        "created_at": "2026-06-12T08:00:00.000Z"
                    }
                }))
                .expect("account viewer shape");

            assert_eq!(current_account_from_viewer(viewer).handle, "");
        }
    }

    #[test]
    fn account_viewer_projection_does_not_invent_handle() {
        let viewer: arkret_models_collaboration::account_lifecycle::AccountView =
            serde_json::from_value(json!({
                "principal_id": "ak:did_core:web:alice.example",
                "state": "active",
                "devices": []
            }))
            .expect("minimal account viewer shape");

        let account = current_account_from_viewer(viewer);

        assert_eq!(
            account.principal_id.as_str(),
            "ak:did_core:web:alice.example"
        );
        assert_eq!(account.handle, "");
        assert_eq!(account.display_name, None);
        assert_eq!(account.created_at, "");
    }

    #[test]
    fn effective_owned_agent_reply_does_not_request_another_governance_write() {
        let scope = arkret_sdk::ParticipationScope::Strand {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH",
            )
            .expect("realm id"),
            strand_id: arkret_sdk::StrandId::new(
                "ak:strand:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M",
            )
            .expect("strand id"),
        };
        let outcome: arkret_sdk::AgentParticipationOutcome = serde_json::from_value(json!({
            "ok": true,
            "agent_id": "ak:did_core:web:agent.example",
            "participation_entries": [{
                "target_scope": scope,
                "selection": {
                    "reply_message": true,
                    "reaction_add": false,
                    "reaction_remove": false,
                    "accept_third_party_mention": false,
                    "act_on_behalf": false
                },
                "version": 1,
                "next_replace_input": {
                    "expected_version": 1
                }
            }]
        }))
        .expect("participation outcome");

        assert!(!owned_agent_reply_update_needed(&outcome, &scope));
    }

    #[test]
    fn reply_enablement_failure_does_not_invalidate_resolved_direct_conversation() {
        let outcome: arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome =
            serde_json::from_value(json!({
                "state": "found",
                "coordinates": {
                    "pair_key": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "realm_id": "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH",
                    "main_strand_id": "ak:strand:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M",
                    "binding_event_ref": "ak:event:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv"
                },
                "group_state_ref": "ak:event:AfR_M7E56E86OkxTne77vQ9fmdFkzpnxO_TBqB4ymjKV",
                "group_state_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "send_blockers": []
            }))
            .expect("found Direct Conversation outcome");

        preserve_resolved_direct_conversation(
            "did:web:agent.example",
            &outcome,
            Err(anyhow::anyhow!("authority_generation_unknown")),
        );

        let coordinates = direct_conversation_coordinates(&outcome).expect("found coordinates");
        assert_eq!(
            coordinates.realm_id.as_str(),
            "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH"
        );
        assert_eq!(
            coordinates.main_strand_id.as_str(),
            "ak:strand:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M"
        );
    }

    #[test]
    fn suspended_direct_conversation_never_offers_recreation() {
        let outcome: arkret_sdk::direct_conversation_ops::DirectConversationResolveOutcome =
            serde_json::from_value(json!({
                "state": "suspended",
                "coordinates": {
                    "pair_key": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "realm_id": "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH",
                    "main_strand_id": "ak:strand:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M",
                    "binding_event_ref": "ak:event:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv"
                },
                "blockers": ["mls_reconcile_required"]
            }))
            .expect("suspended Direct Conversation outcome");

        assert_eq!(
            direct_conversation_entry(&outcome),
            DirectConversationEntry::Suspended
        );
        assert!(direct_conversation_coordinates(&outcome).is_some());
    }

    #[test]
    fn owned_agent_direct_peer_keeps_its_controller_binding() {
        let actor = json!({"kind":"hosted_principal", "principal_id":"ak:did_core:web:agents.example:assistant", "station_id":"ak:did_core:web:remote-station.example"});
        let controller = json!({"principal_id":"ak:did_core:web:alice.example", "station_id":"ak:did_core:web:remote-station.example"});
        let peer =
            direct_conversation_peer_descriptor(&actor.to_string(), Some(&controller.to_string()))
                .expect("owned Agent peer");

        assert_eq!(
            serde_json::to_value(peer).expect("serialize peer"),
            json!({
                "kind": "agent",
                "actor_id": actor,
                "controller_account_id": controller
            })
        );
    }

    #[test]
    fn direct_peer_requires_complete_remote_account() {
        assert!(direct_conversation_peer_descriptor("did:web:alice.example", None).is_err());
        let account = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap(),
        );
        let actor = arkret_sdk::ActorId::account(account.clone());
        let peer = direct_conversation_peer_descriptor(&actor.to_string(), None).unwrap();
        assert_eq!(
            serde_json::to_value(peer).unwrap(),
            json!({"kind":"human", "account_id":account})
        );
    }
}
