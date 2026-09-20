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

use serde_json::Value;

use crate::event_submit::EventSubmitter;
use crate::models::{ContactList, CurrentAccount};
use crate::state::LocalStateStore;

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
) -> anyhow::Result<arkret_models_collaboration::account_operations::AccountView> {
    let viewer = http
        .account_viewer()
        .await
        .map_err(|error| anyhow::Error::new(error).context("account viewer"))?;
    Ok(viewer)
}

pub async fn account_me(http: &arkret_sdk::http_client::Client) -> anyhow::Result<CurrentAccount> {
    let viewer = account_viewer(http).await?;
    Ok(current_account_from_viewer(viewer))
}

/// Read the authenticated Station result without downloading method history.
pub(crate) async fn current_principal_for_authority(
    http: &arkret_sdk::http_client::Client,
    authority: &arkret_sdk::AccountId,
) -> anyhow::Result<arkret_sdk::CurrentPrincipalOutcome> {
    let generation = crate::identity::device_directory::cache_epoch();
    let active_scope = crate::secure_key_store::active_device_seed_scope();
    let request = arkret_sdk::CurrentPrincipalRequestBody {
        request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
        account_id: authority.clone(),
    };
    let result = http.current_principal(&request).await?;
    anyhow::ensure!(
        generation == crate::identity::device_directory::cache_epoch(),
        "current principal response belongs to an old identity session"
    );
    let current_scope = crate::secure_key_store::active_device_seed_scope();
    anyhow::ensure!(
        active_scope.as_ref().map(|s| (&s.authority, &s.device_id))
            == current_scope.as_ref().map(|s| (&s.authority, &s.device_id)),
        "current principal device scope changed during the request"
    );
    result.validate_for_request(&request)?;
    if let Some(known) = crate::config::LocalConfigStore::default().known_account_context(authority)
    {
        anyhow::ensure!(
            known.principal_control_realm_id == result.principal_control_realm_id,
            "current principal changes the Account's pinned PCR"
        );
        anyhow::ensure!(
            known.resolution.updated_at <= result.resolution_projection.updated_at,
            "current principal projection regressed"
        );
    }
    Ok(result)
}

pub async fn resolve_active_account_context(
    http: &arkret_sdk::http_client::Client,
    profile_id: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    server_url: url::Url,
) -> anyhow::Result<crate::config::ActiveAccountContext> {
    anyhow::ensure!(
        http.base_url().origin() == server_url.origin(),
        "current principal transport does not match the authenticated Station route"
    );
    let result = current_principal_for_authority(http, &authority).await?;
    crate::config::ActiveAccountContext::new(
        profile_id,
        authority,
        result.principal_control_realm_id,
        result.resolution_projection,
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
        || authority_evidence.pcr_genesis_commits[0].realm_id
            != authority_evidence.principal_control_realm_id
        || authority_evidence.pcr_genesis_commits[1].realm_id
            != authority_evidence.principal_control_realm_id
    {
        anyhow::bail!(
            "durable profile-authoring evidence does not bind the authenticated principal's exact PCR"
        );
    }

    let event = if let Some(profile) = viewer.profile {
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
        crate::operation::ak_ops::account_profile_update(
            &principal_control_realm_id,
            &authority_evidence.account_id,
            profile_id,
            patch,
        )?
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
        crate::operation::ak_ops::account_profile_create(
            &principal_control_realm_id,
            &authority_evidence.account_id,
            profile,
        )?
    };
    let signed = submitter.author_for_direct_submission(&event).await?;
    let body = arkret_models_collaboration::account_operations::AccountUpdateProfileRequestBody {
        profile_event: arkret_wire::EventCommitSubmission {
            event: signed.into_event(),
            approval_signatures: None,
        },
    };
    body.validate()?;
    submitter
        .http()
        .account_update_profile(&body)
        .await
        .map_err(Into::into)
}

pub async fn respond_contact(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
    action: &str,
) -> anyhow::Result<()> {
    let requester_actor: arkret_sdk::ActorId = serde_json::from_str(requester)?;
    let pending =
        crate::transport::contacts::pending::PendingOperation::begin(Some(serde_json::json!([
            "response",
            requester_actor,
            action,
            None::<&str>
        ])))
        .await?;
    if let Some(outcome) = pending.resume(http).await? {
        return crate::transport::contacts::require_contact_success(outcome);
    }
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
    let request_event_ref = row
        .request_event_ref
        .ok_or_else(|| anyhow::anyhow!("pending_incoming Contact row omitted request_event_ref"))?;
    submit_contact_response(http, row.peer, request_event_ref, action, &pending).await
}

pub async fn respond_contact_with_request_id(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
    request_event_ref: &str,
    action: &str,
) -> anyhow::Result<()> {
    let requester_actor: arkret_sdk::ActorId = serde_json::from_str(requester)?;
    let pending =
        crate::transport::contacts::pending::PendingOperation::begin(Some(serde_json::json!([
            "response",
            requester_actor,
            action,
            Some(request_event_ref.trim())
        ])))
        .await?;
    if let Some(outcome) = pending.resume(http).await? {
        return crate::transport::contacts::require_contact_success(outcome);
    }
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
    let request_event_ref = row
        .request_event_ref
        .ok_or_else(|| anyhow::anyhow!("pending_incoming Contact row omitted request_event_ref"))?;
    submit_contact_response(http, row.peer, request_event_ref, action, &pending).await
}

async fn submit_contact_response(
    http: &arkret_sdk::http_client::Client,
    peer: arkret_sdk::contact_operations::ContactPeer,
    request_event_ref: arkret_sdk::EventId,
    action: &str,
    pending: &crate::transport::contacts::pending::PendingOperation,
) -> anyhow::Result<()> {
    let session = crate::transport::contacts::ContactSessionFence::capture()?;
    use arkret_sdk::contact_operations::{
        ContactAcceptAction, ContactAcceptPrepareRequestBody, ContactAcceptRequestBody,
        ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome, ContactPreparePhase,
        ContactPreparedOutcome, ContactRejectAction, ContactRejectPrepareRequestBody,
        ContactRejectRequestBody,
    };

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
            peer: peer.clone(),
            request_event_ref: request_event_ref.clone(),
            action: ContactAcceptAction::Accept,
            granted_to_peer_scopes: crate::transport::contacts::default_contact_scopes(),
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
        let draft_event =
            event_draft.unsigned_event_for_kind(arkret_wire::event_kind_str::CONTACT_ACCEPTED)?;
        let draft_payload: arkret_sdk::ContactAcceptedPayload =
            serde_json::from_value(serde_json::to_value(&draft_event.payload)?)?;
        if draft_payload.peer != peer
            || draft_payload.request_event_ref != request_event_ref
            || draft_payload.granted_to_peer_scopes
                != crate::transport::contacts::default_contact_scopes()
        {
            anyhow::bail!("Contact prepare changed the selected proposal or response intent");
        }
        session.check()?;
        let signed_event = crate::transport::contacts::sign_prepared_contact_event(
            &event_draft,
            arkret_wire::event_kind_str::CONTACT_ACCEPTED,
        )?;
        let seal_context =
            crate::transport::contacts::prepare_principal_successor_seal(http, &signed_event)
                .await?;
        let commit = ContactAcceptRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id: operation_id.clone(),
            idempotency_key,
            reservation_handle,
            signed_event: signed_event.event().clone(),
            control_proposal_ack: None,
        });
        session.check()?;
        match crate::transport::contacts::finish_contact_commit(
            http,
            seal_context,
            &pending,
            &commit,
        )
        .await?
        {
            ContactOperationOutcome::Accepted { .. } => Ok(()),
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
            peer: peer.clone(),
            request_event_ref: request_event_ref.clone(),
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
        let draft_event =
            event_draft.unsigned_event_for_kind(arkret_wire::event_kind_str::CONTACT_REJECTED)?;
        let draft_payload: arkret_sdk::ContactRejectedPayload =
            serde_json::from_value(serde_json::to_value(&draft_event.payload)?)?;
        if draft_payload.peer != peer || draft_payload.request_event_ref != request_event_ref {
            anyhow::bail!("Contact prepare changed the selected proposal or response intent");
        }
        session.check()?;
        let signed_event = crate::transport::contacts::sign_prepared_contact_event(
            &event_draft,
            arkret_wire::event_kind_str::CONTACT_REJECTED,
        )?;
        let seal_context =
            crate::transport::contacts::prepare_principal_successor_seal(http, &signed_event)
                .await?;
        let commit = ContactRejectRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id: operation_id.clone(),
            idempotency_key,
            reservation_handle,
            signed_event: signed_event.event().clone(),
            control_proposal_ack: None,
        });
        session.check()?;
        match crate::transport::contacts::finish_contact_commit(
            http,
            seal_context,
            &pending,
            &commit,
        )
        .await?
        {
            ContactOperationOutcome::Accepted { .. } => Ok(()),
            ContactOperationOutcome::Failed { outcome } => {
                anyhow::bail!("Contact reject commit failed: {:?}", outcome.reason)
            }
            _ => anyhow::bail!("Contact reject commit returned the wrong result kind"),
        }
    } else {
        anyhow::bail!("unsupported Contact response action `{action}`")
    }
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
    state_store: &crate::runtime::input::StateStoreHandle,
    peer: &str,
    peer_controller: Option<&str>,
    enable_owned_agent_reply: bool,
) -> anyhow::Result<arkret_sdk::direct_conversation::DirectConversationResolveOutcome> {
    let authority = state_store
        .read(|store| store.active_authority())
        .ok_or_else(|| anyhow::anyhow!("Direct Conversation requires active account"))?;
    let epoch = crate::identity::device_directory::cache_epoch();
    let http = api.http();
    let peer_descriptor = direct_conversation_peer_descriptor(peer, peer_controller)?;
    let peer_actor = peer_descriptor.contact_actor_id();
    let body = arkret_sdk::direct_conversation::DirectConversationResolveRequestBody {
        peer: peer_descriptor,
    };
    let query_sequence = crate::mls::direct_binding::begin_query(&authority, &body.peer)?;
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
    if let Err(error) = crate::mls::direct_binding::install_resolved_message_context(
        http,
        state_store,
        &authority,
        epoch,
        query_sequence,
        body.peer.clone(),
        &outcome,
    )
    .await
    {
        tracing::debug!(%error,"Direct Conversation authoring remains pending");
    }
    Ok(outcome)
}

/// Submit the caller-authored founding Events for a pair the resolver granted
/// creation authority over.
///
/// A RealmCommit covers exactly one Event, so the founding "unit" is submitted
/// as an ordered sequence of ordinary Event commits rather than one atomic
/// multi-Event carrier: `ak.realm.create` first, then the members that name it.
/// Ambiguous network failures are retried by passing the same authored Events
/// again; the authority is idempotent on a repeated `event_id`. This helper
/// never authors or substitutes coordinates.
pub async fn direct_conversation_found(
    submitter: &crate::event_submit::EventSubmitter,
    resolve: &arkret_sdk::direct_conversation::DirectConversationResolveOutcome,
    authored: Vec<arkret_sdk::AuthoredEvent>,
) -> anyhow::Result<Vec<crate::models::SubmitEventResult>> {
    if !matches!(
        garth::direct_conversation_action(resolve),
        garth::DirectConversationAction::SubmitCreation { .. }
    ) {
        anyhow::bail!("Direct Conversation resolve state does not permit founding submission");
    }
    let authority = garth::AuthorityClient::new(submitter.http().clone());
    let mut results = Vec::with_capacity(authored.len());
    for event in authored {
        let event = event.into_event();
        let mut queued = garth::QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::Event(
            arkret_wire::EventCommitSubmission {
                event,
                approval_signatures: None,
            },
        ))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        authority
            .submit(
                &mut queued,
                &arkret_sdk::http_client::ClientRequestOptions::new(),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let event_id = queued.event_id.to_string();
        let result = match queued.state {
            garth::SubmissionState::Committed { commit, .. } => {
                crate::models::SubmitEventResult::committed(event_id, *commit)
            }
            garth::SubmissionState::Rejected { reason_code, .. } => {
                anyhow::bail!("Direct Conversation founding Event rejected: {reason_code}");
            }
            garth::SubmissionState::Queued => {
                anyhow::bail!(
                    "Direct Conversation founding Event was not answered by the authority"
                )
            }
        };
        results.push(result);
    }
    Ok(results)
}

/// Author, sign and submit the resolver-authorized founding Events.
///
/// The founding authority evidence is a caller input: the resolver outcome
/// carries only `expected_contact_revision`, so the pair's root Contact round
/// evidence (or the controller/Agent provision reference) must be supplied by
/// the caller that read it. Coordinates are read back by re-resolving after the
/// last Event commits; the founding submission itself returns only its commits.
pub async fn create_direct_conversation_from_resolve(
    submitter: &crate::event_submit::EventSubmitter,
    resolve: &arkret_sdk::DirectConversationResolveOutcome,
    founder_account: &arkret_sdk::AccountId,
    peer_account: &arkret_sdk::AccountId,
    founding_authority: &arkret_sdk::DirectConversationFoundingAuthorityEvidence,
) -> anyhow::Result<Vec<crate::models::SubmitEventResult>> {
    if !matches!(
        resolve,
        arkret_sdk::DirectConversationResolveOutcome::CreationRequired { .. }
    ) {
        anyhow::bail!("Direct Conversation resolver did not grant founding authority");
    }
    anyhow::ensure!(
        submitter.authority()? == founder_account,
        "Direct Conversation founder differs from the authenticated AccountId"
    );
    let trust_domain = submitter.service_describe().await?.trust_domain;
    let steps = crate::event_builders::build_direct_conversation_founding_steps(
        founder_account,
        peer_account,
        trust_domain,
        founding_authority,
    )?;
    let signed = submitter.author_event_unit(steps).await?;
    direct_conversation_found(submitter, resolve, signed).await
}

fn direct_conversation_peer_descriptor(
    peer: &str,
    peer_controller_account_id: Option<&str>,
) -> anyhow::Result<arkret_sdk::contact_operations::ContactPeer> {
    let actor_id: arkret_sdk::ActorId = serde_json::from_str(peer)?;
    Ok(match peer_controller_account_id {
        Some(controller_account_id) => arkret_sdk::contact_operations::ContactPeer::Agent {
            actor_id,
            controller_account_id: serde_json::from_str(controller_account_id)?,
        },
        None => arkret_sdk::contact_operations::ContactPeer::Human {
            account_id: actor_id.as_account_id().cloned().ok_or_else(|| {
                anyhow::anyhow!("human Contact peer requires a complete AccountId actor")
            })?,
        },
    })
}

pub(crate) fn direct_conversation_coordinates(
    outcome: &arkret_sdk::direct_conversation::DirectConversationResolveOutcome,
) -> Option<&arkret_sdk::direct_conversation::DirectConversationCoordinates> {
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
    outcome: &arkret_sdk::direct_conversation::DirectConversationResolveOutcome,
) -> DirectConversationEntry {
    use arkret_sdk::direct_conversation::DirectConversationResolveOutcome as Outcome;
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
    outcome: &arkret_sdk::direct_conversation::DirectConversationResolveOutcome,
) -> std::collections::BTreeSet<arkret_sdk::direct_conversation::DirectConversationClientLocalBlocker>
{
    use arkret_sdk::direct_conversation::DirectConversationClientLocalBlocker as Local;

    let mut blockers = std::collections::BTreeSet::new();
    if crate::account_data::is_blocked(&state_store.client_blocklist_for_actor(peer), peer) {
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
                crate::state::mls_scope_checkpoint_key_for_group(&scope, &group_id).ok()
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
    outcome: &arkret_sdk::direct_conversation::DirectConversationResolveOutcome,
    local_blockers: &std::collections::BTreeSet<
        arkret_sdk::direct_conversation::DirectConversationClientLocalBlocker,
    >,
) -> DirectConversationEntry {
    let entry = direct_conversation_entry(outcome);
    // Missing history secrets block sending, not entering a conversation to
    // receive its MLS Welcome and converge keys. The chat's verified MLS gate
    // remains responsible for enabling Send.
    if local_blockers.contains(
        &arkret_sdk::direct_conversation::DirectConversationClientLocalBlocker::PersonalBlocked,
    ) && matches!(entry, DirectConversationEntry::Openable)
    {
        DirectConversationEntry::Suspended
    } else {
        entry
    }
}

pub(crate) fn cached_direct_conversation_peer(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    _strand_id: &str,
) -> Option<String> {
    state_store
        .direct_conversation_peer(realm_id)
        .map(|peer| peer.contact_actor_id().to_string())
}

/// Opening a canonical Direct Conversation and changing an Agent's participation
/// policy are separate protocol operations.  The latter is best-effort here: a
/// stale selection state or restrictive current target policy may stop
/// the Agent from replying, but MUST NOT turn an already resolved conversation
/// into an unavailable navigation target.
fn preserve_resolved_direct_conversation(
    agent_id: &str,
    outcome: &arkret_sdk::direct_conversation::DirectConversationResolveOutcome,
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
    state_store: &crate::runtime::input::StateStoreHandle,
    agent_id: &str,
    outcome: &arkret_sdk::direct_conversation::DirectConversationResolveOutcome,
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
        .write(|store| {
            store.record_mls_coverage_stale(
                scope.realm_id().as_str().to_owned(),
                None,
                "agent reply participation grant changed the Realm governance frontier",
            )
        })
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
) -> anyhow::Result<arkret_sdk::ConsentList> {
    http.get(arkret_wire::PATH_SELF_CONSENT_RESULTS)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn identity_describe(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::ServiceDescribe> {
    http.identity_describe()
        .await
        .map_err(|error| anyhow::Error::new(error).context("identity describe"))
}

pub async fn sync_describe(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_models_discovery::ServiceDescribe> {
    http.account_describe().await.map_err(anyhow::Error::from)
}

fn current_account_from_viewer(
    viewer: arkret_models_collaboration::account_operations::AccountView,
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
    viewer: &arkret_models_collaboration::account_operations::AccountView,
) -> String {
    viewer
        .primary_handle_claim
        .as_ref()
        .filter(|claim| {
            claim.claim.subject_account_id.principal_id == viewer.principal_id
                && claim.status == arkret_models_identity::HandleClaimStatus::Verified
                && claim.revocation.is_none()
                && claim.fresh_until > chrono::Utc::now()
        })
        .map(|claim| &claim.claim.handle)
        .map(|handle| handle.canonical().trim())
        .filter(|handle| !handle.is_empty())
        .unwrap_or_default()
        .to_owned()
}

fn contact_scope_update_prepare(
    row: arkret_sdk::ContactListRow,
    mut granted_to_peer_scopes: Vec<arkret_sdk::contact_operations::ContactScope>,
    operation_id: arkret_sdk::ProtocolOperationId,
    idempotency_key: arkret_sdk::IdempotencyKey,
) -> anyhow::Result<arkret_sdk::contact_operations::ContactScopeUpdateRequestBody> {
    use arkret_sdk::contact_operations::{
        ContactPreparePhase, ContactScopeUpdatePrepareRequestBody, ContactScopeUpdateRequestBody,
    };

    if row.state != arkret_sdk::ContactState::Accepted {
        anyhow::bail!("Contact scope update requires an accepted Contact row");
    }
    let next = row.next_prepare_input.ok_or_else(|| {
        anyhow::anyhow!("accepted Contact row omitted its exact next_prepare_input")
    })?;
    next.validate_shape()?;
    granted_to_peer_scopes.sort();
    granted_to_peer_scopes.dedup();
    Ok(ContactScopeUpdateRequestBody::Prepare(
        ContactScopeUpdatePrepareRequestBody {
            phase: ContactPreparePhase::Prepare,
            operation_id,
            idempotency_key,
            peer: row.peer,
            contact_round_id: next.contact_round_id,
            version: next.version,
            predecessor_event_ref: next.predecessor_event_ref,
            granted_to_peer_scopes,
        },
    ))
}

/// Replace the holder-signed directional scope set for one accepted Contact.
///
/// The fresh list projection is the only source of the lineage CAS cursor. An
/// empty scope set is intentional and suspends the round without tombstoning
/// it; callers must therefore pass the complete desired set, not a delta.
pub async fn update_contact_scopes(
    http: &arkret_sdk::http_client::Client,
    peer: &str,
    granted_to_peer_scopes: Vec<arkret_sdk::contact_operations::ContactScope>,
) -> anyhow::Result<()> {
    let session = crate::transport::contacts::ContactSessionFence::capture()?;
    use arkret_sdk::contact_operations::{
        ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
        ContactPreparedOutcome, ContactScopeUpdateRequestBody,
    };

    let peer_actor: arkret_sdk::ActorId = serde_json::from_str(peer)?;
    let pending =
        crate::transport::contacts::pending::PendingOperation::begin(Some(serde_json::json!([
            "update_contact_scopes",
            peer_actor,
            granted_to_peer_scopes
        ])))
        .await?;
    if let Some(outcome) = pending.resume(http).await? {
        return crate::transport::contacts::require_contact_success(outcome);
    }
    let contacts = http.contacts_list().await?;
    let row = contacts
        .contacts
        .into_iter()
        .find(|row| {
            row.state == arkret_sdk::ContactState::Accepted
                && row.peer.contact_actor_id() == peer_actor
        })
        .ok_or_else(|| {
            anyhow::anyhow!("Contact scope update for `{peer}` requires a fresh accepted list row")
        })?;
    let nonce = crate::operation::uuid_v7();
    let operation_id =
        arkret_sdk::ProtocolOperationId::new(format!("ak:operation:contact.scope_update.{nonce}"))
            .map_err(anyhow::Error::msg)?;
    let idempotency_key = arkret_sdk::IdempotencyKey::new(nonce).map_err(anyhow::Error::msg)?;
    let prepare = contact_scope_update_prepare(
        row,
        granted_to_peer_scopes,
        operation_id.clone(),
        idempotency_key.clone(),
    )?;
    let prepared: ContactOperationOutcome = http
        .post("/_arkret/self/contacts/scope-update", &prepare)
        .await?;
    let (returned_operation_id, reservation_handle, event_draft) = match prepared {
        ContactOperationOutcome::Prepared {
            outcome:
                ContactPreparedOutcome::ScopeUpdate {
                    operation_id,
                    reservation_handle,
                    event_draft,
                    ..
                },
        } => (operation_id, reservation_handle, event_draft),
        ContactOperationOutcome::Failed { outcome } => {
            anyhow::bail!("Contact scope update prepare failed: {:?}", outcome.reason)
        }
        _ => anyhow::bail!("Contact scope update prepare returned the wrong result kind"),
    };
    if returned_operation_id != operation_id {
        anyhow::bail!("Contact scope update prepare changed operation_id");
    }
    session.check()?;
    let signed_event = crate::transport::contacts::sign_prepared_contact_event(
        &event_draft,
        arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE,
    )?;
    let seal_context =
        crate::transport::contacts::prepare_principal_successor_seal(http, &signed_event).await?;
    let commit = ContactScopeUpdateRequestBody::Commit(ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id: operation_id.clone(),
        idempotency_key,
        reservation_handle,
        signed_event: signed_event.event().clone(),
        control_proposal_ack: None,
    });
    session.check()?;
    let committed =
        crate::transport::contacts::finish_contact_commit(http, seal_context, &pending, &commit)
            .await?;
    match committed {
        ContactOperationOutcome::Accepted { .. } => Ok(()),
        ContactOperationOutcome::Failed { outcome } => {
            anyhow::bail!("Contact scope update commit failed: {:?}", outcome.reason)
        }
        _ => anyhow::bail!("Contact scope update commit returned the wrong result kind"),
    }
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
    let session = crate::transport::contacts::ContactSessionFence::capture()?;
    use arkret_sdk::contact_operations::{
        ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome, ContactPreparePhase,
        ContactPreparedOutcome, ContactTombstonePrepareRequestBody, ContactTombstoneRequestBody,
    };

    let peer_actor: arkret_sdk::ActorId = serde_json::from_str(peer)?;
    let pending =
        crate::transport::contacts::pending::PendingOperation::begin(Some(serde_json::json!([
            "tombstone_contact",
            peer_actor,
            block_peer
        ])))
        .await?;
    if let Some(outcome) = pending.resume(http).await? {
        return crate::transport::contacts::require_contact_success(outcome);
    }
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
    session.check()?;
    let signed_event = crate::transport::contacts::sign_prepared_contact_event(
        &event_draft,
        arkret_wire::event_kind_str::CONTACT_TOMBSTONE,
    )?;
    let seal_context =
        crate::transport::contacts::prepare_principal_successor_seal(http, &signed_event).await?;
    let commit = ContactTombstoneRequestBody::Commit(ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id: operation_id.clone(),
        idempotency_key,
        reservation_handle,
        signed_event: signed_event.event().clone(),
        control_proposal_ack: None,
    });
    session.check()?;
    match crate::transport::contacts::finish_contact_commit(http, seal_context, &pending, &commit)
        .await?
    {
        ContactOperationOutcome::Accepted { .. } => Ok(()),
        ContactOperationOutcome::Failed { outcome } => {
            anyhow::bail!("Contact tombstone commit failed: {:?}", outcome.reason)
        }
        _ => anyhow::bail!("Contact tombstone commit returned the wrong result kind"),
    }
}

/// Read one holder-private consent result. Spec OpenAPI
/// `ak.self.consent.resource.get.v1`.
///
/// The result is addressed by its exact frozen `consent_peer`, both kinds
/// included. Nothing here reconstructs a peer from a bare DID: an ordinary
/// Account peer carries its complete ActorId and a Realm-local ephemeral
/// pairwise peer its `(realm_id, principal_id)` pair, and the two never
/// address each other's result.
pub async fn consent_result(
    http: &arkret_sdk::http_client::Client,
    _holder: &str,
    peer: &arkret_sdk::ConsentPeer,
    scope: &str,
) -> anyhow::Result<arkret_sdk::ConsentView> {
    let peer = serde_json::to_string(peer)?;
    let path = format!(
        "{}?peer={}&consent_scope={}",
        arkret_wire::PATH_SELF_CONSENT_RESULT,
        crate::wire_helpers::path_component(&peer),
        crate::wire_helpers::path_component(scope.trim()),
    );
    let view: arkret_sdk::ConsentView = http.get(&path).await.map_err(anyhow::Error::from)?;
    view.validate()?;
    Ok(view)
}

/// Grant scoped consent to `peer` from the holder result. `expires_at` is an
/// optional RFC 3339 time window upper bound. Spec OpenAPI
/// `ak.self.consent.command.grant.v1`.
///
/// The Event is authored and signed here: its `consent_id` is the result
/// subject, so it is never the server's to choose. A result that already exists
/// keeps its `consent_id`; a new one gets a freshly minted producer-allocated
/// id.
pub async fn grant_consent(
    submitter: &crate::event_submit::EventSubmitter,
    holder: &str,
    peer: &arkret_sdk::ConsentPeer,
    scope: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<arkret_sdk::ConsentView> {
    // Reuse the existing subject when there is one, so a re-grant lands on the
    // same result instead of opening a second one for the same (peer, scope).
    let consent_id = match consent_result(submitter.http(), holder, peer, scope).await {
        Ok(view) => view.consent_id,
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
    let signed_event = submitter.author_for_direct_submission(&event).await?;
    let body = arkret_sdk::ConsentGrantRequestBody {
        grant_event: arkret_wire::EventCommitSubmission {
            event: signed_event.into_event(),
            approval_signatures: None,
        },
    };
    body.validate()?;
    let view: arkret_sdk::ConsentView = submitter
        .http()
        .post(arkret_wire::PATH_SELF_CONSENT_RESULTS_GRANT, &body)
        .await
        .map_err(anyhow::Error::from)?;
    view.validate()?;
    Ok(view)
}

/// Revoke scoped consent from `peer`. Spec OpenAPI
/// `ak.self.consent.command.revoke.v1`.
///
/// The current result is read first because the Event MUST carry the exact
/// revision it supersedes: `ConsentRevokePayload.expected_revision` is the
/// current-state compare-and-set that closes the concurrent-revoke race, and it
/// is the Realm stream position of the result's last accepted commit.
pub async fn revoke_consent(
    submitter: &crate::event_submit::EventSubmitter,
    holder: &str,
    peer: &arkret_sdk::ConsentPeer,
    scope: &str,
) -> anyhow::Result<arkret_sdk::ConsentView> {
    let view = consent_result(submitter.http(), holder, peer, scope).await?;
    let holder_did = did_for_request_field("holder", holder)?;
    let principal_control_realm_id =
        crate::identity::principal_control::resolve_accepted(submitter.http(), &holder_did).await?;
    let event = crate::operation::ak_ops::consent_revoke(
        principal_control_realm_id.as_str(),
        holder.trim(),
        &view.consent_id,
        view.revision.stream_position,
    )?
    .build_sdk_event("inkson")?;
    let signed_event = submitter.author_for_direct_submission(&event).await?;
    let body = arkret_sdk::ConsentRevokeRequestBody {
        revoke_event: arkret_wire::EventCommitSubmission {
            event: signed_event.into_event(),
            approval_signatures: None,
        },
    };
    body.validate()?;
    let view: arkret_sdk::ConsentView = submitter
        .http()
        .post(arkret_wire::PATH_SELF_CONSENT_RESULTS_REVOKE, &body)
        .await
        .map_err(anyhow::Error::from)?;
    view.validate()?;
    Ok(view)
}

/// Open an outbound consent request: ask `holder` to grant the
/// authenticated actor the given scope. `scope` is the consent-model section 4
/// enum **minus `invite`** — an invite belongs to invite delivery and the
/// registered body rejects it — so an out-of-range value fails here rather than
/// reaching the Station. The response is deliberately opaque: admission to the
/// holder's quarantine cell, an anti-abuse drop, an unknown holder and a policy
/// deny all return the same bytes. Spec OpenAPI
/// `ak.self.consent.command.request.v1`.
pub async fn request_consent(
    http: &arkret_sdk::http_client::Client,
    // The counterparty whose consent is requested, closed by the caller. Its
    // Station is part of the identity; this client's authoring Station is not
    // a stand-in for it (account-lifecycle.md §156).
    holder: &arkret_sdk::AccountId,
    scope: &str,
) -> anyhow::Result<arkret_sdk::ConsentRequestOutcome> {
    let body = arkret_sdk::ConsentRequestRequestBody {
        holder_account_id: holder.clone(),
        consent_scope: scope.trim().parse()?,
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

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AccountDataMergeDecision {
    Replace(Value),
    KeepCurrent,
    /// The merge concluded there is nothing left to store, so the key is
    /// physically deleted on the same revision it was read at. A whole-value
    /// domain needs this: deciding removal before the read would delete
    /// whatever another device wrote in the meantime.
    Delete,
}

fn account_data_snapshot_from_details(
    type_key: &str,
    details: &std::collections::BTreeMap<String, Value>,
) -> anyhow::Result<AccountDataSnapshot> {
    let details = serde_json::from_value::<arkret_sdk::AccountDataCasConflict>(Value::Object(
        details.clone().into_iter().collect(),
    ))
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
    if error.code() != "cas_conflict" {
        return Ok(None);
    }
    account_data_snapshot_from_details(type_key, &error.extensions).map(Some)
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
            account_data_snapshot_from_details(type_key, &error.extensions)
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
    expected_server_revision: u64,
) -> anyhow::Result<arkret_wire::Event> {
    let (holder, _) = account_data_holder()?;
    let realm_id =
        crate::identity::principal_control::resolve_accepted(submitter.http(), &holder).await?;
    let builder = match value {
        Some(value) => crate::account_data::build_account_data_set(
            realm_id.as_str(),
            holder.as_str(),
            type_key,
            value,
            expected_server_revision,
        ),
        None => crate::account_data::build_account_data_tombstone(
            realm_id.as_str(),
            holder.as_str(),
            type_key,
            expected_server_revision,
        ),
    }?;
    let event = builder.build_sdk_event("inkson")?;
    submitter
        .author_independent_events(vec![event.into_intent()])
        .await?
        .into_iter()
        .next()
        .map(arkret_sdk::AuthoredEvent::into_event)
        .ok_or_else(|| anyhow::anyhow!("account_data submission was not authored"))
}

/// Apply a domain merge against the latest Account Data value and retry
/// compare-and-set conflicts with the authoritative conflict snapshot.
pub(crate) async fn update_account_data_with_conditional_merge<F>(
    submitter: &EventSubmitter,
    type_key: &str,
    mut merge: F,
) -> anyhow::Result<Value>
where
    F: FnMut(&AccountDataSnapshot) -> anyhow::Result<AccountDataMergeDecision>,
{
    let mut snapshot = account_data_snapshot(submitter.http(), type_key).await?;
    for attempt in 1..=MAX_ACCOUNT_DATA_CAS_ATTEMPTS {
        let content = match merge(&snapshot)? {
            AccountDataMergeDecision::Replace(value) => Some(value),
            AccountDataMergeDecision::KeepCurrent => {
                let current = snapshot.entry.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("account_data merge cannot keep an absent current entry")
                })?;
                return serde_json::to_value(current).map_err(anyhow::Error::from);
            }
            AccountDataMergeDecision::Delete => {
                if snapshot.entry.is_none() {
                    return Ok(Value::Null);
                }
                None
            }
        };
        let deleting = content.is_none();
        let set_event =
            account_data_set_submission(submitter, type_key, content, snapshot.revision).await?;
        // A delete has no entry to return, so the two branches meet as
        // `Option<entry>` rather than by forcing the replace result through a
        // serialization step the delete path never needs.
        let outcome = if deleting {
            submitter
                .http()
                .account_data_delete(
                    type_key,
                    &arkret_sdk::AccountDataDeleteRequestBody { set_event },
                )
                .await
                .map(|_| None)
        } else {
            submitter
                .http()
                .account_data_replace(
                    type_key,
                    &arkret_sdk::AccountDataReplaceRequestBody { set_event },
                )
                .await
                .map(Some)
        };
        match outcome {
            Ok(None) => return Ok(Value::Null),
            Ok(Some(entry)) => return serde_json::to_value(entry).map_err(anyhow::Error::from),
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

/// Apply a merge that always replaces the current Account Data value.
///
/// This preserves the original helper API for domains whose merge result is
/// always a write. LWW domains that can keep an authoritative current value
/// use [`update_account_data_with_conditional_merge`] so a losing or exact
/// replay does not create a no-op Event and revision.
pub(crate) async fn update_account_data_with_merge<F>(
    submitter: &EventSubmitter,
    type_key: &str,
    mut merge: F,
) -> anyhow::Result<Value>
where
    F: FnMut(&AccountDataSnapshot) -> anyhow::Result<Value>,
{
    update_account_data_with_conditional_merge(submitter, type_key, |snapshot| {
        merge(snapshot).map(AccountDataMergeDecision::Replace)
    })
    .await
}

/// Persist one holder-private blocklist successor, then close every durable
/// Contact-tombstone leg whose exact actor is still a live DM block in that
/// accepted full-list value. The ordering is deliberate: a Contact lineage is
/// never changed for a blocklist write that failed CAS/admission.
///
/// A target without a current accepted Contact has no directional authority to
/// revoke, so that leg closes without synthesizing a peer lineage. Existing
/// accepted Contacts use the canonical holder self operation with
/// `block_peer=true`; Consent is not read or written anywhere in this saga.
pub(crate) async fn persist_personal_block_saga(
    submitter: &EventSubmitter,
    authority: &arkret_sdk::AccountId,
    state_store: &crate::runtime::input::StateStoreHandle,
    entries: &[arkret_models_collaboration::objects::productivity::AccountBlocklistPayloadEntry],
) -> anyhow::Result<Value> {
    let outcome = update_account_data_with_conditional_merge(
        submitter,
        arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST,
        |snapshot| {
            if let Some(current) = snapshot.entry.as_ref()
                && let Ok(plaintext) = crate::account_data::decrypt_account_data_entry(
                    authority,
                    arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST,
                    current,
                )
                && let Ok(payload) =
                    crate::account_data::blocklist_payload_from_account_data(&plaintext)
                && payload.version == current.revision
                && payload.entries == entries
            {
                return Ok(AccountDataMergeDecision::KeepCurrent);
            }
            let plaintext = crate::account_data::build_blocklist_account_data_body(
                snapshot
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("ak.account.blocklist revision overflow"))?,
                entries,
            )
            .map_err(anyhow::Error::msg)?;
            crate::account_data::encrypt_account_data_value(
                authority,
                arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST,
                &plaintext,
            )
            .map(AccountDataMergeDecision::Replace)
        },
    )
    .await?;

    state_store.write(LocalStateStore::mark_personal_blocklist_sagas_committed);
    resume_personal_block_contact_sagas(submitter.http(), state_store, entries).await?;
    Ok(outcome)
}

/// Resume only the already-accepted Contact legs. Keeping this separate from
/// the Account Data write is what makes a tombstone transport failure an exact
/// retry instead of manufacturing a new full-list revision on every tick.
pub(crate) async fn resume_personal_block_contact_sagas(
    http: &arkret_sdk::http_client::Client,
    state_store: &crate::runtime::input::StateStoreHandle,
    entries: &[arkret_models_collaboration::objects::productivity::AccountBlocklistPayloadEntry],
) -> anyhow::Result<()> {
    let pending = state_store.read(LocalStateStore::committed_personal_block_sagas);
    if pending.is_empty() {
        return Ok(());
    }
    let now = chrono::Utc::now();
    let accepted_peers = http
        .contacts_list()
        .await?
        .contacts
        .into_iter()
        .filter(|row| row.state == arkret_sdk::ContactState::Accepted)
        .map(|row| row.peer.contact_actor_id().to_string())
        .collect::<std::collections::BTreeSet<_>>();

    for peer in pending {
        if !crate::account_data::requires_contact_tombstone(entries, &peer, now)
            || !accepted_peers.contains(&peer)
        {
            state_store.write(|store| store.complete_personal_block_saga(&peer));
            continue;
        }
        tombstone_contact(http, &peer, true).await?;
        state_store.write(|store| store.complete_personal_block_saga(&peer));
    }
    Ok(())
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
/// atomic revision loop; a stale revision re-reads the authoritative entry,
/// merges on decrypted plaintext, and retries with the new
/// `expected_server_revision`.
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
    let authority = submitter.authority()?;
    if crate::mls_api_helpers::principal_core_id(&marker.actor)? != authority.principal_id {
        anyhow::bail!("read marker actor does not belong to the authenticated account");
    }
    // A notification may be read before this device ever opens its Realm.
    // Resolve and verify the digest-suite authority before signing the cursor.
    submitter
        .refresh_realm_governance_frontier(&marker.body.realm_id)
        .await?;
    let payload = arkret_sdk::ReadCursor {
        schema: marker.body.schema.clone(),
        actor_id: arkret_sdk::ActorId::account(authority.clone()),
        device_id: arkret_sdk::DeviceId::new(marker.device_id.clone())?,
        realm_id: arkret_sdk::RealmId::new(marker.body.realm_id.clone())?,
        read_scope: marker.body.read_scope.clone(),
        position: marker.body.position.clone(),
    };
    // read-receipts.md §6.1: the cursor object carries no `updated_at`. The
    // time this device read the position is carried by the envelope
    // `created_at`, which is why the local marker time is the authoring time.
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

    fn accepted_contact_row_for_scope_update() -> arkret_sdk::ContactListRow {
        serde_json::from_value(json!({
            "peer": {"kind": "human", "account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:station.example"
            }},
            "state": "accepted",
            "next_prepare_input": {
                "contact_round_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "version": 7,
                "predecessor_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            },
            "granted_to_peer_scopes": ["direct_message"],
            "granted_by_peer_scopes": ["direct_message"],
            "bidirectional_scopes": ["direct_message"]
        }))
        .expect("accepted Contact row")
    }

    #[test]
    fn scope_update_prepare_copies_fresh_lineage_cursor_and_full_set() {
        let request = contact_scope_update_prepare(
            accepted_contact_row_for_scope_update(),
            vec![
                arkret_sdk::contact_operations::ContactScope::Presence,
                arkret_sdk::contact_operations::ContactScope::Invite,
                arkret_sdk::contact_operations::ContactScope::Presence,
            ],
            arkret_sdk::ProtocolOperationId::new(
                "ak:operation:contact.scope_update.0198f254-30c1-7f32-a1ab-4e52f4e14d9d",
            )
            .expect("operation id"),
            arkret_sdk::IdempotencyKey::new("0198f254-30c1-7f32-a1ab-4e52f4e14d9d")
                .expect("idempotency key"),
        )
        .expect("scope-update prepare");

        let arkret_sdk::contact_operations::ContactScopeUpdateRequestBody::Prepare(prepare) =
            request
        else {
            panic!("builder must return the prepare branch");
        };
        assert_eq!(prepare.version, 7);
        assert_eq!(
            prepare.contact_round_id.as_str(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            prepare.predecessor_event_ref.as_str(),
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        );
        assert_eq!(
            prepare.granted_to_peer_scopes,
            vec![
                arkret_sdk::contact_operations::ContactScope::Invite,
                arkret_sdk::contact_operations::ContactScope::Presence,
            ]
        );
    }

    #[test]
    fn scope_update_prepare_allows_explicit_empty_replacement() {
        let request = contact_scope_update_prepare(
            accepted_contact_row_for_scope_update(),
            Vec::new(),
            arkret_sdk::ProtocolOperationId::new(
                "ak:operation:contact.scope_update.0198f254-30c1-7f32-a1ab-4e52f4e14d9e",
            )
            .expect("operation id"),
            arkret_sdk::IdempotencyKey::new("0198f254-30c1-7f32-a1ab-4e52f4e14d9e")
                .expect("idempotency key"),
        )
        .expect("empty scope-update prepare");

        let arkret_sdk::contact_operations::ContactScopeUpdateRequestBody::Prepare(prepare) =
            request
        else {
            panic!("builder must return the prepare branch");
        };
        assert!(prepare.granted_to_peer_scopes.is_empty());
    }

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
                arkret_wire::Problem::from_code("cas_conflict", "expected_revision does not match")
                    .with_extension("account_data_key", json!("ak.client.ui_state"))
                    .with_extension("current_revision", json!(8))
                    .with_extension("current_entry", current_entry),
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
                arkret_wire::Problem::from_code("cas_conflict", "expected_revision does not match")
                    .with_extension("account_data_key", json!("ak.client.ui_state"))
                    .with_extension("current_revision", json!(8))
                    .with_extension(
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
        let now = chrono::Utc::now();
        let claim = crate::views::helpers::verified_handle_claim(
            "alice:local.host",
            arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            ),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            now,
            now + chrono::Duration::days(1),
        );
        let viewer: arkret_models_collaboration::account_operations::AccountView =
            serde_json::from_value(json!({
                "principal_id": "ak:did_core:web:alice.example",
                "state": "active",
                "devices": [],
                "primary_handle_claim": claim,
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
        for (subject, status) in [
            ("ak:did_core:web:mallory.example", "verified"),
            ("ak:did_core:web:alice.example", "pending"),
        ] {
            let now = chrono::Utc::now();
            let mut claim = crate::views::helpers::verified_handle_claim(
                "alice:auth.local.host",
                arkret_sdk::AccountId::new(
                    arkret_sdk::DidCoreId::new(subject).unwrap(),
                    arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
                ),
                arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
                now,
                now + chrono::Duration::days(1),
            );
            if status == "pending" {
                claim.status = arkret_models_identity::HandleClaimStatus::Pending;
                claim.verified_at = None;
            }
            let viewer: arkret_models_collaboration::account_operations::AccountView =
                serde_json::from_value(json!({
                    "principal_id": "ak:did_core:web:alice.example",
                    "state": "active",
                    "devices": [],
                    "primary_handle_claim": claim
                }))
                .expect("account viewer shape");

            assert_eq!(current_account_from_viewer(viewer).handle, "");
        }
    }

    #[test]
    fn account_viewer_projection_does_not_invent_handle() {
        let viewer: arkret_models_collaboration::account_operations::AccountView =
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
        let outcome: arkret_sdk::direct_conversation::DirectConversationResolveOutcome =
            serde_json::from_value(json!({
                "state": "found",
                "coordinates": {
                    "pair_key": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "realm_id": "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH",
                    "main_strand_id": "ak:strand:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M",
                    "binding_event_ref": "ak:event:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv"
                },
                "group_state_ref": "ak:event:AfR_M7E56E86OkxTne77vQ9fmdFkzpnxO_TBqB4ymjKV",
                "send_blockers": []
            }))
            .expect("found Direct Conversation outcome");

        use arkret_sdk::direct_conversation::DirectConversationClientLocalBlocker as Local;
        let missing_keys = std::collections::BTreeSet::from([Local::HistoryKeyUnavailable]);
        assert_eq!(
            direct_conversation_entry_with_local_blockers(&outcome, &missing_keys),
            DirectConversationEntry::Openable,
            "the peer must be able to enter and receive its Welcome"
        );
        let blocked = std::collections::BTreeSet::from([
            Local::PersonalBlocked,
            Local::HistoryKeyUnavailable,
        ]);
        assert_eq!(
            direct_conversation_entry_with_local_blockers(&outcome, &blocked),
            DirectConversationEntry::Suspended
        );

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
        let outcome: arkret_sdk::direct_conversation::DirectConversationResolveOutcome =
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
        let actor = json!({"kind": "account", "account_id": { "principal_id":"ak:did_core:web:agents.example:assistant", "station_id":"ak:did_core:web:remote-station.example"}});
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
