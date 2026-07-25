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
//! The durable-event-authoring account writes (`set_account_data`,
//! `set_private_account_data_with_cas`, `delete_account_data`,
//! `submit_read_cursor_advance`) are free functions taking an
//! [`crate::event_submit::EventSubmitter`], reached through
//! [`crate::transport::auth::with_event_submitter`]; the account-data actor-scope
//! lookup they need runs through `submitter.http()`.
//!
//! Only the `request_contact` family remains an inherent `TransportClient` method,
//! because it resolves contact addressing via the struct-cached
//! `describe_cached` (see `contact_request_addressing`).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::event_submit::EventSubmitter;
use crate::models::{
    ContactListView, CurrentAccount, IdentityDescribeOutcome, IdentityResolveOutcome,
    SubmitEventResult,
};

pub(crate) fn did_for_request_field(field: &str, value: &str) -> anyhow::Result<arkret_sdk::Did> {
    let value = value.trim();
    arkret_sdk::Did::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid {field} DID `{value}`: {err}"))
}

fn contact_response_action(action: &str) -> anyhow::Result<String> {
    match action.trim() {
        "accept" | "reject" => Ok(action.trim().to_owned()),
        other => anyhow::bail!("unsupported contact response action `{other}`"),
    }
}

fn optional_did_for_request_field(
    field: &str,
    value: Option<&str>,
) -> anyhow::Result<Option<arkret_sdk::Did>> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| did_for_request_field(field, value))
        .transpose()
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

/// A4b — update the authenticated principal's public profile
/// (display_name / bio / avatar_blob_ref). Mirrors the
/// `ak.self.account.command.update_profile` wire shape: each field is
/// `Option<String>`; `None` leaves the field untouched server-side,
/// `Some("")` explicitly clears it. The server normalises empty
/// strings to `None` on write.
pub async fn update_profile(
    http: &arkret_sdk::http_client::Client,
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
    if patch.is_empty() {
        anyhow::bail!("profile update patch is empty");
    }
    patch
        .validate()
        .map_err(|err| anyhow::anyhow!("invalid profile patch: {err}"))?;
    let body =
        arkret_models_collaboration::account_lifecycle::AccountUpdateProfileRequestBody { patch };
    http.account_update_profile(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn respond_contact(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
    action: &str,
) -> anyhow::Result<arkret_sdk::ContactRespondOutcome> {
    respond_contact_with_service(http, requester, action, None).await
}

async fn contact_request_event_id_for_requester(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
) -> anyhow::Result<String> {
    let requester = requester.trim();
    let contacts = contacts(http).await?;
    contacts
        .contacts
        .into_iter()
        .find(|row| row.peer == requester && row.request_event_ref.is_some())
        .and_then(|row| row.request_event_ref)
        .ok_or_else(|| {
            anyhow::anyhow!("contact request_id is required for responding to `{requester}`")
        })
}

/// Respond to an incoming contact request, optionally carrying the
/// requester's Principal Server service DID for cross-PS reverse delivery.
///
/// Protocol contract (soland finalized): the `contacts/respond` body
/// accepts an optional `requester_service_id`. Same-PS responses leave it
/// empty; cross-PS responses pass the originating PS so soland can route the
/// accept/reject back. Empty / whitespace-only values are dropped.
pub async fn respond_contact_with_service(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
    action: &str,
    requester_service_id: Option<&str>,
) -> anyhow::Result<arkret_sdk::ContactRespondOutcome> {
    let request_event_ref = contact_request_event_id_for_requester(http, requester).await?;
    respond_contact_with_request_id_and_service(
        http,
        requester,
        &request_event_ref,
        action,
        requester_service_id,
    )
    .await
}

pub async fn respond_contact_with_request_id_and_service(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
    request_event_ref: &str,
    action: &str,
    requester_service_id: Option<&str>,
) -> anyhow::Result<arkret_sdk::ContactRespondOutcome> {
    let body = arkret_sdk::ContactRespondRequestBody {
        request_id: arkret_sdk::EventId::new(request_event_ref.trim().to_owned()).map_err(
            |err| anyhow::anyhow!("invalid contact request_id `{request_event_ref}`: {err}"),
        )?,
        requester: did_for_request_field("requester", requester)?,
        action: contact_response_action(action)?,
        granted_scopes: Vec::new(),
        requester_service_id: optional_did_for_request_field(
            "requester_service_id",
            requester_service_id,
        )?,
    };
    http.contacts_respond(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn contacts(http: &arkret_sdk::http_client::Client) -> anyhow::Result<ContactListView> {
    let response: arkret_sdk::ContactList =
        http.contacts_list().await.map_err(anyhow::Error::from)?;
    ContactListView::from_sdk(response)
}

/// Read the actor's `invite_receive_policy` ("who can invite me", U4).
///
/// Spec `invite-addressing.md` §5 / OpenAPI
/// `ak.self.invite_receive_policy.resource.get`: served from the self plane at
/// `GET /_arkret/self/invite-receive-policy` and returns the bare
/// `arkret_sdk::InviteReceivePolicy` (soland echoes the stored override or
/// its recommended default). When the deployment does not yet wire this
/// surface the caller treats 404/501/405 as "use defaults" rather than a
/// hard error (see [`crate::models::default_invite_receive_policy`]).
pub async fn get_invite_receive_policy(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<crate::models::InviteReceivePolicy> {
    http.get("/_arkret/self/invite-receive-policy")
        .await
        .map_err(anyhow::Error::from)
}

/// Persist the actor's `invite_receive_policy` (U4).
///
/// Spec `ak.self.invite_receive_policy.resource.replace`:
/// `PUT /_arkret/self/invite-receive-policy` with the bare
/// `arkret_sdk::InviteReceivePolicy` as the body. The handler enforces
/// `subject_id == session actor` and requires the `schema` constant, so the
/// caller MUST stamp both before calling (see the U4 view); the server
/// echoes the stored policy back.
pub async fn set_invite_receive_policy(
    http: &arkret_sdk::http_client::Client,
    policy: &crate::models::InviteReceivePolicy,
) -> anyhow::Result<crate::models::InviteReceivePolicy> {
    http.put("/_arkret/self/invite-receive-policy", policy)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn direct_conversation_resolve(
    api: &crate::transport::TransportClient,
    state_store: SyncSignal<crate::state::LocalStateStore>,
    peer: &str,
    create: bool,
    enable_owned_agent_reply: bool,
) -> anyhow::Result<arkret_sdk::DirectConversationResolveOutcome> {
    let http = api.http();
    let body = arkret_sdk::DirectConversationResolveRequestBody {
        peer: did_for_request_field("peer", peer)?,
        create,
        idempotency_key: None,
        peer_claim_request: None,
    };
    let mut outcome = http
        .direct_conversation_resolve(&body)
        .await
        .map_err(anyhow::Error::from)?;
    if outcome.state == arkret_sdk::DirectConversationResolveState::AuthoringRequired
        && outcome.authoring_kind
            == Some(arkret_sdk::DirectConversationAuthoringKind::RemoteKeypackageClaim)
    {
        let draft = outcome.claim_authorization_draft.take().ok_or_else(|| {
            anyhow::anyhow!(
                "direct conversation resolver omitted the remote KeyPackage authorization draft"
            )
        })?;
        let claim_request = sign_peer_keypackage_claim_authorization(http, &draft).await?;
        let claim_request_id = claim_request.claim_request_id.as_str().to_owned();
        outcome = http
            .direct_conversation_resolve(&arkret_sdk::DirectConversationResolveRequestBody {
                peer: did_for_request_field("peer", peer)?,
                create: true,
                idempotency_key: Some(claim_request_id),
                peer_claim_request: Some(claim_request),
            })
            .await
            .map_err(anyhow::Error::from)?;
    }
    if let Some(draft) = outcome.materialization_draft.take() {
        if outcome.state != arkret_sdk::DirectConversationResolveState::AuthoringRequired
            || outcome.authoring_kind
                != Some(
                    arkret_sdk::DirectConversationAuthoringKind::DirectConversationMaterialization,
                )
        {
            anyhow::bail!(
                "direct conversation resolver returned a materialization draft outside its authoring_required state"
            );
        }
        materialize_direct_conversation(api, state_store, peer, draft).await?;
        let confirmed = http
            .direct_conversation_resolve(&arkret_sdk::DirectConversationResolveRequestBody {
                peer: did_for_request_field("peer", peer)?,
                create: false,
                idempotency_key: None,
                peer_claim_request: None,
            })
            .await
            .map_err(anyhow::Error::from)?;
        if confirmed.state != arkret_sdk::DirectConversationResolveState::Found {
            anyhow::bail!(
                "canonical direct conversation binding was not projected after signed Event submission"
            );
        }
        if enable_owned_agent_reply {
            ensure_owned_agent_direct_reply(http, peer, &confirmed).await?;
        }
        return Ok(confirmed);
    }
    if outcome.state == arkret_sdk::DirectConversationResolveState::AuthoringRequired {
        anyhow::bail!(
            "direct conversation resolver requires authoring but omitted the materialization draft"
        );
    }
    if enable_owned_agent_reply
        && outcome.state == arkret_sdk::DirectConversationResolveState::Found
    {
        ensure_owned_agent_direct_reply(http, peer, &outcome).await?;
    }
    Ok(outcome)
}

async fn ensure_owned_agent_direct_reply(
    http: &arkret_sdk::http_client::Client,
    agent_id: &str,
    outcome: &arkret_sdk::DirectConversationResolveOutcome,
) -> anyhow::Result<()> {
    let realm_id = outcome
        .realm_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("owned-Agent Direct Conversation omitted realm_id"))?;
    let strand_id = outcome
        .main_strand_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("owned-Agent Direct Conversation omitted main_strand_id"))?;
    let scope = arkret_sdk::AgentParticipationScope::Strand {
        realm_id,
        strand_id,
    };
    let existing = http
        .agent_participation_get(agent_id)
        .await
        .map_err(anyhow::Error::from)?;
    if existing
        .entries
        .iter()
        .any(|entry| entry.scope == scope && entry.effective.reply)
    {
        return Ok(());
    }
    let mut selection = existing
        .entries
        .iter()
        .find(|entry| entry.scope == scope)
        .map(|entry| entry.selection)
        .unwrap_or_default();
    selection.reply = true;
    let replace_result = http
        .agent_participation_replace(
            agent_id,
            &arkret_sdk::AgentParticipationReplaceRequestBody {
                scope: scope.clone(),
                selection,
            },
        )
        .await;
    let updated = match replace_result {
        Ok(updated) => updated,
        Err(replace_error) => {
            // Soland persists the controller's participation selection before
            // attempting its legacy development fan-out. Newer servers reject
            // that unsigned fan-out with `controller_signed_event_required`.
            // Re-read the canonical selection so a committed reply policy does
            // not turn an otherwise successful Direct Conversation into a
            // dead-end UI action. If the selection was not committed, preserve
            // the original error.
            let refreshed = match http.agent_participation_get(agent_id).await {
                Ok(refreshed) => refreshed,
                Err(_) => return Err(anyhow::Error::from(replace_error)),
            };
            if !participation_reply_is_effective(&refreshed, &scope) {
                return Err(anyhow::Error::from(replace_error));
            }
            refreshed
        }
    };
    if !participation_reply_is_effective(&updated, &scope) {
        anyhow::bail!("owned-Agent Direct Conversation reply participation remains disabled");
    }
    Ok(())
}

fn participation_reply_is_effective(
    outcome: &arkret_sdk::AgentParticipationOutcome,
    scope: &arkret_sdk::AgentParticipationScope,
) -> bool {
    outcome
        .entries
        .iter()
        .any(|entry| &entry.scope == scope && entry.effective.reply)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingDirectConversationMls {
    commit: arkret_sdk::Event,
    welcome: arkret_sdk::Event,
    binding: Option<arkret_sdk::Event>,
    snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingDirectConversationBootstrap {
    events: Vec<arkret_sdk::Event>,
}

fn pending_direct_conversation_key(materialization_id: &str) -> String {
    format!("direct_conversation.materialization.{materialization_id}")
}

fn pending_direct_conversation_bootstrap_key(materialization_id: &str) -> String {
    format!("direct_conversation.bootstrap.{materialization_id}")
}

/// Hardened-secure-store key for the resumable signed MLS transaction
/// (`PendingDirectConversationMls`). Account-scoped so a re-login cannot read a
/// prior account's pending Commit material.
fn direct_conversation_pending_secure_key(actor_id: &str, pending_key: &str) -> String {
    format!("direct_conversation.pending_mls.{actor_id}.{pending_key}")
}

/// Load the resumable signed MLS transaction, preferring the durable secure
/// store and falling back to the legacy plaintext-state entry (migrating it
/// forward on read) so a transaction persisted by an older build still resumes.
fn load_pending_direct_conversation_mls(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    state_store: &SyncSignal<crate::state::LocalStateStore>,
    actor_id: &str,
    pending_key: &str,
    pending_secure_key: &str,
) -> anyhow::Result<Option<PendingDirectConversationMls>> {
    if let Some(raw) = secure_store
        .get_secret(pending_secure_key)
        .map_err(|error| anyhow::anyhow!("read pending direct conversation MLS secret: {error}"))?
    {
        return serde_json::from_str::<PendingDirectConversationMls>(&raw)
            .map(Some)
            .map_err(|error| {
                anyhow::anyhow!("decode pending direct conversation MLS transaction: {error}")
            });
    }
    state_store
        .read()
        .load_private_data(actor_id, pending_key)
        .map(|raw| serde_json::from_str::<PendingDirectConversationMls>(&raw))
        .transpose()
        .map_err(|error| {
            anyhow::anyhow!("decode pending direct conversation MLS transaction: {error}")
        })
}

/// Durably persist the resumable signed MLS transaction to the hardened secure
/// store (awaited) so a mid-flow reload can replay the exact same Commit /
/// Welcome / snapshot. The prior plaintext-state copy is cleared to avoid a
/// stale divergent resume.
async fn persist_pending_direct_conversation_mls(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    state_store: &mut SyncSignal<crate::state::LocalStateStore>,
    actor_id: &str,
    pending_key: &str,
    pending_secure_key: &str,
    pending: &PendingDirectConversationMls,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(pending)?;
    secure_store
        .store_secret_durable(pending_secure_key, &json)
        .await
        .map_err(|error| {
            anyhow::anyhow!("durably persist pending direct conversation MLS transaction: {error}")
        })?;
    let _ = actor_id;
    state_store.write().remove_private_data(pending_key);
    Ok(())
}

async fn materialize_direct_conversation(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    peer: &str,
    draft: arkret_sdk::DirectConversationMaterializationDraft,
) -> anyhow::Result<()> {
    draft.validate_shape().map_err(|error| {
        anyhow::anyhow!("invalid direct conversation materialization draft: {error}")
    })?;
    if draft.expires_at <= chrono::Utc::now() {
        anyhow::bail!("direct conversation materialization draft expired");
    }

    let submitter = api.event_submitter()?;
    let realm_id = draft.realm_event.realm_id.to_string();
    let actor_id = draft.realm_event.actor_id.to_string();
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!("direct conversation materialization requires an active device signer")
    })?;
    let device_id = signer.device_id().ok_or_else(|| {
        anyhow::anyhow!("direct conversation materialization signer has no device id")
    })?;
    let mut founding_grant_event = draft.founding_grant_event.clone();
    crate::event_submit::attach_capability_grant_payload_proof_with_signer(
        &mut founding_grant_event,
        &signer,
    )?;

    let bootstrap_key =
        pending_direct_conversation_bootstrap_key(draft.materialization_id.as_str());
    let mut accepted = accepted_direct_materialization_events(&submitter, &realm_id).await;
    if !accepted.contains(draft.realm_event.event_id.as_str()) {
        let pending_bootstrap = state_store
            .read()
            .load_private_data(&actor_id, &bootstrap_key)
            .map(|raw| serde_json::from_str::<PendingDirectConversationBootstrap>(&raw))
            .transpose()
            .map_err(|error| {
                anyhow::anyhow!("decode pending direct conversation bootstrap: {error}")
            })?;
        let pending_bootstrap = match pending_bootstrap {
            Some(pending) => pending,
            None => {
                crate::identity::authoring_generation::resolve_event_authoring_generation(
                    submitter.http(),
                    &draft.realm_event,
                )
                .await?;
                let pending = PendingDirectConversationBootstrap {
                    events: submitter
                        .prepare_sdk_events_batch(vec![
                            draft.realm_event.clone(),
                            founding_grant_event,
                            draft.peer_member_event.clone(),
                        ])
                        .await?,
                };
                state_store.write().save_private_data(
                    &actor_id,
                    bootstrap_key.clone(),
                    serde_json::to_string(&pending)?,
                );
                pending
            }
        };
        submitter
            .submit_signed_sdk_events_batch(
                &pending_bootstrap.events,
                Some(draft.materialization_id.as_str()),
            )
            .await?;
        state_store.write().remove_private_data(&bootstrap_key);
        accepted = accepted_direct_materialization_events(&submitter, &realm_id).await;
    } else {
        state_store.write().remove_private_data(&bootstrap_key);
    }

    save_direct_conversation_realm_projection(&mut state_store, &realm_id, &actor_id, peer);
    refresh_direct_conversation_seal(&submitter, &mut state_store, &realm_id).await?;

    if !accepted.contains(draft.main_strand_event.event_id.as_str()) {
        submitter.submit_sdk_event(&draft.main_strand_event).await?;
    }
    refresh_direct_conversation_seal(&submitter, &mut state_store, &realm_id).await?;

    // The signed Commit / Welcome / post-commit MLS snapshot MUST survive a
    // page reload so a resumed materialization replays the SAME Commit and
    // ciphertext instead of rebuilding a divergent one (contact-and-direct-
    // conversation.md: crash recovery MUST replay the same Event id + ciphertext,
    // MUST NOT generate a second Commit). The plaintext-state `save_private_data`
    // channel is a wasm no-op before the IndexedDB tier is ready and otherwise a
    // fire-and-forget enqueue, so a reload mid-flow lost `pending` and the retry
    // hit `epoch-0 MLS snapshot is unavailable`. Persist it through the hardened
    // secure store with an awaited durable write instead.
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let pending_key = pending_direct_conversation_key(draft.materialization_id.as_str());
    let pending_secure_key = direct_conversation_pending_secure_key(&actor_id, &pending_key);
    let mut pending = load_pending_direct_conversation_mls(
        secure_store.as_ref(),
        &state_store,
        &actor_id,
        &pending_key,
        &pending_secure_key,
    )?;
    if pending.is_none() {
        let genesis_request = crate::mls::governance_proof::proof_request(
            &state_store.read(),
            &realm_id,
            None,
            draft.mls_group_id.as_str().to_owned(),
            0,
            0,
        )
        .map_err(anyhow::Error::msg)?;
        crate::mls::governance_proof::fetch_verify_and_cache_proof(
            api,
            state_store,
            &genesis_request,
        )
        .await
        .map_err(anyhow::Error::msg)?;

        let fresh_summary = {
            let mut store = state_store.write();
            crate::mls::runtime::ensure_creator_mls_snapshot(
                &mut store,
                secure_store.as_ref(),
                &realm_id,
                &actor_id,
                &device_id,
            )
            .map_err(|error| anyhow::anyhow!(error.user_message()))?
        };
        let summary = match fresh_summary {
            Some(summary) => summary,
            None => crate::mls::runtime::initial_mls_snapshot_summary_from_existing(
                &state_store.read(),
                secure_store.as_ref(),
                &realm_id,
                &actor_id,
                &device_id,
            )
            .map_err(|error| anyhow::anyhow!(error.user_message()))?
            .ok_or_else(|| {
                anyhow::anyhow!("direct conversation epoch-0 MLS snapshot is unavailable")
            })?,
        };
        if summary.group_id != draft.mls_group_id.as_str() {
            anyhow::bail!(
                "direct conversation MLS group id differs from immutable materialization draft"
            );
        }

        accepted = accepted_direct_materialization_events(&submitter, &realm_id).await;
        if !accepted.contains(draft.mls_genesis_event_ref.as_str()) {
            let mut genesis = crate::mls::group_events::build_creator_mls_genesis_event(
                &mut state_store.write(),
                &realm_id,
                &actor_id,
                &device_id,
                Some(&summary),
            )
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| {
                anyhow::anyhow!("direct conversation MLS genesis Event is unavailable")
            })?;
            genesis.event_id = draft.mls_genesis_event_ref.clone();
            submitter.submit_sdk_event(&genesis).await?;
        }
        state_store
            .write()
            .mark_mls_genesis_emitted_with_event(&realm_id, &draft.mls_genesis_event_ref);
        refresh_direct_conversation_seal(&submitter, &mut state_store, &realm_id).await?;

        let commit_request = crate::mls::governance_proof::proof_request(
            &state_store.read(),
            &realm_id,
            None,
            draft.mls_group_id.as_str().to_owned(),
            0,
            1,
        )
        .map_err(anyhow::Error::msg)?;
        crate::mls::governance_proof::fetch_verify_and_cache_proof(
            api,
            state_store,
            &commit_request,
        )
        .await
        .map_err(anyhow::Error::msg)?;

        let admission = crate::mls::admission::build_realm_mls_admission_events_from_claim(
            &state_store.read(),
            secure_store.as_ref(),
            &realm_id,
            &actor_id,
            &device_id,
            &draft.claimed_keypackage,
            draft.claim_nonce.as_str(),
            draft.claim_receipt.as_ref(),
        )
        .map_err(anyhow::Error::msg)?;
        let mut commit = admission.commit;
        let mut welcome = admission.welcome;
        commit.event_id = draft.mls_commit_event_ref.clone();
        welcome.event_id = draft.mls_welcome_event_ref.clone();
        welcome.payload.insert(
            "commit_ref".to_owned(),
            Value::String(draft.mls_commit_event_ref.to_string()),
        );
        let commit = submitter
            .prepare_sdk_events_batch(vec![commit])
            .await?
            .into_iter()
            .next()
            .expect("single Event preparation preserves cardinality");
        let prepared = PendingDirectConversationMls {
            commit,
            welcome,
            binding: None,
            snapshot: admission.snapshot,
        };
        persist_pending_direct_conversation_mls(
            secure_store.as_ref(),
            &mut state_store,
            &actor_id,
            &pending_key,
            &pending_secure_key,
            &prepared,
        )
        .await?;
        pending = Some(prepared);
    }

    let mut pending = pending.expect("pending direct conversation MLS transaction is initialized");
    submitter.submit_signed_sdk_event(&pending.commit).await?;
    state_store
        .write()
        .record_mls_group_state_ref_for_effective_scope(
            realm_id.clone(),
            None,
            pending.snapshot.group_id.as_str(),
            pending.snapshot.epoch,
            pending.commit.event_id.clone(),
        )
        .map_err(anyhow::Error::msg)?;
    state_store
        .write()
        .save_mls_snapshot(realm_id.clone(), pending.snapshot.clone());
    refresh_direct_conversation_seal(&submitter, &mut state_store, &realm_id).await?;

    if pending.welcome.proofs.is_empty() {
        pending.welcome = submitter
            .prepare_sdk_events_batch(vec![pending.welcome])
            .await?
            .into_iter()
            .next()
            .expect("single Event preparation preserves cardinality");
        persist_pending_direct_conversation_mls(
            secure_store.as_ref(),
            &mut state_store,
            &actor_id,
            &pending_key,
            &pending_secure_key,
            &pending,
        )
        .await?;
    }
    submitter.submit_signed_sdk_event(&pending.welcome).await?;
    refresh_direct_conversation_seal(&submitter, &mut state_store, &realm_id).await?;

    if pending.binding.is_none() {
        pending.binding = Some(
            submitter
                .prepare_sdk_events_batch(vec![draft.binding_event.clone()])
                .await?
                .into_iter()
                .next()
                .expect("single Event preparation preserves cardinality"),
        );
        persist_pending_direct_conversation_mls(
            secure_store.as_ref(),
            &mut state_store,
            &actor_id,
            &pending_key,
            &pending_secure_key,
            &pending,
        )
        .await?;
    }
    submitter
        .submit_signed_sdk_event(
            pending
                .binding
                .as_ref()
                .expect("pending direct binding is initialized"),
        )
        .await?;
    state_store.write().remove_private_data(&pending_key);
    let _ = secure_store.delete_secret(&pending_secure_key);
    Ok(())
}

async fn accepted_direct_materialization_events(
    submitter: &EventSubmitter,
    realm_id: &str,
) -> std::collections::BTreeSet<String> {
    submitter
        .backfill(realm_id)
        .await
        .map(|view| {
            view.events
                .into_iter()
                .map(|event| event.event_id.to_string())
                .collect()
        })
        .unwrap_or_default()
}

async fn refresh_direct_conversation_seal(
    submitter: &EventSubmitter,
    state_store: &mut SyncSignal<crate::state::LocalStateStore>,
    realm_id: &str,
) -> anyhow::Result<()> {
    const ATTEMPTS: usize = 20;
    for attempt in 0..ATTEMPTS {
        match submitter.events_frontier_realm_seal_view(realm_id).await {
            Ok(view) => {
                state_store.write().set_realm_seal_view(
                    realm_id.to_owned(),
                    crate::state::LocalSealView {
                        frontier: vec![view.seal_id.to_string()],
                        state_root: Some(view.state_root.to_string()),
                        ..Default::default()
                    },
                );
                return Ok(());
            }
            Err(error)
                if attempt + 1 < ATTEMPTS
                    && (error.to_string().contains("404")
                        || error.to_string().contains("no accepted Seal")) =>
            {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(250)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("direct conversation Seal retry loop returns on its final attempt")
}

fn save_direct_conversation_realm_projection(
    state_store: &mut SyncSignal<crate::state::LocalStateStore>,
    realm_id: &str,
    actor_id: &str,
    peer: &str,
) {
    let projection = crate::realm_tree::OptimisticRealmTreeProjection::realm(
        crate::realm_tree::RealmProjectionInput {
            owner: actor_id.to_owned(),
            admins: vec![actor_id.to_owned()],
            members: vec![actor_id.to_owned(), peer.to_owned()],
            title: "Direct conversation".to_owned(),
            summary: String::new(),
            discoverability: "invite_only".to_owned(),
            encryption_profile: "mls_rfc9420".to_owned(),
            content_scheme: "mls-rfc9420".to_owned(),
            history_visibility: "joined".to_owned(),
            plaintext_visible_services: Vec::new(),
            encryption_floor: Some(
                crate::realm_defaults::RECOMMENDED_REALM_ENCRYPTION_FLOOR.to_owned(),
            ),
        },
    )
    .into_value();
    state_store
        .write()
        .save_realm_tree_projection(realm_id.to_owned(), projection);
}

async fn sign_peer_keypackage_claim_authorization(
    http: &arkret_sdk::http_client::Client,
    draft: &arkret_sdk::PeerKeyPackagesClaimAuthorizationDraft,
) -> anyhow::Result<arkret_sdk::PeerKeyPackagesClaimRequestBody> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!("no active signer configured for remote KeyPackage authorization")
    })?;
    let requester = draft.request.requester.clone();
    let device_id = signer.device_id().ok_or_else(|| {
        anyhow::anyhow!("active signer has no device id for remote KeyPackage authorization")
    })?;
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned())?;
    let keys =
        crate::transport::keys::query_keys(http, requester.as_str(), device_id.as_str()).await?;
    let device = keys
        .device_keys
        .get(&requester)
        .and_then(|devices| devices.get(&device_id))
        .ok_or_else(|| anyhow::anyhow!("active signing device is absent from the key directory"))?;
    if device.device_status != Some(arkret_models_crypto::DeviceStatus::Active) {
        anyhow::bail!("active signing device is not accepted by the key directory");
    }
    let device_authorize_event_id = device
        .device_authorize_event_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("active signing device omits device authorization proof"))?;
    let verification_method =
        arkret_sdk::NonEmptyString::new(format!("{}#{}", requester, device_id))
            .map_err(anyhow::Error::msg)?;
    let signed_at = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
        .ok_or_else(|| anyhow::anyhow!("current authorization timestamp is invalid"))?;
    let mut authorization = arkret_sdk::PeerKeyPackageRequesterAuthorization {
        verification_method: verification_method.clone(),
        requester_device_id: Some(device_id),
        ssk_generation: None,
        device_authorize_event_id: Some(
            arkret_sdk::NonEmptyString::new(device_authorize_event_id.as_str())
                .map_err(anyhow::Error::msg)?,
        ),
        signed_at,
        signature: arkret_sdk::KeyOperationSignature {
            kid: verification_method,
            alg: Some(arkret_sdk::NonEmptyString::new("EdDSA").map_err(anyhow::Error::msg)?),
            sig: arkret_sdk::Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
        },
    };
    let signing_bytes =
        arkret_sdk::peer_keypackage_claim_authorization_signing_bytes(draft, &authorization)?;
    authorization.signature.sig =
        arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signer.sign_raw(&signing_bytes)?))
            .map_err(anyhow::Error::msg)?;

    let request = &draft.request;
    let body = arkret_sdk::PeerKeyPackagesClaimRequestBody {
        claim_request_id: request.claim_request_id.clone(),
        target_principal_id: request.target_principal_id.clone(),
        requester: request.requester.clone(),
        intended_realm_id: request.intended_realm_id.clone(),
        mls_group_id: request.mls_group_id.clone(),
        claim_purpose: request.claim_purpose,
        required_capabilities: request.required_capabilities.clone(),
        claim_nonce: request.claim_nonce.clone(),
        expires_at: request.expires_at,
        target_device_ids: request.target_device_ids.clone(),
        minimal_metadata_allowed: request.minimal_metadata_allowed,
        timeout_ms: request.timeout_ms,
        strand_id: request.strand_id.clone(),
        pair_key: request.pair_key.clone(),
        allow_last_resort: request.allow_last_resort,
        requester_authorization: authorization,
        requester_signing_key_evidence: None,
    };
    body.validate_shape()
        .map_err(|error| anyhow::anyhow!("remote KeyPackage claim shape is invalid: {error}"))?;
    Ok(body)
}

/// List the holder-private consent cells visible to the authenticated
/// actor (cells where the actor is either holder or peer). Spec
/// `identity/consent-model.md` §3 / OpenAPI `ak.self.consent.query.list`.
pub async fn consent_cells(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::ConsentCellList> {
    http.get(arkret_wire::PATH_SELF_CONSENT_CELLS)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn identity_describe(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<IdentityDescribeOutcome> {
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

pub async fn invites(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::AuthzInviteList> {
    let subject = account_me(http).await?.did;
    http.authz_invites(&subject, None, None)
        .await
        .map_err(anyhow::Error::from)
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
        did: viewer.principal_id.as_str().to_owned(),
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
            claim.subject.as_ref() == Some(&viewer.principal_id)
                && claim.binding_state == Some(arkret_models_identity::HandleBindingState::Verified)
        })
        .and_then(|claim| claim.handle.as_ref())
        .map(|handle| handle.canonical().trim())
        .filter(|handle| !handle.is_empty())
        .unwrap_or_default()
        .to_owned()
}

/// Tombstone a contact relationship via `contacts/tombstone`. When
/// `block_peer` is true the protocol additionally records a block so the
/// peer can no longer re-request; this is the block path (U5).
///
/// Protocol contract: `contacts/tombstone` body carries `contact` and an
/// optional `block_peer: true`.
pub async fn tombstone_contact(
    http: &arkret_sdk::http_client::Client,
    peer: &str,
    block_peer: bool,
) -> anyhow::Result<arkret_sdk::ContactTombstone> {
    let body = arkret_sdk::ContactTombstoneRequestBody {
        contact: did_for_request_field("contact", peer)?,
        revoke_scopes: Vec::new(),
        full_peer_revoke: false,
        block_peer,
        peer_service_id: None,
    };
    http.contacts_tombstone(&body)
        .await
        .map_err(anyhow::Error::from)
}

/// Grant scoped consent to `peer` from the holder cell. `expires_at` is an
/// optional RFC 3339 time window upper bound. Spec OpenAPI
/// `ak.self.consent.command.grant`.
pub async fn grant_consent(
    http: &arkret_sdk::http_client::Client,
    holder: &str,
    peer: &str,
    scope: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<arkret_sdk::ConsentCellView> {
    let body = arkret_sdk::ConsentUpdateRequestBody {
        peer_did: did_for_request_field("peer", peer)?,
        consent_scope: Some(scope.trim().to_owned()),
        expires_at,
    };
    let path = format!(
        "{}/{}/grant",
        arkret_wire::PATH_SELF_CONSENT_CELLS,
        crate::wire_helpers::path_component(holder.trim()),
    );
    http.post(&path, &body).await.map_err(anyhow::Error::from)
}

/// Revoke scoped consent from `peer`. Spec OpenAPI
/// `ak.self.consent.command.revoke`.
pub async fn revoke_consent(
    http: &arkret_sdk::http_client::Client,
    holder: &str,
    peer: &str,
    scope: &str,
) -> anyhow::Result<arkret_sdk::ConsentCellView> {
    let body = arkret_sdk::ConsentUpdateRequestBody {
        peer_did: did_for_request_field("peer", peer)?,
        consent_scope: Some(scope.trim().to_owned()),
        expires_at: None,
    };
    let path = format!(
        "{}/{}/revoke",
        arkret_wire::PATH_SELF_CONSENT_CELLS,
        crate::wire_helpers::path_component(holder.trim()),
    );
    http.post(&path, &body).await.map_err(anyhow::Error::from)
}

/// Open an outbound consent request: ask `holder` to grant the
/// authenticated actor (`peer`) the given scope. Produces a holder-side
/// pending cell. Spec OpenAPI `ak.self.consent.command.request`.
pub async fn request_consent(
    http: &arkret_sdk::http_client::Client,
    holder: &str,
    peer: &str,
    scope: &str,
) -> anyhow::Result<arkret_sdk::ConsentCellView> {
    let body = arkret_sdk::ConsentRequestRequestBody {
        holder_did: did_for_request_field("holder", holder)?,
        peer_did: Some(did_for_request_field("peer", peer)?),
        consent_scope: Some(scope.trim().to_owned()),
    };
    http.post(arkret_wire::PATH_SELF_CONSENT_REQUEST, &body)
        .await
        .map_err(anyhow::Error::from)
}

/// Submit a `did:webvh` DID operation (inception / rotation) to soland's
/// embedded identity provider. Spec op
/// `ak.root.identity.command.submit_did_operation`
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

async fn account_data_actor_scope(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<(String, String)> {
    let account = account_me(http).await?;
    let principal = arkret_sdk::Did::new(account.did.clone())
        .map_err(|err| anyhow::anyhow!("invalid account DID `{}`: {err}", account.did))?;
    let realm_id = arkret_sdk::principal_control_realm_id(&principal);
    Ok((account.did, realm_id.to_string()))
}

/// Submit a per-account `ak.account_data.set` event so settings UIs can
/// push preferences (for example `ak.read_receipt.preferences`) to soland
/// for cross-device sync.
pub async fn set_account_data(
    submitter: &EventSubmitter,
    type_key: &str,
    content: Value,
) -> anyhow::Result<Value> {
    let (actor, principal_realm_id) = account_data_actor_scope(submitter.http()).await?;
    let key = crate::account_data::AccountDataKey::from_wire(type_key);
    let event =
        crate::account_data::build_account_data_set(&principal_realm_id, &actor, &key, content)
            .build_sdk_event("inkson-account-data")?;
    Ok(serde_json::to_value(
        submitter.submit_sdk_event(&event).await?,
    )?)
}

/// Submit a private account-data value with an optional CAS guard. Callers
/// pass already-encrypted account-data material; plaintext draft/saved
/// content must not cross this API boundary.
pub async fn set_private_account_data_with_cas(
    submitter: &EventSubmitter,
    type_key: &str,
    encrypted_payload: Value,
    expected_state_digest: Option<&str>,
) -> anyhow::Result<Value> {
    let (actor, principal_realm_id) = account_data_actor_scope(submitter.http()).await?;
    let event = crate::account_data::build_private_account_data_set_with_cas(
        &principal_realm_id,
        &actor,
        type_key,
        encrypted_payload,
        expected_state_digest,
    )?
    .build_sdk_event("inkson-private-account-data")?;
    Ok(serde_json::to_value(
        submitter.submit_sdk_event(&event).await?,
    )?)
}

/// Tombstone an account_data entry by submitting `ak.account_data.set` with
/// `tombstone: true`.
pub async fn delete_account_data(submitter: &EventSubmitter, type_key: &str) -> anyhow::Result<()> {
    let (actor, principal_realm_id) = account_data_actor_scope(submitter.http()).await?;
    let key = crate::account_data::AccountDataKey::from_wire(type_key);
    let event =
        crate::account_data::build_account_data_tombstone(&principal_realm_id, &actor, &key)
            .build_sdk_event("inkson-account-data")?;
    submitter.submit_sdk_event(&event).await?;
    Ok(())
}

pub async fn submit_read_cursor_advance(
    submitter: &EventSubmitter,
    marker: &crate::state::ReadMarkerRecord,
) -> anyhow::Result<SubmitEventResult> {
    let event = crate::ephemeral::build_read_cursor_advance_event(marker)?;
    submitter.submit_sdk_event(&event).await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn account_viewer_projection_uses_signed_handle_claim() {
        let viewer: arkret_models_collaboration::account_lifecycle::AccountView =
            serde_json::from_value(json!({
                "principal_id": "did:web:alice.example",
                "state": "active",
                "devices": [],
                "primary_handle_claim": {
                    "schema": "ak.schema.handle_claim.v1",
                    "handle": "alice:local.host",
                    "subject": "did:web:alice.example",
                    "binding_state": "verified"
                },
                "profile": {
                    "id": "ak:actor_profile:01970000-0000-7000-8000-000000000001",
                    "schema": "ak.schema.actor_profile.v1",
                    "principal_id": "did:web:alice.example",
                    "actor_kind": "user",
                    "display_name": "Alice",
                    "created_at": "2026-06-12T08:00:00.000Z"
                }
            }))
            .expect("account viewer shape");

        let account = current_account_from_viewer(viewer);

        assert_eq!(account.did, "did:web:alice.example");
        assert_eq!(account.handle, "alice:local.host");
        assert_eq!(account.display_name.as_deref(), Some("Alice"));
        assert_eq!(account.created_at, "2026-06-12T08:00:00.000Z");
    }

    #[test]
    fn account_viewer_projection_rejects_unverified_or_foreign_handle_claim() {
        for (subject, binding_state) in [
            ("did:web:mallory.example", "verified"),
            ("did:web:alice.example", "pending"),
        ] {
            let viewer: arkret_models_collaboration::account_lifecycle::AccountView =
                serde_json::from_value(json!({
                    "principal_id": "did:web:alice.example",
                    "state": "active",
                    "devices": [],
                    "primary_handle_claim": {
                        "schema": "ak.schema.handle_claim.v1",
                        "handle": "alice:auth.local.host",
                        "subject": subject,
                        "binding_state": binding_state
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
                "principal_id": "did:web:alice.example",
                "state": "active",
                "devices": []
            }))
            .expect("minimal account viewer shape");

        let account = current_account_from_viewer(viewer);

        assert_eq!(account.did, "did:web:alice.example");
        assert_eq!(account.handle, "");
        assert_eq!(account.display_name, None);
        assert_eq!(account.created_at, "");
    }

    #[test]
    fn direct_founding_grant_gets_a_verifiable_issuer_attestation() {
        let actor = "did:web:alice.example";
        let event: arkret_sdk::Event = serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "kind": "ak.capability.grant",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
            "actor_id": actor,
            "actor_seq": 2,
            "created_at": "2026-07-21T08:00:00.000Z",
            "hlc": "019041000000-0002-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "grant_id": "ak:grant:01904100-0000-7000-8000-000000000003",
                "grant": {
                    "id": "ak:grant:01904100-0000-7000-8000-000000000003",
                    "schema": "ak.schema.capability.v1",
                    "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
                    "issuer": actor,
                    "subject": actor,
                    "actions": ["ak.realm.configure"],
                    "resources": [{
                        "kind": "realm",
                        "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-07-21T08:00:00.000Z",
                    "proofs": []
                }
            },
            "proofs": []
        }))
        .expect("unsigned founding grant Event");
        let signer = crate::event_signer::build_ed25519_device_signer(
            [17_u8; 32],
            "did:key:zfixture",
            "ak:device:01904100-0000-7000-8000-000000000004",
        );

        let mut signed = event;
        crate::event_submit::attach_capability_grant_payload_proof_with_signer(
            &mut signed,
            &signer,
        )
        .expect("sign founding grant");
        let grant: arkret_sdk::CapabilityGrant =
            serde_json::from_value(signed.payload["grant"].clone()).expect("signed grant");
        assert_eq!(grant.proofs.len(), 1);
        let proof = &grant.proofs[0];
        assert_eq!(
            proof.proof_purpose,
            Some(arkret_sdk::PayloadProofPurpose::IssuerAttestation)
        );
        assert_eq!(proof.payload_digest, grant.payload_digest().unwrap());
        let public_key = arkret_sdk::signatures::PublicKeyMaterial::Ed25519Multibase {
            value: signer.public_key_multibase().expect("local public key"),
        };
        arkret_sdk::signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &proof.jws,
                &grant.canonical_proof_binding_bytes(proof).unwrap(),
                &public_key,
            )
            .expect("issuer attestation verifies");
    }
}
