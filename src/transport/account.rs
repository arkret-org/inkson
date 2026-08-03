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

use dioxus::prelude::{SyncSignal, WritableExt};
use serde_json::Value;

use crate::event_submit::EventSubmitter;
use crate::models::{
    ContactListView, CurrentAccount, IdentityDescribeOutcome, IdentityResolveOutcome,
};

pub(crate) fn did_for_request_field(field: &str, value: &str) -> anyhow::Result<arkret_sdk::Did> {
    let value = value.trim();
    arkret_sdk::Did::new(value.to_owned())
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
    _http: &arkret_sdk::http_client::Client,
    requester: &str,
    action: &str,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "Contact {action} for `{requester}` is unavailable: the Contact projection does not expose the signed request acceptance receipt required by prepare"
    )
}

/// Respond to an incoming contact request, optionally carrying the
/// requester's Principal Server service DID for cross-PS reverse delivery.
///
/// Protocol contract (soland finalized): the `contacts/respond` body
/// accepts an optional `requester_service_id`. Same-PS responses leave it
/// empty; cross-PS responses pass the originating PS so soland can route the
/// accept/reject back. Empty / whitespace-only values are dropped.
pub async fn respond_contact_with_service(
    _http: &arkret_sdk::http_client::Client,
    requester: &str,
    action: &str,
    _requester_service_id: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "Contact {action} for `{requester}` is unavailable: the Contact projection does not expose the signed request acceptance receipt required by prepare"
    )
}

pub async fn respond_contact_with_request_id_and_service(
    _http: &arkret_sdk::http_client::Client,
    requester: &str,
    _request_event_ref: &str,
    action: &str,
    _requester_service_id: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "Contact {action} for `{requester}` is unavailable: request_event_ref alone is not the signed request acceptance receipt required by prepare"
    )
}

pub async fn contacts(http: &arkret_sdk::http_client::Client) -> anyhow::Result<ContactListView> {
    http.contacts_list().await.map_err(anyhow::Error::from)
}

/// Read the actor's `invite_receive_policy` ("who can invite me", U4).
///
/// Spec `invite-addressing.md` §5 / OpenAPI
/// `ak.self.invite_receive_policy.resource.get`: served from the self plane at
/// `GET /_arkret/self/invite-receive-policy` and returns the bare
/// `arkret_sdk::InviteReceivePolicy` (soland echoes the stored override or
/// its recommended default). When the deployment does not yet wire this
/// surface the caller treats 404/501/405 as "use defaults" rather than a
/// hard error; the settings surface keeps the SDK fail-closed default.
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
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    peer: &str,
    create: bool,
    enable_owned_agent_reply: bool,
) -> anyhow::Result<arkret_sdk::protocol_journey::DirectConversationResolveOutcome> {
    if create {
        anyhow::bail!(
            "Direct Conversation creation is unavailable until the full authorization/materialization ceremony is wired"
        );
    }
    let http = api.http();
    let body = arkret_sdk::protocol_journey::DirectConversationResolveRequestBody::Lookup(
        arkret_sdk::protocol_journey::DirectConversationLookupRequestBody {
            peer: arkret_sdk::protocol_journey::ContactPeer::Human {
                principal_id: did_for_request_field("peer", peer)?,
            },
            create: arkret_sdk::protocol_journey::DirectConversationLookupMarker,
        },
    );
    let outcome = http
        .direct_conversation_resolve(&body)
        .await
        .map_err(anyhow::Error::from)?;
    if enable_owned_agent_reply && direct_conversation_coordinates(&outcome).is_some() {
        preserve_resolved_direct_conversation(
            peer,
            &outcome,
            ensure_owned_agent_direct_reply(http, state_store, peer, &outcome).await,
        );
    }
    if direct_conversation_coordinates(&outcome).is_some() {
        remember_direct_conversation_peer(&mut state_store, peer, &outcome);
    }
    Ok(outcome)
}

fn direct_conversation_peer_cache_key(realm_id: &str, strand_id: &str) -> String {
    format!("direct_conversation.peer.{realm_id}.{strand_id}")
}

pub(crate) fn direct_conversation_coordinates(
    outcome: &arkret_sdk::protocol_journey::DirectConversationResolveOutcome,
) -> Option<&arkret_sdk::protocol_journey::DirectConversationCoordinates> {
    match outcome {
        arkret_sdk::protocol_journey::DirectConversationResolveOutcome::State(
            arkret_sdk::protocol_journey::DirectConversationResolveStateOutcome::Found {
                coordinates,
                ..
            }
            | arkret_sdk::protocol_journey::DirectConversationResolveStateOutcome::Suspended {
                coordinates,
                ..
            },
        ) => Some(coordinates),
        arkret_sdk::protocol_journey::DirectConversationResolveOutcome::Tombstoned(outcome) => {
            Some(&outcome.coordinates)
        }
        _ => None,
    }
}

const DIRECT_CONVERSATION_PEER_CACHE_OBFUSCATION_KEY: &str = "ak.local.direct_conversation.peer.v1";

fn remember_direct_conversation_peer(
    state_store: &mut SyncSignal<crate::state::LocalStateStore>,
    peer: &str,
    outcome: &arkret_sdk::protocol_journey::DirectConversationResolveOutcome,
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
    outcome: &arkret_sdk::protocol_journey::DirectConversationResolveOutcome,
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
    outcome: &arkret_sdk::protocol_journey::DirectConversationResolveOutcome,
) -> anyhow::Result<()> {
    let coordinates = direct_conversation_coordinates(outcome)
        .ok_or_else(|| anyhow::anyhow!("owned-Agent Direct Conversation omitted realm_id"))?;
    let realm_id = coordinates.realm_id.clone();
    let strand_id = coordinates.main_strand_id.clone();
    let scope = arkret_sdk::protocol_journey::ParticipationScope::Strand {
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
        .entries
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
    state_store.write().record_mls_coverage_stale(
        scope.realm_id().as_str().to_owned(),
        None,
        "agent reply participation grant changed the Realm governance frontier",
    );
    Ok(())
}

pub(crate) async fn replace_agent_participation(
    http: &arkret_sdk::http_client::Client,
    agent_id: &str,
    scope: arkret_sdk::protocol_journey::ParticipationScope,
    selection: arkret_sdk::protocol_journey::ParticipationBits,
) -> anyhow::Result<arkret_sdk::AgentParticipationOutcome> {
    let current = http.agent_participation_get(agent_id).await?;
    let expected_version = current
        .entries
        .iter()
        .find(|entry| entry.scope == scope)
        .map(|entry| entry.version)
        .unwrap_or(0);
    let request = arkret_sdk::protocol_journey::ParticipationReplaceRequestBody {
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
    scope: &arkret_sdk::protocol_journey::ParticipationScope,
) -> bool {
    outcome
        .entries
        .iter()
        .any(|entry| &entry.scope == scope && entry.selection.reply_message)
}

fn owned_agent_reply_update_needed(
    outcome: &arkret_sdk::AgentParticipationOutcome,
    scope: &arkret_sdk::protocol_journey::ParticipationScope,
) -> bool {
    !participation_reply_is_effective(outcome, scope)
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
    _http: &arkret_sdk::http_client::Client,
    peer: &str,
    _block_peer: bool,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "Contact tombstone for `{peer}` is unavailable: the Contact projection does not expose basis_id, version and predecessor_event_ref required by prepare"
    )
}

/// Complete the non-blocklist legs of a personal block saga using the
/// standard contact command. `full_peer_revoke` revokes every consent scope
/// while the tombstone removes the contact projection; no private endpoint or
/// receiver-visible block response is introduced.
pub async fn tombstone_contact_and_revoke_all(
    _http: &arkret_sdk::http_client::Client,
    peer: &str,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "Contact tombstone for `{peer}` is unavailable: the Contact projection does not expose basis_id, version and predecessor_event_ref required by prepare"
    )
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

const ACCOUNT_DATA_RESOURCE_PATH: &str = "/_arkret/self/account_data";
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
    let path = format!(
        "{ACCOUNT_DATA_RESOURCE_PATH}/{}",
        crate::wire_helpers::path_component(type_key),
    );
    match http.get::<arkret_sdk::AccountDataRow>(&path).await {
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
    let path = format!(
        "{ACCOUNT_DATA_RESOURCE_PATH}/{}",
        crate::wire_helpers::path_component(type_key),
    );
    let mut snapshot = account_data_snapshot(submitter.http(), type_key).await?;
    for attempt in 1..=MAX_ACCOUNT_DATA_CAS_ATTEMPTS {
        let body = arkret_sdk::AccountDataReplaceRequestBody {
            expected_revision: snapshot.revision,
            content: merge(&snapshot)?,
        };
        match submitter
            .http()
            .put::<_, arkret_sdk::AccountDataRow>(&path, &body)
            .await
        {
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
        let path = format!(
            "{ACCOUNT_DATA_RESOURCE_PATH}/{}?expected_revision={}",
            crate::wire_helpers::path_component(type_key),
            snapshot.revision,
        );
        match submitter
            .http()
            .delete::<arkret_sdk::AccountDataDeleteOutcome>(&path)
            .await
        {
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

pub async fn submit_read_cursor_advance(
    submitter: &EventSubmitter,
    marker: &crate::state::ReadMarkerRecord,
) -> anyhow::Result<arkret_sdk::ReadMarkerOutcome> {
    let body = arkret_sdk::ReadCursorAdvanceRequestBody {
        realm_id: arkret_sdk::RealmId::new(marker.body.realm_id.clone())?,
        read_scope: marker.body.read_scope.clone(),
        position: marker.body.position.clone(),
    };
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
    fn effective_owned_agent_reply_does_not_request_another_governance_write() {
        let scope = arkret_sdk::protocol_journey::ParticipationScope::Strand {
            realm_id: arkret_sdk::RealmId::new("ak:realm:01970000-0000-7000-8000-000000000001")
                .expect("realm id"),
            strand_id: arkret_sdk::StrandId::new("ak:strand:01970000-0000-7000-8000-000000000002")
                .expect("strand id"),
        };
        let outcome: arkret_sdk::AgentParticipationOutcome = serde_json::from_value(json!({
            "ok": true,
            "agent_id": "did:web:agent.example",
            "entries": [{
                "target_scope": scope,
                "selection": {
                    "reply_message": true,
                    "reaction_add": false,
                    "reaction_remove": false,
                    "accept_third_party_mention": false,
                    "act_on_behalf": false
                },
                "version": 1
            }]
        }))
        .expect("participation outcome");

        assert!(!owned_agent_reply_update_needed(&outcome, &scope));
    }

    #[test]
    fn reply_enablement_failure_does_not_invalidate_resolved_direct_conversation() {
        let outcome: arkret_sdk::protocol_journey::DirectConversationResolveOutcome =
            serde_json::from_value(json!({
                "state": "found",
                "coordinates": {
                    "pair_key": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "realm_id": "ak:realm:01970000-0000-7000-8000-000000000001",
                    "main_strand_id": "ak:strand:01970000-0000-7000-8000-000000000002",
                    "binding_event_ref": "ak:event:01970000-0000-7000-8000-000000000003"
                },
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
            "ak:realm:01970000-0000-7000-8000-000000000001"
        );
        assert_eq!(
            coordinates.main_strand_id.as_str(),
            "ak:strand:01970000-0000-7000-8000-000000000002"
        );
    }
}
