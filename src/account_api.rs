//! Free-function account/self READ + simple-write transport (E2 CokretApi
//! strangler).
//!
//! These are the pure-passthrough account/self operations that used to live as
//! thin inherent methods on [`crate::api::CokretApi`]. They build a typed SDK
//! request body (and do input validation / small projections) and call the
//! shared SDK `http-client::Client` directly. Call sites reach them through
//! [`crate::authed_api::with_authed_sdk_client`], which keeps the
//! session-refresh + terminal-session classification identical to the old
//! facade path while dropping the per-domain facade method.
//!
//! The durable-event-authoring account writes (`set_account_data`,
//! `set_private_account_data_with_cas`, `delete_account_data`,
//! `submit_read_cursor_advance`) are free functions taking an
//! [`crate::event_submit::EventSubmitter`], reached through
//! [`crate::authed_api::with_event_submitter`]; the account-data actor-scope
//! lookup they need runs through `submitter.http()`.
//!
//! Only the `request_contact` family remains an inherent `CokretApi` method,
//! because it resolves contact addressing via the struct-cached
//! `describe_cached` (see `contact_request_addressing`).

use serde_json::Value;

use crate::event_submit::EventSubmitter;
use crate::models::{
    AccountDataSetResult, ContactListView, CurrentAccount, IdentityDescribeOutcome,
    IdentityResolveOutcome, SubmitEventResult,
};

pub(crate) fn did_for_request_field(field: &str, value: &str) -> anyhow::Result<arkret_sdk::Did> {
    let value = value.trim();
    arkret_sdk::Did::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid {field} DID `{value}`: {err}"))
}

fn device_id_for_request_field(field: &str, value: &str) -> anyhow::Result<arkret_sdk::DeviceId> {
    let value = value.trim();
    arkret_sdk::DeviceId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid {field} `{value}`: {err}"))
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

pub async fn register_account(
    http: &arkret_sdk::http_client::Client,
    did: &str,
    _handle: &str,
    display_name: Option<&str>,
    device_id: Option<&str>,
) -> anyhow::Result<arkret_sdk::models::AccountRegisterOutcome> {
    let body = arkret_sdk::models::AccountRegisterRequestBody {
        principal_id: did_for_request_field("principal_id", did)?,
        // Canonical registration handle is asserted by the Account Authority
        // on the coauth -> soland register path; this direct client path
        // leaves it unset (the Principal Server falls back to a synthetic
        // bootstrap localpart).
        handle: None,
        display_name: display_name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        device_id: device_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| device_id_for_request_field("device_id", value))
            .transpose()?,
        policy_evidence: None,
        proof: None,
    };
    http.account_register(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn account_viewer(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::models::AccountView> {
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
) -> anyhow::Result<arkret_sdk::models::AccountUpdateProfileOutcome> {
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
    let body = arkret_sdk::models::AccountUpdateProfileRequestBody {
        patch: serde_json::to_value(&patch)?,
    };
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
/// accepts an optional `requester_service_did`. Same-PS responses leave it
/// empty; cross-PS responses pass the originating PS so soland can route the
/// accept/reject back. Empty / whitespace-only values are dropped.
pub async fn respond_contact_with_service(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
    action: &str,
    requester_service_did: Option<&str>,
) -> anyhow::Result<arkret_sdk::ContactRespondOutcome> {
    let request_event_ref = contact_request_event_id_for_requester(http, requester).await?;
    respond_contact_with_request_id_and_service(
        http,
        requester,
        &request_event_ref,
        action,
        requester_service_did,
    )
    .await
}

pub async fn respond_contact_with_request_id_and_service(
    http: &arkret_sdk::http_client::Client,
    requester: &str,
    request_event_ref: &str,
    action: &str,
    requester_service_did: Option<&str>,
) -> anyhow::Result<arkret_sdk::ContactRespondOutcome> {
    let body = arkret_sdk::ContactRespondRequestBody {
        request_id: arkret_sdk::EventId::new(request_event_ref.trim().to_owned()).map_err(
            |err| anyhow::anyhow!("invalid contact request_id `{request_event_ref}`: {err}"),
        )?,
        requester: did_for_request_field("requester", requester)?,
        action: contact_response_action(action)?,
        granted_scopes: Vec::new(),
        requester_service_did: optional_did_for_request_field(
            "requester_service_did",
            requester_service_did,
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
    http: &arkret_sdk::http_client::Client,
    peer: &str,
    create: bool,
) -> anyhow::Result<arkret_sdk::DirectConversationResolveOutcome> {
    let body = arkret_sdk::DirectConversationResolveRequestBody {
        peer: did_for_request_field("peer", peer)?,
        create,
        idempotency_key: None,
    };
    http.direct_conversation_resolve(&body)
        .await
        .map_err(anyhow::Error::from)
}

/// List the holder-private consent cells visible to the authenticated
/// actor (cells where the actor is either holder or peer). Spec
/// `identity/consent-model.md` §3 / OpenAPI `ak.self.consent.query.list`.
pub async fn consent_cells(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::ConsentCellList> {
    http.get(arkret_sdk::http::PATH_SELF_CONSENT_CELLS)
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
    let body = arkret_sdk::models::IdentityResolveRequestBody {
        did: subject,
        requested_evidence_kinds: Vec::new(),
    };
    http.identity_resolve(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn sync_describe(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::models::SyncDescription> {
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

fn current_account_from_viewer(viewer: arkret_sdk::models::AccountView) -> CurrentAccount {
    let display_name = viewer.profile.as_ref().and_then(|profile| {
        let value = profile.display_name.trim();
        (!value.is_empty()).then(|| value.to_owned())
    });
    let created_at = viewer
        .profile
        .as_ref()
        .map(|profile| {
            profile
                .created_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        })
        .unwrap_or_default();
    CurrentAccount {
        did: viewer.principal_id.as_str().to_owned(),
        handle: primary_handle_from_viewer(&viewer),
        display_name,
        created_at,
    }
}

fn primary_handle_from_viewer(viewer: &arkret_sdk::models::AccountView) -> String {
    viewer
        .primary_handle_claim
        .as_ref()
        .and_then(|claim| claim.get("handle"))
        .and_then(Value::as_str)
        .map(str::trim)
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
        peer_service_did: None,
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
        arkret_sdk::http::PATH_SELF_CONSENT_CELLS,
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
        arkret_sdk::http::PATH_SELF_CONSENT_CELLS,
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
    http.post(arkret_sdk::http::PATH_SELF_CONSENT_REQUEST, &body)
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
    body: &arkret_sdk::models::DidOperationSubmitRequestBody,
) -> anyhow::Result<arkret_sdk::models::DidOperationSubmitOutcome> {
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
    let realm_id = arkret_sdk::auth::principal_control_realm_id(&principal);
    Ok((account.did, realm_id.to_string()))
}

/// Submit a per-account `ak.account_data.set` event so settings UIs can
/// push preferences (for example `ak.read_receipt.preferences`) to soland
/// for cross-device sync. If the current server cannot resolve the
/// principal control Realm yet, 404 / 501 / 405 still degrade to
/// `Unsupported` and local state remains authoritative.
pub async fn set_account_data(
    submitter: &EventSubmitter,
    type_key: &str,
    content: Value,
) -> anyhow::Result<AccountDataSetResult> {
    let (actor, principal_realm_id) = match account_data_actor_scope(submitter.http()).await {
        Ok(scope) => scope,
        Err(error) => {
            if let Some(status) = crate::api_error::unsupported_endpoint_status(&error) {
                tracing::warn!(
                    "principal-realm lookup for account_data returned {status}; \
                     keeping local state authoritative"
                );
                return Ok(AccountDataSetResult::Unsupported { status });
            }
            return Err(error);
        }
    };
    let key = crate::account_data::AccountDataKey::from_wire(type_key);
    let event =
        crate::account_data::build_account_data_set(&principal_realm_id, &actor, &key, content)
            .build_sdk_event("inkson-account-data")?;
    let result = submitter.submit_sdk_event(&event).await;
    match result {
        Ok(value) => Ok(AccountDataSetResult::Stored {
            response: serde_json::to_value(value)?,
        }),
        Err(error) => {
            if let Some(status) = crate::api_error::unsupported_endpoint_status(&error) {
                tracing::warn!(
                    "ak.account_data.set submit for {type_key} returned {status}; \
                     keeping local state authoritative"
                );
                return Ok(AccountDataSetResult::Unsupported { status });
            }
            Err(error)
        }
    }
}

/// Submit a private account-data value with an optional CAS guard. Callers
/// pass already-encrypted account-data material; plaintext draft/saved
/// content must not cross this API boundary.
pub async fn set_private_account_data_with_cas(
    submitter: &EventSubmitter,
    type_key: &str,
    encrypted_payload: Value,
    expected_state_digest: Option<&str>,
) -> anyhow::Result<AccountDataSetResult> {
    let (actor, principal_realm_id) = match account_data_actor_scope(submitter.http()).await {
        Ok(scope) => scope,
        Err(error) => {
            if let Some(status) = crate::api_error::unsupported_endpoint_status(&error) {
                tracing::warn!(
                    "principal-realm lookup for private account_data returned {status}; \
                     keeping local state authoritative"
                );
                return Ok(AccountDataSetResult::Unsupported { status });
            }
            return Err(error);
        }
    };
    let event = crate::account_data::build_private_account_data_set_with_cas(
        &principal_realm_id,
        &actor,
        type_key,
        encrypted_payload,
        expected_state_digest,
    )?
    .build_sdk_event("inkson-private-account-data")?;
    let result = submitter.submit_sdk_event(&event).await;
    match result {
        Ok(value) => Ok(AccountDataSetResult::Stored {
            response: serde_json::to_value(value)?,
        }),
        Err(error) => {
            if let Some(status) = crate::api_error::unsupported_endpoint_status(&error) {
                tracing::warn!(
                    "ak.account_data.set submit for private {type_key} returned {status}; \
                     keeping local state authoritative"
                );
                return Ok(AccountDataSetResult::Unsupported { status });
            }
            Err(error)
        }
    }
}

/// Tombstone an account_data entry by submitting `ak.account_data.set` with
/// `tombstone: true`. Same graceful-degradation contract as
/// [`set_account_data`].
pub async fn delete_account_data(submitter: &EventSubmitter, type_key: &str) -> anyhow::Result<()> {
    let (actor, principal_realm_id) = match account_data_actor_scope(submitter.http()).await {
        Ok(scope) => scope,
        Err(error) => {
            if crate::api_error::unsupported_endpoint_status(&error).is_some() {
                return Ok(());
            }
            return Err(error);
        }
    };
    let key = crate::account_data::AccountDataKey::from_wire(type_key);
    let event =
        crate::account_data::build_account_data_tombstone(&principal_realm_id, &actor, &key)
            .build_sdk_event("inkson-account-data")?;
    match submitter.submit_sdk_event(&event).await {
        Ok(_) => Ok(()),
        Err(error) => {
            if crate::api_error::unsupported_endpoint_status(&error).is_some() {
                return Ok(());
            }
            Err(error)
        }
    }
}

pub async fn submit_read_cursor_advance(
    submitter: &EventSubmitter,
    marker: &crate::local_state::ReadMarkerRecord,
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
        let viewer: arkret_sdk::models::AccountView = serde_json::from_value(json!({
            "principal_id": "did:web:alice.example",
            "state": "active",
            "devices": [],
            "primary_handle_claim": {
                "schema": "ak.schema.handle_claim.v1",
                "handle": "alice:local.host",
                "subject": "did:web:alice.example"
            },
            "profile": {
                "id": "ak:actor_profile:01970000-0000-7000-8000-000000000001",
                "schema": "ak.schema.actor_profile.v1",
                "principal_id": "did:web:alice.example",
                "actor_kind": "user",
                "display_name": "Alice",
                "created_at": "2026-06-12T08:00:00Z"
            }
        }))
        .expect("account viewer shape");

        let account = current_account_from_viewer(viewer);

        assert_eq!(account.did, "did:web:alice.example");
        assert_eq!(account.handle, "alice:local.host");
        assert_eq!(account.display_name.as_deref(), Some("Alice"));
        assert_eq!(account.created_at, "2026-06-12T08:00:00Z");
    }

    #[test]
    fn account_viewer_projection_does_not_invent_handle() {
        let viewer: arkret_sdk::models::AccountView = serde_json::from_value(json!({
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
}
