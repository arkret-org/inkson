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
//! Methods that go through the durable event submitter, the DPoP-signed write
//! path, or the cached `describe` (`set_account_data`, the consent grant /
//! revoke / request commands, `submit_did_operation`,
//! `submit_read_cursor_advance`, `tombstone_contact`, and the `request_contact`
//! family — which resolves contact addressing via `describe_cached`) remain
//! inherent `CokretApi` methods and are intentionally NOT migrated here.

use serde_json::Value;

use crate::models::{
    ContactListView, CurrentAccount, IdentityDescribeOutcome, IdentityResolveOutcome,
};

pub(crate) fn did_for_request_field(field: &str, value: &str) -> anyhow::Result<cokret_sdk::Did> {
    let value = value.trim();
    cokret_sdk::Did::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid {field} DID `{value}`: {err}"))
}

fn device_id_for_request_field(field: &str, value: &str) -> anyhow::Result<cokret_sdk::DeviceId> {
    let value = value.trim();
    cokret_sdk::DeviceId::new(value.to_owned())
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
) -> anyhow::Result<Option<cokret_sdk::Did>> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| did_for_request_field(field, value))
        .transpose()
}

pub async fn register_account(
    http: &cokret_sdk::http_client::Client,
    did: &str,
    _handle: &str,
    display_name: Option<&str>,
    device_id: Option<&str>,
) -> anyhow::Result<cokret_sdk::models::AccountRegisterOutcome> {
    let body = cokret_sdk::models::AccountRegisterRequestBody {
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
    http: &cokret_sdk::http_client::Client,
) -> anyhow::Result<cokret_sdk::models::AccountView> {
    http.account_viewer()
        .await
        .map_err(|error| anyhow::anyhow!("account viewer: {error}"))
}

pub async fn account_me(http: &cokret_sdk::http_client::Client) -> anyhow::Result<CurrentAccount> {
    let viewer = account_viewer(http).await?;
    Ok(current_account_from_viewer(viewer))
}

/// A4b — update the authenticated principal's public profile
/// (display_name / bio / avatar_blob_ref). Mirrors the
/// `ck.self.account.command.update_profile` wire shape: each field is
/// `Option<String>`; `None` leaves the field untouched server-side,
/// `Some("")` explicitly clears it. The server normalises empty
/// strings to `None` on write.
pub async fn update_profile(
    http: &cokret_sdk::http_client::Client,
    display_name: Option<&str>,
    bio: Option<&str>,
    avatar_blob_ref: Option<&str>,
) -> anyhow::Result<cokret_sdk::models::AccountUpdateProfileOutcome> {
    let mut patch = cokret_sdk::Patch::new();
    if let Some(display_name) = display_name {
        let display_name = display_name.trim();
        if display_name.is_empty() {
            patch.insert_op("display_name", cokret_sdk::PatchOp::unset())?;
        } else {
            patch.insert("display_name", display_name)?;
        }
    }
    if let Some(bio) = bio {
        let bio = bio.trim();
        if bio.is_empty() {
            patch.insert_op("profile_fields.bio", cokret_sdk::PatchOp::unset())?;
        } else {
            patch.insert("profile_fields.bio", bio)?;
        }
    }
    if let Some(avatar_blob_ref) = avatar_blob_ref {
        let avatar_blob_ref = avatar_blob_ref.trim();
        if avatar_blob_ref.is_empty() {
            patch.insert_op("avatar_blob_ref", cokret_sdk::PatchOp::unset())?;
        } else {
            cokret_sdk::BlobRef::new(avatar_blob_ref.to_owned()).map_err(|err| {
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
    let body = cokret_sdk::models::AccountUpdateProfileRequestBody {
        patch: serde_json::to_value(&patch)?,
    };
    http.account_update_profile(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn respond_contact(
    http: &cokret_sdk::http_client::Client,
    requester: &str,
    action: &str,
) -> anyhow::Result<cokret_sdk::ContactRespondOutcome> {
    respond_contact_with_service(http, requester, action, None).await
}

async fn contact_request_event_id_for_requester(
    http: &cokret_sdk::http_client::Client,
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
    http: &cokret_sdk::http_client::Client,
    requester: &str,
    action: &str,
    requester_service_did: Option<&str>,
) -> anyhow::Result<cokret_sdk::ContactRespondOutcome> {
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
    http: &cokret_sdk::http_client::Client,
    requester: &str,
    request_event_ref: &str,
    action: &str,
    requester_service_did: Option<&str>,
) -> anyhow::Result<cokret_sdk::ContactRespondOutcome> {
    let body = cokret_sdk::ContactRespondRequestBody {
        request_id: cokret_sdk::EventId::new(request_event_ref.trim().to_owned()).map_err(
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

pub async fn contacts(http: &cokret_sdk::http_client::Client) -> anyhow::Result<ContactListView> {
    let response: cokret_sdk::ContactList =
        http.contacts_list().await.map_err(anyhow::Error::from)?;
    ContactListView::from_sdk(response)
}

/// Read the actor's `invite_receive_policy` ("who can invite me", U4).
///
/// Spec `invite-addressing.md` §5 / OpenAPI
/// `ck.self.invite_receive_policy.resource.get`: served from the self plane at
/// `GET /_cokret/self/invite-receive-policy` and returns the bare
/// `cokret_sdk::InviteReceivePolicy` (soland echoes the stored override or
/// its recommended default). When the deployment does not yet wire this
/// surface the caller treats 404/501/405 as "use defaults" rather than a
/// hard error (see [`crate::models::default_invite_receive_policy`]).
pub async fn get_invite_receive_policy(
    http: &cokret_sdk::http_client::Client,
) -> anyhow::Result<crate::models::InviteReceivePolicy> {
    http.get("/_cokret/self/invite-receive-policy")
        .await
        .map_err(anyhow::Error::from)
}

/// Persist the actor's `invite_receive_policy` (U4).
///
/// Spec `ck.self.invite_receive_policy.resource.replace`:
/// `PUT /_cokret/self/invite-receive-policy` with the bare
/// `cokret_sdk::InviteReceivePolicy` as the body. The handler enforces
/// `subject_id == session actor` and requires the `schema` constant, so the
/// caller MUST stamp both before calling (see the U4 view); the server
/// echoes the stored policy back.
pub async fn set_invite_receive_policy(
    http: &cokret_sdk::http_client::Client,
    policy: &crate::models::InviteReceivePolicy,
) -> anyhow::Result<crate::models::InviteReceivePolicy> {
    http.put("/_cokret/self/invite-receive-policy", policy)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn direct_conversation_resolve(
    http: &cokret_sdk::http_client::Client,
    peer: &str,
    create: bool,
) -> anyhow::Result<cokret_sdk::DirectConversationResolveOutcome> {
    let body = cokret_sdk::DirectConversationResolveRequestBody {
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
/// `identity/consent-model.md` §3 / OpenAPI `ck.self.consent.query.list`.
pub async fn consent_cells(
    http: &cokret_sdk::http_client::Client,
) -> anyhow::Result<cokret_sdk::ConsentCellList> {
    http.get(cokret_sdk::http::PATH_SELF_CONSENT_CELLS)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn identity_describe(
    http: &cokret_sdk::http_client::Client,
) -> anyhow::Result<IdentityDescribeOutcome> {
    http.identity_describe()
        .await
        .map_err(|error| anyhow::anyhow!("identity describe: {error}"))
}

pub async fn identity_resolve(
    http: &cokret_sdk::http_client::Client,
    did: &str,
) -> anyhow::Result<IdentityResolveOutcome> {
    let subject = cokret_sdk::Did::new(did.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid did `{did}`: {err}"))?;
    let body = cokret_sdk::models::IdentityResolveRequestBody {
        did: subject,
        requested_evidence_kinds: Vec::new(),
    };
    http.identity_resolve(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn sync_describe(
    http: &cokret_sdk::http_client::Client,
) -> anyhow::Result<cokret_sdk::models::SyncDescription> {
    http.account_describe().await.map_err(anyhow::Error::from)
}

pub async fn invites(
    http: &cokret_sdk::http_client::Client,
) -> anyhow::Result<cokret_sdk::AuthzInviteList> {
    let subject = account_me(http).await?.did;
    http.authz_invites(&subject, None, None)
        .await
        .map_err(anyhow::Error::from)
}

fn current_account_from_viewer(viewer: cokret_sdk::models::AccountView) -> CurrentAccount {
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

fn primary_handle_from_viewer(viewer: &cokret_sdk::models::AccountView) -> String {
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn account_viewer_projection_uses_signed_handle_claim() {
        let viewer: cokret_sdk::models::AccountView = serde_json::from_value(json!({
            "principal_id": "did:web:alice.example",
            "state": "active",
            "devices": [],
            "primary_handle_claim": {
                "schema": "ck.schema.handle_claim.v1",
                "handle": "alice:local.host",
                "subject": "did:web:alice.example"
            },
            "profile": {
                "id": "ck:actor_profile:01970000-0000-7000-8000-000000000001",
                "schema": "ck.schema.actor_profile.v1",
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
        let viewer: cokret_sdk::models::AccountView = serde_json::from_value(json!({
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
