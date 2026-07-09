//! Free-function realm READ transport (E2 CokretApi strangler).
//!
//! These are the pure-passthrough realm read operations (authz checks,
//! effective grants, collection / strand projections, realm-organization
//! relationships, notary describe) that used to live as thin inherent methods
//! on [`crate::api::CokretApi`]. They build a typed SDK request body (and do
//! small projections) and call the shared SDK `http-client::Client` directly.
//! Call sites reach them through [`crate::authed_api::with_authed_sdk_client`]
//! (or, for non-`with_authed_api` receivers,
//! `crate::realm_read_api::<name>(&recv.sdk_http_client()?, …)`), which keeps
//! the session-refresh + terminal-session classification identical to the old
//! facade path while dropping the per-domain facade method.
//!
//! The realm create / mutate methods build + submit signed events via the event
//! submitter and remain inherent `CokretApi` methods.

use serde_json::{Value, json};

use crate::models::{AuthzCheckOutcome, GrantList};
use crate::operation::trim_realm_id;
use crate::projection_views::{
    CollectionProjectionView, LifecycleProjectionView, StrandProjectionView,
};

/// Read the current notary cell value for a Realm (admin-only).
/// Returns the raw JSON shape the server publishes — typically
/// `{ "mode": "single_did" | "threshold" | "open_set" | "mixed",
///    "principals": [...], ... }`. The endpoint is being implemented
/// in soland on a separate track (P0 M4); when it 404s the caller's
/// `Result::Err` arm should surface a clear "endpoint unavailable"
/// message rather than blocking the page.
pub async fn admin_notary_describe(
    http: &cokret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let _ = (http, realm_id);
    anyhow::bail!("admin notary describe has no spec-defined Arkret HTTP endpoint")
}

pub async fn authz_check_resource(
    http: &cokret_sdk::http_client::Client,
    actor: &str,
    action: &str,
    resource: Option<Value>,
) -> anyhow::Result<AuthzCheckOutcome> {
    let body = cokret_sdk::models::AuthzCheckRequestBody {
        actor_id: cokret_sdk::Did::new(actor.trim().to_owned())?,
        action: action.trim().to_owned(),
        resource,
        context: None,
    };
    http.authz_check(&body).await.map_err(anyhow::Error::from)
}

pub async fn authz_check_resource_raw(
    http: &cokret_sdk::http_client::Client,
    actor: &str,
    action: &str,
    resource: Option<Value>,
) -> anyhow::Result<Value> {
    let response = authz_check_resource(http, actor, action, resource).await?;
    Ok(serde_json::to_value(response)?)
}

pub async fn authz_check_raw(
    http: &cokret_sdk::http_client::Client,
    actor: &str,
    action: &str,
    realm_id: &str,
) -> anyhow::Result<Value> {
    let response = authz_check_resource(
        http,
        actor,
        action,
        Some(json!({"kind": "realm", "realm_id": realm_id.trim()})),
    )
    .await?;
    Ok(serde_json::to_value(response)?)
}

pub async fn effective_grants(
    http: &cokret_sdk::http_client::Client,
    subject: &str,
) -> anyhow::Result<GrantList> {
    http.authz_effective_grants_for_subject(subject, None)
        .await
        .map_err(anyhow::Error::from)
}

// ── Views — collection projection (T20 / YOU-01-009 subtask 3) ──────
//
// Spec-registered operation `ck.self.views.collection_projection.command.materialize`
// (`POST /_cokret/self/views/{view_id}/projection`, spec commit
// b0cfa89). The request body is the registered
// `view_projection_request_body` (`{cursor?, limit?}` — an empty
// object is valid) and the response is parsed as the registered
// `collection_projection_view` shape.
pub async fn collection_projection(
    http: &cokret_sdk::http_client::Client,
    view_id: &str,
) -> anyhow::Result<CollectionProjectionView> {
    let body = cokret_sdk::models::ViewProjectionRequestBody::default();
    let view: cokret_sdk::CollectionProjectionView = http
        .collection_projection(view_id, &body)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(view.into())
}

pub async fn list_strand_projections(
    http: &cokret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<LifecycleProjectionView<StrandProjectionView>> {
    let realm_id = trim_realm_id(realm_id);
    let list: cokret_sdk::ProjectionStrandList = http
        .realm_strands(&realm_id)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(list.into())
}

/// Read the verified Realm ↔ organization relationships projection
/// (`ck.self.realm_organization.query.list`,
/// `GET /_cokret/self/realms/{realm_id}/organizations`).
///
/// The server only returns `verified_active` / `revoked_or_expired`
/// lifecycle rows plus `declared_organization_hints` (owning-organization
/// DIDs with no verified statement). `pending_consent` is a client-side
/// bind-flow state and is never projected here. This is read-only: binding
/// and organization-side signing happen in the admin console (sodmin).
pub async fn list_realm_organizations(
    http: &cokret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<cokret_sdk::models::RealmOrganizationRelationshipList> {
    let realm_id = trim_realm_id(realm_id);
    http.realm_organizations(&realm_id)
        .await
        .map_err(anyhow::Error::from)
}
