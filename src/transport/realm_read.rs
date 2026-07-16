//! Typed Realm read transport.
//!
//! These are the pure-passthrough realm read operations (authz checks,
//! effective grants, collection / strand projections, and realm-organization
//! relationships) that used to live as thin inherent methods
//! on [`crate::transport::TransportClient`]. They build a typed SDK request body (and do
//! small projections) and call the shared SDK `http-client::Client` directly.
//! Call sites reach them through [`crate::transport::auth::with_authed_sdk_client`]
//! (or, for non-`with_authed_api` receivers,
//! `crate::transport::realm_read::<name>(&recv.sdk_http_client()?, …)`), which keeps
//! the session-refresh + terminal-session classification identical to the old
//! facade path while dropping the per-domain facade method.
//!
//! The realm create / mutate methods build + submit signed events via the event
//! submitter and remain inherent `TransportClient` methods.

use serde_json::{Value, json};

use crate::models::{AuthzCheckOutcome, GrantList};
use crate::operation::trim_realm_id;
use crate::state::projection_views::CollectionProjectionView;

pub async fn authz_check_resource(
    http: &arkret_sdk::http_client::Client,
    actor: &str,
    action: &str,
    resource: Option<Value>,
) -> anyhow::Result<AuthzCheckOutcome> {
    let body = arkret_sdk::models::AuthzCheckRequestBody {
        actor_id: arkret_sdk::Did::new(actor.trim().to_owned())?,
        action: action.trim().to_owned(),
        resource: resource.map(serde_json::from_value).transpose()?,
        context: None,
    };
    http.authz_check(&body).await.map_err(anyhow::Error::from)
}

pub async fn authz_check_resource_raw(
    http: &arkret_sdk::http_client::Client,
    actor: &str,
    action: &str,
    resource: Option<Value>,
) -> anyhow::Result<Value> {
    let response = authz_check_resource(http, actor, action, resource).await?;
    Ok(serde_json::to_value(response)?)
}

pub async fn authz_check_raw(
    http: &arkret_sdk::http_client::Client,
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
    http: &arkret_sdk::http_client::Client,
    subject: &str,
) -> anyhow::Result<GrantList> {
    http.authz_effective_grants_for_subject(subject, None)
        .await
        .map_err(anyhow::Error::from)
}

// ── Views — collection projection (T20 / YOU-01-009 subtask 3) ──────
//
// Spec-registered operation `ak.self.views.collection_projection.command.materialize`
// (`POST /_arkret/self/views/{view_id}/projection`, spec commit
// b0cfa89). The request body is the registered
// `view_projection_request_body` (`{cursor?, limit?}` — an empty
// object is valid) and the response is parsed as the registered
// `collection_projection_view` shape.
pub async fn collection_projection(
    http: &arkret_sdk::http_client::Client,
    view_id: &str,
) -> anyhow::Result<CollectionProjectionView> {
    let body = arkret_sdk::models::ViewProjectionRequestBody::default();
    let view: arkret_sdk::CollectionProjectionView = http
        .collection_projection(view_id, &body)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(view.into())
}

/// Read the verified Realm ↔ organization relationships projection
/// (`ak.self.realm_organization.query.list`,
/// `GET /_arkret/self/realms/{realm_id}/organizations`).
///
/// The server only returns `verified_active` / `revoked_or_expired`
/// lifecycle rows plus `declared_organization_hints` (owning-organization
/// DIDs with no verified statement). This is read-only: binding
/// and organization-side signing happen in the admin console (sodmin).
pub async fn list_realm_organizations(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<arkret_sdk::models::RealmOrganizationRelationshipList> {
    let realm_id = trim_realm_id(realm_id);
    http.realm_organizations(&realm_id)
        .await
        .map_err(anyhow::Error::from)
}
