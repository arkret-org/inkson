//! Typed Realm read transport.
//!
//! These are the pure-passthrough realm read operations (authz checks,
//! effective grants, strand projections, and realm-organization
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

use crate::models::{AuthzCheckOutcome, GrantList};
use crate::operation::trim_realm_id;

pub async fn authz_check_resource(
    http: &arkret_sdk::http_client::Client,
    actor: &str,
    action: &str,
    resource: Option<arkret_sdk::WireResourceSelector>,
) -> anyhow::Result<AuthzCheckOutcome> {
    let body = arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody {
        actor_id: crate::mls_api_helpers::local_account_actor_id(actor)?,
        action: action.trim().to_owned(),
        resource,
        context: None,
    };
    http.authz_check(&body).await.map_err(anyhow::Error::from)
}

pub async fn authz_check(
    http: &arkret_sdk::http_client::Client,
    actor: &str,
    action: &str,
    realm_id: &str,
) -> anyhow::Result<AuthzCheckOutcome> {
    authz_check_resource(
        http,
        actor,
        action,
        Some(arkret_sdk::WireResourceSelector::realm(
            arkret_sdk::RealmId::new(realm_id.trim().to_owned())?,
        )),
    )
    .await
}

pub fn authz_allowed(outcome: &AuthzCheckOutcome) -> bool {
    matches!(outcome.decision, arkret_sdk::AuthzDecision::Allow)
}

pub async fn effective_grants(
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
    subject: &arkret_sdk::DidCoreId,
    subject_station_id: &arkret_sdk::DidCoreId,
) -> anyhow::Result<GrantList> {
    http.authz_effective_grants(realm_id, subject, subject_station_id, None)
        .await
        .map_err(anyhow::Error::from)
}

/// Read the verified Realm ↔ organization relationships projection
/// (`ak.self.realm_organization.read.list.v1`,
/// `GET /_arkret/self/realms/{realm_id}/organizations`).
///
/// The server only returns `verified_active` / `revoked_or_expired`
/// lifecycle rows plus `declared_organization_hint_ids` (owning-organization
/// DIDs with no verified statement). This is read-only: binding
/// and organization-side signing happen in the admin console (sodmin).
pub async fn list_realm_organizations(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<
    arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipList,
> {
    let realm_id = trim_realm_id(realm_id);
    http.realm_organizations(&realm_id)
        .await
        .map_err(anyhow::Error::from)
}
