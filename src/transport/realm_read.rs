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

use crate::models::{AuthorizationCheckResponseBody, EffectiveGrantSnapshot};
use crate::operation::trim_realm_id;
use crate::wire_helpers::path_component;

mod shared;

fn effective_grants_path(
    realm_id: &arkret_sdk::RealmId,
    subject: &arkret_sdk::ActorId,
) -> anyhow::Result<String> {
    let subject_actor_id = subject.canonical_key()?;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("realm_id", realm_id.as_str())
        .append_pair("subject_actor_id", &subject_actor_id)
        .finish();
    Ok(format!("/_arkret/self/authz/effective-grants?{query}"))
}

fn realm_organizations_path(realm_id: &arkret_sdk::RealmId) -> String {
    format!(
        "/_arkret/self/realms/{}/organizations",
        path_component(realm_id.as_str())
    )
}

fn realm_projection_path(
    realm_id: &arkret_sdk::RealmId,
    collection: &'static str,
    cursor: Option<&str>,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("limit", "500");
    if let Some(cursor) = cursor {
        query.append_pair("cursor", cursor);
    }
    format!(
        "/_arkret/self/realms/{}/{collection}?{}",
        path_component(realm_id.as_str()),
        query.finish()
    )
}

/// Read every registered Space projection page; a partial page is never a
/// complete Board baseline. These rows remain a derived UI view, not an
/// authority source for governance or Event authoring.
pub async fn list_realm_spaces(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<Vec<arkret_sdk::SpaceRow>> {
    let realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))?;
    shared::spaces(http, realm_id, None).await
}

pub(crate) async fn list_realm_spaces_scoped(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
    read_fence: &crate::state::RealmListReadFence,
) -> anyhow::Result<Vec<arkret_sdk::SpaceRow>> {
    let realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))?;
    shared::spaces(http, realm_id, Some(read_fence.clone())).await
}

async fn list_realm_spaces_pages(
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<Vec<arkret_sdk::SpaceRow>> {
    let bound = http
        .own_station_result_client()?
        .ok_or_else(|| anyhow::anyhow!("Space read requires its captured session"))?;
    let mut rows = Vec::new();
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        bound.check_session()?;
        let page: arkret_sdk::SpacePage = http
            .get(&realm_projection_path(
                realm_id,
                "spaces",
                cursor.as_deref(),
            ))
            .await?;
        bound.check_session()?;
        page.validate()?;
        anyhow::ensure!(
            &page.realm_id == realm_id,
            "Space page belongs to another Realm"
        );
        rows.extend(page.spaces);
        if !page.has_more {
            return Ok(rows);
        }
        let next = page
            .next_cursor
            .ok_or_else(|| anyhow::anyhow!("Space page omitted continuation cursor"))?
            .to_string();
        anyhow::ensure!(
            seen.insert(next.clone()),
            "Space projection cursor repeated"
        );
        cursor = Some(next);
    }
}

/// Read every registered Strand projection page for routing and display.
pub async fn list_realm_strands(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<Vec<arkret_sdk::StrandRow>> {
    let realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))?;
    shared::strands(http, realm_id, None).await
}

pub(crate) async fn list_realm_strands_scoped(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
    read_fence: &crate::state::RealmListReadFence,
) -> anyhow::Result<Vec<arkret_sdk::StrandRow>> {
    let realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))?;
    shared::strands(http, realm_id, Some(read_fence.clone())).await
}

async fn list_realm_strands_pages(
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
) -> anyhow::Result<Vec<arkret_sdk::StrandRow>> {
    let bound = http
        .own_station_result_client()?
        .ok_or_else(|| anyhow::anyhow!("Strand read requires its captured session"))?;
    let mut rows = Vec::new();
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        bound.check_session()?;
        let page: arkret_sdk::StrandPage = http
            .get(&realm_projection_path(
                realm_id,
                "strands",
                cursor.as_deref(),
            ))
            .await?;
        bound.check_session()?;
        page.validate()?;
        anyhow::ensure!(
            &page.realm_id == realm_id,
            "Strand page belongs to another Realm"
        );
        rows.extend(page.strands);
        if !page.has_more {
            return Ok(rows);
        }
        let next = page
            .next_cursor
            .ok_or_else(|| anyhow::anyhow!("Strand page omitted continuation cursor"))?
            .to_string();
        anyhow::ensure!(
            seen.insert(next.clone()),
            "Strand projection cursor repeated"
        );
        cursor = Some(next);
    }
}

pub async fn authz_check_resource(
    http: &arkret_sdk::http_client::Client,
    actor: &str,
    action: &str,
    resource: Option<arkret_sdk::WireResourceSelector>,
) -> anyhow::Result<AuthorizationCheckResponseBody> {
    let body =
        arkret_models_collaboration::governance::authorization::AuthorizationCheckRequestBody {
            actor_id: crate::mls_api_helpers::local_account_actor_id(actor)?,
            action: action.trim().to_owned(),
            resource,
            context: None,
        };
    authz_check_request(http, &body).await
}

/// Ask the authenticated account Station to evaluate one authorization query.
///
/// The typed SDK operation derives the registered operation selector. Inkson
/// consumes the Station's current projection without a local policy evaluator.
pub async fn authz_check_request(
    http: &arkret_sdk::http_client::Client,
    body: &arkret_models_collaboration::governance::authorization::AuthorizationCheckRequestBody,
) -> anyhow::Result<AuthorizationCheckResponseBody> {
    http.authz_check(body).await.map_err(anyhow::Error::from)
}

pub async fn authz_check(
    http: &arkret_sdk::http_client::Client,
    actor: &str,
    action: &str,
    realm_id: &str,
) -> anyhow::Result<AuthorizationCheckResponseBody> {
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

pub fn authz_allowed(outcome: &AuthorizationCheckResponseBody) -> bool {
    matches!(outcome.decision, arkret_sdk::AuthorizationDecision::Allow)
}

pub async fn effective_grants(
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
    subject: &arkret_sdk::ActorId,
) -> anyhow::Result<EffectiveGrantSnapshot> {
    // Deliberately no `at` parameter: historical evaluation is not an
    // authoring basis. Settings relinquish and manual admin revoke consume
    // only the exact row revision from this current read.
    http.get(&effective_grants_path(realm_id, subject)?)
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
/// and organization-side signing happen in the admin console (codmin).
pub async fn list_realm_organizations(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<
    arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipList,
> {
    let realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))?;
    http.get(&realm_organizations_path(&realm_id))
        .await
        .map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::{effective_grants_path, realm_organizations_path, realm_projection_path};

    #[test]
    fn effective_grants_uses_the_canonical_actor_query() {
        let realm_id = arkret_sdk::RealmId::new(
            "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH".to_owned(),
        )
        .unwrap();
        let subject = arkret_sdk::ActorId::service(
            arkret_sdk::DidCoreId::new("ak:did_core:web:service.example".to_owned()).unwrap(),
        );

        let path = effective_grants_path(&realm_id, &subject).unwrap();
        let url = url::Url::parse(&format!("https://station.example{path}")).unwrap();
        let query = url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(query.get("realm_id").unwrap(), realm_id.as_str());
        assert_eq!(query.get("subject_actor_id").unwrap(), &subject.to_string());
        assert_eq!(query.len(), 2);
        assert!(!path.contains("subject="));
        assert!(!path.contains("subject_station_id="));
    }

    #[test]
    fn realm_organization_path_encodes_the_typed_realm_id() {
        let realm_id = arkret_sdk::RealmId::new(
            "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH".to_owned(),
        )
        .unwrap();

        assert_eq!(
            realm_organizations_path(&realm_id),
            "/_arkret/self/realms/ak%3Arealm%3AASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH/organizations"
        );
    }

    #[test]
    fn projection_page_path_encodes_opaque_continuation() {
        let realm_id = arkret_sdk::RealmId::new(
            "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH".to_owned(),
        )
        .unwrap();
        let path = realm_projection_path(&realm_id, "strands", Some("ak:cursor:opaque+value"));
        let url = url::Url::parse(&format!("https://station.example{path}")).unwrap();
        assert!(url.path().ends_with("/strands"));
        let query = url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(query.get("limit").unwrap(), "500");
        assert_eq!(query.get("cursor").unwrap(), "ak:cursor:opaque+value");
    }
}
