use std::cell::RefCell;
use std::collections::HashMap;

use url::Url;

use crate::transport::TransportClient;

thread_local! {
    /// Process-wide cache of resolved account authorities, keyed by principal
    /// server URL. The `/_arkret/describe` `auth_metadata` this is derived from
    /// is pinned durably before entering this connection-local cache.
    /// Without it, every session-grant rotation rebuilds a fresh `TransportClient`
    /// and re-fetches describe (the per-instance `describe_cached` OnceCell is
    /// useless across instances), so any upstream refresh loop becomes a
    /// `describe` request storm. Cleared on reconnect via
    /// [`clear_authority_resolver_cache`].
    static AUTHORITY_RESOLVER_CACHE: RefCell<HashMap<String, AuthorityResolver>> =
        RefCell::new(HashMap::new());
}

/// Drop the cached authority resolution(s). Called on an explicit reconnect /
/// server switch (`connect()`), so a genuinely re-pointed Account Authority is
/// re-probed instead of served from a stale cache.
pub fn clear_authority_resolver_cache() {
    AUTHORITY_RESOLVER_CACHE.with(|cache| cache.borrow_mut().clear());
}

/// best-effort deep link to the issuer/coauth handle
/// issuance strand (`/handles/me`). inkson does NOT manage handle lifecycle
/// (per spec §3.2.3 / §3.4): `ak.profile.update` /
/// `ak.member.identity.update` MUST NOT set or override handles. Instead
/// the settings UI surfaces "Handle managed by your organization" with a
/// link out to the issuer strand, where the org-run issuer signs
/// `ak.schema.handle_claim.v1` evidence.
///
/// We derive the link from the supplied base URL synchronously
/// (origin + `/handles/me`). Callers that need the Account Authority origin
/// should resolve `auth_metadata.account_authority.gate_account_base_url` first.
/// Returns `None` for an unparseable base URL.
pub fn issuer_handle_management_url(base_url: &str) -> Option<String> {
    let parsed = Url::parse(base_url.trim()).ok()?;
    let origin = parsed.origin();
    if origin.is_tuple() {
        Some(format!("{}/handles/me", origin.ascii_serialization()))
    } else {
        None
    }
}

pub async fn resolve_principal_gate_account_base_url(station_url: &str) -> anyhow::Result<String> {
    Ok(AuthorityResolver::discover(station_url)
        .await?
        .gate_account_base_url)
}

/// T1.Y4 — Account Authority resolver. The Station's root
/// `/_arkret/describe` (service-surface §2.5.1) publishes a strongly-typed
/// `auth_metadata.account_authority.gate_account_base_url`; every Arkret
/// `/_arkret/gate/account/*` request MUST be derived from that single base,
/// and the available authentication methods come from
/// `auth_metadata.methods[]`.
///
/// The resolver fails closed: if the describe response does not carry a strong
/// `account_authority`, it errors instead of guessing a per-operation route.
#[derive(Clone, Debug)]
pub struct AuthorityResolver {
    /// Absolute `gate_account_base_url` — the only origin client `gate/account`
    /// calls are routed to (service-surface §2.5.1).
    pub gate_account_base_url: String,
    /// Audience the issued session grant authenticates against.
    pub principal_audience: String,
    /// Station trust domain used by the principal-control bootstrap.
    pub principal_trust_domain: arkret_sdk::TrustDomainId,
    /// Authentication methods the Account Authority accepts.
    pub methods: Vec<arkret_sdk::AuthMethod>,
}

impl AuthorityResolver {
    /// Discover the Account Authority from the Station's root
    /// `/_arkret/describe` and its strongly-typed `auth_metadata`.
    pub async fn discover(station_url: &str) -> anyhow::Result<Self> {
        // describe/`auth_metadata` is deployment-stable, so resolve ONCE per
        // Station and reuse it. This is the choke point every
        // session-grant rotation flows through; caching it here is what stops
        // an upstream refresh loop from storming `/_arkret/describe`.
        let key = station_url.trim().to_owned();
        if let Some(cached) =
            AUTHORITY_RESOLVER_CACHE.with(|cache| cache.borrow().get(&key).cloned())
        {
            return Ok(cached);
        }
        let principal = TransportClient::unauthenticated(station_url)?;
        let description = principal.describe().await?;
        let resolver = Self::from_description(station_url, &description)?;
        AUTHORITY_RESOLVER_CACHE.with(|cache| cache.borrow_mut().insert(key, resolver.clone()));
        Ok(resolver)
    }

    pub(crate) fn from_description(
        station_url: &str,
        description: &arkret_sdk::ServiceDescribe,
    ) -> anyhow::Result<Self> {
        let metadata = &description.auth_metadata;
        let gate_account_base_url = resolve_gate_account_base_url(station_url, metadata)?;
        let principal_audience = description.service_id.to_string();
        Ok(Self {
            gate_account_base_url,
            principal_audience,
            principal_trust_domain: description.trust_domain.clone(),
            methods: metadata.methods.clone(),
        })
    }

    /// Pick the first `oidc` method from `auth_metadata.methods[]`.
    pub fn oidc_method(&self) -> anyhow::Result<arkret_sdk::AuthMethod> {
        if let Some(method) = self
            .methods
            .iter()
            .find(|method| method.method == arkret_sdk::AuthMethodKind::Oidc)
        {
            return Ok(method.clone());
        }
        anyhow::bail!("Station describe published no oidc auth method in methods[]")
    }
}

/// Derive the single client-visible `gate_account_base_url` from `auth_metadata`.
///
/// The published base is mandatory; the origin is not a fallback route.
pub(crate) fn resolve_gate_account_base_url(
    _station_url: &str,
    metadata: &arkret_sdk::AuthMetadata,
) -> anyhow::Result<String> {
    let authority = metadata.account_authority.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Station describe is missing auth_metadata.account_authority")
    })?;
    let base = Url::parse(&authority.gate_account_base_url)?;
    arkret_sdk::validate_connection_url(&base, true)?;
    anyhow::ensure!(
        base.origin().ascii_serialization() == authority.origin.as_str(),
        "Account Authority origin differs from its published base"
    );
    Ok(normalize_gate_account_base_url(base.as_str()))
}

fn normalize_gate_account_base_url(base: &str) -> String {
    base.trim_end_matches('/').to_owned()
}
