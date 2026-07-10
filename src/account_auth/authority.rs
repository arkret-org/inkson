use std::cell::RefCell;
use std::collections::HashMap;

use url::Url;

use super::util::principal_audience;
use crate::api::CokretApi;
use crate::config::validate_server_url;

thread_local! {
    /// Process-wide cache of resolved account authorities, keyed by principal
    /// server URL. The `/_arkret/describe` `auth_metadata` this is derived from
    /// is deployment-stable, so ONE probe per server connection suffices.
    /// Without it, every session-grant rotation rebuilds a fresh `CokretApi`
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

/// R3.2 (YG-HC-1) — best-effort deep link to the issuer/coauth handle
/// issuance strand (`/handles/me`). inkson does NOT manage handle lifecycle
/// (per spec §3.2.3 / §3.4): `ak.profile.update` /
/// `ak.member.identity.update` MUST NOT set or override handles. Instead
/// the settings UI surfaces "Handle managed by your organization" with a
/// link out to the issuer strand, where the org-run issuer signs
/// `ak.schema.handle_claim.v1` evidence.
///
/// We derive the link from the supplied base URL synchronously
/// (origin + `/handles/me`). Callers that need the Account Authority origin
/// should resolve `auth_metadata.account_authority.gate_account_base` first.
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

pub async fn resolve_principal_gate_account_base(
    principal_server_url: &str,
) -> anyhow::Result<String> {
    Ok(AuthorityResolver::discover(principal_server_url)
        .await?
        .gate_account_base)
}

/// T1.Y4 — Account Authority resolver. The Principal Server's root
/// `/_arkret/describe` (service-surface §2.5.1) publishes a strongly-typed
/// `auth_metadata.account_authority.gate_account_base`; every Arkret
/// `/_arkret/gate/account/*` request MUST be derived from that single base,
/// and the available authentication methods come from
/// `auth_metadata.methods[]`.
///
/// The resolver fails closed: if the describe response does not carry a strong
/// `account_authority`, it errors instead of guessing a per-operation route.
#[derive(Clone, Debug)]
pub struct AuthorityResolver {
    /// Absolute `gate_account_base` — the only origin client `gate/account`
    /// calls are routed to (service-surface §2.5.1).
    pub gate_account_base: String,
    /// Principal Server origin that published the describe response.
    pub principal_server_url: String,
    /// Audience the issued session grant authenticates against.
    pub principal_audience: String,
    /// Authentication methods the Account Authority accepts.
    pub methods: Vec<arkret_sdk::AuthMethod>,
}

impl AuthorityResolver {
    /// Discover the Account Authority from the Principal Server's root
    /// `/_arkret/describe` and its strongly-typed `auth_metadata`.
    pub async fn discover(principal_server_url: &str) -> anyhow::Result<Self> {
        // describe/`auth_metadata` is deployment-stable, so resolve ONCE per
        // principal server and reuse it. This is the choke point every
        // session-grant rotation flows through; caching it here is what stops
        // an upstream refresh loop from storming `/_arkret/describe`.
        let key = principal_server_url.trim().to_owned();
        if let Some(cached) =
            AUTHORITY_RESOLVER_CACHE.with(|cache| cache.borrow().get(&key).cloned())
        {
            return Ok(cached);
        }
        // DIAG (describe-storm): only reached on a cache MISS, so if `describe`
        // keeps hitting the network from the coauth/session-refresh path this
        // fires repeatedly. A steady stream here means an upstream refresh loop;
        // silence here means describe is coming from another caller. Remove once
        // the driver is fixed.
        tracing::warn!(target: "recovery_diag", server = %key, "authority discover cache-miss -> real describe");
        let principal = CokretApi::new(principal_server_url)?;
        let description = principal.describe().await?;
        let resolver = Self::from_description(principal_server_url, &description)?;
        AUTHORITY_RESOLVER_CACHE.with(|cache| cache.borrow_mut().insert(key, resolver.clone()));
        Ok(resolver)
    }

    pub(crate) fn from_description(
        principal_server_url: &str,
        description: &arkret_sdk::ServerDescription,
    ) -> anyhow::Result<Self> {
        let metadata = &description.auth_metadata;
        let gate_account_base = resolve_gate_account_base(principal_server_url, metadata)?;
        let principal_audience = {
            let service_did = description.service_did.as_str().trim();
            if service_did.is_empty() {
                principal_audience(principal_server_url)?
            } else {
                service_did.to_owned()
            }
        };
        Ok(Self {
            gate_account_base,
            principal_server_url: principal_server_url.to_owned(),
            principal_audience,
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
        anyhow::bail!("principal server describe published no oidc auth method in methods[]")
    }
}

/// Derive the single client-visible `gate_account_base` from `auth_metadata`.
///
/// `account_authority.gate_account_base` is canonical. When the authority
/// publishes only `origin`, derive `{origin}/_arkret/gate/account`.
pub(crate) fn resolve_gate_account_base(
    _principal_server_url: &str,
    metadata: &arkret_sdk::AuthMetadata,
) -> anyhow::Result<String> {
    if let Some(authority) = metadata.account_authority.as_ref() {
        let base = authority.gate_account_base.trim();
        if !base.is_empty() {
            return Ok(normalize_gate_account_base(base));
        }
        let origin = authority.origin.trim();
        if !origin.is_empty() {
            return gate_account_base_from_origin(origin);
        }
    }
    anyhow::bail!("principal server describe is missing auth_metadata.account_authority")
}

fn gate_account_base_from_origin(origin: &str) -> anyhow::Result<String> {
    let url = validate_server_url(origin)?;
    let base = url.join("_arkret/gate/account").map_err(|error| {
        anyhow::anyhow!("invalid gate account base from origin {origin}: {error}")
    })?;
    Ok(normalize_gate_account_base(base.as_str()))
}

fn normalize_gate_account_base(base: &str) -> String {
    base.trim_end_matches('/').to_owned()
}
