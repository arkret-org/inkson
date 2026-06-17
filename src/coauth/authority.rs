use url::Url;

use super::CoauthApi;
use super::util::principal_audience;
use crate::api::CokretApi;
use crate::config::validate_server_url;

/// R3.2 (YG-HC-1) — best-effort deep link to the issuer/coauth handle
/// issuance strand (`/handles/me`). yougen does NOT manage handle lifecycle
/// (per spec §3.2.3 / §3.4): `ck.profile.update` /
/// `ck.member.identity.update` MUST NOT set or override handles. Instead
/// the settings UI surfaces "Handle managed by your organization" with a
/// link out to the issuer strand, where the org-run issuer signs
/// `ck.schema.handle_claim.v1` evidence.
///
/// We derive the link from the principal/auth base URL synchronously
/// (origin + `/handles/me`); deployments that publish a distinct coauth
/// origin via `auth_metadata.auth_server_url` should resolve that first
/// (see [`resolve_principal_auth_server_url`]). Returns `None` for an
/// unparseable base URL.
pub fn issuer_handle_management_url(base_url: &str) -> Option<String> {
    let parsed = Url::parse(base_url.trim()).ok()?;
    let origin = parsed.origin();
    if origin.is_tuple() {
        Some(format!("{}/handles/me", origin.ascii_serialization()))
    } else {
        None
    }
}

pub async fn resolve_principal_auth_server_url(
    principal_server_url: &str,
) -> anyhow::Result<String> {
    Ok(resolve_principal_auth_server(principal_server_url)
        .await?
        .auth_server_url)
}

#[derive(Clone, Debug)]
pub(crate) struct PrincipalAuthServerResolution {
    pub auth_server_url: String,
    pub principal_audience: String,
}

/// T1.Y4 — Account Authority resolver. The Principal Server's root
/// `/_cokret/describe` (service-surface §2.5.1) publishes a strongly-typed
/// `auth_metadata.account_authority.gate_account_base`; every Cokret
/// `/_cokret/gate/account/*` request MUST be derived from that single base
/// (a [`CoauthApi`] rooted at it), and the available authentication methods
/// come from `auth_metadata.methods[]`.
///
/// The resolver fails closed: if the describe response carries neither a
/// strong `account_authority` nor the legacy `auth_server_url` / `oauth_issuer`
/// aliases, it errors instead of guessing a per-operation route.
#[derive(Clone, Debug)]
pub struct AuthorityResolver {
    /// Absolute `gate_account_base` — the only origin client `gate/account`
    /// calls are routed to (service-surface §2.5.1).
    pub gate_account_base: String,
    /// Principal Server origin that published the describe response.
    pub principal_server_url: String,
    /// Audience the issued grant / bearer authenticates against.
    pub principal_audience: String,
    /// Authentication methods the Account Authority accepts.
    pub methods: Vec<cokret_sdk::AuthMethod>,
}

impl AuthorityResolver {
    /// Discover the Account Authority from the Principal Server's root
    /// `/_cokret/describe` and its strongly-typed `auth_metadata`.
    pub async fn discover(principal_server_url: &str) -> anyhow::Result<Self> {
        let principal = CokretApi::new(principal_server_url)?;
        let description = principal.describe().await?;
        Self::from_description(principal_server_url, &description)
    }

    pub(crate) fn from_description(
        principal_server_url: &str,
        description: &cokret_sdk::ServerDescription,
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

    /// A [`CoauthApi`] rooted at the resolved `gate_account_base`. Every
    /// `gate/account` call (session-grants, refresh, logout) goes through it.
    pub fn gate_account_client(&self) -> anyhow::Result<CoauthApi> {
        CoauthApi::new(&self.gate_account_base)
    }

    /// Pick the first `oidc` method, falling back to a synthesised one when the
    /// server only published the legacy `auth_server_url` / `oauth_issuer`
    /// aliases (older Principal Servers that predate `methods[]`).
    pub fn oidc_method(
        &self,
        metadata: Option<&cokret_sdk::AuthMetadata>,
    ) -> anyhow::Result<cokret_sdk::AuthMethod> {
        if let Some(method) = self
            .methods
            .iter()
            .find(|method| method.method == cokret_sdk::AuthMethodKind::Oidc)
        {
            return Ok(method.clone());
        }
        // Legacy alias fallback.
        if let Some(metadata) = metadata {
            if let Some(method) = synthesize_oidc_method_from_aliases(metadata) {
                return Ok(method);
            }
        }
        anyhow::bail!(
            "principal server describe published no oidc auth method (methods[] empty and no auth_server_url/oauth_issuer alias)"
        )
    }
}

/// Derive the single client-visible `gate_account_base` from `auth_metadata`.
///
/// Order of preference (service-surface §2.5.1 + the legacy aliases the SDK
/// `AuthMetadata` retains for old servers):
///
/// 1. `account_authority.gate_account_base` — canonical.
/// 2. legacy `auth_server_url` alias — older deployments that ran the whole Account Authority on
///    the auth origin; derive `{origin}/_cokret/gate/account`.
/// 3. the Principal Server's own origin — personal deployments where the Account Authority is
///    co-located.
pub(crate) fn resolve_gate_account_base(
    principal_server_url: &str,
    metadata: &cokret_sdk::AuthMetadata,
) -> anyhow::Result<String> {
    if let Some(authority) = metadata.account_authority.as_ref() {
        let base = authority.gate_account_base.trim();
        if !base.is_empty() {
            return Ok(normalize_gate_account_base(base));
        }
        let origin = authority.origin.trim();
        if !origin.is_empty() {
            return Ok(gate_account_base_from_origin(origin)?);
        }
    }
    if let Some(auth_server_url) = metadata
        .auth_server_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return gate_account_base_from_origin(auth_server_url);
    }
    // Personal deployment: Account Authority co-located with the Principal
    // Server. Fail closed only if the URL itself is invalid.
    gate_account_base_from_origin(principal_server_url)
}

fn gate_account_base_from_origin(origin: &str) -> anyhow::Result<String> {
    let url = validate_server_url(origin)?;
    let base = url.join("_cokret/gate/account").map_err(|error| {
        anyhow::anyhow!("invalid gate account base from origin {origin}: {error}")
    })?;
    Ok(normalize_gate_account_base(base.as_str()))
}

fn normalize_gate_account_base(base: &str) -> String {
    base.trim_end_matches('/').to_owned()
}

/// Build an `oidc` [`cokret_sdk::AuthMethod`] from the legacy compatibility
/// aliases (`auth_server_url` / `oauth_issuer` / `openid_configuration`) so
/// pre-`methods[]` servers still drive standard OIDC discovery.
pub(crate) fn synthesize_oidc_method_from_aliases(
    metadata: &cokret_sdk::AuthMetadata,
) -> Option<cokret_sdk::AuthMethod> {
    let issuer = metadata
        .oauth_issuer
        .as_deref()
        .or(metadata.auth_server_url.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)?;
    let openid_configuration = metadata
        .openid_configuration
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            Some(format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ))
        });
    Some(cokret_sdk::AuthMethod {
        method: cokret_sdk::AuthMethodKind::Oidc,
        issuer: Some(issuer),
        provider: None,
        openid_configuration,
        client_id: None,
        scopes: Vec::new(),
        grant_exchange: cokret_sdk::AuthGrantExchange {
            proof_kind: cokret_sdk::SessionGrantProofKind::OidcCodeExchange,
        },
    })
}

pub(crate) async fn resolve_principal_auth_server(
    principal_server_url: &str,
) -> anyhow::Result<PrincipalAuthServerResolution> {
    let resolver = AuthorityResolver::discover(principal_server_url).await?;
    Ok(PrincipalAuthServerResolution {
        auth_server_url: resolver.gate_account_base.clone(),
        principal_audience: resolver.principal_audience,
    })
}
