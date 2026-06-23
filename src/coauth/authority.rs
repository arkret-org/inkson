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
/// `/_cokret/describe` (service-surface §2.5.1) publishes a strongly-typed
/// `auth_metadata.account_authority.gate_account_base`; every Cokret
/// `/_cokret/gate/account/*` request MUST be derived from that single base
/// (a [`CoauthApi`] rooted at it), and the available authentication methods
/// come from `auth_metadata.methods[]`.
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

    /// Pick the first `oidc` method from `auth_metadata.methods[]`.
    pub fn oidc_method(&self) -> anyhow::Result<cokret_sdk::AuthMethod> {
        if let Some(method) = self
            .methods
            .iter()
            .find(|method| method.method == cokret_sdk::AuthMethodKind::Oidc)
        {
            return Ok(method.clone());
        }
        anyhow::bail!("principal server describe published no oidc auth method in methods[]")
    }
}

/// Derive the single client-visible `gate_account_base` from `auth_metadata`.
///
/// `account_authority.gate_account_base` is canonical. When the authority
/// publishes only `origin`, derive `{origin}/_cokret/gate/account`.
pub(crate) fn resolve_gate_account_base(
    _principal_server_url: &str,
    metadata: &cokret_sdk::AuthMetadata,
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
    let base = url.join("_cokret/gate/account").map_err(|error| {
        anyhow::anyhow!("invalid gate account base from origin {origin}: {error}")
    })?;
    Ok(normalize_gate_account_base(base.as_str()))
}

fn normalize_gate_account_base(base: &str) -> String {
    base.trim_end_matches('/').to_owned()
}
