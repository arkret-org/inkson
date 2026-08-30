use arkret_sdk::{AccountId, DeviceId, Did, DidCoreId, PrincipalResolutionProjection};
use serde::{Deserialize, Serialize};
use url::Url;

/// The one runtime aggregate that identifies an authenticated local account.
///
/// Identity, current DID resolution and transport route deliberately remain
/// separate coordinates. This type does not implement `PartialEq`/`Eq`; callers
/// must choose the equality they actually mean (`authority`, principal core,
/// current resolution or route).
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveAccountContext {
    pub profile_id: String,
    pub authority: AccountId,
    pub resolution: PrincipalResolutionProjection,
    pub device_id: DeviceId,
    pub server_url: Url,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedActiveAccountContext {
    profile_id: String,
    authority: AccountId,
    resolution: PrincipalResolutionProjection,
    device_id: DeviceId,
    server_url: Url,
}

impl TryFrom<PersistedActiveAccountContext> for ActiveAccountContext {
    type Error = String;

    fn try_from(value: PersistedActiveAccountContext) -> Result<Self, Self::Error> {
        Self::new(
            value.profile_id,
            value.authority,
            value.resolution,
            value.device_id,
            value.server_url,
        )
        .map_err(|error| error.to_string())
    }
}

impl<'de> Deserialize<'de> for ActiveAccountContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        PersistedActiveAccountContext::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl ActiveAccountContext {
    /// Construct from a projection that the caller has already accepted after
    /// attestation, method-history and freshness verification.
    ///
    /// This constructor is crate-private so raw network responses and DID
    /// DIDs cannot create authenticated application state outside the identity
    /// boundary.
    pub(crate) fn new(
        profile_id: String,
        authority: AccountId,
        resolution: PrincipalResolutionProjection,
        device_id: DeviceId,
        server_url: Url,
    ) -> anyhow::Result<Self> {
        if profile_id.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "active account profile_id must be non-empty"
            ));
        }
        authority
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let projected = arkret_sdk::project_did_to_core_id(&resolution.did)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if projected != authority.principal_id {
            return Err(anyhow::anyhow!(
                "accepted principal resolution does not match account authority"
            ));
        }
        if resolution.method_history_head.trim().is_empty()
            || resolution.version_id.trim().is_empty()
            || resolution.resolution_event_ref.trim().is_empty()
        {
            return Err(anyhow::anyhow!(
                "accepted principal resolution is missing evidence coordinates"
            ));
        }
        validate_server_url(&server_url)?;
        Ok(Self {
            profile_id,
            authority,
            resolution,
            device_id,
            server_url,
        })
    }

    pub fn principal_id(&self) -> &DidCoreId {
        &self.authority.principal_id
    }

    pub fn did(&self) -> &Did {
        &self.resolution.did
    }

    pub fn same_authority(&self, other: &Self) -> bool {
        self.authority == other.authority
    }

    /// Replace the complete accepted projection atomically. A DID is
    /// intentionally not accepted by this API.
    pub(crate) fn update_resolution(
        &mut self,
        next: PrincipalResolutionProjection,
    ) -> anyhow::Result<()> {
        let projected = arkret_sdk::project_did_to_core_id(&next.did)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if projected != self.authority.principal_id {
            return Err(anyhow::anyhow!(
                "principal resolution update changes the stable principal"
            ));
        }
        if next.method_history_head.trim().is_empty()
            || next.version_id.trim().is_empty()
            || next.resolution_event_ref.trim().is_empty()
            || next.updated_at < self.resolution.updated_at
        {
            return Err(anyhow::anyhow!(
                "principal resolution update is stale or incomplete"
            ));
        }
        self.resolution = next;
        Ok(())
    }

    /// Refresh only the route after the serving service has been verified to
    /// have the same stable service core.
    pub(crate) fn update_route(
        &mut self,
        verified_service_id: &DidCoreId,
        next: Url,
    ) -> anyhow::Result<()> {
        if verified_service_id != &self.authority.station_id {
            return Err(anyhow::anyhow!(
                "route refresh belongs to a different Station"
            ));
        }
        validate_server_url(&next)?;
        self.server_url = next;
        Ok(())
    }
}

pub(crate) fn authority_namespace(authority: &AccountId) -> anyhow::Result<String> {
    authority
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let canonical = arkret_sdk::canonical::canonical_json_bytes(authority)?;
    Ok(arkret_sdk::canonical::sha256_base64url(canonical))
}

fn validate_server_url(url: &Url) -> anyhow::Result<()> {
    if url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https"
            || matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")))
    {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "active Station route must be HTTPS (or loopback HTTP) without credentials, query or fragment"
    ))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone as _, Utc};

    use super::*;

    fn core(value: &str) -> DidCoreId {
        DidCoreId::new(value.to_owned()).unwrap()
    }

    fn projection(did: &str, revision: u32) -> PrincipalResolutionProjection {
        PrincipalResolutionProjection {
            did: Did::new(did.to_owned()).unwrap(),
            method_history_head: format!("head-{revision}"),
            version_id: revision.to_string(),
            resolution_event_ref: format!(
                "ak:event:{}",
                char::from(b'A' + revision as u8).to_string().repeat(44)
            ),
            updated_at: Utc.with_ymd_and_hms(2026, 8, 22, 12, 0, 0).unwrap()
                + Duration::seconds(i64::from(revision)),
        }
    }

    fn context(service: &str, route: &str) -> ActiveAccountContext {
        ActiveAccountContext::new(
            "ak:profile:019b0000-0000-7000-8000-000000000001".to_owned(),
            AccountId::new(core("ak:did_core:webvh:zAlice"), core(service)),
            projection("did:webvh:zAlice:old.example:users:alice", 1),
            DeviceId::new("ak:device:019b0000-0000-7000-8000-000000000001").unwrap(),
            Url::parse(route).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn identity_change_matrix_keeps_only_the_intended_coordinate_stable() {
        let mut same_account =
            context("ak:did_core:webvh:zServerA", "https://principal-a.example/");
        let namespace = authority_namespace(&same_account.authority).unwrap();
        let profile_id = same_account.profile_id.clone();
        let device_id = same_account.device_id.clone();

        same_account
            .update_resolution(projection("did:webvh:zAlice:new.example:people:alice", 2))
            .unwrap();
        assert_eq!(same_account.profile_id, profile_id);
        assert_eq!(same_account.device_id, device_id);
        assert_eq!(
            authority_namespace(&same_account.authority).unwrap(),
            namespace
        );

        same_account
            .update_route(
                &core("ak:did_core:webvh:zServerA"),
                Url::parse("https://principal-a-mirror.example:8443/").unwrap(),
            )
            .unwrap();
        assert_eq!(
            authority_namespace(&same_account.authority).unwrap(),
            namespace
        );

        let other_authority = context("ak:did_core:webvh:zServerB", "https://principal-b.example/");
        assert_ne!(
            authority_namespace(&same_account.authority).unwrap(),
            authority_namespace(&other_authority.authority).unwrap()
        );

        let other_principal = ActiveAccountContext::new(
            "ak:profile:019b0000-0000-7000-8000-000000000002".to_owned(),
            AccountId::new(
                core("ak:did_core:webvh:zBob"),
                core("ak:did_core:webvh:zServerA"),
            ),
            projection("did:webvh:zBob:old.example:users:bob", 1),
            DeviceId::new("ak:device:019b0000-0000-7000-8000-000000000002").unwrap(),
            Url::parse("https://principal-a.example/").unwrap(),
        )
        .unwrap();
        assert_ne!(
            authority_namespace(&same_account.authority).unwrap(),
            authority_namespace(&other_principal.authority).unwrap()
        );
    }

    #[test]
    fn update_boundaries_reject_core_or_service_changes() {
        let mut account = context("ak:did_core:webvh:zServerA", "https://principal-a.example/");
        assert!(
            account
                .update_resolution(projection("did:webvh:zMallory:elsewhere.example", 2))
                .is_err()
        );
        assert!(
            account
                .update_route(
                    &core("ak:did_core:webvh:zServerB"),
                    Url::parse("https://principal-b.example/").unwrap(),
                )
                .is_err()
        );
    }
}
