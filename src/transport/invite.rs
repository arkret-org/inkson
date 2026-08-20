use serde_json::Value;
use url::Url;

use crate::directory_helpers::{
    ResolveHandleContext, canonical_invitee_handle, resolve_handle_request_body,
};
use crate::models::ResolveHandleView;

#[derive(Clone, Debug, PartialEq)]
pub struct InviteeResolution {
    pub did: String,
    pub handle: Option<String>,
    pub invite_delivery_target: arkret_sdk::InviteDeliveryTarget,
    pub introduction_evidence: arkret_sdk::IntroductionEvidence,
    pub introduction_evidence_digest: String,
}

impl InviteeResolution {
    // The DID was validated during resolution; the `expect` documents that
    // invariant rather than a reachable error path.
    #[allow(clippy::expect_used)]
    fn invite_address(&self) -> arkret_sdk::InviteAddress {
        arkret_sdk::InviteAddress {
            subject_id: arkret_sdk::DidCoreId::new(self.did.clone())
                .expect("resolved invitee DID remains valid"),
            recipient_service_id: self.invite_delivery_target.recipient_service_id.clone(),
            service_resolution: self.invite_delivery_target.service_resolution.clone(),
            route_assistance: None,
            recipient_service_kind: self.invite_delivery_target.recipient_service_kind.clone(),
        }
    }
}

pub(crate) struct ContactRequestAddressing {
    pub(crate) target: arkret_sdk::DidCoreId,
    pub(crate) introduction_evidence: arkret_sdk::ContactIntroductionEvidence,
}

fn invitee_resolution(
    invite_address: arkret_sdk::InviteAddress,
    handle: Option<String>,
    introduction_evidence: arkret_sdk::IntroductionEvidence,
) -> anyhow::Result<InviteeResolution> {
    invite_address
        .validate()
        .map_err(|err| anyhow::anyhow!("invalid invite_address: {err}"))?;
    let did = invite_address.subject_id.to_string();
    let invite_delivery_target =
        arkret_sdk::InviteDeliveryTarget::from_invite_address(&invite_address);
    invite_delivery_target
        .validate()
        .map_err(|err| anyhow::anyhow!("invalid invite_delivery_target: {err}"))?;
    let introduction_evidence_value = serde_json::to_value(&introduction_evidence)?;
    let introduction_evidence_digest =
        crate::canonical::canonical_sha256(&introduction_evidence_value)?;
    Ok(InviteeResolution {
        did,
        handle,
        invite_delivery_target,
        introduction_evidence,
        introduction_evidence_digest,
    })
}

fn explicit_invitee_resolution(
    invite_address: arkret_sdk::InviteAddress,
    handle: Option<String>,
) -> anyhow::Result<InviteeResolution> {
    invitee_resolution(
        invite_address,
        handle,
        arkret_sdk::IntroductionEvidence::ExplicitAddress,
    )
}

fn invite_address(
    subject_id: &str,
    recipient_service_id: &str,
) -> anyhow::Result<arkret_sdk::InviteAddress> {
    let _subject = arkret_sdk::DidCoreId::new(subject_id.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid invite subject core_id `{subject_id}`: {err}"))?;
    let _recipient_service = arkret_sdk::DidCoreId::new(recipient_service_id.trim().to_owned())
        .map_err(|err| {
            anyhow::anyhow!(
                "invalid invite recipient service core_id `{recipient_service_id}`: {err}"
            )
        })?;
    anyhow::bail!(
        "DID + server invite addressing omits service_resolution; use a principal locator or invite address carrying current resolution evidence"
    )
}

/// A Contact scope is not a Consent grant. The direct-DID contact path uses
/// the protocol's explicit-address introduction evidence and relies on the
/// independent directional `invite` scope gate; it never fabricates a
/// `consent_grant_ref` from Contact request/response Events.
fn contact_explicit_address_evidence_digest() -> anyhow::Result<String> {
    crate::canonical::canonical_sha256(&serde_json::json!({
        "kind": "explicit_address",
    }))
}

fn invitee_from_principal_locator(
    locator: arkret_sdk::PrincipalLocator,
) -> anyhow::Result<InviteeResolution> {
    locator
        .validate_minimal()
        .map_err(|err| anyhow::anyhow!("principal locator validation failed: {err}"))?;
    let address = locator.invite_address();
    invitee_resolution(
        address,
        None,
        arkret_sdk::IntroductionEvidence::LocatorRef {
            principal_locator: locator,
        },
    )
}

fn invitee_from_target_json(target: &str) -> anyhow::Result<Option<InviteeResolution>> {
    let value = match serde_json::from_str::<Value>(target) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if value.get("schema").and_then(Value::as_str)
        == Some(arkret_sdk::SchemaId::PRINCIPAL_LOCATOR_V1)
    {
        let locator: arkret_sdk::PrincipalLocator = serde_json::from_value(value)?;
        return invitee_from_principal_locator(locator).map(Some);
    }
    if value.get("subject_id").is_some() && value.get("recipient_service_id").is_some() {
        let address: arkret_sdk::InviteAddress = serde_json::from_value(value)?;
        return explicit_invitee_resolution(address, None).map(Some);
    }
    anyhow::bail!("invite target JSON must be a principal locator or invite address")
}

fn locator_url_token(url: &Url) -> anyhow::Result<String> {
    if url
        .query_pairs()
        .any(|(key, _)| key == "token" || key == "locator_token")
    {
        anyhow::bail!("invite locator token must be carried in the URL fragment, not query");
    }
    let fragment = url
        .fragment()
        .map(str::trim)
        .filter(|fragment| !fragment.is_empty())
        .ok_or_else(|| anyhow::anyhow!("invite locator URL must include a #token fragment"))?;
    url::form_urlencoded::parse(fragment.as_bytes())
        .find(|(key, _)| key == "token" || key == "locator_token")
        .map(|(_, value)| value.into_owned())
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("invite locator URL must include a non-empty #token fragment")
        })
}

fn locator_url_origin(url: &Url) -> anyhow::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("invite locator URL must include a host"))?;
    let mut origin = format!("{}://{host}", url.scheme());
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn parse_invite_locator_url(target: &str) -> anyhow::Result<Option<(String, String)>> {
    let url = match Url::parse(target) {
        Ok(url) => url,
        Err(_) => return Ok(None),
    };
    if url.path() != "/_arkret/open/invite-locators/resolve" {
        anyhow::bail!("invite locator URL path must be /_arkret/open/invite-locators/resolve");
    }
    let token = locator_url_token(&url)?;
    Ok(Some((locator_url_origin(&url)?, token)))
}

fn token_value<'a>(token: &'a str, names: &[&str]) -> Option<&'a str> {
    let (key, value) = token.split_once('=')?;
    let key = key.trim().to_ascii_lowercase();
    names
        .iter()
        .any(|name| key == *name)
        .then(|| value.trim())
        .filter(|value| !value.is_empty())
}

fn parse_explicit_invite_target(target: &str) -> anyhow::Result<Option<InviteeResolution>> {
    let tokens: Vec<&str> = target
        .split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';' | '|'))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect();
    let mut subject = None;
    let mut server = None;
    for token in &tokens {
        if let Some(value) = token_value(token, &["did", "subject", "subject_id", "target"]) {
            subject = Some(value);
        } else if let Some(value) =
            token_value(token, &["server", "service", "recipient_service_id"])
        {
            server = Some(value);
        }
    }
    if let (Some(subject), Some(server)) = (subject, server) {
        return explicit_invitee_resolution(invite_address(subject, server)?, None).map(Some);
    }
    let core_ids: Vec<&str> = tokens
        .iter()
        .copied()
        .filter(|token| arkret_sdk::DidCoreId::new((*token).to_owned()).is_ok())
        .collect();
    if core_ids.len() == 2 {
        let (subject, server) =
            if core_ids[1].contains(":users:") && !core_ids[0].contains(":users:") {
                (core_ids[1], core_ids[0])
            } else {
                (core_ids[0], core_ids[1])
            };
        return explicit_invitee_resolution(invite_address(subject, server)?, None).map(Some);
    }
    Ok(None)
}

fn resolved_handle_claim(
    resolved: &ResolveHandleView,
) -> anyhow::Result<Option<arkret_models_identity::HandleClaim>> {
    let Some(claim) = resolved.handle_claim.clone() else {
        return Ok(None);
    };
    claim
        .validate()
        .map_err(|err| anyhow::anyhow!("directory returned invalid handle_claim: {err}"))?;
    Ok(Some(claim))
}

fn resolved_member_delivery_binding(
    resolved: &ResolveHandleView,
) -> anyhow::Result<Option<arkret_models_identity::DeliveryBindingHint>> {
    Ok(resolved.member_delivery_binding_ref().cloned())
}

fn resolved_by_did(resolved: &ResolveHandleView) -> Option<arkret_sdk::DidCoreId> {
    resolved
        .via_services
        .iter()
        .find_map(|did| arkret_sdk::DidCoreId::new(did.clone()).ok())
}

fn resolved_at(resolved: &ResolveHandleView) -> Option<chrono::DateTime<chrono::Utc>> {
    resolved
        .as_of
        .as_deref()
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|ts| ts.with_timezone(&chrono::Utc))
}

impl crate::transport::TransportClient {
    // ── Identity & Directory ────────────────────────────────────────

    pub(crate) async fn dispatch_accepted_invite(
        &self,
        accepted_event_id: &str,
        invitee: &InviteeResolution,
    ) -> anyhow::Result<arkret_sdk::InviteDeliveryOutcome> {
        let event_id = arkret_sdk::EventId::new(accepted_event_id.to_owned())
            .map_err(|error| anyhow::anyhow!("accepted invite event id is invalid: {error}"))?;
        let resolved = self
            .sdk_http_client()?
            .events_resolve(&arkret_sdk::EventsResolveRequestBody {
                event_ids: vec![event_id.clone()],
                event_digests: Vec::new(),
                seal_refs: Vec::new(),
                include_payload: Some(true),
            })
            .await?;
        let event = resolved
            .events
            .into_iter()
            .find(|event| event.event_id == event_id)
            .ok_or_else(|| anyhow::anyhow!("accepted invite Event was not resolvable"))?;
        let delivery = arkret_sdk::InviteDeliveryRequestBody::new(
            event,
            invitee.invite_address(),
            invitee.introduction_evidence.clone(),
            accepted_event_id,
        );
        delivery
            .validate_minimal()
            .map_err(|error| anyhow::anyhow!("invite delivery request is invalid: {error}"))?;
        self.sdk_http_client()?
            .post("/_arkret/self/invites/dispatch", &delivery)
            .await
            .map_err(Into::into)
    }

    async fn resolve_handle_with_context(
        &self,
        handle: &str,
        context: ResolveHandleContext<'_>,
    ) -> anyhow::Result<ResolveHandleView> {
        let body = resolve_handle_request_body(handle, context)?;
        let outcome: arkret_sdk::DirectoryHandleResolutionOutcome = self
            .sdk_http_client()?
            .directory_resolve_handle(&body)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(outcome.into())
    }

    pub async fn resolve_agent_selector_mention(
        &self,
        controller_handle: &str,
        agent_slug: &str,
        realm_id: &str,
        requester: &str,
    ) -> anyhow::Result<arkret_models_discovery::DirectoryAgentSelectorResolutionOutcome> {
        let controller_handle =
            arkret_models_identity::Handle::parse(controller_handle).map_err(|err| {
                anyhow::anyhow!("invalid controller handle `{controller_handle}`: {err}")
            })?;
        arkret_models_identity::validate_agent_slug(agent_slug)
            .map_err(|err| anyhow::anyhow!("invalid agent_slug `{agent_slug}`: {err}"))?;
        let requester = crate::mls_api_helpers::principal_core_id(requester)
            .map_err(|err| anyhow::anyhow!("invalid requester DID `{requester}`: {err}"))?;
        let realm_id = arkret_sdk::RealmId::new(realm_id.trim().to_owned())
            .map_err(|err| anyhow::anyhow!("invalid realm_id `{realm_id}`: {err}"))?;
        let body = arkret_models_discovery::DirectoryResolveAgentSelectorRequestBody {
            controller_handle,
            agent_slug: agent_slug.to_owned(),
            expected_actor_id: None,
            proof_challenge: None,
            intent: arkret_models_discovery::DirectoryIntent::Mention,
            realm_id: Some(realm_id),
            requester,
            proofs: Vec::new(),
        };
        let outcome: arkret_models_discovery::DirectoryAgentSelectorResolutionOutcome = self
            .sdk_http_client()?
            .directory_resolve_agent_selector(&body)
            .await
            .map_err(anyhow::Error::from)?;
        outcome
            .validate()
            .map_err(|err| anyhow::anyhow!("invalid agent selector outcome: {err}"))?;
        Ok(outcome)
    }

    async fn resolve_invitee_handle_for_invite(
        &self,
        handle: &str,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<InviteeResolution> {
        let resolved = self
            .resolve_handle_with_context(
                handle,
                ResolveHandleContext {
                    intent: Some("invite"),
                    requester: Some(actor_id),
                    audience: Some(realm_id),
                    realm_id: Some(realm_id),
                    ..ResolveHandleContext::default()
                },
            )
            .await?;
        let subject = resolved.subject_did().ok_or_else(|| {
            anyhow::anyhow!("directory resolve_handle response did not include subject DID")
        })?;
        let recipient_service = resolved_member_delivery_binding(&resolved)?
            .map(|binding| binding.recipient_service_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "directory handle result did not include a recipient service; use DID + server"
                )
            })?;
        let address = invite_address(subject, recipient_service.as_str())?;
        let handle = arkret_models_identity::Handle::parse(&resolved.handle)
            .map_err(|err| anyhow::anyhow!("directory returned invalid handle: {err}"))?;
        let resolved_by = resolved_by_did(&resolved);
        let evidence = match resolved_handle_claim(&resolved)? {
            Some(handle_claim) => arkret_sdk::IntroductionEvidence::HandleClaim {
                handle: handle.clone(),
                handle_claim: Box::new(handle_claim),
                member_delivery_binding_candidate: None,
                resolved_by,
                resolved_at: resolved_at(&resolved),
            },
            None => arkret_sdk::IntroductionEvidence::ExplicitAddress,
        };
        invitee_resolution(address, Some(handle.canonical().to_owned()), evidence)
    }

    pub(crate) async fn contact_request_addressing(
        &self,
        target: &str,
    ) -> anyhow::Result<ContactRequestAddressing> {
        let target = target.trim();
        if target.is_empty() {
            anyhow::bail!("contact target is required");
        }
        if let Ok(handle) = canonical_invitee_handle(target) {
            let requester = crate::transport::account::account_me(&self.sdk_http_client()?)
                .await?
                .principal_id;
            let resolved = self
                .resolve_handle_with_context(
                    &handle,
                    ResolveHandleContext {
                        intent: Some("contact_request"),
                        requester: Some(requester.as_str()),
                        audience: Some(requester.as_str()),
                        ..ResolveHandleContext::default()
                    },
                )
                .await?;
            let subject = resolved.subject_did().ok_or_else(|| {
                anyhow::anyhow!("directory resolve_handle response did not include subject DID")
            })?;
            let target_did = crate::mls_api_helpers::principal_core_id(subject).map_err(|err| {
                anyhow::anyhow!("directory resolved invalid DID `{subject}`: {err}")
            })?;
            let handle = arkret_models_identity::Handle::parse(&resolved.handle)
                .map_err(|err| anyhow::anyhow!("directory returned invalid handle: {err}"))?;
            let resolved_by = resolved_by_did(&resolved);
            let introduction_evidence = match resolved_handle_claim(&resolved)? {
                Some(handle_claim) => arkret_sdk::ContactIntroductionEvidence::HandleClaim {
                    handle,
                    handle_claim: Box::new(handle_claim),
                    resolved_by,
                    resolved_at: resolved_at(&resolved),
                },
                None => arkret_sdk::ContactIntroductionEvidence::ExplicitAddress,
            };
            return Ok(ContactRequestAddressing {
                target: target_did,
                introduction_evidence,
            });
        }
        let target_did = crate::mls_api_helpers::principal_core_id(target)
            .map_err(|err| anyhow::anyhow!("invalid contact target DID `{target}`: {err}"))?;
        Ok(ContactRequestAddressing {
            target: target_did,
            introduction_evidence: arkret_sdk::ContactIntroductionEvidence::ExplicitAddress,
        })
    }

    /// U3 — pull an existing contact into a Realm using their DID directly,
    /// with explicit-address evidence (no locator URL). The Contact's current
    /// bidirectional `invite` scope is checked by the caller as an independent
    /// action gate and is never translated into Consent evidence.
    ///
    /// Returns the submitted invite event id and invite id on success.
    pub async fn invite_contact_to_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        contact_did: &str,
        recipient_service_id: Option<&str>,
    ) -> anyhow::Result<(String, String)> {
        let contact_did = contact_did.trim();
        arkret_sdk::DidFullId::new(contact_did.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid contact DID `{contact_did}`: {err}"))?;
        let recipient_service_id = recipient_service_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "contact `{contact_did}` has no attested recipient service; use the invite link path instead"
                )
            })?;
        let _recipient_service = arkret_sdk::DidCoreId::new(recipient_service_id.to_owned())
            .map_err(|err| {
                anyhow::anyhow!("invalid contact recipient service `{recipient_service_id}`: {err}")
            })?;
        let _ = (
            realm_id,
            actor_id,
            contact_explicit_address_evidence_digest()?,
        );
        anyhow::bail!(
            "contact delivery binding omits service_resolution; refresh the contact through a principal locator before inviting"
        )
    }

    pub async fn resolve_invitee_for_invite(
        &self,
        target: &str,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<InviteeResolution> {
        let target = target.trim();
        if target.is_empty() {
            anyhow::bail!("invite target is required");
        }
        if let Some(invitee) = invitee_from_target_json(target)? {
            return Ok(invitee);
        }
        if let Some((resolver_origin, locator_token)) = parse_invite_locator_url(target)? {
            // Loopback allowance (the SDK still rejects insecure remote URLs) so
            // an invite locator resolves against a local dev / joint-e2e
            // resolver on `http://127.0.0.1`.
            let resolver =
                arkret_sdk::http_client::ClientBuilder::new(Url::parse(&resolver_origin)?)
                    .allow_insecure_localhost()
                    .build()?;
            let body = arkret_sdk::InviteLocatorResolveRequestBody::new(locator_token);
            body.validate_minimal()
                .map_err(|err| anyhow::anyhow!("invalid invite locator token: {err}"))?;
            let locator: arkret_sdk::PrincipalLocator = resolver
                .post(arkret_sdk::INVITE_LOCATOR_RESOLVE_PATH, &body)
                .await
                .map_err(anyhow::Error::from)?;
            return invitee_from_principal_locator(locator);
        }

        if let Ok(handle) = canonical_invitee_handle(target) {
            return self
                .resolve_invitee_handle_for_invite(&handle, realm_id, actor_id)
                .await;
        }
        if let Some(invitee) = parse_explicit_invite_target(target)? {
            return Ok(invitee);
        }
        if arkret_sdk::DidFullId::new(target.to_owned()).is_ok() {
            anyhow::bail!("raw DID invite target also needs a recipient server DID");
        }
        anyhow::bail!(
            "invite target must be a locator, handle, principal locator JSON, or DID + server"
        )
    }
}

#[cfg(test)]
mod invite_addressing_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn locator_url_reads_token_from_fragment() {
        let (origin, token) = parse_invite_locator_url(
            "https://ps.bob.example:9443/_arkret/open/invite-locators/resolve#token=abc%20123",
        )
        .expect("valid locator url")
        .expect("locator url parsed");
        assert_eq!(origin, "https://ps.bob.example:9443");
        assert_eq!(token, "abc 123");
    }

    #[test]
    fn locator_url_rejects_query_token() {
        let err = parse_invite_locator_url(
            "https://ps.bob.example/_arkret/open/invite-locators/resolve?locator_token=abc",
        )
        .expect_err("query token must be rejected");
        assert!(err.to_string().contains("fragment"));
    }

    #[test]
    fn principal_locator_builds_locator_ref_evidence() {
        let locator = json!({
            "schema": arkret_sdk::SchemaId::PRINCIPAL_LOCATOR_V1,
            "subject_id": "ak:did_core:web:bob.example",
            "recipient_service_id": "ak:did_core:web:ps.bob.example",
            "service_resolution": {
                "current_record_url": "https://ps.bob.example/_arkret/open/services/ak%3Adid_core%3Aweb%3Aps.bob.example/resolution"
            },
            "issued_at": "2026-06-07T00:00:00.000Z",
            "expires_at": "2026-06-07T00:15:00.000Z",
            "locator_ref_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "proofs": [{
                "proof_purpose": "recipient_service_acceptance",
                "proof": {
                    "kind": "detached_jws",
                    "verification_method": "did:web:ps.bob.example#server-key-1",
                    "payload_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "created_at": "2026-06-07T00:00:00.000Z",
                    "jws": "header..sig"
                }
            }],
        });
        let locator = serde_json::from_value(locator).expect("typed principal locator");
        let invitee = invitee_from_principal_locator(locator).expect("principal locator");
        assert_eq!(invitee.did, "ak:did_core:web:bob.example");
        assert_eq!(
            invitee.invite_delivery_target.recipient_service_id.as_str(),
            "ak:did_core:web:ps.bob.example"
        );
        assert_eq!(invitee.introduction_evidence.kind(), "locator_ref");
    }

    #[test]
    fn invite_target_json_accepts_invite_address_as_explicit() {
        let raw_invite_address = json!({
            "subject_id": "ak:did_core:web:bob.example",
            "recipient_service_id": "ak:did_core:web:ps.bob.example",
            "service_resolution": {
                "current_record_url": "https://ps.bob.example/_arkret/open/services/ak%3Adid_core%3Aweb%3Aps.bob.example/resolution"
            },
        })
        .to_string();
        let invitee = invitee_from_target_json(&raw_invite_address)
            .expect("json target parsed")
            .expect("invite address target");
        assert_eq!(invitee.did, "ak:did_core:web:bob.example");
        assert_eq!(invitee.introduction_evidence.kind(), "explicit_address");
    }

    #[test]
    fn explicit_invite_target_without_resolution_fails_closed() {
        let error = parse_explicit_invite_target(
            "ak:did_core:web:bob.example ak:did_core:web:ps.bob.example",
        )
        .expect_err("DID + server without resolution carrier must fail closed");
        assert!(error.to_string().contains("omits service_resolution"));
    }
}
