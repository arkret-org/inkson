use serde_json::Value;
use url::Url;

use crate::directory_helpers::{
    ResolveHandleContext, canonical_invitee_handle, resolve_handle_request_body,
};
use crate::models::ResolveHandleView;

#[derive(Clone, Debug, PartialEq)]
pub struct InviteeResolution {
    pub invite_address: arkret_sdk::InviteAddress,
    pub handle: Option<String>,
    pub introduction_evidence: arkret_sdk::IntroductionEvidence,
    pub introduction_evidence_digest: String,
}

impl InviteeResolution {
    pub fn account_id(&self) -> &arkret_sdk::AccountId {
        &self.invite_address.account_id
    }
}

pub(crate) struct ContactRequestAddressing {
    pub(crate) target: arkret_sdk::AccountId,
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
    let introduction_evidence_value = serde_json::to_value(&introduction_evidence)?;
    let introduction_evidence_digest =
        crate::canonical::canonical_sha256(&introduction_evidence_value)?;
    Ok(InviteeResolution {
        invite_address,
        handle,
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
    recipient_id: &str,
) -> anyhow::Result<arkret_sdk::InviteAddress> {
    let _subject = arkret_sdk::DidCoreId::new(subject_id.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid invite subject core_id `{subject_id}`: {err}"))?;
    let _recipient_service =
        arkret_sdk::DidCoreId::new(recipient_id.trim().to_owned()).map_err(|err| {
            anyhow::anyhow!("invalid invite recipient service core_id `{recipient_id}`: {err}")
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
    if value.get("account_id").is_some() {
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
    if !matches!(url.scheme(), "https" | "http") {
        return Ok(None);
    }
    if url.path() != "/_arkret/open/invite-locators/resolve" {
        anyhow::bail!("invite locator URL path must be /_arkret/open/invite-locators/resolve");
    }
    let token = locator_url_token(&url)?;
    Ok(Some((locator_url_origin(&url)?, token)))
}

async fn resolve_principal_locator_url(
    target: &str,
) -> anyhow::Result<Option<arkret_sdk::PrincipalLocator>> {
    let Some((origin, token)) = parse_invite_locator_url(target)? else {
        return Ok(None);
    };
    // Resolve public introduction evidence without forwarding the caller's
    // session credential to the locator's Station.
    let resolver = arkret_sdk::http_client::ClientBuilder::new(Url::parse(&origin)?)
        .allow_insecure_localhost()
        .build()?;
    let body = arkret_sdk::InviteLocatorResolveRequestBody::new(token);
    body.validate_minimal()
        .map_err(|err| anyhow::anyhow!("invalid invite locator token: {err}"))?;
    let locator: arkret_sdk::PrincipalLocator = resolver
        .post(arkret_sdk::INVITE_LOCATOR_RESOLVE_PATH, &body)
        .await
        .map_err(|error| {
            let unavailable = matches!(
                &error,
                arkret_sdk::http_client::Error::Api { status: 404, error }
                    if error.code() == arkret_sdk::error_codes::ErrorCode::NOT_FOUND
            );
            let error = anyhow::Error::from(error);
            if unavailable {
                error.context(crate::api_error::InviteLocatorUnavailable)
            } else {
                error
            }
        })?;
    locator.validate_minimal()?;
    Ok(Some(locator))
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
        } else if let Some(value) = token_value(token, &["server", "service", "recipient_id"]) {
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
    let Some(claim) = resolved
        .claims
        .as_ref()
        .and_then(|claims| claims.first())
        .cloned()
    else {
        return Ok(None);
    };
    claim
        .validate()
        .map_err(|err| anyhow::anyhow!("directory returned invalid handle_claim: {err}"))?;
    Ok(Some(claim))
}

fn resolved_account_invite_address(
    account_id: &arkret_sdk::AccountId,
) -> anyhow::Result<arkret_sdk::InviteAddress> {
    let host = account_id
        .station_id
        .as_str()
        .strip_prefix("ak:did_core:web:")
        .and_then(|rest| rest.split(':').next())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "handle result Station has no derivable HTTPS origin; use a principal locator"
            )
        })?;
    let current_record_url = format!(
        "https://{host}{}",
        arkret_sdk::canonical_service_current_record_path(&account_id.station_id)
    );
    let target = arkret_sdk::InviteAddress {
        account_id: account_id.clone(),
        service_resolution: arkret_sdk::ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url,
            pinned_record_digest: None,
        },
        route_assistance: None,
    };
    target.validate()?;
    Ok(target)
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
        // The self dispatch endpoint resolves the already accepted Event from
        // durable local storage.  Carrying the full Event here would be the
        // peer-delivery wire shape and is rejected by the closed self schema.
        let delivery = arkret_sdk::SelfInviteDispatchRequestBody {
            schema: arkret_sdk::SchemaId::INVITE_DELIVERY_REQUEST_V1.to_owned(),
            invite_event_id: event_id,
            invite_address: invitee.invite_address.clone(),
            introduction_evidence: invitee.introduction_evidence.clone(),
            idempotency_key: accepted_event_id.to_owned(),
        };
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
        Ok(outcome)
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
            requester_id: requester,
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
        let address = resolved_account_invite_address(&resolved.account_id)?;
        let handle = arkret_models_identity::Handle::parse(&resolved.handle)
            .map_err(|err| anyhow::anyhow!("directory returned invalid handle: {err}"))?;
        let evidence = match resolved_handle_claim(&resolved)? {
            Some(handle_claim) => arkret_sdk::IntroductionEvidence::HandleClaim {
                handle: handle.clone(),
                handle_claim: Box::new(handle_claim),
                resolved_by: None,
                resolved_at: None,
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
        if let Some(principal_locator) = resolve_principal_locator_url(target).await? {
            return Ok(ContactRequestAddressing {
                target: principal_locator.account_id.clone(),
                introduction_evidence: arkret_sdk::ContactIntroductionEvidence::LocatorRef {
                    principal_locator,
                },
            });
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
            let handle = arkret_models_identity::Handle::parse(&resolved.handle)
                .map_err(|err| anyhow::anyhow!("directory returned invalid handle: {err}"))?;
            let introduction_evidence = match resolved_handle_claim(&resolved)? {
                Some(handle_claim) => arkret_sdk::ContactIntroductionEvidence::HandleClaim {
                    handle,
                    handle_claim: Box::new(handle_claim),
                    resolved_by: None,
                    resolved_at: None,
                },
                None => arkret_sdk::ContactIntroductionEvidence::ExplicitAddress,
            };
            return Ok(ContactRequestAddressing {
                target: resolved.account_id,
                introduction_evidence,
            });
        }
        // An explicit address is the counterparty's complete account. A bare
        // principal has no Station, and this client's Station is not a stand-in
        // for it: the same principal at another Station is a different account
        // (account-lifecycle.md §156/§158), so the request fails closed instead
        // of being addressed to whoever holds that principal here.
        let target_account =
            crate::mls_api_helpers::account_id_from_selector(target).ok_or_else(|| {
                anyhow::anyhow!(
                    "contact target must be an invite link, handle, or complete account selector"
                )
            })?;
        Ok(ContactRequestAddressing {
            target: target_account,
            introduction_evidence: arkret_sdk::ContactIntroductionEvidence::ExplicitAddress,
        })
    }

    /// U3 — pull an existing contact into a Realm using their complete AccountId,
    /// with explicit-address evidence (no locator URL). The Contact's current
    /// bidirectional `invite` scope is checked by the caller as an independent
    /// action gate and is never translated into Consent evidence.
    ///
    /// Returns the submitted invite event id and invite id on success.
    pub async fn invite_contact_to_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        contact_account: &arkret_sdk::AccountId,
    ) -> anyhow::Result<(String, String)> {
        let _ = (
            realm_id,
            actor_id,
            contact_account,
            contact_explicit_address_evidence_digest()?,
        );
        anyhow::bail!(
            "the contact AccountId identifies its Station but carries no authenticated service_resolution; refresh the contact through a principal locator before inviting"
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
        if let Some(locator) = resolve_principal_locator_url(target).await? {
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
        if arkret_sdk::Did::new(target.to_owned()).is_ok() {
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

    fn principal_locator_fixture() -> Value {
        json!({
            "schema": arkret_sdk::SchemaId::PRINCIPAL_LOCATOR_V1,
            "account_id": {"principal_id": "ak:did_core:web:bob.example", "station_id": "ak:did_core:web:ps.bob.example"},
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
        })
    }

    #[test]
    fn principal_locator_builds_locator_ref_evidence() {
        let locator = principal_locator_fixture();
        let locator = serde_json::from_value(locator).expect("typed principal locator");
        let invitee = invitee_from_principal_locator(locator).expect("principal locator");
        assert_eq!(
            invitee.account_id().principal_id.as_str(),
            "ak:did_core:web:bob.example"
        );
        assert_eq!(
            invitee.account_id().station_id.as_str(),
            "ak:did_core:web:ps.bob.example"
        );
        assert_eq!(invitee.introduction_evidence.kind(), "locator_ref");
    }

    #[test]
    fn locator_url_parser_leaves_handles_and_account_selectors_to_their_resolvers() {
        for target in [
            "alice:example.com",
            "ak:did_core:web:alice.example",
            "{\"account_id\":{}}",
        ] {
            assert!(parse_invite_locator_url(target).unwrap().is_none());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn contact_invite_link_resolves_exact_account_and_keeps_locator_evidence() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected = principal_locator_fixture();
        let response = expected.to_string();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let count = socket.read(&mut buffer).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        assert!(
                            headers
                                .starts_with("post /_arkret/open/invite-locators/resolve http/1.1")
                        );
                        assert!(!headers.contains("authorization:"));
                        assert!(!headers.contains("bG9jYXRvci1zZWNyZXQtMTIzNDU2Nzg5"));
                        let body: Value = serde_json::from_slice(&request[end + 4..]).unwrap();
                        assert_eq!(body["locator_token"], "bG9jYXRvci1zZWNyZXQtMTIzNDU2Nzg5");
                        break;
                    }
                }
            }
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
        });
        let client = crate::transport::TransportClient::new(
            "http://127.0.0.1:1",
            crate::transport::RequestContext::new("private-session-must-not-be-forwarded"),
        )
        .unwrap();
        let result = client
            .contact_request_addressing(&format!(
                "http://{address}/_arkret/open/invite-locators/resolve#token=bG9jYXRvci1zZWNyZXQtMTIzNDU2Nzg5"
            ))
            .await
            .unwrap();
        server.join().unwrap();
        assert_eq!(
            serde_json::to_value(result.target).unwrap(),
            expected["account_id"]
        );
        let arkret_sdk::ContactIntroductionEvidence::LocatorRef { principal_locator } =
            result.introduction_evidence
        else {
            panic!("contact must carry the resolved locator evidence");
        };
        assert_eq!(serde_json::to_value(principal_locator).unwrap(), expected);
    }

    #[test]
    fn invite_target_json_accepts_invite_address_as_explicit() {
        let raw_invite_address = json!({
            "account_id": {"principal_id": "ak:did_core:web:bob.example", "station_id": "ak:did_core:web:ps.bob.example"},
            "service_resolution": {
                "current_record_url": "https://ps.bob.example/_arkret/open/services/ak%3Adid_core%3Aweb%3Aps.bob.example/resolution"
            },
        })
        .to_string();
        let invitee = invitee_from_target_json(&raw_invite_address)
            .expect("json target parsed")
            .expect("invite address target");
        assert_eq!(
            invitee.account_id().principal_id.as_str(),
            "ak:did_core:web:bob.example"
        );
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
