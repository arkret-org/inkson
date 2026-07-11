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

pub(crate) struct ContactRequestAddressing {
    pub(crate) target: arkret_sdk::Did,
    pub(crate) recipient_service_id: Option<arkret_sdk::Did>,
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
    let subject = arkret_sdk::Did::new(subject_id.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid invite subject DID `{subject_id}`: {err}"))?;
    let recipient_service =
        arkret_sdk::Did::new(recipient_service_id.trim().to_owned()).map_err(|err| {
            anyhow::anyhow!("invalid invite recipient service DID `{recipient_service_id}`: {err}")
        })?;
    Ok(arkret_sdk::InviteAddress::principal_server(
        subject,
        recipient_service,
    ))
}

/// U3 — build the `consent_grant` introduction evidence for a contact-path
/// invite and return its canonical digest (the value
/// `ak_ops::invite_create_structured` stamps into the invite event).
///
/// We build the evidence object by hand (matching
/// `IntroductionEvidence::ConsentGrant`'s `{kind, consent_grant_ref}` wire
/// shape) rather than through the strict typed enum: the consent event ref
/// comes straight from the contacts projection and the digest is opaque to the
/// client — soland re-validates the ref server-side. Going through
/// `EventId::new` here would reject synthetic refs (e.g. e2e fixtures) before
/// the server ever gets a chance to check them.
fn contact_consent_evidence_digest(consent_grant_ref: &str) -> anyhow::Result<String> {
    let consent_grant_ref = consent_grant_ref.trim();
    if consent_grant_ref.is_empty() {
        anyhow::bail!("consent_grant_ref is required for the contacts invite path");
    }
    let value = serde_json::json!({
        "kind": "consent_grant",
        "consent_grant_ref": consent_grant_ref,
    });
    crate::canonical::canonical_sha256(&value)
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
    if value.get("schema").and_then(Value::as_str) == Some(arkret_sdk::PRINCIPAL_LOCATOR_SCHEMA) {
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
    let dids: Vec<&str> = tokens
        .iter()
        .copied()
        .filter(|token| arkret_sdk::Did::new((*token).to_owned()).is_ok())
        .collect();
    if dids.len() == 2 {
        let (subject, server) = if dids[1].contains(":users:") && !dids[0].contains(":users:") {
            (dids[1], dids[0])
        } else {
            (dids[0], dids[1])
        };
        return explicit_invitee_resolution(invite_address(subject, server)?, None).map(Some);
    }
    Ok(None)
}

fn resolved_handle_claim(
    resolved: &ResolveHandleView,
) -> anyhow::Result<Option<arkret_sdk::models::HandleClaim>> {
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
) -> anyhow::Result<Option<arkret_sdk::models::DeliveryBindingHint>> {
    Ok(resolved.member_delivery_binding_ref().cloned())
}

fn resolved_by_did(resolved: &ResolveHandleView) -> Option<arkret_sdk::Did> {
    resolved
        .via_services
        .iter()
        .find_map(|did| arkret_sdk::Did::new(did.clone()).ok())
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
    ) -> anyhow::Result<arkret_sdk::models::DirectoryAgentSelectorResolutionOutcome> {
        let controller_handle =
            arkret_sdk::models::Handle::parse(controller_handle).map_err(|err| {
                anyhow::anyhow!("invalid controller handle `{controller_handle}`: {err}")
            })?;
        arkret_sdk::models::validate_agent_slug(agent_slug)
            .map_err(|err| anyhow::anyhow!("invalid agent_slug `{agent_slug}`: {err}"))?;
        let requester = arkret_sdk::Did::new(requester.trim().to_owned())
            .map_err(|err| anyhow::anyhow!("invalid requester DID `{requester}`: {err}"))?;
        let realm_id = arkret_sdk::RealmId::new(realm_id.trim().to_owned())
            .map_err(|err| anyhow::anyhow!("invalid realm_id `{realm_id}`: {err}"))?;
        let body = arkret_sdk::models::DirectoryResolveAgentSelectorRequestBody {
            controller_handle,
            agent_slug: agent_slug.to_owned(),
            expected_agent_did: None,
            proof_challenge: None,
            intent: arkret_sdk::models::DirectoryIntent::Mention,
            realm_id: Some(realm_id),
            requester,
            proofs: Vec::new(),
        };
        let outcome: arkret_sdk::models::DirectoryAgentSelectorResolutionOutcome = self
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
        let handle = arkret_sdk::models::Handle::parse(&resolved.handle)
            .map_err(|err| anyhow::anyhow!("directory returned invalid handle: {err}"))?;
        let fallback_resolved_by = self
            .describe_cached()
            .await
            .ok()
            .map(|description| description.service_id.clone());
        let resolved_by = resolved_by_did(&resolved).or(fallback_resolved_by);
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
        recipient_service_id: Option<&str>,
    ) -> anyhow::Result<ContactRequestAddressing> {
        let target = target.trim();
        if target.is_empty() {
            anyhow::bail!("contact target is required");
        }
        if let Ok(handle) = canonical_invitee_handle(target) {
            let requester = crate::transport::account::account_me(&self.sdk_http_client()?)
                .await?
                .did;
            let resolved = self
                .resolve_handle_with_context(
                    &handle,
                    ResolveHandleContext {
                        intent: Some("contact_request"),
                        requester: Some(&requester),
                        audience: Some(&requester),
                        ..ResolveHandleContext::default()
                    },
                )
                .await?;
            let subject = resolved.subject_did().ok_or_else(|| {
                anyhow::anyhow!("directory resolve_handle response did not include subject DID")
            })?;
            let target_did = arkret_sdk::Did::new(subject.to_owned()).map_err(|err| {
                anyhow::anyhow!("directory resolved invalid DID `{subject}`: {err}")
            })?;
            let resolved_service = resolved_member_delivery_binding(&resolved)?
                .map(|binding| binding.recipient_service_id);
            let explicit_service = recipient_service_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    arkret_sdk::Did::new(value.to_owned()).map_err(|err| {
                        anyhow::anyhow!("invalid recipient_service_id `{value}`: {err}")
                    })
                })
                .transpose()?;
            let recipient_service_id = explicit_service.or(resolved_service);
            let handle = arkret_sdk::models::Handle::parse(&resolved.handle)
                .map_err(|err| anyhow::anyhow!("directory returned invalid handle: {err}"))?;
            let fallback_resolved_by = self
                .describe_cached()
                .await
                .ok()
                .map(|description| description.service_id.clone());
            let resolved_by = resolved_by_did(&resolved).or(fallback_resolved_by);
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
                recipient_service_id,
                introduction_evidence,
            });
        }
        let target_did = arkret_sdk::Did::new(target.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid contact target DID `{target}`: {err}"))?;
        let recipient_service_id = recipient_service_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                arkret_sdk::Did::new(value.to_owned())
                    .map_err(|err| anyhow::anyhow!("invalid recipient_service_id `{value}`: {err}"))
            })
            .transpose()?;
        Ok(ContactRequestAddressing {
            target: target_did,
            recipient_service_id,
            introduction_evidence: arkret_sdk::ContactIntroductionEvidence::ExplicitAddress,
        })
    }

    /// U3 — resolve the authoritative `recipient_service_id` for a contact DID
    /// through the Directory.
    ///
    /// The recipient principal-server DID MUST come from a directory-attested
    /// `resolve_handle` response (`member_delivery_binding.recipient_service_id`),
    /// never from a client-side `did:web:<domain>` fabrication: the latter both
    /// hard-codes the wrong default method (v1 core defaults to `did:webvh`) and
    /// bypasses the verified-claim reduction required by
    /// `identity-handles.md §80`.
    ///
    /// The handle materialised from the contact DID is used only as the resolve
    /// *query key*; the returned recipient service is taken from the verified
    /// binding. If the DID has no handle shape, or the directory does not return
    /// a binding, this fails closed so the caller falls back to the locator path.
    async fn contact_recipient_service_via_directory(
        &self,
        contact_did: &str,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<arkret_sdk::Did> {
        let handle = crate::views::helpers::handle_display_from_did(contact_did).ok_or_else(|| {
            anyhow::anyhow!(
                "cannot address contact `{contact_did}` by handle; use the invite link path instead"
            )
        })?;
        let resolved = self
            .resolve_handle_with_context(
                &handle,
                ResolveHandleContext {
                    intent: Some("invite"),
                    requester: Some(actor_id),
                    audience: Some(realm_id),
                    realm_id: Some(realm_id),
                    ..ResolveHandleContext::default()
                },
            )
            .await?;
        // Bind the verified subject back to the contact DID we were asked to
        // invite — never trust a resolve that names a different principal.
        let subject = resolved.subject_did().ok_or_else(|| {
            anyhow::anyhow!("directory resolve_handle response did not include subject DID")
        })?;
        if subject != contact_did {
            anyhow::bail!(
                "directory resolved handle `{handle}` to `{subject}`, not contact `{contact_did}`"
            );
        }
        resolved_member_delivery_binding(&resolved)?
            .map(|binding| binding.recipient_service_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "directory result for `{contact_did}` did not include a recipient service; use the invite link path instead"
                )
            })
    }

    /// U3 — pull an existing contact into a Realm using their DID directly,
    /// with `IntroductionEvidence::ConsentGrant` (no locator URL).
    ///
    /// `consent_grant_ref` is the event ref of the `invite`-scope consent the
    /// contact gave me (read from the contact row via
    /// [`crate::models::ContactListRow::invite_consent_ref`]). The delivery
    /// target is resolved through the Directory
    /// ([`Self::contact_recipient_service_via_directory`]); if it can't be
    /// resolved this fails closed so the UI can fall back to the locator path.
    ///
    /// Returns the submitted invite event id and invite id on success.
    pub async fn invite_contact_to_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        contact_did: &str,
        consent_grant_ref: &str,
    ) -> anyhow::Result<(String, String)> {
        let contact_did = contact_did.trim();
        arkret_sdk::Did::new(contact_did.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid contact DID `{contact_did}`: {err}"))?;
        let recipient_did = self
            .contact_recipient_service_via_directory(contact_did, realm_id, actor_id)
            .await?;
        let invite_delivery_target =
            arkret_sdk::InviteDeliveryTarget::principal_server(recipient_did);
        invite_delivery_target
            .validate()
            .map_err(|err| anyhow::anyhow!("invalid invite_delivery_target: {err}"))?;
        let introduction_evidence_digest = contact_consent_evidence_digest(consent_grant_ref)?;
        let invite_id = format!("ak:invite:{}", crate::operation::uuid_v7());
        let event = crate::operation::ak_ops::invite_create_structured(
            realm_id,
            actor_id,
            &invite_id,
            contact_did,
            None,
            invite_delivery_target,
            &introduction_evidence_digest,
        )?
        .build_sdk_event("inkson")?;
        let submitted = self.event_submitter()?.submit_sdk_event(&event).await?;
        Ok((submitted.event_id, invite_id))
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

    #[test]
    fn principal_locator_builds_locator_ref_evidence() {
        let locator = json!({
            "schema": arkret_sdk::PRINCIPAL_LOCATOR_SCHEMA,
            "subject_id": "did:web:bob.example",
            "recipient_service_id": "did:web:ps.bob.example",
            "issued_at": "2026-06-07T00:00:00Z",
            "expires_at": "2026-06-07T00:15:00Z",
            "locator_ref_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "proofs": [{
                "proof_purpose": "recipient_service_acceptance",
                "proof": {
                    "kind": "detached_jws",
                    "verification_method": "did:web:ps.bob.example#server-key-1",
                    "alg": "EdDSA",
                    "payload_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "created_at": "2026-06-07T00:00:00Z",
                    "jws": "header..sig"
                }
            }],
        });
        let locator = serde_json::from_value(locator).expect("typed principal locator");
        let invitee = invitee_from_principal_locator(locator).expect("principal locator");
        assert_eq!(invitee.did, "did:web:bob.example");
        assert_eq!(
            invitee.invite_delivery_target.recipient_service_id.as_str(),
            "did:web:ps.bob.example"
        );
        assert_eq!(invitee.introduction_evidence.kind(), "locator_ref");
    }

    #[test]
    fn invite_target_json_accepts_invite_address_as_explicit() {
        let raw_invite_address = json!({
            "subject_id": "did:web:bob.example",
            "recipient_service_id": "did:web:ps.bob.example",
        })
        .to_string();
        let invitee = invitee_from_target_json(&raw_invite_address)
            .expect("json target parsed")
            .expect("invite address target");
        assert_eq!(invitee.did, "did:web:bob.example");
        assert_eq!(invitee.introduction_evidence.kind(), "explicit_address");
    }

    #[test]
    fn explicit_invite_target_accepts_did_plus_server() {
        let invitee = parse_explicit_invite_target("did:web:bob.example did:web:ps.bob.example")
            .expect("explicit target parsed")
            .expect("did plus server target");
        assert_eq!(invitee.did, "did:web:bob.example");
        assert_eq!(
            invitee.invite_delivery_target.recipient_service_id.as_str(),
            "did:web:ps.bob.example"
        );
        assert_eq!(invitee.introduction_evidence.kind(), "explicit_address");
    }
}
