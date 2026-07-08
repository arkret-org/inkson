use super::*;
use crate::models::ServerDescriptionExt;

#[derive(Clone, Debug, PartialEq)]
pub struct InviteeResolution {
    pub did: String,
    pub handle: Option<String>,
    pub invite_delivery_target: cokret_sdk::InviteDeliveryTarget,
    pub introduction_evidence: cokret_sdk::IntroductionEvidence,
    pub introduction_evidence_digest: String,
}

pub(crate) struct ContactRequestAddressing {
    pub(crate) target: cokret_sdk::Did,
    pub(crate) recipient_service_did: Option<cokret_sdk::Did>,
    pub(crate) introduction_evidence: cokret_sdk::ContactIntroductionEvidence,
}

fn invitee_resolution(
    invite_address: cokret_sdk::InviteAddress,
    handle: Option<String>,
    introduction_evidence: cokret_sdk::IntroductionEvidence,
) -> anyhow::Result<InviteeResolution> {
    invite_address
        .validate()
        .map_err(|err| anyhow::anyhow!("invalid invite_address: {err}"))?;
    let did = invite_address.subject_id.to_string();
    let invite_delivery_target =
        cokret_sdk::InviteDeliveryTarget::from_invite_address(&invite_address);
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
    invite_address: cokret_sdk::InviteAddress,
    handle: Option<String>,
) -> anyhow::Result<InviteeResolution> {
    invitee_resolution(
        invite_address,
        handle,
        cokret_sdk::IntroductionEvidence::ExplicitAddress,
    )
}

fn invite_address(
    subject_id: &str,
    recipient_service_did: &str,
) -> anyhow::Result<cokret_sdk::InviteAddress> {
    let subject = cokret_sdk::Did::new(subject_id.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid invite subject DID `{subject_id}`: {err}"))?;
    let recipient_service =
        cokret_sdk::Did::new(recipient_service_did.trim().to_owned()).map_err(|err| {
            anyhow::anyhow!("invalid invite recipient service DID `{recipient_service_did}`: {err}")
        })?;
    Ok(cokret_sdk::InviteAddress::principal_server(
        subject,
        recipient_service,
    ))
}

/// U3 — build the `consent_grant` introduction evidence for a contact-path
/// invite and return its canonical digest (the value
/// `ck_ops::invite_create_structured` stamps into the invite event).
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
    locator: cokret_sdk::PrincipalLocator,
) -> anyhow::Result<InviteeResolution> {
    locator
        .validate_minimal()
        .map_err(|err| anyhow::anyhow!("principal locator validation failed: {err}"))?;
    let address = locator.invite_address();
    invitee_resolution(
        address,
        None,
        cokret_sdk::IntroductionEvidence::LocatorRef {
            principal_locator: locator,
        },
    )
}

fn invitee_from_target_json(target: &str) -> anyhow::Result<Option<InviteeResolution>> {
    let value = match serde_json::from_str::<Value>(target) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if value.get("schema").and_then(Value::as_str) == Some(cokret_sdk::PRINCIPAL_LOCATOR_SCHEMA) {
        let locator: cokret_sdk::PrincipalLocator = serde_json::from_value(value)?;
        return invitee_from_principal_locator(locator).map(Some);
    }
    if value.get("subject_id").is_some() && value.get("recipient_service_did").is_some() {
        let address: cokret_sdk::InviteAddress = serde_json::from_value(value)?;
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
    if url.path() != "/_cokret/open/invite-locators/resolve" {
        anyhow::bail!("invite locator URL path must be /_cokret/open/invite-locators/resolve");
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
            token_value(token, &["server", "service", "recipient_service_did"])
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
        .filter(|token| cokret_sdk::Did::new((*token).to_owned()).is_ok())
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
) -> anyhow::Result<Option<cokret_sdk::models::HandleClaim>> {
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
) -> anyhow::Result<Option<cokret_sdk::models::DeliveryBindingHint>> {
    Ok(resolved.member_delivery_binding_ref().cloned())
}

fn resolved_by_did(resolved: &ResolveHandleView) -> Option<cokret_sdk::Did> {
    resolved
        .via_services
        .iter()
        .find_map(|did| cokret_sdk::Did::new(did.clone()).ok())
}

fn resolved_at(resolved: &ResolveHandleView) -> Option<chrono::DateTime<chrono::Utc>> {
    resolved
        .as_of
        .as_deref()
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|ts| ts.with_timezone(&chrono::Utc))
}

impl CokretApi {
    pub async fn search_realms(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::models::DirectoryRealmSearchOutcome> {
        if let Some(token) = next_cursor {
            validate_cursor(token)?;
        }
        let body = cokret_sdk::models::DirectorySearchRealmsRequestBody {
            query: Some(query.to_owned()),
            organization_did: None,
            source_realm_id: None,
            requester: None,
            proof_challenge: None,
            claim_presentations: Vec::new(),
            cursor: next_cursor.map(ToOwned::to_owned),
            limit: Some(20),
        };
        self.sdk_http_client()?
            .directory_search_realms(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn directory_describe(&self) -> anyhow::Result<DirectoryDescription> {
        self.sdk_http_client()?
            .directory_describe()
            .await
            .map_err(anyhow::Error::from)
    }

    /// Resolve a Realm by either its `ck:realm:<uuid>` id OR a human-readable
    /// realm alias (`engineering`, `engineering:acme.example`, `#engineering…`).
    ///
    /// The input is classified: a valid [`cokret_sdk::RealmId`] is sent as
    /// `realm_id`; otherwise it is treated as an alias — the `#` share sigil is
    /// stripped and the bare localpart / canonical form is sent as `alias`,
    /// which soland binds to its deployment authority domain and validates
    /// (object-addressing.md §3.3). The client need not know the deployment
    /// domain to look up by a bare localpart.
    pub async fn resolve_realm(
        &self,
        realm_id_or_alias: &str,
    ) -> anyhow::Result<ResolveRealmOutcome> {
        let input = realm_id_or_alias.trim();
        let (realm_id, alias) = match cokret_sdk::RealmId::new(input) {
            Ok(realm) => (Some(realm), None),
            Err(_) => {
                let alias = input.trim_start_matches('#').trim();
                if alias.is_empty() {
                    return Err(anyhow::anyhow!("empty realm id / alias"));
                }
                (None, Some(alias.to_owned()))
            }
        };
        let body = cokret_sdk::models::DirectoryResolveRealmRequestBody {
            realm_id,
            alias,
            invite_token: None,
            signed_link: None,
            requester: None,
            proof_challenge: None,
            claim_presentations: Vec::new(),
        };
        self.sdk_http_client()?
            .directory_resolve_realm(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// R3.3 (CKP-0011) — resolve a shareable object address (Realm / Strand /
    /// Message) to a directory preview via `ck.find.directory.query.resolve_target`
    /// (`POST /_cokret/find/directory/resolve-target`).
    ///
    /// `address` is the canonical `web+cokret:` (or HTTPS-fragment) string
    /// derived from [`cokret_sdk::models::parse_address`]; `token` is present
    /// iff the address carried `lt=invite` or `lt=preview`. The server binds
    /// an invite or preview token to the resolved object via the SDK's
    /// [`cokret_sdk::models::verify_token_target`]; the client only forwards
    /// the opaque token here.
    ///
    /// Wraps the SDK's typed request/response bodies so the wire shape stays
    /// in sync with `spec/v1` (mirrors how [`Self::resolve_realm`] wraps the
    /// `resolve-realm` endpoint). On any failure the caller MUST collapse the
    /// error to a single "link unavailable" message — `not_found` and
    /// `unauthorized` are intentionally indistinguishable (anti-enumeration).
    pub async fn directory_resolve_target(
        &self,
        address: &str,
        token: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::models::DirectoryTargetResolutionOutcome> {
        let body = cokret_sdk::models::DirectoryResolveTargetRequestBody {
            address: address.to_owned(),
            requester: None,
            proof_challenge: None,
            claim_presentations: Vec::new(),
            proofs: Vec::new(),
            token: token.map(str::to_owned),
        };
        self.sdk_http_client()?
            .directory_resolve_target(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// `ck.self.snapshot.query.manifest_head`.
    ///
    /// Snapshot bootstrap is an acceleration layer. If the server does not
    /// advertise or serve the operation, callers silently fall back to event
    /// replay.
    pub async fn snapshot_head(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<cokret_sdk::SnapshotManifest>> {
        let describe = self.describe_cached().await?;
        if !describe.supports_operation(OP_SNAPSHOT_HEAD) {
            return Ok(None);
        }
        let result = self.sdk_http_client()?.snapshot_head(realm_id).await;
        let result = result.map_err(anyhow::Error::from);
        match result {
            Ok(manifest) => Ok(Some(manifest)),
            Err(error) if is_snapshot_unavailable_error(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    // ── Identity & Directory ────────────────────────────────────────

    pub async fn search_organizations(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchOrganizationsView> {
        if let Some(token) = next_cursor {
            validate_cursor(token)?;
        }
        let body = cokret_sdk::models::DirectorySearchOrganizationsRequestBody {
            query: Some(query.to_owned()),
            claims: Value::Null,
            cursor: next_cursor.map(ToOwned::to_owned),
            limit: Some(20),
        };
        self.sdk_http_client()?
            .directory_search_organizations(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn search_actors(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchActorsView> {
        if let Some(token) = next_cursor {
            validate_cursor(token)?;
        }
        let body = cokret_sdk::models::DirectorySearchActorsRequestBody {
            query: Some(query.to_owned()),
            realm_id: None,
            organization_did: None,
            cursor: next_cursor.map(ToOwned::to_owned),
            limit: Some(20),
        };
        self.sdk_http_client()?
            .directory_search_actors(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Global index search has no spec-defined Cokret HTTP endpoint.
    pub async fn index_search(
        &self,
        query: &str,
        realm_ids: &[String],
        object_kinds: Option<&[&str]>,
        limit: u32,
    ) -> anyhow::Result<IndexSearchView> {
        let _ = (query, realm_ids, object_kinds, limit);
        anyhow::bail!("index_search has no spec-defined Cokret HTTP endpoint")
    }

    pub async fn resolve_handle(&self, handle: &str) -> anyhow::Result<ResolveHandleView> {
        self.resolve_handle_with_context(
            handle,
            ResolveHandleContext {
                intent: Some("lookup"),
                ..ResolveHandleContext::default()
            },
        )
        .await
    }

    pub async fn resolve_handle_with_context(
        &self,
        handle: &str,
        context: ResolveHandleContext<'_>,
    ) -> anyhow::Result<ResolveHandleView> {
        let body = resolve_handle_request_body(handle, context)?;
        let outcome: cokret_sdk::DirectoryHandleResolutionOutcome = self
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
    ) -> anyhow::Result<cokret_sdk::models::DirectoryAgentSelectorResolutionOutcome> {
        let controller_handle =
            cokret_sdk::models::Handle::parse(controller_handle).map_err(|err| {
                anyhow::anyhow!("invalid controller handle `{controller_handle}`: {err}")
            })?;
        cokret_sdk::models::validate_agent_slug(agent_slug)
            .map_err(|err| anyhow::anyhow!("invalid agent_slug `{agent_slug}`: {err}"))?;
        let requester = cokret_sdk::Did::new(requester.trim().to_owned())
            .map_err(|err| anyhow::anyhow!("invalid requester DID `{requester}`: {err}"))?;
        let realm_id = cokret_sdk::RealmId::new(realm_id.trim().to_owned())
            .map_err(|err| anyhow::anyhow!("invalid realm_id `{realm_id}`: {err}"))?;
        let body = cokret_sdk::models::DirectoryResolveAgentSelectorRequestBody {
            controller_handle,
            agent_slug: agent_slug.to_owned(),
            expected_agent_did: None,
            proof_challenge: None,
            intent: cokret_sdk::models::DirectoryIntent::Mention,
            realm_id: Some(realm_id),
            requester,
            proofs: Vec::new(),
        };
        let outcome: cokret_sdk::models::DirectoryAgentSelectorResolutionOutcome = self
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
            .map(|binding| binding.recipient_service_did)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "directory handle result did not include a recipient service; use DID + server"
                )
            })?;
        let address = invite_address(subject, recipient_service.as_str())?;
        let handle = cokret_sdk::models::Handle::parse(&resolved.handle)
            .map_err(|err| anyhow::anyhow!("directory returned invalid handle: {err}"))?;
        let fallback_resolved_by = self
            .describe_cached()
            .await
            .ok()
            .map(|description| description.service_did.clone());
        let resolved_by = resolved_by_did(&resolved).or(fallback_resolved_by);
        let evidence = match resolved_handle_claim(&resolved)? {
            Some(handle_claim) => cokret_sdk::IntroductionEvidence::HandleClaim {
                handle: handle.clone(),
                handle_claim: Box::new(handle_claim),
                member_delivery_binding_candidate: None,
                resolved_by,
                resolved_at: resolved_at(&resolved),
            },
            None => cokret_sdk::IntroductionEvidence::ExplicitAddress,
        };
        invitee_resolution(address, Some(handle.canonical().to_owned()), evidence)
    }

    pub(crate) async fn contact_request_addressing(
        &self,
        target: &str,
        recipient_service_did: Option<&str>,
    ) -> anyhow::Result<ContactRequestAddressing> {
        let target = target.trim();
        if target.is_empty() {
            anyhow::bail!("contact target is required");
        }
        if let Ok(handle) = canonical_invitee_handle(target) {
            let requester = self.account_me().await?.did;
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
            let target_did = cokret_sdk::Did::new(subject.to_owned()).map_err(|err| {
                anyhow::anyhow!("directory resolved invalid DID `{subject}`: {err}")
            })?;
            let resolved_service = resolved_member_delivery_binding(&resolved)?
                .map(|binding| binding.recipient_service_did);
            let explicit_service = recipient_service_did
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    cokret_sdk::Did::new(value.to_owned()).map_err(|err| {
                        anyhow::anyhow!("invalid recipient_service_did `{value}`: {err}")
                    })
                })
                .transpose()?;
            let recipient_service_did = explicit_service.or(resolved_service);
            let handle = cokret_sdk::models::Handle::parse(&resolved.handle)
                .map_err(|err| anyhow::anyhow!("directory returned invalid handle: {err}"))?;
            let fallback_resolved_by = self
                .describe_cached()
                .await
                .ok()
                .map(|description| description.service_did.clone());
            let resolved_by = resolved_by_did(&resolved).or(fallback_resolved_by);
            let introduction_evidence = match resolved_handle_claim(&resolved)? {
                Some(handle_claim) => cokret_sdk::ContactIntroductionEvidence::HandleClaim {
                    handle,
                    handle_claim: Box::new(handle_claim),
                    resolved_by,
                    resolved_at: resolved_at(&resolved),
                },
                None => cokret_sdk::ContactIntroductionEvidence::ExplicitAddress,
            };
            return Ok(ContactRequestAddressing {
                target: target_did,
                recipient_service_did,
                introduction_evidence,
            });
        }
        let target_did = cokret_sdk::Did::new(target.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid contact target DID `{target}`: {err}"))?;
        let recipient_service_did = recipient_service_did
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                cokret_sdk::Did::new(value.to_owned()).map_err(|err| {
                    anyhow::anyhow!("invalid recipient_service_did `{value}`: {err}")
                })
            })
            .transpose()?;
        Ok(ContactRequestAddressing {
            target: target_did,
            recipient_service_did,
            introduction_evidence: cokret_sdk::ContactIntroductionEvidence::ExplicitAddress,
        })
    }

    pub async fn resolve_invitee_did(&self, target: &str) -> anyhow::Result<String> {
        let target = target.trim();
        if target.is_empty() {
            anyhow::bail!("invitee is required");
        }
        if cokret_sdk::Did::new(target.to_owned()).is_ok() {
            return Ok(target.to_owned());
        }
        let handle = canonical_invitee_handle(target)?;
        let resolved = self.resolve_handle(&handle).await?;
        let subject = resolved.subject_did().ok_or_else(|| {
            anyhow::anyhow!("directory resolve_handle response did not include subject DID")
        })?;
        cokret_sdk::Did::new(subject.to_owned())
            .map_err(|err| anyhow::anyhow!("directory resolved invalid DID `{subject}`: {err}"))?;
        Ok(subject.to_owned())
    }

    pub async fn resolve_invitee_did_for_invite(
        &self,
        target: &str,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<String> {
        Ok(self
            .resolve_invitee_for_invite(target, realm_id, actor_id)
            .await?
            .did)
    }

    /// U3 — resolve the authoritative `recipient_service_did` for a contact DID
    /// through the Directory.
    ///
    /// The recipient principal-server DID MUST come from a directory-attested
    /// `resolve_handle` response (`member_delivery_binding.recipient_service_did`),
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
    ) -> anyhow::Result<cokret_sdk::Did> {
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
            .map(|binding| binding.recipient_service_did)
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
        cokret_sdk::Did::new(contact_did.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid contact DID `{contact_did}`: {err}"))?;
        let recipient_did = self
            .contact_recipient_service_via_directory(contact_did, realm_id, actor_id)
            .await?;
        let invite_delivery_target =
            cokret_sdk::InviteDeliveryTarget::principal_server(recipient_did);
        invite_delivery_target
            .validate()
            .map_err(|err| anyhow::anyhow!("invalid invite_delivery_target: {err}"))?;
        let introduction_evidence_digest = contact_consent_evidence_digest(consent_grant_ref)?;
        let invite_id = format!("ck:invite:{}", crate::operation::uuid_v7());
        let event = crate::operation::ck_ops::invite_create_structured(
            realm_id,
            actor_id,
            &invite_id,
            contact_did,
            None,
            invite_delivery_target,
            &introduction_evidence_digest,
        )?
        .build_sdk_event("yougen")?;
        let submitted = self.submit_sdk_event(&event).await?;
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
            let resolver = cokret_sdk::http_client::Client::new(Url::parse(&resolver_origin)?)?;
            let body = cokret_sdk::InviteLocatorResolveRequestBody::new(locator_token);
            body.validate_minimal()
                .map_err(|err| anyhow::anyhow!("invalid invite locator token: {err}"))?;
            let locator: cokret_sdk::PrincipalLocator = resolver
                .post(cokret_sdk::INVITE_LOCATOR_RESOLVE_PATH, &body)
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
        if cokret_sdk::Did::new(target.to_owned()).is_ok() {
            anyhow::bail!("raw DID invite target also needs a recipient server DID");
        }
        anyhow::bail!(
            "invite target must be a locator, handle, principal locator JSON, or DID + server"
        )
    }

    /// R3.2 (cokret-spec @ b56cab1) — `ck.find.directory.query.list_handles_for_subject`.
    ///
    /// Inverse of [`Self::resolve_handle`]: given a known holder/principal
    /// DID, return the current context-visible signed handle claims +
    /// the §3.2.1 primary handle. Powers the "Why am I seeing this
    /// handle?" panel (YG-DIR-1/2) and the own-handles list (YG-HC-2).
    ///
    /// The response is validated with
    /// [`cokret_sdk::models::DirectorySubjectHandleList::validate`]
    /// which fails closed unless every `claims[].subject` byte-equals the
    /// response `subject`.
    ///
    /// `realm_id` / `intent` scope the disclosure policy; pass `None` for
    /// an unscoped lookup. `TODO(R3.2.1)`: thread `requester` /
    /// `proof_challenge` / `proofs` for proof-gated disclosure.
    pub async fn list_handles_for_subject(
        &self,
        subject: &str,
        realm_id: Option<&str>,
        intent: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::models::DirectorySubjectHandleList> {
        use cokret_sdk::models::DirectoryListHandlesForSubjectRequestBody;

        let subject_did = cokret_sdk::Did::new(subject.trim().to_owned())
            .map_err(|err| anyhow::anyhow!("invalid subject DID `{subject}`: {err}"))?;
        let realm = match realm_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(r) => Some(
                cokret_sdk::RealmId::new(r)
                    .map_err(|err| anyhow::anyhow!("invalid realm_id `{r}`: {err}"))?,
            ),
            None => None,
        };
        let body = DirectoryListHandlesForSubjectRequestBody {
            subject: subject_did,
            realm_id: realm,
            intent: intent
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned),
            requester: None,
            proof_challenge: None,
            proofs: Vec::new(),
            as_of: None,
            cursor: None,
            limit: None,
        };
        let res: cokret_sdk::models::DirectorySubjectHandleList = self
            .sdk_http_client()?
            .directory_list_handles_for_subject(&body)
            .await
            .map_err(anyhow::Error::from)?;
        // §0.2 fail-closed: drop the whole response if any claim's subject
        // doesn't match.
        res.validate()
            .map_err(|err| anyhow::anyhow!("list_handles_for_subject validation failed: {err}"))?;
        Ok(res)
    }
}

#[cfg(test)]
mod invite_addressing_tests {
    use super::*;

    #[test]
    fn locator_url_reads_token_from_fragment() {
        let (origin, token) = parse_invite_locator_url(
            "https://ps.bob.example:9443/_cokret/open/invite-locators/resolve#token=abc%20123",
        )
        .expect("valid locator url")
        .expect("locator url parsed");
        assert_eq!(origin, "https://ps.bob.example:9443");
        assert_eq!(token, "abc 123");
    }

    #[test]
    fn locator_url_rejects_query_token() {
        let err = parse_invite_locator_url(
            "https://ps.bob.example/_cokret/open/invite-locators/resolve?locator_token=abc",
        )
        .expect_err("query token must be rejected");
        assert!(err.to_string().contains("fragment"));
    }

    #[test]
    fn principal_locator_builds_locator_ref_evidence() {
        let locator = json!({
            "schema": cokret_sdk::PRINCIPAL_LOCATOR_SCHEMA,
            "subject_id": "did:web:bob.example",
            "recipient_service_did": "did:web:ps.bob.example",
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
            invitee
                .invite_delivery_target
                .recipient_service_did
                .as_str(),
            "did:web:ps.bob.example"
        );
        assert_eq!(invitee.introduction_evidence.kind(), "locator_ref");
    }

    #[test]
    fn invite_target_json_accepts_invite_address_as_explicit() {
        let raw_invite_address = json!({
            "subject_id": "did:web:bob.example",
            "recipient_service_did": "did:web:ps.bob.example",
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
            invitee
                .invite_delivery_target
                .recipient_service_did
                .as_str(),
            "did:web:ps.bob.example"
        );
        assert_eq!(invitee.introduction_evidence.kind(), "explicit_address");
    }
}
