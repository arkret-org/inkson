use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct InviteeResolution {
    pub did: String,
    pub handle: Option<String>,
    pub invite_delivery_target: cokret_sdk::InviteDeliveryTarget,
    pub introduction_evidence: cokret_sdk::IntroductionEvidence,
    pub introduction_evidence_digest: String,
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

/// U3 — derive the `recipient_service_did` (principal-server delivery target)
/// for a contact DID so the realm-invite "from contacts" path can build an
/// `InviteDeliveryTarget` without a locator URL.
///
/// For materialized user handles (`did:web:<domain>:users:<localpart>` /
/// `did:webvh:<scid>:<domain>:users:<localpart>`) the hosting principal server
/// is `did:web:<domain>`, which is what `parse_user_handle` already computes.
/// For other DID shapes we cannot infer the server, so this returns `None` and
/// the caller surfaces "暂不可用" for that contact.
fn contact_recipient_service_did(contact_did: &str) -> Option<String> {
    let display = crate::views::helpers::handle_display_from_did(contact_did)?;
    crate::identity_handle::parse_user_handle(&display).map(|handle| handle.principal_server_did)
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
    anyhow::bail!("invite target JSON must be a principal locator")
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

fn reject_legacy_invite_target(target: &str) -> anyhow::Result<()> {
    if cokret_sdk::Did::new(target.to_owned()).is_ok() {
        anyhow::bail!("raw DID is not an invite target; paste an invite locator URL");
    }
    if canonical_invitee_handle(target).is_ok() {
        anyhow::bail!(
            "handle lookup is not used for invites; paste the recipient's invite locator URL"
        );
    }
    Ok(())
}

impl CokretApi {
    pub async fn search_realms(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchRealmsOutcome> {
        if let Some(token) = next_cursor {
            validate_cursor(token)?;
        }
        let body = cokret_sdk::model::DirectorySearchRealmsRequestBody {
            query: Some(query.to_owned()),
            organization_did: None,
            parent_space_id: None,
            requester: None,
            proofs: Vec::new(),
            cursor: next_cursor.map(ToOwned::to_owned),
            limit: Some(20),
        };
        self.post_json(
            "_cokret/find/directory/search-realms",
            serde_json::to_value(&body)?,
        )
        .await
    }

    pub async fn directory_describe(&self) -> anyhow::Result<SolandDirectoryDescribeResBody> {
        self.get_json("_cokret/find/directory/describe").await
    }

    pub async fn resolve_realm(&self, realm_id: &str) -> anyhow::Result<ResolveRealmOutcome> {
        let realm = cokret_sdk::RealmId::new(realm_id)
            .map_err(|err| anyhow::anyhow!("invalid realm_id `{realm_id}`: {err}"))?;
        let body = cokret_sdk::model::DirectoryResolveRealmRequestBody {
            realm_id: Some(realm),
            alias: None,
            invite_token: None,
            signed_link: None,
            requester: None,
            proofs: Vec::new(),
        };
        self.post_json(
            "_cokret/find/directory/resolve-realm",
            serde_json::to_value(&body)?,
        )
        .await
    }

    /// R3.3 (CKP-0011) — resolve a shareable object address (Realm / Flow /
    /// Message) to a directory preview via `ck.find.directory.resolve_target`
    /// (`POST /_cokret/find/directory/resolve-target`).
    ///
    /// `address` is the canonical `web+cokret:` (or HTTPS-fragment) string
    /// derived from [`cokret_sdk::model::parse_address`]; `token` is present
    /// iff the address carried `lt=invite` or `lt=preview`. The server binds
    /// an invite or preview token to the resolved object via the SDK's
    /// [`cokret_sdk::model::verify_token_target`]; the client only forwards
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
    ) -> anyhow::Result<cokret_sdk::model::DirectoryTargetResolutionOutcome> {
        let body = cokret_sdk::model::DirectoryResolveTargetRequestBody {
            address: address.to_owned(),
            requester: None,
            proofs: Vec::new(),
            token: token.map(str::to_owned),
        };
        self.post_json(
            "_cokret/find/directory/resolve-target",
            serde_json::to_value(&body)?,
        )
        .await
    }

    /// `ck.self.snapshot.head`. Spec resolution (2026-06-11,
    /// `renames.json` migration group `snapshot_head_returns_manifest`):
    /// the response is the full signed `ck.schema.snapshot.v1` manifest
    /// (`service-surface.md` §5.2); the legacy `SnapshotHeadState` pointer
    /// DTO is hard-rejected on current wire. The manifest is returned as
    /// raw JSON until the SDK grows a typed wire manifest. soland
    /// currently does not declare this operation and fails closed with
    /// `not_implemented`.
    pub async fn snapshot_head(&self, realm_id: &str) -> anyhow::Result<Value> {
        self.get_json(&format!("_cokret/self/snapshot/head?realm_id={realm_id}"))
            .await
    }

    // ── Identity & Directory ────────────────────────────────────────

    pub async fn search_organizations(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchOrganizationsOutcome> {
        if let Some(token) = next_cursor {
            validate_cursor(token)?;
        }
        let body = cokret_sdk::model::DirectorySearchOrganizationsRequestBody {
            query: Some(query.to_owned()),
            claims: Value::Null,
            cursor: next_cursor.map(ToOwned::to_owned),
            limit: Some(20),
        };
        self.post_json(
            "_cokret/find/directory/search-organizations",
            serde_json::to_value(&body)?,
        )
        .await
    }

    pub async fn search_actors(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchActorsOutcome> {
        if let Some(token) = next_cursor {
            validate_cursor(token)?;
        }
        let body = cokret_sdk::model::DirectorySearchActorsRequestBody {
            query: Some(query.to_owned()),
            realm_id: None,
            organization_did: None,
            cursor: next_cursor.map(ToOwned::to_owned),
            limit: Some(20),
        };
        self.post_json(
            "_cokret/find/directory/search-actors",
            serde_json::to_value(&body)?,
        )
        .await
    }

    /// A6.1 — global cross-Realm message search backed by soland's
    /// `POST /_soland/self/index/search`. The server accepts `realm_ids` to
    /// scope the search; pass an empty slice for "search everywhere I
    /// have access to". `object_kinds` defaults to `["message"]` when
    /// `None`, mirroring the panel's primary affordance.
    ///
    /// Note: soland's current index is best-effort substring search
    /// over the in-memory projection; encrypted messages are skipped
    /// server-side. Cross-space coverage will improve as the durable
    /// projection lands (see `_claude_todos.md` D-lane).
    pub async fn index_search(
        &self,
        query: &str,
        realm_ids: &[String],
        object_kinds: Option<&[&str]>,
        limit: u32,
    ) -> anyhow::Result<IndexSearchOutcome> {
        let kinds: Vec<&str> = object_kinds
            .map(|k| k.to_vec())
            .unwrap_or_else(|| vec!["message"]);
        let body = json!({
            "query": query,
            "limit": limit,
            "object_kinds": kinds,
            "realm_ids": realm_ids,
        });
        self.post_json("_soland/self/index/search", body).await
    }

    pub async fn resolve_handle(&self, handle: &str) -> anyhow::Result<ResolveHandleOutcome> {
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
    ) -> anyhow::Result<ResolveHandleOutcome> {
        self.post_json(
            "_cokret/find/directory/resolve-handle",
            resolve_handle_request_body(handle, context)?,
        )
        .await
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

    /// U3 — pull an existing contact into a Realm using their DID directly,
    /// with `IntroductionEvidence::ConsentGrant` (no locator URL).
    ///
    /// `consent_grant_ref` is the event ref of the `invite`-scope consent the
    /// contact gave me (read from the contact row via
    /// [`crate::models::ContactListRow::invite_consent_ref`]). The delivery
    /// target is derived from the contact DID via
    /// [`contact_recipient_service_did`]; if it can't be derived this fails
    /// closed so the UI can fall back to the locator path.
    ///
    /// Returns the submitted invite event id on success.
    pub async fn invite_contact_to_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        contact_did: &str,
        consent_grant_ref: &str,
    ) -> anyhow::Result<String> {
        let contact_did = contact_did.trim();
        cokret_sdk::Did::new(contact_did.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid contact DID `{contact_did}`: {err}"))?;
        let recipient_service_did = contact_recipient_service_did(contact_did).ok_or_else(|| {
            anyhow::anyhow!(
                "cannot derive principal server for contact `{contact_did}`; use the invite link path instead"
            )
        })?;
        let recipient_did = cokret_sdk::Did::new(recipient_service_did)
            .map_err(|err| anyhow::anyhow!("invalid recipient service DID: {err}"))?;
        let invite_delivery_target =
            cokret_sdk::InviteDeliveryTarget::principal_server(recipient_did);
        invite_delivery_target
            .validate()
            .map_err(|err| anyhow::anyhow!("invalid invite_delivery_target: {err}"))?;
        let introduction_evidence_digest = contact_consent_evidence_digest(consent_grant_ref)?;
        let invite_id = format!("ck:invite:{}", crate::operation::uuid_v7());
        let op = crate::operation::ck_ops::invite_create_structured(
            realm_id,
            actor_id,
            &invite_id,
            contact_did,
            None,
            invite_delivery_target,
            &introduction_evidence_digest,
        )?
        .build("yougen");
        let submitted = self.submit_event_envelope(&op).await?;
        Ok(submitted.event_id)
    }

    pub async fn resolve_invitee_for_invite(
        &self,
        target: &str,
        _realm_id: &str,
        _actor_id: &str,
    ) -> anyhow::Result<InviteeResolution> {
        let target = target.trim();
        if target.is_empty() {
            anyhow::bail!("invite locator is required");
        }
        if let Some(invitee) = invitee_from_target_json(target)? {
            return Ok(invitee);
        }
        if let Some((resolver_origin, locator_token)) = parse_invite_locator_url(target)? {
            let resolver = CokretApi::new(&resolver_origin)?;
            let body = cokret_sdk::InviteLocatorResolveRequestBody::new(locator_token);
            body.validate_minimal()
                .map_err(|err| anyhow::anyhow!("invalid invite locator token: {err}"))?;
            let locator: cokret_sdk::PrincipalLocator = resolver
                .post_json(
                    cokret_sdk::INVITE_LOCATOR_RESOLVE_PATH,
                    serde_json::to_value(&body)?,
                )
                .await?;
            return invitee_from_principal_locator(locator);
        }

        reject_legacy_invite_target(target)?;
        anyhow::bail!("invite target must be an invite locator URL or principal locator JSON")
    }

    /// R3.2 (cokret-spec @ b56cab1) — `ck.find.directory.list_handles_for_subject`.
    ///
    /// Inverse of [`Self::resolve_handle`]: given a known holder/principal
    /// DID, return the current context-visible signed handle claims +
    /// the §3.2.1 primary handle. Powers the "Why am I seeing this
    /// handle?" panel (YG-DIR-1/2) and the own-handles list (YG-HC-2).
    ///
    /// The response is validated with
    /// [`cokret_sdk::model::DirectorySubjectHandleList::validate`]
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
    ) -> anyhow::Result<cokret_sdk::model::DirectorySubjectHandleList> {
        use cokret_sdk::model::DirectoryListHandlesForSubjectRequestBody;

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
        let res: cokret_sdk::model::DirectorySubjectHandleList = self
            .post_json(
                "_cokret/find/directory/list-handles-for-subject",
                serde_json::to_value(&body)?,
            )
            .await?;
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
    fn invite_target_json_rejects_raw_invite_address() {
        let raw_invite_address = json!({
            "subject_id": "did:web:bob.example",
            "recipient_service_did": "did:web:ps.bob.example",
        })
        .to_string();
        let err = invitee_from_target_json(&raw_invite_address)
            .expect_err("raw invite_address JSON must be rejected");
        assert!(err.to_string().contains("principal locator"));
    }

    #[test]
    fn invite_target_rejects_raw_did_and_handle() {
        let did_err = reject_legacy_invite_target("did:web:bob.example")
            .expect_err("raw DID is no longer an invite target");
        assert!(did_err.to_string().contains("raw DID"));

        let handle_err = reject_legacy_invite_target("bob:example.com")
            .expect_err("handle must not drive invite delivery");
        assert!(handle_err.to_string().contains("handle lookup"));
    }
}
