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

fn invitee_from_invite_address(
    address: cokret_sdk::InviteAddress,
) -> anyhow::Result<InviteeResolution> {
    invitee_resolution(
        address,
        None,
        cokret_sdk::IntroductionEvidence::ExplicitAddress,
    )
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
        return invitee_from_invite_address(address).map(Some);
    }
    anyhow::bail!("invite target JSON must be a principal locator or invite_address")
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
        anyhow::bail!(
            "raw DID is not an invite target; paste an invite locator URL or invite_address JSON"
        );
    }
    if canonical_invitee_handle(target).is_ok() {
        anyhow::bail!(
            "handle lookup is not used for invites; paste the recipient's invite locator URL or invite_address JSON"
        );
    }
    Ok(())
}

impl CokretApi {
    pub async fn search_realms(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchRealmsResponse> {
        if let Some(token) = next_cursor {
            validate_cursor(token)?;
        }
        let mut body = json!({"query": query, "limit": 20});
        if let Some(cursor) = next_cursor {
            body["next_cursor"] = json!(cursor);
        }
        self.post_json("_cokret/find/directory/search-realms", body)
            .await
    }

    pub async fn directory_describe(&self) -> anyhow::Result<SolandDirectoryDescribeResBody> {
        self.get_json("_cokret/find/directory/describe").await
    }

    pub async fn resolve_realm(&self, realm_id: &str) -> anyhow::Result<ResolveRealmResponse> {
        self.post_json(
            "_cokret/find/directory/resolve-realm",
            json!({"realm_id": realm_id}),
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

    pub async fn snapshot_head(&self, realm_id: &str) -> anyhow::Result<SnapshotHeadState> {
        self.get_json(&format!("_cokret/self/snapshot/head?realm_id={realm_id}"))
            .await
    }

    // ── Identity & Directory ────────────────────────────────────────

    pub async fn search_organizations(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchOrganizationsResponse> {
        if let Some(token) = next_cursor {
            validate_cursor(token)?;
        }
        let mut body = json!({"query": query, "limit": 20});
        if let Some(cursor) = next_cursor {
            body["next_cursor"] = json!(cursor);
        }
        self.post_json("_cokret/find/directory/search-organizations", body)
            .await
    }

    pub async fn search_actors(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchActorsResponse> {
        if let Some(token) = next_cursor {
            validate_cursor(token)?;
        }
        let mut body = json!({"query": query, "limit": 20});
        if let Some(cursor) = next_cursor {
            body["next_cursor"] = json!(cursor);
        }
        self.post_json("_cokret/find/directory/search-actors", body)
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
    ) -> anyhow::Result<IndexSearchResponse> {
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

    pub async fn resolve_handle(&self, handle: &str) -> anyhow::Result<ResolveHandleResponse> {
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
    ) -> anyhow::Result<ResolveHandleResponse> {
        self.post_json(
            "_cokret/find/directory/resolve-handle",
            resolve_handle_request_body(handle, context),
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
        anyhow::bail!("invite target must be an invite locator URL or invite_address JSON")
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
    fn invite_target_rejects_raw_did_and_handle() {
        let did_err = reject_legacy_invite_target("did:web:bob.example")
            .expect_err("raw DID is no longer an invite target");
        assert!(did_err.to_string().contains("raw DID"));

        let handle_err = reject_legacy_invite_target("bob:example.com")
            .expect_err("handle must not drive invite delivery");
        assert!(handle_err.to_string().contains("handle lookup"));
    }
}
