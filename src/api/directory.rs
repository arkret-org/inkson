use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct InviteeResolution {
    pub did: String,
    pub handle: Option<String>,
    pub member_delivery_binding: Option<Value>,
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
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<InviteeResolution> {
        let target = target.trim();
        if target.is_empty() {
            anyhow::bail!("invitee is required");
        }
        if cokret_sdk::Did::new(target.to_owned()).is_ok() {
            return Ok(InviteeResolution {
                did: target.to_owned(),
                handle: None,
                member_delivery_binding: None,
            });
        }

        let handle = canonical_invitee_handle(target)?;
        let realm_id = trim_realm_id(realm_id);
        let resolved = self
            .resolve_handle_with_context(
                &handle,
                ResolveHandleContext {
                    intent: Some("invite"),
                    requester: Some(actor_id),
                    audience: Some(&realm_id),
                    realm_id: Some(&realm_id),
                    ..ResolveHandleContext::default()
                },
            )
            .await?;
        validate_invite_handle_resolution(&resolved, &realm_id)?;
        let invitee = resolved.subject_did().ok_or_else(|| {
            anyhow::anyhow!("directory resolve_handle response did not include subject DID")
        })?;
        cokret_sdk::Did::new(invitee.to_owned())
            .map_err(|err| anyhow::anyhow!("directory resolved invalid DID `{invitee}`: {err}"))?;
        let invitee = invitee.to_owned();
        let member_delivery_binding = resolved.member_delivery_binding_value();
        let handle = resolved.handle;
        Ok(InviteeResolution {
            did: invitee,
            handle: Some(handle),
            member_delivery_binding,
        })
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
