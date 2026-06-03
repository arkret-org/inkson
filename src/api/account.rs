use super::*;

impl CokretApi {
    pub async fn health(&self) -> anyhow::Result<HealthResponse> {
        self.get_json("health").await
    }

    pub async fn describe(&self) -> anyhow::Result<ServerDescription> {
        self.get_json("_cokret/describe").await
    }

    pub async fn auth_bridge_describe(
        &self,
    ) -> anyhow::Result<PrincipalAuthBridgeDescribeResponse> {
        self.get_json("_cokret/gate/auth/bridge/describe").await
    }

    pub async fn dev_login(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<DevLoginResponse> {
        self.post_json(
            "_cokret/gate/auth/dev-login",
            json!({
                "actor": actor,
                "device_id": device_id,
                "display_name": crate::device_name::default_device_display_name(),
            }),
        )
        .await
    }

    pub async fn exchange_session_grant_at(
        &self,
        path: &str,
        grant_jwt: &str,
        principal_id: &str,
        device_id: &str,
    ) -> anyhow::Result<DevLoginResponse> {
        self.exchange_session_grant_at_with_proof(path, grant_jwt, principal_id, device_id, None)
            .await
    }

    pub async fn exchange_session_grant_at_with_proof(
        &self,
        path: &str,
        grant_jwt: &str,
        principal_id: &str,
        device_id: &str,
        introspection_proof: Option<&SessionGrantIntrospectionProof>,
    ) -> anyhow::Result<DevLoginResponse> {
        let mut body = json!({
            "grant_jwt": grant_jwt,
            "principal_id": principal_id,
            "device_id": device_id,
            "display_name": crate::device_name::default_device_display_name(),
        });
        if let Some(introspection_proof) = introspection_proof {
            body["introspection_proof"] = serde_json::to_value(introspection_proof)?;
        }
        self.post_json(path, body).await
    }

    pub async fn exchange_session_grant(
        &self,
        grant_jwt: &str,
        principal_id: &str,
        device_id: &str,
    ) -> anyhow::Result<DevLoginResponse> {
        self.exchange_session_grant_at(
            "_cokret/gate/auth/session-grant/exchange",
            grant_jwt,
            principal_id,
            device_id,
        )
        .await
    }

    pub async fn register_account(
        &self,
        did: &str,
        handle: &str,
        display_name: Option<&str>,
        device_id: Option<&str>,
    ) -> anyhow::Result<AccountResponse> {
        self.post_json(
            "_cokret/self/account/register",
            json!({
                "did": did,
                "handle": handle,
                "display_name": display_name,
                "device_id": device_id
            }),
        )
        .await
    }

    pub async fn account_me(&self) -> anyhow::Result<AccountResponse> {
        self.get_json("_cokret/self/account/me").await
    }

    /// A4b — update the authenticated principal's public profile
    /// (display_name / bio / avatar_url). Mirrors soland's
    /// `ck.account.update_profile` wire shape: each field is
    /// `Option<String>`; `None` leaves the field untouched server-side,
    /// `Some("")` explicitly clears it. The server normalises empty
    /// strings to `None` on write.
    ///
    /// `avatar_url` MUST be either an `http://` / `https://` URL or
    /// empty — soland rejects other shapes with `invalid_avatar_url`.
    /// To publish a yougen-uploaded blob, the caller constructs the
    /// download URL via [`Self::blob_download_url`] before passing it
    /// here.
    pub async fn update_profile(
        &self,
        display_name: Option<&str>,
        bio: Option<&str>,
        avatar_url: Option<&str>,
    ) -> anyhow::Result<UpdateProfileResponse> {
        self.post_json(
            "_cokret/self/account/profile",
            json!({
                "display_name": display_name,
                "bio": bio,
                "avatar_url": avatar_url,
            }),
        )
        .await
    }

    pub async fn request_contact(&self, target: &str) -> anyhow::Result<ContactResponse> {
        self.post_json("_cokret/self/contacts/request", json!({"target": target}))
            .await
    }

    pub async fn request_contact_scoped(
        &self,
        target: &str,
        scope: &str,
    ) -> anyhow::Result<ContactResponse> {
        self.post_json(
            "_cokret/self/contacts/request",
            json!({"target": target, "scope": scope}),
        )
        .await
    }

    pub async fn respond_contact(
        &self,
        requester: &str,
        action: &str,
    ) -> anyhow::Result<ContactResponse> {
        self.post_json(
            "_cokret/self/contacts/respond",
            json!({"requester": requester, "action": action}),
        )
        .await
    }

    pub async fn contacts(&self) -> anyhow::Result<ContactsResponse> {
        self.get_json("_cokret/self/contacts").await
    }

    pub async fn list_consent_cells(&self) -> anyhow::Result<ConsentCellsResponse> {
        self.get_json("_cokret/self/consent/cells").await
    }

    pub async fn grant_consent_cell(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
        expires_at: Option<&str>,
    ) -> anyhow::Result<ConsentCellResponse> {
        self.post_json(
            &format!(
                "_cokret/self/consent/cells/{}/grant",
                url::form_urlencoded::byte_serialize(holder.as_bytes()).collect::<String>()
            ),
            json!({
                "peer_did": peer,
                // Spec consent-model.md §3: domain-prefixed `consent_scope`.
                "consent_scope": scope,
                "expires_at": expires_at,
            }),
        )
        .await
    }

    pub async fn revoke_consent_cell(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> anyhow::Result<ConsentCellResponse> {
        self.post_json(
            &format!(
                "_cokret/self/consent/cells/{}/revoke",
                url::form_urlencoded::byte_serialize(holder.as_bytes()).collect::<String>()
            ),
            json!({
                "peer_did": peer,
                "consent_scope": scope,
            }),
        )
        .await
    }

    pub async fn logout(&self) -> anyhow::Result<LogoutResponse> {
        self.post_json("_cokret/gate/auth/logout", json!({})).await
    }

    /// PUT a per-account `ck.account_data.set` entry. Thin wrapper around
    /// `PUT /_cokret/self/account_data/{type}` so settings UIs can push preferences
    /// (e.g. `ck.read_receipt.preferences`) up to soland for cross-device
    /// sync. When the endpoint returns 404 / 501 / 405 we treat the outcome
    /// as `Unsupported` and let the caller swallow it (local state stays
    /// authoritative). Anything else surfaces as `Err`.
    ///
    /// Structural: the body is `{ "content": <value> }` — soland's existing
    /// `ck.account_data.set` pipeline treats the path's `{type}` segment as
    /// the canonical account-data key.
    pub async fn set_account_data(
        &self,
        type_key: &str,
        content: Value,
    ) -> anyhow::Result<AccountDataSetOutcome> {
        let body = json!({ "content": content });
        let result: anyhow::Result<Value> = self
            .put_json(&format!("_cokret/self/account_data/{type_key}"), body)
            .await;
        match result {
            Ok(value) => Ok(AccountDataSetOutcome::Stored { response: value }),
            Err(error) => {
                // Detect the "endpoint not yet implemented" shape. We accept
                // 404 (route absent), 501 (NotImplemented), and 405 (route
                // exists for another method but PUT not wired) as graceful
                // degradation — anything else propagates.
                if let Some(api_error) = error.downcast_ref::<CokretApiError>() {
                    let status = api_error.status;
                    if matches!(
                        status,
                        StatusCode::NOT_FOUND
                            | StatusCode::NOT_IMPLEMENTED
                            | StatusCode::METHOD_NOT_ALLOWED
                    ) {
                        tracing::warn!(
                            "account_data PUT for {type_key} returned {status}; \
                             keeping local state authoritative until soland wires it"
                        );
                        return Ok(AccountDataSetOutcome::Unsupported { status });
                    }
                }
                Err(error)
            }
        }
    }

    /// DELETE an account_data entry. Same graceful-degradation contract as
    /// [`Self::set_account_data`] — 404 means the row was already absent
    /// (treated as success) and is logged at debug level; other errors
    /// propagate.
    pub async fn delete_account_data(&self, type_key: &str) -> anyhow::Result<()> {
        let path = format!("_cokret/self/account_data/{type_key}");
        let result: anyhow::Result<Value> = self.delete_json(&path).await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                if let Some(api_error) = error.downcast_ref::<CokretApiError>()
                    && matches!(
                        api_error.status,
                        StatusCode::NOT_FOUND
                            | StatusCode::NOT_IMPLEMENTED
                            | StatusCode::METHOD_NOT_ALLOWED
                    )
                {
                    return Ok(());
                }
                Err(error)
            }
        }
    }

    pub async fn identity_describe(&self) -> anyhow::Result<IdentityDescribeResBody> {
        self.get_json("_cokret/root/identity/describe").await
    }

    pub async fn identity_resolve(&self, did: &str) -> anyhow::Result<IdentityResolveResBody> {
        self.post_json(
            "_cokret/root/identity/resolve",
            json!({"did": did, "include": []}),
        )
        .await
    }

    pub async fn profile_presence(&self, did: &str) -> anyhow::Result<Value> {
        self.get_json(&format!(
            "_cokret/self/profile/presence?did={}",
            query_component(did)
        ))
        .await
    }

    pub async fn sync_describe(&self) -> anyhow::Result<SyncDescribeResBody> {
        self.get_json("_cokret/self/account/describe").await
    }

    /// `ck.account.subscribe` snapshot fold. The server returns NDJSON frames;
    /// this consumes the first `delta` frame and keeps the rest of the app on
    /// the existing folded `ClientSyncResponse` projection path.
    pub async fn account_subscribe_snapshot(
        &self,
        after: Option<&str>,
    ) -> anyhow::Result<ClientSyncResponse> {
        match self.account_subscribe_snapshot_outcome(after).await? {
            AccountSubscribeSnapshotOutcome::Delta(response) => Ok(response),
            AccountSubscribeSnapshotOutcome::ReconnectAfter {
                reconnect_after_ms,
                reason,
                reset_cursor,
            } => Err(AccountSubscribeReconnectAfter {
                reconnect_after_ms,
                reason,
                reset_cursor,
            }
            .into()),
        }
    }

    pub async fn account_subscribe_snapshot_outcome(
        &self,
        after: Option<&str>,
    ) -> anyhow::Result<AccountSubscribeSnapshotOutcome> {
        // H3 — enforce `ck:cursor:*` prefix on non-nil values. nil
        // (`None`) is the boot bootstrap case and stays untouched.
        if let Some(token) = after {
            validate_cursor(token)?;
        }
        let mut url = self.endpoint("_cokret/self/account/subscribe")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("catchup", "true");
            query.append_pair("set_presence", "online");
            if let Some(cursor) = after {
                query.append_pair("after", cursor);
            }
        }
        let request = self.http.get(url).header(ACCEPT, "application/x-ndjson");
        let response = self
            .send_with_retry(self.prepare_request(request), Method::GET, true)
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(CokretApiError {
                status,
                error: decode_cokret_error(status, &bytes),
            }
            .into());
        }
        parse_account_subscribe_snapshot_outcome(&bytes)
    }

    pub async fn list_notifications(&self) -> anyhow::Result<Value> {
        self.get_json("_cokret/self/notifications").await
    }

    pub async fn mark_all_notifications_read(&self) -> anyhow::Result<Value> {
        self.post_json("_cokret/self/notifications/mark-all-read", json!({}))
            .await
    }

    pub async fn invites(&self) -> anyhow::Result<InvitesResponse> {
        self.get_json("_cokret/self/authz/invites").await
    }
}
