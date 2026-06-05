use super::*;

#[derive(Debug, serde::Deserialize)]
struct PrincipalRealmLookupResponse {
    realm_id: String,
}

/// Canonical, protocol-namespace location of the auth-bridge describe
/// document. Per `service-http-binding.md` the auth bridge lives under the
/// versionless `/_cokret/gate/...` trust surface; coauth already serves the
/// bridge describe here (see `coauth.rs`), so this is the single bootstrap
/// anchor both adapters share.
const AUTH_BRIDGE_DESCRIBE_PATH: &str = "_cokret/gate/auth/bridge/describe";

/// Legacy product-namespace fallback for servers that have not yet aliased
/// their auth bridge into the protocol namespace. Probed only when the
/// canonical path returns `404 unrecognized_endpoint`.
///
/// TODO: drop once soland serves the bridge describe under `/_cokret/gate/...`
/// (or advertises its location via `/_cokret/describe.auth_metadata`).
const AUTH_BRIDGE_DESCRIBE_PATH_LEGACY: &str = "_soland/gate/auth/bridge/describe";

impl CokretApi {
    pub async fn health(&self) -> anyhow::Result<HealthResponse> {
        self.get_json("health").await
    }

    pub async fn describe(&self) -> anyhow::Result<ServerDescription> {
        self.get_json("_cokret/describe").await
    }

    /// Resolve the principal server's auth-bridge describe document from a
    /// single bootstrap anchor. Prefers the canonical protocol-namespace path
    /// (`/_cokret/gate/auth/bridge/describe`) so the soland and coauth adapters
    /// share one discovery entry point, and falls back to the legacy vendor
    /// path (`/_soland/gate/...`) only when the canonical alias is absent
    /// (`404 unrecognized_endpoint`). All other errors propagate unchanged.
    pub async fn auth_bridge_describe(
        &self,
    ) -> anyhow::Result<PrincipalAuthBridgeDescribeResponse> {
        match self
            .get_json::<PrincipalAuthBridgeDescribeResponse>(AUTH_BRIDGE_DESCRIBE_PATH)
            .await
        {
            Ok(describe) => Ok(describe),
            Err(error) if is_endpoint_absent(&error) => {
                self.get_json(AUTH_BRIDGE_DESCRIBE_PATH_LEGACY).await
            }
            Err(error) => Err(error),
        }
    }

    pub async fn dev_login(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<DevLoginResponse> {
        self.post_json(
            "_soland/gate/auth/dev-login",
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
            "_cokret/gate/account/session-grants",
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
            "_soland/self/account/register",
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
        self.get_json("_soland/self/account/me").await
    }

    /// A4b — update the authenticated principal's public profile
    /// (display_name / bio / avatar_url). Mirrors soland's
    /// `ck.self.account.update_profile` wire shape: each field is
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
            "_soland/self/account/profile",
            json!({
                "display_name": display_name,
                "bio": bio,
                "avatar_url": avatar_url,
            }),
        )
        .await
    }

    pub async fn request_contact(&self, target: &str) -> anyhow::Result<ContactResponse> {
        self.post_json("_soland/self/contacts/request", json!({"target": target}))
            .await
    }

    pub async fn request_contact_scoped(
        &self,
        target: &str,
        scope: &str,
    ) -> anyhow::Result<ContactResponse> {
        self.post_json(
            "_soland/self/contacts/request",
            json!({"target": target, "consent_scope": scope}),
        )
        .await
    }

    pub async fn respond_contact(
        &self,
        requester: &str,
        action: &str,
    ) -> anyhow::Result<ContactResponse> {
        self.post_json(
            "_soland/self/contacts/respond",
            json!({"requester": requester, "action": action}),
        )
        .await
    }

    pub async fn contacts(&self) -> anyhow::Result<ContactsResponse> {
        self.get_json("_soland/self/contacts").await
    }

    pub async fn list_consent_cells(&self) -> anyhow::Result<ConsentCellsResponse> {
        self.get_json("_soland/self/consent/cells").await
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
                "_soland/self/consent/cells/{}/grant",
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
                "_soland/self/consent/cells/{}/revoke",
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
        self.post_json("_soland/gate/auth/logout", json!({})).await
    }

    /// Submit a per-account `ck.account_data.set` event so settings UIs can
    /// push preferences (for example `ck.read_receipt.preferences`) to soland
    /// for cross-device sync. If the current server cannot resolve the
    /// principal control Realm yet, 404 / 501 / 405 still degrade to
    /// `Unsupported` and local state remains authoritative.
    pub async fn set_account_data(
        &self,
        type_key: &str,
        content: Value,
    ) -> anyhow::Result<AccountDataSetOutcome> {
        let (actor, principal_realm_id) = match self.account_data_actor_scope().await {
            Ok(scope) => scope,
            Err(error) => {
                if let Some(status) = unsupported_status(&error) {
                    tracing::warn!(
                        "principal-realm lookup for account_data returned {status}; \
                         keeping local state authoritative"
                    );
                    return Ok(AccountDataSetOutcome::Unsupported { status });
                }
                return Err(error);
            }
        };
        let key = crate::account_data::AccountDataKey::from_wire(type_key);
        let event =
            crate::account_data::build_account_data_set(&principal_realm_id, &actor, &key, content)
                .build("yougen-account-data");
        let result = self.submit_event_envelope(&event).await;
        match result {
            Ok(value) => Ok(AccountDataSetOutcome::Stored {
                response: serde_json::to_value(value)?,
            }),
            Err(error) => {
                if let Some(status) = unsupported_status(&error) {
                    tracing::warn!(
                        "ck.account_data.set submit for {type_key} returned {status}; \
                         keeping local state authoritative"
                    );
                    return Ok(AccountDataSetOutcome::Unsupported { status });
                }
                Err(error)
            }
        }
    }

    /// Tombstone an account_data entry by submitting `ck.account_data.set` with
    /// `tombstone: true`. Same graceful-degradation contract as
    /// [`Self::set_account_data`].
    pub async fn delete_account_data(&self, type_key: &str) -> anyhow::Result<()> {
        let (actor, principal_realm_id) = match self.account_data_actor_scope().await {
            Ok(scope) => scope,
            Err(error) => {
                if unsupported_status(&error).is_some() {
                    return Ok(());
                }
                return Err(error);
            }
        };
        let key = crate::account_data::AccountDataKey::from_wire(type_key);
        let event =
            crate::account_data::build_account_data_tombstone(&principal_realm_id, &actor, &key)
                .build("yougen-account-data");
        match self.submit_event_envelope(&event).await {
            Ok(_) => Ok(()),
            Err(error) => {
                if unsupported_status(&error).is_some() {
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
            json!({"did": did, "requested_evidence_kinds": []}),
        )
        .await
    }

    pub async fn profile_presence(&self, did: &str) -> anyhow::Result<Value> {
        let sync = self.account_subscribe_snapshot(None).await?;
        let presence = sync
            .presence
            .iter()
            .find(|event| {
                event
                    .get("actor_id")
                    .or_else(|| event.get("user_id"))
                    .or_else(|| event.get("actor"))
                    .and_then(Value::as_str)
                    == Some(did)
            })
            .cloned()
            .unwrap_or_else(
                || json!({"actor_id": did, "status": "offline", "presence": "offline"}),
            );
        let status = presence
            .get("status")
            .and_then(Value::as_str)
            .or_else(|| presence.get("presence").and_then(Value::as_str))
            .unwrap_or("offline");
        Ok(json!({
            "actor": did,
            "display_name": did,
            "presence": {
                "status": status,
            },
        }))
    }

    async fn account_data_actor_scope(&self) -> anyhow::Result<(String, String)> {
        let account = self.account_me().await?;
        let lookup: PrincipalRealmLookupResponse = self
            .get_json(&format!(
                "_soland/self/account/{}/principal-realm",
                path_component(&account.did)
            ))
            .await?;
        Ok((account.did, lookup.realm_id))
    }

    pub async fn sync_describe(&self) -> anyhow::Result<SyncDescribeResBody> {
        self.get_json("_cokret/self/account/describe").await
    }

    /// `ck.self.account.subscribe` snapshot fold. The server returns NDJSON frames;
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
        self.get_json("_soland/self/notifications").await
    }

    pub async fn mark_all_notifications_read(&self) -> anyhow::Result<Value> {
        self.post_json("_soland/self/notifications/mark-all-read", json!({}))
            .await
    }

    pub async fn invites(&self) -> anyhow::Result<InvitesResponse> {
        self.get_json("_cokret/self/authz/invites").await
    }
}

fn unsupported_status(error: &anyhow::Error) -> Option<StatusCode> {
    error
        .downcast_ref::<CokretApiError>()
        .map(|api_error| api_error.status)
        .filter(|status| {
            matches!(
                *status,
                StatusCode::NOT_FOUND
                    | StatusCode::NOT_IMPLEMENTED
                    | StatusCode::METHOD_NOT_ALLOWED
            )
        })
}
