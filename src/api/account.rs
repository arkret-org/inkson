use super::*;

#[derive(Debug, serde::Deserialize)]
struct PrincipalRealmLookupOutcome {
    realm_id: String,
}

impl CokretApi {
    pub async fn health(&self) -> anyhow::Result<HealthOutcome> {
        self.get_json("health").await
    }

    pub async fn describe(&self) -> anyhow::Result<ServerDescription> {
        self.get_json("_cokret/describe").await
    }

    pub async fn describe_cached(&self) -> anyhow::Result<&ServerDescription> {
        self.service_describe_cache
            .get_or_try_init(|| async { self.describe().await })
            .await
    }

    pub async fn auth_bridge_describe(&self) -> anyhow::Result<PrincipalAuthBridgeDescribeOutcome> {
        anyhow::bail!(
            "principal auth bridge describe is not part of the Cokret spec; yougen must not call private bridge paths"
        )
    }

    pub async fn dev_login(&self, actor: &str, device_id: &str) -> anyhow::Result<DevLoginOutcome> {
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
    ) -> anyhow::Result<DevLoginOutcome> {
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
    ) -> anyhow::Result<DevLoginOutcome> {
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
    ) -> anyhow::Result<DevLoginOutcome> {
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
    ) -> anyhow::Result<SolandAccountRegisterOutcome> {
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

    pub async fn account_viewer(&self) -> anyhow::Result<cokret_sdk::model::AccountView> {
        self.get_json("_cokret/self/account/viewer").await
    }

    pub async fn account_me(&self) -> anyhow::Result<CurrentAccountOutcome> {
        let viewer = self.account_viewer().await?;
        Ok(current_account_from_viewer(viewer))
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
    ) -> anyhow::Result<SolandAccountUpdateProfileOutcome> {
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

    pub async fn request_contact(&self, target: &str) -> anyhow::Result<ContactOutcome> {
        self.request_contact_scoped(target, "direct_message").await
    }

    pub async fn request_contact_scoped(
        &self,
        target: &str,
        scope: &str,
    ) -> anyhow::Result<ContactOutcome> {
        self.request_contact_with_message(target, &[scope.to_owned()], None, None)
            .await
    }

    /// Send a contact request carrying one or more requested scopes plus an
    /// optional free-text greeting.
    ///
    /// Protocol contract (soland finalized): the `contacts/request` body
    /// accepts an optional `message` field (1..2000 chars) and an optional
    /// `recipient_service_did` (the target Principal Server's service DID). The
    /// latter is required for cross-PS addressing since v1 DIDs do not embed a
    /// home PS; leave it empty for same-PS contacts. We only emit either field
    /// when actually populated so same-PS no-greeting requests stay minimal; an
    /// empty / whitespace-only string is dropped client-side rather than sent
    /// as `""`.
    pub async fn request_contact_with_message(
        &self,
        target: &str,
        scopes: &[String],
        message: Option<&str>,
        recipient_service_did: Option<&str>,
    ) -> anyhow::Result<ContactOutcome> {
        let scopes: Vec<&str> = scopes
            .iter()
            .map(|scope| scope.trim())
            .filter(|scope| !scope.is_empty())
            .collect();
        let mut body = json!({"target": target, "requested_scopes": scopes});
        if let Some(message) = message.map(str::trim).filter(|message| !message.is_empty()) {
            body["message"] = json!(message);
        }
        if let Some(service_did) = recipient_service_did
            .map(str::trim)
            .filter(|service_did| !service_did.is_empty())
        {
            body["recipient_service_did"] = json!(service_did);
        }
        self.post_json("_cokret/self/contacts/request", body).await
    }

    pub async fn respond_contact(
        &self,
        requester: &str,
        action: &str,
    ) -> anyhow::Result<ContactOutcome> {
        self.respond_contact_with_service(requester, action, None)
            .await
    }

    /// Respond to an incoming contact request, optionally carrying the
    /// requester's Principal Server service DID for cross-PS reverse delivery.
    ///
    /// Protocol contract (soland finalized): the `contacts/respond` body
    /// accepts an optional `requester_service_did`. Same-PS responses leave it
    /// empty; cross-PS responses pass the originating PS so soland can route the
    /// accept/reject back. Empty / whitespace-only values are dropped.
    pub async fn respond_contact_with_service(
        &self,
        requester: &str,
        action: &str,
        requester_service_did: Option<&str>,
    ) -> anyhow::Result<ContactOutcome> {
        let mut body = json!({"requester": requester, "action": action});
        if let Some(service_did) = requester_service_did
            .map(str::trim)
            .filter(|service_did| !service_did.is_empty())
        {
            body["requester_service_did"] = json!(service_did);
        }
        self.post_json("_cokret/self/contacts/respond", body).await
    }

    pub async fn contacts(&self) -> anyhow::Result<ContactsOutcome> {
        self.get_json("_cokret/self/contacts").await
    }

    /// Tombstone a contact relationship via `contacts/tombstone`. When
    /// `block_peer` is true the protocol additionally records a block so the
    /// peer can no longer re-request — this is the "拉黑" path (U5).
    ///
    /// Protocol contract (soland in-flight): `contacts/tombstone` body carries
    /// `peer` and an optional `block_peer: true`.
    pub async fn tombstone_contact(
        &self,
        peer: &str,
        block_peer: bool,
    ) -> anyhow::Result<ContactOutcome> {
        let mut body = json!({"peer": peer});
        if block_peer {
            body["block_peer"] = json!(true);
        }
        self.post_json("_cokret/self/contacts/tombstone", body)
            .await
    }

    /// Read the actor's `invite_receive_policy` ("谁可以邀请我", U4).
    ///
    /// Spec `invite-addressing.md` §5 / OpenAPI
    /// `ck.self.invite_receive_policy.get`: served from the self plane at
    /// `GET /_cokret/self/invite-receive-policy` and returns the bare
    /// `cokret_sdk::InviteReceivePolicy` (soland echoes the stored override or
    /// its recommended default). When the deployment does not yet wire this
    /// surface the caller treats 404/501/405 as "use defaults" rather than a
    /// hard error (see [`crate::models::default_invite_receive_policy`]).
    pub async fn get_invite_receive_policy(
        &self,
    ) -> anyhow::Result<crate::models::InviteReceivePolicy> {
        self.get_json("_cokret/self/invite-receive-policy").await
    }

    /// Persist the actor's `invite_receive_policy` (U4).
    ///
    /// Spec `ck.self.invite_receive_policy.set`:
    /// `POST /_cokret/self/invite-receive-policy` with the bare
    /// `cokret_sdk::InviteReceivePolicy` as the body. The handler enforces
    /// `subject_id == session actor` and requires the `schema` constant, so the
    /// caller MUST stamp both before calling (see the U4 view); the server
    /// echoes the stored policy back.
    pub async fn set_invite_receive_policy(
        &self,
        policy: &crate::models::InviteReceivePolicy,
    ) -> anyhow::Result<crate::models::InviteReceivePolicy> {
        self.post_json(
            "_cokret/self/invite-receive-policy",
            serde_json::to_value(policy)?,
        )
        .await
    }

    pub async fn direct_conversation_resolve(
        &self,
        peer: &str,
        create: bool,
    ) -> anyhow::Result<crate::models::DirectConversationResolveOutcome> {
        self.post_json(
            "_cokret/self/direct-conversations/resolve",
            json!({
                "peer": peer,
                "create": create,
            }),
        )
        .await
    }

    pub async fn list_consent_cells(&self) -> anyhow::Result<ConsentCellsOutcome> {
        self.get_json("_soland/self/consent/cells").await
    }

    pub async fn grant_consent_cell(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
        expires_at: Option<&str>,
    ) -> anyhow::Result<ConsentCellOutcome> {
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
    ) -> anyhow::Result<ConsentCellOutcome> {
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

    /// Open a scoped consent request toward `holder` (`ck.consent.request`).
    /// The authenticated actor is the requester/peer, so `peer_did` is left to
    /// soland's default (the session actor); only the `holder` and scope are
    /// sent. Records a pending cell the holder can later grant.
    pub async fn request_consent_cell(
        &self,
        holder: &str,
        scope: &str,
    ) -> anyhow::Result<ConsentCellOutcome> {
        self.post_json(
            "_soland/self/consent/request",
            json!({
                "holder_did": holder,
                // Spec consent-model.md §3: domain-prefixed `consent_scope`.
                "consent_scope": scope,
            }),
        )
        .await
    }

    pub async fn logout(&self) -> anyhow::Result<LogoutOutcome> {
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

    pub async fn identity_describe(&self) -> anyhow::Result<IdentityDescribeOutcome> {
        self.get_json("_cokret/root/identity/describe").await
    }

    pub async fn identity_resolve(&self, did: &str) -> anyhow::Result<IdentityResolveOutcome> {
        let subject = cokret_sdk::Did::new(did.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid did `{did}`: {err}"))?;
        let body = cokret_sdk::model::IdentityResolveRequestBody {
            did: subject,
            requested_evidence_kinds: Vec::new(),
        };
        self.post_json(
            "_cokret/root/identity/resolve",
            serde_json::to_value(&body)?,
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
        let lookup: PrincipalRealmLookupOutcome = self
            .get_json(&format!(
                "_soland/self/account/{}/principal-realm",
                path_component(&account.did)
            ))
            .await?;
        Ok((account.did, lookup.realm_id))
    }

    pub async fn sync_describe(&self) -> anyhow::Result<SyncDescribeOutcome> {
        self.get_json("_cokret/self/account/describe").await
    }

    /// `ck.self.account.subscribe` snapshot fold. The server returns NDJSON frames;
    /// this consumes EVERY frame of the response (merging catchup deltas and
    /// advancing the cursor to the last cursor-bearing frame per
    /// client-sync.md §2.2) and keeps the rest of the app on the existing
    /// folded `ClientSyncOutcome` projection path.
    pub async fn account_subscribe_snapshot(
        &self,
        after: Option<&str>,
    ) -> anyhow::Result<ClientSyncOutcome> {
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
        let _subscribe_gate = ACCOUNT_SUBSCRIBE_NETWORK_GATE.lock().await;
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
        if !status.is_success() {
            let bytes = response.bytes().await?;
            return Err(CokretApiError {
                status,
                error: decode_cokret_error(status, &bytes),
            }
            .into());
        }
        // YOU-01-010 — native reads the NDJSON stream frame by frame and
        // returns at `catchup_complete` / control frames, so a
        // spec-compliant server that keeps the stream open for realtime
        // push does not stall the client until timeout. wasm32 stays on
        // the buffered read (reqwest's browser-fetch backend exposes no
        // chunk reader; a web-sys ReadableStream frame reader is the
        // remaining gap).
        #[cfg(not(target_arch = "wasm32"))]
        {
            super::drain_account_subscribe_response(response).await
        }
        #[cfg(target_arch = "wasm32")]
        {
            let bytes = response.bytes().await?;
            parse_account_subscribe_snapshot_outcome(&bytes)
        }
    }

    pub async fn list_notifications(&self) -> anyhow::Result<Value> {
        Ok(self.account_subscribe_snapshot(None).await?.notifications)
    }

    pub async fn mark_all_notifications_read(&self) -> anyhow::Result<Value> {
        Ok(json!({
            "ok": true,
            "local_only": true,
        }))
    }

    pub async fn submit_read_cursor_advance(
        &self,
        marker: &crate::local_state::ReadMarkerRecord,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let event = build_read_cursor_advance_event(marker);
        self.submit_event_envelope(&event).await
    }

    pub async fn invites(&self) -> anyhow::Result<InvitesOutcome> {
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

fn current_account_from_viewer(viewer: cokret_sdk::model::AccountView) -> CurrentAccountOutcome {
    let display_name = viewer.profile.as_ref().and_then(|profile| {
        let value = profile.display_name.trim();
        (!value.is_empty()).then(|| value.to_owned())
    });
    let created_at = viewer
        .profile
        .as_ref()
        .map(|profile| {
            profile
                .created_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        })
        .unwrap_or_default();
    CurrentAccountOutcome {
        did: viewer.principal_id.as_str().to_owned(),
        handle: primary_handle_from_viewer(&viewer),
        display_name,
        created_at,
    }
}

fn primary_handle_from_viewer(viewer: &cokret_sdk::model::AccountView) -> String {
    viewer
        .primary_handle_claim
        .as_ref()
        .and_then(|claim| claim.get("handle"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|handle| !handle.is_empty())
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_viewer_projection_uses_signed_handle_claim() {
        let viewer: cokret_sdk::model::AccountView = serde_json::from_value(json!({
            "principal_id": "did:web:alice.example",
            "state": "active",
            "devices": [],
            "primary_handle_claim": {
                "schema": "ck.schema.handle_claim.v1",
                "handle": "alice:local.host",
                "subject": "did:web:alice.example"
            },
            "profile": {
                "id": "ck:actor_profile:01970000-0000-7000-8000-000000000001",
                "schema": "ck.schema.actor_profile.v1",
                "principal_id": "did:web:alice.example",
                "actor_kind": "user",
                "display_name": "Alice",
                "created_at": "2026-06-12T08:00:00Z"
            }
        }))
        .expect("account viewer shape");

        let account = current_account_from_viewer(viewer);

        assert_eq!(account.did, "did:web:alice.example");
        assert_eq!(account.handle, "alice:local.host");
        assert_eq!(account.display_name.as_deref(), Some("Alice"));
        assert_eq!(account.created_at, "2026-06-12T08:00:00Z");
    }

    #[test]
    fn account_viewer_projection_does_not_invent_handle() {
        let viewer: cokret_sdk::model::AccountView = serde_json::from_value(json!({
            "principal_id": "did:web:alice.example",
            "state": "active",
            "devices": []
        }))
        .expect("minimal account viewer shape");

        let account = current_account_from_viewer(viewer);

        assert_eq!(account.did, "did:web:alice.example");
        assert_eq!(account.handle, "");
        assert_eq!(account.display_name, None);
        assert_eq!(account.created_at, "");
    }
}
