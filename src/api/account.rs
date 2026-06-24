use super::*;

fn did_for_request_field(field: &str, value: &str) -> anyhow::Result<cokret_sdk::Did> {
    let value = value.trim();
    cokret_sdk::Did::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid {field} DID `{value}`: {err}"))
}

fn device_id_for_request_field(field: &str, value: &str) -> anyhow::Result<cokret_sdk::DeviceId> {
    let value = value.trim();
    cokret_sdk::DeviceId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid {field} `{value}`: {err}"))
}

fn contact_response_action(action: &str) -> anyhow::Result<String> {
    match action.trim() {
        "accept" | "reject" => Ok(action.trim().to_owned()),
        other => anyhow::bail!("unsupported contact response action `{other}`"),
    }
}

fn optional_did_for_request_field(
    field: &str,
    value: Option<&str>,
) -> anyhow::Result<Option<cokret_sdk::Did>> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| did_for_request_field(field, value))
        .transpose()
}

impl CokretApi {
    pub async fn describe(&self) -> anyhow::Result<ServerDescription> {
        self.get_json("_cokret/describe").await
    }

    pub async fn describe_cached(&self) -> anyhow::Result<&ServerDescription> {
        self.service_describe_cache
            .get_or_try_init(|| async { self.describe().await })
            .await
    }

    pub async fn auth_bridge_describe(&self) -> anyhow::Result<PrincipalAuthBridgeDescribeView> {
        anyhow::bail!(
            "principal auth bridge describe is not part of the Cokret spec; yougen must not call private bridge paths"
        )
    }

    // ②(A+②): the Principal Server does not mint a second client-visible
    // credential. The held credential is the `ck.session.grant` itself,
    // presented per-request as
    // `Authorization: Bearer <grant>` + a `DPoP` proof (see
    // `CokretApi::with_bearer` / `with_dpop_device`).

    pub async fn register_account(
        &self,
        did: &str,
        _handle: &str,
        display_name: Option<&str>,
        device_id: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::models::AccountRegisterOutcome> {
        let body = cokret_sdk::models::AccountRegisterRequestBody {
            principal_id: did_for_request_field("principal_id", did)?,
            // Canonical registration handle is asserted by the Account Authority
            // on the coauth -> soland register path; this direct client path
            // leaves it unset (the Principal Server falls back to a synthetic
            // bootstrap localpart).
            handle: None,
            display_name: display_name
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            device_id: device_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| device_id_for_request_field("device_id", value))
                .transpose()?,
            policy_evidence: None,
            proof: None,
        };
        self.post_json("_cokret/gate/account/register", &body).await
    }

    pub async fn account_viewer(&self) -> anyhow::Result<cokret_sdk::models::AccountView> {
        self.get_json("_cokret/self/account/viewer").await
    }

    pub async fn account_me(&self) -> anyhow::Result<CurrentAccount> {
        let viewer = self.account_viewer().await?;
        Ok(current_account_from_viewer(viewer))
    }

    /// A4b — update the authenticated principal's public profile
    /// (display_name / bio / avatar_blob_ref). Mirrors the
    /// `ck.self.account.command.update_profile` wire shape: each field is
    /// `Option<String>`; `None` leaves the field untouched server-side,
    /// `Some("")` explicitly clears it. The server normalises empty
    /// strings to `None` on write.
    pub async fn update_profile(
        &self,
        display_name: Option<&str>,
        bio: Option<&str>,
        avatar_blob_ref: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::models::AccountUpdateProfileOutcome> {
        let mut patch = cokret_sdk::Patch::new();
        if let Some(display_name) = display_name {
            let display_name = display_name.trim();
            if display_name.is_empty() {
                patch.insert_op("display_name", cokret_sdk::PatchOp::unset())?;
            } else {
                patch.insert("display_name", display_name)?;
            }
        }
        if let Some(bio) = bio {
            let bio = bio.trim();
            if bio.is_empty() {
                patch.insert_op("profile_fields.bio", cokret_sdk::PatchOp::unset())?;
            } else {
                patch.insert("profile_fields.bio", bio)?;
            }
        }
        if let Some(avatar_blob_ref) = avatar_blob_ref {
            let avatar_blob_ref = avatar_blob_ref.trim();
            if avatar_blob_ref.is_empty() {
                patch.insert_op("avatar_blob_ref", cokret_sdk::PatchOp::unset())?;
            } else {
                cokret_sdk::BlobRef::new(avatar_blob_ref.to_owned()).map_err(|err| {
                    anyhow::anyhow!("invalid avatar_blob_ref `{avatar_blob_ref}`: {err}")
                })?;
                patch.insert("avatar_blob_ref", avatar_blob_ref)?;
            }
        }
        if patch.is_empty() {
            anyhow::bail!("profile update patch is empty");
        }
        patch
            .validate()
            .map_err(|err| anyhow::anyhow!("invalid profile patch: {err}"))?;
        let body = cokret_sdk::models::AccountUpdateProfileRequestBody {
            patch: serde_json::to_value(&patch)?,
        };
        self.post_json("_cokret/self/account/profile", &body).await
    }

    pub async fn request_contact(
        &self,
        target: &str,
    ) -> anyhow::Result<cokret_sdk::ContactRequestOutcome> {
        self.request_contact_scoped(target, "direct_message").await
    }

    pub async fn request_contact_scoped(
        &self,
        target: &str,
        scope: &str,
    ) -> anyhow::Result<cokret_sdk::ContactRequestOutcome> {
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
    ) -> anyhow::Result<cokret_sdk::ContactRequestOutcome> {
        let requested_scopes: Vec<String> = scopes
            .iter()
            .map(|scope| scope.trim())
            .filter(|scope| !scope.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let addressing = self
            .contact_request_addressing(target, recipient_service_did)
            .await?;
        let body = cokret_sdk::ContactRequestRequestBody {
            target: addressing.target,
            requested_scopes,
            message: message
                .map(str::trim)
                .filter(|message| !message.is_empty())
                .map(ToOwned::to_owned),
            idempotency_key: None,
            recipient_service_did: addressing.recipient_service_did,
            introduction_evidence: Some(addressing.introduction_evidence),
        };
        self.post_json(cokret_sdk::http::PATH_SELF_CONTACTS_REQUEST, &body)
            .await
    }

    pub async fn respond_contact(
        &self,
        requester: &str,
        action: &str,
    ) -> anyhow::Result<cokret_sdk::ContactRespondOutcome> {
        self.respond_contact_with_service(requester, action, None)
            .await
    }

    async fn contact_request_event_id_for_requester(
        &self,
        requester: &str,
    ) -> anyhow::Result<String> {
        let requester = requester.trim();
        let contacts = self.contacts().await?;
        contacts
            .contacts
            .into_iter()
            .find(|row| row.peer == requester && row.request_event_ref.is_some())
            .and_then(|row| row.request_event_ref)
            .ok_or_else(|| {
                anyhow::anyhow!("contact request_id is required for responding to `{requester}`")
            })
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
    ) -> anyhow::Result<cokret_sdk::ContactRespondOutcome> {
        let request_event_ref = self
            .contact_request_event_id_for_requester(requester)
            .await?;
        self.respond_contact_with_request_id_and_service(
            requester,
            &request_event_ref,
            action,
            requester_service_did,
        )
        .await
    }

    pub async fn respond_contact_with_request_id_and_service(
        &self,
        requester: &str,
        request_event_ref: &str,
        action: &str,
        requester_service_did: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::ContactRespondOutcome> {
        let body = cokret_sdk::ContactRespondRequestBody {
            request_id: cokret_sdk::EventId::new(request_event_ref.trim().to_owned()).map_err(
                |err| anyhow::anyhow!("invalid contact request_id `{request_event_ref}`: {err}"),
            )?,
            requester: did_for_request_field("requester", requester)?,
            action: contact_response_action(action)?,
            granted_scopes: Vec::new(),
            requester_service_did: optional_did_for_request_field(
                "requester_service_did",
                requester_service_did,
            )?,
        };
        self.post_json(cokret_sdk::http::PATH_SELF_CONTACTS_RESPOND, &body)
            .await
    }

    pub async fn contacts(&self) -> anyhow::Result<ContactListView> {
        let response: cokret_sdk::ContactList =
            self.get_json(cokret_sdk::http::PATH_SELF_CONTACTS).await?;
        ContactListView::from_sdk(response)
    }

    /// Tombstone a contact relationship via `contacts/tombstone`. When
    /// `block_peer` is true the protocol additionally records a block so the
    /// peer can no longer re-request; this is the block path (U5).
    ///
    /// Protocol contract (soland in-flight): `contacts/tombstone` body carries
    /// `peer` and an optional `block_peer: true`.
    pub async fn tombstone_contact(
        &self,
        peer: &str,
        block_peer: bool,
    ) -> anyhow::Result<cokret_sdk::ContactTombstone> {
        let body = cokret_sdk::ContactTombstoneRequestBody {
            contact: did_for_request_field("contact", peer)?,
            revoke_scopes: Vec::new(),
            full_peer_revoke: false,
            block_peer,
            peer_service_did: None,
        };
        self.post_json(cokret_sdk::http::PATH_SELF_CONTACTS_TOMBSTONE, &body)
            .await
    }

    /// Read the actor's `invite_receive_policy` ("who can invite me", U4).
    ///
    /// Spec `invite-addressing.md` §5 / OpenAPI
    /// `ck.self.invite_receive_policy.resource.get`: served from the self plane at
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
    /// Spec `ck.self.invite_receive_policy.resource.replace`:
    /// `PUT /_cokret/self/invite-receive-policy` with the bare
    /// `cokret_sdk::InviteReceivePolicy` as the body. The handler enforces
    /// `subject_id == session actor` and requires the `schema` constant, so the
    /// caller MUST stamp both before calling (see the U4 view); the server
    /// echoes the stored policy back.
    pub async fn set_invite_receive_policy(
        &self,
        policy: &crate::models::InviteReceivePolicy,
    ) -> anyhow::Result<crate::models::InviteReceivePolicy> {
        self.put_json("_cokret/self/invite-receive-policy", policy)
            .await
    }

    pub async fn direct_conversation_resolve(
        &self,
        peer: &str,
        create: bool,
    ) -> anyhow::Result<cokret_sdk::DirectConversationResolveOutcome> {
        let body = cokret_sdk::DirectConversationResolveRequestBody {
            peer: did_for_request_field("peer", peer)?,
            create,
            idempotency_key: None,
        };
        self.post_json(
            cokret_sdk::http::PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE,
            &body,
        )
        .await
    }

    /// List the holder-private consent cells visible to the authenticated
    /// actor (cells where the actor is either holder or peer). Spec
    /// `identity/consent-model.md` §3 / OpenAPI `ck.self.consent.query.list`.
    pub async fn consent_cells(&self) -> anyhow::Result<cokret_sdk::ConsentCellList> {
        self.get_json(cokret_sdk::http::PATH_SELF_CONSENT_CELLS)
            .await
    }

    /// Read one holder-private consent cell for `(holder, peer, scope)`.
    /// Spec OpenAPI `ck.self.consent.resource.get`. Returns `None` on 404 so
    /// callers can treat a missing cell as `no-consent` rather than an error.
    pub async fn consent_cell(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> anyhow::Result<Option<cokret_sdk::ConsentCellView>> {
        let path = format!(
            "{}/{}?peer={}&consent_scope={}",
            cokret_sdk::http::PATH_SELF_CONSENT_CELLS,
            path_component(holder.trim()),
            query_component(peer.trim()),
            query_component(scope.trim()),
        );
        match self.get_json::<cokret_sdk::ConsentCellView>(&path).await {
            Ok(view) => Ok(Some(view)),
            Err(err) => {
                if err.to_string().contains("404") {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Grant scoped consent to `peer` from the holder cell. `expires_at` is an
    /// optional RFC 3339 time window upper bound. Spec OpenAPI
    /// `ck.self.consent.command.grant`.
    pub async fn grant_consent(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<cokret_sdk::ConsentCellView> {
        let body = cokret_sdk::ConsentUpdateRequestBody {
            peer_did: did_for_request_field("peer", peer)?,
            consent_scope: Some(scope.trim().to_owned()),
            expires_at,
        };
        let path = format!(
            "{}/{}/grant",
            cokret_sdk::http::PATH_SELF_CONSENT_CELLS,
            path_component(holder.trim()),
        );
        self.post_json(&path, &body).await
    }

    /// Revoke scoped consent from `peer`. Spec OpenAPI
    /// `ck.self.consent.command.revoke`.
    pub async fn revoke_consent(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> anyhow::Result<cokret_sdk::ConsentCellView> {
        let body = cokret_sdk::ConsentUpdateRequestBody {
            peer_did: did_for_request_field("peer", peer)?,
            consent_scope: Some(scope.trim().to_owned()),
            expires_at: None,
        };
        let path = format!(
            "{}/{}/revoke",
            cokret_sdk::http::PATH_SELF_CONSENT_CELLS,
            path_component(holder.trim()),
        );
        self.post_json(&path, &body).await
    }

    /// Open an outbound consent request: ask `holder` to grant the
    /// authenticated actor (`peer`) the given scope. Produces a holder-side
    /// pending cell. Spec OpenAPI `ck.self.consent.command.request`.
    pub async fn request_consent(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> anyhow::Result<cokret_sdk::ConsentCellView> {
        let body = cokret_sdk::ConsentRequestRequestBody {
            holder_did: did_for_request_field("holder", holder)?,
            peer_did: Some(did_for_request_field("peer", peer)?),
            consent_scope: Some(scope.trim().to_owned()),
        };
        self.post_json(cokret_sdk::http::PATH_SELF_CONSENT_REQUEST, &body)
            .await
    }

    /// Single hard logout (account-lifecycle §4.1): the client presents the
    /// current session grant + DPoP proof to `/_cokret/gate/account/logout`.
    /// The Account Authority/Principal Server path terminates the Auth-side
    /// grant chain and the Principal-side device session. Returns whether the
    /// server reports a session was revoked.
    pub async fn logout(&self) -> anyhow::Result<bool> {
        // Spec strong types for the POST body + response, so the wire shape
        // stays in lockstep with the OpenAPI/DTO contract.
        let outcome: cokret_sdk::AccountLogoutOutcome = self
            .post_json(
                "_cokret/gate/account/logout",
                &cokret_sdk::AccountLogoutRequestBody::default(),
            )
            .await?;
        Ok(outcome.revoked)
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
    ) -> anyhow::Result<AccountDataSetResult> {
        let (actor, principal_realm_id) = match self.account_data_actor_scope().await {
            Ok(scope) => scope,
            Err(error) => {
                if let Some(status) = unsupported_status(&error) {
                    tracing::warn!(
                        "principal-realm lookup for account_data returned {status}; \
                         keeping local state authoritative"
                    );
                    return Ok(AccountDataSetResult::Unsupported { status });
                }
                return Err(error);
            }
        };
        let key = crate::account_data::AccountDataKey::from_wire(type_key);
        let event =
            crate::account_data::build_account_data_set(&principal_realm_id, &actor, &key, content)
                .build_sdk_event("yougen-account-data")?;
        let result = self.submit_sdk_event(&event).await;
        match result {
            Ok(value) => Ok(AccountDataSetResult::Stored {
                response: serde_json::to_value(value)?,
            }),
            Err(error) => {
                if let Some(status) = unsupported_status(&error) {
                    tracing::warn!(
                        "ck.account_data.set submit for {type_key} returned {status}; \
                         keeping local state authoritative"
                    );
                    return Ok(AccountDataSetResult::Unsupported { status });
                }
                Err(error)
            }
        }
    }

    /// Submit a private account-data value with an optional CAS guard. Callers
    /// pass already-encrypted account-data material; plaintext draft/saved
    /// content must not cross this API boundary.
    pub async fn set_private_account_data_with_cas(
        &self,
        type_key: &str,
        encrypted_payload: Value,
        expected_state_digest: Option<&str>,
    ) -> anyhow::Result<AccountDataSetResult> {
        let (actor, principal_realm_id) = match self.account_data_actor_scope().await {
            Ok(scope) => scope,
            Err(error) => {
                if let Some(status) = unsupported_status(&error) {
                    tracing::warn!(
                        "principal-realm lookup for private account_data returned {status}; \
                         keeping local state authoritative"
                    );
                    return Ok(AccountDataSetResult::Unsupported { status });
                }
                return Err(error);
            }
        };
        let event = crate::account_data::build_private_account_data_set_with_cas(
            &principal_realm_id,
            &actor,
            type_key,
            encrypted_payload,
            expected_state_digest,
        )?
        .build_sdk_event("yougen-private-account-data")?;
        let result = self.submit_sdk_event(&event).await;
        match result {
            Ok(value) => Ok(AccountDataSetResult::Stored {
                response: serde_json::to_value(value)?,
            }),
            Err(error) => {
                if let Some(status) = unsupported_status(&error) {
                    tracing::warn!(
                        "ck.account_data.set submit for private {type_key} returned {status}; \
                         keeping local state authoritative"
                    );
                    return Ok(AccountDataSetResult::Unsupported { status });
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
                .build_sdk_event("yougen-account-data")?;
        match self.submit_sdk_event(&event).await {
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
        let body = cokret_sdk::models::IdentityResolveRequestBody {
            did: subject,
            requested_evidence_kinds: Vec::new(),
        };
        self.post_json("_cokret/root/identity/resolve", &body).await
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
            .unwrap_or_else(|| json!({"actor_id": did, "state": "offline"}));
        let state = presence
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("offline");
        Ok(json!({
            "actor": did,
            "display_name": did,
            "presence": {
                "state": state,
            },
        }))
    }

    async fn account_data_actor_scope(&self) -> anyhow::Result<(String, String)> {
        let account = self.account_me().await?;
        let principal = cokret_sdk::Did::new(account.did.clone())
            .map_err(|err| anyhow::anyhow!("invalid account DID `{}`: {err}", account.did))?;
        let realm_id = cokret_sdk::auth::principal_control_realm_id(&principal);
        Ok((account.did, realm_id.to_string()))
    }

    pub async fn sync_describe(&self) -> anyhow::Result<SyncDescribeView> {
        self.get_json("_cokret/self/account/describe").await
    }

    /// `ck.self.account.stream.subscribe` snapshot fold. The server returns NDJSON frames;
    /// this consumes EVERY frame of the response (merging catchup deltas and
    /// advancing the cursor to the last cursor-bearing frame per
    /// client-sync.md §2.2) and keeps the rest of the app on the existing
    /// folded `ClientSyncOutcome` projection path.
    pub async fn account_subscribe_snapshot(
        &self,
        after: Option<&str>,
    ) -> anyhow::Result<ClientSyncOutcome> {
        match self.account_subscribe_snapshot_outcome(after).await? {
            AccountSubscribeSnapshotResult::Delta(response) => Ok(*response),
            AccountSubscribeSnapshotResult::ReconnectAfter {
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
    ) -> anyhow::Result<AccountSubscribeSnapshotResult> {
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
    ) -> anyhow::Result<SubmitEventResult> {
        let event = build_read_cursor_advance_event(marker)?;
        self.submit_sdk_event(&event).await
    }

    pub async fn invites(&self) -> anyhow::Result<InvitesView> {
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

fn current_account_from_viewer(viewer: cokret_sdk::models::AccountView) -> CurrentAccount {
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
    CurrentAccount {
        did: viewer.principal_id.as_str().to_owned(),
        handle: primary_handle_from_viewer(&viewer),
        display_name,
        created_at,
    }
}

fn primary_handle_from_viewer(viewer: &cokret_sdk::models::AccountView) -> String {
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
        let viewer: cokret_sdk::models::AccountView = serde_json::from_value(json!({
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
        let viewer: cokret_sdk::models::AccountView = serde_json::from_value(json!({
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
