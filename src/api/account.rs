use reqwest::StatusCode;

use super::*;
use crate::api_error::CokretApiError;
use crate::ephemeral::build_read_cursor_advance_event;

impl CokretApi {
    pub async fn describe(&self) -> anyhow::Result<ServerDescription> {
        self.sdk_http_client()?
            .describe()
            .await
            .map_err(|error| anyhow::anyhow!("server describe: {error}"))
    }

    pub async fn describe_cached(&self) -> anyhow::Result<&ServerDescription> {
        self.service_describe_cache
            .get_or_try_init(|| async { self.describe().await })
            .await
    }

    // ②(A+②): the Principal Server does not mint a second client-visible
    // credential. The held credential is the `ck.session.grant` itself,
    // presented per-request as
    // `Authorization: Bearer <grant>` + a `DPoP` proof (see
    // `CokretApi::with_bearer` / `with_dpop_device`).

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
        self.sdk_http_client()?
            .contacts_request(&body)
            .await
            .map_err(anyhow::Error::from)
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
            contact: crate::account_api::did_for_request_field("contact", peer)?,
            revoke_scopes: Vec::new(),
            full_peer_revoke: false,
            block_peer,
            peer_service_did: None,
        };
        self.sdk_http_client()?
            .contacts_tombstone(&body)
            .await
            .map_err(anyhow::Error::from)
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
            peer_did: crate::account_api::did_for_request_field("peer", peer)?,
            consent_scope: Some(scope.trim().to_owned()),
            expires_at,
        };
        let path = format!(
            "{}/{}/grant",
            cokret_sdk::http::PATH_SELF_CONSENT_CELLS,
            path_component(holder.trim()),
        );
        self.sdk_http_client()?
            .post(&path, &body)
            .await
            .map_err(anyhow::Error::from)
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
            peer_did: crate::account_api::did_for_request_field("peer", peer)?,
            consent_scope: Some(scope.trim().to_owned()),
            expires_at: None,
        };
        let path = format!(
            "{}/{}/revoke",
            cokret_sdk::http::PATH_SELF_CONSENT_CELLS,
            path_component(holder.trim()),
        );
        self.sdk_http_client()?
            .post(&path, &body)
            .await
            .map_err(anyhow::Error::from)
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
            holder_did: crate::account_api::did_for_request_field("holder", holder)?,
            peer_did: Some(crate::account_api::did_for_request_field("peer", peer)?),
            consent_scope: Some(scope.trim().to_owned()),
        };
        self.sdk_http_client()?
            .post(cokret_sdk::http::PATH_SELF_CONSENT_REQUEST, &body)
            .await
            .map_err(anyhow::Error::from)
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
                .build_sdk_event("inkson-account-data")?;
        let result = self.event_submitter()?.submit_sdk_event(&event).await;
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
        .build_sdk_event("inkson-private-account-data")?;
        let result = self.event_submitter()?.submit_sdk_event(&event).await;
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
                .build_sdk_event("inkson-account-data")?;
        match self.event_submitter()?.submit_sdk_event(&event).await {
            Ok(_) => Ok(()),
            Err(error) => {
                if unsupported_status(&error).is_some() {
                    return Ok(());
                }
                Err(error)
            }
        }
    }

    /// Submit a `did:webvh` DID operation (inception / rotation) to soland's
    /// embedded identity provider. Spec op
    /// `ck.root.identity.command.submit_did_operation`
    /// (`POST /_cokret/root/identity/submit-did-operation`). The body is the
    /// SDK-built `submit_body` from `cokret_sdk::webvh::prepare_inception`.
    pub async fn submit_did_operation(
        &self,
        body: &cokret_sdk::models::DidOperationSubmitRequestBody,
    ) -> anyhow::Result<cokret_sdk::models::DidOperationSubmitOutcome> {
        self.sdk_http_client()?
            .identity_submit_did_operation(body)
            .await
            .map_err(anyhow::Error::from)
    }

    async fn account_data_actor_scope(&self) -> anyhow::Result<(String, String)> {
        let account = crate::account_api::account_me(&self.sdk_http_client()?).await?;
        let principal = cokret_sdk::Did::new(account.did.clone())
            .map_err(|err| anyhow::anyhow!("invalid account DID `{}`: {err}", account.did))?;
        let realm_id = cokret_sdk::auth::principal_control_realm_id(&principal);
        Ok((account.did, realm_id.to_string()))
    }

    pub async fn submit_read_cursor_advance(
        &self,
        marker: &crate::local_state::ReadMarkerRecord,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = build_read_cursor_advance_event(marker)?;
        self.event_submitter()?.submit_sdk_event(&event).await
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
