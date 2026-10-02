#[derive(Clone)]
pub struct EndpointClients {
    transport: super::TransportClient,
}

impl EndpointClients {
    pub fn new(transport: super::TransportClient) -> Self {
        Self { transport }
    }

    pub(crate) fn from_http(http: arkret_sdk::http_client::Client) -> Self {
        Self::new(super::TransportClient::from_http(
            http,
            super::RequestContext::new(""),
        ))
    }

    pub fn account(&self) -> AccountEndpoints<'_> {
        AccountEndpoints {
            transport: &self.transport,
        }
    }

    pub fn mls(&self) -> MlsEndpoints<'_> {
        MlsEndpoints {
            transport: &self.transport,
        }
    }

    pub fn blob(&self) -> super::BlobEndpoints<'_> {
        super::BlobEndpoints::new(&self.transport)
    }

    pub fn keys(&self) -> KeysEndpoints<'_> {
        KeysEndpoints {
            transport: &self.transport,
        }
    }

    pub fn media(&self) -> super::MediaEndpoints<'_> {
        super::MediaEndpoints::new(&self.transport)
    }
}

pub struct MlsEndpoints<'a> {
    transport: &'a super::TransportClient,
}

pub struct KeysEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl KeysEndpoints<'_> {
    pub async fn receive_device_messages(
        &self,
    ) -> anyhow::Result<crate::models::DeviceMessagesGetOutcome> {
        self.receive_device_messages_page(None, None).await
    }

    pub async fn receive_device_messages_page(
        &self,
        from: Option<&str>,
        limit: Option<u32>,
    ) -> anyhow::Result<crate::models::DeviceMessagesGetOutcome> {
        let from = from.map(str::trim).filter(|value| !value.is_empty());
        self.transport
            .http()
            .receive_device_messages(from, limit)
            .await
            .map_err(|error| anyhow::anyhow!("receive device messages: {error}"))
    }

    pub async fn ack_device_messages(
        &self,
        ack_token: &str,
    ) -> anyhow::Result<crate::models::DeviceMessagesAckOutcome> {
        let body = crate::models::DeviceMessagesAckRequestBody {
            ack_token: ack_token.to_owned(),
        };
        self.transport
            .http()
            .ack_device_messages(&body)
            .await
            .map_err(|error| anyhow::anyhow!("ack device messages: {error}"))
    }

    /// Resolve a scanned/pasted pairing token into the staged bootstrap
    /// (`ak.open.device_pairing.read.resolve.v1`).
    pub async fn device_pairing_resolve(
        &self,
        body: &arkret_sdk::DevicePairingResolveRequestBody,
    ) -> anyhow::Result<arkret_sdk::DevicePairingBootstrap> {
        self.transport
            .http()
            .device_pairing_resolve(body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Claim a typed-in eight-character pairing code
    /// (`ak.gate.account.read.claim_device_pairing_code.v1`). The caller's own
    /// accepted-device session supplies the account, so this is the typed
    /// sibling of the short-link resolve rather than a weaker code-only
    /// authorization branch: it returns the same bootstrap plus the target
    /// proof the short link carries out of band, and grants nothing.
    pub async fn device_pairing_claim_code(
        &self,
        body: &arkret_sdk::DevicePairingCodeClaimRequestBody,
    ) -> anyhow::Result<arkret_sdk::DevicePairingCodeClaimOutcome> {
        self.transport
            .http()
            .device_pairing_claim_code(body)
            .await
            .map_err(anyhow::Error::from)
    }
}

impl MlsEndpoints<'_> {
    /// Read exact accepted Genesis public bytes through this member's Account
    /// Station. Callers must independently verify the Genesis/target cut and
    /// roster proof before installing any MLS leaf binding.
    pub async fn member_group_state_material(
        &self,
        request: &arkret_sdk::MlsMemberGroupStateMaterialReadRequestBody,
    ) -> anyhow::Result<arkret_sdk::ValidatedMlsGroupStateMaterial> {
        let outcome = self
            .transport
            .http()
            .self_mls_group_state_material(request)
            .await
            .map_err(anyhow::Error::from)?;
        outcome
            .validate_for_request(&request.as_peer_request())
            .map_err(anyhow::Error::from)
    }

    /// Fetch one unverified historical roster page from this member's Account
    /// Station. The caller must verify the complete signed page set, each
    /// attestor and the RFC public tree before binding any MLS leaf.
    pub async fn unverified_member_roster_authority_page(
        &self,
        request: &arkret_sdk::MlsRosterAuthorityReadRequestBody,
    ) -> anyhow::Result<arkret_sdk::MlsRosterAuthorityReadOutcome> {
        request.validate().map_err(anyhow::Error::from)?;
        let page = self
            .transport
            .http()
            .self_mls_roster_authority(request)
            .await
            .map_err(anyhow::Error::from)?;
        page.manifest
            .validate_for_request(request)
            .map_err(anyhow::Error::from)?;
        Ok(page)
    }

    /// Follow the opaque cursor to collect the complete unverified roster.
    /// The caller must verify the signed manifest, all pages, Add attestations
    /// and public MLS tree before using any record as a leaf authority.
    pub async fn unverified_member_roster_authority_pages(
        &self,
        request: &arkret_sdk::MlsRosterAuthorityReadRequestBody,
    ) -> anyhow::Result<Vec<arkret_sdk::MlsRosterAuthorityReadOutcome>> {
        let mut next_request = request.clone();
        let mut seen_cursors = std::collections::HashSet::new();
        let mut pages = Vec::new();
        loop {
            let page = self
                .unverified_member_roster_authority_page(&next_request)
                .await?;
            let page_number = u64::try_from(pages.len())?;
            if page.page_index != page_number
                || page_number >= page.manifest.page_count
                || pages
                    .first()
                    .is_some_and(|first: &arkret_sdk::MlsRosterAuthorityReadOutcome| {
                        first.manifest.page_count != page.manifest.page_count
                    })
            {
                anyhow::bail!("MLS roster page order or count is inconsistent");
            }
            let page_count = page.manifest.page_count;
            let next_cursor = page.next_cursor.clone();
            pages.push(page);
            match next_cursor {
                Some(cursor) if u64::try_from(pages.len())? < page_count => {
                    if !seen_cursors.insert(cursor.clone()) {
                        anyhow::bail!("MLS roster cursor repeats");
                    }
                    next_request.cursor = Some(cursor);
                }
                None if u64::try_from(pages.len())? == page_count => return Ok(pages),
                _ => anyhow::bail!("MLS roster pagination is incomplete"),
            }
        }
    }

    pub async fn publish_key_packages(
        &self,
        device_id: &str,
        records: &[arkret_sdk::MlsKeyPackageRecord],
    ) -> anyhow::Result<arkret_sdk::KeyPackagesUploadOutcome> {
        let signer = crate::event_signer::active_signer().ok_or_else(|| {
            anyhow::anyhow!(
                "keypackages/upload endpoint_signature requires an active event-signer (fail-closed)"
            )
        })?;
        let first = records
            .first()
            .ok_or_else(|| anyhow::anyhow!("KeyPackage upload batch is empty"))?;
        let requested_device_id = arkret_sdk::DeviceId::new(device_id.trim().to_owned())?;
        let (principal_id, device_id) = match &first.endpoint {
            arkret_sdk::MlsEndpointIdentity::HumanDevice {
                principal_id,
                device_id,
            } if device_id == &requested_device_id => (principal_id.clone(), device_id.clone()),
            arkret_sdk::MlsEndpointIdentity::HumanDevice { .. } => {
                anyhow::bail!("KeyPackage endpoint device differs from upload signer device")
            }
            arkret_sdk::MlsEndpointIdentity::AgentRuntime { .. } => {
                anyhow::bail!("Agent KeyPackage requires the agent-authorized upload flow")
            }
            arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => anyhow::bail!(
                "minimal-metadata KeyPackage upload requires publish_pairwise_key_package"
            ),
        };
        if records
            .iter()
            .any(|record| record.endpoint != first.endpoint || record.actor_id != first.actor_id)
        {
            anyhow::bail!("KeyPackage upload batch mixes endpoint identities");
        }
        let keypackages = records
            .iter()
            .map(crate::mls_api_helpers::mls_key_package_record_upload_entry)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let unsigned = arkret_sdk::KeyPackagesUploadUnsignedRequest {
            actor_id: first.actor_id.clone(),
            principal_id,
            device_id: Some(device_id),
            pairwise_verification_method: None,
            intended_realm_id: None,
            agent_verification_method: None,
            agent_key_authorize_event_id: None,
            keypackages,
            expires_at: None,
            strand_id: None,
            mls_group_id: None,
        };
        let endpoint_signature =
            crate::mls_api_helpers::sign_keypackage_upload_batch_with_signer(&signer, &unsigned)?;
        let body = unsigned.into_signed(endpoint_signature);
        self.transport
            .http()
            .keypackages_upload(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn revoke_key_packages(
        &self,
        device_id: &arkret_sdk::DeviceId,
        key_package_refs: Vec<String>,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesRevokeOutcome> {
        if key_package_refs.is_empty() {
            anyhow::bail!("KeyPackage revoke batch is empty");
        }
        let unsigned = arkret_sdk::KeyPackagesRevokeUnsignedRequest {
            key_package_refs,
            device_id: device_id.clone(),
            reason: None,
        };
        let signature = crate::mls_api_helpers::sign_keypackage_revoke_batch(&unsigned)?;
        self.transport
            .http()
            .keypackages_revoke(&unsigned.into_signed(signature))
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn consume_key_package(
        &self,
        request: &arkret_sdk::KeyPackagesConsumeRequestBody,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesConsumeOutcome> {
        request.validate_shape().map_err(anyhow::Error::msg)?;
        self.transport
            .http()
            .keypackages_consume(request)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Read the exact outcome of the claim a Welcome names from this
    /// endpoint's own Account Station (`ak.self.keys.keypackages.read.claim.v1`)
    /// and verify its receipt before anything is decrypted
    /// (device-lifecycle.md §9 `claims/query`). The receipt must be this
    /// Station's own, signed under its service key effective at `claimed_at`.
    pub async fn own_key_package_claim(
        &self,
        claim_id: &arkret_wire::KeypackageClaimId,
    ) -> anyhow::Result<(arkret_sdk::KeyPackagesClaimOutcome, arkret_sdk::DidCoreId)> {
        let station = self.transport.describe_cached().await?.service_id.clone();
        let outcome = self
            .transport
            .http()
            .keypackages_claim_query(&arkret_sdk::KeyPackagesClaimQueryRequestBody {
                claim_id: claim_id.clone(),
            })
            .await
            .map_err(anyhow::Error::from)?;
        outcome
            .validate_shape()
            .map_err(|error| anyhow::anyhow!("KeyPackage claim outcome is invalid: {error}"))?;
        let receipt = &outcome.claim_receipt;
        if receipt.destination_id != station {
            anyhow::bail!("KeyPackage claim receipt is not this Station's own");
        }
        let resolution = self
            .transport
            .http()
            .open_service_resolution(&receipt.destination_id)
            .await
            .map_err(anyhow::Error::from)?;
        arkret_sdk::verify_peer_keypackage_claim_receipt_signature(receipt, &resolution).map_err(
            |error| anyhow::anyhow!("KeyPackage claim receipt signature is invalid: {error}"),
        )?;
        Ok((outcome, station))
    }

    pub async fn claim_key_package(
        &self,
        target_principal_id: &str,
        intended_realm_id: &str,
        requester: &str,
        requester_device_id: &str,
        destination_id: Option<&str>,
        claim_request_id: &str,
        target_device_id: Option<&str>,
        mls_group_id: &str,
        target_agent: Option<&arkret_sdk::MlsEndpointIdentity>,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesClaimOutcome> {
        let destination_id = destination_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "KeyPackage claim requires the destination Station from the accepted invitee AccountId"
                )
            })?;
        let source_id = self.transport.describe_cached().await?.service_id.clone();
        let requester_device_authorize_event_id =
            crate::mls::admission::current_requester_device_authorize_event_id(
                self.transport.http(),
                requester_device_id,
            )
            .await
            .map_err(anyhow::Error::msg)?;
        let body = crate::mls_api_helpers::build_mls_keypackage_claim_request(
            target_principal_id,
            intended_realm_id,
            requester,
            requester_device_id,
            &requester_device_authorize_event_id,
            source_id.as_str(),
            destination_id,
            claim_request_id,
            target_device_id,
            mls_group_id,
            target_agent,
        )?;
        let expected_request = body.unsigned_request();
        let expected_service_binding = body.service_binding.clone();
        let expected_request_digest =
            arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(&body)?)?;
        // A remote claim is relayed durably. Replay the exact frozen body
        // until its result arrives; re-signing or minting a new request would
        // reserve a different KeyPackage on every retry.
        let deadline = crate::clock::now_utc() + chrono::Duration::seconds(30);
        let outcome = loop {
            match self.transport.http().keypackages_claim(&body).await {
                Ok(outcome) => break outcome,
                Err(error)
                    if source_id.as_str() != destination_id
                        && error.error_code()
                            == Some(arkret_sdk::ErrorCode::FailedPrecondition)
                        && crate::clock::now_utc() < deadline =>
                {
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(500)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        outcome
            .validate_shape()
            .map_err(|error| anyhow::anyhow!("KeyPackage claim outcome is invalid: {error}"))?;
        let receipt = &outcome.claim_receipt;
        if receipt.request != expected_request
            || receipt.source_id != expected_service_binding.source_id
            || receipt.destination_id != expected_service_binding.destination_id
            || receipt.request_digest != expected_request_digest
            || receipt.expires_at <= chrono::Utc::now()
        {
            anyhow::bail!(
                "KeyPackage claim receipt does not bind the exact authorized request and service route"
            );
        }
        let destination_resolution = if receipt.destination_id == source_id {
            self.transport
                .http()
                .open_service_resolution(&receipt.destination_id)
                .await?
        } else {
            // The receipt's method is only a DID locator. Its native history
            // and exact service identity supply the key independently.
            let did = arkret_sdk::verification_method_did(receipt.signature.kid.as_str())?;
            crate::media::service_route::authenticated_candidate_from_did(
                &reqwest::Client::new(),
                &receipt.destination_id,
                "station",
                &did,
                crate::clock::now_utc(),
            )
            .await?
            .resolution
        };
        arkret_sdk::verify_peer_keypackage_claim_receipt_signature(
            receipt,
            &destination_resolution,
        )
        .map_err(|error| {
            anyhow::anyhow!("KeyPackage claim receipt signature is invalid: {error}")
        })?;
        Ok(outcome)
    }
}

pub struct AccountEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl AccountEndpoints<'_> {
    pub async fn viewer(
        &self,
    ) -> anyhow::Result<arkret_models_collaboration::account_operations::AccountView> {
        crate::transport::account::account_viewer(self.transport.http()).await
    }

    pub async fn contacts(&self) -> anyhow::Result<crate::models::ContactList> {
        crate::transport::account::contacts(self.transport.http()).await
    }
}
