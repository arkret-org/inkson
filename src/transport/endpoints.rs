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

    pub fn directory(&self) -> DirectoryEndpoints<'_> {
        DirectoryEndpoints {
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

    pub async fn account_device_pair(
        &self,
        body: &arkret_sdk::AccountDevicePairRequestBody,
    ) -> anyhow::Result<arkret_sdk::AccountDevicePairOutcome> {
        self.transport
            .http()
            .account_device_pair(body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Stage a new device's key server-side, returning the short pairing handle
    /// + code (`ak.open.device_pairing.command.stage`).
    pub async fn device_pairing_stage(
        &self,
        body: &arkret_sdk::DevicePairingStageRequestBody,
    ) -> anyhow::Result<arkret_sdk::DevicePairingStageOutcome> {
        self.transport
            .http()
            .device_pairing_stage(body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Resolve a scanned/pasted pairing token into the staged bootstrap
    /// (`ak.open.device_pairing.read.resolve`).
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

    /// Poll whether a staged pairing request has been authorized
    /// (`ak.open.device_pairing.read.status`).
    pub async fn device_pairing_status(
        &self,
        body: &arkret_sdk::DevicePairingStatusRequestBody,
    ) -> anyhow::Result<arkret_sdk::DevicePairingStatusOutcome> {
        self.transport
            .http()
            .device_pairing_status(body)
            .await
            .map_err(anyhow::Error::from)
    }
}

impl MlsEndpoints<'_> {
    pub async fn publish_key_package(
        &self,
        device_id: &str,
        record: &arkret_sdk::MlsKeyPackageRecord,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesUploadOutcome> {
        let requested_device_id = arkret_sdk::DeviceId::new(device_id.trim().to_owned())?;
        let (principal_id, device_id) = match &record.endpoint {
            arkret_sdk::MlsEndpointIdentity::HumanDevice {
                principal_id,
                device_id,
            } if device_id == &requested_device_id => (principal_id.clone(), device_id.clone()),
            arkret_sdk::MlsEndpointIdentity::HumanDevice { .. } => {
                anyhow::bail!("KeyPackage endpoint device differs from upload signer device")
            }
            arkret_sdk::MlsEndpointIdentity::NativeAgentRuntime { .. } => {
                anyhow::bail!("Native Agent KeyPackage requires the agent-authorized upload flow")
            }
        };
        let entry = crate::mls_api_helpers::mls_key_package_record_upload_entry(record)?;
        let unsigned = arkret_sdk::KeyPackagesUploadUnsignedRequest {
            principal_id,
            device_id,
            keypackages: vec![entry],
            expires_at: None,
            strand_id: None,
            mls_group_id: None,
        };
        let device_signature = crate::mls_api_helpers::sign_keypackage_upload_batch(&unsigned)?;
        let body = unsigned.into_signed(device_signature);
        self.transport
            .http()
            .keypackages_upload(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn consume_key_package(
        &self,
        _candidate: &crate::mls::runtime::WelcomeConsumeCandidate,
        _consumer_device_id: &str,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesConsumeOutcome> {
        anyhow::bail!(
            "KeyPackage consume is unavailable because the accepted Welcome projection does not expose the required recipient durable receipt"
        )
    }

    pub async fn claim_key_package(
        &self,
        target_principal_id: &str,
        intended_realm_id: &str,
        requester: &str,
        requester_device_id: &str,
        destination_service_id: Option<&str>,
        claim_nonce: &str,
        target_device_id: Option<&str>,
        mls_group_id: &str,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesClaimOutcome> {
        let destination_service_id = destination_service_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "KeyPackage claim requires the destination service DID from the accepted invite delivery binding"
                )
            })?;
        let source_service_id = self.transport.describe_cached().await?.service_id.clone();
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
            source_service_id.as_str(),
            destination_service_id,
            claim_nonce,
            target_device_id,
            mls_group_id,
        )?;
        let expected_request = body.unsigned_request();
        let expected_service_binding = body.service_binding.clone();
        let expected_request_digest =
            arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(&body)?)?;
        let outcome = self
            .transport
            .http()
            .keypackages_claim(&body)
            .await
            .map_err(anyhow::Error::from)?;
        outcome
            .validate_shape()
            .map_err(|error| anyhow::anyhow!("KeyPackage claim outcome is invalid: {error}"))?;
        let receipt = &outcome.claim_receipt;
        if receipt.request != expected_request
            || receipt.source_service_id != expected_service_binding.source_service_id
            || receipt.destination_service_id != expected_service_binding.destination_service_id
            || receipt.request_digest != expected_request_digest
        {
            anyhow::bail!(
                "KeyPackage claim receipt does not bind the exact authorized request and service route"
            );
        }
        Ok(outcome)
    }
}

pub struct AccountEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl AccountEndpoints<'_> {
    pub async fn viewer(
        &self,
    ) -> anyhow::Result<arkret_models_collaboration::account_lifecycle::AccountView> {
        crate::transport::account::account_viewer(self.transport.http()).await
    }

    pub async fn contacts(&self) -> anyhow::Result<crate::models::ContactListView> {
        crate::transport::account::contacts(self.transport.http()).await
    }
}

pub struct DirectoryEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl DirectoryEndpoints<'_> {
    pub async fn snapshot_head(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<arkret_sdk::SnapshotManifest>> {
        let describe = self.transport.describe_cached().await?;
        if !crate::models::service_supports_operation(
            describe,
            arkret_sdk::ServiceOperationId::SELF_SNAPSHOT_READ_MANIFEST_HEAD,
        ) {
            return Ok(None);
        }
        match self.transport.http().snapshot_head(realm_id).await {
            Ok(manifest) => Ok(Some(manifest)),
            Err(error) => {
                let error = anyhow::Error::from(error);
                if crate::api_error::is_snapshot_unavailable_error(&error) {
                    Ok(None)
                } else {
                    Err(error)
                }
            }
        }
    }

    pub async fn list_handles_for_subject(
        &self,
        subject: &str,
        realm_id: Option<&str>,
        intent: Option<arkret_models_discovery::DirectoryIntent>,
    ) -> anyhow::Result<arkret_models_discovery::DirectorySubjectHandleList> {
        super::directory::list_handles_for_subject(self.transport.http(), subject, realm_id, intent)
            .await
    }
}
