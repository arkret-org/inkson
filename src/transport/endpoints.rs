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
}

impl MlsEndpoints<'_> {
    pub async fn publish_key_package(
        &self,
        device_id: &str,
        record: &arkret_sdk::MlsKeyPackageRecord,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesUploadOutcome> {
        let device_id = device_id.trim();
        let entry = crate::mls_api_helpers::mls_key_package_record_upload_entry(record)?;
        let key_package_values = vec![serde_json::to_value(&entry)?];
        let device_signature =
            crate::mls_api_helpers::sign_keypackage_upload_batch(device_id, &key_package_values)?;
        let body = arkret_sdk::KeyPackagesUploadRequestBody {
            principal_id: record.principal_id.clone(),
            device_id: arkret_sdk::DeviceId::new(device_id.to_owned())?,
            key_packages: vec![entry],
            device_signature,
            expires_at: None,
            strand_id: None,
            mls_group_id: None,
        };
        self.transport
            .http()
            .keypackages_upload(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn claim_key_package(
        &self,
        target_principal_id: &str,
        intended_realm_id: &str,
        requester: &str,
        claim_nonce: &str,
        target_device_id: Option<&str>,
        mls_group_id: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesClaimOutcome> {
        let body = crate::mls_api_helpers::build_mls_keypackage_claim_request(
            target_principal_id,
            intended_realm_id,
            requester,
            claim_nonce,
            target_device_id,
            mls_group_id,
        )?;
        self.transport
            .http()
            .keypackages_claim(&body)
            .await
            .map_err(anyhow::Error::from)
    }
}

pub struct AccountEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl AccountEndpoints<'_> {
    pub async fn viewer(&self) -> anyhow::Result<arkret_sdk::models::AccountView> {
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
        if !crate::models::service_supports_operation(&describe, crate::models::OP_SNAPSHOT_HEAD) {
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
        intent: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::models::DirectorySubjectHandleList> {
        super::directory::list_handles_for_subject(self.transport.http(), subject, realm_id, intent)
            .await
    }
}
