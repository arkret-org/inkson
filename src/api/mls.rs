use super::*;

impl CokretApi {
    /// Publish an MLS `MlsKeyPackageRecord` to
    /// soland's `/_cokret/self/keys/upload` endpoint so peers can fetch it via
    /// `query_keys` and `add_member()` against it. Other key fields
    /// (one_time_keys / fallback_keys / device_signature) carry their
    /// default-test shape; soland tolerates them being placeholder when
    /// the only consumer is the MLS Welcome strand.
    #[cfg(feature = "demo-crypto")]
    pub async fn publish_mls_key_package(
        &self,
        device_id: &str,
        record: &cokret_sdk::MlsKeyPackageRecord,
    ) -> anyhow::Result<cokret_sdk::KeyPackagesUploadOutcome> {
        self.ensure_demo_crypto_fallback_allowed("keys/upload MLS demo device_signature")?;
        let body = cokret_sdk::KeyPackagesUploadRequestBody {
            principal_id: record.principal_id.clone(),
            device_id: cokret_sdk::DeviceId::new(device_id.trim().to_owned())?,
            key_packages: vec![serde_json::to_value(record)?],
            device_signature: json!({"alg": "EdDSA", "signature": "yougen-dev-signature"}),
            expires_at: None,
            strand_id: None,
            mls_group_id: None,
        };
        self.post_json("_cokret/self/keys/keypackages/upload", &body)
            .await
    }

    #[cfg(not(feature = "demo-crypto"))]
    pub async fn publish_mls_key_package(
        &self,
        _device_id: &str,
        _record: &cokret_sdk::MlsKeyPackageRecord,
    ) -> anyhow::Result<KeysUploadOutcome> {
        anyhow::bail!(
            "publish_mls_key_package ships a dev `device_signature` placeholder and requires the `demo-crypto` build feature"
        )
    }

    /// Fetch a peer's MLS key package via
    /// `query_keys`, decoding the most recent `mls_key_packages` entry
    /// into a typed `MlsKeyPackageRecord`. Returns `Ok(None)` when the
    /// device exists but has no MLS key package on file (in which case
    /// the caller should fall back to a non-MLS path or ask the peer to
    /// publish).
    pub async fn fetch_mls_key_package(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<Option<cokret_sdk::MlsKeyPackageRecord>> {
        let resp = self.query_keys(actor, device_id).await?;
        // SDK `KeysQueryOutcome::device_keys` is a typed
        // `BTreeMap<Did, BTreeMap<DeviceId, Value>>`; the keys are newtype
        // identifiers, so match them by their string form rather than a
        // borrow-keyed `BTreeMap::get`.
        let packages = resp
            .device_keys
            .iter()
            .find(|(did, _)| did.as_str() == actor)
            .and_then(|(_, actor_map)| actor_map.iter().find(|(dev, _)| dev.as_str() == device_id))
            .and_then(|(_, device_value)| device_value.get("mls_key_packages"));
        let Some(packages) = packages else {
            return Ok(None);
        };
        let map = match packages.as_object() {
            Some(m) => m,
            None => return Ok(None),
        };
        let Some((_, value)) = map.iter().next() else {
            return Ok(None);
        };
        let record: cokret_sdk::MlsKeyPackageRecord = serde_json::from_value(value.clone())?;
        Ok(Some(record))
    }

    // YOU-01-009: the former `rotate_mls_epoch` helper (non-spec
    // `POST /_cokret/self/mls/rotate` shim) was removed — epoch rotation
    // is carried by the canonical `ck.mls.commit` event built from a
    // local `self_update_commit`
    // (`crate::mls::runtime::force_epoch_rotation_commit`).

    // ── MIMI Provider Facade ─────────────────────────────────────

    pub async fn mimi_provider_directory(
        &self,
    ) -> anyhow::Result<cokret_sdk::MimiProviderDirectory> {
        self.get_json("_cokret/open/mimi/provider-directory").await
    }

    pub async fn mimi_key_material(
        &self,
        request: &cokret_sdk::MimiKeyMaterialRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiKeyMaterialOutcome> {
        self.post_json("_cokret/open/mimi/key-material", request)
            .await
    }

    pub async fn mimi_room_update(
        &self,
        room_id: &str,
        request: &cokret_sdk::MimiRoomUpdateRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiRoomUpdateOutcome> {
        self.put_json(
            &format!("_cokret/open/mimi/strands/{room_id}/update"),
            request,
        )
        .await
    }

    pub async fn mimi_notify(
        &self,
        room_id: &str,
        request: &cokret_sdk::MimiNotifyRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiNotifyOutcome> {
        self.post_json(
            &format!("_cokret/open/mimi/strands/{room_id}/notify"),
            request,
        )
        .await
    }

    pub async fn mimi_submit_message(
        &self,
        room_id: &str,
        request: &cokret_sdk::MimiSubmitMessageRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiSubmitMessageOutcome> {
        self.post_json(
            &format!("_cokret/open/mimi/strands/{room_id}/messages"),
            request,
        )
        .await
    }

    pub async fn mimi_group_info(
        &self,
        room_id: &str,
    ) -> anyhow::Result<cokret_sdk::MimiGroupInfoOutcome> {
        self.get_json(&format!("_cokret/open/mimi/strands/{room_id}/group-info"))
            .await
    }

    pub async fn mimi_request_consent(
        &self,
        request: &cokret_sdk::MimiRequestConsentRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiRequestConsentOutcome> {
        self.post_json("_cokret/open/mimi/consent/request", request)
            .await
    }

    pub async fn mimi_update_consent(
        &self,
        request: &cokret_sdk::MimiUpdateConsentRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiUpdateConsentOutcome> {
        self.post_json("_cokret/open/mimi/consent/update", request)
            .await
    }

    pub async fn mimi_identifier_query(
        &self,
        request: &cokret_sdk::MimiIdentifierQueryRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiIdentifierQueryOutcome> {
        self.post_json("_cokret/open/mimi/identifiers/query", request)
            .await
    }

    pub async fn mimi_report_abuse(
        &self,
        request: &cokret_sdk::MimiReportAbuseRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiReportAbuseOutcome> {
        self.post_json("_cokret/open/mimi/report-abuse", request)
            .await
    }

    pub async fn mimi_proxy_download(
        &self,
        request: &cokret_sdk::MimiProxyDownloadRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiProxyDownloadOutcome> {
        self.post_json("_cokret/open/mimi/proxy-download", request)
            .await
    }
}
