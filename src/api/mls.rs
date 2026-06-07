use super::*;

impl CokretApi {
    /// Publish an MLS `MlsKeyPackageRecord` to
    /// soland's `/_cokret/self/keys/upload` endpoint so peers can fetch it via
    /// `query_keys` and `add_member()` against it. Other key fields
    /// (one_time_keys / fallback_keys / device_signature) carry their
    /// default-test shape; soland tolerates them being placeholder when
    /// the only consumer is the MLS Welcome flow.
    #[cfg(feature = "demo-crypto")]
    pub async fn publish_mls_key_package(
        &self,
        device_id: &str,
        record: &cokret_sdk::MlsKeyPackageRecord,
    ) -> anyhow::Result<KeysUploadOutcome> {
        self.ensure_demo_crypto_fallback_allowed("keys/upload MLS demo device_signature")?;
        self.post_json(
            "_cokret/self/keys/upload",
            json!({
                "device_id": device_id,
                "one_time_keys": {
                    "signed_curve25519:yougen-otk-1": {
                        "key_id": "yougen-otk-1",
                        "key": "yougen-one-time"
                    }
                },
                "fallback_keys": {},
                "device_signature": {"alg": "EdDSA", "signature": "yougen-dev-signature"},
                "mls_key_packages": {
                    record.keypackage_id.clone(): serde_json::to_value(record)?,
                },
            }),
        )
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

    pub async fn rotate_mls_epoch(&self, mls_group_ref: &str) -> anyhow::Result<MlsRotateResponse> {
        self.post_json(
            "_cokret/self/mls/rotate",
            json!({"mls_group_ref": mls_group_ref}),
        )
        .await
    }

    // ── MIMI Provider Facade ─────────────────────────────────────

    pub async fn mimi_provider_directory(&self) -> anyhow::Result<MimiProviderDirectory> {
        self.get_json("_cokret/open/mimi/provider-directory").await
    }

    pub async fn mimi_key_material(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiKeyMaterialOutcome> {
        self.post_json("_cokret/open/mimi/key-material", request)
            .await
    }

    pub async fn mimi_room_update(
        &self,
        room_id: &str,
        request: Value,
    ) -> anyhow::Result<MimiRoomUpdateOutcome> {
        self.put_json(
            &format!("_cokret/open/mimi/flows/{room_id}/update"),
            request,
        )
        .await
    }

    pub async fn mimi_notify(
        &self,
        room_id: &str,
        request: Value,
    ) -> anyhow::Result<MimiNotifyOutcome> {
        self.post_json(
            &format!("_cokret/open/mimi/flows/{room_id}/notify"),
            request,
        )
        .await
    }

    pub async fn mimi_submit_message(
        &self,
        room_id: &str,
        request: Value,
    ) -> anyhow::Result<MimiSubmitMessageOutcome> {
        self.post_json(
            &format!("_cokret/open/mimi/flows/{room_id}/messages"),
            request,
        )
        .await
    }

    pub async fn mimi_group_info(&self, room_id: &str) -> anyhow::Result<MimiGroupInfoOutcome> {
        self.get_json(&format!("_cokret/open/mimi/flows/{room_id}/group-info"))
            .await
    }

    pub async fn mimi_request_consent(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiRequestConsentOutcome> {
        self.post_json("_cokret/open/mimi/consent/request", request)
            .await
    }

    pub async fn mimi_update_consent(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiRequestConsentOutcome> {
        self.post_json("_cokret/open/mimi/consent/update", request)
            .await
    }

    pub async fn mimi_identifier_query(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiIdentifierQueryOutcome> {
        self.post_json("_cokret/open/mimi/identifiers/query", request)
            .await
    }

    pub async fn mimi_report_abuse(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiReportAbuseOutcome> {
        self.post_json("_cokret/open/mimi/report-abuse", request)
            .await
    }

    pub async fn mimi_proxy_download(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiProxyDownloadOutcome> {
        self.post_json("_cokret/open/mimi/proxy-download", request)
            .await
    }
}
