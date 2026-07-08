use super::*;
use crate::mls_api_helpers::{
    build_mls_keypackage_claim_request, mls_key_package_record_upload_entry,
    sign_keypackage_upload_batch,
};

impl CokretApi {
    /// Publish an MLS `MlsKeyPackageRecord` to
    /// soland's `/_cokret/self/keys/keypackages/upload` endpoint so peers can
    /// fetch it via `query_keys` and `add_member()` against it. The
    /// `device_signature` is a real EdDSA signature produced by the local
    /// event-signer over the published KeyPackage batch (no placeholder).
    pub async fn publish_mls_key_package(
        &self,
        device_id: &str,
        record: &cokret_sdk::MlsKeyPackageRecord,
    ) -> anyhow::Result<cokret_sdk::KeyPackagesUploadOutcome> {
        let device_id = device_id.trim();
        let entry = mls_key_package_record_upload_entry(record)?;
        // The signing input covers the exact serialized wire entries so the
        // server can recompute it from the received body.
        let key_package_values = vec![serde_json::to_value(&entry)?];
        let device_signature = sign_keypackage_upload_batch(device_id, &key_package_values)?;
        let body = cokret_sdk::KeyPackagesUploadRequestBody {
            principal_id: record.principal_id.clone(),
            device_id: cokret_sdk::DeviceId::new(device_id.to_owned())?,
            key_packages: vec![entry],
            device_signature,
            expires_at: None,
            strand_id: None,
            mls_group_id: None,
        };
        self.sdk_http_client()?
            .keypackages_upload(&body)
            .await
            .map_err(anyhow::Error::from)
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
        // SDK `KeysQueryOutcome::device_keys` is now a typed
        // `BTreeMap<Did, BTreeMap<DeviceId, QueryDeviceRecord>>`; the prekey /
        // keypackage bundle lives under `record.algorithms`. Match the newtype
        // identifier keys by their string form rather than a borrow-keyed
        // `BTreeMap::get`.
        let packages = resp
            .device_keys
            .iter()
            .find(|(did, _)| did.as_str() == actor)
            .and_then(|(_, actor_map)| actor_map.iter().find(|(dev, _)| dev.as_str() == device_id))
            .and_then(|(_, record)| record.algorithms.get("mls_key_packages"));
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

    pub async fn claim_mls_key_package(
        &self,
        target_principal_id: &str,
        intended_realm_id: &str,
        requester: &str,
        claim_nonce: &str,
        target_device_id: Option<&str>,
        mls_group_id: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::KeyPackagesClaimOutcome> {
        let body = build_mls_keypackage_claim_request(
            target_principal_id,
            intended_realm_id,
            requester,
            claim_nonce,
            target_device_id,
            mls_group_id,
        )?;
        self.sdk_http_client()?
            .keypackages_claim(&body)
            .await
            .map_err(anyhow::Error::from)
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
        self.sdk_http_client()?
            .mimi_provider_directory(None, &[])
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_key_material(
        &self,
        request: &cokret_sdk::MimiKeyMaterialRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiKeyMaterialOutcome> {
        self.sdk_http_client()?
            .post("/_cokret/open/mimi/key-material", request)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_room_update(
        &self,
        room_id: &str,
        request: &cokret_sdk::MimiRoomUpdateRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiRoomUpdateOutcome> {
        self.sdk_http_client()?
            .post(
                &format!("/_cokret/open/mimi/strands/{room_id}/update"),
                request,
            )
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_notify(
        &self,
        room_id: &str,
        request: &cokret_sdk::MimiNotifyRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiNotifyOutcome> {
        self.sdk_http_client()?
            .post(
                &format!("/_cokret/open/mimi/strands/{room_id}/notify"),
                request,
            )
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_submit_message(
        &self,
        room_id: &str,
        request: &cokret_sdk::MimiSubmitMessageRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiSubmitMessageOutcome> {
        self.sdk_http_client()?
            .post(
                &format!("/_cokret/open/mimi/strands/{room_id}/messages"),
                request,
            )
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_group_info(
        &self,
        room_id: &str,
    ) -> anyhow::Result<cokret_sdk::MimiGroupInfoOutcome> {
        self.sdk_http_client()?
            .get(&format!("/_cokret/open/mimi/strands/{room_id}/group-info"))
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_request_consent(
        &self,
        request: &cokret_sdk::MimiRequestConsentRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiRequestConsentOutcome> {
        self.sdk_http_client()?
            .post("/_cokret/open/mimi/consent/request", request)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_update_consent(
        &self,
        request: &cokret_sdk::MimiUpdateConsentRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiUpdateConsentOutcome> {
        self.sdk_http_client()?
            .post("/_cokret/open/mimi/consent/update", request)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_identifier_query(
        &self,
        request: &cokret_sdk::MimiIdentifierQueryRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiIdentifierQueryOutcome> {
        self.sdk_http_client()?
            .post("/_cokret/open/mimi/identifiers/query", request)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_report_abuse(
        &self,
        request: &cokret_sdk::MimiReportAbuseRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiReportAbuseOutcome> {
        self.sdk_http_client()?
            .mimi_report_abuse(request)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn mimi_proxy_download(
        &self,
        request: &cokret_sdk::MimiProxyDownloadRequestBody,
    ) -> anyhow::Result<cokret_sdk::MimiProxyDownloadOutcome> {
        self.sdk_http_client()?
            .post("/_cokret/open/mimi/proxy-download", request)
            .await
            .map_err(anyhow::Error::from)
    }
}
