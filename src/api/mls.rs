use super::*;
use crate::mls_api_helpers::{
    build_mls_keypackage_claim_request, mls_key_package_record_upload_entry,
    sign_keypackage_upload_batch,
};

impl ArkretApi {
    /// Publish an MLS `MlsKeyPackageRecord` to
    /// soland's `/_arkret/self/keys/keypackages/upload` endpoint so peers can
    /// fetch it via `query_keys` and `add_member()` against it. The
    /// `device_signature` is a real EdDSA signature produced by the local
    /// event-signer over the published KeyPackage batch (no placeholder).
    pub async fn publish_mls_key_package(
        &self,
        device_id: &str,
        record: &arkret_sdk::MlsKeyPackageRecord,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesUploadOutcome> {
        let device_id = device_id.trim();
        let entry = mls_key_package_record_upload_entry(record)?;
        // The signing input covers the exact serialized wire entries so the
        // server can recompute it from the received body.
        let key_package_values = vec![serde_json::to_value(&entry)?];
        let device_signature = sign_keypackage_upload_batch(device_id, &key_package_values)?;
        let body = arkret_sdk::KeyPackagesUploadRequestBody {
            principal_id: record.principal_id.clone(),
            device_id: arkret_sdk::DeviceId::new(device_id.to_owned())?,
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

    pub async fn claim_mls_key_package(
        &self,
        target_principal_id: &str,
        intended_realm_id: &str,
        requester: &str,
        claim_nonce: &str,
        target_device_id: Option<&str>,
        mls_group_id: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::KeyPackagesClaimOutcome> {
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
    // `POST /_arkret/self/mls/rotate` shim) was removed — epoch rotation
    // is carried by the canonical `ak.mls.commit` event built from a
    // local `self_update_commit`
    // (`crate::mls::runtime::force_epoch_rotation_commit`).
}
