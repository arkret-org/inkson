use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;

/// Canonical signing-input prefix for the MLS `keypackages/upload`
/// `device_signature`. Distinct domain string from the prekey `keys/upload`
/// (`ck-keys-upload-v1`, spec §8.1) so a signature over one batch can never be
/// replayed as the other; binds the device + the published KeyPackage batch.
const KEYPACKAGE_UPLOAD_SIGNATURE_PREFIX: &str = "ck-keypackage-upload-v1\n";

/// Sign the MLS KeyPackage upload batch with the local event-signer (device
/// identity Ed25519 `did:key`), binding `device_id` + the published
/// `key_packages`. Fail-closed (`bail!`) when no signer is installed.
pub(crate) fn keypackage_upload_signing_input(
    device_id: &str,
    key_packages: &[Value],
) -> anyhow::Result<Vec<u8>> {
    let body = json!({
        "device_id": device_id,
        "key_packages": key_packages,
    });
    let canonical = crate::canonical::canonical_json_bytes(&body)?;
    let mut input = Vec::with_capacity(KEYPACKAGE_UPLOAD_SIGNATURE_PREFIX.len() + canonical.len());
    input.extend_from_slice(KEYPACKAGE_UPLOAD_SIGNATURE_PREFIX.as_bytes());
    input.extend_from_slice(&canonical);
    Ok(input)
}

pub(crate) fn sign_keypackage_upload_batch_with_signer(
    signer: &crate::event_signer::YougenEventSigner,
    device_id: &str,
    key_packages: &[Value],
) -> anyhow::Result<Value> {
    let input = keypackage_upload_signing_input(device_id, key_packages)?;
    super::keys::device_signature_tuple_for_input(signer, &input, "keypackages/upload")
}

fn sign_keypackage_upload_batch(device_id: &str, key_packages: &[Value]) -> anyhow::Result<Value> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!(
            "keypackages/upload device_signature requires an active event-signer (fail-closed)"
        )
    })?;
    sign_keypackage_upload_batch_with_signer(&signer, device_id, key_packages)
}

pub(crate) fn mls_key_package_record_upload_value(
    record: &cokret_sdk::MlsKeyPackageRecord,
) -> anyhow::Result<Value> {
    let mut value = serde_json::to_value(record)?;
    let Some(object) = value.as_object_mut() else {
        anyhow::bail!("MLS KeyPackage record did not serialize to an object");
    };
    object
        .entry("keypackage_digest".to_owned())
        .or_insert_with(|| json!(record.keypackage_ref.as_str()));
    Ok(value)
}

pub(crate) fn generate_mls_claim_nonce() -> anyhow::Result<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes)
        .map_err(|err| anyhow::anyhow!("generate MLS KeyPackage claim nonce: {err}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn keypackage_claim_record_to_mls_record(
    claim: &cokret_sdk::KeypackageClaimRecord,
) -> anyhow::Result<cokret_sdk::MlsKeyPackageRecord> {
    Ok(cokret_sdk::MlsKeyPackageRecord {
        keypackage_id: claim.keypackage_ref.as_str().to_owned(),
        principal_id: claim.principal_id.clone(),
        device_id: cokret_sdk::DeviceId::new(claim.device_id.clone())?,
        key_package: claim.key_package.clone(),
        keypackage_ref: claim.keypackage_digest.clone(),
        cipher_suites: Vec::new(),
        capabilities: claim.capabilities.clone(),
        state: cokret_sdk::MlsKeyPackageState::Published,
        claim_id: Some(claim.claim_id.clone()),
        created_at: crate::clock::now_utc(),
        expires_at: Some(claim.expires_at),
        device_signature: None,
        // Reconstructed claim-side record (admin builds the Welcome from the
        // KeyPackage bytes, which already carry any last_resort extension); the
        // flag is not re-published, so a plain default is correct here.
        last_resort: false,
    })
}

pub(crate) fn mls_keypackage_claim_required_capabilities() -> Vec<String> {
    cokret_sdk::COKRET_MLS_KEY_PACKAGE_CAPABILITIES
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect()
}

pub(crate) fn build_mls_keypackage_claim_request(
    target_principal_id: &str,
    intended_realm_id: &str,
    requester: &str,
    claim_nonce: &str,
    target_device_id: Option<&str>,
    mls_group_id: Option<&str>,
) -> anyhow::Result<cokret_sdk::KeyPackagesClaimRequestBody> {
    let target_device_ids = target_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| cokret_sdk::DeviceId::new(value.to_owned()))
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    Ok(cokret_sdk::KeyPackagesClaimRequestBody {
        target_principal_id: cokret_sdk::Did::new(target_principal_id.trim().to_owned())?,
        intended_realm_id: cokret_sdk::RealmId::new(crate::operation::trim_realm_id(
            intended_realm_id,
        ))?,
        requester: cokret_sdk::Did::new(requester.trim().to_owned())?,
        required_capabilities: mls_keypackage_claim_required_capabilities(),
        claim_nonce: claim_nonce.trim().to_owned(),
        expires_at: crate::clock::now_utc() + chrono::Duration::minutes(10),
        target_device_ids,
        minimal_metadata_allowed: Some(true),
        timeout_ms: Some(30_000),
        strand_id: None,
        mls_group_id: mls_group_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        proofs: Vec::new(),
    })
}

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
        let key_packages = vec![mls_key_package_record_upload_value(record)?];
        let device_signature = sign_keypackage_upload_batch(device_id, &key_packages)?;
        let body = cokret_sdk::KeyPackagesUploadRequestBody {
            principal_id: record.principal_id.clone(),
            device_id: cokret_sdk::DeviceId::new(device_id.to_owned())?,
            key_packages,
            device_signature,
            expires_at: None,
            strand_id: None,
            mls_group_id: None,
        };
        self.post_json("_cokret/self/keys/keypackages/upload", &body)
            .await
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
        self.post_json("_cokret/self/keys/keypackages/claim", &body)
            .await
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
        self.post_json(
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
