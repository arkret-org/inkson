//! MLS KeyPackage helper functions shared by API endpoints and admission code.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(crate) fn ordinary_mls_identity(
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
) -> Result<arkret_sdk::ArkretMlsIdentity, String> {
    let actor_id = arkret_sdk::ActorId::account(authority);
    #[cfg(test)]
    {
        arkret_sdk::ArkretMlsIdentity::new_test_human_device(actor_id, device_id)
            .map_err(|error| error.to_string())
    }
    #[cfg(not(test))]
    {
        let Some(signer) = crate::event_signer::active_signer() else {
            return Err("active accepted-device signer is unavailable".to_owned());
        };
        if signer.device_id() != Some(device_id.as_str()) {
            return Err("active signer device differs from MLS endpoint".to_owned());
        }
        let signing_key = signer
            .clone_raw_signing_key()
            .map_err(|error| error.to_string())?;
        arkret_sdk::ArkretMlsIdentity::new_human_device(
            actor_id,
            device_id,
            arkret_sdk::ArkretMlsSigner::from_ed25519_signing_key(signing_key),
        )
        .map_err(|error| error.to_string())
    }
}

pub(crate) fn principal_core_id(principal_id: &str) -> anyhow::Result<arkret_sdk::DidCoreId> {
    let principal_id = principal_id.trim();
    if let Ok(core_id) = arkret_sdk::DidCoreId::new(principal_id.to_owned()) {
        return Ok(core_id);
    }
    let did = arkret_sdk::Did::new(principal_id.to_owned())?;
    arkret_sdk::project_did_to_core_id(&did).map_err(anyhow::Error::msg)
}

/// Complete account for a principal authored at the selected Station.
///
/// Valid only for identities that really are hosted here: the active account
/// and the Agents it owns, which this client hosts at its own authoring
/// Station. `connect.rs` accepts an `ActiveAccountContext` only when its
/// `authority.station_id` equals the described Station, so for the active
/// account this is the same closed `AccountId` the store holds -- but a caller
/// that already holds that `AccountId` MUST pass it instead of re-deriving it
/// here (account-lifecycle.md §156 forbids passing the two components as a
/// loose identity), and a caller that can run before `describe` succeeds MUST
/// NOT use it at all. Never use it to guess a remote subject's Station.
pub(crate) fn local_account_id(value: &str) -> anyhow::Result<arkret_sdk::AccountId> {
    Ok(arkret_sdk::AccountId::new(
        principal_core_id(value)?,
        crate::operation::authoring_station_id()?,
    ))
}

/// Complete account actor for a principal authored at the selected Station.
/// Same preconditions as [`local_account_id`].
pub(crate) fn local_account_actor_id(value: &str) -> anyhow::Result<arkret_sdk::ActorId> {
    Ok(arkret_sdk::ActorId::account(local_account_id(value)?))
}

/// Parse a complete account from its canonical selector: either the
/// `AccountId` JSON object or an account-kind `ActorId` JSON object. This is
/// the form the UI already accepts wherever a remote identity is pasted
/// (`contact-requester-did-input`), and the only string form that carries both
/// components.
pub(crate) fn account_id_from_selector(value: &str) -> Option<arkret_sdk::AccountId> {
    let value = value.trim();
    let account = serde_json::from_str::<arkret_sdk::AccountId>(value)
        .ok()
        .or_else(|| {
            serde_json::from_str::<arkret_sdk::ActorId>(value)
                .ok()?
                .as_account_id()
                .cloned()
        })?;
    account.validate().ok()?;
    Some(account)
}

/// Resolve a user-typed identity for a subject that is NOT this account into a
/// closed `AccountId`, failing closed on a bare principal.
///
/// `primary` is either the canonical account selector (see
/// [`account_id_from_selector`]) or a principal DID / core id; in the latter
/// case `station` must name the subject's Station. There is deliberately no
/// fallback to the ambient authoring Station: for a remote subject that
/// Station is a guess, and a wrong guess names a different account
/// (account-lifecycle.md §156/§158) instead of failing.
pub(crate) fn closed_account_id_input(
    primary: &str,
    station: Option<&str>,
) -> anyhow::Result<arkret_sdk::AccountId> {
    let primary = primary.trim();
    if primary.is_empty() {
        anyhow::bail!("an account identity is required");
    }
    let station = station.map(str::trim).filter(|value| !value.is_empty());
    if let Some(account) = account_id_from_selector(primary) {
        if let Some(station) = station {
            let station = principal_core_id(station)?;
            if station != account.station_id {
                anyhow::bail!(
                    "the account selector names Station {} but Station {} was also given",
                    account.station_id,
                    station
                );
            }
        }
        return Ok(account);
    }
    let principal_id = principal_core_id(primary)?;
    let Some(station) = station else {
        anyhow::bail!(
            "a complete account is required: give the principal together with its Station DID, or paste the canonical account selector"
        );
    };
    Ok(arkret_sdk::AccountId::new(
        principal_id,
        principal_core_id(station)?,
    ))
}

#[cfg(test)]
mod principal_id_tests {
    use super::*;

    #[test]
    fn principal_core_id_accepts_stable_and_resolvable_forms() {
        let core = "ak:did_core:web:alice.example";
        assert_eq!(principal_core_id(core).unwrap().as_str(), core);
        assert_eq!(
            principal_core_id("did:web:alice.example").unwrap().as_str(),
            core
        );
        assert_eq!(
            principal_core_id("  did:web:alice.example  ")
                .unwrap()
                .as_str(),
            core
        );
    }
}
pub(crate) fn sign_keypackage_upload_batch_with_signer(
    signer: &crate::event_signer::InksonEventSigner,
    unsigned: &arkret_sdk::KeyPackagesUploadUnsignedRequest,
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    let input = arkret_sdk::keypackages_upload_signing_input(unsigned)?;
    let sig = signer.sign_raw(&input).map_err(|err| {
        anyhow::anyhow!("keypackages/upload endpoint_signature sign failed: {err}")
    })?;
    Ok(arkret_sdk::KeyOperationSignature {
        kid: arkret_sdk::NonEmptyString::new(signer.verification_method())
            .map_err(anyhow::Error::msg)?,
        signature_algorithm: Some(
            arkret_sdk::NonEmptyString::new(signer.algorithm()).map_err(anyhow::Error::msg)?,
        ),
        sig: arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(sig))
            .map_err(anyhow::Error::msg)?,
    })
}

pub(crate) fn sign_keypackage_revoke_batch(
    unsigned: &arkret_sdk::KeyPackagesRevokeUnsignedRequest,
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!(
            "keypackages/revoke signature requires an active event-signer (fail-closed)"
        )
    })?;
    let input = arkret_sdk::keypackages_revoke_signing_input(unsigned)?;
    let sig = signer
        .sign_raw(&input)
        .map_err(|error| anyhow::anyhow!("keypackages/revoke signature failed: {error}"))?;
    Ok(arkret_sdk::KeyOperationSignature {
        kid: arkret_sdk::NonEmptyString::new(signer.verification_method())
            .map_err(anyhow::Error::msg)?,
        signature_algorithm: Some(
            arkret_sdk::NonEmptyString::new(signer.algorithm()).map_err(anyhow::Error::msg)?,
        ),
        sig: arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(sig))
            .map_err(anyhow::Error::msg)?,
    })
}

/// Convert a local `MlsKeyPackageRecord` into the typed wire entry for
/// `keypackages/upload`
/// (`keypackage-operations.schema.json#/$defs/keypackage_upload_entry`).
/// `keypackage_ref` carries the canonical KeyPackage hash; a missing
/// `expires_at` falls back to the SDK default KeyPackage lifetime
/// (`created_at` + 7 days).
pub(crate) fn mls_key_package_record_upload_entry(
    record: &arkret_sdk::MlsKeyPackageRecord,
) -> anyhow::Result<arkret_sdk::KeyPackageUploadEntry> {
    let keypackage = arkret_sdk::base64url_decode(record.keypackage.as_bytes())?;
    let leaf = arkret_sdk::mls::author_leaf_from_key_package_bytes(&keypackage, 0)?;
    let arkret_sdk::mls::AuthorLeafCredential::Basic { identity } = leaf.credential else {
        anyhow::bail!("uploaded KeyPackage does not carry an Arkret BasicCredential");
    };
    let credential_actor = arkret_sdk::decode_mls_basic_credential_identity(&identity)?;
    anyhow::ensure!(
        credential_actor == record.actor_id,
        "uploaded KeyPackage credential differs from record actor_id"
    );
    arkret_sdk::mls_key_package_record_upload_entry(record).map_err(anyhow::Error::msg)
}

pub(crate) fn generate_mls_claim_request_id() -> anyhow::Result<String> {
    crate::random::base64url_token(24, "generate MLS KeyPackage claim request id")
}

pub(crate) fn keypackage_claim_record_to_mls_record(
    claim: &arkret_sdk::KeyPackageClaimRecord,
) -> anyhow::Result<arkret_sdk::MlsKeyPackageRecord> {
    if claim.device_id.is_some() && claim.device_authorize_event_id.is_none() {
        anyhow::bail!("device KeyPackage claim is missing its authorization event");
    }
    if claim.agent_id.is_some() && claim.device_authorize_event_id.is_some() {
        anyhow::bail!("Agent KeyPackage claim has mixed authorization evidence");
    }
    anyhow::ensure!(
        claim.pairwise_verification_method.is_none(),
        "retired pairwise KeyPackage claim is not an active MLS endpoint"
    );
    let endpoint = match (
        &claim.device_id,
        &claim.agent_id,
        &claim.agent_verification_method,
        &claim.agent_key_authorize_event_id,
    ) {
        (Some(device_id), None, None, None) => arkret_sdk::MlsEndpointIdentity::human_device(
            claim.principal_id.clone(),
            device_id.clone(),
        ),
        (None, Some(agent_id), Some(method), Some(authorization_ref)) => {
            if agent_id != &claim.principal_id {
                anyhow::bail!("Agent KeyPackage claim endpoint binding mismatch");
            }
            arkret_sdk::MlsEndpointIdentity::agent_runtime(
                agent_id.clone(),
                method.clone(),
                authorization_ref.clone(),
            )?
        }
        (None, None, None, None) => {
            anyhow::bail!("retired pairwise KeyPackage claim is not an active MLS endpoint")
        }
        _ => anyhow::bail!("KeyPackage claim has an incomplete or mixed endpoint identity"),
    };
    let keypackage = arkret_sdk::base64url_decode(claim.keypackage.as_bytes())?;
    let leaf = arkret_sdk::mls::author_leaf_from_key_package_bytes(&keypackage, 0)?;
    let arkret_sdk::mls::AuthorLeafCredential::Basic { identity } = leaf.credential else {
        anyhow::bail!("claimed KeyPackage does not carry an Arkret BasicCredential");
    };
    let credential_actor = arkret_sdk::decode_mls_basic_credential_identity(&identity)?;
    anyhow::ensure!(
        credential_actor == claim.actor_id,
        "claimed KeyPackage credential differs from claim actor_id"
    );
    let keypackage_ref = arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&keypackage))?;
    Ok(arkret_sdk::MlsKeyPackageRecord {
        keypackage_id: claim.keypackage_ref.as_str().to_owned(),
        actor_id: claim.actor_id.clone(),
        endpoint,
        keypackage: claim.keypackage.clone(),
        keypackage_ref,
        cipher_suites: vec![
            arkret_sdk::mls::keypackage_ciphersuite_canonical_id(&keypackage)?.to_owned(),
        ],
        capabilities: claim.capabilities.clone(),
        state: arkret_sdk::MlsKeyPackageState::Claimed,
        claim_id: Some(claim.claim_id.clone()),
        created_at: crate::clock::now_utc(),
        expires_at: Some(claim.expires_at),
        // Reconstructed claim-side record (admin builds the Welcome from the
        // KeyPackage bytes, which already carry any last_resort extension); the
        // flag is not re-published, so a plain default is correct here.
        last_resort: false,
    })
}

pub(crate) fn mls_keypackage_claim_required_capabilities()
-> anyhow::Result<Vec<arkret_sdk::NonEmptyString>> {
    arkret_sdk::ARKRET_MLS_KEY_PACKAGE_CAPABILITIES
        .iter()
        .map(|capability| arkret_sdk::NonEmptyString::new(*capability).map_err(anyhow::Error::msg))
        .collect()
}

pub(crate) fn build_mls_keypackage_claim_request(
    target_principal_id: &str,
    intended_realm_id: &str,
    requester: &str,
    requester_device_id: &str,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    source_id: &str,
    destination_id: &str,
    claim_request_id: &str,
    target_device_id: Option<&str>,
    mls_group_id: &str,
    target_agent: Option<&arkret_sdk::MlsEndpointIdentity>,
) -> anyhow::Result<arkret_sdk::KeyPackagesClaimRequestBody> {
    let requester_core_id = principal_core_id(requester)?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("KeyPackage claim requires an active device signer"))?;
    let requester_did = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    anyhow::ensure!(
        arkret_sdk::project_did_to_core_id(&requester_did)? == requester_core_id,
        "active device signer DID does not project to the KeyPackage claim requester"
    );
    let verification_method = signer.verification_method_for_principal(&requester_did)?;
    build_mls_keypackage_claim_request_with_requester(
        target_principal_id,
        intended_realm_id,
        requester_core_id,
        ClaimRequester::Device {
            requester_device_id: arkret_sdk::DeviceId::new(requester_device_id.trim().to_owned())?,
            device_authorize_event_id: requester_device_authorize_event_id.clone(),
            verification_method,
            signer: signer.as_ref(),
        },
        source_id,
        destination_id,
        claim_request_id,
        target_device_id,
        mls_group_id,
        target_agent,
    )
}

enum ClaimRequester<'a> {
    Device {
        requester_device_id: arkret_sdk::DeviceId,
        device_authorize_event_id: arkret_sdk::EventId,
        verification_method: arkret_sdk::DidUrl,
        signer: &'a crate::event_signer::InksonEventSigner,
    },
}

#[allow(clippy::too_many_arguments)]
fn build_mls_keypackage_claim_request_with_requester(
    target_principal_id: &str,
    intended_realm_id: &str,
    requester: arkret_sdk::DidCoreId,
    requester_authority: ClaimRequester<'_>,
    source_id: &str,
    destination_id: &str,
    claim_request_id: &str,
    target_device_id: Option<&str>,
    mls_group_id: &str,
    target_agent: Option<&arkret_sdk::MlsEndpointIdentity>,
) -> anyhow::Result<arkret_sdk::KeyPackagesClaimRequestBody> {
    let target_device_ids = target_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| arkret_sdk::DeviceId::new(value.to_owned()))
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    let source_id = arkret_sdk::DidCoreId::new(source_id.trim().to_owned())?;
    let destination_id = arkret_sdk::DidCoreId::new(destination_id.trim().to_owned())?;
    let target_core_id = principal_core_id(target_principal_id)?;
    let (target_agent_id, target_agent_verification_method, target_agent_key_authorize_event_id) =
        match target_agent {
            Some(arkret_sdk::MlsEndpointIdentity::AgentRuntime {
                agent_id,
                verification_method,
                agent_key_authorize_event_id,
            }) => {
                anyhow::ensure!(
                    *agent_id == target_core_id && target_device_ids.is_empty(),
                    "Agent claim selector does not match the requested peer"
                );
                (
                    Some(agent_id.clone()),
                    Some(verification_method.clone()),
                    Some(agent_key_authorize_event_id.clone()),
                )
            }
            Some(_) => anyhow::bail!("Agent claim selector requires a runtime endpoint"),
            None => (None, None, None),
        };
    let target_account_id = target_agent_id
        .is_none()
        .then(|| arkret_sdk::AccountId::new(target_core_id, destination_id.clone()));
    let requester_account_id = Some(arkret_sdk::AccountId::new(
        requester.clone(),
        source_id.clone(),
    ));
    let signed_at = crate::clock::now_utc();
    let unsigned = arkret_sdk::PeerKeyPackagesClaimUnsignedRequest {
        claim_request_id: arkret_sdk::Base64UrlString::new(claim_request_id.trim().to_owned())
            .map_err(anyhow::Error::msg)?,
        target_account_id,
        requester_account_id,
        intended_realm_id: arkret_sdk::RealmId::new(crate::operation::trim_realm_id(
            intended_realm_id,
        ))?,
        mls_group_id: arkret_sdk::MlsGroupId::new(mls_group_id.trim())
            .map_err(anyhow::Error::msg)?,
        claim_purpose: arkret_sdk::PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: mls_keypackage_claim_required_capabilities()?,
        expires_at: signed_at + chrono::Duration::minutes(5),
        target_device_ids,
        target_keypackage_ref: None,
        target_agent_id,
        target_agent_verification_method,
        target_agent_key_authorize_event_id,
        target_pairwise_verification_method: None,
        timeout_ms: Some(30_000),
        strand_id: None,
        pair_key: None,
        last_resort_allowed: Some(false),
    };
    let service_binding = arkret_sdk::KeyPackagesClaimServiceBinding {
        source_id,
        destination_id,
    };
    let (mut requester_authorization, signer) = match requester_authority {
        ClaimRequester::Device {
            requester_device_id,
            device_authorize_event_id,
            verification_method,
            signer,
        } => (
            arkret_sdk::PeerKeyPackageRequesterAuthorization::Device {
                signature: placeholder_key_operation_signature(&verification_method, signer)?,
                verification_method,
                requester_device_id,
                device_authorize_event_id,
                signed_at,
            },
            signer,
        ),
    };
    let signing_bytes = arkret_sdk::keypackage_claim_authorization_signing_bytes(
        &unsigned,
        &service_binding,
        &requester_authorization,
    )?;
    let signature = arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(
        signer.sign_raw(&signing_bytes).map_err(|error| {
            anyhow::anyhow!("KeyPackage claim authorization sign failed: {error}")
        })?,
    ))
    .map_err(anyhow::Error::msg)?;
    match &mut requester_authorization {
        arkret_sdk::PeerKeyPackageRequesterAuthorization::Device {
            signature: proof, ..
        }
        | arkret_sdk::PeerKeyPackageRequesterAuthorization::Agent {
            signature: proof, ..
        }
        | arkret_sdk::PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise {
            signature: proof,
            ..
        } => proof.sig = signature,
    }
    let body = arkret_sdk::KeyPackagesClaimRequestBody {
        claim_request_id: unsigned.claim_request_id,
        target_account_id: unsigned.target_account_id,
        requester_account_id: unsigned.requester_account_id,
        intended_realm_id: unsigned.intended_realm_id,
        mls_group_id: unsigned.mls_group_id,
        claim_purpose: unsigned.claim_purpose,
        required_capabilities: unsigned.required_capabilities,
        expires_at: unsigned.expires_at,
        target_device_ids: unsigned.target_device_ids,
        target_keypackage_ref: unsigned.target_keypackage_ref,
        target_agent_id: unsigned.target_agent_id,
        target_agent_verification_method: unsigned.target_agent_verification_method,
        target_agent_key_authorize_event_id: unsigned.target_agent_key_authorize_event_id,
        target_pairwise_verification_method: unsigned.target_pairwise_verification_method,
        timeout_ms: unsigned.timeout_ms,
        strand_id: unsigned.strand_id,
        pair_key: unsigned.pair_key,
        last_resort_allowed: unsigned.last_resort_allowed,
        service_binding,
        requester_authorization,
    };
    body.validate_shape()
        .map_err(|error| anyhow::anyhow!("invalid KeyPackage claim request: {error}"))?;
    Ok(body)
}

fn placeholder_key_operation_signature(
    verification_method: &arkret_sdk::DidUrl,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    Ok(arkret_sdk::KeyOperationSignature {
        kid: arkret_sdk::NonEmptyString::new(verification_method.as_str())
            .map_err(anyhow::Error::msg)?,
        signature_algorithm: Some(
            arkret_sdk::NonEmptyString::new(signer.algorithm()).map_err(anyhow::Error::msg)?,
        ),
        sig: arkret_sdk::Base64UrlString::new("YQ").map_err(anyhow::Error::msg)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim_for(
        record: &arkret_sdk::MlsKeyPackageRecord,
        _kid: &str,
    ) -> arkret_sdk::KeyPackageClaimRecord {
        let (principal_id, device_id) = match &record.endpoint {
            arkret_sdk::MlsEndpointIdentity::HumanDevice {
                principal_id,
                device_id,
            } => (principal_id.clone(), device_id.clone()),
            arkret_sdk::MlsEndpointIdentity::AgentRuntime { .. }
            | arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
                panic!("test fixture requires a human-device record")
            }
        };
        arkret_sdk::KeyPackageClaimRecord {
            claim_id: "claim".to_owned(),
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            actor_id: record.actor_id.clone(),
            principal_id,
            device_id: Some(device_id),
            agent_id: None,
            agent_verification_method: None,
            pairwise_verification_method: None,
            keypackage: record.keypackage.clone(),
            capabilities: record.capabilities.clone(),
            device_authorize_event_id: Some(
                arkret_sdk::EventId::new("ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc")
                    .unwrap(),
            ),
            agent_key_authorize_event_id: None,
            expires_at: crate::clock::now_utc() + chrono::Duration::minutes(5),
            revocation_status: None,
            last_resort: None,
        }
    }

    #[test]
    fn claimed_record_can_prepare_a_real_mls_add_without_republishing_it() {
        let station = principal_core_id("did:web:station.example").unwrap();
        let identity = |name: &str, index| {
            arkret_sdk::ArkretMlsIdentity::new_test_human_device(
                arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                    principal_core_id(name).unwrap(),
                    station.clone(),
                )),
                arkret_sdk::DeviceId::new(format!("ak:device:01964137-0000-7000-8000-{index:012}"))
                    .unwrap(),
            )
            .unwrap()
        };
        let alice = identity("did:web:alice.example", 1);
        let bob = identity("did:web:bob.example", 2);
        let published = bob.key_package_record().unwrap();
        let mut claim = claim_for(&published, "unused");
        claim.claim_id = "ak:keypackage_claim:01964137-0000-7000-8000-000000000003".to_owned();
        let claimed = keypackage_claim_record_to_mls_record(&claim).unwrap();
        assert_eq!(claimed.state, arkret_sdk::MlsKeyPackageState::Claimed);
        assert_eq!(claimed.claim_id.as_deref(), Some(claim.claim_id.as_str()));
        assert_eq!(claimed.keypackage, published.keypackage);
        assert_eq!(claimed.cipher_suites, published.cipher_suites);
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [0x54; 32],
            )),
        };
        let mut group = alice.create_group(&scope).unwrap();
        let transition = arkret_sdk::MlsGovernanceBindingPayload::new(
            scope,
            Some(arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [0x51; 32],
            )),
            0,
            1,
            0,
        )
        .unwrap();
        assert!(
            group
                .add_member_with_governance_binding(&published, &transition)
                .is_err()
        );
        group
            .add_member_with_governance_binding(&claimed, &transition)
            .unwrap();
    }

    #[test]
    fn agent_claim_is_preserved_as_a_agent_endpoint() {
        let principal = principal_core_id("did:web:agent.example").unwrap();
        let device =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000002".to_owned())
                .unwrap();
        let identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal.clone(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
            )),
            device,
        )
        .unwrap();
        let record = identity.key_package_record().unwrap();
        let method = arkret_sdk::DidUrl::new("did:web:agent.example#runtime-key").unwrap();
        let mut claim = claim_for(&record, method.as_str());
        claim.device_id = None;
        claim.device_authorize_event_id = None;
        claim.agent_id = Some(principal.clone());
        claim.agent_verification_method = Some(method.clone());
        let authorization_ref =
            arkret_sdk::EventId::new("ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc")
                .unwrap();
        claim.agent_key_authorize_event_id = Some(authorization_ref.clone());

        let converted = keypackage_claim_record_to_mls_record(&claim).unwrap();
        assert_eq!(
            converted.endpoint,
            arkret_sdk::MlsEndpointIdentity::AgentRuntime {
                agent_id: principal,
                verification_method: method,
                agent_key_authorize_event_id: authorization_ref,
            }
        );
    }

    #[test]
    fn retired_pairwise_claim_cannot_become_an_active_mls_endpoint() {
        let identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            crate::test_support::account_actor("did:web:bob.example"),
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000004".to_owned())
                .unwrap(),
        )
        .unwrap();
        let record = identity.key_package_record().unwrap();
        let mut claim = claim_for(&record, "did:web:bob.example#device");
        claim.pairwise_verification_method =
            Some(arkret_sdk::DidUrl::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x").unwrap());
        assert!(
            keypackage_claim_record_to_mls_record(&claim)
                .unwrap_err()
                .to_string()
                .contains("retired pairwise")
        );
    }

    #[test]
    fn claim_actor_must_equal_the_keypackage_credential_actor() {
        let principal = principal_core_id("did:web:bob.example").unwrap();
        let identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal.clone(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station-a.example".to_owned()).unwrap(),
            )),
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000003".to_owned())
                .unwrap(),
        )
        .unwrap();
        let record = identity.key_package_record().unwrap();
        let mut claim = claim_for(&record, "did:web:bob.example#device");
        claim.actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            principal,
            arkret_sdk::DidCoreId::new("ak:did_core:web:station-b.example".to_owned()).unwrap(),
        ));

        let error = keypackage_claim_record_to_mls_record(&claim).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("credential differs from claim actor_id")
        );

        let mut mismatched_record = record;
        mismatched_record.actor_id = claim.actor_id;
        let error = mls_key_package_record_upload_entry(&mismatched_record).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("credential differs from record actor_id")
        );
    }
}
