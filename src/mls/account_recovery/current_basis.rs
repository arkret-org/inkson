//! Holder-private backup projection provenance, separate from collaboration snapshots.

use anyhow::{Result, anyhow};
use arkret_sdk::http_client::own_station_results::OwnStationStateClient;

use super::rotation_transaction::{
    ControllerBackupTrustAnchor, current_controller_backup_trust_anchor,
};

pub(super) struct ConfirmedBackupBasis {
    source: OwnStationStateClient,
    state: arkret_sdk::BackupActiveSeriesState,
    trust_anchor: ControllerBackupTrustAnchor,
    signer: std::sync::Arc<crate::event_signer::InksonEventSigner>,
}

impl ConfirmedBackupBasis {
    pub(super) async fn read(
        api: &crate::transport::TransportClient,
        authority: &arkret_sdk::AccountId,
        control_realm: &arkret_sdk::RealmId,
        device_id: &str,
        expected: Option<&arkret_sdk::BackupActiveSeriesState>,
    ) -> Result<Self> {
        let http = api.sdk_http_client()?;
        let source = crate::transport::own_station_results::client_for_http(&http).await?;
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow!("active device signer is required"))?;
        anyhow::ensure!(
            signer.device_id() == Some(device_id),
            "backup basis signer has another device"
        );
        anyhow::ensure!(
            crate::mls_api_helpers::principal_core_id(signer.signer_did())?
                == authority.principal_id,
            "backup basis signer has another principal"
        );
        source.check_session()?;
        let before = current_controller_backup_trust_anchor(&http, authority, device_id).await?;
        source.check_session()?;
        let state =
            read_list_with_source(&http, &source, authority, control_realm, expected).await?;
        let after = current_controller_backup_trust_anchor(&http, authority, device_id).await?;
        source.check_session()?;
        anyhow::ensure!(
            before == after,
            "backup device authority changed across the confirmed basis"
        );
        let basis = Self {
            source,
            state,
            trust_anchor: after,
            signer,
        };
        basis.check()?;
        Ok(basis)
    }

    pub(super) fn check(&self) -> Result<()> {
        self.source.check_session()?;
        anyhow::ensure!(
            crate::event_signer::active_signer()
                .is_some_and(|active| std::sync::Arc::ptr_eq(&active, &self.signer)),
            "backup signer changed after the confirmed basis"
        );
        Ok(())
    }

    pub(super) fn check_auth(
        &self,
        auth: &arkret_crypto::backup::KeyBackupAuthBinding,
    ) -> Result<()> {
        self.check()?;
        anyhow::ensure!(
            self.signer.device_id() == Some(auth.device_id.as_str())
                && auth.device_authorize_event_id == self.trust_anchor.authorize_event_id,
            "backup signature authority differs from the confirmed device basis"
        );
        Ok(())
    }

    pub(super) fn state(&self) -> Result<&arkret_sdk::BackupActiveSeriesState> {
        self.check()?;
        Ok(&self.state)
    }

    pub(super) fn trust_anchor(&self) -> Result<&ControllerBackupTrustAnchor> {
        self.check()?;
        Ok(&self.trust_anchor)
    }

    pub(super) fn source_commit_ref(&self) -> Result<arkret_sdk::KeyBackupSourceCommitRef> {
        self.check()?;
        anyhow::ensure!(
            self.trust_anchor.generation_ref > 0,
            "backup device generation must be positive"
        );
        Ok(arkret_sdk::KeyBackupSourceCommitRef {
            realm_commit_id: self.state.authority_commit_id.clone(),
            device_generation_ref: self.trust_anchor.generation_ref,
        })
    }
}

pub(super) async fn read_list_with_source(
    http: &arkret_sdk::http_client::Client,
    source: &OwnStationStateClient,
    authority: &arkret_sdk::AccountId,
    control_realm: &arkret_sdk::RealmId,
    expected: Option<&arkret_sdk::BackupActiveSeriesState>,
) -> Result<arkret_sdk::BackupActiveSeriesState> {
    source.check_session()?;
    anyhow::ensure!(
        http.base_url().as_str() == source.session()?.binding().base_url,
        "backup read HTTP origin differs from its accepted session"
    );
    anyhow::ensure!(
        source.session()?.account_id() == authority,
        "backup read is not the current complete Account"
    );
    let response = http
        .list_key_backups(&arkret_sdk::KeyBackupsListQuery {
            series_id: None,
            backup_kind: None,
            cursor: None,
            limit: Some(1),
            agent_id: None,
        })
        .await?;
    source.check_session()?;
    let state = response.active_series;
    validate_basis(&state, authority, control_realm, expected)?;
    source.check_session()?;
    Ok(state)
}

fn validate_basis(
    state: &arkret_sdk::BackupActiveSeriesState,
    authority: &arkret_sdk::AccountId,
    control_realm: &arkret_sdk::RealmId,
    expected: Option<&arkret_sdk::BackupActiveSeriesState>,
) -> Result<()> {
    anyhow::ensure!(
        state.account_id == *authority && state.control_realm_id == *control_realm,
        "backup confirmed basis belongs to another Account or PCR"
    );
    if let arkret_sdk::BackupActiveSeriesPointer::Active {
        series_pointer_version,
        ..
    } = state.secret_storage
    {
        anyhow::ensure!(
            series_pointer_version > 0,
            "backup pointer version must be positive"
        );
    }
    if let Some(expected) = expected {
        anyhow::ensure!(
            expected.account_id == *authority && expected.control_realm_id == *control_realm,
            "previous backup pointer belongs to another Account or PCR"
        );
        anyhow::ensure!(
            state.secret_storage == expected.secret_storage,
            "backup pointer changed after selecting its immutable predecessor"
        );
    }
    Ok(())
}

/// Verify an envelope read from the holder-private native backup resource.
/// The original accepted authorization supplies its historical signing key;
/// current-device and active-series admission remain independent read gates.
pub(super) async fn verify_envelope_source(
    http: &arkret_sdk::http_client::Client,
    source: &OwnStationStateClient,
    authority: &arkret_sdk::AccountId,
    control_realm: &arkret_sdk::RealmId,
    body: &arkret_sdk::KeyBackup,
) -> Result<()> {
    source.check_session()?;
    anyhow::ensure!(
        http.base_url().as_str() == source.session()?.binding().base_url,
        "backup read HTTP origin differs from its accepted session"
    );
    anyhow::ensure!(
        source.session()?.account_id() == authority,
        "backup envelope source has another Account"
    );
    body.validate()?;
    let authorization = body
        .signature_proof
        .device_authorize_event_id
        .as_ref()
        .ok_or_else(|| anyhow!("Human backup has no original Device authorization"))?;
    let response = source.committed_event_get(authorization).await?;
    let arkret_sdk::CommittedEventView::Full(original) = response.value()? else {
        anyhow::bail!("backup original Device authorization is withheld");
    };
    anyhow::ensure!(
        original.event.event_id == *authorization
            && original.event.kind == arkret_sdk::EventKind::DeviceAuthorize
            && original.event.realm_id == *control_realm
            && original.event.scope_ref
                == (arkret_sdk::ScopeRef::Realm {
                    realm_id: control_realm.clone()
                })
            && original.event.actor_id == arkret_sdk::ActorId::account(authority.clone())
            && original.event.executed_by.is_none(),
        "backup authorization is not its original same-Account PCR unit"
    );
    let reference = arkret_sdk::CommittedEventRef {
        event_id: original.event.event_id.clone(),
        commit_id: original.commit.commit_id.clone(),
        stream_ref: original.commit.stream_ref.clone(),
        stream_position: original.commit.stream_position,
    };
    // The shared consumer re-reads the exact stream row and verifies its
    // historical producer, original Event proof and covering Commit.
    let response =
        garth::own_station_results::consume_bound_event(source, &reference, response).await?;
    let arkret_sdk::CommittedEventView::Full(original) = response.value()? else {
        anyhow::bail!("verified backup authorization is not a full original");
    };
    let payload: arkret_sdk::DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&original.event.payload)?)?;
    verify_envelope_authorization(body, authority, authorization, &payload)?;
    source.check_session()?;
    Ok(())
}

/// The caller has already consumed this authorization's exact native original.
/// This validates historical signature binding, not current endpoint admission.
pub(super) fn verify_envelope_authorization(
    body: &arkret_sdk::KeyBackup,
    authority: &arkret_sdk::AccountId,
    authorization_event_id: &arkret_sdk::EventId,
    authorization: &arkret_sdk::DeviceAuthorizePayload,
) -> Result<()> {
    body.validate()?;
    anyhow::ensure!(
        body.actor_id == arkret_sdk::ActorId::account(authority.clone())
            && body.custodian_actor_id.is_none()
            && body.custody_authorization_ref.is_none()
            && body.device_id.as_ref() == Some(&authorization.device_id)
            && body.signature_proof.device_id.as_ref() == Some(&authorization.device_id)
            && body.signature_proof.agent_authorization_event_ref.is_none(),
        "backup envelope complete Account/device differs"
    );
    anyhow::ensure!(
        body.signature_proof.device_authorize_event_id.as_ref() == Some(authorization_event_id),
        "backup envelope historical authorization differs from its exact original"
    );
    arkret_signatures::verify_device_authorize_possession(authorization, authority)
        .map_err(|error| anyhow!("backup authorization possession: {error}"))?;
    if let Some(checkpoint) = body.source_commit_ref.as_ref() {
        anyhow::ensure!(
            checkpoint.device_generation_ref == authorization.authorized_generation_ref
                && authorization.authorized_generation_ref > 0,
            "backup envelope historical generation differs from its original authorization"
        );
    }
    anyhow::ensure!(
        authorization.not_before <= body.created_at
            && authorization
                .expires_at
                .flatten()
                .is_none_or(|end| body.created_at < end),
        "backup envelope was signed outside its accepted authorization window"
    );
    let multibase = authorization
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| anyhow!("backup signing key is not a registered did:key"))?;
    let method = body.signature_proof.verification_method.as_str();
    let (controller, fragment) = method
        .split_once('#')
        .ok_or_else(|| anyhow!("backup verification method has no exact selector"))?;
    anyhow::ensure!(
        crate::mls_api_helpers::principal_core_id(controller)? == authority.principal_id
            && fragment == authorization.device_id.as_str(),
        "backup verification method differs from its complete Account/device"
    );
    anyhow::ensure!(
        body.signature_proof.signature_algorithm
            == arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
        "backup envelope signature algorithm is unsupported"
    );
    let public = arkret_sdk::decode_ed25519_multibase(multibase)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&public)?;
    let bytes = arkret_sdk::base64url_decode(body.signature_proof.signature.as_str())?;
    let signature = ed25519_dalek::Signature::from_slice(&bytes)?;
    key.verify_strict(&body.signing_payload_bytes()?, &signature)
        .map_err(|_| anyhow!("backup envelope signature is invalid"))?;
    Ok(())
}

pub(super) fn state_from_payload(
    payload: &serde_json::Value,
) -> Result<arkret_sdk::BackupActiveSeriesState> {
    serde_json::from_value(
        payload
            .get("active_series")
            .cloned()
            .ok_or_else(|| anyhow!("backup listing omitted its confirmed active series"))?,
    )
    .map_err(|_| anyhow!("backup listing has an invalid confirmed active series"))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    use arkret_sdk::http_client::own_station_results::{
        OwnStationSessionSnapshot, OwnStationSessionSource,
    };

    use super::*;

    struct Source(Mutex<OwnStationSessionSnapshot>);
    impl OwnStationSessionSource for Source {
        fn snapshot(&self) -> arkret_sdk::http_client::Result<OwnStationSessionSnapshot> {
            Ok(self.0.lock().unwrap().clone())
        }
    }
    fn state() -> arkret_sdk::BackupActiveSeriesState {
        arkret_sdk::BackupActiveSeriesState {
            account_id: crate::test_support::authority("did:web:alice.example"),
            control_realm_id: arkret_sdk::RealmId::from_event_id(
                &arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [3; 32]),
            ),
            authority_commit_id: arkret_sdk::RealmCommitId::from_digest([7; 32]),
            secret_storage: arkret_sdk::BackupActiveSeriesPointer::Absent {},
        }
    }
    fn http(
        body: serde_json::Value,
        replace: bool,
    ) -> (
        arkret_sdk::http_client::Client,
        OwnStationStateClient,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let account = state().account_id;
        let binding = arkret_sdk::StationConnectionBinding {
            service_id: account.station_id.clone(),
            base_url: base.clone(),
            trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            authentication_metadata: arkret_sdk::AuthenticationMetadata::minimal(),
        };
        let source = Arc::new(Source(Mutex::new(
            OwnStationSessionSnapshot::new(
                binding.clone(),
                account.clone(),
                account.station_id.clone(),
                arkret_wire::SessionGrantId::from_issuance_digest([3; 32]),
                1,
                "fixture-grant".into(),
            )
            .unwrap()
            .with_provider_identity(Default::default()),
        )));
        let raw = arkret_sdk::http_client::ClientBuilder::new(url::Url::parse(&base).unwrap())
            .allow_insecure_localhost()
            .auth(arkret_sdk::http_client::Auth::Bearer(
                "fixture-grant".into(),
            ))
            .build()
            .unwrap();
        let own = OwnStationStateClient::new(raw.clone(), binding, source.clone()).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut buffer = [0; 2048];
                let count = socket.read(&mut buffer).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
            }
            let headers = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(headers.starts_with("get /_arkret/self/keys/backups"));
            assert!(headers.contains("authorization: bearer fixture-grant"));
            if replace {
                let old = source.snapshot().unwrap();
                *source.0.lock().unwrap() = OwnStationSessionSnapshot::new(
                    old.binding().clone(),
                    old.account_id().clone(),
                    old.account_id().station_id.clone(),
                    old.grant_id().clone(),
                    old.epoch(),
                    "fixture-grant".into(),
                )
                .unwrap()
                .with_provider_identity(Default::default());
            }
            let bytes = serde_json::to_vec(&body).unwrap();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", bytes.len()).unwrap();
            socket.write_all(&bytes).unwrap();
        });
        (raw, own, server)
    }
    fn body(state: &arkret_sdk::BackupActiveSeriesState) -> serde_json::Value {
        serde_json::to_value(arkret_sdk::KeysBackupsPage {
            backups: vec![],
            active_series: state.clone(),
            next_cursor: None,
            has_more: false,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn backup_basis_actual_http_uses_holder_projection_without_snapshot_or_history() {
        let expected = state();
        let (raw, source, server) = http(body(&expected), false);
        let result = read_list_with_source(
            &raw,
            &source,
            &expected.account_id,
            &expected.control_realm_id,
            None,
        )
        .await
        .unwrap();
        assert_eq!(result, expected);
        source.check_session().unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn backup_basis_actual_http_rejects_foreign_account_pcr_and_late_same_grant_aba() {
        for invalid in 0..3 {
            let expected = state();
            let mut returned = expected.clone();
            if invalid == 0 {
                returned.account_id.station_id =
                    arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
            }
            if invalid == 1 {
                returned.control_realm_id = arkret_sdk::RealmId::from_event_id(
                    &arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [4; 32]),
                );
            }
            let (raw, source, server) = http(body(&returned), invalid == 2);
            let result = read_list_with_source(
                &raw,
                &source,
                &expected.account_id,
                &expected.control_realm_id,
                None,
            )
            .await;
            assert!(
                result.is_err(),
                "foreign or stale result must publish no basis"
            );
            server.join().unwrap();
        }
    }

    #[tokio::test]
    async fn backup_basis_actual_http_rejects_pointer_version_fork_and_closed_zero_version() {
        let mut expected = state();
        let series = arkret_sdk::BackupSeriesId::new(
            "ak:backup_series:01964137-1000-7000-8000-0000000000a1",
        )
        .unwrap();
        expected.secret_storage = arkret_sdk::BackupActiveSeriesPointer::Active {
            active_series_id: series,
            series_pointer_version: 2,
        };
        for version in [0, 1, 3] {
            let mut returned = body(&expected);
            returned["active_series"]["secret_storage"]["series_pointer_version"] =
                serde_json::json!(version);
            let (raw, source, server) = http(returned, false);
            assert!(
                read_list_with_source(
                    &raw,
                    &source,
                    &expected.account_id,
                    &expected.control_realm_id,
                    Some(&expected)
                )
                .await
                .is_err()
            );
            server.join().unwrap();
        }
    }
}
