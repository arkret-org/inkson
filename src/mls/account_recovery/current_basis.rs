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
    let principal = source
        .current_principal(&arkret_sdk::CurrentPrincipalRequestBody {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
            account_id: authority.clone(),
        })
        .await?;
    let pcr =
        garth::own_station_results::read_own_station_human_pcr_genesis(source, principal).await?;
    anyhow::ensure!(
        pcr.account()? == authority && pcr.realm()? == control_realm,
        "backup authorization source has another registered Account or PCR"
    );
    // Private PCR originals use their native registration and historical
    // admission proofs, not the public collaboration producer-fact branch.
    let verified = pcr.read_original(authorization).await?;
    let original = verified.full()?;
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

    #[tokio::test]
    async fn backup_signature_reads_native_pcr_original_without_public_producer_fact() {
        use arkret_test_kit::pcr_genesis::{HumanPcrFixtureInput, HumanPcrOriginalsFixture};
        use ed25519_dalek::Signer as _;
        use serde_json::json;

        let fixture = HumanPcrOriginalsFixture::webvh(HumanPcrFixtureInput {
            station_id: &"ak:did_core:web:station.example".parse().unwrap(),
            endpoint: &url::Url::parse("https://principal.example/").unwrap(),
            root_seed: [7; 32],
            next_root_seed: [8; 32],
            device_seed: [41; 32],
            device_hpke_private_key: [51; 32],
            device_id: "ak:device:01964137-0000-7000-8000-000000000001"
                .parse()
                .unwrap(),
            genesis_salt: arkret_sdk::GenesisSalt::new(arkret_sdk::base64url_encode([61; 32]))
                .unwrap(),
            created_at: "2026-09-16T00:00:00.000Z".parse().unwrap(),
        })
        .unwrap();
        let station_key = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
        let station_method =
            arkret_sdk::DidUrl::new("did:web:station.example#realm-authority").unwrap();
        let genesis = fixture.unit.create();
        let create = arkret_sdk::CommittedEventFullView {
            event: genesis.clone(),
            commit: arkret_test_kit::authority_objects::signed_commit(
                &station_method,
                &station_key,
                genesis,
                0,
                None,
                genesis.event_id.clone(),
                None,
            )
            .unwrap(),
        };
        let authorize = fixture.unit.founding_authorize();
        let authorize = arkret_sdk::CommittedEventFullView {
            event: authorize.clone(),
            commit: arkret_test_kit::authority_objects::signed_commit(
                &station_method,
                &station_key,
                authorize,
                1,
                Some(create.commit.commit_id.clone()),
                genesis.event_id.clone(),
                None,
            )
            .unwrap(),
        };
        assert!(authorize.commit.producer_signer_fact_digest.is_none());
        let auth = arkret_crypto::backup::KeyBackupAuthBinding {
            device_id: fixture.device_id.clone(),
            verification_method: fixture.device_verification_method.clone(),
            signature_algorithm: arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
            device_authorize_event_id: authorize.event.event_id.clone(),
        };
        let kek = crate::recovery_crypto::derive_vault_kek(b"native PCR fixture recovery").unwrap();
        let backup = super::super::backup_body::build_mls_account_secret_backup_body_with_kek(
            "ak:backup:01964137-0000-7000-8000-00000000beef",
            &fixture.account,
            fixture.device_id.as_str(),
            &kek,
            &arkret_sdk::base64url_encode([17; 32]),
            &auth,
            &|bytes| Ok(fixture.device_signing_key.sign(bytes).to_bytes().to_vec()),
            None,
        )
        .unwrap();

        for refusal in ["none", "foreign_pcr", "wrong_envelope_key", "late_session"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base = format!("http://{}/", listener.local_addr().unwrap());
            let binding = arkret_sdk::StationConnectionBinding {
                service_id: fixture.account.station_id.clone(),
                base_url: base.clone(),
                trust_domain: "ak:trust_domain:station.example".parse().unwrap(),
                authentication_metadata: arkret_sdk::AuthenticationMetadata::minimal(),
            };
            let holder = Arc::new(Source(Mutex::new(
                OwnStationSessionSnapshot::new(
                    binding.clone(),
                    fixture.account.clone(),
                    fixture.account.station_id.clone(),
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
            let source = OwnStationStateClient::new(raw.clone(), binding, holder.clone()).unwrap();
            let replies = vec![
                json!(fixture.current_principal(arkret_sdk::RequestId::new_v7_at(1))),
                json!(arkret_sdk::CommittedEventView::Full(create.clone())),
                json!(arkret_sdk::StreamScanResponseBody {
                    committed_events: vec![
                        arkret_sdk::CommittedEventView::Full(create.clone()),
                        arkret_sdk::CommittedEventView::Full(authorize.clone()),
                    ],
                    readable_floor: Some(arkret_sdk::ReadableFloor {
                        oldest_position: 0,
                        floor_commit_id: create.commit.commit_id.clone(),
                        floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
                    }),
                    truncated: false,
                }),
                json!(fixture.document),
                json!(fixture.log),
            ];
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let server_done = done.clone();
            let server = std::thread::spawn(move || {
                let mut observed = Vec::new();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
                for (index, mut reply) in replies.into_iter().enumerate() {
                    let mut socket = loop {
                        match listener.accept() {
                            Ok((socket, _)) => break socket,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                if server_done.load(std::sync::atomic::Ordering::SeqCst)
                                    || std::time::Instant::now() >= deadline
                                {
                                    return observed;
                                }
                                std::thread::sleep(std::time::Duration::from_millis(2));
                            }
                            Err(error) => panic!("fixture accept: {error}"),
                        }
                    };
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let header_end = loop {
                        let mut chunk = [0; 4096];
                        let count = socket.read(&mut chunk).unwrap();
                        assert!(count > 0);
                        bytes.extend_from_slice(&chunk[..count]);
                        if let Some(position) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                            break position + 4;
                        }
                    };
                    let headers =
                        String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
                    assert!(headers.contains("authorization: bearer fixture-grant"));
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map(|length| length.trim().parse::<usize>().unwrap())
                        .unwrap_or(0);
                    while bytes.len() < header_end + length {
                        let mut chunk = [0; 4096];
                        let count = socket.read(&mut chunk).unwrap();
                        assert!(count > 0);
                        bytes.extend_from_slice(&chunk[..count]);
                    }
                    let route = headers.lines().next().unwrap().to_owned();
                    if index == 0 {
                        assert!(route.starts_with("post /_arkret/self/account/current-principal "));
                        let request: arkret_sdk::CurrentPrincipalRequestBody =
                            serde_json::from_slice(&bytes[header_end..header_end + length])
                                .unwrap();
                        reply["request_id"] = json!(request.request_id);
                    }
                    assert!(!route.contains("signer-keys") && !route.contains("snapshot"));
                    observed.push(route);
                    if index == 4 && refusal == "late_session" {
                        let old = holder.snapshot().unwrap();
                        *holder.0.lock().unwrap() = OwnStationSessionSnapshot::new(
                            old.binding().clone(),
                            old.account_id().clone(),
                            old.account_id().station_id.clone(),
                            old.grant_id().clone(),
                            old.epoch() + 1,
                            "fixture-grant".into(),
                        )
                        .unwrap()
                        .with_provider_identity(Default::default());
                    }
                    let body = serde_json::to_vec(&reply).unwrap();
                    write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", body.len()).unwrap();
                    socket.write_all(&body).unwrap();
                }
                observed
            });
            let control_realm = if refusal == "foreign_pcr" {
                arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
                    arkret_sdk::DigestSuite::Sha256,
                    [99; 32],
                ))
            } else {
                genesis.realm_id.clone()
            };
            let mut body = backup.clone();
            if refusal == "wrong_envelope_key" {
                body.signature_proof.signature =
                    arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
                        ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                            .sign(&body.signing_payload_bytes().unwrap())
                            .to_bytes(),
                    ))
                    .unwrap();
            }
            let result =
                verify_envelope_source(&raw, &source, &fixture.account, &control_realm, &body)
                    .await;
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            let observed = server.join().unwrap();
            assert_eq!(
                observed.len(),
                5,
                "native founding unit and method history must be read"
            );
            match refusal {
                "none" => result
                    .expect("holder-private founding authorization verifies without a public fact"),
                "foreign_pcr" => assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("another registered Account or PCR")
                ),
                "wrong_envelope_key" => assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("signature is invalid")
                ),
                "late_session" => {
                    assert!(result.is_err(), "withdrawn source cannot verify the backup")
                }
                _ => unreachable!(),
            }
        }
    }
}
