//! Host-bound ordinary governance consumption. Audit capabilities remain
//! distinct and are never manufactured from authenticated client responses.

use arkret_sdk::CommittedEventView;
use arkret_sdk::http_client::own_station_results::OwnStationResultClient;

mod sealed {
    pub trait Sealed {}
}

/// Only a Garth-produced capability can supply rows to durable projection.
/// Ordinary pages re-check their host/session fence on every consumption.
pub trait AcceptedPageRows: sealed::Sealed {
    fn accepted_rows(&self) -> Result<&[CommittedEventView], String>;
    fn accepted_account(&self) -> Option<&arkret_sdk::AccountId> {
        None
    }
}

impl sealed::Sealed for garth::VerifiedScanPage {}
impl AcceptedPageRows for garth::VerifiedScanPage {
    fn accepted_rows(&self) -> Result<&[CommittedEventView], String> {
        Ok(self.rows())
    }
}

impl sealed::Sealed for garth::own_station_results::OwnStationScanPage {}
impl AcceptedPageRows for garth::own_station_results::OwnStationScanPage {
    fn accepted_account(&self) -> Option<&arkret_sdk::AccountId> {
        Some(self.session().account_id())
    }
    fn accepted_rows(&self) -> Result<&[CommittedEventView], String> {
        self.rows().map_err(|error| error.to_string())
    }
}

pub(crate) async fn client_for_http(
    http: &arkret_sdk::http_client::Client,
) -> garth::Result<OwnStationResultClient> {
    if let Some(client) = http.own_station_result_client()? {
        return Ok(client);
    }
    crate::identity::session_refresh::own_station_result_client_for_http(http)
        .await
        .map_err(|error| garth::Error::Protocol(error.to_string()))
}

pub(crate) async fn verify_local_publication<T: arkret_sdk::PublicationRequest>(
    http: &arkret_sdk::http_client::Client,
    request: T,
) -> anyhow::Result<arkret_sdk::VerifiedSubmission<T>> {
    let client = client_for_http(http).await?;
    let actor = arkret_sdk::ActorId::account(client.session()?.account_id().clone());
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("producer signing context is unavailable"))?;
    let context = signer.publication_context(&actor)?;
    Ok(arkret_sdk::VerifiedSubmission::verify(request, |_| {
        Ok(context.clone())
    })?)
}

/// Read the immutable founding original only when the authenticated Station
/// discloses it. A withheld result never becomes a synthetic Genesis Event.
pub(crate) async fn accepted_genesis(
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
) -> garth::Result<arkret_sdk::CommittedEventFullView> {
    let client = client_for_http(http).await?;
    let response = genesis_response(&client, realm).await?;
    let arkret_sdk::CommittedEventView::Full(full) = response.into_value()? else {
        return Err(garth::Error::Protocol(
            "Genesis original is withheld".into(),
        ));
    };
    Ok(full)
}

pub(crate) async fn genesis_response(
    client: &OwnStationResultClient,
    realm: &arkret_sdk::RealmId,
) -> garth::Result<
    arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
        arkret_sdk::EventId,
        arkret_sdk::CommittedEventView,
    >,
> {
    let event_id = arkret_sdk::EventId::from_digest(
        realm.digest_suite_code().digest_suite(),
        realm.digest_bytes(),
    );
    let response = client.committed_event_get(&event_id).await?;
    let row = response.value()?;
    let commit = row.commit();
    let stream = arkret_sdk::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    if commit.realm_id != *realm
        || commit.event_ref != event_id
        || commit.stream_ref != stream
        || commit.stream_position != 0
        || commit.previous_commit_ref.is_some()
    {
        return Err(garth::Error::Protocol(
            "own Station Genesis original has inconsistent coordinates".into(),
        ));
    }
    let reference = arkret_sdk::CommittedEventRef {
        event_id,
        commit_id: commit.commit_id.clone(),
        stream_ref: stream,
        stream_position: 0,
    };
    let response =
        garth::own_station_results::consume_bound_event(client, &reference, response).await?;
    let arkret_sdk::CommittedEventView::Full(full) = response.value()? else {
        return Err(garth::Error::Protocol(
            "Genesis original is withheld".into(),
        ));
    };
    if full.event.kind != arkret_sdk::EventKind::RealmCreate
        || full.event.realm_id != *realm
        || full.event.scope_ref != arkret_sdk::ScopeRef::RealmGenesis
        || arkret_sdk::RealmId::from_event_id(&full.event.event_id) != *realm
    {
        return Err(garth::Error::Protocol(
            "own Station founding original is not Realm Genesis".into(),
        ));
    }
    let payload: arkret_sdk::RealmCreatePayload = serde_json::to_value(&full.event.payload)
        .and_then(serde_json::from_value)
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    payload
        .object
        .validate()
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    Ok(response)
}

/// Anchor private Consent independently of the read's claimed signer and tenure.
pub(crate) async fn consent_authority(
    http: &arkret_sdk::http_client::Client,
    client: &OwnStationResultClient,
    holder: &arkret_sdk::AccountId,
    registered_pcr: &arkret_sdk::RealmId,
) -> anyhow::Result<arkret_sdk::http_client::own_station_results::ConsentCurrentReadAuthority> {
    use arkret_sdk::http_client::own_station_results::ConsentCurrentReadAuthority;
    anyhow::ensure!(
        client.session()?.account_id() == holder,
        "Consent holder session changed"
    );
    let principal =
        crate::transport::account::current_principal_for_authority(http, holder).await?;
    anyhow::ensure!(
        principal.account_id == *holder && principal.principal_control_realm_id == *registered_pcr,
        "Consent authority differs from the registered holder PCR"
    );
    // The SDK Human constructor accepts the original disclosed by this exact
    // live own-Station session. PCR Genesis is not an ordinary collaboration
    // signer source and must not be routed through that separate verifier.
    let genesis_id = arkret_sdk::EventId::from_digest(
        registered_pcr.digest_suite_code().digest_suite(),
        registered_pcr.digest_bytes(),
    );
    let original = client.committed_event_get(&genesis_id).await?;
    let arkret_sdk::CommittedEventView::Full(full) = original.value()? else {
        anyhow::bail!("Consent authority requires the accepted PCR Genesis original");
    };
    let governance = arkret_sdk::GenesisGovernance::from_genesis(&full.event)?;
    if matches!(governance, arkret_sdk::GenesisGovernance::Human(_)) {
        return Ok(ConsentCurrentReadAuthority::from_human_genesis(
            holder,
            registered_pcr,
            &original,
        )?);
    }
    anyhow::ensure!(
        governance.is_principal_control(),
        "Consent authority is not a principal-control Realm"
    );
    let request = arkret_sdk::AuthorityBundleRequest {
        realm_id: registered_pcr.clone(),
        nonce: arkret_sdk::Base64UrlString::new(crate::random::base64url_token(
            32,
            "Consent authority nonce unavailable",
        )?)
        .map_err(|error| anyhow::anyhow!(error))?,
    };
    let bundle = garth::AuthorityClient::new(http.clone())
        .resolve_authority(&request)
        .await?;
    anyhow::ensure!(
        bundle.realm_id == *registered_pcr && bundle.genesis_event == full.event,
        "Consent authority chain differs from accepted holder inception"
    );
    let keys = garth::fetch_historical_station_key_directory(http, &bundle, None, None).await?;
    let verified = arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &arkret_identity::RealmAuthorityFreshness::new(crate::clock::now_utc(), request.nonce),
        &keys,
    )?;
    let route = http
        .open_service_resolution(verified.current_service_id())
        .await?;
    client.check_session()?;
    Ok(ConsentCurrentReadAuthority::from_verified_realm(
        &verified, &route,
    )?)
}

/// A holder's closed self-principal result pins its immutable PCR. Its lifetime
/// root reference is the Genesis Event identity from which that PCR is derived;
/// no private PCR Event is reclassified as a collaboration signing-key source.
pub(crate) async fn holder_pcr_root_ref(
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    holder: &arkret_sdk::AccountId,
) -> anyhow::Result<arkret_sdk::EventId> {
    let client = client_for_http(http).await?;
    anyhow::ensure!(
        client.session()?.account_id() == holder,
        "PCR root is not the current complete holder Account"
    );
    client.check_session()?;
    let current = crate::transport::account::current_principal_for_authority(http, holder).await?;
    client.check_session()?;
    anyhow::ensure!(
        current.account_id == *holder && current.principal_control_realm_id == *realm,
        "self principal result does not name the holder's exact pinned PCR"
    );
    Ok(arkret_sdk::EventId::from_digest(
        realm.digest_suite_code().digest_suite(),
        realm.digest_bytes(),
    ))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod test_http {
    use std::io::{Read, Write};
    use std::sync::Arc;

    use arkret_sdk::http_client::own_station_results::{
        OwnStationSessionSnapshot, OwnStationSessionSource,
    };

    use super::*;

    struct Source(
        OwnStationSessionSnapshot,
        Arc<std::sync::atomic::AtomicBool>,
    );
    impl OwnStationSessionSource for Source {
        fn snapshot(&self) -> arkret_sdk::http_client::Result<OwnStationSessionSnapshot> {
            if !self.1.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(arkret_sdk::http_client::Error::Protocol(
                    "session replaced".into(),
                ));
            }
            Ok(self.0.clone())
        }
    }
    /// Real bound-response fixture; it does not mint a private Bound directly
    /// or claim to validate a Station's session issuer/signatures.
    pub(crate) fn client(
        account: &arkret_sdk::AccountId,
        bodies: Vec<serde_json::Value>,
    ) -> (OwnStationResultClient, std::thread::JoinHandle<()>) {
        client_with_status(
            account,
            bodies.into_iter().map(|body| (200, body)).collect(),
        )
    }

    pub(crate) fn client_with_status(
        account: &arkret_sdk::AccountId,
        bodies: Vec<(u16, serde_json::Value)>,
    ) -> (OwnStationResultClient, std::thread::JoinHandle<()>) {
        let (client, server, _) = revocable_client(account, bodies, false);
        (client, server)
    }

    pub(crate) fn revocable_client(
        account: &arkret_sdk::AccountId,
        bodies: Vec<(u16, serde_json::Value)>,
        invalidate_on_response: bool,
    ) -> (
        OwnStationResultClient,
        std::thread::JoinHandle<()>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let binding = arkret_sdk::StationConnectionBinding {
            service_id: account.station_id.clone(),
            base_url: base.clone(),
            trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            auth_metadata: arkret_sdk::AuthMetadata::minimal(),
        };
        let session = OwnStationSessionSnapshot::new(
            binding.clone(),
            account.clone(),
            account.station_id.clone(),
            arkret_wire::SessionGrantId::from_issuance_digest([3; 32]),
            1,
            "own-result-grant".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default());
        let raw = arkret_sdk::http_client::ClientBuilder::new(url::Url::parse(&base).unwrap())
            .allow_insecure_localhost()
            .auth(arkret_sdk::http_client::Auth::Bearer(
                "own-result-grant".into(),
            ))
            .build()
            .unwrap();
        let active = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let server_active = active.clone();
        let server = std::thread::spawn(move || {
            for (status, body) in bodies {
                let (mut connection, _) = listener.accept().unwrap();
                connection
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 8192];
                let header_end = loop {
                    let n = connection.read(&mut buffer).unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buffer[..n]);
                    if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
                assert!(headers.contains("authorization: bearer own-result-grant"));
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .map(|n| n.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while request.len() < header_end + length {
                    let n = connection.read(&mut buffer).unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buffer[..n]);
                }
                let bytes = serde_json::to_vec(&body).unwrap();
                if invalidate_on_response {
                    server_active.store(false, std::sync::atomic::Ordering::SeqCst);
                }
                write!(connection,"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",bytes.len()).unwrap();
                connection.write_all(&bytes).unwrap();
            }
        });
        (
            OwnStationResultClient::new(raw, binding, Arc::new(Source(session, active.clone())))
                .unwrap(),
            server,
            active,
        )
    }
}
