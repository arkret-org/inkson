use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::Context as _;
use arkret_sdk::identity::{DidResolver as _, DidWebResolver, DidWebvhResolver};
use arkret_sdk::{Did, DidCoreId};
use chrono::{DateTime, Utc};
use garth::{ServiceRouteCandidate, ServiceRouteDurableSnapshot, ServiceRouteStateStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
pub(crate) const MEDIA_SERVICE_KIND: &str = "media_service";

/// Hard byte ceiling for fetched DID route evidence and describe, matching
/// the SDK service-resolution transport bound (`service-surface.md` §2.6).
const ROUTE_FETCH_MAX_BYTES: usize = arkret_sdk::http_client::SERVICE_RESOLUTION_FETCH_MAX_BYTES;

// ─── Durable anti-rollback ledger ────────────────────────────────────────────

/// One persisted ledger entry. The `version` counter is the single-key CAS
/// token: a writer must have loaded exactly this version to replace it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedRouteLedger {
    version: u64,
    snapshot: ServiceRouteDurableSnapshot,
}

/// Durable [`ServiceRouteStateStore`] for this host.
///
/// Fail-closed by construction: a corrupt or identity-mismatched persisted
/// entry is an error (never `None`, which would allow silent re-anchoring at
/// an unanchored method state), a regressed / erased method state is refused, and clearing a
/// quarantine requires deliberate out-of-band intervention rather than a
/// routine save.
pub struct InksonServiceRouteStore {
    #[cfg(not(target_arch = "wasm32"))]
    root: std::path::PathBuf,
    /// Storage key → the persisted version this instance last loaded.
    loaded_versions: Mutex<BTreeMap<String, u64>>,
}

impl InksonServiceRouteStore {
    /// The production store at this host's default durable location.
    #[must_use]
    pub fn open_default() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self::at_root(crate::state::app_data_dir().join("service_routes"))
        }
        #[cfg(target_arch = "wasm32")]
        {
            Self {
                loaded_versions: Mutex::new(BTreeMap::new()),
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn at_root(root: std::path::PathBuf) -> Self {
        Self {
            root,
            loaded_versions: Mutex::new(BTreeMap::new()),
        }
    }

    /// Stable storage key for one `(service_id, service_kind)` ledger entry.
    /// Hash-derived so arbitrary DID bytes never reach a file name or
    /// localStorage key.
    fn ledger_key(service_id: &DidCoreId, service_kind: &str) -> String {
        let digest = crate::canonical::sha256_hex(
            format!("{}\n{service_kind}", service_id.as_str()).as_bytes(),
        );
        format!("service_route.v1.{}", &digest[..32])
    }

    fn read_raw(&self, key: &str) -> garth::Result<Option<String>> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = self.root.join(format!("{key}.json"));
            match std::fs::read_to_string(&path) {
                Ok(text) => Ok(Some(text)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(garth::Error::Protocol(format!(
                    "service_route_ledger_read_failed: {error}"
                ))),
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            let storage = crate::browser_storage::browser_storage().ok_or_else(|| {
                garth::Error::Protocol("service_route_ledger_unavailable".to_owned())
            })?;
            storage.get_item(&format!("inkson.{key}")).map_err(|error| {
                garth::Error::Protocol(format!("service_route_ledger_read_failed: {error:?}"))
            })
        }
    }

    fn write_raw(&self, key: &str, value: &str) -> garth::Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            use std::io::Write as _;

            std::fs::create_dir_all(&self.root).map_err(|error| {
                garth::Error::Protocol(format!("service_route_ledger_write_failed: {error}"))
            })?;
            let path = self.root.join(format!("{key}.json"));
            let tmp_path = self.root.join(format!("{key}.json.tmp"));
            let write = || -> std::io::Result<()> {
                {
                    let mut tmp = std::fs::File::create(&tmp_path)?;
                    tmp.write_all(value.as_bytes())?;
                    tmp.sync_all()?;
                }
                std::fs::rename(&tmp_path, &path)
            };
            write().map_err(|error| {
                garth::Error::Protocol(format!("service_route_ledger_write_failed: {error}"))
            })
        }
        #[cfg(target_arch = "wasm32")]
        {
            let storage = crate::browser_storage::browser_storage().ok_or_else(|| {
                garth::Error::Protocol("service_route_ledger_unavailable".to_owned())
            })?;
            storage
                .set_item(&format!("inkson.{key}"), value)
                .map_err(|error| {
                    garth::Error::Protocol(format!("service_route_ledger_write_failed: {error:?}"))
                })
        }
    }

    fn read_persisted(&self, key: &str) -> garth::Result<Option<PersistedRouteLedger>> {
        let Some(text) = self.read_raw(key)? else {
            return Ok(None);
        };
        // Corrupt bytes are an error, not an empty ledger: returning `None`
        // here would let silently replace the accepted method state.
        serde_json::from_str(&text).map(Some).map_err(|error| {
            garth::Error::Protocol(format!("service_route_ledger_corrupt: {error}"))
        })
    }
}

/// The durable method state may only stand still or advance; a quarantine may not be
/// silently cleared by a routine save.
fn guard_monotonic(
    previous: &ServiceRouteDurableSnapshot,
    next: &ServiceRouteDurableSnapshot,
) -> garth::Result<()> {
    match (&previous.method_state, &next.method_state) {
        (Some(prev), Some(new)) => {
            if new.verified_at < prev.verified_at
                || (prev.did.method() == "web" && new.did != prev.did)
            {
                return Err(garth::Error::Protocol(
                    "service_method_state_regression_refused".into(),
                ));
            }
            if prev.did.method() == "webvh" {
                let sequence = |version: &str| {
                    version
                        .split('-')
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                };
                let before = sequence(&prev.version_id).ok_or_else(|| {
                    garth::Error::Protocol("invalid persisted method version".into())
                })?;
                let after = sequence(&new.version_id)
                    .ok_or_else(|| garth::Error::Protocol("invalid next method version".into()))?;
                if after < before
                    || (after == before
                        && (new.method_history_head != prev.method_history_head
                            || new.did != prev.did))
                {
                    return Err(garth::Error::Protocol(
                        "service_method_state_regression_refused".into(),
                    ));
                }
            }
        }
        (Some(_), None) => {
            return Err(garth::Error::Protocol(
                "service_method_state_erase_refused".into(),
            ));
        }
        (None, _) => {}
    }
    if previous.quarantine.is_some() && next.quarantine.is_none() {
        return Err(garth::Error::Protocol(
            "service_route_quarantine_clear_refused".to_owned(),
        ));
    }
    Ok(())
}

impl ServiceRouteStateStore for InksonServiceRouteStore {
    fn load_route_state(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> garth::Result<Option<ServiceRouteDurableSnapshot>> {
        let key = Self::ledger_key(service_id, service_kind);
        match self.read_persisted(&key)? {
            None => {
                self.loaded_versions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(key, 0);
                Ok(None)
            }
            Some(persisted) => {
                if &persisted.snapshot.service_id != service_id
                    || persisted.snapshot.service_kind != service_kind
                {
                    return Err(garth::Error::Protocol(
                        "service_route_ledger_identity_mismatch".to_owned(),
                    ));
                }
                self.loaded_versions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(key, persisted.version);
                Ok(Some(persisted.snapshot))
            }
        }
    }

    fn save_route_state(&mut self, snapshot: &ServiceRouteDurableSnapshot) -> garth::Result<()> {
        let key = Self::ledger_key(&snapshot.service_id, &snapshot.service_kind);
        // Single-key CAS: re-read the persisted entry and require it to be the
        // exact version this instance loaded. On wasm (weak atomicity, two
        // tabs) this collapses lost-update races into a hard error.
        let current = self.read_persisted(&key)?;
        let current_version = current.as_ref().map(|entry| entry.version).unwrap_or(0);
        let expected = self
            .loaded_versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .copied();
        if expected != Some(current_version) {
            return Err(garth::Error::Protocol(
                "service_route_ledger_write_conflict".to_owned(),
            ));
        }
        if let Some(previous) = current.as_ref() {
            guard_monotonic(&previous.snapshot, snapshot)?;
        }
        let next = PersistedRouteLedger {
            version: current_version + 1,
            snapshot: snapshot.clone(),
        };
        let text = serde_json::to_string(&next).map_err(|error| {
            garth::Error::Protocol(format!("service_route_ledger_encode_failed: {error}"))
        })?;
        self.write_raw(&key, &text)?;
        self.loaded_versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, next.version);
        Ok(())
    }
}

// ─── Route-material fetch (async, SSRF-guarded) ──────────────────────────────

pub(crate) async fn authenticated_candidate_from_did(
    http: &reqwest::Client,
    service_id: &DidCoreId,
    service_kind: &str,
    did: &Did,
    now: DateTime<Utc>,
) -> anyhow::Result<ServiceRouteCandidate> {
    anyhow::ensure!(
        arkret_sdk::project_did_to_core_id(did)? == *service_id,
        "service method does not bind the requested service"
    );
    let (current, log_entries, witness_records) = fetch_current_service_material(http, did).await?;
    let resolution = match did.method() {
        "webvh" => arkret_identity::build_authenticated_webvh_service_resolution(
            service_id.clone(),
            service_kind.to_owned(),
            current.document.clone(),
            log_entries,
            witness_records,
            now,
        )?,
        "web" => arkret_identity::build_authenticated_did_web_service_resolution(
            service_id.clone(),
            service_kind.to_owned(),
            current.document.clone(),
            now,
        )?,
        _ => anyhow::bail!("unsupported persisted service method"),
    };
    let candidate = garth::authenticate_fetched_resolution(resolution, current, now)?;
    Ok(candidate)
}

// ─── Evaluation ──────────────────────────────────────────────────────────────

/// Produce the evaluator-verified route material the RTC token exchange
/// requires, one verified binding per anchored media `service_id`.
///
/// Fail-closed: any fetch, verification, method state or quarantine failure is a
/// hard error — the caller must surface it and refuse the join, never degrade
/// to an empty route set.
pub type VerifiedMediaBinding =
    arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
        (
            arkret_sdk::MediaServiceBindingRequestBody,
            arkret_sdk::DidCoreId,
        ),
        arkret_sdk::MediaServiceBindingOutcome,
    >;

pub async fn binding_for_http(
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    service: &arkret_sdk::DidCoreId,
) -> anyhow::Result<VerifiedMediaBinding> {
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    let request = arkret_sdk::MediaServiceBindingRequestBody {
        request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
        realm_id: realm.clone(),
    };
    Ok(client.media_service_binding(&request, service).await?)
}

pub async fn evaluate_media_routes(
    own_station_base: &str,
    realm: &str,
    media_service_ids: &[String],
) -> anyhow::Result<Vec<VerifiedMediaBinding>> {
    anyhow::ensure!(
        !media_service_ids.is_empty(),
        "Realm has no accepted media service"
    );
    let http = crate::identity::session_refresh::provide_authenticated_sdk_client(own_station_base)
        .await?;
    let realm = arkret_sdk::RealmId::new(realm.to_owned())?;
    let mut bindings = Vec::new();
    for service in media_service_ids {
        bindings.push(binding_for_http(&http, &realm, &DidCoreId::new(service.clone())?).await?);
    }
    Ok(bindings)
}

/// Fresh method-scoped fetch shared by media and Directory consumers.
pub(crate) async fn fetch_current_service_document(
    http: &reqwest::Client,
    did: &Did,
) -> anyhow::Result<arkret_identity::ResolvedDid> {
    Ok(fetch_current_service_material(http, did).await?.0)
}

async fn fetch_current_service_material(
    http: &reqwest::Client,
    did: &Did,
) -> anyhow::Result<(arkret_identity::ResolvedDid, Vec<Value>, Vec<Value>)> {
    let expected_core = arkret_sdk::project_did_to_core_id(did)?;
    let mut current_did = did.clone();
    for _ in 0..4 {
        let did = &current_did;
        match did.method() {
            "web" => {
                let outcome = super::http_fetch::fetch_did_web_document(http, did)
                    .await
                    .context("did:web current fetch failed")?;
                return Ok((
                    arkret_identity::ResolvedDid::proofless(
                        DidWebResolver::new().insert_from_https_response(did, outcome)?,
                    ),
                    Vec::new(),
                    Vec::new(),
                ));
            }
            "webvh" => {
                let log_url = DidWebvhResolver::log_url(did)?;
                let (log_type, log_body) =
                    super::http_fetch::fetch_did_bytes(http, &log_url, ROUTE_FETCH_MAX_BYTES)
                        .await
                        .context("did:webvh current log fetch failed")?;
                let discovered =
                    arkret_identity::discover_webvh_current_did(&expected_core, &log_body)?;
                if discovered != current_did {
                    current_did = discovered;
                    continue;
                }
                let doc_url = DidWebvhResolver::document_url(did)?;
                let (doc_type, doc_body) = super::http_fetch::fetch_did_bytes(
                    http,
                    &doc_url,
                    arkret_identity::DID_WEB_MAX_DOCUMENT_BYTES,
                )
                .await
                .context("did:webvh current document fetch failed")?;
                let mut resolver = DidWebvhResolver::new();
                resolver.insert_from_https_response(
                    did,
                    arkret_identity::DidWebvhDocumentOutcome {
                        url: doc_url,
                        content_type: doc_type,
                        body: doc_body,
                    },
                )?;
                let verified_log =
                    arkret_identity::verify_did_webvh_v1_chain_bytes(did, &log_body)?;
                resolver.ingest_log(
                    did,
                    arkret_identity::DidWebvhLogOutcome {
                        url: log_url,
                        content_type: log_type,
                        body: log_body,
                    },
                )?;
                let mut witness_records = Vec::new();
                let witness_url = DidWebvhResolver::witness_url(did)?;
                if let Some((_, bytes)) =
                    super::http_fetch::fetch_did_bytes(http, &witness_url, ROUTE_FETCH_MAX_BYTES)
                        .await
                {
                    resolver.ingest_witness_records(did, &bytes)?;
                    witness_records = serde_json::from_slice(&bytes)?;
                }
                return Ok((
                    resolver.resolve_did(did)?,
                    verified_log.raw_entries,
                    witness_records,
                ));
            }
            _ => anyhow::bail!("unsupported service DID method"),
        }
    }
    anyhow::bail!("DID portability discovery exceeded hop limit")
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use garth::service_route_material::test_fixture::current_web_route_fixture;

    use super::*;
    fn state(now: DateTime<Utc>) -> ServiceRouteDurableSnapshot {
        let now = DateTime::from_timestamp_millis(now.timestamp_millis()).unwrap();
        let fixture = current_web_route_fixture("media.example", MEDIA_SERVICE_KIND, 31);
        let projection = fixture.resolution.projection().unwrap();
        ServiceRouteDurableSnapshot {
            service_id: projection.service_id.clone(),
            service_kind: MEDIA_SERVICE_KIND.into(),
            method_state: Some(arkret_models_identity::ServiceMethodState {
                service_id: projection.service_id,
                service_kind: MEDIA_SERVICE_KIND.into(),
                did: projection.did,
                method_history_head: projection.method_history_head,
                version_id: projection.version_id,
                verified_at: now,
            }),
            quarantine: None,
        }
    }
    #[test]
    fn native_method_state_survives_restart_and_cas_rejects_stale_writer() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_path_buf();
        let snapshot = state(Utc::now());
        let mut first = InksonServiceRouteStore::at_root(root.clone());
        let mut stale = InksonServiceRouteStore::at_root(root.clone());
        first
            .load_route_state(&snapshot.service_id, MEDIA_SERVICE_KIND)
            .unwrap();
        stale
            .load_route_state(&snapshot.service_id, MEDIA_SERVICE_KIND)
            .unwrap();
        first.save_route_state(&snapshot).unwrap();
        assert!(stale.save_route_state(&snapshot).is_err());
        let restarted = InksonServiceRouteStore::at_root(root.clone());
        assert_eq!(
            restarted
                .load_route_state(&snapshot.service_id, MEDIA_SERVICE_KIND)
                .unwrap(),
            Some(snapshot)
        );
    }
    #[test]
    fn accepted_method_state_and_quarantine_cannot_be_erased() {
        let snapshot = state(Utc::now());
        let mut erased = snapshot.clone();
        erased.method_state = None;
        assert!(guard_monotonic(&snapshot, &erased).is_err());
        let mut quarantined = snapshot.clone();
        quarantined.quarantine = Some(garth::RouteForkQuarantine {
            reason: "native fork".into(),
            quarantined_at: Utc::now(),
        });
        assert!(guard_monotonic(&quarantined, &snapshot).is_err());
    }
}
