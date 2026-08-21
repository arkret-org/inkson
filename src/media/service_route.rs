//! Media-plane service-route evaluation — the client half of
//! `service-surface.md` §2.6 / L183 and `federation.md` §6.4.
//!
//! The RTC token exchange (`crate::media::rtc`) only accepts
//! evaluator-produced [`garth::RouteResolution`] material as issuer anchors.
//! This module makes that material real on this host:
//!
//! 1. [`InksonServiceRouteStore`] — the durable anti-rollback ledger (`{service_kind,
//!    last_seen_record_sequence, last_seen_record_digest}` plus notice / quarantine state). Native
//!    persists one JSON file per `(service_id, service_kind)` under the app data dir with
//!    write-temp-then-rename; wasm persists one localStorage entry per pair. Every save is wrapped
//!    in single-key CAS semantics (a persisted version counter must match the version this instance
//!    loaded) and a monotonic guard: the floor can never be lowered or erased and a quarantine can
//!    never be silently cleared. Restart / cache eviction therefore cannot lower the floor.
//! 2. [`fetch_route_material`] — SSRF-guarded, size-bounded fetches of the signed
//!    `ServiceResolutionRecord`, the target's DID document and the role-scoped `ServiceDescribe`,
//!    materialized through [`garth::authenticate_fetched_record`] /
//!    [`garth::describe_route_binding`]. The candidate origins come from the realm's accepted
//!    `ak.realm.media_service` cell and are treated as untrusted hints — every byte is
//!    independently verified against the target-signed record.
//! 3. [`evaluate_media_routes`] — runs [`garth::ServiceRouteEvaluator`] (durable floor advance,
//!    gap/fork quarantine, describe reverse binding) over the fetched material and returns the
//!    `Vec<RouteResolution>` the call panel passes into [`crate::media::rtc::MediaJoinRequest`].
//!    Any failure is a hard error the caller surfaces — never an empty "try anyway" vector.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use anyhow::Context as _;
use arkret_models_identity::{
    ServiceResolutionRecord, canonical_service_current_record_path,
    validate_service_current_record_url,
};
use arkret_sdk::identity::{DidKeyResolver, DidResolver as _, DidWebResolver};
use arkret_sdk::{DidCoreId, DidFullId};
use chrono::{DateTime, Utc};
use garth::{
    PrefetchedRouteSource, RouteResolution, ServiceDescribeBinding, ServiceRouteCandidate,
    ServiceRouteDurableSnapshot, ServiceRouteEvaluator, ServiceRouteStateStore,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const MEDIA_SERVICE_KIND: &str = "media_service";

/// Hard byte ceiling for fetched route material (record / describe), matching
/// the SDK service-resolution transport bound (`service-surface.md` §2.6).
const ROUTE_FETCH_MAX_BYTES: usize = 64 * 1024;

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
/// sequence 0), a lowered / erased floor is refused, and clearing a
/// quarantine requires deliberate out-of-band intervention rather than a
/// routine save.
pub struct InksonServiceRouteStore {
    #[cfg(not(target_arch = "wasm32"))]
    root: std::path::PathBuf,
    /// storage key → the persisted version this instance last loaded.
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
            let storage = crate::state::browser_storage().ok_or_else(|| {
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
            let storage = crate::state::browser_storage().ok_or_else(|| {
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
        // here would let a fresh floor re-anchor below the durable one.
        serde_json::from_str(&text).map(Some).map_err(|error| {
            garth::Error::Protocol(format!("service_route_ledger_corrupt: {error}"))
        })
    }
}

/// The durable floor may only stand still or advance; a quarantine may not be
/// silently cleared by a routine save.
fn guard_monotonic(
    previous: &ServiceRouteDurableSnapshot,
    next: &ServiceRouteDurableSnapshot,
) -> garth::Result<()> {
    match (&previous.floor, &next.floor) {
        (Some(prev), Some(new)) => {
            if new.record_sequence < prev.record_sequence
                || (new.record_sequence == prev.record_sequence
                    && new.record_digest != prev.record_digest)
            {
                return Err(garth::Error::Protocol(
                    "service_route_floor_regression_refused".to_owned(),
                ));
            }
        }
        (Some(_), None) => {
            return Err(garth::Error::Protocol(
                "service_route_floor_erase_refused".to_owned(),
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

/// Verified inputs for one evaluator run.
pub(crate) struct FetchedRouteMaterial {
    pub(crate) candidate: ServiceRouteCandidate,
    pub(crate) describe: ServiceDescribeBinding,
}

/// Candidate origins (`https://host[:port]/`) for each anchored media
/// `service_id`, read from the realm's accepted `ak.realm.media_service`
/// cell (`ice_config_endpoint` + `foci[].token_endpoint`). Untrusted hints:
/// the fetched record is independently verified against the target's own
/// signature and method adapter before any of it is trusted.
pub(crate) fn media_service_route_origins(
    state: &crate::state::ClientLocalState,
    realm_id: &str,
) -> BTreeMap<String, Vec<String>> {
    let mut origins_by_service: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for record in &state.raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if kind != arkret_wire::event_kind_str::REALM_MEDIA_SERVICE
            || record.realm_id.as_deref() != Some(realm_id)
        {
            continue;
        }
        let body = record
            .payload
            .get("body")
            .or_else(|| record.payload.get("payload"))
            .unwrap_or(&record.payload);
        let Some(service_id) = body.get("service_id").and_then(Value::as_str) else {
            continue;
        };
        let origins = origins_by_service.entry(service_id.to_owned()).or_default();
        let mut push_endpoint = |endpoint: &str| {
            if let Ok(url) = url::Url::parse(endpoint) {
                let origin = url.origin().ascii_serialization();
                if origin != "null" {
                    origins.insert(format!("{origin}/"));
                }
            }
        };
        if let Some(endpoint) = body.get("ice_config_endpoint").and_then(Value::as_str) {
            push_endpoint(endpoint);
        }
        if let Some(foci) = body.get("foci").and_then(Value::as_array) {
            for focus in foci {
                if let Some(endpoint) = focus.get("token_endpoint").and_then(Value::as_str) {
                    push_endpoint(endpoint);
                }
            }
        }
    }
    origins_by_service
        .into_iter()
        .map(|(service_id, origins)| (service_id, origins.into_iter().collect()))
        .collect()
}

/// Fetch and verify the route material for one media service, trying each
/// candidate origin in order. Every fetch goes through the shared DID-fetch
/// SSRF guard (native: DNS-pinned egress-locked client; wasm: static host
/// classification) and hard byte ceilings.
pub(crate) async fn fetch_route_material(
    http: &reqwest::Client,
    service_id: &DidCoreId,
    candidate_origins: &[String],
    now: DateTime<Utc>,
) -> anyhow::Result<FetchedRouteMaterial> {
    anyhow::ensure!(
        !candidate_origins.is_empty(),
        "realm media_service cell carries no endpoint origin for {service_id}"
    );
    let mut last_error = None;
    for origin in candidate_origins {
        match fetch_route_material_from_origin(http, service_id, origin, now).await {
            Ok(material) => return Ok(material),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("at least one origin was tried"))
}

async fn fetch_route_material_from_origin(
    http: &reqwest::Client,
    service_id: &DidCoreId,
    origin: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<FetchedRouteMaterial> {
    // First hop: the current signed ServiceResolutionRecord at the canonical
    // derived locator. The locator shape (canonical HTTPS, exact path) is
    // validated before any request leaves the process.
    let record_url = format!(
        "{}{}",
        origin.trim_end_matches('/'),
        canonical_service_current_record_path(service_id)
    );
    validate_service_current_record_url(&record_url, service_id)
        .map_err(|error| anyhow::anyhow!("derived record locator rejected: {error}"))?;
    let (_, record_bytes) =
        crate::identity::did_resolver::fetch_did_bytes(http, &record_url, ROUTE_FETCH_MAX_BYTES)
            .await
            .with_context(|| format!("service resolution fetch refused or failed: {record_url}"))?;
    let record: ServiceResolutionRecord =
        arkret_sdk::canonical::canonical::from_canonical_json_slice(&record_bytes)
            .map_err(|error| anyhow::anyhow!("service resolution record not canonical: {error}"))?;
    anyhow::ensure!(
        &record.record.service_id == service_id,
        "fetched service resolution targets a different service"
    );

    // Method-scoped DID document for the record's full id.
    let full_id: DidFullId = record.record.full_id.clone();
    let document = match full_id.method() {
        "web" => {
            let outcome = crate::identity::did_resolver::fetch_did_web_document(http, &full_id)
                .await
                .with_context(|| format!("did:web document fetch refused for {full_id}"))?;
            DidWebResolver::new()
                .insert_from_https_response(&full_id, outcome)
                .map_err(|error| anyhow::anyhow!("did:web document rejected: {error}"))?
        }
        "key" => {
            DidKeyResolver::new()
                .resolve_did(&full_id)
                .map_err(|error| anyhow::anyhow!("did:key expansion failed: {error}"))?
                .document
        }
        other => anyhow::bail!("no client route adapter for did method {other:?} (fail closed)"),
    };

    // Materialize + verify (route binding, method coordinates, target proof).
    let resolution = garth::authenticate_fetched_record(record.clone(), document, now)
        .map_err(|error| anyhow::anyhow!("route material verification failed: {error}"))?;

    // Second hop: role-scoped describe confirmation from the *verified* base.
    let describe_url = format!(
        "{}_arkret/describe?service_kind={MEDIA_SERVICE_KIND}",
        record.record.base_url
    );
    let (_, describe_bytes) =
        crate::identity::did_resolver::fetch_did_bytes(http, &describe_url, ROUTE_FETCH_MAX_BYTES)
            .await
            .with_context(|| format!("service describe fetch refused or failed: {describe_url}"))?;
    let describe: arkret_models_discovery::ServiceDescribe =
        serde_json::from_slice(&describe_bytes)
            .map_err(|error| anyhow::anyhow!("ServiceDescribe parse failed: {error}"))?;
    let describe = garth::describe_route_binding(&record, &describe, now)
        .map_err(|error| anyhow::anyhow!("describe reverse binding failed: {error}"))?;

    Ok(FetchedRouteMaterial {
        candidate: ServiceRouteCandidate { resolution },
        describe,
    })
}

// ─── Evaluation ──────────────────────────────────────────────────────────────

/// Run the evaluator (durable floor advance / gap-fork quarantine / describe
/// reverse binding) over prefetched material for one service.
pub(crate) fn resolve_route_with_material<S: ServiceRouteStateStore>(
    evaluator: &mut ServiceRouteEvaluator<S>,
    service_id: &DidCoreId,
    material: FetchedRouteMaterial,
    now: DateTime<Utc>,
) -> anyhow::Result<RouteResolution> {
    let mut source = PrefetchedRouteSource::new(Some(material.candidate));
    source.insert_describe(material.describe);
    evaluator
        .resolve(service_id, MEDIA_SERVICE_KIND, now, &mut source)
        .map_err(|error| anyhow::anyhow!("service route evaluation failed: {error}"))
}

/// Produce the evaluator-verified route material the RTC token exchange
/// requires, one [`RouteResolution`] per anchored media `service_id`.
///
/// Fail-closed: any fetch, verification, floor or quarantine failure is a
/// hard error — the caller must surface it and refuse the join, never degrade
/// to an empty route set.
pub async fn evaluate_media_routes(
    media_service_ids: &[String],
    endpoint_origins_by_service: &BTreeMap<String, Vec<String>>,
) -> anyhow::Result<Vec<RouteResolution>> {
    anyhow::ensure!(
        !media_service_ids.is_empty(),
        "realm has no anchored media service"
    );
    let http = reqwest::Client::new();
    let mut evaluator = ServiceRouteEvaluator::new(
        InksonServiceRouteStore::open_default(),
        chrono::Duration::minutes(5),
    )
    .map_err(|error| anyhow::anyhow!("service route evaluator init failed: {error}"))?;
    let mut routes = Vec::with_capacity(media_service_ids.len());
    for id in media_service_ids {
        let service_id = DidCoreId::new(id.clone())
            .map_err(|error| anyhow::anyhow!("invalid media service id {id}: {error}"))?;
        let origins = endpoint_origins_by_service
            .get(id)
            .cloned()
            .unwrap_or_default();
        let now = Utc::now();
        let material = fetch_route_material(&http, &service_id, &origins, now)
            .await
            .with_context(|| format!("media route material fetch failed for {id}"))?;
        routes.push(resolve_route_with_material(
            &mut evaluator,
            &service_id,
            material,
            now,
        )?);
    }
    Ok(routes)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use arkret_models_identity::ServiceResolutionLastSeenFloor;
    use arkret_sdk::Hash;
    use chrono::{Duration, TimeZone as _};
    use garth::service_route_material::test_fixture::signed_web_route_fixture;

    use super::*;

    fn floor_snapshot(
        service_id: &DidCoreId,
        sequence: u64,
        digest: char,
        now: DateTime<Utc>,
    ) -> ServiceRouteDurableSnapshot {
        ServiceRouteDurableSnapshot {
            service_id: service_id.clone(),
            service_kind: MEDIA_SERVICE_KIND.to_owned(),
            floor: Some(ServiceResolutionLastSeenFloor {
                service_id: service_id.clone(),
                service_kind: MEDIA_SERVICE_KIND.to_owned(),
                record_sequence: sequence,
                record_digest: Hash::new(format!("sha256:{}", digest.to_string().repeat(64)))
                    .unwrap(),
                verified_at: now,
            }),
            notice: None,
            quarantine: None,
        }
    }

    fn temp_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "inkson-route-store-{tag}-{}",
            crate::operation::uuid_v7()
        ))
    }

    fn now_fixture() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 20, 1, 0, 0).unwrap()
    }

    fn material_for(
        fixture: &garth::service_route_material::test_fixture::SignedRouteFixture,
        now: DateTime<Utc>,
    ) -> FetchedRouteMaterial {
        let resolution = garth::authenticate_fetched_record(
            fixture.record.clone(),
            fixture.document.clone(),
            now,
        )
        .unwrap();
        FetchedRouteMaterial {
            candidate: ServiceRouteCandidate { resolution },
            describe: garth::describe_route_binding(&fixture.record, &fixture.describe, now)
                .unwrap(),
        }
    }

    #[test]
    fn durable_store_survives_restart_and_keeps_the_floor() {
        let root = temp_root("restart");
        let now = now_fixture();
        let fixture =
            signed_web_route_fixture("media.example", MEDIA_SERVICE_KIND, now, 0, None, 31);

        // First "process": anchor at sequence 0.
        {
            let mut evaluator = ServiceRouteEvaluator::new(
                InksonServiceRouteStore::at_root(root.clone()),
                Duration::minutes(5),
            )
            .unwrap();
            let route = resolve_route_with_material(
                &mut evaluator,
                &fixture.service_id,
                material_for(&fixture, now),
                now,
            )
            .unwrap();
            assert_eq!(route.route().record_sequence, 0);
        }

        // Second "process": the durable floor is still there.
        let store = InksonServiceRouteStore::at_root(root.clone());
        let snapshot = store
            .load_route_state(&fixture.service_id, MEDIA_SERVICE_KIND)
            .unwrap()
            .expect("floor must survive restart");
        assert_eq!(snapshot.floor.as_ref().unwrap().record_sequence, 0);

        // Third "process": a freshly signed rollback offer (same sequence,
        // different digest) is quarantined, and the floor stays.
        let later = now + Duration::minutes(2);
        let rollback =
            signed_web_route_fixture("media.example", MEDIA_SERVICE_KIND, later, 0, None, 31);
        let mut evaluator = ServiceRouteEvaluator::new(
            InksonServiceRouteStore::at_root(root.clone()),
            Duration::minutes(5),
        )
        .unwrap();
        let error = resolve_route_with_material(
            &mut evaluator,
            &rollback.service_id,
            material_for(&rollback, later),
            later,
        )
        .unwrap_err();
        assert!(error.to_string().contains("service_route_gap_or_fork"));
        let store = InksonServiceRouteStore::at_root(root);
        let snapshot = store
            .load_route_state(&fixture.service_id, MEDIA_SERVICE_KIND)
            .unwrap()
            .unwrap();
        assert!(snapshot.quarantine.is_some());
        assert_eq!(snapshot.floor.unwrap().record_sequence, 0);
    }

    #[test]
    fn store_refuses_floor_regression_and_quarantine_clear() {
        let root = temp_root("monotonic");
        let now = now_fixture();
        let fixture =
            signed_web_route_fixture("media.example", MEDIA_SERVICE_KIND, now, 0, None, 31);
        let service_id = fixture.service_id.clone();
        let floor_at =
            |sequence: u64, digest: char| floor_snapshot(&service_id, sequence, digest, now);

        let mut store = InksonServiceRouteStore::at_root(root.clone());
        assert!(
            store
                .load_route_state(&service_id, MEDIA_SERVICE_KIND)
                .unwrap()
                .is_none()
        );
        store.save_route_state(&floor_at(3, 'a')).unwrap();

        // Lower sequence → refused.
        let mut fresh = InksonServiceRouteStore::at_root(root.clone());
        fresh
            .load_route_state(&service_id, MEDIA_SERVICE_KIND)
            .unwrap();
        let error = fresh.save_route_state(&floor_at(2, 'a')).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("service_route_floor_regression_refused")
        );

        // Same sequence, different digest → refused.
        let error = fresh.save_route_state(&floor_at(3, 'b')).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("service_route_floor_regression_refused")
        );

        // Quarantine may not be silently cleared.
        let mut quarantined = floor_at(3, 'a');
        quarantined.quarantine = Some(garth::RouteForkQuarantine {
            service_id: service_id.clone(),
            service_kind: MEDIA_SERVICE_KIND.to_owned(),
            expected_sequence: 3,
            expected_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            observed_sequence: 3,
            observed_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            reason: "fork".to_owned(),
            quarantined_at: now,
        });
        fresh.save_route_state(&quarantined).unwrap();
        let mut third = InksonServiceRouteStore::at_root(root);
        third
            .load_route_state(&service_id, MEDIA_SERVICE_KIND)
            .unwrap();
        let error = third.save_route_state(&floor_at(3, 'a')).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("service_route_quarantine_clear_refused")
        );
    }

    #[test]
    fn store_save_uses_single_key_cas() {
        let root = temp_root("cas");
        let now = now_fixture();
        let fixture =
            signed_web_route_fixture("media.example", MEDIA_SERVICE_KIND, now, 0, None, 31);
        let service_id = fixture.service_id.clone();
        let snapshot = floor_snapshot(&service_id, 1, 'c', now);

        let mut writer_a = InksonServiceRouteStore::at_root(root.clone());
        writer_a
            .load_route_state(&service_id, MEDIA_SERVICE_KIND)
            .unwrap();
        let mut writer_b = InksonServiceRouteStore::at_root(root);
        writer_b
            .load_route_state(&service_id, MEDIA_SERVICE_KIND)
            .unwrap();

        writer_b.save_route_state(&snapshot).unwrap();
        // Writer A loaded version 0 but the persisted entry is now version 1:
        // its save must be refused instead of silently clobbering.
        let error = writer_a.save_route_state(&snapshot).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("service_route_ledger_write_conflict")
        );
    }

    #[test]
    fn corrupt_ledger_entry_fails_closed_instead_of_reanchoring() {
        let root = temp_root("corrupt");
        let now = now_fixture();
        let fixture =
            signed_web_route_fixture("media.example", MEDIA_SERVICE_KIND, now, 0, None, 31);
        let service_id = fixture.service_id.clone();
        let key = InksonServiceRouteStore::ledger_key(&service_id, MEDIA_SERVICE_KIND);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(format!("{key}.json")), b"{not json").unwrap();
        let store = InksonServiceRouteStore::at_root(root);
        let error = store
            .load_route_state(&service_id, MEDIA_SERVICE_KIND)
            .unwrap_err();
        assert!(error.to_string().contains("service_route_ledger_corrupt"));
    }

    #[test]
    fn media_service_route_origins_reads_realm_cell_endpoints() {
        let mut state = crate::state::ClientLocalState::default();
        state.raw_operations.push(crate::state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned()),
            received_at: chrono::Utc::now(),
            payload: serde_json::json!({
                "kind": "ak.realm.media_service",
                "body": {
                    "service_id": "ak:did_core:web:media.example",
                    "ice_config_endpoint": "https://media.example/_arkret/self/rtc/ice-config",
                    "foci": [
                        {"focus_id": "fra-1", "type": "livekit",
                         "token_endpoint": "https://media.example/_arkret/self/rtc/token"},
                        {"focus_id": "us-east-1", "type": "livekit",
                         "token_endpoint": "https://media-use.example/_arkret/self/rtc/token"}
                    ]
                }
            }),
        });
        let origins = media_service_route_origins(
            &state,
            "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
        );
        assert_eq!(
            origins.get("ak:did_core:web:media.example").unwrap(),
            &vec![
                "https://media-use.example/".to_owned(),
                "https://media.example/".to_owned(),
            ]
        );
    }
}
