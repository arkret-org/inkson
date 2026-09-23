//! Typed transport for the Realm-only public Directory.

use std::sync::{Mutex, OnceLock, PoisonError};

use chrono::{Duration, Utc};
use garth::{PrefetchedRouteSource, ServiceRouteEvaluator};

use crate::models::DirectoryRealmResolutionOutcome;
use crate::wire_helpers::validate_cursor;

const DIRECTORY_ROUTE_CACHE_CAPACITY: usize = 16;
const DIRECTORY_ROUTE_CACHE_TTL_SECONDS: i64 = 300;

type DirectoryRouteEvaluator =
    ServiceRouteEvaluator<crate::media::service_route::InksonServiceRouteStore>;

struct DirectoryRouteCacheEntry {
    candidate_base: String,
    service_id: arkret_sdk::DidCoreId,
    route_base: String,
    valid_until: chrono::DateTime<Utc>,
    last_used_at: chrono::DateTime<Utc>,
    evaluator: DirectoryRouteEvaluator,
}

fn directory_route_cache() -> &'static Mutex<Vec<DirectoryRouteCacheEntry>> {
    static CACHE: OnceLock<Mutex<Vec<DirectoryRouteCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Vec::new()))
}

fn public_directory_client(base_url: &str) -> anyhow::Result<arkret_sdk::http_client::Client> {
    let base_url = crate::config::validate_server_url(base_url)?;
    arkret_sdk::http_client::ClientBuilder::new(base_url)
        .allow_insecure_localhost()
        .build()
        .map_err(|error| anyhow::anyhow!("build verified Directory client: {error}"))
}

fn realm_search_http_json_base(description: &arkret_sdk::ServiceDescribe) -> anyhow::Result<&str> {
    anyhow::ensure!(
        description.service_kind == arkret_sdk::ServiceKind::DirectoryService,
        "Directory role describe returned another service kind"
    );
    let operation = arkret_sdk::ServiceOperationId::from_wire(
        arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
    )
    .ok_or_else(|| anyhow::anyhow!("registered search_realms operation is missing"))?;
    anyhow::ensure!(
        description.supports_operation_binding(operation, arkret_sdk::BindingKind::HttpJson),
        "Directory does not advertise search_realms over HTTP/JSON"
    );
    let transport = description
        .select_transport_binding(operation, &[arkret_sdk::BindingKind::HttpJson])
        .ok_or_else(|| anyhow::anyhow!("Directory has no usable HTTP/JSON transport"))?;
    let arkret_sdk::TransportBinding::HttpJson { base_url, .. } = transport else {
        anyhow::bail!("Directory selected a non-HTTP/JSON transport");
    };
    Ok(base_url)
}

/// Resolve the Directory role independently from the Principal service and
/// return an unauthenticated client pinned to its verified public route.
pub async fn verified_directory_client(
    candidate_base_url: &str,
) -> anyhow::Result<arkret_sdk::http_client::Client> {
    let candidate = crate::config::validate_server_url(candidate_base_url)?.to_string();
    let now = Utc::now();
    if let Some(route_base) = {
        let mut cache = directory_route_cache()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        cache
            .iter_mut()
            .find(|entry| entry.candidate_base == candidate && now < entry.valid_until)
            .map(|entry| {
                entry.last_used_at = now;
                entry.route_base.clone()
            })
    } {
        return public_directory_client(&route_base);
    }

    let candidate_client = public_directory_client(&candidate)?;
    let description = candidate_client
        .describe_for_role(arkret_sdk::ServiceKind::DirectoryService)
        .await
        .map_err(|error| anyhow::anyhow!("Directory role describe failed: {error}"))?;
    let advertised_base = realm_search_http_json_base(&description)?;
    let service_id = description.service_id.clone();
    let authenticated_resolution = candidate_client
        .open_service_resolution(&service_id)
        .await
        .map_err(|error| anyhow::anyhow!("Directory service resolution failed: {error}"))?;
    let describe_binding =
        garth::describe_route_binding(&authenticated_resolution, &description, now).map_err(
            |error| anyhow::anyhow!("Directory describe reverse binding failed: {error}"),
        )?;
    anyhow::ensure!(
        describe_binding.base_url == *advertised_base,
        "Directory selected transport disagrees with its signed route"
    );

    let current_document = crate::media::service_route::fetch_current_service_document(
        &reqwest::Client::new(),
        &authenticated_resolution.normalized_did_document.id,
    )
    .await?;
    let authenticated_candidate =
        garth::authenticate_fetched_resolution(authenticated_resolution, current_document, now)?;
    let mut source = PrefetchedRouteSource::new(Some(authenticated_candidate));
    source.insert_describe(describe_binding);

    let route_base = {
        let mut cache = directory_route_cache()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let existing_index = cache
            .iter()
            .position(|entry| entry.candidate_base == candidate);
        let mut entry = if let Some(index) = existing_index {
            let entry = cache.remove(index);
            if entry.service_id != service_id {
                cache.push(entry);
                anyhow::bail!("Directory candidate changed service identity");
            }
            entry
        } else {
            DirectoryRouteCacheEntry {
                candidate_base: candidate.clone(),
                service_id: service_id.clone(),
                route_base: String::new(),
                valid_until: now,
                last_used_at: now,
                evaluator: ServiceRouteEvaluator::new(
                    crate::media::service_route::InksonServiceRouteStore::open_default(),
                    Duration::seconds(DIRECTORY_ROUTE_CACHE_TTL_SECONDS),
                )
                .map_err(|error| anyhow::anyhow!("create Directory route evaluator: {error}"))?,
            }
        };
        let resolved = match entry.evaluator.resolve(
            &service_id,
            arkret_sdk::ServiceKind::DirectoryService.as_str(),
            now,
            &mut source,
        ) {
            Ok(resolved) => resolved,
            Err(error) => {
                cache.push(entry);
                return Err(anyhow::anyhow!(
                    "Directory route verification failed: {error}"
                ));
            }
        };
        entry.route_base = resolved.route().base_url().to_owned();
        entry.valid_until = resolved.route().cache_expires_at;
        entry.last_used_at = now;
        let route_base = entry.route_base.clone();
        cache.push(entry);
        if cache.len() > DIRECTORY_ROUTE_CACHE_CAPACITY
            && let Some(oldest) = cache
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_used_at)
                .map(|(index, _)| index)
        {
            cache.remove(oldest);
        }
        route_base
    };
    public_directory_client(&route_base)
}

pub async fn search_realms(
    http: &arkret_sdk::http_client::Client,
    query: &str,
    next_cursor: Option<&str>,
) -> anyhow::Result<arkret_models_discovery::DirectoryRealmSearchOutcome> {
    let cursor = next_cursor
        .map(validate_cursor)
        .transpose()?
        .map(|cursor| cursor.into_string());
    let body = arkret_models_discovery::DirectorySearchRealmsRequestBody {
        query: (!query.trim().is_empty()).then(|| query.trim().to_owned()),
        limit: Some(20),
        cursor,
    };
    http.directory_search_realms(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn resolve_realm(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
) -> anyhow::Result<DirectoryRealmResolutionOutcome> {
    let body = arkret_models_discovery::DirectoryResolveRealmRequestBody {
        realm_id: arkret_sdk::RealmId::new(realm_id.trim().to_owned())?,
    };
    http.directory_resolve_realm(&body)
        .await
        .map_err(anyhow::Error::from)
}

#[cfg(test)]
mod route_tests {
    use arkret_sdk::{Did, ServiceKind, TransportBinding, TrustDomainId};

    use super::realm_search_http_json_base;

    fn description(service_kind: ServiceKind, bundles: Vec<String>) -> arkret_sdk::ServiceDescribe {
        arkret_sdk::ServiceDescribe::development(
            Did::new("did:web:directory.example").unwrap(),
            TrustDomainId::new("ak:trust_domain:directory.example").unwrap(),
            service_kind,
            bundles,
            vec![TransportBinding::HttpJson {
                base_url: "https://directory.example/".to_owned(),
                extension_profile_required: (),
            }],
        )
    }

    #[test]
    fn realm_directory_bundle_selects_http_json_route() {
        let description = description(
            ServiceKind::DirectoryService,
            vec!["ak.operation_bundle.directory_service.public_read.v1".to_owned()],
        );
        assert_eq!(
            realm_search_http_json_base(&description).unwrap(),
            "https://directory.example/"
        );
    }

    #[test]
    fn principal_description_is_never_a_directory_fallback() {
        let description = description(
            ServiceKind::Station,
            vec!["ak.operation_bundle.directory_service.public_read.v1".to_owned()],
        );
        assert!(realm_search_http_json_base(&description).is_err());
    }
}
