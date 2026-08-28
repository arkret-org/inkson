//! Typed directory read transport.
//!
//! These are the pure-passthrough directory read operations that used to live
//! as thin inherent methods on [`crate::transport::TransportClient`]. They build a typed SDK
//! request body and call the shared SDK `http-client::Client` directly. Call
//! sites reach them through
//! [`crate::transport::auth::with_directory_sdk_client`], which verifies an
//! independent Directory role route and never derives Directory capability
//! from the Principal description.

use std::sync::{Mutex, OnceLock, PoisonError};

use arkret_models_discovery::{DirectoryActorSearchOutcome, DirectoryOrganizationSearchOutcome};
use chrono::{Duration, Utc};
use garth::{
    MemoryServiceRouteStateStore, PrefetchedRouteSource, ServiceRouteCandidate,
    ServiceRouteEvaluator,
};

use crate::directory_helpers::{ResolveHandleContext, resolve_handle_request_body};
use crate::models::{DirectoryRealmResolutionOutcome, ResolveHandleView};
use crate::wire_helpers::validate_cursor;

const DIRECTORY_ROUTE_CACHE_CAPACITY: usize = 16;
const DIRECTORY_ROUTE_CACHE_TTL_SECONDS: i64 = 300;

type DirectoryRouteEvaluator = ServiceRouteEvaluator<MemoryServiceRouteStateStore>;

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

fn list_handles_http_json_base(description: &arkret_sdk::ServiceDescribe) -> anyhow::Result<&str> {
    anyhow::ensure!(
        description.service_kind == arkret_sdk::ServiceKind::DirectoryService,
        "Directory role describe returned another service kind"
    );
    let operation = arkret_sdk::ServiceOperationId::from_wire(
        arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT_V1,
    )
    .expect("list_handles_for_subject is a generated registered operation");
    anyhow::ensure!(
        description.supports_operation_binding(operation, arkret_sdk::BindingKind::HttpJson),
        "Directory does not advertise the exact list_handles_for_subject HTTP/JSON binding"
    );
    let transport = description
        .select_transport_binding(operation, &[arkret_sdk::BindingKind::HttpJson])
        .ok_or_else(|| anyhow::anyhow!("Directory has no usable HTTP/JSON transport"))?;
    let arkret_sdk::TransportBinding::HttpJson {
        base_uri: base_url, ..
    } = transport
    else {
        anyhow::bail!("Directory selected a non-HTTP/JSON transport");
    };
    Ok(base_url)
}

/// Resolve the co-located Directory role independently from the Principal
/// description and return an unauthenticated client pinned to its verified
/// HTTP/JSON route.
///
/// The Principal session grant is deliberately not attached: Directory reads
/// carry their own requester/proof fields and a Principal-scoped bearer must
/// never be forwarded to a separately resolved service.
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
    let advertised_base = list_handles_http_json_base(&description)?;

    let service_id = description.service_id.clone();
    let authenticated_resolution = candidate_client
        .open_service_resolution(&service_id)
        .await
        .map_err(|error| anyhow::anyhow!("Directory service resolution failed: {error}"))?;
    let describe_binding = garth::describe_route_binding(
        &authenticated_resolution.service_resolution_record,
        &description,
        now,
    )
    .map_err(|error| anyhow::anyhow!("Directory describe reverse binding failed: {error}"))?;
    anyhow::ensure!(
        describe_binding.base_url == *advertised_base,
        "Directory selected transport disagrees with its signed route"
    );

    let mut source = PrefetchedRouteSource::new(Some(ServiceRouteCandidate {
        resolution: authenticated_resolution,
    }));
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
                anyhow::bail!("Directory candidate changed service identity without handover");
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
                    MemoryServiceRouteStateStore::default(),
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
        entry.route_base = resolved.route().base_uri.clone();
        entry.valid_until = resolved.route().cache_expires_at;
        entry.last_used_at = now;
        let route_base = entry.route_base.clone();
        cache.push(entry);
        if cache.len() > DIRECTORY_ROUTE_CACHE_CAPACITY {
            let oldest = cache
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_used_at)
                .map(|(index, _)| index)
                .expect("over-capacity Directory cache is non-empty");
            cache.remove(oldest);
        }
        route_base
    };

    public_directory_client(&route_base)
}

#[cfg(test)]
mod route_tests {
    use arkret_sdk::{Did, ServiceKind, TransportBinding, TrustDomainId};

    use super::list_handles_http_json_base;

    fn description(service_kind: ServiceKind, bundles: Vec<String>) -> arkret_sdk::ServiceDescribe {
        arkret_sdk::ServiceDescribe::development(
            Did::new("did:web:directory.example").unwrap(),
            TrustDomainId::new("ak:trust_domain:directory.example").unwrap(),
            service_kind,
            bundles,
            vec![TransportBinding::HttpJson {
                base_uri: "https://directory.example/".to_owned(),
                extension_profile_required: (),
            }],
        )
    }

    #[test]
    fn exact_directory_bundle_selects_http_json_route() {
        let description = description(
            ServiceKind::DirectoryService,
            vec!["ak.operation_bundle.directory_service.http_core.v1".to_owned()],
        );
        assert_eq!(
            list_handles_http_json_base(&description).unwrap(),
            "https://directory.example/"
        );
    }

    #[test]
    fn principal_description_is_never_a_directory_fallback() {
        let description = description(
            ServiceKind::PrincipalServer,
            vec!["ak.operation_bundle.directory_service.http_core.v1".to_owned()],
        );
        assert!(list_handles_http_json_base(&description).is_err());
    }

    #[test]
    fn missing_directory_bundle_fails_closed() {
        let description = description(
            ServiceKind::DirectoryService,
            vec!["ak.operation_bundle.directory_service.describe.v1".to_owned()],
        );
        assert!(list_handles_http_json_base(&description).is_err());
    }
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
        query: Some(query.to_owned()),
        organization_principal_id: None,
        source_realm_id: None,
        requester_id: None,
        proof_challenge: None,
        claim_presentations: Vec::new(),
        cursor,
        limit: Some(20),
    };
    http.directory_search_realms(&body)
        .await
        .map_err(anyhow::Error::from)
}

/// Resolve a Realm by either its event-derived `ak:realm:<event-token>` id OR a human-readable
/// realm alias (`engineering`, `engineering:acme.example`, `#engineering…`).
///
/// The input is classified: a valid [`arkret_sdk::RealmId`] is sent as
/// `realm_id`; otherwise it is treated as an alias — the `#` share sigil is
/// stripped and the bare localpart / canonical form is sent as `alias`,
/// which soland binds to its deployment authority domain and validates
/// (object-addressing.md §3.3). The client need not know the deployment
/// domain to look up by a bare localpart.
pub async fn resolve_realm(
    http: &arkret_sdk::http_client::Client,
    realm_id_or_alias: &str,
) -> anyhow::Result<DirectoryRealmResolutionOutcome> {
    resolve_realm_with_invite_token(http, realm_id_or_alias, None).await
}

pub async fn resolve_realm_with_invite_token(
    http: &arkret_sdk::http_client::Client,
    realm_id_or_alias: &str,
    invite_token: Option<&str>,
) -> anyhow::Result<DirectoryRealmResolutionOutcome> {
    let input = realm_id_or_alias.trim();
    let (realm_id, alias) = match arkret_sdk::RealmId::new(input) {
        Ok(realm) => (Some(realm), None),
        Err(_) => {
            let alias = input.trim_start_matches('#').trim();
            if alias.is_empty() {
                return Err(anyhow::anyhow!("empty realm id / alias"));
            }
            (None, Some(alias.to_owned()))
        }
    };
    let body = arkret_models_discovery::DirectoryResolveRealmRequestBody {
        realm_id,
        alias,
        invite_token: invite_token.map(str::to_owned),
        signed_link: None,
        requester_id: None,
        proof_challenge: None,
        claim_presentations: Vec::new(),
    };
    http.directory_resolve_realm(&body)
        .await
        .map_err(anyhow::Error::from)
}

/// R3.3 (AKP-0011) — resolve a shareable object address (Realm / Strand /
/// Message) to a directory preview via `ak.find.directory.read.resolve_target.v1`
/// (`POST /_arkret/find/directory/resolve-target`).
///
/// `address` is the canonical `web+arkret:` (or HTTPS-fragment) string
/// derived from [`arkret_wire::parse_address`]; `token` is present
/// iff the address carried `lt=invite` or `lt=preview`. The server binds
/// an invite or preview token to the resolved object via the SDK's
/// [`arkret_wire::verify_token_target`]; the client only forwards
/// the opaque token here.
///
/// Wraps the SDK's typed request/response bodies so the wire shape stays
/// in sync with `spec/v1` (mirrors how [`resolve_realm`] wraps the
/// `resolve-realm` endpoint). On any failure the caller MUST collapse the
/// error to a single "link unavailable" message — `not_found` and
/// `unauthorized` are intentionally indistinguishable (anti-enumeration).
pub async fn directory_resolve_target(
    http: &arkret_sdk::http_client::Client,
    address: &str,
    token: Option<&str>,
) -> anyhow::Result<arkret_models_discovery::DirectoryTargetResolutionOutcome> {
    let body = arkret_models_discovery::DirectoryResolveTargetRequestBody {
        address: address.to_owned(),
        requester_id: None,
        proof_challenge: None,
        claim_presentations: Vec::new(),
        proofs: Vec::new(),
        token: token.map(str::to_owned),
    };
    http.directory_resolve_target(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn search_organizations(
    http: &arkret_sdk::http_client::Client,
    query: &str,
    next_cursor: Option<&str>,
) -> anyhow::Result<DirectoryOrganizationSearchOutcome> {
    let cursor = next_cursor
        .map(validate_cursor)
        .transpose()?
        .map(|cursor| cursor.into_string());
    let body = arkret_models_discovery::DirectorySearchOrganizationsRequestBody {
        query: Some(query.to_owned()),
        claims: None,
        cursor,
        limit: Some(20),
    };
    http.directory_search_organizations(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn search_actors(
    http: &arkret_sdk::http_client::Client,
    query: &str,
    next_cursor: Option<&str>,
) -> anyhow::Result<DirectoryActorSearchOutcome> {
    let cursor = next_cursor
        .map(validate_cursor)
        .transpose()?
        .map(|cursor| cursor.into_string());
    let body = arkret_models_discovery::DirectorySearchActorsRequestBody {
        query: Some(query.to_owned()),
        realm_id: None,
        organization_principal_id: None,
        cursor,
        limit: Some(20),
    };
    http.directory_search_actors(&body)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn resolve_handle(
    http: &arkret_sdk::http_client::Client,
    handle: &str,
) -> anyhow::Result<ResolveHandleView> {
    let body = resolve_handle_request_body(
        handle,
        ResolveHandleContext {
            intent: Some("lookup"),
            ..ResolveHandleContext::default()
        },
    )?;
    let outcome: arkret_models_discovery::DirectoryHandleResolutionOutcome = http
        .directory_resolve_handle(&body)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(outcome.into())
}

/// R3.2 (arkret-spec @ b56cab1) — `ak.find.directory.read.list_handles_for_subject.v1`.
///
/// Inverse of [`resolve_handle`]: given a known holder/principal
/// DID, return the current context-visible signed handle claims +
/// the §3.2.1 primary handle. Powers the "Why am I seeing this
/// handle?" panel (YG-DIR-1/2) and the own-handles list (YG-HC-2).
///
/// The response is validated with
/// [`arkret_models_discovery::DirectorySubjectHandleList::validate`]
/// which fails closed unless every `claims[].subject` byte-equals the
/// response `subject`.
///
/// `realm_id` / `intent` scope the disclosure policy; pass `None` for
/// an unscoped lookup. `TODO(R3.2.1)`: thread `requester` /
/// `proof_challenge` / `proofs` for proof-gated disclosure.
pub async fn list_handles_for_subject(
    http: &arkret_sdk::http_client::Client,
    subject: &str,
    realm_id: Option<&str>,
    intent: Option<arkret_models_discovery::DirectoryIntent>,
) -> anyhow::Result<arkret_models_discovery::DirectorySubjectHandleList> {
    use arkret_models_discovery::DirectoryListHandlesForSubjectRequestBody;

    let subject_id = crate::mls_api_helpers::principal_core_id(subject)
        .map_err(|err| anyhow::anyhow!("invalid subject DID `{subject}`: {err}"))?;
    let realm = match realm_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(r) => Some(
            arkret_sdk::RealmId::new(r)
                .map_err(|err| anyhow::anyhow!("invalid realm_id `{r}`: {err}"))?,
        ),
        None => None,
    };
    let body = DirectoryListHandlesForSubjectRequestBody {
        subject_id,
        realm_id: realm,
        intent: intent.map(|value| value.as_str().to_owned()),
        requester_id: None,
        proof_challenge: None,
        proofs: Vec::new(),
        as_of: None,
        cursor: None,
        limit: None,
    };
    let res: arkret_models_discovery::DirectorySubjectHandleList = http
        .directory_list_handles_for_subject(&body)
        .await
        .map_err(anyhow::Error::from)?;
    // §0.2 fail-closed: drop the whole response if any claim's subject
    // doesn't match.
    res.validate()
        .map_err(|err| anyhow::anyhow!("list_handles_for_subject validation failed: {err}"))?;
    Ok(res)
}
