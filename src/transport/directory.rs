//! Typed directory read transport.
//!
//! These are the pure-passthrough directory read operations that used to live
//! as thin inherent methods on [`crate::transport::TransportClient`]. They build a typed SDK
//! request body and call the shared SDK `http-client::Client` directly. Call
//! sites reach them through
//! [`crate::transport::auth::with_authed_sdk_client`], which keeps the
//! session-refresh + terminal-session classification identical to the old
//! facade path while dropping the per-domain facade method.

use serde_json::Value;

use crate::directory_helpers::{ResolveHandleContext, resolve_handle_request_body};
use crate::models::{
    ResolveHandleView, ResolveRealmOutcome, SearchActorsView, SearchOrganizationsView,
};
use crate::wire_helpers::validate_cursor;

pub async fn search_realms(
    http: &arkret_sdk::http_client::Client,
    query: &str,
    next_cursor: Option<&str>,
) -> anyhow::Result<arkret_sdk::models::DirectoryRealmSearchOutcome> {
    let cursor = next_cursor
        .map(validate_cursor)
        .transpose()?
        .map(|cursor| cursor.into_string());
    let body = arkret_sdk::models::DirectorySearchRealmsRequestBody {
        query: Some(query.to_owned()),
        organization_did: None,
        source_realm_id: None,
        requester: None,
        proof_challenge: None,
        claim_presentations: Vec::new(),
        cursor,
        limit: Some(20),
    };
    http.directory_search_realms(&body)
        .await
        .map_err(anyhow::Error::from)
}

/// Resolve a Realm by either its `ak:realm:<uuid>` id OR a human-readable
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
) -> anyhow::Result<ResolveRealmOutcome> {
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
    let body = arkret_sdk::models::DirectoryResolveRealmRequestBody {
        realm_id,
        alias,
        invite_token: None,
        signed_link: None,
        requester: None,
        proof_challenge: None,
        claim_presentations: Vec::new(),
    };
    http.directory_resolve_realm(&body)
        .await
        .map_err(anyhow::Error::from)
}

/// R3.3 (AKP-0011) — resolve a shareable object address (Realm / Strand /
/// Message) to a directory preview via `ak.find.directory.query.resolve_target`
/// (`POST /_arkret/find/directory/resolve-target`).
///
/// `address` is the canonical `web+arkret:` (or HTTPS-fragment) string
/// derived from [`arkret_sdk::models::parse_address`]; `token` is present
/// iff the address carried `lt=invite` or `lt=preview`. The server binds
/// an invite or preview token to the resolved object via the SDK's
/// [`arkret_sdk::models::verify_token_target`]; the client only forwards
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
) -> anyhow::Result<arkret_sdk::models::DirectoryTargetResolutionOutcome> {
    let body = arkret_sdk::models::DirectoryResolveTargetRequestBody {
        address: address.to_owned(),
        requester: None,
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
) -> anyhow::Result<SearchOrganizationsView> {
    let cursor = next_cursor
        .map(validate_cursor)
        .transpose()?
        .map(|cursor| cursor.into_string());
    let body = arkret_sdk::models::DirectorySearchOrganizationsRequestBody {
        query: Some(query.to_owned()),
        claims: Value::Null,
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
) -> anyhow::Result<SearchActorsView> {
    let cursor = next_cursor
        .map(validate_cursor)
        .transpose()?
        .map(|cursor| cursor.into_string());
    let body = arkret_sdk::models::DirectorySearchActorsRequestBody {
        query: Some(query.to_owned()),
        realm_id: None,
        organization_did: None,
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
    let outcome: arkret_sdk::models::DirectoryHandleResolutionOutcome = http
        .directory_resolve_handle(&body)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(outcome.into())
}

/// R3.2 (arkret-spec @ b56cab1) — `ak.find.directory.query.list_handles_for_subject`.
///
/// Inverse of [`resolve_handle`]: given a known holder/principal
/// DID, return the current context-visible signed handle claims +
/// the §3.2.1 primary handle. Powers the "Why am I seeing this
/// handle?" panel (YG-DIR-1/2) and the own-handles list (YG-HC-2).
///
/// The response is validated with
/// [`arkret_sdk::models::DirectorySubjectHandleList::validate`]
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
    intent: Option<&str>,
) -> anyhow::Result<arkret_sdk::models::DirectorySubjectHandleList> {
    use arkret_sdk::models::DirectoryListHandlesForSubjectRequestBody;

    let subject_did = arkret_sdk::Did::new(subject.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid subject DID `{subject}`: {err}"))?;
    let realm = match realm_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(r) => Some(
            arkret_sdk::RealmId::new(r)
                .map_err(|err| anyhow::anyhow!("invalid realm_id `{r}`: {err}"))?,
        ),
        None => None,
    };
    let body = DirectoryListHandlesForSubjectRequestBody {
        subject: subject_did,
        realm_id: realm,
        intent: intent
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned),
        requester: None,
        proof_challenge: None,
        proofs: Vec::new(),
        as_of: None,
        cursor: None,
        limit: None,
    };
    let res: arkret_sdk::models::DirectorySubjectHandleList = http
        .directory_list_handles_for_subject(&body)
        .await
        .map_err(anyhow::Error::from)?;
    // §0.2 fail-closed: drop the whole response if any claim's subject
    // doesn't match.
    res.validate()
        .map_err(|err| anyhow::anyhow!("list_handles_for_subject validation failed: {err}"))?;
    Ok(res)
}
