//! Federation trust bundle + transaction verification helpers.
//!
//! Spec: `sync/federation.md`. Cross-domain Event exchange requires:
//! - Each domain advertises `.well-known/contrix/server` with its service DID.
//! - Trust anchors are pinned per peer domain (DID + public key).
//! - Every `FederationTransaction` carries a signature the receiver verifies
//!   against the origin domain's trust anchor.
//!
//! Yougen previously called the federation HTTP endpoints (`api.rs:1458-1521`)
//! as opaque pass-throughs. This module adds a client-side trust bundle that
//! collects [`contrix_sdk::TrustAnchor`] entries, verifies the well-known
//! discovery record against the active anchor set, and gates inbound
//! `FederationTransaction` payloads on bundle membership.

use std::collections::BTreeMap;

use contrix_sdk::{FederationManager, FederationTransaction, TrustAnchor, WellKnownContrixServer};
use serde::{Deserialize, Serialize};

/// Outcome of trust bundle verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustCheck {
    /// Domain is pinned and the transaction's origin matches the anchor.
    Trusted,
    /// Domain is not in the bundle; reject the transaction.
    UnknownDomain(String),
    /// Domain is pinned but the transaction signature does not match.
    SignatureMismatch(String),
    /// Origin/destination disagreement (e.g. transaction sent to wrong host).
    OriginMismatch { declared: String, expected: String },
}

/// Pinned trust bundle. Maps `domain` → [`TrustAnchor`].
#[derive(Clone, Debug, Default)]
pub struct TrustBundle {
    anchors: BTreeMap<String, TrustAnchor>,
}

impl TrustBundle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin a [`TrustAnchor`] for `anchor.domain`. Subsequent calls overwrite
    /// the existing entry for that domain.
    pub fn add_anchor(&mut self, anchor: TrustAnchor) {
        self.anchors.insert(anchor.domain.clone(), anchor);
    }

    /// Remove a pinned anchor. Returns the removed anchor on success.
    pub fn remove(&mut self, domain: &str) -> Option<TrustAnchor> {
        self.anchors.remove(domain)
    }

    /// Lookup the anchor for a domain.
    pub fn anchor_for(&self, domain: &str) -> Option<&TrustAnchor> {
        self.anchors.get(domain)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &TrustAnchor)> {
        self.anchors.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Verify a [`FederationTransaction`] against this bundle. Checks origin
    /// pinning + destination matching. Signature verification is delegated to
    /// the SDK's `FederationManager` (the active service DID's public key is
    /// the trust anchor we pinned).
    pub fn verify_transaction(
        &self,
        local_domain: &str,
        transaction: &FederationTransaction,
    ) -> TrustCheck {
        let anchor = match self.anchors.get(&transaction.origin) {
            Some(a) => a,
            None => {
                return TrustCheck::UnknownDomain(transaction.origin.clone());
            }
        };
        if transaction.destination != local_domain {
            return TrustCheck::OriginMismatch {
                declared: transaction.destination.clone(),
                expected: local_domain.to_owned(),
            };
        }
        // Delegate signature verification to the SDK's canonical verifier
        // (`FederationManager::verify_transaction`), feeding it just this
        // anchor. Yougen pins the trust anchor; the SDK owns the signing
        // algorithm (today a SHA-256 chained MAC, in the future an Ed25519
        // detached signature). Routing through the SDK means yougen's
        // verification automatically tracks whatever wire-format the SDK
        // upgrades to, with no protocol drift between sender and receiver.
        if anchor.public_key.is_empty() || transaction.signature.is_empty() {
            return TrustCheck::SignatureMismatch(transaction.transaction_id.clone());
        }
        let mut sdk_mgr = FederationManager::new();
        sdk_mgr.add_trust_anchor(anchor.clone());
        if !sdk_mgr.verify_transaction(transaction) {
            return TrustCheck::SignatureMismatch(transaction.transaction_id.clone());
        }
        TrustCheck::Trusted
    }

    /// Verify a `.well-known/contrix/server` record against this bundle:
    /// the record's service DID must be pinned for `expected_domain`.
    pub fn verify_well_known(
        &self,
        expected_domain: &str,
        record: &WellKnownContrixServer,
    ) -> TrustCheck {
        let anchor = match self.anchors.get(expected_domain) {
            Some(a) => a,
            None => return TrustCheck::UnknownDomain(expected_domain.to_owned()),
        };
        // Pinned `public_key` is interpreted as the expected service DID
        // string until the SDK exposes a typed Ed25519 verifier surface to
        // yougen. We match it case-sensitively against the well-known DID.
        if anchor.public_key != record.service_did.as_str() {
            return TrustCheck::SignatureMismatch(record.service_did.as_str().to_owned());
        }
        TrustCheck::Trusted
    }
}

/// F-WELLKNOWN-1: errors surfaced by [`fetch_well_known_contrix_server`].
#[derive(Debug)]
pub enum WellKnownFetchError {
    /// `base_url` couldn't be turned into a URL (bad scheme, missing
    /// host, etc.).
    BadBaseUrl(String),
    /// HTTP request itself failed (network down, TLS error, etc.).
    Network(String),
    /// Server returned a non-2xx status.
    HttpStatus { status: u16, body: String },
    /// Response body wasn't a parseable `WellKnownContrixServer`.
    Decode(String),
}

impl std::fmt::Display for WellKnownFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadBaseUrl(s) => write!(f, "bad base url: {s}"),
            Self::Network(s) => write!(f, "well-known network error: {s}"),
            Self::HttpStatus { status, body } => {
                write!(f, "well-known HTTP {status}: {body}")
            }
            Self::Decode(s) => write!(f, "well-known decode error: {s}"),
        }
    }
}

impl std::error::Error for WellKnownFetchError {}

/// F-WELLKNOWN-1: derive the `.well-known/contrix/server` URL from a
/// service base URL.
///
/// Per `discovery/server-discovery.md`, the well-known record lives at
/// `https://<host>/.well-known/contrix/server` relative to the origin
/// — not under the service's `/api/v1` namespace. This helper trims a
/// trailing slash and concatenates the well-known path, returning an
/// error when `base_url` is empty or doesn't carry a scheme.
pub fn well_known_contrix_server_url(base_url: &str) -> Result<String, WellKnownFetchError> {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(WellKnownFetchError::BadBaseUrl(
            "base_url is empty".to_owned(),
        ));
    }
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(WellKnownFetchError::BadBaseUrl(format!(
            "missing scheme: {trimmed}"
        )));
    }
    // Strip everything after the host so we don't accidentally nest the
    // well-known path under an API prefix (`/api/v1`, etc.).
    let after_scheme = if let Some(rest) = trimmed.strip_prefix("https://") {
        ("https://", rest)
    } else {
        ("http://", trimmed.strip_prefix("http://").unwrap_or(trimmed))
    };
    let (scheme, rest) = after_scheme;
    let host_only = rest.split('/').next().unwrap_or(rest);
    if host_only.is_empty() {
        return Err(WellKnownFetchError::BadBaseUrl(format!(
            "missing host: {trimmed}"
        )));
    }
    Ok(format!("{scheme}{host_only}/.well-known/contrix/server"))
}

/// F-WELLKNOWN-1: fetch + parse the peer domain's
/// `.well-known/contrix/server` record.
///
/// Spec `discovery/server-discovery.md` mandates clients call this on
/// first contact with a new domain so they can pre-flight the service
/// DID against the trust bundle before issuing any privileged request.
/// Yougen wraps the SDK [`WellKnownContrixServer`] type — that struct
/// owns the JSON shape, and yougen owns the HTTP + error mapping.
///
/// This helper deliberately does **no** caching; the caller threads
/// the result through [`TrustBundle::verify_well_known`] and decides
/// what to persist (typically into the trust bundle alongside the
/// pinned anchor). Caching is a follow-up.
pub async fn fetch_well_known_contrix_server(
    base_url: &str,
) -> Result<WellKnownContrixServer, WellKnownFetchError> {
    let url = well_known_contrix_server_url(base_url)?;
    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|err| WellKnownFetchError::Network(err.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(WellKnownFetchError::HttpStatus {
            status: status.as_u16(),
            body,
        });
    }
    response
        .json::<WellKnownContrixServer>()
        .await
        .map_err(|err| WellKnownFetchError::Decode(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(domain: &str, key: &str) -> TrustAnchor {
        TrustAnchor {
            domain: domain.to_owned(),
            public_key: key.to_owned(),
        }
    }

    #[test]
    fn add_and_lookup_anchor() {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(anchor("alice.example", "did:web:alice.example"));
        assert_eq!(bundle.len(), 1);
        assert!(bundle.anchor_for("alice.example").is_some());
        assert!(bundle.anchor_for("bob.example").is_none());
    }

    #[test]
    fn unknown_origin_is_rejected() {
        let bundle = TrustBundle::new();
        let tx = FederationTransaction {
            transaction_id: "t1".into(),
            origin: "bob.example".into(),
            destination: "alice.example".into(),
            events: Vec::new(),
            signature: "sig".into(),
        };
        match bundle.verify_transaction("alice.example", &tx) {
            TrustCheck::UnknownDomain(d) => assert_eq!(d, "bob.example"),
            other => panic!("expected UnknownDomain, got {other:?}"),
        }
    }

    #[test]
    fn destination_mismatch_is_caught() {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(anchor("bob.example", "did:web:bob.example"));
        let tx = FederationTransaction {
            transaction_id: "t1".into(),
            origin: "bob.example".into(),
            destination: "carol.example".into(),
            events: Vec::new(),
            signature: "sig".into(),
        };
        match bundle.verify_transaction("alice.example", &tx) {
            TrustCheck::OriginMismatch { declared, expected } => {
                assert_eq!(declared, "carol.example");
                assert_eq!(expected, "alice.example");
            }
            other => panic!("expected OriginMismatch, got {other:?}"),
        }
    }

    #[test]
    fn pinned_origin_with_signature_passes() {
        // Use the SDK to produce a transaction whose signature matches the
        // verifier — yougen must accept exactly the same bytes the SDK
        // peer emits, otherwise federation breaks at the boundary.
        let mut sdk_mgr = FederationManager::new();
        let signing_key = "shared-secret-for-bob";
        sdk_mgr.add_trust_anchor(anchor("bob.example", signing_key));
        let tx =
            sdk_mgr.create_transaction("bob.example", "alice.example", Vec::new(), signing_key);

        let mut bundle = TrustBundle::new();
        bundle.add_anchor(anchor("bob.example", signing_key));
        assert_eq!(
            bundle.verify_transaction("alice.example", &tx),
            TrustCheck::Trusted
        );
    }

    #[test]
    fn pinned_origin_with_forged_signature_is_rejected() {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(anchor("bob.example", "bob-key"));
        // Hand-rolled signature that does NOT match the SDK's algorithm.
        let tx = FederationTransaction {
            transaction_id: "t-forged".into(),
            origin: "bob.example".into(),
            destination: "alice.example".into(),
            events: Vec::new(),
            signature: "obviously-wrong".into(),
        };
        match bundle.verify_transaction("alice.example", &tx) {
            TrustCheck::SignatureMismatch(id) => assert_eq!(id, "t-forged"),
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn pinned_origin_with_wrong_key_is_rejected() {
        // Sender used `wrong-key`; we pinned `right-key`. The signatures
        // mix the key into the hash chain, so they diverge.
        let mut sdk_mgr = FederationManager::new();
        sdk_mgr.add_trust_anchor(anchor("bob.example", "wrong-key"));
        let tx =
            sdk_mgr.create_transaction("bob.example", "alice.example", Vec::new(), "wrong-key");

        let mut bundle = TrustBundle::new();
        bundle.add_anchor(anchor("bob.example", "right-key"));
        match bundle.verify_transaction("alice.example", &tx) {
            TrustCheck::SignatureMismatch(_) => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn well_known_matches_pinned_did() {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(anchor("bob.example", "did:web:bob.example"));
        let record = WellKnownContrixServer {
            service_did: contrix_sdk::Did::new("did:web:bob.example".to_owned()).unwrap(),
            base_url: "https://bob.example".to_owned(),
            protocol_versions: vec!["1.0".to_owned()],
            endpoints: Vec::new(),
            capabilities: Default::default(),
        };
        assert_eq!(
            bundle.verify_well_known("bob.example", &record),
            TrustCheck::Trusted
        );
    }

    #[test]
    fn well_known_with_wrong_did_is_rejected() {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(anchor("bob.example", "did:web:bob.example"));
        let record = WellKnownContrixServer {
            service_did: contrix_sdk::Did::new("did:web:eve.example".to_owned()).unwrap(),
            base_url: "https://eve.example".to_owned(),
            protocol_versions: vec!["1.0".to_owned()],
            endpoints: Vec::new(),
            capabilities: Default::default(),
        };
        match bundle.verify_well_known("bob.example", &record) {
            TrustCheck::SignatureMismatch(_) => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    // ── F-WELLKNOWN-1 ────────────────────────────────────────────────

    #[test]
    fn well_known_url_derives_origin_from_base_url() {
        // Plain origin.
        assert_eq!(
            well_known_contrix_server_url("https://bob.example").unwrap(),
            "https://bob.example/.well-known/contrix/server"
        );
        // Origin + trailing slash.
        assert_eq!(
            well_known_contrix_server_url("https://bob.example/").unwrap(),
            "https://bob.example/.well-known/contrix/server"
        );
        // Origin + API prefix gets stripped — well-known lives at the
        // top of the host, not nested under /api/v1.
        assert_eq!(
            well_known_contrix_server_url("https://bob.example/api/v1").unwrap(),
            "https://bob.example/.well-known/contrix/server"
        );
        // Loopback dev URLs are allowed.
        assert_eq!(
            well_known_contrix_server_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080/.well-known/contrix/server"
        );
    }

    #[test]
    fn well_known_url_rejects_malformed_base_url() {
        assert!(matches!(
            well_known_contrix_server_url(""),
            Err(WellKnownFetchError::BadBaseUrl(_))
        ));
        assert!(matches!(
            well_known_contrix_server_url("   "),
            Err(WellKnownFetchError::BadBaseUrl(_))
        ));
        // Missing scheme.
        assert!(matches!(
            well_known_contrix_server_url("bob.example"),
            Err(WellKnownFetchError::BadBaseUrl(_))
        ));
        // Scheme only.
        assert!(matches!(
            well_known_contrix_server_url("https://"),
            Err(WellKnownFetchError::BadBaseUrl(_))
        ));
    }
}
