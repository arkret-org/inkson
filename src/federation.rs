//! Federation trust bundle helpers.
//!
//! Spec: `sync/federation.md`. Cross-domain Event exchange requires:
//! - Each domain advertises `.well-known/arkret/server` with its service DID.
//! - Trust seals are pinned per peer domain (DID + public key).
//!
//! This module owns the local trust-anchor set and verifies the well-known
//! discovery record against it. It deliberately does not implement federation
//! transaction verification; production federation ingress must use the SDK /
//! server RFC 9421 and signed Event Envelope verifiers, not a local placeholder.

use std::collections::BTreeMap;

use arkret_models_collaboration::federation::frames::WellKnownArkretServer;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchor {
    pub domain: String,
    pub public_key: String,
}

/// Outcome of trust bundle verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustCheck {
    /// Domain is pinned and the checked record matches the pinned DID.
    Trusted,
    /// Domain is not in the bundle; reject the transaction.
    UnknownDomain(String),
    /// Domain is pinned but the advertised service DID does not match.
    SignatureMismatch(String),
}

/// Pinned trust bundle. Maps `domain` → [`TrustAnchor`].
///
/// F-FED-1 (2026-05-19): now `Serialize` / `Deserialize` so the
/// local state store can persist the pinned seal set across
/// restarts. Without persistence the user has to re-pin every
/// federated peer on every launch.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustBundle {
    #[serde(default)]
    seals: BTreeMap<String, TrustAnchor>,
}

impl TrustBundle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin a [`TrustAnchor`] for `seal.domain`. Subsequent calls overwrite
    /// the existing entry for that domain.
    pub fn add_anchor(&mut self, seal: TrustAnchor) {
        self.seals.insert(seal.domain.clone(), seal);
    }

    /// Remove a pinned seal. Returns the removed seal on success.
    pub fn remove(&mut self, domain: &str) -> Option<TrustAnchor> {
        self.seals.remove(domain)
    }

    /// Lookup the seal for a domain.
    pub fn anchor_for(&self, domain: &str) -> Option<&TrustAnchor> {
        self.seals.get(domain)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &TrustAnchor)> {
        self.seals.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.seals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seals.is_empty()
    }

    /// Verify a `.well-known/arkret/server` record against this bundle:
    /// the record's service DID must be pinned for `expected_domain`.
    pub fn verify_well_known(
        &self,
        expected_domain: &str,
        record: &WellKnownArkretServer,
    ) -> TrustCheck {
        let seal = match self.seals.get(expected_domain) {
            Some(a) => a,
            None => return TrustCheck::UnknownDomain(expected_domain.to_owned()),
        };
        // Pinned `public_key` is interpreted as the expected service DID
        // string until the SDK exposes a typed Ed25519 verifier surface to
        // inkson. We match it case-sensitively against the well-known DID.
        if seal.public_key != record.service_id.as_str() {
            return TrustCheck::SignatureMismatch(record.service_id.as_str().to_owned());
        }
        TrustCheck::Trusted
    }
}

/// F-WELLKNOWN-1: errors surfaced by [`fetch_well_known_arkret_server`].
#[derive(Debug, thiserror::Error)]
pub enum WellKnownFetchError {
    /// `base_url` couldn't be turned into a URL (bad scheme, missing
    /// host, etc.).
    #[error("bad base url: {0}")]
    BadBaseUrl(String),
    /// HTTP request itself failed (network down, TLS error, etc.).
    #[error("well-known network error: {0}")]
    Network(String),
    /// Server returned a non-2xx status.
    #[error("well-known HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    /// Response body wasn't a parseable `WellKnownArkretServer`.
    #[error("well-known decode error: {0}")]
    Decode(String),
}

/// F-WELLKNOWN-1: derive the `.well-known/arkret/server` URL from a
/// service base URL.
///
/// Per `discovery/server-discovery.md`, the well-known record lives at
/// `https://<host>/.well-known/arkret/server` relative to the origin
/// — not under the service's `/_arkret` namespace. This helper trims a
/// trailing slash and concatenates the well-known path, returning an
/// error when `base_url` is empty or doesn't carry a scheme.
pub fn well_known_arkret_server_url(base_url: &str) -> Result<String, WellKnownFetchError> {
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
    // well-known path under an API prefix (`/_arkret`, etc.).
    let after_scheme = if let Some(rest) = trimmed.strip_prefix("https://") {
        ("https://", rest)
    } else {
        (
            "http://",
            trimmed.strip_prefix("http://").unwrap_or(trimmed),
        )
    };
    let (scheme, rest) = after_scheme;
    let host_only = rest.split('/').next().unwrap_or(rest);
    if host_only.is_empty() {
        return Err(WellKnownFetchError::BadBaseUrl(format!(
            "missing host: {trimmed}"
        )));
    }
    Ok(format!("{scheme}{host_only}/.well-known/arkret/server"))
}

/// F-WELLKNOWN-1: fetch + parse the peer domain's
/// `.well-known/arkret/server` record.
///
/// Spec `discovery/server-discovery.md` mandates clients call this on
/// first contact with a new domain so they can pre-flight the service
/// DID against the trust bundle before issuing any privileged request.
/// Inkson wraps the SDK [`WellKnownArkretServer`] type — that struct
/// owns the JSON shape, and inkson owns the HTTP + error mapping.
///
/// This helper deliberately does **no** caching; the caller threads
/// the result through [`TrustBundle::verify_well_known`] and decides
/// what to persist (typically into the trust bundle alongside the
/// pinned seal). Caching is a follow-up.
pub async fn fetch_well_known_arkret_server(
    base_url: &str,
) -> Result<WellKnownArkretServer, WellKnownFetchError> {
    let url = well_known_arkret_server_url(base_url)?;
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
        .json::<WellKnownArkretServer>()
        .await
        .map_err(|err| WellKnownFetchError::Decode(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(domain: &str, key: &str) -> TrustAnchor {
        TrustAnchor {
            domain: domain.to_owned(),
            public_key: key.to_owned(),
        }
    }

    #[test]
    fn add_and_lookup_anchor() {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(seal("alice.example", "did:web:alice.example"));
        assert_eq!(bundle.len(), 1);
        assert!(bundle.anchor_for("alice.example").is_some());
        assert!(bundle.anchor_for("bob.example").is_none());
    }

    #[test]
    fn well_known_matches_pinned_did() {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(seal("bob.example", "did:web:bob.example"));
        let record = WellKnownArkretServer {
            service_id: arkret_sdk::Did::new("did:web:bob.example".to_owned()).unwrap(),
            base_url: "https://bob.example".to_owned(),
            protocol_versions: vec!["1.0".to_owned()],
            endpoints: Vec::new(),
            capabilities: Default::default(),
            operations: Vec::new(),
        };
        assert_eq!(
            bundle.verify_well_known("bob.example", &record),
            TrustCheck::Trusted
        );
    }

    #[test]
    fn well_known_with_wrong_did_is_rejected() {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(seal("bob.example", "did:web:bob.example"));
        let record = WellKnownArkretServer {
            service_id: arkret_sdk::Did::new("did:web:eve.example".to_owned()).unwrap(),
            base_url: "https://eve.example".to_owned(),
            protocol_versions: vec!["1.0".to_owned()],
            endpoints: Vec::new(),
            capabilities: Default::default(),
            operations: Vec::new(),
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
            well_known_arkret_server_url("https://bob.example").unwrap(),
            "https://bob.example/.well-known/arkret/server"
        );
        // Origin + trailing slash.
        assert_eq!(
            well_known_arkret_server_url("https://bob.example/").unwrap(),
            "https://bob.example/.well-known/arkret/server"
        );
        // Origin + API prefix gets stripped — well-known lives at the
        // top of the host, not nested under /_arkret.
        assert_eq!(
            well_known_arkret_server_url("https://bob.example/_arkret").unwrap(),
            "https://bob.example/.well-known/arkret/server"
        );
        // Loopback dev URLs are allowed.
        assert_eq!(
            well_known_arkret_server_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080/.well-known/arkret/server"
        );
    }

    #[test]
    fn trust_bundle_round_trips_through_serde() {
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(seal("alice.example", "did:web:alice.example"));

        let bytes = serde_json::to_string(&bundle).expect("serialize");
        let restored: TrustBundle = serde_json::from_str(&bytes).expect("deserialize");
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn well_known_url_rejects_malformed_base_url() {
        assert!(matches!(
            well_known_arkret_server_url(""),
            Err(WellKnownFetchError::BadBaseUrl(_))
        ));
        assert!(matches!(
            well_known_arkret_server_url("   "),
            Err(WellKnownFetchError::BadBaseUrl(_))
        ));
        // Missing scheme.
        assert!(matches!(
            well_known_arkret_server_url("bob.example"),
            Err(WellKnownFetchError::BadBaseUrl(_))
        ));
        // Scheme only.
        assert!(matches!(
            well_known_arkret_server_url("https://"),
            Err(WellKnownFetchError::BadBaseUrl(_))
        ));
    }
}
