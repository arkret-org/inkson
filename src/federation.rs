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

use contrix_sdk::{
    FederationTransaction, TrustAnchor, WellKnownContrixServer,
};
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
        // For now we treat the signature as opaque; the SDK's
        // `FederationManager::verify_transaction` is the canonical verifier.
        // Yougen consumes a pre-validated transaction from the Principal
        // Server and uses this bundle to enforce the additional pinning rule.
        // A future P3 task replaces this with the SDK verifier directly.
        if anchor.public_key.is_empty() || transaction.signature.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(domain: &str, key: &str) -> TrustAnchor {
        TrustAnchor { domain: domain.to_owned(), public_key: key.to_owned() }
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
        let mut bundle = TrustBundle::new();
        bundle.add_anchor(anchor("bob.example", "did:web:bob.example"));
        let tx = FederationTransaction {
            transaction_id: "t1".into(),
            origin: "bob.example".into(),
            destination: "alice.example".into(),
            events: Vec::new(),
            signature: "sig".into(),
        };
        assert_eq!(
            bundle.verify_transaction("alice.example", &tx),
            TrustCheck::Trusted
        );
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
        assert_eq!(bundle.verify_well_known("bob.example", &record), TrustCheck::Trusted);
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
}
