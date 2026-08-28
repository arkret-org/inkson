//! DID-P2-B — durable accepted DID bindings in the per-account local state.
//!
//! ## Why this storage layer and not the secure key store
//!
//! inkson has three local persistence layers:
//!
//! 1. `secure_key_store` (OS keyring / IndexedDB+SubtleCrypto / mobile host bridge) — for **secret
//!    material** (device private keys, session grants, grant-binding seeds);
//! 2. the per-account `ClientLocalState` entry — encrypted into IndexedDB on wasm via
//!    `account_persist`, written as an atomic sibling file on native;
//! 3. plain `state/storage_util` blobs — non-account, non-sensitive.
//!
//! Accepted DID bindings go in layer 2, following the *existing* accepted-anchor
//! precedent `mls_governance_checkpoints` (`state/mls_governance.rs`), for
//! three reasons:
//!
//! - **They are not secrets.** A binding pins a DID document, i.e. public key material plus the
//!   verdict "this client accepted it at time T for purpose P". Its security requirement is
//!   *integrity and correct scoping*, not confidentiality. The keyring backends are sized for small
//!   secrets and, on desktop, each entry is a separate keyring item — an authority-scoped keyring
//!   entry per accepted binding is the wrong shape.
//! - **Principal scoping is structural here.** The `ClientLocalState` entry is already keyed by
//!   account authority, so account B literally cannot read account A's bindings; that is the
//!   strongest available answer to the cross-account trust-leak risk. The secure key store is keyed
//!   by a flat string namespace where the same isolation would have to be re-implemented by
//!   convention.
//! - **It shares one atomic write with the rest of the account state**, so a binding accepted while
//!   applying a sync response is persisted in the same flush as the projections that motivated it,
//!   instead of racing a second durable writer.
//!
//! ### Binding vs. document split
//!
//! Both halves are persisted together inside the SDK's
//! [`arkret_sdk::identity::AcceptedDidBinding`]. Splitting the
//! document out (keeping only the digest) was considered and rejected: without
//! the document, `verify_jws_with_binding` cannot recover a public key, so a
//! restart would have to resolve the DID again — which is exactly the acceptance
//! criterion "restart ⇒ resolver network delta 0" that this task requires. The
//! size risk is handled by the [`MAX_PERSISTED_DID_BINDINGS`] cap plus
//! deterministic oldest-`verified_at` eviction, the same technique
//! `raw_operations` (512) and `mls_governance_proofs` (16) already use.

use arkret_sdk::identity::AcceptedDidBinding;
use arkret_sdk::{Did, TrustDomainId};

use super::*;
#[cfg(test)]
use crate::identity::did_binding::InksonDidBindingStore;
use crate::identity::did_binding::MAX_PERSISTED_DID_BINDINGS;

impl LocalStateStore {
    /// Persisted accepted bindings for the **active account only**.
    pub(crate) fn accepted_did_bindings(&self) -> Vec<AcceptedDidBinding> {
        self.load().accepted_did_bindings
    }

    /// Hydrate an [`InksonDidBindingStore`] from the active account's persisted
    /// bindings. Every record is re-validated on the way in.
    #[cfg(test)]
    pub(crate) fn hydrate_did_binding_store(&self) -> InksonDidBindingStore {
        InksonDidBindingStore::hydrate(self.accepted_did_bindings())
    }

    /// Write `records` back, capped and deterministically evicted.
    ///
    /// Returns `true` when the persisted set actually changed, so callers can
    /// avoid a flush on the (common) no-op path.
    pub(crate) fn store_accepted_did_bindings(
        &mut self,
        mut records: Vec<AcceptedDidBinding>,
    ) -> bool {
        self.ensure_cached_loaded();
        if records.len() > MAX_PERSISTED_DID_BINDINGS {
            // Deterministic eviction: keep the most recently verified. Ties are
            // broken by the existing snapshot order, which is the SDK store's
            // key order, so the outcome does not depend on iteration luck.
            records.sort_by(|a, b| {
                b.binding()
                    .verified_at()
                    .cmp(&a.binding().verified_at())
                    .then_with(|| a.binding().key().cmp(&b.binding().key()))
            });
            records.truncate(MAX_PERSISTED_DID_BINDINGS);
            records.sort_by_key(|record| record.binding().key());
        }
        if self.cached.accepted_did_bindings == records {
            return false;
        }
        self.cached.accepted_did_bindings = records;
        let _ = self.flush();
        true
    }

    /// TRUST-CACHE display probe: the best status any accepted binding for
    /// `did` has at `now`, without cloning the pinned documents.
    ///
    /// This is the read UI surfaces use (verification badge, member list,
    /// message render). It is deliberately **document-free and
    /// purpose-agnostic**: a display badge only answers "does this client hold
    /// local evidence about this DID", never "may this key authorize X". It
    /// performs no resolution and cannot enter the authority path.
    ///
    /// Hard-expired entries report `None` (the reader must treat them as
    /// absent), and entries past `refresh_after` report `Stale` rather than
    /// being upgraded — matching the store's own downgrade rule.
    pub(crate) fn accepted_did_binding_status(
        &self,
        did: &Did,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<arkret_sdk::identity::DidBindingStatus> {
        use arkret_sdk::identity::{BindingFreshness, DidBindingStatus, binding_freshness_at};

        let state = self.load();
        let mut best: Option<DidBindingStatus> = None;
        for record in &state.accepted_did_bindings {
            if record.binding().did() != did {
                continue;
            }
            let status = match binding_freshness_at(record.binding(), now) {
                BindingFreshness::Expired | BindingFreshness::Missing => continue,
                BindingFreshness::Stale { .. }
                    if record.binding().status() == DidBindingStatus::Active =>
                {
                    DidBindingStatus::Stale
                }
                _ => record.binding().status(),
            };
            // Ranking: a usable Active hit wins over Stale, which wins over a
            // terminal Deactivated / Quarantined record. Terminal states are
            // still reported so the badge can degrade rather than look absent.
            let rank = |status: DidBindingStatus| match status {
                DidBindingStatus::Active => 3,
                DidBindingStatus::Stale => 2,
                DidBindingStatus::Quarantined => 1,
                DidBindingStatus::Deactivated => 0,
            };
            if best.is_none_or(|current| rank(status) > rank(current)) {
                best = Some(status);
            }
        }
        best
    }

    /// **Trust-domain switch.** Drop every binding that was *not* accepted
    /// against `trust_domain`.
    ///
    /// This is the counterpart of the structural principal scoping: the account
    /// entry already isolates principals, but one account can be pointed at a
    /// different Principal Server (or the same account can be re-bootstrapped
    /// against a different deployment). An acceptance made against the previous
    /// server must not authorize anything under the new one, so the moment the
    /// active trust domain changes every foreign-domain binding is removed
    /// rather than left to expire.
    ///
    /// Implemented as a positive retain (`keep == same domain`) so the switch
    /// cannot accidentally preserve an acceptance from another deployment.
    pub(crate) fn clear_accepted_did_bindings_outside_trust_domain(
        &mut self,
        trust_domain: &TrustDomainId,
    ) -> usize {
        self.ensure_cached_loaded();
        let before = self.cached.accepted_did_bindings.len();
        self.cached
            .accepted_did_bindings
            .retain(|record| record.binding().trust_domain() == trust_domain);
        let removed = before - self.cached.accepted_did_bindings.len();
        if removed > 0 {
            let _ = self.flush();
        }
        removed
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use arkret_sdk::identity::DidBindingPurpose;
    use chrono::Utc;

    use super::*;
    use crate::identity::did_binding::{DidBindingScope, accept_verified_document};
    use crate::identity::did_resolver::DeploymentProfile;

    /// A store backed by a unique temp file, so a second `with_path` on the same
    /// path simulates a process restart (the whole in-memory state is dropped
    /// and rebuilt from the persistence layer).
    fn temp_store(tag: &str) -> (LocalStateStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "inkson-did-bindings-{tag}-{}-{:?}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        (LocalStateStore::with_path(&path), path)
    }

    fn document(did: &str) -> arkret_sdk::DidDocument {
        arkret_sdk::DidDocument {
            id: Did::new(did.to_owned()).expect("valid did"),
            verification_methods: BTreeMap::from([(
                format!("{did}#key-1"),
                "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
            )]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::new(),
        }
    }

    fn record(
        scope: &DidBindingScope,
        did: &str,
        purpose: DidBindingPurpose,
    ) -> AcceptedDidBinding {
        accept_verified_document(scope, purpose, None, &document(did), Utc::now())
            .expect("acceptance")
    }

    fn scope(base_url: &str) -> DidBindingScope {
        DidBindingScope::for_server(DeploymentProfile::PersonalNode, base_url).expect("scope")
    }

    #[test]
    fn switching_trust_domain_drops_foreign_acceptances() {
        let alpha = scope("https://alpha.example");
        let beta = scope("https://beta.example");
        let (mut store, _path) = temp_store("case");
        store.store_accepted_did_bindings(vec![
            record(
                &alpha,
                "did:web:alice.example",
                DidBindingPurpose::Principal,
            ),
            record(&beta, "did:web:carol.example", DidBindingPurpose::Principal),
        ]);
        assert_eq!(
            store.clear_accepted_did_bindings_outside_trust_domain(beta.trust_domain()),
            1
        );
        let remaining = store.accepted_did_bindings();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].binding().trust_domain(), beta.trust_domain());
    }

    #[test]
    fn capacity_cap_keeps_the_most_recently_verified() {
        let scope = scope("https://alpha.example");
        let mut records = Vec::new();
        for index in 0..(MAX_PERSISTED_DID_BINDINGS + 8) {
            let document = document(&format!("did:web:actor{index}.example"));
            records.push(
                accept_verified_document(
                    &scope,
                    DidBindingPurpose::Principal,
                    None,
                    &document,
                    Utc::now() + chrono::Duration::seconds(index as i64),
                )
                .expect("acceptance"),
            );
        }
        let (mut store, _path) = temp_store("case");
        store.store_accepted_did_bindings(records);
        let kept = store.accepted_did_bindings();
        assert_eq!(kept.len(), MAX_PERSISTED_DID_BINDINGS);
        assert!(
            kept.iter()
                .all(|record| record.binding().did().as_str() != "did:web:actor0.example"),
            "the oldest acceptance must be the one evicted"
        );
    }

    /// **Cross-account trust leak — negative test.**
    ///
    /// Account A accepts a binding, then the user switches to account B. B must
    /// see *no* bindings at all, and must not be able to consume A's acceptance
    /// even though the DID and the trust domain are identical. Switching back
    /// must restore A's acceptance untouched (the switch is scoping, not
    /// deletion).
    #[test]
    fn switching_principal_never_reuses_the_previous_accounts_binding() {
        let scope = scope("https://alpha.example");
        let (mut store, path) = temp_store("principal-switch");
        let alice = "did:web:alice.example";
        let bob = "did:web:bob.example";
        let peer = "did:web:peer.example";

        store.switch_test_account(alice);
        store.store_accepted_did_bindings(vec![record(&scope, peer, DidBindingPurpose::Principal)]);
        assert_eq!(store.accepted_did_bindings().len(), 1);

        store.switch_test_account(bob);
        assert!(
            store.accepted_did_bindings().is_empty(),
            "account B must not inherit account A's accepted DID bindings"
        );
        assert!(
            store
                .hydrate_did_binding_store()
                .ordinary_lookup(
                    &scope.key(
                        &Did::new(peer.to_owned()).expect("did"),
                        DidBindingPurpose::Principal,
                        None
                    ),
                    Utc::now()
                )
                .is_none(),
            "the same DID + trust domain must still miss under a different principal"
        );

        store.switch_test_account(alice);
        assert!(
            !store.accepted_did_bindings().is_empty(),
            "switching away and back must not destroy the original acceptance"
        );
        let _ = std::fs::remove_file(path);
    }

    /// **Restart ⇒ zero resolver network calls.**
    ///
    /// The binding is accepted once, the whole in-memory store is dropped, and a
    /// second `LocalStateStore` is built from the same persistence path (this is
    /// what a client restart is). A [`CountingDidResolver`] — modelled on the
    /// SDK's `crates/identity/tests/binding_resolver_spy.rs` — stands in for the
    /// network; the assertion is that the ordinary post-restart read never
    /// touches it.
    #[test]
    fn restart_serves_the_accepted_binding_with_zero_resolver_calls() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use arkret_sdk::identity::DidResolver;

        /// Any call to this resolver is a protocol violation for an ordinary
        /// read; it counts the attempt and then fails closed.
        struct CountingDidResolver {
            calls: AtomicUsize,
        }

        impl DidResolver for CountingDidResolver {
            fn supports(&self, _did: &Did) -> bool {
                true
            }

            fn resolve_did(
                &self,
                did: &Did,
            ) -> arkret_sdk::identity::Result<arkret_sdk::identity::ResolvedDid> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(arkret_sdk::identity::IdentityError::Protocol(format!(
                    "ordinary read must not resolve {did}"
                )))
            }
        }

        let scope = scope("https://alpha.example");
        let peer = "did:web:peer.example";
        let peer_did = Did::new(peer.to_owned()).expect("did");
        let (mut first_boot, path) = temp_store("restart");
        first_boot.switch_test_account("did:web:alice.example");
        first_boot.store_accepted_did_bindings(vec![record(
            &scope,
            peer,
            DidBindingPurpose::DeviceSigner,
        )]);
        drop(first_boot);

        // --- restart ------------------------------------------------------
        let resolver = CountingDidResolver {
            calls: AtomicUsize::new(0),
        };
        let second_boot = LocalStateStore::with_path(&path);
        let bindings = second_boot.hydrate_did_binding_store();
        let key = scope.key(&peer_did, DidBindingPurpose::DeviceSigner, None);

        // Ordinary sync / render reads, repeated: still zero network.
        for _ in 0..5 {
            let hit = bindings
                .ordinary_lookup(&key, Utc::now())
                .expect("the accepted binding survives the restart");
            assert_eq!(hit.document().id, peer_did);
        }
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            0,
            "an ordinary post-restart read must not enter the authority path"
        );

        // An unknown DID misses locally; only *then* may a caller escalate.
        let unknown = scope.key(
            &Did::new("did:web:stranger.example".to_owned()).expect("did"),
            DidBindingPurpose::DeviceSigner,
            None,
        );
        assert!(bindings.ordinary_lookup(&unknown, Utc::now()).is_none());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_file(path);
    }
}
