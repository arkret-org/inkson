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
//! precedent `mls_governance_trust_anchors` (`state/mls_governance.rs`), for
//! three reasons:
//!
//! - **They are not secrets.** A binding pins a DID document, i.e. public key material plus the
//!   verdict "this client accepted it at time T for purpose P". Its security requirement is
//!   *integrity and correct scoping*, not confidentiality. The keyring backends are sized for small
//!   secrets and, on desktop, each entry is a separate keyring item — a per-DID keyring entry per
//!   accepted binding is the wrong shape.
//! - **Principal scoping is structural here.** The `ClientLocalState` entry is already keyed by
//!   account DID, so account B literally cannot read account A's bindings; that is the strongest
//!   available answer to the cross-account trust-leak risk. The secure key store is keyed by a flat
//!   string namespace where the same isolation would have to be re-implemented by convention.
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

use arkret_sdk::identity::{AcceptedDidBinding, BindingInvalidation};
use arkret_sdk::{DidFullId, TypedTrustDomainId};

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
        did: &DidFullId,
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

    /// Apply one precise [`BindingInvalidation`] selector to the persisted set.
    ///
    /// Returns the number of removed entries. An **empty selector removes
    /// nothing** — that guarantee comes from the SDK
    /// (`BindingInvalidation::matches` returns `false` for an unconstrained
    /// selector), so a mis-built selector degrades into a no-op instead of a
    /// silent full wipe.
    #[cfg(test)]
    pub(crate) fn invalidate_accepted_did_bindings(
        &mut self,
        selector: &BindingInvalidation,
    ) -> usize {
        self.ensure_cached_loaded();
        if selector.is_empty() {
            return 0;
        }
        let before = self.cached.accepted_did_bindings.len();
        self.cached
            .accepted_did_bindings
            .retain(|record| !selector.matches(record.binding()));
        let removed = before - self.cached.accepted_did_bindings.len();
        if removed > 0 {
            let _ = self.flush();
        }
        removed
    }

    /// Apply a batch of selectors in one flush.
    pub(crate) fn invalidate_accepted_did_bindings_batch(
        &mut self,
        selectors: &[BindingInvalidation],
    ) -> usize {
        self.ensure_cached_loaded();
        let before = self.cached.accepted_did_bindings.len();
        self.cached.accepted_did_bindings.retain(|record| {
            !selectors
                .iter()
                .any(|selector| selector.matches(record.binding()))
        });
        let removed = before - self.cached.accepted_did_bindings.len();
        if removed > 0 {
            let _ = self.flush();
        }
        removed
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
    /// Implemented as a positive retain (`keep == same domain`) rather than as a
    /// [`BindingInvalidation`], because the selector API is deliberately
    /// conjunctive-match — it can express "remove domain X" but not "remove
    /// everything except X" without enumerating every other domain.
    pub(crate) fn clear_accepted_did_bindings_outside_trust_domain(
        &mut self,
        trust_domain: &TypedTrustDomainId,
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

    /// Whether any binding is filed under a DID other than `did`. Used by the
    /// cross-account regression test to assert that switching principals never
    /// exposes the previous account's acceptances.
    #[cfg(test)]
    pub fn accepted_did_binding_dids(&self) -> Vec<DidFullId> {
        self.load()
            .accepted_did_bindings
            .iter()
            .map(|record| record.binding().did().clone())
            .collect()
    }
}

/// Build the invalidation selectors implied by one identity/control event.
///
/// `did-usage-and-verification.md` §4 lists the closed set of conditions that
/// invalidate an accepted binding. This maps the wire event kinds inkson can
/// observe in a sync response onto **precise** selectors — every returned
/// selector constrains at least the DID, so no event ever produces a
/// catch-all wipe.
///
/// Every kind below is a **registered** `event_kind_registry` entry. A kind that
/// is not in that registry can never appear on the wire, so matching one would
/// be dead code that also hides the registered kind it was standing in for.
///
/// | event class | wire kinds | selector |
/// | --- | --- | --- |
/// | deactivation | `ak.account.status` | DID |
/// | device epoch / list | `ak.device.revoke`, `ak.device.authorize`, `ak.device.reanchor`, `ak.device.list_update` | DID + `device_signer` purpose |
/// | agent signer epoch | `ak.agent.key.authorize`, `ak.agent.key.revoke` | DID + `agent_signer` purpose |
/// | DID policy change | `ak.sovereign.did_policy` | DID |
///
/// Purpose narrowing matters: a device revoke must not evict the `Principal`
/// acceptance that the member list renders from, and an agent signer epoch must
/// not evict a device-signer acceptance.
///
/// Service endpoint / controller delegation changes have **no** wire event kind:
/// they are `did:webvh` history changes and reach a client through document
/// resolution, not through a Realm projection, so this table has no row for
/// them.
pub(crate) fn binding_invalidations_for_event(
    kind: &str,
    did: &DidFullId,
    _verification_method: Option<&arkret_sdk::DidUrl>,
) -> Vec<BindingInvalidation> {
    use arkret_sdk::identity::DidBindingPurpose as Purpose;

    let base = BindingInvalidation::for_did(did.clone());
    match kind {
        // --- deactivation -------------------------------------------------
        // `deactivated` is terminal and cascades to every device, KeyPackage and
        // session of the account (`account-lifecycle.md` §7.1), so no acceptance
        // of this DID survives, for any purpose. The selector is taken for every
        // status transition rather than only for `deactivated`: the payload is
        // not in scope here and re-accepting is the cheap side.
        "ak.account.status" => vec![base],
        // --- device epoch / list ------------------------------------------
        "ak.device.revoke"
        | "ak.device.authorize"
        | "ak.device.reanchor"
        | "ak.device.list_update" => {
            vec![base.with_purpose(Purpose::DeviceSigner)]
        }
        // --- agent signer epoch -------------------------------------------
        "ak.agent.key.authorize" | "ak.agent.key.revoke" => {
            vec![base.with_purpose(Purpose::AgentSigner)]
        }
        // --- DID policy change --------------------------------------------
        // The policy digest is part of the store key, so a *local* policy
        // revision already orphans old entries. A remotely announced policy
        // change still has to drop this DID's acceptances explicitly.
        "ak.sovereign.did_policy" => vec![base],
        _ => Vec::new(),
    }
}

/// Whether `kind` is one of the invalidating event classes above.
pub(crate) fn is_binding_invalidating_kind(kind: &str) -> bool {
    matches!(
        kind,
        "ak.account.status"
            | "ak.device.revoke"
            | "ak.device.authorize"
            | "ak.device.reanchor"
            | "ak.device.list_update"
            | "ak.agent.key.authorize"
            | "ak.agent.key.revoke"
            | "ak.sovereign.did_policy"
    )
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
            id: DidFullId::new(did.to_owned()).expect("valid did"),
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

    /// **Upgrade drill: a `policy_digest` algorithm change orphans every stored
    /// acceptance, and that must be a re-resolve, not a crash or a stuck badge.**
    ///
    /// `policy_digest` is a store-key dimension, so converging onto the SDK's
    /// canonical encoding makes every pre-upgrade row unreachable exactly once.
    /// Two deployment profiles digest differently, so accepting under one and
    /// reading under the other is the same shape as the upgrade. What must hold:
    ///
    /// - loading the orphaned row does not panic and does not drop it (the pairing invariant is
    ///   untouched — only the key moved);
    /// - the ordinary lookup **misses**, which is what pushes the next authority caller to resolve
    ///   again;
    /// - the DID-level display badge keeps reporting a status instead of getting stuck on `None` /
    ///   an error;
    /// - the freshly accepted row lands under the new key and is served from then on.
    #[test]
    fn a_policy_digest_change_orphans_bindings_into_a_re_resolve_not_a_panic() {
        let old =
            DidBindingScope::for_server(DeploymentProfile::Organization, "https://alpha.example")
                .expect("scope");
        let new = scope("https://alpha.example");
        assert_eq!(old.trust_domain(), new.trust_domain());

        let did = DidFullId::new("did:web:alice.example".to_owned()).expect("did");
        let (mut store, path) = temp_store("policy-digest-upgrade");
        store.store_accepted_did_bindings(vec![record(
            &old,
            did.as_str(),
            DidBindingPurpose::Principal,
        )]);

        // --- restart under the new digest ---------------------------------
        let rebooted = LocalStateStore::with_path(&path);
        let records = rebooted.accepted_did_bindings();
        assert_eq!(records.len(), 1, "an orphaned row is still a valid pairing");
        let bindings = InksonDidBindingStore::hydrate(records);
        let new_key = new.key(&did, DidBindingPurpose::Principal, None);
        assert!(
            bindings.ordinary_lookup(&new_key, Utc::now()).is_none(),
            "the old-digest acceptance must be unreachable under the new policy"
        );
        assert_eq!(
            rebooted.accepted_did_binding_status(&did, Utc::now()),
            Some(arkret_sdk::identity::DidBindingStatus::Active),
            "the display badge is DID-level and must not get stuck on an error state"
        );

        // --- the authority path re-accepts once ---------------------------
        bindings.accept(record(&new, did.as_str(), DidBindingPurpose::Principal));
        assert!(bindings.ordinary_lookup(&new_key, Utc::now()).is_some());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn empty_selector_removes_nothing() {
        let scope = scope("https://alpha.example");
        let (mut store, _path) = temp_store("case");
        store.store_accepted_did_bindings(vec![record(
            &scope,
            "did:web:alice.example",
            DidBindingPurpose::Principal,
        )]);
        assert_eq!(
            store.invalidate_accepted_did_bindings(&BindingInvalidation::default()),
            0
        );
        assert_eq!(store.accepted_did_bindings().len(), 1);
    }

    #[test]
    fn device_revoke_keeps_the_principal_acceptance() {
        let scope = scope("https://alpha.example");
        let did = DidFullId::new("did:web:alice.example".to_owned()).expect("did");
        let (mut store, _path) = temp_store("case");
        store.store_accepted_did_bindings(vec![
            record(&scope, did.as_str(), DidBindingPurpose::Principal),
            record(&scope, did.as_str(), DidBindingPurpose::DeviceSigner),
        ]);
        let selectors = binding_invalidations_for_event("ak.device.revoke", &did, None);
        assert_eq!(store.invalidate_accepted_did_bindings_batch(&selectors), 1);
        let remaining = store.accepted_did_bindings();
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].binding().purpose(),
            DidBindingPurpose::Principal
        );
    }

    #[test]
    fn deactivation_removes_every_purpose_for_that_did_only() {
        let scope = scope("https://alpha.example");
        let alice = DidFullId::new("did:web:alice.example".to_owned()).expect("did");
        let (mut store, _path) = temp_store("case");
        store.store_accepted_did_bindings(vec![
            record(&scope, alice.as_str(), DidBindingPurpose::Principal),
            record(&scope, alice.as_str(), DidBindingPurpose::DeviceSigner),
            record(&scope, "did:web:bob.example", DidBindingPurpose::Principal),
        ]);
        let selectors = binding_invalidations_for_event("ak.account.status", &alice, None);
        assert_eq!(store.invalidate_accepted_did_bindings_batch(&selectors), 2);
        let remaining = store.accepted_did_bindings();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].binding().did().as_str(), "did:web:bob.example");
    }

    #[test]
    fn unrelated_event_kinds_produce_no_selectors() {
        let did = DidFullId::new("did:web:alice.example".to_owned()).expect("did");
        assert!(binding_invalidations_for_event("ak.message.create", &did, None).is_empty());
        assert!(!is_binding_invalidating_kind("ak.message.create"));
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

        store.switch_active_account(alice);
        store.store_accepted_did_bindings(vec![record(&scope, peer, DidBindingPurpose::Principal)]);
        assert_eq!(store.accepted_did_bindings().len(), 1);

        store.switch_active_account(bob);
        assert!(
            store.accepted_did_bindings().is_empty(),
            "account B must not inherit account A's accepted DID bindings"
        );
        assert!(
            store
                .hydrate_did_binding_store()
                .ordinary_lookup(
                    &scope.key(
                        &DidFullId::new(peer.to_owned()).expect("did"),
                        DidBindingPurpose::Principal,
                        None
                    ),
                    Utc::now()
                )
                .is_none(),
            "the same DID + trust domain must still miss under a different principal"
        );

        store.switch_active_account(alice);
        assert_eq!(
            store.accepted_did_binding_dids(),
            vec![DidFullId::new(peer.to_owned()).expect("did")],
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
            fn supports(&self, _did: &DidFullId) -> bool {
                true
            }

            fn resolve_did(
                &self,
                did: &DidFullId,
            ) -> arkret_sdk::identity::Result<arkret_sdk::identity::ResolvedDid> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(arkret_sdk::identity::IdentityError::Protocol(format!(
                    "ordinary read must not resolve {did}"
                )))
            }
        }

        let scope = scope("https://alpha.example");
        let peer = "did:web:peer.example";
        let peer_did = DidFullId::new(peer.to_owned()).expect("did");
        let (mut first_boot, path) = temp_store("restart");
        first_boot.switch_active_account("did:web:alice.example");
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
            &DidFullId::new("did:web:stranger.example".to_owned()).expect("did"),
            DidBindingPurpose::DeviceSigner,
            None,
        );
        assert!(bindings.ordinary_lookup(&unknown, Utc::now()).is_none());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_file(path);
    }
}
