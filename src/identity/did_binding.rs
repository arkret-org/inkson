//! DID-P2-B — durable accepted DID bindings for inkson.
//!
//! Spec source: `spec/v1/zh/identity/did-usage-and-verification.md` §4 (closed
//! authority triggers), §5 (binding fields, store, precise invalidation) and §6
//! (verifier authority / cache split).
//!
//! ## Why this module exists
//!
//! Before P2-B the only reusable DID state inkson kept was
//! [`arkret_sdk::identity::DidResolutionCache`] — an in-memory, login-session
//! scoped map from DID to document. It has three gaps the spec closes:
//!
//! 1. it dies with the login session, so **every restart re-resolves**;
//! 2. it is keyed by DID alone, so it cannot express "accepted for *this* trust domain and *this*
//!    purpose under *this* policy";
//! 3. it can only be invalidated per-DID or wholesale.
//!
//! This module layers the SDK's shared model on top of it. **No parallel
//! binding type is defined here** (task line 81): [`VerifiedDidBinding`],
//! [`AcceptedDidBinding`], [`DidBindingPurpose`], [`BindingInvalidation`] and
//! [`VerifiedDidBindingStore`] all come from `arkret_sdk::identity` verbatim.
//! What inkson adds is (a) how a client picks its trust domain / policy digest,
//! and (b) hydration from and snapshotting back into the per-account persisted
//! state.
//!
//! ## Trust boundary
//!
//! A hit in this store is a **zero-network** read. It is therefore usable by
//! ordinary render / sync paths (`did-usage-and-verification.md` §4: ordinary
//! business MUST NOT resolve per object). Entering the authority path is
//! `arkret_sdk::identity::resolve_and_verify_binding`, which consults this same
//! store first and calls the resolver at most once.

use arkret_sdk::identity::{
    AcceptedDidBinding, BindingError, BindingInvalidation, BindingStoreError, DidBindingPurpose,
    DidBindingStatus, DigestError, EvidenceReceipt, InMemoryVerifiedDidBindingStore, LimitedTrust,
    MethodEvidence, VerifiedDidBinding, VerifiedDidBindingDocumentInput, VerifiedDidBindingKey,
    VerifiedDidBindingStore, policy_digest,
};
#[cfg(test)]
use arkret_sdk::identity::{FreshnessProfile, FreshnessRequirement};
use arkret_sdk::{DidDocument, DidFullId, DidUrl, Hash, TrustDomainId};
use chrono::{DateTime, Duration, Utc};

/// Hard cap on persisted bindings per account.
///
/// Each record carries a pinned DID document, and the whole
/// `ClientLocalState` blob is re-serialized on every flush (and, on wasm, must
/// fit the browser storage budget) — the same constraint that caps
/// `raw_operations` at 512 and the MLS governance proof cache at 16. A client
/// realistically pins its own principal, its server's service DID and the
/// members of the Realms it renders; 256 leaves ample headroom while keeping
/// the worst-case blob bounded.
pub(crate) const MAX_PERSISTED_DID_BINDINGS: usize = 256;

/// Background-refresh point for a client-side acceptance. Matches the
/// 15-minute resolver-policy TTL used by
/// [`crate::identity::did_resolver::policy_for`], so a binding turns `Stale`
/// exactly when the old document cache would have expired.
pub(crate) const BINDING_REFRESH_MINUTES: i64 = 15;

/// Hard-expiry point. Crossing it makes the entry invisible to readers, which
/// forces the next *authority* caller to resolve again. It is deliberately far
/// past the refresh point: `did-usage-and-verification.md` §5 states TTL expiry
/// alone MUST NOT turn an ordinary read into an online resolution, so ordinary
/// render / sync keeps consuming the `Stale` binding for the whole window.
pub(crate) const BINDING_HARD_EXPIRY_DAYS: i64 = 30;

/// The local trust domain + policy snapshot every acceptance made by this
/// client is scoped to.
///
/// `did-usage-and-verification.md` §4 permits reusing an earlier verification
/// result "only when it is bound to the same DID, trust domain, purpose, policy
/// digest and an acceptable freshness". For a client the trust domain is *the
/// deployment whose word we took* — i.e. the Principal Server origin the
/// account is signed in to. Two accounts on two servers therefore never share
/// an acceptance even if the same DID appears in both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DidBindingScope {
    trust_domain: TrustDomainId,
    policy_digest: Hash,
}

impl DidBindingScope {
    /// Build the scope for `profile` at `base_url`.
    ///
    /// Fails when the canonical [`policy_digest`] cannot be computed. That
    /// digest is a store-key dimension, so a fallback value would silently make
    /// two different policies share one key; the caller must degrade into "no
    /// durable bindings for this call" instead.
    pub(crate) fn for_server(
        profile: crate::identity::did_resolver::DeploymentProfile,
        base_url: &str,
    ) -> Result<Self, DigestError> {
        Ok(Self {
            trust_domain: Self::trust_domain_for(base_url),
            policy_digest: policy_digest(&crate::identity::did_resolver::policy_for(profile))?,
        })
    }

    /// The trust domain a server origin maps to.
    ///
    /// Derived from the origin's host (lowercased, port appended with `:` which
    /// the `ak:trust_domain:` charset allows). A `base_url` that has no host —
    /// or whose host contains characters outside the trust-domain charset —
    /// falls back to the deployment-profile-only domain rather than silently
    /// widening the scope.
    ///
    /// Split out of [`Self::for_server`] because the trust-domain half is
    /// infallible and is on its own the input to
    /// [`crate::state::LocalStateStore::clear_accepted_did_bindings_outside_trust_domain`]:
    /// a failure to digest the resolver policy must not be able to skip that
    /// cross-deployment cleanup.
    pub(crate) fn trust_domain_for(base_url: &str) -> TrustDomainId {
        let scope = url::Url::parse(base_url)
            .ok()
            .and_then(|url| {
                let host = url.host_str()?.to_ascii_lowercase();
                Some(match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host,
                })
            })
            .unwrap_or_default();
        TrustDomainId::new(format!("ak:trust_domain:{scope}"))
            .unwrap_or_else(|_| Self::local_trust_domain())
    }

    /// Fallback trust domain used when no server origin is known (pre-login,
    /// or a malformed base URL). It is a *distinct* domain, so a binding
    /// accepted with no known server is never reused as if it came from one.
    #[allow(
        clippy::expect_used,
        reason = "the argument is a compile-time literal that satisfies `is_trust_domain`; a failure here would mean the identifier grammar changed and must fail loudly rather than silently widen the scope"
    )]
    fn local_trust_domain() -> TrustDomainId {
        TrustDomainId::new("ak:trust_domain:inkson.local".to_owned())
            .expect("static trust domain literal is valid")
    }

    /// The trust domain this scope's acceptances are filed under. Production
    /// callers that only need the domain (the trust-domain-switch cleanup) take
    /// the infallible [`Self::trust_domain_for`] instead of building a scope.
    #[cfg(test)]
    pub(crate) fn trust_domain(&self) -> &TrustDomainId {
        &self.trust_domain
    }

    #[cfg(test)]
    pub(crate) fn policy_digest(&self) -> &Hash {
        &self.policy_digest
    }

    /// The store key an ordinary reader looks a binding up under.
    ///
    /// `version_id` is not a key dimension: §5.2 makes it a product of the
    /// resolution, so a reader cannot know it before the lookup.
    pub(crate) fn key(
        &self,
        did: &DidFullId,
        purpose: DidBindingPurpose,
        verification_method: Option<DidUrl>,
    ) -> VerifiedDidBindingKey {
        VerifiedDidBindingKey {
            did: did.clone(),
            trust_domain: self.trust_domain.clone(),
            purpose,
            policy_digest: self.policy_digest.clone(),
            verification_method,
        }
    }
}

/// The method evidence a client-side acceptance rests on.
///
/// inkson's `did:web` / `did:webvh` ingest already validated content type,
/// size, `document.id`, and (for webvh) the SCID + append-only log chain before
/// the document reached the resolver. The evidence digest commits to *which*
/// document body and *under which policy* that verdict was reached, so an
/// acceptance can be audited and so a different document — or the same document
/// under a revised policy — produces a different, non-reusable acceptance.
///
/// The receipt comes from the SDK ([`EvidenceReceipt`]) rather than being
/// hand-rolled here, so it is byte-comparable with the other repos. §5.2 fixes
/// its inputs to the DID method, the digest of the verified normalized document
/// and the registered method-proof rows — `policy_digest` deliberately stays
/// *outside* it, side by side on the binding, so evidence invalidation is not
/// coupled to policy rotation.
///
/// inkson surfaces no proof rows: its `did:webvh` ingest validates the SCID and
/// the append-only chain but the SDK resolver does not hand back the witness set
/// a `webvh_log` row requires, and a row the caller invented is exactly what
/// §5.2 makes unconstructible.
pub(crate) fn evidence_receipt_for_document(
    document: &DidDocument,
) -> Result<EvidenceReceipt, BindingError> {
    Ok(EvidenceReceipt::new(
        document.id.method(),
        arkret_sdk::identity::document_canonical_digest(document)?,
        &MethodEvidence::none(),
    ))
}

/// Why a locally-verified document could not be turned into an acceptance.
///
/// Every variant is a *refusal to record*, never a downgraded digest: a wrong
/// digest would collide two different inputs onto one store key, which is the
/// one failure mode a trust cache may not have.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BindingAcceptError {
    #[error("evidence digest could not be computed: {0}")]
    Evidence(#[from] DigestError),
    #[error("verified binding could not be built: {0}")]
    Binding(#[from] BindingError),
    #[error("binding does not match its pinned document: {0}")]
    Pairing(#[from] BindingStoreError),
}

/// Turn an already-verified DID document into an [`AcceptedDidBinding`] for
/// `scope` / `purpose`.
///
/// Callers MUST only pass a document that came out of the authority-grade
/// resolver chain (`did_resolver::verify_principal` / `resolve_with_cache`),
/// which already enforced the method policy and compared `document.id`. This
/// function does not itself verify anything about the document; it records what
/// was verified.
///
/// `history_head` / `version_id` are `None` for every method inkson resolves
/// today (`did:key`, `did:web`, and `did:webvh` whose head state the SDK
/// validates but does not surface as a typed pin), so the per-pin limited-trust
/// record is written explicitly — leaving it implicit is rejected by the SDK
/// constructor.
pub(crate) fn accept_verified_document(
    scope: &DidBindingScope,
    purpose: DidBindingPurpose,
    verification_method: Option<DidUrl>,
    document: &DidDocument,
    now: DateTime<Utc>,
) -> Result<AcceptedDidBinding, BindingAcceptError> {
    let receipt = evidence_receipt_for_document(document)?;
    let binding = VerifiedDidBinding::from_verified_document(
        document,
        VerifiedDidBindingDocumentInput {
            trust_domain: scope.trust_domain.clone(),
            purpose,
            verification_method,
            history_head: None,
            version_id: None,
            // Neither pin is surfaced, and no method inkson resolves publishes
            // proof rows here, so both absences are the terminal
            // `method_unsupported` rather than a resolver failure.
            limited_trust: LimitedTrust::for_proofless_method(None, None).record_for(),
            evidence_digest: receipt.digest()?,
            evidence_dependencies: receipt.evidence_dependencies()?,
            policy_digest: scope.policy_digest.clone(),
            verified_at: now,
            refresh_after: Some(now + Duration::minutes(BINDING_REFRESH_MINUTES)),
            expires_at: Some(now + Duration::days(BINDING_HARD_EXPIRY_DAYS)),
            status: DidBindingStatus::Active,
        },
    )?;
    Ok(AcceptedDidBinding::new(binding, document.clone(), receipt)?)
}

/// inkson's [`VerifiedDidBindingStore`], hydrated from and snapshotted back
/// into the per-account persisted state.
///
/// The SDK trait requires `Send + Sync`, which rules out holding any Dioxus
/// signal or `Rc`-based state handle inside. This type therefore owns only the
/// SDK's in-memory reference store; persistence is a snapshot / hydrate pair at
/// the edges, mirroring the pattern
/// [`crate::identity::did_resolver::ResolverDidAnchor`] already uses for
/// `DidResolutionCache` (`from_profile(cache)` … `into_cache()`).
#[derive(Debug)]
pub(crate) struct InksonDidBindingStore {
    inner: InMemoryVerifiedDidBindingStore,
}

impl InksonDidBindingStore {
    /// Build a store from persisted records.
    ///
    /// The pairing invariant (pinned document's canonical digest ==
    /// `binding.document_digest()`, and `document.id == binding.did()`) is
    /// enforced by [`AcceptedDidBinding`]'s own `Deserialize`, which routes
    /// through its validating constructor — so a record that reaches this
    /// function has already been re-validated on the way off disk, and a
    /// tampered one was **dropped** by
    /// [`crate::state::decode_accepted_did_bindings`] rather than trusted.
    pub(crate) fn hydrate(records: Vec<AcceptedDidBinding>) -> Self {
        let inner = InMemoryVerifiedDidBindingStore::new(MAX_PERSISTED_DID_BINDINGS);
        for accepted in records {
            let _ = inner.accept(accepted);
        }
        Self { inner }
    }

    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            inner: InMemoryVerifiedDidBindingStore::new(MAX_PERSISTED_DID_BINDINGS),
        }
    }

    /// Deterministic snapshot for persistence (ordered by store key).
    ///
    /// [`AcceptedDidBinding`] serializes as `{binding, document}` — exactly the
    /// shape the previous local `PersistedDidBinding` wrapper produced — so this
    /// is the SDK snapshot verbatim, with no manual split / recombine step that
    /// could drift from the pairing invariant.
    pub(crate) fn persisted_records(&self) -> Vec<AcceptedDidBinding> {
        self.inner.snapshot()
    }

    /// Zero-network read for ordinary render / sync paths.
    ///
    /// Uses [`FreshnessRequirement::any_accepted`] deliberately: a `Stale`
    /// binding is still usable for ordinary verification, and an ordinary read
    /// must never live-fallback (`did-usage-and-verification.md` §5).
    pub(crate) fn ordinary_lookup(
        &self,
        key: &VerifiedDidBindingKey,
        now: DateTime<Utc>,
    ) -> Option<AcceptedDidBinding> {
        let accepted = self.inner.get(key, now)?;
        accepted
            .binding()
            .is_usable_for_ordinary_verification()
            .then_some(accepted)
    }

    pub(crate) fn accept(&self, accepted: AcceptedDidBinding) {
        if let Err(error) = self.inner.accept(accepted) {
            tracing::warn!(%error, "rejected an inconsistent accepted DID binding");
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }
}

impl VerifiedDidBindingStore for InksonDidBindingStore {
    fn get_with_freshness(
        &self,
        key: &VerifiedDidBindingKey,
        now: DateTime<Utc>,
    ) -> (
        Option<AcceptedDidBinding>,
        arkret_sdk::identity::BindingFreshness,
    ) {
        self.inner.get_with_freshness(key, now)
    }

    fn accept(
        &self,
        accepted: AcceptedDidBinding,
    ) -> Result<(), arkret_sdk::identity::BindingStoreError> {
        self.inner.accept(accepted)
    }

    fn invalidate(&self, selector: &BindingInvalidation) -> usize {
        self.inner.invalidate(selector)
    }

    fn snapshot(&self) -> Vec<AcceptedDidBinding> {
        self.inner.snapshot()
    }
}

/// Freshness required only by an explicit registration-current call site.
///
/// §5.4 derives this from a registered profile rather than letting a call site
/// hand-write a window: `fresh_for_seconds` is simultaneously the
/// `refresh_after` offset and the authority `max_age`, so the two cannot drift.
/// Ordinary PCR authorization never calls this helper or a current DID resolver.
#[cfg(test)]
pub(crate) fn registration_freshness() -> FreshnessRequirement {
    FreshnessProfile::high_tier(
        arkret_sdk::DidFreshnessProfileId::RegistrationCurrentV1,
        Duration::minutes(BINDING_REFRESH_MINUTES),
        Some(Duration::days(BINDING_HARD_EXPIRY_DAYS)),
    )
    .requirement()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::did_resolver::DeploymentProfile;

    pub(crate) fn document(did: &str) -> DidDocument {
        DidDocument {
            id: DidFullId::new(did.to_owned()).expect("valid did"),
            verification_methods: std::collections::BTreeMap::from([(
                format!("{did}#key-1"),
                "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
            )]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: std::collections::BTreeMap::new(),
        }
    }

    fn scope(base_url: &str) -> DidBindingScope {
        DidBindingScope::for_server(DeploymentProfile::PersonalNode, base_url).expect("scope")
    }

    #[test]
    fn server_origin_drives_the_trust_domain() {
        let a = scope("https://Alpha.Example:8443/base");
        let b = scope("https://beta.example");
        assert_eq!(
            a.trust_domain().as_str(),
            "ak:trust_domain:alpha.example:8443"
        );
        assert_eq!(b.trust_domain().as_str(), "ak:trust_domain:beta.example");
        assert_ne!(a.trust_domain(), b.trust_domain());
        // Same deployment profile → same policy digest.
        assert_eq!(a.policy_digest(), b.policy_digest());
    }

    #[test]
    fn malformed_base_url_falls_back_to_a_distinct_local_domain() {
        let fallback = scope("not a url");
        assert_eq!(
            fallback.trust_domain().as_str(),
            "ak:trust_domain:inkson.local"
        );
        assert_ne!(
            fallback.trust_domain(),
            scope("https://beta.example").trust_domain()
        );
    }

    /// The fork this convergence closed: the local digest used
    /// `format!("{:?}", fail_mode)` → `"FailClosed"` while the peer repos wrote
    /// `"fail_closed"` by hand, so the *same* policy value produced two
    /// different digests. The §5.3 snapshot must emit the registered snake_case
    /// token and no `Debug` output anywhere in the digested object.
    #[test]
    fn policy_digest_encodes_the_fail_mode_as_a_closed_token() {
        let policy = crate::identity::did_resolver::policy_for(DeploymentProfile::PersonalNode);
        let canonical = policy
            .policy_snapshot()
            .expect("the personal-node policy declares a closed method list")
            .canonical_value();
        assert_eq!(canonical["fail_mode"], serde_json::json!("fail_closed"));
        assert_eq!(
            canonical["policy_profile"],
            serde_json::json!(arkret_sdk::identity::BASE_RESOLVER_POLICY_PROFILE)
        );
        let rendered = canonical.to_string();
        assert!(
            !rendered.contains("FailClosed"),
            "no Debug output may reach the digest: {rendered}"
        );
    }

    #[test]
    fn accepted_binding_round_trips_through_persistence() {
        let scope = scope("https://alpha.example");
        let document = document("did:web:alice.example");
        let accepted = accept_verified_document(
            &scope,
            DidBindingPurpose::DeviceSigner,
            None,
            &document,
            Utc::now(),
        )
        .expect("acceptance");
        let store = InksonDidBindingStore::empty();
        store.accept(accepted);
        let records = store.persisted_records();
        assert_eq!(records.len(), 1);

        let rehydrated = InksonDidBindingStore::hydrate(records);
        let key = scope.key(&document.id, DidBindingPurpose::DeviceSigner, None);
        let hit = rehydrated
            .ordinary_lookup(&key, Utc::now())
            .expect("binding survives a restart");
        assert_eq!(hit.document(), &document);
    }

    /// **The pinned document may not be edited underneath the digest.**
    ///
    /// The tamper is applied at the real boundary — the serialized on-disk row —
    /// because [`AcceptedDidBinding`]'s fields are private and the pairing is
    /// now re-validated by its own `Deserialize`. Three things are asserted:
    /// the row itself fails to deserialize; the state decoder *drops* it rather
    /// than trusting it (and rather than failing the whole account blob, which
    /// `read_account_state` would treat as corruption); and a store hydrated
    /// from the survivors holds nothing.
    #[test]
    fn tampered_persisted_document_is_dropped_not_trusted() {
        let scope = scope("https://alpha.example");
        let document = document("did:web:alice.example");
        let store = InksonDidBindingStore::empty();
        store.accept(
            accept_verified_document(
                &scope,
                DidBindingPurpose::Principal,
                None,
                &document,
                Utc::now(),
            )
            .expect("acceptance"),
        );
        // Also persist an untouched sibling, so "dropped" is provably per-record
        // and not a wholesale wipe.
        store.accept(
            accept_verified_document(
                &scope,
                DidBindingPurpose::Principal,
                None,
                &self::document("did:web:bob.example"),
                Utc::now(),
            )
            .expect("acceptance"),
        );

        let mut rows = match serde_json::to_value(store.persisted_records()).expect("serialize") {
            serde_json::Value::Array(rows) => rows,
            other => panic!("expected an array of persisted rows, got {other}"),
        };
        assert_eq!(rows.len(), 2);
        let tampered = rows
            .iter_mut()
            .find(|row| row["binding"]["did"] == serde_json::json!("did:web:alice.example"))
            .expect("alice's row");
        // Swap in a different key set without touching the recorded digest.
        tampered["document"]["verification_methods"]["did:web:alice.example#attacker"] =
            serde_json::json!("z6MkAttackerControlledKeyMaterialXXXXXXXXXXXXXXXX");
        assert!(
            serde_json::from_value::<AcceptedDidBinding>(tampered.clone()).is_err(),
            "a document edited under a recorded digest must not deserialize"
        );

        let decoded = crate::state::decode_accepted_did_bindings(rows);
        assert_eq!(decoded.len(), 1, "only the tampered row may be dropped");
        assert_eq!(decoded[0].document().id.as_str(), "did:web:bob.example");

        let rehydrated = InksonDidBindingStore::hydrate(decoded);
        assert_eq!(rehydrated.len(), 1);
        assert!(
            rehydrated
                .ordinary_lookup(
                    &scope.key(&document.id, DidBindingPurpose::Principal, None),
                    Utc::now()
                )
                .is_none(),
            "the tampered acceptance must be unreachable, not merely downgraded"
        );
    }

    #[test]
    fn a_purpose_acceptance_does_not_authorize_another_purpose() {
        let scope = scope("https://alpha.example");
        let document = document("did:web:alice.example");
        let store = InksonDidBindingStore::empty();
        store.accept(
            accept_verified_document(
                &scope,
                DidBindingPurpose::DeviceSigner,
                None,
                &document,
                Utc::now(),
            )
            .expect("acceptance"),
        );
        let other = scope.key(&document.id, DidBindingPurpose::Issuer, None);
        assert!(store.ordinary_lookup(&other, Utc::now()).is_none());
    }

    #[test]
    fn a_binding_from_another_trust_domain_is_never_reused() {
        let alpha = scope("https://alpha.example");
        let beta = scope("https://beta.example");
        let document = document("did:web:alice.example");
        let store = InksonDidBindingStore::empty();
        store.accept(
            accept_verified_document(
                &alpha,
                DidBindingPurpose::Principal,
                None,
                &document,
                Utc::now(),
            )
            .expect("acceptance"),
        );
        assert!(
            store
                .ordinary_lookup(
                    &beta.key(&document.id, DidBindingPurpose::Principal, None),
                    Utc::now()
                )
                .is_none(),
            "an acceptance made against alpha must not authorize beta"
        );
        assert!(
            store
                .ordinary_lookup(
                    &alpha.key(&document.id, DidBindingPurpose::Principal, None),
                    Utc::now()
                )
                .is_some()
        );
    }

    #[test]
    fn stale_binding_is_still_usable_for_ordinary_reads_but_not_for_authority() {
        let scope = scope("https://alpha.example");
        let document = document("did:web:alice.example");
        let accepted_at = Utc::now() - Duration::hours(2);
        let store = InksonDidBindingStore::empty();
        store.accept(
            accept_verified_document(
                &scope,
                DidBindingPurpose::Principal,
                None,
                &document,
                accepted_at,
            )
            .expect("acceptance"),
        );
        let key = scope.key(&document.id, DidBindingPurpose::Principal, None);
        let now = Utc::now();
        let hit = store
            .ordinary_lookup(&key, now)
            .expect("stale entries stay readable");
        assert_eq!(hit.binding().status(), DidBindingStatus::Stale);
        assert!(
            !hit.binding()
                .is_usable_for_authority(&registration_freshness(), now)
        );
    }

    #[test]
    fn hard_expired_binding_disappears_for_readers() {
        let scope = scope("https://alpha.example");
        let document = document("did:web:alice.example");
        let accepted_at = Utc::now() - Duration::days(BINDING_HARD_EXPIRY_DAYS + 1);
        let store = InksonDidBindingStore::empty();
        store.accept(
            accept_verified_document(
                &scope,
                DidBindingPurpose::Principal,
                None,
                &document,
                accepted_at,
            )
            .expect("acceptance"),
        );
        let key = scope.key(&document.id, DidBindingPurpose::Principal, None);
        assert!(store.ordinary_lookup(&key, Utc::now()).is_none());
    }
}
