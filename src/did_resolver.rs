//! Default DID resolver chain for yougen.
//!
//! Wraps `contrix_sdk::identity::*` resolvers with a yougen-specific
//! `ResolverPolicy` so login / coauth / Move-signing call sites can validate
//! principal DIDs before relying on a server-asserted identity.
//!
//! Spec sources:
//! - `identity/identity-did.md` (§3 default DID methods, §4 resolver policy)
//! - `identity/identity-handles.md` (§5 fail-closed rules)

use contrix_sdk::identity::{
    CompositeDidResolver, DidKeyResolver, DidResolver as _, DidWebResolver, DidWebvhResolver,
    ResolverFailMode, ResolverPolicy,
};
use contrix_sdk::{Did, DidDocument};

/// Deployment profile drives which DID methods are accepted as principal.
///
/// Mirrors `spec/v1/zh/identity/identity-did.md` §3.3 / §3.4:
/// - `PersonalNode`: `did:web` allowed as principal fallback.
/// - `SmallTeam` / `Organization` / higher: principal MUST be `did:webvh`.
/// - `Sovereign`: principal limited to a deployment-specific method list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentProfile {
    PersonalNode,
    SmallTeam,
    Organization,
    HighSecurity,
    Sovereign,
}

impl DeploymentProfile {
    fn allowed_principal_methods(self) -> Vec<String> {
        match self {
            // did:key remains valid for device / bootstrap on every tier.
            Self::PersonalNode => vec!["did:webvh:".into(), "did:web:".into(), "did:key:".into()],
            Self::SmallTeam | Self::Organization | Self::HighSecurity => {
                vec!["did:webvh:".into(), "did:key:".into()]
            }
            // Sovereign deployments configure their own method list; default to
            // webvh + key and let callers extend via `policy_for()`.
            Self::Sovereign => vec!["did:webvh:".into(), "did:key:".into()],
        }
    }

    fn default_principal_method(self) -> &'static str {
        match self {
            Self::PersonalNode => "did:webvh:",
            _ => "did:webvh:",
        }
    }
}

/// Build the default policy for `profile`. Fails closed on resolver errors,
/// 15-minute TTL on cached resolutions.
pub fn policy_for(profile: DeploymentProfile) -> ResolverPolicy {
    ResolverPolicy {
        allowed_methods: profile.allowed_principal_methods(),
        default_principal_method: Some(profile.default_principal_method().to_owned()),
        trust_roots: Vec::new(),
        ttl: Some(chrono::Duration::minutes(15)),
        fail_mode: ResolverFailMode::FailClosed,
    }
}

/// Build a composite resolver chain with `did:web` + `did:webvh` + `did:key`
/// adapters and the given policy. Documents must be ingested via the SDK
/// resolver APIs (`insert_from_https_response`, `ingest_log`, etc.) before
/// `resolve()` will succeed for that DID.
pub fn build_default_resolver(profile: DeploymentProfile) -> CompositeDidResolver {
    let mut composite = CompositeDidResolver::new().with_policy(policy_for(profile));
    composite.push(DidKeyResolver::new());
    composite.push(DidWebResolver::new());
    composite.push(DidWebvhResolver::new());
    composite
}

/// High-level verification surface for login / coauth.
///
/// Errors:
/// - `Disallowed` — DID method is not in `allowed_methods` for the active profile.
/// - `Unresolved` — no resolver could resolve the DID (likely missing document evidence).
/// - `MethodMismatch` — returned document `id` does not equal the requested DID.
#[derive(Debug)]
pub enum VerifyError {
    Disallowed(String),
    Unresolved(String),
    MethodMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disallowed(d) => write!(f, "DID method not allowed: {d}"),
            Self::Unresolved(d) => write!(f, "DID resolution failed: {d}"),
            Self::MethodMismatch => f.write_str("DID document id does not match requested DID"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify `principal` against the resolver chain. Returns the resolved
/// `DidDocument` on success.
///
/// The resolver must already have document / log evidence registered for
/// `principal` (e.g. the caller fetched `did.json` and ingested it via
/// `DidWebResolver::insert_from_https_response`).
pub fn verify_principal(
    resolver: &CompositeDidResolver,
    principal: &Did,
) -> Result<DidDocument, VerifyError> {
    resolver
        .policy()
        .validate(principal)
        .map_err(|e| VerifyError::Disallowed(format!("{e:?}")))?;
    let doc = resolver
        .resolve_did(principal)
        .map_err(|e| VerifyError::Unresolved(format!("{e:?}")))?;
    if &doc.id != principal {
        return Err(VerifyError::MethodMismatch);
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(did: &str) -> Did {
        Did::new(did.to_owned()).expect("valid did")
    }

    #[test]
    fn personal_node_allows_did_web() {
        let policy = policy_for(DeploymentProfile::PersonalNode);
        assert!(policy.permits(&parse("did:web:alice.example")));
        assert!(policy.permits(&parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")));
    }

    #[test]
    fn organization_rejects_plain_did_web_principal() {
        let policy = policy_for(DeploymentProfile::Organization);
        assert!(!policy.permits(&parse("did:web:alice.example")));
        assert!(policy.permits(&parse(
            "did:webvh:QmExampleScidValue123456:alice.example"
        )));
    }

    #[test]
    fn default_resolver_rejects_unknown_method() {
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let bogus = parse("did:bogus:1234");
        let err = verify_principal(&resolver, &bogus).expect_err("must be disallowed");
        match err {
            VerifyError::Disallowed(_) => {}
            other => panic!("expected Disallowed, got {other:?}"),
        }
    }

    #[test]
    fn unresolved_did_web_fails_closed() {
        // Allowed method, but no document evidence ingested -> fail-closed.
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let did = parse("did:web:alice.example");
        match verify_principal(&resolver, &did) {
            Err(VerifyError::Unresolved(_)) => {}
            other => panic!("expected Unresolved, got {other:?}"),
        }
    }
}
