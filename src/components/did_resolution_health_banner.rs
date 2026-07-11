//! App-level DID resolution health banner.
//!
//! Authority-grade DID checks still fail closed in `did_resolver`; this module
//! only renders a session-wide warning when the identity describe probe says
//! live resolution is unavailable or falling back to cached evidence.

use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use super::UiIcon;
use crate::identity::did_resolver::DidResolutionCache;
use crate::models::IdentityDescribeOutcome;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidResolutionHealthReason {
    IdentityDescribeFailedFreshCache,
    IdentityDescribeFailedStaleCache,
    IdentityDescribeFailedNoCache,
    UnsupportedIdentityProtocol,
    UnsupportedPrincipalServer,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DidResolutionHealth {
    #[default]
    Healthy,
    Degraded {
        reason: DidResolutionHealthReason,
    },
    Outage {
        reason: DidResolutionHealthReason,
    },
}

struct DidResolutionHealthPresentation {
    token: &'static str,
    label: &'static str,
    title: &'static str,
    detail: &'static str,
}

impl DidResolutionHealth {
    pub fn healthy() -> Self {
        Self::Healthy
    }

    pub fn unsupported_principal_server() -> Self {
        Self::Outage {
            reason: DidResolutionHealthReason::UnsupportedPrincipalServer,
        }
    }

    pub fn from_identity_description(description: &IdentityDescribeOutcome) -> Self {
        if description.protocol_version.trim() == "1.0" {
            Self::Healthy
        } else {
            Self::Degraded {
                reason: DidResolutionHealthReason::UnsupportedIdentityProtocol,
            }
        }
    }

    pub fn from_identity_probe_failure(cache: &DidResolutionCache, now: DateTime<Utc>) -> Self {
        if cache.has_fresh_entry(now) {
            Self::Degraded {
                reason: DidResolutionHealthReason::IdentityDescribeFailedFreshCache,
            }
        } else if cache.has_only_stale_entries(now) {
            Self::Degraded {
                reason: DidResolutionHealthReason::IdentityDescribeFailedStaleCache,
            }
        } else {
            Self::Outage {
                reason: DidResolutionHealthReason::IdentityDescribeFailedNoCache,
            }
        }
    }

    fn presentation(&self) -> Option<DidResolutionHealthPresentation> {
        match self {
            Self::Healthy => None,
            Self::Degraded { reason } => Some(match reason {
                DidResolutionHealthReason::IdentityDescribeFailedFreshCache => {
                    DidResolutionHealthPresentation {
                        token: "degraded",
                        label: "degraded",
                        title: "Identity resolution degraded",
                        detail: "Live identity checks are unreachable; fresh cached identity evidence is available for display only.",
                    }
                }
                DidResolutionHealthReason::IdentityDescribeFailedStaleCache => {
                    DidResolutionHealthPresentation {
                        token: "degraded",
                        label: "stale cache",
                        title: "Identity resolution degraded",
                        detail: "Live identity checks are unreachable; cached identity evidence is stale and trust decisions fail closed.",
                    }
                }
                DidResolutionHealthReason::UnsupportedIdentityProtocol => {
                    DidResolutionHealthPresentation {
                        token: "degraded",
                        label: "metadata",
                        title: "Identity metadata mismatch",
                        detail: "The identity service did not advertise the required v1 protocol shape; trust checks remain guarded.",
                    }
                }
                DidResolutionHealthReason::IdentityDescribeFailedNoCache
                | DidResolutionHealthReason::UnsupportedPrincipalServer => {
                    DidResolutionHealthPresentation {
                        token: "degraded",
                        label: "degraded",
                        title: "Identity resolution degraded",
                        detail: "Live identity checks are partially unavailable; trust decisions remain guarded.",
                    }
                }
            }),
            Self::Outage { reason } => Some(match reason {
                DidResolutionHealthReason::IdentityDescribeFailedNoCache => {
                    DidResolutionHealthPresentation {
                        token: "outage",
                        label: "outage",
                        title: "Identity resolution unavailable",
                        detail: "Live identity checks are unreachable and no cached identity evidence is available; trust decisions fail closed.",
                    }
                }
                DidResolutionHealthReason::UnsupportedPrincipalServer => {
                    DidResolutionHealthPresentation {
                        token: "outage",
                        label: "server metadata",
                        title: "Identity service unavailable",
                        detail: "This server did not advertise the required v1 principal-server metadata; identity authority checks are blocked.",
                    }
                }
                DidResolutionHealthReason::IdentityDescribeFailedFreshCache
                | DidResolutionHealthReason::IdentityDescribeFailedStaleCache
                | DidResolutionHealthReason::UnsupportedIdentityProtocol => {
                    DidResolutionHealthPresentation {
                        token: "outage",
                        label: "outage",
                        title: "Identity resolution unavailable",
                        detail: "Identity authority checks are blocked until the service recovers.",
                    }
                }
            }),
        }
    }
}

#[component]
pub fn DidResolutionHealthBanner(health: Signal<DidResolutionHealth>) -> Element {
    let current = health();
    let Some(presentation) = current.presentation() else {
        return rsx! {};
    };
    let role = if presentation.token == "outage" {
        "alert"
    } else {
        "status"
    };
    let live = if presentation.token == "outage" {
        "assertive"
    } else {
        "polite"
    };
    let token = presentation.token;
    let title = presentation.title;
    let label = presentation.label;
    let detail = presentation.detail;

    rsx! {
        div {
            class: "did-resolution-health-banner did-resolution-health-banner--{token}",
            role: "{role}",
            "aria-live": "{live}",
            "data-testid": "did-resolution-health-banner",
            "data-health": "{token}",
            div { class: "did-resolution-health-banner-row",
                span { class: "did-resolution-health-banner-icon",
                    UiIcon { name: "alert" }
                }
                strong { "{title}" }
                span { class: "did-resolution-health-banner-label", "{label}" }
            }
            p { "{detail}" }
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{Did, DidDocument};
    use chrono::Duration;

    use super::*;

    fn identity_description(protocol_version: &str) -> IdentityDescribeOutcome {
        IdentityDescribeOutcome {
            service_did: Did::new("did:web:identity.example".to_owned()).expect("valid did"),
            registry_mode: "local".to_owned(),
            supported_receipts: Vec::new(),
            protocol_version: protocol_version.to_owned(),
            profiles: Vec::new(),
        }
    }

    fn cache_with_entry(ttl: Duration, now: DateTime<Utc>) -> DidResolutionCache {
        let mut cache = DidResolutionCache::new(8);
        let did = Did::new("did:web:alice.example".to_owned()).expect("valid did");
        let document = DidDocument::new(did.clone(), "owner", "z6Mksample");
        cache.insert(did, document, now, ttl);
        cache
    }

    #[test]
    fn successful_v1_identity_description_is_healthy() {
        let description = identity_description("1.0");
        assert_eq!(
            DidResolutionHealth::from_identity_description(&description),
            DidResolutionHealth::Healthy
        );
    }

    #[test]
    fn unsupported_identity_protocol_is_degraded() {
        let description = identity_description("2.0");
        assert_eq!(
            DidResolutionHealth::from_identity_description(&description),
            DidResolutionHealth::Degraded {
                reason: DidResolutionHealthReason::UnsupportedIdentityProtocol
            }
        );
    }

    #[test]
    fn probe_failure_with_fresh_cache_is_degraded() {
        let now = Utc::now();
        let cache = cache_with_entry(Duration::seconds(60), now);
        assert_eq!(
            DidResolutionHealth::from_identity_probe_failure(&cache, now + Duration::seconds(30)),
            DidResolutionHealth::Degraded {
                reason: DidResolutionHealthReason::IdentityDescribeFailedFreshCache
            }
        );
    }

    #[test]
    fn probe_failure_with_only_stale_cache_is_degraded() {
        let now = Utc::now();
        let cache = cache_with_entry(Duration::seconds(60), now);
        assert_eq!(
            DidResolutionHealth::from_identity_probe_failure(&cache, now + Duration::seconds(60)),
            DidResolutionHealth::Degraded {
                reason: DidResolutionHealthReason::IdentityDescribeFailedStaleCache
            }
        );
    }

    #[test]
    fn probe_failure_without_cache_is_outage() {
        let cache = DidResolutionCache::new(8);
        assert_eq!(
            DidResolutionHealth::from_identity_probe_failure(&cache, Utc::now()),
            DidResolutionHealth::Outage {
                reason: DidResolutionHealthReason::IdentityDescribeFailedNoCache
            }
        );
    }
}
