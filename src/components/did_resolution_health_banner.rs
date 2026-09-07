//! App-level DID resolution health banner.
//!
//! Authority-grade DID checks still fail closed in `did_resolver`; this module
//! only renders a session-wide warning when the identity describe probe says
//! live resolution is unavailable or falling back to cached evidence.

use arkret_sdk::identity::DidResolutionCache;
use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use super::UiIcon;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidResolutionHealthReason {
    IdentityDescribeFailedFreshCache,
    IdentityDescribeFailedStaleCache,
    IdentityDescribeFailedNoCache,
    UnsupportedIdentityProtocol,
    UnsupportedStation,
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

/// Presentation carries i18n keys, not copy: the banner resolves them through
/// `tr()` at render time so both shipped locales work.
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

    pub fn unsupported_station() -> Self {
        Self::Outage {
            reason: DidResolutionHealthReason::UnsupportedStation,
        }
    }

    pub fn from_identity_description(description: &arkret_sdk::ServiceDescribe) -> Self {
        if description.protocol_version.as_str() == arkret_sdk::PROTOCOL_VERSION {
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

    pub(crate) fn from_probe_error(
        error: &anyhow::Error,
        cache: &DidResolutionCache,
        now: DateTime<Utc>,
    ) -> Self {
        if crate::api_error::is_response_format_error(error) {
            Self::Degraded {
                reason: DidResolutionHealthReason::UnsupportedIdentityProtocol,
            }
        } else {
            Self::from_identity_probe_failure(cache, now)
        }
    }

    fn presentation(&self) -> Option<DidResolutionHealthPresentation> {
        match self {
            Self::Healthy => None,
            Self::Degraded { reason } => Some(match reason {
                DidResolutionHealthReason::IdentityDescribeFailedFreshCache => {
                    DidResolutionHealthPresentation {
                        token: "degraded",
                        label: "did_health.label.degraded",
                        title: "did_health.title.degraded",
                        detail: "did_health.detail.fresh_cache",
                    }
                }
                DidResolutionHealthReason::IdentityDescribeFailedStaleCache => {
                    DidResolutionHealthPresentation {
                        token: "degraded",
                        label: "did_health.label.stale_cache",
                        title: "did_health.title.degraded",
                        detail: "did_health.detail.stale_cache",
                    }
                }
                DidResolutionHealthReason::UnsupportedIdentityProtocol => {
                    DidResolutionHealthPresentation {
                        token: "degraded",
                        label: "did_health.label.metadata",
                        title: "did_health.title.metadata_mismatch",
                        detail: "did_health.detail.metadata_mismatch",
                    }
                }
                DidResolutionHealthReason::IdentityDescribeFailedNoCache
                | DidResolutionHealthReason::UnsupportedStation => {
                    DidResolutionHealthPresentation {
                        token: "degraded",
                        label: "did_health.label.degraded",
                        title: "did_health.title.degraded",
                        detail: "did_health.detail.partial",
                    }
                }
            }),
            Self::Outage { reason } => Some(match reason {
                DidResolutionHealthReason::IdentityDescribeFailedNoCache => {
                    DidResolutionHealthPresentation {
                        token: "outage",
                        label: "did_health.label.outage",
                        title: "did_health.title.unavailable",
                        detail: "did_health.detail.no_cache",
                    }
                }
                DidResolutionHealthReason::UnsupportedStation => DidResolutionHealthPresentation {
                    token: "outage",
                    label: "did_health.label.server_metadata",
                    title: "did_health.title.service_unavailable",
                    detail: "did_health.detail.server_metadata",
                },
                DidResolutionHealthReason::IdentityDescribeFailedFreshCache
                | DidResolutionHealthReason::IdentityDescribeFailedStaleCache
                | DidResolutionHealthReason::UnsupportedIdentityProtocol => {
                    DidResolutionHealthPresentation {
                        token: "outage",
                        label: "did_health.label.outage",
                        title: "did_health.title.unavailable",
                        detail: "did_health.detail.blocked",
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
    let title = crate::i18n::tr(presentation.title);
    let label = crate::i18n::tr(presentation.label);
    let detail = crate::i18n::tr(presentation.detail);

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
    use arkret_sdk::{
        Did, DidDocument, ServiceDescribe, ServiceKind, TransportBinding, TrustDomainId,
    };
    use chrono::Duration;

    use super::*;

    fn identity_description() -> ServiceDescribe {
        ServiceDescribe::development(
            Did::new("did:web:identity.example".to_owned()).expect("valid did"),
            TrustDomainId::new("ak:trust_domain:identity.example").expect("valid trust domain"),
            ServiceKind::IdentityRegistry,
            vec!["ak.operation_bundle.identity_registry.describe.v1".to_owned()],
            vec![TransportBinding::HttpJson {
                base_url: "https://identity.example/".to_owned(),
                extension_profile_required: (),
            }],
        )
    }

    fn cache_with_entry(ttl: Duration, now: DateTime<Utc>) -> DidResolutionCache {
        let cache = DidResolutionCache::new(8);
        let did = Did::new("did:web:alice.example".to_owned()).expect("valid did");
        let document = DidDocument::new(did.clone(), "owner", "z6Mksample");
        // `did:web` publishes no method proof.
        cache
            .insert(
                did,
                arkret_sdk::identity::ResolvedDid::proofless(document),
                now,
                ttl,
            )
            .unwrap();
        cache
    }

    #[test]
    fn successful_v1_identity_description_is_healthy() {
        let description = identity_description();
        assert_eq!(
            DidResolutionHealth::from_identity_description(&description),
            DidResolutionHealth::Healthy
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

    #[test]
    fn response_format_failure_is_metadata_mismatch_and_can_recover() {
        let decode = serde_json::from_str::<ServiceKind>("\"unknown_service\"").unwrap_err();
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Json(decode))
            .context("identity describe");
        let cache = DidResolutionCache::new(8);
        let health = DidResolutionHealth::from_probe_error(&error, &cache, Utc::now());
        assert_eq!(
            health,
            DidResolutionHealth::Degraded {
                reason: DidResolutionHealthReason::UnsupportedIdentityProtocol,
            }
        );
        assert_eq!(
            health.presentation().unwrap().label,
            "did_health.label.metadata"
        );
        let recovered = DidResolutionHealth::from_identity_description(&identity_description());
        assert!(recovered.presentation().is_none());
    }

    #[test]
    fn transport_failure_remains_outage() {
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Http(
            "connection refused".into(),
        ));
        let cache = DidResolutionCache::new(8);
        assert_eq!(
            DidResolutionHealth::from_probe_error(&error, &cache, Utc::now()),
            DidResolutionHealth::Outage {
                reason: DidResolutionHealthReason::IdentityDescribeFailedNoCache
            }
        );
    }

    #[test]
    fn contact_initialization_preserves_format_error_copy() {
        let decode = serde_json::from_str::<ServiceKind>("\"unknown_service\"").unwrap_err();
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Json(decode))
            .context("server describe")
            .context("resolve Account Authority");
        let error = crate::transport::auth::ApiCallError::Unavailable(error);
        assert_eq!(
            error.display(),
            crate::api_error::localized_error_copy("error.server_format_mismatch")
        );
    }
}
