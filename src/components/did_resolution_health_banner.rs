//! App-level DID resolution health banner.
//!
//! Renders the availability of the configured Station identity service.

use std::rc::Rc;

use glory::prelude::*;

use super::ui_icon;
use crate::presentation::widgets::{line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidResolutionHealthReason {
    IdentityDescribeFailed,
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

    pub(crate) fn from_probe_error(error: &anyhow::Error) -> Self {
        if crate::api_error::is_response_format_error(error) {
            Self::Degraded {
                reason: DidResolutionHealthReason::UnsupportedIdentityProtocol,
            }
        } else {
            Self::Outage {
                reason: DidResolutionHealthReason::IdentityDescribeFailed,
            }
        }
    }

    fn presentation(&self) -> Option<DidResolutionHealthPresentation> {
        match self {
            Self::Healthy => None,
            Self::Degraded { reason } => Some(match reason {
                DidResolutionHealthReason::UnsupportedIdentityProtocol => {
                    DidResolutionHealthPresentation {
                        token: "degraded",
                        label: "did_health.label.metadata",
                        title: "did_health.title.metadata_mismatch",
                        detail: "did_health.detail.metadata_mismatch",
                    }
                }
                DidResolutionHealthReason::IdentityDescribeFailed
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
                DidResolutionHealthReason::IdentityDescribeFailed => {
                    DidResolutionHealthPresentation {
                        token: "outage",
                        label: "did_health.label.outage",
                        title: "did_health.title.unavailable",
                        detail: "did_health.detail.unavailable",
                    }
                }
                DidResolutionHealthReason::UnsupportedStation => DidResolutionHealthPresentation {
                    token: "outage",
                    label: "did_health.label.server_metadata",
                    title: "did_health.title.service_unavailable",
                    detail: "did_health.detail.server_metadata",
                },
                DidResolutionHealthReason::UnsupportedIdentityProtocol => {
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

pub fn did_resolution_health_banner(
    _scope: &Scope,
    context: Rc<InksonContext>,
    health: Cage<DidResolutionHealth>,
) -> View {
    reactive(health, move |scope, current| {
        let Some(presentation) = current.presentation() else {
            return Box::new(widget(|_| Ok(())));
        };
        let content = stack(
            format!(
                "did-resolution-health-banner did-resolution-health-banner--{}",
                presentation.token
            ),
            vec![
                line(
                    "did-resolution-health-banner-row",
                    vec![
                        ui_icon("alert"),
                        paragraph(
                            "did-resolution-health-banner-title",
                            context.translated(scope, presentation.title),
                        ),
                        paragraph(
                            "did-resolution-health-banner-label",
                            context.translated(scope, presentation.label),
                        ),
                    ],
                ),
                paragraph("", context.translated(scope, presentation.detail)),
            ],
        );
        Box::new(
            sapid::alert("did-resolution-health")
                .unstyled()
                .severity(if presentation.token == "outage" {
                    sapid::AlertSeverity::Danger
                } else {
                    sapid::AlertSeverity::Warning
                })
                .fill(content),
        )
    })
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{Did, ServiceDescribe, ServiceKind, TransportBinding, TrustDomainId};

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

    #[test]
    fn successful_v1_identity_description_is_healthy() {
        let description = identity_description();
        assert_eq!(
            DidResolutionHealth::from_identity_description(&description),
            DidResolutionHealth::Healthy
        );
    }

    #[test]
    fn response_format_failure_is_metadata_mismatch_and_can_recover() {
        let decode = serde_json::from_str::<ServiceKind>("\"unknown_service\"").unwrap_err();
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Json(decode))
            .context("identity describe");
        let health = DidResolutionHealth::from_probe_error(&error);
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
        assert_eq!(
            DidResolutionHealth::from_probe_error(&error),
            DidResolutionHealth::Outage {
                reason: DidResolutionHealthReason::IdentityDescribeFailed
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
