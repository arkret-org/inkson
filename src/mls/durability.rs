//! Realm Recovery Key (RRK) durability — client-side seal/recover orchestration.
//!
//! Spec sources:
//! - `crypto-media/encryption-and-audit.md` §2.10.8 (sealing obligation, disclosure obligation, RYW
//!   guard, eager timing).
//! - `models/realm-and-space.md` §2.3.1 (`durability_policy`).
//! - `identity/identity-did.md` §8.3 (`ArkretRealmHistoryRecoveryKey`).
//!
//! ## Owner contract boundary
//!
//! Recovery-recipient DID service resolution is owned by `arkret-identity`;
//! HPKE seal/open is owned by `arkret-crypto`. This module is the **thin Inkson
//! adapter** both the eager seal hook (§2.10.8) and the disclosure banner route
//! through. It only:
//!
//! - fetches / ingests the recipient principal's raw DID Document (the SDK `DidDocument` projection
//!   drops `service` / `keyAgreement`, so the resolver's original document value is threaded
//!   through unmodified), and
//! - assembles the application-owned durable payload around those owner calls so the call sites
//!   stay stable.

use arkret_identity::history_recovery::{
    RealmHistoryRecoveryKeyError, ResolvedRealmHistoryRecoveryKey,
    resolve_realm_history_recovery_key,
};
use arkret_models_collaboration::objects::realm::{
    DurabilityMode, DurabilityPolicy, RealmRecoveryRecipient,
};
use serde_json::Value;

/// Effective disclosure mode label (encryption-and-audit.md §2.10.8): the banner
/// MUST mark `org_recovery_key` (single) vs `threshold` (k-of-n). `None` for
/// `mode == none` (no banner).
pub fn durability_mode_label(policy: &DurabilityPolicy) -> Option<&'static str> {
    match policy.mode {
        DurabilityMode::None => None,
        DurabilityMode::OrgRecoveryKey => Some("org_recovery_key"),
        DurabilityMode::Threshold => Some("threshold"),
    }
}

/// True when the durability policy is effective (`mode != none`). The §2.10.8
/// sealing + disclosure obligations only apply when this holds AND the Realm uses
/// `content_scheme=mls_exporter_aead_v1` (the caller checks the scheme).
pub fn durability_is_effective(policy: &DurabilityPolicy) -> bool {
    !matches!(policy.mode, DurabilityMode::None)
}

/// Resolve + verify one recovery recipient against its principal's raw DID
/// Document JSON. Pure delegation to the Identity owner
/// [`resolve_realm_history_recovery_key`] — fail-closed
/// (`durability_recovery_recipient_unverified`) on any resolution / designation
/// gap; never falls back to an arbitrary key.
///
/// `did_document_json` MUST be the raw W3C DID Document (carrying `service` and
/// `keyAgreement`), resolved as of the seal Event's accepted-at for historical
/// re-verification (identity-did.md §8.3 point-in-time rule). For the live seal
/// path it is the current document.
pub fn resolve_recovery_recipient(
    recipient: &RealmRecoveryRecipient,
    did_document_json: &Value,
) -> Result<ResolvedRealmHistoryRecoveryKey, RealmHistoryRecoveryKeyError> {
    resolve_realm_history_recovery_key(
        &recipient.recipient_id,
        &recipient.principal_id,
        &recipient.verification_method,
        did_document_json,
    )
}

/// Outcome of verifying one recovery recipient against its published DID
/// document — the service-entry designation check, decoupled from any UI
/// concern (no display formatting).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRecipientCheck {
    pub recipient_id: String,
    pub principal_did: String,
    pub controller_organization: Option<String>,
    pub verified: bool,
}

/// Resolve + verify a whole set of recovery recipients. Encapsulates the
/// public DID-document fetch and the per-recipient `ArkretRealmHistoryRecoveryKey`
/// service-entry designation check so UI surfaces (e.g. the durability banner)
/// consume typed results instead of driving the HTTP orchestration in the view
/// layer. `http` is a shared unauthenticated client — recovery-recipient DID
/// documents are public `did.json`, so no auth material is involved.
pub async fn verify_recovery_recipients(
    http: &reqwest::Client,
    recipients: &[RealmRecoveryRecipient],
) -> Vec<RecoveryRecipientCheck> {
    let mut out = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let principal_full_id = recipient
            .verification_method
            .as_str()
            .split_once('#')
            .and_then(|(controller, _)| arkret_sdk::DidFullId::new(controller.to_owned()).ok())
            .filter(|full_id| {
                arkret_sdk::project_full_id_to_core_id(full_id)
                    .is_ok_and(|core_id| core_id == recipient.principal_id)
            });
        let principal_did = principal_full_id
            .as_ref()
            .map_or_else(|| recipient.principal_id.to_string(), ToString::to_string);
        let document = match principal_full_id {
            Some(full_id) => {
                crate::identity::did_resolver::fetch_raw_did_document_json(http, &full_id).await
            }
            None => None,
        };
        let verified = document
            .as_ref()
            .is_some_and(|document| resolve_recovery_recipient(recipient, document).is_ok());
        out.push(RecoveryRecipientCheck {
            recipient_id: recipient.recipient_id.clone(),
            principal_did,
            controller_organization: recipient
                .controller_organization
                .as_ref()
                .map(|did| did.as_str().to_owned()),
            verified,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::objects::realm::DurabilityThreshold;
    use serde_json::json;

    use super::*;

    fn policy(mode: DurabilityMode) -> DurabilityPolicy {
        DurabilityPolicy {
            mode,
            recovery_recipients: Vec::new(),
            threshold: matches!(mode, DurabilityMode::Threshold)
                .then_some(DurabilityThreshold { k: 2, n: 3 }),
        }
    }

    #[test]
    fn mode_label_distinguishes_modes() {
        assert_eq!(durability_mode_label(&policy(DurabilityMode::None)), None);
        assert_eq!(
            durability_mode_label(&policy(DurabilityMode::OrgRecoveryKey)),
            Some("org_recovery_key")
        );
        assert_eq!(
            durability_mode_label(&policy(DurabilityMode::Threshold)),
            Some("threshold")
        );
    }

    #[test]
    fn effective_only_when_mode_not_none() {
        assert!(!durability_is_effective(&policy(DurabilityMode::None)));
        assert!(durability_is_effective(&policy(
            DurabilityMode::OrgRecoveryKey
        )));
        assert!(durability_is_effective(&policy(DurabilityMode::Threshold)));
    }

    fn recipient() -> RealmRecoveryRecipient {
        RealmRecoveryRecipient {
            recipient_id: "acme-org-rrk-1".to_owned(),
            principal_id: crate::mls_api_helpers::principal_core_id("did:web:acme.example")
                .unwrap(),
            verification_method: arkret_sdk::DidUrl::new(
                "did:web:acme.example#realm-history-recovery-1",
            )
            .unwrap(),
            controller_organization: None,
        }
    }

    fn x25519_multibase(pubkey: &[u8; 32]) -> String {
        let mut bytes = vec![0xecu8, 0x01];
        bytes.extend_from_slice(pubkey);
        arkret_sdk::encode_multibase_base58btc(bytes)
    }

    fn did_document(recipient: &RealmRecoveryRecipient, pubkey: &[u8; 32]) -> Value {
        json!({
            "id": recipient.principal_id.as_str(),
            "verificationMethod": [
                {
                    "id": recipient.verification_method,
                    "type": "Multikey",
                    "controller": recipient.principal_id.as_str(),
                    "publicKeyMultibase": x25519_multibase(pubkey),
                }
            ],
            "keyAgreement": [recipient.verification_method],
            "service": [
                {
                    "id": "did:web:acme.example#realm-history-recovery",
                    "type": "ArkretRealmHistoryRecoveryKey",
                    "serviceEndpoint": {
                        "verificationMethod": recipient.verification_method,
                        "kem": "hpke",
                        "domain": "mls_history",
                    }
                }
            ]
        })
    }

    #[test]
    fn adapter_resolve_fails_closed_on_missing_service() {
        let recipient = recipient();
        let mut document = did_document(&recipient, &[3u8; 32]);
        document["service"] = json!([]);
        assert!(resolve_recovery_recipient(&recipient, &document).is_err());
    }
}
