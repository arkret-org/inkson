//! Realm Recovery Key (RRK) durability — client-side seal/recover orchestration.
//!
//! Spec sources:
//! - `crypto-media/encryption-and-audit.md` §2.10.8 (sealing obligation, disclosure obligation, RYW
//!   guard, eager timing).
//! - `models/realm-and-space.md` §2.3.1 (`durability_policy`).
//! - `identity/identity-did.md` §8.3 (`CokretRealmHistoryRecoveryKey`).
//!
//! ## SDK contract boundary
//!
//! The authoritative recovery-recipient resolution + seal are owned by the SDK
//! (`arkret_sdk::history_recovery`): [`resolve_realm_history_recovery_key`] and
//! [`seal_history_secrets_to_recovery_recipient`]. This module is the **thin
//! inkson adapter** both the eager seal hook (§2.10.8) and the disclosure banner
//! route through — it never re-implements the RRK crypto or the
//! service-entry verification. It only:
//!
//! - fetches / ingests the recipient principal's raw DID Document (the SDK `DidDocument` projection
//!   drops `service` / `keyAgreement`, so the resolver's original document value is threaded
//!   through unmodified), and
//! - wraps the two SDK calls behind [`resolve_recovery_recipient`] / [`seal_history_secrets`] so
//!   the call sites stay stable.
//!
//! If the SDK signatures move, only this file changes.

use arkret_sdk::history_recovery::{
    RealmHistoryRecoveryKeyError, ResolvedRealmHistoryRecoveryKey,
    resolve_realm_history_recovery_key, rrk_key_scope, seal_history_secrets_to_recovery_recipient,
};
use arkret_sdk::models::{DurabilityMode, DurabilityPolicy, RealmRecoveryRecipient};
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
/// `content_scheme=mls-exporter-aead-v1` (the caller checks the scheme).
pub fn durability_is_effective(policy: &DurabilityPolicy) -> bool {
    !matches!(policy.mode, DurabilityMode::None)
}

/// Resolve + verify one recovery recipient against its principal's raw DID
/// Document JSON. Pure delegation to the SDK authority
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
    resolve_realm_history_recovery_key(recipient, did_document_json)
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
/// public DID-document fetch and the per-recipient `CokretRealmHistoryRecoveryKey`
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
        let principal_did = recipient.principal_id.as_str().to_owned();
        let document =
            crate::did_resolver::fetch_raw_did_document_json(http, &recipient.principal_id).await;
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

/// HPKE-seal the retained `(epoch, history_secret)` rows to a resolved RRK and
/// return the durable `ck.realm_key.share` payload. Pure delegation to the SDK
/// authority [`seal_history_secrets_to_recovery_recipient`].
///
/// `policy_digest` binds the effective history-sharing policy at seal time;
/// `sender_device_id` / `sender_device_signature` author the share (the caller's
/// signing layer fills the detached signature).
#[allow(clippy::too_many_arguments)]
pub fn seal_history_secrets(
    recovery_key: &ResolvedRealmHistoryRecoveryKey,
    history_secrets: &[(u64, Vec<u8>)],
    realm_id: &str,
    from_epoch: u64,
    to_epoch: u64,
    policy_digest: Value,
    sender_device_id: &str,
    sender_device_signature: Value,
) -> Result<arkret_sdk::RealmKeySharePayload, String> {
    let scope = rrk_key_scope(realm_id, from_epoch, to_epoch, policy_digest, None);
    seal_history_secrets_to_recovery_recipient(
        recovery_key,
        history_secrets,
        realm_id,
        scope,
        sender_device_id.to_owned(),
        sender_device_signature,
        crate::clock::now_utc_secs(),
        None,
    )
    .map_err(|err| format!("seal history secrets to RRK: {err:?}"))
}

/// HKDF `info` deriving the offline RRK X25519 private key from the 24-word
/// recovery credential. Distinct from the `did_recovery` HPKE key-schedule info
/// in `crate::hpke_backup` so the RRK domain is isolated
/// (identity-did.md §8.3 / realm-and-space.md §2.3.1: the same key MUST NOT serve
/// both `did_recovery` and `CokretRealmHistoryRecoveryKey`).
const RRK_DERIVE_INFO: &[u8] = b"arkret-realm-history-recovery-key-x25519-v1";

/// Derive the offline RRK X25519 keypair (raw 32-byte `(private, public)`) from
/// the canonical 24-word recovery credential, in the history-recovery domain.
///
/// The keypair is raw-X25519 (not routed through hpke-rs) so it is byte-for-byte
/// compatible with the SDK seal/open primitive
/// (`open_history_secret_with_device_privkey`, which treats the private key as an
/// `x25519_dalek::StaticSecret`). The public half equals the
/// `publicKeyMultibase` an organization publishes in its
/// `CokretRealmHistoryRecoveryKey` service entry.
pub fn derive_rrk_keypair_from_recovery_key(
    recovery_key: &str,
) -> Result<([u8; 32], [u8; 32]), String> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let canonical = crate::recovery_crypto::normalize_recovery_key_input(recovery_key)
        .ok_or_else(|| "RRK recovery key must be a canonical 24-word BIP-39 mnemonic".to_owned())?;
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, canonical.as_str())
        .map_err(|err| format!("RRK recovery key mnemonic: {err}"))?;
    let entropy = mnemonic.to_entropy();
    let mut seed = [0u8; 32];
    Hkdf::<Sha256>::new(None, &entropy)
        .expand(RRK_DERIVE_INFO, &mut seed)
        .map_err(|_| "RRK key hkdf expand failed".to_owned())?;
    let secret = x25519_dalek::StaticSecret::from(seed);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((*secret.as_bytes(), *public.as_bytes()))
}

/// Open one RRK-targeted `ck.realm_key.share` ciphertext with the recovered RRK
/// private key, returning the `[(epoch, history_secret)]` rows. Pure delegation
/// to the SDK open primitive (the seal/open pair is symmetric and domain-bound).
pub fn open_rrk_share(
    rrk_private_key: &[u8; 32],
    sealed_ciphertext: &str,
) -> Result<Vec<(u64, Vec<u8>)>, String> {
    arkret_sdk::secret_share::open_history_secret_with_device_privkey(
        rrk_private_key,
        sealed_ciphertext,
    )
    .map_err(|err| format!("open RRK ak.realm_key.share: {err:?}"))
}

/// Filter a batch of `ck.realm_key.share` events down to those an RRK holder can
/// open: the ones whose payload `ciphertext` decrypts with `rrk_private_key`.
/// Returns every recovered `(epoch, history_secret)` row across all openable
/// shares, deduplicated by epoch (last wins). The caller installs these to
/// reconstruct `K_content[N]` and decrypt history (encryption-and-audit.md
/// §2.10.1 / §2.10.8 recovery read path).
pub fn recover_history_from_rrk_shares(
    rrk_private_key: &[u8; 32],
    share_events: &[Value],
) -> std::collections::BTreeMap<u64, Vec<u8>> {
    let mut recovered: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();
    for event in share_events {
        let content = event.get("content").unwrap_or(event);
        let Some(ciphertext) = content
            .get("ciphertext")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        if let Ok(rows) = open_rrk_share(rrk_private_key, ciphertext) {
            for (epoch, secret) in rows {
                if !secret.is_empty() {
                    recovered.insert(epoch, secret);
                }
            }
        }
    }
    recovered
}

/// Per-recipient outcome of an eager seal pass (encryption-and-audit.md
/// §2.10.8). `Sealed` carries the ready-to-submit `ck.realm_key.share` Event;
/// `Unverified` records a fail-closed recipient (the seal MUST NOT proceed for
/// it and the RYW guard MUST treat that recipient as not-yet-sealed).
pub enum RecipientSealOutcome {
    Sealed {
        recipient_id: String,
        event: arkret_sdk::Event,
    },
    Unverified {
        recipient_id: String,
        reason: String,
    },
}

/// Build the eager RRK seal Events for one epoch's `history_secrets`, one per
/// recovery recipient (encryption-and-audit.md §2.10.8 sealing obligation).
///
/// Pure orchestration over the SDK authority: resolve each recipient against its
/// pre-fetched raw DID Document (`did_documents[recipient_id]`), seal the
/// `(epoch, secret)` rows, and wrap + sign a `ck.realm_key.share` Event. A
/// recipient whose DID Document is missing or whose RRK is unverified yields an
/// [`RecipientSealOutcome::Unverified`] — the caller's RYW guard then refuses to
/// treat that epoch as durably sealed.
///
/// `policy_digest` binds the effective history-sharing policy at seal time
/// (e.g. the realm seal view `state_root`).
pub fn build_eager_seal_events(
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    policy: &DurabilityPolicy,
    history_secrets: &[(u64, Vec<u8>)],
    did_documents: &std::collections::BTreeMap<String, Value>,
    policy_digest: Value,
) -> Vec<RecipientSealOutcome> {
    if history_secrets.is_empty() || !durability_is_effective(policy) {
        return Vec::new();
    }
    let (from_epoch, to_epoch) = history_secrets
        .iter()
        .fold((u64::MAX, 0_u64), |(lo, hi), (epoch, _)| {
            (lo.min(*epoch), hi.max(*epoch))
        });
    policy
        .recovery_recipients
        .iter()
        .map(|recipient| {
            let recipient_id = recipient.recipient_id.clone();
            let Some(document) = did_documents.get(&recipient_id) else {
                return RecipientSealOutcome::Unverified {
                    recipient_id,
                    reason: "durability_recovery_recipient_unverified: DID document not fetched"
                        .to_owned(),
                };
            };
            let resolved = match resolve_recovery_recipient(recipient, document) {
                Ok(resolved) => resolved,
                Err(err) => {
                    return RecipientSealOutcome::Unverified {
                        recipient_id,
                        reason: err.to_string(),
                    };
                }
            };
            let payload = match seal_history_secrets(
                &resolved,
                history_secrets,
                realm_id,
                from_epoch,
                to_epoch,
                policy_digest.clone(),
                device_id,
                serde_json::json!({}),
            ) {
                Ok(payload) => payload,
                Err(reason) => {
                    return RecipientSealOutcome::Unverified {
                        recipient_id,
                        reason,
                    };
                }
            };
            match crate::mls::admission::wrap_realm_key_share_payload_event(
                realm_id, actor_id, payload,
            ) {
                Ok(event) => RecipientSealOutcome::Sealed {
                    recipient_id,
                    event,
                },
                Err(reason) => RecipientSealOutcome::Unverified {
                    recipient_id,
                    reason,
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use arkret_sdk::Did;
    use arkret_sdk::models::DurabilityThreshold;
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
            principal_id: Did::new("did:web:acme.example").unwrap(),
            verification_method: "did:web:acme.example#realm-history-recovery-1".to_owned(),
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
                    "type": "CokretRealmHistoryRecoveryKey",
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
    fn adapter_resolve_then_seal_round_trips() {
        // The adapter delegates to the SDK authority; an end-to-end resolve+seal
        // proves the inkson wrapper threads the document and scope correctly.
        let (sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
        let pk32: [u8; 32] = pk.as_slice().try_into().unwrap();
        let recipient = recipient();
        let document = did_document(&recipient, &pk32);

        let resolved = resolve_recovery_recipient(&recipient, &document).unwrap();
        let realm = "ak:realm:01904100-0000-7000-8000-e2eeae0d0001";
        let rows = vec![(7u64, vec![7u8; 32]), (8u64, vec![8u8; 32])];
        let payload = seal_history_secrets(
            &resolved,
            &rows,
            realm,
            7,
            8,
            json!("sha256:policy"),
            "ak:device:01904100-0000-7000-8000-00000000ae01",
            json!({}),
        )
        .unwrap();

        let opened = arkret_sdk::secret_share::open_history_secret_with_device_privkey(
            &sk,
            payload.ciphertext.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(opened, rows);
    }

    #[test]
    fn adapter_resolve_fails_closed_on_missing_service() {
        let recipient = recipient();
        let mut document = did_document(&recipient, &[3u8; 32]);
        document["service"] = json!([]);
        assert!(resolve_recovery_recipient(&recipient, &document).is_err());
    }

    const RRK_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

    #[test]
    fn rrk_keypair_derivation_is_deterministic_and_domain_isolated() {
        let (sk1, pk1) = derive_rrk_keypair_from_recovery_key(RRK_MNEMONIC).unwrap();
        let (sk2, pk2) = derive_rrk_keypair_from_recovery_key(RRK_MNEMONIC).unwrap();
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
        // pk MUST equal X25519(pk) of the sk (raw-X25519, SDK-compatible).
        let expected_pub =
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sk1)).as_bytes();
        assert_eq!(pk1, expected_pub);
        // Domain isolation: the RRK private key MUST differ from the did_recovery
        // HPKE key derived from the same mnemonic.
        let (did_recovery_sk, _) =
            crate::hpke_backup::derive_recovery_keypair_from_recovery_key(RRK_MNEMONIC).unwrap();
        assert_ne!(sk1.as_slice(), did_recovery_sk.as_slice());
    }

    #[test]
    fn rrk_recovery_round_trip_from_24_words() {
        // Org publishes pk; provider seals to it; org recovers with its 24 words.
        let (rrk_sk, rrk_pk) = derive_rrk_keypair_from_recovery_key(RRK_MNEMONIC).unwrap();
        let rows = vec![(11u64, vec![0xau8; 32]), (12u64, vec![0xbu8; 32])];
        let sealed =
            arkret_sdk::secret_share::seal_history_secret_to_device_pubkey(&rrk_pk, &rows).unwrap();
        let share = json!({
            "kind": "ak.realm_key.share",
            "content": { "ciphertext": sealed }
        });
        let recovered = recover_history_from_rrk_shares(&rrk_sk, std::slice::from_ref(&share));
        assert_eq!(recovered.get(&11), Some(&vec![0xau8; 32]));
        assert_eq!(recovered.get(&12), Some(&vec![0xbu8; 32]));
        assert_eq!(recovered.len(), 2);
    }

    #[test]
    fn rrk_recovery_skips_unopenable_shares() {
        let (rrk_sk, _rrk_pk) = derive_rrk_keypair_from_recovery_key(RRK_MNEMONIC).unwrap();
        // A share sealed to a DIFFERENT key cannot be opened.
        let (_other_sk, other_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
        let other_pk32: [u8; 32] = other_pk.as_slice().try_into().unwrap();
        let sealed = arkret_sdk::secret_share::seal_history_secret_to_device_pubkey(
            &other_pk32,
            &[(9u64, vec![9u8; 32])],
        )
        .unwrap();
        let share = json!({ "content": { "ciphertext": sealed } });
        let recovered = recover_history_from_rrk_shares(&rrk_sk, std::slice::from_ref(&share));
        assert!(recovered.is_empty());
    }
}
