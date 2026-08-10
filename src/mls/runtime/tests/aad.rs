//! Tests for the SEC-08 minimal-metadata AAD policy enforcement.

use crate::mls::runtime::*;

#[test]
fn minimal_metadata_aad_enforcement_is_fail_closed() {
    use arkret_sdk::EncryptedEnvelopeAadVisibility;
    // Hidden is always accepted.
    assert_minimal_metadata_aad(&EncryptedEnvelopeAadVisibility::Hidden, true).unwrap();
    assert_minimal_metadata_aad(&EncryptedEnvelopeAadVisibility::Hidden, false).unwrap();
    // Non-hidden on a minimal Realm is rejected with the typed policy error.
    for v in [
        EncryptedEnvelopeAadVisibility::RoutingDigest,
        EncryptedEnvelopeAadVisibility::OpaqueId,
    ] {
        let err = assert_minimal_metadata_aad(&v, true).unwrap_err();
        assert!(matches!(err, MlsRuntimeError::AadPolicy(_)));
    }
    // Non-minimal Realm is unaffected by any visibility.
    assert_minimal_metadata_aad(&EncryptedEnvelopeAadVisibility::RoutingDigest, false).unwrap();
    assert_minimal_metadata_aad(&EncryptedEnvelopeAadVisibility::OpaqueId, false).unwrap();
}

#[test]
fn aad_visibility_inferred_from_canonical_aad_shape() {
    use arkret_sdk::EncryptedEnvelopeAadVisibility;
    // hidden() omits both event-id fields ⇒ Hidden.
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(
            "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned(),
        )
        .unwrap(),
    };
    let hidden = arkret_sdk::EncryptedEnvelopeAad::hidden(&scope, "ak.message.create").unwrap();
    assert_eq!(
        aad_visibility_of(&hidden),
        EncryptedEnvelopeAadVisibility::Hidden
    );
    // event_ref_digest present ⇒ RoutingDigest.
    assert_eq!(
        aad_visibility_of(&arkret_sdk::EncryptedEnvelopeAad {
            event_ref_digest: Some(
                arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap()
            ),
            ..hidden.clone()
        }),
        EncryptedEnvelopeAadVisibility::RoutingDigest
    );
    // event_id present ⇒ OpaqueId (checked first / least private).
    assert_eq!(
        aad_visibility_of(&arkret_sdk::EncryptedEnvelopeAad {
            event_id: Some(
                arkret_sdk::EventId::new("ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
                    .unwrap()
            ),
            ..hidden.clone()
        }),
        EncryptedEnvelopeAadVisibility::OpaqueId
    );
    // Null event-id fields are treated as absent ⇒ Hidden.
    assert_eq!(
        aad_visibility_of(&hidden),
        EncryptedEnvelopeAadVisibility::Hidden
    );
}
