//! Tests for the SEC-08 minimal-metadata AAD policy enforcement.

use serde_json::json;

use crate::mls::runtime::*;

#[test]
fn minimal_metadata_aad_enforcement_is_fail_closed() {
    use arkret_sdk::AadVisibility;
    // Hidden is always accepted.
    assert_minimal_metadata_aad(&AadVisibility::Hidden, true).unwrap();
    assert_minimal_metadata_aad(&AadVisibility::Hidden, false).unwrap();
    // Non-hidden on a minimal Realm is rejected with the typed policy error.
    for v in [AadVisibility::RoutingDigest, AadVisibility::OpaqueId] {
        let err = assert_minimal_metadata_aad(&v, true).unwrap_err();
        assert!(matches!(err, MlsRuntimeError::AadPolicy(_)));
    }
    // Non-minimal Realm is unaffected by any visibility.
    assert_minimal_metadata_aad(&AadVisibility::RoutingDigest, false).unwrap();
    assert_minimal_metadata_aad(&AadVisibility::OpaqueId, false).unwrap();
}

#[test]
fn aad_visibility_inferred_from_canonical_aad_shape() {
    use arkret_sdk::AadVisibility;
    // hidden() omits both event-id fields ⇒ Hidden.
    let hidden = serde_json::to_value(arkret_sdk::EncryptedEnvelopeAadV1::hidden(
        "ak:realm:r",
        "ck.message.create",
    ))
    .unwrap();
    assert_eq!(aad_visibility_of(&hidden), AadVisibility::Hidden);
    // event_ref_digest present ⇒ RoutingDigest.
    assert_eq!(
        aad_visibility_of(&json!({
            "realm_id": "ak:realm:r",
            "event_kind": "ck.message.create",
            "event_ref_digest": "sha256:aa"
        })),
        AadVisibility::RoutingDigest
    );
    // event_id present ⇒ OpaqueId (checked first / least private).
    assert_eq!(
        aad_visibility_of(&json!({
            "realm_id": "ak:realm:r",
            "event_kind": "ck.message.create",
            "event_id": "ak:event:1"
        })),
        AadVisibility::OpaqueId
    );
    // Null event-id fields are treated as absent ⇒ Hidden.
    assert_eq!(
        aad_visibility_of(&json!({
            "realm_id": "ak:realm:r",
            "event_kind": "ck.message.create",
            "event_id": null,
            "event_ref_digest": null
        })),
        AadVisibility::Hidden
    );
}
