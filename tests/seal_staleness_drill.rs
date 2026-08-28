#![cfg(not(target_arch = "wasm32"))]

//! End-to-end: with proof_mode = RealEd25519, build a Realm bootstrap +
//! send a message, verify each event's seal_ref is real and proofs[0].jws
//! is a real Ed25519 signature (not "a..b").
//!
//! Stream J / J5 — seal staleness drill. The full end-to-end shape
//! requires a live soland endpoint to mint a real Seal and an active
//! event-signer to attach a detached JWS proof; without those it's a
//! pure shape check on the builder output.
//!
//! What this file asserts unconditionally (no server required):
//!   1. `build_realm_create_event` accepts well-formed inputs and returns a typed envelope whose
//!      canonical shape passes the regex-level "real signature, real seal" checks once the submit
//!      pipeline stamps them. We simulate that stamping with an in-process Ed25519 signer and a
//!      SHA-256-derived seal ref.
//!   2. `proofs[0].jws` matches `^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$` (detached-JWS shape) and is
//!      NOT the dev placeholder `"a..b"`.
//!   3. `proofs[0].event_digest` starts with `sha256:` and has 64 hex chars.
//!   4. `seal_ref` is `Some(_)` for reducer-input kinds AND matches
//!      `^ak:seal:sha256:[0-9a-f]{64}$`. The fake seal is NOT the all-zero hash.
use ed25519_dalek::SigningKey;
use inkson::canonical::hex_encode;
use inkson::event_builders;
use inkson::operation::{AuthoredEventExt, Event, LocalOperation};

mod common;
use regex::Regex;
use sha2::{Digest, Sha256};

const TEST_ACTOR_ID: &str = "did:web:alice.example";
const TEST_SERVICE_ID: &str = "did:web:server.example";

fn test_genesis_salt() -> arkret_sdk::GenesisSalt {
    inkson::operation::set_authoring_principal_server_id(Some(
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned())
            .expect("test Principal Server core id is canonical"),
    ));
    arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .expect("test Realm genesis salt is canonical")
}

/// Deterministic Ed25519 seed used in this test process. Different
/// seed from `conformance_gates.rs::test_signing_key` so a future
/// signature-aware verifier never confuses the two test surfaces.
fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE,
        0x0F, 0x10,
    ])
}

/// Stamp the envelope with a real Ed25519 detached-JWS proof and a
/// concrete `ak:seal:sha256:<hex>` ref derived from the envelope's
/// own kind. We deliberately do NOT use the zero hash, so the test
/// catches a downstream regression that would forget to mint a real
/// seal.
fn author_with_real_proof_and_anchor(operation: LocalOperation) -> arkret_sdk::AuthoredEvent {
    author_intent_with_real_proof_and_anchor(operation.into_intent())
}

fn author_intent_with_real_proof_and_anchor(
    intent: inkson::operation::EventIntent,
) -> arkret_sdk::AuthoredEvent {
    // The seal ref is producer-signed content, so it has to be in place before
    // the identity is derived from it. Stamping it onto a finished envelope
    // would leave that envelope carrying an id its own content no longer
    // derives, which is exactly what the signer now refuses.
    let seal_ref = test_seal_ref(intent.kind().as_str());
    sign_real(common::author_intent_at_seq(
        intent.with_seal_ref(seal_ref),
        1,
    ))
}

/// The stand-in seal ref for `kind`, derived so it is stable and non-zero.
fn test_seal_ref(kind: &str) -> arkret_sdk::SealId {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b":seal_staleness_drill");
    let digest = hasher.finalize();
    arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", hex_encode(&digest)))
        .expect("test seal ref is valid")
}

/// Attach the producer proof to an authored envelope.
fn sign_real(mut envelope: arkret_sdk::AuthoredEvent) -> arkret_sdk::AuthoredEvent {
    let signer_did = TEST_ACTOR_ID;
    let key_id = format!("{signer_did}#device");
    envelope
        .sign_ed25519(signer_did, key_id, &signing_key())
        .expect("real Ed25519 sign succeeds");
    envelope
}

#[test]
fn realm_create_envelope_carries_real_proof_and_real_anchor() {
    let envelope = event_builders::build_realm_create_event(
        test_genesis_salt(),
        TEST_ACTOR_ID,
        common::test_notary(TEST_SERVICE_ID),
        "Engineering",
        Some("Roadmap work"),
        "listed",
        "invite",
        "since_join",
        "mls_rfc9420",
        "standard",
        "restricted",
        "sha256",
        "ak:trust_domain:server.example",
        None,
    )
    .expect("build_realm_create_event succeeds");

    let envelope = author_with_real_proof_and_anchor(envelope);

    assert_jws_is_real_signature(&envelope);
    assert_event_digest_is_sha256(&envelope);
    assert_seal_ref_is_real(&envelope);
}

#[test]
fn full_bootstrap_chain_carries_real_proofs_and_anchors() {
    // Every stage of the unit is authored in order, so a later member can name
    // an earlier one — which is what the seal stamp then rides on.
    let events = common::author_unit(
        event_builders::build_realm_bootstrap_steps(
            test_genesis_salt(),
            TEST_ACTOR_ID,
            TEST_SERVICE_ID,
            common::test_notary(TEST_SERVICE_ID),
            "https://server.example",
            "Engineering",
            None,
            "listed",
            "invite",
            "since_join",
            "mls_rfc9420",
            "standard",
            "restricted",
            "sha256",
            "ak:trust_domain:server.example",
            &["did:web:server.example".to_owned()],
            None,
            None,
        )
        .expect("build_realm_bootstrap_steps succeeds"),
    );

    assert!(
        events.len() >= 5,
        "bootstrap chain expected ≥5 envelopes (realm.create + 3 state events + plaintext_visible_services + invitee), got {}",
        events.len()
    );

    for envelope in events {
        // The unit's members are authored together, so each is re-authored here
        // with the drill's seal ref in place before the identity is derived.
        let envelope = author_intent_with_real_proof_and_anchor(
            inkson::operation::EventIntent::from_authored(&envelope),
        );
        assert_jws_is_real_signature(&envelope);
        assert_event_digest_is_sha256(&envelope);
        assert_seal_ref_is_real(&envelope);
    }
}

fn assert_jws_is_real_signature(envelope: &Event) {
    let proof = envelope
        .proofs
        .iter()
        .find_map(arkret_sdk::EventProof::as_producer)
        .unwrap_or_else(|| panic!("envelope kind={} missing proofs[0]", envelope.kind));
    assert_ne!(
        proof.jws, "a..b",
        "envelope kind={} carried the dev placeholder JWS `a..b`",
        envelope.kind
    );
    let detached_re =
        Regex::new(r"^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$").expect("detached-JWS regex compiles");
    assert!(
        detached_re.is_match(&proof.jws),
        "envelope kind={} has malformed detached JWS `{}` (expected `<header_b64>..<sig_b64>`)",
        envelope.kind,
        proof.jws
    );
    // Ed25519 signatures are 64 bytes → ~86 b64u chars; sanity check
    // the signature segment is non-trivial in length so the test
    // catches a regression that would write an empty signature.
    let (_header, sig_b64) = proof
        .jws
        .split_once("..")
        .expect("detached JWS has `..` separator");
    assert!(
        sig_b64.len() >= 80,
        "envelope kind={} has implausibly short Ed25519 signature segment `{}`",
        envelope.kind,
        sig_b64
    );
}

fn assert_event_digest_is_sha256(envelope: &Event) {
    let proof = envelope
        .proofs
        .iter()
        .find_map(arkret_sdk::EventProof::as_producer)
        .unwrap_or_else(|| panic!("envelope kind={} missing proofs[0]", envelope.kind));
    let hex = proof
        .event_digest
        .as_str()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| {
            panic!(
                "envelope kind={} event_digest `{}` does not start with `sha256:`",
                envelope.kind, proof.event_digest
            )
        });
    assert_eq!(
        hex.len(),
        64,
        "envelope kind={} event_digest hex segment is {} chars (expected 64): `{}`",
        envelope.kind,
        hex.len(),
        hex
    );
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "envelope kind={} event_digest `{}` contains non-hex characters",
        envelope.kind,
        hex
    );
}

fn assert_seal_ref_is_real(envelope: &Event) {
    let seal = envelope
        .seal_ref
        .as_ref()
        .map(|seal| seal.as_str())
        .unwrap_or_else(|| {
            panic!(
                "envelope kind={} has no seal_ref (reducer-input events MUST carry one)",
                envelope.kind
            )
        });
    let anchor_re = Regex::new(r"^ak:seal:sha256:[0-9a-f]{64}$").expect("seal regex compiles");
    assert!(
        anchor_re.is_match(seal),
        "envelope kind={} seal_ref `{}` does not match ak:seal:sha256:<64 hex>",
        envelope.kind,
        seal
    );
    let zero_anchor =
        "ak:seal:sha256:0000000000000000000000000000000000000000000000000000000000000000";
    assert_ne!(
        seal, zero_anchor,
        "envelope kind={} seal_ref is the all-zero sha256 hash (placeholder leak)",
        envelope.kind
    );
}
