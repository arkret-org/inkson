//! Q3 regression: the production build path must never ship a development
//! placeholder push token to a real push gateway.
//!
//! This file is the durable contract that backs `_todos.md` Q3. Two layers
//! enforce it:
//!
//! 1. `is_placeholder_push_key()` recognises every literal we hand-rolled in
//!    `src/push.rs` (`yougen-dev-…`, `placeholder`).
//! 2. `ensure_production_register_request()` refuses to hand a request that
//!    still carries one of those placeholders to the gateway.
//!
//! If either check stops firing — because we added another scaffold marker,
//! or removed the predicate — these tests fail loudly.

use yougen::push::{
    PLACEHOLDER_PUSH_KEY_MARKERS, build_register_request, build_register_request_for_actor,
    ensure_production_register_request, is_placeholder_push_key,
};

#[test]
fn placeholder_marker_set_is_non_empty() {
    assert!(
        !PLACEHOLDER_PUSH_KEY_MARKERS.is_empty(),
        "the placeholder marker set must include at least one literal — \
         removing it would silently let a dev token reach the push gateway."
    );
}

#[test]
fn default_scaffold_push_key_is_recognised_as_placeholder() {
    let request = build_register_request("dev_yougen").expect("scaffold register request builds");
    assert!(
        is_placeholder_push_key(&request.push_key),
        "default-build push key `{}` must still be flagged as a development placeholder; \
         either keep the dev marker (`yougen-dev-`/`placeholder`) or wire a real OS push \
         token before changing this assertion.",
        request.push_key
    );
}

#[test]
fn ensure_production_register_request_blocks_default_scaffold() {
    let request =
        build_register_request_for_actor("dev_yougen", Some("did:web:alice.example")).unwrap();

    let err = ensure_production_register_request(&request)
        .expect_err("default-build register request must NOT be accepted by the production guard");

    let message = err.to_string();
    assert!(
        message.contains("dev_yougen"),
        "guard error must mention the device id, got: {message}"
    );
    assert!(
        message.contains("placeholder") || message.contains("CHASK_PUSH_KEY"),
        "guard error must explain how to swap in a real token, got: {message}"
    );
}

#[test]
fn ensure_production_register_request_passes_real_token() {
    let mut request = build_register_request("dev_yougen").unwrap();
    request.push_key = "apns:0123456789abcdef0123456789abcdef".to_owned();
    ensure_production_register_request(&request)
        .expect("a real platform push token must clear the production guard");
}

#[test]
fn placeholder_predicate_is_case_insensitive() {
    assert!(is_placeholder_push_key("DESKTOP:YOUGEN-DEV-XYZ"));
    assert!(is_placeholder_push_key("webpush:Yougen-Dev-Token"));
    assert!(is_placeholder_push_key("Some-Placeholder-Marker"));
    assert!(!is_placeholder_push_key("apns:5dccd5b9c8be12a8d10dc1ad6c0a3a8d"));
}
