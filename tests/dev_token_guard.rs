#![cfg(not(target_arch = "wasm32"))]

//! Q3 regression: the production build path must never ship a development
//! placeholder push token to a real push gateway.
//!
//! This file is the durable contract that backs `_todos.md` Q3. Two layers
//! enforce it:
//!
//! 1. `is_placeholder_push_key()` recognises every literal we hand-rolled in `src/push.rs`
//!    (`inkson-dev-…`, `placeholder`).
//! 2. `ensure_production_register_request()` refuses to hand a request that still carries one of
//!    those placeholders to the gateway.
//!
//! If either check stops firing — because we added another scaffold marker,
//! or removed the predicate — these tests fail loudly.

use inkson::push::{
    PLACEHOLDER_PUSH_KEY_MARKERS, ensure_production_register_request, is_placeholder_push_key,
};

fn request_with_push_key(push_key: &str) -> chime::ChimePushRegisterDeviceRequest {
    let mut request = chime::ChimePushRegisterDeviceRequest::default();
    request.device_id = "dev_inkson".to_owned();
    request.push_key = push_key.to_owned();
    request
}

#[test]
fn placeholder_marker_set_is_non_empty() {
    assert!(!PLACEHOLDER_PUSH_KEY_MARKERS.is_empty());
}

#[test]
fn ensure_production_register_request_blocks_placeholder() {
    let request = request_with_push_key("desktop:inkson-dev-placeholder-token");

    let err = ensure_production_register_request(&request)
        .expect_err("placeholder register request must not pass the production guard");

    let message = err.to_string();
    assert!(
        message.contains("dev_inkson"),
        "guard error must mention the device id, got: {message}"
    );
    assert!(
        message.contains("placeholder") || message.contains("CHASK_PUSH_KEY"),
        "guard error must explain how to swap in a real token, got: {message}"
    );
}

#[test]
fn ensure_production_register_request_passes_real_token() {
    let request = request_with_push_key("apns:0123456789abcdef0123456789abcdef");
    ensure_production_register_request(&request)
        .expect("a real platform push token must clear the production guard");
}

#[test]
fn placeholder_predicate_is_case_insensitive() {
    assert!(is_placeholder_push_key("DESKTOP:INKSON-DEV-XYZ"));
    assert!(is_placeholder_push_key("webpush:Inkson-Dev-Token"));
    assert!(is_placeholder_push_key("Some-Placeholder-Marker"));
    assert!(!is_placeholder_push_key(
        "apns:5dccd5b9c8be12a8d10dc1ad6c0a3a8d"
    ));
}
