use crate::wire_helpers::{path_component, safe_blob_filename_header};

#[test]
fn endpoint_join_keeps_api_paths_under_base_url() {
    let api = crate::transport::TransportClient::unauthenticated("http://127.0.0.1:8787/").unwrap();
    assert_eq!(
        api.endpoint("/_arkret/describe").unwrap().as_str(),
        "http://127.0.0.1:8787/_arkret/describe"
    );
}

#[test]
fn endpoint_enforces_private_path_redline() {
    let api = crate::transport::TransportClient::unauthenticated("http://127.0.0.1:8787/").unwrap();
    assert!(api.endpoint("_arkret/self/events").is_ok());
    let private_prefix = concat!("_so", "land");
    let private_consent = [private_prefix, "self", "consent", "cells", "alice", "grant"].join("/");
    assert!(api.endpoint(&private_consent).is_err());
    let retired_account_me = [private_prefix, "self", "account", "me"].join("/");
    assert!(api.endpoint(&retired_account_me).is_err());
    let unlisted = format!("{private_prefix}/self/spaces/ak:space:1");
    let error = api
        .endpoint(&unlisted)
        .expect_err("soland private paths must be rejected");
    assert!(
        error.to_string().contains("redline"),
        "error should mention the redline: {error}"
    );
}

#[test]
fn path_component_percent_encodes_did_as_path_segment() {
    assert_eq!(
        path_component("did:web:agent.example"),
        "did%3Aweb%3Aagent.example"
    );
    assert_eq!(
        path_component("did:web:example.com:agents/alice"),
        "did%3Aweb%3Aexample.com%3Aagents%2Falice"
    );
}

#[test]
fn blob_upload_filename_header_is_ascii_safe() {
    assert_eq!(
        safe_blob_filename_header("..\\danger<script>.txt").as_deref(),
        Some("danger_script_.txt")
    );
    assert_eq!(
        safe_blob_filename_header("数据库.dump"),
        Some("dump".to_owned())
    );
    assert_eq!(safe_blob_filename_header("🧪").as_deref(), None);
}

#[test]
fn insecure_remote_http_is_rejected() {
    let error = crate::transport::TransportClient::unauthenticated("http://arkret.example")
        .err()
        .expect("insecure remote HTTP must be rejected");
    assert!(
        error
            .to_string()
            .contains("HTTPS is required for non-local servers")
    );
}
