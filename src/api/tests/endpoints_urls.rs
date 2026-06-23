use super::super::*;

#[test]
fn endpoint_join_keeps_api_paths_under_base_url() {
    let api = CokretApi::new("http://127.0.0.1:8787/").unwrap();
    assert_eq!(
        api.endpoint("/_cokret/describe").unwrap().as_str(),
        "http://127.0.0.1:8787/_cokret/describe"
    );
}

#[test]
fn endpoint_enforces_private_path_redline() {
    let api = CokretApi::new("http://127.0.0.1:8787/").unwrap();
    assert!(api.endpoint("_cokret/self/events").is_ok());
    let private_prefix = concat!("_so", "land");
    let private_consent = [private_prefix, "self", "consent", "cells", "alice", "grant"].join("/");
    assert!(api.endpoint(&private_consent).is_err());
    let retired_account_me = [private_prefix, "self", "account", "me"].join("/");
    assert!(api.endpoint(&retired_account_me).is_err());
    let unlisted = format!("{private_prefix}/self/spaces/ck:space:1");
    let error = api
        .endpoint(&unlisted)
        .expect_err("soland private paths must be rejected");
    assert!(
        error.to_string().contains("redline"),
        "error should mention the redline: {error}"
    );
}

#[test]
fn endpoint_absent_only_triggers_on_404() {
    // 404 unrecognized_endpoint means the canonical endpoint is absent.
    let not_found: anyhow::Error = CokretApiError {
        status: StatusCode::NOT_FOUND,
        error: decode_cokret_error(StatusCode::NOT_FOUND, b"{}"),
    }
    .into();
    assert!(is_endpoint_absent(&not_found));

    // A 5xx is a real server failure, not an absent endpoint — must propagate.
    let server_error: anyhow::Error = CokretApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        error: decode_cokret_error(StatusCode::INTERNAL_SERVER_ERROR, b"{}"),
    }
    .into();
    assert!(!is_endpoint_absent(&server_error));

    // A non-API transport error must not be mistaken for an absent endpoint.
    let transport: anyhow::Error = anyhow::anyhow!("connection refused");
    assert!(!is_endpoint_absent(&transport));
}

#[test]
fn blob_download_url_strips_media_hint_before_query() {
    let url = blob_download_url_for("http://127.0.0.1:8787/", "ck:blob:sha256:abcdef#image/png");
    assert_eq!(
        url,
        "http://127.0.0.1:8787/_cokret/self/blob/get?blob_ref=ck%3Ablob%3Asha256%3Aabcdef&purpose=profile_avatar"
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
fn event_paths_use_v1_query_parameters() {
    let backfill = events_query_path("ck:realm:demo");
    assert_eq!(backfill, "_cokret/self/events?realms=ck%3Arealm%3Ademo");
    assert!(!backfill.contains("direction="));

    let subscribe = events_subscribe_path("ck:realm:demo", Some("ck:cursor:demo"), Some(true));
    assert_eq!(
        subscribe,
        "_cokret/self/events/subscribe?realms=ck%3Arealm%3Ademo&after=ck%3Acursor%3Ademo&include_history=true"
    );
    assert!(!subscribe.contains("&from="));
}

#[test]
fn event_frontier_selectors_preserve_did_percent_escapes() {
    let actor = "did:webvh:zQmExampleScid:127.0.0.1%3A22375:webvh:01kvsk95qeev5t63b5njft1xzk";
    let actor_selector = format!(
        "_cokret/self/events/frontier?actor_id={}",
        query_component(actor)
    );
    assert_eq!(
        actor_selector,
        "_cokret/self/events/frontier?actor_id=did%3Awebvh%3AzQmExampleScid%3A127.0.0.1%253A22375%3Awebvh%3A01kvsk95qeev5t63b5njft1xzk"
    );

    let realm_selector = format!(
        "_cokret/self/events/frontier?realm_id={}",
        query_component("ck:realm:0196419b-0000-7000-8000-000000000000")
    );
    assert_eq!(
        realm_selector,
        "_cokret/self/events/frontier?realm_id=ck%3Arealm%3A0196419b-0000-7000-8000-000000000000"
    );
}

#[test]
fn insecure_remote_http_is_rejected() {
    let error = CokretApi::new("http://cokret.example").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("HTTPS is required for non-local servers")
    );
}
