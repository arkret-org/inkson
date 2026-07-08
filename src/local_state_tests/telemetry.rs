//! Telemetry flush re-buffering and audit-post error classification.

use super::*;

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "multi_thread")]
async fn flush_telemetry_404_re_buffers_entries() {
    // When the audit endpoint isn't wired (404), the flush
    // re-buffers each entry so a later flush attempt picks it up. We
    // simulate the 404 by pointing the API at a localhost port that
    // nothing's listening on - reqwest emits a connection error which
    // maps to `AuditPostError::Other`. To exercise the 404 path
    // specifically we spawn a minimal hyper-free TCP listener that
    // blanket-replies with 404.
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::telemetry::{UserActionOutcome, build_user_action_entry};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        // Reply 404 to a single request — enough for one
        // telemetry entry.
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            // Drain the request body opportunistically so the
            // client sees the response.
            let _ = socket.read(&mut buf).await;
            let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(resp).await;
            let _ = socket.shutdown().await;
        }
    });

    let mut store = LocalStateStore::with_path(temp_state_path("flush-404"));
    store.append_telemetry(build_user_action_entry(
        "did:key:zAlice",
        "settings.theme.set",
        UserActionOutcome::Success,
        None,
    ));
    assert_eq!(store.telemetry_log().len(), 1);

    let base = format!("http://{}/", addr);
    let api = crate::api::CokretApi::new(&base).unwrap();
    let sent = store.flush_telemetry_to_server(&api).await;
    assert_eq!(sent, 0, "404 must not count as sent");
    // 404-tolerant: entry survives for next attempt.
    assert_eq!(
        store.telemetry_log().len(),
        1,
        "404 must re-buffer the entry"
    );
    server.abort();
}

#[test]
fn audit_post_error_display_and_classification() {
    // The typed error variants are how callers branch between
    // "re-buffer" and "drop" - the strings here drive operator-facing
    // copy and are part of the contract.
    let not_wired = crate::api_error::AuditPostError::NotWired;
    assert!(not_wired.to_string().contains("404"));
    let other = crate::api_error::AuditPostError::Other("conn refused".to_owned());
    assert!(other.to_string().contains("conn refused"));
}
