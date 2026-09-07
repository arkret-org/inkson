//! Server-issued invite-locator URL and QR helpers.

pub(super) fn build_invite_locator_url(base_url: &str, locator_token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/_arkret/open/invite-locators/resolve#token={locator_token}")
}

pub(super) async fn issue_invite_locator(
    client: arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::InviteLocatorIssueOutcome> {
    client
        .post(
            arkret_sdk::INVITE_LOCATOR_ISSUE_PATH,
            &arkret_sdk::InviteLocatorIssueRequestBody {
                ttl_seconds: Some(arkret_sdk::INVITE_LOCATOR_DEFAULT_TTL_SECONDS),
                one_time_use: Some(false),
                display_hint: None,
            },
        )
        .await
        .map_err(anyhow::Error::from)
}

pub(super) async fn rotate_invite_locator(
    client: arkret_sdk::http_client::Client,
    locator_id: String,
) -> anyhow::Result<arkret_sdk::InviteLocatorIssueOutcome> {
    let result = client
        .post(
            arkret_sdk::INVITE_LOCATOR_ROTATE_PATH,
            &arkret_sdk::InviteLocatorRotateRequestBody {
                locator_id: arkret_identifiers::InviteLocatorId::new(locator_id)?,
                ttl_seconds: Some(arkret_sdk::INVITE_LOCATOR_DEFAULT_TTL_SECONDS),
                one_time_use: Some(false),
                display_hint: None,
            },
        )
        .await;
    match result {
        // Expired/revoked locators cannot be rotated. Issue a fresh one only
        // after a definitive not_found; never retry an ambiguous write failure.
        Err(arkret_sdk::http_client::Error::Api { status: 404, error })
            if error.code() == arkret_sdk::error_codes::ErrorCode::NOT_FOUND =>
        {
            issue_invite_locator(client).await
        }
        other => other.map_err(anyhow::Error::from),
    }
}

pub(super) fn render_invite_locator_qr_svg(locator_url: &str) -> String {
    if locator_url.trim().is_empty() {
        return String::new();
    }
    match qrcode::QrCode::with_error_correction_level(locator_url.as_bytes(), qrcode::EcLevel::M) {
        Ok(code) => code
            .render::<qrcode::render::svg::Color<'_>>()
            .min_dimensions(192, 192)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[tokio::test]
    async fn expired_invite_locator_refresh_issues_a_new_link() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let locator_id = "ak:invite_locator:0196419b-0000-7000-8000-000000000000";
        let server = std::thread::spawn(move || {
            for (path, status, response) in [
                (arkret_sdk::INVITE_LOCATOR_ROTATE_PATH, "404 Not Found",
                 serde_json::to_string(&arkret_sdk::Problem::from_code("not_found", "invite locator not found")).unwrap()),
                (arkret_sdk::INVITE_LOCATOR_ISSUE_PATH, "200 OK",
                 serde_json::json!({"locator_id": locator_id, "locator_token": "fresh-token", "expires_at": "2026-09-07T07:00:00.000Z", "one_time_use": false}).to_string()),
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 4096];
                    let count = socket.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                        let length: usize = headers.lines().find_map(|line| line.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                        if request.len() >= end + 4 + length {
                            assert!(headers.starts_with(&format!("post /{path} http/1.1")));
                            let body: serde_json::Value = serde_json::from_slice(&request[end + 4..]).unwrap();
                            assert_eq!(body["ttl_seconds"], 900);
                            assert_eq!(body["one_time_use"], false);
                            break;
                        }
                    }
                }
                write!(socket, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
            }
        });
        let client = arkret_sdk::http_client::ClientBuilder::new(
            url::Url::parse(&format!("http://{address}")).unwrap(),
        ).allow_insecure_localhost().build().unwrap();
        let outcome = rotate_invite_locator(client, locator_id.to_owned()).await.unwrap();
        server.join().unwrap();
        assert_eq!(outcome.locator_token, "fresh-token");
        assert!(!outcome.one_time_use);
    }
}
