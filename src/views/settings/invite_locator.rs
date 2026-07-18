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
    client
        .post(
            arkret_sdk::INVITE_LOCATOR_ROTATE_PATH,
            &arkret_sdk::InviteLocatorRotateRequestBody {
                locator_id,
                ttl_seconds: Some(arkret_sdk::INVITE_LOCATOR_DEFAULT_TTL_SECONDS),
                one_time_use: Some(false),
                display_hint: None,
            },
        )
        .await
        .map_err(anyhow::Error::from)
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
