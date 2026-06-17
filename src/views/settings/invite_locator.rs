//! Invite-locator token/URL/QR helpers plus the small avatar-crop staging
//! type, factored out of the settings panel. The locator helpers mint a
//! short-lived self-locator the user can hand out as a QR/link; the avatar
//! helpers stage a cropped image preview before upload.

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
};
use serde_json::json;

pub(super) const INVITE_LOCATOR_TTL_MINUTES: i64 = 15;

#[derive(Clone, Debug, PartialEq)]
pub(super) struct PendingAvatarCrop {
    pub(super) bytes: Vec<u8>,
    pub(super) media_type: String,
    pub(super) preview_data_url: String,
    pub(super) dimensions: (u32, u32),
}

pub(super) fn avatar_preview_data_url(bytes: &[u8], media_type: &str) -> String {
    let media_type = if media_type.trim().is_empty() {
        "application/octet-stream"
    } else {
        media_type
    };
    format!("data:{media_type};base64,{}", BASE64_STANDARD.encode(bytes))
}

pub(super) fn random_invite_locator_nonce() -> String {
    let mut bytes = [0_u8; 24];
    if getrandom::fill(&mut bytes).is_ok() {
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    } else {
        crate::operation::uuid_v7()
    }
}

pub(super) fn build_invite_locator_token(account_did: &str) -> String {
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(INVITE_LOCATOR_TTL_MINUTES))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    BASE64_URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "subject_id": account_did,
            "nonce": random_invite_locator_nonce(),
            "expires_at": expires_at,
        }))
        .unwrap_or_default(),
    )
}

pub(super) fn build_invite_locator_url(base_url: &str, locator_token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/_cokret/open/invite-locators/resolve#token={locator_token}")
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

pub(super) fn copy_text_to_clipboard(text: &str) {
    let Ok(encoded) = serde_json::to_string(text) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const text = {encoded};
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = text;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = dioxus::document::eval(&script);
}
